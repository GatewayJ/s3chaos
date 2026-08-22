// Copyright 2025 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::{Context, Result, ensure};
use serde::Serialize;
#[cfg(unix)]
use std::fs::File;
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Component, Path, PathBuf},
};
use uuid::Uuid;

/// The only filesystem capability required by protocol artifact production.
///
/// Remote-resource cleanup deliberately has no access to this port. That keeps
/// diagnostic artifacts available after both successful and failed cleanup.
pub(crate) trait ProtocolArtifactSink: Send + Sync {
    fn create_dir_all(&self, path: &Path) -> Result<()>;
    fn read(&self, path: &Path) -> Result<Vec<u8>>;
    fn validate_destination(&self, root: &Path, destination: &Path) -> Result<()>;
    fn write(&self, path: &Path, contents: &[u8]) -> Result<()>;
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct FileProtocolArtifactSink;

impl ProtocolArtifactSink for FileProtocolArtifactSink {
    fn create_dir_all(&self, path: &Path) -> Result<()> {
        std::fs::create_dir_all(path)
            .with_context(|| format!("create protocol artifact directory {}", path.display()))
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>> {
        std::fs::read(path)
            .with_context(|| format!("read protocol artifact source {}", path.display()))
    }

    fn validate_destination(&self, root: &Path, destination: &Path) -> Result<()> {
        let canonical_root = std::fs::canonicalize(root)
            .with_context(|| format!("resolve protocol artifact root {}", root.display()))?;
        let parent = destination
            .parent()
            .context("protocol artifact destination has no parent")?;
        let canonical_parent = std::fs::canonicalize(parent).with_context(|| {
            format!(
                "resolve protocol artifact destination parent {}",
                parent.display()
            )
        })?;
        ensure!(
            canonical_parent.starts_with(&canonical_root),
            "protocol artifact destination escapes root through a symlink"
        );
        Ok(())
    }

    fn write(&self, path: &Path, contents: &[u8]) -> Result<()> {
        let parent = path
            .parent()
            .context("protocol artifact path has no parent")?;
        let name = path
            .file_name()
            .context("protocol artifact path has no file name")?
            .to_string_lossy();
        let temporary = parent.join(format!(".{name}-{}.tmp", Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .with_context(|| {
                    format!("create temporary protocol artifact {}", temporary.display())
                })?;
            file.write_all(contents)?;
            file.sync_all()?;
            std::fs::rename(&temporary, path).with_context(|| {
                format!(
                    "replace protocol artifact {} with {}",
                    path.display(),
                    temporary.display()
                )
            })?;
            sync_parent_directory(parent)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result.with_context(|| format!("write protocol artifact {}", path.display()))
    }
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> Result<()> {
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_directory(_parent: &Path) -> Result<()> {
    // Opening directories as ordinary files is not portable (notably on Windows). The artifact
    // file itself is still synced before the atomic rename.
    Ok(())
}

/// Serializes all run artifacts through one root-scoped boundary.
///
/// Callers provide relative paths only. The writer owns path validation and
/// serialization so execution and cleanup code do not depend on filesystem
/// mechanics or artifact representation.
pub(crate) struct ProtocolArtifactWriter<S = FileProtocolArtifactSink> {
    root: PathBuf,
    sink: S,
}

impl ProtocolArtifactWriter<FileProtocolArtifactSink> {
    pub(crate) fn file(root: impl Into<PathBuf>) -> Self {
        Self::new(root, FileProtocolArtifactSink)
    }
}

impl<S: ProtocolArtifactSink> ProtocolArtifactWriter<S> {
    pub(crate) fn new(root: impl Into<PathBuf>, sink: S) -> Self {
        Self {
            root: root.into(),
            sink,
        }
    }

    pub(crate) fn initialize_run(&self, suite_source: &Path) -> Result<()> {
        self.sink.create_dir_all(&self.root.join("cases"))?;
        let suite = self.sink.read(suite_source)?;
        self.write("protocol-suite.yaml", &suite)
    }

    pub(crate) fn create_case_dir(&self, case_id: &str) -> Result<()> {
        let relative = Path::new("cases").join(case_id);
        self.validate_relative(&relative)?;
        self.sink
            .validate_destination(&self.root, &self.root.join("cases").join(".case-boundary"))?;
        self.sink.create_dir_all(&self.root.join(relative))
    }

    pub(crate) fn write_json(
        &self,
        relative: impl AsRef<Path>,
        value: &impl Serialize,
    ) -> Result<()> {
        let mut contents = serde_json::to_vec_pretty(value)?;
        contents.push(b'\n');
        self.write(relative, &contents)
    }

    pub(crate) fn write_json_lines<T: Serialize>(
        &self,
        relative: impl AsRef<Path>,
        values: &[T],
    ) -> Result<()> {
        let mut contents = Vec::new();
        for value in values {
            serde_json::to_writer(&mut contents, value)?;
            contents.push(b'\n');
        }
        self.write(relative, &contents)
    }

    pub(crate) fn write_text(&self, relative: impl AsRef<Path>, contents: &str) -> Result<()> {
        self.write(relative, contents.as_bytes())
    }

    pub(crate) fn relative_path(&self, path: &Path) -> Result<String> {
        Ok(path
            .strip_prefix(&self.root)
            .with_context(|| {
                format!(
                    "protocol artifact {} is outside root {}",
                    path.display(),
                    self.root.display()
                )
            })?
            .display()
            .to_string())
    }

    fn write(&self, relative: impl AsRef<Path>, contents: &[u8]) -> Result<()> {
        let relative = relative.as_ref();
        self.validate_relative(relative)?;
        let destination = self.root.join(relative);
        self.sink.validate_destination(&self.root, &destination)?;
        self.sink.write(&destination, contents)
    }

    fn validate_relative(&self, relative: &Path) -> Result<()> {
        ensure!(
            !relative.as_os_str().is_empty() && !relative.is_absolute(),
            "protocol artifact path must be non-empty and relative"
        );
        ensure!(
            relative
                .components()
                .all(|component| matches!(component, Component::Normal(_) | Component::CurDir)),
            "protocol artifact path must stay within the artifact root"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ProtocolArtifactSink, ProtocolArtifactWriter};
    use anyhow::Result;
    use serde::Serialize;
    use std::{
        collections::BTreeMap,
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    };

    #[derive(Clone, Default)]
    struct MemorySink(Arc<Mutex<BTreeMap<PathBuf, Vec<u8>>>>);

    impl ProtocolArtifactSink for MemorySink {
        fn create_dir_all(&self, _path: &Path) -> Result<()> {
            Ok(())
        }

        fn read(&self, _path: &Path) -> Result<Vec<u8>> {
            Ok(b"suite".to_vec())
        }

        fn validate_destination(&self, root: &Path, destination: &Path) -> Result<()> {
            anyhow::ensure!(destination.starts_with(root), "destination outside root");
            Ok(())
        }

        fn write(&self, path: &Path, contents: &[u8]) -> Result<()> {
            self.0
                .lock()
                .expect("memory sink")
                .insert(path.to_path_buf(), contents.to_vec());
            Ok(())
        }
    }

    #[derive(Serialize)]
    struct Example<'a> {
        value: &'a str,
    }

    #[test]
    fn writer_preserves_json_and_json_lines_contract_without_filesystem() {
        let sink = MemorySink::default();
        let writer = ProtocolArtifactWriter::new("artifacts/run", sink.clone());
        writer
            .write_json("summary.json", &Example { value: "ok" })
            .expect("json");
        writer
            .write_json_lines(
                "history.jsonl",
                &[Example { value: "one" }, Example { value: "two" }],
            )
            .expect("json lines");

        let files = sink.0.lock().expect("memory sink");
        let summary = files
            .get(Path::new("artifacts/run/summary.json"))
            .expect("summary");
        assert_eq!(summary.last(), Some(&b'\n'));
        let history = files
            .get(Path::new("artifacts/run/history.jsonl"))
            .expect("history");
        assert_eq!(history.iter().filter(|byte| **byte == b'\n').count(), 2);
    }

    #[test]
    fn writer_rejects_paths_outside_artifact_root() {
        let writer = ProtocolArtifactWriter::new("artifacts/run", MemorySink::default());
        let error = writer
            .write_json("../resource-registry.json", &Example { value: "bad" })
            .expect_err("parent traversal must fail");
        assert!(error.to_string().contains("stay within"));
    }

    #[test]
    fn file_writer_atomically_replaces_complete_contents_without_temporary_files() {
        let root = tempfile::tempdir().expect("tempdir");
        let writer = ProtocolArtifactWriter::file(root.path());
        writer
            .write_json("summary.json", &Example { value: "first" })
            .expect("first write");
        writer
            .write_json("summary.json", &Example { value: "second" })
            .expect("replacement write");

        let contents =
            std::fs::read_to_string(root.path().join("summary.json")).expect("complete artifact");
        let decoded: serde_json::Value = serde_json::from_str(&contents).expect("valid json");
        assert_eq!(decoded["value"], "second");
        assert!(
            std::fs::read_dir(root.path())
                .expect("artifact root")
                .all(|entry| !entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp"))
        );
    }

    #[test]
    fn failed_atomic_replace_removes_temporary_file() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(root.path().join("occupied.json")).expect("occupied directory");
        let writer = ProtocolArtifactWriter::file(root.path());

        writer
            .write_json(
                "occupied.json",
                &Example {
                    value: "cannot-replace",
                },
            )
            .expect_err("renaming a file over a directory must fail");

        assert!(
            std::fs::read_dir(root.path())
                .expect("artifact root")
                .all(|entry| !entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp"))
        );
    }

    #[test]
    fn suite_source_is_written_through_the_atomic_artifact_boundary() {
        let source = tempfile::NamedTempFile::new().expect("source");
        std::fs::write(source.path(), b"apiVersion: test\n").expect("suite source");
        let root = tempfile::tempdir().expect("artifact root");
        let writer = ProtocolArtifactWriter::file(root.path());

        writer
            .initialize_run(source.path())
            .expect("initialize run");

        assert_eq!(
            std::fs::read(root.path().join("protocol-suite.yaml")).expect("suite artifact"),
            b"apiVersion: test\n"
        );
        assert!(
            std::fs::read_dir(root.path())
                .expect("artifact root")
                .all(|entry| !entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn file_writer_rejects_symlink_escape_from_artifact_root() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("root");
        let outside = tempfile::tempdir().expect("outside");
        symlink(outside.path(), root.path().join("cases")).expect("escape symlink");
        let writer = ProtocolArtifactWriter::file(root.path());

        writer
            .write_json("cases/escape.json", &Example { value: "escape" })
            .expect_err("symlink escape must fail");

        assert!(!outside.path().join("escape.json").exists());
    }
}
