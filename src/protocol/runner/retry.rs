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

use std::time::Duration;

use crate::protocol::suite_plan::ProtocolEventualConsistencyPolicy;

pub(crate) fn eventual_consistency_policy() -> ProtocolEventualConsistencyPolicy {
    ProtocolEventualConsistencyPolicy::default()
}

pub(crate) async fn wait_for_eventual_retry() {
    tokio::time::sleep(Duration::from_millis(
        eventual_consistency_policy().interval_millis,
    ))
    .await;
}

pub(crate) async fn wait_for_required_delay(duration: Duration) {
    tokio::time::sleep(duration).await;
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    fn collect_rust_sources(root: &Path, sources: &mut Vec<std::path::PathBuf>) {
        for entry in fs::read_dir(root).expect("case source directory") {
            let path = entry.expect("case source entry").path();
            if path.is_dir() {
                collect_rust_sources(&path, sources);
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
                sources.push(path);
            }
        }
    }

    #[test]
    fn protocol_cases_cannot_bypass_timeout_and_retry_policy() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol/cases");
        let mut sources = Vec::new();
        collect_rust_sources(&root, &mut sources);
        for path in sources {
            let source = fs::read_to_string(&path).expect("case source");
            assert!(
                !source.contains("tokio::time::sleep"),
                "{} bypasses the protocol wait policy",
                path.display()
            );
        }
    }
}
