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
use async_trait::async_trait;
use std::path::Path;

use crate::protocol::{
    fixture::{
        cleanup::cleanup_registered_resources_with_external,
        registry::{RESOURCE_REGISTRY_FILE, ResourceRegistry},
    },
    ports::{ProtocolAdminCleanupPort, ProtocolExternalIdentityPort, ProtocolS3CleanupPort},
    reporting::{ProtocolCleanupAttempt, ProtocolCleanupReport},
    suite_plan::ProtocolSuitePlanCase,
};

/// Cleanup operations required by suite execution.
///
/// The executor owns sequencing policy but has no knowledge of registry files,
/// S3, Admin APIs, external identity providers, or their concrete adapters.
#[async_trait]
pub(crate) trait ProtocolExecutionCleanup: Sync {
    type RunState: Send;

    async fn cleanup_case_registry_if_present(&self, case_id: &str) -> ProtocolCleanupReport;

    async fn cleanup_suite_registries(
        &self,
        cases: &[ProtocolSuitePlanCase],
        run_state: &mut Self::RunState,
    ) -> ProtocolCleanupReport;
}

/// Coordinates replayable cleanup through protocol-owned ports.
///
/// ResourceRegistry records mutations before the remote call. The lower-level
/// cleanup engine orders dependents before dependencies, verifies absence after
/// deletion, and leaves unresolved resources in the report. This coordinator
/// ensures a corrupt case registry cannot prevent later case or root cleanup.
pub(crate) struct ProtocolCleanupCoordinator<'a, A, S> {
    artifact_root: &'a Path,
    admin: &'a A,
    s3: &'a S,
    external_identity: Option<&'a dyn ProtocolExternalIdentityPort>,
    api_version: &'a str,
}

impl<'a, A, S> ProtocolCleanupCoordinator<'a, A, S> {
    pub(crate) fn new(
        artifact_root: &'a Path,
        admin: &'a A,
        s3: &'a S,
        external_identity: Option<&'a dyn ProtocolExternalIdentityPort>,
        api_version: &'a str,
    ) -> Self {
        Self {
            artifact_root,
            admin,
            s3,
            external_identity,
            api_version,
        }
    }
}

impl<A, S> ProtocolCleanupCoordinator<'_, A, S>
where
    A: ProtocolAdminCleanupPort,
    S: ProtocolS3CleanupPort,
{
    pub(crate) async fn cleanup_registry(
        &self,
        registry: &mut ResourceRegistry,
    ) -> ProtocolCleanupReport {
        cleanup_registered_resources_with_external(
            registry,
            self.admin,
            self.s3,
            self.external_identity,
        )
        .await
    }
}

#[async_trait]
impl<A, S> ProtocolExecutionCleanup for ProtocolCleanupCoordinator<'_, A, S>
where
    A: ProtocolAdminCleanupPort + Sync,
    S: ProtocolS3CleanupPort + Sync,
{
    type RunState = ResourceRegistry;

    async fn cleanup_case_registry_if_present(&self, case_id: &str) -> ProtocolCleanupReport {
        let registry_path = self
            .artifact_root
            .join("cases")
            .join(case_id)
            .join(RESOURCE_REGISTRY_FILE);
        if !registry_path.is_file() {
            return ProtocolCleanupReport::empty(self.api_version);
        }
        match ResourceRegistry::load_path(&registry_path) {
            Ok(mut registry) => self.cleanup_registry(&mut registry).await,
            Err(error) => registry_failure(self.api_version, &registry_path, error),
        }
    }

    async fn cleanup_suite_registries(
        &self,
        cases: &[ProtocolSuitePlanCase],
        root_registry: &mut Self::RunState,
    ) -> ProtocolCleanupReport {
        let mut combined = ProtocolCleanupReport::empty(self.api_version);
        for case in cases {
            combined.append(self.cleanup_case_registry_if_present(&case.id).await);
        }
        combined.append(self.cleanup_registry(root_registry).await);
        combined
    }
}

pub(crate) fn registry_failure(
    api_version: &str,
    registry_path: &Path,
    error: impl std::fmt::Display,
) -> ProtocolCleanupReport {
    let resource = registry_path.display().to_string();
    ProtocolCleanupReport {
        api_version: api_version.to_string(),
        kind: "ProtocolCleanupReport".to_string(),
        attempts: vec![ProtocolCleanupAttempt {
            resource_id: format!("registry:{resource}"),
            resource_kind: "registry".to_string(),
            resource_name: resource.clone(),
            retry_count: 0,
            retry_history: Vec::new(),
            succeeded: false,
            error: Some(error.to_string()),
        }],
        leftovers: vec![format!("registry:{resource}")],
        succeeded: false,
    }
}

pub(crate) fn load_cleanup_registry(path: &Path) -> Result<ResourceRegistry> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect resource registry {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "resource registry must be a regular non-symlink file"
    );
    ResourceRegistry::load_path(path)
}

#[cfg(test)]
mod tests {
    use super::{ProtocolCleanupCoordinator, ProtocolExecutionCleanup};
    use crate::protocol::{
        fixture::registry::{
            RESOURCE_REGISTRY_FILE, ResourceKind, ResourceRegistry, ResourceState,
        },
        ports::{
            ExclusiveBucketOwnership, ProtocolAdminCleanupPort, ProtocolAdminError,
            ProtocolS3CleanupPort, ProtocolS3Error,
        },
        suite_plan::{ProtocolSuitePlanCase, TargetFingerprint},
    };
    use async_trait::async_trait;
    use std::{
        collections::BTreeSet,
        fs,
        sync::{Arc, Mutex},
    };

    #[derive(Clone, Default)]
    struct CleanupAdmin;

    #[async_trait]
    impl ProtocolAdminCleanupPort for CleanupAdmin {
        async fn users_with_prefix(
            &self,
            _prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
            Ok(Vec::new())
        }

        async fn remove_user(
            &self,
            _access_key: &str,
        ) -> std::result::Result<(), ProtocolAdminError> {
            Ok(())
        }

        async fn groups_with_prefix(
            &self,
            _prefix: &str,
        ) -> Result<Vec<String>, ProtocolAdminError> {
            Ok(Vec::new())
        }

        async fn group_contains_member(
            &self,
            _group: &str,
            _member: &str,
        ) -> Result<bool, ProtocolAdminError> {
            Ok(false)
        }

        async fn update_group_members(
            &self,
            _group: &str,
            _members: &[String],
            _remove: bool,
        ) -> Result<(), ProtocolAdminError> {
            Ok(())
        }

        async fn remove_group(&self, _group: &str) -> Result<(), ProtocolAdminError> {
            Ok(())
        }

        async fn policies_with_prefix(
            &self,
            _prefix: &str,
        ) -> Result<Vec<String>, ProtocolAdminError> {
            Ok(Vec::new())
        }

        async fn remove_policy(&self, _name: &str) -> Result<(), ProtocolAdminError> {
            Ok(())
        }

        async fn detach_policy(
            &self,
            _policy: &str,
            _principal: &str,
            _is_group: bool,
        ) -> Result<(), ProtocolAdminError> {
            Ok(())
        }

        async fn policy_attached(
            &self,
            _policy: &str,
            _principal: &str,
            _is_group: bool,
        ) -> Result<bool, ProtocolAdminError> {
            Ok(false)
        }

        async fn revoke_sts_sessions_for_provider(
            &self,
            _parent_access_key: &str,
            _provider: &str,
        ) -> Result<(), ProtocolAdminError> {
            Ok(())
        }

        async fn sts_sessions_with_parent_for_provider(
            &self,
            _parent_access_key: &str,
            _provider: &str,
        ) -> Result<Vec<String>, ProtocolAdminError> {
            Ok(Vec::new())
        }
    }

    #[derive(Clone, Default)]
    struct CleanupS3(Arc<Mutex<BTreeSet<String>>>);

    #[async_trait]
    impl ProtocolS3CleanupPort for CleanupS3 {
        async fn cleanup_bucket_names(
            &self,
            prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolS3Error> {
            Ok(self
                .0
                .lock()
                .expect("buckets")
                .iter()
                .filter(|name| name.starts_with(prefix))
                .cloned()
                .collect())
        }

        async fn cleanup_exclusive_bucket(
            &self,
            ownership: ExclusiveBucketOwnership<'_>,
            _include_versions: bool,
        ) -> Result<(), ProtocolS3Error> {
            self.0.lock().expect("buckets").remove(ownership.bucket());
            Ok(())
        }

        async fn cleanup_object_prefix(
            &self,
            _bucket: &str,
            _prefix: &str,
            _include_versions: bool,
        ) -> Result<(), ProtocolS3Error> {
            Ok(())
        }

        async fn cleanup_object_prefix_exists(
            &self,
            _bucket: &str,
            _prefix: &str,
            _include_versions: bool,
        ) -> Result<bool, ProtocolS3Error> {
            Ok(false)
        }

        async fn cleanup_abort_multipart_upload(
            &self,
            _bucket: &str,
            _key: &str,
            _upload_id: &str,
        ) -> Result<(), ProtocolS3Error> {
            Ok(())
        }

        async fn cleanup_multipart_upload_exists(
            &self,
            _bucket: &str,
            _key: &str,
            _upload_id: &str,
        ) -> Result<bool, ProtocolS3Error> {
            Ok(false)
        }

        async fn cleanup_delete_bucket_policy(&self, _bucket: &str) -> Result<(), ProtocolS3Error> {
            Ok(())
        }

        async fn cleanup_bucket_policy_exists(
            &self,
            _bucket: &str,
        ) -> Result<bool, ProtocolS3Error> {
            Ok(false)
        }

        async fn cleanup_delete_public_access_block(
            &self,
            _bucket: &str,
        ) -> Result<(), ProtocolS3Error> {
            Ok(())
        }

        async fn cleanup_public_access_block_exists(
            &self,
            _bucket: &str,
        ) -> Result<bool, ProtocolS3Error> {
            Ok(false)
        }
    }

    fn planned_case(id: &str) -> ProtocolSuitePlanCase {
        ProtocolSuitePlanCase {
            id: id.to_string(),
            domain: crate::protocol::catalog::ProtocolDomain::Other,
            group: "s3-compatibility".to_string(),
            tags: Vec::new(),
            requires: vec!["s3".to_string()],
            isolation: "case".to_string(),
            serial: false,
            worker_index: 0,
            wave_index: 0,
            locks: Vec::new(),
            artifact_dir: format!("cases/{id}"),
            contract: None,
        }
    }

    #[tokio::test]
    async fn corrupt_case_registry_does_not_skip_later_or_root_cleanup() {
        let base = tempfile::tempdir().expect("tempdir");
        let fingerprint = TargetFingerprint::new(
            "http://127.0.0.1:9000",
            "us-east-1",
            "deployment",
            None,
            None,
        )
        .expect("fingerprint");
        let corrupt_dir = base.path().join("cases/corrupt");
        fs::create_dir_all(&corrupt_dir).expect("corrupt case dir");
        fs::write(corrupt_dir.join(RESOURCE_REGISTRY_FILE), "not-json").expect("corrupt registry");

        let valid_dir = base.path().join("cases/valid");
        let mut valid = ResourceRegistry::create(&valid_dir, "run", fingerprint.clone())
            .expect("valid registry");
        let valid_bucket = valid
            .plan(ResourceKind::Bucket, "valid-bucket", "valid", Vec::new())
            .expect("valid bucket");
        valid
            .transition(&valid_bucket.id, ResourceState::Creating, None)
            .expect("creating");
        valid
            .transition(&valid_bucket.id, ResourceState::Created, None)
            .expect("created");

        let mut root =
            ResourceRegistry::create(base.path(), "run", fingerprint).expect("root registry");
        let root_bucket = root
            .plan(ResourceKind::Bucket, "root-bucket", "preflight", Vec::new())
            .expect("root bucket");
        root.transition(&root_bucket.id, ResourceState::Creating, None)
            .expect("creating");
        root.transition(&root_bucket.id, ResourceState::Created, None)
            .expect("created");

        let s3 = CleanupS3(Arc::new(Mutex::new(BTreeSet::from([
            "valid-bucket".to_string(),
            "root-bucket".to_string(),
        ]))));
        let coordinator = ProtocolCleanupCoordinator::new(
            base.path(),
            &CleanupAdmin,
            &s3,
            None,
            "rustfs.com/s3chaos/v1alpha1",
        );
        let report = coordinator
            .cleanup_suite_registries(&[planned_case("corrupt"), planned_case("valid")], &mut root)
            .await;

        assert!(!report.succeeded);
        assert!(
            report
                .attempts
                .iter()
                .any(|attempt| attempt.resource_kind == "registry")
        );
        assert!(s3.0.lock().expect("buckets").is_empty());
        assert!(root.pending_cleanup().next().is_none());
        assert!(base.path().exists(), "cleanup must preserve artifact root");
    }
}
