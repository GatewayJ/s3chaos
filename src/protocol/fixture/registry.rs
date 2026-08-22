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
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::protocol::{
    catalog::{
        ProtocolCleanupScope, ProtocolLockRequirement, ProtocolResourceOwnership, protocol_case,
        validate_protocol_case_descriptor,
    },
    ports::ProtocolExternalIdentityCoordinates,
    suite_plan::TargetFingerprint,
};

pub const RESOURCE_REGISTRY_FILE: &str = "resource-registry.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceState {
    Planned,
    Creating,
    Created,
    CleanupAttempted,
    Cleaned,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKind {
    Bucket,
    BucketPolicy,
    PublicAccessBlock,
    ExternalIdentitySubject,
    IamGroup,
    IamGroupMembership,
    IamPolicy,
    IamPolicyAttachment,
    IamUser,
    MultipartUpload,
    ObjectPrefix,
    StsSession,
}

impl ResourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bucket => "bucket",
            Self::BucketPolicy => "bucket-policy",
            Self::PublicAccessBlock => "public-access-block",
            Self::ExternalIdentitySubject => "external-identity-subject",
            Self::IamGroup => "iam-group",
            Self::IamGroupMembership => "iam-group-membership",
            Self::IamPolicy => "iam-policy",
            Self::IamPolicyAttachment => "iam-policy-attachment",
            Self::IamUser => "iam-user",
            Self::MultipartUpload => "multipart-upload",
            Self::ObjectPrefix => "object-prefix",
            Self::StsSession => "sts-session",
        }
    }

    fn cleanup_rank(self) -> usize {
        match self {
            Self::BucketPolicy
            | Self::PublicAccessBlock
            | Self::IamPolicyAttachment
            | Self::MultipartUpload => 0,
            Self::ObjectPrefix | Self::IamGroupMembership => 1,
            Self::IamPolicy => 2,
            Self::IamGroup | Self::ExternalIdentitySubject => 3,
            Self::StsSession => 4,
            Self::IamUser => 5,
            Self::Bucket => 6,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceHandle {
    pub id: String,
    pub kind: ResourceKind,
    pub name: String,
    pub owning_case_id: String,
    pub owner_phase: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership: Option<ProtocolResourceOwnership>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_scope: Option<ProtocolCleanupScope>,
    pub state: ResourceState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_group: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_identity: Option<ProtocolExternalIdentityCoordinates>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceRegistry {
    pub api_version: String,
    pub kind: String,
    pub run_id: String,
    pub target_fingerprint: TargetFingerprint,
    #[serde(default)]
    pub versioned_cleanup: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<ProtocolRegistryContract>,
    pub resources: Vec<ResourceHandle>,
    #[serde(skip)]
    path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolRegistryContract {
    pub case_id: String,
    pub variant_id: String,
    pub ownership: Vec<ProtocolResourceOwnership>,
    pub cleanup_scopes: Vec<ProtocolCleanupScope>,
    pub lock_requirements: Vec<ProtocolLockRequirement>,
}

struct ResourcePlan {
    kind: ResourceKind,
    name: String,
    owning_case_id: String,
    owner_phase: String,
    depends_on: Vec<String>,
    bucket: Option<String>,
    key_prefix: Option<String>,
    policy: Option<String>,
    principal: Option<String>,
    group: Option<String>,
    member: Option<String>,
    is_group: Option<bool>,
    identity_provider: Option<String>,
    external_identity: Option<ProtocolExternalIdentityCoordinates>,
    upload_id: Option<String>,
}

impl ResourceRegistry {
    pub fn create(
        artifact_root: impl AsRef<Path>,
        run_id: impl Into<String>,
        target_fingerprint: TargetFingerprint,
    ) -> Result<Self> {
        fs::create_dir_all(artifact_root.as_ref()).with_context(|| {
            format!(
                "create protocol artifact root {}",
                artifact_root.as_ref().display()
            )
        })?;
        let mut registry = Self {
            api_version: "rustfs.com/s3chaos/v1alpha1".to_string(),
            kind: "ProtocolResourceRegistry".to_string(),
            run_id: run_id.into(),
            target_fingerprint,
            versioned_cleanup: false,
            contract: None,
            resources: Vec::new(),
            path: artifact_root.as_ref().join(RESOURCE_REGISTRY_FILE),
        };
        registry.persist()?;
        Ok(registry)
    }

    pub fn load(artifact_root: impl AsRef<Path>) -> Result<Self> {
        Self::load_path(artifact_root.as_ref().join(RESOURCE_REGISTRY_FILE))
    }

    pub fn load_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("read resource registry {}", path.display()))?;
        let mut registry: Self = serde_json::from_str(&raw)
            .with_context(|| format!("parse resource registry {}", path.display()))?;
        registry.path = path;
        Ok(registry)
    }

    /// Binds a per-case registry to the descriptor that authorizes its dynamic resources.
    /// Existing unbound registries remain readable for preflight and artifact compatibility.
    pub fn bind_case(&mut self, case_id: &str, variant_id: &str) -> Result<()> {
        ensure!(
            self.resources.is_empty(),
            "resource registry must be bound before resources are planned"
        );
        let case = protocol_case(case_id)
            .with_context(|| format!("unknown protocol resource owner {case_id}"))?;
        validate_protocol_case_descriptor(case)?;
        ensure!(
            case.variant(variant_id).is_some(),
            "unknown protocol variant {variant_id} for case {case_id}"
        );
        let contract = ProtocolRegistryContract {
            case_id: case_id.to_string(),
            variant_id: variant_id.to_string(),
            ownership: case.ownership.to_vec(),
            cleanup_scopes: case.cleanup_scopes.to_vec(),
            lock_requirements: case.lock_requirements.to_vec(),
        };
        if let Some(existing) = &self.contract {
            ensure!(
                existing.case_id == contract.case_id && existing.variant_id == contract.variant_id,
                "resource registry is already bound to {}/{}",
                existing.case_id,
                existing.variant_id
            );
            return Ok(());
        }
        self.contract = Some(contract);
        if let Err(error) = self.persist() {
            self.contract = None;
            return Err(error);
        }
        Ok(())
    }

    pub fn set_versioned_cleanup(&mut self, enabled: bool) -> Result<()> {
        self.versioned_cleanup = enabled;
        self.persist()
    }

    pub fn plan(
        &mut self,
        kind: ResourceKind,
        name: impl Into<String>,
        owning_case_id: impl Into<String>,
        depends_on: Vec<String>,
    ) -> Result<ResourceHandle> {
        self.plan_for_phase(kind, name.into(), owning_case_id.into(), depends_on, "case")
    }

    pub fn plan_for_phase(
        &mut self,
        kind: ResourceKind,
        name: impl Into<String>,
        owning_case_id: impl Into<String>,
        depends_on: Vec<String>,
        owner_phase: impl Into<String>,
    ) -> Result<ResourceHandle> {
        self.plan_internal(ResourcePlan {
            kind,
            name: name.into(),
            owning_case_id: owning_case_id.into(),
            owner_phase: owner_phase.into(),
            depends_on,
            bucket: None,
            key_prefix: None,
            policy: None,
            principal: None,
            group: None,
            member: None,
            is_group: None,
            identity_provider: None,
            external_identity: None,
            upload_id: None,
        })
    }

    fn plan_internal(&mut self, plan: ResourcePlan) -> Result<ResourceHandle> {
        for dependency in &plan.depends_on {
            ensure!(
                self.resources
                    .iter()
                    .any(|resource| resource.id == *dependency),
                "resource plan references unknown dependency {dependency}"
            );
        }
        let (variant_id, ownership, cleanup_scope) =
            validate_dynamic_resource(self.contract.as_ref(), &plan)?;
        let handle = ResourceHandle {
            id: format!("resource-{}", Uuid::new_v4()),
            kind: plan.kind,
            name: plan.name,
            owning_case_id: plan.owning_case_id,
            owner_phase: plan.owner_phase,
            variant_id,
            ownership,
            cleanup_scope,
            state: ResourceState::Planned,
            depends_on: plan.depends_on,
            bucket: plan.bucket,
            key_prefix: plan.key_prefix,
            policy: plan.policy,
            principal: plan.principal,
            group: plan.group,
            member: plan.member,
            is_group: plan.is_group,
            identity_provider: plan.identity_provider,
            external_identity: plan.external_identity,
            upload_id: plan.upload_id,
            last_error: None,
        };
        ensure!(
            !self.resources.iter().any(|resource| {
                resource.kind == handle.kind
                    && resource.name == handle.name
                    && resource.state != ResourceState::Cleaned
            }),
            "active {:?} resource {} is already registered",
            handle.kind,
            handle.name
        );
        self.resources.push(handle.clone());
        if let Err(error) = self.persist() {
            self.resources.pop();
            return Err(error);
        }
        Ok(handle)
    }

    pub fn plan_object_prefix(
        &mut self,
        bucket: impl Into<String>,
        key_prefix: impl Into<String>,
        owning_case_id: impl Into<String>,
        depends_on: Vec<String>,
    ) -> Result<ResourceHandle> {
        let bucket = bucket.into();
        let key_prefix = key_prefix.into();
        self.plan_object_prefix_for_phase(bucket, key_prefix, owning_case_id, depends_on, "case")
    }

    pub fn plan_object_prefix_for_phase(
        &mut self,
        bucket: impl Into<String>,
        key_prefix: impl Into<String>,
        owning_case_id: impl Into<String>,
        depends_on: Vec<String>,
        owner_phase: impl Into<String>,
    ) -> Result<ResourceHandle> {
        let bucket = bucket.into();
        let key_prefix = key_prefix.into();
        self.plan_internal(ResourcePlan {
            kind: ResourceKind::ObjectPrefix,
            name: format!("{bucket}/{key_prefix}"),
            owning_case_id: owning_case_id.into(),
            owner_phase: owner_phase.into(),
            depends_on,
            bucket: Some(bucket),
            key_prefix: Some(key_prefix),
            policy: None,
            principal: None,
            group: None,
            member: None,
            is_group: None,
            identity_provider: None,
            external_identity: None,
            upload_id: None,
        })
    }

    pub fn plan_multipart_upload(
        &mut self,
        bucket: impl Into<String>,
        key: impl Into<String>,
        owning_case_id: impl Into<String>,
        depends_on: Vec<String>,
    ) -> Result<ResourceHandle> {
        let bucket = bucket.into();
        let key = key.into();
        self.plan_internal(ResourcePlan {
            kind: ResourceKind::MultipartUpload,
            name: format!("{bucket}/{key}"),
            owning_case_id: owning_case_id.into(),
            owner_phase: "case".to_string(),
            depends_on,
            bucket: Some(bucket),
            key_prefix: Some(key),
            policy: None,
            principal: None,
            group: None,
            member: None,
            is_group: None,
            identity_provider: None,
            external_identity: None,
            upload_id: None,
        })
    }

    pub fn set_multipart_upload_id(&mut self, resource_id: &str, upload_id: &str) -> Result<()> {
        ensure!(
            !upload_id.is_empty(),
            "multipart upload id must not be empty"
        );
        let resource = self
            .resources
            .iter_mut()
            .find(|resource| resource.id == resource_id)
            .with_context(|| format!("unknown resource handle {resource_id}"))?;
        ensure!(
            resource.kind == ResourceKind::MultipartUpload,
            "resource {resource_id} is not a multipart upload"
        );
        ensure!(
            resource.upload_id.is_none() || resource.upload_id.as_deref() == Some(upload_id),
            "multipart upload id is immutable once recorded"
        );
        let previous = resource.upload_id.replace(upload_id.to_string());
        if let Err(error) = self.persist() {
            let resource = self
                .resources
                .iter_mut()
                .find(|resource| resource.id == resource_id)
                .expect("resource remains present after persist failure");
            resource.upload_id = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn plan_policy_attachment(
        &mut self,
        policy: impl Into<String>,
        principal: impl Into<String>,
        is_group: bool,
        owning_case_id: impl Into<String>,
        depends_on: Vec<String>,
    ) -> Result<ResourceHandle> {
        self.plan_policy_attachment_for_phase(
            policy,
            principal,
            is_group,
            owning_case_id,
            depends_on,
            "case",
        )
    }

    pub fn plan_policy_attachment_for_phase(
        &mut self,
        policy: impl Into<String>,
        principal: impl Into<String>,
        is_group: bool,
        owning_case_id: impl Into<String>,
        depends_on: Vec<String>,
        owner_phase: impl Into<String>,
    ) -> Result<ResourceHandle> {
        let policy = policy.into();
        let principal = principal.into();
        self.plan_internal(ResourcePlan {
            kind: ResourceKind::IamPolicyAttachment,
            name: format!("{principal}/{policy}"),
            owning_case_id: owning_case_id.into(),
            owner_phase: owner_phase.into(),
            depends_on,
            bucket: None,
            key_prefix: None,
            policy: Some(policy),
            principal: Some(principal),
            group: None,
            member: None,
            is_group: Some(is_group),
            identity_provider: None,
            external_identity: None,
            upload_id: None,
        })
    }

    pub fn plan_group_membership(
        &mut self,
        group: impl Into<String>,
        member: impl Into<String>,
        owning_case_id: impl Into<String>,
        depends_on: Vec<String>,
    ) -> Result<ResourceHandle> {
        self.plan_group_membership_for_phase(group, member, owning_case_id, depends_on, "case")
    }

    pub fn plan_group_membership_for_phase(
        &mut self,
        group: impl Into<String>,
        member: impl Into<String>,
        owning_case_id: impl Into<String>,
        depends_on: Vec<String>,
        owner_phase: impl Into<String>,
    ) -> Result<ResourceHandle> {
        let group = group.into();
        let member = member.into();
        self.plan_internal(ResourcePlan {
            kind: ResourceKind::IamGroupMembership,
            name: format!("{group}/{member}"),
            owning_case_id: owning_case_id.into(),
            owner_phase: owner_phase.into(),
            depends_on,
            bucket: None,
            key_prefix: None,
            policy: None,
            principal: None,
            group: Some(group),
            member: Some(member),
            is_group: None,
            identity_provider: None,
            external_identity: None,
            upload_id: None,
        })
    }

    pub fn plan_sts_session(
        &mut self,
        parent_access_key: impl Into<String>,
        owning_case_id: impl Into<String>,
        depends_on: Vec<String>,
    ) -> Result<ResourceHandle> {
        self.plan_sts_session_for_provider_and_phase(
            parent_access_key,
            "builtin",
            owning_case_id,
            depends_on,
            "case",
        )
    }

    pub fn plan_sts_session_for_phase(
        &mut self,
        parent_access_key: impl Into<String>,
        owning_case_id: impl Into<String>,
        depends_on: Vec<String>,
        owner_phase: impl Into<String>,
    ) -> Result<ResourceHandle> {
        self.plan_sts_session_for_provider_and_phase(
            parent_access_key,
            "builtin",
            owning_case_id,
            depends_on,
            owner_phase,
        )
    }

    pub fn plan_sts_session_for_provider(
        &mut self,
        parent: impl Into<String>,
        provider: impl Into<String>,
        owning_case_id: impl Into<String>,
        depends_on: Vec<String>,
    ) -> Result<ResourceHandle> {
        self.plan_sts_session_for_provider_and_phase(
            parent,
            provider,
            owning_case_id,
            depends_on,
            "case",
        )
    }

    fn plan_sts_session_for_provider_and_phase(
        &mut self,
        parent_access_key: impl Into<String>,
        provider: impl Into<String>,
        owning_case_id: impl Into<String>,
        depends_on: Vec<String>,
        owner_phase: impl Into<String>,
    ) -> Result<ResourceHandle> {
        let parent_access_key = parent_access_key.into();
        let owning_case_id = owning_case_id.into();
        self.plan_internal(ResourcePlan {
            kind: ResourceKind::StsSession,
            name: format!("sts-session-{}", uuid::Uuid::new_v4()),
            owning_case_id,
            owner_phase: owner_phase.into(),
            depends_on,
            bucket: None,
            key_prefix: None,
            policy: None,
            principal: Some(parent_access_key),
            group: None,
            member: None,
            is_group: None,
            identity_provider: Some(provider.into()),
            external_identity: None,
            upload_id: None,
        })
    }

    pub fn plan_external_identity_subject(
        &mut self,
        username: impl Into<String>,
        external_identity: ProtocolExternalIdentityCoordinates,
        owning_case_id: impl Into<String>,
        depends_on: Vec<String>,
    ) -> Result<ResourceHandle> {
        self.plan_internal(ResourcePlan {
            kind: ResourceKind::ExternalIdentitySubject,
            name: username.into(),
            owning_case_id: owning_case_id.into(),
            owner_phase: "case".to_string(),
            depends_on,
            bucket: None,
            key_prefix: None,
            policy: None,
            principal: None,
            group: None,
            member: None,
            is_group: None,
            identity_provider: None,
            external_identity: Some(external_identity),
            upload_id: None,
        })
    }

    pub fn transition(
        &mut self,
        resource_id: &str,
        state: ResourceState,
        last_error: Option<String>,
    ) -> Result<()> {
        let resource = self
            .resources
            .iter_mut()
            .find(|resource| resource.id == resource_id)
            .with_context(|| format!("unknown resource handle {resource_id}"))?;
        ensure!(
            valid_transition(resource.state, state),
            "invalid resource transition {:?} -> {:?} for {resource_id}",
            resource.state,
            state
        );
        let previous_state = resource.state;
        let previous_error = resource.last_error.clone();
        resource.state = state;
        resource.last_error = last_error;
        if let Err(error) = self.persist() {
            let resource = self
                .resources
                .iter_mut()
                .find(|resource| resource.id == resource_id)
                .expect("resource remains present after persist failure");
            resource.state = previous_state;
            resource.last_error = previous_error;
            return Err(error);
        }
        Ok(())
    }

    pub fn pending_cleanup(&self) -> impl Iterator<Item = &ResourceHandle> {
        self.resources.iter().rev().filter(|resource| {
            matches!(
                resource.state,
                ResourceState::Planned
                    | ResourceState::Creating
                    | ResourceState::Created
                    | ResourceState::CleanupAttempted
                    | ResourceState::Failed
            )
        })
    }

    pub fn cleanup_order(&self) -> Result<Vec<ResourceHandle>> {
        let indexes = self
            .resources
            .iter()
            .enumerate()
            .map(|(index, resource)| (resource.id.as_str(), index))
            .collect::<HashMap<_, _>>();
        for resource in &self.resources {
            for dependency in &resource.depends_on {
                ensure!(
                    indexes.contains_key(dependency.as_str()),
                    "resource {} references unknown dependency {dependency}",
                    resource.id
                );
            }
        }

        let pending = self
            .pending_cleanup()
            .map(|resource| resource.id.as_str())
            .collect::<HashSet<_>>();
        let mut dependent_count = pending
            .iter()
            .map(|id| (*id, 0usize))
            .collect::<HashMap<_, _>>();
        for resource in self
            .resources
            .iter()
            .filter(|resource| pending.contains(resource.id.as_str()))
        {
            for dependency in &resource.depends_on {
                if let Some(count) = dependent_count.get_mut(dependency.as_str()) {
                    *count += 1;
                }
            }
        }

        let mut emitted = HashSet::new();
        let mut ordered = Vec::with_capacity(pending.len());
        while ordered.len() < pending.len() {
            let next = self
                .resources
                .iter()
                .enumerate()
                .filter(|(_, resource)| {
                    pending.contains(resource.id.as_str())
                        && !emitted.contains(resource.id.as_str())
                        && dependent_count
                            .get(resource.id.as_str())
                            .copied()
                            .unwrap_or_default()
                            == 0
                })
                .min_by_key(|(index, resource)| {
                    (resource.kind.cleanup_rank(), std::cmp::Reverse(*index))
                })
                .map(|(_, resource)| resource);
            let Some(resource) = next else {
                anyhow::bail!("resource dependency graph contains a cleanup cycle");
            };
            emitted.insert(resource.id.as_str());
            ordered.push(resource.clone());
            for dependency in &resource.depends_on {
                if let Some(count) = dependent_count.get_mut(dependency.as_str()) {
                    *count = count.saturating_sub(1);
                }
            }
        }
        Ok(ordered)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn persist(&mut self) -> Result<()> {
        let parent = self
            .path
            .parent()
            .context("resource registry path has no parent")?;
        fs::create_dir_all(parent)?;
        let temporary = parent.join(format!(".resource-registry-{}.tmp", Uuid::new_v4()));
        let bytes = serde_json::to_vec_pretty(self)?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .with_context(|| format!("create temporary registry {}", temporary.display()))?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, &self.path).with_context(|| {
            format!(
                "replace resource registry {} with {}",
                self.path.display(),
                temporary.display()
            )
        })?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

fn validate_dynamic_resource(
    contract: Option<&ProtocolRegistryContract>,
    plan: &ResourcePlan,
) -> Result<(
    Option<String>,
    Option<ProtocolResourceOwnership>,
    Option<ProtocolCleanupScope>,
)> {
    let Some(contract) = contract else {
        return Ok((None, None, None));
    };
    ensure!(
        plan.owning_case_id == contract.case_id,
        "resource owner {} exceeds registry owner {}",
        plan.owning_case_id,
        contract.case_id
    );
    let (ownership, cleanup_scope) = match plan.kind {
        ResourceKind::Bucket => (
            ProtocolResourceOwnership::ExclusiveBucket,
            ProtocolCleanupScope::OwnedBucket,
        ),
        ResourceKind::BucketPolicy => (
            ProtocolResourceOwnership::ExclusiveBucket,
            ProtocolCleanupScope::BucketPolicy,
        ),
        ResourceKind::PublicAccessBlock => (
            ProtocolResourceOwnership::ExclusiveBucket,
            ProtocolCleanupScope::BucketConfiguration,
        ),
        ResourceKind::ObjectPrefix => (
            if contract
                .ownership
                .contains(&ProtocolResourceOwnership::ExclusiveBucket)
            {
                ProtocolResourceOwnership::ExclusiveBucket
            } else {
                ProtocolResourceOwnership::SharedBucketPrefix
            },
            ProtocolCleanupScope::ObjectPrefix,
        ),
        ResourceKind::MultipartUpload => (
            if contract
                .ownership
                .contains(&ProtocolResourceOwnership::ExactMultipartUpload)
            {
                ProtocolResourceOwnership::ExactMultipartUpload
            } else if contract
                .ownership
                .contains(&ProtocolResourceOwnership::ExclusiveBucket)
            {
                ProtocolResourceOwnership::ExclusiveBucket
            } else if contract
                .ownership
                .contains(&ProtocolResourceOwnership::SharedBucketKey)
            {
                ProtocolResourceOwnership::SharedBucketKey
            } else {
                ProtocolResourceOwnership::SharedBucketPrefix
            },
            ProtocolCleanupScope::MultipartUpload,
        ),
        ResourceKind::ExternalIdentitySubject => (
            ProtocolResourceOwnership::ExternalIdentity,
            ProtocolCleanupScope::ExternalIdentity,
        ),
        ResourceKind::StsSession => (
            ProtocolResourceOwnership::IdentityPrefix,
            ProtocolCleanupScope::StsSession,
        ),
        ResourceKind::IamGroup
        | ResourceKind::IamGroupMembership
        | ResourceKind::IamPolicy
        | ResourceKind::IamPolicyAttachment
        | ResourceKind::IamUser => (
            ProtocolResourceOwnership::IdentityPrefix,
            ProtocolCleanupScope::Identity,
        ),
    };
    ensure!(
        contract.ownership.contains(&ownership),
        "resource {:?} exceeds case {} ownership {:?}",
        plan.kind,
        contract.case_id,
        contract.ownership
    );
    ensure!(
        contract.cleanup_scopes.contains(&cleanup_scope),
        "resource {:?} cleanup {:?} exceeds case {} contract",
        plan.kind,
        cleanup_scope,
        contract.case_id
    );
    Ok((
        Some(contract.variant_id.clone()),
        Some(ownership),
        Some(cleanup_scope),
    ))
}

fn valid_transition(from: ResourceState, to: ResourceState) -> bool {
    matches!(
        (from, to),
        (ResourceState::Planned, ResourceState::Creating)
            | (ResourceState::Planned, ResourceState::CleanupAttempted)
            | (ResourceState::Creating, ResourceState::Created)
            | (ResourceState::Creating, ResourceState::Failed)
            | (ResourceState::Creating, ResourceState::CleanupAttempted)
            | (ResourceState::Created, ResourceState::CleanupAttempted)
            | (ResourceState::Failed, ResourceState::CleanupAttempted)
            | (ResourceState::CleanupAttempted, ResourceState::Cleaned)
            | (ResourceState::CleanupAttempted, ResourceState::Failed)
            | (ResourceState::Failed, ResourceState::Creating)
    )
}

#[cfg(test)]
mod tests {
    use super::{ResourceKind, ResourceRegistry, ResourceState};
    use crate::protocol::{
        catalog::{
            COMPAT_OBJECT_PUT_GET_DELETE, ProtocolCleanupScope, ProtocolLockResource,
            ProtocolResourceOwnership,
        },
        suite_plan::TargetFingerprint,
    };

    fn fingerprint() -> TargetFingerprint {
        TargetFingerprint::new(
            "http://127.0.0.1:9000",
            "us-east-1",
            "deployment",
            None,
            None,
        )
        .expect("fingerprint")
    }

    #[test]
    fn every_transition_is_immediately_replayable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint()).expect("registry");
        let handle = registry
            .plan(ResourceKind::Bucket, "bucket", "case", Vec::new())
            .expect("planned");
        registry
            .transition(&handle.id, ResourceState::Creating, None)
            .expect("creating");
        registry
            .transition(&handle.id, ResourceState::Created, None)
            .expect("created");

        let reloaded = ResourceRegistry::load(dir.path()).expect("reloaded");
        assert_eq!(reloaded.resources[0].state, ResourceState::Created);
        assert_eq!(reloaded.pending_cleanup().count(), 1);
    }

    #[test]
    fn rejects_invalid_transition() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint()).expect("registry");
        let handle = registry
            .plan(ResourceKind::IamUser, "user", "case", Vec::new())
            .expect("planned");
        assert!(
            registry
                .transition(&handle.id, ResourceState::Created, None)
                .is_err()
        );
    }

    #[test]
    fn creating_resource_can_enter_replay_cleanup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint()).expect("registry");
        let handle = registry
            .plan(ResourceKind::Bucket, "bucket", "case", Vec::new())
            .expect("planned");
        registry
            .transition(&handle.id, ResourceState::Creating, None)
            .expect("creating");
        registry
            .transition(&handle.id, ResourceState::CleanupAttempted, None)
            .expect("cleanup attempted");
        registry
            .transition(&handle.id, ResourceState::Cleaned, None)
            .expect("cleaned");
    }

    #[test]
    fn object_prefix_is_persisted_with_cleanup_coordinates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint()).expect("registry");
        registry
            .plan_object_prefix("bucket", "cases/case/", "case", Vec::new())
            .expect("object prefix");

        let reloaded = ResourceRegistry::load(dir.path()).expect("reloaded");
        assert_eq!(reloaded.resources[0].bucket.as_deref(), Some("bucket"));
        assert_eq!(
            reloaded.resources[0].key_prefix.as_deref(),
            Some("cases/case/")
        );
    }

    #[test]
    fn cleanup_order_respects_dependencies_and_kind_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint()).expect("registry");
        let user = registry
            .plan(ResourceKind::IamUser, "user", "case", Vec::new())
            .expect("user");
        let bucket = registry
            .plan(ResourceKind::Bucket, "bucket", "case", Vec::new())
            .expect("bucket");
        registry
            .plan(
                ResourceKind::BucketPolicy,
                "bucket",
                "case",
                vec![bucket.id.clone(), user.id.clone()],
            )
            .expect("policy");
        registry
            .plan_object_prefix("bucket", "cases/case/", "case", vec![bucket.id])
            .expect("objects");

        let order = registry
            .cleanup_order()
            .expect("cleanup order")
            .into_iter()
            .map(|resource| resource.kind)
            .collect::<Vec<_>>();
        assert_eq!(
            order,
            vec![
                ResourceKind::BucketPolicy,
                ResourceKind::ObjectPrefix,
                ResourceKind::IamUser,
                ResourceKind::Bucket,
            ]
        );
    }

    #[test]
    fn cleanup_order_rejects_dependency_cycles() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint()).expect("registry");
        let handle = registry
            .plan(ResourceKind::Bucket, "bucket", "case", Vec::new())
            .expect("bucket");
        registry.resources[0].depends_on = vec![handle.id];
        assert!(registry.cleanup_order().is_err());
    }

    #[test]
    fn bound_registry_persists_descriptor_and_rejects_out_of_scope_resource() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint()).expect("registry");
        registry
            .bind_case(COMPAT_OBJECT_PUT_GET_DELETE, "default")
            .expect("bind case");
        let bucket = registry
            .plan(
                ResourceKind::Bucket,
                "bucket",
                COMPAT_OBJECT_PUT_GET_DELETE,
                Vec::new(),
            )
            .expect("bucket");
        let objects = registry
            .plan_object_prefix(
                "bucket",
                "cases/compat-object-put-get-delete/",
                COMPAT_OBJECT_PUT_GET_DELETE,
                vec![bucket.id],
            )
            .expect("objects");
        assert_eq!(
            objects.ownership,
            Some(ProtocolResourceOwnership::ExclusiveBucket)
        );
        assert_eq!(
            objects.cleanup_scope,
            Some(ProtocolCleanupScope::ObjectPrefix)
        );
        assert!(
            registry
                .plan(
                    ResourceKind::IamUser,
                    "foreign-user",
                    COMPAT_OBJECT_PUT_GET_DELETE,
                    Vec::new(),
                )
                .is_err()
        );

        let reloaded = ResourceRegistry::load(dir.path()).expect("reloaded");
        let contract = reloaded.contract.expect("bound contract");
        assert_eq!(contract.case_id, COMPAT_OBJECT_PUT_GET_DELETE);
        assert_eq!(contract.variant_id, "default");
        assert!(
            contract
                .ownership
                .contains(&ProtocolResourceOwnership::ExclusiveBucket)
        );
        assert!(
            contract
                .lock_requirements
                .iter()
                .any(|lock| lock.resource == ProtocolLockResource::Bucket)
        );
    }

    #[test]
    fn registry_rejects_unknown_case_variant_and_cross_case_owner() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint()).expect("registry");
        assert!(registry.bind_case("unknown-case", "default").is_err());
        assert!(
            registry
                .bind_case(COMPAT_OBJECT_PUT_GET_DELETE, "unknown-variant")
                .is_err()
        );
        registry
            .bind_case(COMPAT_OBJECT_PUT_GET_DELETE, "default")
            .expect("bind case");
        assert!(
            registry
                .plan(ResourceKind::Bucket, "bucket", "foreign-case", Vec::new())
                .is_err()
        );
    }
}
