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

//! Cases that attach RustFS built-in canned policies to a harness user and pin down the
//! DeleteObject authorization surface the Console depends on (rustfs/rustfs#7649).

use anyhow::{Result, anyhow, bail, ensure};

use crate::protocol::{
    authorization::{
        ProtocolActorSource, ProtocolAuthorizationDimensions, ProtocolGrantSource,
        ProtocolPolicyEffect,
    },
    cases::{
        CaseContext, ProtocolCaseExecution,
        authz::{
            ExpectationFailure, expect_access_denied, expect_eventual_access_denied,
            expect_eventual_ok, expect_ok,
        },
        iam::clean_attachment,
    },
    catalog::{
        DELETE_FORCE_HEADER_CONTRACT, IAM_CANNED_POLICY_CONSOLE_ADMIN_DELETE,
        IAM_CANNED_POLICY_MATRIX,
    },
    fixture::{
        naming::ProtocolResourceNamer,
        registry::{ResourceHandle, ResourceRegistry, ResourceState},
        resources::{IamFixture, enable_versioned_cleanup, setup_user_bucket, transition_external},
    },
    ports::{
        ActorS3ClientFactory, ProtocolBucketPort, ProtocolIdentityAdminPort, ProtocolListingPort,
        ProtocolObjectPort, ProtocolPolicyAdminPort, ProtocolRequestShape, ProtocolVersioningPort,
    },
    reporting::ProtocolAssertionClass,
    suite::{ForceDeleteHeaderSingleObjectContract, ProtocolSuiteContracts},
};

/// Header the RustFS Console sends on every DeleteObject. `x-minio-force-delete` is an accepted
/// alias on the server (`crates/utils/src/http/header_compat.rs`); the Console form is asserted.
pub(crate) const FORCE_DELETE_HEADER: &str = "x-rustfs-force-delete";

/// RustFS built-in canned policies (`crates/policy/src/policy/policy.rs`, `DEFAULT_POLICIES`).
/// `diagnostics` grants admin actions only and no S3 action, so it has no cell in the matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CannedPolicy {
    ConsoleAdmin,
    ReadWrite,
    WriteOnly,
    ReadOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum MatrixOperation {
    PutObject,
    GetObject,
    DeleteObject,
    DeleteObjects,
    DeleteObjectVersion,
}

impl MatrixOperation {
    pub(crate) const ALL: [Self; 5] = [
        Self::PutObject,
        Self::GetObject,
        Self::DeleteObject,
        Self::DeleteObjects,
        Self::DeleteObjectVersion,
    ];

    /// Prefix of the recorded assertion operation. `delete-objects` must stay distinct from
    /// `delete-` so the exchange summary maps it to POST.
    fn label(self) -> &'static str {
        match self {
            Self::PutObject => "put-object",
            Self::GetObject => "get-object",
            Self::DeleteObject => "delete-object",
            Self::DeleteObjects => "delete-objects",
            Self::DeleteObjectVersion => "delete-object-version",
        }
    }
}

impl CannedPolicy {
    pub(crate) const ALL: [Self; 4] = [
        Self::ConsoleAdmin,
        Self::ReadWrite,
        Self::WriteOnly,
        Self::ReadOnly,
    ];

    /// Exact server-side policy name used with the admin policy attach API.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::ConsoleAdmin => "consoleAdmin",
            Self::ReadWrite => "readwrite",
            Self::WriteOnly => "writeonly",
            Self::ReadOnly => "readonly",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::ConsoleAdmin => "console-admin",
            Self::ReadWrite => "readwrite",
            Self::WriteOnly => "writeonly",
            Self::ReadOnly => "readonly",
        }
    }

    /// Expectation table. Evidence, all from `DEFAULT_POLICIES`:
    /// `consoleAdmin` and `readwrite` grant `s3:*` on `arn:aws:s3:::*`; `writeonly` grants only
    /// `s3:PutObject`; `readonly` grants `s3:GetBucketLocation`, `s3:GetObject`, and
    /// `s3:GetBucketQuota`. A versioned delete additionally requires `s3:DeleteObjectVersion`
    /// (`rustfs/src/storage/access.rs`), which only the `s3:*` policies carry.
    pub(crate) fn allows(self, operation: MatrixOperation) -> bool {
        match self {
            Self::ConsoleAdmin | Self::ReadWrite => true,
            Self::WriteOnly => operation == MatrixOperation::PutObject,
            Self::ReadOnly => operation == MatrixOperation::GetObject,
        }
    }

    /// Operation this policy allows, used to prove attach and detach propagation before the
    /// single-shot cells are asserted.
    fn propagation_probe(self) -> MatrixOperation {
        match self {
            Self::ReadOnly => MatrixOperation::GetObject,
            Self::ConsoleAdmin | Self::ReadWrite | Self::WriteOnly => MatrixOperation::PutObject,
        }
    }
}

fn canned_policy_dimensions() -> ProtocolAuthorizationDimensions {
    ProtocolAuthorizationDimensions {
        actor_source: ProtocolActorSource::IamUser,
        grant_source: ProtocolGrantSource::ManagedPolicy,
        policy_effect: ProtocolPolicyEffect::Allow,
    }
}

fn admin_dimensions() -> ProtocolAuthorizationDimensions {
    ProtocolAuthorizationDimensions {
        actor_source: ProtocolActorSource::Admin,
        grant_source: ProtocolGrantSource::AdminCredential,
        policy_effect: ProtocolPolicyEffect::Allow,
    }
}

pub(crate) async fn run_canned_policy_case<F>(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &(impl ProtocolIdentityAdminPort + ProtocolPolicyAdminPort),
    admin_s3: &(
         impl ProtocolBucketPort + ProtocolObjectPort + ProtocolListingPort + ProtocolVersioningPort
     ),
    actor_clients: &F,
    contracts: ProtocolSuiteContracts,
) -> ProtocolCaseExecution
where
    F: ActorS3ClientFactory,
    F::Client: ProtocolVersioningPort,
{
    let mut context = CaseContext::new(case_id, canned_policy_dimensions());
    let result = match case_id {
        IAM_CANNED_POLICY_MATRIX => {
            run_matrix(
                namer,
                registry,
                admin,
                admin_s3,
                actor_clients,
                &mut context,
            )
            .await
        }
        IAM_CANNED_POLICY_CONSOLE_ADMIN_DELETE => {
            run_console_admin_delete(
                namer,
                registry,
                admin,
                admin_s3,
                actor_clients,
                &mut context,
            )
            .await
        }
        DELETE_FORCE_HEADER_CONTRACT => {
            run_force_header_contract(
                namer,
                registry,
                admin,
                admin_s3,
                actor_clients,
                contracts.force_delete_header_single_object,
                &mut context,
            )
            .await
        }
        _ => Err(anyhow!("unsupported canned policy case {case_id}")),
    };
    context.finish(result)
}

/// Registers and performs the attachment of a built-in policy. Only the attachment is owned by
/// the registry; the policy itself is server-provided and must never be removed.
async fn attach_canned_policy(
    case_id: &str,
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolPolicyAdminPort,
    policy: CannedPolicy,
    fixture: &IamFixture<impl Send + Sync>,
) -> Result<ResourceHandle> {
    let attachment = registry.plan_policy_attachment(
        policy.name(),
        &fixture.user,
        false,
        case_id,
        vec![fixture.user_handle_id.clone()],
    )?;
    transition_external(
        registry,
        &attachment,
        "attach canned policy",
        admin.attach_policy(policy.name(), &fixture.user, false),
    )
    .await?;
    Ok(attachment)
}

async fn seed_object(
    admin_s3: &impl ProtocolObjectPort,
    bucket: &str,
    key: &str,
    body: &[u8],
) -> Result<()> {
    admin_s3
        .put_object(bucket, key, body)
        .await
        .map_err(|error| anyhow!("seed object {key} failed: {error}"))
}

async fn admin_keys(admin_s3: &impl ProtocolListingPort, bucket: &str) -> Result<Vec<String>> {
    admin_s3
        .list_objects(bucket)
        .await
        .map_err(|error| anyhow!("administrative object listing failed: {error}"))
}

async fn ensure_key_presence(
    admin_s3: &impl ProtocolListingPort,
    bucket: &str,
    key: &str,
    present: bool,
    operation: &str,
) -> Result<()> {
    let listed = admin_keys(admin_s3, bucket).await?;
    let is_present = listed.iter().any(|candidate| candidate == key);
    ensure!(
        is_present == present,
        "{operation}: object {key} is {} after the operation",
        if is_present {
            "still listed"
        } else {
            "no longer listed"
        }
    );
    Ok(())
}

async fn ensure_keys_present(
    admin_s3: &impl ProtocolListingPort,
    bucket: &str,
    keys: &[&str],
    operation: &str,
) -> Result<()> {
    let listed = admin_keys(admin_s3, bucket).await?;
    let missing = keys
        .iter()
        .filter(|key| !listed.iter().any(|listed| listed == *key))
        .collect::<Vec<_>>();
    ensure!(
        missing.is_empty(),
        "{operation}: objects {missing:?} outside the targeted key were removed"
    );
    Ok(())
}

async fn single_version_id(
    admin_s3: &impl ProtocolVersioningPort,
    bucket: &str,
    key: &str,
) -> Result<String> {
    let mut versions = admin_s3
        .list_object_versions(bucket)
        .await
        .map_err(|error| anyhow!("administrative version listing failed: {error}"))?
        .into_iter()
        .filter(|version| version.key == key && !version.delete_marker)
        .map(|version| version.version_id);
    let version_id = versions
        .next()
        .ok_or_else(|| anyhow!("seeded object {key} has no listed version"))?;
    ensure!(
        versions.next().is_none(),
        "seeded object {key} unexpectedly has multiple versions"
    );
    Ok(version_id)
}

async fn version_exists(
    admin_s3: &impl ProtocolVersioningPort,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> Result<bool> {
    Ok(admin_s3
        .list_object_versions(bucket)
        .await
        .map_err(|error| anyhow!("administrative version listing failed: {error}"))?
        .iter()
        .any(|version| version.key == key && version.version_id == version_id))
}

struct MatrixKeys {
    probe: String,
    seed: String,
    put: String,
    delete_single: String,
    delete_batch: Vec<String>,
    delete_version: String,
    after_detach: String,
}

impl MatrixKeys {
    fn new(prefix: &str, policy: CannedPolicy) -> Self {
        let label = policy.label();
        Self {
            probe: format!("{prefix}{label}/probe"),
            seed: format!("{prefix}{label}/seed"),
            put: format!("{prefix}{label}/put"),
            delete_single: format!("{prefix}{label}/delete-single"),
            delete_batch: vec![
                format!("{prefix}{label}/delete-batch-1"),
                format!("{prefix}{label}/delete-batch-2"),
            ],
            delete_version: format!("{prefix}{label}/delete-version"),
            after_detach: format!("{prefix}{label}/after-detach"),
        }
    }
}

async fn run_matrix<F>(
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &(impl ProtocolIdentityAdminPort + ProtocolPolicyAdminPort),
    admin_s3: &(
         impl ProtocolBucketPort + ProtocolObjectPort + ProtocolListingPort + ProtocolVersioningPort
     ),
    actor_clients: &F,
    context: &mut CaseContext,
) -> Result<()>
where
    F: ActorS3ClientFactory,
    F::Client: ProtocolVersioningPort,
{
    let case_id = IAM_CANNED_POLICY_MATRIX;
    enable_versioned_cleanup(registry)?;
    let fixture =
        setup_user_bucket(case_id, namer, registry, admin, admin_s3, actor_clients).await?;
    context.add_actor(fixture.actor.clone());
    let bucket = fixture.bucket.clone();
    admin_s3
        .put_bucket_versioning(&bucket, true)
        .await
        .map_err(|error| anyhow!("enable bucket versioning failed: {error}"))?;
    let prefix = format!("cases/{case_id}/");
    let objects = registry.plan_object_prefix(
        &bucket,
        &prefix,
        case_id,
        vec![fixture.bucket_handle_id.clone()],
    )?;
    registry.transition(&objects.id, ResourceState::Creating, None)?;

    for (index, policy) in CannedPolicy::ALL.into_iter().enumerate() {
        let keys = MatrixKeys::new(&prefix, policy);
        context.current_phase = "setup".to_string();
        seed_object(admin_s3, &bucket, &keys.seed, b"seed").await?;
        seed_object(admin_s3, &bucket, &keys.delete_single, b"delete-single").await?;
        for key in &keys.delete_batch {
            seed_object(admin_s3, &bucket, key, b"delete-batch").await?;
        }
        seed_object(admin_s3, &bucket, &keys.delete_version, b"delete-version").await?;
        if index == 0 {
            // Objects now exist under the prefix, so a later failure must not leave the prefix
            // in `Creating` and make cleanup wait for it to settle.
            registry.transition(&objects.id, ResourceState::Created, None)?;
        }
        let version_id = single_version_id(admin_s3, &bucket, &keys.delete_version).await?;
        let attachment = attach_canned_policy(case_id, registry, admin, policy, &fixture).await?;

        context.current_phase = "propagation".to_string();
        propagation_probe(context, &fixture, &bucket, &keys, policy, true).await?;

        context.current_phase = "assertion".to_string();
        for operation in MatrixOperation::ALL {
            assert_matrix_cell(
                context,
                &fixture,
                admin_s3,
                &bucket,
                &keys,
                policy,
                operation,
                &version_id,
            )
            .await?;
        }

        context.current_phase = "cleanup".to_string();
        clean_attachment(
            registry,
            admin,
            &attachment,
            policy.name(),
            &fixture.user,
            false,
        )
        .await?;
        context.current_phase = "propagation".to_string();
        propagation_probe(context, &fixture, &bucket, &keys, policy, false).await?;
    }
    Ok(())
}

/// Proves the current grant state for `policy` has propagated: after attach, its allowed probe
/// operation must succeed; after detach, the same operation must be denied again. Without this
/// barrier a stale grant from the previous policy could leak into the next policy's cells.
async fn propagation_probe<C>(
    context: &mut CaseContext,
    fixture: &IamFixture<C>,
    bucket: &str,
    keys: &MatrixKeys,
    policy: CannedPolicy,
    attached: bool,
) -> Result<()>
where
    C: ProtocolObjectPort,
{
    let label = policy.label();
    match (policy.propagation_probe(), attached) {
        (MatrixOperation::GetObject, true) => {
            expect_eventual_ok(
                context,
                "iam-user",
                &format!("get-object-probe-after-attach-{label}"),
                bucket,
                Some(&keys.seed),
                || async {
                    fixture
                        .actor_s3
                        .get_object(bucket, &keys.seed)
                        .await
                        .map(|_| ())
                },
            )
            .await
        }
        (MatrixOperation::GetObject, false) => {
            expect_eventual_access_denied(
                context,
                "iam-user",
                &format!("get-object-probe-after-detach-{label}"),
                bucket,
                Some(&keys.seed),
                || async { fixture.actor_s3.get_object(bucket, &keys.seed).await },
            )
            .await
        }
        (_, true) => {
            expect_eventual_ok(
                context,
                "iam-user",
                &format!("put-object-probe-after-attach-{label}"),
                bucket,
                Some(&keys.probe),
                || async {
                    fixture
                        .actor_s3
                        .put_object(bucket, &keys.probe, b"probe")
                        .await
                },
            )
            .await
        }
        (_, false) => {
            expect_eventual_access_denied(
                context,
                "iam-user",
                &format!("put-object-probe-after-detach-{label}"),
                bucket,
                Some(&keys.after_detach),
                || async {
                    fixture
                        .actor_s3
                        .put_object(bucket, &keys.after_detach, b"after-detach")
                        .await
                },
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn assert_matrix_cell<C>(
    context: &mut CaseContext,
    fixture: &IamFixture<C>,
    admin_s3: &(impl ProtocolListingPort + ProtocolVersioningPort),
    bucket: &str,
    keys: &MatrixKeys,
    policy: CannedPolicy,
    operation: MatrixOperation,
    version_id: &str,
) -> Result<()>
where
    C: ProtocolObjectPort + ProtocolVersioningPort,
{
    let allowed = policy.allows(operation);
    let name = format!("{}-with-{}", operation.label(), policy.label());
    let actor = &fixture.actor_s3;
    match operation {
        MatrixOperation::PutObject => {
            if allowed {
                expect_ok(
                    context,
                    "iam-user",
                    &name,
                    bucket,
                    Some(&keys.put),
                    || async { actor.put_object(bucket, &keys.put, b"put").await },
                )
                .await?;
            } else {
                expect_access_denied(
                    context,
                    "iam-user",
                    &name,
                    bucket,
                    Some(&keys.put),
                    || async { actor.put_object(bucket, &keys.put, b"put").await },
                )
                .await?;
            }
            ensure_key_presence(admin_s3, bucket, &keys.put, allowed, &name).await
        }
        MatrixOperation::GetObject => {
            if allowed {
                let body = expect_ok(
                    context,
                    "iam-user",
                    &name,
                    bucket,
                    Some(&keys.seed),
                    || async { actor.get_object(bucket, &keys.seed).await },
                )
                .await?;
                ensure!(body == b"seed", "{name}: returned an unexpected body");
                Ok(())
            } else {
                expect_access_denied(
                    context,
                    "iam-user",
                    &name,
                    bucket,
                    Some(&keys.seed),
                    || async { actor.get_object(bucket, &keys.seed).await },
                )
                .await
            }
        }
        MatrixOperation::DeleteObject => {
            let key = &keys.delete_single;
            if allowed {
                expect_ok(context, "iam-user", &name, bucket, Some(key), || async {
                    actor.delete_object(bucket, key).await
                })
                .await?;
            } else {
                expect_access_denied(context, "iam-user", &name, bucket, Some(key), || async {
                    actor.delete_object(bucket, key).await
                })
                .await?;
            }
            ensure_key_presence(admin_s3, bucket, key, !allowed, &name).await
        }
        MatrixOperation::DeleteObjects => {
            let batch = &keys.delete_batch;
            if allowed {
                let mut deleted = expect_ok(context, "iam-user", &name, bucket, None, || async {
                    actor.delete_objects(bucket, batch).await
                })
                .await?;
                deleted.sort();
                ensure!(
                    deleted == *batch,
                    "{name}: DeleteObjects reported {deleted:?} instead of {batch:?}"
                );
            } else {
                expect_access_denied(context, "iam-user", &name, bucket, None, || async {
                    actor.delete_objects(bucket, batch).await
                })
                .await?;
            }
            for key in batch {
                ensure_key_presence(admin_s3, bucket, key, !allowed, &name).await?;
            }
            Ok(())
        }
        MatrixOperation::DeleteObjectVersion => {
            let key = &keys.delete_version;
            if allowed {
                expect_ok(context, "iam-user", &name, bucket, Some(key), || async {
                    actor.delete_object_version(bucket, key, version_id).await
                })
                .await?;
            } else {
                expect_access_denied(context, "iam-user", &name, bucket, Some(key), || async {
                    actor.delete_object_version(bucket, key, version_id).await
                })
                .await?;
            }
            let exists = version_exists(admin_s3, bucket, key, version_id).await?;
            ensure!(
                exists != allowed,
                "{name}: version {version_id} of {key} is {} after the operation",
                if exists { "still listed" } else { "gone" }
            );
            Ok(())
        }
    }
}

async fn run_console_admin_delete<F>(
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &(impl ProtocolIdentityAdminPort + ProtocolPolicyAdminPort),
    admin_s3: &(impl ProtocolBucketPort + ProtocolListingPort),
    actor_clients: &F,
    context: &mut CaseContext,
) -> Result<()>
where
    F: ActorS3ClientFactory,
{
    let case_id = IAM_CANNED_POLICY_CONSOLE_ADMIN_DELETE;
    let fixture =
        setup_user_bucket(case_id, namer, registry, admin, admin_s3, actor_clients).await?;
    context.add_actor(fixture.actor.clone());
    let bucket = fixture.bucket.clone();
    let objects = registry.plan_object_prefix(
        &bucket,
        format!("cases/{case_id}/"),
        case_id,
        vec![fixture.bucket_handle_id.clone()],
    )?;
    registry.transition(&objects.id, ResourceState::Creating, None)?;
    attach_canned_policy(
        case_id,
        registry,
        admin,
        CannedPolicy::ConsoleAdmin,
        &fixture,
    )
    .await?;
    let key = format!("cases/{case_id}/object");
    context.current_phase = "propagation".to_string();
    expect_eventual_ok(
        context,
        "iam-user",
        "put-object-with-console-admin",
        &bucket,
        Some(&key),
        || async {
            fixture
                .actor_s3
                .put_object(&bucket, &key, b"console-admin")
                .await
        },
    )
    .await?;
    registry.transition(&objects.id, ResourceState::Created, None)?;
    context.current_phase = "assertion".to_string();
    expect_ok(
        context,
        "iam-user",
        "delete-object-with-console-admin",
        &bucket,
        Some(&key),
        || async { fixture.actor_s3.delete_object(&bucket, &key).await },
    )
    .await?;
    ensure_key_presence(
        admin_s3,
        &bucket,
        &key,
        false,
        "delete-object-with-console-admin",
    )
    .await
}

async fn run_force_header_contract<F>(
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &(impl ProtocolIdentityAdminPort + ProtocolPolicyAdminPort),
    admin_s3: &(impl ProtocolBucketPort + ProtocolObjectPort + ProtocolListingPort),
    actor_clients: &F,
    contract: ForceDeleteHeaderSingleObjectContract,
    context: &mut CaseContext,
) -> Result<()>
where
    F: ActorS3ClientFactory,
{
    let case_id = DELETE_FORCE_HEADER_CONTRACT;
    let fixture =
        setup_user_bucket(case_id, namer, registry, admin, admin_s3, actor_clients).await?;
    context.add_actor(fixture.actor.clone());
    let bucket = fixture.bucket.clone();
    let prefix = format!("cases/{case_id}/");
    let objects = registry.plan_object_prefix(
        &bucket,
        &prefix,
        case_id,
        vec![fixture.bucket_handle_id.clone()],
    )?;
    registry.transition(&objects.id, ResourceState::Creating, None)?;
    let root_tree = format!("{prefix}root-tree/");
    let actor_tree = format!("{prefix}actor-tree/");
    let actor_tree_keys = [format!("{actor_tree}a"), format!("{actor_tree}nested/b")];
    let single = format!("{prefix}single");
    // `single/child` shares `single` as a key prefix: the header also sets the server's
    // delete_prefix option (rustfs storage/options.rs), so a server that merely relaxed the
    // authorization gate would remove the child too. It must survive a single-object delete.
    let single_child = format!("{single}/child");
    let sacrificial = format!("{prefix}sacrificial");
    for leaf in ["a", "nested/b"] {
        seed_object(admin_s3, &bucket, &format!("{root_tree}{leaf}"), b"tree").await?;
    }
    for key in &actor_tree_keys {
        seed_object(admin_s3, &bucket, key, b"tree").await?;
    }
    seed_object(admin_s3, &bucket, &single, b"single").await?;
    seed_object(admin_s3, &bucket, &single_child, b"child").await?;
    seed_object(admin_s3, &bucket, &sacrificial, b"sacrificial").await?;
    registry.transition(&objects.id, ResourceState::Created, None)?;
    let untouched_by_prefix_deletes = [
        actor_tree_keys[0].as_str(),
        actor_tree_keys[1].as_str(),
        single.as_str(),
        single_child.as_str(),
        sacrificial.as_str(),
    ];

    // The Console attaches consoleAdmin to its operators; that is the non-owner identity the
    // reporter of rustfs/rustfs#7649 used.
    attach_canned_policy(
        case_id,
        registry,
        admin,
        CannedPolicy::ConsoleAdmin,
        &fixture,
    )
    .await?;
    let shape = ProtocolRequestShape::with_header(FORCE_DELETE_HEADER, "true")?;
    let admin_shaped = actor_clients.for_admin_with_shape(&shape).await?;
    let actor_shaped = actor_clients
        .for_actor_with_shape(&fixture.actor, &shape)
        .await?;

    context.current_phase = "propagation".to_string();
    let probe = format!("{prefix}probe");
    expect_eventual_ok(
        context,
        "iam-user",
        "put-object-probe-with-console-admin",
        &bucket,
        Some(&probe),
        || async { fixture.actor_s3.put_object(&bucket, &probe, b"probe").await },
    )
    .await?;

    context.current_phase = "assertion".to_string();
    context.dimensions = admin_dimensions();
    let root_operation = "delete-object-prefix-with-force-header-as-owner";
    expect_ok(
        context,
        "admin",
        root_operation,
        &bucket,
        Some(&root_tree),
        || async { admin_shaped.delete_object(&bucket, &root_tree).await },
    )
    .await?;
    context.dimensions = canned_policy_dimensions();
    let remaining = admin_keys(admin_s3, &bucket)
        .await?
        .into_iter()
        .filter(|key| key.starts_with(&root_tree))
        .collect::<Vec<_>>();
    ensure!(
        remaining.is_empty(),
        "{root_operation}: owner force-delete of {root_tree} was accepted but left {remaining:?}"
    );
    ensure_keys_present(
        admin_s3,
        &bucket,
        &untouched_by_prefix_deletes,
        root_operation,
    )
    .await?;

    let actor_operation = "delete-object-prefix-with-force-header-as-non-owner";
    expect_access_denied(
        context,
        "iam-user",
        actor_operation,
        &bucket,
        Some(&actor_tree),
        || async { actor_shaped.delete_object(&bucket, &actor_tree).await },
    )
    .await?;
    ensure_keys_present(
        admin_s3,
        &bucket,
        &untouched_by_prefix_deletes,
        actor_operation,
    )
    .await?;

    // A plain DeleteObject from the same actor must succeed right now, so the shaped delete
    // that follows is judged against the force-delete gate and not against IAM propagation lag
    // on the node that happens to serve it.
    let plain_operation = "delete-object-plain-without-force-header";
    expect_ok(
        context,
        "iam-user",
        plain_operation,
        &bucket,
        Some(&sacrificial),
        || async { fixture.actor_s3.delete_object(&bucket, &sacrificial).await },
    )
    .await?;
    ensure_key_presence(admin_s3, &bucket, &sacrificial, false, plain_operation).await?;

    let single_operation = "delete-object-single-with-force-header-as-non-owner";
    match contract {
        ForceDeleteHeaderSingleObjectContract::IgnoreHeader => {
            match expect_ok(
                context,
                "iam-user",
                single_operation,
                &bucket,
                Some(&single),
                || async { actor_shaped.delete_object(&bucket, &single).await },
            )
            .await
            {
                Ok(()) => {}
                Err(failure) if failure.observed == ProtocolAssertionClass::AccessDenied => {
                    bail!(
                        "{failure}; contracts.forceDeleteHeaderSingleObject={} expects a non-owner single-object DeleteObject carrying {FORCE_DELETE_HEADER}: true to behave like a plain DeleteObject (rustfs/rustfs#7649 reporter expectation), but RustFS rejected it; RustFS main currently rejects the header for every non-owner in recursive_force_delete_is_authorized (rustfs/src/storage/access.rs). Set contracts.forceDeleteHeaderSingleObject: reject to assert the current server behavior instead",
                        contract.as_str()
                    );
                }
                Err(failure) => return Err(ExpectationFailure::into(failure)),
            }
            ensure_key_presence(admin_s3, &bucket, &single, false, single_operation).await?;
            let listed = admin_keys(admin_s3, &bucket).await?;
            ensure!(
                listed.iter().any(|key| key == &single_child),
                "{single_operation}: the delete was accepted but also removed {single_child}; the header still acted as a prefix delete instead of a plain DeleteObject"
            );
            Ok(())
        }
        ForceDeleteHeaderSingleObjectContract::Reject => {
            expect_access_denied(
                context,
                "iam-user",
                single_operation,
                &bucket,
                Some(&single),
                || async { actor_shaped.delete_object(&bucket, &single).await },
            )
            .await?;
            ensure_keys_present(
                admin_s3,
                &bucket,
                &[single.as_str(), single_child.as_str()],
                single_operation,
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CannedPolicy, FORCE_DELETE_HEADER, MatrixOperation, run_canned_policy_case};
    use crate::protocol::{
        cases::ProtocolCaseExecution,
        catalog::{
            DELETE_FORCE_HEADER_CONTRACT, IAM_CANNED_POLICY_CONSOLE_ADMIN_DELETE,
            IAM_CANNED_POLICY_MATRIX,
        },
        credentials::ActorCredential,
        fixture::{
            cleanup::cleanup_registered_resources, naming::ProtocolResourceNamer,
            registry::ResourceRegistry,
        },
        ports::{
            ActorS3ClientFactory, ExclusiveBucketOwnership, ProtocolAdminCleanupPort,
            ProtocolAdminError, ProtocolBucketPort, ProtocolIdentityAdminPort,
            ProtocolListObjectsResult, ProtocolListingPort, ProtocolObjectPort,
            ProtocolObjectVersion, ProtocolPolicyAdminPort, ProtocolRequestShape,
            ProtocolS3CleanupPort, ProtocolS3Error, ProtocolVersioningPort,
        },
        reporting::{ProtocolAssertionClass, ProtocolCaseStatus},
        suite::{ForceDeleteHeaderSingleObjectContract, ProtocolSuiteContracts},
        suite_plan::TargetFingerprint,
    };
    use anyhow::Result;
    use async_trait::async_trait;
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::{Arc, Mutex},
    };

    /// How the fake server treats `x-rustfs-force-delete: true` from a non-owner. The header
    /// keeps its prefix-delete semantics for every accepted request unless a variant says
    /// otherwise, mirroring `opts.delete_prefix` being set independently of the auth gate.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ForceHeaderGate {
        /// RustFS main: any non-owner request carrying the header is rejected.
        RejectNonOwner,
        /// rustfs/rustfs#7649 reporter expectation: a prefix delete is rejected and a
        /// single-object delete behaves like a plain DeleteObject.
        IgnoreForSingleObject,
        /// Half fix: the gate lets a non-slash key through but the header still deletes every
        /// key sharing that prefix.
        RelaxGateKeepPrefixDelete,
        /// Regressed server: the header is honored for anyone.
        Unrestricted,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Version {
        version_id: String,
        body: Option<Vec<u8>>,
    }

    #[derive(Default)]
    struct State {
        users: BTreeSet<String>,
        buckets: BTreeSet<String>,
        versioned_buckets: BTreeSet<String>,
        user_policies: BTreeMap<String, BTreeSet<String>>,
        objects: BTreeMap<(String, String), Vec<Version>>,
        next_version: usize,
        force_header_gate: Option<ForceHeaderGate>,
        /// Owner prefix delete removes only the literal key instead of the subtree.
        shallow_owner_force_delete: bool,
        /// Server bug simulation: a canned policy also grants one matrix operation.
        extra_grants: Vec<(&'static str, MatrixOperation)>,
        /// Server bug simulation: a denied DeleteObject still removes the object.
        deny_but_delete: bool,
        /// Propagation stall simulation: plain (header-less) non-owner deletes are denied.
        stall_plain_deletes: bool,
        /// Number of authorization decisions after a detach that still see the old grant.
        detach_visibility_lag: usize,
        lagging_grants: BTreeMap<String, BTreeMap<String, usize>>,
    }

    impl State {
        fn with_gate(gate: ForceHeaderGate) -> Self {
            Self {
                force_header_gate: Some(gate),
                ..Self::default()
            }
        }
    }

    #[derive(Clone)]
    struct FakeAdmin(Arc<Mutex<State>>);

    #[derive(Clone)]
    struct FakeS3 {
        state: Arc<Mutex<State>>,
        actor: Option<String>,
        shape: ProtocolRequestShape,
    }

    #[derive(Clone)]
    struct FakeActorFactory(Arc<Mutex<State>>);

    fn canned_actions(policy: &str) -> Option<&'static [&'static str]> {
        match policy {
            "consoleAdmin" | "readwrite" => Some(&["s3:*"]),
            "writeonly" => Some(&["s3:PutObject"]),
            "readonly" => Some(&["s3:GetBucketLocation", "s3:GetObject", "s3:GetBucketQuota"]),
            "diagnostics" => Some(&[]),
            _ => None,
        }
    }

    impl FakeAdmin {
        fn policy_attached_sync(&self, policy: &str, principal: &str) -> bool {
            self.0
                .lock()
                .expect("state")
                .user_policies
                .get(principal)
                .is_some_and(|policies| policies.contains(policy))
        }
    }

    #[async_trait]
    impl ProtocolIdentityAdminPort for FakeAdmin {
        async fn users_with_prefix(&self, prefix: &str) -> Result<Vec<String>, ProtocolAdminError> {
            Ok(self
                .0
                .lock()
                .expect("state")
                .users
                .iter()
                .filter(|name| name.starts_with(prefix))
                .cloned()
                .collect())
        }
        async fn create_user(
            &self,
            credential: &ActorCredential,
        ) -> Result<(), ProtocolAdminError> {
            self.0
                .lock()
                .expect("state")
                .users
                .insert(credential.access_key().to_string());
            Ok(())
        }
        async fn remove_user(&self, access_key: &str) -> Result<(), ProtocolAdminError> {
            let mut state = self.0.lock().expect("state");
            state.users.remove(access_key);
            state.user_policies.remove(access_key);
            Ok(())
        }
    }

    #[async_trait]
    impl ProtocolPolicyAdminPort for FakeAdmin {
        async fn policies_with_prefix(
            &self,
            _prefix: &str,
        ) -> Result<Vec<String>, ProtocolAdminError> {
            Ok(Vec::new())
        }
        async fn create_policy(
            &self,
            _name: &str,
            _document: &str,
        ) -> Result<(), ProtocolAdminError> {
            panic!("canned policy cases must never create a managed policy")
        }
        async fn remove_policy(&self, _name: &str) -> Result<(), ProtocolAdminError> {
            panic!("canned policy cases must never remove a policy")
        }
        async fn attach_policy(
            &self,
            policy: &str,
            principal: &str,
            is_group: bool,
        ) -> Result<(), ProtocolAdminError> {
            assert!(!is_group, "canned policy cases attach to users only");
            if canned_actions(policy).is_none() {
                return Err(ProtocolAdminError::service("NoSuchPolicy", 404, None));
            }
            let mut state = self.0.lock().expect("state");
            if !state.users.contains(principal) {
                return Err(ProtocolAdminError::service("NoSuchUser", 404, None));
            }
            state
                .user_policies
                .entry(principal.to_string())
                .or_default()
                .insert(policy.to_string());
            Ok(())
        }
        async fn detach_policy(
            &self,
            policy: &str,
            principal: &str,
            _is_group: bool,
        ) -> Result<(), ProtocolAdminError> {
            let mut state = self.0.lock().expect("state");
            if let Some(policies) = state.user_policies.get_mut(principal) {
                policies.remove(policy);
                if policies.is_empty() {
                    state.user_policies.remove(principal);
                }
            }
            if state.detach_visibility_lag > 0 {
                let lag = state.detach_visibility_lag;
                state
                    .lagging_grants
                    .entry(principal.to_string())
                    .or_default()
                    .insert(policy.to_string(), lag);
            }
            Ok(())
        }
        async fn policy_attached(
            &self,
            policy: &str,
            principal: &str,
            _is_group: bool,
        ) -> Result<bool, ProtocolAdminError> {
            Ok(self.policy_attached_sync(policy, principal))
        }
    }

    #[async_trait]
    impl ProtocolAdminCleanupPort for FakeAdmin {
        async fn users_with_prefix(&self, prefix: &str) -> Result<Vec<String>, ProtocolAdminError> {
            ProtocolIdentityAdminPort::users_with_prefix(self, prefix).await
        }
        async fn remove_user(&self, access_key: &str) -> Result<(), ProtocolAdminError> {
            ProtocolIdentityAdminPort::remove_user(self, access_key).await
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
            prefix: &str,
        ) -> Result<Vec<String>, ProtocolAdminError> {
            ProtocolPolicyAdminPort::policies_with_prefix(self, prefix).await
        }
        async fn remove_policy(&self, name: &str) -> Result<(), ProtocolAdminError> {
            ProtocolPolicyAdminPort::remove_policy(self, name).await
        }
        async fn detach_policy(
            &self,
            policy: &str,
            principal: &str,
            is_group: bool,
        ) -> Result<(), ProtocolAdminError> {
            ProtocolPolicyAdminPort::detach_policy(self, policy, principal, is_group).await
        }
        async fn policy_attached(
            &self,
            policy: &str,
            principal: &str,
            is_group: bool,
        ) -> Result<bool, ProtocolAdminError> {
            ProtocolPolicyAdminPort::policy_attached(self, policy, principal, is_group).await
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

    fn access_denied() -> ProtocolS3Error {
        ProtocolS3Error {
            code: "AccessDenied".to_string(),
            status: Some(403),
            request_id: Some("fake".to_string()),
        }
    }

    fn not_found(code: &str) -> ProtocolS3Error {
        ProtocolS3Error {
            code: code.to_string(),
            status: Some(404),
            request_id: Some("fake".to_string()),
        }
    }

    impl FakeS3 {
        fn is_owner(&self) -> bool {
            self.actor.is_none()
        }

        fn force_header(&self) -> bool {
            [FORCE_DELETE_HEADER, "x-minio-force-delete"]
                .iter()
                .any(|name| {
                    self.shape
                        .extra_headers
                        .get(*name)
                        .is_some_and(|value| value.eq_ignore_ascii_case("true"))
                })
        }

        fn authorize(
            &self,
            state: &mut State,
            action: &str,
            bucket: &str,
            operation: MatrixOperation,
        ) -> std::result::Result<(), ProtocolS3Error> {
            let Some(actor) = self.actor.as_deref() else {
                return Ok(());
            };
            if !state.buckets.contains(bucket) {
                return Err(not_found("NoSuchBucket"));
            }
            let mut attached = state.user_policies.get(actor).cloned().unwrap_or_default();
            if let Some(lagging) = state.lagging_grants.get_mut(actor) {
                for (policy, remaining) in lagging.iter_mut() {
                    attached.insert(policy.clone());
                    *remaining -= 1;
                }
                lagging.retain(|_, remaining| *remaining > 0);
            }
            let allowed = attached
                .iter()
                .filter_map(|policy| canned_actions(policy).map(|actions| (policy, actions)))
                .any(|(policy, actions)| {
                    actions.contains(&"s3:*")
                        || actions.contains(&action)
                        || state
                            .extra_grants
                            .iter()
                            .any(|(granted, op)| granted == policy && *op == operation)
                });
            if allowed {
                Ok(())
            } else {
                Err(access_denied())
            }
        }

        /// Mirrors `recursive_force_delete_is_authorized` under the configured gate.
        fn force_header_gate(
            &self,
            state: &State,
            key: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            if !self.force_header() || self.is_owner() {
                return Ok(());
            }
            let gate = state
                .force_header_gate
                .expect("force header gate must be configured for shaped requests");
            let rejected = match gate {
                ForceHeaderGate::RejectNonOwner => true,
                ForceHeaderGate::IgnoreForSingleObject
                | ForceHeaderGate::RelaxGateKeepPrefixDelete => key.ends_with('/'),
                ForceHeaderGate::Unrestricted => false,
            };
            if rejected {
                Err(access_denied())
            } else {
                Ok(())
            }
        }

        fn current(versions: &[Version]) -> Option<&Version> {
            versions.last().filter(|version| version.body.is_some())
        }

        fn write(state: &mut State, bucket: &str, key: &str, body: Option<Vec<u8>>) {
            let version_id = if state.versioned_buckets.contains(bucket) {
                state.next_version += 1;
                format!("v{}", state.next_version)
            } else {
                "null".to_string()
            };
            let entry = state
                .objects
                .entry((bucket.to_string(), key.to_string()))
                .or_default();
            if !state.versioned_buckets.contains(bucket) {
                entry.clear();
            }
            entry.push(Version { version_id, body });
        }

        fn delete_current(state: &mut State, bucket: &str, key: &str) {
            if state.versioned_buckets.contains(bucket) {
                Self::write(state, bucket, key, None);
            } else {
                state.objects.remove(&(bucket.to_string(), key.to_string()));
            }
        }
    }

    #[async_trait]
    impl ProtocolBucketPort for FakeS3 {
        async fn list_buckets_with_prefix(
            &self,
            prefix: &str,
        ) -> Result<Vec<String>, ProtocolS3Error> {
            Ok(self
                .state
                .lock()
                .expect("state")
                .buckets
                .iter()
                .filter(|name| name.starts_with(prefix))
                .cloned()
                .collect())
        }
        async fn create_bucket(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
            self.state
                .lock()
                .expect("state")
                .buckets
                .insert(bucket.to_string());
            Ok(())
        }
        async fn delete_bucket(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
            let mut state = self.state.lock().expect("state");
            state.buckets.remove(bucket);
            state.versioned_buckets.remove(bucket);
            Ok(())
        }
        async fn head_bucket(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
            self.state
                .lock()
                .expect("state")
                .buckets
                .contains(bucket)
                .then_some(())
                .ok_or_else(|| not_found("NoSuchBucket"))
        }
    }

    #[async_trait]
    impl ProtocolListingPort for FakeS3 {
        async fn list_objects(&self, bucket: &str) -> Result<Vec<String>, ProtocolS3Error> {
            let mut state = self.state.lock().expect("state");
            self.authorize(
                &mut state,
                "s3:ListBucket",
                bucket,
                MatrixOperation::GetObject,
            )?;
            Ok(state
                .objects
                .iter()
                .filter(|((candidate, _), versions)| {
                    candidate == bucket && FakeS3::current(versions).is_some()
                })
                .map(|((_, key), _)| key.clone())
                .collect())
        }
        async fn list_objects_v2_summary(
            &self,
            bucket: &str,
        ) -> Result<ProtocolListObjectsResult, ProtocolS3Error> {
            let keys = self.list_objects(bucket).await?;
            Ok(ProtocolListObjectsResult {
                key_count: keys.len(),
                keys,
            })
        }
    }

    #[async_trait]
    impl ProtocolObjectPort for FakeS3 {
        async fn put_object(
            &self,
            bucket: &str,
            key: &str,
            body: &[u8],
        ) -> Result<(), ProtocolS3Error> {
            let mut state = self.state.lock().expect("state");
            self.authorize(
                &mut state,
                "s3:PutObject",
                bucket,
                MatrixOperation::PutObject,
            )?;
            FakeS3::write(&mut state, bucket, key, Some(body.to_vec()));
            Ok(())
        }
        async fn get_object(&self, bucket: &str, key: &str) -> Result<Vec<u8>, ProtocolS3Error> {
            let mut state = self.state.lock().expect("state");
            self.authorize(
                &mut state,
                "s3:GetObject",
                bucket,
                MatrixOperation::GetObject,
            )?;
            state
                .objects
                .get(&(bucket.to_string(), key.to_string()))
                .and_then(|versions| FakeS3::current(versions))
                .and_then(|version| version.body.clone())
                .ok_or_else(|| not_found("NoSuchKey"))
        }
        async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), ProtocolS3Error> {
            let mut state = self.state.lock().expect("state");
            if let Err(error) = self.authorize(
                &mut state,
                "s3:DeleteObject",
                bucket,
                MatrixOperation::DeleteObject,
            ) {
                if state.deny_but_delete {
                    FakeS3::delete_current(&mut state, bucket, key);
                }
                return Err(error);
            }
            if state.stall_plain_deletes && !self.is_owner() && !self.force_header() {
                return Err(access_denied());
            }
            self.force_header_gate(&state, key)?;
            // The header selects delete_prefix for every accepted request; only the reporter's
            // expected fix narrows it to keys that name a prefix.
            let prefix_delete = self.force_header()
                && !state.shallow_owner_force_delete
                && (key.ends_with('/')
                    || state.force_header_gate != Some(ForceHeaderGate::IgnoreForSingleObject));
            if prefix_delete {
                state.objects.retain(|(candidate, existing), _| {
                    candidate != bucket || !existing.starts_with(key)
                });
                return Ok(());
            }
            FakeS3::delete_current(&mut state, bucket, key);
            Ok(())
        }
        async fn copy_object(
            &self,
            _bucket: &str,
            _source_key: &str,
            _destination_key: &str,
        ) -> Result<(), ProtocolS3Error> {
            panic!("copy is not part of the canned policy matrix")
        }
        async fn delete_objects(
            &self,
            bucket: &str,
            keys: &[String],
        ) -> Result<Vec<String>, ProtocolS3Error> {
            let mut state = self.state.lock().expect("state");
            self.force_header_gate(&state, "")?;
            let mut deleted = Vec::new();
            for key in keys {
                // RustFS answers 200 with a per-key AccessDenied entry; the real client
                // surfaces the first entry error as the operation error.
                self.authorize(
                    &mut state,
                    "s3:DeleteObject",
                    bucket,
                    MatrixOperation::DeleteObjects,
                )
                .map_err(|error| ProtocolS3Error {
                    status: Some(200),
                    ..error
                })?;
                FakeS3::delete_current(&mut state, bucket, key);
                deleted.push(key.clone());
            }
            Ok(deleted)
        }
    }

    #[async_trait]
    impl ProtocolVersioningPort for FakeS3 {
        async fn put_bucket_versioning(
            &self,
            bucket: &str,
            enabled: bool,
        ) -> Result<(), ProtocolS3Error> {
            let mut state = self.state.lock().expect("state");
            if enabled {
                state.versioned_buckets.insert(bucket.to_string());
            } else {
                state.versioned_buckets.remove(bucket);
            }
            Ok(())
        }
        async fn get_object_version(
            &self,
            bucket: &str,
            key: &str,
            version_id: &str,
        ) -> Result<Vec<u8>, ProtocolS3Error> {
            let mut state = self.state.lock().expect("state");
            self.authorize(
                &mut state,
                "s3:GetObjectVersion",
                bucket,
                MatrixOperation::GetObject,
            )?;
            state
                .objects
                .get(&(bucket.to_string(), key.to_string()))
                .into_iter()
                .flatten()
                .find(|version| version.version_id == version_id)
                .and_then(|version| version.body.clone())
                .ok_or_else(|| not_found("NoSuchVersion"))
        }
        async fn list_object_versions(
            &self,
            bucket: &str,
        ) -> Result<Vec<ProtocolObjectVersion>, ProtocolS3Error> {
            let mut state = self.state.lock().expect("state");
            self.authorize(
                &mut state,
                "s3:ListBucketVersions",
                bucket,
                MatrixOperation::GetObject,
            )?;
            Ok(state
                .objects
                .iter()
                .filter(|((candidate, _), _)| candidate == bucket)
                .flat_map(|((_, key), versions)| {
                    versions.iter().map(move |version| ProtocolObjectVersion {
                        key: key.clone(),
                        version_id: version.version_id.clone(),
                        delete_marker: version.body.is_none(),
                    })
                })
                .collect())
        }
        async fn delete_object_version(
            &self,
            bucket: &str,
            key: &str,
            version_id: &str,
        ) -> Result<(), ProtocolS3Error> {
            let mut state = self.state.lock().expect("state");
            for action in ["s3:DeleteObject", "s3:DeleteObjectVersion"] {
                self.authorize(
                    &mut state,
                    action,
                    bucket,
                    MatrixOperation::DeleteObjectVersion,
                )?;
            }
            self.force_header_gate(&state, key)?;
            let entry = (bucket.to_string(), key.to_string());
            if let Some(versions) = state.objects.get_mut(&entry) {
                versions.retain(|version| version.version_id != version_id);
                if versions.is_empty() {
                    state.objects.remove(&entry);
                }
            }
            Ok(())
        }
    }

    #[async_trait]
    impl ProtocolS3CleanupPort for FakeS3 {
        async fn cleanup_bucket_names(&self, prefix: &str) -> Result<Vec<String>, ProtocolS3Error> {
            self.list_buckets_with_prefix(prefix).await
        }
        async fn cleanup_exclusive_bucket(
            &self,
            ownership: ExclusiveBucketOwnership<'_>,
            _include_versions: bool,
        ) -> Result<(), ProtocolS3Error> {
            let bucket = ownership.bucket();
            self.state
                .lock()
                .expect("state")
                .objects
                .retain(|(candidate, _), _| candidate != bucket);
            self.delete_bucket(bucket).await
        }
        async fn cleanup_object_prefix(
            &self,
            bucket: &str,
            prefix: &str,
            _include_versions: bool,
        ) -> Result<(), ProtocolS3Error> {
            self.state
                .lock()
                .expect("state")
                .objects
                .retain(|(candidate, key), _| candidate != bucket || !key.starts_with(prefix));
            Ok(())
        }
        async fn cleanup_object_prefix_exists(
            &self,
            bucket: &str,
            prefix: &str,
            _include_versions: bool,
        ) -> Result<bool, ProtocolS3Error> {
            Ok(self
                .state
                .lock()
                .expect("state")
                .objects
                .keys()
                .any(|(candidate, key)| candidate == bucket && key.starts_with(prefix)))
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

    #[async_trait]
    impl ActorS3ClientFactory for FakeActorFactory {
        type Client = FakeS3;

        async fn for_actor(&self, credential: &ActorCredential) -> Result<Self::Client> {
            Ok(FakeS3 {
                state: self.0.clone(),
                actor: Some(credential.access_key().to_string()),
                shape: ProtocolRequestShape::default(),
            })
        }

        async fn for_actor_with_shape(
            &self,
            credential: &ActorCredential,
            shape: &ProtocolRequestShape,
        ) -> Result<Self::Client> {
            Ok(FakeS3 {
                state: self.0.clone(),
                actor: Some(credential.access_key().to_string()),
                shape: shape.clone(),
            })
        }

        async fn for_admin_with_shape(&self, shape: &ProtocolRequestShape) -> Result<Self::Client> {
            Ok(FakeS3 {
                state: self.0.clone(),
                actor: None,
                shape: shape.clone(),
            })
        }
    }

    struct Run {
        execution: ProtocolCaseExecution,
        cleanup_succeeded: bool,
        registry_clean: bool,
        state: Arc<Mutex<State>>,
    }

    async fn run_case(case_id: &str, state: State, contracts: ProtocolSuiteContracts) -> Run {
        let state = Arc::new(Mutex::new(state));
        let admin = FakeAdmin(state.clone());
        let admin_s3 = FakeS3 {
            state: state.clone(),
            actor: None,
            shape: ProtocolRequestShape::default(),
        };
        let factory = FakeActorFactory(state.clone());
        let dir = tempfile::tempdir().expect("tempdir");
        let fingerprint =
            TargetFingerprint::new("http://127.0.0.1:9000", "us-east-1", "fake", None, None)
                .expect("fingerprint");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint).expect("registry");
        let namer = ProtocolResourceNamer::new("s3c", "s3chaos", "run").expect("namer");
        let execution = run_canned_policy_case(
            case_id,
            &namer,
            &mut registry,
            &admin,
            &admin_s3,
            &factory,
            contracts,
        )
        .await;
        let cleanup = cleanup_registered_resources(&mut registry, &admin, &admin_s3).await;
        Run {
            execution,
            cleanup_succeeded: cleanup.succeeded,
            registry_clean: registry.pending_cleanup().next().is_none(),
            state,
        }
    }

    fn assert_target_is_clean(run: &Run, case_id: &str) {
        assert!(run.cleanup_succeeded, "{case_id}");
        assert!(run.registry_clean, "{case_id}");
        let state = run.state.lock().expect("state");
        assert!(state.users.is_empty(), "{case_id}: users leaked");
        assert!(state.buckets.is_empty(), "{case_id}: buckets leaked");
        assert!(state.objects.is_empty(), "{case_id}: objects leaked");
        assert!(
            state.user_policies.is_empty(),
            "{case_id}: canned policy attachments leaked"
        );
    }

    fn reject_contract() -> ProtocolSuiteContracts {
        ProtocolSuiteContracts {
            force_delete_header_single_object: ForceDeleteHeaderSingleObjectContract::Reject,
        }
    }

    #[test]
    fn every_matrix_cell_is_encoded_explicitly() {
        use CannedPolicy::{ConsoleAdmin, ReadOnly, ReadWrite, WriteOnly};
        use MatrixOperation::{
            DeleteObject, DeleteObjectVersion, DeleteObjects, GetObject, PutObject,
        };
        let expected = [
            (ConsoleAdmin, PutObject, true),
            (ConsoleAdmin, GetObject, true),
            (ConsoleAdmin, DeleteObject, true),
            (ConsoleAdmin, DeleteObjects, true),
            (ConsoleAdmin, DeleteObjectVersion, true),
            (ReadWrite, PutObject, true),
            (ReadWrite, GetObject, true),
            (ReadWrite, DeleteObject, true),
            (ReadWrite, DeleteObjects, true),
            (ReadWrite, DeleteObjectVersion, true),
            (WriteOnly, PutObject, true),
            (WriteOnly, GetObject, false),
            (WriteOnly, DeleteObject, false),
            (WriteOnly, DeleteObjects, false),
            (WriteOnly, DeleteObjectVersion, false),
            (ReadOnly, PutObject, false),
            (ReadOnly, GetObject, true),
            (ReadOnly, DeleteObject, false),
            (ReadOnly, DeleteObjects, false),
            (ReadOnly, DeleteObjectVersion, false),
        ];
        assert_eq!(
            expected.len(),
            CannedPolicy::ALL.len() * MatrixOperation::ALL.len()
        );
        for (policy, operation, allowed) in expected {
            assert_eq!(
                policy.allows(operation),
                allowed,
                "{policy:?} x {operation:?}"
            );
        }
        assert_eq!(
            CannedPolicy::ALL.map(CannedPolicy::name),
            ["consoleAdmin", "readwrite", "writeonly", "readonly"]
        );
    }

    #[tokio::test]
    async fn matrix_case_asserts_every_cell_and_leaves_the_target_clean() {
        let run = run_case(
            IAM_CANNED_POLICY_MATRIX,
            State::default(),
            ProtocolSuiteContracts::default(),
        )
        .await;
        assert_eq!(
            run.execution.report.status,
            ProtocolCaseStatus::Passed,
            "{:?}",
            run.execution.report.failure
        );
        for policy in CannedPolicy::ALL {
            for operation in MatrixOperation::ALL {
                let name = format!("{}-with-{}", operation.label(), policy.label());
                let cell = run
                    .execution
                    .report
                    .assertions
                    .iter()
                    .find(|assertion| assertion.operation == name)
                    .unwrap_or_else(|| panic!("matrix cell {name} was not asserted"));
                let expected = if policy.allows(operation) {
                    ProtocolAssertionClass::Ok
                } else {
                    ProtocolAssertionClass::AccessDenied
                };
                assert_eq!(cell.expected, expected, "{name}");
                assert_eq!(cell.actual, expected, "{name}");
                assert_eq!(cell.phase, "assertion", "{name}");
                assert_eq!(cell.retry_count, 0, "{name}");
            }
            for suffix in ["after-attach", "after-detach"] {
                let probe = format!("probe-{suffix}-{}", policy.label());
                assert!(
                    run.execution
                        .report
                        .assertions
                        .iter()
                        .any(|assertion| assertion.operation.ends_with(&probe)),
                    "{probe} propagation barrier missing"
                );
            }
        }
        assert_target_is_clean(&run, IAM_CANNED_POLICY_MATRIX);
    }

    #[tokio::test]
    async fn matrix_case_fails_on_every_denied_cell_the_server_grants() {
        let over_grants = [
            (
                "readonly",
                MatrixOperation::PutObject,
                "put-object-with-readonly:",
            ),
            (
                "writeonly",
                MatrixOperation::GetObject,
                "get-object-with-writeonly:",
            ),
            (
                "writeonly",
                MatrixOperation::DeleteObject,
                "delete-object-with-writeonly:",
            ),
            (
                "readonly",
                MatrixOperation::DeleteObjects,
                "delete-objects-with-readonly:",
            ),
            (
                "writeonly",
                MatrixOperation::DeleteObjectVersion,
                "delete-object-version-with-writeonly:",
            ),
        ];
        for (policy, operation, expected_failure) in over_grants {
            let run = run_case(
                IAM_CANNED_POLICY_MATRIX,
                State {
                    extra_grants: vec![(policy, operation)],
                    ..State::default()
                },
                ProtocolSuiteContracts::default(),
            )
            .await;
            assert_eq!(
                run.execution.report.status,
                ProtocolCaseStatus::Failed,
                "{policy} x {operation:?}"
            );
            let failure = run.execution.report.failure.clone().expect("failure");
            assert!(failure.starts_with(expected_failure), "{failure}");
            assert_target_is_clean(&run, IAM_CANNED_POLICY_MATRIX);
        }

        let run = run_case(
            IAM_CANNED_POLICY_MATRIX,
            State {
                deny_but_delete: true,
                ..State::default()
            },
            ProtocolSuiteContracts::default(),
        )
        .await;
        assert_eq!(run.execution.report.status, ProtocolCaseStatus::Failed);
        let failure = run.execution.report.failure.clone().expect("failure");
        assert!(
            failure.starts_with("delete-object-with-writeonly:")
                && failure.contains("no longer listed"),
            "{failure}"
        );
        assert_target_is_clean(&run, IAM_CANNED_POLICY_MATRIX);
    }

    #[tokio::test]
    async fn matrix_detach_barrier_absorbs_lagging_grant_visibility() {
        let run = run_case(
            IAM_CANNED_POLICY_MATRIX,
            State {
                detach_visibility_lag: 1,
                ..State::default()
            },
            ProtocolSuiteContracts::default(),
        )
        .await;
        assert_eq!(
            run.execution.report.status,
            ProtocolCaseStatus::Passed,
            "{:?}",
            run.execution.report.failure
        );
        for policy in CannedPolicy::ALL {
            let barrier = format!("probe-after-detach-{}", policy.label());
            let assertion = run
                .execution
                .report
                .assertions
                .iter()
                .find(|assertion| assertion.operation.ends_with(&barrier))
                .expect("detach barrier");
            assert_eq!(assertion.retry_count, 1, "{barrier}");
            assert_eq!(assertion.actual, ProtocolAssertionClass::AccessDenied);
        }
        assert!(
            run.execution
                .report
                .assertions
                .iter()
                .filter(|assertion| assertion.phase == "assertion")
                .all(|assertion| assertion.retry_count == 0)
        );
        assert_target_is_clean(&run, IAM_CANNED_POLICY_MATRIX);
    }

    #[tokio::test]
    async fn console_admin_delete_smoke_case_passes_and_cleans_up() {
        let run = run_case(
            IAM_CANNED_POLICY_CONSOLE_ADMIN_DELETE,
            State::default(),
            ProtocolSuiteContracts::default(),
        )
        .await;
        assert_eq!(
            run.execution.report.status,
            ProtocolCaseStatus::Passed,
            "{:?}",
            run.execution.report.failure
        );
        let delete = run
            .execution
            .report
            .assertions
            .iter()
            .find(|assertion| assertion.operation == "delete-object-with-console-admin")
            .expect("delete assertion");
        assert_eq!(delete.actual, ProtocolAssertionClass::Ok);
        assert_eq!(delete.exchange.method, "DELETE");
        assert_target_is_clean(&run, IAM_CANNED_POLICY_CONSOLE_ADMIN_DELETE);
    }

    #[tokio::test]
    async fn force_header_default_contract_fails_against_rustfs_main_with_a_divergence_note() {
        let run = run_case(
            DELETE_FORCE_HEADER_CONTRACT,
            State::with_gate(ForceHeaderGate::RejectNonOwner),
            ProtocolSuiteContracts::default(),
        )
        .await;
        assert_eq!(run.execution.report.status, ProtocolCaseStatus::Failed);
        let failure = run.execution.report.failure.clone().expect("failure");
        assert!(
            failure.starts_with("delete-object-single-with-force-header-as-non-owner:"),
            "{failure}"
        );
        for fragment in [
            "rustfs/rustfs#7649",
            "contracts.forceDeleteHeaderSingleObject=ignore-header",
            "recursive_force_delete_is_authorized",
            "forceDeleteHeaderSingleObject: reject",
        ] {
            assert!(failure.contains(fragment), "{failure}");
        }
        let assertions = &run.execution.report.assertions;
        let owner = assertions
            .iter()
            .find(|assertion| {
                assertion.operation == "delete-object-prefix-with-force-header-as-owner"
            })
            .expect("owner assertion");
        assert_eq!(owner.actual, ProtocolAssertionClass::Ok);
        assert_eq!(owner.actor_id, "admin");
        let non_owner = assertions
            .iter()
            .find(|assertion| {
                assertion.operation == "delete-object-prefix-with-force-header-as-non-owner"
            })
            .expect("non-owner assertion");
        assert_eq!(non_owner.actual, ProtocolAssertionClass::AccessDenied);
        let plain = assertions
            .iter()
            .find(|assertion| assertion.operation == "delete-object-plain-without-force-header")
            .expect("plain delete probe");
        assert_eq!(plain.actual, ProtocolAssertionClass::Ok);
        assert_target_is_clean(&run, DELETE_FORCE_HEADER_CONTRACT);
    }

    #[tokio::test]
    async fn force_header_default_contract_fails_when_the_relaxed_gate_still_prefix_deletes() {
        let run = run_case(
            DELETE_FORCE_HEADER_CONTRACT,
            State::with_gate(ForceHeaderGate::RelaxGateKeepPrefixDelete),
            ProtocolSuiteContracts::default(),
        )
        .await;
        assert_eq!(run.execution.report.status, ProtocolCaseStatus::Failed);
        let failure = run.execution.report.failure.clone().expect("failure");
        assert!(
            failure.starts_with("delete-object-single-with-force-header-as-non-owner:")
                && failure.contains("single/child"),
            "{failure}"
        );
        assert_target_is_clean(&run, DELETE_FORCE_HEADER_CONTRACT);
    }

    #[tokio::test]
    async fn force_header_reject_contract_fails_when_the_plain_delete_is_stalled() {
        // Without the plain-delete probe an IAM propagation stall would satisfy the reject
        // expectation for the wrong reason; with it the case fails on the probe first.
        let run = run_case(
            DELETE_FORCE_HEADER_CONTRACT,
            State {
                stall_plain_deletes: true,
                ..State::with_gate(ForceHeaderGate::RejectNonOwner)
            },
            reject_contract(),
        )
        .await;
        assert_eq!(run.execution.report.status, ProtocolCaseStatus::Failed);
        let failure = run.execution.report.failure.clone().expect("failure");
        assert!(
            failure.starts_with("delete-object-plain-without-force-header:"),
            "{failure}"
        );
        assert_target_is_clean(&run, DELETE_FORCE_HEADER_CONTRACT);
    }

    #[tokio::test]
    async fn force_header_reject_contract_passes_against_rustfs_main() {
        let run = run_case(
            DELETE_FORCE_HEADER_CONTRACT,
            State::with_gate(ForceHeaderGate::RejectNonOwner),
            reject_contract(),
        )
        .await;
        assert_eq!(
            run.execution.report.status,
            ProtocolCaseStatus::Passed,
            "{:?}",
            run.execution.report.failure
        );
        assert_target_is_clean(&run, DELETE_FORCE_HEADER_CONTRACT);
    }

    #[tokio::test]
    async fn force_header_default_contract_passes_when_single_object_header_is_ignored() {
        let run = run_case(
            DELETE_FORCE_HEADER_CONTRACT,
            State::with_gate(ForceHeaderGate::IgnoreForSingleObject),
            ProtocolSuiteContracts::default(),
        )
        .await;
        assert_eq!(
            run.execution.report.status,
            ProtocolCaseStatus::Passed,
            "{:?}",
            run.execution.report.failure
        );
        assert_target_is_clean(&run, DELETE_FORCE_HEADER_CONTRACT);

        let run = run_case(
            DELETE_FORCE_HEADER_CONTRACT,
            State::with_gate(ForceHeaderGate::IgnoreForSingleObject),
            reject_contract(),
        )
        .await;
        assert_eq!(run.execution.report.status, ProtocolCaseStatus::Failed);
        assert!(
            run.execution
                .report
                .failure
                .as_deref()
                .is_some_and(|failure| failure
                    .starts_with("delete-object-single-with-force-header-as-non-owner:")),
            "{:?}",
            run.execution.report.failure
        );
    }

    #[tokio::test]
    async fn force_header_contract_fails_when_a_non_owner_recursive_delete_is_honored() {
        for contracts in [ProtocolSuiteContracts::default(), reject_contract()] {
            let run = run_case(
                DELETE_FORCE_HEADER_CONTRACT,
                State::with_gate(ForceHeaderGate::Unrestricted),
                contracts,
            )
            .await;
            assert_eq!(run.execution.report.status, ProtocolCaseStatus::Failed);
            let failure = run.execution.report.failure.clone().expect("failure");
            assert!(
                failure.starts_with("delete-object-prefix-with-force-header-as-non-owner:"),
                "{failure}"
            );
            assert_target_is_clean(&run, DELETE_FORCE_HEADER_CONTRACT);
        }
    }

    #[tokio::test]
    async fn force_header_contract_fails_when_the_owner_prefix_delete_is_not_recursive() {
        let run = run_case(
            DELETE_FORCE_HEADER_CONTRACT,
            State {
                shallow_owner_force_delete: true,
                ..State::with_gate(ForceHeaderGate::RejectNonOwner)
            },
            reject_contract(),
        )
        .await;
        assert_eq!(run.execution.report.status, ProtocolCaseStatus::Failed);
        let failure = run.execution.report.failure.clone().expect("failure");
        assert!(
            failure.starts_with("delete-object-prefix-with-force-header-as-owner:")
                && failure.contains("root-tree/"),
            "{failure}"
        );
        assert_target_is_clean(&run, DELETE_FORCE_HEADER_CONTRACT);
    }

    #[tokio::test]
    async fn force_header_contract_requires_a_shape_aware_client_factory() {
        struct PlainFactory(Arc<Mutex<State>>);

        #[async_trait]
        impl ActorS3ClientFactory for PlainFactory {
            type Client = FakeS3;

            async fn for_actor(&self, credential: &ActorCredential) -> Result<Self::Client> {
                Ok(FakeS3 {
                    state: self.0.clone(),
                    actor: Some(credential.access_key().to_string()),
                    shape: ProtocolRequestShape::default(),
                })
            }
        }

        let state = Arc::new(Mutex::new(State::with_gate(
            ForceHeaderGate::RejectNonOwner,
        )));
        let admin = FakeAdmin(state.clone());
        let admin_s3 = FakeS3 {
            state: state.clone(),
            actor: None,
            shape: ProtocolRequestShape::default(),
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let fingerprint =
            TargetFingerprint::new("http://127.0.0.1:9000", "us-east-1", "fake", None, None)
                .expect("fingerprint");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint).expect("registry");
        let namer = ProtocolResourceNamer::new("s3c", "s3chaos", "run").expect("namer");
        let execution = run_canned_policy_case(
            DELETE_FORCE_HEADER_CONTRACT,
            &namer,
            &mut registry,
            &admin,
            &admin_s3,
            &PlainFactory(state.clone()),
            reject_contract(),
        )
        .await;
        assert_eq!(execution.report.status, ProtocolCaseStatus::Failed);
        assert!(
            execution
                .report
                .failure
                .as_deref()
                .is_some_and(|failure| failure.contains("request shapes")),
            "{:?}",
            execution.report.failure
        );
        let cleanup = cleanup_registered_resources(&mut registry, &admin, &admin_s3).await;
        assert!(cleanup.succeeded);
    }
}
