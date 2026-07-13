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

mod authz;
mod bucket_policy;
mod compatibility;
mod iam;
mod sts;

use crate::protocol::{
    authorization::ProtocolAuthorizationDimensions,
    catalog::protocol_case,
    credentials::ActorCredential,
    fixture::{naming::ProtocolResourceNamer, registry::ResourceRegistry},
    ports::{ActorS3ClientFactory, ProtocolAdminPort, ProtocolS3Port, ProtocolStsPort},
    reporting::{ProtocolCaseReport, ProtocolCaseStatus},
};

pub struct ProtocolCaseExecution {
    pub report: ProtocolCaseReport,
    pub forbidden_secrets: Vec<String>,
}

impl ProtocolCaseExecution {
    pub fn interrupted(case_id: &str) -> Self {
        Self::failed(
            case_id,
            "interrupted",
            "protocol suite interrupted; cleanup requested",
        )
    }

    pub fn preflight_failed(case_id: &str, message: impl Into<String>) -> Self {
        Self::failed(case_id, "preflight", message)
    }

    pub fn not_run(case_id: &str, message: impl Into<String>) -> Self {
        Self::failed(case_id, "not-run", message)
    }

    fn failed(case_id: &str, phase: &str, message: impl Into<String>) -> Self {
        Self {
            report: ProtocolCaseReport {
                api_version: "rustfs.com/s3chaos/v1alpha1".to_string(),
                kind: "ProtocolCaseReport".to_string(),
                case_id: case_id.to_string(),
                status: ProtocolCaseStatus::Failed,
                actors: Vec::new(),
                assertions: Vec::new(),
                failure_phase: Some(phase.to_string()),
                failure: Some(message.into()),
            },
            forbidden_secrets: Vec::new(),
        }
    }
}

pub async fn run_protocol_case<F>(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolAdminPort,
    admin_s3: &impl ProtocolS3Port,
    sts: &impl ProtocolStsPort,
    actor_clients: &F,
) -> ProtocolCaseExecution
where
    F: ActorS3ClientFactory,
{
    let Some(case) = protocol_case(case_id) else {
        return ProtocolCaseExecution::not_run(case_id, "case is not present in protocol catalog");
    };
    match case.group {
        "bucket-policy" => {
            bucket_policy::run_bucket_policy_case(
                case_id,
                namer,
                registry,
                admin,
                admin_s3,
                actor_clients,
            )
            .await
        }
        "s3-compatibility" => {
            compatibility::run_compatibility_case(case_id, namer, registry, admin_s3).await
        }
        "iam-user" | "iam-policy" | "iam-group" => {
            iam::run_iam_case(case_id, namer, registry, admin, admin_s3, actor_clients).await
        }
        "sts-assume-role" | "sts-session-policy" => {
            sts::run_sts_case(
                case_id,
                namer,
                registry,
                admin,
                admin_s3,
                sts,
                actor_clients,
            )
            .await
        }
        group => ProtocolCaseExecution::not_run(
            case_id,
            format!("protocol case group {group} has no executor"),
        ),
    }
}

pub(crate) struct CaseContext {
    case_id: String,
    pub assertions: Vec<crate::protocol::reporting::ProtocolAssertion>,
    pub actors: Vec<ActorCredential>,
    forbidden_secrets: Vec<String>,
    pub current_phase: String,
    pub dimensions: ProtocolAuthorizationDimensions,
}

impl CaseContext {
    pub(crate) fn new(case_id: &str, dimensions: ProtocolAuthorizationDimensions) -> Self {
        Self {
            case_id: case_id.to_string(),
            assertions: Vec::new(),
            actors: Vec::new(),
            forbidden_secrets: Vec::new(),
            current_phase: "setup".to_string(),
            dimensions,
        }
    }

    pub(crate) fn add_actor(&mut self, actor: ActorCredential) {
        self.forbidden_secrets.push(actor.secret_key().to_string());
        if let Some(token) = actor.session_token() {
            self.forbidden_secrets.push(token.to_string());
        }
        self.actors.push(actor);
    }

    pub(crate) fn finish(self, result: anyhow::Result<()>) -> ProtocolCaseExecution {
        let failure = result.as_ref().err().map(ToString::to_string);
        ProtocolCaseExecution {
            report: ProtocolCaseReport {
                api_version: "rustfs.com/s3chaos/v1alpha1".to_string(),
                kind: "ProtocolCaseReport".to_string(),
                case_id: self.case_id,
                status: if result.is_ok() {
                    ProtocolCaseStatus::Passed
                } else {
                    ProtocolCaseStatus::Failed
                },
                actors: self.actors.iter().map(ActorCredential::artifact).collect(),
                assertions: self.assertions,
                failure_phase: failure.as_ref().map(|_| self.current_phase),
                failure,
            },
            forbidden_secrets: self.forbidden_secrets,
        }
    }
}
