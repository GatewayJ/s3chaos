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
mod oidc;
mod sts;

use crate::protocol::{
    authorization::ProtocolAuthorizationDimensions,
    catalog::protocol_case,
    credentials::ActorCredential,
    fixture::{naming::ProtocolResourceNamer, registry::ResourceRegistry},
    ports::{
        ActorS3ClientFactory, ProtocolAdminPort, ProtocolExternalIdentityPort, ProtocolS3Port,
        ProtocolStsPort, ProtocolWebIdentityStsPort,
    },
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
                domain: protocol_case(case_id)
                    .map(|case| case.domain)
                    .unwrap_or(crate::protocol::catalog::ProtocolDomain::Other),
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

pub(crate) struct ProtocolCaseServices<'a, A, S, T, F> {
    pub(crate) admin: &'a A,
    pub(crate) admin_s3: &'a S,
    pub(crate) sts: &'a T,
    pub(crate) external_identity: Option<&'a dyn ProtocolExternalIdentityPort>,
    pub(crate) web_identity_sts: Option<&'a dyn ProtocolWebIdentityStsPort>,
    pub(crate) actor_clients: &'a F,
}

pub(crate) async fn run_protocol_case<A, S, T, F>(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    services: ProtocolCaseServices<'_, A, S, T, F>,
) -> ProtocolCaseExecution
where
    A: ProtocolAdminPort,
    S: ProtocolS3Port,
    T: ProtocolStsPort,
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
                services.admin,
                services.admin_s3,
                services.actor_clients,
            )
            .await
        }
        "s3-compatibility" | "public-access-block" => {
            compatibility::run_compatibility_case(case_id, namer, registry, services.admin_s3).await
        }
        "iam-user" | "iam-policy" | "iam-group" => {
            iam::run_iam_case(
                case_id,
                namer,
                registry,
                services.admin,
                services.admin_s3,
                services.actor_clients,
            )
            .await
        }
        "sts-assume-role" | "sts-session-policy" => {
            sts::run_sts_case(
                case_id,
                namer,
                registry,
                services.admin,
                services.admin_s3,
                services.sts,
                services.actor_clients,
            )
            .await
        }
        "oidc-web-identity" => {
            let (Some(external_identity), Some(web_identity_sts)) =
                (services.external_identity, services.web_identity_sts)
            else {
                return ProtocolCaseExecution::preflight_failed(
                    case_id,
                    "OIDC case requires external identity and WebIdentity STS ports",
                );
            };
            oidc::run_oidc_case(
                case_id,
                registry,
                oidc::OidcCaseServices {
                    namer,
                    admin: services.admin,
                    admin_s3: services.admin_s3,
                    external_identity,
                    web_identity_sts,
                    actor_clients: services.actor_clients,
                },
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
        if actor.session_token().is_some() {
            self.forbidden_secrets.push(actor.access_key().to_string());
        }
        self.forbidden_secrets.push(actor.secret_key().to_string());
        if let Some(token) = actor.session_token() {
            self.forbidden_secrets.push(token.to_string());
        }
        self.actors.push(actor);
    }

    pub(crate) fn add_forbidden_secret(&mut self, secret: impl Into<String>) {
        self.forbidden_secrets.push(secret.into());
    }

    pub(crate) fn finish(self, result: anyhow::Result<()>) -> ProtocolCaseExecution {
        let failure = result.as_ref().err().map(ToString::to_string);
        let domain = protocol_case(&self.case_id)
            .map(|case| case.domain)
            .unwrap_or(crate::protocol::catalog::ProtocolDomain::Other);
        ProtocolCaseExecution {
            report: ProtocolCaseReport {
                api_version: "rustfs.com/s3chaos/v1alpha1".to_string(),
                kind: "ProtocolCaseReport".to_string(),
                case_id: self.case_id,
                domain,
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
