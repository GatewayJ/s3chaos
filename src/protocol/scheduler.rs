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

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::protocol::catalog::ProtocolCase;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolLockScope {
    Tenant,
    BucketPrefix,
    IamPrefix,
    ExternalIdp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolLockMode {
    Shared,
    Exclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolLock {
    pub scope: ProtocolLockScope,
    pub name: String,
    pub mode: ProtocolLockMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolScheduledCase {
    pub case_id: String,
    pub worker_index: usize,
    pub locks: Vec<ProtocolLock>,
}

pub fn plan_protocol_schedule(
    cases: &[&ProtocolCase],
    parallelism: usize,
) -> Result<Vec<Vec<ProtocolScheduledCase>>> {
    ensure!(parallelism > 0, "protocol parallelism must be positive");
    if parallelism > 1 {
        for case in cases {
            ensure!(
                !case.serial && case.tags.contains(&"parallel-safe"),
                "protocol case {} is not parallel-safe; run it with parallelism 1",
                case.id
            );
        }
    }

    let mut waves: Vec<Vec<ProtocolScheduledCase>> = Vec::new();
    for case in cases {
        let locks = locks_for_case(case);
        let wave_index = waves
            .iter()
            .position(|wave| {
                wave.len() < parallelism
                    && wave
                        .iter()
                        .all(|scheduled| locks_compatible(&scheduled.locks, &locks))
            })
            .unwrap_or_else(|| {
                waves.push(Vec::new());
                waves.len() - 1
            });
        let worker_index = waves[wave_index].len();
        waves[wave_index].push(ProtocolScheduledCase {
            case_id: case.id.to_string(),
            worker_index,
            locks,
        });
    }
    Ok(waves)
}

fn locks_for_case(case: &ProtocolCase) -> Vec<ProtocolLock> {
    if case.serial {
        let mut locks = vec![ProtocolLock {
            scope: ProtocolLockScope::Tenant,
            name: "target".to_string(),
            mode: ProtocolLockMode::Exclusive,
        }];
        if case.requires.contains(&"external-idp") {
            locks.push(ProtocolLock {
                scope: ProtocolLockScope::ExternalIdp,
                name: "configured-provider".to_string(),
                mode: ProtocolLockMode::Exclusive,
            });
        }
        return locks;
    }
    vec![
        ProtocolLock {
            scope: ProtocolLockScope::BucketPrefix,
            name: case.id.to_string(),
            mode: ProtocolLockMode::Exclusive,
        },
        ProtocolLock {
            scope: ProtocolLockScope::IamPrefix,
            name: case.id.to_string(),
            mode: ProtocolLockMode::Exclusive,
        },
    ]
}

fn locks_compatible(left: &[ProtocolLock], right: &[ProtocolLock]) -> bool {
    left.iter().all(|left| {
        right.iter().all(|right| {
            left.scope != right.scope
                || left.name != right.name
                || (left.mode == ProtocolLockMode::Shared && right.mode == ProtocolLockMode::Shared)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ProtocolLock, ProtocolLockMode, ProtocolLockScope, locks_compatible, plan_protocol_schedule,
    };
    use crate::protocol::catalog::{ProtocolCase, ProtocolDomain, ProtocolIsolation};

    const PARALLEL_A: ProtocolCase = ProtocolCase {
        id: "parallel-a",
        domain: ProtocolDomain::Other,
        group: "test",
        tags: &["parallel-safe"],
        isolation: ProtocolIsolation::Case,
        requires: &[],
        serial: false,
    };
    const PARALLEL_B: ProtocolCase = ProtocolCase {
        id: "parallel-b",
        domain: ProtocolDomain::Other,
        group: "test",
        tags: &["parallel-safe"],
        isolation: ProtocolIsolation::Case,
        requires: &[],
        serial: false,
    };
    const SERIAL: ProtocolCase = ProtocolCase {
        id: "serial",
        domain: ProtocolDomain::Other,
        group: "test",
        tags: &[],
        isolation: ProtocolIsolation::Case,
        requires: &[],
        serial: true,
    };
    const EXTERNAL_IDP: ProtocolCase = ProtocolCase {
        id: "external-idp",
        domain: ProtocolDomain::Other,
        group: "test",
        tags: &[],
        isolation: ProtocolIsolation::Case,
        requires: &["external-idp"],
        serial: true,
    };

    #[test]
    fn parallel_safe_cases_receive_distinct_workers_and_prefix_locks() {
        let schedule = plan_protocol_schedule(&[&PARALLEL_A, &PARALLEL_B], 2).expect("schedule");
        assert_eq!(schedule.len(), 1);
        assert_eq!(schedule[0][0].worker_index, 0);
        assert_eq!(schedule[0][1].worker_index, 1);
        assert_ne!(schedule[0][0].locks[0].name, schedule[0][1].locks[0].name);
    }

    #[test]
    fn scheduler_rejects_serial_case_when_parallelism_is_requested() {
        assert!(plan_protocol_schedule(&[&SERIAL], 2).is_err());
        assert!(plan_protocol_schedule(&[&SERIAL], 1).is_ok());
    }

    #[test]
    fn external_idp_case_receives_explicit_exclusive_lock() {
        let schedule = plan_protocol_schedule(&[&EXTERNAL_IDP], 1).expect("schedule");
        assert!(schedule[0][0].locks.iter().any(|lock| {
            lock.scope == ProtocolLockScope::ExternalIdp && lock.mode == ProtocolLockMode::Exclusive
        }));
    }

    #[test]
    fn exclusive_locks_conflict_while_shared_locks_coexist() {
        let exclusive = ProtocolLock {
            scope: ProtocolLockScope::Tenant,
            name: "target".to_string(),
            mode: ProtocolLockMode::Exclusive,
        };
        let shared = ProtocolLock {
            mode: ProtocolLockMode::Shared,
            ..exclusive.clone()
        };
        assert!(!locks_compatible(
            std::slice::from_ref(&exclusive),
            std::slice::from_ref(&shared)
        ));
        assert!(locks_compatible(
            std::slice::from_ref(&shared),
            std::slice::from_ref(&shared)
        ));
    }
}
