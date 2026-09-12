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

//! Fail-closed execution route for the planned stale-disk-return qualification.

use anyhow::{Result, bail, ensure};

use crate::{
    fault::{
        config::FaultTestConfig,
        plan::{ExecutionPlan, StorageRecoveryExecutionPlan},
        runner::initialize_fault_run,
        scenarios::{FaultScenario, STALE_DISK_RETURN_DETECT_SCENARIO},
        shutdown::RunDeadline,
        storage_recovery::StorageRecoveryCase,
    },
    framework::artifacts::ArtifactCollector,
};

pub(crate) async fn run_stale_disk_case(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    scenario: &FaultScenario,
    execution_plan: &ExecutionPlan,
    plan: &StorageRecoveryExecutionPlan,
    run_id: &str,
    _deadline: RunDeadline,
) -> Result<()> {
    ensure!(
        config.qualify_planned_storage
            && scenario.name == STALE_DISK_RETURN_DETECT_SCENARIO
            && plan.case == StorageRecoveryCase::StaleDiskReturn
            && plan.scenario == scenario.name,
        "stale-disk qualification requires the exact planned-storage gate and typed case"
    );
    let _context = initialize_fault_run(config, collector, scenario, execution_plan, run_id)?;
    bail!(
        "stale-disk production adapter is unavailable; refusing to mutate storage without a qualified run-owned DM helper"
    )
}
