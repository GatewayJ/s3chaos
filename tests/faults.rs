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

use anyhow::Result;
#[cfg(unix)]
use std::process::{Command, Output};

#[cfg(unix)]
fn fault_supervision_output(host_storage_mutation_possible: bool) -> Output {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fault-test.sh");
    Command::new("bash")
        .args([
            "-c",
            r#"
source "$1"
probe_count=0
observed_signals=""
pgrep() { return 1; }
sleep() { :; }
kill() {
  case "$1" in
    -TERM|-KILL)
      observed_signals="${observed_signals}${1#-} "
      return 0
      ;;
    -0)
      probe_count=$((probe_count + 1))
      (( probe_count <= 3 ))
      ;;
    *)
      return 1
      ;;
  esac
}
terminate_process_tree 4242 "$2" 0
printf '%s\n' "$observed_signals"
"#,
            "fault-process-supervision-test",
            script,
            if host_storage_mutation_possible {
                "true"
            } else {
                "false"
            },
        ])
        .output()
        .expect("run fault process supervision shell test")
}

#[cfg(unix)]
#[test]
fn dm_termination_past_grace_never_escalates_to_sigkill() {
    let output = fault_supervision_output(true);

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "TERM");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("refusing to send SIGKILL"));
    assert!(stderr.contains("waiting for the fault process to restore or quarantine"));
}

#[cfg(unix)]
#[test]
fn ordinary_termination_past_grace_escalates_to_sigkill() {
    let output = fault_supervision_output(false);

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "TERM KILL");
    assert!(String::from_utf8_lossy(&output.stderr).contains("escalating to KILL"));
}

#[tokio::test]
#[ignore = "destructive RustFS workload fault scenario; select with RUSTFS_FAULT_TEST_SCENARIO"]
async fn fault_selected_scenario() -> Result<()> {
    s3chaos::fault::runner::run_selected_scenario_from_env().await
}
