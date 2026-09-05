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
fn fault_supervision_output(host_storage_mutation_active: bool) -> Output {
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
host_storage_mutation_active() { [[ "$2" == "active" ]]; }
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
terminate_process_tree 4242 "$2" token-a 0
printf '%s\n' "$observed_signals"
"#,
            "fault-process-supervision-test",
            script,
            if host_storage_mutation_active {
                "active"
            } else {
                "inactive"
            },
        ])
        .output()
        .expect("run fault process supervision shell test")
}

#[cfg(unix)]
#[test]
fn active_dm_termination_past_grace_never_escalates_to_sigkill() {
    let output = fault_supervision_output(true);

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "TERM");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("refusing to send SIGKILL"));
    assert!(stderr.contains("waiting for the fault process to restore or quarantine"));
}

#[cfg(unix)]
#[test]
fn mixed_suite_ordinary_attempt_past_grace_escalates_to_sigkill() {
    let output = fault_supervision_output(false);

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "TERM KILL");
    assert!(String::from_utf8_lossy(&output.stderr).contains("escalating to KILL"));
}

#[cfg(unix)]
#[test]
fn host_mutation_marker_rejects_wrong_token_and_cross_process_owner() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let marker = temporary.path().join("marker.json");
    std::fs::write(&marker, "{}").expect("marker");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fault-test.sh");
    let output = Command::new("bash")
        .args([
            "-c",
            r#"
source "$1"
descends=yes
jq() {
  case "$2" in
    '.schemaVersion // empty') printf '1\n' ;;
    '.token // empty') printf 'token-a\n' ;;
    '.ownerPid // empty') printf '222\n' ;;
    '.phase // empty') printf 'rollback\n' ;;
    *) return 1 ;;
  esac
}
kill() { [[ "$1" == "-0" && "$2" == "222" ]]; }
process_descends_from() { [[ "$descends" == "yes" && "$1" == "222" && "$2" == "111" ]]; }
host_storage_mutation_active 111 "$2" token-a && printf 'valid\n'
host_storage_mutation_active 111 "$2" token-b || printf 'wrong-token-rejected\n'
descends=no
host_storage_mutation_active 111 "$2" token-a || printf 'cross-process-rejected\n'
"#,
            "fault-mutation-state-test",
            script,
            marker.to_str().expect("marker path"),
        ])
        .output()
        .expect("validate host mutation marker");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "valid\nwrong-token-rejected\ncross-process-rejected\n"
    );
}

#[cfg(unix)]
#[test]
fn wrapper_preserves_unresolved_host_state_after_process_exit() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let marker = temporary.path().join("marker.json");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fault-test.sh");
    for phase in ["active", "rollback", "recovery-required"] {
        let content =
            format!(r#"{{"schemaVersion":1,"token":"token-a","ownerPid":4242,"phase":"{phase}"}}"#);
        std::fs::write(&marker, &content).unwrap();
        let output = Command::new("bash")
            .args([
                "-c",
                r#"
source "$1"
ACTIVE_HOST_MUTATION_STATE_FILE="$2"
ACTIVE_HOST_MUTATION_STATE_TOKEN=token-a
cleanup_host_mutation_state
[[ -z "$ACTIVE_HOST_MUTATION_STATE_FILE" && -z "$ACTIVE_HOST_MUTATION_STATE_TOKEN" ]]
"#,
                "unresolved-host-state-test",
                script,
                marker.to_str().unwrap(),
            ])
            .output()
            .expect("wrapper cleanup");
        assert!(output.status.success());
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), content);
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("preserving unresolved host mutation state")
        );
    }
}

#[tokio::test]
#[ignore = "destructive RustFS workload fault scenario; select with RUSTFS_FAULT_TEST_SCENARIO"]
async fn fault_selected_scenario() -> Result<()> {
    s3chaos::fault::runner::run_selected_scenario_from_env().await
}
