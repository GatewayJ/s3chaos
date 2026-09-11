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

use crate::framework::{command::CommandOutput, config::ClusterTestConfig, kubectl::Kubectl};
use anyhow::{Context, Result, bail, ensure};

const REMOTE_EXIT_MARKER: &str = "__S3CHAOS_HOST_COMMAND_EXIT__=";
const REMOTE_COMMAND_WRAPPER: &str = r#"self_mount_namespace=$(/usr/bin/readlink /proc/self/ns/mnt)
host_mount_namespace=$(/usr/bin/readlink /proc/1/ns/mnt)
if [ -z "$self_mount_namespace" ] || [ "$self_mount_namespace" != "$host_mount_namespace" ]; then
    printf 'host command did not enter PID 1 mount namespace\n' >&2
    status=125
else
    "$@"
    status=$?
fi
printf '\n__S3CHAOS_HOST_COMMAND_EXIT__=%s\n' "$status"
exit 0"#;

pub(super) fn run<I, S>(
    config: &ClusterTestConfig,
    namespace: &str,
    pod: &str,
    args: I,
) -> Result<CommandOutput>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let output = Kubectl::new(config)
        .namespaced(namespace)
        .command(command_args(pod, args))
        .run()?;
    decode_output(output).context("decode host command result from kubectl exec")
}

pub(super) fn run_checked<I, S>(
    config: &ClusterTestConfig,
    namespace: &str,
    pod: &str,
    args: I,
) -> Result<CommandOutput>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let output = run(config, namespace, pod, args)?;
    if output.code == Some(0) {
        Ok(output)
    } else {
        bail!(
            "host command failed: exit={:?}, stdout={}, stderr={}",
            output.code,
            output.stdout,
            output.stderr
        )
    }
}

fn command_args<I, S>(pod: &str, args: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut command = vec![
        "exec".to_string(),
        pod.to_string(),
        "--".to_string(),
        "chroot".to_string(),
        "/host".to_string(),
        "/usr/bin/nsenter".to_string(),
        "--target".to_string(),
        "1".to_string(),
        "--mount".to_string(),
        "--root".to_string(),
        "--wd".to_string(),
        "--".to_string(),
        "/bin/sh".to_string(),
        "-c".to_string(),
        REMOTE_COMMAND_WRAPPER.to_string(),
        "s3chaos-host-command".to_string(),
    ];
    command.extend(args.into_iter().map(Into::into));
    command
}

fn decode_output(output: CommandOutput) -> Result<CommandOutput> {
    ensure!(
        output.code == Some(0),
        "kubectl exec transport failed before the host command result was captured: exit={:?}, stdout={}, stderr={}",
        output.code,
        output.stdout,
        output.stderr
    );
    let framed = output.stdout.strip_suffix('\n').unwrap_or(&output.stdout);
    let (stdout, status) = framed
        .rsplit_once('\n')
        .context("host command result lacks its remote exit marker")?;
    let code = status
        .strip_prefix(REMOTE_EXIT_MARKER)
        .context("host command result has an invalid remote exit marker")?
        .parse::<i32>()
        .context("host command result has an invalid remote exit code")?;
    ensure!(code >= 0, "host command returned a negative exit code");
    Ok(CommandOutput {
        code: Some(code),
        stdout: stdout.to_string(),
        stderr: output.stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::{REMOTE_COMMAND_WRAPPER, command_args, decode_output};
    use crate::framework::command::CommandOutput;

    #[test]
    fn host_command_enters_pid_one_mount_namespace_and_preserves_arguments() {
        let command = command_args("helper", ["/usr/bin/findmnt", "--mountpoint", "/data/pv"]);

        assert_eq!(
            &command[..12],
            [
                "exec",
                "helper",
                "--",
                "chroot",
                "/host",
                "/usr/bin/nsenter",
                "--target",
                "1",
                "--mount",
                "--root",
                "--wd",
                "--",
            ]
        );
        assert_eq!(command[12], "/bin/sh");
        assert_eq!(command[13], "-c");
        assert_eq!(command[14], REMOTE_COMMAND_WRAPPER);
        assert!(
            REMOTE_COMMAND_WRAPPER.contains("/proc/self/ns/mnt")
                && REMOTE_COMMAND_WRAPPER.contains("/proc/1/ns/mnt")
        );
        assert_eq!(
            &command[15..],
            [
                "s3chaos-host-command",
                "/usr/bin/findmnt",
                "--mountpoint",
                "/data/pv",
            ]
        );
    }

    #[test]
    fn host_command_decoder_separates_remote_exit_from_kubectl_transport() {
        let output = decode_output(CommandOutput {
            code: Some(0),
            stdout: "line without trailing newline\n__S3CHAOS_HOST_COMMAND_EXIT__=1\n".to_string(),
            stderr: String::new(),
        })
        .expect("decode output");

        assert_eq!(output.code, Some(1));
        assert_eq!(output.stdout, "line without trailing newline");
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn host_command_decoder_preserves_command_newlines_and_stderr() {
        let output = decode_output(CommandOutput {
            code: Some(0),
            stdout: "first\nsecond\n\n__S3CHAOS_HOST_COMMAND_EXIT__=7\n".to_string(),
            stderr: "remote diagnostic\n".to_string(),
        })
        .expect("decode output");

        assert_eq!(output.code, Some(7));
        assert_eq!(output.stdout, "first\nsecond\n");
        assert_eq!(output.stderr, "remote diagnostic\n");
    }

    #[test]
    fn host_command_decoder_rejects_transport_and_framing_failures() {
        assert!(
            decode_output(CommandOutput {
                code: Some(1),
                stdout: String::new(),
                stderr: "pod unavailable".to_string(),
            })
            .is_err()
        );
        assert!(
            decode_output(CommandOutput {
                code: Some(0),
                stdout: "unframed".to_string(),
                stderr: String::new(),
            })
            .is_err()
        );
    }
}
