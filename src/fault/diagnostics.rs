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

const ERASURE_READ_QUORUM: &str = "erasure read quorum";
const DNS_LOOKUP_FAILURE: &str = "failed to lookup address information";

pub(crate) fn diagnose_rustfs_snapshot(snapshot: &str) -> String {
    let mut lines = vec![
        "RustFS Operator test diagnostic summary".to_string(),
        String::new(),
    ];
    let mut matched = false;

    if snapshot.contains(ERASURE_READ_QUORUM) {
        matched = true;
        lines.extend([
            format!("Detected `{ERASURE_READ_QUORUM}` in RustFS pod logs."),
            "Meaning: RustFS ECStore could not read a majority of matching erasure format metadata during startup.".to_string(),
            "Most likely test causes: stale or partially initialized volumes, peer startup/DNS timing, or a RustFS bootstrap retry window that ended before quorum converged.".to_string(),
            "Inspect: rustfs-pods-current.log, rustfs-pods-previous.log, tenant-describe.txt, rustfs-pods-describe.txt, and pv-paths.txt.".to_string(),
            String::new(),
        ]);
    }

    if snapshot.contains(DNS_LOOKUP_FAILURE) {
        matched = true;
        lines.extend([
            format!("Detected `{DNS_LOOKUP_FAILURE}` in RustFS pod logs."),
            "Meaning: a RustFS peer hostname was not resolvable during early pod startup. Check the headless Service, endpoint publication, and whether pods recovered after restart.".to_string(),
            String::new(),
        ]);
    }

    if !matched {
        lines.push(
            "No built-in RustFS bootstrap signature was detected. Inspect the collected Kubernetes snapshot files for the first failing pod event or container log.".to_string(),
        );
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::diagnose_rustfs_snapshot;

    #[test]
    fn diagnosis_explains_erasure_read_quorum() {
        let diagnosis = diagnose_rustfs_snapshot(
            "[FATAL] store init failed to load formats after 10 retries: erasure read quorum",
        );

        assert!(diagnosis.contains("Detected `erasure read quorum`"));
        assert!(diagnosis.contains("ECStore could not read a majority"));
        assert!(diagnosis.contains("stale or partially initialized volumes"));
    }

    #[test]
    fn diagnosis_explains_dns_lookup_failure() {
        let diagnosis = diagnose_rustfs_snapshot("failed to lookup address information: Try again");

        assert!(diagnosis.contains("Detected `failed to lookup address information`"));
        assert!(diagnosis.contains("headless Service"));
    }
}
