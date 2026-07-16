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
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct ProtocolResourceNamer {
    bucket_prefix: String,
    identity_prefix: String,
    run_token: String,
}

impl ProtocolResourceNamer {
    pub fn new(bucket_prefix: &str, identity_prefix: &str, run_id: &str) -> Result<Self> {
        let run_token = token(run_id, 12);
        let namer = Self {
            bucket_prefix: bucket_prefix.to_string(),
            identity_prefix: identity_prefix.to_string(),
            run_token,
        };
        namer.bucket("validation", 0)?;
        namer.iam_user("validation", 0)?;
        namer.iam_group("validation", 0)?;
        namer.iam_policy("validation", 0)?;
        Ok(namer)
    }

    pub fn bucket(&self, case_id: &str, counter: usize) -> Result<String> {
        let name = format!(
            "{}-{}-{}-{counter}",
            self.bucket_prefix,
            self.run_token,
            token(case_id, 10)
        );
        validate_bucket_name(&name)?;
        Ok(name)
    }

    pub fn for_worker(&self, worker_index: usize) -> Self {
        Self {
            bucket_prefix: self.bucket_prefix.clone(),
            identity_prefix: self.identity_prefix.clone(),
            run_token: token(&format!("{}-worker-{worker_index}", self.run_token), 12),
        }
    }

    pub fn iam_user(&self, case_id: &str, counter: usize) -> Result<String> {
        self.iam_name(case_id, "user", counter)
    }

    pub fn iam_group(&self, case_id: &str, counter: usize) -> Result<String> {
        self.iam_name(case_id, "group", counter)
    }

    pub fn iam_policy(&self, case_id: &str, counter: usize) -> Result<String> {
        self.iam_name(case_id, "policy", counter)
    }

    fn iam_name(&self, case_id: &str, kind: &str, counter: usize) -> Result<String> {
        let name = format!(
            "{}-{}-{}-{kind}-{counter}",
            self.identity_prefix,
            self.run_token,
            token(case_id, 10)
        );
        validate_iam_name(&name)?;
        Ok(name)
    }
}

fn token(value: &str, max_len: usize) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))[..max_len].to_string()
}

pub fn validate_bucket_name(name: &str) -> Result<()> {
    ensure!(
        (3..=63).contains(&name.len()),
        "bucket name must contain 3 to 63 characters"
    );
    ensure!(
        name.bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "bucket name must contain only lowercase letters, digits, and hyphens"
    );
    ensure!(
        !name.starts_with('-') && !name.ends_with('-'),
        "bucket name must not start or end with a hyphen"
    );
    ensure!(
        name.parse::<std::net::IpAddr>().is_err(),
        "bucket name must not have an IP address shape"
    );
    Ok(())
}

pub fn validate_iam_name(name: &str) -> Result<()> {
    ensure!(
        (1..=64).contains(&name.len()),
        "IAM name must contain 1 to 64 characters"
    );
    ensure!(
        name.bytes().all(|byte| byte.is_ascii_alphanumeric()
            || matches!(byte, b'+' | b'=' | b',' | b'.' | b'@' | b'_' | b'-')),
        "IAM name contains unsupported characters"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ProtocolResourceNamer;

    #[test]
    fn long_and_unusual_case_ids_produce_valid_stable_names() {
        let namer = ProtocolResourceNamer::new(
            "s3c",
            "s3chaos",
            "protocol-019f5664-37ed-75a3-ba3f-3837c16c03dd",
        )
        .expect("namer");
        let case_id = "Bucket Policy / a very long case id with unusual characters !!!";
        let first = namer.bucket(case_id, 1).expect("bucket");
        let second = namer.bucket(case_id, 1).expect("bucket");
        assert_eq!(first, second);
        assert!(first.len() <= 63);
        assert!(namer.iam_user(case_id, 1).expect("user").len() <= 64);
    }

    #[test]
    fn similar_long_case_ids_do_not_collide() {
        let namer = ProtocolResourceNamer::new("s3c", "s3chaos", "run").expect("namer");
        let first = namer
            .bucket("bucket-policy-same-prefix-first", 0)
            .expect("first");
        let second = namer
            .bucket("bucket-policy-same-prefix-second", 0)
            .expect("second");
        assert_ne!(first, second);
    }

    #[test]
    fn worker_scoped_namers_never_share_external_resource_names() {
        let namer = ProtocolResourceNamer::new("s3c", "s3chaos", "run").expect("namer");
        let first = namer.for_worker(0);
        let second = namer.for_worker(1);
        assert_ne!(
            first.bucket("parallel-case", 0).expect("first bucket"),
            second.bucket("parallel-case", 0).expect("second bucket")
        );
        assert_ne!(
            first.iam_user("parallel-case", 0).expect("first user"),
            second.iam_user("parallel-case", 0).expect("second user")
        );
    }
}
