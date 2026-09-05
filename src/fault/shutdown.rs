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

use anyhow::{Context, Result, bail};
use std::future::Future;

pub async fn run_signal_aware<F>(operation: F) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    run_until_shutdown(operation, shutdown_signal()?).await
}

async fn run_until_shutdown<F, S>(operation: F, shutdown: S) -> Result<()>
where
    F: Future<Output = Result<()>>,
    S: Future<Output = Result<&'static str>>,
{
    let mut operation = Box::pin(operation);
    let mut shutdown = Box::pin(shutdown);
    let signal = tokio::select! {
        result = &mut operation => return result,
        signal = &mut shutdown => signal?,
    };

    // Cancellation drops the complete fault-run future before returning to the
    // shell wrapper, synchronously running storage/Chaos guards and rollback.
    drop(operation);
    bail!("fault execution interrupted by {signal} after graceful unwind")
}

#[cfg(unix)]
fn shutdown_signal() -> Result<impl Future<Output = Result<&'static str>>> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = signal(SignalKind::interrupt()).context("listen for SIGINT")?;
    let mut terminate = signal(SignalKind::terminate()).context("listen for SIGTERM")?;
    let mut hangup = signal(SignalKind::hangup()).context("listen for SIGHUP")?;
    Ok(async move {
        tokio::select! {
            signal = interrupt.recv() => {
                signal.context("SIGINT listener closed")?;
                Ok("SIGINT")
            }
            signal = terminate.recv() => {
                signal.context("SIGTERM listener closed")?;
                Ok("SIGTERM")
            }
            signal = hangup.recv() => {
                signal.context("SIGHUP listener closed")?;
                Ok("SIGHUP")
            }
        }
    })
}

#[cfg(not(unix))]
fn shutdown_signal() -> Result<impl Future<Output = Result<&'static str>>> {
    Ok(async {
        tokio::signal::ctrl_c()
            .await
            .context("listen for shutdown signal")?;
        Ok("shutdown signal")
    })
}

#[cfg(test)]
mod tests {
    use super::run_until_shutdown;
    use anyhow::Result;
    use std::{
        future::{pending, ready},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    struct RestoreProbe(Arc<AtomicBool>);

    impl Drop for RestoreProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn shutdown_drops_fault_future_before_returning() {
        let restored = Arc::new(AtomicBool::new(false));
        let operation = {
            let restored = Arc::clone(&restored);
            async move {
                let _guard = RestoreProbe(restored);
                pending::<()>().await;
                Ok(())
            }
        };

        let shutdown = async {
            tokio::task::yield_now().await;
            Ok("SIGTERM")
        };
        let error = run_until_shutdown(operation, shutdown)
            .await
            .expect_err("shutdown must interrupt the operation");

        assert!(error.to_string().contains("SIGTERM"));
        assert!(restored.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn operation_result_wins_without_waiting_for_shutdown() -> Result<()> {
        run_until_shutdown(ready(Ok(())), pending()).await
    }
}
