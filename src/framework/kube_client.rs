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
use kube::{
    Api, Client, Config,
    config::{KubeConfigOptions, Kubeconfig},
    core::{ApiResource, DynamicObject, GroupVersionKind},
};

pub async fn default_client() -> Result<Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    Ok(Client::try_default().await?)
}

pub async fn client_for_context(context: &str) -> Result<Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let kubeconfig = Kubeconfig::read()?;
    let config = Config::from_custom_kubeconfig(
        kubeconfig,
        &KubeConfigOptions {
            context: Some(context.to_string()),
            ..KubeConfigOptions::default()
        },
    )
    .await?;
    Ok(Client::try_from(config)?)
}

pub fn tenant_api(client: Client, namespace: &str) -> Api<DynamicObject> {
    let resource =
        ApiResource::from_gvk(&GroupVersionKind::gvk("rustfs.com", "v1alpha1", "Tenant"));
    Api::namespaced_with(client, namespace, &resource)
}
