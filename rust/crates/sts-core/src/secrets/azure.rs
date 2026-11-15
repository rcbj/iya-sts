// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Azure Key Vault secrets (`azure`) and keys (`azure-keys`), through
//! Azure's official Rust crates (`azure_security_keyvault_secrets`,
//! `azure_security_keyvault_keys`, `azure_identity`): `azureProvider` and
//! `azureKeysProvider` in `common/secrets.js`.
//!
//! **THE CREDENTIAL IS JAVASCRIPT'S `DefaultAzureCredential`, WALKED HERE.**
//! The Rust SDK has no `DefaultAzureCredential` — Microsoft left it out on
//! purpose — so [`DefaultChain`] tries what `@azure/identity` 4's does, in
//! its order, and keeps the first that answers:
//!
//!   1. **EnvironmentCredential**: `AZURE_TENANT_ID` and `AZURE_CLIENT_ID`
//!      with `AZURE_CLIENT_SECRET`, or with `AZURE_CLIENT_CERTIFICATE_PATH`
//!      (a PEM, made PKCS#12 by the [`KmsCrypto`] slot, or a PFX) and
//!      `AZURE_CLIENT_CERTIFICATE_PASSWORD`. `AZURE_USERNAME` and
//!      `AZURE_PASSWORD`, which JavaScript still accepts and Microsoft has
//!      deprecated, have no Rust credential and are reported unavailable;
//!   2. **WorkloadIdentityCredential**: `AZURE_FEDERATED_TOKEN_FILE` (AKS);
//!   3. **ManagedIdentityCredential**: App Service's `IDENTITY_ENDPOINT` and
//!      `IDENTITY_HEADER`, else the instance metadata service, user-assigned
//!      by `AZURE_CLIENT_ID` when it is set, as JavaScript's is;
//!   4. **AzureCliCredential** and 6. **AzureDeveloperCliCredential** (5,
//!      Azure PowerShell, has no Rust credential).
//!
//! `AZURE_TOKEN_CREDENTIALS` narrows it as it does in JavaScript: `prod`
//! (1–3), `dev` (4–6), or one credential's name.
//!
//! **Each data key is wrapped under the version this handle holds**
//! (`cryptoFor(latest)`): the version `getKey` named, or the one a rotation
//! made, so the stored text names the version a later unwrap must ask for.
//!
//! TLS is rustls under the reqwest Azure's and Google's libraries share,
//! trusting the platform's roots (`SSL_CERT_FILE` replaces them), where
//! Node's is its own bundle plus `NODE_EXTRA_CA_CERTS`.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use azure_core::credentials::{
    AccessToken, Secret as AzureSecret, SecretBytes, TokenCredential,
    TokenRequestOptions,
};
use azure_identity::{
    AzureCliCredential, AzureDeveloperCliCredential,
    ClientCertificateCredential, ClientCertificateCredentialOptions,
    ClientSecretCredential, ManagedIdentityCredential,
    ManagedIdentityCredentialOptions, UserAssignedId,
    WorkloadIdentityCredential,
};
use azure_security_keyvault_keys::models::{
    EncryptionAlgorithm, Key, KeyClientDecryptOptions, KeyClientEncryptOptions,
    KeyClientUnwrapKeyOptions, KeyClientWrapKeyOptions, KeyOperationParameters,
    KeyOperationResult,
};
use azure_security_keyvault_keys::{KeyClient, ResourceExt};
use azure_security_keyvault_secrets::SecretClient;

use super::forms::{azure_body, azure_version_prefix, b64, node_base64};
use super::{
    kms_parts, kms_text, BoxFuture, Failure, KmsCrypto, RemoteKek, Secrets,
};
use crate::errors::codes;

/// What a failed call said.
fn said(e: &azure_core::Error) -> Failure {
    Failure::uncoded(e.to_string())
}

/// One member of the chain, or why it could not be made.
type Member = (&'static str, Result<Arc<dyn TokenCredential>, String>);

/// `DefaultAzureCredential`, as `@azure/identity` 4 builds it (see the
/// module comment).
pub(super) struct DefaultChain {
    members: Vec<Member>,
    chosen: Mutex<Option<usize>>,
}

impl fmt::Debug for DefaultChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DefaultChain").finish_non_exhaustive()
    }
}

impl DefaultChain {
    fn new(
        env: &HashMap<String, String>,
        crypto: Option<&Arc<dyn KmsCrypto>>,
    ) -> DefaultChain {
        let var = |k: &str| {
            env.get(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let mut members: Vec<Member> = vec![
            ("EnvironmentCredential", environment(&var, crypto)),
            (
                "WorkloadIdentityCredential",
                match var("AZURE_FEDERATED_TOKEN_FILE") {
                    Some(_) => WorkloadIdentityCredential::new(None)
                        .map(|c| c as Arc<dyn TokenCredential>)
                        .map_err(|e| e.to_string()),
                    None => Err("AZURE_FEDERATED_TOKEN_FILE is not set".into()),
                },
            ),
            (
                "ManagedIdentityCredential",
                ManagedIdentityCredential::new(Some(
                    ManagedIdentityCredentialOptions {
                        user_assigned_id: var("AZURE_CLIENT_ID")
                            .map(UserAssignedId::ClientId),
                        ..Default::default()
                    },
                ))
                .map(|c| c as Arc<dyn TokenCredential>)
                .map_err(|e| e.to_string()),
            ),
            (
                "AzureCliCredential",
                AzureCliCredential::new(None)
                    .map(|c| c as Arc<dyn TokenCredential>)
                    .map_err(|e| e.to_string()),
            ),
            (
                "AzurePowerShellCredential",
                Err("Azure PowerShell has no credential in the Rust SDK".into()),
            ),
            (
                "AzureDeveloperCliCredential",
                AzureDeveloperCliCredential::new(None)
                    .map(|c| c as Arc<dyn TokenCredential>)
                    .map_err(|e| e.to_string()),
            ),
        ];
        match var("AZURE_TOKEN_CREDENTIALS")
            .map(|v| v.to_ascii_lowercase())
            .as_deref()
        {
            Some("prod") => members.truncate(3),
            Some("dev") => {
                members.drain(..3);
            }
            Some(name) => {
                members.retain(|(n, _)| n.to_ascii_lowercase() == name);
            }
            None => {}
        }
        DefaultChain {
            members,
            chosen: Mutex::new(None),
        }
    }
}

/// EnvironmentCredential's three shapes.
fn environment(
    var: &dyn Fn(&str) -> Option<String>,
    crypto: Option<&Arc<dyn KmsCrypto>>,
) -> Result<Arc<dyn TokenCredential>, String> {
    let (Some(tenant), Some(client)) =
        (var("AZURE_TENANT_ID"), var("AZURE_CLIENT_ID"))
    else {
        return Err(
            "AZURE_TENANT_ID and AZURE_CLIENT_ID are not both set".into()
        );
    };
    if let Some(secret) = var("AZURE_CLIENT_SECRET") {
        return ClientSecretCredential::new(
            &tenant,
            client,
            AzureSecret::new(secret),
            None,
        )
        .map(|c| c as Arc<dyn TokenCredential>)
        .map_err(|e| e.to_string());
    }
    if let Some(path) = var("AZURE_CLIENT_CERTIFICATE_PATH") {
        let password =
            var("AZURE_CLIENT_CERTIFICATE_PASSWORD").unwrap_or_default();
        let bytes =
            std::fs::read(&path).map_err(|e| format!("{}: {}", path, e))?;
        let (pkcs12, password) =
            if bytes.windows(10).any(|w| w == b"-----BEGIN") {
                let Some(slot) = crypto else {
                    return Err(format!(
                        "{} is a PEM, and no KMS crypto slot is installed to \
                         make it PKCS#12",
                        path
                    ));
                };
                (slot.pkcs12_of_pem(&bytes, &password)?, password)
            } else {
                (bytes, password)
            };
        return ClientCertificateCredential::new(
            tenant,
            client,
            SecretBytes::new(pkcs12),
            Some(ClientCertificateCredentialOptions {
                password: (!password.is_empty())
                    .then(|| AzureSecret::new(password)),
                ..Default::default()
            }),
        )
        .map(|c| c as Arc<dyn TokenCredential>)
        .map_err(|e| e.to_string());
    }
    if var("AZURE_USERNAME").is_some() {
        return Err("AZURE_USERNAME and AZURE_PASSWORD have no credential in \
                    the Rust SDK (Microsoft deprecated them)"
            .into());
    }
    Err(
        "neither AZURE_CLIENT_SECRET nor AZURE_CLIENT_CERTIFICATE_PATH is \
         set"
        .into(),
    )
}

#[async_trait::async_trait]
impl TokenCredential for DefaultChain {
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        let chosen =
            *self.chosen.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(i) = chosen {
            if let (_, Ok(one)) = &self.members[i] {
                return one.get_token(scopes, options).await;
            }
        }
        let mut why = Vec::new();
        for (i, (name, member)) in self.members.iter().enumerate() {
            match member {
                Err(e) => why.push(format!("{} is unavailable: {}", name, e)),
                Ok(one) => match one.get_token(scopes, options.clone()).await {
                    Ok(token) => {
                        tracing::info!(
                            "secrets: authenticated to Azure with {}.",
                            name
                        );
                        *self
                            .chosen
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner) = Some(i);
                        return Ok(token);
                    }
                    Err(e) => why.push(format!("{}: {}", name, e)),
                },
            }
        }
        Err(azure_core::Error::with_message(
            azure_core::error::ErrorKind::Credential,
            format!(
                "DefaultAzureCredential: no credential in the chain could \
                 get a token. {}",
                why.join("; ")
            ),
        ))
    }
}

fn chain(secrets: &Secrets) -> Arc<dyn TokenCredential> {
    Arc::new(DefaultChain::new(&secrets.env, secrets.kms_crypto.get()))
}

/// `getSecret(name)`: its value, or `None`.
#[tracing::instrument(level = "debug", skip_all)]
pub(super) async fn secret_value(
    secrets: &Secrets,
    vault: &str,
    name: &str,
) -> Result<Option<String>, Failure> {
    let client =
        SecretClient::new(vault, chain(secrets), None).map_err(|e| said(&e))?;
    let answer = client
        .get_secret(name, None)
        .await
        .map_err(|e| said(&e))?
        .into_model()
        .map_err(|e| said(&e))?;
    Ok(answer.value)
}

/// What `getKey` says of the key, for `azure_key_refusal()`.
#[derive(Clone)]
pub(super) struct KeyFacts {
    pub kty: String,
    pub enabled: Option<bool>,
    pub ops: Vec<String>,
    pub bits: usize,
    pub version: String,
    client: Arc<KeyClient>,
}

/// The version a key or a result names, from its `kid`.
fn version_of(key: &Key) -> String {
    key.resource_id()
        .ok()
        .and_then(|id| id.version)
        .unwrap_or_default()
}

/// The key, read.
#[tracing::instrument(level = "debug", skip_all)]
pub(super) async fn key_facts(
    secrets: &Secrets,
    vault: &str,
    name: &str,
) -> Result<KeyFacts, Failure> {
    let client =
        KeyClient::new(vault, chain(secrets), None).map_err(|e| said(&e))?;
    let key = client
        .get_key(name, None)
        .await
        .map_err(|e| said(&e))?
        .into_model()
        .map_err(|e| said(&e))?;
    let jwk = key.key.clone().unwrap_or_default();
    let kty = jwk
        .kty
        .as_ref()
        .map(|t| t.as_ref().to_string())
        .unwrap_or_default();
    let rsa = kty == "RSA" || kty == "RSA-HSM";
    Ok(KeyFacts {
        bits: if rsa {
            jwk.n.as_ref().map_or(0, |n| n.len() * 8)
        } else {
            0
        },
        kty,
        enabled: key.attributes.as_ref().and_then(|a| a.enabled),
        ops: jwk.key_ops.clone().unwrap_or_default(),
        version: version_of(&key),
        client: Arc::new(client),
    })
}

/// The `azure-keys` handle for a key `key_facts()` read and found usable.
#[tracing::instrument(level = "debug", skip_all)]
pub(super) fn handle(
    secrets: &Secrets,
    vault: &str,
    name: &str,
    facts: KeyFacts,
    rsa: bool,
) -> Result<Arc<dyn RemoteKek>, Failure> {
    let crypto = secrets.kms_crypto.get().cloned();
    if rsa && crypto.is_none() {
        return Err(Failure::uncoded(format!(
            "the Key Vault key \"{}\" is RSA, whose wrapping binds a data key \
             to SHA-256 of its AAD, and no KMS crypto slot is installed to \
             compute it",
            name
        )));
    }
    Ok(Arc::new(AzureKeys {
        client: facts.client.clone(),
        name: name.to_string(),
        key_ref: format!("{}/keys/{}", vault, name),
        label: format!(
            "Key Vault key {}/keys/{} ({}{})",
            vault,
            name,
            facts.kty,
            if facts.bits > 0 {
                format!(" {}", facts.bits)
            } else {
                String::new()
            }
        ),
        symmetric: !rsa,
        latest: Mutex::new(facts.version),
        crypto,
    }))
}

/// The `azure-keys` handle.
struct AzureKeys {
    client: Arc<KeyClient>,
    name: String,
    key_ref: String,
    label: String,
    symmetric: bool,
    latest: Mutex<String>,
    crypto: Option<Arc<dyn KmsCrypto>>,
}

impl AzureKeys {
    fn latest(&self) -> String {
        self.latest
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn digest(&self, aad: &str) -> Vec<u8> {
        self.crypto
            .as_ref()
            .map(|c| c.sha256(aad.as_bytes()))
            .unwrap_or_default()
    }

    fn params(
        algorithm: EncryptionAlgorithm,
        value: Vec<u8>,
    ) -> KeyOperationParameters {
        KeyOperationParameters {
            algorithm: Some(algorithm),
            value: Some(value),
            ..Default::default()
        }
    }

    fn result(
        answer: azure_core::Result<
            azure_core::http::Response<KeyOperationResult>,
        >,
    ) -> Result<KeyOperationResult, Failure> {
        answer
            .map_err(|e| said(&e))?
            .into_model()
            .map_err(|e| said(&e))
    }
}

impl RemoteKek for AzureKeys {
    fn provider(&self) -> &str {
        "azure-keys"
    }

    fn key_ref(&self) -> &str {
        &self.key_ref
    }

    fn label(&self) -> String {
        self.label.clone()
    }

    fn wrap<'a>(
        &'a self,
        dek: &'a [u8],
        aad: &'a str,
    ) -> BoxFuture<'a, Result<String, Failure>> {
        Box::pin(async move {
            let latest = self.latest();
            let body = if self.symmetric {
                let mut ask = AzureKeys::params(
                    EncryptionAlgorithm::A256Gcm,
                    dek.to_vec(),
                );
                ask.additional_authenticated_data =
                    Some(aad.as_bytes().to_vec());
                let answer = AzureKeys::result(
                    self.client
                        .encrypt(
                            &self.name,
                            ask.try_into().map_err(|e| said(&e))?,
                            Some(KeyClientEncryptOptions {
                                key_version: Some(latest.clone()),
                                ..Default::default()
                            }),
                        )
                        .await,
                )?;
                let (Some(ct), Some(iv), Some(tag)) =
                    (answer.result, answer.iv, answer.authentication_tag)
                else {
                    return Err(Failure::new(
                        codes::STS_KEYS_0103,
                        "Key Vault answered no ciphertext",
                    ));
                };
                format!("{}.{}.{}", b64(&iv), b64(&tag), b64(&ct))
            } else {
                let mut plain = dek.to_vec();
                plain.extend(self.digest(aad));
                let answer = AzureKeys::result(
                    self.client
                        .wrap_key(
                            &self.name,
                            AzureKeys::params(
                                EncryptionAlgorithm::RsaOaep256,
                                plain,
                            )
                            .try_into()
                            .map_err(|e| said(&e))?,
                            Some(KeyClientWrapKeyOptions {
                                key_version: Some(latest.clone()),
                                ..Default::default()
                            }),
                        )
                        .await,
                )?;
                let Some(wrapped) = answer.result else {
                    return Err(Failure::new(
                        codes::STS_KEYS_0103,
                        "Key Vault answered no wrapped key",
                    ));
                };
                b64(&wrapped)
            };
            Ok(kms_text(
                "azure-keys",
                &self.key_ref,
                &format!("{}:{}", latest, body),
            ))
        })
    }

    fn unwrap<'a>(
        &'a self,
        text: &'a str,
        aad: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, Failure>> {
        Box::pin(async move {
            let found = kms_parts(text)
                .filter(|(p, r, _)| p == "azure-keys" && *r == self.key_ref)
                .and_then(|(_, _, ct)| azure_body(&ct));
            let Some((version, body)) = found else {
                return Err(Failure::new(
                    codes::STS_KEYS_0103,
                    format!(
                        "the wrapped data key is not under the Key Vault key \
                         \"{}\"",
                        self.key_ref
                    ),
                ));
            };
            if self.symmetric {
                let pieces: Vec<&str> = body.split('.').collect();
                if pieces.len() != 3 {
                    return Err(Failure::new(
                        codes::STS_KEYS_0103,
                        "the wrapped data key is not an A256GCM ciphertext",
                    ));
                }
                let ask = KeyOperationParameters {
                    algorithm: Some(EncryptionAlgorithm::A256Gcm),
                    iv: Some(node_base64(pieces[0])),
                    authentication_tag: Some(node_base64(pieces[1])),
                    value: Some(node_base64(pieces[2])),
                    additional_authenticated_data: Some(
                        aad.as_bytes().to_vec(),
                    ),
                };
                let answer = AzureKeys::result(
                    self.client
                        .decrypt(
                            &self.name,
                            &version,
                            ask.try_into().map_err(|e| said(&e))?,
                            None::<KeyClientDecryptOptions<'_>>,
                        )
                        .await,
                )?;
                return answer.result.ok_or_else(|| {
                    Failure::new(
                        codes::STS_KEYS_0103,
                        "Key Vault answered no plaintext",
                    )
                });
            }
            let answer = AzureKeys::result(
                self.client
                    .unwrap_key(
                        &self.name,
                        &version,
                        AzureKeys::params(
                            EncryptionAlgorithm::RsaOaep256,
                            node_base64(&body),
                        )
                        .try_into()
                        .map_err(|e| said(&e))?,
                        None::<KeyClientUnwrapKeyOptions<'_>>,
                    )
                    .await,
            )?;
            let out = answer.result.unwrap_or_default();
            let want = self.digest(aad);
            let cut = out.len().saturating_sub(want.len());
            let (dek, got) = out.split_at(cut);
            let bound =
                self.crypto.as_ref().is_some_and(|c| c.equal(got, &want));
            if (dek.len() != 32 && dek.len() != 64) || !bound {
                return Err(Failure::new(
                    codes::STS_KEYS_0103,
                    format!(
                        "the wrapped data key unwrapped under \"{}\" but is \
                         bound to another data key's id, scope, realm or \
                         class: it was moved onto this row",
                        self.key_ref
                    ),
                ));
            }
            Ok(dek.to_vec())
        })
    }

    fn owns(&self, text: &str) -> bool {
        kms_parts(text)
            .is_some_and(|(p, r, _)| p == "azure-keys" && r == self.key_ref)
    }

    /// Wrapped under a version that is not the key's current one.
    fn is_stale(&self, text: &str) -> bool {
        let latest = self.latest();
        kms_parts(text)
            .and_then(|(_, _, ct)| azure_version_prefix(&ct))
            .is_some_and(|v| !latest.is_empty() && v != latest)
    }

    /// A new version, made in the vault; the earlier one stays enabled.
    fn rotate(&self) -> BoxFuture<'_, Result<String, Failure>> {
        Box::pin(async move {
            let made = self
                .client
                .rotate_key(&self.name, None)
                .await
                .map_err(|e| said(&e))?
                .into_model()
                .map_err(|e| said(&e))?;
            let version = version_of(&made);
            if version.is_empty() {
                return Err(Failure::new(
                    codes::STS_KEYS_0103,
                    "Key Vault made no new version",
                ));
            }
            *self.latest.lock().unwrap_or_else(PoisonError::into_inner) =
                version.clone();
            Ok(version)
        })
    }
}
