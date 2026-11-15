// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The six cloud providers' `read()`, in `common/secrets.js`'s order: the
//! settings each reads, the refusals each makes before it asks anybody, and
//! — through `aws.rs`, `gcp.rs` and `azure.rs` — the SDK call. A provider
//! whose SDK this build was made without answers `missingModule()`'s
//! STS-KEYS-0045 at the point Node's `require()` would have thrown, so the
//! order of the refusals is Node's too: `aws`, `gcp` and `azure` load their
//! SDK first; the three key management services check their key's name
//! first.

#![cfg_attr(
    not(all(feature = "aws", feature = "gcp", feature = "azure")),
    allow(unused_imports, unused_variables, unreachable_code, dead_code)
)]

use super::forms::{
    aws_key_refusal, azure_key_refusal, azure_kind, gcp_key_refusal,
    is_azure_key_name, is_gcp_key_name,
};
use super::{missing_sdk, Failure, Secret, Secrets, Spec};
use crate::errors::codes;

impl Secrets {
    /// `awsProvider.read()`: AWS Secrets Manager, by name or ARN, in
    /// `reachOf(spec, 'region')` or the SDK's own region.
    #[tracing::instrument(level = "debug", skip_all)]
    pub(super) async fn read_aws(
        &self,
        spec: &'static Spec,
    ) -> Result<Secret, Failure> {
        let (secret_id, borrowed) = self.location_of(spec, |s| s.ref_);
        #[cfg(not(feature = "aws"))]
        return Err(missing_sdk("aws"));
        if secret_id.is_empty() {
            return Err(Failure::new(
                codes::STS_KEYS_0046,
                format!(
                    "{} is \"aws\" and {} names no secret. Set it to the \
                     secret's name or ARN.",
                    spec.provider, spec.ref_
                ),
            ));
        }
        let region = self.reach_of(spec, |s| s.region);
        #[cfg(feature = "aws")]
        {
            let value =
                super::aws::secret_value(&self.env, &region, &secret_id)
                    .await?;
            tracing::info!(
                "secrets: {} was read from AWS Secrets Manager ({}).",
                spec.label,
                secret_id
            );
            return self.pick(value, spec, borrowed);
        }
        #[allow(unreachable_code)]
        Err(missing_sdk("aws"))
    }

    /// `gcpProvider.read()`: Google Secret Manager, by resource name; a
    /// name with no `/versions/` is completed with `/versions/latest`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub(super) async fn read_gcp(
        &self,
        spec: &'static Spec,
    ) -> Result<Secret, Failure> {
        let (name, borrowed) = self.location_of(spec, |s| s.ref_);
        #[cfg(not(feature = "gcp"))]
        return Err(missing_sdk("gcp"));
        if name.is_empty() {
            return Err(Failure::new(
                codes::STS_KEYS_0046,
                format!(
                    "{} is \"gcp\" and {} names no secret. Set it to \
                     projects/<project>/secrets/<name> (a /versions/<n> \
                     suffix is optional).",
                    spec.provider, spec.ref_
                ),
            ));
        }
        let name = if name.contains("/versions/") {
            name
        } else {
            format!("{}/versions/latest", name.trim_end_matches('/'))
        };
        #[cfg(feature = "gcp")]
        {
            let emulator = self.emulators.get().and_then(|e| e.gcp.clone());
            let Some(payload) =
                super::gcp::access(emulator.as_deref(), &name).await?
            else {
                return Err(Failure::new(
                    codes::STS_KEYS_0048,
                    format!(
                        "the secret version \"{}\" carries no payload",
                        name
                    ),
                ));
            };
            tracing::info!(
                "secrets: {} was read from Google Cloud Secret Manager ({}).",
                spec.label,
                name
            );
            let text = String::from_utf8_lossy(&payload);
            let value = Secret::Value {
                bytes: crate::settings::js_trim(&text).as_bytes().to_vec(),
                text: true,
            };
            return self.pick(value, spec, borrowed);
        }
        #[allow(unreachable_code)]
        Err(missing_sdk("gcp"))
    }

    /// `azureProvider.read()`: an Azure Key Vault secret, by name, in the
    /// vault `reachOf(spec, 'vault')` names.
    #[tracing::instrument(level = "debug", skip_all)]
    pub(super) async fn read_azure(
        &self,
        spec: &'static Spec,
    ) -> Result<Secret, Failure> {
        let (name, borrowed) = self.location_of(spec, |s| s.ref_);
        #[cfg(not(feature = "azure"))]
        return Err(missing_sdk("azure"));
        let vault = self.reach_of(spec, |s| s.vault);
        if vault.is_empty() || name.is_empty() {
            return Err(Failure::new(
                codes::STS_KEYS_0046,
                format!(
                    "{} is \"azure\" and it needs both {} \
                     (https://<name>.vault.azure.net) and {} (the secret \
                     name).",
                    spec.provider,
                    spec.vault.unwrap_or("keys.kekVault"),
                    spec.ref_
                ),
            ));
        }
        #[cfg(feature = "azure")]
        {
            let value = super::azure::secret_value(self, &vault, &name).await?;
            let value = match value {
                Some(v) if !v.is_empty() => v,
                _ => {
                    return Err(Failure::new(
                        codes::STS_KEYS_0048,
                        format!(
                            "the secret \"{}\" in {} has no value",
                            name, vault
                        ),
                    ))
                }
            };
            tracing::info!(
                "secrets: {} was read from Azure Key Vault ({}, {}).",
                spec.label,
                vault,
                name
            );
            let value = Secret::Value {
                bytes: crate::settings::js_trim(&value).as_bytes().to_vec(),
                text: true,
            };
            return self.pick(value, spec, borrowed);
        }
        #[allow(unreachable_code)]
        Err(missing_sdk("azure"))
    }

    /// `awsKmsProvider.read()`: a symmetric ENCRYPT_DECRYPT key, by id,
    /// ARN or alias.
    #[tracing::instrument(level = "debug", skip_all)]
    pub(super) async fn aws_kms(
        &self,
        spec: &'static Spec,
    ) -> Result<Secret, Failure> {
        let (key_id, _) = self.location_of(spec, |s| s.ref_);
        if key_id.is_empty() {
            return Err(Failure::new(
                codes::STS_KEYS_0046,
                format!(
                    "{} is \"aws-kms\" and {} names no key. Set it to the \
                     KMS key's id, ARN or alias.",
                    spec.provider, spec.ref_
                ),
            ));
        }
        #[cfg(feature = "aws")]
        {
            let region = self.reach_of(spec, |s| s.region);
            let (facts, handle) =
                super::aws::kms(&self.env, &region, &key_id).await?;
            if let Some(why) = aws_key_refusal(
                &key_id,
                facts.usage.as_deref(),
                facts.spec.as_deref(),
                facts.enabled,
            ) {
                return Err(Failure::new(codes::STS_KEYS_0102, why));
            }
            tracing::info!(
                "secrets: {} is the AWS KMS key \"{}\"; it never leaves the \
                 KMS, which wraps each data key.",
                spec.label,
                facts.arn.as_deref().unwrap_or(&key_id)
            );
            return Ok(Secret::Remote(handle));
        }
        #[allow(unreachable_code)]
        Err(missing_sdk("aws-kms"))
    }

    /// `gcpKmsProvider.read()`: a CryptoKey of GOOGLE_SYMMETRIC_ENCRYPTION
    /// with an enabled primary version, by its resource name.
    #[tracing::instrument(level = "debug", skip_all)]
    pub(super) async fn gcp_kms(
        &self,
        spec: &'static Spec,
    ) -> Result<Secret, Failure> {
        let (given, _) = self.location_of(spec, |s| s.ref_);
        let name = given.trim_end_matches('/').to_string();
        if name.is_empty() {
            return Err(Failure::new(
                codes::STS_KEYS_0046,
                format!(
                    "{} is \"gcp-kms\" and {} names no key. Set it to \
                     projects/<project>/locations/<location>/keyRings/<ring>/\
                     cryptoKeys/<key>.",
                    spec.provider, spec.ref_
                ),
            ));
        }
        if !is_gcp_key_name(&name) {
            return Err(Failure::new(
                codes::STS_KEYS_0102,
                format!(
                    "{} is \"{}\", which is not a CryptoKey's resource name. \
                     Name the key, not one of its versions: projects/\
                     <project>/locations/<location>/keyRings/<ring>/\
                     cryptoKeys/<key>.",
                    spec.ref_, name
                ),
            ));
        }
        #[cfg(feature = "gcp")]
        {
            let emulator = self.emulators.get().and_then(|e| e.gcp.clone());
            let (facts, handle) =
                super::gcp::kms(emulator.as_deref(), &name).await?;
            if let Some(why) = gcp_key_refusal(
                &name,
                facts.purpose.as_deref(),
                facts.algorithm.as_deref(),
                facts.primary_state.as_deref(),
            ) {
                return Err(Failure::new(codes::STS_KEYS_0102, why));
            }
            tracing::info!(
                "secrets: {} is the Cloud KMS key \"{}\" (primary version \
                 {}); it never leaves the KMS, which wraps each data key.",
                spec.label,
                name,
                facts.primary_version
            );
            return Ok(Secret::Remote(handle));
        }
        #[allow(unreachable_code)]
        Err(missing_sdk("gcp-kms"))
    }

    /// `azureKeysProvider.read()`: an oct-HSM key, or an RSA key of at
    /// least 3072 bits, in a Key Vault or Managed HSM.
    #[tracing::instrument(level = "debug", skip_all)]
    pub(super) async fn azure_keys(
        &self,
        spec: &'static Spec,
    ) -> Result<Secret, Failure> {
        let (name, _) = self.location_of(spec, |s| s.ref_);
        let vault = self.reach_of(spec, |s| s.vault);
        let vault = vault.trim_end_matches('/').to_string();
        if vault.is_empty() || name.is_empty() {
            return Err(Failure::new(
                codes::STS_KEYS_0046,
                format!(
                    "{} is \"azure-keys\" and it needs both {} \
                     (https://<name>.vault.azure.net, or a Managed HSM's \
                     URL) and {} (the key's name).",
                    spec.provider,
                    spec.vault.unwrap_or("keys.kekVault"),
                    spec.ref_
                ),
            ));
        }
        if !is_azure_key_name(&name) {
            return Err(Failure::new(
                codes::STS_KEYS_0102,
                format!(
                    "{} is \"{}\", which is not a Key Vault key name \
                     (letters, digits and \"-\").",
                    spec.ref_, name
                ),
            ));
        }
        #[cfg(feature = "azure")]
        {
            let facts = super::azure::key_facts(self, &vault, &name).await?;
            if let Some(why) = azure_key_refusal(
                &name,
                &vault,
                &facts.kty,
                facts.enabled,
                &facts.ops,
                facts.bits,
            ) {
                return Err(Failure::new(codes::STS_KEYS_0102, why));
            }
            let (_, rsa) = azure_kind(&facts.kty);
            let handle =
                super::azure::handle(self, &vault, &name, facts.clone(), rsa)?;
            tracing::info!(
                "secrets: {} is the Key Vault key \"{}/keys/{}\" ({}{}, \
                 version {}); it never leaves the vault, which wraps each \
                 data key.",
                spec.label,
                vault,
                name,
                facts.kty,
                if facts.bits > 0 {
                    format!(" {}-bit", facts.bits)
                } else {
                    String::new()
                },
                facts.version
            );
            return Ok(Secret::Remote(handle));
        }
        #[allow(unreachable_code)]
        Err(missing_sdk("azure-keys"))
    }
}
