// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! AWS Secrets Manager (`aws`) and AWS KMS (`aws-kms`), through the
//! official SDK: `awsProvider` and `awsKmsProvider` in `common/secrets.js`.
//!
//! **The credential chain is the SDK's own** (`aws-config`'s default chain,
//! as `@aws-sdk/*`'s `defaultProvider` is Node's): the environment
//! (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`), the
//! shared config and credentials files with their SSO and `credential_process`
//! profiles, a web identity token (`AWS_WEB_IDENTITY_TOKEN_FILE` and
//! `AWS_ROLE_ARN`, which is EKS's IRSA), the ECS task role and the EC2
//! instance role. `AWS_ENDPOINT_URL` (and `AWS_ENDPOINT_URL_KMS`,
//! `…_SECRETS_MANAGER`) is honoured by both SDKs, which is how a test
//! reaches LocalStack.
//!
//! **The region** is `keys.kekRegion` (or the secret's own row); empty, it
//! is what Node's SDK resolves — `AWS_REGION`, then the shared config file —
//! and NOT the Rust SDK's wider default, which would also read
//! `AWS_DEFAULT_REGION` and ask the instance metadata service: a region
//! Node would not have found is not one this runtime may quietly use.

use std::collections::HashMap;
use std::sync::Arc;

use aws_config::meta::region::RegionProviderChain;
use aws_config::profile::ProfileFileRegionProvider;
use aws_config::{BehaviorVersion, Region, SdkConfig};
use aws_sdk_kms::error::{DisplayErrorContext, ProvideErrorMetadata};
use aws_sdk_kms::primitives::Blob;

use super::forms::{aws_context, b64, no_bytes, node_base64};
use super::{kms_parts, kms_text, BoxFuture, Failure, RemoteKek, Secret};
use crate::errors::codes;

/// The SDK's configuration for one read, Node's `{ region }` or `{}`.
async fn config(env: &HashMap<String, String>, region: &str) -> SdkConfig {
    let named = if region.is_empty() {
        env.get("AWS_REGION")
            .map(|r| r.trim().to_string())
            .filter(|r| !r.is_empty())
    } else {
        Some(region.to_string())
    };
    let loader = aws_config::defaults(BehaviorVersion::latest());
    let loader = match named {
        Some(r) => loader.region(Region::new(r)),
        None => loader.region(RegionProviderChain::first_try(
            ProfileFileRegionProvider::new(),
        )),
    };
    loader.load().await
}

/// What a failed call said: the service's own message, as Node's error
/// carries it, else the whole chain of causes.
fn said<E>(e: &aws_sdk_kms::error::SdkError<E>) -> Failure
where
    E: ProvideErrorMetadata + std::error::Error + 'static,
{
    match e.message() {
        Some(m) if !m.is_empty() => Failure::uncoded(m.to_string()),
        _ => Failure::uncoded(DisplayErrorContext(e).to_string()),
    }
}

/// `GetSecretValueCommand`: `SecretString` as text, untrimmed, else
/// `SecretBinary` as bytes — both are legitimate, a pasted key and
/// `put-secret-value --secret-binary`.
#[tracing::instrument(level = "debug", skip_all)]
pub(super) async fn secret_value(
    env: &HashMap<String, String>,
    region: &str,
    secret_id: &str,
) -> Result<Secret, Failure> {
    let client =
        aws_sdk_secretsmanager::Client::new(&config(env, region).await);
    let answer = client
        .get_secret_value()
        .secret_id(secret_id)
        .send()
        .await
        .map_err(|e| said(&e))?;
    Ok(match answer.secret_string() {
        Some(text) => Secret::Value {
            bytes: text.as_bytes().to_vec(),
            text: true,
        },
        None => Secret::Value {
            bytes: answer
                .secret_binary()
                .map(|b| b.as_ref().to_vec())
                .unwrap_or_default(),
            text: false,
        },
    })
}

/// What `DescribeKey` says of the key, for `aws_key_refusal()`.
pub(super) struct KeyFacts {
    pub usage: Option<String>,
    pub spec: Option<String>,
    pub enabled: Option<bool>,
    pub arn: Option<String>,
}

/// The key, described, and its handle.
#[tracing::instrument(level = "debug", skip_all)]
pub(super) async fn kms(
    env: &HashMap<String, String>,
    region: &str,
    key_id: &str,
) -> Result<(KeyFacts, Arc<dyn RemoteKek>), Failure> {
    let client = aws_sdk_kms::Client::new(&config(env, region).await);
    let described = client
        .describe_key()
        .key_id(key_id)
        .send()
        .await
        .map_err(|e| said(&e))?;
    let facts = match described.key_metadata() {
        Some(meta) => KeyFacts {
            usage: meta.key_usage().map(|u| u.as_str().to_string()),
            spec: meta.key_spec().map(|s| s.as_str().to_string()).or_else(
                || {
                    // Node reads it as the fallback (`KeySpec ||
                    // CustomerMasterKeySpec`), so this does too.
                    #[allow(deprecated)]
                    meta.customer_master_key_spec()
                        .map(|s| s.as_str().to_string())
                },
            ),
            enabled: Some(meta.enabled()),
            arn: meta.arn().map(String::from),
        },
        None => KeyFacts {
            usage: None,
            spec: None,
            enabled: None,
            arn: None,
        },
    };
    let label =
        format!("AWS KMS key {}", facts.arn.as_deref().unwrap_or(key_id));
    let handle = AwsKms {
        client,
        key_id: key_id.to_string(),
        label,
    };
    Ok((facts, Arc::new(handle)))
}

/// The `aws-kms` handle: the data key's AAD is its encryption context.
struct AwsKms {
    client: aws_sdk_kms::Client,
    key_id: String,
    label: String,
}

impl RemoteKek for AwsKms {
    fn provider(&self) -> &str {
        "aws-kms"
    }

    fn key_ref(&self) -> &str {
        &self.key_id
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
            let (k, v) = aws_context(aad);
            let answer = self
                .client
                .encrypt()
                .key_id(&self.key_id)
                .plaintext(Blob::new(dek.to_vec()))
                .encryption_context(k, v)
                .send()
                .await
                .map_err(|e| said(&e))?;
            // `noBytes()` (#1789): an empty blob is no ciphertext.
            let blob = answer.ciphertext_blob().map(|b| b.as_ref());
            let Some(blob) = blob.filter(|b| !no_bytes(Some(b))) else {
                return Err(Failure::new(
                    codes::STS_KEYS_0103,
                    "AWS KMS answered no ciphertext",
                ));
            };
            Ok(kms_text("aws-kms", &self.key_id, &b64(blob)))
        })
    }

    fn unwrap<'a>(
        &'a self,
        text: &'a str,
        aad: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, Failure>> {
        Box::pin(async move {
            let parts = kms_parts(text)
                .filter(|(p, r, _)| p == "aws-kms" && *r == self.key_id);
            let Some((_, _, ciphertext)) = parts else {
                return Err(Failure::new(
                    codes::STS_KEYS_0103,
                    format!(
                        "the wrapped data key is not under the KMS key \"{}\"",
                        self.key_id
                    ),
                ));
            };
            let (k, v) = aws_context(aad);
            let answer = self
                .client
                .decrypt()
                .key_id(&self.key_id)
                .ciphertext_blob(Blob::new(node_base64(&ciphertext)))
                .encryption_context(k, v)
                .send()
                .await
                .map_err(|e| said(&e))?;
            match answer.plaintext().map(|p| p.as_ref()) {
                Some(plain) if !no_bytes(Some(plain)) => Ok(plain.to_vec()),
                _ => Err(Failure::new(
                    codes::STS_KEYS_0103,
                    "AWS KMS answered no plaintext",
                )),
            }
        })
    }

    fn owns(&self, text: &str) -> bool {
        kms_parts(text)
            .is_some_and(|(p, r, _)| p == "aws-kms" && r == self.key_id)
    }

    /// AWS's own rotation keeps the earlier backing keys behind the same
    /// key id, so nothing here is ever stale.
    fn is_stale(&self, _text: &str) -> bool {
        false
    }

    fn rotate(&self) -> BoxFuture<'_, Result<String, Failure>> {
        Box::pin(async move {
            self.client
                .rotate_key_on_demand()
                .key_id(&self.key_id)
                .send()
                .await
                .map_err(|e| said(&e))?;
            Ok(String::new())
        })
    }
}
