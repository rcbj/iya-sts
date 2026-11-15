// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Google Cloud Secret Manager (`gcp`) and Cloud KMS (`gcp-kms`), through
//! Google's own Rust client libraries (`google-cloud-secretmanager-v1`,
//! `google-cloud-kms-v1`): `gcpProvider` and `gcpKmsProvider` in
//! `common/secrets.js`.
//!
//! **The credentials are Application Default Credentials**, as
//! `google-auth-library` finds them for Node: `GOOGLE_APPLICATION_CREDENTIALS`
//! (a service account key, an external account — workload identity
//! federation — or an authorized user), then gcloud's well-known file, then
//! the metadata server of the VM, Cloud Run service or GKE workload.
//!
//! **The transport differs, and nothing stored does**: Node's libraries
//! speak gRPC and Google's Rust ones the same API's REST binding, which
//! carries the same messages — so the ciphertext, the version names and
//! the AAD are the same bytes. An error is written as grpc-js writes one
//! (`5 NOT_FOUND: …`), so a refusal reads alike in both runtimes.

use std::sync::{Arc, Mutex, PoisonError};

use google_cloud_kms_v1::client::KeyManagementService;
use google_cloud_kms_v1::model::CryptoKeyVersion;
use google_cloud_secretmanager_v1::client::SecretManagerService;

use super::forms::{
    b64, gcp_body, gcp_version_of, gcp_version_prefix, node_base64,
};
use super::{kms_parts, kms_text, BoxFuture, Failure, RemoteKek};
use crate::errors::codes;

/// gRPC's codes, by number, for grpc-js's `<code> <NAME>: <message>`.
const GRPC_CODES: &[&str] = &[
    "OK",
    "CANCELLED",
    "UNKNOWN",
    "INVALID_ARGUMENT",
    "DEADLINE_EXCEEDED",
    "NOT_FOUND",
    "ALREADY_EXISTS",
    "PERMISSION_DENIED",
    "RESOURCE_EXHAUSTED",
    "FAILED_PRECONDITION",
    "ABORTED",
    "OUT_OF_RANGE",
    "UNIMPLEMENTED",
    "INTERNAL",
    "UNAVAILABLE",
    "DATA_LOSS",
    "UNAUTHENTICATED",
];

/// What a failed call said, as grpc-js says it.
fn said(e: &google_cloud_kms_v1::Error) -> Failure {
    match e.status() {
        Some(status) => {
            let name = status.code.name();
            let number =
                GRPC_CODES.iter().position(|n| *n == name).unwrap_or(2);
            Failure::uncoded(format!("{} {}: {}", number, name, status.message))
        }
        None => Failure::uncoded(e.to_string()),
    }
}

/// A client builder pointed at an emulator, with anonymous credentials, or
/// at Google with Application Default Credentials.
macro_rules! client {
    ($kind:ty, $emulator:expr) => {{
        let mut builder = <$kind>::builder();
        if let Some(endpoint) = $emulator {
            builder = builder.with_endpoint(endpoint).with_credentials(
                google_cloud_auth::credentials::anonymous::Builder::new()
                    .build(),
            );
        }
        builder
            .build()
            .await
            .map_err(|e| Failure::uncoded(e.to_string()))?
    }};
}

/// `accessSecretVersion()`: the payload, or `None` when the version
/// carries none.
#[tracing::instrument(level = "debug", skip_all)]
pub(super) async fn access(
    emulator: Option<&str>,
    name: &str,
) -> Result<Option<Vec<u8>>, Failure> {
    let client = client!(SecretManagerService, emulator);
    let answer = client
        .access_secret_version()
        .set_name(name)
        .send()
        .await
        .map_err(|e| said(&e))?;
    Ok(answer.payload.map(|p| p.data.to_vec()))
}

/// What `getCryptoKey` says of the key, for `gcp_key_refusal()`.
pub(super) struct KeyFacts {
    pub purpose: Option<String>,
    pub algorithm: Option<String>,
    pub primary_state: Option<String>,
    pub primary_version: String,
}

/// The key, read, and its handle.
#[tracing::instrument(level = "debug", skip_all)]
pub(super) async fn kms(
    emulator: Option<&str>,
    name: &str,
) -> Result<(KeyFacts, Arc<dyn RemoteKek>), Failure> {
    let client = client!(KeyManagementService, emulator);
    let key = client
        .get_crypto_key()
        .set_name(name)
        .send()
        .await
        .map_err(|e| said(&e))?;
    let primary: Option<&CryptoKeyVersion> = key.primary.as_ref();
    let facts = KeyFacts {
        purpose: key.purpose.name().map(String::from),
        algorithm: key
            .version_template
            .as_ref()
            .and_then(|t| t.algorithm.name().map(String::from)),
        primary_state: primary.and_then(|p| p.state.name().map(String::from)),
        primary_version: primary
            .map(|p| gcp_version_of(&p.name))
            .unwrap_or_default(),
    };
    let handle = GcpKms {
        client,
        name: name.to_string(),
        latest: Mutex::new(facts.primary_version.clone()),
    };
    Ok((facts, Arc::new(handle)))
}

/// The `gcp-kms` handle. `latest` is the version the KMS last encrypted
/// under (or made primary), which `isStale()` measures against.
struct GcpKms {
    client: KeyManagementService,
    name: String,
    latest: Mutex<String>,
}

impl GcpKms {
    fn latest(&self) -> String {
        self.latest
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set_latest(&self, version: &str) {
        *self.latest.lock().unwrap_or_else(PoisonError::into_inner) =
            version.to_string();
    }
}

impl RemoteKek for GcpKms {
    fn provider(&self) -> &str {
        "gcp-kms"
    }

    fn key_ref(&self) -> &str {
        &self.name
    }

    fn label(&self) -> String {
        format!("Cloud KMS key {}", self.name)
    }

    fn wrap<'a>(
        &'a self,
        dek: &'a [u8],
        aad: &'a str,
    ) -> BoxFuture<'a, Result<String, Failure>> {
        Box::pin(async move {
            let answer = self
                .client
                .encrypt()
                .set_name(&self.name)
                .set_plaintext(dek.to_vec())
                .set_additional_authenticated_data(aad.as_bytes().to_vec())
                .send()
                .await
                .map_err(|e| said(&e))?;
            // Node refuses only a missing version: an empty Buffer is
            // truthy.
            let version = gcp_version_of(&answer.name);
            if version.is_empty() {
                return Err(Failure::new(
                    codes::STS_KEYS_0103,
                    "Cloud KMS answered no ciphertext or no key version",
                ));
            }
            self.set_latest(&version);
            Ok(kms_text(
                "gcp-kms",
                &self.name,
                &format!("{}:{}", version, b64(&answer.ciphertext)),
            ))
        })
    }

    fn unwrap<'a>(
        &'a self,
        text: &'a str,
        aad: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, Failure>> {
        Box::pin(async move {
            let body = kms_parts(text)
                .filter(|(p, r, _)| p == "gcp-kms" && *r == self.name)
                .and_then(|(_, _, ct)| gcp_body(&ct));
            let Some((_, ciphertext)) = body else {
                return Err(Failure::new(
                    codes::STS_KEYS_0103,
                    format!(
                        "the wrapped data key is not under the Cloud KMS key \
                         \"{}\"",
                        self.name
                    ),
                ));
            };
            let answer = self
                .client
                .decrypt()
                .set_name(&self.name)
                .set_ciphertext(node_base64(&ciphertext))
                .set_additional_authenticated_data(aad.as_bytes().to_vec())
                .send()
                .await
                .map_err(|e| said(&e))?;
            Ok(answer.plaintext.to_vec())
        })
    }

    fn owns(&self, text: &str) -> bool {
        kms_parts(text)
            .is_some_and(|(p, r, _)| p == "gcp-kms" && r == self.name)
    }

    /// Wrapped under a version that is not the latest: the key was rotated
    /// (or its primary moved), and a re-wrap lets the old version go.
    fn is_stale(&self, text: &str) -> bool {
        let latest = self.latest();
        kms_parts(text)
            .and_then(|(_, _, ct)| gcp_version_prefix(&ct))
            .is_some_and(|v| !latest.is_empty() && v != latest)
    }

    /// A new version made primary; the earlier one stays enabled for the
    /// nodes that have not re-wrapped.
    fn rotate(&self) -> BoxFuture<'_, Result<String, Failure>> {
        Box::pin(async move {
            let made = self
                .client
                .create_crypto_key_version()
                .set_parent(&self.name)
                .set_crypto_key_version(CryptoKeyVersion::default())
                .send()
                .await
                .map_err(|e| said(&e))?;
            let version = gcp_version_of(&made.name);
            if version.is_empty() {
                return Err(Failure::new(
                    codes::STS_KEYS_0103,
                    "Cloud KMS made no new version",
                ));
            }
            self.client
                .update_crypto_key_primary_version()
                .set_name(&self.name)
                .set_crypto_key_version_id(&version)
                .send()
                .await
                .map_err(|e| said(&e))?;
            self.set_latest(&version);
            Ok(version)
        })
    }
}
