// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Where the key-encryption key comes from: a port of `common/secrets.js`'s
//! descriptors and providers (rust/DESIGN.md section 6, *Envelope
//! encryption*; #391).
//!
//! * **A secret is a DESCRIPTOR** ([`Spec`]) naming the settings that hold
//!   its provider, its location and its field — read where it is used, as
//!   every row here is runtime-readable — and the secret whose location it
//!   falls back to (`fallbackRef`). The key-encryption key, the previous one
//!   (#391 P2), the cell key (#98) and the two database passwords are here.
//! * **`pick()` makes one location serve several secrets**: a JSON object
//!   and a named field takes the field; anything else is the whole value —
//!   unless the location was BORROWED, when a value that is not JSON is the
//!   key-encryption key itself and is refused (STS-KEYS-0049) rather than
//!   handed out as a password.
//! * **The providers that READ a key** answer its bytes or its text:
//!   `file` (the default; a group- or other-readable file is warned about,
//!   STS-KEYS-0054, never refused) and `vault` — HashiCorp Vault or OpenBao
//!   KV, version 1 or 2 by the answer's shape, with a token
//!   (`keys.kekToken`, else `VAULT_TOKEN`) or a client certificate logged in
//!   at `auth/<keys.vaultCertAuthMount>/login`, which is how
//!   `docker-compose.yml`'s OpenBao is reached.
//! * **A provider that is a KEY MANAGEMENT SERVICE answers a HANDLE**
//!   ([`RemoteKek`]): the key never enters this process, and each data
//!   encryption key is wrapped by the KMS with its own AAD
//!   (`$dekkms$1$<provider>$<base64url key ref>$<the KMS's ciphertext>`).
//!   `vault-transit` (Vault's or OpenBao's Transit engine, the compose
//!   stack's default) is here; only the key-encryption key and the previous
//!   one may name a KMS (STS-KEYS-0101).
//! * **A failed read is RECORDED** in the ledger `/admin/secrets` draws, its
//!   message without a code, and then returned tagged — the secret's code
//!   (STS-KEYS-0043 for the key, 0044 for a password) and the provider's.
//! * **Product refuses a key-encryption key in a file** (STS-KEYS-0197, ASVS
//!   5.0.0 13.3.1) unless `secrets.allowLocalSecrets` is on.
//!
//! * **The three clouds, through their official SDKs** (rcbj's decision,
//!   2026-11-14), which carry the credential chains `secrets.js`'s header
//!   argues are not a thing to reimplement: AWS Secrets Manager (`aws`) and
//!   AWS KMS (`aws-kms`) through `aws-sdk-*` and `aws-config`'s chain;
//!   Google Secret Manager (`gcp`) and Cloud KMS (`gcp-kms`) through
//!   Google's own Rust client libraries and Application Default
//!   Credentials; Azure Key Vault secrets (`azure`) and keys (`azure-keys`)
//!   through `azure_security_keyvault_*` and the chain JavaScript's
//!   `DefaultAzureCredential` walks. Each is in `secrets/aws.rs`,
//!   `secrets/gcp.rs` and `secrets/azure.rs`, behind an sts-core feature of
//!   the same name, on by default; a build without one refuses the provider
//!   at start with STS-KEYS-0045, the code Node gives a provider whose SDK
//!   is not installed. What is not an SDK call — the settings read, the
//!   refusals, the stored text of a wrapped data key — is here and in
//!   `secrets/forms.rs`, compiled always.
//!
//! **Not here: the mail secrets** (#63), read when the mail channel is
//! ported, and `describe()` and the `/admin/secrets` probes, which are the
//! console's.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Value as Json};

use crate::errors::{codes, ErrorCode};
use crate::log::tag;
use crate::mode::Mode;
use crate::settings::Settings;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A secret's descriptor: the SETTING KEYS that name its provider, location
/// and field, and how its store is reached.
#[derive(Debug)]
pub struct Spec {
    pub id: &'static str,
    pub label: &'static str,
    pub provider: &'static str,
    pub file: &'static str,
    pub ref_: &'static str,
    pub field: &'static str,
    pub default_field: &'static str,
    pub fallback: Option<&'static Spec>,
    pub vault: Option<&'static str>,
    pub region: Option<&'static str>,
    pub token: Option<&'static str>,
    /// A KMS handle is accepted for this secret.
    pub kms_capable: bool,
}

pub static KEK: Spec = Spec {
    id: "kek",
    label: "the key-encryption key",
    provider: "keys.kekProvider",
    file: "keys.kekFile",
    ref_: "keys.kekRef",
    field: "keys.kekField",
    default_field: "",
    fallback: None,
    vault: Some("keys.kekVault"),
    region: Some("keys.kekRegion"),
    token: Some("keys.kekToken"),
    kms_capable: true,
};

pub static PREVIOUS_KEK: Spec = Spec {
    id: "previous-kek",
    label: "the previous key-encryption key",
    provider: "keys.previousKekProvider",
    file: "keys.previousKekRef",
    ref_: "keys.previousKekRef",
    field: "keys.previousKekField",
    default_field: "",
    fallback: None,
    vault: Some("keys.previousKekVault"),
    region: Some("keys.previousKekRegion"),
    token: None,
    kms_capable: true,
};

pub static DATABASE_PASSWORD: Spec = Spec {
    id: "database-password",
    label: "the database password",
    provider: "persistence.databasePasswordProvider",
    file: "persistence.databasePasswordRef",
    ref_: "persistence.databasePasswordRef",
    field: "persistence.databasePasswordField",
    default_field: "databasePassword",
    fallback: Some(&KEK),
    vault: Some("persistence.databasePasswordVault"),
    region: Some("persistence.databasePasswordRegion"),
    token: Some("persistence.databasePasswordToken"),
    kms_capable: false,
};

pub static GLOBAL_DATABASE_PASSWORD: Spec = Spec {
    id: "global-database-password",
    label: "the global tier database password",
    provider: "persistence.globalDatabasePasswordProvider",
    file: "persistence.globalDatabasePasswordRef",
    ref_: "persistence.globalDatabasePasswordRef",
    field: "persistence.globalDatabasePasswordField",
    default_field: "globalDatabasePassword",
    fallback: Some(&KEK),
    vault: None,
    region: Some("persistence.globalDatabasePasswordRegion"),
    token: None,
    kms_capable: false,
};

pub static CELL_KEK: Spec = Spec {
    id: "cell-kek",
    label: "the cell key-encryption key",
    provider: "keys.cellKekProvider",
    file: "keys.cellKekRef",
    ref_: "keys.cellKekRef",
    field: "keys.cellKekField",
    default_field: "",
    fallback: None,
    vault: Some("keys.cellKekVault"),
    region: Some("keys.cellKekRegion"),
    token: None,
    kms_capable: false,
};

/// Every provider id `secrets.js` knows, in its order.
pub const PROVIDER_IDS: &[&str] = &[
    "file",
    "aws",
    "gcp",
    "azure",
    "vault",
    "vault-transit",
    "aws-kms",
    "gcp-kms",
    "azure-keys",
];

/// The providers that are key management services.
const REMOTE: &[&str] = &["vault-transit", "aws-kms", "gcp-kms", "azure-keys"];

mod cloud;
mod forms;
pub use forms::{
    aws_context, azure_body, azure_key_refusal, azure_version_refusal,
    gcp_body, gcp_version_of, is_azure_key_name, is_azure_version,
    is_gcp_key_name, no_bytes, node_base64, rsa_modulus_bits,
    AZURE_RSA_MIN_BITS,
};

#[cfg(feature = "aws")]
mod aws;
#[cfg(feature = "azure")]
mod azure;
#[cfg(feature = "gcp")]
mod gcp;

/// The crate each cloud provider is reached through, and the sts-core
/// feature that builds it in, for `missingModule()`'s refusal.
#[allow(dead_code)] // every provider is built in by default
fn sdk_of(provider: &str) -> (&'static str, &'static str) {
    match provider {
        "aws" => ("aws-sdk-secretsmanager", "aws"),
        "gcp" => ("google-cloud-secretmanager-v1", "gcp"),
        "azure" => ("azure_security_keyvault_secrets", "azure"),
        "aws-kms" => ("aws-sdk-kms", "aws"),
        "gcp-kms" => ("google-cloud-kms-v1", "gcp"),
        _ => ("azure_security_keyvault_keys", "azure"),
    }
}

/// `missingModule()`: the one sentence for a provider this build carries
/// no SDK for, in the Rust runtime's terms (a crate and a feature, where
/// Node names a package to install).
#[allow(dead_code)] // every provider is built in by default
fn missing_sdk(provider: &str) -> Failure {
    let (krate, feature) = sdk_of(provider);
    Failure::new(
        codes::STS_KEYS_0045,
        format!(
            "the \"{}\" key-encryption-key provider needs the {} crate, and \
             this build of the service was made without sts-core's `{}` \
             feature. Build it with the feature (it is on by default), or \
             use keys.kekProvider=file, which needs nothing.",
            provider, krate, feature
        ),
    )
}

/// A refusal from a provider: the condition's code, the sentence without
/// it, and whether `secrets.js` MARKS the condition. An unmarked failure —
/// what an SDK or a store said — carries STS-KEYS-0043, the code a caller
/// that tags `code` (the keystore's unwrap) has always written for one,
/// and the refusal to start carries the secret's code alone, as
/// `tagReadFailure()` writes it.
#[derive(Debug, Clone, PartialEq)]
pub struct Failure {
    pub code: ErrorCode,
    pub message: String,
    pub marked: bool,
}

impl Failure {
    fn new(code: ErrorCode, message: impl Into<String>) -> Failure {
        Failure {
            code,
            message: message.into(),
            marked: true,
        }
    }

    /// An unmarked failure: what a store or an SDK said.
    fn uncoded(message: impl Into<String>) -> Failure {
        Failure {
            code: codes::STS_KEYS_0043,
            message: message.into(),
            marked: false,
        }
    }
}

/// What a read answers: a value (`text` true when it was read as text —
/// `crypto.kekBytes()` decides the shape), or a KMS handle.
#[derive(Clone)]
pub enum Secret {
    Value { bytes: Vec<u8>, text: bool },
    Remote(Arc<dyn RemoteKek>),
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the value.
        match self {
            Secret::Value { text, .. } => {
                write!(f, "Secret::Value {{ text: {} }}", text)
            }
            Secret::Remote(h) => write!(f, "Secret::Remote({})", h.label()),
        }
    }
}

/// The digest and the comparison Azure's RSA wrapping binds a data key's
/// AAD with, and the PKCS#12 an Azure client certificate in PEM is handed
/// to `azure_identity` as: cryptography, which is sts-crypto's (rcbj's
/// rule, #453), so the composition root fills this slot from it, as it
/// fills [`KeyNormalizer`]. With it empty, an `azure-keys` RSA key and a
/// PEM certificate in AZURE_CLIENT_CERTIFICATE_PATH are refused by name.
pub trait KmsCrypto: Send + Sync {
    /// SHA-256 of `data` (`crypto.digest('sha256', …)`).
    fn sha256(&self, data: &[u8]) -> Vec<u8>;
    /// `crypto.bytesEqualConstantTime()`.
    fn equal(&self, a: &[u8], b: &[u8]) -> bool;
    /// A PKCS#12 holding the certificate and private key of `pem`, under
    /// `password` (empty for none).
    fn pkcs12_of_pem(
        &self,
        pem: &[u8],
        password: &str,
    ) -> Result<Vec<u8>, String>;
}

/// Where a test points an SDK at an emulator: Google's client libraries,
/// like Node's, have no variable that names one (AWS's honour
/// `AWS_ENDPOINT_URL`, and Azure's endpoint is the vault URL). The Rust
/// half of Node's `setSdkLoader()`: nothing in the service sets it.
#[derive(Debug, Clone, Default)]
pub struct Emulators {
    /// Google's REST endpoint (`http://127.0.0.1:4588`), reached with
    /// anonymous credentials.
    pub gcp: Option<String>,
}

/// A key that never leaves its key management service (#391 P3): the
/// handle `secrets.js`'s KMS providers answer. `aad` is the data key's own
/// (`keystore.js`'s `dekAad()`).
pub trait RemoteKek: Send + Sync {
    fn provider(&self) -> &str;
    fn key_ref(&self) -> &str;
    fn label(&self) -> String;
    /// `$dekkms$1$…`, the stored form of `dek` wrapped by the KMS.
    fn wrap<'a>(
        &'a self,
        dek: &'a [u8],
        aad: &'a str,
    ) -> BoxFuture<'a, Result<String, Failure>>;
    fn unwrap<'a>(
        &'a self,
        text: &'a str,
        aad: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, Failure>>;
    /// Whether `text` was wrapped by this provider and key.
    fn owns(&self, text: &str) -> bool;
    /// Whether `text` was wrapped under an older version of the key.
    fn is_stale(&self, text: &str) -> bool;
    /// A new version, made in the KMS (#391 P5): its name — empty for AWS
    /// KMS, which keeps its earlier material behind the same key id, so no
    /// data key needs re-wrapping.
    fn rotate(&self) -> BoxFuture<'_, Result<String, Failure>>;
}

const KMS_PREFIX: &str = "$dekkms$1$";

/// `kmsText()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn kms_text(provider: &str, key_ref: &str, ciphertext: &str) -> String {
    format!(
        "{}{}${}${}",
        KMS_PREFIX,
        provider,
        URL_SAFE_NO_PAD.encode(key_ref.as_bytes()),
        ciphertext
    )
}

/// `kmsParts()`: `(provider, key ref, ciphertext)`, or `None`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn kms_parts(text: &str) -> Option<(String, String, String)> {
    let rest = text.strip_prefix(KMS_PREFIX)?;
    let parts: Vec<&str> = rest.split('$').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    // node's base64url decoder forgives padding and stray characters; a
    // reference that does not decode is not ours either way.
    let key_ref = URL_SAFE_NO_PAD
        .decode(parts[1].trim_end_matches('='))
        .ok()?;
    Some((
        parts[0].to_string(),
        String::from_utf8_lossy(&key_ref).into_owned(),
        parts[2].to_string(),
    ))
}

/// One row of the ledger of reads `/admin/secrets` draws.
#[derive(Debug, Clone, PartialEq)]
pub struct LedgerRow {
    pub secret: String,
    pub label: String,
    pub at: String,
    pub provider: String,
    pub took_ms: u128,
    pub ok: bool,
    pub error: Option<String>,
}

/// A client certificate's private key made PKCS#8 for the TLS client,
/// which takes no other form: `openbao/seed.js` writes a PKCS#1 RSA key.
/// Reading a key is the crypto module's (rcbj's rule, #453), so the
/// composition root fills this from `sts-crypto`; with it empty, a key that
/// is not PKCS#8 already is refused by name.
pub trait KeyNormalizer: Send + Sync {
    fn pkcs8_pem(&self, key_pem: &[u8]) -> Result<Vec<u8>, String>;
}

/// The secrets, over the settings that locate them.
pub struct Secrets {
    settings: Arc<Settings>,
    env: HashMap<String, String>,
    ledger: Mutex<Vec<LedgerRow>>,
    normalizer: std::sync::OnceLock<Arc<dyn KeyNormalizer>>,
    kms_crypto: std::sync::OnceLock<Arc<dyn KmsCrypto>>,
    emulators: std::sync::OnceLock<Emulators>,
}

impl Secrets {
    /// `env` is the process environment, for `VAULT_ADDR` and `VAULT_TOKEN`
    /// (node-vault's own fallbacks).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        settings: Arc<Settings>,
        env: HashMap<String, String>,
    ) -> Secrets {
        Secrets {
            settings,
            env,
            ledger: Mutex::new(Vec::new()),
            normalizer: std::sync::OnceLock::new(),
            kms_crypto: std::sync::OnceLock::new(),
            emulators: std::sync::OnceLock::new(),
        }
    }

    /// Fills the cloud providers' cryptography slot, once (see
    /// [`KmsCrypto`]).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn set_kms_crypto(&self, slot: Arc<dyn KmsCrypto>) -> bool {
        self.kms_crypto.set(slot).is_ok()
    }

    /// Points the SDKs at emulators, once, for a test (see [`Emulators`]).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn set_emulators(&self, emulators: Emulators) -> bool {
        self.emulators.set(emulators).is_ok()
    }

    /// Fills the key normalizer's slot, once (see [`KeyNormalizer`]).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn set_key_normalizer(&self, slot: Arc<dyn KeyNormalizer>) -> bool {
        self.normalizer.set(slot).is_ok()
    }

    fn text(&self, key: &str) -> String {
        self.settings.text_named(key).trim().to_string()
    }

    /// `reachOf()`: a secret's own Vault endpoint, region or token, else
    /// its fallback's.
    fn reach_of(
        &self,
        spec: &Spec,
        which: fn(&Spec) -> Option<&'static str>,
    ) -> String {
        let own = which(spec).map(|k| self.text(k)).unwrap_or_default();
        if !own.is_empty() || std::ptr::eq(spec, &KEK) {
            return own;
        }
        match spec.fallback {
            Some(fallback) => self.reach_of(fallback, which),
            None => own,
        }
    }

    /// `locationOf()`: `(where, borrowed)`.
    fn location_of(
        &self,
        spec: &Spec,
        key: fn(&Spec) -> &'static str,
    ) -> (String, bool) {
        let own = self.text(key(spec));
        if !own.is_empty() {
            return (own, false);
        }
        let Some(fallback) = spec.fallback else {
            return (String::new(), false);
        };
        // Nothing is borrowed from a key in a KMS: its ref names a key.
        if REMOTE.contains(&self.text(fallback.provider).as_str()) {
            return (String::new(), false);
        }
        let lent = self.text(key(fallback));
        let borrowed = !lent.is_empty();
        (lent, borrowed)
    }

    fn field_of(&self, spec: &Spec) -> String {
        let named = self.text(spec.field);
        if named.is_empty() {
            spec.default_field.to_string()
        } else {
            named
        }
    }

    /// `pick()`.
    fn pick(
        &self,
        raw: Secret,
        spec: &Spec,
        borrowed: bool,
    ) -> Result<Secret, Failure> {
        let field = self.field_of(spec);
        let Secret::Value { bytes, .. } = &raw else {
            return Ok(raw);
        };
        if field.is_empty() {
            return Ok(raw);
        }
        let parsed: Option<serde_json::Map<String, Json>> =
            serde_json::from_slice::<Json>(bytes)
                .ok()
                .and_then(|v| v.as_object().cloned());
        let Some(object) = parsed else {
            if borrowed {
                let fallback = spec.fallback.map_or("", |f| f.label);
                return Err(Failure::new(
                    codes::STS_KEYS_0049,
                    format!(
                        "what is stored for {} is not a JSON object, and it \
                         is the same place {} is read from — so what is \
                         there is that key rather than a password, and this \
                         service will not hand it to a database. Store \
                         {{\"{}\": \"…\"}} there beside the key, or point {} \
                         at a secret of its own.",
                        spec.label, fallback, field, spec.ref_
                    ),
                ));
            }
            return Ok(raw);
        };
        match object.get(&field) {
            None | Some(Json::Null) => {
                Err(self.no_field(spec, &field, &object))
            }
            Some(Json::String(s)) if s.is_empty() => {
                Err(self.no_field(spec, &field, &object))
            }
            Some(value) => Ok(Secret::Value {
                bytes: js_string(value).into_bytes(),
                text: true,
            }),
        }
    }

    fn no_field(
        &self,
        spec: &Spec,
        field: &str,
        object: &serde_json::Map<String, Json>,
    ) -> Failure {
        Failure::new(
            codes::STS_KEYS_0048,
            format!(
                "what is stored for {} is a JSON object with no \"{}\" in it. \
                 It holds: {}. Set {} to one of those.",
                spec.label,
                field,
                object.keys().cloned().collect::<Vec<_>>().join(", "),
                spec.field
            ),
        )
    }

    /// `configuredFor()`: a provider is set and is not `none`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn configured_for(&self, spec: &Spec) -> bool {
        let named = self.text(spec.provider);
        !named.is_empty() && named != "none"
    }

    /// `read(spec)`: one secret from its configured provider, recorded in
    /// the ledger. `Err` is the refusal to start, tagged with the secret's
    /// code and the provider's.
    #[tracing::instrument(level = "debug", skip_all, fields(secret = spec.id))]
    pub async fn read(&self, spec: &'static Spec) -> Result<Secret, String> {
        let named = self.text(spec.provider);
        let provider = if named.is_empty() {
            "file".to_string()
        } else {
            named
        };
        let began = Instant::now();
        let answer = if !PROVIDER_IDS.contains(&provider.as_str()) {
            Err(Failure::new(
                codes::STS_KEYS_0050,
                format!(
                    "{} is \"{}\", which is not one of: {}.",
                    spec.provider,
                    provider,
                    PROVIDER_IDS.join(", ")
                ),
            ))
        } else if REMOTE.contains(&provider.as_str()) && !spec.kms_capable {
            Err(Failure::new(
                codes::STS_KEYS_0101,
                format!(
                    "{} is \"{}\", a key management service that wraps keys \
                     and holds no secret to read; only keys.kekProvider and \
                     keys.previousKekProvider may name it.",
                    spec.provider, provider
                ),
            ))
        } else {
            match provider.as_str() {
                "file" => self.read_file(spec),
                "vault" => self.read_vault(spec).await,
                "vault-transit" => self.transit(spec).await,
                // BOXED: the SDKs' futures are deep, and inlined into this
                // one they pushed the layout of every future that awaits a
                // read (the runtime's start) past rustc's query depth.
                "aws" => self.boxed(self.read_aws(spec)).await,
                "gcp" => self.boxed(self.read_gcp(spec)).await,
                "azure" => self.boxed(self.read_azure(spec)).await,
                "aws-kms" => self.boxed(self.aws_kms(spec)).await,
                "gcp-kms" => self.boxed(self.gcp_kms(spec)).await,
                _ => self.boxed(self.azure_keys(spec)).await,
            }
        };
        self.record(spec, &provider, began.elapsed(), answer.as_ref().err());
        answer.map_err(|failure| {
            let which = if std::ptr::eq(spec, &KEK) {
                codes::STS_KEYS_0043
            } else {
                codes::STS_KEYS_0044
            };
            format!(
                "{}{}{}",
                tag(which),
                if failure.marked {
                    tag(failure.code)
                } else {
                    String::new()
                },
                failure.message
            )
        })
    }

    fn boxed<'a>(
        &self,
        read: impl Future<Output = Result<Secret, Failure>> + Send + 'a,
    ) -> BoxFuture<'a, Result<Secret, Failure>> {
        Box::pin(read)
    }

    fn record(
        &self,
        spec: &Spec,
        provider: &str,
        took: Duration,
        error: Option<&Failure>,
    ) {
        let row = LedgerRow {
            secret: spec.id.to_string(),
            label: spec.label.to_string(),
            at: crate::time::iso_now(),
            provider: provider.to_string(),
            took_ms: took.as_millis(),
            ok: error.is_none(),
            error: error.map(|f| f.message.clone()),
        };
        let mut ledger =
            self.ledger.lock().unwrap_or_else(PoisonError::into_inner);
        ledger.retain(|one| one.secret != row.secret);
        ledger.push(row);
    }

    /// `readLedger()`: every secret's last read, by id; a secret never
    /// read is absent.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn ledger(&self) -> Json {
        let ledger = self.ledger.lock().unwrap_or_else(PoisonError::into_inner);
        let mut out = serde_json::Map::new();
        for row in ledger.iter() {
            let mut one = json!({
                "secret": row.secret, "label": row.label, "at": row.at,
                "provider": row.provider, "tookMs": row.took_ms as u64,
                "ok": row.ok,
            });
            if let Some(e) = &row.error {
                one["error"] = json!(e);
            }
            out.insert(row.secret.clone(), one);
        }
        Json::Object(out)
    }

    /// `readKek()`: the key-encryption key, refused in a file in product
    /// (STS-KEYS-0197) unless `secrets.allowLocalSecrets` is on.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn read_kek(&self, mode: &Mode) -> Result<Secret, String> {
        if self.text(KEK.provider) == "file" && mode.requires_secret_store() {
            return Err(format!(
                "{}{} is \"file\", and product mode takes a key-encryption \
                 key from a secret store or a key management service (vault, \
                 vault-transit, aws, aws-kms, gcp, gcp-kms, azure or \
                 azure-keys). Configure one, or turn on \
                 secrets.allowLocalSecrets to accept the file.",
                tag(codes::STS_KEYS_0197),
                KEK.provider
            ));
        }
        self.read(&KEK).await
    }

    /// `readPreviousKek()`: `None` when no previous key is configured;
    /// one with no location of its own is refused (STS-KEYS-0098) — it has
    /// no fallback.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn read_previous_kek(&self) -> Result<Option<Secret>, String> {
        if !self.configured_for(&PREVIOUS_KEK) {
            return Ok(None);
        }
        let provider = self.text(PREVIOUS_KEK.provider);
        // `file` or `ref`: one setting, keys.previousKekRef, either way.
        let (wher, _) = self.location_of(&PREVIOUS_KEK, |s| s.ref_);
        if wher.is_empty() {
            return Err(format!(
                "{}{} is \"{}\" and keys.previousKekRef is empty. The \
                 previous key has no fallback location.",
                tag(codes::STS_KEYS_0098),
                PREVIOUS_KEK.provider,
                provider
            ));
        }
        self.read(&PREVIOUS_KEK).await.map(Some)
    }

    // -----------------------------------------------------------------
    // file — THE DEFAULT.
    // -----------------------------------------------------------------

    fn read_file(&self, spec: &Spec) -> Result<Secret, Failure> {
        let (path, borrowed) = self.location_of(spec, |s| s.file);
        if path.is_empty() {
            return Err(Failure::new(
                codes::STS_KEYS_0046,
                format!(
                    "{} is \"file\" and {} names no path. Set it to a file \
                     holding {} — for a key-encryption key, `openssl rand \
                     -base64 32 > /run/secrets/sts-kek`.",
                    spec.provider, spec.file, spec.label
                ),
            ));
        }
        let unreadable = |e: std::io::Error| {
            Failure::new(
                codes::STS_KEYS_0047,
                format!(
                    "the file \"{}\" holding {} could not be read: {}. In \
                     product mode this service will not start without it, \
                     because the alternative is generating a new signing key \
                     and silently invalidating every token it ever issued.",
                    path,
                    spec.label,
                    node_io(&e, "stat", &path)
                ),
            )
        };
        let meta = std::fs::metadata(&path).map_err(unreadable)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                tracing::warn!(
                    "{}secrets: the file \"{}\" holding {} is readable by \
                     group or other (mode {:o}). {} `chmod 600` it.",
                    tag(codes::STS_KEYS_0054),
                    path,
                    spec.label,
                    mode & 0o777,
                    if std::ptr::eq(spec, &KEK) {
                        "Every signing key this service holds is protected by it."
                    } else {
                        "It is a credential for this service's store."
                    }
                );
            }
        }
        #[cfg(not(unix))]
        let _ = &meta;
        let body = std::fs::read(&path).map_err(unreadable)?;
        tracing::info!("secrets: {} was read from {}.", spec.label, path);
        // `body.toString('utf8').trim() || body`: the trimmed text, unless
        // it trims to nothing, when the bytes.
        let text = String::from_utf8_lossy(&body);
        let trimmed = crate::settings::js_trim(&text);
        let value = if trimmed.is_empty() {
            Secret::Value {
                bytes: body.clone(),
                text: false,
            }
        } else {
            Secret::Value {
                bytes: trimmed.as_bytes().to_vec(),
                text: true,
            }
        };
        self.pick(value, spec, borrowed)
    }

    // -----------------------------------------------------------------
    // vault — HashiCorp Vault or OpenBao, KV v1 or v2.
    // -----------------------------------------------------------------

    async fn read_vault(&self, spec: &Spec) -> Result<Secret, Failure> {
        let (path, _) = self.location_of(spec, |s| s.ref_);
        if path.is_empty() {
            return Err(Failure::new(
                codes::STS_KEYS_0046,
                format!(
                    "{} is \"vault\" and {} names no path. Set it to the read \
                     path, e.g. secret/data/sts-kek.",
                    spec.provider, spec.ref_
                ),
            ));
        }
        let vault = self.vault_connect(spec).await?;
        let answer = vault.call("GET", &format!("/{}", path), None).await?;
        let field = {
            let f = self.field_of(spec);
            if f.is_empty() {
                "value".to_string()
            } else {
                f
            }
        };
        let Some(data) = answer.get("data").filter(|d| !d.is_null()) else {
            return Err(Failure::new(
                codes::STS_KEYS_0048,
                format!("the Vault path \"{}\" returned no data", path),
            ));
        };
        let holder = match data.get("data") {
            Some(inner) if inner.is_object() => inner,
            _ => data,
        };
        let value = holder.get(&field);
        let empty = match value {
            None | Some(Json::Null) => true,
            Some(Json::String(s)) => s.is_empty(),
            _ => false,
        };
        if empty {
            let keys = holder
                .as_object()
                .map(|o| o.keys().cloned().collect::<Vec<_>>().join(", "))
                .unwrap_or_default();
            return Err(Failure::new(
                codes::STS_KEYS_0048,
                format!(
                    "the Vault path \"{}\" has no \"{}\" field. It holds: {}. \
                     Set {} to one of those.",
                    path, field, keys, spec.field
                ),
            ));
        }
        tracing::info!(
            "secrets: {} was read from HashiCorp Vault ({}).",
            spec.label,
            path
        );
        let text = js_string(value.unwrap_or(&Json::Null));
        Ok(Secret::Value {
            bytes: crate::settings::js_trim(&text).as_bytes().to_vec(),
            text: true,
        })
    }

    /// `vaultConnect()`: a client for the store `spec` reaches, logged in
    /// with the client certificate when one is configured.
    async fn vault_connect(&self, spec: &Spec) -> Result<Vault, Failure> {
        let endpoint = {
            let own = self.reach_of(spec, |s| s.vault);
            if own.is_empty() {
                self.env
                    .get("VAULT_ADDR")
                    .cloned()
                    .unwrap_or_else(|| "http://127.0.0.1:8200".to_string())
            } else {
                own
            }
        };
        let token = {
            let own = self.reach_of(spec, |s| s.token);
            if own.is_empty() {
                self.env.get("VAULT_TOKEN").cloned().unwrap_or_default()
            } else {
                own
            }
        };
        let cert = self.text("keys.vaultClientCert");
        let key = self.text("keys.vaultClientKey");
        let ca = self.text("keys.vaultCaCert");
        let fail = |what: String| Failure::uncoded(what);
        let mut builder = reqwest::Client::builder()
            .pool_max_idle_per_host(8)
            .timeout(Duration::from_secs(30));
        if !ca.is_empty() {
            let pem = std::fs::read(&ca)
                .map_err(|e| fail(node_io(&e, "open", &ca)))?;
            let anchor = reqwest::Certificate::from_pem(&pem)
                .map_err(|e| fail(format!("{}: {}", ca, e)))?;
            builder = builder.add_root_certificate(anchor);
        }
        let authenticates = !cert.is_empty() && !key.is_empty();
        if authenticates {
            let c = std::fs::read(&cert)
                .map_err(|e| fail(node_io(&e, "open", &cert)))?;
            let k = std::fs::read(&key)
                .map_err(|e| fail(node_io(&e, "open", &key)))?;
            let k = if k.starts_with(b"-----BEGIN PRIVATE KEY-----") {
                k
            } else {
                match self.normalizer.get() {
                    Some(slot) => slot
                        .pkcs8_pem(&k)
                        .map_err(|e| fail(format!("{}: {}", key, e)))?,
                    None => {
                        return Err(fail(format!(
                            "{} is not a PKCS#8 key, and no key normalizer \
                             is installed to read it",
                            key
                        )))
                    }
                }
            };
            let identity = reqwest::Identity::from_pkcs8_pem(&c, &k)
                .map_err(|e| fail(format!("{}: {}", cert, e)))?;
            builder = builder.identity(identity);
        }
        let client = builder.build().map_err(|e| fail(e.to_string()))?;
        let mut vault = Vault {
            client,
            endpoint: endpoint.trim_end_matches('/').to_string(),
            token,
        };
        if !authenticates {
            return Ok(vault);
        }
        let mount = self.cert_auth_mount()?;
        let role = self.text("keys.vaultCertRole");
        let body = if role.is_empty() {
            json!({})
        } else {
            json!({ "name": role })
        };
        let login = vault
            .call("POST", &format!("/auth/{}/login", mount), Some(body))
            .await?;
        let issued = login["auth"]["client_token"].as_str().unwrap_or("");
        if issued.is_empty() {
            return Err(Failure::new(
                codes::STS_KEYS_0051,
                format!(
                    "the secret store accepted the client certificate and \
                     returned no token, which is a store with the `cert` auth \
                     method enabled at auth/{} and no certificate bound to a \
                     policy.",
                    mount
                ),
            ));
        }
        vault.token = issued.to_string();
        let policies: Vec<String> = login["auth"]["policies"]
            .as_array()
            .map(|p| {
                p.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        tracing::info!(
            "secrets: authenticated to the secret store with a CLIENT \
             CERTIFICATE ({}){}. The token it returned carries {} and lives \
             {}s.",
            cert,
            if role.is_empty() {
                String::new()
            } else {
                format!(", role \"{}\"", role)
            },
            if policies.is_empty() {
                "no policies".to_string()
            } else {
                policies.join(", ")
            },
            login["auth"]["lease_duration"].as_i64().unwrap_or(0)
        );
        Ok(vault)
    }

    /// `certAuthMount()`.
    fn cert_auth_mount(&self) -> Result<String, Failure> {
        let given = self.text("keys.vaultCertAuthMount");
        let raw = if given.is_empty() {
            "cert".to_string()
        } else {
            given
        };
        let raw = raw.trim_matches('/').to_string();
        let alphabet = raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-/".contains(c));
        let dotted = raw.split('/').any(|seg| seg == "." || seg == "..");
        if raw.is_empty() || !alphabet || dotted {
            return Err(Failure::new(
                codes::STS_KEYS_0052,
                format!(
                    "keys.vaultCertAuthMount is \"{}\", which is not a mount \
                     path this service will put into a request. Use letters, \
                     digits, \"-\", \"_\", \".\" and \"/\" only — the path the \
                     cert auth method was enabled at, `cert` by default.",
                    raw
                ),
            ));
        }
        Ok(raw)
    }

    /// `transitMount()`.
    fn transit_mount(&self) -> Result<String, Failure> {
        let given = self.text("keys.kekTransitMount");
        let mount = if given.is_empty() {
            "transit".to_string()
        } else {
            given
        };
        let mount = mount.trim_matches('/').to_string();
        let plain = !mount.is_empty()
            && mount.split('/').all(|seg| {
                !seg.is_empty()
                    && seg
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
            });
        if !plain {
            return Err(Failure::new(
                codes::STS_KEYS_0102,
                format!(
                    "keys.kekTransitMount \"{}\" is not a plain path.",
                    mount
                ),
            ));
        }
        Ok(mount)
    }

    // -----------------------------------------------------------------
    // vault-transit — the key never leaves the store.
    // -----------------------------------------------------------------

    async fn transit(&self, spec: &'static Spec) -> Result<Secret, Failure> {
        let (name, _) = self.location_of(spec, |s| s.ref_);
        if name.is_empty() {
            return Err(Failure::new(
                codes::STS_KEYS_0046,
                format!(
                    "{} is \"vault-transit\" and {} names no key. Set it to \
                     the Transit key's name.",
                    spec.provider, spec.ref_
                ),
            ));
        }
        let mount = self.transit_mount()?;
        let vault = self.vault_connect(spec).await?;
        let handle = Transit {
            vault: tokio::sync::Mutex::new(vault),
            secrets: self.reconnector(spec),
            mount,
            name,
            latest: Mutex::new(1),
        };
        let info = handle
            .call(
                "GET",
                &format!("/keys/{}", encode_component(&handle.name)),
                None,
            )
            .await?;
        let kind = info["data"]["type"].as_str().unwrap_or("").to_string();
        if !TRANSIT_AEAD.contains(&kind.as_str()) {
            return Err(Failure::new(
                codes::STS_KEYS_0102,
                format!(
                    "the Transit key \"{}\" is of type \"{}\"; a data key is \
                     wrapped with its id, scope, realm and class as \
                     associated data, which only {} accept.",
                    handle.name,
                    if kind.is_empty() { "?" } else { &kind },
                    TRANSIT_AEAD.join(", ")
                ),
            ));
        }
        let latest =
            info["data"]["latest_version"].as_i64().unwrap_or(1).max(1);
        *handle.latest.lock().unwrap_or_else(PoisonError::into_inner) = latest;
        tracing::info!(
            "secrets: {} is the Transit key \"{}/{}\" ({}, version {}); it \
             never leaves the KMS, which wraps each data key.",
            spec.label,
            handle.mount,
            handle.name,
            kind,
            latest
        );
        Ok(Secret::Remote(Arc::new(handle)))
    }

    /// A way back to the store for a handle whose token expired: the same
    /// settings, read again.
    fn reconnector(&self, spec: &'static Spec) -> Reconnect {
        Reconnect {
            secrets: {
                let again =
                    Secrets::new(self.settings.clone(), self.env.clone());
                if let Some(slot) = self.normalizer.get() {
                    again.set_key_normalizer(slot.clone());
                }
                if let Some(slot) = self.kms_crypto.get() {
                    again.set_kms_crypto(slot.clone());
                }
                again
            },
            spec,
        }
    }
}

const TRANSIT_AEAD: &[&str] =
    &["aes256-gcm96", "aes128-gcm96", "chacha20-poly1305"];

/// node's `String(value)` for what a store holds.
fn js_string(value: &Json) -> String {
    match value {
        Json::String(s) => s.clone(),
        Json::Object(_) => "[object Object]".to_string(),
        other => crate::settings::js_string(other),
    }
}

/// An I/O error in node's words.
fn node_io(e: &std::io::Error, syscall: &str, path: &str) -> String {
    let (code, text) = match e.kind() {
        std::io::ErrorKind::NotFound => ("ENOENT", "no such file or directory"),
        std::io::ErrorKind::PermissionDenied => ("EACCES", "permission denied"),
        _ => return format!("{}, {} '{}'", e, syscall, path),
    };
    format!("{}: {}, {} '{}'", code, text, syscall, path)
}

/// `encodeURIComponent()`.
fn encode_component(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// A logged-in client of one Vault or OpenBao.
struct Vault {
    client: reqwest::Client,
    endpoint: String,
    token: String,
}

impl Vault {
    /// One API call under `/v1`; a non-2xx answer is a failure carrying
    /// its status, and `status` says which.
    async fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<Json>,
    ) -> Result<Json, Failure> {
        self.call_status(method, path, body)
            .await
            .map_err(|(_, f)| f)
    }

    async fn call_status(
        &self,
        method: &str,
        path: &str,
        body: Option<Json>,
    ) -> Result<Json, (u16, Failure)> {
        let url = format!("{}/v1{}", self.endpoint, path);
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .unwrap_or(reqwest::Method::GET);
        let mut ask = self.client.request(method, &url);
        if !self.token.is_empty() {
            ask = ask.header("X-Vault-Token", &self.token);
        }
        if let Some(body) = body {
            ask = ask.json(&body);
        }
        let failed = |status: u16, why: String| (status, Failure::uncoded(why));
        let answer = ask.send().await.map_err(|e| failed(0, e.to_string()))?;
        let status = answer.status().as_u16();
        let text = answer
            .text()
            .await
            .map_err(|e| failed(status, e.to_string()))?;
        let parsed: Json = if text.trim().is_empty() {
            Json::Null
        } else {
            serde_json::from_str(&text).unwrap_or(Json::Null)
        };
        if !(200..300).contains(&status) {
            // node-vault's message: the store's own errors, else the status.
            let errors = parsed["errors"]
                .as_array()
                .map(|e| {
                    e.iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            return Err(failed(
                status,
                if errors.is_empty() {
                    format!("Status {}", status)
                } else {
                    errors
                },
            ));
        }
        Ok(parsed)
    }
}

struct Reconnect {
    secrets: Secrets,
    spec: &'static Spec,
}

/// The `vault-transit` handle.
struct Transit {
    vault: tokio::sync::Mutex<Vault>,
    secrets: Reconnect,
    mount: String,
    name: String,
    latest: Mutex<i64>,
}

impl Transit {
    /// A call, logged in again once on a 403 (a login's token expires).
    async fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<Json>,
    ) -> Result<Json, Failure> {
        let full = format!("/{}{}", self.mount, path);
        let mut vault = self.vault.lock().await;
        match vault.call_status(method, &full, body.clone()).await {
            Ok(answer) => Ok(answer),
            Err((403, _)) => {
                tracing::info!(
                    "secrets: the secret store refused the token (403); \
                     logging in again once."
                );
                *vault = self
                    .secrets
                    .secrets
                    .vault_connect(self.secrets.spec)
                    .await?;
                vault.call(method, &full, body).await
            }
            Err((_, failure)) => Err(failure),
        }
    }

    fn version_of(ciphertext: &str) -> Option<i64> {
        let rest = ciphertext.strip_prefix("vault:v")?;
        let digits: String =
            rest.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() || !rest[digits.len()..].starts_with(':') {
            return None;
        }
        digits.parse().ok()
    }
}

impl RemoteKek for Transit {
    fn provider(&self) -> &str {
        "vault-transit"
    }

    fn key_ref(&self) -> &str {
        &self.name
    }

    fn label(&self) -> String {
        format!("Transit key {}/{}", self.mount, self.name)
    }

    fn wrap<'a>(
        &'a self,
        dek: &'a [u8],
        aad: &'a str,
    ) -> BoxFuture<'a, Result<String, Failure>> {
        Box::pin(async move {
            let answer = self
                .call(
                    "POST",
                    &format!("/encrypt/{}", encode_component(&self.name)),
                    Some(json!({
                        "plaintext": STANDARD.encode(dek),
                        "associated_data": STANDARD.encode(aad.as_bytes()),
                    })),
                )
                .await?;
            let ct = answer["data"]["ciphertext"].as_str().unwrap_or("");
            if ct.is_empty() || ct.contains('$') {
                return Err(Failure::new(
                    codes::STS_KEYS_0103,
                    "Transit answered no ciphertext",
                ));
            }
            if let Some(v) = Transit::version_of(ct) {
                let mut latest =
                    self.latest.lock().unwrap_or_else(PoisonError::into_inner);
                *latest = (*latest).max(v);
            }
            Ok(kms_text("vault-transit", &self.name, ct))
        })
    }

    fn unwrap<'a>(
        &'a self,
        text: &'a str,
        aad: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, Failure>> {
        Box::pin(async move {
            let parts = kms_parts(text)
                .filter(|(p, r, _)| p == "vault-transit" && *r == self.name);
            let Some((_, _, ciphertext)) = parts else {
                return Err(Failure::new(
                    codes::STS_KEYS_0103,
                    format!(
                        "the wrapped data key is not under the Transit key \"{}\"",
                        self.name
                    ),
                ));
            };
            let answer = self
                .call(
                    "POST",
                    &format!("/decrypt/{}", encode_component(&self.name)),
                    Some(json!({
                        "ciphertext": ciphertext,
                        "associated_data": STANDARD.encode(aad.as_bytes()),
                    })),
                )
                .await?;
            let plain = answer["data"]["plaintext"].as_str().unwrap_or("");
            if plain.is_empty() {
                return Err(Failure::new(
                    codes::STS_KEYS_0103,
                    "Transit answered no plaintext",
                ));
            }
            STANDARD
                .decode(plain)
                .map_err(|e| Failure::new(codes::STS_KEYS_0103, e.to_string()))
        })
    }

    fn owns(&self, text: &str) -> bool {
        kms_parts(text)
            .is_some_and(|(p, r, _)| p == "vault-transit" && r == self.name)
    }

    fn is_stale(&self, text: &str) -> bool {
        let latest =
            *self.latest.lock().unwrap_or_else(PoisonError::into_inner);
        kms_parts(text)
            .and_then(|(_, _, ct)| Transit::version_of(&ct))
            .is_some_and(|v| v < latest)
    }

    fn rotate(&self) -> BoxFuture<'_, Result<String, Failure>> {
        Box::pin(async move {
            let key = encode_component(&self.name);
            self.call("POST", &format!("/keys/{}/rotate", key), None)
                .await?;
            let now = self.call("GET", &format!("/keys/{}", key), None).await?;
            let mut latest =
                self.latest.lock().unwrap_or_else(PoisonError::into_inner);
            *latest = (*latest)
                .max(now["data"]["latest_version"].as_i64().unwrap_or(0));
            Ok(format!("v{}", *latest))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets(pairs: &[(&str, &str)]) -> Secrets {
        let env: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Secrets::new(Arc::new(Settings::new(Json::Null, env.clone())), env)
    }

    #[test]
    fn kms_text_round_trips() {
        let text = kms_text("vault-transit", "arn:aws:kms/x", "vault:v2:abc");
        assert!(text.starts_with("$dekkms$1$vault-transit$"));
        assert_eq!(
            kms_parts(&text),
            Some((
                "vault-transit".into(),
                "arn:aws:kms/x".into(),
                "vault:v2:abc".into()
            ))
        );
        assert_eq!(kms_parts("$dekkms$1$a$$c"), None);
        assert_eq!(Transit::version_of("vault:v12:x"), Some(12));
        assert_eq!(Transit::version_of("vault:x"), None);
    }

    #[tokio::test]
    async fn the_file_provider_and_pick() {
        let dir = std::env::temp_dir()
            .join(format!("sts-secrets-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let raw = dir.join("kek");
        std::fs::write(&raw, "  c2VjcmV0\n").unwrap();
        let shared = dir.join("shared.json");
        std::fs::write(&shared, r#"{"kek":"k","databasePassword":"pw"}"#)
            .unwrap();
        let s = secrets(&[("STS_KEYS_KEK_FILE", raw.to_str().unwrap())]);
        match s.read(&KEK).await.unwrap() {
            Secret::Value { bytes, text } => {
                assert_eq!(bytes, b"c2VjcmV0");
                assert!(text);
            }
            other => panic!("{:?}", other),
        }
        // A password borrowing the key's file, which is not JSON: refused.
        let s = secrets(&[
            ("STS_KEYS_KEK_FILE", raw.to_str().unwrap()),
            ("STS_DATABASE_PASSWORD_PROVIDER", "file"),
        ]);
        let refused = s.read(&DATABASE_PASSWORD).await.unwrap_err();
        assert!(refused.contains(&tag(codes::STS_KEYS_0049)));
        assert!(refused.starts_with(&tag(codes::STS_KEYS_0044)));
        assert_eq!(s.ledger()["database-password"]["ok"], json!(false));
        // A shared JSON object serves both.
        let s = secrets(&[
            ("STS_KEYS_KEK_FILE", shared.to_str().unwrap()),
            ("STS_KEYS_KEK_FIELD", "kek"),
            ("STS_DATABASE_PASSWORD_PROVIDER", "file"),
        ]);
        let Secret::Value { bytes, .. } =
            s.read(&DATABASE_PASSWORD).await.unwrap()
        else {
            panic!()
        };
        assert_eq!(bytes, b"pw");
        let Secret::Value { bytes, .. } = s.read(&KEK).await.unwrap() else {
            panic!()
        };
        assert_eq!(bytes, b"k");
        // A cloud provider with no location, refused before any SDK call
        // (or, in a build without the SDK, as Node's missing package is).
        let s = secrets(&[("STS_KEYS_KEK_PROVIDER", "aws")]);
        let refused = s.read(&KEK).await.unwrap_err();
        let want = if cfg!(feature = "aws") {
            codes::STS_KEYS_0046
        } else {
            codes::STS_KEYS_0045
        };
        assert_eq!(
            refused,
            format!(
                "{}{}{}",
                tag(codes::STS_KEYS_0043),
                tag(want),
                if cfg!(feature = "aws") {
                    "keys.kekProvider is \"aws\" and keys.kekRef names no \
                     secret. Set it to the secret's name or ARN."
                        .to_string()
                } else {
                    missing_sdk("aws").message
                }
            )
        );
        for (provider, ref_, code, says) in [
            (
                "gcp-kms",
                "projects/p/keyRings/r",
                codes::STS_KEYS_0102,
                "keys.kekRef is \"projects/p/keyRings/r\", which is not a \
              CryptoKey's resource name.",
            ),
            (
                "azure-keys",
                "",
                codes::STS_KEYS_0046,
                "keys.kekProvider is \"azure-keys\" and it needs both \
              keys.kekVault",
            ),
            (
                "aws-kms",
                "",
                codes::STS_KEYS_0046,
                "keys.kekProvider is \"aws-kms\" and keys.kekRef names no key.",
            ),
        ] {
            let s = secrets(&[
                ("STS_KEYS_KEK_PROVIDER", provider),
                ("STS_KEYS_KEK_REF", ref_),
            ]);
            let refused = s.read(&KEK).await.unwrap_err();
            assert!(
                refused.starts_with(&format!(
                    "{}{}{}",
                    tag(codes::STS_KEYS_0043),
                    tag(code),
                    says
                )),
                "{}",
                refused
            );
        }
        let s = secrets(&[
            ("STS_KEYS_KEK_PROVIDER", "azure-keys"),
            ("STS_KEYS_KEK_REF", "a_b"),
            ("STS_KEYS_KEK_VAULT", "https://v.vault.azure.net/"),
        ]);
        assert!(s.read(&KEK).await.unwrap_err().contains(
            "keys.kekRef is \"a_b\", which is not a Key Vault key name"
        ));
        let s = secrets(&[("STS_DATABASE_PASSWORD_PROVIDER", "vault-transit")]);
        let refused = s.read(&DATABASE_PASSWORD).await.unwrap_err();
        assert!(refused.contains(&tag(codes::STS_KEYS_0101)));
        let s = secrets(&[("STS_KEYS_KEK_FILE", "/nonexistent/kek")]);
        let refused = s.read(&KEK).await.unwrap_err();
        assert!(refused.contains("ENOENT: no such file or directory"));
    }
}
