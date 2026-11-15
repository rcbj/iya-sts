// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! SAML 2.0 IN THE RUNTIME (`common/protocol_stack.ts`'s `10a`,
//! `saml/saml2_sso`): `sts-saml`'s libraries over what the runtime holds,
//! and the routes ported so far.
//!
//! | Route | Answered by |
//! |---|---|
//! | `GET /saml2/autopost.js` | the POST binding's one script |
//! | `GET /saml2/metadata` | [`sts_saml::metadata::metadata_for`], signed with the realm's XML key |
//!
//! THE STORES ARE DECLARED UNDER NODE'S HANDLES before the store opens —
//! `saml2_sso.artifacts` (keyed by the artifact's digest, `expires` in ms)
//! and `saml2_sso.pendingRequests` — so what a 1.x install held is what this
//! runtime holds (D11).
//!
//! WHAT IS NOT HERE YET, and how it is answered meanwhile: single sign-on,
//! Single Logout, artifact resolution, the attribute authority, the
//! identity-provider-initiated link and a document for one service provider
//! (`/saml2/metadata/{sp}`) are not routes of this runtime; a deployment
//! beside a Node service sends them there (`tests/tools/rust-saml-jobs.sh`'s
//! proxy). WS-Federation's view of the document is the WS-Federation
//! slice's; the other listeners SAML 2.0 is on (#472) are none here.

use std::sync::{Arc, OnceLock};

use axum::extract::Request as AxumRequest;
use axum::response::{IntoResponse, Response};
use serde_json::Value as Json;
use sts_core::mode::Mode;
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{
    expiry_field, RealmMap, Retain, StoreHandles, StoreSpec,
};
use sts_core::settings::Settings;
use sts_crypto::xmldsig::{self, XmlPolicy};
use sts_saml::assertion::XmlSigner;
use sts_saml::metadata::{self, MetadataInputs, Published};
use sts_store::persistence::Persistence;

/// What the back channel presents: each listener certificate (PEM) with
/// the chain the first is stored with, and the service Root.
pub type BackChannel =
    Arc<dyn Fn() -> (Vec<String>, Vec<String>, Option<String>) + Send + Sync>;

/// What the main listener presents, read when a document is drawn (a
/// rebuilt hierarchy replaces it in place).
#[tracing::instrument(level = "debug", skip_all)]
pub fn back_channel_of(
    listeners: &Arc<crate::listeners::Listeners>,
) -> BackChannel {
    let listeners = listeners.clone();
    Arc::new(move || {
        let material = listeners
            .material
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let certs: Vec<String> = material
            .certificates
            .iter()
            .map(|c| c.cert_pem.clone())
            .collect();
        let chain = material
            .certificates
            .first()
            .map(|c| c.chain_pem.clone())
            .unwrap_or_default();
        (certs, chain, material.root_pem())
    })
}

/// SAML 2.0, built.
pub struct SamlStack {
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    pub persistence: Arc<Persistence>,
    /// `saml2_sso.artifacts`.
    pub artifacts: RealmMap<Json>,
    /// `saml2_sso.pendingRequests`.
    pub pending: RealmMap<Json>,
    back_channel: OnceLock<BackChannel>,
}

/// `settingList()`: an array, or a comma-separated string.
fn list_of(settings: &Settings, key: &str) -> Vec<String> {
    let v = settings.value_of(key);
    let raw: Vec<String> = if v.as_list().is_empty() {
        v.as_str().split(',').map(str::to_string).collect()
    } else {
        v.as_list().to_vec()
    };
    raw.into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// The realm's XML signature policy (#1368), as `signature_policy.ts` reads
/// it for the `xml` surface.
#[tracing::instrument(level = "debug", skip_all)]
pub fn xml_policy(settings: &Settings, mode: &Mode) -> XmlPolicy {
    XmlPolicy {
        sha1_allowed: mode.value_in_force("saml.allowSha1Signatures").as_bool(),
        broken_algorithms: mode.uses_broken_algorithms(),
        signature_algorithms: list_of(settings, "saml.signatureAlgorithms"),
        accepted_signature_algorithms: list_of(
            settings,
            "saml.acceptedSignatureAlgorithms",
        ),
        accepted_digest_algorithms: list_of(
            settings,
            "saml.acceptedDigestAlgorithms",
        ),
        pqc_only: settings.value_of("keys.pqcOnly").as_bool(),
        jose_signing_algorithms: list_of(settings, "keys.signingAlgorithms"),
        jose_accepted_algorithms: list_of(
            settings,
            "keys.acceptedSigningAlgorithms",
        ),
        omits_unapproved_curves: mode.omits_unapproved_signing_curves(),
    }
}

/// `pki.chainThroughRoot()`: the certificate, its chain, and the service
/// Root where the chain's top was issued by it.
fn through_root(chain: &[String], root: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = chain.to_vec();
    if let (Some(top), Some(root)) = (chain.last(), root) {
        if !out.iter().any(|c| c == root)
            && sts_crypto::keys::certificate_signed_by(top, root)
        {
            out.push(root.to_string());
        }
    }
    out
}

/// `IssuerNames.issuer(base)` through `oauth2.issuerOf()`: a pinned
/// `oauth2.issuer` wins — upgraded to `https://` on an HTTPS listener —
/// and otherwise the base (#523).
fn issuer_of(settings: &Settings, base: &str) -> String {
    let pinned = settings.value_of("oauth2.issuer").as_str().to_string();
    if pinned.is_empty() {
        return base.to_string();
    }
    if settings.value_of("global.https").as_bool()
        && pinned.len() >= 7
        && pinned[..7].eq_ignore_ascii_case("http://")
    {
        return format!("https://{}", &pinned[7..]);
    }
    pinned
}

/// A base64 DER as PEM.
fn pem_of(b64: &str) -> String {
    sts_saml::sp_signature::pem_of(b64)
}

impl SamlStack {
    /// The stores, under Node's handles, before the store opens.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare(
        settings: Arc<Settings>,
        mode: Arc<Mode>,
        persistence: Arc<Persistence>,
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
    ) -> Arc<SamlStack> {
        let spec = |handle: &str| StoreSpec {
            retain: Retain::Age,
            expires_at: Some(expiry_field(Some("expires"), 1.0)),
            ..StoreSpec::persisted(handle)
        };
        Arc::new(SamlStack {
            settings,
            mode,
            persistence,
            artifacts: RealmMap::new(
                lifecycle,
                handles,
                spec(sts_saml::artifact::STORE_HANDLE),
            ),
            pending: RealmMap::new(
                lifecycle,
                handles,
                spec("saml2_sso.pendingRequests"),
            ),
            back_channel: OnceLock::new(),
        })
    }

    /// What the back channel presents (`listener_keys.ts`), once the
    /// listeners are made.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn set_back_channel(&self, source: BackChannel) {
        if self.back_channel.set(source).is_err() {
            tracing::debug!("saml2: the back channel was already set");
        }
    }

    /// The realm's XML signer (`STS.xmlSigner`) for rsa-sha256 and the
    /// configured canonicalization: the key set's `xmlKey`, with the
    /// certificate its hierarchy issued over it where there is one.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn signer(&self) -> Option<(XmlSigner, Vec<Published>)> {
        let sets = self.persistence.key_sets()?;
        let realm = sts_core::realm::current_id();
        let set = sets.open(&realm)?;
        let xml = set.blob.get("xmlKey")?;
        let private_key_pem = xml.get("privateKeyPem")?.as_str()?.to_string();
        let self_b64 = xml.get("certB64")?.as_str()?.to_string();
        let kid = sts_store::key_sets::kid_of(&self_b64);
        let (cert_b64, chain) = sets
            .published_certificate_for(&realm, "xml", "RS256", &kid)
            .unwrap_or((self_b64, Vec::new()));
        let root = self.back_channel.get().and_then(|f| f().2);
        let chain_pem: Vec<String> = chain.iter().map(|c| pem_of(c)).collect();
        let chain_pem = through_root(&chain_pem, root.as_deref());
        let cert_pem = pem_of(&cert_b64);
        // `documentSettings.signatureOptions()`: exclusive only, with or
        // without comments; the RSA family's rsa-sha256 (the other
        // algorithms' group keys are not ported).
        let c14n_alg = match self
            .settings
            .value_of("saml.canonicalizationAlgorithm")
            .as_str()
        {
            "exclusive-with-comments" => xmldsig::uri::C14N_EXCLUSIVE_WC,
            _ => xmldsig::uri::C14N_EXCLUSIVE,
        };
        let published = vec![Published {
            cert_pem: cert_pem.clone(),
            chain_pem: chain_pem.clone(),
        }];
        Some((
            XmlSigner {
                private_key_pem,
                cert_pem,
                chain_pem,
                sig_alg: xmldsig::uri::RSA_SHA256.to_string(),
                c14n_alg: c14n_alg.to_string(),
                policy: xml_policy(&self.settings, &self.mode),
            },
            published,
        ))
    }

    /// `listenerKeys.keyDescriptors()`: one signing KeyDescriptor per
    /// certificate the back channel presents, on an HTTPS main port.
    fn back_channel_keys(&self) -> String {
        if !self.settings.value_of("global.https").as_bool() {
            return String::new();
        }
        let Some((certs, chain, root)) = self.back_channel.get().map(|f| f())
        else {
            return String::new();
        };
        let chain = through_root(&chain, root.as_deref());
        let mut seen: Vec<String> = Vec::new();
        let mut out = String::new();
        for pem in certs {
            let b64 = sts_saml::assertion::strip_pem(&pem);
            if b64.is_empty() || seen.contains(&b64) {
                continue;
            }
            seen.push(b64);
            out.push_str(&format!(
                "<md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"{}\">\
                 {}</ds:KeyInfo></md:KeyDescriptor>",
                xmldsig::uri::DS_NS,
                sts_saml::assertion::x509_data_xml(&pem, &chain)
            ));
        }
        out
    }

    /// `metadataFor(base, '')`: the unscoped document.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn metadata_document(&self, base: &str, issuer: &str) -> String {
        let s = &self.settings;
        let policy = xml_policy(s, &self.mode);
        let (digests, signing) = xmldsig::xml_algorithm_support(&policy);
        // `config.value('saml2.publishAlgorithmSupport') === false`.
        let support = if s.value_of("saml2.publishAlgorithmSupport").as_bool() {
            metadata::algorithm_support(&digests, &signing)
        } else {
            String::new()
        };
        let need = sts_saml::sp_signature::Requirement {
            declared: String::new(),
            setting: s
                .value_of("saml2.requireSignedAuthnRequests")
                .as_str()
                .to_string(),
            accepts_unsigned: self.mode.accepts_unsigned_saml_requests(),
        };
        let Some((signer, published)) = self.signer() else {
            tracing::error!(
                "{}the SAML 2.0 metadata has no XML signing key in this realm",
                sts_core::log::tag(
                    sts_core::errors::codes::STS_SAML_0014.as_str()
                )
            );
            return String::new();
        };
        let inputs = MetadataInputs {
            id: sts_saml::assertion::gen_id(),
            idp_entity_id: issuer.to_string(),
            base: base.to_string(),
            endpoints: metadata::endpoints_for(base, ""),
            signing: published.clone(),
            encryption: published,
            back_channel_keys: self.back_channel_keys(),
            saml11: metadata::saml11_parts(base, ""),
            wsfed_role: String::new(),
            elsewhere: Vec::new(),
            want_authn_requests_signed: need.required().0,
            pki_base: base.to_string(),
            algorithm_support: support,
            organization: metadata::organization_element(
                s.value_of("saml.organizationName").as_str(),
                s.value_of("saml.organizationDisplayName").as_str(),
                s.value_of("saml.organizationUrl").as_str(),
                base,
            ),
        };
        metadata::metadata_for(&inputs, &signer)
    }

    /// The routes ported so far.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn router(
        self: &Arc<Self>,
        http: Arc<sts_http::HttpLayer>,
    ) -> axum::Router {
        let me = self.clone();
        axum::Router::new()
            .route(
                sts_saml::binding::AUTOPOST_PATH,
                axum::routing::get(|| async { autopost() }),
            )
            .route(
                metadata::METADATA_PATH,
                axum::routing::get(move |r: AxumRequest| {
                    let (me, http) = (me.clone(), http.clone());
                    async move { me.serve_metadata(&http, r) }
                }),
            )
    }

    /// `artifactCount()` and `pendingRequestCount()`: what the ambient
    /// realm holds unresolved, for the console.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn counts(&self) -> (usize, usize) {
        (self.artifacts.len(), self.pending.len())
    }

    /// `serveMetadata()` for the unscoped document.
    fn serve_metadata(
        &self,
        http: &sts_http::HttpLayer,
        request: AxumRequest,
    ) -> Response {
        let over_tls = request
            .extensions()
            .get::<sts_http::cookie_wire::OverTls>()
            .is_some();
        let prefix = http.registry().current_prefix();
        let base = sts_authn_api::router::base_of(
            &self.settings,
            request.headers(),
            over_tls,
            &prefix,
        );
        let issuer = issuer_of(&self.settings, &base);
        let body = self.metadata_document(&base, &issuer);
        let (artifacts, pending) = self.counts();
        tracing::debug!(
            "saml2: metadata served; {} artifact(s) and {} request(s) held",
            artifacts,
            pending
        );
        (
            axum::http::StatusCode::OK,
            [
                (
                    axum::http::header::CONTENT_TYPE,
                    "application/samlmetadata+xml; charset=utf-8",
                ),
                (axum::http::header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response()
    }
}

/// `GET /saml2/autopost.js`: the one script the POST binding's page names,
/// under the policy without `style-src` and `img-src`.
fn autopost() -> Response {
    let mut response = (
        axum::http::StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        sts_saml::binding::AUTOPOST_SCRIPT,
    )
        .into_response();
    if let Ok(v) = axum::http::HeaderValue::from_str(
        &sts_http::csp::content_security_policy(&[
            ("style-src", None),
            ("img-src", None),
        ]),
    ) {
        response.headers_mut().insert("content-security-policy", v);
    }
    response
}
