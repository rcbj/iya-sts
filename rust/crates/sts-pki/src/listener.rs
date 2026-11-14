// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The key material every TLS listener presents (#444 phase 3, the `tls`
//! slice): `tls/tls_server.js`'s `makeServerCertificate()`,
//! `makeMlDsaServerCertificate()`, `suppliedServerCertificate()` and
//! `presentedBundlePem()`, and the part of `common/pki.js` that certifies
//! the listener — the service Root, the PROCESS Intermediate and its TLS
//! Issuing CA (`USE_CASES`' `tls`), and the leaf over the listener's own
//! key.
//!
//! **What is here and what is not.** `common/pki.js` keeps its hierarchy in
//! the keystore (`pki:*service`, `pki:*process` rows), rebuilds it on
//! `POST /admin-api/pki/build-root`, and serves its CRLs and OCSP; that is
//! phase 6. Until then [`ProcessBranch`] is the same three certificates
//! built IN MEMORY with the profiles, names, lifetimes and distribution
//! points `pki.js` gives them — which is exactly what Node does in
//! development mode, where the Root is built afresh at every start. A
//! product install's stored Root is not read yet; the runtime says so when
//! it starts (`sts-runtime`'s listener module).
//!
//! The listener KEY is made once per start (the self-signed bootstrap) and
//! the leaf is issued OVER IT, as `settleListenerKey()` and
//! `takeIssuedCertificate()` do: a socket never holds a key without its
//! certificate. Keeping that key per node in `tls.listenerKeys` where
//! minted state persists is phase 6's with the rest of the hierarchy.
//!
//! Everything a listener needs from OpenSSL's X.509 and key types is built
//! here, because this crate and `sts-crypto` are the crypto module (the
//! guard `crypto_centralised`): the TLS layer is handed
//! [`OpenedCredential`]s and anchors and names no `openssl::x509` itself.

use chrono::{DateTime, Duration, Utc};
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use serde_json::{json, Value as Json};

use crate::error::{PkiError, PkiResult};
use crate::x509::extensions as ext;
use crate::x509::issue::{issue_certificate, random_serial_hex};
use crate::x509::keys::{describe_spki, pem_to_der};
use crate::x509::read::Certificate;

/// Where a listener certificate came from (`certificateProvenance()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Made at this start and self-signed: no hierarchy certified it.
    SelfSigned,
    /// A leaf of the process branch's TLS Issuing CA, over the key made
    /// at this start.
    Issued,
    /// `tls.certificateFile` and `tls.keyFile`: somebody else's.
    Supplied,
}

/// The names a listener certificate is made for, and the literals
/// `tls.selfSigned*` replaced.
#[derive(Debug, Clone)]
pub struct ListenerIdentity {
    /// `tls.hostnames`: the first is the CN, all are dNSNames.
    pub hostnames: Vec<String>,
    /// `tls.ips`: iPAddress names.
    pub ips: Vec<String>,
    /// `tls.selfSignedOrganization`: the O= of the leaf.
    pub organisation: String,
    /// `tls.selfSignedKeyBits`: the RSA modulus.
    pub rsa_bits: u32,
    /// `tls.selfSignedValidityYears`: a self-signed certificate's life.
    pub self_signed_years: i32,
}

impl ListenerIdentity {
    fn common_name(&self) -> String {
        self.hostnames
            .first()
            .filter(|h| !h.is_empty())
            .cloned()
            .unwrap_or_else(|| "localhost".to_string())
    }

    /// `CN=<first hostname>, O=<organisation>`, the subject Node reports.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn subject(&self) -> String {
        format!("CN={}, O={}", self.common_name(), self.organisation)
    }

    fn alt_names(&self) -> Json {
        let mut names: Vec<Json> = self
            .hostnames
            .iter()
            .map(|h| json!({ "kind": "dns", "value": h }))
            .collect();
        names.extend(
            self.ips
                .iter()
                .map(|ip| json!({ "kind": "ip", "value": ip })),
        );
        Json::Array(names)
    }
}

/// One certificate a listener presents, with what it travels with.
#[derive(Debug, Clone)]
pub struct ListenerCertificate {
    /// `rsa`, `ml-dsa-44`/`65`/`87`, or `supplied`.
    pub algorithm: String,
    pub private_key_pem: String,
    pub cert_pem: String,
    /// The issuers it is STORED with, leaf-first, without the Root
    /// (`chainPem`).
    pub chain_pem: Vec<String>,
    /// What a caller verifies it against (`trustAnchorPem`): the Root,
    /// or the certificate itself when it is self-signed.
    pub anchor_pem: Option<String>,
    pub provenance: Provenance,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    /// `openssl x509 -fingerprint -sha256`'s spelling.
    pub fingerprint256: String,
}

/// A listener certificate as OpenSSL takes it.
pub struct OpenedCredential {
    pub leaf: X509,
    /// Everything sent after the leaf (`presentedBundlePem()` less it).
    pub chain: Vec<X509>,
    pub key: PKey<Private>,
}

impl ListenerCertificate {
    /// `presentedBundlePem()` (#1064): the leaf, its chain and the Root —
    /// every listener sends four certificates where there is a hierarchy.
    /// Sending the Root trusts nothing (RFC 5280 section 6.1) and lets a
    /// client SHOW which Root it chained to.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn presented_pems(&self) -> Vec<String> {
        let mut out = vec![self.cert_pem.clone()];
        out.extend(self.chain_pem.iter().cloned());
        if let Some(root) = &self.anchor_pem {
            let already = out.iter().any(|p| same_certificate(p, root));
            if !already {
                out.push(root.clone());
            }
        }
        out
    }

    /// The bundle, concatenated: what `GET /tls/server-certificate`
    /// publishes ahead of the Root.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn presented_bundle_pem(&self) -> String {
        self.presented_pems().concat()
    }

    /// The certificate, its chain and its key as OpenSSL objects.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn open(&self) -> PkiResult<OpenedCredential> {
        let mut pems = self.presented_pems().into_iter();
        let leaf_pem = pems.next().unwrap_or_default();
        let leaf = X509::from_pem(leaf_pem.as_bytes())?;
        let chain = pems
            .map(|p| X509::from_pem(p.as_bytes()).map_err(PkiError::from))
            .collect::<PkiResult<Vec<X509>>>()?;
        let key = PKey::private_key_from_pem(self.private_key_pem.as_bytes())?;
        Ok(OpenedCredential { leaf, chain, key })
    }

    /// Whether two thirds of its life are gone (`tls/listeners.js`'s
    /// `renewDue()`), at `now`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn renewal_due(&self, now: DateTime<Utc>) -> bool {
        let life = self.not_after - self.not_before;
        life > Duration::zero() && now >= self.not_before + (life * 2) / 3
    }
}

fn body_of(pem: &str) -> String {
    pem.lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::trim)
        .collect()
}

fn same_certificate(a: &str, b: &str) -> bool {
    body_of(a) == body_of(b)
}

/// SHA-256 over the DER, colon-separated upper-case hex
/// (`certificateThumbprint(…, { format: 'colon-hex' })`).
#[tracing::instrument(level = "debug", skip_all)]
pub fn fingerprint_colon_hex(der: &[u8]) -> String {
    sts_crypto::jws_alg::Hash::Sha256
        .digest(der)
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Every PEM certificate in a text, each re-normalised to end in a
/// newline (`splitPemCertificates()`): concatenated PEMs are
/// self-delimiting.
#[tracing::instrument(level = "debug", skip_all)]
pub fn split_pem_certificates(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start..];
        let Some(end) = after.find(END) else {
            break;
        };
        out.push(format!("{}\n", &after[..end + END.len()]));
        rest = &after[end + END.len()..];
    }
    out
}

fn generate_key(algorithm: &str, rsa_bits: u32) -> PkiResult<PKey<Private>> {
    let a = algorithm.to_ascii_lowercase();
    if let Some(bits) = a.strip_prefix("rsa-") {
        let bits: u32 = bits.parse().unwrap_or(2048);
        return Ok(PKey::from_rsa(openssl::rsa::Rsa::generate(bits)?)?);
    }
    if a == "rsa" {
        return Ok(PKey::from_rsa(openssl::rsa::Rsa::generate(rsa_bits)?)?);
    }
    if let Some(curve) = a.strip_prefix("ec-") {
        let nid = match curve {
            "p384" => openssl::nid::Nid::SECP384R1,
            "p521" => openssl::nid::Nid::SECP521R1,
            _ => openssl::nid::Nid::X9_62_PRIME256V1,
        };
        let group = openssl::ec::EcGroup::from_curve_name(nid)?;
        return Ok(PKey::from_ec_key(openssl::ec::EcKey::generate(&group)?)?);
    }
    if a == "ed25519" {
        return Ok(PKey::generate_ed25519()?);
    }
    // ML-DSA and SLH-DSA by their OpenSSL names.
    Ok(sts_crypto::pq::generate(&a.to_ascii_uppercase())?)
}

fn pem_pair(key: &PKey<Private>) -> PkiResult<(String, String)> {
    let private = String::from_utf8(key.private_key_to_pem_pkcs8()?)
        .map_err(|e| PkiError::new(e.to_string()))?;
    let public = String::from_utf8(key.public_key_to_pem()?)
        .map_err(|e| PkiError::new(e.to_string()))?;
    Ok((private, public))
}

/// The signature algorithm a key of this algorithm signs with
/// (`defaultSignatureAlgorithm()`).
fn signature_alg_for(algorithm: &str) -> String {
    let a = algorithm.to_ascii_lowercase();
    if a.starts_with("rsa") {
        "sha256-rsa".to_string()
    } else if a == "ec-p384" {
        "sha384-ecdsa".to_string()
    } else if a == "ec-p521" {
        "sha512-ecdsa".to_string()
    } else if a.starts_with("ec-") {
        "sha256-ecdsa".to_string()
    } else {
        a
    }
}

/// `certificateSerial(prefix)`: the caller's byte in front of random
/// bytes, sixteen in all, positive.
fn prefixed_serial(prefix: u8) -> PkiResult<String> {
    let tail = random_serial_hex(15)?;
    let head = match prefix & 0x7f {
        0 => 1,
        b => b,
    };
    Ok(format!("{:02x}{}", head, tail))
}

/// The self-signed bootstrap (`makeServerCertificate()`, and
/// `makeMlDsaServerCertificate()` for an `ml-dsa-*` algorithm): a key made
/// now and a certificate over it, `CA:FALSE`, serverAuth, every name in
/// the subjectAltName. Its serial's leading byte is `03` (RSA) or `04`
/// (ML-DSA), so a capture still says which certificate it is.
#[tracing::instrument(level = "debug", skip(identity))]
pub fn bootstrap(
    identity: &ListenerIdentity,
    algorithm: &str,
) -> PkiResult<ListenerCertificate> {
    let rsa = algorithm == "rsa";
    let key = generate_key(algorithm, identity.rsa_bits)?;
    let (private_pem, public_pem) = pem_pair(&key)?;
    let now = Utc::now();
    let usages: Vec<&str> = if rsa {
        vec!["digitalSignature", "keyEncipherment"]
    } else {
        vec!["digitalSignature"]
    };
    let mut extensions = ext::default_extensions("");
    extensions["basicConstraints"] =
        json!({ "present": true, "ca": false, "critical": true });
    extensions["keyUsage"] =
        json!({ "present": true, "usages": usages, "critical": true });
    extensions["extKeyUsage"] = json!({ "present": true,
        "usages": ["serverAuth"], "critical": false });
    extensions["subjectAltName"] = json!({ "present": true,
        "names": identity.alt_names(), "critical": false });
    // node-forge wrote these four and no key identifiers.
    extensions["subjectKeyIdentifier"] = json!({ "present": false });
    extensions["authorityKeyIdentifier"] = json!({ "present": false });
    let issued = issue_certificate(&json!({
        "subject": identity.subject().replace(", ", ","),
        "subjectPublicKey": public_pem,
        "issuerPrivateKey": private_pem,
        "signatureAlg": signature_alg_for(algorithm),
        "serial": prefixed_serial(if rsa { 0x03 } else { 0x04 })?,
        "notBefore": now.to_rfc3339(),
        "notAfter": add_years(now, identity.self_signed_years.max(1))
            .to_rfc3339(),
        "extensions": extensions,
    }))?;
    Ok(ListenerCertificate {
        algorithm: algorithm.to_string(),
        private_key_pem: private_pem,
        anchor_pem: Some(issued.pem.clone()),
        cert_pem: issued.pem,
        chain_pem: Vec::new(),
        provenance: Provenance::SelfSigned,
        not_before: now,
        not_after: add_years(now, identity.self_signed_years.max(1)),
        fingerprint256: fingerprint_colon_hex(&issued.der),
    })
}

fn add_years(t: DateTime<Utc>, years: i32) -> DateTime<Utc> {
    use chrono::Datelike;
    t.with_year(t.year() + years)
        .unwrap_or_else(|| t + Duration::days(365 * i64::from(years)))
}

/// Where a certificate's issuer publishes its revocation status
/// (`pki_revocation.js`'s `distributionPoints()`): the http and ldap CRL
/// addresses, the OCSP responder and caIssuers.
#[derive(Debug, Clone)]
pub struct DistributionPoints {
    /// `httpBase()`: `pki.distributionBaseUrl`, else the plain revocation
    /// listener `http://<first hostname>:<pki.distributionPort or
    /// pki.httpPort>`, else the main port in its scheme.
    pub http_base: String,
    /// `ldap://<host>:<port>`: `pki.distributionLdapHost` or the first
    /// hostname, `pki.distributionLdapPort` or `ldap.port`.
    pub ldap_base: String,
    /// The default realm's base DN (`dc=example,dc=com`).
    pub directory_base: String,
}

impl DistributionPoints {
    fn of(&self, scope: &str, ca: &str) -> Json {
        let file = format!("{}/{}", scope, ca);
        let dn =
            format!("cn={},ou={},ou=crl,{}", ca, scope, self.directory_base);
        json!({
            "crl": [
                format!("{}/pki/crl/{}.crl", self.http_base, file),
                format!(
                    "{}/{}?certificateRevocationList;binary",
                    self.ldap_base,
                    encode_uri(&dn)
                ),
            ],
            "ocsp": format!("{}/pki/ocsp/{}", self.http_base, file),
            "caIssuers": format!("{}/pki/ca/{}.cer", self.http_base, file),
        })
    }
}

/// JavaScript's `encodeURI()`: everything but the unreserved and reserved
/// characters percent-encoded as UTF-8.
fn encode_uri(text: &str) -> String {
    const KEEP: &str = "-_.!~*'();/?:@&=+$,#";
    let mut out = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || KEEP.contains(c) {
            out.push(c);
        } else {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

fn with_points(mut extensions: Json, points: &Json) -> Json {
    extensions["cRLDistributionPoints"] = json!({ "present": true,
        "urls": points["crl"].clone(), "critical": false });
    extensions["authorityInfoAccess"] = json!({ "present": true,
        "entries": [
            { "method": "ocsp", "url": points["ocsp"].clone() },
            { "method": "caIssuers", "url": points["caIssuers"].clone() },
        ],
        "critical": false });
    extensions
}

/// One authority of the branch: its certificate and key.
#[derive(Debug, Clone)]
struct Authority {
    cert_pem: String,
    key_pem: String,
    key_algorithm: String,
    not_after: DateTime<Utc>,
}

/// What the branch is built from: `pki.organisation`, `pki.keyAlgorithm`,
/// the three `pki.*LifetimeYears` (0 is the profile's 20, 10 and 5), and
/// where its addresses point.
#[derive(Debug, Clone)]
pub struct BranchOptions {
    pub organisation: String,
    pub key_algorithm: String,
    pub root_years: i32,
    pub intermediate_years: i32,
    pub issuing_years: i32,
    pub points: DistributionPoints,
}

/// THE KEY ALGORITHMS A LISTENER'S CHAIN CANNOT CARRY (#1412's rule, the
/// memory note "PQC limited by the ecosystem"): a composite ML-DSA key on
/// the Root or the process branch is on every listener's chain, and
/// OpenSSL cannot read one, so every listener would refuse its new
/// certificate. `pki.js` refuses one a caller names (`STS-PKI-0272`) and
/// falls back to the classical default where only `pki.keyAlgorithm`
/// names it (`STS-PKI-0273`).
#[tracing::instrument(level = "debug", skip_all)]
pub fn is_composite(key_algorithm: &str) -> bool {
    let a = key_algorithm.to_ascii_lowercase();
    a.starts_with("mldsa") && a.contains('-')
}

/// The service Root, the process Intermediate and its TLS Issuing CA —
/// `common/pki.js`'s `*service` and `*process` scopes as development mode
/// builds them at every start (the stand-in until phase 6 reads the
/// stored ones).
#[derive(Debug, Clone)]
pub struct ProcessBranch {
    root: Authority,
    intermediate: Authority,
    issuing: Authority,
    points: DistributionPoints,
}

impl ProcessBranch {
    /// Builds the three, Root first (`TIERS`' order). A composite key
    /// algorithm falls back to `rsa-2048`, and the caller is told
    /// (`fell_back`) so it can log `STS-PKI-0273`.
    #[tracing::instrument(level = "debug", skip(options))]
    pub fn build(options: &BranchOptions) -> PkiResult<(ProcessBranch, bool)> {
        let fell_back = is_composite(&options.key_algorithm);
        let algorithm = if fell_back || options.key_algorithm.is_empty() {
            "rsa-2048".to_string()
        } else {
            options.key_algorithm.clone()
        };
        let org = &options.organisation;
        let root = authority(
            &algorithm,
            &format!("CN={} Root CA,O={}", org, org),
            "root-ca",
            pick_years(options.root_years, 20),
            None,
            None,
        )?;
        let service_points = options.points.of("service", "root");
        let intermediate = authority(
            &algorithm,
            &format!("CN={} Intermediate CA (Process),O={}", org, org),
            "intermediate-ca",
            pick_years(options.intermediate_years, 10),
            Some(&root),
            Some(&service_points),
        )?;
        let process_points = options.points.of("process", "intermediate");
        let issuing = authority(
            &algorithm,
            &format!("CN={} TLS Issuing CA (Process),O={}", org, org),
            "issuing-ca",
            pick_years(options.issuing_years, 5),
            Some(&intermediate),
            Some(&process_points),
        )?;
        Ok((
            ProcessBranch {
                root,
                intermediate,
                issuing,
                points: options.points.clone(),
            },
            fell_back,
        ))
    }

    /// The service Root, PEM.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn root_pem(&self) -> &str {
        &self.root.cert_pem
    }

    /// `certify()` for the `tls:server` slot: a leaf of the TLS Issuing CA
    /// over the bootstrap's own key, for the same names, `leaf_days` long
    /// (clamped to the Issuing CA's own expiry, as `pki.leafLifetimeDays`
    /// is). `digitalSignature` and `keyEncipherment` for RSA,
    /// `digitalSignature` alone for ML-DSA (`serverCertificateExtensions()`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn certify(
        &self,
        bootstrap: &ListenerCertificate,
        identity: &ListenerIdentity,
        leaf_days: i64,
    ) -> PkiResult<ListenerCertificate> {
        let key =
            PKey::private_key_from_pem(bootstrap.private_key_pem.as_bytes())?;
        let (_, public_pem) = pem_pair(&key)?;
        let now = Utc::now();
        let mut not_after = now + Duration::days(leaf_days.max(1));
        if not_after > self.issuing.not_after {
            not_after = self.issuing.not_after;
        }
        let usages: Vec<&str> = if bootstrap.algorithm == "rsa" {
            vec!["digitalSignature", "keyEncipherment"]
        } else {
            vec!["digitalSignature"]
        };
        let mut extensions = ext::default_extensions("");
        extensions["basicConstraints"] =
            json!({ "present": true, "ca": false, "critical": true });
        extensions["keyUsage"] =
            json!({ "present": true, "usages": usages, "critical": true });
        extensions["extKeyUsage"] = json!({ "present": true,
            "usages": ["serverAuth"], "critical": false });
        extensions["subjectAltName"] = json!({ "present": true,
            "names": identity.alt_names(), "critical": false });
        let extensions =
            with_points(extensions, &self.points.of("process", "tls"));
        let issued = issue_certificate(&json!({
            "subject": identity.subject().replace(", ", ","),
            "subjectPublicKey": public_pem,
            "issuer": { "certificatePem": self.issuing.cert_pem,
                        "privateKeyPem": self.issuing.key_pem },
            "signatureAlg": signature_alg_for(&self.issuing.key_algorithm),
            "notBefore": now.to_rfc3339(),
            "notAfter": not_after.to_rfc3339(),
            "extensions": extensions,
        }))?;
        Ok(ListenerCertificate {
            algorithm: bootstrap.algorithm.clone(),
            private_key_pem: bootstrap.private_key_pem.clone(),
            fingerprint256: fingerprint_colon_hex(&issued.der),
            cert_pem: issued.pem,
            chain_pem: vec![
                self.issuing.cert_pem.clone(),
                self.intermediate.cert_pem.clone(),
            ],
            anchor_pem: Some(self.root.cert_pem.clone()),
            provenance: Provenance::Issued,
            not_before: now,
            not_after,
        })
    }

    /// `strandedListenerCertificates()`' question: whether a certificate
    /// travels with THIS branch's Issuing CA and Intermediate, certificate
    /// for certificate — the signature is not enough, two Roots of one name
    /// being the case to tell apart.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn holds_chain_of(&self, certificate: &ListenerCertificate) -> bool {
        certificate.chain_pem.len() == 2
            && same_certificate(
                &certificate.chain_pem[0],
                &self.issuing.cert_pem,
            )
            && same_certificate(
                &certificate.chain_pem[1],
                &self.intermediate.cert_pem,
            )
    }
}

fn pick_years(set: i32, profile: i32) -> i32 {
    if set > 0 {
        set
    } else {
        profile
    }
}

fn authority(
    algorithm: &str,
    subject: &str,
    profile: &str,
    years: i32,
    issuer: Option<&Authority>,
    points: Option<&Json>,
) -> PkiResult<Authority> {
    let key = generate_key(algorithm, 2048)?;
    let (private_pem, public_pem) = pem_pair(&key)?;
    let now = Utc::now();
    let mut not_after = add_years(now, years);
    if let Some(i) = issuer {
        if not_after > i.not_after {
            not_after = i.not_after;
        }
    }
    let mut extensions = ext::default_extensions(profile);
    if let Some(points) = points {
        extensions = with_points(extensions, points);
    }
    let spec = match issuer {
        Some(i) => json!({
            "subject": subject,
            "subjectPublicKey": public_pem,
            "issuer": { "certificatePem": i.cert_pem,
                        "privateKeyPem": i.key_pem },
            "signatureAlg": signature_alg_for(&i.key_algorithm),
            "notBefore": now.to_rfc3339(),
            "notAfter": not_after.to_rfc3339(),
            "profile": profile,
            "extensions": extensions,
        }),
        None => json!({
            "subject": subject,
            "subjectPublicKey": public_pem,
            "issuerPrivateKey": private_pem,
            "signatureAlg": signature_alg_for(algorithm),
            "notBefore": now.to_rfc3339(),
            "notAfter": not_after.to_rfc3339(),
            "profile": profile,
            "extensions": extensions,
        }),
    };
    let issued = issue_certificate(&spec)?;
    Ok(Authority {
        cert_pem: issued.pem,
        key_pem: private_pem,
        key_algorithm: algorithm.to_string(),
        not_after,
    })
}

/// Why a supplied certificate was refused: the code and Node's sentence.
#[derive(Debug, Clone)]
pub struct SuppliedProblem {
    pub code: sts_core::errors::ErrorCode,
    pub message: String,
}

/// `suppliedServerCertificate()`'s checks over the two files' TEXT (the
/// caller reads them, so a file that cannot be read is its `STS-TLS-0003`):
/// a PEM certificate (`STS-TLS-0004`), a readable key (`STS-TLS-0005`)
/// that matches it (`STS-TLS-0006`). The file may be a chain, leaf first,
/// and all of it is sent; a self-signed certificate in it is the anchor.
#[tracing::instrument(level = "debug", skip_all)]
pub fn supplied(
    cert_file: &str,
    cert_text: &str,
    key_file: &str,
    key_text: &str,
) -> Result<ListenerCertificate, SuppliedProblem> {
    use sts_core::errors::codes;
    let pems = split_pem_certificates(cert_text);
    let refuse = |code, message: String| SuppliedProblem { code, message };
    let Some(leaf_pem) = pems.first() else {
        return Err(refuse(
            codes::STS_TLS_0004,
            format!(
                "tls.certificateFile ({}) holds no PEM certificate.",
                cert_file
            ),
        ));
    };
    let leaf = X509::from_pem(leaf_pem.as_bytes()).map_err(|e| {
        refuse(
            codes::STS_TLS_0004,
            format!(
                "tls.certificateFile ({}) is not a PEM certificate: {}",
                cert_file, e
            ),
        )
    })?;
    let key = PKey::private_key_from_pem(key_text.as_bytes()).map_err(|e| {
        refuse(
            codes::STS_TLS_0005,
            format!(
                "tls.keyFile ({}) is not a readable private key: {}",
                key_file, e
            ),
        )
    })?;
    let matches = leaf
        .public_key()
        .map(|public| public.public_eq(&key))
        .unwrap_or(false);
    if !matches {
        return Err(refuse(
            codes::STS_TLS_0006,
            format!(
                "the key in tls.keyFile ({}) does not match the certificate \
                 in tls.certificateFile ({}).",
                key_file, cert_file
            ),
        ));
    }
    let private_pem = key
        .private_key_to_pem_pkcs8()
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| key_text.to_string());
    let read = Certificate::from_pem(leaf_pem).ok();
    // `splitSuppliedBundle()`: a self-signed certificate after the leaf is
    // the anchor and stays out of the chain; it is still SENT (#1064).
    let mut chain = Vec::new();
    let mut anchor = None;
    for pem in pems.iter().skip(1) {
        match Certificate::from_pem(pem) {
            Ok(c) if c.issuer_der == c.subject_der => {
                anchor = Some(pem.clone());
            }
            _ => chain.push(pem.clone()),
        }
    }
    Ok(ListenerCertificate {
        algorithm: "supplied".to_string(),
        private_key_pem: private_pem,
        cert_pem: leaf_pem.clone(),
        chain_pem: chain,
        anchor_pem: anchor,
        provenance: Provenance::Supplied,
        not_before: read.as_ref().map_or_else(Utc::now, |c| c.not_before),
        not_after: read.as_ref().map_or_else(Utc::now, |c| c.not_after),
        fingerprint256: read
            .as_ref()
            .map(|c| fingerprint_colon_hex(&c.der))
            .unwrap_or_default(),
    })
}

/// What the client truststore says about one anchor (`describePem()`).
#[derive(Debug, Clone)]
pub struct AnchorFacts {
    pub subject: String,
    pub issuer: String,
    pub serial_hex: String,
    pub not_before: String,
    pub not_after: String,
    pub fingerprint256: String,
    pub ca: bool,
    pub der: Vec<u8>,
}

/// Reads one anchor PEM, or why OpenSSL cannot.
#[tracing::instrument(level = "debug", skip_all)]
pub fn describe_anchor(pem: &str) -> PkiResult<AnchorFacts> {
    // OpenSSL first: it reads the ML-DSA anchors too, and an anchor it
    // cannot load would make every listener's next context fail.
    X509::from_pem(pem.as_bytes())?;
    let c = Certificate::from_pem(pem)?;
    let ca = crate::x509::read::describe_certificate(&c)
        .ok()
        .and_then(|d| d.pointer("/basicConstraints/ca").and_then(Json::as_bool))
        .unwrap_or(false);
    Ok(AnchorFacts {
        subject: c.subject(),
        issuer: c.issuer(),
        serial_hex: crate::der::hex(&c.serial),
        not_before: c.not_before.to_rfc3339(),
        not_after: c.not_after.to_rfc3339(),
        fingerprint256: fingerprint_colon_hex(&c.der),
        ca,
        der: c.der.clone(),
    })
}

/// The anchors as OpenSSL takes them, for the client truststore.
#[tracing::instrument(level = "debug", skip_all)]
pub fn open_anchors(pems: &[String]) -> PkiResult<Vec<X509>> {
    pems.iter()
        .map(|p| X509::from_pem(p.as_bytes()).map_err(PkiError::from))
        .collect()
}

/// The EC curves a client certificate may be on (`ACCEPTED_CLIENT_CURVES`):
/// the NIST set. #212 found a third-party defect reachable through a
/// certificate on any other curve; such a chain is refused before any
/// certificate object is built from it.
const ACCEPTED_CURVES: &[&str] = &["P-256", "P-384", "P-521"];

/// `nonNistCurvePeerCertificate()`: whether any certificate of a chain
/// (DER, leaf first) has an EC key on a curve outside the NIST set. An
/// unreadable SPKI is not judged here: the path rules refuse it.
// A hot path: asked of every connection, so no span of its own.
pub fn chain_has_refused_curve(chain: &[Vec<u8>]) -> bool {
    chain.iter().any(|der| {
        let Ok(c) = Certificate::from_der(der) else {
            return false;
        };
        match describe_spki(&c.spki) {
            Some(d) if d.kind() == "ec" => !d
                .curve()
                .is_some_and(|curve| ACCEPTED_CURVES.contains(&curve)),
            _ => false,
        }
    })
}

/// A PEM's DER, for a caller that holds a chain as text.
#[tracing::instrument(level = "debug", skip_all)]
pub fn der_of_pem(pem: &str) -> PkiResult<Vec<u8>> {
    pem_to_der(pem)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // tests

    use super::*;

    fn identity() -> ListenerIdentity {
        ListenerIdentity {
            hostnames: vec!["localhost".into(), "sts".into()],
            ips: vec!["127.0.0.1".into()],
            organisation: "iya-sts".into(),
            rsa_bits: 2048,
            self_signed_years: 2,
        }
    }

    fn options() -> BranchOptions {
        BranchOptions {
            organisation: "iya-sts".into(),
            key_algorithm: "rsa-2048".into(),
            root_years: 0,
            intermediate_years: 0,
            issuing_years: 0,
            points: DistributionPoints {
                http_base: "http://localhost:8082".into(),
                ldap_base: "ldap://localhost:389".into(),
                directory_base: "dc=example,dc=com".into(),
            },
        }
    }

    #[test]
    fn a_bootstrap_is_self_signed_and_its_own_anchor() {
        let b = bootstrap(&identity(), "rsa").unwrap();
        assert_eq!(b.provenance, Provenance::SelfSigned);
        assert_eq!(b.presented_pems().len(), 1);
        let c = Certificate::from_pem(&b.cert_pem).unwrap();
        assert_eq!(c.subject_der, c.issuer_der);
        assert!(crate::der::hex(&c.serial).starts_with("03"));
    }

    #[test]
    fn the_listener_presents_leaf_issuing_intermediate_root() {
        let id = identity();
        let b = bootstrap(&id, "rsa").unwrap();
        let (branch, fell_back) = ProcessBranch::build(&options()).unwrap();
        assert!(!fell_back);
        let leaf = branch.certify(&b, &id, 365).unwrap();
        let pems = leaf.presented_pems();
        assert_eq!(pems.len(), 4);
        let refs: Vec<&str> = pems.iter().map(String::as_str).collect();
        crate::x509::read::verify_chain(&refs).unwrap();
        let subjects: Vec<String> = pems
            .iter()
            .map(|p| Certificate::from_pem(p).unwrap().subject())
            .collect();
        assert!(subjects[1].contains("TLS Issuing CA (Process)"));
        assert!(subjects[2].contains("Intermediate CA (Process)"));
        assert!(subjects[3].contains("iya-sts Root CA"));
        // Over the bootstrap's own key.
        assert_eq!(leaf.private_key_pem, b.private_key_pem);
        assert!(branch.holds_chain_of(&leaf));
        assert!(leaf.open().is_ok());
    }

    #[test]
    fn a_composite_root_falls_back() {
        let mut o = options();
        o.key_algorithm = "mldsa65-ecdsa-p256-sha512".into();
        let (_, fell_back) = ProcessBranch::build(&o).unwrap();
        assert!(fell_back);
    }

    #[test]
    fn a_supplied_pair_that_does_not_match_is_refused() {
        let a = bootstrap(&identity(), "rsa").unwrap();
        let b = bootstrap(&identity(), "rsa").unwrap();
        let err = supplied("c", &a.cert_pem, "k", &b.private_key_pem)
            .err()
            .unwrap();
        assert_eq!(err.code, sts_core::errors::codes::STS_TLS_0006);
        assert!(supplied("c", &a.cert_pem, "k", &a.private_key_pem).is_ok());
    }

    #[test]
    fn encode_uri_keeps_a_dn() {
        assert_eq!(
            encode_uri("cn=tls,ou=process,ou=crl,dc=example,dc=com"),
            "cn=tls,ou=process,ou=crl,dc=example,dc=com"
        );
        assert_eq!(encode_uri("a b"), "a%20b");
    }
}
