// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Somebody else's certificates (`pki.js` #40, #105, #170, #62 P5): PEM
//! bundles of an operator's anchors, a WebAuthn attestation certificate's
//! facts, OpenSSH keys and host certificates, the FIDO Metadata Service's
//! signed BLOB, and a sigstore signing certificate with its embedded SCTs.
//! Every path in here is `path::verify_path_to_anchors()`; every signature
//! `sts-crypto`'s.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{TimeZone, Utc};
use openssl::bn::BigNumContext;
use openssl::hash::{hash, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Public};
use serde_json::{json, Map, Value as Json};
use sts_crypto::raw_sig::{self, EcdsaEncoding, RawFamily, RawHash, RawScheme};
use sts_crypto::{jws, keys as jose_keys, pq_x509, sigstore};

use crate::der;
use crate::path::entry::{name_lines, one_line_name};
use crate::path::{self, Entry, PathOptions};
use crate::x509::read::Certificate;
use crate::x509::time;

/// `certificateBundle()`: every certificate in a PEM text, a block that does
/// not parse counted and skipped.
pub fn certificate_bundle(pem_text: &str) -> (Vec<Entry>, usize) {
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    let mut certificates = Vec::new();
    let mut unreadable = 0;
    let mut rest = pem_text;
    while let Some(a) = rest.find(begin) {
        let after = &rest[a + begin.len()..];
        let Some(b) = after.find(end) else {
            break;
        };
        let body: String =
            after[..b].chars().filter(|c| !c.is_whitespace()).collect();
        let der = node_base64(&body);
        match Entry::from_der(&der) {
            Some(e) => certificates.push(e),
            None => unreadable += 1,
        }
        rest = &after[b + end.len()..];
    }
    (certificates, unreadable)
}

/// `Buffer.from(text, 'base64')`, lenient as node is.
pub fn node_base64(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => continue,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn colon_hex_lower(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// node's `X509Certificate.ca`: `X509_check_ca() == 1` — basicConstraints
/// cA, and a keyUsage, where present, that permits keyCertSign.
fn node_ca(cert: &Certificate) -> bool {
    let bc = cert.extension("2.5.29.19").and_then(|e| {
        der::read(&e.value).map(|s| {
            der::children(s.content)
                .unwrap_or_default()
                .iter()
                .any(|f| {
                    f.tag == der::BOOLEAN
                        && f.content.first().is_some_and(|b| *b != 0)
                })
        })
    });
    let ku_ok = cert.extension("2.5.29.15").is_none_or(|e| {
        der::read(&e.value)
            .map(|b| b.content.get(1).is_some_and(|byte| byte & 0x04 != 0))
            .unwrap_or(false)
    });
    bc == Some(true) && ku_ok
}

/// `describeCertificateBundle()`.
pub fn describe_certificate_bundle(pem_text: &str, now_ms: i64) -> Json {
    let (certs, unreadable) = certificate_bundle(pem_text);
    let rows: Vec<Json> = certs
        .iter()
        .filter_map(|e| {
            let c = Certificate::from_der(&e.der).ok()?;
            let subject = one_line_name(&c.subject_der);
            let issuer = one_line_name(&c.issuer_der);
            let from = c.not_before.timestamp_millis();
            let to = c.not_after.timestamp_millis();
            Some(json!({
                "subject": subject, "issuer": issuer,
                "notBefore": time::iso(&c.not_before), "notAfter": time::iso(&c.not_after),
                "expired": to < now_ms, "notYetValid": from > now_ms,
                "ca": node_ca(&c),
                "selfSigned": name_lines(&c.subject_der) == name_lines(&c.issuer_der),
                "sha256": colon_hex_lower(&hash(MessageDigest::sha256(), &e.der).ok()?),
            }))
        })
        .collect();
    json!({ "certificates": rows, "unreadable": unreadable })
}

/// The RSA modulus size of a certificate's key; 0 for any other key.
pub fn rsa_key_bits(e: &Entry) -> u32 {
    e.x509
        .public_key()
        .ok()
        .filter(|k| k.id() == Id::RSA || k.id() == Id::RSA_PSS)
        .map_or(0, |k| k.bits())
}

/// A key as node's `export({ format: 'jwk' })`, its `asymmetricKeyType`
/// and named curve. Post-quantum keys answer their type and no JWK.
fn node_key(spki: &[u8]) -> (Option<Json>, String, String) {
    if let Some((alg, _)) = pq_x509::decode_spki(spki) {
        let pure = alg.composite.is_none();
        return (
            None,
            if pure {
                alg.id.to_lowercase()
            } else {
                String::new()
            },
            String::new(),
        );
    }
    let Ok(key) = PKey::<Public>::public_key_from_der(spki) else {
        return (None, String::new(), String::new());
    };
    let b64u = |b: &[u8]| URL_SAFE_NO_PAD.encode(b);
    match key.id() {
        Id::RSA => match key.rsa() {
            Ok(r) => (
                Some(
                    json!({ "kty": "RSA", "n": b64u(&r.n().to_vec()), "e": b64u(&r.e().to_vec()) }),
                ),
                "rsa".to_string(),
                String::new(),
            ),
            Err(_) => (None, "rsa".to_string(), String::new()),
        },
        Id::RSA_PSS => (None, "rsa-pss".to_string(), String::new()),
        Id::EC => {
            let Ok(ec) = key.ec_key() else {
                return (None, "ec".to_string(), String::new());
            };
            let nid = ec.group().curve_name();
            let (crv, name, width) = match nid {
                Some(Nid::X9_62_PRIME256V1) => ("P-256", "prime256v1", 32),
                Some(Nid::SECP384R1) => ("P-384", "secp384r1", 48),
                Some(Nid::SECP521R1) => ("P-521", "secp521r1", 66),
                Some(Nid::SECP256K1) => ("secp256k1", "secp256k1", 32),
                _ => return (None, "ec".to_string(), String::new()),
            };
            let mut ctx = match BigNumContext::new() {
                Ok(c) => c,
                Err(_) => return (None, "ec".to_string(), name.to_string()),
            };
            let (Ok(mut x), Ok(mut y)) =
                (openssl::bn::BigNum::new(), openssl::bn::BigNum::new())
            else {
                return (None, "ec".to_string(), name.to_string());
            };
            if ec
                .public_key()
                .affine_coordinates(ec.group(), &mut x, &mut y, &mut ctx)
                .is_err()
            {
                return (None, "ec".to_string(), name.to_string());
            }
            let pad = |b: &openssl::bn::BigNum| {
                b.to_vec_padded(width).unwrap_or_default()
            };
            (
                Some(
                    json!({ "kty": "EC", "x": b64u(&pad(&x)), "y": b64u(&pad(&y)), "crv": crv }),
                ),
                "ec".to_string(),
                name.to_string(),
            )
        }
        Id::ED25519 | Id::ED448 => {
            let crv = if key.id() == Id::ED25519 {
                "Ed25519"
            } else {
                "Ed448"
            };
            let raw = key.raw_public_key().unwrap_or_default();
            (
                Some(json!({ "crv": crv, "x": b64u(&raw), "kty": "OKP" })),
                crv.to_lowercase(),
                String::new(),
            )
        }
        _ => (None, String::new(), String::new()),
    }
}

/// node's `PrintAltName()`: a name with a character that would make the
/// list ambiguous (`"`, `\`, `,`, `'`, a control character, or for a
/// non-UTF-8 value anything outside printable ASCII) is quoted with JSON
/// escapes; any other is written as it is.
fn node_alt_name(prefix: Option<&str>, name: &[u8], utf8: bool) -> String {
    let safe = name.iter().all(|&c| match c {
        b'"' | b'\\' | b',' | b'\'' => false,
        _ if utf8 => c >= b' ' && c != 0x7f,
        _ => (b' '..=b'~').contains(&c),
    });
    let mut out: Vec<u8> = Vec::new();
    if safe {
        if let Some(p) = prefix {
            out.extend(format!("{}:", p).as_bytes());
        }
        out.extend(name);
    } else {
        out.push(b'"');
        if let Some(p) = prefix {
            out.extend(format!("{}:", p).as_bytes());
        }
        for &c in name {
            if c == b'"' || c == b'\\' {
                out.push(b'\\');
                out.push(c);
            } else if (c >= b' ' && c != b',' && c <= b'~')
                || (utf8 && c & 0x80 != 0)
            {
                out.push(c);
            } else {
                out.extend(format!("\\u00{:02x}", c).as_bytes());
            }
        }
        out.push(b'"');
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// node's `X509Certificate.subjectAltName` for the forms a certificate
/// here carries: `DNS:`, `email:`, `URI:`, `IP Address:`, `DirName:`,
/// `Registered ID:`.
fn node_subject_alt_name(cert: &Certificate) -> String {
    let Some(e) = cert.extension("2.5.29.17") else {
        return String::new();
    };
    let Some(seq) = der::read(&e.value) else {
        return String::new();
    };
    der::children(seq.content)
        .unwrap_or_default()
        .iter()
        .map(|gn| match gn.number {
            1 => node_alt_name(Some("email"), gn.content, false),
            2 => node_alt_name(Some("DNS"), gn.content, false),
            6 => node_alt_name(Some("URI"), gn.content, false),
            7 if gn.content.len() == 4 => {
                format!(
                    "IP Address:{}",
                    gn.content
                        .iter()
                        .map(u8::to_string)
                        .collect::<Vec<_>>()
                        .join(".")
                )
            }
            7 if gn.content.len() == 16 => format!(
                "IP Address:{}",
                gn.content
                    .chunks(2)
                    .map(|c| format!(
                        "{:X}",
                        (u16::from(c[0]) << 8) | u16::from(c[1])
                    ))
                    .collect::<Vec<_>>()
                    .join(":")
            ),
            7 => format!("IP Address:<invalid length={}>", gn.content.len()),
            4 => {
                let printed = der::read(gn.content)
                    .map(|n| crate::path::entry::rfc2253_name(n.raw))
                    .unwrap_or_default();
                format!(
                    "DirName:{}",
                    node_alt_name(None, printed.as_bytes(), true)
                )
            }
            8 => format!(
                "Registered ID:{}",
                der::oid_string(gn.content).unwrap_or_default()
            ),
            _ => "othername:<unsupported>".to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// `attestationCertificateFacts()`: a WebAuthn attestation certificate's
/// own fields, the extension values handed over raw.
pub fn attestation_certificate_facts(der_bytes: &[u8]) -> Option<Json> {
    let entry = Entry::from_der(der_bytes)?;
    let cert = Certificate::from_der(der_bytes).ok()?;
    let mut subject = Map::new();
    let mut attribute_count = 0;
    if let Some(name) = der::read(&cert.subject_der) {
        for set in der::children(name.content).unwrap_or_default() {
            for atv in der::children(set.content).unwrap_or_default() {
                attribute_count += 1;
                let parts = der::children(atv.content).unwrap_or_default();
                if parts.len() < 2 {
                    continue;
                }
                let label = match der::oid_string(parts[0].content).as_deref() {
                    Some("2.5.4.6") => "C",
                    Some("2.5.4.10") => "O",
                    Some("2.5.4.11") => "OU",
                    Some("2.5.4.3") => "CN",
                    _ => continue,
                };
                subject.insert(
                    label.to_string(),
                    json!(crate::path::facts::string_of(&parts[1])),
                );
            }
        }
    }
    let mut extensions = Map::new();
    let mut ca = Json::Null;
    let mut eku: Vec<String> = Vec::new();
    let mut san_directory_types: Vec<String> = Vec::new();
    for e in &cert.extensions {
        extensions.insert(e.oid.clone(), json!({ "critical": e.critical, "value": STANDARD.encode(&e.value) }));
        let Some(node) = der::read(&e.value) else {
            continue;
        };
        match e.oid.as_str() {
            "2.5.29.19" => {
                ca = json!(der::children(node.content)
                    .unwrap_or_default()
                    .iter()
                    .any(|f| f.tag == der::BOOLEAN
                        && f.content.first().is_some_and(|b| *b != 0)));
            }
            "2.5.29.37" => {
                eku = der::children(node.content)
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|o| der::oid_string(o.content))
                    .collect();
            }
            "2.5.29.17" => {
                for gn in der::children(node.content).unwrap_or_default() {
                    if gn.class != 2 || gn.number != 4 {
                        continue;
                    }
                    if let Some(name) = der::read(gn.content) {
                        for set in
                            der::children(name.content).unwrap_or_default()
                        {
                            for atv in
                                der::children(set.content).unwrap_or_default()
                            {
                                if let Some(oid) = der::children(atv.content)
                                    .and_then(|p| {
                                        p.first().and_then(|o| {
                                            der::oid_string(o.content)
                                        })
                                    })
                                {
                                    san_directory_types.push(oid);
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    let (jwk, key_type, curve) = node_key(&cert.spki);
    Some(json!({
        "version": cert.version + 1,
        "subject": subject,
        "subjectEmpty": attribute_count == 0,
        "ca": ca,
        "eku": eku,
        "extensions": extensions,
        "sanDirectoryTypes": san_directory_types,
        "publicKeyJwk": jwk,
        "keyType": key_type,
        "curve": curve,
        "pem": entry.pem,
        "subjectText": name_lines(&cert.subject_der).join("\n"),
        "subjectAltName": node_subject_alt_name(&cert),
    }))
}

/// `attestationKeyIdentifier()`: the hex SHA-1 of the subjectPublicKey
/// BIT STRING's value, as the FIDO Metadata Service lists it.
pub fn attestation_key_identifier(der_bytes: &[u8]) -> String {
    Certificate::from_der(der_bytes)
        .ok()
        .and_then(|c| crate::x509::extensions::key_identifier(&c.spki).ok())
        .map(|k| der::hex(&k))
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// OpenSSH (RFC 4251's types, PROTOCOL.certkeys).

const SSH_CERT_SUFFIX: &str = "-cert-v01@openssh.com";
/// SSH_CERT_TYPE_HOST.
pub const SSH_HOST_CERT: u32 = 2;
const SSH_FOREVER: u64 = u64::MAX;
const SSH_LATEST: u64 = i64::MAX as u64;

struct SshReader<'a> {
    buf: &'a [u8],
    at: usize,
}

type SshResult<T> = Result<T, String>;

impl<'a> SshReader<'a> {
    fn new(buf: &'a [u8]) -> SshReader<'a> {
        SshReader { buf, at: 0 }
    }
    fn take(&mut self, n: usize) -> SshResult<&'a [u8]> {
        if self.at + n > self.buf.len() {
            return Err("the SSH structure is truncated".to_string());
        }
        let out = &self.buf[self.at..self.at + n];
        self.at += n;
        Ok(out)
    }
    fn uint32(&mut self) -> SshResult<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn uint64(&mut self) -> SshResult<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }
    fn string(&mut self) -> SshResult<&'a [u8]> {
        let n = self.uint32()? as usize;
        self.take(n)
    }
    fn text(&mut self) -> SshResult<String> {
        Ok(String::from_utf8_lossy(self.string()?).into_owned())
    }
    fn mpint(&mut self) -> SshResult<&'a [u8]> {
        let raw = self.string()?;
        let mut start = 0;
        while start + 1 < raw.len() && raw[start] == 0 {
            start += 1;
        }
        Ok(&raw[start..])
    }
    fn rest(&mut self) -> SshResult<&'a [u8]> {
        self.take(self.buf.len() - self.at)
    }
    fn done(&self) -> bool {
        self.at == self.buf.len()
    }
}

/// An SSH public key or certificate (`ssh.ParsePublicKey()`).
#[derive(Clone, Debug)]
pub struct SshKey {
    pub key_type: String,
    /// The key as a DER SubjectPublicKeyInfo.
    pub spki: Vec<u8>,
    /// `nistp256` and the like for ECDSA.
    pub curve: String,
    pub blob: Vec<u8>,
    pub cert: Option<Box<SshCert>>,
}

#[derive(Clone, Debug)]
pub struct SshCert {
    pub cert_type: String,
    pub nonce: Vec<u8>,
    pub serial: u64,
    pub kind: u32,
    pub key_id: String,
    pub principals: Vec<String>,
    pub valid_after: u64,
    pub valid_before: u64,
    pub critical_options: Vec<(String, String)>,
    pub extensions: Vec<(String, String)>,
    pub signature_key: SshKey,
    pub signature_format: String,
    pub signature: Vec<u8>,
    pub signed: Vec<u8>,
}

fn ssh_curve(name: &str) -> Option<(Nid, usize, RawHash)> {
    Some(match name {
        "nistp256" => (Nid::X9_62_PRIME256V1, 32, RawHash::Sha256),
        "nistp384" => (Nid::SECP384R1, 48, RawHash::Sha384),
        "nistp521" => (Nid::SECP521R1, 66, RawHash::Sha512),
        _ => return None,
    })
}

fn ssh_key_fields(
    key_type: &str,
    r: &mut SshReader<'_>,
) -> SshResult<(Vec<u8>, String)> {
    let jwk_spki = |jwk: Json| -> SshResult<Vec<u8>> {
        jose_keys::JwsKey::from_jwk(&jwk)
            .and_then(|k| k.public_key())
            .and_then(|p| {
                p.public_key_to_der().map_err(sts_crypto::CryptoError::from)
            })
            .map_err(|e| e.0)
    };
    let b64u = |b: &[u8]| URL_SAFE_NO_PAD.encode(b);
    if key_type == "ssh-rsa" {
        let e = r.mpint()?.to_vec();
        let n = r.mpint()?.to_vec();
        return Ok((
            jwk_spki(json!({ "kty": "RSA", "n": b64u(&n), "e": b64u(&e) }))?,
            String::new(),
        ));
    }
    if let Some(name) = key_type.strip_prefix("ecdsa-sha2-") {
        if let Some((_, width, _)) = ssh_curve(name) {
            let curve = r.text()?;
            let q = r.string()?;
            if curve != name
                || q.first() != Some(&4)
                || q.len() != 1 + 2 * width
            {
                return Err(format!(
                    "the ECDSA key is not an uncompressed {} point",
                    curve
                ));
            }
            let crv = match name {
                "nistp256" => "P-256",
                "nistp384" => "P-384",
                _ => "P-521",
            };
            let jwk = json!({ "kty": "EC", "crv": crv, "x": b64u(&q[1..1 + width]), "y": b64u(&q[1 + width..]) });
            return Ok((jwk_spki(jwk)?, name.to_string()));
        }
    }
    if key_type == "ssh-ed25519" {
        let pk = r.string()?;
        if pk.len() != 32 {
            return Err("an Ed25519 key is 32 bytes".to_string());
        }
        return Ok((
            jwk_spki(json!({ "kty": "OKP", "crv": "Ed25519", "x": b64u(pk) }))?,
            String::new(),
        ));
    }
    Err(format!(
        "the SSH key type {} is not supported (ssh-rsa, ecdsa-sha2-nistp256/384/521 and ssh-ed25519 are)",
        key_type
    ))
}

fn ssh_options(bytes: &[u8]) -> SshResult<Vec<(String, String)>> {
    let mut r = SshReader::new(bytes);
    let mut out: Vec<(String, String)> = Vec::new();
    while !r.done() {
        let name = r.text()?;
        let data = r.string()?;
        let value = if data.is_empty() {
            String::new()
        } else {
            SshReader::new(data).text()?
        };
        // A later duplicate replaces an earlier one, as an object key does.
        out.retain(|(n, _)| *n != name);
        out.push((name, value));
    }
    Ok(out)
}

/// `parseSshPublicKey()`.
pub fn parse_ssh_public_key(blob: &[u8]) -> SshResult<SshKey> {
    let mut r = SshReader::new(blob);
    let key_type = r.text()?;
    let Some(base) = key_type.strip_suffix(SSH_CERT_SUFFIX) else {
        let (spki, curve) = ssh_key_fields(&key_type, &mut r)?;
        if !r.done() {
            return Err("trailing bytes after the SSH public key".to_string());
        }
        return Ok(SshKey {
            key_type,
            spki,
            curve,
            blob: blob.to_vec(),
            cert: None,
        });
    };
    let nonce = r.string()?.to_vec();
    let (spki, curve) = ssh_key_fields(base, &mut r)?;
    let serial = r.uint64()?;
    let kind = r.uint32()?;
    let key_id = r.text()?;
    let mut pr = SshReader::new(r.string()?);
    let mut principals = Vec::new();
    while !pr.done() {
        principals.push(pr.text()?);
    }
    let valid_after = r.uint64()?;
    let valid_before = r.uint64()?;
    let critical_options = ssh_options(r.string()?)?;
    let extensions = ssh_options(r.string()?)?;
    r.string()?;
    let signature_key_blob = r.string()?;
    let signed_length = r.at;
    let mut sr = SshReader::new(r.string()?);
    if !r.done() {
        return Err("trailing bytes after the SSH certificate".to_string());
    }
    let signature_key = parse_ssh_public_key(signature_key_blob)?;
    if signature_key.cert.is_some() {
        return Err(
            "a certificate's signature key cannot itself be a certificate"
                .to_string(),
        );
    }
    let signature_format = sr.text()?;
    let signature = sr.string()?.to_vec();
    sr.rest()?;
    Ok(SshKey {
        key_type: base.to_string(),
        spki,
        curve,
        blob: blob.to_vec(),
        cert: Some(Box::new(SshCert {
            cert_type: key_type.clone(),
            nonce,
            serial,
            kind,
            key_id,
            principals,
            valid_after,
            valid_before,
            critical_options,
            extensions,
            signature_key,
            signature_format,
            signature,
            signed: blob[..signed_length].to_vec(),
        })),
    })
}

/// `parseSshAuthorizedKey()`: `[options] type base64 [comment]`.
pub fn parse_ssh_authorized_key(line: &str) -> Option<SshKey> {
    let text = line.trim();
    if text.is_empty() || text.starts_with('#') {
        return None;
    }
    // `"(?:[^"\\]|\\.)*"|\S+`
    let mut fields = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        if chars[i] == '"' {
            let mut j = i + 1;
            let mut closed = None;
            while j < chars.len() {
                if chars[j] == '\\' && j + 1 < chars.len() {
                    j += 2;
                    continue;
                }
                if chars[j] == '"' {
                    closed = Some(j);
                    break;
                }
                j += 1;
            }
            if let Some(end) = closed {
                fields.push(chars[start..=end].iter().collect::<String>());
                i = end + 1;
                continue;
            }
        }
        while i < chars.len() && !chars[i].is_whitespace() {
            i += 1;
        }
        fields.push(chars[start..i].iter().collect::<String>());
    }
    for i in 0..fields.len().saturating_sub(1) {
        let f = &fields[i];
        if !(f.starts_with("ssh-")
            || f.starts_with("ecdsa-")
            || f.starts_with("sk-"))
            && !f.contains("@openssh.com")
        {
            continue;
        }
        if let Ok(key) = parse_ssh_public_key(&node_base64(&fields[i + 1])) {
            let cert_type = key.cert.as_ref().map(|c| c.cert_type.clone());
            if key.key_type == *f || cert_type.as_deref() == Some(f.as_str()) {
                return Some(key);
            }
        }
    }
    None
}

/// `ssh.FingerprintSHA256()` without its prefix.
pub fn ssh_fingerprint(key: &SshKey) -> String {
    hash(MessageDigest::sha256(), &key.blob)
        .map(|d| STANDARD.encode(d).trim_end_matches('=').to_string())
        .unwrap_or_default()
}

/// `verifySshSignature()`: only the formats Go's `Verify()` accepts.
pub fn verify_ssh_signature(
    key: &SshKey,
    data: &[u8],
    format: &str,
    blob: &[u8],
) -> bool {
    if blob.is_empty() {
        return false;
    }
    let described = raw_sig::public_key_from_spki(&key.spki);
    if key.key_type == "ssh-rsa" {
        let hash = match format {
            "ssh-rsa" => RawHash::Sha1,
            "rsa-sha2-256" => RawHash::Sha256,
            "rsa-sha2-512" => RawHash::Sha512,
            _ => return false,
        };
        return raw_sig::verify_raw_signature(
            &RawScheme::new(RawFamily::RsaPkcs1, Some(hash)),
            &described,
            data,
            blob,
        );
    }
    if !key.curve.is_empty() {
        if format != key.key_type {
            return false;
        }
        let Some((_, _, hash)) = ssh_curve(&key.curve) else {
            return false;
        };
        let node_curve = match key.curve.as_str() {
            "nistp256" => "prime256v1",
            "nistp384" => "secp384r1",
            _ => "secp521r1",
        };
        let mut inner = SshReader::new(blob);
        let raw = (|| -> SshResult<Option<Vec<u8>>> {
            let r = inner.mpint()?.to_vec();
            let s = inner.mpint()?.to_vec();
            Ok(raw_sig::ecdsa_integers_to_p1363(node_curve, &r, &s))
        })()
        .ok()
        .flatten();
        let Some(raw) = raw else {
            return false;
        };
        let scheme = RawScheme::new(RawFamily::Ecdsa, Some(hash))
            .with_encoding(EcdsaEncoding::P1363);
        return raw_sig::verify_raw_signature(&scheme, &described, data, &raw);
    }
    if key.key_type == "ssh-ed25519" && format == "ssh-ed25519" {
        return raw_sig::verify_raw_signature(
            &RawScheme::new(RawFamily::EdDsa, None),
            &described,
            data,
            blob,
        );
    }
    false
}

/// `checkSshHostCertificate()`: `CertChecker.CheckHostKey(principal +
/// ':22', …)`; empty when acceptable, otherwise why not.
pub fn check_ssh_host_certificate(
    key: &SshKey,
    principal: &str,
    authorities: &[SshKey],
    now_seconds: f64,
) -> String {
    let Some(cert) = key.cert.as_ref() else {
        return "ssh: certificate presented as a host key has type undefined"
            .to_string();
    };
    if cert.kind != SSH_HOST_CERT {
        return format!(
            "ssh: certificate presented as a host key has type {}",
            cert.kind
        );
    }
    let authority = ssh_fingerprint(&cert.signature_key);
    if !authorities.iter().any(|a| ssh_fingerprint(a) == authority) {
        return format!("ssh: no authorities for hostname: {}", principal);
    }
    if let Some((name, _)) = cert
        .critical_options
        .iter()
        .find(|(n, _)| n != "source-address")
    {
        return format!(
            "ssh: unsupported critical option \"{}\" in certificate",
            name
        );
    }
    if !cert.principals.is_empty()
        && !cert.principals.iter().any(|p| p == principal)
    {
        return format!(
            "ssh: principal \"{}\" not in the set of valid principals for given certificate",
            principal
        );
    }
    let now = now_seconds.floor() as i128;
    if cert.valid_after > SSH_LATEST || now < i128::from(cert.valid_after) {
        return "ssh: cert is not yet valid".to_string();
    }
    if cert.valid_before != SSH_FOREVER
        && (cert.valid_before > SSH_LATEST
            || now >= i128::from(cert.valid_before))
    {
        return "ssh: cert has expired".to_string();
    }
    if !verify_ssh_signature(
        &cert.signature_key,
        &cert.signed,
        &cert.signature_format,
        &cert.signature,
    ) {
        return "ssh: certificate signature does not verify".to_string();
    }
    String::new()
}

// ---------------------------------------------------------------------------
// The FIDO Metadata Service's BLOB (MDS3 section 3.1.8).

const MDS_ALGORITHMS: &[&str] = &[
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384",
    "ES512", "EdDSA",
];

/// `verifyFidoMdsBlob()`: the x5c chain to `anchors`, the signature under
/// the leaf with an algorithm section 3.1.7 allows, and a payload that is a
/// BLOB. `override_signature` lets an administrator load one whose anchor,
/// path or signature fails, and says so in `overridden`.
pub fn verify_fido_mds_blob(
    token: &str,
    anchors: &[Entry],
    now_ms: i64,
    override_signature: bool,
) -> Json {
    let text = token.trim();
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() != 3 {
        return json!({ "ok": false, "reason": format!("the BLOB is not a compact JWS (it has {} part(s), not 3)", parts.len()) });
    }
    let Some(header) =
        serde_json::from_slice::<Json>(&node_base64(parts[0])).ok()
    else {
        return json!({ "ok": false, "reason": "the BLOB's header is not JSON" });
    };
    let x5c: Vec<Vec<u8>> = header
        .get("x5c")
        .and_then(Json::as_array)
        .map(|a| {
            a.iter()
                .map(|c| node_base64(c.as_str().unwrap_or("")))
                .collect()
        })
        .unwrap_or_default();
    if x5c.is_empty() {
        return json!({ "ok": false, "reason": "the BLOB's header carries no x5c: MDS3 section 3.1.7 signs it with a certificate chain" });
    }
    let mut failure = String::new();
    let mut verified: Option<Json> = None;
    let mut path_chain: Vec<Vec<u8>> = Vec::new();
    if anchors.is_empty() {
        failure = "no FIDO MDS trust anchor: none is configured (risk.mdsTrustAnchors) and GlobalSign Root CA - R3 is not in this node's root store".to_string();
    } else {
        let options = PathOptions {
            now_ms,
            ..PathOptions::default()
        };
        let verdict =
            path::verify_path_to_anchors(&x5c[0], &x5c[1..], anchors, &options);
        if !verdict.ok {
            failure = format!(
                "the BLOB's signing chain does not verify: {}",
                verdict.reason
            );
        } else {
            path_chain = verdict.chain;
            let leaf_pem =
                Entry::from_der(&x5c[0]).map(|e| e.pem).unwrap_or_default();
            let checked =
                jose_keys::JwsKey::from_pem(&leaf_pem).and_then(|key| {
                    jws::verify_compact(
                        text,
                        &key,
                        &jws::VerifyOptions {
                            algorithms: MDS_ALGORITHMS,
                            empty_payload: false,
                            policy: jose_keys::KeyPolicy::STRICT,
                        },
                    )
                });
            match checked {
                Ok(v) => verified = v.claims,
                Err(e) => {
                    failure = format!("the BLOB's signature does not verify under its signing certificate: {}", e.0)
                }
            }
        }
    }
    if !failure.is_empty() && !override_signature {
        return json!({ "ok": false, "reason": failure });
    }
    let payload = if failure.is_empty() {
        verified
    } else {
        serde_json::from_slice::<Json>(&node_base64(parts[1])).ok()
    };
    let is_blob = payload.as_ref().is_some_and(|p| {
        p.is_object()
            && p.get("entries").is_some_and(Json::is_array)
            && p.get("no").is_some_and(|n| {
                n.as_f64().is_some_and(f64::is_finite)
                    || n.as_str()
                        .is_some_and(|s| s.trim().parse::<f64>().is_ok())
            })
    });
    if !is_blob {
        return json!({ "ok": false, "reason": "the payload is not an MDS3 BLOB: it needs a serial number (no) and a list of entries" });
    }
    let chain_pems: Vec<String> =
        if failure.is_empty() && !path_chain.is_empty() {
            path_chain
                .iter()
                .filter_map(|d| Entry::from_der(d).map(|e| e.pem))
                .collect()
        } else {
            x5c.iter()
                .filter_map(|d| Entry::from_der(d).map(|e| e.pem))
                .collect()
        };
    let mut out = json!({ "ok": true, "header": header, "payload": payload, "chainPems": chain_pems });
    if !failure.is_empty() {
        out["overridden"] = json!(failure);
    }
    out
}

// ---------------------------------------------------------------------------
// Sigstore signing certificates and their SCTs (#170).

const OID_FULCIO_ISSUER_V1: &str = "1.3.6.1.4.1.57264.1.1";
const OID_FULCIO_ISSUER_V2: &str = "1.3.6.1.4.1.57264.1.8";
const OID_SCT_LIST: &str = "1.3.6.1.4.1.11129.2.4.2";
const OID_CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";

/// `sigstoreSignerFacts()`: the first non-empty subjectAltName in
/// sigstore's order (DNS, email, IP, URI, an otherName's value) and the
/// OIDC issuer, the UTF8String form first.
pub fn sigstore_signer_facts(der_bytes: &[u8]) -> Option<Json> {
    let entry = Entry::from_der(der_bytes)?;
    let cert = Certificate::from_der(der_bytes).ok()?;
    let (mut dns, mut email, mut ip, mut uri, mut other) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let (mut issuer_v1, mut issuer_v2, mut code_signing) =
        (String::new(), String::new(), false);
    for e in &cert.extensions {
        match e.oid.as_str() {
            "2.5.29.17" => {
                for gn in der::read(&e.value)
                    .and_then(|s| der::children(s.content))
                    .unwrap_or_default()
                {
                    let text = || {
                        gn.content
                            .iter()
                            .map(|&b| char::from(b))
                            .collect::<String>()
                    };
                    match gn.number {
                        2 => dns.push(text()),
                        1 => email.push(text()),
                        6 => uri.push(text()),
                        7 => ip.push(if gn.content.len() == 4 {
                            gn.content
                                .iter()
                                .map(u8::to_string)
                                .collect::<Vec<_>>()
                                .join(".")
                        } else {
                            der::hex(gn.content)
                        }),
                        0 => {
                            let value = der::children(gn.content)
                                .and_then(|p| {
                                    p.get(1).and_then(|h| der::read(h.content))
                                })
                                .filter(|v| {
                                    crate::path::facts::is_string_type(v.tag)
                                })
                                .map(|v| crate::path::facts::string_of(&v));
                            if let Some(v) = value {
                                other.push(v);
                            }
                        }
                        _ => {}
                    }
                }
            }
            "2.5.29.37" => {
                code_signing = der::read(&e.value)
                    .and_then(|s| der::children(s.content))
                    .unwrap_or_default()
                    .iter()
                    .any(|o| {
                        der::oid_string(o.content).as_deref()
                            == Some(OID_CODE_SIGNING)
                    });
            }
            OID_FULCIO_ISSUER_V1 => {
                issuer_v1 = String::from_utf8_lossy(&e.value).into_owned()
            }
            OID_FULCIO_ISSUER_V2 => {
                if let Some(v) = der::read(&e.value)
                    .filter(|v| crate::path::facts::is_string_type(v.tag))
                {
                    issuer_v2 = crate::path::facts::string_of(&v);
                }
            }
            _ => {}
        }
    }
    let subject = dns
        .into_iter()
        .chain(email)
        .chain(ip)
        .chain(uri)
        .chain(other)
        .find(|s| !s.is_empty())
        .unwrap_or_default();
    Some(json!({
        "subject": subject,
        "issuer": if issuer_v2.is_empty() { issuer_v1 } else { issuer_v2 },
        "codeSigning": code_signing,
        "notBefore": cert.not_before.timestamp_millis(),
        "notAfter": cert.not_after.timestamp_millis(),
        "spki": STANDARD.encode(&cert.spki),
        "pem": entry.pem,
    }))
}

/// A trusted CT log: its id, key and the window its key signed in.
pub struct CtLog {
    pub log_id_hex: String,
    pub spki: Vec<u8>,
    pub start_ms: Option<i64>,
    pub end_ms: Option<i64>,
}

/// RFC 6962 section 3.2: the TBS without the SCT list.
fn precertificate_tbs(cert: &Certificate) -> Option<Vec<u8>> {
    let seq = der::read(&cert.tbs)?;
    let mut parts = Vec::new();
    for item in der::children(seq.content)? {
        if item.tag == 0xa3 {
            let kept: Vec<Vec<u8>> = der::read(item.content)
                .and_then(|h| der::children(h.content))
                .unwrap_or_default()
                .into_iter()
                .filter(|e| {
                    der::children(e.content)
                        .and_then(|p| {
                            p.first().and_then(|o| der::oid_string(o.content))
                        })
                        .as_deref()
                        != Some(OID_SCT_LIST)
                })
                .map(|e| e.raw.to_vec())
                .collect();
            parts.push(der::context(3, true, &der::sequence(&kept)));
        } else {
            parts.push(item.raw.to_vec());
        }
    }
    Some(der::sequence(&parts))
}

/// `verifyEmbeddedScts()`: ok when one SCT is from a trusted log, inside
/// its key's window, and verifies over the precertificate entry.
pub fn verify_embedded_scts(
    leaf_der: &[u8],
    issuer_der: &[u8],
    logs: &[CtLog],
) -> (bool, String) {
    let (Ok(leaf), Ok(issuer)) = (
        Certificate::from_der(leaf_der),
        Certificate::from_der(issuer_der),
    ) else {
        return (
            false,
            "the certificate or its issuer could not be read".to_string(),
        );
    };
    let Some(ext) = leaf.extension(OID_SCT_LIST) else {
        return (
            false,
            "certificate does not include required embedded SCT".to_string(),
        );
    };
    let list = der::read(&ext.value).map(|o| o.content.to_vec());
    let list = match list {
        Some(l)
            if l.len() >= 2
                && usize::from(u16::from_be_bytes([l[0], l[1]]))
                    == l.len() - 2 =>
        {
            l
        }
        _ => return (false, "the embedded SCT list is malformed".to_string()),
    };
    let (Some(tbs), Ok(issuer_key_hash)) = (
        precertificate_tbs(&leaf),
        hash(MessageDigest::sha256(), &issuer.spki),
    ) else {
        return (
            false,
            "the precertificate entry could not be built".to_string(),
        );
    };
    let tbs_len = (tbs.len() as u32).to_be_bytes();
    let mut problems: Vec<String> = Vec::new();
    let mut at = 2;
    while at + 2 <= list.len() {
        let size = usize::from(u16::from_be_bytes([list[at], list[at + 1]]));
        let sct =
            &list[(at + 2).min(list.len())..(at + 2 + size).min(list.len())];
        at += 2 + size;
        if sct.len() != size || size < 47 || sct[0] != 0 {
            problems.push("an SCT that is not version 1".to_string());
            continue;
        }
        let log_id = der::hex(&sct[1..33]);
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&sct[33..41]);
        let timestamp = u64::from_be_bytes(ts);
        let ext_len = usize::from(u16::from_be_bytes([sct[41], sct[42]]));
        let extensions = &sct[43..(43 + ext_len).min(sct.len())];
        let mut p = 43 + ext_len;
        if p + 4 > sct.len() {
            problems.push("a truncated SCT".to_string());
            continue;
        }
        let sig_len = usize::from(u16::from_be_bytes([sct[p + 2], sct[p + 3]]));
        let signature =
            &sct[(p + 4).min(sct.len())..(p + 4 + sig_len).min(sct.len())];
        p += 4 + sig_len;
        if p != sct.len() || signature.len() != sig_len {
            problems.push("a truncated SCT signature".to_string());
            continue;
        }
        let Some(trusted) =
            logs.iter().find(|l| l.log_id_hex.to_lowercase() == log_id)
        else {
            problems.push(format!(
                "an SCT from a CT log not in the trust root ({})",
                log_id
            ));
            continue;
        };
        let t = timestamp as i64;
        if trusted.start_ms.is_some_and(|s| s != 0 && t < s)
            || trusted.end_ms.is_some_and(|e| e != 0 && t > e)
        {
            problems
                .push("an SCT made outside its log key's validity".to_string());
            continue;
        }
        let mut signed = vec![0, 0];
        signed.extend(timestamp.to_be_bytes());
        signed.extend([0, 1]);
        signed.extend(issuer_key_hash.iter());
        signed.extend(&tbs_len[1..]);
        signed.extend(&tbs);
        signed.extend((extensions.len() as u16).to_be_bytes());
        signed.extend(extensions);
        if sigstore::verify_with_public_key(
            &trusted.spki,
            &signed,
            signature,
            false,
        ) {
            return (true, String::new());
        }
        problems.push(
            "an SCT whose signature does not verify under its log".to_string(),
        );
    }
    (
        false,
        format!(
            "no embedded SCT verified: {}",
            if problems.is_empty() {
                "the list is empty".to_string()
            } else {
                problems.join("; ")
            }
        ),
    )
}

/// An instant in milliseconds as ISO text.
pub fn iso_ms(ms: i64) -> String {
    Utc.timestamp_millis_opt(ms)
        .single()
        .map(|t| time::iso(&t))
        .unwrap_or_default()
}
