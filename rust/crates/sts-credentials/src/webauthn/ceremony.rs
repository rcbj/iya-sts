// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The two WebAuthn Level 3 ceremonies as `authn/webauthn.js` checks them:
//! `verifyRegistration()` (section 7.1, the attestation object's
//! authenticator data and client data, the credential key as a JWK) and
//! `verifyAssertion()` (section 7.2, the signature over authenticator data
//! ‖ SHA-256(clientDataJSON) with the stored key, the signature counter).
//!
//! Each answers Node's `{ ok, checks, failed, … }`: a list of NAMED checks
//! in Node's order, every one evaluated, so a refusal says which checks
//! failed and the caller decides. Malformed input — CBOR that is not
//! CTAP2's, authenticator data that runs short, client data that is not
//! JSON — is an `Err` with Node's sentence, where Node throws.
//!
//! The attestation statement is verified separately, by
//! [`super::attestation`], over the registration's raw parts — as
//! `webauthn_attestation.ts`'s `assess()` takes Node's verdict.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Map, Value as Json};
use sts_crypto::jws_alg::Hash;
use sts_crypto::webauthn::{
    verify_cose_signature, CoseKey, CoseOptions, COSE_SIGNATURE_ALGS,
};

use super::cbor::{decode_first, Cbor};

/// The longest credential ID section 5.8.3 allows.
pub const MAX_CREDENTIAL_ID_BYTES: usize = 1023;
/// AKP, the COSE key type of an ML-DSA key (RFC 9964 / draft).
pub const COSE_KTY_AKP: i64 = 7;

/// `COSE_CURVES`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn cose_curve(id: i64) -> Option<&'static str> {
    match id {
        1 => Some("P-256"),
        2 => Some("P-384"),
        3 => Some("P-521"),
        6 => Some("Ed25519"),
        7 => Some("Ed448"),
        8 => Some("secp256k1"),
        _ => None,
    }
}

/// `COSE_ALGS[id]`: the verifier's name for a COSE algorithm.
#[tracing::instrument(level = "debug", skip_all)]
pub fn cose_name(id: i64) -> Option<&'static str> {
    COSE_SIGNATURE_ALGS
        .iter()
        .find(|a| a.id == id)
        .map(|a| a.name)
}

/// `INSECURE_COSE_ALGS`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn insecure_cose_ids() -> Vec<i64> {
    COSE_SIGNATURE_ALGS
        .iter()
        .filter(|a| a.insecure)
        .map(|a| a.id)
        .collect()
}

fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// `Buffer.from(text, 'base64url')`: lenient, as node is — characters
/// outside the alphabet are skipped, padding and both alphabets accepted.
#[tracing::instrument(level = "debug", skip_all)]
pub fn from_base64url(text: &str) -> Vec<u8> {
    let cleaned: String = text
        .chars()
        .filter_map(|c| match c {
            '+' => Some('-'),
            '/' => Some('_'),
            c if c.is_ascii_alphanumeric() || c == '-' || c == '_' => Some(c),
            _ => None,
        })
        .take_while(|_| true)
        .collect();
    let cut = if cleaned.len() % 4 == 1 {
        &cleaned[..cleaned.len() - 1]
    } else {
        &cleaned[..]
    };
    URL_SAFE_NO_PAD.decode(cut).unwrap_or_default()
}

/// The flags byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags {
    pub up: bool,
    pub uv: bool,
    pub be: bool,
    pub bs: bool,
    pub at: bool,
    pub ed: bool,
}

impl Flags {
    /// As Node's object.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn to_json(self) -> Json {
        json!({ "up": self.up, "uv": self.uv, "be": self.be, "bs": self.bs,
                "at": self.at, "ed": self.ed })
    }
}

/// `parseAuthenticatorData()`'s answer.
#[derive(Debug, Clone)]
pub struct AuthenticatorData {
    pub rp_id_hash: Vec<u8>,
    pub flags: Flags,
    pub sign_count: u32,
    pub aaguid: Option<Vec<u8>>,
    pub credential_id: Option<Vec<u8>>,
    pub credential_public_key: Option<Cbor>,
    pub extensions: Option<Cbor>,
}

/// `parseAuthenticatorData(buf)`.
#[tracing::instrument(level = "debug", skip(buf))]
pub fn parse_authenticator_data(
    buf: &[u8],
) -> Result<AuthenticatorData, String> {
    if buf.len() < 37 {
        return Err(format!(
            "authenticator data is {} bytes; the fixed part alone is 37",
            buf.len()
        ));
    }
    let f = buf[32];
    let flags = Flags {
        up: f & 0x01 != 0,
        uv: f & 0x04 != 0,
        be: f & 0x08 != 0,
        bs: f & 0x10 != 0,
        at: f & 0x40 != 0,
        ed: f & 0x80 != 0,
    };
    let sign_count = u32::from_be_bytes([buf[33], buf[34], buf[35], buf[36]]);
    let mut out = AuthenticatorData {
        rp_id_hash: buf[..32].to_vec(),
        flags,
        sign_count,
        aaguid: None,
        credential_id: None,
        credential_public_key: None,
        extensions: None,
    };
    let mut cursor = 37;
    if flags.at {
        if buf.len() < cursor + 18 {
            return Err("the AT flag is set but the attested credential data \
                        does not fit"
                .to_string());
        }
        out.aaguid = Some(buf[cursor..cursor + 16].to_vec());
        cursor += 16;
        let id_length =
            usize::from(u16::from_be_bytes([buf[cursor], buf[cursor + 1]]));
        cursor += 2;
        if buf.len() < cursor + id_length {
            return Err(format!(
                "the credential ID claims {id_length} bytes, past the end"
            ));
        }
        out.credential_id = Some(buf[cursor..cursor + id_length].to_vec());
        cursor += id_length;
        let (key, next) = decode_first(buf, cursor)?;
        out.credential_public_key = Some(key);
        cursor = next;
    }
    if flags.ed {
        let (ext, _) = decode_first(buf, cursor)?;
        out.extensions = Some(ext);
    }
    Ok(out)
}

/// `coseKeyToJwk(coseKey)`: `(jwk, algorithm name, COSE alg)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn cose_key_to_jwk(
    key: &Cbor,
) -> Result<(Json, Option<&'static str>, Cbor), String> {
    if !matches!(key, Cbor::Map(_)) {
        return Err(
            "the credential public key is not a COSE_Key map".to_string()
        );
    }
    let kty = key.get_int(1).cloned().unwrap_or(Cbor::Null);
    let alg = key.get_int(3).cloned().unwrap_or(Cbor::Null);
    let b = |k: i64| {
        key.get_int(k)
            .and_then(Cbor::bytes)
            .map(b64u)
            .unwrap_or_default()
    };
    let name = alg.int().and_then(cose_name);
    let mut jwk = Map::new();
    match kty.int() {
        Some(2) => {
            let c = key.get_int(-1).and_then(Cbor::int).and_then(cose_curve);
            let Some(crv) = c else {
                return Err(format!(
                    "unsupported COSE curve {}",
                    key.get_int(-1)
                        .map_or("undefined".to_string(), Cbor::text_of)
                ));
            };
            jwk.insert("kty".into(), json!("EC"));
            jwk.insert("crv".into(), json!(crv));
            jwk.insert("x".into(), json!(b(-2)));
            jwk.insert("y".into(), json!(b(-3)));
        }
        Some(3) => {
            jwk.insert("kty".into(), json!("RSA"));
            jwk.insert("n".into(), json!(b(-1)));
            jwk.insert("e".into(), json!(b(-2)));
        }
        Some(1) => {
            let c = key.get_int(-1).and_then(Cbor::int).and_then(cose_curve);
            let Some(crv) = c else {
                return Err(format!(
                    "unsupported COSE OKP curve {}",
                    key.get_int(-1)
                        .map_or("undefined".to_string(), Cbor::text_of)
                ));
            };
            jwk.insert("kty".into(), json!("OKP"));
            jwk.insert("crv".into(), json!(crv));
            jwk.insert("x".into(), json!(b(-2)));
        }
        Some(COSE_KTY_AKP) => {
            let ml = name.is_some_and(|n| n.starts_with("ML-DSA-"));
            if !ml || key.get_int(-1).and_then(Cbor::bytes).is_none() {
                return Err(format!(
                    "an AKP COSE key needs an ML-DSA alg and a pub; this one \
                     has alg {}",
                    if alg == Cbor::Null {
                        "undefined".to_string()
                    } else {
                        alg.text_of()
                    }
                ));
            }
            jwk.insert("kty".into(), json!("AKP"));
            jwk.insert("pub".into(), json!(b(-1)));
        }
        _ => {
            return Err(format!(
                "unsupported COSE key type {}",
                if kty == Cbor::Null {
                    "undefined".to_string()
                } else {
                    kty.text_of()
                }
            ))
        }
    }
    if let Some(n) = name {
        jwk.insert("alg".into(), json!(n));
    }
    Ok((Json::Object(jwk), name, alg))
}

/// `coseAlgOfJwk(jwk)`: the JWK's `alg` by name, else the usual one for
/// its key type.
#[tracing::instrument(level = "debug", skip_all)]
pub fn cose_alg_of_jwk(jwk: &Json) -> i64 {
    let alg = jwk.get("alg").and_then(Json::as_str);
    if let Some(a) =
        alg.and_then(|n| COSE_SIGNATURE_ALGS.iter().find(|c| c.name == n))
    {
        return a.id;
    }
    match (
        jwk.get("kty").and_then(Json::as_str),
        jwk.get("crv").and_then(Json::as_str),
    ) {
        (Some("RSA"), _) => -257,
        (Some("OKP"), _) => -8,
        (_, Some("P-384")) => -35,
        (_, Some("P-521")) => -36,
        _ => -7,
    }
}

struct Checks(Vec<Json>);

impl Checks {
    fn add(&mut self, name: &str, ok: bool, detail: String) -> bool {
        self.0
            .push(json!({ "name": name, "ok": ok, "detail": detail }));
        ok
    }
    fn ok(&self) -> bool {
        self.0.iter().all(|c| c["ok"] == json!(true))
    }
    fn failed(&self) -> Vec<Json> {
        self.0
            .iter()
            .filter(|c| c["ok"] != json!(true))
            .map(|c| c["name"].clone())
            .collect()
    }
}

fn sha256(data: &[u8]) -> Vec<u8> {
    Hash::Sha256.digest(data)
}

/// The client data, parsed.
fn client_data(bytes: &[u8]) -> Result<Json, String> {
    let text = String::from_utf8_lossy(bytes);
    serde_json::from_str(&text)
        .map_err(|e| format!("clientDataJSON is not JSON: {e}"))
}

fn js_text(v: Option<&Json>) -> String {
    match v {
        None => "undefined".to_string(),
        Some(Json::String(s)) => s.clone(),
        Some(Json::Null) => "null".to_string(),
        Some(other) => crate::js::string(other),
    }
}

/// What `verifyRegistration()` reads.
#[derive(Debug, Clone, Default)]
pub struct RegistrationInput {
    pub attestation_object: String,
    pub client_data_json: String,
    pub expected_challenge: Json,
    pub expected_origin: Json,
    pub expected_rp_id: String,
    pub require_user_verification: bool,
    pub expected_algorithms: Option<Vec<f64>>,
}

/// What a registration's attestation is verified over, besides its
/// public answer.
#[derive(Debug, Clone)]
pub struct Registration {
    /// Node's answer (`ok`, `checks`, `failed`, `fmt`, `aaguid`,
    /// `credentialId`, `publicKeyJwk`, `algorithm`, `signCount`, `flags`,
    /// `attStmt`, `coseAlg`, `extensions`).
    pub answer: Json,
    pub att_stmt: Option<Cbor>,
    pub auth_data: Vec<u8>,
    pub client_data_hash: Vec<u8>,
    pub credential_public_key: Option<Cbor>,
    pub credential_id: Vec<u8>,
    pub rp_id_hash: Vec<u8>,
    pub cose_alg: Option<i64>,
    pub aaguid: Vec<u8>,
}

/// `verifyRegistration(input)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn verify_registration(
    input: &RegistrationInput,
) -> Result<Registration, String> {
    let mut c = Checks(Vec::new());
    let object = from_base64url(&input.attestation_object);
    let client_bytes = from_base64url(&input.client_data_json);
    let (decoded, _) = decode_first(&object, 0)?;
    if !matches!(decoded, Cbor::Map(_)) {
        return Err("the attestation object is not a CBOR map".to_string());
    }
    let fmt = decoded.get_text("fmt").cloned();
    let auth_buf = decoded
        .get_text("authData")
        .and_then(Cbor::bytes)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| {
            "Cannot read properties of undefined (reading 'length')".to_string()
        })?;
    let auth = parse_authenticator_data(&auth_buf)?;
    let cd = client_data(&client_bytes)?;
    let ty = cd.get("type");
    c.add(
        "clientData.type is webauthn.create",
        ty == Some(&json!("webauthn.create")),
        format!("type={}", js_text(ty)),
    );
    c.add(
        "challenge matches",
        cd.get("challenge") == Some(&input.expected_challenge),
        format!("got {}", js_text(cd.get("challenge"))),
    );
    c.add(
        "origin matches",
        cd.get("origin") == Some(&input.expected_origin),
        format!(
            "got {}, expected {}",
            js_text(cd.get("origin")),
            js_text(Some(&input.expected_origin))
        ),
    );
    c.add(
        "rpIdHash is SHA-256 of the RP ID",
        auth.rp_id_hash == sha256(input.expected_rp_id.as_bytes()),
        format!("rpId={}", input.expected_rp_id),
    );
    c.add(
        "user presence",
        auth.flags.up,
        format!("UP={}", auth.flags.up),
    );
    if input.require_user_verification {
        c.add(
            "user verification",
            auth.flags.uv,
            format!("UV={}", auth.flags.uv),
        );
    }
    c.add(
        "attested credential data present",
        auth.flags.at,
        format!("AT={}", auth.flags.at),
    );
    c.add(
        "backup state only where backup eligible",
        auth.flags.be || !auth.flags.bs,
        format!("BE={} BS={}", auth.flags.be, auth.flags.bs),
    );
    let mut key = None;
    if auth.flags.at {
        let cose = auth.credential_public_key.clone().unwrap_or(Cbor::Null);
        let k = cose_key_to_jwk(&cose)?;
        if let Some(offered) = &input.expected_algorithms {
            let alg = match &k.2 {
                Cbor::Int(n) => *n as f64,
                _ => f64::NAN,
            };
            c.add(
                "credential algorithm was offered",
                offered.contains(&alg),
                format!(
                    "alg {}, offered {}",
                    if k.2 == Cbor::Null {
                        "undefined".to_string()
                    } else {
                        k.2.text_of()
                    },
                    offered
                        .iter()
                        .map(|n| crate::js::number_text(*n))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
        }
        let id_len = auth.credential_id.as_ref().map_or(0, Vec::len);
        c.add(
            "credential ID is at most 1023 bytes",
            id_len <= MAX_CREDENTIAL_ID_BYTES,
            format!("{id_len} bytes"),
        );
        key = Some(k);
    }
    let att_stmt = decoded.get_text("attStmt").cloned();
    let answer = json!({
        "ok": c.ok(),
        "checks": c.0,
        "failed": c.failed(),
        "fmt": fmt.as_ref().map_or(Json::Null, Cbor::plain),
        "aaguid": auth.aaguid.as_ref().map(|a| hex(a)),
        "credentialId": auth.credential_id.as_ref().map(|i| b64u(i)),
        "publicKeyJwk": key.as_ref().map(|k| k.0.clone()),
        "algorithm": key.as_ref().and_then(|k| k.1),
        "signCount": auth.sign_count,
        "flags": auth.flags.to_json(),
        "attStmt": att_stmt.as_ref().map_or(Json::Null, Cbor::plain),
        "coseAlg": key.as_ref().map_or(Json::Null, |k| k.2.plain()),
        "extensions": auth.extensions.as_ref().map(Cbor::plain),
    });
    Ok(Registration {
        answer,
        att_stmt,
        client_data_hash: sha256(&client_bytes),
        credential_public_key: auth.credential_public_key.clone(),
        credential_id: auth.credential_id.clone().unwrap_or_default(),
        rp_id_hash: auth.rp_id_hash.clone(),
        cose_alg: key.as_ref().and_then(|k| k.2.int()),
        aaguid: auth.aaguid.clone().unwrap_or_default(),
        auth_data: auth_buf,
    })
}

/// What `verifyAssertion()` reads.
#[derive(Debug, Clone, Default)]
pub struct AssertionInput {
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
    pub expected_challenge: Json,
    pub expected_origin: Json,
    pub expected_rp_id: String,
    pub require_user_verification: bool,
    pub previous_sign_count: Option<f64>,
    pub public_key_jwk: Json,
    pub allow_insecure: bool,
}

/// `verifyAssertion(input)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn verify_assertion(input: &AssertionInput) -> Result<Json, String> {
    let mut c = Checks(Vec::new());
    let auth_buf = from_base64url(&input.authenticator_data);
    let client_bytes = from_base64url(&input.client_data_json);
    let signature = from_base64url(&input.signature);
    let auth = parse_authenticator_data(&auth_buf)?;
    let cd = client_data(&client_bytes)?;
    let ty = cd.get("type");
    c.add(
        "clientData.type is webauthn.get",
        ty == Some(&json!("webauthn.get")),
        format!("type={}", js_text(ty)),
    );
    c.add(
        "challenge matches",
        cd.get("challenge") == Some(&input.expected_challenge),
        format!("got {}", js_text(cd.get("challenge"))),
    );
    c.add(
        "origin matches",
        cd.get("origin") == Some(&input.expected_origin),
        format!(
            "got {}, expected {}",
            js_text(cd.get("origin")),
            js_text(Some(&input.expected_origin))
        ),
    );
    c.add(
        "rpIdHash is SHA-256 of the RP ID",
        auth.rp_id_hash == sha256(input.expected_rp_id.as_bytes()),
        format!("rpId={}", input.expected_rp_id),
    );
    c.add(
        "user presence",
        auth.flags.up,
        format!("UP={}", auth.flags.up),
    );
    if input.require_user_verification {
        c.add(
            "user verification",
            auth.flags.uv,
            format!("UV={}", auth.flags.uv),
        );
    }
    if let Some(previous) = input.previous_sign_count {
        let now = f64::from(auth.sign_count);
        let advanced = if now == 0.0 && previous == 0.0 {
            true
        } else {
            now > previous
        };
        c.add(
            "signature counter advanced",
            advanced,
            format!(
                "now {}, was {}",
                auth.sign_count,
                crate::js::number_text(previous)
            ),
        );
    }
    let cose_alg = cose_alg_of_jwk(&input.public_key_jwk);
    if insecure_cose_ids().contains(&cose_alg) {
        c.add(
            "algorithm is allowed",
            input.allow_insecure,
            format!(
                "{} is insecure and webauthn.insecureAlgorithms is off",
                cose_name(cose_alg).unwrap_or("undefined")
            ),
        );
    }
    let mut signed = auth_buf.clone();
    signed.extend(sha256(&client_bytes));
    // Node's floor is the strict one in every mode (`rsaKeyProblem(key,
    // 2048)` inside `verifyCoseSignature()`).
    let options = CoseOptions {
        allow_insecure: input.allow_insecure,
        ..CoseOptions::default()
    };
    let valid = verify_cose_signature(
        cose_alg,
        CoseKey::Jwk(&input.public_key_jwk),
        &signed,
        &signature,
        &options,
    );
    let label = input
        .public_key_jwk
        .get("alg")
        .filter(|v| crate::js::truthy(v))
        .or_else(|| input.public_key_jwk.get("kty"))
        .map_or("undefined".to_string(), |v| js_text(Some(v)));
    c.add(
        "signature verifies",
        valid,
        format!("{label} over {} bytes", signed.len()),
    );
    Ok(json!({
        "ok": c.ok(),
        "checks": c.0,
        "failed": c.failed(),
        "signatureValid": valid,
        "signCount": auth.sign_count,
        "flags": auth.flags.to_json(),
        "coseAlg": cose_alg,
        "algorithm": cose_name(cose_alg),
    }))
}

/// Lower-case hex.
#[tracing::instrument(level = "debug", skip_all)]
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
