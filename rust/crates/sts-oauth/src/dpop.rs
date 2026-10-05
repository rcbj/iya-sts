// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! RFC 9449's proof check (`dpop.ts`'s `verifyProof()`), in Node's order and
//! with Node's codes.
//!
//! * **It never answers a request.** An authorization server says
//!   `use_dpop_nonce` in a 400 JSON body and a resource server in a 401
//!   `WWW-Authenticate`; the caller decides which, from [`Failure`].
//! * **The stores are the caller's** ([`ProofContext`]): whether nonces are
//!   asked for and which are current, the per-realm replay history and the
//!   cross-node reservation, the `iat` window, and FAPI's one-minute rule.
//!   The function is complete without them; what holds them comes with the
//!   runtime.
//! * **The algorithm list is explicit** — RFC 8725 section 3.1, doubly so
//!   here, because the key verified against is the one the proof supplied: a
//!   verifier that also took the algorithm from the proof would let it choose
//!   both halves. Every asymmetric algorithm this service verifies, and of the
//!   post-quantum ones only the three ML-DSA sets RFC 9964 gives a
//!   thumbprint (`cnf.jkt` is one).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{Map, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_crypto::jws::{verify_compact, VerifyOptions};
use sts_crypto::jws_alg::{Family, JwsAlg, ALGS};
use sts_crypto::keys::{JwsKey, KeyPolicy};

/// The `typ` a proof must carry.
pub const PROOF_TYP: &str = "dpop+jwt";
/// The default `iat` allowance (`oauth2.dpopIatSkewS`).
pub const IAT_SKEW_SECONDS: i64 = 300;

/// `SIGNING_ALGS`: every asymmetric algorithm, the post-quantum ones only
/// where RFC 9964 defines a thumbprint (ML-DSA).
pub fn signing_algs() -> Vec<&'static str> {
    ALGS.iter()
        .filter(|a| a.is_asymmetric())
        .filter(|a| {
            !a.is_post_quantum() || matches!(a.family, Family::MlDsa { .. })
        })
        .map(|a| a.name)
        .collect()
}

/// The key type (and curve) an algorithm's key must be.
fn key_type_of(alg: &JwsAlg) -> (&'static str, Option<&'static str>) {
    match alg.family {
        Family::Rsa(_) | Family::RsaPss(_) => ("RSA", None),
        Family::Ec { crv, .. } => ("EC", Some(crv)),
        Family::EdDsa => ("OKP", None),
        Family::MlDsa { .. } | Family::SlhDsa { .. } => ("AKP", None),
        Family::Hmac(_) => ("oct", None),
        Family::Composite(_) => ("AKP", None),
    }
}

/// RFC 7638's thumbprint, never truncated — what becomes `cnf.jkt` — over
/// the member list of the key's type (RFC 9964's for AKP). `None` for a key
/// type with no list or a member missing.
pub fn thumbprint(jwk: &Json) -> Option<String> {
    let members: &[&str] = match jwk.get("kty")?.as_str()? {
        "RSA" => &["e", "kty", "n"],
        "EC" => &["crv", "kty", "x", "y"],
        "OKP" => &["crv", "kty", "x"],
        "AKP" => &["alg", "kty", "pub"],
        "oct" => &["k", "kty"],
        _ => return None,
    };
    let mut parts = Vec::new();
    for m in members {
        let value = jwk
            .get(*m)
            .filter(|v| !v.is_null() && v.as_str() != Some(""))?;
        parts.push(format!("\"{}\":{}", m, value));
    }
    Some(URL_SAFE_NO_PAD.encode(openssl::sha::sha256(
        format!("{{{}}}", parts.join(",")).as_bytes(),
    )))
}

/// `ath` (section 4.2): base64url(SHA-256(ASCII(access token))).
pub fn ath_of(access_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(openssl::sha::sha256(access_token.as_bytes()))
}

/// `normalizeHtu()`: scheme and host lower-cased, the scheme's default port
/// dropped, no query or fragment. An unparseable value comes back as itself,
/// so the comparison fails and says what arrived.
pub fn normalize_htu(value: &str) -> String {
    let Ok(parsed) = url::Url::parse(value) else {
        return value.to_string();
    };
    let port = parsed.port().map(|p| format!(":{}", p)).unwrap_or_default();
    format!(
        "{}://{}{}{}",
        parsed.scheme(),
        parsed.host_str().unwrap_or("").to_lowercase(),
        port,
        parsed.path()
    )
}

/// What the replay history says of a `jti`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seen {
    /// Never: this proof may be used.
    No,
    /// This process saw it (STS-OAUTH-0110).
    Here,
    /// Another request's reservation, on any node, holds it (0519).
    Elsewhere,
    /// Whether it was used could not be recorded (0520).
    Unknown,
}

/// The stores and settings a proof is checked against.
pub trait ProofContext {
    /// `oauth2.dpopIatSkewS`.
    fn iat_skew_seconds(&self) -> i64 {
        IAT_SKEW_SECONDS
    }
    /// `global.trustProxy`, named in an `htu` refusal when it is off.
    fn trust_proxy(&self) -> bool;
    /// FAPI 2.0's one-minute rule on a timestamp ahead, where a profile is on.
    fn future_refusal(&self, _iat: &Json) -> Option<(ErrorCode, String)> {
        None
    }
    /// Whether this server asks for a nonce.
    fn nonce_required(&self) -> bool;
    fn nonce_is_current(&self, nonce: &Json) -> bool;
    /// The history's answer, asked before anything is remembered.
    fn seen(&self, jti: &str) -> Seen;
    /// Remembers it, last; `false` when the history is full of live proofs.
    fn remember(&self, jti: &str, now: i64) -> bool;
    fn key_policy(&self) -> KeyPolicy {
        KeyPolicy::STRICT
    }
}

/// The request a proof was sent with.
pub struct ProofRequest<'a> {
    pub htm: &'a str,
    pub htu: &'a str,
    /// The access token presented with it, where one was.
    pub access_token: Option<&'a str>,
    /// That token's `cnf.jkt`.
    pub expected_jkt: Option<&'a str>,
    pub now: i64,
}

/// A refused proof: `invalid_dpop_proof`, with the sentence and the code.
#[derive(Clone, Debug, PartialEq)]
pub struct Failure {
    pub code: ErrorCode,
    pub description: String,
    /// No proof at all: a resource server answers it as a Bearer challenge.
    pub missing: bool,
    /// Ask again with a fresh nonce.
    pub need_nonce: bool,
}

impl Failure {
    pub const ERROR: &'static str = "invalid_dpop_proof";
}

/// A proof that passed.
#[derive(Clone, Debug, PartialEq)]
pub struct Proof {
    pub jkt: String,
    pub jwk: Json,
    pub header: Map<String, Json>,
    pub claims: Map<String, Json>,
}

fn fail(code: ErrorCode, description: impl Into<String>) -> Failure {
    Failure {
        code,
        description: description.into(),
        missing: false,
        need_nonce: false,
    }
}

fn object(part: &str) -> Result<Option<Map<String, Json>>, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part.trim_end_matches('='))
        .map_err(|e| e.to_string())?;
    match serde_json::from_slice::<Json>(&bytes).map_err(|e| e.to_string())? {
        Json::Object(m) => Ok(Some(m)),
        _ => Ok(None),
    }
}

/// `verifyProof()`: the twelve checks.
pub fn verify_proof(
    raw_header: Option<&str>,
    request: &ProofRequest,
    ctx: &dyn ProofContext,
) -> Result<Proof, Failure> {
    // Check 1: exactly one header field. Repeated fields arrive joined with
    // ", ", and a compact JWS holds no comma.
    let raw = raw_header.map(str::trim).unwrap_or("");
    if raw.is_empty() {
        let mut f = fail(codes::STS_OAUTH_0093, "No DPoP proof was presented.");
        f.missing = true;
        return Err(f);
    }
    if raw.contains(',') {
        return Err(fail(
            codes::STS_OAUTH_0094,
            "More than one DPoP header field was sent; RFC 9449 permits exactly one.",
        ));
    }
    // Check 2: a single well-formed JWT.
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() != 3 {
        return Err(fail(
            codes::STS_OAUTH_0095,
            "The DPoP proof is not a compact JWS with three parts.",
        ));
    }
    let (header, claims) = match (object(parts[0]), object(parts[1])) {
        (Ok(Some(h)), Ok(Some(c))) => (h, c),
        (Err(e), _) | (_, Err(e)) => {
            return Err(fail(
                codes::STS_OAUTH_0096,
                format!("The DPoP proof could not be decoded: {}", e),
            ))
        }
        _ => {
            return Err(fail(
                codes::STS_OAUTH_0097,
                "The DPoP proof header or payload is not a JSON object.",
            ))
        }
    };
    // Check 4: typ, before the signature: it stops a JWT signed for another
    // purpose with the same key being accepted as a proof.
    if header.get("typ").and_then(Json::as_str) != Some(PROOF_TYP) {
        return Err(fail(
            codes::STS_OAUTH_0098,
            format!(
                "The DPoP proof must have typ \"{}\"; this one has {}. Without this check some other JWT the \
                 client signed with the same key would be accepted as a proof.",
                PROOF_TYP,
                header.get("typ").cloned().unwrap_or(Json::Null)
            ),
        ));
    }
    // Check 5: a registered asymmetric algorithm, never none, never a MAC.
    let allowed = signing_algs();
    let alg_name = header.get("alg").and_then(Json::as_str).unwrap_or("");
    let Some(alg) =
        JwsAlg::by_name(alg_name).filter(|a| allowed.contains(&a.name))
    else {
        return Err(fail(
            codes::STS_OAUTH_0099,
            format!(
                "The DPoP proof is signed with {}, which this server does not accept. RFC 9449 requires a \
                 registered asymmetric algorithm, never none and never a MAC: {}.",
                header.get("alg").cloned().unwrap_or(Json::Null),
                allowed.join(", ")
            ),
        ));
    };
    // Check 7: a public key, and no private member — checked before the
    // signature, or a client could hand over a whole key pair and be
    // believed.
    let jwk = match header.get("jwk") {
        Some(j @ Json::Object(m))
            if m.get("kty").is_some_and(|k| !k.is_null()) =>
        {
            j.clone()
        }
        _ => {
            return Err(fail(
                codes::STS_OAUTH_0100,
                "The DPoP proof header must carry the public key as a jwk.",
            ))
        }
    };
    let private: Vec<&str> = ["d", "p", "q", "dp", "dq", "qi", "k", "priv"]
        .into_iter()
        .filter(|m| jwk.get(*m).is_some())
        .collect();
    if !private.is_empty() {
        return Err(fail(
            codes::STS_OAUTH_0101,
            format!(
                "The DPoP proof header carries private key material ({}), which RFC 9449 forbids.",
                private.join(", ")
            ),
        ));
    }
    let kty = jwk.get("kty").and_then(Json::as_str).unwrap_or("");
    let crv = jwk.get("crv").and_then(Json::as_str);
    let (want_kty, want_crv) = key_type_of(alg);
    if kty != want_kty || want_crv.is_some_and(|c| crv != Some(c)) {
        return Err(fail(
            codes::STS_OAUTH_0102,
            format!(
                "The DPoP proof header key ({}{}) does not match its alg {}.",
                kty,
                crv.map(|c| format!("/{}", c)).unwrap_or_default(),
                alg.name
            ),
        ));
    }
    // RFC 9964: an AKP key names its one algorithm, a thumbprint member.
    if kty == "AKP" && jwk.get("alg").and_then(Json::as_str) != Some(alg.name) {
        return Err(fail(
            codes::STS_OAUTH_0102,
            format!(
                "The DPoP proof header key is an AKP key for {}, which does not match its alg {}.",
                jwk.get("alg").and_then(Json::as_str).unwrap_or("undefined"),
                alg.name
            ),
        ));
    }
    // Check 3: the required claims, named.
    let absent: Vec<&str> = ["jti", "htm", "htu", "iat"]
        .into_iter()
        .filter(|c| {
            matches!(claims.get(*c), None | Some(Json::Null))
                || claims.get(*c).and_then(Json::as_str) == Some("")
        })
        .collect();
    if !absent.is_empty() {
        return Err(fail(
            codes::STS_OAUTH_0103,
            format!("The DPoP proof is missing {}.", absent.join(", ")),
        ));
    }
    // Check 6: the signature, with the key in the header and the explicit
    // list.
    let verified = JwsKey::from_jwk(&jwk).and_then(|key| {
        verify_compact(
            raw,
            &key,
            &VerifyOptions {
                algorithms: &allowed,
                empty_payload: false,
                policy: ctx.key_policy(),
            },
        )
    });
    if let Err(e) = verified {
        return Err(fail(
            codes::STS_OAUTH_0104,
            format!("The DPoP proof signature does not verify with the key in its own header: {}", e),
        ));
    }
    let text = |c: &str| match claims.get(c) {
        Some(Json::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => String::new(),
    };
    // Check 8: htm.
    if text("htm").to_uppercase() != request.htm.to_uppercase() {
        return Err(fail(
            codes::STS_OAUTH_0105,
            format!("The DPoP proof was made for HTTP {}, but this is a {} request.", text("htm"), request.htm),
        ));
    }
    // Check 9: htu, without query or fragment.
    if normalize_htu(&text("htu")) != normalize_htu(request.htu) {
        return Err(fail(
            codes::STS_OAUTH_0106,
            format!(
                "The DPoP proof was made for {}, but this request went to {}.{}",
                text("htu"),
                request.htu,
                if ctx.trust_proxy() {
                    ""
                } else {
                    " If something is terminating TLS in front of this service, that is why: global.trustProxy \
                     is OFF, so X-Forwarded-Proto and X-Forwarded-Host are ignored and this server describes the \
                     LAST HOP rather than the URL the client used. Turn it on where a proxy really is in front — \
                     and leave it off where one is not, because those are headers any client can set, and a \
                     client that chooses its own htu has unbound its own proof."
                }
            ),
        ));
    }
    // Check 11: iat inside the window, and FAPI's minute ahead.
    let iat = claims.get("iat").cloned().unwrap_or(Json::Null);
    let window = ctx.iat_skew_seconds();
    let age = iat
        .as_f64()
        .or_else(|| iat.as_str().and_then(|s| s.trim().parse::<f64>().ok()))
        .map(|i| request.now as f64 - i)
        .filter(|a| a.is_finite());
    match age {
        Some(a) if a.abs() <= window as f64 => {}
        _ => {
            return Err(fail(
                codes::STS_OAUTH_0107,
                format!(
                    "The DPoP proof iat is {}; this server accepts {} seconds either way (oauth2.dpopIatSkewS).",
                    age.map(|a| format!("{} seconds away", a)).unwrap_or_else(|| "not a number".into()),
                    window
                ),
            ))
        }
    }
    if let Some((code, description)) = ctx.future_refusal(&iat) {
        return Err(fail(code, description));
    }
    // Check 10: the nonce; a missing one is a request for one.
    if ctx.nonce_required() {
        let refused = match claims.get("nonce") {
            None => Some(fail(codes::STS_OAUTH_0108, "This server requires a DPoP nonce.")),
            Some(n) if !ctx.nonce_is_current(n) => Some(fail(
                codes::STS_OAUTH_0109,
                "The DPoP proof nonce is not one this server issued, or it has expired.",
            )),
            Some(_) => None,
        };
        if let Some(mut f) = refused {
            f.need_nonce = true;
            return Err(f);
        }
    }
    // Section 11.1: a proof is good for one request — here, then anywhere.
    let jti = text("jti");
    match ctx.seen(&jti) {
        Seen::No => {}
        Seen::Here => {
            return Err(fail(
                codes::STS_OAUTH_0110,
                format!("This DPoP proof has already been used (jti {}). A proof is good for one request.", jti),
            ))
        }
        Seen::Elsewhere => {
            return Err(fail(
                codes::STS_OAUTH_0519,
                format!(
                    "This DPoP proof has already been used (jti {}) by another request. A proof is good for one \
                     request.",
                    jti
                ),
            ))
        }
        Seen::Unknown => {
            return Err(fail(
                codes::STS_OAUTH_0520,
                format!(
                    "Whether this DPoP proof (jti {}) has already been used could not be recorded, so it is \
                     refused. Send a fresh proof.",
                    jti
                ),
            ))
        }
    }
    // Check 12: ath with a token, and the token's own binding.
    let Some(jkt) = thumbprint(&jwk) else {
        return Err(fail(
            codes::STS_OAUTH_0100,
            "The DPoP proof header key has no RFC 7638 thumbprint, so nothing can be bound to it.",
        ));
    };
    if let Some(token) = request.access_token {
        match claims.get("ath") {
            None => {
                return Err(fail(
                    codes::STS_OAUTH_0111,
                    "The DPoP proof must carry ath when it accompanies an access token; without it a proof \
                     captured with one token could be presented with another.",
                ))
            }
            Some(a) if a.as_str() != Some(ath_of(token).as_str()) => {
                return Err(fail(
                    codes::STS_OAUTH_0112,
                    "The DPoP proof ath does not match the access token presented with it.",
                ))
            }
            Some(_) => {}
        }
    }
    if let Some(expected) = request.expected_jkt.filter(|e| !e.is_empty()) {
        if expected != jkt {
            return Err(fail(
                codes::STS_OAUTH_0113,
                format!(
                    "The access token is bound to a different key than the one that signed this DPoP proof \
                     (cnf.jkt {}, proof key {}).",
                    expected, jkt
                ),
            ));
        }
    }
    // The bound, asked last so every other refusal keeps its own code.
    if !ctx.remember(&jti, request.now) {
        return Err(fail(
            codes::STS_OAUTH_0554,
            "This server cannot remember another DPoP proof right now: its replay history for this realm is \
             full of live proofs, and forgetting one would let it be replayed. Retry shortly with a fresh proof.",
        ));
    }
    Ok(Proof {
        jkt,
        jwk,
        header,
        claims,
    })
}
