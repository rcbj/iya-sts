// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Every refresh token is encrypted to its own realm
//! (`oauth-oidc/refresh_token_crypto.ts`): a signed JWT nested in a compact
//! JWE (`cty: JWT`), under the realm's `refreshTokenEncKeys` — the set's
//! secret through HKDF for the symmetric algorithms
//! (`iya-sts refresh token v1|<alg>|<enc>`), its RSA or EC key for the
//! asymmetric ones. `oauth2.refreshTokenEncryptionAlg` and `…Enc` choose,
//! A256KW and A256GCM by default, and a value this service does not
//! implement falls back to them, as Node's `configured()` does.
//!
//! Opening refuses as Node refuses, with its codes and sentences: an
//! unencrypted JWT (`STS-OAUTH-0237`), anything else not a JWE, a `kid`
//! that is not this realm's, a ciphertext that does not open
//! (`STS-OAUTH-0238`), and a plaintext that is not a nested JWT
//! (`STS-OAUTH-0239`). The KEM algorithms (`kemKeyFor()`) and the retired
//! key sets of a rotation are not read here yet.

use serde_json::Value as Json;
use sts_core::errors::{codes, ErrorCode};
use sts_crypto::jwe::{
    decrypt_compact, encrypt_compact, DecryptOptions, EncryptOptions,
};

/// The defaults.
pub const DEFAULT_ALG: &str = "A256KW";
pub const DEFAULT_ENC: &str = "A256GCM";

/// A refusal with its code.
#[derive(Debug, Clone, PartialEq)]
pub struct Refused {
    pub code: ErrorCode,
    pub message: String,
}

fn refused(code: ErrorCode, message: &str) -> Refused {
    Refused {
        code,
        message: message.to_string(),
    }
}

/// `kindOf(alg)`.
fn kind_of(alg: &str) -> &'static str {
    if alg.starts_with("RSA-OAEP") {
        "rsa"
    } else if alg.starts_with("ECDH-ES") {
        "ec"
    } else {
        "secret"
    }
}

fn symmetric_bytes(alg: &str, enc: &str) -> Result<usize, Refused> {
    if alg == "dir" {
        return sts_crypto::jwe::enc(enc).map(|e| e.cek_bytes).ok_or_else(
            || {
                refused(
                    codes::STS_OAUTH_0238,
                    &format!(
                    "the content encryption algorithm \"{}\" is not one this \
                     service implements.",
                    enc
                ),
                )
            },
        );
    }
    let bits = alg
        .strip_prefix('A')
        .and_then(|rest| rest.strip_suffix("KW"))
        .map(|rest| rest.trim_end_matches("GCM"))
        .and_then(|b| b.parse::<usize>().ok())
        .filter(|b| [128, 192, 256].contains(b));
    bits.map(|b| b / 8).ok_or_else(|| {
        refused(
            codes::STS_OAUTH_0238,
            &format!(
                "the key management algorithm \"{}\" is not one this service \
                 implements.",
                alg
            ),
        )
    })
}

/// `symmetricKeyFor(secret, alg, enc)`.
fn symmetric_key(
    secret: &[u8],
    alg: &str,
    enc: &str,
) -> Result<Vec<u8>, Refused> {
    let length = symmetric_bytes(alg, enc)?;
    sts_crypto::secrets::hkdf_sha256(
        secret,
        format!("iya-sts refresh token v1|{}|{}", alg, enc).as_bytes(),
        length,
    )
    .map_err(|e| refused(codes::STS_OAUTH_0240, &e.to_string()))
}

/// The realm's refresh-token keys, as the key set stores them.
pub struct RefreshKeys<'a>(pub &'a Json);

impl RefreshKeys<'_> {
    fn secret(&self) -> Vec<u8> {
        self.0
            .get("secret")
            .and_then(Json::as_str)
            .and_then(|s| {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.decode(s).ok()
            })
            .unwrap_or_default()
    }
    fn secret_kid(&self) -> String {
        crate::js::string_of(self.0.get("secretKid"))
    }
    fn kid_for(&self, kind: &str) -> String {
        if kind == "secret" {
            return self.secret_kid();
        }
        crate::js::string_of(
            self.0.pointer(&format!("/{}/publicJwk/kid", kind)),
        )
    }
}

/// `configured()`: the pair from the settings, the defaults where one is
/// not implemented.
#[tracing::instrument(level = "debug")]
pub fn configured(alg: &str, enc: &str) -> (String, String) {
    let alg_ok = !alg.is_empty()
        && !alg.starts_with("PBES2-")
        && sts_crypto::jwe::alg(alg).is_some();
    let enc_ok = !enc.is_empty() && sts_crypto::jwe::enc(enc).is_some();
    (
        if alg_ok { alg } else { DEFAULT_ALG }.to_string(),
        if enc_ok { enc } else { DEFAULT_ENC }.to_string(),
    )
}

/// `seal(jws)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn seal(
    jws: &str,
    keys: &Json,
    alg: &str,
    enc: &str,
) -> Result<String, Refused> {
    let keys = RefreshKeys(keys);
    let kind = kind_of(alg);
    let secret;
    let kid_jwk;
    let mut options = EncryptOptions {
        alg: Some(alg),
        enc,
        typ: Some("JWT"),
        cty: Some("JWT"),
        ..EncryptOptions::default()
    };
    if kind == "secret" {
        secret = symmetric_key(&keys.secret(), alg, enc)?;
        kid_jwk = serde_json::json!({ "kid": keys.secret_kid() });
        options.secret = Some(&secret);
        options.jwk = Some(&kid_jwk);
    } else {
        options.jwk = keys.0.pointer(&format!("/{}/publicJwk", kind));
    }
    encrypt_compact(jws.as_bytes(), &options).map_err(|e| {
        tracing::error!(
            "{}a refresh token could not be encrypted with {} / {}, so none \
             was issued: {}",
            sts_core::log::tag(codes::STS_OAUTH_0240),
            alg,
            enc,
            e
        );
        refused(codes::STS_OAUTH_0240, &e.to_string())
    })
}

/// `open(token)`: the nested JWS, or why not.
#[tracing::instrument(level = "debug", skip_all)]
pub fn open(token: &str, keys: &Json) -> Result<String, Refused> {
    let text = token.trim();
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() == 3 {
        return Err(refused(
            codes::STS_OAUTH_0237,
            "refresh tokens issued by this service are encrypted, and this \
             one is not; sign in again to get a new one.",
        ));
    }
    let not_ours = || {
        refused(
            codes::STS_OAUTH_0238,
            "the refresh token is not a token this service issued.",
        )
    };
    if parts.len() != 5 {
        return Err(not_ours());
    }
    let header = crate::js::segment_json(text, 0).map_err(|_| not_ours())?;
    let alg = crate::js::string_of(header.get("alg"));
    let enc = crate::js::string_of(header.get("enc"));
    let keys = RefreshKeys(keys);
    let kind = kind_of(&alg);
    let expected = keys.kid_for(kind);
    if crate::js::string_of(header.get("kid")) != expected {
        return Err(refused(
            codes::STS_OAUTH_0238,
            "the refresh token was not issued by this realm, or was issued \
             under keys that have since been rotated.",
        ));
    }
    let undecryptable = || {
        refused(
            codes::STS_OAUTH_0238,
            "the refresh token could not be decrypted; it has been altered, \
             or was not issued by this realm.",
        )
    };
    let secret;
    let private;
    let mut options = DecryptOptions {
        expected_kid: Some(&expected),
        ..DecryptOptions::default()
    };
    if kind == "secret" {
        secret = symmetric_key(&keys.secret(), &alg, &enc)
            .map_err(|_| undecryptable())?;
        options.secret = Some(&secret);
    } else {
        let pem = crate::js::string_of(
            keys.0.pointer(&format!("/{}/privateKeyPem", kind)),
        );
        private = openssl_private(&pem).ok_or_else(undecryptable)?;
        options.private_key = Some(&private);
    }
    let opened =
        decrypt_compact(text, &options).map_err(|_| undecryptable())?;
    let cty = opened
        .header
        .get("cty")
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_ascii_uppercase();
    let plain = String::from_utf8(opened.plaintext).unwrap_or_default();
    if cty != "JWT" || plain.split('.').count() != 3 {
        return Err(refused(
            codes::STS_OAUTH_0239,
            "the refresh token decrypted to something that is not a signed \
             JWT.",
        ));
    }
    Ok(plain)
}

fn openssl_private(pem: &str) -> Option<sts_crypto::keys::PrivateKey> {
    sts_crypto::keys::private_key_from_pem(pem).ok()
}
