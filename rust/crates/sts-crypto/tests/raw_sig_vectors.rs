// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Signatures over raw bytes and the TPM against Node: `raw-sig-node.json`,
//! which `tests/tools/crypto-vectors.js` writes.
//!
//! * every verdict `verifyRawSignature()` gave — on the signature, on it
//!   tampered with, under the wrong key, under the wrong salt — is given
//!   here, in every family and encoding, the post-quantum ones included;
//! * TPM KDFa and the P1363 conversion are Node's bytes;
//! * Node's MakeCredential output is activated here (the seed unwrapped
//!   with the endorsement key, the integrity HMAC checked, the secret
//!   decrypted) — TPM2_ActivateCredential's arithmetic;
//! * Node's verdict on each CMS SignedData is this one, with the content
//!   and the signer.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use openssl::encrypt::Decrypter;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use openssl::sign::Signer;
use openssl::symm::Cipher;
use serde_json::Value as Json;
use sts_crypto::raw_sig::{
    self, EcdsaEncoding, RawFamily, RawHash, RawScheme, Salt,
};

fn b64(v: &Json) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}

fn scheme_of(v: &Json) -> RawScheme {
    let family = match v["family"].as_str().unwrap() {
        "rsa-pkcs1" => RawFamily::RsaPkcs1,
        "rsa-pss" => RawFamily::RsaPss,
        "ecdsa" => RawFamily::Ecdsa,
        "eddsa" => RawFamily::EdDsa,
        _ => RawFamily::PostQuantum,
    };
    let mut s =
        RawScheme::new(family, v["hash"].as_str().and_then(RawHash::from_name));
    match v["encoding"].as_str() {
        Some("p1363") => s = s.with_encoding(EcdsaEncoding::P1363),
        Some("der") => s = s.with_encoding(EcdsaEncoding::Der),
        _ => {}
    }
    if let Some(n) = v["saltLength"].as_u64() {
        s = s.with_salt(Salt::Length(n as u32));
    }
    s
}

#[test]
fn raw_signatures_and_the_tpm_match_node() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: raw-sig-node.json is not checked"
        );
        return;
    };
    let path = std::path::Path::new(&dir).join("raw-sig-node.json");
    let v: Json =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut failures = Vec::new();
    let mut checked = 0;
    let mut check = |ok: bool, what: String| {
        checked += 1;
        if !ok {
            failures.push(what);
        }
    };
    for r in v["signatures"].as_array().unwrap() {
        let name = r["name"].as_str().unwrap();
        let scheme = scheme_of(&r["scheme"]);
        let key = raw_sig::public_key_from_spki(&b64(&r["spki"]));
        let wrong = raw_sig::public_key_from_spki(&b64(&r["wrongSpki"]));
        let sig = b64(&r["signature"]);
        let mut tampered = sig.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let data = b"a challenge the attestor signs";
        check(
            raw_sig::verify_raw_signature(&scheme, &key, data, &sig)
                == r["ok"].as_bool().unwrap(),
            format!("{}: the signature", name),
        );
        check(
            raw_sig::verify_raw_signature(&scheme, &key, data, &tampered)
                == r["tampered"].as_bool().unwrap(),
            format!("{}: tampered", name),
        );
        check(
            raw_sig::verify_raw_signature(&scheme, &wrong, data, &sig)
                == r["wrongKey"].as_bool().unwrap(),
            format!("{}: the wrong key", name),
        );
    }
    for k in v["kdfa"].as_array().unwrap() {
        let hash = RawHash::from_name(k["hash"].as_str().unwrap()).unwrap();
        let out = raw_sig::tpm_kdfa(
            hash,
            &b64(&k["key"]),
            k["label"].as_str().unwrap(),
            &b64(&k["u"]),
            &b64(&k["v"]),
            k["bits"].as_u64().unwrap() as u32,
        )
        .unwrap();
        check(out == b64(&k["out"]), format!("KDFa {}", k));
    }
    for i in v["integers"].as_array().unwrap() {
        let hex = |s: &str| {
            (0..s.len())
                .step_by(2)
                .map(|j| u8::from_str_radix(&s[j..j + 2], 16).unwrap())
                .collect::<Vec<u8>>()
        };
        let out = raw_sig::ecdsa_integers_to_p1363(
            i["curve"].as_str().unwrap(),
            &hex(i["r"].as_str().unwrap()),
            &hex(i["s"].as_str().unwrap()),
        );
        let want = i["out"].as_str().map(hex);
        check(out == want, format!("integers {}", i));
    }

    // TPM2_ActivateCredential over Node's MakeCredential.
    let c = &v["credential"];
    let ek = PKey::private_key_from_pem(
        c["ekPrivatePem"].as_str().unwrap().as_bytes(),
    )
    .unwrap();
    let ak_name = b64(&c["akName"]);
    let mut dec = Decrypter::new(&ek).unwrap();
    dec.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
    dec.set_rsa_oaep_md(MessageDigest::sha256()).unwrap();
    dec.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
    dec.set_rsa_oaep_label(b"IDENTITY\0").unwrap();
    let encrypted = b64(&c["encryptedSecret"]);
    let mut seed = vec![0u8; dec.decrypt_len(&encrypted).unwrap()];
    let n = dec.decrypt(&encrypted, &mut seed).unwrap();
    seed.truncate(n);
    let credential = b64(&c["credential"]);
    let integrity_len =
        u16::from_be_bytes([credential[0], credential[1]]) as usize;
    let (integrity, enc_identity) = credential[2..].split_at(integrity_len);
    let mac_key =
        raw_sig::tpm_kdfa(RawHash::Sha256, &seed, "INTEGRITY", &[], &[], 256)
            .unwrap();
    let k = PKey::hmac(&mac_key).unwrap();
    let mut s = Signer::new(MessageDigest::sha256(), &k).unwrap();
    s.update(enc_identity).unwrap();
    s.update(&ak_name).unwrap();
    check(
        s.sign_to_vec().unwrap() == integrity,
        "Node's credential: the integrity HMAC".to_string(),
    );
    let storage = raw_sig::tpm_kdfa(
        RawHash::Sha256,
        &seed,
        "STORAGE",
        &ak_name,
        &[],
        128,
    )
    .unwrap();
    let plain = openssl::symm::decrypt(
        Cipher::aes_128_cfb128(),
        &storage,
        Some(&[0u8; 16]),
        enc_identity,
    )
    .unwrap();
    check(
        &plain[2..] == c["secret"].as_str().unwrap().as_bytes(),
        "Node's credential: the secret".to_string(),
    );

    for p in v["pkcs7"].as_array().unwrap() {
        let name = p["name"].as_str().unwrap();
        let certs: Vec<Vec<u8>> = p["certificates"]
            .as_array()
            .unwrap()
            .iter()
            .map(b64)
            .collect();
        let ours = raw_sig::verify_pkcs7_signed_data(&b64(&p["der"]), &certs);
        check(
            ours.is_ok() == p["ok"].as_bool().unwrap(),
            format!("CMS {}: the verdict", name),
        );
        if let Ok(found) = ours {
            check(
                found.content == b64(&p["content"]),
                format!("CMS {}: the content", name),
            );
            check(
                found.signer_der == b64(&p["signer"]),
                format!("CMS {}: the signer", name),
            );
            check(
                found.embedded_ders.len() as u64
                    == p["embedded"].as_u64().unwrap(),
                format!("CMS {}: the embedded certificates", name),
            );
        }
    }
    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!("{} answers as Node gives them", checked);
}
