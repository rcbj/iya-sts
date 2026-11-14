// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The Kerberos codec against Node: `krb5-codec-node.json`, which
//! `tests/tools/crypto-vectors.js` writes from `kerberos/`'s codec modules.
//! Everything there is deterministic (the confounders are in the vector),
//! so every answer must be Node's bytes, Node's JSON and Node's sentence:
//!
//! * MD4, MD5, HMAC-MD5, RC4, UTF-16LE, strict UTF-8, n-fold;
//! * every enctype's profile, name and refusal; string-to-key (with RFC
//!   3962's and RFC 8009's published keys), Ke/Ki/Kc, encryptions
//!   (decrypting back to the plaintext and the confounder), checksums,
//!   decryption refusals, CTS (RFC 3962's vectors);
//! * every message kind decoded to Node's JSON, re-encoded byte for byte
//!   (raw bytes kept, and rebuilt without them), and every refusal;
//! * the generic TLV tree, identify(), principals, flag names, the error
//!   table, INTEGER and KerberosTime encodings;
//! * the 0x8003 checksum, InitialContextTokens, MIC and Wrap tokens (a
//!   Wrap rebuilt with the confounder recovered from Node's token);
//! * SPNEGO's tokens, OIDs, mechListMIC and MIC requirement;
//! * PKINIT's OtherInfo, ExternalPrincipalIdentifier and OIDs;
//! * the MS-KKDCP envelope, refusal for refusal.
//!
//! With `STS_WRITE_VECTORS=1` the second test writes `krb5-codec-rust.json`
//! — keys, ciphertexts, checksums, messages and tokens Rust made — which
//! `tests/rust_crypto_vectors.js` reads back in Node.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; unset, these
//! tests say so and pass.

#![allow(clippy::unwrap_used)] // a test file

use serde::Serialize;
use serde_json::{json, Value as Json};
use sts_kerberos::asn1::{self, Tlv};
use sts_kerberos::crypto::{self, Enctype};
use sts_kerberos::error::Krb5Error;
use sts_kerberos::fast;
use sts_kerberos::gss::{self, GssChecksumOptions, Role, TokenOptions};
use sts_kerberos::keytab::{self, KeytabEntry};
use sts_kerberos::kkdcp;
use sts_kerberos::messages::*;
use sts_kerberos::pkinit;
use sts_kerberos::primitives as prim;
use sts_kerberos::spnego;
use sts_kerberos::time::KrbTime;

fn unhex(v: &Json) -> Vec<u8> {
    prim::from_hex(v.as_str().unwrap()).unwrap()
}

fn hex(b: &[u8]) -> String {
    prim::to_hex(b)
}

fn opt_bytes(v: &Json) -> Option<Vec<u8>> {
    v.as_str().map(|s| prim::from_hex(s).unwrap())
}

fn js<T: Serialize>(v: &T) -> Json {
    serde_json::to_value(v).unwrap()
}

fn i(v: &Json) -> i64 {
    v.as_i64().unwrap()
}

fn role(v: &Json) -> Role {
    Role::parse(v.as_str().unwrap()).unwrap()
}

/// What a kind's reader made, its re-encoding with raw bytes kept and
/// rebuilt without them.
type Decoded = (Json, Option<Vec<u8>>, Option<Vec<u8>>);

fn strip_ticket(t: &mut Ticket) {
    t.raw = None;
}

fn strip_body(b: &mut KdcReqBody) {
    b.raw = None;
    if let Some(list) = b.additional_tickets.as_mut() {
        list.iter_mut().for_each(strip_ticket);
    }
}

fn tlv(b: &[u8]) -> Result<Tlv<'_>, Krb5Error> {
    asn1::read_tlv(b, 0, 0)
}

/// A kind's reader and encoder, as the Node builder's KINDS table names
/// them.
fn decode(kind: &str, b: &[u8]) -> Result<Decoded, Krb5Error> {
    Ok(match kind {
        "PrincipalName" => {
            let v = PrincipalName::read(&tlv(b)?)?;
            (js(&v), Some(v.encode()), Some(v.encode()))
        }
        "EncryptedData" => {
            let v = EncryptedData::read(&tlv(b)?)?;
            (js(&v), Some(v.encode()), Some(v.encode()))
        }
        "EncryptionKey" => {
            let v = EncryptionKey::read(&tlv(b)?)?;
            (js(&v), Some(v.encode()), Some(v.encode()))
        }
        "Checksum" => {
            let v = Checksum::read(&tlv(b)?)?;
            (js(&v), Some(v.encode()), Some(v.encode()))
        }
        "PaData" => {
            let v = PaData::read(&tlv(b)?)?;
            (js(&v), Some(v.encode()), Some(v.encode()))
        }
        "HostAddresses" => {
            let v = read_host_addresses(&tlv(b)?)?;
            let e = enc_host_addresses(&v);
            (js(&v), Some(e.clone()), Some(e))
        }
        "AuthorizationData" => {
            let v = read_authorization_data(&tlv(b)?)?;
            let e = enc_authorization_data(&v);
            (js(&v), Some(e.clone()), Some(e))
        }
        "Ticket" => {
            let v = Ticket::read(b)?;
            let mut s = v.clone();
            strip_ticket(&mut s);
            (js(&v), Some(v.encode()), Some(s.encode()))
        }
        "EncTicketPart" => {
            let v = EncTicketPart::read(b)?;
            (js(&v), v.encode().ok(), v.encode().ok())
        }
        "KdcReqBody" => {
            let v = KdcReqBody::read(&tlv(b)?)?;
            let mut s = v.clone();
            strip_body(&mut s);
            (js(&v), v.encode().ok(), s.encode().ok())
        }
        "KdcReq" => {
            let v = KdcReq::read(b)?;
            let mut s = v.clone();
            strip_body(&mut s.req_body);
            (js(&v), v.encode().ok(), s.encode().ok())
        }
        "KdcRep" => {
            let v = KdcRep::read(b)?;
            let mut s = v.clone();
            strip_ticket(&mut s.ticket);
            (js(&v), Some(v.encode()), Some(s.encode()))
        }
        "EncKdcRepPart" => {
            let v = EncKdcRepPart::read(b)?;
            let n = if v.tagged_as == "EncTGSRepPart" {
                26
            } else {
                25
            };
            (js(&v), v.encode(Some(n)).ok(), v.encode(Some(n)).ok())
        }
        "Authenticator" => {
            let v = Authenticator::read(b)?;
            (js(&v), Some(v.encode()), Some(v.encode()))
        }
        "ApReq" => {
            let v = ApReq::read(b)?;
            let mut s = v.clone();
            strip_ticket(&mut s.ticket);
            (js(&v), v.encode().ok(), s.encode().ok())
        }
        "ApRep" => {
            let v = ApRep::read(b)?;
            (js(&v), Some(v.encode()), Some(v.encode()))
        }
        "EncApRepPart" => {
            let v = EncApRepPart::read(b)?;
            (js(&v), Some(v.encode()), Some(v.encode()))
        }
        "KrbError" => {
            let v = KrbError::read(b)?;
            (js(&v), Some(v.encode()), Some(v.encode()))
        }
        "PaEncTsEnc" => {
            let v = PaEncTsEnc::read(b)?;
            let e = PaEncTsEnc::encode(v.patimestamp, v.pausec);
            (js(&v), Some(e.clone()), Some(e))
        }
        "EtypeInfo2" => {
            let v = read_etype_info2(b)?;
            let e = enc_etype_info2(&v);
            (js(&v), Some(e.clone()), Some(e))
        }
        "EtypeInfo" => (js(&read_etype_info(b)?), None, None),
        "PaPacRequest" => {
            let v = read_pa_pac_request(b)?;
            let e = v.include_pac.map(enc_pa_pac_request);
            (js(&v), e.clone(), e)
        }
        "PaForUser" => {
            let v = PaForUser::read(b)?;
            (js(&v), Some(v.encode()), Some(v.encode()))
        }
        "PaPacOptions" => {
            let v = read_pa_pac_options(b)?;
            let e = enc_pa_pac_options(&v.flags).ok();
            (js(&v), e.clone(), e)
        }
        "EncKrbCredPart" => {
            let v = EncKrbCredPart::read(b)?;
            (js(&v), v.encode().ok(), v.encode().ok())
        }
        "KrbCred" => {
            let v = KrbCred::read(b)?;
            let mut s = v.clone();
            s.tickets.iter_mut().for_each(strip_ticket);
            (js(&v), Some(v.encode()), Some(s.encode()))
        }
        "KdcResponse" => (js(&read_kdc_response(b)?), None, None),
        "fast.Armor" => {
            let v = fast::Armor::read(&tlv(b)?)?;
            (js(&v), Some(v.encode()), Some(v.encode()))
        }
        "fast.FastRequest" => {
            let v = fast::FastRequest::read(b)?;
            (js(&v), Some(v.encode()), Some(v.encode()))
        }
        "fast.FastReq" => {
            let v = fast::FastReq::read(b)?;
            let mut s = v.clone();
            strip_body(&mut s.req_body);
            (js(&v), v.encode().ok(), s.encode().ok())
        }
        "fast.FastReply" => {
            let v = fast::read_fast_reply(b)?;
            let e = fast::enc_fast_reply(&v);
            (js(&v), Some(e.clone()), Some(e))
        }
        "fast.FastResponse" => {
            let v = fast::FastResponse::read(b)?;
            (js(&v), Some(v.encode()), Some(v.encode()))
        }
        "fast.FastFinished" => {
            let v = fast::FastFinished::read(&tlv(b)?)?;
            (js(&v), Some(v.encode()), Some(v.encode()))
        }
        "fast.OtpChallenge" => {
            let v = fast::OtpChallenge::read(b)?;
            (js(&v), v.encode().ok(), v.encode().ok())
        }
        "fast.TokenInfo" => {
            let v = fast::TokenInfo::read(&tlv(b)?)?;
            (js(&v), v.encode().ok(), v.encode().ok())
        }
        "fast.OtpRequest" => {
            let v = fast::OtpRequest::read(b)?;
            (js(&v), v.encode().ok(), v.encode().ok())
        }
        "fast.OtpEncData" => (js(&fast::read_otp_enc_data(b)?), None, None),
        "fast.VerifierMac" => {
            let v = fast::VerifierMac::read(&tlv(b)?)?;
            (js(&v), Some(v.encode()), Some(v.encode()))
        }
        "fast.Cammac" => {
            let v = fast::Cammac::read(b)?;
            (js(&v), Some(v.encode()), Some(v.encode()))
        }
        "fast.Indicators" => {
            let v = fast::read_indicators(b)?;
            let e = fast::enc_indicators(&v);
            (js(&v), Some(e.clone()), Some(e))
        }
        "pkinit.Krb5PrincipalName" => {
            let v = pkinit::Krb5PrincipalName::read(b)?;
            (js(&v), Some(v.encode()), Some(v.encode()))
        }
        "pkinit.PaPkAsReq" => {
            let v = pkinit::PaPkAsReq::read(b)?;
            (js(&v), Some(v.encode()), Some(v.encode()))
        }
        "pkinit.AuthPack" => {
            let v = pkinit::AuthPack::read(b)?;
            (js(&v), v.encode().ok(), v.encode().ok())
        }
        "pkinit.KdfAlgorithmId" => {
            let v = pkinit::read_kdf_algorithm_id(&tlv(b)?)?;
            let e = pkinit::enc_kdf_algorithm_id(&v).ok();
            (js(&v), e.clone(), e)
        }
        "pkinit.KdcDhKeyInfo" => {
            let v = pkinit::KdcDhKeyInfo::read(b)?;
            (js(&v), Some(v.encode()), Some(v.encode()))
        }
        "pkinit.PaPkAsRep" => {
            let v = pkinit::PaPkAsRep::read(b)?;
            (js(&v), v.encode().ok(), v.encode().ok())
        }
        "pkinit.TypedData" => {
            let v = pkinit::read_typed_data(b)?;
            let e = pkinit::enc_typed_data(&v);
            (js(&v), Some(e.clone()), Some(e))
        }
        other => panic!("no reader for kind {}", other),
    })
}

struct Checker {
    checked: usize,
    failures: Vec<String>,
}

impl Checker {
    fn check(&mut self, ok: bool, what: impl FnOnce() -> String) {
        self.checked += 1;
        if !ok {
            let w = what();
            if self.failures.len() < 60 {
                eprintln!("MISMATCH: {}", w);
            }
            self.failures.push(w);
        }
    }

    fn eq(&mut self, got: &Json, want: &Json, what: impl FnOnce() -> String) {
        let ok = got == want;
        self.check(ok, || {
            format!("{}\n   rust: {}\n   node: {}", what(), got, want)
        });
    }
}

fn err_json<T>(r: &Result<T, Krb5Error>) -> Json {
    match r {
        Ok(_) => Json::Null,
        Err(e) => json!(e.message()),
    }
}

fn vectors(name: &str) -> Option<Json> {
    let dir = std::env::var("STS_CRYPTO_VECTORS").ok()?;
    let path = std::path::Path::new(&dir).join(name);
    Some(serde_json::from_str(&std::fs::read_to_string(path).ok()?).unwrap())
}

#[test]
fn the_kerberos_codec_matches_node() {
    let Some(v) = vectors("krb5-codec-node.json") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set (or has no krb5-codec-node.json): \
             the Kerberos codec is not checked against Node"
        );
        return;
    };
    let mut c = Checker {
        checked: 0,
        failures: Vec::new(),
    };

    for p in v["primitives"].as_array().unwrap() {
        let b = unhex(&p["input"]);
        c.eq(&json!(prim::from_utf8(&b)), &p["fromUtf8"], || {
            format!("fromUtf8 {}", p["input"])
        });
        if p["text"].is_null() {
            continue;
        }
        let text = p["text"].as_str().unwrap();
        c.eq(&json!(hex(&prim::md4(&b))), &p["md4"], || "md4".into());
        c.eq(&json!(hex(&prim::md5(&b))), &p["md5"], || "md5".into());
        c.eq(&json!(hex(&prim::utf16le(text))), &p["utf16le"], || {
            "utf16le".into()
        });
        c.eq(
            &json!(hex(&prim::hmac_md5(b"key", &b))),
            &p["hmacShort"],
            || "hmac-md5".into(),
        );
        c.eq(
            &json!(hex(&prim::hmac_md5(&[7u8; 100], &b))),
            &p["hmacLong"],
            || "hmac-md5 long key".into(),
        );
        c.eq(
            &json!(hex(&prim::rc4(b"Secret", &b).unwrap())),
            &p["rc4"],
            || "rc4".into(),
        );
    }
    for n in v["nfold"].as_array().unwrap() {
        let r = prim::nfold(&unhex(&n["input"]), i(&n["bits"]) as usize);
        let out = r.as_ref().map(|o| json!(hex(o))).unwrap_or(Json::Null);
        c.eq(&out, &n["out"], || format!("nfold {}", n));
        c.eq(&err_json(&r), &n["error"], || format!("nfold error {}", n));
    }

    // ---- enctypes --------------------------------------------------------
    for p in v["profiles"].as_array().unwrap() {
        let e = Enctype::by_id(i(&p["id"])).unwrap();
        let got = json!({
            "id": e.id, "name": e.name, "keyBytes": e.key_bytes,
            "blockBytes": e.block_bytes,
            "confounderBytes": e.confounder_bytes,
            "checksumBytes": e.checksum_bytes,
            "checksumType": e.checksum_type,
            "defaultIterations": e.default_iterations, "rfc": e.rfc,
            "legacy": e.legacy
        });
        c.eq(&got, p, || format!("profile {}", e.id));
    }
    for n in v["etypeNames"].as_array().unwrap() {
        let id = i(&n["id"]);
        c.eq(&json!(crypto::etype_name(id)), &n["name"], || {
            format!("etype name {}", id)
        });
        c.eq(
            &json!(crypto::is_supported_etype(id)),
            &n["supported"],
            || format!("supported {}", id),
        );
        c.eq(&err_json(&Enctype::by_id(id)), &n["error"], || {
            format!("etype refusal {}", id)
        });
    }
    c.eq(
        &json!(crypto::DEFAULT_ETYPE_PREFERENCE),
        &v["preference"],
        || "preference".into(),
    );
    for s in v["stringToKey"].as_array().unwrap() {
        let e = Enctype::by_id(i(&s["etype"])).unwrap();
        let params = opt_bytes(&s["params"]);
        let r = e.string_to_key(
            s["password"].as_str().unwrap(),
            &unhex(&s["salt"]),
            params.as_deref(),
        );
        let key = r.as_ref().map(|k| json!(hex(k))).unwrap_or(Json::Null);
        c.eq(&key, &s["key"], || format!("string-to-key {}", s));
        c.eq(&err_json(&r), &s["error"], || format!("s2k error {}", s));
        if !s["expect"].is_null() {
            c.eq(&key, &s["expect"], || format!("published key {}", s));
        }
    }
    for d in v["derived"].as_array().unwrap() {
        let e = Enctype::by_id(i(&d["etype"])).unwrap();
        let (k, u) = (unhex(&d["key"]), i(&d["usage"]) as u32);
        let got = json!({
            "ke": hex(&e.encryption_key(&k, u).unwrap()),
            "ki": hex(&e.integrity_key(&k, u).unwrap()),
            "kc": hex(&e.checksum_key(&k, u).unwrap())
        });
        let want = json!({"ke": d["ke"], "ki": d["ki"], "kc": d["kc"]});
        c.eq(&got, &want, || format!("derived {} usage {}", e.id, u));
        if !d["expect"].is_null() {
            c.eq(&got, &d["expect"], || "RFC 8009 derived keys".into());
        }
    }
    for x in v["encryptions"].as_array().unwrap() {
        let e = Enctype::by_id(i(&x["etype"])).unwrap();
        let (k, u) = (unhex(&x["key"]), i(&x["usage"]) as u32);
        let (plain, conf) = (unhex(&x["plain"]), unhex(&x["confounder"]));
        let cipher = e.encrypt(&k, u, &plain, Some(&conf)).unwrap();
        c.eq(&json!(hex(&cipher)), &x["cipher"], || {
            format!("encrypt {} usage {} len {}", e.id, u, plain.len())
        });
        if !x["expect"].is_null() {
            c.eq(&json!(hex(&cipher)), &x["expect"], || {
                "RFC 8009 encryption".into()
            });
        }
        let (got_conf, got_plain) = e
            .decrypt_with_confounder(&k, u, &unhex(&x["cipher"]))
            .unwrap();
        c.check(got_conf == conf && got_plain == plain, || {
            format!("decrypt {} usage {}", e.id, u)
        });
    }
    for x in v["checksums"].as_array().unwrap() {
        let e = Enctype::by_id(i(&x["etype"])).unwrap();
        let (k, u) = (unhex(&x["key"]), i(&x["usage"]) as u32);
        let msg = unhex(&x["message"]);
        let sum = e.checksum(&k, u, &msg).unwrap();
        c.eq(&json!(hex(&sum)), &x["checksum"], || {
            format!("checksum {} usage {}", e.id, u)
        });
        if !x["expect"].is_null() {
            c.eq(&json!(hex(&sum)), &x["expect"], || {
                "RFC 8009 checksum".into()
            });
        }
        c.check(
            e.verify_checksum(&k, u, &msg, &unhex(&x["checksum"]))
                .unwrap(),
            || "verify checksum".into(),
        );
    }
    for x in v["decryptErrors"].as_array().unwrap() {
        let e = Enctype::by_id(i(&x["etype"])).unwrap();
        let r = e.decrypt(
            &unhex(&x["key"]),
            i(&x["usage"]) as u32,
            &unhex(&x["cipher"]),
        );
        c.eq(&err_json(&r), &x["error"], || {
            format!("decrypt refusal {}", x)
        });
        let plain = r.as_ref().map(|p| json!(hex(p))).unwrap_or(Json::Null);
        c.eq(&plain, &x["plain"], || format!("decrypt {}", x));
    }
    for x in v["cts"].as_array().unwrap() {
        let (k, plain) = (unhex(&x["key"]), unhex(&x["plain"]));
        let r = crypto::cts_encrypt(&k, &[0u8; 16], &plain);
        let got = r.as_ref().map(|o| json!(hex(o))).unwrap_or(Json::Null);
        c.eq(&got, &x["cipher"], || format!("cts {}", plain.len()));
        if !x["expect"].is_null() {
            c.eq(&got, &x["expect"], || "RFC 3962 CTS".into());
        }
        if let Ok(cipher) = r {
            c.check(
                crypto::cts_decrypt(&k, &[0u8; 16], &cipher).unwrap() == plain,
                || "cts decrypt".into(),
            );
        } else {
            c.eq(&err_json(&r), &x["error"], || "cts refusal".into());
        }
    }

    // ---- messages --------------------------------------------------------
    let mut kinds = std::collections::BTreeSet::new();
    for x in v["messages"].as_array().unwrap() {
        let kind = x["kind"].as_str().unwrap();
        kinds.insert(kind.to_string());
        let what = || format!("{} ({})", kind, x["note"]);
        match decode(kind, &unhex(&x["bytes"])) {
            Err(e) => c.eq(&json!(e.message()), &x["error"], what),
            Ok((decoded, re, rebuilt)) => {
                c.check(x["error"].is_null(), || {
                    format!("{}: Rust read what Node refused", what())
                });
                c.eq(&decoded, &x["decoded"], what);
                if x.get("reencoded").is_some() {
                    c.eq(&json!(re.map(|b| hex(&b))), &x["reencoded"], || {
                        format!("{} re-encoded", what())
                    });
                    c.eq(
                        &json!(rebuilt.map(|b| hex(&b))),
                        &x["rebuilt"],
                        || format!("{} rebuilt", what()),
                    );
                }
            }
        }
    }
    let pk = &v["pkinit"];
    let oi = &pk["otherInfo"];
    let other = pkinit::enc_other_info(&pkinit::OtherInfo {
        kdf: oi["kdf"].as_str().unwrap(),
        client: &unhex(&oi["client"]),
        server: &unhex(&oi["server"]),
        etype: i(&oi["etype"]),
        as_req: &unhex(&oi["asReq"]),
        pk_as_rep: &unhex(&oi["pkAsRep"]),
    })
    .unwrap();
    c.eq(&json!(hex(&other)), &oi["bytes"], || "OtherInfo".into());
    let mut epis = Vec::new();
    for e in pk["epis"].as_array().unwrap() {
        let epi = pkinit::ExternalPrincipalIdentifier {
            subject_name: opt_bytes(&e["subjectName"]),
            issuer_and_serial_number: opt_bytes(&e["issuerAndSerialNumber"]),
            subject_key_identifier: opt_bytes(&e["subjectKeyIdentifier"]),
        };
        c.eq(&json!(hex(&epi.encode())), &e["bytes"], || "EPI".into());
        epis.push(epi);
    }
    c.eq(
        &js(&pkinit::initial_verified_cas(&epis)),
        &pk["initialVerifiedCas"],
        || "AD-INITIAL-VERIFIED-CAS".into(),
    );
    for o in pk["oids"].as_array().unwrap() {
        let enc = pkinit::enc_oid(o["oid"].as_str().unwrap()).unwrap();
        c.eq(&json!(hex(&enc)), &o["bytes"], || {
            format!("pkinit oid {}", o)
        });
        let back = pkinit::dec_oid(Some(&tlv(&enc).unwrap())).unwrap();
        c.eq(&json!(back), &o["back"], || {
            format!("pkinit oid back {}", o)
        });
    }

    // ---- tree, identify, principals, tables ------------------------------
    for x in v["tree"].as_array().unwrap() {
        let r = asn1::tree(&unhex(&x["bytes"]), 0);
        let got = r.as_ref().map(js).unwrap_or(Json::Null);
        c.eq(&got, &x["tree"], || format!("tree {}", x["bytes"]));
        c.eq(&err_json(&r), &x["error"], || "tree error".into());
    }
    for x in v["identify"].as_array().unwrap() {
        c.eq(&js(&identify(&unhex(&x["bytes"]))), &x["id"], || {
            format!("identify {}", x["bytes"])
        });
    }
    for x in v["principals"].as_array().unwrap() {
        let r = parse_principal(
            x["text"].as_str().unwrap(),
            x["defaultType"].as_i64(),
        );
        let got = r.as_ref().map(js).unwrap_or(Json::Null);
        c.eq(&got, &x["parsed"], || {
            format!("parsePrincipal {}", x["text"])
        });
        c.eq(&err_json(&r), &x["error"], || "principal error".into());
        if let Ok(p) = r {
            let text = PrincipalName {
                r#type: p.r#type,
                name: p.name.clone(),
            }
            .to_text(p.realm.as_deref());
            c.eq(&json!(text), &x["text2"], || "principalToString".into());
        }
    }
    let bits: Vec<u32> = (0..33).collect();
    let f = &v["flags"];
    c.eq(&json!(kdc_option_names(&bits)), &f["kdc"], || {
        "kdc names".into()
    });
    c.eq(&json!(ticket_flag_names(&bits)), &f["ticket"], || {
        "ticket flag names".into()
    });
    c.eq(&json!(ap_option_names(&bits)), &f["ap"], || {
        "ap names".into()
    });
    c.eq(
        &json!(hex(&asn1::flags_from_bits(&[0, 7, 8, 31]))),
        &f["fromBits"],
        || "flagsFromBits".into(),
    );
    c.eq(
        &json!(asn1::bits_from_flags(&[0x80, 0x01, 0xff, 0x00])),
        &f["bits"],
        || "bitsFromFlags".into(),
    );
    for x in v["errors"].as_array().unwrap() {
        c.eq(&js(&describe_error(i(&x["code"]))), x, || {
            format!("describeError {}", x["code"])
        });
    }
    for x in v["integers"].as_array().unwrap() {
        c.eq(
            &json!(hex(&asn1::enc_integer(i(&x["value"])))),
            &x["der"],
            || format!("INTEGER {}", x["value"]),
        );
    }
    for x in v["times"].as_array().unwrap() {
        let t = KrbTime(x["secs"].as_f64().unwrap() as i64);
        c.eq(&json!(hex(&asn1::enc_kerberos_time(t))), &x["der"], || {
            format!("KerberosTime {}", x["iso"])
        });
        c.eq(
            &json!(t.iso()),
            &x["iso"]
                .as_str()
                .map(|s| json!(s.replace("Z", ".000Z")))
                .unwrap(),
            || "iso".into(),
        );
    }

    // ---- GSS -------------------------------------------------------------
    let g = &v["gss"];
    for x in g["checksums"].as_array().unwrap() {
        let o = GssChecksumOptions {
            flags: x["flags"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| i(f) as u32)
                .collect(),
            channel_bindings: opt_bytes(&x["channelBindings"]),
            delegation: opt_bytes(&x["delegation"]),
            extensions: opt_bytes(&x["extensions"]),
        };
        let r = gss::build_gss_checksum(&o);
        let got = r.as_ref().map(|b| json!(hex(b))).unwrap_or(Json::Null);
        c.eq(&got, &x["bytes"], || format!("0x8003 {}", x));
        c.eq(&err_json(&r), &x["error"], || "0x8003 refusal".into());
    }
    for x in g["parsed"].as_array().unwrap() {
        let r = gss::parse_gss_checksum(&unhex(&x["bytes"]));
        let got = r.as_ref().map(js).unwrap_or(Json::Null);
        c.eq(&got, &x["parsed"], || {
            format!("parse 0x8003 {}", x["bytes"])
        });
        c.eq(&err_json(&r), &x["error"], || "parse 0x8003 refusal".into());
    }
    for x in g["ict"].as_array().unwrap() {
        let b = unhex(&x["bytes"]);
        let r = gss::decode_initial_context_token(&b);
        let got = r.as_ref().map(js).unwrap_or(Json::Null);
        c.eq(&got, &x["decoded"], || format!("ICT {}", x["bytes"]));
        c.eq(&err_json(&r), &x["error"], || format!("ICT {}", x["bytes"]));
        if let Ok(t) = r {
            c.check(
                gss::encode_initial_context_token(t.tok_id, &t.inner) == b,
                || "ICT re-encoded".into(),
            );
        }
    }
    for x in g["mics"].as_array().unwrap() {
        let (k, msg) = (unhex(&x["key"]), unhex(&x["message"]));
        let o = TokenOptions {
            key: &k,
            etype: i(&x["etype"]),
            role: role(&x["role"]),
            acceptor_subkey: x["acceptorSubkey"].as_bool().unwrap(),
            message: &msg,
            sequence_number: x["sequenceNumber"].as_u64().unwrap(),
        };
        c.eq(&json!(hex(&gss::get_mic(&o).unwrap())), &x["token"], || {
            format!("MIC {} {}", x["etype"], x["role"])
        });
        let verdict =
            gss::verify_mic(&k, o.etype, &unhex(&x["token"]), &msg).unwrap();
        c.eq(&js(&verdict), &x["verdict"], || "verifyMic".into());
        let bad =
            gss::verify_mic(&k, o.etype, &unhex(&x["tampered"]), &msg).unwrap();
        c.eq(&js(&bad), &x["tamperedVerdict"], || {
            "verifyMic tampered".into()
        });
    }
    for x in g["wraps"].as_array().unwrap() {
        let (k, msg) = (unhex(&x["key"]), unhex(&x["message"]));
        let etype = i(&x["etype"]);
        let token = unhex(&x["token"]);
        let u = match gss::unwrap(&k, etype, &token) {
            Ok(u) => u,
            Err(e) => {
                c.check(false, || format!("unwrap refused: {}", e));
                continue;
            }
        };
        c.eq(&js(&u), &x["unwrapped"], || {
            format!("unwrap {} {}", etype, x["role"])
        });
        let o = TokenOptions {
            key: &k,
            etype,
            role: role(&x["role"]),
            acceptor_subkey: x["acceptorSubkey"].as_bool().unwrap(),
            message: &msg,
            sequence_number: x["sequenceNumber"].as_u64().unwrap(),
        };
        let again = gss::wrap(
            &o,
            i(&x["extraCount"]) as u16,
            i(&x["rrc"]) as u16,
            Some(&u.confounder),
        )
        .unwrap();
        c.check(again == token, || {
            format!(
                "wrap rebuilt {} ec {} rrc {}",
                etype, x["extraCount"], x["rrc"]
            )
        });
    }
    for x in g["errors"].as_array().unwrap() {
        let (k, t) = (unhex(&x["key"]), unhex(&x["token"]));
        let e = if x["mic"].as_bool() == Some(true) {
            err_json(&gss::verify_mic(&k, i(&x["etype"]), &t, b"x"))
        } else {
            err_json(&gss::unwrap(&k, i(&x["etype"]), &t))
        };
        c.eq(&e, &x["error"], || format!("GSS refusal {}", x["token"]));
    }
    for x in g["rotations"].as_array().unwrap() {
        let b = unhex(&x["bytes"]);
        let n = i(&x["count"]) as usize;
        c.eq(&json!(hex(&gss::rotate_right(&b, n))), &x["right"], || {
            "rotateRight".into()
        });
        c.eq(&json!(hex(&gss::rotate_left(&b, n))), &x["left"], || {
            "rotateLeft".into()
        });
    }

    // ---- SPNEGO ----------------------------------------------------------
    let s = &v["spnego"];
    for x in s["inits"].as_array().unwrap() {
        let mechs: Option<Vec<String>> = x["mechTypes"].as_array().map(|a| {
            a.iter().map(|o| o.as_str().unwrap().to_string()).collect()
        });
        let (tok, mic) =
            (opt_bytes(&x["mechToken"]), opt_bytes(&x["mechListMic"]));
        let r = spnego::encode_neg_token_init(
            mechs.as_deref(),
            tok.as_deref(),
            mic.as_deref(),
        );
        let got = r
            .as_ref()
            .map(|e| json!([hex(&e.token), hex(&e.mech_list_der)]))
            .unwrap_or(Json::Null);
        let want = if x["token"].is_null() {
            Json::Null
        } else {
            json!([x["token"], x["mechListDer"]])
        };
        c.eq(&got, &want, || format!("NegTokenInit {}", x["mechTypes"]));
        c.eq(&err_json(&r), &x["error"], || "NegTokenInit refusal".into());
    }
    for x in s["resps"].as_array().unwrap() {
        let (tok, mic) =
            (opt_bytes(&x["responseToken"]), opt_bytes(&x["mechListMic"]));
        let t = spnego::encode_neg_token_resp(
            x["negState"].as_i64(),
            x["supportedMech"].as_str(),
            tok.as_deref(),
            mic.as_deref(),
        )
        .unwrap();
        c.eq(&json!(hex(&t)), &x["token"], || {
            format!("NegTokenResp {}", x)
        });
    }
    for x in s["decoded"].as_array().unwrap() {
        let r = spnego::decode_negotiation_token(&unhex(&x["bytes"]));
        let got = r.as_ref().map(js).unwrap_or(Json::Null);
        c.eq(&got, &x["decoded"], || format!("SPNEGO {}", x["bytes"]));
        c.eq(&err_json(&r), &x["error"], || {
            format!("SPNEGO {}", x["bytes"])
        });
    }
    for x in s["oids"].as_array().unwrap() {
        if let Some(oid) = x["oid"].as_str() {
            let r = spnego::encode_oid_content(oid);
            let got = r.as_ref().map(|b| json!(hex(b))).unwrap_or(Json::Null);
            c.eq(&got, &x["content"], || format!("OID {}", oid));
            c.eq(&err_json(&r), &x["error"], || format!("OID {}", oid));
            if let Ok(b) = r {
                c.eq(
                    &json!(spnego::decode_oid_content(&b).unwrap()),
                    &x["back"],
                    || format!("OID back {}", oid),
                );
            }
        } else {
            let r = spnego::decode_oid_content(&unhex(&x["content"]));
            c.eq(&json!(r.as_ref().ok()), &x["back"], || "OID decode".into());
            c.eq(&err_json(&r), &x["error"], || "OID decode refusal".into());
        }
    }
    for x in s["mics"].as_array().unwrap() {
        let (k, der) = (unhex(&x["key"]), unhex(&x["mechListDer"]));
        let mic = spnego::compute_mech_list_mic(
            &k,
            i(&x["etype"]),
            role(&x["role"]),
            x["acceptorSubkey"].as_bool().unwrap(),
            &der,
            x["sequenceNumber"].as_u64().unwrap(),
        )
        .unwrap();
        c.eq(&json!(hex(&mic)), &x["mic"], || "mechListMIC".into());
        let verdict =
            spnego::verify_mech_list_mic(&k, i(&x["etype"]), &mic, &der)
                .unwrap();
        c.eq(&js(&verdict), &x["verdict"], || {
            "mechListMIC verdict".into()
        });
    }
    for x in s["requirements"].as_array().unwrap() {
        let list: Vec<String> = x["mechTypes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o.as_str().unwrap().to_string())
            .collect();
        c.eq(
            &js(&spnego::mic_requirement(&list, x["selected"].as_str())),
            &x["requirement"],
            || format!("micRequirement {}", x),
        );
    }
    for x in s["negStates"].as_array().unwrap() {
        c.eq(
            &js(&spnego::neg_state_info(i(&x["value"]))),
            &x["info"],
            || "negStateInfo".into(),
        );
    }
    c.eq(&js(&spnego::MECHS), &s["mechs"], || "MECHS".into());

    // ---- MS-KKDCP --------------------------------------------------------
    for x in v["kkdcp"]["bodies"].as_array().unwrap() {
        let body = unhex(&x["body"]);
        let got = match kkdcp::unwrap_proxy_message(&body) {
            Ok(msg) => json!({"message": hex(&msg)}),
            Err(r) => json!({"refusal": r.code().as_str(), "body": r.body()}),
        };
        c.eq(&got, &x["read"], || format!("/KdcProxy {}", x["body"]));
        if x["messageOf"] != json!("unavailable") {
            c.eq(
                &json!(kkdcp::message_of(&body).map(|m| hex(&m))),
                &x["messageOf"],
                || "messageOf".into(),
            );
        }
    }
    for x in v["kkdcp"]["replies"].as_array().unwrap() {
        c.eq(
            &json!(hex(&kkdcp::wrap_proxy_message(&unhex(&x["reply"])))),
            &x["envelope"],
            || "KdcProxy reply".into(),
        );
    }

    // ---- the keytab file format -------------------------------------
    for x in v["keytab"]["written"].as_array().unwrap() {
        let entries: Vec<KeytabEntry> = x["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| KeytabEntry {
                realm: e["realm"].as_str().unwrap().into(),
                components: e["components"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|c| c.as_str().unwrap().to_string())
                    .collect(),
                name_type: e["nameType"].as_u64().map(|n| n as u32),
                timestamp: Some(i(&e["timestamp"])),
                kvno: i(&e["kvno"]) as u32,
                etype: i(&e["etype"]),
                key: unhex(&e["key"]),
            })
            .collect();
        let r = keytab::write_keytab(&entries);
        let got = r.as_ref().map(|b| json!(hex(b))).unwrap_or(Json::Null);
        c.eq(&got, &x["bytes"], || "writeKeytab".into());
        c.eq(&err_json(&r), &x["error"], || "writeKeytab refusal".into());
    }
    for x in v["keytab"]["read"].as_array().unwrap() {
        let r = keytab::read_keytab(&unhex(&x["bytes"]));
        let got = r.as_ref().map(js).unwrap_or(Json::Null);
        c.eq(&got, &x["entries"], || format!("readKeytab {}", x["bytes"]));
        c.eq(&err_json(&r), &x["error"], || "readKeytab refusal".into());
    }

    eprintln!(
        "krb5-codec-node.json: {} checks over {} message kinds, {} failed",
        c.checked,
        kinds.len(),
        c.failures.len()
    );
    assert!(c.failures.is_empty(), "{} mismatches", c.failures.len());
}

// ---------------------------------------------------------------------------
// The other direction: what Rust makes, for Node to read.
// ---------------------------------------------------------------------------

fn t(secs: i64) -> KrbTime {
    KrbTime(secs)
}

fn pname(t: i64, n: &[&str]) -> PrincipalName {
    PrincipalName::new(t, n)
}

fn row(kind: &str, bytes: Vec<u8>) -> Json {
    let (decoded, _, _) = decode(kind, &bytes).unwrap();
    json!({"kind": kind, "bytes": hex(&bytes), "decoded": decoded})
}

fn rust_messages() -> Vec<Json> {
    let realm = "RUST.EXAMPLE";
    let carol = pname(1, &["carol"]);
    let tgs = pname(2, &["krbtgt", realm]);
    let svc = pname(3, &["host", "rust.example"]);
    let enc = EncryptedData::new(20, Some(9), vec![0xde, 0xad, 0xbe, 0xef]);
    let key = EncryptionKey::new(19, vec![0x11; 16]);
    let ticket = Ticket {
        tkt_vno: 5,
        realm: realm.into(),
        sname: tgs.clone(),
        enc_part: enc.clone(),
        raw: None,
    };
    let t0 = t(1_800_000_000);
    let t1 = t(1_800_036_000);
    let body = KdcReqBody {
        kdc_options: vec![1, 8, 15],
        cname: Some(carol.clone()),
        realm: realm.into(),
        sname: Some(tgs.clone()),
        from: None,
        till: t1,
        rtime: Some(t(1_800_600_000)),
        nonce: 424_242,
        etypes: vec![20, 19, 18, 17],
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
        raw: None,
    };
    let mut out = Vec::new();
    out.push(row("Ticket", ticket.encode()));
    let ts = PaEncTsEnc::encode(t0, Some(5));
    out.push(row("PaEncTsEnc", ts.clone()));
    let req = KdcReq {
        pvno: 5,
        msg_type: msg_type::AS_REQ,
        padata: vec![
            PaData::new(2, EncryptedData::new(20, None, ts).encode()),
            PaData::new(128, enc_pa_pac_request(false)),
        ],
        req_body: body.clone(),
    };
    out.push(row("KdcReq", req.encode().unwrap()));
    let tgs_req = KdcReq {
        pvno: 5,
        msg_type: msg_type::TGS_REQ,
        padata: vec![],
        req_body: KdcReqBody {
            cname: None,
            sname: Some(svc.clone()),
            additional_tickets: Some(vec![ticket.clone()]),
            enc_authorization_data: Some(enc.clone()),
            addresses: Some(vec![HostAddress {
                r#type: 2,
                address: vec![10, 1, 2, 3],
            }]),
            ..body.clone()
        },
    };
    out.push(row("KdcReq", tgs_req.encode().unwrap()));
    let rep = KdcRep {
        pvno: 5,
        msg_type: msg_type::AS_REP,
        padata: vec![PaData::new(
            19,
            enc_etype_info2(&[EtypeInfo2Entry {
                etype: 20,
                etype_name: crypto::etype_name(20),
                salt: Some(format!("{}carol", realm)),
                s2kparams: Some(vec![0, 0, 0x80, 0]),
            }]),
        )],
        crealm: realm.into(),
        cname: carol.clone(),
        ticket: ticket.clone(),
        enc_part: enc.clone(),
    };
    out.push(row("KdcRep", rep.encode()));
    let part = EncKdcRepPart {
        tagged_as: "EncTGSRepPart".into(),
        key: key.clone(),
        last_req: vec![LastReq {
            r#type: 0,
            value: t0,
        }],
        nonce: 424_242,
        key_expiration: None,
        flags: vec![1, 9, 10, 15],
        authtime: t0,
        starttime: Some(t0),
        endtime: t1,
        renew_till: None,
        srealm: realm.into(),
        sname: svc.clone(),
        caddr: None,
        encrypted_pa_data: Some(vec![PaData::new(149, vec![1])]),
    };
    out.push(row("EncKdcRepPart", part.encode(Some(26)).unwrap()));
    let etp = EncTicketPart {
        flags: vec![1, 9, 10],
        key: key.clone(),
        crealm: realm.into(),
        cname: carol.clone(),
        transited: None,
        authtime: t0,
        starttime: None,
        endtime: t1,
        renew_till: Some(t(1_800_600_000)),
        caddr: None,
        authorization_data: Some(vec![AuthorizationEntry {
            r#type: 1,
            data: vec![0x30, 0],
        }]),
    };
    out.push(row("EncTicketPart", etp.encode().unwrap()));
    let auth = Authenticator {
        vno: 5,
        crealm: realm.into(),
        cname: carol.clone(),
        cksum: Some(Checksum {
            r#type: gss::CHECKSUM_TYPE_GSS,
            checksum: gss::build_gss_checksum(&GssChecksumOptions {
                flags: vec![2, 8],
                ..GssChecksumOptions::default()
            })
            .unwrap(),
        }),
        cusec: 12,
        ctime: t0,
        subkey: Some(key.clone()),
        seq_number: Some(7),
        authorization_data: None,
    };
    out.push(row("Authenticator", auth.encode()));
    let ap = ApReq {
        pvno: 5,
        msg_type: msg_type::AP_REQ,
        ap_options: vec![2],
        ticket: ticket.clone(),
        authenticator: enc.clone(),
    };
    out.push(row("ApReq", ap.encode().unwrap()));
    out.push(row(
        "ApRep",
        ApRep {
            pvno: 5,
            msg_type: msg_type::AP_REP,
            enc_part: enc.clone(),
        }
        .encode(),
    ));
    out.push(row(
        "EncApRepPart",
        EncApRepPart {
            ctime: t0,
            cusec: 3,
            subkey: None,
            seq_number: Some(0),
        }
        .encode(),
    ));
    let mut err = KrbError::new(25, t0, realm, tgs.clone());
    err.e_text = Some("pre-authentication required".into());
    err.cname = Some(carol.clone());
    err.crealm = Some(realm.into());
    err.e_data = Some(enc_padata_list(&[PaData::new(
        19,
        enc_etype_info2(&[EtypeInfo2Entry {
            etype: 18,
            etype_name: crypto::etype_name(18),
            salt: None,
            s2kparams: None,
        }]),
    )]));
    out.push(row("KrbError", err.encode()));
    out.push(row(
        "KrbError",
        KrbError::new(6, t1, realm, tgs.clone()).encode(),
    ));
    out.push(row(
        "PaForUser",
        PaForUser {
            user_name: pname(10, &["dave@rust.example"]),
            user_realm: realm.into(),
            cksum: Checksum {
                r#type: -138,
                checksum: vec![0; 16],
            },
            auth_package: String::new(),
        }
        .encode(),
    ));
    out.push(row("PaPacOptions", enc_pa_pac_options(&[0, 3]).unwrap()));
    let cred = EncKrbCredPart {
        ticket_info: vec![KrbCredInfo {
            key: key.clone(),
            prealm: Some(realm.into()),
            pname: Some(carol.clone()),
            flags: Some(vec![1, 2]),
            authtime: Some(t0),
            starttime: None,
            endtime: Some(t1),
            renew_till: None,
            srealm: Some(realm.into()),
            sname: Some(tgs.clone()),
            caddr: None,
        }],
        nonce: Some(1),
        timestamp: Some(t0),
        usec: Some(0),
        s_address: None,
        r_address: None,
    };
    out.push(row("EncKrbCredPart", cred.encode().unwrap()));
    out.push(row(
        "KrbCred",
        KrbCred {
            pvno: 5,
            msg_type: msg_type::CRED,
            tickets: vec![ticket.clone()],
            enc_part: enc.clone(),
        }
        .encode(),
    ));
    // FAST.
    let fast_req = fast::FastReq {
        fast_options: vec![1],
        padata: vec![PaData::new(fast::pa::FX_COOKIE, b"rust".to_vec())],
        req_body: body.clone(),
    };
    out.push(row("fast.FastReq", fast_req.encode().unwrap()));
    out.push(row(
        "fast.FastRequest",
        fast::FastRequest {
            armor: Some(fast::Armor {
                r#type: fast::ARMOR_AP_REQUEST,
                value: ap.encode().unwrap(),
            }),
            req_checksum: Checksum {
                r#type: 19,
                checksum: vec![9; 16],
            },
            enc_fast_req: enc.clone(),
        }
        .encode(),
    ));
    out.push(row("fast.FastReply", fast::enc_fast_reply(&enc)));
    out.push(row(
        "fast.FastResponse",
        fast::FastResponse {
            padata: vec![],
            strengthen_key: Some(key.clone()),
            finished: Some(fast::FastFinished {
                timestamp: t0,
                usec: 1,
                crealm: realm.into(),
                cname: carol.clone(),
                ticket_checksum: Checksum {
                    r#type: 19,
                    checksum: vec![1; 16],
                },
            }),
            nonce: 5,
        }
        .encode(),
    ));
    let info = fast::TokenInfo {
        flags: vec![2, 4],
        vendor: Some("Rust".into()),
        challenge: None,
        length: Some(8),
        format: Some(fast::otp_format::DECIMAL),
        token_id: Some(b"r1".to_vec()),
        alg_id: None,
        hashing: false,
    };
    out.push(row(
        "fast.OtpChallenge",
        fast::OtpChallenge {
            nonce: vec![1, 2, 3, 4],
            service: Some("Rust OTP".into()),
            token_info: vec![info],
            salt: None,
            s2kparams: None,
        }
        .encode()
        .unwrap(),
    ));
    out.push(row(
        "fast.OtpRequest",
        fast::OtpRequest {
            flags: vec![],
            nonce: Some(vec![1, 2, 3, 4]),
            enc_data: enc.clone(),
            hashing: false,
            value: Some("987654".into()),
            pin: None,
            time: Some(t0),
            vendor: None,
        }
        .encode()
        .unwrap(),
    ));
    let vmac = fast::VerifierMac {
        identifier: Some(tgs.clone()),
        kvno: Some(1),
        enctype: Some(20),
        mac: Checksum {
            r#type: 20,
            checksum: vec![2; 24],
        },
    };
    out.push(row(
        "fast.Cammac",
        fast::Cammac {
            elements_bytes: enc_authorization_data(&[AuthorizationEntry {
                r#type: fast::ad::AUTHENTICATION_INDICATOR,
                data: fast::enc_indicators(&["otp".into()]),
            }]),
            elements: vec![],
            kdc_verifier: Some(vmac.clone()),
            svc_verifier: None,
        }
        .encode(),
    ));
    out.push(row(
        "fast.Indicators",
        fast::enc_indicators(&["pkinit".into(), "otp".into()]),
    ));
    // PKINIT.
    out.push(row(
        "pkinit.Krb5PrincipalName",
        pkinit::Krb5PrincipalName {
            realm: realm.into(),
            name: carol.clone(),
        }
        .encode(),
    ));
    out.push(row(
        "pkinit.PaPkAsReq",
        pkinit::PaPkAsReq {
            signed_auth_pack: vec![0x30, 0],
            trusted_certifiers: None,
            kdc_pk_id: Some(vec![4, 0]),
        }
        .encode(),
    ));
    out.push(row(
        "pkinit.AuthPack",
        pkinit::AuthPack {
            cusec: 1,
            ctime: t0,
            nonce: 77,
            pa_checksum: Some(vec![0; 32]),
            freshness_token: None,
            client_public_value: Some(vec![0x30, 0]),
            supported_cms_types: 0,
            client_dh_nonce: None,
            supported_kdfs: Some(vec!["1.3.6.1.5.2.3.6.2".into()]),
        }
        .encode()
        .unwrap(),
    ));
    out.push(row(
        "pkinit.PaPkAsRep",
        pkinit::PaPkAsRep {
            dh_signed_data: vec![0x30, 0],
            kdf: Some("1.3.6.1.5.2.3.6.3".into()),
        }
        .encode()
        .unwrap(),
    ));
    out.push(row(
        "pkinit.KdcDhKeyInfo",
        pkinit::KdcDhKeyInfo {
            subject_public_key: vec![2, 1, 5],
            nonce: 3,
        }
        .encode(),
    ));
    out
}

#[test]
fn write_the_rust_vectors_when_asked() {
    if std::env::var("STS_WRITE_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        return;
    };
    let ids = [17i64, 18, 19, 20, 23];
    let mut encryptions = Vec::new();
    let mut checksums = Vec::new();
    let mut keys = Vec::new();
    for id in ids {
        let e = Enctype::by_id(id).unwrap();
        for (pw, salt) in [
            ("rust password", "RUST.EXAMPLEcarol"),
            ("pässwörd", "RUST.EXAMPLEdave"),
        ] {
            for params in [None, Some(vec![0, 0, 0, 3])] {
                let key = e
                    .string_to_key(pw, salt.as_bytes(), params.as_deref())
                    .unwrap();
                keys.push(json!({"etype": id, "password": pw,
                    "salt": hex(salt.as_bytes()),
                    "params": params.as_ref().map(|p| hex(p)),
                    "key": hex(&key)}));
            }
        }
        let key = crypto::random_bytes(e.key_bytes).unwrap();
        for usage in [1u32, 3, 7, 11, 12, 22, 25] {
            for len in [0usize, 5, 16, 33, 64] {
                let plain: Vec<u8> = (0..len).map(|i| i as u8 ^ 0x5a).collect();
                encryptions.push(json!({"etype": id, "key": hex(&key),
                    "usage": usage, "plain": hex(&plain),
                    "cipher": hex(&e.encrypt(&key, usage, &plain, None)
                        .unwrap())}));
                checksums.push(json!({"etype": id, "key": hex(&key),
                    "usage": usage, "message": hex(&plain),
                    "checksum": hex(&e.checksum(&key, usage, &plain)
                        .unwrap())}));
            }
        }
    }
    let mut tokens = Vec::new();
    for id in ids {
        let key = crypto::random_bytes(Enctype::by_id(id).unwrap().key_bytes)
            .unwrap();
        for r in [Role::Initiator, Role::Acceptor] {
            let msg = b"a message Rust protected";
            let o = TokenOptions {
                key: &key,
                etype: id,
                role: r,
                acceptor_subkey: r == Role::Acceptor,
                message: msg,
                sequence_number: 4_000_000_001,
            };
            tokens.push(json!({"etype": id, "key": hex(&key),
                "message": hex(msg),
                "mic": hex(&gss::get_mic(&o).unwrap()),
                "wrap": hex(&gss::wrap(&o, 4, 28, None).unwrap())}));
        }
    }
    let init = spnego::encode_neg_token_init(
        Some(&[
            spnego::MS_KRB5_MECH_OID.to_string(),
            spnego::KRB5_MECH_OID.to_string(),
        ]),
        Some(&[0x60, 0x00]),
        None,
    )
    .unwrap();
    let resp = spnego::encode_neg_token_resp(
        Some(spnego::NEG_STATE_ACCEPT_COMPLETED),
        Some(spnego::KRB5_MECH_OID),
        Some(&[0x6f, 0x00]),
        None,
    )
    .unwrap();
    let spnego_tokens: Vec<Json> = [init.token.clone(), resp]
        .iter()
        .map(|b| {
            json!({"bytes": hex(b),
                   "decoded": js(&spnego::decode_negotiation_token(b)
                       .unwrap())})
        })
        .collect();
    let gss_checksum = gss::build_gss_checksum(&GssChecksumOptions {
        flags: vec![1, 2, 32],
        channel_bindings: Some(vec![0xab; 16]),
        delegation: Some(vec![0x76, 0x00]),
        extensions: None,
    })
    .unwrap();
    let asreq = rust_messages()[2]["bytes"].as_str().unwrap().to_string();
    let reply = prim::from_hex(&asreq).unwrap();
    let out = json!({
        "stringToKey": keys,
        "encryptions": encryptions,
        "checksums": checksums,
        "messages": rust_messages(),
        "tokens": tokens,
        "spnego": spnego_tokens,
        "gssChecksum": {"bytes": hex(&gss_checksum),
            "parsed": js(&gss::parse_gss_checksum(&gss_checksum).unwrap())},
        "kkdcp": {"message": asreq,
            "envelope": hex(&kkdcp::wrap_proxy_message(&reply)),
            "client": hex(&kkdcp::client_proxy_message(&reply,
                Some("RUST.EXAMPLE")))}
    });
    let tab = keytab::write_keytab(&[
        KeytabEntry {
            realm: "RUST.EXAMPLE".into(),
            components: vec!["HTTP".into(), "rust.example".into()],
            name_type: None,
            timestamp: Some(1_800_000_000),
            kvno: 70_000,
            etype: 20,
            key: crypto::random_bytes(32).unwrap(),
        },
        KeytabEntry {
            realm: "RUST.EXAMPLE".into(),
            components: vec!["carol".into()],
            name_type: Some(1),
            timestamp: Some(1),
            kvno: 2,
            etype: 23,
            key: crypto::random_bytes(16).unwrap(),
        },
    ])
    .unwrap();
    let mut out = out;
    out["keytab"] = json!({"bytes": hex(&tab),
        "entries": js(&keytab::read_keytab(&tab).unwrap())});
    let path = std::path::Path::new(&dir).join("krb5-codec-rust.json");
    std::fs::write(&path, serde_json::to_string_pretty(&out).unwrap()).unwrap();
    eprintln!("wrote {}", path.display());
}
