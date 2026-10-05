// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! XML Encryption: `common/crypto.js` section 2, `encryptElement()` and
//! `decryptElement()`, on `sts-xml`.
//!
//! **IT IS SECTION 2 THAT IS PORTED, NOT THE VENDORED encryptXml()**, for
//! the reason that section gives: its output is the vendored one's, and
//! what it has besides is the DIAGNOSIS — an unknown cipher and an unknown
//! key transport named apart, the unwrapped key's length checked (RSA-1_5
//! unwraps a wrong key to plausible garbage), the plaintext parsed before
//! CBC is called a success, every AES-CBC failure one refusal (the padding
//! oracle, #202). Every refusal here has Node's code and Node's words.
//!
//! * Content: AES-GCM (128, 192, 256; IV 12, tag 16) and AES-CBC (IV 16,
//!   XML Encryption's padding — the last octet counts it, the rest is
//!   arbitrary, so NOT PKCS#7 on the way in).
//! * Key transport: `rsa-oaep` (a named digest, MGF1 the same), `rsa-oaep-
//!   mgf1p` (SHA-1), `rsa-1_5` (development only — section 6.1.2).
//! * Key agreement: ECDH-ES over P-256/384/521 with ConcatKDF and an AES
//!   key wrap, or the agreed key as the content key.
//!
//! It ANSWERS RATHER THAN FAILS: [`decrypt_element`] returns a
//! [`Decrypted`] whose `code` names the refusal.

use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::encrypt::{Decrypter, Encrypter};
use openssl::hash::{hash, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, PKeyRef, Private, Public};
use openssl::rand::rand_bytes;
use openssl::rsa::Padding;
use openssl::symm::{
    decrypt_aead, encrypt_aead, Cipher as SymmCipher, Crypter, Mode,
};
use openssl::x509::X509;
use sts_core::errors::{codes, ErrorCode};
use sts_xml::dom::{Document, NodeId};

use crate::error::{CryptoError, CryptoResult};
use crate::jwe::{aes_key_unwrap, aes_key_wrap};

const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XENC_NS: &str = "http://www.w3.org/2001/04/xmlenc#";
const XENC11_NS: &str = "http://www.w3.org/2009/xmlenc11#";
const DSIG11_NS: &str = "http://www.w3.org/2009/xmldsig11#";
const NS_SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const NS_SAMLP: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

/// One block cipher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockCipher {
    pub name: &'static str,
    pub uri: &'static str,
    pub key_bytes: usize,
    pub gcm: bool,
}

impl BlockCipher {
    fn iv_bytes(self) -> usize {
        if self.gcm {
            12
        } else {
            16
        }
    }

    fn tag_bytes(self) -> usize {
        if self.gcm {
            16
        } else {
            0
        }
    }

    fn symm(self) -> SymmCipher {
        match (self.gcm, self.key_bytes) {
            (true, 16) => SymmCipher::aes_128_gcm(),
            (true, 24) => SymmCipher::aes_192_gcm(),
            (true, _) => SymmCipher::aes_256_gcm(),
            (false, 16) => SymmCipher::aes_128_cbc(),
            (false, 24) => SymmCipher::aes_192_cbc(),
            (false, _) => SymmCipher::aes_256_cbc(),
        }
    }
}

/// Every block cipher, in `BLOCK_CIPHERS`' order.
pub const BLOCK_CIPHERS: [BlockCipher; 6] = [
    BlockCipher {
        name: "aes256-gcm",
        uri: "http://www.w3.org/2009/xmlenc11#aes256-gcm",
        key_bytes: 32,
        gcm: true,
    },
    BlockCipher {
        name: "aes128-gcm",
        uri: "http://www.w3.org/2009/xmlenc11#aes128-gcm",
        key_bytes: 16,
        gcm: true,
    },
    BlockCipher {
        name: "aes256-cbc",
        uri: "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
        key_bytes: 32,
        gcm: false,
    },
    BlockCipher {
        name: "aes128-cbc",
        uri: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
        key_bytes: 16,
        gcm: false,
    },
    BlockCipher {
        name: "aes192-gcm",
        uri: "http://www.w3.org/2009/xmlenc11#aes192-gcm",
        key_bytes: 24,
        gcm: true,
    },
    BlockCipher {
        name: "aes192-cbc",
        uri: "http://www.w3.org/2001/04/xmlenc#aes192-cbc",
        key_bytes: 24,
        gcm: false,
    },
];

/// The three key transports, in `KEY_TRANSPORTS`' order: `(name, uri)`.
pub const KEY_TRANSPORTS: [(&str, &str); 3] = [
    ("rsa-oaep", "http://www.w3.org/2009/xmlenc11#rsa-oaep"),
    (
        "rsa-oaep-mgf1p",
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
    ),
    ("rsa-1_5", "http://www.w3.org/2001/04/xmlenc#rsa-1_5"),
];

/// The AES key wraps an agreed key wraps the content key with.
pub const KEY_WRAPS: [(&str, &str, usize); 3] = [
    (
        "kw-aes128",
        "http://www.w3.org/2001/04/xmlenc#kw-aes128",
        16,
    ),
    (
        "kw-aes192",
        "http://www.w3.org/2001/04/xmlenc#kw-aes192",
        24,
    ),
    (
        "kw-aes256",
        "http://www.w3.org/2001/04/xmlenc#kw-aes256",
        32,
    ),
];

/// The digests an `rsa-oaep` (and a ConcatKDF) may name.
const OAEP_DIGESTS: [(&str, &str); 4] = [
    ("sha1", "http://www.w3.org/2000/09/xmldsig#sha1"),
    ("sha256", "http://www.w3.org/2001/04/xmlenc#sha256"),
    ("sha384", "http://www.w3.org/2001/04/xmldsig-more#sha384"),
    ("sha512", "http://www.w3.org/2001/04/xmlenc#sha512"),
];

const MGF1_URIS: [(&str, &str); 4] = [
    ("sha1", "http://www.w3.org/2009/xmlenc11#mgf1sha1"),
    ("sha256", "http://www.w3.org/2009/xmlenc11#mgf1sha256"),
    ("sha384", "http://www.w3.org/2009/xmlenc11#mgf1sha384"),
    ("sha512", "http://www.w3.org/2009/xmlenc11#mgf1sha512"),
];

const ECDH_ES_URI: &str = "http://www.w3.org/2009/xmlenc11#ECDH-ES";
const CONCAT_KDF_URI: &str = "http://www.w3.org/2009/xmlenc11#ConcatKDF";

/// The curves an ECKeyValue may name: `(oid URI, crv, coordinate octets,
/// nid)`.
const XML_EC_CURVES: [(&str, &str, usize, Nid); 3] = [
    (
        "urn:oid:1.2.840.10045.3.1.7",
        "P-256",
        32,
        Nid::X9_62_PRIME256V1,
    ),
    ("urn:oid:1.3.132.0.34", "P-384", 48, Nid::SECP384R1),
    ("urn:oid:1.3.132.0.35", "P-521", 66, Nid::SECP521R1),
];

const CURVE_LIST: &str = "P-256, P-384, P-521";

fn name_of(table: &[(&'static str, &str)], uri: &str) -> &'static str {
    table
        .iter()
        .find(|(_, u)| *u == uri)
        .map(|(n, _)| *n)
        .unwrap_or("")
}

fn uri_of(table: &[(&str, &'static str)], name: &str) -> &'static str {
    table
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, u)| *u)
        .unwrap_or("")
}

fn md_of(name: &str) -> MessageDigest {
    match name {
        "sha256" => MessageDigest::sha256(),
        "sha384" => MessageDigest::sha384(),
        "sha512" => MessageDigest::sha512(),
        _ => MessageDigest::sha1(),
    }
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Node's `Buffer.from(text, 'base64')`: lenient, never failing.
fn b64_lenient(text: &str) -> Vec<u8> {
    use base64::alphabet::STANDARD;
    use base64::engine::{
        DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig,
    };
    use base64::Engine;
    let cleaned: String = text
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/')
        .collect();
    let engine = GeneralPurpose::new(
        &STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    );
    let usable = cleaned.len() - cleaned.len() % 4
        + if cleaned.len() % 4 >= 2 {
            cleaned.len() % 4
        } else {
            0
        };
    engine.decode(&cleaned[..usable]).unwrap_or_default()
}

/// Section 5.4.1's KDF over Z.
fn concat_kdf(
    z: &[u8],
    key_bytes: usize,
    digest: &str,
    other: &[u8],
) -> CryptoResult<Vec<u8>> {
    let md = md_of(digest);
    let mut out = Vec::new();
    let mut counter: u32 = 1;
    while out.len() < key_bytes {
        let mut input = counter.to_be_bytes().to_vec();
        input.extend_from_slice(z);
        input.extend_from_slice(other);
        out.extend(hash(md, &input)?.to_vec());
        counter += 1;
    }
    out.truncate(key_bytes);
    Ok(out)
}

fn hex_bits(bytes: &[u8]) -> String {
    let mut out = String::from("00");
    for b in bytes {
        out.push_str(&format!("{:02X}", b));
    }
    out
}

// ---------------------------------------------------------------------------
// Encryption.
// ---------------------------------------------------------------------------

/// `encryptElement()`'s options, by the names Node takes.
#[derive(Clone, Debug, Default)]
pub struct EncryptOptions<'a> {
    /// The element around the result; `saml:EncryptedAssertion` by default.
    pub wrapper: Option<&'a str>,
    /// A [`BLOCK_CIPHERS`] name; `aes256-gcm` when absent or unknown.
    pub algorithm: Option<&'a str>,
    /// A [`KEY_TRANSPORTS`] name; `rsa-oaep-mgf1p` when absent or unknown.
    pub key_transport: Option<&'a str>,
    /// A [`KEY_WRAPS`] name, for an EC recipient; `kw-aes256` by default.
    pub key_wrap: Option<&'a str>,
}

fn random(n: usize) -> CryptoResult<Vec<u8>> {
    let mut out = vec![0u8; n];
    rand_bytes(&mut out)?;
    Ok(out)
}

/// The content, encrypted: IV || ciphertext [|| tag].
fn seal_content(
    cipher: BlockCipher,
    key: &[u8],
    plain: &[u8],
) -> CryptoResult<Vec<u8>> {
    let iv = random(cipher.iv_bytes())?;
    let mut out = iv.clone();
    if cipher.gcm {
        let mut tag = vec![0u8; 16];
        out.extend(encrypt_aead(
            cipher.symm(),
            key,
            Some(&iv),
            &[],
            plain,
            &mut tag,
        )?);
        out.extend(tag);
    } else {
        // forge's CBC pads with PKCS#7, which is one of the paddings XML
        // Encryption's rule accepts.
        out.extend(openssl::symm::encrypt(
            cipher.symm(),
            key,
            Some(&iv),
            plain,
        )?);
    }
    Ok(out)
}

/// `encryptElement()`: one element encrypted to a recipient's certificate,
/// wrapped in the element the caller names. RSA recipients get the content
/// key transported, EC ones agreed with ECDH-ES.
pub fn encrypt_element(
    xml: &str,
    cert_pem: &str,
    o: &EncryptOptions,
) -> CryptoResult<String> {
    let wrapper = o.wrapper.unwrap_or("saml:EncryptedAssertion");
    let cipher = o
        .algorithm
        .and_then(|a| BLOCK_CIPHERS.iter().find(|c| c.name == a))
        .copied()
        .unwrap_or(BLOCK_CIPHERS[0]);
    let transport = o
        .key_transport
        .filter(|t| KEY_TRANSPORTS.iter().any(|(n, _)| n == t))
        .unwrap_or("rsa-oaep-mgf1p");
    let wrap = o
        .key_wrap
        .and_then(|w| KEY_WRAPS.iter().find(|k| k.0 == w))
        .copied()
        .unwrap_or(KEY_WRAPS[2]);
    let recipient = X509::from_pem(cert_pem.as_bytes())?.public_key()?;
    let content_key = random(cipher.key_bytes)?;
    let body = seal_content(cipher, &content_key, xml.as_bytes())?;
    let cert_b64: String = strip_armor(cert_pem);
    let recipient_info = format!(
        "<ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data>",
        cert_b64
    );
    let encrypted_key = if recipient.id() == Id::EC {
        ecdh_es_key(&recipient, &content_key, wrap, &recipient_info)?
    } else {
        rsa_key(&recipient, &content_key, transport, &recipient_info)?
    };
    Ok(format!(
        "<{w} xmlns:saml=\"{saml}\"><xenc:EncryptedData xmlns:xenc=\"{xenc}\" \
         Type=\"{xenc}Element\"><xenc:EncryptionMethod Algorithm=\"{alg}\"/>\
         <ds:KeyInfo xmlns:ds=\"{ds}\">{key}</ds:KeyInfo><xenc:CipherData>\
         <xenc:CipherValue>{body}</xenc:CipherValue></xenc:CipherData>\
         </xenc:EncryptedData></{w}>",
        w = wrapper,
        saml = NS_SAML,
        xenc = XENC_NS,
        alg = cipher.uri,
        ds = DS_NS,
        key = encrypted_key,
        body = b64(&body)
    ))
}

/// The certificate's base64, its `-----…-----` lines and whitespace gone.
fn strip_armor(pem: &str) -> String {
    let mut out = String::new();
    let mut rest = pem;
    while let Some(start) = rest.find("-----") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 5..];
        match after.find("-----") {
            Some(end) => rest = &after[end + 5..],
            None => {
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out.chars().filter(|c| !c.is_whitespace()).collect()
}

fn rsa_key(
    recipient: &PKeyRef<Public>,
    content_key: &[u8],
    transport: &str,
    recipient_info: &str,
) -> CryptoResult<String> {
    let mut enc = Encrypter::new(recipient)?;
    let oaep = transport != "rsa-1_5";
    let hash_name = if transport == "rsa-oaep" {
        "sha256"
    } else {
        "sha1"
    };
    if oaep {
        enc.set_rsa_padding(Padding::PKCS1_OAEP)?;
        enc.set_rsa_oaep_md(md_of(hash_name))?;
        enc.set_rsa_mgf1_md(md_of(hash_name))?;
    } else {
        enc.set_rsa_padding(Padding::PKCS1)?;
    }
    let mut wrapped = vec![0u8; enc.encrypt_len(content_key)?];
    let n = enc.encrypt(content_key, &mut wrapped)?;
    wrapped.truncate(n);
    let digest = if oaep {
        format!(
            "<ds:DigestMethod xmlns:ds=\"{}\" Algorithm=\"{}\"/>",
            DS_NS,
            uri_of(&OAEP_DIGESTS, hash_name)
        )
    } else {
        String::new()
    };
    let mgf = if transport == "rsa-oaep" {
        format!(
            "<xenc11:MGF xmlns:xenc11=\"{}\" Algorithm=\"{}\"/>",
            XENC11_NS,
            uri_of(&MGF1_URIS, hash_name)
        )
    } else {
        String::new()
    };
    Ok(format!(
        "<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"{}\">{}{}\
         </xenc:EncryptionMethod><ds:KeyInfo>{}</ds:KeyInfo><xenc:CipherData>\
         <xenc:CipherValue>{}</xenc:CipherValue></xenc:CipherData>\
         </xenc:EncryptedKey>",
        uri_of(&KEY_TRANSPORTS, transport),
        digest,
        mgf,
        recipient_info,
        b64(&wrapped)
    ))
}

fn ecdh_es_key(
    recipient: &PKeyRef<Public>,
    content_key: &[u8],
    wrap: (&str, &str, usize),
    recipient_info: &str,
) -> CryptoResult<String> {
    let ec = recipient.ec_key()?;
    let nid = ec.group().curve_name();
    let curve =
        XML_EC_CURVES
            .iter()
            .find(|c| Some(c.3) == nid)
            .ok_or_else(|| {
                CryptoError::new(format!(
                    "the recipient's EC key is on curve {}, and this service \
                 agrees over {}",
                    nid.and_then(|n| n.short_name().ok())
                        .unwrap_or("(unnamed)"),
                    CURVE_LIST
                ))
            })?;
    let group = EcGroup::from_curve_name(curve.3)?;
    let ephemeral = PKey::from_ec_key(EcKey::generate(&group)?)?;
    let mut deriver = Deriver::new(&ephemeral)?;
    deriver.set_peer(recipient)?;
    let z = deriver.derive_to_vec()?;
    let algorithm_id = wrap.1.as_bytes();
    let kek = concat_kdf(&z, wrap.2, "sha256", algorithm_id)?;
    let wrapped = aes_key_wrap(&kek, content_key)?;
    let mut ctx = BigNumContext::new()?;
    let point = ephemeral.ec_key()?.public_key().to_bytes(
        &group,
        PointConversionForm::UNCOMPRESSED,
        &mut ctx,
    )?;
    Ok(format!(
        "<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"{wrap}\"/>\
         <ds:KeyInfo><xenc:AgreementMethod Algorithm=\"{ecdh}\">\
         <xenc11:KeyDerivationMethod xmlns:xenc11=\"{xenc11}\" Algorithm=\"{kdf}\">\
         <xenc11:ConcatKDFParams AlgorithmID=\"{aid}\" PartyUInfo=\"00\" \
         PartyVInfo=\"00\"><ds:DigestMethod Algorithm=\"{sha256}\"/>\
         </xenc11:ConcatKDFParams></xenc11:KeyDerivationMethod>\
         <xenc:OriginatorKeyInfo><ds:KeyValue><dsig11:ECKeyValue \
         xmlns:dsig11=\"{dsig11}\"><dsig11:NamedCurve URI=\"{oid}\"/>\
         <dsig11:PublicKey>{point}</dsig11:PublicKey></dsig11:ECKeyValue>\
         </ds:KeyValue></xenc:OriginatorKeyInfo><xenc:RecipientKeyInfo>{rcpt}\
         </xenc:RecipientKeyInfo></xenc:AgreementMethod></ds:KeyInfo>\
         <xenc:CipherData><xenc:CipherValue>{value}</xenc:CipherValue>\
         </xenc:CipherData></xenc:EncryptedKey>",
        wrap = wrap.1,
        ecdh = ECDH_ES_URI,
        xenc11 = XENC11_NS,
        kdf = CONCAT_KDF_URI,
        aid = hex_bits(algorithm_id),
        sha256 = uri_of(&OAEP_DIGESTS, "sha256"),
        dsig11 = DSIG11_NS,
        oid = curve.0,
        point = b64(&point),
        rcpt = recipient_info,
        value = b64(&wrapped)
    ))
}

// ---------------------------------------------------------------------------
// Decryption.
// ---------------------------------------------------------------------------

/// The caller's allow-lists and the mode. `None` allows everything.
#[derive(Clone, Debug, Default)]
pub struct DecryptOptions {
    pub allowed_ciphers: Option<Vec<String>>,
    pub allowed_key_management: Option<Vec<String>>,
    pub allowed_oaep_digests: Option<Vec<String>>,
    /// `mode.usesBrokenAlgorithms()`: whether an `rsa-1_5` key is unwrapped.
    pub broken_algorithms: bool,
}

/// `decryptElement()`'s answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Decrypted {
    pub ok: bool,
    pub xml: String,
    pub why: String,
    pub code: Option<ErrorCode>,
    /// An algorithm this door does not take, as opposed to a document that
    /// did not decrypt.
    pub refused: bool,
    pub algorithm: String,
    pub key_transport: String,
    pub key_wrap: String,
    pub oaep_digest: String,
}

fn refusal(why: impl Into<String>, code: ErrorCode) -> Decrypted {
    Decrypted {
        why: why.into(),
        code: Some(code),
        ..Decrypted::default()
    }
}

fn refused_by_name(algorithm: &str, why: String, code: ErrorCode) -> Decrypted {
    Decrypted {
        refused: true,
        algorithm: algorithm.to_string(),
        ..refusal(why, code)
    }
}

/// `refusedAlgorithm()`: the caller's allow-list, asked before any key.
fn not_allowed(
    list: &Option<Vec<String>>,
    name: &str,
    what: &str,
) -> Option<Decrypted> {
    let allowed = list.as_ref()?;
    if allowed.iter().any(|a| a == name) {
        return None;
    }
    Some(refused_by_name(
        name,
        format!(
            "the {} is {}, and this recipient accepts only {}",
            what,
            name,
            if allowed.is_empty() {
                "nothing".to_string()
            } else {
                allowed.join(", ")
            }
        ),
        codes::STS_KEYS_0071,
    ))
}

fn attr<'d>(doc: &'d Document, el: NodeId, name: &str) -> &'d str {
    doc.element(el).and_then(|e| e.attr(name)).unwrap_or("")
}

fn child(doc: &Document, el: Option<NodeId>, local: &str) -> Option<NodeId> {
    let el = el?;
    doc.child_elements(el)
        .into_iter()
        .find(|&c| doc.element(c).is_some_and(|e| e.local == local))
}

/// `getElementsByTagNameNS('*', local)[0]` under `el` (never `el` itself),
/// or anywhere in the document when `el` is the document.
fn first(doc: &Document, el: NodeId, local: &str) -> Option<NodeId> {
    doc.descendants(el)
        .into_iter()
        .filter(|&n| n != el)
        .find(|&n| doc.element(n).is_some_and(|e| e.local == local))
}

/// `parsesAsFragment()`: as it stands, or inside a container declaring the
/// prefixes a SAML fragment may inherit.
pub fn parses_as_fragment(text: &str) -> bool {
    if Document::parse(text).is_ok_and(|d| d.document_element().is_some()) {
        return true;
    }
    let wrapped = format!(
        "<x xmlns:saml=\"{}\" xmlns:samlp=\"{}\" xmlns:ds=\"{}\" \
         xmlns:xenc=\"{}\">{}</x>",
        NS_SAML, NS_SAMLP, DS_NS, XENC_NS, text
    );
    Document::parse(&wrapped).is_ok()
}

/// `concatKdfBits()`.
fn concat_kdf_bits(hex: &str, what: &str) -> Result<Vec<u8>, String> {
    if hex.is_empty() {
        return Ok(Vec::new());
    }
    if hex.len() % 2 != 0 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("the ConcatKDFParams {} is not hexBinary", what));
    }
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0))
        .collect();
    if bytes[0] != 0 {
        return Err(format!(
            "the ConcatKDFParams {} declares {} padding bits, and this \
             service reads whole octets",
            what, bytes[0]
        ));
    }
    Ok(bytes[1..].to_vec())
}

/// The ConcatKDF's digest name, when it is one this service derives with.
fn kdf_digest(
    doc: &Document,
    agreement: NodeId,
) -> Option<(NodeId, Option<NodeId>, &'static str)> {
    let kdf = first(doc, agreement, "KeyDerivationMethod")?;
    let params = first(doc, kdf, "ConcatKDFParams")?;
    let digest_el = first(doc, params, "DigestMethod");
    let hash = name_of(
        &OAEP_DIGESTS,
        digest_el.map_or("", |d| attr(doc, d, "Algorithm")),
    );
    Some((params, digest_el, hash))
}

/// `agreementRefusal()`: what an ECDH-ES agreement asks for that this
/// service does not perform, before any key operation; `None` when usable.
fn agreement_refusal(doc: &Document, agreement: NodeId) -> Option<String> {
    let kdf = first(doc, agreement, "KeyDerivationMethod");
    let kdf_uri = kdf.map_or("", |k| attr(doc, k, "Algorithm"));
    if kdf_uri != CONCAT_KDF_URI {
        return Some(format!(
            "the ECDH-ES agreement derives its key with {}, and this service \
             derives with ConcatKDF only (XML Encryption 1.1 section 5.4.1)",
            if kdf_uri.is_empty() {
                "no KeyDerivationMethod"
            } else {
                kdf_uri
            }
        ));
    }
    let params = kdf.and_then(|k| first(doc, k, "ConcatKDFParams"));
    let digest_el = params.and_then(|p| first(doc, p, "DigestMethod"));
    let hash = name_of(
        &OAEP_DIGESTS,
        digest_el.map_or("", |d| attr(doc, d, "Algorithm")),
    );
    if params.is_none() || hash.is_empty() || hash == "sha1" {
        return Some(format!(
            "the ConcatKDF names {}, and this service derives with SHA-256, \
             SHA-384 or SHA-512 only",
            digest_el.map_or("no digest", |d| attr(doc, d, "Algorithm"))
        ));
    }
    let originator = first(doc, agreement, "OriginatorKeyInfo");
    let curve = originator
        .and_then(|o| first(doc, o, "NamedCurve"))
        .map(|c| attr(doc, c, "URI"));
    if !curve.is_some_and(|c| XML_EC_CURVES.iter().any(|x| x.0 == c)) {
        return Some(format!(
            "the agreement carries no originator ECKeyValue on a curve this \
             service agrees over ({})",
            CURVE_LIST
        ));
    }
    None
}

/// `agreedKey()`: Z from our key and the originator's, and the KDF over it.
fn agreed_key(
    doc: &Document,
    agreement: NodeId,
    private: &PKeyRef<Private>,
    key_bytes: usize,
) -> Result<Vec<u8>, String> {
    let Some((params, _, hash)) = kdf_digest(doc, agreement) else {
        return Err("the ConcatKDF names no digest this service derives with \
                    (SHA-256, SHA-384 or SHA-512)"
            .to_string());
    };
    if hash.is_empty() || hash == "sha1" {
        return Err("the ConcatKDF names no digest this service derives with \
                    (SHA-256, SHA-384 or SHA-512)"
            .to_string());
    }
    let mut other = Vec::new();
    for name in [
        "AlgorithmID",
        "PartyUInfo",
        "PartyVInfo",
        "SuppPubInfo",
        "SuppPrivInfo",
    ] {
        other.extend(concat_kdf_bits(attr(doc, params, name), name)?);
    }
    let originator = first(doc, agreement, "OriginatorKeyInfo");
    let ec_value = originator.and_then(|o| first(doc, o, "ECKeyValue"));
    let curve =
        ec_value
            .and_then(|e| first(doc, e, "NamedCurve"))
            .and_then(|c| {
                XML_EC_CURVES.iter().find(|x| x.0 == attr(doc, c, "URI"))
            });
    let point_el = ec_value.and_then(|e| first(doc, e, "PublicKey"));
    let (Some(curve), Some(point_el)) = (curve, point_el) else {
        return Err(format!(
            "the agreement carries no originator ECKeyValue on a curve this \
             service agrees over ({})",
            CURVE_LIST
        ));
    };
    let point = b64_lenient(doc.text(point_el).trim());
    if point.len() != 1 + 2 * curve.2 || point[0] != 4 {
        return Err(format!(
            "the originator's public key is not an uncompressed point on {}",
            curve.1
        ));
    }
    // Node builds the originator's key from a JWK, which refuses a point
    // off the curve as "Invalid JWK EC key"; the agreement itself fails with
    // OpenSSL's own reason, which is what its catch-all then classifies.
    let originator =
        (|| -> Result<PKey<Public>, openssl::error::ErrorStack> {
            let group = EcGroup::from_curve_name(curve.3)?;
            let mut ctx = BigNumContext::new()?;
            let p = EcPoint::from_bytes(&group, &point, &mut ctx)?;
            PKey::from_ec_key(EcKey::from_public_key(&group, &p)?)
        })()
        .map_err(|_| "Invalid JWK EC key".to_string())?;
    let z = (|| {
        let mut deriver = Deriver::new(private)?;
        deriver.set_peer(&originator)?;
        deriver.derive_to_vec()
    })()
    .map_err(|e| reasons(&e))?;
    concat_kdf(&z, key_bytes, hash, &other).map_err(|e| e.to_string())
}

/// `openXmlContent()`: `(plain, padding ok)`, or `None` when the cipher
/// refuses it outright.
fn open_content(
    cipher: BlockCipher,
    key: &[u8],
    raw: &[u8],
) -> Option<(Vec<u8>, bool)> {
    if raw.len() < cipher.iv_bytes() + cipher.tag_bytes() {
        return None;
    }
    let iv = &raw[..cipher.iv_bytes()];
    if cipher.gcm {
        let tag = &raw[raw.len() - 16..];
        let body = &raw[cipher.iv_bytes()..raw.len() - 16];
        return decrypt_aead(cipher.symm(), key, Some(iv), &[], body, tag)
            .ok()
            .map(|p| (p, true));
    }
    let body = &raw[cipher.iv_bytes()..];
    if body.is_empty() || body.len() % 16 != 0 {
        return None;
    }
    let mut crypter =
        Crypter::new(cipher.symm(), Mode::Decrypt, key, Some(iv)).ok()?;
    crypter.pad(false);
    let mut padded = vec![0u8; body.len() + 16];
    let mut n = crypter.update(body, &mut padded).ok()?;
    n += crypter.finalize(&mut padded[n..]).ok()?;
    padded.truncate(n);
    // No early return on the padding: the caller decodes and parses either
    // way and refuses the three failures as one.
    let count = *padded.last()? as usize;
    let pad_ok = (1..=16).contains(&count);
    let keep = padded.len() - if pad_ok { count } else { 0 };
    padded.truncate(keep);
    Some((padded, pad_ok))
}

const CBC_REFUSAL: &str = "the AES-CBC ciphertext did not decrypt to a \
     well-formed XML element — the key, the ciphertext or its padding is \
     wrong, and which of those it was is deliberately not said (XML \
     Encryption 1.1 section 6.1.3). AES-CBC is unauthenticated; AES-GCM \
     would have detected an altered ciphertext";

/// OpenSSL's reasons for an error, without the codes and source paths a
/// keyword search would match on.
fn reasons(e: &openssl::error::ErrorStack) -> String {
    let all: Vec<String> = e
        .errors()
        .iter()
        .map(|x| x.reason().unwrap_or("an OpenSSL error").to_string())
        .collect();
    if all.is_empty() {
        "an OpenSSL error".to_string()
    } else {
        all.join("; ")
    }
}

/// Node's catch-all: is a thrown message about the key?
fn about_the_key(message: &str) -> bool {
    let lower = message.to_lowercase();
    [
        "oaep", "padding", "rsa", "decrypt", "key", "wrap", "agree", "ecdh",
        "kdf",
    ]
    .iter()
    .any(|w| lower.contains(w))
}

fn thrown(message: String) -> Decrypted {
    if about_the_key(&message) {
        refusal(
            format!(
                "the wrapped key could not be unwrapped with this service's \
                 private key ({}). It was encrypted to a different \
                 certificate — and this service regenerates its key on every \
                 start, so a stale copy of its metadata is the usual cause",
                message
            ),
            codes::STS_KEYS_0024,
        )
    } else {
        refusal(
            format!("the encrypted element could not be read: {}", message),
            codes::STS_KEYS_0025,
        )
    }
}

/// `decryptElement()`: one encrypted element opened with this service's
/// private key. It answers rather than fails.
pub fn decrypt_element(
    xml: &str,
    private: &PKeyRef<Private>,
    o: &DecryptOptions,
) -> Decrypted {
    let doc = match Document::parse(xml) {
        Ok(d) => d,
        Err(e) => {
            return refusal(
                format!("the encrypted element is not well-formed XML: {}", e),
                codes::STS_KEYS_0015,
            )
        }
    };
    let root = Document::ROOT;
    let Some(data) = first(&doc, root, "EncryptedData") else {
        return refusal(
            "there is no <xenc:EncryptedData> inside it",
            codes::STS_KEYS_0016,
        );
    };
    let data_method = child(&doc, Some(data), "EncryptionMethod");
    let data_uri = data_method.map_or("", |m| attr(&doc, m, "Algorithm"));
    let Some(cipher) =
        BLOCK_CIPHERS.iter().find(|c| c.uri == data_uri).copied()
    else {
        return refusal(
            format!(
                "the data is encrypted with {}, and this service reads only {}",
                if data_uri.is_empty() {
                    "(no algorithm stated)"
                } else {
                    data_uri
                },
                BLOCK_CIPHERS.map(|c| c.name).join(", ")
            ),
            codes::STS_KEYS_0017,
        );
    };
    if let Some(r) =
        not_allowed(&o.allowed_ciphers, cipher.name, "block cipher")
    {
        return r;
    }
    let data_key_info = child(&doc, Some(data), "KeyInfo");
    let key_el = child(&doc, data_key_info, "EncryptedKey")
        .or_else(|| first(&doc, root, "EncryptedKey"));
    let direct_agreement = if key_el.is_none() {
        child(&doc, data_key_info, "AgreementMethod")
    } else {
        None
    };
    if key_el.is_none() && direct_agreement.is_none() {
        return refusal(
            "there is no <xenc:EncryptedKey> inside the KeyInfo or beside the \
             EncryptedData, and no key agreement. A key pointed at with \
             <ds:RetrievalMethod> is legal and is not implemented here",
            codes::STS_KEYS_0018,
        );
    }
    let key_method = child(&doc, key_el, "EncryptionMethod");
    let key_uri = key_method.map_or("", |m| attr(&doc, m, "Algorithm"));
    let transport =
        key_el.and(KEY_TRANSPORTS.iter().find(|t| t.1 == key_uri).map(|t| t.0));
    let wrap = if key_el.is_some() && transport.is_none() {
        KEY_WRAPS.iter().find(|w| w.1 == key_uri).copied()
    } else {
        None
    };
    let key_info_of_key = child(&doc, key_el, "KeyInfo");
    let agreement = direct_agreement.or(if wrap.is_some() {
        child(&doc, key_info_of_key, "AgreementMethod")
    } else {
        None
    });
    if key_el.is_some()
        && transport.is_none()
        && !(wrap.is_some() && agreement.is_some())
    {
        return refusal(
            format!(
                "the key is wrapped with {}, and this service unwraps only {}, \
                 or {} under an ECDH-ES agreement",
                if key_uri.is_empty() {
                    "(no algorithm stated)"
                } else {
                    key_uri
                },
                KEY_TRANSPORTS.map(|t| t.0).join(", "),
                KEY_WRAPS.map(|w| w.0).join(", ")
            ),
            codes::STS_KEYS_0019,
        );
    }
    if let Some(a) = agreement {
        let alg = attr(&doc, a, "Algorithm");
        if alg != ECDH_ES_URI {
            return refused_by_name(
                alg,
                format!(
                    "the key is agreed with {}, and this service agrees only \
                     with ECDH-ES",
                    if alg.is_empty() {
                        "(no algorithm)"
                    } else {
                        alg
                    }
                ),
                codes::STS_KEYS_0073,
            );
        }
        if let Some(why) = agreement_refusal(&doc, a) {
            return refused_by_name("ecdh-es", why, codes::STS_KEYS_0090);
        }
    }
    let management = transport.unwrap_or("ecdh-es");
    if let Some(r) =
        not_allowed(&o.allowed_key_management, management, "key management")
    {
        return r;
    }
    if transport == Some("rsa-1_5") && !o.broken_algorithms {
        return refused_by_name(
            "rsa-1_5",
            "the key is wrapped with rsa-1_5 (RSAES-PKCS1-v1_5), which this \
             realm does not unwrap in product mode — XML Encryption 1.1 \
             section 6.1.2. Encrypt to it with rsa-oaep"
                .to_string(),
            codes::STS_KEYS_0070,
        );
    }
    let mut oaep_hash = "";
    if let Some(t @ ("rsa-oaep" | "rsa-oaep-mgf1p")) = transport {
        let mgf1p = t == "rsa-oaep-mgf1p";
        let digest_el = child(&doc, key_method, "DigestMethod");
        let mgf_el = if mgf1p {
            None
        } else {
            child(&doc, key_method, "MGF")
        };
        let digest = match digest_el {
            Some(d) => name_of(&OAEP_DIGESTS, attr(&doc, d, "Algorithm")),
            None => "sha1",
        };
        let mgf = match mgf_el {
            Some(m) => name_of(&MGF1_URIS, attr(&doc, m, "Algorithm")),
            None => "sha1",
        };
        if digest.is_empty() || mgf.is_empty() || digest != mgf {
            return refused_by_name(
                t,
                format!(
                    "the {} key transport names {} as its digest and {} as \
                     its mask generation function{}; this service unwraps \
                     only a matching pair of SHA-1, SHA-256, SHA-384 or \
                     SHA-512",
                    t,
                    digest_el.map_or("SHA-1", |d| attr(&doc, d, "Algorithm")),
                    mgf_el.map_or("MGF1-SHA-1", |m| attr(&doc, m, "Algorithm")),
                    if mgf1p {
                        " (rsa-oaep-mgf1p fixes MGF1 at SHA-1)"
                    } else {
                        ""
                    }
                ),
                codes::STS_KEYS_0072,
            );
        }
        if !mgf1p {
            if let Some(r) =
                not_allowed(&o.allowed_oaep_digests, digest, "OAEP digest")
            {
                return r;
            }
        }
        oaep_hash = digest;
    }
    let data_cipher =
        child(&doc, child(&doc, Some(data), "CipherData"), "CipherValue");
    let key_cipher =
        child(&doc, child(&doc, key_el, "CipherData"), "CipherValue");
    let Some(data_cipher) =
        data_cipher.filter(|_| key_el.is_none() || key_cipher.is_some())
    else {
        return refusal(
            "the element is missing one of its two <xenc:CipherValue>s — the \
             wrapped key, or the data",
            codes::STS_KEYS_0020,
        );
    };
    let oaep_label = child(&doc, key_method, "OAEPparams")
        .map(|p| b64_lenient(doc.text(p).trim()));
    let wrapped =
        key_cipher.map_or_else(Vec::new, |k| b64_lenient(doc.text(k).trim()));

    // The key.
    let key: Result<Vec<u8>, String> = if let Some(a) = agreement {
        if private.id() != Id::EC {
            return refusal(
                "the element is encrypted by ECDH-ES key agreement and this \
                 recipient's key is not an EC key",
                codes::STS_KEYS_0074,
            );
        }
        let needed = wrap.map_or(cipher.key_bytes, |w| w.2);
        agreed_key(&doc, a, private, needed).and_then(|agreed| match wrap {
            // A wrong key fails the wrap's integrity check, which OpenSSL
            // (node's id-aes*-wrap) reports in these words.
            Some(_) => aes_key_unwrap(&agreed, &wrapped).map_err(|e| {
                if wrapped.len() < 24 || wrapped.len() % 8 != 0 {
                    e.to_string()
                } else {
                    "cipher operation failed".to_string()
                }
            }),
            None => Ok(agreed),
        })
    } else {
        let t = transport.unwrap_or("");
        rsa_unwrap(private, t, oaep_hash, oaep_label.as_deref(), &wrapped)
    };
    let key = match key {
        Ok(k) => k,
        Err(message) => return thrown(message),
    };
    if key.len() != cipher.key_bytes {
        return refusal(
            format!(
                "the wrapped key did not unwrap to a {}-byte key, so it was \
                 encrypted to a different certificate. This service \
                 regenerates its key on every start, so a stale copy of its \
                 metadata is the usual cause — fetch /saml2/metadata again",
                cipher.key_bytes
            ),
            codes::STS_KEYS_0021,
        );
    }
    let opened =
        open_content(cipher, &key, &b64_lenient(doc.text(data_cipher).trim()));
    let plain =
        if !cipher.gcm {
            // AES-CBC: one refusal for the padding, the encoding and the parse,
            // all three checked whatever the first said.
            let (bytes, pad_ok) = opened.clone().unwrap_or_default();
            let (text, utf8_ok) = match String::from_utf8(bytes) {
                Ok(t) => (t, true),
                Err(e) => {
                    (String::from_utf8_lossy(e.as_bytes()).into_owned(), false)
                }
            };
            let xml_ok = parses_as_fragment(&text);
            if !(pad_ok && utf8_ok && xml_ok && opened.is_some()) {
                return refusal(CBC_REFUSAL, codes::STS_KEYS_0078);
            }
            text
        } else {
            let Some((bytes, _)) = opened else {
                return refusal(
                    "the AES-GCM authentication tag did not verify, so the \
                 ciphertext was altered after it was encrypted",
                    codes::STS_KEYS_0022,
                );
            };
            match String::from_utf8(bytes) {
                Ok(t) => t,
                Err(_) => return refusal(
                    "the decryption produced octets that are not UTF-8 text, \
                     so not an XML element — binary data, which this service \
                     does not decrypt",
                    codes::STS_KEYS_0023,
                ),
            }
        };
    if !parses_as_fragment(&plain) {
        return refusal(
            "the decryption produced something that is not well-formed XML",
            codes::STS_KEYS_0023,
        );
    }
    Decrypted {
        ok: true,
        xml: plain,
        algorithm: cipher.name.to_string(),
        key_transport: management.to_string(),
        key_wrap: wrap.map_or(String::new(), |w| w.0.to_string()),
        oaep_digest: oaep_hash.to_string(),
        ..Decrypted::default()
    }
}

fn rsa_unwrap(
    private: &PKeyRef<Private>,
    transport: &str,
    oaep_hash: &str,
    label: Option<&[u8]>,
    wrapped: &[u8],
) -> Result<Vec<u8>, String> {
    let run = || -> Result<Vec<u8>, openssl::error::ErrorStack> {
        let mut dec = Decrypter::new(private)?;
        if transport == "rsa-1_5" {
            // OpenSSL's implicit rejection, as node's: a padding that does
            // not check unwraps to a deterministic random value, and the
            // length check names the wrong key.
            dec.set_rsa_padding(Padding::PKCS1)?;
        } else {
            let hash = if transport == "rsa-oaep" {
                oaep_hash
            } else {
                "sha1"
            };
            dec.set_rsa_padding(Padding::PKCS1_OAEP)?;
            dec.set_rsa_oaep_md(md_of(hash))?;
            dec.set_rsa_mgf1_md(md_of(hash))?;
            if let Some(label) = label.filter(|l| !l.is_empty()) {
                dec.set_rsa_oaep_label(label)?;
            }
        }
        let mut out = vec![0u8; dec.decrypt_len(wrapped)?];
        let n = dec.decrypt(wrapped, &mut out)?;
        out.truncate(n);
        Ok(out)
    };
    run().map_err(|e| format!("RSA decryption failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Builder, X509NameBuilder};

    fn certificate(key: &PKey<Private>) -> String {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, "enc").unwrap();
        let name = name.build();
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        b.sign(key, MessageDigest::sha256()).unwrap();
        String::from_utf8(b.build().to_pem().unwrap()).unwrap()
    }

    const PLAIN: &str = "<saml:NameID>alice \u{e9}</saml:NameID>";

    #[test]
    fn every_cipher_and_transport_round_trips() {
        let rsa = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let cert = certificate(&rsa);
        let open = DecryptOptions {
            broken_algorithms: true,
            ..DecryptOptions::default()
        };
        for cipher in BLOCK_CIPHERS {
            for (transport, _) in KEY_TRANSPORTS {
                let enc = encrypt_element(
                    PLAIN,
                    &cert,
                    &EncryptOptions {
                        wrapper: Some("saml:EncryptedID"),
                        algorithm: Some(cipher.name),
                        key_transport: Some(transport),
                        ..EncryptOptions::default()
                    },
                )
                .unwrap();
                let d = decrypt_element(&enc, &rsa, &open);
                assert!(d.ok, "{} {}: {}", cipher.name, transport, d.why);
                assert_eq!(d.xml, PLAIN);
            }
        }
        let product = DecryptOptions::default();
        let enc = encrypt_element(
            PLAIN,
            &cert,
            &EncryptOptions {
                key_transport: Some("rsa-1_5"),
                ..EncryptOptions::default()
            },
        )
        .unwrap();
        assert_eq!(
            decrypt_element(&enc, &rsa, &product).code,
            Some(codes::STS_KEYS_0070)
        );
    }

    #[test]
    fn ecdh_es_on_every_curve() {
        for nid in [Nid::X9_62_PRIME256V1, Nid::SECP384R1, Nid::SECP521R1] {
            let group = EcGroup::from_curve_name(nid).unwrap();
            let key =
                PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
            let cert = certificate(&key);
            for (wrap, _, _) in KEY_WRAPS {
                let enc = encrypt_element(
                    PLAIN,
                    &cert,
                    &EncryptOptions {
                        key_wrap: Some(wrap),
                        ..EncryptOptions::default()
                    },
                )
                .unwrap();
                let d = decrypt_element(&enc, &key, &DecryptOptions::default());
                assert!(d.ok, "{:?} {}: {}", nid, wrap, d.why);
                assert_eq!(d.key_transport, "ecdh-es");
            }
        }
    }

    #[test]
    fn concat_kdf_bits_read_whole_octets() {
        assert_eq!(concat_kdf_bits("00AB", "x").unwrap(), vec![0xab]);
        assert!(concat_kdf_bits("01AB", "x").is_err());
        assert!(concat_kdf_bits("0", "x").is_err());
        assert!(concat_kdf_bits("", "x").unwrap().is_empty());
    }
}
