# PROVENANCE — the W3C XML Security interop cases `tests/w3c_xmlsec.js` runs

**None of these files is in this repository, and none is ever committed.**
They carry private keys — PKCS#8 and PKCS#12 decryption keys, and the signers'
keys beside the signature cases — and this repository holds no key material.
`tests/tools/fetch-w3c-xmlsec.sh` downloads them into the tests image at build
time (one layer of `tests/Dockerfile`, into `/usr/src/corpora/w3c-xmlsec`,
named to the test by `STS_W3C_XMLSEC_DIR`), and `tests/tools/w3c-xmlsec.sha256`
pins every one of them by SHA-256: a file that changes upstream FAILS THE
BUILD rather than quietly becoming a different case under the same name.
What is committed is the list of URLs and digests, and this note.

Fetched and pinned on **2026-09-24**. 336 downloads (eight of them archives,
unpacked where they land).

## What was taken, and from where

| Set | Published by | URL | What it is |
|---|---|---|---|
| XML Signature 1.1 interop | W3C XML Security WG, Working Group Note 13 Nov 2012 | <https://www.w3.org/TR/xmldsig-core1-interop/> — files under `interop/xmldsig11/oracle/` and `oracle/keys/` | 45 cases: ECDSA P-256/384/521 × SHA-1/224/256/384/512 in both KeyValue forms (XMLDSig 1.1 ECKeyValue, RFC 4050), RSA-SHA224..512, SHA-224..512 digests, HMAC-SHA224..512, HMACOutputLength 40 (must fail) and 160, DEREncodedKeyValue, KeyInfoReference, X509Digest; with their certificates and PKCS#8 keys |
| XML Encryption 1.1 interop | W3C XML Security WG, Working Group Note | <https://www.w3.org/TR/xmlenc-core1-interop/> — `files/ibm/`, `files/microsoft/`, `files/oracle/` (directory listings from <https://www.w3.org/2008/xmlsec/Drafts/xmlenc-core-11/test-cases/files/>) | RSA-OAEP (mgf1p and 1.1 `rsa-oaep`, digest, MGF and PSource variants), ECDH-ES and DH-ES with ConcatKDF and PBKDF2, AES-GCM, AES key wrap, derived keys, plain AES-GCM; with the PKCS#12 keys and `plaintext.xml` |
| XML Signature 2nd Edition test cases | W3C XML Security Specifications Maintenance WG | <https://www.w3.org/TR/xmldsig2ed-tests/> — `c14n11/` (inputs, XPath subsets, reference outputs, appendix A), `xmldsig/c14n11/`, `xmldsig/defCan-*`, `xmldsig/dname/` (with `certs/`), `xmldsig/xpointer/` — every vendor's signature (IAIK, IBM, ORCL, SUN, UPC) | Canonical XML 1.1, default canonicalization, XPointer references, distinguished-name encoding |
| merlin-xmldsig-twenty-three | Merlin Hughes (Baltimore), the XML Signature interop set named Y2 on <https://www.w3.org/Signature/2001/04/05-xmldsig-interop.html> | <https://lists.w3.org/Archives/Public/w3c-ietf-xmldsig/2002AprJun/att-0016/01-merlin-xmldsig-twenty-three.tar.gz> | DSA, RSA, HMAC; enveloped, enveloping, detached, base64; the X.509 KeyInfo forms; the large signature with every transform; every intermediate canonical form |
| phaos-xmldsig-three | Phaos Technology, same page | <https://lists.w3.org/Archives/Public/w3c-ietf-xmldsig/2003JulSep/att-0018/phaos-xmldsig-three.zip> | RSA, DSA, HMAC (MD5, SHA-1, truncated), manifests, X.509 data forms, XPath and XSLT transforms, two bad signatures |
| merlin-exc-c14n-one, merlin-c14n-three, merlin-iaikTests-two | Merlin Hughes, the Exclusive C14N interop set on <https://www.w3.org/Signature/2002/02/01-exc-c14n-interop.html> | <https://lists.w3.org/Archives/Public/w3c-ietf-xmldsig/2002JanMar/att-0032/01-merlin-exc-c14n-one.tgz>, <https://lists.w3.org/Archives/Public/w3c-ietf-xmldsig/2002AprJun/att-0228/01-merlin-c14n-three.tar.gz>, <https://lists.w3.org/Archives/Public/w3c-ietf-xmldsig/2002AprJun/att-0056/01-merlin-iaikTests-two.tar.gz> | Exclusive C14N with and without comments and InclusiveNamespaces, and their canonical forms |
| merlin-xmlenc-five | Merlin Hughes, the XML Encryption interop set Y1 on <https://www.w3.org/Encryption/2002/02-xenc-interop.html> | <https://lists.w3.org/Archives/Public/xml-encryption/2002Mar/att-0008/merlin-xmlenc-five.tar.gz> (the page links the list message <https://lists.w3.org/Archives/Public/xml-encryption/2002Mar/0008.html>) | Element, content and data encryption over AES and 3DES, RSA-1_5 and RSA-OAEP transport, key wrap, DH agreement, and signatures keyed through XML Encryption |
| merlin-decrypt-two | Merlin Hughes, same page | <https://lists.w3.org/Archives/Public/xml-encryption/2002Aug/att-0000/01-merlin-decrypt-two.tar.gz> | The Decryption Transform for XML Signature |
| phaos-xmlenc-3 | Phaos Technology, same page | <https://lists.w3.org/Archives/Public/xml-encryption/2002Mar/att-0052/01-phaos-xmlenc-3.zip> | Element, content and text encryption, key transport, key wrap, DH agreement |

## What was tried and not taken

* **The Microsoft and Sun XML Signature 1.1 vectors** (48 ECDSA and 14 + 18
  SHA/HMAC files the 1.1 interop report describes) — the report says "see
  test file directory", and the only directory it publishes,
  `interop/xmldsig11/`, holds the Oracle set alone. Not found anywhere else
  under `www.w3.org/2008/xmlsec/`.
* **merlin-xmldsig-fifteen and -sixteen** — still downloadable, but the XML
  Signature interop page marks them deprecated ("we no longer recommend
  testing against this set"); twenty-three supersedes them.
* **The Canonical XML 1.0 and Exclusive C14N specification examples** — they
  exist only as HTML-rendered text inside the Recommendations (whitespace as
  `&nbsp;`, no way to write a carriage return) and several need DTD
  processing; there is no published file set. The canonical forms the merlin
  sets publish (`c14n-N.txt`) are the case set used instead.

## Licence

The W3C Technical Reports and the files under them are © W3C (MIT, ERCIM,
Keio, Beihang) and used under the **W3C Document License**
(<https://www.w3.org/copyright/document-license/>) — the TR notes say "W3C
liability, trademark and document use rules apply". The archives are
attachments posted to W3C's public mailing lists by their authors (Baltimore
Technologies, Phaos Technology) for interoperability testing, and carry no
licence of their own.

**Nothing is redistributed**: this repository commits URLs and digests only,
and the files exist in a tests image built from them. That is the rule for
key material (no keys in git), and it is also the conservative answer for
files whose licence is the archive's silence.
