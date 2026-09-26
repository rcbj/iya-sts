"use strict";
//
// File: tlsfuzzer_kit.js
//
// ===========================================================================
// TLSFUZZER AGAINST THIS SERVICE'S THREE TLS LISTENERS (#212, 2026-09-26).
//
// Not a job. `sts_tlsfuzzer.js` (the main port and LDAPS 636 of a running
// stack) and `tests/tlsfuzzer_debugger.js` (the debugger's listener, which no
// test stack binds) run the same PLAN below through this file.
//
// tlsfuzzer (GPL-2.0) and tlslite-ng (LGPL-2.1) are fetched at pinned
// commits into the tests image by tests/tlsfuzzer/build-tlsfuzzer.sh and are
// never vendored; STS_TLSFUZZER_DIR names where they are (/opt/tlsfuzzer).
// Every script runs UNMODIFIED through tests/tlsfuzzer/sts_adapter.py, which
// answers three facts about the far end no script can be told on its command
// line — each argued in its header:
//
//   --client-cert-request  the main port and the debugger ASK for a client
//                          certificate and require none;
//   --ldap                 LDAPS speaks LDAP, so "GET / HTTP/1.0" becomes an
//                          LDAP bind of the same length;
//   --tls12-aead           TLS 1.2 is BCP 195's ECDHE-RSA AES-GCM and nothing
//                          else, so a TLS 1.2 script's default suites (RSA
//                          key exchange, CBC) are swapped for it.
//
// THE PLAN IS EVERY SCRIPT tlsfuzzer SHIPS, EACH ONE OF THREE THINGS:
//
//   * RUN, with the arguments that fit this service (its groups, signature
//     algorithms, ticket count), and every probe that does not pass named
//     with -x (expected to fail, with the alert it must fail with: -X) or -e
//     (not run) and the REASON — `design` (a choice this service made and
//     documents), `openssl` (Node/OpenSSL behaviour this service cannot
//     change) or `tool` (the probe cannot be pointed at this service). A
//     probe marked -x that passes fails the script (XPASS), so a behaviour
//     that changes cannot go unnoticed;
//   * NOT APPLICABLE, with the reason: the script tests a feature this
//     service does not offer at all (CBC, RSA key exchange, finite-field
//     DHE, heartbeat, PSK, an echo server's replies), or it measures TIMING,
//     which needs a quiet dedicated host and a packet capture;
//   * RUN AS A REFUSAL, where the whole script is an attack or a version
//     this service must refuse (SSLv2, export suites, TLS 1.0 and 1.1).
//
// A script passes when it exits 0 with FAIL: 0 and XPASS: 0 in its summary.
// ===========================================================================

const childProcess = require("child_process");
const fs = require("fs");
const path = require("path");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "tlsfuzzer_kit",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const TLSFUZZER_DIR = process.env.STS_TLSFUZZER_DIR || "/opt/tlsfuzzer";
const ADAPTER = path.join(__dirname, "..", "tlsfuzzer", "sts_adapter.py");

// What each listener is, to the adapter.
const LISTENERS = {
  main: { flags: ["--client-cert-request"], requestsCertificate: true,
          label: "the main HTTPS port" },
  ldaps: { flags: ["--ldap"], requestsCertificate: false,
           label: "LDAPS 636" },
  debugger: { flags: ["--client-cert-request"], requestsCertificate: true,
              label: "the debugger's listener" }
};

// ---------------------------------------------------------------------------
// WHY A PROBE MAY FAIL, ONCE EACH. Every exception below names one of these
// and says which kind it is: DESIGN (a choice this service made, documented
// in tls/CLAUDE.md and docs/tls.md), OPENSSL (Node/OpenSSL behaviour this
// service cannot change — recorded on #212 with the evidence) or TOOL (the
// probe cannot be pointed at this service as written).
// ---------------------------------------------------------------------------
const WHY = {
  oldVersion: { why: "design", reason: "tls.minVersion is TLS 1.2 (BCP " +
    "195; RFC 8996 deprecates TLS 1.0 and 1.1), so an SSL 3.0, TLS 1.0 or " +
    "TLS 1.1 handshake is refused, with protocol_version (or " +
    "handshake_failure where the hello offers nothing else in common)" },
  renegotiation: { why: "design", reason: "TLS 1.2 renegotiation is " +
    "refused on every listener (SSL_OP_NO_RENEGOTIATION, #212): OpenSSL " +
    "answers a renegotiating ClientHello with a no_renegotiation warning; " +
    "test-renegotiation-disabled holds the refusal" },
  sessionCache: { why: "openssl", reason: "node keeps no server-side TLS " +
    "session cache — stateful TLS 1.2 session-ID resumption needs a " +
    "newSession/resumeSession handler — so a session ID is never resumed " +
    "and the server answers with a full handshake; resumption works through " +
    "session tickets (test-session-ticket-resumption, and TLS 1.3 PSK)" },
  noFfdhe: { why: "design", reason: "tls.groups offers no finite-field " +
    "group (#212): ffdhe2048 and up are an order of magnitude slower than " +
    "any curve, and every TLS 1.3 client offers a curve" },
  noSha1: { why: "design", reason: "tls.signatureAlgorithms has no SHA-1 " +
    "scheme (RFC 9155), so a hello offering only SHA-1 signatures has " +
    "nothing to sign with" },
  noCcm: { why: "design", reason: "tls.ciphers is BCP 195's list; " +
    "TLS_AES_128_CCM_SHA256 and TLS_AES_128_CCM_8_SHA256 are not on it" },
  noDhe: { why: "design", reason: "TLS 1.2 is ECDHE-RSA AES-GCM alone " +
    "(BCP 195, RFC 9325 section 4.2): with no curve in common there is no " +
    "finite-field DHE or RSA key exchange to fall back to, and " +
    "handshake_failure is the answer" },
  rsaKey: { why: "openssl", reason: "the listener's key is rsaEncryption, " +
    "which cannot sign an rsa_pss_pss_* scheme (RFC 8446 section 4.2.3); " +
    "OpenSSL refuses with handshake_failure" },
  overflow: { why: "tool", reason: "the probe fills a length field to its " +
    "maximum, and the two extensions the adapter adds so that a TLS 1.2 " +
    "hello can negotiate ECDHE (signature_algorithms, supported_groups) " +
    "overflow it inside tlslite before anything is sent" },
  addedSigAlgs: { why: "tool", reason: "the probe sends a TLS 1.2 hello with " +
    "no signature_algorithms or supported_groups; the adapter adds both, " +
    "because this service's only TLS 1.2 key exchange is ECDHE, so the " +
    "probe tests something else" },
  sniParse: { why: "openssl", reason: "OpenSSL's server_name parsing: " +
    "node binds no SNICallback on these listeners, so a name is not " +
    "judged — OpenSSL continues the handshake for an unknown, empty or " +
    "control-character name (RFC 6066 section 3 allows continuing), and " +
    "answers malformed lists with decode_error or unrecognized_name where " +
    "tlsfuzzer expects illegal_parameter" },
  alertChoice: { why: "openssl", reason: "OpenSSL refuses the malformed " +
    "message with a different alert description from the one tlsfuzzer " +
    "expects (both abort the handshake)" },
  keyUpdateLazy: { why: "openssl", reason: "OpenSSL answers a KeyUpdate " +
    "with update_requested when it next WRITES, which RFC 8446 section " +
    "4.6.3 allows (\"prior to sending its next Application Data record\"); " +
    "the probe's request is incomplete, so the server writes nothing and " +
    "tlsfuzzer times out waiting. On LDAPS it depends on timing: seen in " +
    "one run of two" },
  noTicketAfterResumption: { why: "openssl", reason: "after a PSK " +
    "resumption node's OpenSSL sends no new NewSessionTicket (a full " +
    "handshake gets two); RFC 8446 section 4.6.1 makes tickets optional" },
  noPskKe: { why: "openssl", reason: "OpenSSL does not accept psk_ke " +
    "(resumption without (EC)DHE), which would give up forward secrecy; " +
    "it falls back to a full handshake" },
  secondHelloOrder: { why: "openssl", reason: "OpenSSL does not compare " +
    "the ORDER of the extensions in the ClientHello that answers a " +
    "HelloRetryRequest with the first one's; tlsfuzzer expects " +
    "illegal_parameter" },
  recordVersion: { why: "openssl", reason: "OpenSSL checks the " +
    "legacy_record_version of the records around a TLS 1.3 handshake " +
    "(tls13_validate_record_header: wrong version number) and aborts with " +
    "decode_error on the 0x0300 tlsfuzzer writes on its compatibility " +
    "ChangeCipherSpec — or closes before the alert reaches the client, as " +
    "the in-process debugger listener does; RFC 8446 section 5.1 says the " +
    "field MUST be ignored" },
  paddedRecord: { why: "openssl", reason: "OpenSSL takes a TLS 1.3 record " +
    "whose content plus padding exceeds 2^14 + 1 bytes (RFC 8446 section " +
    "5.4 asks for record_overflow), and waits for more of a padded " +
    "maximum-size Finished rather than refusing it" },
  pointFormats: { why: "openssl", reason: "OpenSSL accepts a TLS 1.2 " +
    "ECDHE key share in the hybrid point encoding and a client " +
    "ec_point_formats list without `uncompressed`, both of which RFC 8422 " +
    "section 5.1.2 excludes; it then waits for the rest of the handshake" },
  hybridPointMlkem: { why: "openssl", reason: "OpenSSL accepts the " +
    "ECDH half of a SecP256r1MLKEM768 or SecP384r1MLKEM1024 key share in " +
    "the hybrid point encoding (0x06/0x07); the hybrid-group draft " +
    "(draft-ietf-tls-ecdhe-mlkem) asks for the uncompressed point, and so " +
    "does tlsfuzzer. X25519MLKEM768, the default's first group, has no " +
    "point encoding to get wrong" },
  defaultCurve: { why: "openssl", reason: "a TLS 1.2 client that sends no " +
    "supported_groups is given OpenSSL's first configured curve (X25519, " +
    "tls.groups) where tlsfuzzer expects P-256" },
  legacyVersion: { why: "openssl", reason: "OpenSSL answers a TLS 1.3 " +
    "hello whose legacy_version is SSL 3.0 with handshake_failure where " +
    "tlsfuzzer expects protocol_version" },
  certAuthorities: { why: "design", reason: "the CertificateRequest " +
    "carries certificate_authorities (RFC 8446 section 4.2.4) naming the " +
    "anchors the client truststore holds — the service Root, so a client " +
    "can pick the certificate this service issued it (tls/CLAUDE.md)" },
  noSha224: { why: "design", reason: "tls.signatureAlgorithms has no " +
    "SHA-224 scheme (#212), so a CertificateVerify made or labelled with " +
    "one is refused" },
  sha1Envelope: { why: "design", reason: "tls.signatureAlgorithms has no " +
    "SHA-1 scheme (RFC 9155): a CertificateVerify that NAMES one is refused " +
    "with illegal_parameter before its signature is checked, where " +
    "tlsfuzzer expects decrypt_error" },
  schemeBeforeSignature: { why: "openssl", reason: "OpenSSL checks the " +
    "signature scheme against the certificate's key type before it checks " +
    "the signature, so a scheme the key cannot use is illegal_parameter " +
    "where tlsfuzzer expects decrypt_error" },
  sslv2Hello: { why: "design", reason: "an SSLv2-compatible ClientHello " +
    "carries no extensions — no supported_groups, no " +
    "signature_algorithms — and this service's only TLS 1.2 key exchange " +
    "is ECDHE signed with SHA-2, so there is nothing to agree on" },
  emptySslv2: { why: "openssl", reason: "OpenSSL closes the connection " +
    "on an empty SSLv2-format record without sending an alert" },
  ticketAsPsk: { why: "openssl", reason: "OpenSSL answers a TLS 1.2 " +
    "session ticket presented as a TLS 1.3 PSK identity with decode_error; " +
    "RFC 8446 section 4.2.11 has the server ignore an identity it cannot " +
    "use and continue with a full handshake" },
  levelZeroAlert: { why: "tool", reason: "the script's closing alert is " +
    "built with the DESCRIPTION as its level (AlertGenerator(" +
    "close_notify)), so it is sent with level 0; the directory keeps the " +
    "connection open, reads it, and answers illegal_parameter — correctly. " +
    "The main port's HTTP/1.0 server has closed the connection first" },
  brainpoolRefused: { why: "design", reason: "a client certificate on a " +
    "brainpool curve is refused (#212): node 24.16.0 crashes converting " +
    "one for getPeerCertificate(), so tls.signatureAlgorithms offers no " +
    "brainpool scheme and the handshake fails in OpenSSL; " +
    "refuseUnreadableCertificatesOn() closes any that gets through " +
    "(STS-TLS-0035)" },
  cipherOrder: { why: "design", reason: "honorCipherOrder: the SERVER's " +
    "BCP 195 order wins, which puts AES-128-GCM before AES-256-GCM for TLS " +
    "1.2 where the probe expects the client's first choice" }
};

// The signature algorithms this service advertises (tls.signatureAlgorithms'
// default), in tlsfuzzer's names and the order a CertificateRequest carries
// them: the TLS 1.3 list, and the TLS 1.2 list OpenSSL derives from it (no
// ML-DSA, a TLS 1.3 scheme). No brainpool in either (#212: node crashes
// reading such a certificate).
const SIGALGS_13 = "mldsa65 mldsa87 mldsa44 ecdsa_secp256r1_sha256 " +
  "ecdsa_secp384r1_sha384 ecdsa_secp521r1_sha512 ed25519 ed448 " +
  "rsa_pss_pss_sha256 rsa_pss_pss_sha384 " +
  "rsa_pss_pss_sha512 rsa_pss_rsae_sha256 rsa_pss_rsae_sha384 " +
  "rsa_pss_rsae_sha512 rsa_pkcs1_sha256 rsa_pkcs1_sha384 rsa_pkcs1_sha512";
const SIGALGS_12 = "ecdsa_secp256r1_sha256 ecdsa_secp384r1_sha384 " +
  "ecdsa_secp521r1_sha512 ed25519 ed448 rsa_pss_pss_sha256 " +
  "rsa_pss_pss_sha384 rsa_pss_pss_sha512 rsa_pss_rsae_sha256 " +
  "rsa_pss_rsae_sha384 rsa_pss_rsae_sha512 rsa_pkcs1_sha256 " +
  "rsa_pkcs1_sha384 rsa_pkcs1_sha512";
// tls.groups' default, in tlsfuzzer's names.
const GROUPS = "x25519mlkem768,secp256r1mlkem768,secp384r1mlkem1024," +
  "x25519,secp256r1,x448,secp384r1,secp521r1";

const OLD = /Protocol \(3, [012]\)|TLSv1\.[01]|SSLv3|SSL3\.0|\(3, [012]\)/;
const REFUSED_OLD = ["protocol_version", "handshake_failure"];

// One exception: the probe (a name, or a pattern for a family of names),
// the text its failure must carry (one string or several), and its reason.
function ex(probe, alert, key, extra) {
  log.debug("Entering ex(). " + key);
  log.debug("Leaving ex().");
  return Object.assign({ probe: probe, alert: alert }, WHY[key],
                       extra || {});
}

const CR = ["main", "debugger"];
const NOT_CR = "LDAPS asks for no client certificate (ldap/CLAUDE.md), so " +
  "there is no CertificateRequest to check or certificate to send";

const PLAN = [
  // --- not applicable: a feature this service does not offer ------------
  { script: "test-aesccm.py", skip: "AES-CCM suites are not offered " +
    "(tls.ciphers is BCP 195: AES-GCM and ChaCha20-Poly1305 only)" },
  { script: "test-atypical-padding.py", skip: "CBC record padding: no CBC " +
    "suite is offered (BCP 195)" },
  { script: "test-bleichenbacher-workaround.py", skip: "RSA key exchange " +
    "is not offered (BCP 195: ECDHE only), so there is no PKCS #1 v1.5 " +
    "decryption to attack" },
  { script: "test-bleichenbacher-timing-marvin.py", skip: "TIMING, and RSA " +
    "key exchange is not offered: a Marvin/ROBOT measurement needs an RSA " +
    "key exchange, a quiet dedicated host and a packet capture" },
  { script: "test-bleichenbacher-timing-pregenerate.py", skip: "TIMING " +
    "(the Marvin ciphertext pre-generation for the above); RSA key " +
    "exchange is not offered" },
  { script: "test-chacha20.py", skip: "the TLS 1.2 ChaCha20-Poly1305 suites " +
    "are not offered (BCP 195's four TLS 1.2 suites are AES-GCM); TLS 1.3's " +
    "is, and test-tls13-symetric-ciphers covers it" },
  { script: "test-cve-2016-2107.py", skip: "the AES-NI CBC padding oracle: " +
    "no CBC suite is offered" },
  { script: "test-cve-2016-7054.py", skip: "a TLS 1.2 ChaCha20-Poly1305 " +
    "heap overflow: no TLS 1.2 ChaCha20 suite is offered" },
  { script: "test-dhe-key-share-random.py", skip: "finite-field DHE is " +
    "not offered in TLS 1.2 (BCP 195) or 1.3 (tls.groups)" },
  { script: "test-dhe-no-shared-secret-padding.py", skip: "finite-field " +
    "DHE is not offered" },
  { script: "test-dhe-rsa-key-exchange.py", skip: "finite-field DHE is " +
    "not offered" },
  { script: "test-dhe-rsa-key-exchange-signatures.py", skip: "finite-field " +
    "DHE is not offered" },
  { script: "test-dhe-rsa-key-exchange-with-bad-messages.py", skip:
    "finite-field DHE is not offered" },
  { script: "test-dsa-in-certificate-verify.py", skip: "DSA is not in " +
    "tls.signatureAlgorithms (#212; FIPS 186-5 withdrew it for signing), " +
    "so a DSA client certificate cannot sign a CertificateVerify here" },
  { script: "test-dsa-sig-flexibility.py", skip: "needs a DSA server " +
    "certificate; the listeners present RSA (and ML-DSA when configured)" },
  { script: "test-ecdsa-sig-flexibility.py", skip: "needs an ECDSA server " +
    "certificate; the listeners present RSA (tls.certificateAlgorithms)" },
  { script: "test-encrypt-then-mac.py", skip: "encrypt-then-MAC (RFC 7366) " +
    "applies to CBC suites, and none is offered" },
  { script: "test-encrypt-then-mac-renegotiation.py", skip: "CBC " +
    "encrypt-then-MAC across a renegotiation: neither is offered" },
  { script: "test-ffdhe-expected-params.py", skip: "finite-field DHE is " +
    "not offered" },
  { script: "test-ffdhe-negotiation.py", skip: "finite-field DHE is not " +
    "offered" },
  { script: "test-fuzzed-MAC.py", skip: "HMAC record protection: no CBC " +
    "suite is offered, and the AEAD tag is fuzzed by test-fuzzed-ciphertext " +
    "and test-tls13-symetric-ciphers" },
  { script: "test-fuzzed-padding.py", skip: "CBC padding: no CBC suite is " +
    "offered" },
  { script: "test-fuzzed-plaintext.py", skip: "fuzzed CBC plaintext " +
    "(padding and MAC): no CBC suite is offered" },
  { script: "test-heartbeat.py", skip: "the heartbeat extension (RFC 6520) " +
    "is not supported; test-no-heartbeat holds that it is refused" },
  { script: "test-invalid-rsa-key-exchange-messages.py", skip: "RSA key " +
    "exchange is not offered" },
  { script: "test-lengths.py", skip: "needs an ECHO server (tlsfuzzer runs " +
    "it against `tls.py server --echo`); record lengths are covered by " +
    "test-record-layer-fragmentation and test-tls13-record-layer-limits" },
  { script: "test-tls13-lengths.py", skip: "needs an echo server, as " +
    "test-lengths" },
  { script: "test-lucky13.py", skip: "TIMING, and CBC is not offered" },
  { script: "test-record-size-limit.py", skip: "the record_size_limit " +
    "extension (RFC 8449) is not implemented by node's OpenSSL; the script " +
    "tests a server that implements it" },
  { script: "test-renegotiation-changed-clienthello.py", skip: "every probe " +
    "renegotiates, and renegotiation is refused (#212); " +
    "test-renegotiation-disabled holds the refusal" },
  { script: "test-interleaved-application-data-and-fragmented-handshakes-" +
    "in-renegotiation.py", skip: "every probe renegotiates; refused (#212)" },
  { script: "test-interleaved-application-data-in-renegotiation.py", skip:
    "every probe renegotiates; refused (#212)" },
  { script: "test-resumption-with-wrong-ciphers.py", skip: "every probe " +
    "resumes a TLS 1.2 session by session ID, which node does not cache " +
    "(tickets are how this service resumes)" },
  { script: "test-SSLv3-padding.py", skip: "SSL 3.0 is refused " +
    "(tls.minVersion); test-version-numbers and the SSLv2 scripts hold " +
    "the refusals" },
  { script: "test-TLSv1_2-rejected-without-TLSv1_2.py", skip: "for a " +
    "server that does not support TLS 1.2; this one does" },
  { script: "test-tls13-certificate-compression.py", skip: "certificate " +
    "compression (RFC 8879) is not offered: node's OpenSSL is built " +
    "without zlib and brotli" },
  { script: "test-tls13-client-certificate-compression.py", skip: "the " +
    "server offers no certificate compression (RFC 8879)" },
  { script: "test-tls13-ecdhe-brainpool-curves.py", skip: "the brainpool " +
    "TLS 1.3 groups (RFC 8734) are not in tls.groups" },
  { script: "test-tls13-ecdsa-support.py", skip: "needs an ECDSA server " +
    "certificate; the listeners present RSA" },
  { script: "test-tls13-eddsa.py", skip: "needs an EdDSA server " +
    "certificate; the listeners present RSA" },
  { script: "test-tls13-ffdhe-groups.py", skip: "finite-field groups are " +
    "not in tls.groups (#212)" },
  { script: "test-tls13-ffdhe-sanity.py", skip: "finite-field groups are " +
    "not in tls.groups (#212)" },
  { script: "test-tls13-keyupdate-from-server.py", skip: "needs a server " +
    "that sends a KeyUpdate when asked by an application request" },
  { script: "test-tls13-minerva.py", skip: "TIMING of ECDSA signing, and " +
    "the listeners sign with RSA" },
  { script: "test-tls13-non-support.py", skip: "for a server without TLS " +
    "1.3; this one has it" },
  { script: "test-tls13-psk_dhe_ke.py", skip: "external PSKs are not " +
    "configured on any listener" },
  { script: "test-tls13-psk_ke.py", skip: "external PSKs are not " +
    "configured on any listener" },
  { script: "test-tls13-rsapss-signatures.py", skip: "needs an RSA-PSS " +
    "(id-RSASSA-PSS) server key; the listener's is rsaEncryption, whose " +
    "PSS signatures test-tls13-rsa-signatures and " +
    "test-tls13-signature-algorithms cover" },
  { script: "test-truncating-of-kRSA-client-key-exchange.py", skip: "RSA " +
    "key exchange is not offered" },
  { script: "test-tls13-post-handshake-auth.py", skip: "no listener asks " +
    "for a certificate after the handshake: the main port and the " +
    "debugger ask during it, LDAPS never" },

  // --- run as written (with the arguments that describe this service) --
  { script: "test-aes-gcm-nonces.py" },
  { script: "test-alpn-negotiation.py", on: CR, notOn: { ldaps: "LDAPS " +
    "negotiates no ALPN: ldapjs sets no ALPNProtocols, no identifier is " +
    "registered for LDAP, and RFC 7301 lets a server ignore the extension" },
    exceptions: [
      ex(/^renegotiation/, "no_renegotiation", "renegotiation"),
      ex(/^resumption with(out)? alpn( change)?$/,
         ["session_id == srv_hello.session_id", "no_application_protocol"],
         "sessionCache")] },
  { script: "test-ccs.py" },
  { script: "test-certificate-malformed.py", on: CR, certificate: "rsa",
    exceptions: [ex(/^fuzz empty certificate/, "decode_error",
                    "alertChoice")] },
  { script: "test-certificate-request.py", on: CR,
    args: ["-s", SIGALGS_12, "-T", "rsa_sign ecdsa_sign"] },
  { script: "test-certificate-verify.py", on: CR, certificate: "rsa" },
  { script: "test-certificate-verify-malformed.py", on: CR,
    certificate: "rsa" },
  { script: "test-certificate-verify-malformed-sig.py", on: CR,
    certificate: "rsa",
    exceptions: [ex(/sha1|SHA-1/, "illegal_parameter", "sha1Envelope")] },
  { script: "test-client-compatibility.py", args: ["-n", "0"],
    exceptions: [ex(/./, REFUSED_OLD, "oldVersion", { reason:
      WHY.oldVersion.reason + " — the replayed hellos of 2013-era " +
      "browsers, crawlers and Java/Android runtimes that offer nothing " +
      "BCP 195 allows" })] },
  { script: "test-client-hello-max-size.py",
    exceptions: [ex("max client hello", "Can't represent value",
                    "overflow")] },
  { script: "test-clienthello-md5.py" },
  { script: "test-connection-abort.py" },
  { script: "test-conversation.py" },
  { script: "test-cve-2004-0079.py" },
  { script: "test-cve-2016-6309.py" },
  { script: "test-downgrade-protection.py",
    args: ["--server-max-protocol=TLSv1.3"],
    exceptions: [ex(OLD, REFUSED_OLD, "oldVersion")] },
  { script: "test-early-application-data.py" },
  { script: "test-ecdhe-padded-shared-secret.py", args: ["-n", "0"],
    exceptions: [ex(OLD, REFUSED_OLD, "oldVersion"),
                 ex(/in SSLv2 compatible ClientHello/, "handshake_failure",
                    "sslv2Hello")] },
  { script: "test-ecdhe-rsa-key-exchange.py" },
  { script: "test-ecdhe-rsa-key-exchange-with-bad-messages.py" },
  { script: "test-ecdhe-rsa-key-share-random.py",
    exceptions: [ex(OLD, REFUSED_OLD, "oldVersion"),
                 ex(/in SSLv2 compatible ClientHello/, "handshake_failure",
                    "sslv2Hello")] },
  { script: "test-ecdsa-in-certificate-verify.py", on: CR,
    certificate: "ec",
    exceptions: [ex(/sha1\+ecdsa/, "illegal_parameter", "sha1Envelope"),
                 ex(/sha224\+ecdsa/, "handshake_failure", "noSha224")] },
  { script: "test-eddsa-in-certificate-verify.py", on: CR,
    certificate: "ed25519" },
  { script: "test-empty-extensions.py" },
  { script: "test-export-ciphers-rejected.py", refusal: true,
    exceptions: [ex(/./, REFUSED_OLD, "noDhe", { why: "design", reason:
      "RUN AS A REFUSAL: no export suite, and no CBC suite for the " +
      "script's AES_128 fallback either, so every hello is refused — " +
      "handshake_failure in TLS 1.2, protocol_version below it" })] },
  { script: "test-extended-master-secret-extension.py",
    exceptions: [
      ex(/renegotiat/, "no_renegotiation", "renegotiation"),
      ex(/^EMS with session resume/, ["session_id == srv_hello.session_id",
         "server_hello"], "sessionCache"),
      ex(/TLSv1\.1/, REFUSED_OLD, "oldVersion")] },
  { script: "test-extended-master-secret-extension-with-client-cert.py",
    on: CR, certificate: "rsa",
    exceptions: [ex("resume with certificate and EMS",
                    "session_id == srv_hello", "sessionCache")] },
  { script: "test-extensions.py",
    exceptions: [ex(/^16383 extensions/, "Can't represent value",
                    "overflow")] },
  { script: "test-fallback-scsv.py", args: ["--tls-1.3"],
    exceptions: [ex(/TLSv1\.[01]|SSL3\.0/, REFUSED_OLD, "oldVersion")] },
  { script: "test-fuzzed-ciphertext.py" },
  { script: "test-fuzzed-finished.py" },
  { script: "test-hello-request-by-client.py" },
  { script: "test-interleaved-CKE-with-CCS.py" },
  { script: "test-invalid-cipher-suites.py" },
  { script: "test-invalid-client-hello.py" },
  { script: "test-invalid-client-hello-w-record-overflow.py" },
  { script: "test-invalid-compression-methods.py" },
  { script: "test-invalid-content-type.py" },
  { script: "test-invalid-server-name-extension.py",
    exceptions: [ex(/^sanity$|^Sanity check, SNI$/, "\"illegal_parameter\"",
                    "levelZeroAlert", { on: ["ldaps"] }),
                 ex(/SNI|hostname|host_name/,
                    ["server_hello", "decode_error", "unrecognized_name"],
                    "sniParse")] },
  { script: "test-invalid-server-name-extension-resumption.py",
    exceptions: [ex(/^sanity$|^Sanity check, SNI$/, "\"illegal_parameter\"",
                    "levelZeroAlert", { on: ["ldaps"] }),
                 ex(/bad SNI|malformed SNI/, "unrecognized_name",
                    "sniParse")] },
  { script: "test-invalid-session-id.py" },
  { script: "test-invalid-version.py" },
  { script: "test-large-hello.py", timeoutMs: 1800000,
    exceptions: [ex(/./, "Can't represent value", "overflow")] },
  { script: "test-large-number-of-extensions.py",
    exceptions: [ex(/^16383 extensions/, "Can't represent value",
                    "overflow")] },
  { script: "test-legacy-renegotiation.py",
    exceptions: [ex(/renegotiat/, "no_renegotiation", "renegotiation")] },
  { script: "test-message-duplication.py" },
  { script: "test-message-skipping.py" },
  { script: "test-no-heartbeat.py" },
  { script: "test-no-mlkem-in-old-tls.py" },
  { script: "test-ocsp-stapling.py", args: ["--no-status"],
    exceptions: [ex(/^renegotiate/, "no_renegotiation", "renegotiation")] },
  { script: "test-openssl-3712.py",
    exceptions: [ex("weaved app data and handshake proto",
                    "no_renegotiation", "renegotiation")] },
  { script: "test-point-extension.py", args: ["--ec-point-f", "0:1:2"],
    exceptions: [ex(/hybrid encoding|compressed encoding|code point missing/,
                    ["Timeout", "server_hello"], "pointFormats")] },
  { script: "test-record-layer-fragmentation.py",
    exceptions: [ex(/^maximum size/, "Can't represent value",
                    "overflow")] },
  { script: "test-renegotiation-disabled.py" },
  { script: "test-renegotiation-disabled-client-cert.py", on: CR,
    certificate: "rsa",
    // tlsfuzzer's own run excludes these two too: they renegotiate from a
    // handshake that did not expect a CertificateRequest.
    exceptions: [
      Object.assign({ exclude: true, probe: "try insecure (legacy) " +
                      "renegotiation" }, WHY.renegotiation),
      Object.assign({ exclude: true, probe: "try secure renegotiation" },
                    WHY.renegotiation)] },
  { script: "test-rsa-pss-sigs-on-certificate-verify.py", on: CR,
    certificate: "rsa",
    exceptions: [ex(/^rsa_pss_pss_sha\d+ in CertificateVerify with rsa key$/,
                    "illegal_parameter", "schemeBeforeSignature")] },
  { script: "test-rsa-sigs-on-certificate-verify.py", on: CR,
    certificate: "rsa",
    exceptions: [ex(/sha1/, "illegal_parameter", "sha1Envelope")] },
  { script: "test-serverhello-random.py",
    exceptions: [ex(OLD, REFUSED_OLD, "oldVersion"),
                 ex(/in SSLv2 compatible ClientHello/, "handshake_failure",
                    "sslv2Hello")] },
  { script: "test-sessionID-resumption.py",
    exceptions: [ex("session ID resume", "session_id == srv_hello",
                    "sessionCache")] },
  { script: "test-session-ticket-resumption.py",
    args: ["--no-new-ticket-on-resumption"],
    exceptions: [ex(/renegotiation/, "no_renegotiation",
                    "renegotiation")] },
  { script: "test-sig-algs.py",
    exceptions: [ex(/^rsa_pss_pss_sha\d+ only$/, "handshake_failure",
                    "rsaKey")] },
  { script: "test-sig-algs-renegotiation-resumption.py",
    exceptions: [
      ex(/renegotiation/, "no_renegotiation", "renegotiation"),
      ex(/sha1|sha-1/, "handshake_failure", "noSha1"),
      ex("without signature_algorithms ext", "server_hello",
         "addedSigAlgs")] },
  { script: "test-signature-algorithms.py",
    exceptions: [ex("explicit SHA-1+RSA/ECDSA", "handshake_failure",
                    "noSha1")] },
  { script: "test-ssl-death-alert.py" },
  { script: "test-sslv2-connection.py" },
  { script: "test-sslv2-force-cipher-3des.py" },
  { script: "test-sslv2-force-cipher-non3des.py" },
  { script: "test-sslv2-force-cipher.py" },
  { script: "test-sslv2-force-export-cipher.py" },
  { script: "test-sslv2hello-protocol.py", args: ["--no-ssl2"],
    exceptions: [ex(/^Empty SSLv2 record/, "Unexpected closure",
                    "emptySslv2")] },
  { script: "test-tls13-0rtt-garbage.py" },
  { script: "test-tls13-ccs.py" },
  { script: "test-tls13-certificate-request.py", on: CR,
    args: ["-s", SIGALGS_13],
    exceptions: [ex("verify extensions in CertificateRequest",
                    "unexpected extension(s): 47", "certAuthorities")] },
  { script: "test-tls13-certificate-verify.py", on: CR, certificate: "rsa",
    args: ["-s", SIGALGS_13] },
  { script: "test-tls13-connection-abort.py" },
  { script: "test-tls13-conversation.py" },
  { script: "test-tls13-count-tickets.py", args: ["-t", "2"] },
  { script: "test-tls13-crfg-curves.py",
    exceptions: [ex(/^empty x(25519|448) key share$/, "decode_error",
                    "alertChoice")] },
  { script: "test-tls13-dhe-shared-secret-padding.py",
    exceptions: [ex(/ffdhe/, "handshake_failure", "noFfdhe")] },
  { script: "test-tls13-ecdhe-curves.py" },
  // RUN AS A REFUSAL, AND THE REGRESSION CHECK FOR THE CRASH #212 FOUND:
  // with brainpool offered, the first probe of this script took the service
  // down (SIGSEGV in node's getPeerCertificate()). Every probe must now be
  // refused in the handshake, and the service must still be there after.
  { script: "test-tls13-ecdsa-brainpool-in-certificate-verify.py", on: CR,
    certificate: "brainpool", args: ["-s", SIGALGS_13], refusal: true,
    exceptions: [ex(/./, ["illegal_parameter", "handshake_failure",
                          "Unexpected closure"], "brainpoolRefused")] },
  { script: "test-tls13-ecdsa-in-certificate-verify.py", on: CR,
    certificate: "ec", args: ["-s", SIGALGS_13] },
  { script: "test-tls13-eddsa-in-certificate-verify.py", on: CR,
    certificate: "ed25519", args: ["-s", SIGALGS_13] },
  { script: "test-tls13-empty-alert.py" },
  { script: "test-tls13-finished.py",
    exceptions: [ex(/^padding - /, "illegal_parameter", "alertChoice")] },
  { script: "test-tls13-finished-plaintext.py" },
  { script: "test-tls13-hrr.py" },
  { script: "test-tls13-invalid-ciphers.py" },
  { script: "test-tls13-keyshare-omitted.py" },
  { script: "test-tls13-keyupdate.py",
    exceptions: [ex("app data split, conversation with KeyUpdate msg",
                    "Timeout", "keyUpdateLazy"),
                 ex("large KeyUpdate message", "illegal_parameter",
                    "alertChoice")] },
  { script: "test-tls13-large-number-of-extensions.py",
    args: ["--supgroup"] },
  { script: "test-tls13-legacy-version.py",
    exceptions: [ex("version (3, 0)", "handshake_failure",
                    "legacyVersion")] },
  { script: "test-tls13-mldsa-in-certificate-verify.py", on: CR,
    certificate: "mldsa", args: ["-s", SIGALGS_13] },
  { script: "test-tls13-mlkem.py",
    exceptions: [ex(/mlkem\d+: invalid ECDH point format: hybrid$/,
                    "server_hello", "hybridPointMlkem")] },
  { script: "test-tls13-multiple-ccs-messages.py",
    exceptions: [ex(/CCS/, ["decode_error", "Unexpected closure",
                            "BrokenPipe"], "recordVersion")] },
  { script: "test-tls13-nociphers.py" },
  { script: "test-tls13-no-unknown-groups.py", args: ["--groups", GROUPS] },
  { script: "test-tls13-obsolete-curves.py",
    args: ["--relaxed", "-a", "handshake_failure"] },
  { script: "test-tls13-pkcs-signature.py" },
  { script: "test-tls13-record-layer-limits.py",
    exceptions: [
      ex(/^too big plaintext/, "ApplicationData", "paddedRecord"),
      ex(/^max size of Finished msg/, "Timeout", "paddedRecord"),
      ex(/^max size payload/, "illegal_parameter", "alertChoice")] },
  { script: "test-tls13-record-padding.py" },
  { script: "test-tls13-rsa-signatures.py" },
  { script: "test-tls13-serverhello-random.py",
    exceptions: [ex(/ffdhe/, "handshake_failure", "noFfdhe")] },
  { script: "test-tls13-session-resumption.py",
    exceptions: [
      ex(/^session resumption( - PSK_WITH_DHE)?$/, "ApplicationData",
         "noTicketAfterResumption"),
      ex("session resumption - PSK_ONLY", "pre_shared_key", "noPskKe"),
      ex("use TLS 1.2 ticket in TLS 1.3", "decode_error", "ticketAsPsk")] },
  { script: "test-tls13-shuffled-extentions.py",
    exceptions: [ex(/^HRR reversed order/, "server_hello",
                    "secondHelloOrder")] },
  { script: "test-tls13-signature-algorithms.py" },
  { script: "test-tls13-symetric-ciphers.py",
    exceptions: [ex(/CCM/, "handshake_failure", "noCcm")] },
  { script: "test-tls13-unencrypted-alert.py" },
  { script: "test-tls13-unrecognised-groups.py",
    exceptions: [ex(/ffdhe2048/, "handshake_failure", "noFfdhe")] },
  { script: "test-tls13-version-negotiation.py",
    exceptions: [ex(/ to 1\.[01]$/, REFUSED_OLD, "oldVersion")] },
  { script: "test-tls13-zero-content-type.py" },
  { script: "test-tls13-zero-length-data.py" },
  { script: "test-truncating-of-client-hello.py",
    exceptions: [
      ex(/^max pad/, "Can't represent value", "overflow"),
      ex(/^hello truncate|^huge pad/, ["handshake_failure",
         "illegal_parameter"], "alertChoice")] },
  { script: "test-truncating-of-finished.py" },
  { script: "test-unsupported-curve-fallback.py",
    exceptions: [ex("check for unsupported curve fallback",
                    "handshake_failure", "noDhe")] },
  { script: "test-version-numbers.py" },
  { script: "test-x25519.py",
    exceptions: [
      ex(/^empty x(25519|448) key share$/, "illegal_parameter",
         "alertChoice"),
      ex("default to P-256 when no groups specified", "Server picked curve",
         "defaultCurve"),
      ex("default to P-256/sha-1 when no extensions specified",
         "Server picked curve", "addedSigAlgs"),
      ex(/fallback to DHE$/, "handshake_failure", "noDhe")] },
  { script: "test-zero-length-data.py" }
];

// ---------------------------------------------------------------------------
// The command line for one script on one listener.
// ---------------------------------------------------------------------------
function argsFor(entry, listener, target) {
  log.debug("Entering argsFor(). " + entry.script + " " + listener);
  const argv = [ADAPTER].concat(LISTENERS[listener].flags);
  // Every script: the swap touches TLS 1.2 suites only, and a TLS 1.3
  // script's fallback probes offer those too.
  argv.push("--tls12-aead");
  argv.push(path.join(TLSFUZZER_DIR, "tlsfuzzer", "scripts", entry.script),
            "-h", target.host, "-p", String(target.port));
  (entry.args || []).forEach(function (one) {
    argv.push(one);
  });
  if (entry.certificate) {
    const pair = target.certificates && target.certificates[entry.certificate];
    if (!pair) {
      log.debug("Leaving argsFor(). No " + entry.certificate + " pair.");
      throw new Error(entry.script + " needs a " + entry.certificate +
                      " client certificate and none was made");
    }
    argv.push("-k", pair.key, "-c", pair.cert);
  }
  exceptionsFor(entry, listener).filter(function (one) {
    return one.exclude;
  }).forEach(function (one) {
    argv.push("-e", one.probe);
  });
  log.debug("Leaving argsFor().");
  return argv;
}

// The exceptions that apply on this listener.
function exceptionsFor(entry, listener) {
  log.debug("Entering exceptionsFor().");
  log.debug("Leaving exceptionsFor().");
  return (entry.exceptions || []).filter(function (one) {
    return !one.on || one.on.indexOf(listener) >= 0;
  });
}

// Whether a script runs on this listener at all.
function appliesTo(entry, listener) {
  log.debug("Entering appliesTo().");
  log.debug("Leaving appliesTo().");
  return !entry.skip && (!entry.on || entry.on.indexOf(listener) >= 0);
}

// The text tlsfuzzer printed for one failed probe: from the line that
// starts it ("name ..." or "\"name\" repeat N...") to the next probe's.
function probeBlock(out, name) {
  log.debug("Entering probeBlock().");
  const lines = out.split("\n");
  const blocks = [];
  let current = null;
  lines.forEach(function (l) {
    const starts = / \.\.\.$/.test(l) || /" repeat \d+\.\.\.$/.test(l);
    if (starts) {
      current = { head: l, text: [] };
      blocks.push(current);
    } else if (current) {
      current.text.push(l);
    }
  });
  const mine = blocks.filter(function (b) {
    return b.head === name + " ..." ||
      b.head.indexOf("\"" + name + "\" repeat") === 0;
  });
  log.debug("Leaving probeBlock(). " + mine.length);
  return mine.map(function (b) {
    return b.text.join("\n");
  }).join("\n");
}

// Every failed probe, each either explained by an exception of this entry
// on this listener — its name matches and its failure text carries the
// alert the exception names — or unexplained.
function classify(entry, listener, out, failed) {
  log.debug("Entering classify().");
  const exceptions = exceptionsFor(entry, listener).filter(function (one) {
    return !one.exclude;
  });
  const seen = new Set();
  const unexplained = [];
  const explained = [];
  Array.from(new Set(failed)).forEach(function (name) {
    const text = probeBlock(out, name);
    const hit = exceptions.find(function (one) {
      const named = one.probe instanceof RegExp ? one.probe.test(name)
                                                : one.probe === name;
      const alerts = [].concat(one.alert);
      return named && alerts.some(function (a) {
        return text.indexOf(a) >= 0;
      });
    });
    if (hit) {
      seen.add(hit);
      explained.push({ probe: name, why: hit.why, reason: hit.reason });
    } else {
      const last = (text.match(/^(?:AssertionError|\w+Error)\b.*$/gm) ||
                    [text.trim().split("\n").pop() || "no output"]).pop();
      unexplained.push(name + ": " + last);
    }
  });
  const unseen = exceptions.filter(function (one) {
    return !seen.has(one);
  }).map(function (one) {
    return String(one.probe);
  });
  log.debug("Leaving classify().");
  return { explained: explained, unexplained: unexplained, unseen: unseen };
}

// The summary block every tlsfuzzer script prints last.
function summarise(out) {
  log.debug("Entering summarise().");
  const counts = {};
  ["TOTAL", "SKIP", "PASS", "XFAIL", "FAIL", "XPASS"].forEach(function (k) {
    const m = new RegExp("^" + k + ":\\s*(\\d+)\\s*$", "m").exec(out);
    counts[k.toLowerCase()] = m ? Number(m[1]) : null;
  });
  const failed = /^FAILED:\n((?:\t.*\n?)+)/m.exec(out);
  // Each name is printed quoted, 'like this' (or "like this" when it has
  // an apostrophe of its own).
  const unquote = function (l) {
    log.debug("Entering unquote().");
    log.debug("Leaving unquote().");
    return l.trim().replace(/^'(.*)'$/, "$1").replace(/^"(.*)"$/, "$1");
  };
  counts.failed = failed
    ? failed[1].split("\n").map(unquote).filter(Boolean) : [];
  const xpassed = /^XPASSED:\n((?:\t.*\n?)+)/m.exec(out);
  counts.xpassed = xpassed
    ? xpassed[1].split("\n").map(unquote).filter(Boolean) : [];
  log.debug("Leaving summarise().");
  return counts;
}

// One script, asynchronously and with a bound: a spawnSync would hold the
// event loop of the in-process file for as long as the script runs.
function runScript(entry, listener, target) {
  log.debug("Entering runScript(). " + entry.script);
  const argv = argsFor(entry, listener, target);
  const python = path.join(TLSFUZZER_DIR, "venv", "bin", "python");
  const env = Object.assign({}, process.env, {
    PYTHONPATH: [path.join(TLSFUZZER_DIR, "tlsfuzzer"),
                 path.join(TLSFUZZER_DIR, "tlslite-ng")].join(path.delimiter),
    PYTHONUNBUFFERED: "1"
  });
  const bound = entry.timeoutMs || 900000;
  log.debug("Leaving runScript().");
  return new Promise(function (resolve) {
    const started = Date.now();
    const child = childProcess.spawn(python, argv,
      { cwd: path.join(TLSFUZZER_DIR, "tlsfuzzer"), env: env,
        stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", function (chunk) {
      out += chunk;
    });
    child.stderr.on("data", function (chunk) {
      out += chunk;
    });
    const timer = setTimeout(function () {
      child.kill("SIGKILL");
    }, bound);
    child.on("error", function (e) {
      log.debug("Caught in runScript(): " + ((e && e.message) || e));
      out += "\n[could not start " + python + ": " + e.message + "]";
    });
    child.on("close", function (code, signal) {
      clearTimeout(timer);
      const counts = summarise(out);
      const verdict = classify(entry, listener, out, counts.failed);
      // Passed: a summary, nothing unexpectedly passing, and every failed
      // probe explained. A script with failures exits 1, so the exit code
      // is read only where nothing failed.
      const ok = counts.total !== null && counts.xpass === 0 &&
        verdict.unexplained.length === 0 &&
        (counts.fail > 0 || code === 0);
      resolve({ script: entry.script, listener: listener, code: code,
                verdict: verdict,
                signal: signal, seconds: Math.round((Date.now() - started) /
                                                    1000),
                counts: counts, ok: ok, output: out,
                command: ["python"].concat(argv).join(" ") });
    });
  });
}

// ---------------------------------------------------------------------------
// The whole plan against one listener, `concurrency` scripts at a time.
// `only` narrows it to scripts whose names contain one of its strings.
// ---------------------------------------------------------------------------
async function runPlan(target, listener, options) {
  log.debug("Entering runPlan(). " + listener);
  const opts = options || {};
  const entries = PLAN.filter(function (entry) {
    return appliesTo(entry, listener) &&
      (!entry.certificate || LISTENERS[listener].requestsCertificate) &&
      (!opts.only || !opts.only.length || opts.only.some(function (o) {
        return entry.script.indexOf(o) >= 0;
      }));
  });
  const results = [];
  let next = 0;
  async function worker() {
    log.debug("Entering worker().");
    while (next < entries.length) {
      const entry = entries[next];
      next += 1;
      const r = await runScript(entry, listener, target);
      (opts.onResult || function () {})(r);
      results.push(r);
    }
    log.debug("Leaving worker().");
  }
  const workers = [];
  for (let i = 0; i < (opts.concurrency || 6); i += 1) {
    workers.push(worker());
  }
  await Promise.all(workers);
  log.debug("Leaving runPlan(). " + results.length + " script(s)");
  return results;
}

// The one line a result is reported as.
function line(r) {
  log.debug("Entering line().");
  const c = r.counts;
  log.debug("Leaving line().");
  const v = r.verdict;
  return (r.ok ? "[ok] " : "[FAILED] ") + r.listener + " " + r.script +
    " — " + (c.total === null ? "no summary" : c.pass + " passed, " +
    v.explained.length + " failed as documented, " + c.skip +
    " skipped, " + v.unexplained.length + " unexplained, " + c.xpass +
    " unexpectedly passed") + " (" + r.seconds + " s" +
    (r.code !== 0 ? ", exit " + r.code : "") + ")" +
    (v.unexplained.length ? "\n      UNEXPLAINED: " +
      v.unexplained.slice(0, 20).join("\n      UNEXPLAINED: ") : "") +
    (v.unseen.length ? "\n      (exception not seen this run: " +
      v.unseen.join(" | ") + ")" : "");
}

// What is not run, and why — logged by each job so the record is in its
// output as well as here.
function notApplicable(listener) {
  log.debug("Entering notApplicable().");
  log.debug("Leaving notApplicable().");
  return PLAN.filter(function (entry) {
    return !!entry.skip || (listener && entry.on &&
                            entry.on.indexOf(listener) < 0);
  }).map(function (entry) {
    return { script: entry.script, reason: entry.skip ||
             (entry.notOn && entry.notOn[listener]) ||
             (entry.certificate || entry.on === CR ? NOT_CR : "") };
  });
}

module.exports = {
  PLAN: PLAN,
  LISTENERS: LISTENERS,
  TLSFUZZER_DIR: TLSFUZZER_DIR,
  argsFor: argsFor,
  runPlan: runPlan,
  line: line,
  notApplicable: notApplicable,
  summarise: summarise,
  classify: classify,
  WHY: WHY
};

// ---------------------------------------------------------------------------
// BY HAND: node tests/vendored/tlsfuzzer_kit.js <listener> <host> <port>
//   [script-substring...] — with STS_TLSFUZZER_DIR pointing at a tree
// build-tlsfuzzer.sh made, and STS_TLSFUZZER_CERTS at a directory holding
// <kind>.key and <kind>.crt for each client certificate the plan names.
// ---------------------------------------------------------------------------
if (require.main === module) {
  const [listener, host, port, ...only] = process.argv.slice(2);
  const certDir = process.env.STS_TLSFUZZER_CERTS || "";
  const certificates = {};
  if (certDir) {
    fs.readdirSync(certDir).filter(function (f) {
      return /\.key$/.test(f);
    }).forEach(function (f) {
      const kind = f.replace(/\.key$/, "");
      certificates[kind] = { key: path.join(certDir, f),
                             cert: path.join(certDir, kind + ".crt") };
    });
  }
  runPlan({ host: host, port: Number(port), certificates: certificates },
          listener, { only: only, concurrency: Number(process.env
            .STS_TLSFUZZER_CONCURRENCY || 6),
          onResult: function (r) {
            process.stdout.write(line(r) + "\n");
            if (!r.ok && process.env.STS_TLSFUZZER_OUT) {
              fs.writeFileSync(path.join(process.env.STS_TLSFUZZER_OUT,
                listener + "-" + r.script + ".log"), r.command + "\n" +
                r.output);
            }
          } })
    .then(function (results) {
      const bad = results.filter(function (r) {
        return !r.ok;
      });
      process.stdout.write(results.length + " script(s), " + bad.length +
                           " failed\n");
      process.exit(bad.length ? 1 : 0);
    });
}
