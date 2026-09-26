// @ts-check
'use strict';
//
// File: pki.js
//
// ===========================================================================
// A CERTIFICATE AUTHORITY THIS SERVICE MAINTAINS: ONE ROOT, AN INTERMEDIATE
// PER TRUST REALM (since 2026-09-11 — see THE SHAPE OF THE HIERARCHY below).
//
// **WHAT IT WAS FOR FIRST, IN ONE SENTENCE**: RFC 7521 and RFC 7523 let an
// application authenticate with a signed assertion instead of a shared secret,
// and a signing key that nobody vouched for is a key an operator has to move
// by hand. This was the other half — a Root CA, an Intermediate CA and an
// Issuing CA that this service builds and keeps, and a signing key pair per
// application issued from the bottom of it. Every key pair this service
// generates is a leaf of it now (the use cases below).
//
// ---------------------------------------------------------------------------
// THREE TIERS, BUILT IN ONE ACT, AND THAT IS NOT LAZINESS.
//
// A trust chain is only worth anything WHOLE: an Issuing CA with no
// Intermediate above it is a two-tier chain wearing a three-tier name, and a
// half-built hierarchy is exactly the state in which somebody issues a
// certificate that verifies here and nowhere else. So `buildChain()` makes all
// three or none, and a second call REPLACES the hierarchy rather than adding to
// it — with everything already issued from the old one saying so, because a
// leaf whose issuer is gone is a leaf that stopped verifying and there is no
// honest way to hide that.
//
// The three tiers are the debugger's own `root-ca`, `intermediate-ca` and
// `issuing-ca` PROFILES, taken from `common/vendored/x509.js` rather than
// written out again — same `pathLen` (null, 1, 0), same key usages, same
// default lifetimes. That module is byte-identical to the parent project's, so
// a certificate issued here and one issued on that project's PKI / X.509 page
// are built by ONE encoder, and a difference between them is a difference in
// the arguments rather than in two implementations that drifted.
//
// ---------------------------------------------------------------------------
// WHERE THE PRIVATE KEYS LIVE, AND WHY IT IS NOT A STORE OF THIS MODULE'S OWN.
//
// In `sts_keys`, in the realm's own row, beside the signing keys this service
// already keeps there — sealed under the same key-encryption key, read back by
// the same `keystore.start()`, and shared across the request-worker pool over
// the same IPC channel. `keystore.attachPki()` is the whole of the mechanism
// and its header argues it.
//
// **SO IT INHERITS THE MODE, WHICH IS THE HONEST ANSWER RATHER THAN A GAP.** In
// PRODUCT mode the hierarchy survives a restart, because the keystore persists.
// In DEVELOPMENT mode — the default — it lives exactly as long as the process
// does, which is the same rule the signing key follows and for the same reason:
// a mock is disposable and its credentials are meant to die with it. A page
// that promised otherwise would be promising on behalf of a mode it is not in.
//
// **AND THE ROW IS PER REALM**, declared per realm AT ITS DECLARATION as rule 2
// of the realm design requires (`common/realms.js`). The AUTHORITY is not: the
// Root is shared and the realm boundary is each realm's own Intermediate —
// THE SHAPE OF THE HIERARCHY below records the reversal of the sentence that
// stood here.
//
// ---------------------------------------------------------------------------
// WHAT IS HANDED OUT AND WHAT NEVER IS.
//
// A CA's private key never leaves this module. What leaves is a LEAF: a key
// pair generated for one application, its certificate, and the chain above it —
// handed back ONCE, at issuance, and written onto that application's entry.
// After that this module holds no copy, because holding one would make
// `ou=applications` and this module two answers to "what is that client's
// signing key" and the second one unreadable.
//
// A LIBRARY (rule 3): it registers no route. It requires `config`, `crypto`,
// `keystore`, `realms`, `error_codes`, `cluster/cluster_capabilities`, `pkijs`
// and four vendored modules (`x509`, `key_material`, `pqc_x509`, `pqc`) —
// none of which requires it back — so it is a LEAF and anything here may
// require it.
// ===========================================================================

// A LOGGER OF ITS OWN rather than helpers.js's, for `keystore.js`'s reason one
// file along: this module is required by `oauth-oidc/assertion_grant.js`, which
// is on the token endpoint's path, and a require of `helpers.js` here would put
// the whole key-set proxy behind a module whose only job is certificates.
// `crypto.js`, `config.js` and `keystore.js` all make their own for the same
// reason.
const bunyan = require('bunyan');
const config = require('./config');

const log = bunyan.createLogger({
  name: 'pki',
  level: config.value('global.logLevel')
});

const nodeCrypto = require('crypto');
// THE ONE PLACE THIS SERVICE SIGNS AND HASHES. Used here for the thumbprint and
// the JWK canonicalisation only — the certificate encoding is the vendored
// module's, which is the point of vendoring it.
const stsCrypto = require('./crypto');
const keystore = require('./keystore');
const realms = require('./realms');
// The error-code registry, a LEAF that requires nothing here. A refusal this
// module RETURNS carries its code NON-ENUMERABLY through `mark()` — these
// results are serialised to `/admin-api` clients whole, and a code must never
// reach a client — and `errorCodes.codeOf(result)` reads it back. A failure
// with no caller to hand it to is `tag()`ged onto its log line instead: this
// module does not require `audit.js`, for the leaf rule above.
const errorCodes = require('./error_codes');
// THE MODE, for SHA-1 certificate signatures, which are development's (#181).
// A LEAF (`config` and `error_codes` only), so no cycle.
const mode = require('./mode');
// THE ISSUED REGISTER'S DISPLACED RECORD (#185), shared with the cluster
// merge. A LEAF (`config` and bunyan), already in the parent project's
// Kerberos COPY closure through `keystore.js`, which requires it at load.
const pkiMerge = require('./pki_merge');
// The debugger's own PKI code, byte-identical. DO NOT EDIT THEM HERE — see
// `common/vendored/CLAUDE.md`.
const x509 = require('./vendored/x509');
const keyMaterial = require('./vendored/key_material');
// The X.509 binding of the post-quantum algorithms, and the algorithm table it
// rests on — for ONE thing: writing the SubjectPublicKeyInfo of a
// post-quantum JOSE key this service holds, so that key can be certified.
// See `PQ_JOSE_IN_X509` below for what may cross and what may not.
const pqcX509 = require('./vendored/pqc_x509');
const pqc = require('./vendored/pqc');
// An npm leaf, for one reading node cannot make: the SubjectPublicKeyInfo of a
// certificate whose key OpenSSL does not parse, which `certificateHoldsKey()`
// compares against a registered post-quantum JWK.
const pkijs = require('pkijs');
// The DER reader pkijs is built on, for the two sigstore extensions pkijs
// does not parse itself (#170).
const asn1js = require('asn1js');
// The table of what active-active mode depends on, for `pki.agreement` (at the
// bottom of this file). A LEAF over config and bunyan.
const capabilities = require('../cluster/cluster_capabilities');

// ---------------------------------------------------------------------------
// THE THREE TIERS. The `profile` names an entry in the vendored module's
// PROFILES table, which is where the basicConstraints, the key usages and the
// default lifetime come from — so a change to what an Intermediate CA IS
// happens in one place and reaches the debugger's page and this one together.
//
// `order` is the position from the ROOT downwards, which is the order they are
// built in and the reverse of the order they are sent in a chain. Both
// spellings exist in the wild and getting them the wrong way round produces a
// chain that every validator refuses with a message about the leaf.
// ---------------------------------------------------------------------------
const TIERS = [
  { id: 'root', order: 0, profile: 'root-ca', label: 'Root CA',
    what: 'The trust anchor. Self-signed, the longest-lived of the three, ' +
          'and the only certificate in the hierarchy a relying party has to ' +
          'be given out of band — everything below it travels in the chain.' },
  { id: 'intermediate', order: 1, profile: 'intermediate-ca',
    label: 'Intermediate CA',
    what: 'Signed by the Root. It exists so that the Root\'s key can be used ' +
          'once and then left alone: a compromise here is repaired by ' +
          'reissuing this tier, and a compromise of the Root is not repaired ' +
          'at all. pathLen is 1, so it may sign one more CA and no deeper.' },
  { id: 'issuing', order: 2, profile: 'issuing-ca', label: 'Issuing CA',
    what: 'Signed by the Intermediate, and the only tier that signs anything ' +
          'this service hands out. pathLen is 0 — it signs LEAVES and no ' +
          'further CA, which is what makes "an application certificate ' +
          'cannot be used to mint another" a property of the encoding rather ' +
          'than of this service\'s manners.' }
];

const TIER_IDS = TIERS.map(function (one) { return one.id; });

// ===========================================================================
// THE SHAPE OF THE HIERARCHY (2026-09-11), AND THE SENTENCE IT REVERSED.
//
// Until this date the three tiers were PER REALM and this file said, at
// length, that a CA shared across realms would be "one authority vouching for
// several identity services, which is the one thing a realm boundary exists to
// prevent". **That is reversed deliberately and by request**, and what replaces
// it is not a weaker claim but a different one:
//
//        Root CA                          ONE, service-wide
//        ├── Intermediate — process       for what belongs to no realm
//        │    └── Issuing: TLS
//        ├── Intermediate — realm ""      the default realm
//        │    ├── Issuing: JOSE signing
//        │    ├── Issuing: XML signing
//        │    ├── Issuing: application assertions
//        │    └── …SPIFFE, remote PEP TLS, ACME, EST, SCEP, TLS client
//        │         (USE_CASES below; SPIFFE moved here from the process
//        │         branch, and the other five arrived on 2026-09-13)
//        └── Intermediate — realm acme    …and one per realm, unique
//
// **THE BOUNDARY MOVED DOWN A TIER AND IT HAD TO BE MOVED IN CODE AS WELL.**
// With one Root, "this certificate chains to our Root" is true of every realm's
// leaves, so it stopped being a realm boundary the moment the Root was shared.
// `verifyLeaf()` therefore requires the path to pass through THIS SCOPE'S OWN
// INTERMEDIATE, and a leaf from another realm is refused there rather than
// being accepted by an anchor check that is now too weak. That is the single
// most important consequence of this change: **an anchor test that was a
// boundary became an anchor test that is not one**, and a reader who assumed
// the old rule still held would have written a check that passes for every
// certificate this service has ever issued.
//
// What the shared Root buys is what was asked for: one trust anchor an
// operator installs once, under which every key this service holds — in every
// realm, for every use case — is a leaf with a path.
// ===========================================================================

// The two rows that are not a realm's. A realm id is `[a-z0-9-]` and must
// start with a letter or a digit (`realms.js` enforces it), so a leading `*`
// cannot collide with one — which is what lets these share `keystore`'s one
// `pki:` row family rather than needing a table of their own.
const SERVICE_SCOPE = '*service';
const PROCESS_SCOPE = '*process';

// ---------------------------------------------------------------------------
// THE USE CASES: ONE ISSUING CA EACH.
//
// A use case is a FAMILY of key material with one reason to exist, and it gets
// an Issuing CA of its own so that an operator can narrow, reissue or replace
// one without touching the rest. Cutting them any finer — an Issuing CA per
// ALGORITHM — was considered and refused: the eleven post-quantum keys alone
// would then be eleven authorities, and what an operator actually wants to say
// is "reissue what signs my tokens", not "reissue what signs my ES384".
//
// `scope` is which Intermediate signs it, and it is a property of the KEY
// rather than a filing decision: a TLS certificate is served on a socket every
// realm answers on, so a realm's Intermediate signing it would be one realm
// vouching for every other realm's front door.
//
// **`assertions` IS THE OLD `issuing` TIER UNDER A NEW NAME**, and that is why
// the compatibility shape below still reports three tiers: everything this
// module did before this change it still does, through that use case.
// ---------------------------------------------------------------------------
const USE_CASES = [
  { id: 'jose', scope: 'realm', label: 'JOSE signing',
    cn: 'JOSE Signing CA',
    what: 'The keys this realm signs JWTs with — the RSA key behind RS256, ' +
          'the four ECDSA curves, both Edwards curves, and the eleven ' +
          'post-quantum keys when they are made. What a client verifies ' +
          'against /oauth2/jwks.' },
  { id: 'xml', scope: 'realm', label: 'XML signing',
    cn: 'XML Signing CA',
    what: 'What signs an XML document: SAML 2.0 and 1.1 assertions and ' +
          'responses, WS-Federation, WS-Trust, and the per-service-provider ' +
          'metadata. It is a SEPARATE authority from the one above even ' +
          'though one RSA key does both jobs today — a relying party that ' +
          'trusts this service for SAML has not thereby said anything about ' +
          'its OAuth tokens, and two Issuing CAs are how that is sayable.' },
  { id: 'assertions', scope: 'realm', label: 'Application assertions',
    cn: 'Application Assertion CA',
    what: 'The signing key pairs issued to APPLICATIONS for RFC 7521 and RFC ' +
          '7523 — a client assertion, or a JWT bearer authorization grant. ' +
          'This is the Issuing CA this module had before the hierarchy grew ' +
          'the others, under a name that says which of the five it is.' },
  { id: 'tls', scope: 'process', label: 'TLS listeners',
    cn: 'TLS Issuing CA',
    what: 'The certificate served on LDAPS 636, on the main port when ' +
          'global.https is on, and on the embedded debugger\'s listener — ' +
          'the 8443 and 9443 listeners this use case is still named for ' +
          'were deleted on 2026-09-16. ' +
          'PROCESS-scoped because those sockets are: one certificate answers ' +
          'every realm, so a realm\'s Intermediate signing it would make one ' +
          'realm vouch for every other realm\'s front door.' },
  // **THE ONE USE CASE WITH ROOM BENEATH IT (2026-09-11).** Every other
  // Issuing CA here signs LEAVES and nothing else, which is what `pathLen: 0`
  // in the `issuing-ca` profile says. This one signs leaves AND, for
  // `NewDownstreamX509CA` on the SPIRE Server API, one further CA — so it
  // carries `pathLen: 1` and the Intermediate above it is widened to match
  // (see `intermediatePathLen()`). Without both numbers the downstream CA
  // encodes perfectly and every path builder refuses the chain with a message
  // about path length that names neither certificate.
  // **AND THE ONE USE CASE WITH A KEY ALGORITHM OF ITS OWN**, for the reason
  // `spiffe/spiffe_ca.ts`'s header gives at length and which is why the
  // vendored encoder is here at all: EC P-256 is what SPIRE issues and what
  // the X509-SVID specification recommends, and `node-forge` — what this
  // service used before that module arrived — cannot sign with an EC key at
  // all. It is a PREFERENCE and not an override: an operator who chose an
  // algorithm for the branch, on /admin/pki or through `pki.keyAlgorithm`,
  // gets the one they chose for every Issuing CA in it including this one.
  // See `algorithmsForUseCase()`.
  { id: 'spiffe', scope: 'realm', label: 'SPIFFE authority',
    cn: 'SPIFFE Issuing CA', pathLen: 1,
    keyAlg: 'ec-p256', signatureAlg: 'sha256-ecdsa',
    what: 'The X.509 authority every X509-SVID minted in this realm is ' +
          'signed by. REALM-scoped since 2026-09-11 \u2014 it was under the ' +
          'process Intermediate, self-signed and outside this tree entirely ' +
          'before that. The trust ANCHOR is unaffected by the move and that ' +
          'is the point: the bundle publishes the service Root, which every ' +
          'realm shares, so an SVID signed by any realm\'s authority ' +
          'verifies against one anchor while its chain still says which ' +
          'realm issued it.' },
  // **THE LISTENER CERTIFICATE OF A REMOTE XACML PEP (2026-09-13).** The only
  // use case whose leaves are served by a process this service does not run,
  // and the reason it is REALM-scoped rather than beside `tls`: a remote PEP
  // registers against ONE realm's PDP and enforces that realm's policy, so the
  // authority vouching for its front door is that realm's. `tls` is
  // process-scoped because its sockets answer every realm; a PEP's answers
  // one. A leaf from here certifies `serverAuth` and nothing else, and it is
  // issued with `issueTlsServerKeyPair()` below — the one door in this module
  // that hands a SERVER private key to something that is not this service.
  { id: 'pep-tls', scope: 'realm', label: 'Remote PEP listeners',
    cn: 'Remote PEP TLS Issuing CA',
    what: 'The certificates a remote XACML Policy Enforcement Point serves ' +
          'on its HTTPS listener. REALM-scoped because a remote PEP ' +
          'registers against one realm and enforces that realm\'s policy, ' +
          'so the authority vouching for its front door is that realm\'s. ' +
          'Issued to a REGISTERED PEP from /admin/xacml/peps or POST ' +
          '/admin-api/xacml/issue-pep-certificate; the private key is ' +
          'handed over once and this service keeps no copy.' },
  // **THE THREE ENROLLMENT PROTOCOLS (2026-09-13).** One Issuing CA per
  // protocol rather than one for all three, for the reason `jose` and `xml`
  // are two: a relying party that trusts what ACME issued has said nothing
  // about what SCEP issued, and an operator who has to stop trusting one
  // protocol's certificates wants a CA to distrust and a CRL to read rather
  // than a filter over serials. What a certificate from any of them CONTAINS,
  // and for whom it may be issued, is `common/cert_enrollment.ts`'s and the
  // same for all three; `issueEnrolled()` below is the door they sign through.
  { id: 'acme', scope: 'realm', label: 'ACME enrollment',
    cn: 'ACME Issuing CA',
    what: 'Certificates issued over ACME (RFC 8555) at /enroll/acme, to a ' +
          'person or application entry an External Account Binding key was ' +
          'issued for. Every leaf names that entry in a urn:sts:person: or ' +
          'urn:sts:application: subjectAltName.' },
  { id: 'est', scope: 'realm', label: 'EST enrollment',
    cn: 'EST Issuing CA',
    what: 'Certificates issued over EST (RFC 7030) at /.well-known/est, to ' +
          'the entry a password, client secret or realm-issued client ' +
          'certificate authenticated, or — for an administrator — to the ' +
          'entry the request names. The one enrollment path on which this ' +
          'service may generate the key pair (/serverkeygen).' },
  { id: 'scep', scope: 'realm', label: 'SCEP enrollment',
    cn: 'SCEP Issuing CA',
    what: 'Certificates issued over SCEP (RFC 8894) at /enroll/scep, to the ' +
          'entry a single-use challenge password was issued for. The RA ' +
          'certificate SCEP encrypts requests to is a leaf of this CA too, ' +
          'with an RSA key because SCEP\'s key transport is RSA.' },
  // **A PERSON'S TLS CLIENT CERTIFICATE (2026-09-13).** Issued on
  // /portal/signing-key by the person it names, installed in a browser, and
  // presented to the main port — which trusts the service Root for client
  // certificates since the same day and accepts a chain through it as an
  // identity ONLY when the leaf came from THIS use case's Issuing CA (see
  // `common/tls_client_certificates.js`). That is why it is an authority of
  // its own and not the `assertions` one: "issued here" stopped being a
  // statement about identity the day the Root was trusted, and "issued by the
  // TLS client Issuing CA" is the one that still is. REALM-scoped because the
  // realm a certificate signs somebody in to is read off the authority that
  // signed it — a socket has no path to carry one.
  { id: 'tls-client', scope: 'realm', label: 'TLS client certificates',
    cn: 'TLS Client Issuing CA',
    what: 'The TLS client certificates people issue themselves on the user ' +
          'portal: clientAuth, the person\'s urn:sts:person: name, and a ' +
          'private key handed over once as a PKCS#12. A certificate from ' +
          'this authority signs its holder in at GET /tls/sign-in on the ' +
          'main port, in this ' +
          'realm; a certificate from any other authority of this service ' +
          'does not, although every one of them chains to the same Root.' }
];

const USE_CASE_IDS = USE_CASES.map(function (one) { return one.id; });

function useCase(id) {
  log.debug("Entering useCase().");
  log.debug("Leaving useCase().");
  return USE_CASES.filter(function (one) {
    return one.id === String(id || '');
  })[0] || null;
}

// The use cases an Intermediate of this kind carries. `realm` for a realm's
// own, `process` for the one beside them.
function useCasesFor(kind) {
  log.debug("Entering useCasesFor().");
  log.debug("Leaving useCasesFor().");
  return USE_CASES.filter(function (one) { return one.scope === kind; });
}

// ---------------------------------------------------------------------------
// HOW DEEP AN INTERMEDIATE HAS TO BE, WHICH IS COMPUTED RATHER THAN WRITTEN
// DOWN (2026-09-11).
//
// `intermediate-ca`'s profile says `pathLen: 1` — one more CA below it, which
// is the Issuing CA and nothing further. That was true of every use case until
// `spiffe` needed room for a downstream CA, and the fix has to be made in TWO
// places or it is made in none: widening the Issuing CA alone leaves the
// Intermediate refusing the extra level, and widening the Intermediate alone
// leaves the Issuing CA refusing it. Both numbers, or a chain that encodes
// cleanly and validates nowhere.
//
// **IT IS DERIVED FROM THE USE CASES SO THAT THE TWO CANNOT DRIFT.** A scope's
// Intermediate is one deeper than the deepest Issuing CA it carries, so adding
// a `pathLen` to a use case widens the branch that carries it AND ONLY THAT
// BRANCH: the process Intermediate holds `tls` alone and stays at 1, and a
// realm's holds `spiffe` and becomes 2. Writing the 2 in by hand would have
// widened every Intermediate in the service for one use case in one of them.
// ---------------------------------------------------------------------------
function intermediatePathLen(kind) {
  log.debug("Entering intermediatePathLen().");
  const deepest = useCasesFor(kind).reduce(function (most, one) {
    return Math.max(most, Number(one.pathLen) || 0);
  }, 0);
  log.debug("Leaving intermediatePathLen().");
  return 1 + deepest;
}

// ---------------------------------------------------------------------------
// THE ALGORITHMS ONE ISSUING CA IS BUILT WITH, which are the branch's unless
// NOBODY CHOSE and the use case prefers something else.
//
// **"NOBODY CHOSE" IS TWO TESTS AND THE SECOND ONE IS AWKWARD ON PURPOSE.** A
// build from `/admin/pki` or `/admin-api/pki/build` names its algorithms in
// the call, so a hierarchy an operator asked to be RSA-4096 is RSA-4096 all
// the way down — including the SPIFFE authority, which is what choosing one
// algorithm for your certificate authority means. `pki.keyAlgorithm` is the
// other way to say it, and it cannot be tested for presence: it has a non-empty
// DEFAULT (`rsa-2048`, beside `pki.signatureAlgorithm`, which is `""`), so
// `config.value()` is never falsy and a presence test would make this branch
// unreachable — which is exactly what the first version of this function did,
// silently, and it took an `openssl x509 -text` on a leaf to notice.
//
// So it is compared with `DEFAULT_KEY_ALG`, which is the same string the
// setting defaults to. The consequence is one stated edge: an operator who
// sets `pki.keyAlgorithm` to `rsa-2048` EXPLICITLY is indistinguishable from
// one who left it alone, and gets an EC SPIFFE authority. Naming the algorithm
// in the build is how to say it unambiguously, and that is the door the
// console uses.
//
// What the preference is FOR is the default case: out of the box an X509-SVID
// is signed ES256 by an EC P-256 authority, as it was before the SPIFFE
// authority joined this hierarchy and as SPIRE does. `spiffe/spiffe_ca.ts`'s
// header argues why that particular fidelity was worth vendoring a certificate
// encoder for.
//
// A preference that cannot be honoured falls back to the branch's rather than
// failing the build: a use case asking for an algorithm this service cannot
// generate is a defect in the table above, and a certificate authority that
// will not build is a much worse way to report one than a log line.
// ---------------------------------------------------------------------------
function algorithmsForUseCase(uc, chosen, options) {
  log.debug("Entering algorithmsForUseCase().");
  const configured = String(config.value('pki.keyAlgorithm') || '');
  if (!uc.keyAlg || options.keyAlg ||
      (configured && configured !== DEFAULT_KEY_ALG)) {
    log.debug("Leaving algorithmsForUseCase().");
    return chosen;
  }
  const preferred = algorithmsFrom({ keyAlg: uc.keyAlg,
                                     signatureAlg: uc.signatureAlg });
  if (!preferred.ok) {
    log.error(errorCodes.tag('STS-PKI-0001') + 'pki: the ' + uc.label + ' ' +
        'use case prefers "' + uc.keyAlg +
              '", which this service cannot use (' +
              preferred.errors.join(' ') + '). Building it with the ' +
              'branch\'s ' + chosen.keyAlg + ' instead.');
    log.debug("Leaving algorithmsForUseCase().");
    return chosen;
  }
  log.debug("Leaving algorithmsForUseCase().");
  return preferred;
}

// The `pathLen` an Issuing CA for this use case carries. `0` — leaves and no
// further authority — unless the use case says otherwise, which exactly one
// does.
function issuingPathLen(useCaseId) {
  log.debug("Entering issuingPathLen().");
  const uc = useCase(useCaseId);
  log.debug("Leaving issuingPathLen().");
  return (uc && Number(uc.pathLen)) || 0;
}

// Which row an Intermediate lives in. A realm id is the row; the process
// branch has one of its own.
function scopeKindOf(scopeId) {
  log.debug("Entering scopeKindOf().");
  log.debug("Leaving scopeKindOf().");
  return String(scopeId) === PROCESS_SCOPE ? 'process' : 'realm';
}


// The default key algorithm and signature algorithm for a hierarchy nobody
// chose one for. RSA-2048 with SHA-256 because it is what every JWS verifier in
// existence can read, and because the leaf this chain is FOR signs a client
// assertion that somebody else's OAuth library has to check.
const DEFAULT_KEY_ALG = 'rsa-2048';
const DEFAULT_SIG_ALG = 'sha256-rsa';

// The default subject fields. Overridable per build; they are here so that a
// hierarchy built with the button and nothing typed still reads as something
// rather than as `CN=RootCA`.
const DEFAULT_ORGANISATION = 'sts';

// ---------------------------------------------------------------------------
// THE ALTERNATIVE KEY EVERY AUTHORITY HOLDS (2026-09-26, #68 — rcbj's D4,
// "whole chain hybrid").
//
// ITU-T X.509 (2019) clause 9.8: an authority's certificate carries a SECOND
// public key in `subjectAltPublicKeyInfo`, and every certificate it issues
// carries a SECOND signature — `altSignatureAlgorithm` and `altSignatureValue`
// over the preTBSCertificate — made with that key's private half. The
// extensions are non-critical, so a validator that has never heard of them
// sees an ordinary classical chain; one that has, checks both. The encoder
// and the verifier are the vendored `x509.js`'s (`issueCertificate()`'s
// `subjectAltPublicKey` and `altSignature`, `verifyChain()`'s
// `link.alternative`); what is HERE is which key, where it is held, and the
// policy `alternativeProblem()` enforces.
//
// **A PURE post-quantum SIGNATURE key and nothing else.** A composite is
// already two algorithms and would make the certificate carry three; a KEM
// cannot sign; a classical alternative is "a certificate signed twice by the
// same century", as `pki_authoring.ts` puts it for the same menu.
//
// **`none` MEANS A CLASSICAL AUTHORITY**, and is the weaker option rcbj's rule
// allows only behind a setting with a warning on it (`config.js`'s row).
// ---------------------------------------------------------------------------
const ALTERNATIVE_NONE = 'none';
const DEFAULT_ALTERNATIVE_KEY_ALG = 'ml-dsa-87';

function alternativeKeyAlgs() {
  log.debug("Entering alternativeKeyAlgs().");
  const out = keyMaterial.keyAlgIds().filter(function (id) {
    const desc = keyMaterial.keyAlg(id);
    return !!desc && desc.kind === 'pqc' && desc.use === 'sig' &&
           (desc.family === 'ML-DSA' || desc.family === 'SLH-DSA');
  });
  log.debug("Leaving alternativeKeyAlgs(). " + out.length + " of them.");
  return out;
}

// The alternative key algorithm a build asked for — the caller's, else the
// setting, else ML-DSA-87 — as `{ ok, altKeyAlg }` with `altKeyAlg` null for
// `none`, or a refusal naming what it knows.
function alternativeKeyAlgFrom(asked) {
  log.debug("Entering alternativeKeyAlgFrom().");
  const id = String(asked || config.value('pki.alternativeKeyAlgorithm') ||
                    DEFAULT_ALTERNATIVE_KEY_ALG).trim().toLowerCase();
  if (id === ALTERNATIVE_NONE) {
    log.debug("Leaving alternativeKeyAlgFrom(). None: classical only.");
    return { ok: true, altKeyAlg: null };
  }
  const known = alternativeKeyAlgs();
  if (known.indexOf(id) < 0) {
    log.debug("Leaving alternativeKeyAlgFrom(). Unknown.");
    return errorCodes.mark({ ok: false,
             errors: ['"' + id + '" is not an alternative key algorithm an ' +
                      'authority here can hold. It must be a post-quantum ' +
                      'signature algorithm — ' + known.join(', ') + ' — or ' +
                      '"none" for a classical-only authority.'] },
                           'STS-PKI-0200');
  }
  log.debug("Leaving alternativeKeyAlgFrom(). " + id);
  return { ok: true, altKeyAlg: id };
}

// What an issuing authority adds to an `x509.issueCertificate()` spec: its
// alternative signature, when it holds an alternative key, and nothing when it
// does not (a classical or imported authority). ONE place, so that every door
// that issues — a tier, a signing key's certificate, an application's key
// pair, a TLS server, an enrollment — signs twice or not by the same rule.
function alternativeSignatureBy(ca) {
  log.debug("Entering alternativeSignatureBy().");
  if (!ca || !ca.altPrivateKeyPem || !ca.altKeyAlg) {
    log.debug("Leaving alternativeSignatureBy(). The issuer is classical.");
    return {};
  }
  log.debug("Leaving alternativeSignatureBy(). " + ca.altKeyAlg);
  return { altSignature: { signatureAlg: ca.altKeyAlg,
                           privateKeyPem: ca.altPrivateKeyPem,
                           keyAlg: ca.altKeyAlg } };
}

// ---------------------------------------------------------------------------
// LIFETIMES NOBODY TYPED (2026-09-12).
//
// `leafLifetimeDays()` is `pki.leafLifetimeDays`, read in ONE place for both
// doors that issue a leaf. `configuredTierYears()` is the three
// `pki.*LifetimeYears` rows, where ZERO means "the vendored profile's own
// number" — so an unedited service builds the twenty, ten and five it always
// did, and a change to a profile in the parent project still reaches this
// service instead of being frozen into a default here.
//
// `tierYearsFrom()` exists because the three builders were handed `years` in
// TWO shapes and read one of them. `buildScope()` passes the `{ root,
// intermediate, issuing }` object straight on to `ensureRoot()`, and
// `buildRoot()` did `Number(object)`, which is NaN — so the Root lifetime the
// console's Build form collects was ignored whenever that form built the Root,
// and nothing said so because NaN falls to the profile's default like a blank.
// ---------------------------------------------------------------------------
const TIER_YEARS_SETTINGS = {
  root: 'pki.rootLifetimeYears',
  intermediate: 'pki.intermediateLifetimeYears',
  issuing: 'pki.issuingLifetimeYears'
};

function leafLifetimeDays() {
  log.debug("Entering leafLifetimeDays().");
  const n = Number(config.value('pki.leafLifetimeDays'));
  log.debug("Leaving leafLifetimeDays().");
  return isFinite(n) && n > 0 ? Math.floor(n) : 365;
}

function configuredTierYears(tier) {
  log.debug("Entering configuredTierYears().");
  const key = TIER_YEARS_SETTINGS[tier];
  const n = key ? Number(config.value(key)) : 0;
  log.debug("Leaving configuredTierYears().");
  return isFinite(n) && n > 0 ? Math.floor(n) : 0;
}

// What a build was asked for, for one tier: the caller's number where there
// is one — that tier's member of an object, or a bare number, which is what
// `buildRoot()`'s own callers pass and so means the ROOT and nothing else —
// then the setting, then 0, which `issueCaTier()` reads as the profile's own.
function tierYearsFrom(years, tier) {
  log.debug("Entering tierYearsFrom().");
  const asked = (years && typeof years === 'object') ? years[tier]
    : (tier === 'root' ? years : undefined);
  const n = Number(asked);
  if (isFinite(n) && n > 0) {
    log.debug("Leaving tierYearsFrom().");
    return Math.floor(n);
  }
  log.debug("Leaving tierYearsFrom().");
  return configuredTierYears(tier);
}

// ---------------------------------------------------------------------------
// WHICH ALGORITHMS MAY BE ASKED FOR. Both lists are READ FROM THE MODULE THAT
// PERFORMS THEM rather than written here, which is `crypto_metadata.js`'s rule
// applied one layer down: a page offering an algorithm the encoder cannot
// produce is a dropdown whose third entry is a 500.
// ---------------------------------------------------------------------------
function keyAlgorithms() {
  log.debug('Entering keyAlgorithms().');
  const out = keyMaterial.keyAlgIds().map(function (id) {
    const desc = keyMaterial.keyAlg(id);
    return { id: id, label: desc.label, kind: desc.kind };
  });
  log.debug('Leaving keyAlgorithms(). ' + out.length + ' algorithm(s).');
  return out;
}

// The signature algorithms a key of this kind can produce. Handed the KEY
// algorithm id, because that is what a form has — offering ECDSA against an RSA
// key produces a Web Crypto error naming neither.
function signatureAlgorithms(keyAlgId) {
  log.debug('Entering signatureAlgorithms(). keyAlg=' + keyAlgId);
  const desc = keyMaterial.keyAlg(keyAlgId || DEFAULT_KEY_ALG);
  if (!desc) {
    log.debug('Leaving signatureAlgorithms(). Unknown key algorithm.');
    return [];
  }
  // It answers a list of IDS rather than descriptors — the descriptor comes
  // from `sigAlg()` beside it — so this maps rather than reshapes. Getting
  // that backwards produces a dropdown of `undefined`, which is what the
  // first version of this function did.
  const out = x509.signatureAlgorithmsFor(desc).map(function (id) {
    const spec = x509.sigAlg(id) || {};
    return { id: id, label: spec.label || id, weak: !!spec.weak };
  });
  log.debug('Leaving signatureAlgorithms(). ' + out.length + ' algorithm(s).');
  return out;
}

// The default signature algorithm for a key algorithm, so that a caller that
// names only the key gets a matching pair rather than a refusal.
function defaultSignatureAlgorithmFor(keyAlgId) {
  log.debug("Entering defaultSignatureAlgorithmFor().");
  // The vendored module's own answer, not a first-non-weak scan: for an EC key
  // the right digest is decided by the CURVE (P-384 wants SHA-384) and a scan
  // over its list would hand a P-521 key SHA-256, which is legal, verifies,
  // and is nobody's intention.
  const desc = keyMaterial.keyAlg(keyAlgId || DEFAULT_KEY_ALG);
  if (!desc) {
    log.debug("Leaving defaultSignatureAlgorithmFor().");
    return DEFAULT_SIG_ALG;
  }
  log.debug("Leaving defaultSignatureAlgorithmFor().");
  return x509.defaultSignatureAlgorithm(desc) || DEFAULT_SIG_ALG;
}

// ---------------------------------------------------------------------------
// THE REALM THIS CALL IS ABOUT. Every function here takes an explicit realm id
// or falls back to the AMBIENT one, which is the shape every per-realm store in
// this service has: the console passes what the switcher is showing, and a
// protocol endpoint passes nothing and gets the realm the request arrived in.
// ---------------------------------------------------------------------------
function realmIdOf(realmId) {
  log.debug("Entering realmIdOf().");
  if (realmId !== undefined && realmId !== null && realmId !== '') {
    log.debug("Leaving realmIdOf().");
    return String(realmId);
  }
  const current = realms.current();
  log.debug("Leaving realmIdOf().");
  return String((current && current.id) || '');
}

// ---------------------------------------------------------------------------
// BUILD THE HIERARCHY. Asynchronous all the way down — the encoder is Web
// Crypto and every signature in it is a promise — and it is the only
// asynchronous thing in this module that a console action awaits.
//
// `opts`:
//   keyAlg        one of keyAlgorithms(). One algorithm for all three tiers,
//                 because a hierarchy that mixes them is a thing to be able to
//                 build deliberately and a terrible default: the leaf's
//                 signature algorithm is what a client library has to support,
//                 and it is decided by the ISSUING CA's key.
//   signatureAlg  one of signatureAlgorithms(keyAlg).
//   organisation  the O= every tier carries.
//   country       the C=, optional. PrintableString, which the encoder handles.
//   commonNames   { root, intermediate, issuing } — each optional.
//   years         { root, intermediate, issuing } — each optional; the profile's
//                 own default is used where one is absent.
// ---------------------------------------------------------------------------
// The signature algorithm a tier is signed WITH: one the issuer's key can
// actually produce. For a self-signed Root that is the subject's own key, so
// the preference stands; under a parent it is the parent's, and a preference
// its key cannot produce is REPLACED rather than refused — the caller asked
// for an EC *hierarchy*, and the tier they asked for is EC whatever signed it.
// A SHA-1 value (`weak` in the vendored table) is passed over the same way in
// PRODUCT (#181, `mode.usesBrokenAlgorithms()`): a tier or a leaf under an
// authority a development realm built with SHA-1 is signed with the key's
// default once the realm is switched, rather than refused — the refusal is
// for somebody NAMING SHA-1, which `algorithmsFrom()` and
// `issueSigningKeyPair()` make.
function signatureForIssuer(parent, preferred, subjectKeyAlg) {
  log.debug("Entering signatureForIssuer().");
  const issuerKeyAlg = parent ? parent.keyAlg : subjectKeyAlg;
  const issuerDesc = keyMaterial.keyAlg(issuerKeyAlg);
  const wanted = x509.sigAlg(preferred);
  if (issuerDesc && wanted && wanted.kind === issuerDesc.kind &&
      (!wanted.weak || mode.usesBrokenAlgorithms())) {
    log.debug("Leaving signatureForIssuer().");
    return preferred;
  }
  log.debug("Leaving signatureForIssuer().");
  return defaultSignatureAlgorithmFor(issuerKeyAlg);
}

// ---------------------------------------------------------------------------
// ISSUE ONE CA CERTIFICATE. The shared half of building a Root, an
// Intermediate or an Issuing CA: generate a pair, issue the certificate from
// the profile, and hand back the record. `parent` is null for the Root, which
// signs itself.
//
// It is a function rather than three because the three differ ONLY in the
// profile and the parent, and the vendored PROFILES table already holds every
// other difference — the basicConstraints, the pathLen, the key usages and the
// default lifetime. Writing them out here would be a second table that agrees
// with that one until somebody edits one of them.
// ---------------------------------------------------------------------------
// A CERTIFICATE VALIDITY INSTANT, WITH THE MILLISECONDS TAKEN OFF (2026-09-11).
//
// **RFC 5280 SECTION 4.1.2.5.2: A GeneralizedTime IN A CERTIFICATE MUST NOT
// INCLUDE FRACTIONAL SECONDS.** `new Date()` carries milliseconds and the
// encoder writes what it is handed, so a `notAfter` of 2056 came out as
// `20560911143530.614Z` and OpenSSL refused the certificate outright:
// `format error in certificate's notAfter`.
//
// **IT ONLY EVER BIT THE ROOT, WHICH IS WHY IT LOOKED LIKE SOMETHING ELSE.**
// RFC 5280 section 4.1.2.5 makes a time before 2050 a UTCTime and 2050 or
// later a GeneralizedTime; UTCTime has no fractional part at all, so the leaf,
// the Issuing CA and the Intermediate — one, five and ten years out — were all
// encoded cleanly. Only the Root's thirty-year lifetime crosses 2050.
//
// So the single malformed certificate was the TRUST ANCHOR. The chain
// verified, every console page drew it correctly, `openssl x509` printed it
// happily — and any client asked to TRUST it rejected it before it could check
// anything. To a node client that is `unable to get local issuer certificate`;
// on this service's own console it is **Signing in did not complete**, because
// the OpenID Connect back channel puts exactly that certificate in its
// truststore to dial itself.
//
// **IT IS FIXED HERE AND NOT IN THE ENCODER**, and that is a rule rather than
// a preference: `common/vendored/x509.js` is a byte-identical copy of the
// parent project's file and the root CLAUDE.md says not to edit one here. The
// encoder writing what it is handed is defensible; handing it a time with
// milliseconds in it is what this module was doing wrong. The parent project
// should still drop fractional seconds on the way out — that is its bug to
// fix, and `docs/parent-project-migration.md` is where this repository records
// what it owes that one.
// ---------------------------------------------------------------------------
function certificateInstant(at) {
  log.debug("Entering certificateInstant().");
  const when = (at === undefined || at === null) ? new Date() : new Date(at);
  when.setUTCMilliseconds(0);
  log.debug("Leaving certificateInstant().");
  return when;
}

// ---------------------------------------------------------------------------
async function issueCaTier(spec) {
  log.debug('Entering issueCaTier(). profile=' + spec.profile);
  const profile = x509.profile(spec.profile);
  const keyAlgId = spec.keyAlg;
  // **THE SIGNATURE IS THE PARENT'S TO MAKE, NOT THE SUBJECT'S**, and this
  // line is the whole of that. Asking for an EC hierarchy under an RSA Root
  // hands `sha256-ecdsa` to a key that cannot produce it, and the primitive
  // answers `Invalid key type` — naming neither the tier, the key nor the
  // algorithm. `common/vendored/x509.js`'s own header spends a paragraph on
  // what getting this backwards produces; `tests/pki.js` caught it here within
  // a minute of the hierarchy growing a shared Root, because a shared Root is
  // the first arrangement in which the two can legitimately differ.
  const sigAlgId = signatureForIssuer(spec.parent, spec.signatureAlg, keyAlgId);
  const years = Number(spec.years) > 0 ? Math.floor(Number(spec.years))
                                       : profile.years;
  const pair = await keyMaterial.generateKeyPair(keyAlgId);
  // THE ALTERNATIVE KEY (#68). `spec.altKeyAlg` is null for a classical tier;
  // absent, it is the setting — so a caller that predates the field (a reissue
  // of a tier built before it) still gets the service's choice.
  let altKeyAlg = spec.altKeyAlg;
  if (altKeyAlg === undefined) {
    const chosenAlt = alternativeKeyAlgFrom('');
    altKeyAlg = chosenAlt.ok ? chosenAlt.altKeyAlg : null;
  }
  const altPair = altKeyAlg
    ? await keyMaterial.generateKeyPair(altKeyAlg) : null;
  // The alternative SIGNATURE is the issuer's to make, as the classical one
  // is: the parent's alternative key, or this tier's own for a self-signed
  // Root. A parent with none (classical, or imported) leaves this tier
  // carrying its alternative key and no alternative signature — a state
  // clause 9.8 allows, and one `alternativeProblem()` does not refuse,
  // because there is no key above it that could have made one.
  const altSigner = spec.parent
    ? spec.parent
    : (altPair ? { altKeyAlg: altKeyAlg,
                   altPrivateKeyPem: altPair.privatePem } : null);
  // SECONDS AND NO FINER — see certificateInstant(). The Root's thirty years
  // cross 2050, which makes it the one validity in this hierarchy encoded as a
  // GeneralizedTime and therefore the one a fractional second invalidates.
  const notBefore = certificateInstant();
  const notAfter = certificateInstant(notBefore.getTime());
  notAfter.setUTCFullYear(notAfter.getUTCFullYear() + years);
  // A CA may not outlive the CA that signed it. Clamped rather than refused,
  // for `issueSigningKeyPair()`'s reason: the ordinary cause is a twenty-year
  // Root in its nineteenth year, and an operator who asked for ten should get
  // one rather than an error about arithmetic.
  if (spec.parent) {
    const parentEnds = new Date(spec.parent.notAfter).getTime();
    if (notAfter.getTime() > parentEnds) {
      log.warn('pki: the ' + spec.profile + ' asked for would outlive the CA ' +
               'that signs it, so it was shortened to that CA\'s own expiry (' +
               spec.parent.notAfter + ').');
      notAfter.setTime(parentEnds);
    }
  }
  const subject = [{ name: 'CN', value: spec.cn },
                   { name: 'O', value: spec.organisation }]
    .concat(spec.country ? [{ name: 'C', value: spec.country }] : []);
  const issued = await x509.issueCertificate(Object.assign({
    subject: subject,
    subjectPublicKey: pair.publicPem,
    subjectAltPublicKey: altPair ? altPair.publicPem : undefined,
    signatureAlg: sigAlgId,
    profile: spec.profile,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    issuer: spec.parent
      ? { certificatePem: spec.parent.certificatePem,
          privateKeyPem: spec.parent.privateKeyPem,
          keyAlg: spec.parent.keyAlg }
      : { privateKeyPem: pair.privatePem, keyAlg: keyAlgId },
    extensions: Object.assign({
      // **THE PROFILE'S `pathLen` UNLESS THE CALLER NAMES ONE**, which since
      // 2026-09-11 one caller does: the SPIFFE Issuing CA needs room for a
      // downstream CA and the Intermediate above it needs room for both. See
      // `intermediatePathLen()`. `spec.pathLen` is checked against `undefined`
      // rather than for truthiness, because the value that matters most here
      // is 0 and `|| profile.pathLen` would silently discard it.
      basicConstraints: { present: true, critical: true, ca: true,
                          pathLen: spec.pathLen === undefined
                            ? profile.pathLen : spec.pathLen },
      keyUsage: { present: true, critical: true, usages: profile.keyUsage },
      subjectKeyIdentifier: { present: true },
      // Present on every tier including the Root, where it names the
      // certificate's own key. RFC 5280 section 4.2.1.1 says it MAY be omitted
      // on a self-signed one; several path builders are much happier when it
      // is there, and nothing is worse for having it.
      authorityKeyIdentifier: { present: true }
    },
    // **WHERE THE LIST THAT WOULD REVOKE *THIS* CA IS — ITS PARENT'S.** A
    // self-signed Root gets none: a Root that named its own CRL would be
    // asking a validator to consult a list the Root itself signs to find out
    // whether the Root is trustworthy, which answers nothing.
    spec.parent
      ? revocationExtensionsFor(spec.parent.scope || spec.scope,
                                spec.parent.useCase || spec.parent.tier)
      : {})
  }, alternativeSignatureBy(altSigner)));
  log.debug('Leaving issueCaTier(). ' + issued.subject +
            (altPair ? ' (hybrid, ' + altKeyAlg + ')' : ''));
  return {
    tier: spec.tier,
    label: spec.label,
    useCase: spec.useCase || null,
    scope: spec.scope || null,
    keyAlg: keyAlgId,
    signatureAlg: sigAlgId,
    subject: issued.subject || spec.cn,
    serialHex: issued.serialHex,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    certificatePem: issued.pem,
    privateKeyPem: pair.privatePem,
    publicKeyPem: pair.publicPem,
    // THE ALTERNATIVE HALF (#68): the key this tier signs its children's
    // alternative signatures with, sealed with the rest of the row, and the
    // algorithm its OWN alternative signature was made with (its issuer's).
    altKeyAlg: altPair ? altKeyAlg : null,
    altPrivateKeyPem: altPair ? altPair.privatePem : null,
    altPublicKeyPem: altPair ? altPair.publicPem : null,
    altSignatureAlg: (altSigner && altSigner.altPrivateKeyPem &&
                      altSigner.altKeyAlg) || null,
    thumbprint: thumbprintOf(issued.pem),
    imported: false,
    createdAt: Date.now()
  };
}

// ---------------------------------------------------------------------------
// THE ROOT, WHICH IS THE SERVICE'S AND NOT A REALM'S.
//
// `serviceRoot()` answers what is there; `ensureRoot()` makes one if there is
// none. **An EXISTING Root is never replaced by ensure()** — every realm's
// Intermediate is signed by it, so replacing it silently would break every
// chain in the process at the moment somebody created their second realm.
// Replacing it is `buildRoot()`, which is a deliberate act with its own button
// and its own warning.
// ---------------------------------------------------------------------------
function serviceRow() {
  log.debug("Entering serviceRow().");
  log.debug("Leaving serviceRow().");
  return keystore.pkiFor(SERVICE_SCOPE) || null;
}

function serviceRoot() {
  log.debug("Entering serviceRoot().");
  const row = serviceRow();
  log.debug("Leaving serviceRoot().");
  return (row && row.root) || null;
}

function hasRoot() {
  log.debug("Entering hasRoot().");
  log.debug("Leaving hasRoot().");
  return !!serviceRoot();
}

// ---------------------------------------------------------------------------
// DOES A SCOPE'S INTERMEDIATE CARRY THIS SERVICE'S CURRENT ROOT'S SIGNATURE?
//
// **THE SIGNATURE AND NOT THE NAME.** Every Root this service builds is called
// `<organisation> Root CA`, so two of them are indistinguishable by subject,
// issuer, or anything else a comparison of strings could reach — which is
// precisely how the state this detects survives being looked at. `verify()`
// against the Root's public key is the only check that tells them apart.
//
// A scope with no Intermediate answers TRUE rather than false: there is
// nothing to be stale, `certify()`'s own "no Issuing CA" refusal is the right
// message for it, and rebuilding on the way past would turn a clear error into
// a confusing one.
// ---------------------------------------------------------------------------
function scopeChainsToRoot(scopeId) {
  log.debug('Entering scopeChainsToRoot(). scope=' + scopeId);
  const root = serviceRoot();
  const row = rawRowFor(String(scopeId));
  const intermediate = row && row.intermediate;
  if (!root || !root.certificatePem || !intermediate ||
      !intermediate.certificatePem) {
    log.debug('Leaving scopeChainsToRoot(). Nothing to compare.');
    return true;
  }
  try {
    const signed = new nodeCrypto.X509Certificate(intermediate.certificatePem)
      .verify(new nodeCrypto.X509Certificate(root.certificatePem).publicKey);
    log.debug('Leaving scopeChainsToRoot(). ' + signed);
    return signed;
  } catch (e) {
    // NAMED rather than swallowed, and answered TRUE: a certificate this
    // module cannot parse is not evidence that a rebuild is wanted, and
    // rebuilding a hierarchy on the strength of a parse failure would throw
    // away key material over a bad read.
    log.warn('pki: the "' + scopeId + '" branch could not be checked against ' +
             'the Root (' + e.message + '), so it is left alone.');
    log.debug('Leaving scopeChainsToRoot(). It threw.');
    return true;
  }
}

async function buildRootNow(opts) {
  log.debug('Entering buildRoot().');
  const options = opts || {};
  const chosen = algorithmsFrom(options);
  if (!chosen.ok) {
    log.debug('Leaving buildRoot(). ' + chosen.errors.join(' '));
    return chosen;
  }
  const organisation = String(options.organisation || DEFAULT_ORGANISATION);
  const country = String(options.country || '');
  let root;
  try {
    root = await issueCaTier({
      tier: 'root', profile: 'root-ca', label: 'Root CA', scope: SERVICE_SCOPE,
      cn: String(options.commonName || (organisation + ' Root CA')),
      organisation: organisation, country: country,
      keyAlg: chosen.keyAlg, signatureAlg: chosen.signatureAlg,
      altKeyAlg: chosen.altKeyAlg,
      years: tierYearsFrom(options.years, 'root'), parent: null
    });
  } catch (e) {
    log.error(errorCodes.tag('STS-PKI-0005') + 'pki: the Root CA could not ' +
                                               'be issued: ' + e.message +
              '. Nothing was stored.');
    log.debug('Leaving buildRoot(). The encoder refused.');
    return errorCodes.mark({ ok: false,
             errors: ['The Root CA could not be issued: ' + e.message +
                      '. Nothing was stored.'] }, 'STS-PKI-0005');
  }
  const row = serviceRow() || {};
  // **A ROOT CANNOT USEFULLY REVOKE ITSELF AND THIS DOES NOT PRETEND TO.**
  // The old Root is self-signed, so the only list that could carry it is the
  // one it signs — and a validator that does not already trust it will not
  // read that list, while one that does has no reason to. What replaces a Root
  // is an operator removing it from their truststore, which is said on the
  // page rather than faked here with an entry nobody consults.
  keystore.attachPki(SERVICE_SCOPE, Object.assign({}, row, {
    version: 2, scope: SERVICE_SCOPE, root: root,
    organisation: organisation, country: country,
    keyAlg: chosen.keyAlg, signatureAlg: chosen.signatureAlg,
    altKeyAlg: chosen.altKeyAlg,
    createdAt: Date.now()
  }));
  log.info('pki: THE SERVICE HAS A ROOT CA — ' + root.subject + ', ' +
           chosen.keyAlg + ' signed ' + chosen.signatureAlg +
           (chosen.altKeyAlg ? ', with an alternative ' + chosen.altKeyAlg +
                               ' key and signature (hybrid)'
                             : ', classical only') + '. Every ' +
           'realm\'s Intermediate is signed by it, so it is the one anchor ' +
           'an operator installs. ' +
           (keystore.persists()
             ? 'It is written to the persistence store, sealed.'
             : 'It is held in memory only — this service is in development ' +
               'mode, where key material is generated per start.'));
  log.debug('Leaving buildRoot().');
  return { ok: true, root: describeTier(root) };
}

async function ensureRoot(opts) {
  log.debug("Entering ensureRoot().");
  log.debug("Leaving ensureRoot().");
  return oneBuildAtATime(SERVICE_SCOPE, function () {
    const existing = function () {
      log.debug("Entering existing().");
      const held = serviceRoot();
      log.debug("Leaving existing().");
      return held ? { ok: true, root: describeTier(held), existing: true }
                  : null;
    };
    return existing() || oneBuildInTheCluster(SERVICE_SCOPE, 'root', existing,
                                              function () {
                                                return buildRootNow(opts);
                                              });
  });
}

// The deliberate replacement — its own button — waits behind any build of the
// Root already running, so it replaces the Root that build made rather than
// racing it.
async function buildRoot(opts) {
  log.debug("Entering buildRoot().");
  log.debug("Leaving buildRoot().");
  return oneBuildAtATime(SERVICE_SCOPE, function () {
    return oneBuildInTheCluster(SERVICE_SCOPE, 'root', null, function () {
      return buildRootNow(opts);
    });
  });
}

// ---------------------------------------------------------------------------
// ONE BUILD OF A SCOPE AT A TIME IN THE CLUSTER, AND THE STORE READ FIRST
// (2026-09-14, #46 section 1).
//
// `oneBuildAtATime()` below is per PROCESS, and `ensureRoot()` asked THIS
// process's copy of the hierarchy whether a Root existed — which on a cold
// start of several nodes against an empty store was "no" on every one of
// them, so each built a Root, each built a process branch and a default-realm
// branch under it, each certified its listener, and the last save of each row
// won. Nothing failed; the nodes simply had different anchors.
//
// Two things close it, and they are different kinds of guard:
//
//   * **A CLAIM, so only one node builds a scope at a time**
//     (`cluster/cluster_claims.js`, scope `pki.build`). A node that finds it
//     held waits, re-reading the row, and takes the other node's build the
//     moment it is committed. The claim has a lifetime, so a node that died
//     holding it costs one lifetime and not a service with no CA.
//   * **THE WRITE ITSELF, which is the arbiter the claim is only an
//     optimisation of.** `keystore.js` merges the row under its lock and a CA
//     tier is first writer wins (`common/pki_merge.js`), so a build that
//     somehow ran anyway — a claim that expired mid-build — cannot replace a
//     Root another node already issued under. The build's caller is told: an
//     ENSURE takes the other node's tier as its answer; a DELIBERATE build is
//     refused, because the operator's Build did not happen.
//
// The claim is a mutual exclusion and not a fence, which is why it is not
// `cluster.withLease()`: a lease there is a ROLE a node keeps and renews, and
// a Build pressed on a node that does not hold it would be refused for as long
// as the holder lives. The fence every write already carries (the node's
// membership, checked in the transaction) is what stops a deposed node.
//
// Where the store does not arbitrate — development, `ldif`, one process —
// this is `build()` and nothing else.
// ---------------------------------------------------------------------------
const CLUSTER_BUILD_CLAIM_MS = 120000;
const CLUSTER_BUILD_WAIT_MS = 180000;
const CLUSTER_BUILD_POLL_MS = 250;

function sleepMs(ms) {
  log.debug("Entering sleepMs().");
  log.debug("Leaving sleepMs().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

function lostTier(outcome, tiers) {
  log.debug("Entering lostTier().");
  const wanted = [].concat(tiers);
  log.debug("Leaving lostTier().");
  return ((outcome && outcome.lost) || []).some(function (one) {
    return wanted.some(function (tier) {
      return one === tier || one.indexOf(tier + '.') === 0;
    });
  });
}

// `options.claim` names the claim when what is built is not the branch itself
// (a certificate kept in the scope's row — the SCEP RA's), and must, because a
// build of that thing may repair the branch under the branch's own claim;
// `options.label` is how the log and a refusal name it.
async function oneBuildInTheCluster(scopeId, tier, existing, build, options) {
  log.debug("Entering oneBuildInTheCluster(). scope=" + scopeId);
  if (typeof keystore.arbitrates !== 'function' || !keystore.arbitrates()) {
    log.debug("Leaving oneBuildInTheCluster(). Nothing to coordinate.");
    return build();
  }
  // Required lazily: `cluster_claims.js` reaches the store through
  // `persistence.js`, which requires the keystore this file sits on.
  const claims = require('../cluster/cluster_claims');
  const opts = options || {};
  const label = opts.label ? String(opts.label)
    : scopeId === SERVICE_SCOPE ? 'the service Root'
    : scopeId === PROCESS_SCOPE ? 'the process branch'
    : 'the "' + (scopeId || 'default') + '" branch';
  const began = Date.now();
  let announced = false;
  for (;;) {
    await keystore.refreshPki(scopeId);
    const before = existing ? existing() : null;
    if (before) {
      log.debug("Leaving oneBuildInTheCluster(). Another node built it.");
      return before;
    }
    const claim = await claims.claim({ scope: 'pki.build',
                                       value: opts.claim ||
                                              'scope:' + String(scopeId),
                                       ttlMs: CLUSTER_BUILD_CLAIM_MS,
                                       realm: '' });
    if (claim.ok) {
      try {
        // READ AGAIN WITH THE CLAIM HELD: a build that finished between the
        // read above and the claim is committed now.
        await keystore.refreshPki(scopeId);
        const under = existing ? existing() : null;
        if (under) {
          log.debug("Leaving oneBuildInTheCluster(). Built meanwhile.");
          return under;
        }
        const made = await build();
        const outcome = await keystore.pkiSettled(scopeId);
        if (made && made.ok && lostTier(outcome, tier)) {
          const theirs = existing ? existing() : null;
          if (theirs) {
            log.warn(errorCodes.tag('STS-PKI-0182') + 'pki: ' + label + ' ' +
                     'was built here and by another node at the same ' +
                     'moment; the other node\'s committed first and is ' +
                     'the one this node now holds.');
            log.debug("Leaving oneBuildInTheCluster(). Adopted theirs.");
            return Object.assign({}, theirs, { adoptedFromCluster: true });
          }
          log.debug("Leaving oneBuildInTheCluster(). Lost to another build.");
          return errorCodes.mark({ ok: false,
            errors: [label.charAt(0).toUpperCase() + label.slice(1) + ' was ' +
                     'made again by another node at the same moment and ' +
                     'that one committed first, so this one was NOT kept. ' +
                     'Reload the page to see what the service holds, and ' +
                     'build again if it is still not what you want.'] },
                                 'STS-PKI-0182');
        }
        log.debug("Leaving oneBuildInTheCluster(). Built.");
        return made;
      } finally {
        await claims.release(claim.handle);
      }
    }
    if (claim.reason === 'store') {
      log.error(errorCodes.tag('STS-PKI-0183') + 'pki: ' + label + ' could ' +
                'not be built, because the store could not be asked whether ' +
                'another node is building it (' + claim.why + ').');
      log.debug("Leaving oneBuildInTheCluster(). The store refused.");
      return errorCodes.mark({ ok: false,
        errors: [label.charAt(0).toUpperCase() + label.slice(1) + ' was ' +
                 'not built: the store could not be asked whether another ' +
                 'node is building it, and two nodes building one would ' +
                 'publish two authorities of one name.'] }, 'STS-PKI-0183');
    }
    if (Date.now() - began > CLUSTER_BUILD_WAIT_MS) {
      log.error(errorCodes.tag('STS-PKI-0184') + 'pki: ' + label + ' is ' +
                'being built by another node and has not appeared in ' +
                (CLUSTER_BUILD_WAIT_MS / 1000) + 's; this node gives up ' +
                'waiting.');
      log.debug("Leaving oneBuildInTheCluster(). Waited too long.");
      return errorCodes.mark({ ok: false,
        errors: ['Another node has been building ' + label + ' for longer ' +
                 'than ' + (CLUSTER_BUILD_WAIT_MS / 1000) + 's and it has ' +
                 'not appeared in the store.'] }, 'STS-PKI-0184');
    }
    if (!announced) {
      announced = true;
      log.info('pki: another node is building ' + label + '; this node ' +
               'waits for it rather than building a second one.');
    }
    await sleepMs(CLUSTER_BUILD_POLL_MS);
  }
}

// ---------------------------------------------------------------------------
// ONE BUILD OF A SCOPE AT A TIME, IN THIS PROCESS (2026-09-12).
//
// `ensureScope()` looked for a complete branch and, finding none, AWAITED a
// build — nine signatures, a noticeable fraction of a second. Two callers
// arriving inside that window both found none and both built, and the one that
// finished second REPLACED the branch the first had made. Nothing failed at the
// time. What failed was the next certificate check: a leaf issued from the
// first branch was "not signed by" an Issuing CA of the same name, because that
// CA had been thrown away under it.
//
// **THE TWO CALLERS WERE ORDINARY.** `realms.create()` fires this module's
// realm watcher, which builds the new realm's branch without being awaited; the
// code that created the realm very often asks for that branch next — to issue a
// key pair, or, in `tests/revocation_status.js`, to build it explicitly.
// Nothing about either call is wrong on its own.
//
// So a build of one scope waits for any build of that scope already running,
// and `ensureScope()` looks for the branch AFTER waiting rather than before —
// which is what turns the second caller into a reader of the first caller's
// branch instead of its replacement. A deliberate `buildScope()` (a console
// rebuild, `certify()`'s repair of a stale branch) queues the same way and then
// replaces, which is what it was asked to do. The Root is one more scope
// (`SERVICE_SCOPE`), because two branches built at once on a service with no
// Root had the same race one level up: two Roots, and one of the two new
// Intermediates signed by the one that lost.
//
// **A QUEUE, NOT A LOCK THAT CAN BE HELD.** A build that throws or refuses
// releases its place; the next caller runs regardless, because a failed build
// is not a reason to fail the one behind it. And it is per PROCESS: two
// processes of one service are kept from building the same realm's branch by
// the realm watcher's rule about replicated realms, below, and two NODES by
// `oneBuildInTheCluster()` above (2026-09-14) — not by this.
// ---------------------------------------------------------------------------
const scopeBuilds = new Map();   // scope id -> the tail of that scope's queue

function oneBuildAtATime(scopeId, build) {
  log.debug("Entering oneBuildAtATime().");
  const key = String(scopeId);
  const ahead = scopeBuilds.get(key) || Promise.resolve();
  const mine = ahead.then(function () { return null; }, function (e) {
    // The build ahead of this one failed. Its caller has that failure; this
    // caller only needed it to finish before starting.
    log.debug("Caught in oneBuildAtATime(): the build ahead failed: " +
              ((e && e.message) || e));
    return null;
  }).then(function () {
    return build();
  });
  const tail = mine.then(function () { return null; }, function (e) {
    // This build's own caller holds `mine` and has the failure; the queue's
    // tail only has to settle.
    log.debug("Caught in oneBuildAtATime(): " + ((e && e.message) || e));
    return null;
  });
  scopeBuilds.set(key, tail);
  tail.then(function () {
    if (scopeBuilds.get(key) === tail) {
      scopeBuilds.delete(key);
    }
  });
  log.debug("Leaving oneBuildAtATime().");
  return mine;
}

// The key and signature algorithm a build is to use, checked as a PAIR. It is
// one function because the three checks belong together — an unknown key
// algorithm, an unknown signature algorithm, and a pair whose families
// disagree — and because every builder below makes all three.
function algorithmsFrom(options) {
  log.debug("Entering algorithmsFrom().");
  const keyAlgId = String(options.keyAlg || config.value('pki.keyAlgorithm') ||
                          DEFAULT_KEY_ALG);
  const keyDesc = keyMaterial.keyAlg(keyAlgId);
  if (!keyDesc) {
    log.debug("Leaving algorithmsFrom().");
    return errorCodes.mark({ ok: false,
             errors: ['"' + keyAlgId + '" is not a key algorithm this ' +
                      'service can generate. It knows ' +
                      keyMaterial.keyAlgIds().join(', ') + '.'] },
                           'STS-PKI-0002');
  }
  // -------------------------------------------------------------------------
  // `pki.signatureAlgorithm` IS THE DEFAULT HERE AND IT WAS NOT (fixed
  // 2026-09-12).
  //
  // The key algorithm above has always fallen back to its setting; the
  // signature algorithm fell straight past its own to the per-key default, so
  // the setting was honoured by exactly one caller — the console's Build form,
  // which reads it itself — and ignored by the startup auto-build, a realm
  // created at runtime and the repair `certify()` makes on a stale branch.
  // An operator who set SHA-384 got SHA-384 on the day they pressed Build and
  // SHA-256 on every branch built without them.
  //
  // **A CONFIGURED VALUE THE KEY CANNOT PRODUCE IS SKIPPED, NOT REFUSED.** The
  // setting is one value for every build, and a build may name another key
  // family — the SPIFFE use case prefers EC while the setting names an RSA
  // digest. Refusing would make one sensible setting break every EC build; a
  // CALLER that names a mismatched pair is still refused below, because that is
  // somebody asking for the impossible rather than a default not fitting.
  // -------------------------------------------------------------------------
  //
  // **SHA-1 IS DEVELOPMENT'S (#181).** The setting is read AS IN FORCE, so
  // `sha1-rsa` or `sha1-ecdsa` stored in a product realm reads as empty (the
  // key's own default), said once; and a CALLER naming either is refused
  // below, because a build form is a second door onto the same choice.
  // -------------------------------------------------------------------------
  const configuredSig = String(mode.valueInForce('pki.signatureAlgorithm') ||
                               '').trim();
  const configuredFits = !!configuredSig && !!x509.sigAlg(configuredSig) &&
                         x509.sigAlg(configuredSig).kind === keyDesc.kind;
  const sigAlgId = String(options.signatureAlg ||
                          (configuredFits ? configuredSig : '') ||
                          defaultSignatureAlgorithmFor(keyAlgId));
  const sig = x509.sigAlg(sigAlgId);
  if (!sig) {
    log.debug("Leaving algorithmsFrom().");
    return errorCodes.mark({ ok: false,
             errors: ['"' + sigAlgId + '" is not a signature algorithm this ' +
                      'service can produce.'] }, 'STS-PKI-0003');
  }
  if (sig.weak && !mode.usesBrokenAlgorithms()) {
    log.debug("Leaving algorithmsFrom(). SHA-1, in product.");
    return errorCodes.mark({ ok: false,
             errors: ['"' + sigAlgId + '" signs with SHA-1, which this ' +
                      'realm does not use in product mode ' +
                      '(global.mode=product). Choose ' +
                      signatureAlgorithms(keyAlgId).filter(function (one) {
                        return !one.weak;
                      }).map(function (one) {
                        return one.id;
                      }).join(', ') + '.'] }, 'STS-PKI-0191');
  }
  if (sig.kind !== keyDesc.kind) {
    log.debug("Leaving algorithmsFrom().");
    // Refused here rather than left to Web Crypto, which reports it as a key
    // usage error naming neither the key nor the algorithm.
    return errorCodes.mark({ ok: false,
             errors: ['A ' + keyDesc.label + ' key cannot produce a ' +
                      sig.label + ' signature. The algorithms this key can ' +
                      'sign with are ' +
                      signatureAlgorithms(keyAlgId).map(function (one) {
                        return one.id;
                      }).join(', ') + '.'] }, 'STS-PKI-0004');
  }
  const alternative = alternativeKeyAlgFrom(options.altKeyAlg);
  if (!alternative.ok) {
    log.debug("Leaving algorithmsFrom(). The alternative key algorithm.");
    return alternative;
  }
  log.debug("Leaving algorithmsFrom().");
  return { ok: true, keyAlg: keyAlgId, signatureAlg: sigAlgId,
           keyDesc: keyDesc, sig: sig, altKeyAlg: alternative.altKeyAlg };
}

// ---------------------------------------------------------------------------
// BUILD ONE SCOPE'S BRANCH: an Intermediate signed by the service Root, and an
// Issuing CA under it for each of that scope's use cases.
//
// **ALL OF IT OR NONE OF IT, which is the rule the three tiers had and is now
// about more tiers.** A branch with an Intermediate and two of its three
// Issuing CAs is exactly the state in which one use case silently has no
// authority and its keys come out uncertified — so a failure anywhere stores
// nothing.
//
// An IMPORTED tier is never replaced by a rebuild unless the caller says so:
// somebody who pasted a corporate Intermediate in did not press this button to
// have it thrown away.
// ---------------------------------------------------------------------------
async function buildScope(scopeId, opts) {
  log.debug("Entering buildScope().");
  log.debug("Leaving buildScope().");
  return oneBuildAtATime(String(scopeId), function () {
    return oneBuildInTheCluster(String(scopeId), ['intermediate', 'issuing'],
                                null,
                                function () {
                                  return buildScopeNow(scopeId, opts);
                                });
  });
}

// ---------------------------------------------------------------------------
// A STALE BRANCH IS REPAIRED ONCE, NOT ONCE PER CALLER THAT NOTICED IT
// (2026-09-21). `certify()` and `issueUnder()` rebuild a branch the Root no
// longer signs, and both asked `buildScope()` — which queues behind a build
// already running and then builds UNCONDITIONALLY. So a leaf requested in the
// middle of build-root's rebuildEveryScope() (the SPIFFE server's re-key,
// which fires when the listener certificate is re-issued, before the realm
// branches are) queued a SECOND build of a branch the first had just made
// current: the realm ended with two Intermediates of one name and one CRL
// address, its signing keys certified under the first and everything else
// under the second (tests/vendored/sts_pki_distribution_points.js). The
// question is asked again INSIDE the queue, where it can no longer change
// under the answer. Both callers reach this only for a branch that exists and
// is stale, so "chains to the Root" here means another build got there first.
//
// **AND ACROSS PROCESSES TOO (the same day).** The question was asked of this
// process's copy and the cluster claim was taken with no `existing` check, so
// a second PROCESS that queued behind the claim built the branch again when it
// got it. `single-node` (three request workers on one store) showed it: after
// build-root in one worker, another worker certifying a key saw the new Root
// before its branch, took the default branch's claim first and repaired it,
// and then build-root's own rebuild of that branch made a second Intermediate
// CA (default) — the realm's JWKS chained to one nobody listed any more. So
// the claim now carries the same question (`existing` is asked after the
// claim-holder's build is committed and re-read), and `rebuildEveryScope()`
// repairs through here rather than building unconditionally: whichever
// process reaches a stale branch first rebuilds it, and the other adopts it.
// `opts` are `buildScopeNow()`'s.
// ---------------------------------------------------------------------------
async function repairBranch(scopeId, opts) {
  log.debug("Entering repairBranch(). scope=" + scopeId);
  const id = String(scopeId);
  const already = function () {
    log.debug("Entering already().");
    const current = scopeChainsToRoot(id);
    log.debug("Leaving already(). " + current);
    return current ? { ok: true, existing: true } : null;
  };
  log.debug("Leaving repairBranch().");
  return oneBuildAtATime(id, function () {
    if (already()) {
      log.info('pki: the "' + (id || 'default') + '" branch ' +
               'was rebuilt by another caller while this repair waited, ' +
               'so it is not rebuilt again.');
      return { ok: true, existing: true };
    }
    return oneBuildInTheCluster(id, ['intermediate', 'issuing'], already,
                                function () {
                                  return buildScopeNow(scopeId, opts || {});
                                });
  });
}

async function buildScopeNow(scopeId, opts) {
  log.debug('Entering buildScope(). scope=' + scopeId);
  const id = String(scopeId);
  const kind = scopeKindOf(id);
  const options = opts || {};
  // The algorithms are decided BEFORE the Root is made, so that a build
  // refused for its algorithm (a SHA-1 one in product, #181, or an
  // impossible pair) creates nothing on its way to the refusal.
  const chosen = algorithmsFrom(options);
  if (!chosen.ok) {
    log.debug('Leaving buildScope(). ' + chosen.errors.join(' '));
    return chosen;
  }
  const rooted = await ensureRoot(options);
  if (!rooted.ok) {
    log.debug('Leaving buildScope(). No Root.');
    return rooted;
  }
  const root = serviceRoot();
  const organisation = String(options.organisation ||
                              (serviceRow() || {}).organisation ||
                              DEFAULT_ORGANISATION);
  const country = String(options.country === undefined
                           ? ((serviceRow() || {}).country || '')
                           : options.country);
  const existing = rawRowFor(id) || {};
  const label = kind === 'process' ? 'the process'
                                   : ('the "' + (id || 'default') + '" realm');
  const named = kind === 'process' ? 'Process' : (id || 'default');

  // THE INTERMEDIATE. Kept where it was imported, unless this call says
  // otherwise — see the header.
  let intermediate = existing.intermediate;
  const keepImported = intermediate && intermediate.imported &&
                       !options.replaceImported;
  if (!intermediate || !keepImported) {
    try {
      intermediate = await issueCaTier({
        tier: 'intermediate', profile: 'intermediate-ca',
        label: 'Intermediate CA', scope: id,
        // **NOT `String(a && b) || c`** — `String(undefined)` is the string
        // "undefined", which is truthy, so the fallback was unreachable and
        // every Intermediate this built was called `CN=undefined`. It shipped
        // in the first run of this function and was visible in the
        // console's own tree.
        cn: (options.commonNames && options.commonNames.intermediate) ||
            (organisation + ' Intermediate CA (' + named + ')'),
        organisation: organisation, country: country,
        keyAlg: chosen.keyAlg, signatureAlg: chosen.signatureAlg,
        altKeyAlg: chosen.altKeyAlg,
        // One deeper than the deepest Issuing CA this scope carries — see
        // `intermediatePathLen()`. A realm's is 2 because it carries `spiffe`;
        // the process branch's is 1, exactly as the profile says.
        pathLen: intermediatePathLen(kind),
        years: tierYearsFrom(options.years, 'intermediate'), parent: root
      });
    } catch (e) {
      log.error(errorCodes.tag('STS-PKI-0006') + 'pki: ' + label + '\'s ' +
          'Intermediate CA could not be issued: ' +
                e.message + '. Nothing was stored.');
      log.debug('Leaving buildScope(). The Intermediate failed.');
      return errorCodes.mark({ ok: false,
               errors: ['The Intermediate CA could not be issued: ' +
                        e.message + '. Nothing was stored.'] }, 'STS-PKI-0006');
    }
  }

  // THE ISSUING CAs, one per use case this scope carries.
  const issuing = {};
  const wanted = useCasesFor(kind);
  for (let i = 0; i < wanted.length; i++) {
    const uc = wanted[i];
    const held = (existing.issuing || {})[uc.id];
    if (held && held.imported && !options.replaceImported) {
      issuing[uc.id] = held;
      continue;
    }
    const forThis = algorithmsForUseCase(uc, chosen, options);
    try {
      issuing[uc.id] = await issueCaTier({
        tier: 'issuing', profile: 'issuing-ca', label: uc.label + ' CA',
        useCase: uc.id, scope: id,
        cn: organisation + ' ' + uc.cn + ' (' + named + ')',
        organisation: organisation, country: country,
        keyAlg: forThis.keyAlg, signatureAlg: forThis.signatureAlg,
        altKeyAlg: chosen.altKeyAlg,
        pathLen: issuingPathLen(uc.id),
        years: tierYearsFrom(options.years, 'issuing'),
        parent: intermediate
      });
    } catch (e) {
      log.error(errorCodes.tag('STS-PKI-0007') + 'pki: ' + label + '\'s ' +
                uc.label + ' ' +
                'Issuing CA could not be ' +
                'issued: ' + e.message + '. Nothing was stored.');
      log.debug('Leaving buildScope(). The ' + uc.id + ' Issuing CA failed.');
      return errorCodes.mark({ ok: false,
               errors: ['The ' + uc.label + ' Issuing CA could not be ' +
                        'issued: ' + e.message + '. Nothing was stored.'] },
                             'STS-PKI-0007');
    }
  }

  // **THE BRANCH BEING REPLACED IS SUPERSEDED.** Everything under the old
  // Intermediate chains to an authority that is about to stop existing, so the
  // Intermediate goes on the ROOT's list and each old Issuing CA on the old
  // Intermediate's. Done here, before the row is written, because these are
  // the certificates that are about to be overwritten.
  if (existing.intermediate && intermediate !== existing.intermediate) {
    Object.keys(existing.issuing || {}).forEach(function (useCaseId) {
      supersede(id, 'intermediate', existing.issuing[useCaseId],
                'its Intermediate CA was rebuilt');
    });
    supersede(pki_rootScopeOf(), 'root', existing.intermediate,
              'the "' + (id || 'default') + '" branch was rebuilt');
  }
  // **ON THE ROW AS IT IS NOW, NOT AS IT WAS READ (2026-09-14, #46).** The
  // tiers above took several awaits, and `supersede()` and a row adopted from
  // another node both replace what `rawRowFor()` answers in the meantime — a
  // row built from the copy read before them would write their revocations
  // and certificates back out of it.
  const row = Object.assign({}, rawRowFor(id) || existing, {
    version: 2,
    scope: id,
    realm: kind === 'realm' ? id : null,
    createdAt: existing.createdAt || Date.now(),
    keyAlg: chosen.keyAlg,
    signatureAlg: chosen.signatureAlg,
    altKeyAlg: chosen.altKeyAlg,
    organisation: organisation,
    country: country,
    intermediate: intermediate,
    issuing: issuing,
    // Everything the workbench authored is left alone — those are somebody's
    // key pairs and a button labelled "build the certificate authority" has no
    // business discarding them.
    objects: (rawRowFor(id) || existing).objects || [],
    // **THE COUNT RESETS, because the Issuing CA it counts for is new.** It is
    // how many leaves THIS hierarchy has signed, and a rebuild replaces the
    // authority that signed them — everything it issued chains to nothing from
    // this moment, which is what the page says, so carrying the number over
    // would be counting certificates that no longer have an issuer.
    issuedCount: 0
  });
  // THE COMPATIBILITY SHAPE IS NOT STORED. `tiers` is composed on the way out
  // by `rawChainFor()` — the Root lives in the service row and one copy of a
  // private key is the whole of `pki.js`'s placement argument.
  delete row.tiers;
  saveRow(id, row);
  log.info('pki: ' + label + ' has a certificate authority branch: an ' +
           'Intermediate CA signed by the service Root, and ' + wanted.length +
           ' Issuing CA(s) — ' +
           wanted.map(function (one) { return one.label; }).join(', ') + '. ' +
           chosen.keyAlg + ' keys signed ' + chosen.signatureAlg +
           (chosen.altKeyAlg ? ', each with an alternative ' +
                               chosen.altKeyAlg + ' key (hybrid).'
                             : ', classical only.'));
  log.debug('Leaving buildScope(). ' + wanted.length + ' Issuing CA(s).');
  return { ok: true, chain: describeChain(rawChainFor(id)),
           scope: describeScope(id) };
}

// The door the console and `/admin-api` have always called, and the realm's
// branch is what it builds. **`buildChain()` KEEPS ITS NAME AND ITS SHAPE**:
// every caller of it means "give this realm a certificate authority", which is
// still exactly what happens — the Root it hangs from is simply the service's
// now rather than one of this realm's own.
async function buildChain(realmId, opts) {
  log.debug("Entering buildChain().");
  log.debug("Leaving buildChain().");
  return buildScope(realmIdOf(realmId), opts);
}

// ---------------------------------------------------------------------------
// THE HIERARCHY THIS REALM HOLDS, WHOLE — private keys included. Internal:
// nothing outside this module should call it, and `describe()` is what the
// console and the management API get.
//
// **`rawRowFor()` AND `rawChainFor()` ARE TWO QUESTIONS AND THE SPLIT ARRIVED
// WITH THE OBJECT STORE (2026-09-10).** The `pki:<realm>` row holds the three
// tiers AND the workbench's objects, and the two can exist independently: a
// self-signed certificate authored on `/admin/pki` before anybody pressed
// Build is a row with objects and no tiers. So the row accessor answers
// whatever is there and the CHAIN accessor keeps the check it has always had —
// three tiers or nothing — because "is there a hierarchy" is the question nine
// callers here ask and a half-built one must go on answering no.
// ---------------------------------------------------------------------------
function rawRowFor(realmId) {
  log.debug("Entering rawRowFor().");
  const id = realmIdOf(realmId);
  log.debug("Leaving rawRowFor().");
  return keystore.pkiFor(id) || null;
}

// **THE THREE-TIER VIEW IS COMPOSED AND NOT STORED, SINCE 2026-09-11.** The
// Root lives in the service row and one copy of a private key is the whole of
// this module's placement argument, so a realm's row holds its Intermediate
// and its Issuing CAs and this puts the Root back on top of them on the way
// out. Every caller that has ever asked for `tiers` — `describeChain()`,
// `chainPemFor()`, `trustAnchorsFor()`, `issueSigningKeyPair()`, the console
// and `/admin-api` — therefore sees exactly the shape it saw before the
// hierarchy grew: Root, Intermediate, Issuing.
//
// **WHICH ISSUING CA IT SHOWS AS THE THIRD TIER IS `assertions`**, because that
// use case IS the old `issuing` tier under a name: everything those callers did
// before this change they still do, through it. The other Issuing CAs are
// beside it in `issuing` and on `describeScope()`.
function rawChainFor(realmId) {
  log.debug("Entering rawChainFor().");
  const held = rawRowFor(realmId);
  const root = serviceRoot();
  if (!root || !held || !held.intermediate) {
    log.debug("Leaving rawChainFor().");
    return null;
  }
  const primary = (held.issuing || {})[primaryUseCaseFor(realmIdOf(realmId))];
  if (!primary) {
    log.debug("Leaving rawChainFor().");
    return null;
  }
  log.debug("Leaving rawChainFor().");
  return Object.assign({}, held, { tiers: [root, held.intermediate, primary] });
}

// The Issuing CA a scope's three-tier view ends at. A realm's is the
// application-assertion one, for the reason above; the process branch has no
// `assertions` use case at all, so it shows its TLS one — the branch still has
// a chain and a reader asking for it should get the one that certifies the
// thing that surface is mostly about.
function primaryUseCaseFor(scopeId) {
  log.debug("Entering primaryUseCaseFor().");
  log.debug("Leaving primaryUseCaseFor().");
  return scopeKindOf(scopeId) === 'process' ? 'tls' : 'assertions';
}

function hasChain(realmId) {
  log.debug("Entering hasChain().");
  log.debug("Leaving hasChain().");
  return !!rawChainFor(realmId);
}

// Write the row back, or REMOVE it when there is nothing left in it. An empty
// row is not the same as no row for a store that persists: a `pki:` row with
// neither tiers nor objects would be read back at the next start, counted in
// the "certificate authorities recovered" line and describe as nothing, which
// is a service reporting a hierarchy it does not have.
function saveRow(realmId, row) {
  log.debug('Entering saveRow().');
  const id = realmIdOf(realmId);
  const tiers = (row && row.tiers) || [];
  const objects = (row && row.objects) || [];
  // **AND THE BRANCH, SINCE 2026-09-11.** A scope's row holds an Intermediate
  // and its Issuing CAs where it used to hold three tiers, and a row counted as
  // empty because it has no `tiers` member would be a branch deleted the next
  // time anything wrote to it.
  const branch = (row && row.intermediate) ? 1 : 0;
  // **AND THE ROOT, AND THE REVOCATION LISTS (2026-09-11), AND THIS OMISSION
  // DESTROYED THE SERVICE'S ROOT CA.**
  //
  // The emptiness test above was written when every row held `tiers`. Two
  // kinds of row have arrived since that hold NEITHER `tiers`, `objects` nor
  // an `intermediate`:
  //
  //   * **the SERVICE row**, which holds the Root and nothing else — it is the
  //     whole point of that row that the branches are elsewhere;
  //   * **a row that holds only REVOCATION ENTRIES**, which is what an
  //     authority's list is when its scope carries nothing else.
  //
  // So `saveRow(SERVICE_SCOPE, row)` counted the Root as nothing and called
  // `attachPki(id, null)`, which REMOVES the row. `pki_revocation.revoke()`
  // saves through here, and a rotation supersedes the certificate it replaced
  // at its issuer — so `buildChain()` on any realm revoked the old
  // Intermediate at the ROOT's authority and deleted the Root in the same
  // act. Every chain in the process then composed to nothing.
  //
  // **NOTHING THREW AND THE BUILD REPORTED SUCCESS.** `buildChain()` answered
  // `{ ok: true }`, the branch it had just built was intact, and the failure
  // appeared one call later as `trustAnchorsFor()` returning an empty array —
  // an anchor test with nothing to test. `tests/pki.js`'s *and KEEPS the
  // Root* is what caught it, which is the assertion that exists because the
  // Root moving to service scope was itself a reversal.
  //
  // The test is *is there anything in this row at all*, spelt out rather than
  // narrowed to the two new cases, because that is the question and the last
  // three answers to it were each right when they were written.
  const rooted = (row && row.root) ? 1 : 0;
  const lists = (row && row.revoked &&
                 Object.keys(row.revoked).some(function (caId) {
                   return (row.revoked[caId] || []).length;
                 })) ? 1 : 0;
  if (!tiers.length && !objects.length && !branch && !rooted && !lists) {
    keystore.attachPki(id, null);
    log.debug('Leaving saveRow(). Nothing left; the row was removed.');
    return;
  }
  keystore.attachPki(id, row);
  // AND PUT ITS REVOCATION LISTS IN THE DIRECTORY, because every certificate
  // this row's authorities sign names an `ldap://` address for one — see
  // `publishScopeSoon()`. Lazily required for `revocationExtensionsFor()`'s
  // reason. Coalesced there, so a build of nine saves publishes once.
  try {
    require('./pki_revocation').publishScopeSoon(id);
  } catch (e) {
    log.debug("Caught in saveRow(): " + ((e && e.message) || e));
  }
  log.debug('Leaving saveRow(). ' + tiers.length + ' tier(s), ' +
            objects.length + ' object(s).');
}

// The public view. Every private key is dropped HERE and not at each caller,
// which is the one rule that keeps a PEM out of `/admin-api` and out of the
// audit log: a caller that forgot would be handing out the Root's key.
function describeChain(chain) {
  log.debug('Entering describeChain().');
  if (!chain) {
    log.debug('Leaving describeChain(). Nothing to describe.');
    return null;
  }
  log.debug('Leaving describeChain(). ' + (chain.tiers || []).length +
            ' tier(s).');
  return {
    realm: chain.realm,
    createdAt: chain.createdAt,
    keyAlg: chain.keyAlg,
    signatureAlg: chain.signatureAlg,
    altKeyAlg: chain.altKeyAlg || null,
    organisation: chain.organisation,
    country: chain.country,
    issuedCount: chain.issuedCount || 0,
    persisted: keystore.persists(),
    tiers: (chain.tiers || []).map(function (one, index) {
      const tier = /** @type {any} */ (TIERS[index] || {});
      return {
        tier: one.tier,
        label: one.label,
        what: tier.what || '',
        subject: one.subject,
        serialHex: one.serialHex,
        notBefore: one.notBefore,
        notAfter: one.notAfter,
        keyAlg: one.keyAlg,
        signatureAlg: one.signatureAlg,
        // The hybrid half (#68), as describeTier() reports it.
        altKeyAlg: one.altKeyAlg || null,
        altSignatureAlg: one.altSignatureAlg || null,
        thumbprint: one.thumbprint,
        // The certificate is PUBLIC and is the thing a relying party needs, so
        // it goes out whole. The private key is not here at all.
        certificatePem: one.certificatePem,
        expired: new Date(one.notAfter).getTime() < Date.now()
      };
    })
  };
}

function describe(realmId) {
  log.debug('Entering describe().');
  const out = describeChain(rawChainFor(realmId));
  log.debug('Leaving describe(). ' + (out ? 'A hierarchy.' : 'None.'));
  return out;
}

// ONE TIER, PUBLIC. The same dropping rule `describeChain()` follows and for
// its reason: every private key goes on the way out HERE, so a caller cannot
// leak one by forgetting.
function describeTier(one) {
  log.debug("Entering describeTier().");
  if (!one) {
    log.debug("Leaving describeTier().");
    return null;
  }
  const uc = one.useCase ? useCase(one.useCase) : null;
  log.debug("Leaving describeTier().");
  return {
    tier: one.tier,
    useCase: one.useCase || null,
    label: one.label,
    what: uc ? uc.what
             : ((TIERS.filter(function (t) { return t.id === one.tier; })[0] ||
                 {}).what || ''),
    scope: one.scope || null,
    subject: one.subject,
    serialHex: one.serialHex,
    notBefore: one.notBefore,
    notAfter: one.notAfter,
    keyAlg: one.keyAlg,
    signatureAlg: one.signatureAlg,
    // The hybrid half (#68): the alternative key this tier holds and the
    // algorithm its own alternative signature was made with — null for a
    // classical tier. Never the private half.
    altKeyAlg: one.altKeyAlg || null,
    altSignatureAlg: one.altSignatureAlg || null,
    thumbprint: one.thumbprint,
    imported: !!one.imported,
    certificatePem: one.certificatePem,
    expired: new Date(one.notAfter).getTime() < Date.now()
  };
}

// ---------------------------------------------------------------------------
// ONE SCOPE'S WHOLE BRANCH — the Intermediate and every Issuing CA under it,
// with the certificates each one has issued counted. This is what the console
// draws a tree from and what `GET /admin-api/pki` publishes beside the
// three-tier view.
// ---------------------------------------------------------------------------
function describeScope(scopeId) {
  log.debug('Entering describeScope(). scope=' + scopeId);
  const id = String(scopeId);
  const kind = scopeKindOf(id);
  const row = rawRowFor(id);
  const out = {
    scope: id,
    kind: kind,
    label: kind === 'process' ? 'Process' : (id || 'default'),
    built: !!(row && row.intermediate),
    keyAlg: (row && row.keyAlg) || '',
    signatureAlg: (row && row.signatureAlg) || '',
    // The branch's alternative key algorithm (#68): an id, `none` for a
    // branch built classical on purpose, '' for one built before the field.
    altKeyAlg: (row && row.altKeyAlg) ||
               (row && row.altKeyAlg === null ? ALTERNATIVE_NONE : ''),
    organisation: (row && row.organisation) || '',
    country: (row && row.country) || '',
    intermediate: describeTier(row && row.intermediate),
    issuing: useCasesFor(kind).map(function (uc) {
      const held = (row && row.issuing) ? row.issuing[uc.id] : null;
      return {
        id: uc.id,
        label: uc.label,
        what: uc.what,
        built: !!held,
        ca: describeTier(held),
        // What this Issuing CA has actually certified, which is the half a
        // tree of authorities cannot show on its own: an Issuing CA with no
        // leaves under it is either brand new or the one nothing is wired to.
        certified: certificatesFor(id, uc.id).map(describeCertificate)
      };
    })
  };
  log.debug('Leaving describeScope(). ' + out.issuing.length +
            ' Issuing CA(s).');
  return out;
}

// THE WHOLE TREE: the Root, the process branch, and every realm's. It is one
// function because the console's picture and the management API's reply are
// one question asked twice, and two walks of this store would eventually
// disagree about what a branch is.
function describeTree(realmIds) {
  log.debug('Entering describeTree().');
  const root = serviceRoot();
  const scopes = [PROCESS_SCOPE].concat(
    (realmIds || []).map(function (one) { return String(one); }));
  const out = {
    root: describeTier(root),
    rootBuilt: !!root,
    persisted: keystore.persists(),
    organisation: (serviceRow() || {}).organisation || '',
    useCases: USE_CASES.map(function (one) {
      return { id: one.id, label: one.label, scope: one.scope,
               what: one.what };
    }),
    scopes: scopes.map(describeScope)
  };
  log.debug('Leaving describeTree(). ' + out.scopes.length + ' scope(s).');
  return out;
}

// The chain a leaf issued here travels with, leaf-first and WITHOUT the root —
// which is what RFC 5246 section 7.4.2 asks of a TLS certificate_list and what
// every JWS `x5c` header does. The root is a trust anchor: sending it is
// harmless and relying on it having been sent is the mistake.
function chainPemFor(realmId) {
  log.debug("Entering chainPemFor().");
  const chain = rawChainFor(realmId);
  if (!chain) {
    log.debug("Leaving chainPemFor().");
    return [];
  }
  log.debug("Leaving chainPemFor().");
  return chain.tiers.slice().reverse()
    .filter(function (one) { return one.tier !== 'root'; })
    .map(function (one) { return one.certificatePem; });
}

// The trust anchors — the Root, and nothing else. What `verifyLeaf()` builds a
// path to, and what an operator hands to a relying party out of band.
function trustAnchorsFor(realmId) {
  log.debug("Entering trustAnchorsFor().");
  const chain = rawChainFor(realmId);
  if (!chain) {
    log.debug("Leaving trustAnchorsFor().");
    return [];
  }
  log.debug("Leaving trustAnchorsFor().");
  return chain.tiers.filter(function (one) { return one.tier === 'root'; })
    .map(function (one) { return one.certificatePem; });
}

// ---------------------------------------------------------------------------
// ISSUE A SIGNING KEY PAIR FOR ONE APPLICATION.
//
// The leaf is a `digital-signature` profile certificate — `digitalSignature`
// and `nonRepudiation`, no extended key usage — because what it signs is a JWT,
// not a TLS handshake. Giving it `clientAuth` would make it usable for RFC 8705
// as well, which is a DIFFERENT credential with a different registration
// attribute, and one certificate quietly doing both is how a deployment ends up
// unable to revoke either.
//
// **THE PRIVATE KEY IS RETURNED AND NOT KEPT.** The caller writes it onto the
// application's entry; this module forgets it on the way out. See the header.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// WHAT A LEAF IS FOR, AND WHY IT IS A FIELD RATHER THAN A CONVENTION.
//
// An application may hold TWO signing key pairs issued from this hierarchy —
// one for RFC 7523 (a JWT assertion) and one for RFC 7522 (a SAML 2.0
// assertion) — and they must be genuinely separate: `applications.js` keeps
// them in two attribute sets and no verifier reads the other's.
//
// **THE PURPOSE IS PUT IN THE CERTIFICATE ITSELF, as a second URI
// subjectAltName**, so that a certificate read out of context says which
// profile it was issued for. That is worth a line of encoder work because the
// alternative — telling them apart by which directory attribute they were
// stored in — is an answer nobody holding a PEM file can get to.
//
// `jwt` is the DEFAULT and its certificate is byte-for-byte what this function
// produced before purposes existed: one SAN, the application URI. That is
// deliberate rather than tidy — every certificate issued before 2026-09-11 is
// a `jwt` one, and a default that changed their shape would make this
// function's output depend on when it was called.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// WHO A LEAF IS ISSUED TO, AND WHY THAT IS A FIELD AS WELL (2026-09-11).
//
// This function issued to APPLICATIONS and to nothing else until RFC 7523
// section 2.1 grew a second kind of issuer. A PERSON may hold a signing key
// pair now — `common/person_assertions.js` is the register — and sign an
// assertion saying *this is me, issue a token for me*, which is the shape
// section 2.1 describes when the `sub` is a resource owner rather than a
// client.
//
// **IT IS A FIELD RATHER THAN A SECOND FUNCTION** because nothing else about
// the issue differs: the same Issuing CA, the same profile, the same
// `digital-signature` certificate, the same JWKS with the chain in `x5c`. Two
// functions would be two answers to *how does this service issue a signing key
// pair*, and the second would be the one that stopped getting the next fix.
//
// **WHAT IT DECIDES IS TWO STRINGS, AND BOTH ARE READ BY SOMETHING.** The URN
// in the certificate's URI subjectAltName — which `assertion_grant.js` reads
// off a presented `x5c` to decide whether a certificate this service issued
// authorizes an assertion ABOUT ANYBODY or only about the person named in it —
// and the `kid` prefix, which is a display convention and is what an operator
// looking at a JWKS sees first.
//
// `application` is the DEFAULT and both of its strings are what this function
// produced before this field existed, so every certificate and every kid
// issued before 2026-09-11 reads the same. That is the same decision the
// PURPOSES table below records about `jwt`.
// ---------------------------------------------------------------------------
const SUBJECT_KINDS = [
  { id: 'application', label: 'an application',
    urnPrefix: 'urn:sts:application:', kidPrefix: 'app-',
    what: 'A registered OAuth client or relying party. Its key pair is ' +
          'written onto its own entry in ou=applications.' },
  { id: 'person', label: 'a person',
    urnPrefix: 'urn:sts:person:', kidPrefix: 'person-',
    what: 'Somebody in ou=users. Their key pair signs an RFC 7523 section ' +
          '2.1 assertion ABOUT THEMSELVES and about nobody else — see ' +
          'common/person_assertions.js, which is where the refusal is ' +
          'argued.' }
];

const SUBJECT_KIND_IDS = SUBJECT_KINDS.map(function (one) { return one.id; });

function subjectKindFor(id) {
  log.debug("Entering subjectKindFor().");
  const wanted = String(id || 'application');
  log.debug("Leaving subjectKindFor().");
  return SUBJECT_KINDS.filter(function (one) {
    return one.id === wanted;
  })[0] || null;
}

const PURPOSES = [
  { id: 'jwt', label: 'RFC 7523 — a JWT assertion',
    profileUri: '',
    what: 'A JWS signing key. Its public half is written onto the ' +
          'application as a JWKS (oauthAssertionJwks) carrying the ' +
          'certificate chain in x5c, which is how RFC 7523 registers a key.' },
  { id: 'saml', label: 'RFC 7522 — a SAML 2.0 assertion',
    profileUri: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
    what: 'An XML Signature key. Its certificate is written onto the ' +
          'application as a PEM (oauthSamlAssertionCertificate), because ' +
          'SAML has no JWKS and what a party registers for that profile IS a ' +
          'certificate.' }
];

const PURPOSE_IDS = PURPOSES.map(function (one) { return one.id; });

function purposeFor(id) {
  log.debug("Entering purposeFor().");
  const wanted = String(id || 'jwt');
  log.debug("Leaving purposeFor().");
  return PURPOSES.filter(function (one) { return one.id === wanted; })[0] ||
         null;
}

// ---------------------------------------------------------------------------
// AN ENCRYPTION KEY PAIR (#168): the same leaf, the same Issuing CA, the same
// revocation register — for a KEY THIS SERVICE DECRYPTS WITH rather than one
// it or somebody else signs with. A federation relationship's service-provider
// key is the first, published in its metadata (`KeyDescriptor
// use="encryption"`) and its relying-party JWKS (`use: enc`).
//
// It differs from a signing leaf in exactly four places, and each is RFC
// 5280's or RFC 7517's rather than a preference: KeyUsage says
// `keyEncipherment` for an RSA key (it transports a content key) and
// `keyAgreement` for an EC one (it agrees one), and never `digitalSignature`
// — a decryption key that also signs is the XML Encryption 1.1 section 6.1.3
// hazard; the JWK says `use: enc`; the subjectAltName URN names a federation
// relationship; and the kid is prefixed `fedenc-`.
//
// It goes through `issueSigningKeyPair()` rather than beside it, with a
// marker only this module can make, because the other ninety lines — the
// chain, the lifetime clamp, the issuer's algorithm, the revocation
// extensions, the serial the OCSP responder answers for — are the SAME and a
// second copy is the one that drifts. The marker is a Symbol, so no request
// body passed through to that function can ask for it.
// ---------------------------------------------------------------------------
const ENCRYPTION_LEAF = Symbol('encryption-leaf');
const ENCRYPTION_KEY_ALGS = ['rsa-3072', 'ec-p256'];

async function issueEncryptionKeyPair(realmId, opts) {
  log.debug('Entering issueEncryptionKeyPair().');
  const options = opts || {};
  const keyAlg = String(options.keyAlg || 'rsa-3072');
  if (ENCRYPTION_KEY_ALGS.indexOf(keyAlg) < 0) {
    log.debug('Leaving issueEncryptionKeyPair(). Unknown key type.');
    return errorCodes.mark({ ok: false,
             errors: ['"' + keyAlg + '" is not a key type this service ' +
                      'issues an encryption key pair of. It issues ' +
                      ENCRYPTION_KEY_ALGS.join(' and ') + '.'] },
                           'STS-PKI-0192');
  }
  const out = await issueSigningKeyPair(realmId, Object.assign({}, options,
    { keyAlg: keyAlg, [ENCRYPTION_LEAF]: true }));
  log.debug('Leaving issueEncryptionKeyPair(). ' + (out.ok ? 'Issued.' :
                                                    'Refused.'));
  return out;
}

async function issueSigningKeyPair(realmId, opts) {
  log.debug('Entering issueSigningKeyPair().');
  const id = realmIdOf(realmId);
  const options = opts || {};
  const encryption = options[ENCRYPTION_LEAF] === true;
  const chain = rawChainFor(id);
  if (!chain) {
    log.debug('Leaving issueSigningKeyPair(). No hierarchy.');
    return errorCodes.mark({ ok: false,
             errors: ['The "' + (id || 'default') + '" realm has no ' +
                      'certificate authority yet. Build one on /admin/pki — ' +
                      'or POST /admin-api/pki/build — and then issue from ' +
                      'it. A key pair signed by nothing is a key pair an ' +
                      'operator has to move by hand, which is what this ' +
                      'exists to avoid.'] }, 'STS-PKI-0008');
  }
  const identifier = String(options.identifier || '');
  if (!identifier) {
    log.debug('Leaving issueSigningKeyPair(). No identifier.');
    return errorCodes.mark({ ok: false,
             errors: ['A certificate is issued TO something. Name the ' +
                      'application it is for.'] }, 'STS-PKI-0010');
  }
  // WHICH PROFILE THIS LEAF IS FOR. Refused rather than defaulted when it is
  // named and unknown: a caller that asked for a purpose this service does not
  // have wants a certificate for something, and silently handing back a JWT
  // one would put a key pair on the wrong attribute set with nothing saying so.
  const purpose = encryption
    ? { id: 'encryption', label: 'an encryption key', profileUri: '' }
    : purposeFor(options.purpose);
  if (!purpose) {
    log.debug('Leaving issueSigningKeyPair(). Unknown purpose.');
    return errorCodes.mark({ ok: false,
             errors: ['"' + options.purpose + '" is not a purpose this ' +
                      'service issues a signing key pair for. It issues ' +
                      PURPOSE_IDS.join(' and ') + '.'] }, 'STS-PKI-0011');
  }
  // WHO THIS LEAF IS FOR. Refused rather than defaulted when it is named and
  // unknown, for the reason the purpose above is: a caller that asked for a
  // subject kind this service does not have wants a certificate that says
  // something, and handing back an `application` one would put the wrong URN
  // in the subjectAltName with nothing saying so.
  const subjectKind = encryption
    ? { id: 'federation', label: 'a federation relationship',
        urnPrefix: 'urn:sts:federation:', kidPrefix: 'fedenc-' }
    : subjectKindFor(options.subjectKind);
  if (!subjectKind) {
    log.debug('Leaving issueSigningKeyPair(). Unknown subject kind.');
    return errorCodes.mark({ ok: false,
             errors: ['"' + options.subjectKind + '" is not a kind of ' +
                      'subject this service issues a signing key pair to. It ' +
                      'issues ' +
                      'to ' + SUBJECT_KIND_IDS.join(' and ') + '.'] },
                           'STS-PKI-0012');
  }
  const issuing = chain.tiers[chain.tiers.length - 1];
  // The leaf follows the ISSUING CA's key algorithm by default, because a chain
  // whose leaf and issuer are the same family is the one a client library is
  // least likely to surprise anybody with. A caller may name another.
  const keyAlgId = String(options.keyAlg || chain.keyAlg);
  const keyDesc = keyMaterial.keyAlg(keyAlgId);
  if (!keyDesc) {
    log.debug("Leaving issueSigningKeyPair().");
    return errorCodes.mark({ ok: false,
             errors: ['"' + keyAlgId + '" is not a key algorithm this ' +
                      'service can generate.'] }, 'STS-PKI-0002');
  }
  // The SIGNATURE on the leaf is made by the ISSUING CA's key, so it is the
  // issuer's algorithm that constrains it and not the subject's. Getting this
  // the wrong way round produces a certificate whose declared algorithm and
  // actual signature disagree, which `openssl verify` reports as a bad
  // signature naming neither — the vendored module's header says so at length.
  if (options.signatureAlg &&
      (x509.sigAlg(String(options.signatureAlg)) || {}).weak &&
      !mode.usesBrokenAlgorithms()) {
    log.debug("Leaving issueSigningKeyPair(). SHA-1, in product.");
    return errorCodes.mark({ ok: false,
             errors: ['"' + options.signatureAlg + '" signs with SHA-1, ' +
                      'which this realm does not use in product mode ' +
                      '(global.mode=product).'] }, 'STS-PKI-0191');
  }
  // An algorithm INHERITED from the branch is passed over in product when it
  // is SHA-1 (#181), as `signatureForIssuer()` does for the tiers.
  const inherited = x509.sigAlg(String(chain.signatureAlg || '')) || {};
  const sigAlgId = String(options.signatureAlg ||
                          (inherited.weak && !mode.usesBrokenAlgorithms()
                            ? defaultSignatureAlgorithmFor(issuing.keyAlg)
                            : chain.signatureAlg));
  const sig = x509.sigAlg(sigAlgId);
  const issuerDesc = keyMaterial.keyAlg(issuing.keyAlg);
  if (!sig || !issuerDesc || sig.kind !== issuerDesc.kind) {
    log.debug("Leaving issueSigningKeyPair().");
    return errorCodes.mark({ ok: false,
             errors: ['The Issuing CA holds a ' + (issuerDesc || {}).label +
                      ' key, which cannot produce a "' + sigAlgId +
                      '" signature. It can produce ' +
                      signatureAlgorithms(issuing.keyAlg).map(function (one) {
                        return one.id;
                      }).join(', ') + '.'] }, 'STS-PKI-0004');
  }

  // `pki.leafLifetimeDays` WHEN THE CALLER NAMES NONE, and not the literal 365
  // this was until 2026-09-12. `certify()` below read the setting; this door —
  // an application's RFC 7523 key pair, a person's, the SAML one — did not, so
  // the one setting described as "the default lifetime of an issued key pair"
  // governed every issued key pair except the ones it was written for. The two
  // happened to agree at the default, which is why nothing noticed.
  const days = Number(options.days) > 0 ? Math.floor(Number(options.days))
                                        : leafLifetimeDays();
  const commonName = String(options.commonName || identifier);
  // Seconds and no finer, like the CA tiers above. A leaf is years rather than
  // decades out, so it is a UTCTime and carries no fractional part anyway — it
  // goes through the same helper so that there is ONE answer to "what does a
  // validity in this module look like" rather than one per lifetime.
  const notBefore = certificateInstant();
  const notAfter = certificateInstant(notBefore.getTime() + days * 86400000);
  // A leaf may not outlive the CA that signed it. Clamped rather than refused:
  // the ordinary cause is a five-year Issuing CA in its fifth year, and an
  // operator who asked for a year should get eleven months rather than an error
  // about arithmetic.
  const issuerNotAfter = new Date(issuing.notAfter).getTime();
  if (notAfter.getTime() > issuerNotAfter) {
    log.warn('pki: the certificate asked for "' + identifier + '" would ' +
             'outlive the Issuing CA that signs it, so it was shortened to ' +
             'the CA\'s own expiry (' + issuing.notAfter + ').');
    notAfter.setTime(issuerNotAfter);
  }

  const pair = await keyMaterial.generateKeyPair(keyAlgId);
  const subject = [{ name: 'CN', value: commonName },
                   { name: 'O', value: chain.organisation }]
    .concat(chain.country ? [{ name: 'C', value: chain.country }] : []);
  let issued;
  try {
    // Signed twice where the Issuing CA is hybrid (#68) — see
    // alternativeSignatureBy().
    issued = await x509.issueCertificate(Object.assign({
      subject: subject,
      subjectPublicKey: pair.publicPem,
      signatureAlg: sigAlgId,
      profile: encryption ? 'key-encipherment' : 'digital-signature',
      notBefore: notBefore.toISOString(),
      notAfter: notAfter.toISOString(),
      issuer: { certificatePem: issuing.certificatePem,
                privateKeyPem: issuing.privateKeyPem,
                keyAlg: issuing.keyAlg },
      extensions: Object.assign({
        basicConstraints: { present: true, critical: true, ca: false },
        keyUsage: { present: true, critical: true,
                    usages: !encryption
                      ? ['digitalSignature', 'nonRepudiation']
                      : (keyDesc.kind === 'ec' ? ['keyAgreement']
                                               : ['keyEncipherment']) },
        subjectKeyIdentifier: { present: true },
        authorityKeyIdentifier: { present: true },
        // The subject's own identifier as a URI subjectAltName, so that a
        // certificate read out of context says WHO it is for. The CN says it
        // too; a CN is a display name and a SAN is the machine-readable one,
        // and every path validator written since RFC 2818 reads the SAN.
        // A SECOND URI NAME WHERE THE PURPOSE HAS ONE — see the PURPOSES
        // table. `jwt` carries none, so a certificate issued for it has the
        // same subjectAltName it had before purposes existed.
        //
        // **AND THE URN SAYS WHICH KIND OF SUBJECT IT IS** — see SUBJECT_KINDS
        // above. `application` is the default and its URN is unchanged, so
        // every certificate issued before 2026-09-11 still reads the same; a
        // PERSON's says `person`, and `assertion_grant.js` reads exactly that
        // to decide what an assertion signed with this key may say.
        subjectAltName: { present: true, critical: false,
                          names: [{ kind: 'uri',
                                    value: subjectKind.urnPrefix + identifier }]
                            .concat(purpose.profileUri
                              ? [{ kind: 'uri', value: purpose.profileUri }]
                              : []) }
      },
      // **WHERE THE LIST THAT WOULD REVOKE THIS KEY PAIR IS (2026-09-12).**
      // `certify()` and `issueCaTier()` have named their issuer's CRL and OCSP
      // responder since 2026-09-11 and this door did not, so the one leaf this
      // hierarchy hands to something that is NOT this service — an
      // application's or a person's RFC 7523 / RFC 7522 key pair, the
      // certificate a relying party is most likely to be handed out of context
      // — was the one certificate that could not say where to look. The
      // issuer is the use case the chain's Issuing tier belongs to.
      revocationExtensionsFor(id, issuing.useCase || primaryUseCaseFor(id)))
    }, alternativeSignatureBy(issuing)));
  } catch (e) {
    log.error(errorCodes.tag('STS-PKI-0013') + 'pki: a signing certificate ' +
                                               'for ' +
                                               '"' + identifier + '" ' +
              'could not be issued: ' + e.message);
    log.debug('Leaving issueSigningKeyPair(). The encoder refused.');
    return errorCodes.mark({ ok: false,
             errors: ['The certificate could not be issued: ' + e.message] },
                           'STS-PKI-0013');
  }

  // The public half as a JWK, with a `kid` derived FROM THE KEY MATERIAL — the
  // same rule every kid in this service follows, and for the same reason: two
  // keys under one name is a verifier reporting a bad signature about a key it
  // fetched from the wrong place.
  const publicJwk = publicJwkOf(pair.publicPem);
  const jwsAlg = jwsAlgFor(keyDesc, sigAlgId);
  publicJwk.kid = subjectKind.kidPrefix +
                  stsCrypto.jwkThumbprint(publicJwk, { truncate: 16 });
  publicJwk.use = encryption ? 'enc' : 'sig';
  if (jwsAlg && !encryption) {
    publicJwk.alg = jwsAlg;
  }
  // `x5c` is the certificate chain in the JWK itself (RFC 7517 section 4.7):
  // base64 DER, leaf first, NOT base64url. A client that registers this JWKS
  // therefore registers the chain as well, which is what lets `client_auth.js`
  // check a path to the service Root through this realm's Intermediate
  // (`verifyLeaf()`) instead of trusting a bare public key.
  // **NO `slice()` HERE — `chainPemFor()` DOES NOT INCLUDE THE LEAF.** It
  // answers the Issuing CA and the Intermediate, leaf-first order without the
  // leaf, so dropping its first member drops the ISSUING CA — and an `x5c`
  // missing the certificate that signed the leaf is a chain nothing can build
  // a path from. `tests/pki.js` counts the members for exactly that reason.
  publicJwk.x5c = [stsCrypto.stripPem(issued.pem)]
    .concat(chainPemFor(id).map(stsCrypto.stripPem));
  publicJwk['x5t#S256'] = stsCrypto.certificateThumbprint(issued.pem,
                                                          { format:
                                                              'base64url' });

  const record = {
    identifier: identifier,
    realm: id,
    // WHICH PROFILE, on the record as well as in the certificate. The caller
    // decides which attribute set to write from this rather than from what it
    // asked for, so a purpose that was defaulted and one that was named land
    // in the same place.
    purpose: purpose.id,
    purposeLabel: purpose.label,
    // WHICH KIND OF SUBJECT, on the record for the reason the purpose is on
    // it: the caller writes from the record rather than from what it asked
    // for, so a kind that was defaulted and one that was named land in the
    // same place.
    subjectKind: subjectKind.id,
    subjectKindLabel: subjectKind.label,
    subjectUri: subjectKind.urnPrefix + identifier,
    kid: publicJwk.kid,
    keyAlg: keyAlgId,
    signatureAlg: sigAlgId,
    jwsAlg: jwsAlg,
    subject: issued.subject,
    serialHex: issued.serialHex,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    certificatePem: issued.pem,
    chainPem: chainPemFor(id),
    privateKeyPem: pair.privatePem,
    publicKeyPem: pair.publicPem,
    publicJwk: publicJwk,
    jwks: { keys: [publicJwk] },
    thumbprint: thumbprintOf(issued.pem),
    // THE SAME DIGEST IN THE SPELLING RFC 7522's VERIFIER MATCHES ON. The
    // `thumbprint` above is this module's own display form; this is
    // `certificateThumbprint(..., base64url)`, which is what `x5t#S256` above
    // carries and what `saml_assertion_grant.js` compares a presented
    // <ds:KeyInfo> against. Two spellings of one digest, both computed here,
    // because a caller deriving the second from the first would be a second
    // place for the encoding to go wrong.
    certificateThumbprint: stsCrypto.certificateThumbprint(issued.pem,
                                                           { format:
                                                               'base64url' }),
    issuedAt: Date.now()
  };
  // The count moves and the hierarchy is written back.
  //
  // **AND THE LEAF'S SERIAL IS RECORDED, WITHOUT ITS KEY (2026-09-12).** This
  // said *nothing about the LEAF is stored, so this is one integer and not a
  // register*, and that was affordable only while the certificate named no
  // revocation service. It names one now, and `pki_revocation.js`'s OCSP
  // responder answers `good` only for a serial its authority is known to have
  // issued — so an unrecorded key pair would have pointed a relying party at a
  // responder that disowns it (`unknown`), and the revoke pane on /admin/pki
  // could not have offered it. What is kept is what a CRL entry and an OCSP
  // answer are made of — serial, subject, expiry, who it was for — and never
  // the private or public key, so *this module forgets the key on the way out*
  // is still true. An expired record is dropped at the next issue: RFC 5280
  // section 3.3 lets a list forget an expired certificate, and a revoked one
  // stays on its list through `revoked`, which is a different member.
  const nowMs = Date.now();
  chain.issuedKeyPairs = (chain.issuedKeyPairs || []).filter(function (one) {
    return one && new Date(one.notAfter).getTime() > nowMs;
  }).concat([{
    serialHex: issued.serialHex,
    subject: issued.subject,
    notAfter: record.notAfter,
    identifier: identifier,
    subjectKind: subjectKind.id,
    purpose: purpose.id,
    useCase: issuing.useCase || primaryUseCaseFor(id),
    issuedAt: record.issuedAt
  }]);
  chain.issuedCount = (chain.issuedCount || 0) + 1;
  saveRow(id, chain);
  log.info('pki: a ' + keyDesc.label + ' signing key pair was issued for "' +
           identifier + '" in the "' + id + '" realm for ' + purpose.label +
           ', signed ' + sig.label + ' by the Issuing CA. kid=' + record.kid +
           ', thumbprint=' + record.certificateThumbprint + ', expires ' +
           record.notAfter + '.');
  log.debug('Leaving issueSigningKeyPair(). kid=' + record.kid);
  return { ok: true, issued: record };
}

// ===========================================================================
// RFC 5280 SECTION 6.1, ONCE: THE RULES EVERY PATH HERE IS HELD TO
// (#201, 2026-09-24).
//
// **UNTIL THIS DATE THERE WERE THREE SETS OF RULES AND NONE OF THEM WAS
// WHOLE.** `authorityProblem()` below held a path to cA, keyCertSign and
// pathLenConstraint and to nothing else — so `verifyLeaf()`,
// `verifySignerChain()` and `registerCertificate()` accepted a path through a
// CA whose nameConstraints EXCLUDED the leaf, and a certificate carrying a
// critical extension nothing here implements. `verifyPathToAnchors()` refused
// both, but refused EVERY path through a nameConstraints CA, built its path
// greedily (the first issuer whose NAME matched, never the next one), and
// counted self-issued certificates against a pathLenConstraint that RFC 5280
// section 6.1.4(l) says they do not count against. C2SP x509-limbo, driven
// through all of them by `tests/x509_limbo.js`, is what found each of those.
//
// So the certificate FACTS are read once (`pathFactsOf()`), and one function
// (`pathRuleProblem()`) answers, for a path leaf first and anchor last, every
// section 6.1 question that is not a signature or a clock:
//
//   * every certificate: parses; no extension twice (4.2); no critical
//     extension this module does not implement (4.2), unless the caller
//     names it; a subjectAltName that parses and is critical when the
//     subject is empty (4.2.1.6); an ML-DSA key whose keyUsage names only
//     what RFC 9881 section 5 permits;
//   * every certificate above the leaf: cA=TRUE (6.1.4(k)), keyCertSign where
//     a keyUsage is present (6.1.4(n)), a pathLenConstraint not exceeded by
//     the NON-SELF-ISSUED certificates below it (6.1.4(l), (m)), a non-empty
//     subject (4.1.2.6);
//   * the leaf: keyCertSign only on a CA (4.2.1.9), nameConstraints only on a
//     CA (4.2.1.10);
//   * NAME CONSTRAINTS (4.2.1.10, 6.1.3(b), (c), 6.1.4(g)), for dNSName,
//     rfc822Name, uniformResourceIdentifier, iPAddress and directoryName —
//     every name of every certificate below a constraining CA, the leaf
//     always and a self-issued intermediate never, against each CA's
//     permitted and excluded subtrees. A constraint in a form this module
//     does not evaluate (otherName, x400Address, ediPartyName, registeredID,
//     or a subtree with a minimum or maximum) refuses a certificate that
//     carries a name of that form, which is what 4.2.1.10 requires of an
//     application that cannot process it. A malformed extension is refused.
//   * CERTIFICATE POLICIES (6.1.3(d)-(f), 6.1.4(a)-(j), 6.1.5), whole: the
//     valid_policy_tree, explicit_policy, inhibit_anyPolicy and
//     policy_mapping, with certificatePolicies, policyMappings,
//     policyConstraints and inhibitAnyPolicy read and so understood when
//     critical (`pathPolicyOutcome()`; NIST PKITS section 4.8-4.12 holds it).
//
// What it does NOT answer is argued where it is not: a signature and the
// issuer-to-subject link are the path BUILDER's (a path is only ever made of
// certificates that verified each other); the clock is `pathValidityProblem()`;
// revocation is `revocation_status.js`'s; the purpose of the leaf
// (extKeyUsage, a digitalSignature bit) is each CALLER's, because an
// attestation EK and a JWS signing key are asked different things.
//
// Everything here is SYNCHRONOUS, pkijs and asn1js only, so a synchronous door
// (`verifyIssuedDirectly()`) asks the same rules as the asynchronous ones.
// ===========================================================================

const PATH_EXTENSION_OIDS = {
  subjectKeyIdentifier: '2.5.29.14',
  keyUsage: '2.5.29.15',
  subjectAltName: '2.5.29.17',
  basicConstraints: '2.5.29.19',
  nameConstraints: '2.5.29.30',
  authorityKeyIdentifier: '2.5.29.35',
  extKeyUsage: '2.5.29.37',
  // RFC 5280 section 6.1's policy processing (#201): read, and so understood
  // when critical.
  certificatePolicies: '2.5.29.32',
  policyMappings: '2.5.29.33',
  policyConstraints: '2.5.29.36',
  inhibitAnyPolicy: '2.5.29.54'
};
const ANY_POLICY = '2.5.29.32.0';
// The most nodes one path's valid_policy_tree may hold. A tree grows with
// the product of the policies and mappings along the path, and an unbounded
// one is a denial of service (CVE-2023-0464 in OpenSSL); a path past it is
// refused rather than evaluated.
const PATH_MAX_POLICY_NODES = 10000;
// Every extension this module reads and so may accept marked critical. The
// purpose extensions (keyUsage, extKeyUsage) are the caller's to ask about,
// and understanding them is what lets a caller ask.
const PATH_UNDERSTOOD_CRITICAL = Object.keys(PATH_EXTENSION_OIDS)
  .map(function (name) { return PATH_EXTENSION_OIDS[name]; });
const PATH_KEY_USAGE_BITS = ['digitalSignature', 'nonRepudiation',
                             'keyEncipherment', 'dataEncipherment',
                             'keyAgreement', 'keyCertSign', 'cRLSign',
                             'encipherOnly', 'decipherOnly'];
const PATH_EMAIL_ADDRESS_OID = '1.2.840.113549.1.9.1';
// RFC 9881 section 2's three ML-DSA parameter sets, and section 5's rule for
// the keyUsage a certificate carrying one of them may state.
const PATH_ML_DSA_OIDS = ['2.16.840.1.101.3.4.3.17',
                          '2.16.840.1.101.3.4.3.18',
                          '2.16.840.1.101.3.4.3.19'];
const PATH_ML_DSA_USAGES = ['digitalSignature', 'nonRepudiation',
                            'keyCertSign', 'cRLSign'];
// Signature algorithms whose hash is broken, by the OID a certificate's
// signatureAlgorithm names: MD2 and MD5 are refused on every path; SHA-1 on
// every path but this service's own hierarchy in development, where
// `pki.signatureAlgorithm` `sha1-*` may have built it (#181) —
// `opts.allowSha1`, which only `verifyLeaf()` passes. RSASSA-PSS names its
// hash in its parameters, SHA-1 when they name none (RFC 4055 section 3.1).
const PATH_MD_SIGNATURES = ['1.2.840.113549.1.1.2', '1.2.840.113549.1.1.4'];
const PATH_SHA1_SIGNATURES = ['1.2.840.113549.1.1.5', '1.3.14.3.2.29',
                              '1.2.840.10045.4.1', '1.2.840.10040.4.3'];
const PATH_RSASSA_PSS = '1.2.840.113549.1.1.10';
const PATH_SHA1 = '1.3.14.3.2.26';
const PATH_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
// GeneralName's CHOICE tags (RFC 5280 section 4.2.1.6), and the forms this
// module evaluates a name constraint in.
const GENERAL_NAME_FORMS = { 0: 'otherName', 1: 'email', 2: 'dns',
                             3: 'x400Address', 4: 'dn', 5: 'ediPartyName',
                             6: 'uri', 7: 'ip', 8: 'registeredID' };
const PATH_EVALUATED_FORMS = ['email', 'dns', 'uri', 'ip', 'dn'];
// THE BUILDER'S BOUNDS. A path is at most this many certificates, and one
// build checks at most this many signatures — Go's
// `maxChainSignatureChecks` is 100; this is higher because a failed rule
// check makes the builder try the next path rather than stop. x509-limbo's
// `pathological::` cases are what these are held to.
const PATH_MAX_LENGTH = 12;
const PATH_MAX_SIGNATURES = 256;
// And the name-constraint work one path may cost: names times subtrees,
// summed over every constraining CA. OpenSSL's NAME_CHECK_MAX is the same
// 2^20; a path past it is refused rather than evaluated, because what it
// buys an attacker is CPU (x509-limbo `pathological::nc-dos-*`).
const PATH_MAX_NAME_CHECKS = 1 << 20;

// One DER value from bytes, refusing trailing bytes: an extension value that
// is one value followed by something else is not the value it claims to be.
function derValueOf(bytes) {
  log.debug("Entering derValueOf().");
  const view = new Uint8Array(bytes);
  const parsed = asn1js.fromBER(view);
  if (parsed.offset === -1 || parsed.offset !== view.byteLength) {
    log.debug("Leaving derValueOf(). Not one DER value.");
    throw new Error('not one DER value' +
                    (parsed.result && parsed.result.error
                      ? ' (' + parsed.result.error + ')' : ''));
  }
  log.debug("Leaving derValueOf().");
  return parsed.result;
}

// The bytes of a primitive value as ASCII, or null when any byte is not
// (an IA5String is seven-bit).
function asciiOf(node) {
  log.debug("Entering asciiOf().");
  const bytes = Buffer.from(node.valueBlock.valueHexView || []);
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] > 0x7e || bytes[i] < 0x20) {
      log.debug("Leaving asciiOf(). Not printable ASCII.");
      return null;
    }
  }
  log.debug("Leaving asciiOf().");
  return bytes.toString('latin1');
}

// A Name as a list of RDNs, each the sorted `oid=value` of its attributes
// with a string value compared as RFC 5280 section 7.1 asks — case folded,
// leading and trailing space removed, internal space collapsed — and any
// other value by its DER. Two names are the same name when these lists are
// equal; a directoryName constraint is a PREFIX of this list.
function rdnsOfName(node) {
  log.debug("Entering rdnsOfName().");
  if (!(node instanceof asn1js.Sequence)) {
    log.debug("Leaving rdnsOfName(). Not a Name.");
    throw new Error('a Name is not a SEQUENCE');
  }
  // An EMPTY RDN (a SET with no attribute) is read as no RDN at all: the
  // ASN.1 says SIZE (1..MAX), and pkijs writes one for an empty name — the
  // Fulcio-shaped certificates the SPIFFE sigstore tests make, and a TPM
  // attestation key's — so what it means is not in doubt.
  const sets = node.valueBlock.value.filter(function (set) {
    return !(set instanceof asn1js.Set) || set.valueBlock.value.length > 0;
  });
  const out = sets.map(function (set) {
    if (!(set instanceof asn1js.Set)) {
      throw new Error('a RelativeDistinguishedName is not a SET');
    }
    return set.valueBlock.value.map(function (atv) {
      // asn1js declares a generic ValueBlock; a constructed one has `value`.
      const block = /** @type {any} */ (atv.valueBlock);
      const parts = block && block.value;
      if (!parts || parts.length !== 2 ||
          !(parts[0] instanceof asn1js.ObjectIdentifier)) {
        throw new Error('an attribute is not a type and a value');
      }
      const value = parts[1];
      const text = value instanceof asn1js.BaseStringBlock
        ? String(value.getValue()).trim().replace(/\s+/g, ' ').toLowerCase()
        : '#' + Buffer.from(value.toBER(false)).toString('hex');
      return parts[0].getValue() + '=' + text;
    }).sort().join('+');
  });
  log.debug("Leaving rdnsOfName(). " + out.length + " RDN(s).");
  return out;
}

// The e-mail addresses a subject carries in the PKCS #9 emailAddress
// attribute, which section 6.1.3(b) holds to rfc822Name constraints.
function subjectEmailsOf(node) {
  log.debug("Entering subjectEmailsOf().");
  const out = [];
  node.valueBlock.value.forEach(function (set) {
    (set.valueBlock.value || []).forEach(function (atv) {
      const parts = atv.valueBlock.value;
      if (parts[0].getValue() === PATH_EMAIL_ADDRESS_OID &&
          parts[1] instanceof asn1js.BaseStringBlock) {
        out.push(String(parts[1].getValue()));
      }
    });
  });
  log.debug("Leaving subjectEmailsOf(). " + out.length + ".");
  return out;
}

// One GeneralName: `{ form, value }` — a string for email, dns and uri (null
// when not ASCII, which no name in those forms may be), the bytes for ip,
// the RDN list for dn, and nothing for a form this module does not evaluate.
function generalNameOf(node) {
  log.debug("Entering generalNameOf().");
  if (node.idBlock.tagClass !== 3) {
    log.debug("Leaving generalNameOf(). Untagged.");
    throw new Error('a GeneralName is not context-tagged');
  }
  const form = GENERAL_NAME_FORMS[node.idBlock.tagNumber];
  if (!form) {
    log.debug("Leaving generalNameOf(). Unknown tag.");
    throw new Error('a GeneralName has tag ' + node.idBlock.tagNumber);
  }
  let value = null;
  if (form === 'email' || form === 'dns' || form === 'uri') {
    if (node.idBlock.isConstructed) {
      throw new Error('a ' + form + ' GeneralName is constructed');
    }
    value = asciiOf(node);
  } else if (form === 'ip') {
    if (node.idBlock.isConstructed) {
      throw new Error('an iPAddress GeneralName is constructed');
    }
    value = Buffer.from(node.valueBlock.valueHexView || []);
  } else if (form === 'dn') {
    const inner = node.valueBlock && node.valueBlock.value;
    if (!inner || inner.length !== 1) {
      throw new Error('a directoryName holds no single Name');
    }
    value = rdnsOfName(inner[0]);
  }
  log.debug("Leaving generalNameOf(). " + form);
  return { form: form, value: value };
}

// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName.
function generalNamesOf(bytes) {
  log.debug("Entering generalNamesOf().");
  const node = derValueOf(bytes);
  if (!(node instanceof asn1js.Sequence) || !node.valueBlock.value.length) {
    log.debug("Leaving generalNamesOf(). Not a non-empty SEQUENCE.");
    throw new Error('GeneralNames is not a non-empty SEQUENCE');
  }
  const out = node.valueBlock.value.map(generalNameOf);
  log.debug("Leaving generalNamesOf(). " + out.length + ".");
  return out;
}

// NameConstraints (section 4.2.1.10): `{ permitted, excluded }`, each a list
// of `{ form, value, bounded }` or null when absent. `bounded` is a subtree
// with a minimum other than 0 or any maximum, which this profile says a CA
// MUST NOT use and which is therefore not evaluated.
function nameConstraintsOf(bytes) {
  log.debug("Entering nameConstraintsOf().");
  const node = derValueOf(bytes);
  if (!(node instanceof asn1js.Sequence)) {
    throw new Error('NameConstraints is not a SEQUENCE');
  }
  const out = { permitted: null, excluded: null };
  node.valueBlock.value.forEach(function (part) {
    const tag = part.idBlock.tagNumber;
    if (part.idBlock.tagClass !== 3 || (tag !== 0 && tag !== 1) ||
        !part.idBlock.isConstructed) {
      throw new Error('NameConstraints holds something other than ' +
                      'permittedSubtrees [0] and excludedSubtrees [1]');
    }
    const key = tag === 0 ? 'permitted' : 'excluded';
    if (out[key]) {
      throw new Error('NameConstraints names ' + key + 'Subtrees twice');
    }
    const subtrees = /** @type {any} */ (part.valueBlock).value || [];
    if (!subtrees.length) {
      // GeneralSubtrees ::= SEQUENCE SIZE (1..MAX): an empty one is not DER
      // this ASN.1 can produce.
      throw new Error(key + 'Subtrees is an empty sequence');
    }
    out[key] = subtrees.map(function (subtree) {
      if (!(subtree instanceof asn1js.Sequence) ||
          !subtree.valueBlock.value.length) {
        throw new Error('a GeneralSubtree is not a SEQUENCE');
      }
      const fields = subtree.valueBlock.value;
      const base = generalNameOf(fields[0]);
      let bounded = false;
      fields.slice(1).forEach(function (field) {
        const which = field.idBlock.tagNumber;
        const bytesOf = Buffer.from(
          /** @type {any} */ (field.valueBlock).valueHexView || []);
        if (which === 0 && bytesOf.length === 1 && bytesOf[0] === 0) {
          return;
        }
        bounded = true;
      });
      return { form: base.form, value: base.value, bounded: bounded };
    });
  });
  if (!out.permitted && !out.excluded) {
    // "Conforming CAs ... MUST NOT issue certificates where name constraints
    // is an empty sequence" — at least one of the two MUST be present.
    throw new Error('NameConstraints has neither permittedSubtrees nor ' +
                    'excludedSubtrees');
  }
  log.debug("Leaving nameConstraintsOf().");
  return out;
}

// A host name in RFC 1034 section 3.5's preferred syntax as RFC 1123 section
// 2.1 relaxed it: letters, digits and hyphens, no label empty, longer than
// 63 or starting or ending with a hyphen. `wildcard` allows a whole `*` as
// the first label, which is how a certificate names every host one level
// down; nothing else may hold a `*`.
function hostNameValid(name, wildcard) {
  log.debug("Entering hostNameValid().");
  if (!name || name.length > 253) {
    log.debug("Leaving hostNameValid(). Empty or too long.");
    return false;
  }
  const labels = name.split('.');
  const ok = labels.every(function (label, at) {
    if (wildcard && at === 0 && label === '*' && labels.length > 1) {
      return true;
    }
    return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(label);
  });
  log.debug("Leaving hostNameValid(). " + ok);
  return ok;
}

// An iPAddress constraint: an address and a mask of the same family whose
// bits are ones and then zeros (section 4.2.1.10).
function ipConstraintValid(bytes) {
  log.debug("Entering ipConstraintValid().");
  if (bytes.length !== 8 && bytes.length !== 32) {
    log.debug("Leaving ipConstraintValid(). Wrong length.");
    return false;
  }
  const mask = bytes.subarray(bytes.length / 2);
  let zero = false;
  for (let i = 0; i < mask.length; i++) {
    for (let bit = 7; bit >= 0; bit--) {
      const one = (mask[i] >> bit) & 1;
      if (one && zero) {
        log.debug("Leaving ipConstraintValid(). A non-contiguous mask.");
        return false;
      }
      if (!one) {
        zero = true;
      }
    }
  }
  log.debug("Leaving ipConstraintValid().");
  return true;
}

// Whether a constraint's own base is well formed for its form. A malformed
// one refuses the path: what it was meant to limit cannot be known.
function constraintBaseProblem(subtree) {
  log.debug("Entering constraintBaseProblem(). " + subtree.form);
  const v = subtree.value;
  let problem = '';
  if (subtree.form === 'dns') {
    // An empty dNSName constraint is the whole namespace; a leading period
    // is URI syntax, not dNSName (section 4.2.1.10), and a `*` is never a
    // constraint.
    if (v === null || (v !== '' && !hostNameValid(v, false))) {
      problem = 'the dNSName constraint "' + v + '" is not a host name';
    }
  } else if (subtree.form === 'email') {
    const at = v === null ? -1 : v.indexOf('@');
    if (v === null || !v) {
      problem = 'an rfc822Name constraint is empty or not ASCII';
    } else if (at >= 0) {
      if (at === 0 || v.indexOf('@', at + 1) >= 0 ||
          !hostNameValid(v.slice(at + 1), false)) {
        problem = 'the rfc822Name constraint "' + v + '" is not a mailbox';
      }
    } else if (!hostNameValid(v.replace(/^\./, ''), false)) {
      problem = 'the rfc822Name constraint "' + v + '" is not a host or ' +
                'domain';
    }
  } else if (subtree.form === 'uri') {
    if (v === null || !hostNameValid(v.replace(/^\./, ''), false)) {
      problem = 'the URI constraint "' + v + '" is not a host or domain';
    }
  } else if (subtree.form === 'ip') {
    if (!ipConstraintValid(v)) {
      problem = 'an iPAddress constraint is not an address and a ' +
                'contiguous mask of one family';
    }
  }
  log.debug("Leaving constraintBaseProblem().");
  return problem;
}

// The host a URI names, or '' when it names none this module may compare —
// an IP literal, or no authority at all (section 4.2.1.10: a URI constraint
// "applies to the host part of the name").
function uriHostOf(uri) {
  log.debug("Entering uriHostOf().");
  let host = '';
  try {
    host = new URL(uri).hostname.toLowerCase();
  } catch (e) {
    log.debug("Caught in uriHostOf(): " + ((e && e.message) || e));
    host = '';
  }
  if (!hostNameValid(host, false)) {
    host = '';
  }
  log.debug("Leaving uriHostOf(). " + (host || 'none'));
  return host;
}

// Does `name` (one of a certificate's names) fall inside `subtree`? Both of
// the same form; a name malformed for its form is inside nothing and, where
// it is constrained, refused by the caller.
function nameWithinSubtree(name, subtree) {
  log.debug("Entering nameWithinSubtree(). " + name.form);
  const c = subtree.value;
  let inside = false;
  if (name.form === 'dns') {
    const n = String(name.value).toLowerCase().replace(/^\*\./, '');
    const base = String(c).toLowerCase();
    inside = base === '' || n === base || n.endsWith('.' + base);
  } else if (name.form === 'email') {
    const at = name.value.lastIndexOf('@');
    const host = name.value.slice(at + 1).toLowerCase();
    if (c.indexOf('@') >= 0) {
      const cat = c.lastIndexOf('@');
      inside = name.value.slice(0, at) === c.slice(0, cat) &&
               host === c.slice(cat + 1).toLowerCase();
    } else if (c.charAt(0) === '.') {
      inside = host.endsWith(c.toLowerCase());
    } else {
      inside = host === c.toLowerCase();
    }
  } else if (name.form === 'uri') {
    const host = uriHostOf(name.value);
    const base = String(c).toLowerCase();
    inside = !!host && (base.charAt(0) === '.' ? host.endsWith(base)
                                                : host === base);
  } else if (name.form === 'ip') {
    const half = c.length / 2;
    if (name.value.length === half) {
      inside = true;
      for (let i = 0; i < half; i++) {
        if ((name.value[i] & c[half + i]) !== (c[i] & c[half + i])) {
          inside = false;
        }
      }
    }
  } else if (name.form === 'dn') {
    inside = c.length <= name.value.length && c.every(function (rdn, at) {
      return name.value[at] === rdn;
    });
  }
  log.debug("Leaving nameWithinSubtree(). " + inside);
  return inside;
}

// Whether one of a certificate's names is well formed for its form — asked
// only of a name some CA above it constrains.
function constrainedNameProblem(name) {
  log.debug("Entering constrainedNameProblem(). " + name.form);
  let problem = '';
  if (name.form === 'dns' && (name.value === null ||
                              !hostNameValid(name.value, true))) {
    problem = 'the dNSName "' + name.value + '" is not a host name';
  } else if (name.form === 'email') {
    const at = name.value === null ? -1 : name.value.lastIndexOf('@');
    if (at <= 0 || name.value.indexOf('@') !== at ||
        !hostNameValid(name.value.slice(at + 1), false)) {
      problem = 'the rfc822Name "' + name.value + '" is not a mailbox';
    }
  } else if (name.form === 'uri' && (name.value === null ||
                                     !uriHostOf(name.value))) {
    problem = 'the URI "' + name.value + '" names no host a constraint ' +
              'can be applied to';
  } else if (name.form === 'ip' && name.value.length !== 4 &&
             name.value.length !== 16) {
    problem = 'an iPAddress is neither four nor sixteen bytes';
  }
  log.debug("Leaving constrainedNameProblem().");
  return problem;
}

// The DER a pkijs Name was decoded from, or its re-encoding where pkijs kept
// none (a name built rather than read).
function nameBytesOf(name) {
  log.debug("Entering nameBytesOf().");
  const kept = name && name.valueBeforeDecode;
  const bytes = kept && kept.byteLength ? new Uint8Array(kept)
    : new Uint8Array(name.toSchema().toBER(false));
  log.debug("Leaving nameBytesOf().");
  return bytes;
}

// ---------------------------------------------------------------------------
// THE FACTS OF ONE CERTIFICATE, read once and kept on the entry
// (`certificateFromDer()`'s shape, or anything with `der`). `problem` is set
// when the certificate cannot be held to the rules at all — it does not
// parse, it repeats an extension, or an extension this module reads is
// malformed — and every rule question then refuses it.
// ---------------------------------------------------------------------------
function pathFactsOf(one) {
  log.debug("Entering pathFactsOf().");
  if (one.pathFacts) {
    log.debug("Leaving pathFactsOf(). Already read.");
    return one.pathFacts;
  }
  const facts = { problem: '', extensions: [], critical: [], ca: false,
                  hasBasicConstraints: false, pathLen: null,
                  keyUsage: null, ekus: null, names: [], subjectRdns: [],
                  issuerRdns: [], nameConstraints: null, sanCritical: false,
                  hasSan: false, selfIssued: false, spkiOid: '',
                  keyIdentifier: '', authorityKeyIdentifier: '',
                  notBefore: 0, notAfter: 0, pk: null, commonNames: [],
                  weakSignature: '', policies: null, policyMappings: null,
                  requireExplicitPolicy: null, inhibitPolicyMapping: null,
                  inhibitAnyPolicy: null };
  try {
    const pk = pkijs.Certificate.fromBER(new Uint8Array(one.der));
    facts.pk = pk;
    // The names AS ENCODED: pkijs re-encodes an empty subject as a
    // SEQUENCE holding an empty SET, which is not what was signed.
    const subjectNode = derValueOf(nameBytesOf(pk.subject));
    facts.subjectRdns = rdnsOfName(subjectNode);
    facts.issuerRdns = rdnsOfName(derValueOf(nameBytesOf(pk.issuer)));
    facts.selfIssued = facts.subjectRdns.join(',') ===
                       facts.issuerRdns.join(',');
    subjectEmailsOf(subjectNode)
      .forEach(function (address) {
        facts.names.push({ form: 'email', value: address, fromSubject: true });
      });
    if (facts.subjectRdns.length) {
      facts.names.push({ form: 'dn', value: facts.subjectRdns,
                         fromSubject: true });
    }
    (pk.subject.typesAndValues || []).forEach(function (atv) {
      if (atv.type === '2.5.4.3' && atv.value &&
          typeof atv.value.valueBlock.value === 'string') {
        facts.commonNames.push(atv.value.valueBlock.value);
      }
    });
    facts.spkiOid = pk.subjectPublicKeyInfo.algorithm.algorithmId;
    // An EC key's parameters MUST be a named curve (RFC 5480 section 2.1.1:
    // implicitCurve and specifiedCurve MUST NOT be used): a curve spelled
    // out in the certificate is whatever curve its issuer wrote down.
    if (facts.spkiOid === PATH_EC_PUBLIC_KEY &&
        !(pk.subjectPublicKeyInfo.algorithm.algorithmParams instanceof
          asn1js.ObjectIdentifier)) {
      throw new Error('its EC key names no named curve (RFC 5480 section ' +
                      '2.1.1 forbids specifiedCurve and implicitCurve)');
    }
    const signedWith = pk.signatureAlgorithm.algorithmId;
    if (PATH_MD_SIGNATURES.indexOf(signedWith) >= 0) {
      facts.weakSignature = 'md';
    } else if (PATH_SHA1_SIGNATURES.indexOf(signedWith) >= 0) {
      facts.weakSignature = 'sha1';
    } else if (signedWith === PATH_RSASSA_PSS) {
      let hash = PATH_SHA1;
      try {
        const params = new pkijs.RSASSAPSSParams({
          schema: pk.signatureAlgorithm.algorithmParams });
        hash = params.hashAlgorithm.algorithmId;
      } catch (e) {
        log.debug("Caught in pathFactsOf(): " + ((e && e.message) || e));
        hash = PATH_SHA1;
      }
      facts.weakSignature = hash === PATH_SHA1 ? 'sha1' : '';
    }
    facts.notBefore = pk.notBefore.value.getTime();
    facts.notAfter = pk.notAfter.value.getTime();
    const seen = {};
    (pk.extensions || []).forEach(function (ext) {
      const oid = ext.extnID;
      if (seen[oid]) {
        throw new Error('the extension ' + oid + ' appears twice (RFC 5280 ' +
                        'section 4.2)');
      }
      seen[oid] = true;
      facts.extensions.push(oid);
      if (ext.critical) {
        facts.critical.push(oid);
      }
      const bytes = Buffer.from(ext.extnValue.valueBlock.valueHexView);
      if (oid === PATH_EXTENSION_OIDS.basicConstraints) {
        const node = derValueOf(bytes);
        if (!(node instanceof asn1js.Sequence)) {
          throw new Error('basicConstraints is not a SEQUENCE');
        }
        facts.hasBasicConstraints = true;
        node.valueBlock.value.forEach(function (field) {
          if (field instanceof asn1js.Boolean) {
            facts.ca = !!field.getValue();
          } else if (field instanceof asn1js.Integer) {
            facts.pathLen = field.valueBlock.valueDec;
          } else {
            throw new Error('basicConstraints holds an unexpected field');
          }
        });
      } else if (oid === PATH_EXTENSION_OIDS.keyUsage) {
        const node = derValueOf(bytes);
        if (!(node instanceof asn1js.BitString)) {
          throw new Error('keyUsage is not a BIT STRING');
        }
        const raw = Buffer.from(node.valueBlock.valueHexView || []);
        facts.keyUsage = PATH_KEY_USAGE_BITS.filter(function (name, bit) {
          return raw.length > (bit >> 3) &&
                 ((raw[bit >> 3] >> (7 - (bit & 7))) & 1) === 1;
        });
      } else if (oid === PATH_EXTENSION_OIDS.extKeyUsage) {
        const node = derValueOf(bytes);
        if (!(node instanceof asn1js.Sequence) ||
            !node.valueBlock.value.length) {
          throw new Error('extKeyUsage is not a non-empty SEQUENCE');
        }
        facts.ekus = node.valueBlock.value.map(function (purpose) {
          if (!(purpose instanceof asn1js.ObjectIdentifier)) {
            throw new Error('extKeyUsage holds something not a purpose');
          }
          return purpose.getValue();
        });
      } else if (oid === PATH_EXTENSION_OIDS.subjectAltName) {
        facts.hasSan = true;
        facts.sanCritical = !!ext.critical;
        generalNamesOf(bytes).forEach(function (name) {
          facts.names.push(name);
        });
      } else if (oid === PATH_EXTENSION_OIDS.nameConstraints) {
        facts.nameConstraints = nameConstraintsOf(bytes);
      } else if (oid === PATH_EXTENSION_OIDS.certificatePolicies) {
        facts.policies = certificatePoliciesOf(bytes);
      } else if (oid === PATH_EXTENSION_OIDS.policyMappings) {
        facts.policyMappings = policyMappingsOf(bytes);
      } else if (oid === PATH_EXTENSION_OIDS.policyConstraints) {
        const pc = policyConstraintsOf(bytes);
        facts.requireExplicitPolicy = pc.requireExplicitPolicy;
        facts.inhibitPolicyMapping = pc.inhibitPolicyMapping;
      } else if (oid === PATH_EXTENSION_OIDS.inhibitAnyPolicy) {
        const node = derValueOf(bytes);
        if (!(node instanceof asn1js.Integer) ||
            node.valueBlock.isHexOnly || node.valueBlock.valueDec < 0) {
          throw new Error('inhibitAnyPolicy is not a SkipCerts INTEGER');
        }
        facts.inhibitAnyPolicy = node.valueBlock.valueDec;
      } else if (oid === PATH_EXTENSION_OIDS.subjectKeyIdentifier) {
        const node = derValueOf(bytes);
        facts.keyIdentifier = node instanceof asn1js.OctetString
          ? Buffer.from(node.valueBlock.valueHexView).toString('hex') : '';
      } else if (oid === PATH_EXTENSION_OIDS.authorityKeyIdentifier) {
        const node = derValueOf(bytes);
        const id = node instanceof asn1js.Sequence
          ? node.valueBlock.value.filter(function (field) {
            return field.idBlock.tagClass === 3 &&
                   field.idBlock.tagNumber === 0;
          })[0] : null;
        facts.authorityKeyIdentifier = id
          ? Buffer.from(/** @type {any} */ (id.valueBlock).valueHexView ||
                        []).toString('hex') : '';
      }
    });
  } catch (e) {
    log.debug("Caught in pathFactsOf(): " + ((e && e.message) || e));
    facts.problem = 'it cannot be held to RFC 5280: ' +
                    ((e && e.message) || e);
  }
  one.pathFacts = facts;
  log.debug("Leaving pathFactsOf()." + (facts.problem ? ' Unusable.' : ''));
  return facts;
}

// The certificate's subject for a sentence.
function pathSubjectOf(one) {
  log.debug("Entering pathSubjectOf().");
  let text = '';
  try {
    text = oneLineName(new nodeCrypto.X509Certificate(one.der).subject);
  } catch (e) {
    log.debug("Caught in pathSubjectOf(): " + ((e && e.message) || e));
    text = '';
  }
  log.debug("Leaving pathSubjectOf().");
  return text || 'the certificate with an empty subject';
}

// Does a wildcard dNSName reach into `subtree`? `*.example.com` names every
// host one label below example.com, so an excluded `bar.example.com` is
// inside what it can be presented for even though the name itself is not
// inside the subtree. Refused, as CVE-2025-61727's fix refuses it: neither
// RFC 5280 nor RFC 9525 says how a constraint meets a wildcard, and the
// defensive reading is the one that cannot be used to escape an exclusion.
function wildcardReaches(name, subtree) {
  log.debug("Entering wildcardReaches().");
  const n = String(name.value || '').toLowerCase();
  const base = String(subtree.value || '').toLowerCase();
  const reaches = n.indexOf('*.') === 0 &&
                  base.endsWith('.' + n.slice(2));
  log.debug("Leaving wildcardReaches(). " + reaches);
  return reaches;
}

// The first name of `below` that the constraints of `ca` refuse, as a
// sentence, or ''. `isLeaf` adds the leaf's common names that are host names
// as dNSNames when it carries no subjectAltName at all — the only case in
// which a TLS client still matches on the CN (RFC 6125 section 6.4.4), and
// so a name a dNSName constraint has to reach; OpenSSL constrains it too.
// `budget.checks` counts names times subtrees across the path.
function constraintProblem(ca, below, isLeaf, budget) {
  log.debug("Entering constraintProblem().");
  const nc = pathFactsOf(ca).nameConstraints;
  const facts = pathFactsOf(below);
  let names = facts.names;
  if (isLeaf && !facts.hasSan) {
    names = names.concat(facts.commonNames.filter(function (cn) {
      return hostNameValid(cn, true);
    }).map(function (cn) {
      return { form: 'dns', value: cn, fromCommonName: true };
    }));
  }
  budget.checks += names.length *
    ((nc.permitted || []).length + (nc.excluded || []).length);
  if (budget.checks > PATH_MAX_NAME_CHECKS) {
    log.debug("Leaving constraintProblem(). Too much work.");
    return 'it and the CAs above it carry more names and name constraints ' +
           'between them than this service will compare (' +
           PATH_MAX_NAME_CHECKS + ' comparisons)';
  }
  for (let n = 0; n < names.length; n++) {
    const name = names[n];
    const permitted = (nc.permitted || []).filter(function (subtree) {
      return subtree.form === name.form;
    });
    const excluded = (nc.excluded || []).filter(function (subtree) {
      return subtree.form === name.form;
    });
    if (!permitted.length && !excluded.length) {
      continue;
    }
    const unevaluated = permitted.concat(excluded).some(function (subtree) {
      return subtree.bounded ||
             PATH_EVALUATED_FORMS.indexOf(subtree.form) < 0;
    });
    if (unevaluated) {
      log.debug("Leaving constraintProblem(). A form not evaluated.");
      return 'it carries a ' + name.form + ' name and a CA above it ' +
             'constrains that form in a way this service does not evaluate ' +
             '(RFC 5280 section 4.2.1.10 then requires the certificate be ' +
             'refused)';
    }
    const malformed = constrainedNameProblem(name);
    if (malformed) {
      log.debug("Leaving constraintProblem(). A malformed name.");
      return malformed + ', and a CA above it constrains that form';
    }
    if (permitted.length && !permitted.some(function (subtree) {
      return nameWithinSubtree(name, subtree);
    })) {
      log.debug("Leaving constraintProblem(). Not permitted.");
      return 'its ' + name.form + ' name ' + describePathName(name) +
             ' is outside every permitted subtree of that form';
    }
    if (excluded.some(function (subtree) {
      return nameWithinSubtree(name, subtree) ||
             (name.form === 'dns' && wildcardReaches(name, subtree));
    })) {
      log.debug("Leaving constraintProblem(). Excluded.");
      return 'its ' + name.form + ' name ' + describePathName(name) +
             ' is inside an excluded subtree';
    }
  }
  log.debug("Leaving constraintProblem(). Within them.");
  return '';
}

// ---------------------------------------------------------------------------
// CERTIFICATE POLICIES (RFC 5280 sections 4.2.1.4-4.2.1.14 and 6.1, #201).
// ---------------------------------------------------------------------------

// certificatePolicies: the policy OIDs, in order. A policy named twice is
// refused (section 4.2.1.4: "MUST NOT appear more than once"); qualifiers
// are read as present and not interpreted — section 6.1 carries them and
// decides nothing on them.
function certificatePoliciesOf(bytes) {
  log.debug("Entering certificatePoliciesOf().");
  const node = derValueOf(bytes);
  if (!(node instanceof asn1js.Sequence) || !node.valueBlock.value.length) {
    throw new Error('certificatePolicies is not a non-empty SEQUENCE');
  }
  const out = [];
  node.valueBlock.value.forEach(function (info) {
    const parts = info instanceof asn1js.Sequence
      ? info.valueBlock.value : null;
    if (!parts || !parts.length || parts.length > 2 ||
        !(parts[0] instanceof asn1js.ObjectIdentifier)) {
      throw new Error('a PolicyInformation is not a policy and qualifiers');
    }
    const oid = parts[0].getValue();
    if (out.indexOf(oid) >= 0) {
      throw new Error('certificatePolicies names ' + oid + ' twice (RFC ' +
                      '5280 section 4.2.1.4)');
    }
    out.push(oid);
  });
  log.debug("Leaving certificatePoliciesOf(). " + out.length + ".");
  return out;
}

// policyMappings: `[{ issuer, subject }]`.
function policyMappingsOf(bytes) {
  log.debug("Entering policyMappingsOf().");
  const node = derValueOf(bytes);
  if (!(node instanceof asn1js.Sequence) || !node.valueBlock.value.length) {
    throw new Error('policyMappings is not a non-empty SEQUENCE');
  }
  const out = node.valueBlock.value.map(function (pair) {
    const parts = pair instanceof asn1js.Sequence ? pair.valueBlock.value
                                                  : null;
    if (!parts || parts.length !== 2 ||
        !(parts[0] instanceof asn1js.ObjectIdentifier) ||
        !(parts[1] instanceof asn1js.ObjectIdentifier)) {
      throw new Error('a policy mapping is not two policy OIDs');
    }
    return { issuer: parts[0].getValue(), subject: parts[1].getValue() };
  });
  log.debug("Leaving policyMappingsOf(). " + out.length + ".");
  return out;
}

// policyConstraints: `{ requireExplicitPolicy, inhibitPolicyMapping }`, each
// a SkipCerts or null. "Conforming CAs MUST NOT issue certificates where
// policy constraints is an empty sequence" (section 4.2.1.11).
function policyConstraintsOf(bytes) {
  log.debug("Entering policyConstraintsOf().");
  const node = derValueOf(bytes);
  if (!(node instanceof asn1js.Sequence) || !node.valueBlock.value.length) {
    throw new Error('policyConstraints is not a non-empty SEQUENCE');
  }
  const out = { requireExplicitPolicy: null, inhibitPolicyMapping: null };
  node.valueBlock.value.forEach(function (field) {
    const tag = field.idBlock.tagNumber;
    const raw = Buffer.from(
      /** @type {any} */ (field.valueBlock).valueHexView || []);
    if (field.idBlock.tagClass !== 3 || (tag !== 0 && tag !== 1) ||
        field.idBlock.isConstructed || !raw.length || raw.length > 4 ||
        (raw[0] & 0x80)) {
      throw new Error('policyConstraints holds something other than two ' +
                      'SkipCerts');
    }
    const key = tag === 0 ? 'requireExplicitPolicy' : 'inhibitPolicyMapping';
    if (out[key] !== null) {
      throw new Error('policyConstraints names ' + key + ' twice');
    }
    out[key] = raw.readUIntBE(0, raw.length);
  });
  log.debug("Leaving policyConstraintsOf().");
  return out;
}

// ---------------------------------------------------------------------------
// RFC 5280 SECTION 6.1's POLICY PROCESSING, WHOLE (#201).
//
// The valid_policy_tree, explicit_policy, inhibit_anyPolicy and
// policy_mapping, exactly as sections 6.1.2-6.1.5 define them, over `path`
// (leaf first, anchor last — the anchor is not processed, section 6.1:
// certificates 1..n run from the one the anchor issued down to the leaf).
// `opts` carries the four inputs a caller may set; none of this service's
// callers sets one, so the defaults — initial-policy-set {anyPolicy} and the
// three indicators clear — are what runs, and a path is refused only where
// its own certificates demand an explicit policy (requireExplicitPolicy)
// and the tree came out empty, or where a mapping names anyPolicy.
//
// Answers `{ ok, why, userConstrainedPolicySet, explicitPolicy }`. The
// qualifiers are carried by no node: nothing here reads them, and section
// 6.1 decides nothing on them.
// ---------------------------------------------------------------------------
function pathPolicyOutcome(path, opts) {
  log.debug("Entering pathPolicyOutcome().");
  const options = opts || {};
  const n = path.length - 1;
  const initial = (options.initialPolicySet && options.initialPolicySet.length)
    ? options.initialPolicySet.slice(0) : [ANY_POLICY];
  if (n < 1) {
    log.debug("Leaving pathPolicyOutcome(). Nothing below the anchor.");
    return { ok: true, why: '', userConstrainedPolicySet: initial,
             explicitPolicy: false };
  }
  let explicitPolicy = options.initialExplicitPolicy ? 0 : n + 1;
  let inhibitAnyPolicy = options.initialInhibitAnyPolicy ? 0 : n + 1;
  let policyMapping = options.initialPolicyMappingInhibit ? 0 : n + 1;
  let count = 1;
  const nodeOf = function (policy, expected, parent) {
    log.debug("Entering nodeOf().");
    const node = { policy: policy, expected: expected.slice(0),
                   parent: parent, children: [],
                   depth: parent ? parent.depth + 1 : 0 };
    if (parent) {
      parent.children.push(node);
    }
    count++;
    log.debug("Leaving nodeOf().");
    return node;
  };
  let root = nodeOf(ANY_POLICY, [ANY_POLICY], null);
  const atDepth = function (depth) {
    log.debug("Entering atDepth().");
    const out = [];
    const walk = function (node) {
      if (node.depth === depth) {
        out.push(node);
        return;
      }
      node.children.forEach(walk);
    };
    if (root) {
      walk(root);
    }
    log.debug("Leaving atDepth().");
    return out;
  };
  const remove = function (node) {
    log.debug("Entering remove().");
    if (!node.parent) {
      root = null;
    } else {
      node.parent.children = node.parent.children.filter(function (one) {
        return one !== node;
      });
    }
    log.debug("Leaving remove().");
  };
  // Delete every node shallower than `depth` that has no children, until
  // none is left; the root going makes the tree NULL.
  const prune = function (depth) {
    log.debug("Entering prune().");
    for (let d = depth - 1; d >= 0 && root; d--) {
      atDepth(d).forEach(function (node) {
        if (!node.children.length) {
          remove(node);
        }
      });
    }
    log.debug("Leaving prune().");
  };
  const refuse = function (why) {
    log.debug("Entering refuse().");
    log.debug("Leaving refuse().");
    return { ok: false, why: why, userConstrainedPolicySet: [],
             explicitPolicy: true };
  };
  for (let i = 1; i <= n; i++) {
    const cert = path[n - i];
    const facts = pathFactsOf(cert);
    // (d) the certificate's policies.
    if (facts.policies && root) {
      const parents = atDepth(i - 1);
      facts.policies.forEach(function (policy) {
        if (policy === ANY_POLICY) {
          return;
        }
        let matched = false;
        parents.forEach(function (parent) {
          if (parent.expected.indexOf(policy) >= 0) {
            nodeOf(policy, [policy], parent);
            matched = true;
          }
        });
        if (!matched) {
          parents.filter(function (parent) {
            return parent.policy === ANY_POLICY;
          }).forEach(function (parent) {
            nodeOf(policy, [policy], parent);
          });
        }
      });
      if (facts.policies.indexOf(ANY_POLICY) >= 0 &&
          (inhibitAnyPolicy > 0 || (i < n && facts.selfIssued))) {
        parents.forEach(function (parent) {
          parent.expected.forEach(function (policy) {
            const has = parent.children.some(function (child) {
              return child.policy === policy;
            });
            if (!has) {
              nodeOf(policy, [policy], parent);
            }
          });
        });
      }
      prune(i);
      if (count > PATH_MAX_POLICY_NODES) {
        log.debug("Leaving pathPolicyOutcome(). Too many nodes.");
        return refuse('the certificate policies and mappings along the ' +
                      'path make more than ' + PATH_MAX_POLICY_NODES +
                      ' policy tree nodes');
      }
    } else {
      // (e) no certificatePolicies: the tree is NULL.
      root = null;
    }
    // (f)
    if (explicitPolicy <= 0 && !root) {
      log.debug("Leaving pathPolicyOutcome(). Explicit policy, no tree.");
      return refuse('"' + pathSubjectOf(cert) + '" leaves no acceptable ' +
                    'certificate policy and the path requires an explicit ' +
                    'one (RFC 5280 section 6.1.3(f))');
    }
    if (i === n) {
      break;
    }
    // Preparation for certificate i+1 (section 6.1.4).
    const mappings = facts.policyMappings || [];
    if (mappings.some(function (m) {
      return m.issuer === ANY_POLICY || m.subject === ANY_POLICY;
    })) {
      log.debug("Leaving pathPolicyOutcome(). anyPolicy mapped.");
      return refuse('"' + pathSubjectOf(cert) + '" maps anyPolicy, which ' +
                    'RFC 5280 section 6.1.4(a) refuses');
    }
    if (mappings.length && root) {
      const issuers = [];
      mappings.forEach(function (m) {
        if (issuers.indexOf(m.issuer) < 0) {
          issuers.push(m.issuer);
        }
      });
      issuers.forEach(function (issuerPolicy) {
        const mapped = mappings.filter(function (m) {
          return m.issuer === issuerPolicy;
        }).map(function (m) { return m.subject; })
          .filter(function (p, at, all) { return all.indexOf(p) === at; });
        const level = atDepth(i);
        const holders = level.filter(function (node) {
          return node.policy === issuerPolicy;
        });
        if (policyMapping > 0) {
          if (holders.length) {
            holders.forEach(function (node) {
              node.expected = mapped.slice(0);
            });
          } else {
            const any = level.filter(function (node) {
              return node.policy === ANY_POLICY;
            })[0];
            if (any && any.parent) {
              nodeOf(issuerPolicy, mapped, any.parent);
            }
          }
        } else {
          holders.forEach(remove);
          prune(i);
        }
      });
    }
    // (h) (i) (j)
    if (!facts.selfIssued) {
      explicitPolicy = explicitPolicy > 0 ? explicitPolicy - 1 : 0;
      policyMapping = policyMapping > 0 ? policyMapping - 1 : 0;
      inhibitAnyPolicy = inhibitAnyPolicy > 0 ? inhibitAnyPolicy - 1 : 0;
    }
    if (facts.requireExplicitPolicy !== null) {
      explicitPolicy = Math.min(explicitPolicy, facts.requireExplicitPolicy);
    }
    if (facts.inhibitPolicyMapping !== null) {
      policyMapping = Math.min(policyMapping, facts.inhibitPolicyMapping);
    }
    if (facts.inhibitAnyPolicy !== null) {
      inhibitAnyPolicy = Math.min(inhibitAnyPolicy, facts.inhibitAnyPolicy);
    }
  }
  // Wrap-up (section 6.1.5).
  const leafFacts = pathFactsOf(path[0]);
  if (explicitPolicy > 0) {
    explicitPolicy--;
  }
  if (leafFacts.requireExplicitPolicy === 0) {
    explicitPolicy = 0;
  }
  // (g) the intersection with the initial-policy-set.
  if (root && initial.indexOf(ANY_POLICY) < 0) {
    const boundary = [];
    const collect = function (node) {
      node.children.forEach(function (child) {
        if (node.policy === ANY_POLICY) {
          boundary.push(child);
        }
        if (child.policy === ANY_POLICY) {
          collect(child);
        }
      });
    };
    collect(root);
    boundary.forEach(function (node) {
      if (node.policy !== ANY_POLICY && initial.indexOf(node.policy) < 0) {
        remove(node);
      }
    });
    const leafAny = atDepth(n).filter(function (node) {
      return node.policy === ANY_POLICY;
    })[0];
    if (leafAny) {
      const present = boundary.map(function (node) { return node.policy; });
      initial.forEach(function (policy) {
        if (present.indexOf(policy) < 0) {
          nodeOf(policy, [policy], leafAny.parent);
        }
      });
      remove(leafAny);
    }
    prune(n);
  }
  if (explicitPolicy <= 0 && !root) {
    log.debug("Leaving pathPolicyOutcome(). No policy in the end.");
    return refuse('no certificate policy acceptable to the path and to ' +
                  'this service remains, and the path requires an explicit ' +
                  'one (RFC 5280 section 6.1.5(g))');
  }
  // The user-constrained-policy-set (section 6.1.6), in the ANCHOR's policy
  // domain: the valid_policy of every node whose parent is anyPolicy — the
  // nodes step (g)(iii) calls the valid_policy_node_set — and anyPolicy only
  // where it reaches the leaf. The leaf level's own policies are mapped
  // ones, named in the subject's domain after a policyMappings, and are not
  // the answer (NIST PKITS 4.10, 4.11).
  const user = [];
  const gather = function (node) {
    node.children.forEach(function (child) {
      if (node.policy === ANY_POLICY &&
          (child.policy !== ANY_POLICY || child.depth === n) &&
          user.indexOf(child.policy) < 0) {
        user.push(child.policy);
      }
      if (child.policy === ANY_POLICY) {
        gather(child);
      }
    });
  };
  if (root) {
    gather(root);
  }
  log.debug("Leaving pathPolicyOutcome(). " + user.join(','));
  return { ok: true, why: '', userConstrainedPolicySet: user,
           explicitPolicy: explicitPolicy <= 0 };
}

// A name for a sentence.
function describePathName(name) {
  log.debug("Entering describePathName().");
  let text;
  if (name.form === 'ip') {
    text = name.value.length === 4 ? Array.from(name.value).join('.')
                                   : name.value.toString('hex');
  } else if (name.form === 'dn') {
    text = name.value.join(', ');
  } else {
    text = String(name.value);
  }
  log.debug("Leaving describePathName().");
  return '"' + text + '"';
}

// ---------------------------------------------------------------------------
// THE RULES. `path` is leaf first and anchor last — entries with `der`, as
// `certificateFromDer()` makes them. `opts.allowCritical` names critical
// extensions (by name or OID) the caller evaluates itself. Answers null, or
// `{ check, index, why }`, `check` one of:
//
//   unusable        the certificate cannot be held to the rules (see
//                   `pathFactsOf()`)
//   critical        a critical extension nothing here implements
//   weak-signature  a certificate signed with MD2, MD5 or (unless
//                   `opts.allowSha1`) SHA-1
//   malformed       a rule of RFC 5280 section 4 a relying party can and
//                   does hold a certificate to (named in `why`)
//   not-ca          a certificate above the leaf is not a CA
//   key-cert-sign   one whose keyUsage does not permit keyCertSign
//   path-len        a pathLenConstraint exceeded (`pathLen`, `below`)
//   name-constraints  a name outside what a CA above it permits
//   policy          RFC 5280 section 6.1's certificate policy processing
//                   refuses it (`pathPolicyOutcome()`, `opts.policy` its
//                   four inputs)
//
// in that order along the path from the leaf: the first certificate with a
// problem is the one reported.
// ---------------------------------------------------------------------------
function pathRuleProblem(path, opts) {
  log.debug("Entering pathRuleProblem(). " + path.length +
            " certificate(s).");
  const options = opts || {};
  const allowed = (options.allowCritical || []).map(function (name) {
    return PATH_EXTENSION_OIDS[name] || name;
  });
  const refuse = function (check, index, why, extra) {
    log.debug("Entering refuse(). check=" + check);
    log.debug("Leaving refuse().");
    return Object.assign({ check: check, index: index,
                           why: '"' + pathSubjectOf(path[index]) + '" ' +
                                why }, extra || {});
  };
  for (let i = 0; i < path.length; i++) {
    const facts = pathFactsOf(path[i]);
    if (facts.problem) {
      log.debug("Leaving pathRuleProblem(). Unusable at " + i + ".");
      return refuse('unusable', i, facts.problem);
    }
    const unknown = facts.critical.filter(function (oid) {
      return PATH_UNDERSTOOD_CRITICAL.indexOf(oid) < 0 &&
             allowed.indexOf(oid) < 0;
    });
    if (unknown.length) {
      log.debug("Leaving pathRuleProblem(). Critical at " + i + ".");
      return refuse('critical', i, 'carries a critical extension this ' +
                    'service does not implement (' + unknown.join(', ') +
                    '), which RFC 5280 section 4.2 says must be refused');
    }
    if (i < path.length - 1 && facts.weakSignature &&
        (facts.weakSignature === 'md' || !options.allowSha1)) {
      log.debug("Leaving pathRuleProblem(). A broken hash at " + i + ".");
      return refuse('weak-signature', i, 'is signed with ' +
                    (facts.weakSignature === 'md' ? 'MD2 or MD5'
                                                  : 'SHA-1') +
                    ', a hash whose collisions are practical, so the ' +
                    'signature does not bind what it signs');
    }
    if (!facts.subjectRdns.length && (!facts.hasSan || !facts.sanCritical)) {
      log.debug("Leaving pathRuleProblem(). Empty subject at " + i + ".");
      return refuse('malformed', i, 'has an empty subject and no critical ' +
                    'subjectAltName (RFC 5280 section 4.2.1.6)');
    }
    if (PATH_ML_DSA_OIDS.indexOf(facts.spkiOid) >= 0 && facts.keyUsage &&
        facts.keyUsage.some(function (usage) {
          return PATH_ML_DSA_USAGES.indexOf(usage) < 0;
        })) {
      log.debug("Leaving pathRuleProblem(). ML-DSA usage at " + i + ".");
      return refuse('malformed', i, 'holds an ML-DSA key and a keyUsage ' +
                    'naming ' + facts.keyUsage.join(', ') + ' — RFC 9881 ' +
                    'section 5 permits only digitalSignature, ' +
                    'nonRepudiation, keyCertSign and cRLSign');
    }
    // Above the leaf a certificate that is not a CA is refused as not-ca
    // below, whatever its keyUsage says; this is the leaf's rule.
    if (i === 0 && !facts.ca && facts.keyUsage &&
        facts.keyUsage.indexOf('keyCertSign') >= 0) {
      log.debug("Leaving pathRuleProblem(). keyCertSign on a non-CA.");
      return refuse('malformed', i, 'asserts keyCertSign and is not a CA ' +
                    '(RFC 5280 section 4.2.1.9)');
    }
    if (!facts.ca && facts.nameConstraints) {
      log.debug("Leaving pathRuleProblem(). nameConstraints on a non-CA.");
      return refuse('malformed', i, 'carries nameConstraints and is not a ' +
                    'CA (RFC 5280 section 4.2.1.10)');
    }
    if (i === 0) {
      continue;
    }
    if (!facts.ca) {
      log.debug("Leaving pathRuleProblem(). Not a CA at " + i + ".");
      return refuse('not-ca', i, 'signs the certificate below it and is not ' +
                    'a certificate authority (basicConstraints cA is not ' +
                    'set)');
    }
    if (facts.keyUsage && facts.keyUsage.indexOf('keyCertSign') < 0) {
      log.debug("Leaving pathRuleProblem(). keyCertSign at " + i + ".");
      return refuse('key-cert-sign', i, 'carries a keyUsage that does not ' +
                    'permit keyCertSign');
    }
    if (!facts.subjectRdns.length) {
      log.debug("Leaving pathRuleProblem(). A CA with no subject.");
      return refuse('malformed', i, 'is a CA with an empty subject (RFC 5280 ' +
                    'section 4.1.2.6)');
    }
    // Section 6.1.4(l): a self-issued certificate does not count against a
    // pathLenConstraint above it, and the leaf never does.
    let below = 0;
    for (let k = 1; k < i; k++) {
      if (!pathFactsOf(path[k]).selfIssued) {
        below++;
      }
    }
    if (facts.pathLen !== null && below > Number(facts.pathLen)) {
      log.debug("Leaving pathRuleProblem(). pathLen at " + i + ".");
      return refuse('path-len', i, 'allows ' + facts.pathLen + ' CA ' +
                    'certificate(s) below it (pathLenConstraint) and the ' +
                    'path has ' + below, { pathLen: facts.pathLen,
                                           below: below });
    }
  }
  // Name constraints, top down: each constraining CA against every
  // certificate below it that is the leaf or not self-issued.
  const budget = { checks: 0 };
  for (let i = path.length - 1; i > 0; i--) {
    if (!pathFactsOf(path[i]).nameConstraints) {
      continue;
    }
    for (let j = i - 1; j >= 0; j--) {
      if (j > 0 && pathFactsOf(path[j]).selfIssued) {
        continue;
      }
      const problem = constraintProblem(path[i], path[j], j === 0, budget);
      if (problem) {
        log.debug("Leaving pathRuleProblem(). Name constraints.");
        return refuse('name-constraints', j, problem + ' (nameConstraints ' +
                      'of "' + pathSubjectOf(path[i]) + '", RFC 5280 ' +
                      'section 4.2.1.10)', { constrainedBy: i });
      }
    }
  }
  // Certificate policies (section 6.1), once the rules above hold.
  const policy = pathPolicyOutcome(path, options.policy);
  if (!policy.ok) {
    log.debug("Leaving pathRuleProblem(). Policy.");
    return { check: 'policy', index: 0, why: policy.why };
  }
  log.debug("Leaving pathRuleProblem(). The path holds.");
  return null;
}

// Every certificate inside its validity window at `now` (milliseconds),
// widened by `skewMs`. The instant is taken at the granularity a
// certificate's times are written in — whole seconds — so a certificate is
// valid through the whole second its notAfter names (x509-limbo
// `rfc5280::validity::notafter-fractional`). `{ index, why }` or null.
function pathValidityProblem(path, now, skewMs) {
  log.debug("Entering pathValidityProblem().");
  const at = Math.floor(now / 1000) * 1000;
  const skew = Number(skewMs) || 0;
  for (let i = 0; i < path.length; i++) {
    const facts = pathFactsOf(path[i]);
    if (facts.problem) {
      continue;
    }
    if (facts.notBefore - skew > at || facts.notAfter + skew < at) {
      log.debug("Leaving pathValidityProblem(). Outside at " + i + ".");
      return { index: i, check: 'validity',
               why: '"' + pathSubjectOf(path[i]) + '" is outside its ' +
                    'validity window (' +
                    new Date(facts.notBefore).toISOString() + ' to ' +
                    new Date(facts.notAfter).toISOString() + ')' };
    }
  }
  log.debug("Leaving pathValidityProblem().");
  return null;
}

// Did `issuer` sign `cert`? Names first — the RDN lists compared as section
// 7.1 compares them — then the signature, with the vendored engine, which
// reads ML-DSA, SLH-DSA and Ed25519 as well as what pkijs reads.
async function pathSigned(cert, issuer) {
  log.debug("Entering pathSigned().");
  const a = pathFactsOf(cert);
  const b = pathFactsOf(issuer);
  if (a.problem || b.problem ||
      a.issuerRdns.join(',') !== b.subjectRdns.join(',')) {
    log.debug("Leaving pathSigned(). The names differ.");
    return false;
  }
  let ok = false;
  try {
    ok = !!(await x509.verifySignature(a.pk, b.pk));
  } catch (e) {
    log.debug("Caught in pathSigned(): " + ((e && e.message) || e));
    ok = false;
  }
  log.debug("Leaving pathSigned(). " + ok);
  return ok;
}

// ===========================================================================
// WHAT EACH CERTIFICATE ON A PATH IS ALLOWED TO DO (2026-09-13).
//
// A signature walk answers WHO SIGNED WHAT and nothing about whether the signer
// was ENTITLED to. **THE OLDEST CHAIN-VALIDATION BUG THERE IS** — a chain whose
// "intermediate" is somebody's end-entity certificate — verifies every
// signature and vouches for nothing, and `verifyLeaf()` walked signatures,
// names and validity windows and stopped there. `registerCertificate()` below
// already held an uploaded chain to these rules; the path check an `x5c` header
// is believed on did not, so every key pair this service hands out — a
// PERSON's from `/portal/signing-key` included — could sign a certificate of
// its own, present it with its own leaf above it, and the path "anchored here".
// With no subjectAltName the forged leaf names no person, and an assertion
// signed with it may name any `sub` (`assertion_grant.js`'s x5c path).
//
// RFC 5280 section 6.1.4 is what is applied, in the parts that decide
// something here:
//
//   (k)  every certificate that signs the one below it carries
//        basicConstraints cA=TRUE;
//   (n)  and a KeyUsage, where it has one, that permits keyCertSign;
//   (m)  and a pathLenConstraint the certificates below it respect —
//        intermediates only, the leaf does not count;
//
// and for the certificate whose key verifies the assertion: it is NOT a
// certificate authority, and its KeyUsage, where it has one, permits
// digitalSignature. The two functions answer with the INDEX that failed and
// leave the sentence to the caller, because an upload form and a token endpoint
// say it to different readers — and one set of rules is the point.
// ===========================================================================
async function basicConstraintsOf(pem) {
  log.debug("Entering basicConstraintsOf().");
  const described = await x509.describeCertificate(pem);
  const bc = (described.extensions || []).filter(function (ext) {
    return ext.name === 'basicConstraints';
  })[0];
  log.debug("Leaving basicConstraintsOf().");
  return (bc && bc.value) || null;
}

// `pems` is the path, leaf first. Null when every certificate on it holds
// RFC 5280's rules; otherwise `pathRuleProblem()`'s answer — `{ index, check,
// why }`, with `pathLen` and `below` for `path-len`. **SINCE #201 IT IS THE
// SHARED RULES AND NOT A SECOND COPY OF THREE OF THEM**: it was cA,
// keyCertSign and pathLenConstraint and nothing else, so a path through a
// CA whose nameConstraints excluded the leaf, or one carrying a critical
// extension nothing here implements, was accepted by every caller. `links`
// is no longer read and is kept so the three callers did not change shape.
async function authorityProblem(pems, links, opts) {
  log.debug("Entering authorityProblem(). " + pems.length + " certificate(s).");
  const path = pems.map(function (pem) {
    return certificateFromDer(pemToDer(pem)) || { der: Buffer.alloc(0) };
  });
  const problem = pathRuleProblem(path, opts || {});
  log.debug("Leaving authorityProblem(). " +
            (problem ? problem.check + ' at ' + problem.index
                     : 'The path holds.'));
  return problem;
}

// The code each of the rules' refusals is recorded under at the three doors
// that hold a path to them (#201). The three about who may issue keep the
// door's own code, as they always had one.
function authorityCode(problem, issuerCode) {
  log.debug("Entering authorityCode(). check=" + problem.check);
  const codes = { 'name-constraints': 'STS-PKI-0194',
                  critical: 'STS-PKI-0195', malformed: 'STS-PKI-0196',
                  unusable: 'STS-PKI-0196', 'weak-signature': 'STS-PKI-0197',
                  policy: 'STS-PKI-0199' };
  const code = codes[problem.check] || issuerCode;
  log.debug("Leaving authorityCode(). " + code);
  return code;
}

// The certificate whose key verifies the signature. Null when it may sign;
// otherwise `{ check }`, one of `is-ca` and `digital-signature`. A caller that
// has decided a self-signed certificate is its own anchor passes `allowCa`,
// because `openssl req -x509` writes cA=TRUE on every certificate it makes and
// a key pinned by value is not being asked to issue anything.
async function signerProblem(leafPem, links, opts) {
  log.debug("Entering signerProblem().");
  const options = opts || {};
  if (!options.allowCa) {
    const bc = await basicConstraintsOf(leafPem);
    if (bc && bc.ca) {
      log.debug("Leaving signerProblem(). The signer is a CA.");
      return { check: 'is-ca' };
    }
  }
  if (!x509.keyUsagePermits(links[0] && links[0].keyUsage,
                            'digitalSignature')) {
    log.debug("Leaving signerProblem(). digitalSignature not permitted.");
    return { check: 'digital-signature' };
  }
  log.debug("Leaving signerProblem(). It may sign.");
  return null;
}

// The sentence each problem gets at a verifier, naming the certificate at the
// failing position in whatever form the caller prints a subject.
function authoritySentence(problem, subject) {
  log.debug("Entering authoritySentence(). check=" + problem.check);
  let out;
  if (problem.check === 'not-ca') {
    out = 'The certificate "' + subject + '" signs the one below it and is ' +
          'not a certificate authority (it carries no basicConstraints ' +
          'cA=TRUE). A chain through an end-entity certificate verifies ' +
          'every signature and vouches for nothing.';
  } else if (problem.check === 'key-cert-sign') {
    out = 'The certificate "' + subject + '" carries a KeyUsage that does ' +
          'not permit keyCertSign, so it may not sign the certificate below ' +
          'it.';
  } else if (problem.check === 'path-len') {
    out = 'The certificate "' + subject + '" allows ' + problem.pathLen +
          ' intermediate CA certificate(s) below it and the chain puts ' +
          problem.below + ' there.';
  } else {
    // The rules #201 added — name constraints, a critical extension nothing
    // here implements, a certificate RFC 5280 section 4 refuses — say which
    // certificate in their own sentence.
    out = 'The certificate path breaks RFC 5280: ' + problem.why + '.';
  }
  log.debug("Leaving authoritySentence().");
  return out;
}

function signerSentence(problem, subject) {
  log.debug("Entering signerSentence(). check=" + problem.check);
  log.debug("Leaving signerSentence().");
  return problem.check === 'is-ca'
    ? 'The certificate "' + subject + '" is a certificate authority ' +
      '(basicConstraints cA=TRUE). A signature on an assertion is made ' +
      'with a LEAF\'s key; a CA\'s key signs certificates.'
    : 'The certificate "' + subject + '" carries a KeyUsage that does not ' +
      'permit digitalSignature, so its key may not sign an assertion.';
}

// ===========================================================================
// THE ALTERNATIVE SIGNATURES ON A PATH (2026-09-26, #68).
//
// `x509.verifyChain()` reports each link's alternative signature BESIDE the
// classical one and never folds the two together, because no published
// profile says what a PKIX validator should do when they disagree
// (draft-truskovsky-lamps-pq-hybrid-x509 expired). The verdict is therefore
// this module's, and it is one sentence: **a hybrid certificate is verified
// as hybrid or not at all.**
//
//   * PRESENT AND WRONG is refused everywhere (`alt-invalid`). A certificate
//     whose second signature fails is a forged or corrupted certificate
//     whatever its first one says.
//   * PRESENT AND UNCHECKABLE — no alternative key on the issuer, or an
//     algorithm the encoder does not know — is refused where `required` is
//     set (`alt-unverifiable`) and let through otherwise.
//   * ABSENT UNDER AN ISSUER THAT HOLDS AN ALTERNATIVE KEY is refused where
//     `required` is set (`alt-missing`). This is the DOWNGRADE the article
//     behind #68 warns about: "ECDSA + ML-DSA" that a relying party accepts
//     as "ECDSA OR ML-DSA" is post-quantum cryptography nobody is required
//     to use. A certificate stripped of its extensions keeps a classical
//     signature that verifies — over a different TBSCertificate, so it
//     cannot be stripped from THIS certificate, but an authority whose
//     classical key alone were compromised could mint one without them.
//
// `required` is for this service's OWN hierarchy (`verifyLeaf()`), where
// every authority holding an alternative key signs everything it issues with
// it, so an absent or uncheckable alternative signature cannot be legitimate.
// A FOREIGN hierarchy (`verifyPathToAnchors()`) may issue classical leaves
// under a hybrid CA — clause 9.8 allows it — so only a wrong signature is
// refused there.
//
// `pems` is the path, leaf first; `links` is `x509.verifyChain()` over it,
// whose last link is the top certificate checked against itself. Resolves
// null, or `{ index, check, algorithm, reason }`.
// ===========================================================================
async function holdsAlternativeKey(pem) {
  log.debug("Entering holdsAlternativeKey().");
  let described;
  try {
    described = await x509.describeCertificate(pem);
  } catch (e) {
    log.debug("Caught in holdsAlternativeKey(): " + ((e && e.message) || e));
    // Unreadable: the classical link walk has already refused anything that
    // does not parse, so this answers for a certificate it could read.
    log.debug("Leaving holdsAlternativeKey(). Unreadable.");
    return false;
  }
  const held = (described.extensions || []).some(function (ext) {
    return ext.name === 'subjectAltPublicKeyInfo' ||
           ext.oid === x509.EXT_OIDS.subjectAltPublicKeyInfo;
  });
  log.debug("Leaving holdsAlternativeKey(). " + held);
  return held;
}

async function alternativeProblem(pems, links, opts) {
  log.debug("Entering alternativeProblem(). " + pems.length +
            " certificate(s).");
  const required = !!(opts && opts.required);
  for (let i = 0; i < links.length; i++) {
    const alt = (links[i] && links[i].alternative) || { present: false };
    if (alt.present && alt.valid === false) {
      log.debug("Leaving alternativeProblem(). Link " + i + " is wrong.");
      return { index: i, check: 'alt-invalid', algorithm: alt.algorithm };
    }
    if (alt.present && alt.valid !== true) {
      if (required) {
        log.debug("Leaving alternativeProblem(). Link " + i +
                  " cannot be checked.");
        return { index: i, check: 'alt-unverifiable',
                 reason: alt.reason || '' };
      }
      continue;
    }
    if (!alt.present && required &&
        await holdsAlternativeKey(pems[i + 1] || pems[i])) {
      log.debug("Leaving alternativeProblem(). Link " + i + " is missing " +
                "the alternative signature its issuer makes.");
      return { index: i, check: 'alt-missing' };
    }
  }
  log.debug("Leaving alternativeProblem(). Every alternative signature " +
            "holds.");
  return null;
}

function alternativeSentence(problem, subject) {
  log.debug("Entering alternativeSentence(). check=" + problem.check);
  let out;
  if (problem.check === 'alt-invalid') {
    out = 'The certificate "' + subject + '" carries an alternative (' +
          (problem.algorithm || 'post-quantum') + ') signature, ITU-T X.509 ' +
          'clause 9.8, that does NOT verify under its issuer\'s alternative ' +
          'key. A hybrid certificate whose second signature fails is not a ' +
          'certificate its issuer signed, whatever the first one says.';
  } else if (problem.check === 'alt-unverifiable') {
    out = 'The certificate "' + subject + '" carries an alternative ' +
          'signature that cannot be checked' +
          (problem.reason ? ' (' + problem.reason + ')' : '') + '. In this ' +
          'service\'s own hierarchy every alternative signature is checked, ' +
          'so one that cannot be is refused rather than ignored.';
  } else {
    out = 'The certificate "' + subject + '" was issued by an authority ' +
          'that holds an alternative (post-quantum) key and carries NO ' +
          'alternative signature. Every authority here signs everything it ' +
          'issues with both keys, so a certificate with only the classical ' +
          'signature is refused: accepting it would make the post-quantum ' +
          'half optional, which is no protection at all.';
  }
  log.debug("Leaving alternativeSentence().");
  return out;
}

// ---------------------------------------------------------------------------
// DOES THIS CERTIFICATE CHAIN TO THIS SERVICE'S ROOT, THROUGH THIS REALM'S
// INTERMEDIATE?
//
// **THIS IS A REAL PATH CHECK AND IT IS THE ONE THING IN THIS MODULE A SECURITY
// CLAIM RESTS ON.** `oauth-oidc/assertion_grant.js` calls it (for
// `client_auth.js`'s client assertions and the JWT bearer grant) when an
// assertion's `x5c` is one this service is asked to believe, and the answer
// decides whether a signature counts. So it verifies every link — the
// signature, the issuer name, the validity window — and it refuses a chain
// that ends anywhere but the service Root or that does not pass through this
// realm's own Intermediate (the realm boundary, below).
//
// **WHAT IT DOES NOT DO IS CONSULT A REVOCATION LIST**, and since 2026-09-11
// that sentence is narrower than it was and more important. It used to read
// *this service publishes no CRL and answers no OCSP, so a certificate it
// issued is good until it expires.* Both halves of that are now wrong — every
// authority signs a CRL and answers OCSP, and `common/pki_revocation.js` is
// the register.
//
// ~~**THIS FUNCTION STILL DOES NOT LOOK.**~~ — **IT LOOKS SINCE 2026-09-12.**
// That paragraph read: *a chain presented in an `x5c` is checked link by link
// and against this realm's own Intermediate, and no list is fetched for any
// certificate in it — so a certificate revoked on this service's own
// `/admin/pki` is still accepted HERE.* The last check below asks the register
// about every certificate on the path, and a revoked one is refused. No list is
// FETCHED, and none needs to be: the checks before it guarantee the whole path
// is this service's own. `admin-ui/crypto_metadata.ts` still draws published
// and consulted as two rows, because they are still two claims.
// ---------------------------------------------------------------------------
async function verifyLeaf(realmId, leafPem, presentedChainPems, opts) {
  log.debug('Entering verifyLeaf().');
  const id = realmIdOf(realmId);
  // `revocation: false` is for `verifySignerChain()` alone, whose callers ask
  // `revocation_status.registeredVerdictFor()` next — the door that reports a
  // REGISTERED certificate's revocation as `STS-PKI-0129` under that module's
  // policy. Asking the register here too would answer the same question first,
  // under a different code.
  const checkRevocation = !(opts && opts.revocation === false);
  const anchors = trustAnchorsFor(id);
  if (!anchors.length) {
    log.debug('Leaving verifyLeaf(). No trust anchor.');
    return errorCodes.mark({ ok: false,
             why: 'The "' + (id || 'default') + '" realm has no certificate ' +
                  'authority, so there is no anchor to build a path to.' },
                           'STS-PKI-0014');
  }
  // The path this service will check: what was presented, then whatever of this
  // realm's own hierarchy is missing from it. A client that sends the whole
  // chain and one that sends only its leaf are both answerable, and a client
  // that sends a DIFFERENT chain is refused by the signature check below rather
  // than by being told what to send.
  const presented = (presentedChainPems || []).slice();
  const path = [leafPem].concat(presented);
  const chain = rawChainFor(id);
  // -------------------------------------------------------------------------
  // FILL IN WHAT THIS REALM'S OWN HIERARCHY WOULD SUPPLY — but only where the
  // presented path does not already END somewhere.
  //
  // **GRAFTING UNCONDITIONALLY MAKES THE REFUSAL SAY THE WRONG THING**, which
  // is what the first version of this function did and what `tests/pki.js`
  // caught. A caller presenting a complete chain to SOMEBODY ELSE'S root — a
  // real hierarchy, every link of which verifies — had this realm's three
  // tiers appended after it, so the link walk reported that their root "is not
  // signed by" our Issuing CA. True, useless, and about a signature when the
  // thing that is wrong is the ANCHOR.
  //
  // A path that already ends at a self-signed certificate is FINISHED: it is
  // walked as it stands and refused, if it must be, by the anchor check below,
  // which says so in those words. Only an incomplete path is filled in, which
  // is the case this exists for — a client sending its leaf and nothing else.
  // -------------------------------------------------------------------------
  const terminates = (function () {
    try {
      const last = new nodeCrypto.X509Certificate(path[path.length - 1]);
      return last.subject === last.issuer;
    } catch (e) {
      log.debug("Caught in a callback in verifyLeaf(): " +
                ((e && e.message) || e));
      // Unreadable: let the link walk below report it, which says more about a
      // malformed certificate than a guess here could.
      return false;
    }
  })();
  // -------------------------------------------------------------------------
  // **AND IT FOLLOWS THE ISSUER RATHER THAN APPENDING THE BRANCH, SINCE
  // 2026-09-11.** The rule above was "append this realm's three tiers", which
  // was right while every realm had a Root of its own: a presented path always
  // either terminated at somebody else's root or was one of ours missing its
  // top, and appending the whole branch completed the second case.
  //
  // One shared Root breaks that. A leaf issued in ANOTHER realm arrives with
  // its own Issuing CA and Intermediate — a path that does NOT terminate,
  // because the Root is missing — so the old rule appended THIS realm's tiers
  // after another realm's Intermediate, and the link walk reported that their
  // Intermediate "is not signed by" our Issuing CA. True, useless, and about a
  // signature when the thing that is wrong is the REALM. It is the same defect
  // the paragraph above records, in the new shape, and `tests/pki.js` caught
  // it the same way.
  //
  // So the walk matches SUBJECT to ISSUER and appends only a certificate that
  // really signed the top of the path. A path that cannot be continued is left
  // short and refused below by the check that is actually about it.
  // -------------------------------------------------------------------------
  if (!terminates) {
    const candidates = [];
    Object.keys(chain.issuing || {}).forEach(function (id) {
      candidates.push(chain.issuing[id].certificatePem);
    });
    if (chain.intermediate) {
      candidates.push(chain.intermediate.certificatePem);
    }
    const root = serviceRoot();
    if (root) {
      candidates.push(root.certificatePem);
    }
    const nameOf = function (pem) {
      log.debug("Entering nameOf().");
      try {
        const cert = new nodeCrypto.X509Certificate(pem);
        log.debug("Leaving nameOf().");
        return { subject: cert.subject, issuer: cert.issuer };
      } catch (e) {
        log.debug("Caught in nameOf(): " + ((e && e.message) || e));
        log.debug("Leaving nameOf().");
        // Unreadable: the link walk below reports it, which says more about a
        // malformed certificate than a guess here could.
        return null;
      }
    };
    for (let hop = 0; hop < 8; hop++) {
      const top = nameOf(path[path.length - 1]);
      if (!top || top.subject === top.issuer) {
        break;
      }
      const next = candidates.filter(function (pem) {
        const named = nameOf(pem);
        if (!named || named.subject !== top.issuer) {
          return false;
        }
        return !path.some(function (had) {
          return stsCrypto.stripPem(had) === stsCrypto.stripPem(pem);
        });
      })[0];
      if (!next) {
        break;
      }
      path.push(next);
    }
  }
  let links;
  try {
    links = await x509.verifyChain(path);
  } catch (e) {
    log.debug('Leaving verifyLeaf(). The path would not parse.');
    return errorCodes.mark({ ok: false,
             why: 'The certificate path could not be read: ' + e.message },
                           'STS-PKI-0015');
  }
  for (let i = 0; i < links.length; i++) {
    const link = links[i];
    if (!link.signatureValid) {
      log.debug('Leaving verifyLeaf(). Link ' + i + ' does not verify.');
      return errorCodes.mark({ ok: false, links: links,
               why: 'The certificate "' + link.subject + '" is not signed by ' +
                    '"' + link.signedBy + '"' +
                    (link.error ? ' (' + link.error + ')' : '') + '.' },
                             'STS-PKI-0016');
    }
    if (!link.namesMatch) {
      log.debug("Leaving verifyLeaf().");
      return errorCodes.mark({ ok: false, links: links,
               why: 'The certificate "' + link.subject + '" names "' +
                    link.issuer + '" as its issuer and the next certificate ' +
                    'in the path is ' +
                    '"' + link.signedBy + '".' }, 'STS-PKI-0017');
    }
    if (link.expired) {
      log.debug("Leaving verifyLeaf().");
      return errorCodes.mark({ ok: false, links: links,
               why: 'The certificate "' + link.subject + '" has expired.' },
                             'STS-PKI-0018');
    }
    if (link.notYetValid) {
      log.debug("Leaving verifyLeaf().");
      return errorCodes.mark({ ok: false, links: links,
               why: 'The certificate "' + link.subject +
                    '" is not valid yet.' }, 'STS-PKI-0019');
    }
  }
  // And the top of the path has to be OUR root. A perfectly self-consistent
  // chain to somebody else's anchor verifies every link and means nothing here.
  const top = path[path.length - 1];
  const anchored = anchors.some(function (anchor) {
    return stsCrypto.stripPem(anchor) === stsCrypto.stripPem(top);
  });
  if (!anchored) {
    log.debug('Leaving verifyLeaf(). It anchors somewhere else.');
    return errorCodes.mark({ ok: false, links: links,
             why: 'The path is internally consistent and does not end at ' +
                  'this service\'s Root CA. A chain to somebody else\'s ' +
                  'anchor verifies every link and proves nothing ' +
                  'here.' }, 'STS-PKI-0020');
  }

  // =======================================================================
  // **AND IT HAS TO PASS THROUGH THIS REALM'S OWN INTERMEDIATE. THIS IS THE
  // CHECK THAT REPLACED THE ANCHOR TEST AS THE REALM BOUNDARY (2026-09-11).**
  //
  // Until the Root was shared, "it ends at this realm's Root" WAS the realm
  // boundary: every realm had a Root of its own, so a certificate from another
  // realm failed the test above. One Root for the service makes that test true
  // of every leaf this service has ever issued, in any realm — so on the day
  // the Root was shared, the anchor check silently stopped being a boundary
  // and started being a check that the certificate is ours at all.
  //
  // What is still a boundary is the INTERMEDIATE, which is per realm and
  // unique by construction. So the path must contain it. A reader who assumed
  // the old rule still held would have left a gate that admits every realm's
  // clients to every other realm's token endpoint, with every signature
  // verifying and nothing to see.
  // =======================================================================
  const mine = rawRowFor(id);
  const ourIntermediate = mine && mine.intermediate
    ? stsCrypto.stripPem(mine.intermediate.certificatePem) : '';
  const through = ourIntermediate && path.some(function (pem) {
    return stsCrypto.stripPem(pem) === ourIntermediate;
  });
  if (!through) {
    log.debug('Leaving verifyLeaf(). It is another scope\'s branch.');
    return errorCodes.mark({ ok: false, links: links,
             why: 'The path ends at this service\'s Root CA and does NOT ' +
                  'pass through the "' + (id || 'default') + '" realm\'s own ' +
                  'Intermediate CA, so it was issued somewhere else in this ' +
                  'service. One Root is shared by every realm — the ' +
                  'Intermediate is what a realm has of its own, and it is ' +
                  'the boundary.' }, 'STS-PKI-0021');
  }
  // =======================================================================
  // **AND EVERY CERTIFICATE ON IT MUST BE ALLOWED TO DO WHAT IT DID
  // (2026-09-13).** The two checks above prove the path ENDS here and passes
  // through this realm; they say nothing about the certificates BELOW the
  // Issuing CA. Every key pair this hierarchy issues is handed to its holder
  // with the private half, so a holder could sign a certificate of their own
  // and present it under their leaf — every link verified, the path anchored,
  // the Intermediate on it, and this function answered yes. See
  // `authorityProblem()`. After the realm checks, so a path that is not ours is
  // refused for THAT; before revocation, so a forged link is refused for what
  // it is rather than as a certificate no list has heard of.
  // =======================================================================
  const nameAt = function (index) {
    log.debug("Entering nameAt().");
    log.debug("Leaving nameAt().");
    return links[index] ? links[index].subject : '';
  };
  // A development realm may have built its hierarchy with SHA-1 (#181,
  // `pki.signatureAlgorithm`); its own paths are then SHA-1 by construction.
  const issuerProblem = await authorityProblem(path, links, {
    allowSha1: mode.usesBrokenAlgorithms() });
  if (issuerProblem) {
    log.debug('Leaving verifyLeaf(). An issuer on the path may not issue.');
    return errorCodes.mark({ ok: false, links: links,
             why: authoritySentence(issuerProblem,
                                    nameAt(issuerProblem.index)) },
                           authorityCode(issuerProblem, 'STS-PKI-0158'));
  }
  const leafProblem = await signerProblem(leafPem, links);
  if (leafProblem) {
    log.debug('Leaving verifyLeaf(). The leaf may not sign.');
    return errorCodes.mark({ ok: false, links: links,
             why: signerSentence(leafProblem, nameAt(0)) }, 'STS-PKI-0159');
  }
  // =======================================================================
  // **AND A HYBRID PATH IS VERIFIED AS HYBRID (2026-09-26, #68).** Every
  // authority of this service holding an alternative key signs everything it
  // issues with it, so on this path an alternative signature that is wrong,
  // uncheckable or MISSING is refused — see `alternativeProblem()`. After the
  // classical checks, so a path that is not ours or not well formed is
  // refused for that; before revocation, for `authorityProblem()`'s reason.
  // =======================================================================
  const altProblem = await alternativeProblem(path, links, { required: true });
  if (altProblem) {
    log.debug('Leaving verifyLeaf(). An alternative signature: ' +
              altProblem.check + '.');
    return errorCodes.mark({ ok: false, links: links,
             why: alternativeSentence(altProblem, nameAt(altProblem.index)) },
             altProblem.check === 'alt-missing' ? 'STS-PKI-0202'
                                                : 'STS-PKI-0201');
  }
  // =======================================================================
  // **AND NOTHING ON IT MAY BE REVOKED (2026-09-12).** The header above said
  // this function consulted no list, so a certificate revoked on this
  // service's own /admin/pki was still accepted here. It asks the register
  // now, through `common/revocation_status.js`'s SYNCHRONOUS door: every
  // certificate on this path was issued by an authority this service holds —
  // the two checks above guarantee it — so the register is the whole answer
  // and there is nothing to fetch. The leaf, the Issuing CA and the
  // Intermediate are each looked up at the authority that signed them, which
  // is what makes a revoked Intermediate revoke every assertion under it.
  //
  // LAST, and deliberately: a path that is not ours is refused for THAT, in
  // those words, rather than being answered about a list it was never on.
  // Required lazily for the cycle `pki_revocation.js` is — that module
  // requires this one.
  // =======================================================================
  if (!checkRevocation) {
    log.debug('Leaving verifyLeaf(). It anchors here; revocation is the ' +
              'caller\'s.');
    return { ok: true, links: links, revocation: null,
             anchor: 'the "' + (id || 'default') + '" realm\'s Root CA' };
  }
  const revocation = require('./revocation_status').localVerdictFor({
    leaf: leafPem, chain: path.slice(1), verified: true
  });
  if (revocation.refused) {
    log.debug('Leaving verifyLeaf(). Refused on revocation.');
    return errorCodes.mark({ ok: false, links: links, revocation: revocation,
             why: 'The path anchors at this realm and was REFUSED ON ' +
                  'REVOCATION (pki.revocationCheck is ' + revocation.policy +
                  '): ' + revocation.why },
             errorCodes.codeOf(revocation) || 'STS-PKI-0118');
  }
  log.debug('Leaving verifyLeaf(). It anchors here.');
  return { ok: true, links: links, revocation: revocation,
           anchor: 'the "' + (id || 'default') + '" realm\'s Root CA' };
}

// ===========================================================================
// A CERTIFICATE AN OPERATOR UPLOADS IN PLACE OF AN ISSUED KEY PAIR
// (2026-09-13).
//
// `issueSigningKeyPair()` above is one of the two ways an application's RFC
// 7523 or RFC 7522 key pair is replaced; this is the other. The application
// generated its own key pair — in an HSM, a cloud KMS, somebody else's
// certificate authority — and what arrives here is the PUBLIC half: a leaf
// certificate and the chain that vouches for it. Nothing here generates,
// receives or stores a private key, and an upload carrying one is REFUSED
// rather than having the key quietly dropped, because somebody who pasted a
// private key into a form has just exposed it and needs to be told.
//
// **THE CHAIN IS WHAT IS CHECKED, AND WHAT "COMPLETE" MEANS DEPENDS ON WHO
// ISSUED IT.**
//
//   * A leaf issued by THIS REALM'S OWN certificate authority may arrive
//     alone: this module holds every tier above it, fills them in, and holds
//     the path to exactly the rule `verifyLeaf()` holds a presented `x5c` to —
//     it must pass through this realm's own Intermediate and nothing on it may
//     be revoked.
//   * A leaf from ANY OTHER authority must arrive with its WHOLE chain, up to
//     and including a SELF-SIGNED ROOT, and every link must verify: each
//     signature, each issuer name, each validity window, each issuer being a
//     CA whose key usage permits certificate signing and whose path length
//     constraint the chain below it respects. The root need not be trusted by
//     anything here — the application is registering a KEY, and the chain is
//     the evidence that key is what its issuer says it is — but an incomplete
//     chain is refused by name, because a registration that cannot say who
//     vouched for its key cannot be checked for revocation either.
//
// **A CHAIN THAT ENDS AT THIS SERVICE'S OWN ROOT IS NEVER "EXTERNAL".** A
// certificate issued in ANOTHER REALM builds a perfectly consistent chain to
// the one Root every realm shares, and accepting it here as a foreign
// authority's would let one realm's key pair be registered in another with
// every link verifying — the realm boundary `verifyLeaf()` spends a page on,
// walked around through an upload form. So a path that terminates at the
// service Root is held to that function's rule and refused by its sentence.
//
// **THE RECORD IT RETURNS IS `issueSigningKeyPair()`'s SHAPE WITH AN EMPTY
// PRIVATE KEY**, so `admin-ui/pki_admin.ts` writes both through ONE table and
// taking a key pair off is one act whichever way it arrived. `source` is the
// one member an issue does not carry, and it is what the application's page
// draws: `uploaded-realm-ca` or `uploaded-external-ca`.
//
// **UNLIKE THE ISSUED CHAIN, AN EXTERNAL ONE IS STORED WITH ITS ROOT.** The
// issued convention leaves the Root out because this service's Root is an
// anchor a relying party is given out of band. A foreign root is not anything
// this service or a relying party holds, so leaving it out would throw away
// the one certificate that makes the chain checkable — and
// `revocation_status.js` needs every issuer on the path to verify the lists
// that could revoke the leaf.
// ===========================================================================
const PEM_BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----/g;

// Every PEM block in a text, in order, with its label. A value that carries
// base64 and no armour is not a PEM block and is reported as such rather than
// guessed at: a certificate is uploaded as PEM, which is what every tool that
// produces one writes.
function pemBlocksOf(text) {
  log.debug("Entering pemBlocksOf().");
  const out = [];
  const source = Array.isArray(text) ? text.join('\n') : String(text || '');
  let match;
  PEM_BLOCK.lastIndex = 0;
  while ((match = PEM_BLOCK.exec(source)) !== null) {
    out.push({ label: match[1], pem: match[0].trim() + '\n' });
  }
  log.debug("Leaving pemBlocksOf(). " + out.length + " block(s).");
  return out;
}

// A refusal in this module's shape, with its code attached where a caller
// reads it and never on the wire.
function uploadRefusal(code, sentence) {
  log.debug("Entering uploadRefusal(). code=" + code);
  log.debug("Leaving uploadRefusal().");
  return errorCodes.mark({ ok: false, errors: [sentence] }, code);
}

// A certificate's subject or issuer on one line, the way this module's other
// sentences print a name.
function oneLineName(name) {
  log.debug("Entering oneLineName().");
  log.debug("Leaving oneLineName().");
  return String(name || '').split('\n').filter(Boolean).join(', ');
}

// WHICH KEYS A PROFILE'S VERIFIER CAN ACTUALLY USE. An uploaded certificate
// over a key the verifier cannot check registers perfectly and then fails
// every assertion it signs, somewhere else, later — so it is refused here,
// naming what would work. The two lists differ because the two verifiers do:
// RFC 7523's is JOSE (`common/crypto.js`'s JWS table, which has EdDSA and
// ES256K), and RFC 7522's is XML Signature (`common/crypto.js` section 1a
// since the #37 follow-up: RSA, EC on any curve node knows, Ed25519, Ed448,
// DSA, ML-DSA and SLH-DSA — it used to name ECDSA here, which nothing
// actually verified).
const UPLOAD_CURVES = { 'prime256v1': 'ES256', 'secp384r1': 'ES384',
                        'secp521r1': 'ES512', 'secp256k1': 'ES256K' };

function uploadedKeyProblem(publicKey, purposeId) {
  log.debug("Entering uploadedKeyProblem(). purpose=" + purposeId);
  const type = publicKey.asymmetricKeyType;
  const details = publicKey.asymmetricKeyDetails || {};
  const saml = purposeId === 'saml';
  const accepted = saml
    ? 'an RSA key of at least 2048 bits, or an ECDSA, EdDSA, DSA, ML-DSA or ' +
      'SLH-DSA key'
    : 'an RSA key of at least 2048 bits, an ECDSA key on P-256, P-384, P-521 ' +
      'or secp256k1, or an Ed25519 key';
  if (type === 'rsa') {
    if (Number(details.modulusLength) < 2048) {
      log.debug("Leaving uploadedKeyProblem(). A short RSA key.");
      return 'The certificate carries a ' + details.modulusLength + '-bit ' +
             'RSA key. This service accepts ' + accepted + '.';
    }
    log.debug("Leaving uploadedKeyProblem(). RSA.");
    return '';
  }
  if (saml) {
    const usable = stsCrypto.xmlSignatureKeyTypeUsable(type);
    log.debug("Leaving uploadedKeyProblem(). XML Signature: " + usable);
    return usable ? ''
      : 'The certificate carries a "' + type + '" key, which the XML ' +
        'Signature verifier behind this profile cannot check. This service ' +
        'accepts ' + accepted + '.';
  }
  if (type === 'ec') {
    const curve = String(details.namedCurve || '');
    if (!UPLOAD_CURVES[curve]) {
      log.debug("Leaving uploadedKeyProblem(). An unusable curve.");
      return 'The certificate carries an ECDSA key on "' + curve + '", which ' +
             'the ' + (saml ? 'XML Signature' : 'JWS') + ' verifier behind ' +
             'this profile cannot check. This service accepts ' + accepted +
             '.';
    }
    log.debug("Leaving uploadedKeyProblem(). ECDSA.");
    return '';
  }
  if (type === 'ed25519' && !saml) {
    log.debug("Leaving uploadedKeyProblem(). Ed25519.");
    return '';
  }
  log.debug("Leaving uploadedKeyProblem(). An unusable key type.");
  return 'The certificate carries a "' + type + '" key, which the ' +
         (saml ? 'XML Signature' : 'JWS') + ' verifier behind this profile ' +
         'cannot check. This service accepts ' + accepted + '.';
}

// The JWS `alg` a JWK built from an uploaded key names, or '' where the key
// does not decide one. An RSA key signs RS256, RS384, PS256 or any of the
// others with equal right, and naming one on the JWK would be this service
// guessing what the application's signer does — so it names none. A curve
// decides its ECDSA algorithm (RFC 7518 section 3.4) and Ed25519 is EdDSA.
function uploadedJwsAlg(publicKey) {
  log.debug("Entering uploadedJwsAlg().");
  const type = publicKey.asymmetricKeyType;
  const details = publicKey.asymmetricKeyDetails || {};
  if (type === 'ec') {
    log.debug("Leaving uploadedJwsAlg(). A curve.");
    return UPLOAD_CURVES[String(details.namedCurve || '')] || '';
  }
  if (type === 'ed25519') {
    log.debug("Leaving uploadedJwsAlg(). EdDSA.");
    return 'EdDSA';
  }
  log.debug("Leaving uploadedJwsAlg(). None.");
  return '';
}

// Is `issuer` the certificate that signed `cert`? Names first, then the
// signature where node can check it. A signature node cannot check — a
// post-quantum issuer — falls back to the name match, and the link walk below
// then reports the signature for what it is rather than this function
// pretending the issuer was not supplied.
function issuedBy(cert, issuer) {
  log.debug("Entering issuedBy().");
  if (!namesChain(cert, issuer)) {
    log.debug("Leaving issuedBy(). The names differ.");
    return 0;
  }
  try {
    if (cert.checkIssued(issuer) && cert.verify(issuer.publicKey)) {
      log.debug("Leaving issuedBy(). It signed it.");
      return 2;
    }
  } catch (e) {
    log.debug("Caught in issuedBy(): " + ((e && e.message) || e));
    // A key node cannot read. Handled as a NAME match, for the reason above.
    log.debug("Leaving issuedBy(). The signature could not be checked here.");
    return 1;
  }
  log.debug("Leaving issuedBy(). The names match and the signature does not.");
  return 1;
}

// Does `cert` name `issuer` as its issuer? The two names compared as RFC
// 5280 section 7.1 compares them (`rdnsOfName()`: case, and leading,
// trailing and repeated spaces, do not count), not as node spells them —
// until #201 a chain whose names differed only in capitalisation or
// whitespace did not chain here (NIST PKITS 4.3.3-4.3.5, 4.3.11). Node's
// string comparison stands where the names cannot be read.
function namesChain(cert, issuer) {
  log.debug("Entering namesChain().");
  const a = certificateFromDer(cert.raw);
  const b = issuer === cert ? a : certificateFromDer(issuer.raw);
  const fa = a ? pathFactsOf(a) : null;
  const fb = b ? pathFactsOf(b) : null;
  const same = fa && fb && !fa.problem && !fb.problem
    ? fa.issuerRdns.join(',') === fb.subjectRdns.join(',')
    : cert.issuer === issuer.subject;
  log.debug("Leaving namesChain(). " + same);
  return same;
}

function selfSignedCert(cert) {
  log.debug("Entering selfSignedCert().");
  if (!namesChain(cert, cert)) {
    log.debug("Leaving selfSignedCert(). No.");
    return false;
  }
  try {
    const signed = cert.verify(cert.publicKey);
    log.debug("Leaving selfSignedCert(). " + signed);
    return signed;
  } catch (e) {
    log.debug("Caught in selfSignedCert(): " + ((e && e.message) || e));
    // A key node cannot read: the names say self-issued, and verifyChain()
    // below checks the self-signature with the vendored engine.
    log.debug("Leaving selfSignedCert(). Unverifiable here.");
    return true;
  }
}

async function registerCertificate(realmId, opts) {
  log.debug('Entering registerCertificate().');
  const id = realmIdOf(realmId);
  const options = opts || {};
  const identifier = String(options.identifier || '');
  // WHO IT IS FOR (2026-09-13): an application, as it was written for, or a
  // PERSON — whose key pair a certificate may now replace too. The kind
  // decides the `kid` prefix and which subjectAltName a certificate this
  // realm issued must carry; everything about the chain is the same.
  const subjectKind = subjectKindFor(options.subjectKind || 'application');
  if (!subjectKind) {
    log.debug('Leaving registerCertificate(). Unknown subject kind.');
    return uploadRefusal('STS-PKI-0012', '"' + options.subjectKind + '" is ' +
                         'not a kind of subject a certificate is registered ' +
                         'for. There are ' + SUBJECT_KIND_IDS.join(' and ') +
                         '.');
  }
  if (!identifier) {
    log.debug('Leaving registerCertificate(). No identifier.');
    return uploadRefusal('STS-PKI-0140', 'A certificate is registered FOR ' +
                         'something. Name the ' + subjectKind.id + ' it is ' +
                         'for.');
  }
  const purpose = purposeFor(options.purpose);
  if (!purpose) {
    log.debug('Leaving registerCertificate(). Unknown purpose.');
    return uploadRefusal('STS-PKI-0011', '"' + options.purpose + '" is not a ' +
                         'profile this service registers a signing ' +
                         'certificate for. It registers ' +
                         PURPOSE_IDS.join(' and ') + '.');
  }
  const given = pemBlocksOf(options.certificatePem);
  const supplied = pemBlocksOf(options.chainPem);
  const everything = given.concat(supplied);
  // A PRIVATE KEY IS REFUSED BY NAME. Dropping it and carrying on would leave
  // somebody believing the service now holds their key, and — the half that
  // matters — would say nothing to a person who has just pasted a private key
  // into a web form and should treat it as exposed.
  const keyBlock = everything.filter(function (one) {
    return /PRIVATE KEY/.test(one.label);
  })[0];
  if (keyBlock) {
    log.debug('Leaving registerCertificate(). A private key was uploaded.');
    return uploadRefusal('STS-PKI-0141', 'The upload carries a "' +
                         keyBlock.label + '" block. Uploading replaces the ' +
                         'key pair with a CERTIFICATE — the ' +
                         subjectKind.id + ' keeps its own private key and ' +
                         'this service never ' +
                         'holds it — so nothing was stored. If that key was ' +
                         'pasted here by mistake, treat it as exposed.');
  }
  const stray = everything.filter(function (one) {
    return one.label !== 'CERTIFICATE';
  })[0];
  if (stray) {
    log.debug('Leaving registerCertificate(). Not a certificate block.');
    return uploadRefusal('STS-PKI-0142', 'The upload carries a "' +
                         stray.label + '" block, and only CERTIFICATE blocks ' +
                         'are read: the leaf first, then the chain above it.');
  }
  if (!given.length) {
    log.debug('Leaving registerCertificate(). No certificate.');
    return uploadRefusal('STS-PKI-0142', 'No PEM certificate was uploaded. ' +
                         'Paste the leaf as "-----BEGIN CERTIFICATE-----" ' +
                         'and the chain above it in the same form.');
  }
  // Parsed once, deduplicated by DER — the same intermediate pasted into both
  // boxes is one certificate, not an extra one on the path.
  const parsed = [];
  const seen = {};
  for (let i = 0; i < everything.length; i++) {
    let cert;
    try {
      cert = new nodeCrypto.X509Certificate(everything[i].pem);
    } catch (e) {
      log.debug("Caught in registerCertificate(): " + ((e && e.message) || e));
      log.debug('Leaving registerCertificate(). An unreadable certificate.');
      return uploadRefusal('STS-PKI-0143', 'Certificate ' + (i + 1) + ' of ' +
                           everything.length + ' in the upload could not be ' +
                           'read: ' + e.message + '.');
    }
    const key = cert.raw.toString('base64');
    if (seen[key]) {
      continue;
    }
    seen[key] = true;
    parsed.push({ cert: cert, pem: cert.toString() });
  }
  const leaf = parsed[0];
  const nowMs = Date.now();
  if (leaf.cert.ca) {
    log.debug('Leaving registerCertificate(). The leaf is a CA.');
    return uploadRefusal('STS-PKI-0144', 'The first certificate, "' +
                         oneLineName(leaf.cert.subject) + '", is a ' +
                         'certificate authority (basicConstraints cA=TRUE). ' +
                         'The key pair an assertion is signed with is a ' +
                         'LEAF; put the ' + subjectKind.id + '\'s own ' +
                         'certificate first and its issuers after it.');
  }
  if (new Date(leaf.cert.validTo).getTime() < nowMs ||
      new Date(leaf.cert.validFrom).getTime() > nowMs) {
    log.debug('Leaving registerCertificate(). Outside its validity.');
    return uploadRefusal('STS-PKI-0145', 'The certificate "' +
                         oneLineName(leaf.cert.subject) + '" is valid from ' +
                         leaf.cert.validFrom + ' to ' + leaf.cert.validTo +
                         ', and it is not valid now. A key pair registered ' +
                         'outside its validity would verify nothing.');
  }
  const keyProblem = uploadedKeyProblem(leaf.cert.publicKey, purpose.id);
  if (keyProblem) {
    log.debug('Leaving registerCertificate(). An unusable key.');
    return uploadRefusal('STS-PKI-0146', keyProblem);
  }

  // A SELF-SIGNED LEAF HAS NO CHAIN TO BE COMPLETE. It is its own issuer, so
  // "the full trust chain" is the certificate itself and nothing vouched for
  // it — which is what the attributes a party REGISTERS by value are for
  // (`oauthJwks`, `oauthSamlAssertionSigningCertificate`), and not what this
  // door, which replaces the key pair a certificate authority stands behind,
  // is for.
  if (selfSignedCert(leaf.cert)) {
    log.debug('Leaving registerCertificate(). A self-signed leaf.');
    return uploadRefusal('STS-PKI-0147', 'The certificate "' +
                         oneLineName(leaf.cert.subject) + '" is self-signed, ' +
                         'so no certificate authority vouches for it and ' +
                         'there is no chain to check. Upload a certificate ' +
                         'issued by this realm\'s certificate authority or ' +
                         'by another one, with that authority\'s chain' +
                         (subjectKind.id === 'person'
                           // A PERSON HAS NO BY-VALUE DOOR. Their entry holds
                           // the one key pair this set describes, and a key
                           // nobody vouched for is not a credential this
                           // service will register for somebody.
                           ? '. A person has no by-value registration, so ' +
                             'a self-signed key cannot be used for one.'
                           : ' — or register a self-signed key by value on ' +
                             (purpose.id === 'saml'
                               ? 'oauthSamlAssertionSigningCertificate'
                               : 'oauthJwks') + '.'));
  }

  // -------------------------------------------------------------------------
  // THE PATH. Built by ISSUER rather than by the order things were pasted in,
  // because nobody agrees on that order and a refusal for it would be a
  // refusal about formatting. Candidates are what was uploaded and, where this
  // realm has a certificate authority, its own tiers — so a leaf this realm
  // issued needs nothing uploaded above it. `pathByIssuer()` is shared with
  // `verifySignerChain()`, which builds the same path every time the key is
  // USED, so the registration and the use cannot disagree about it.
  // -------------------------------------------------------------------------
  const candidates = parsed.slice(1).map(function (one) {
    return { cert: one.cert, pem: one.pem, uploaded: true };
  }).concat(realmCandidatesFor(id));
  const root = serviceRoot();
  const built = pathByIssuer({ cert: leaf.cert, pem: leaf.pem,
                               uploaded: true }, candidates);
  const path = built.path;
  const used = built.used;
  const top = path[path.length - 1].cert;
  if (path.length === 1 || !selfSignedCert(top)) {
    log.debug('Leaving registerCertificate(). An incomplete chain.');
    return uploadRefusal('STS-PKI-0147', 'The chain is incomplete: nothing ' +
                         'uploaded issued "' + oneLineName(top.subject) +
                         '" (its issuer is "' + oneLineName(top.issuer) +
                         '"). A certificate from a certificate authority ' +
                         'other than this realm\'s must be uploaded with its ' +
                         'WHOLE chain — every intermediate and the ' +
                         'self-signed root — so that this service can verify ' +
                         'who vouched for the key and check every list that ' +
                         'could revoke it.');
  }
  const leftover = candidates.filter(function (candidate, index) {
    return candidate.uploaded && !used[index];
  })[0];
  if (leftover) {
    log.debug('Leaving registerCertificate(). An unrelated certificate.');
    return uploadRefusal('STS-PKI-0148', 'The certificate "' +
                         oneLineName(leftover.cert.subject) + '" was ' +
                         'uploaded and is not on the path from "' +
                         oneLineName(leaf.cert.subject) + '" to its root. ' +
                         'Upload the leaf and exactly the chain above it, so ' +
                         'that what is stored is the path that was checked.');
  }

  const ours = root && stsCrypto.stripPem(path[path.length - 1].pem) ===
                       stsCrypto.stripPem(root.certificatePem);
  let source;
  let storedChain;
  let revocation = null;
  if (ours) {
    // THE REALM BOUNDARY. `verifyLeaf()` is the one function that decides
    // whether a path anchored at this service's Root belongs to THIS realm,
    // and asking anything else would be a second answer to that question.
    const verdict = await verifyLeaf(id, leaf.pem, path.slice(1).map(
        function (one) { return one.pem; }));
    if (!verdict.ok) {
      log.debug('Leaving registerCertificate(). This service\'s own chain ' +
                'was refused.');
      return uploadRefusal(errorCodes.codeOf(verdict) || 'STS-PKI-0149',
                           'The certificate chains to this service\'s own ' +
                           'Root CA and was refused: ' + verdict.why);
    }
    // THE SUBJECT THE CERTIFICATE NAMES (2026-09-13). A leaf this realm issued
    // carries `urn:sts:application:<id>` or `urn:sts:person:<name>`, and
    // `assertion_grant.js` reads that URI off a presented `x5c` to decide
    // whether the signer may assert about anybody. Two registrations would
    // WIDEN whoever holds the key, and both are refused:
    //
    //   * FOR A PERSON, a leaf naming anybody else — another person's, whose
    //     holder could then assert as this one, or an application's. A person's
    //     key pair is ONE PERSON's credential; that is the whole rule
    //     `person_assertions.js` exists for.
    //   * FOR AN APPLICATION, a leaf naming a PERSON — whose holder would then
    //     speak for whoever the application may speak for, which is the
    //     authority the person rule withholds.
    //
    // One application's leaf registered for another stays allowed, as it was
    // on the day uploads arrived: an operator moving an application's key is
    // making the same decision an external certificate is. A leaf naming no
    // subject of this service (one the Certificate & Key pane authored)
    // carries no such claim, and is registered on the entry's word alone.
    const named = String(leaf.cert.subjectAltName || '').split(',')
      .map(function (one) { return one.trim(); })
      .map(function (one) {
        return /^URI:(urn:sts:(?:application|person):.+)$/.exec(one);
      })
      .filter(Boolean)
      .map(function (match) { return match[1]; });
    const wanted = subjectKind.urnPrefix + identifier;
    const widens = subjectKind.id === 'person'
      ? named.length && named.indexOf(wanted) < 0
      : named.some(function (one) { return /^urn:sts:person:/.test(one); });
    if (widens) {
      log.debug('Leaving registerCertificate(). It names another subject.');
      return uploadRefusal('STS-PKI-0155', 'The certificate was issued by ' +
                           'this realm\'s certificate authority to ' +
                           named.map(function (one) {
                             return '"' + one + '"';
                           }).join(' and ') + ', and it is being registered ' +
                           'for "' + wanted + '". A certificate this service ' +
                           'issued says in its subjectAltName who it belongs ' +
                           'to, and the token endpoint reads that name; ' +
                           (subjectKind.id === 'person'
                             ? 'a person\'s key pair is that one person\'s ' +
                               'credential, and registering somebody else\'s ' +
                               'would let its holder assert as them. '
                             : 'a person\'s certificate registered for an ' +
                               'application would let that person speak for ' +
                               'others. ') +
                           'Issue a key pair to this ' + subjectKind.id +
                           ' instead.');
    }
    source = 'uploaded-realm-ca';
    revocation = verdict.revocation || null;
    // The issued convention: the Root is an anchor handed over out of band,
    // so it is not carried in the chain.
    storedChain = path.slice(1).filter(function (one) {
      return stsCrypto.stripPem(one.pem) !==
             stsCrypto.stripPem(root.certificatePem);
    }).map(function (one) { return one.pem; });
  } else {
    const pems = path.map(function (one) { return one.pem; });
    let links;
    try {
      links = await x509.verifyChain(pems);
    } catch (e) {
      log.debug("Caught in registerCertificate(): " + ((e && e.message) || e));
      log.debug('Leaving registerCertificate(). The path would not parse.');
      return uploadRefusal('STS-PKI-0143', 'The chain could not be read: ' +
                           e.message + '.');
    }
    for (let i = 0; i < links.length; i++) {
      const link = links[i];
      const problem = !link.signatureValid
        ? 'is not signed by "' + link.signedBy + '"' +
          (link.error ? ' (' + link.error + ')' : '')
        : !link.namesMatch
          ? 'names "' + link.issuer + '" as its issuer and the next ' +
            'certificate is "' + link.signedBy + '"'
          : link.expired ? 'has expired'
            : link.notYetValid ? 'is not valid yet' : '';
      if (problem) {
        log.debug('Leaving registerCertificate(). Link ' + i + ' failed.');
        return uploadRefusal('STS-PKI-0150', 'The chain does not verify: "' +
                             link.subject + '" ' + problem + '.');
      }
    }
    // EVERY ISSUER MUST BE ALLOWED TO ISSUE. A chain whose "intermediate" is
    // somebody's end-entity certificate verifies every signature and vouches
    // for nothing — the oldest chain-validation bug there is, and the one a
    // signature walk alone does not see. `authorityProblem()` is the one set
    // of rules; `verifyLeaf()` and `verifySignerChain()` ask it too.
    const issuerProblem = await authorityProblem(path.map(function (one) {
      return one.pem;
    }), links);
    if (issuerProblem) {
      log.debug('Leaving registerCertificate(). An issuer may not issue.');
      return uploadRefusal(authorityCode(issuerProblem, 'STS-PKI-0151'),
        authoritySentence(issuerProblem,
                          oneLineName(path[issuerProblem.index].cert
                            .subject)));
    }
    // A WRONG ALTERNATIVE SIGNATURE IS REFUSED HERE TOO (#68) — the foreign
    // rule of `alternativeProblem()`: somebody else's hybrid CA may issue a
    // classical leaf, and may not issue a leaf whose second signature fails.
    const altProblem = await alternativeProblem(path.map(function (one) {
      return one.pem;
    }), links, { required: false });
    if (altProblem) {
      log.debug('Leaving registerCertificate(). A wrong alternative ' +
                'signature.');
      return uploadRefusal('STS-PKI-0201', alternativeSentence(altProblem,
        oneLineName(path[altProblem.index].cert.subject)));
    }
    if (!x509.keyUsagePermits(links[0].keyUsage, 'digitalSignature')) {
      log.debug('Leaving registerCertificate(). No digitalSignature.');
      return uploadRefusal('STS-PKI-0146', 'The certificate "' +
                           oneLineName(leaf.cert.subject) + '" carries a ' +
                           'KeyUsage that does not permit digitalSignature, ' +
                           'so its key may not sign an assertion.');
    }
    // REVOCATION, the way a registered certificate is checked when it is used
    // — `revocation_status.js`'s own door for exactly this, so an upload is
    // refused for what would refuse its first assertion. Lazily required, for
    // the cycle `verifyLeaf()` already records.
    revocation = await require('./revocation_status').registeredVerdictFor({
      certificate: leaf.pem,
      chain: path.slice(1).map(function (one) { return one.pem; }),
      source: 'the certificate uploaded for "' + identifier + '"'
    });
    if (revocation && revocation.refused) {
      log.debug('Leaving registerCertificate(). Refused on revocation.');
      return uploadRefusal(errorCodes.codeOf(revocation) || 'STS-PKI-0152',
                           'The chain verifies and was REFUSED ON ' +
                           'REVOCATION: ' + revocation.why);
    }
    source = 'uploaded-external-ca';
    storedChain = path.slice(1).map(function (one) { return one.pem; });
  }

  const publicJwk = leaf.cert.publicKey.export({ format: 'jwk' });
  publicJwk.kid = subjectKind.kidPrefix +
                  stsCrypto.jwkThumbprint(publicJwk, { truncate: 16 });
  publicJwk.use = 'sig';
  const jwsAlg = uploadedJwsAlg(leaf.cert.publicKey);
  if (jwsAlg) {
    publicJwk.alg = jwsAlg;
  }
  publicJwk.x5c = [stsCrypto.stripPem(leaf.pem)]
    .concat(storedChain.map(stsCrypto.stripPem));
  publicJwk['x5t#S256'] = stsCrypto.certificateThumbprint(leaf.pem,
                                                          { format:
                                                              'base64url' });
  const details = leaf.cert.publicKey.asymmetricKeyDetails || {};
  const record = {
    identifier: identifier,
    realm: id,
    purpose: purpose.id,
    purposeLabel: purpose.label,
    subjectKind: subjectKind.id,
    source: source,
    kid: publicJwk.kid,
    keyAlg: leaf.cert.publicKey.asymmetricKeyType +
            (details.modulusLength ? '-' + details.modulusLength : '') +
            (details.namedCurve ? '-' + details.namedCurve : ''),
    jwsAlg: jwsAlg,
    subject: oneLineName(leaf.cert.subject),
    issuer: oneLineName(leaf.cert.issuer),
    serialHex: String(leaf.cert.serialNumber || '').toLowerCase(),
    notBefore: new Date(leaf.cert.validFrom).toISOString(),
    notAfter: new Date(leaf.cert.validTo).toISOString(),
    certificatePem: leaf.pem,
    chainPem: storedChain,
    chainSubjects: path.slice(1).map(function (one) {
      return oneLineName(one.cert.subject);
    }),
    privateKeyPem: '',
    publicJwk: publicJwk,
    jwks: { keys: [publicJwk] },
    thumbprint: thumbprintOf(leaf.pem),
    certificateThumbprint: stsCrypto.certificateThumbprint(leaf.pem,
                                                           { format:
                                                               'base64url' }),
    revocation: revocation ? { status: revocation.status || '',
                               policy: revocation.policy || '' } : null,
    registeredAt: nowMs
  };
  log.info('pki: a ' + source + ' certificate was registered for the ' +
           subjectKind.id + ' "' +
           identifier + '" in the "' + id + '" realm for ' + purpose.label +
           '. subject=' + record.subject + ', issuer=' + record.issuer +
           ', kid=' + record.kid + ', expires ' + record.notAfter + '.');
  log.debug('Leaving registerCertificate(). ' + source);
  return { ok: true, registered: record };
}

// This realm's own tiers and the service Root, as path candidates — so a leaf
// this realm issued needs nothing registered above it.
function realmCandidatesFor(id) {
  log.debug("Entering realmCandidatesFor().");
  const out = [];
  const push = function (pem) {
    log.debug("Entering push().");
    try {
      out.push({ cert: new nodeCrypto.X509Certificate(pem), pem: pem,
                 uploaded: false });
    } catch (e) {
      // A tier node cannot read is not a candidate; the path simply does not
      // continue through it, and the refusal below names what is missing.
      log.debug("Caught in push(): " + ((e && e.message) || e));
    }
    log.debug("Leaving push().");
  };
  const row = rawChainFor(id);
  if (row) {
    Object.keys(row.issuing || {}).forEach(function (useCaseId) {
      push(row.issuing[useCaseId].certificatePem);
    });
    if (row.intermediate) {
      push(row.intermediate.certificatePem);
    }
  }
  const root = serviceRoot();
  if (root) {
    push(root.certificatePem);
  }
  log.debug("Leaving realmCandidatesFor(). " + out.length + " candidate(s).");
  return out;
}

// Walk from `leafEntry` up through `candidates` by ISSUER — names first, then
// the signature where node can check it — stopping at a self-signed
// certificate or where nothing continues the path.
function pathByIssuer(leafEntry, candidates) {
  log.debug("Entering pathByIssuer(). " + candidates.length + " candidate(s).");
  const path = [leafEntry];
  const used = {};
  for (let hop = 0; hop < 10; hop++) {
    const top = path[path.length - 1].cert;
    if (hop > 0 && selfSignedCert(top)) {
      break;
    }
    let best = null;
    let bestScore = 0;
    candidates.forEach(function (candidate, index) {
      if (used[index]) {
        return;
      }
      const score = issuedBy(top, candidate.cert);
      if (score > bestScore) {
        best = index;
        bestScore = score;
      }
    });
    if (best === null) {
      break;
    }
    used[best] = true;
    path.push(candidates[best]);
  }
  log.debug("Leaving pathByIssuer(). " + path.length + " certificate(s).");
  return { path: path, used: used };
}

// One certificate out of whatever spelling a registration holds it in: a PEM
// block, or the base64 DER an `x5c` member carries. '' where there is none.
function certificatePemOf(value) {
  log.debug("Entering certificatePemOf().");
  const text = String(value || '').trim();
  if (!text) {
    log.debug("Leaving certificatePemOf(). Nothing.");
    return '';
  }
  if (/-----BEGIN/.test(text)) {
    const blocks = pemBlocksOf(text).filter(function (one) {
      return one.label === 'CERTIFICATE';
    });
    log.debug("Leaving certificatePemOf(). PEM.");
    return blocks.length ? blocks[0].pem : '';
  }
  log.debug("Leaving certificatePemOf(). Base64 DER.");
  return '-----BEGIN CERTIFICATE-----\n' +
         text.replace(/\s+/g, '').replace(/(.{64})/g, '$1\n')
           .replace(/\n$/, '') +
         '\n-----END CERTIFICATE-----\n';
}

// Every certificate in a registered chain, however it was held: an array of
// PEM or base64 members, or one text of PEM blocks.
function chainPemsOf(value) {
  log.debug("Entering chainPemsOf().");
  const out = [];
  (Array.isArray(value) ? value : [value]).forEach(function (one) {
    const text = String(one || '').trim();
    if (!text) {
      return;
    }
    if (/-----BEGIN/.test(text)) {
      pemBlocksOf(text).forEach(function (block) {
        if (block.label === 'CERTIFICATE') {
          out.push(block.pem);
        }
      });
      return;
    }
    out.push(certificatePemOf(text));
  });
  log.debug("Leaving chainPemsOf(). " + out.length + " certificate(s).");
  return out;
}

// The SubjectPublicKeyInfo a certificate carries, as DER. node's reading where
// it has one, pkijs's where OpenSSL cannot parse the key (a post-quantum one).
function certificateSpkiDer(pem) {
  log.debug("Entering certificateSpkiDer().");
  try {
    const der = new nodeCrypto.X509Certificate(pem).publicKey
      .export({ type: 'spki', format: 'der' });
    log.debug("Leaving certificateSpkiDer(). node.");
    return der;
  } catch (e) {
    log.debug("Caught in certificateSpkiDer(): " + ((e && e.message) || e));
  }
  const cert = pkijs.Certificate.fromBER(
    Buffer.from(stsCrypto.stripPem(pem), 'base64'));
  log.debug("Leaving certificateSpkiDer(). pkijs.");
  return Buffer.from(cert.subjectPublicKeyInfo.toSchema().toBER(false));
}

// Does the certificate hold THIS key? RFC 7517 section 4.7: the key in the
// first `x5c` certificate MUST match the key the JWK represents. Without it a
// registration could carry somebody's perfectly valid chain beside a key that
// chain never vouched for, and the check below would validate a certificate
// that has nothing to do with the signature.
function certificateHoldsKey(pem, key) {
  log.debug("Entering certificateHoldsKey().");
  let want;
  try {
    if (key && key.kty === 'AKP') {
      want = Buffer.from(stsCrypto.stripPem(pqSubjectPublicKeyPem(key.alg,
                                                                  key)),
                         'base64');
    } else if (key && typeof key.export === 'function') {
      want = key.export({ type: 'spki', format: 'der' });
    } else {
      const jwk = Object.assign({}, key);
      delete jwk.x5c;
      want = nodeCrypto.createPublicKey({ key: jwk, format: 'jwk' })
        .export({ type: 'spki', format: 'der' });
    }
    const held = certificateSpkiDer(pem);
    const same = Buffer.isBuffer(held) && held.equals(want);
    log.debug("Leaving certificateHoldsKey(). " + same);
    return same;
  } catch (e) {
    log.debug("Caught in certificateHoldsKey(): " + ((e && e.message) || e));
    // A key that cannot be compared is not a key that matched.
    log.debug("Leaving certificateHoldsKey(). Could not compare.");
    return false;
  }
}

// ===========================================================================
// THE SIGNER CERTIFICATE'S WHOLE CHAIN, VALIDATED WHERE THE SIGNATURE IS
// (2026-09-13).
//
// **UNTIL THIS DATE A REGISTERED CERTIFICATE'S CHAIN WAS CHECKED ONCE, WHEN IT
// WAS REGISTERED, AND NEVER AGAIN.** An RFC 7523 key out of `oauthJwks`,
// `oauthAssertionJwks` or `stsAssertionJwks` carrying an `x5c`, and an RFC 7522
// certificate registered by value or issued, verified an assertion and then got
// a REVOCATION check and nothing else. A certificate expires; an Intermediate
// above it expires; an operator replaces the Root and every branch under it; a
// JWKS pasted by hand carries whatever chain somebody typed — and every one of
// those went on signing assertions this service believed, because the only
// time anything looked at the path was the day it was written down. The one
// certificate that WAS path-checked at every use, a presented `x5c` header, was
// checked for signatures and never for who was entitled to make them (see
// `authorityProblem()`).
//
// So this is asked by all three verifiers — `oauth-oidc/assertion_grant.js`,
// `client_auth.js` and `saml_assertion_grant.js` — AFTER the signature has
// verified and BEFORE revocation and before any claim is believed. What
// anchors the chain is decided by who issued the leaf, and there are three
// answers:
//
//   `realm`            the path ends at this service's Root and passes through
//                      THIS realm's Intermediate. `verifyLeaf()` decides it,
//                      because it is the one function that says what belongs
//                      to a realm; a leaf may be registered alone.
//   `registered-root`  the path ends at a SELF-SIGNED ROOT that was registered
//                      with the certificate. The registration is the trust
//                      decision, which is the rule `registerCertificate()`
//                      applies to an upload and is held to again here: every
//                      signature, every issuer name, every validity window,
//                      every issuer a CA permitted to sign within its path
//                      length, and a leaf that is not a CA and may sign. A
//                      chain that does NOT reach a self-signed root is refused
//                      as incomplete — nothing here fetches an issuer to finish
//                      it, because a certificate fetched from an address inside
//                      the certificate is not one anybody registered.
//   `pinned`           the certificate is itself self-signed. It is its own
//                      whole chain, so its self-signature and validity are what
//                      is checked, and a cA=TRUE on it is NOT refused: every
//                      `openssl req -x509` certificate carries one, and a key
//                      pinned by value is not being asked to issue anything.
//
// `material.key`, where the certificate rides beside a key (a JWK), must be the
// key the certificate holds — RFC 7517 section 4.7.
//
// **REFUSED IN BOTH MODES.** The signature is the whole security of both
// grants, and a signature checked against a chain that does not hold is not a
// signature this service may believe — the reason the registered-issuer
// refusal beside it is on by default and has no mode.
//
// A bare key has no certificate and is not asked about: RFC 7523 permits one,
// and there is nothing to chain.
// ===========================================================================
async function verifySignerChain(realmId, material) {
  log.debug('Entering verifySignerChain().');
  const id = realmIdOf(realmId);
  const m = material || {};
  const source = m.source || 'the registered certificate';
  // The code rides on the verdict under the error-code Symbol and the caller
  // marks its response with it, so the audit row carries it and writes the one
  // log line (`audit.js`'s rule); a second line here would be the same failure
  // logged twice.
  const refuse = function (code, why, extra) {
    log.debug("Entering refuse(). code=" + code);
    log.debug("Leaving refuse().");
    return errorCodes.mark(Object.assign({ ok: false, why: why }, extra || {}),
                           code);
  };
  const leafPem = certificatePemOf(m.certificate);
  if (!leafPem) {
    log.debug('Leaving verifySignerChain(). No certificate.');
    return refuse('STS-PKI-0161', 'There is no certificate to validate — ' +
                  source + ' holds nothing readable where one is expected.');
  }
  const entryOf = function (pem, uploaded) {
    log.debug("Entering entryOf().");
    const cert = new nodeCrypto.X509Certificate(pem);
    log.debug("Leaving entryOf().");
    return { cert: cert, pem: cert.toString(), uploaded: uploaded };
  };
  let leaf;
  const registered = [];
  try {
    leaf = entryOf(leafPem, true);
    chainPemsOf(m.chain).forEach(function (pem) {
      const one = entryOf(pem, true);
      if (stsCrypto.stripPem(one.pem) !== stsCrypto.stripPem(leaf.pem)) {
        registered.push(one);
      }
    });
  } catch (e) {
    log.debug("Caught in verifySignerChain(): " + ((e && e.message) || e));
    log.debug('Leaving verifySignerChain(). Unreadable.');
    return refuse('STS-PKI-0161', 'A certificate in ' + source + ' could not ' +
                  'be read: ' + e.message + '.');
  }
  const leafName = oneLineName(leaf.cert.subject);

  if (m.key && !certificateHoldsKey(leaf.pem, m.key)) {
    log.debug('Leaving verifySignerChain(). The key is not the ' +
              'certificate\'s.');
    return refuse('STS-PKI-0160', 'The certificate "' + leafName + '" in ' +
                  source + ' does not hold the key that verified the ' +
                  'signature. RFC 7517 section 4.7 requires the first x5c ' +
                  'certificate to hold the key the JWK represents; a chain ' +
                  'beside a different key vouches for nothing about it.');
  }

  const linkProblem = function (links) {
    log.debug("Entering linkProblem().");
    for (let i = 0; i < links.length; i++) {
      const link = links[i];
      const problem = !link.signatureValid
        ? 'is not signed by "' + link.signedBy + '"' +
          (link.error ? ' (' + link.error + ')' : '')
        : !link.namesMatch
          ? 'names "' + link.issuer + '" as its issuer and the next ' +
            'certificate is "' + link.signedBy + '"'
          : link.expired ? 'has expired'
            : link.notYetValid ? 'is not valid yet' : '';
      if (problem) {
        log.debug("Leaving linkProblem(). Link " + i + ".");
        return '"' + link.subject + '" ' + problem;
      }
    }
    log.debug("Leaving linkProblem(). None.");
    return '';
  };

  // --- PINNED: a self-signed certificate is its own chain -------------------
  if (selfSignedCert(leaf.cert)) {
    let links;
    try {
      links = await x509.verifyChain([leaf.pem]);
    } catch (e) {
      log.debug("Caught in verifySignerChain(): " + ((e && e.message) || e));
      log.debug('Leaving verifySignerChain(). The pinned certificate would ' +
                'not parse.');
      return refuse('STS-PKI-0161', 'The certificate "' + leafName + '" in ' +
                    source + ' could not be read: ' + e.message + '.');
    }
    const broken = linkProblem(links);
    if (broken) {
      log.debug('Leaving verifySignerChain(). The pinned certificate fails.');
      return refuse('STS-PKI-0157', 'The self-signed certificate ' + broken +
                    '. A certificate registered by value is its own whole ' +
                    'chain, and it has to hold.', { links: links });
    }
    // The rules a certificate is held to on its own (#201): a pinned
    // certificate carrying a critical extension nothing here implements is
    // refused as it would be anywhere on a path.
    const alone = await authorityProblem([leaf.pem], links);
    if (alone) {
      log.debug('Leaving verifySignerChain(). The pinned certificate ' +
                'breaks a rule.');
      return refuse(authorityCode(alone, 'STS-PKI-0157'),
                    authoritySentence(alone, leafName), { links: links });
    }
    const signs = await signerProblem(leaf.pem, links, { allowCa: true });
    if (signs) {
      log.debug('Leaving verifySignerChain(). The pinned key may not sign.');
      return refuse('STS-PKI-0159', signerSentence(signs, leafName),
                    { links: links });
    }
    log.debug('Leaving verifySignerChain(). Pinned.');
    return { ok: true, anchor: 'pinned', links: links,
             path: [leafName] };
  }

  // --- the path, built by issuer --------------------------------------------
  const root = serviceRoot();
  const built = pathByIssuer(leaf, registered.concat(realmCandidatesFor(id)));
  const path = built.path;
  const top = path[path.length - 1];
  const subjects = path.map(function (one) {
    return oneLineName(one.cert.subject);
  });

  // --- THIS SERVICE'S OWN ROOT: the realm decides ---------------------------
  if (root && stsCrypto.stripPem(top.pem) ===
              stsCrypto.stripPem(root.certificatePem)) {
    const verdict = await verifyLeaf(id, leaf.pem, path.slice(1)
      .map(function (one) { return one.pem; }), { revocation: false });
    if (!verdict.ok) {
      log.debug('Leaving verifySignerChain(). Refused by the realm path ' +
                'check.');
      return refuse(errorCodes.codeOf(verdict) || 'STS-PKI-0157',
                    'The certificate "' + leafName + '" chains to this ' +
                    'service\'s Root CA and the path was refused: ' +
                    verdict.why, { links: verdict.links || [],
                                   path: subjects });
    }
    log.debug('Leaving verifySignerChain(). Anchored in this realm.');
    return { ok: true, anchor: 'realm', links: verdict.links, path: subjects,
             revocation: verdict.revocation || null };
  }

  // --- ANYBODY ELSE'S: a path to a registered self-signed root -------------
  //
  // **BUILT BY `verifyPathToAnchors()` SINCE #201**, the self-signed
  // certificates registered with the key as its anchors and the rest as
  // intermediates. The greedy walk above answers only whether the path ends
  // at this service's Root; as the builder of a foreign path it took the
  // first issuer whose name matched and never the next, so an expired
  // sibling or a cross-certificate registered beside the right one refused a
  // chain that held, and it held the path to cA, keyCertSign and
  // pathLenConstraint and nothing else — a registered chain through a CA
  // whose nameConstraints excluded the leaf verified assertions (x509-limbo,
  // `tests/x509_limbo.js`). The anchors are what the operator registered,
  // which is the trust decision `registerCertificate()` records.
  const anchors = registered.filter(function (one) {
    return selfSignedCert(one.cert);
  }).map(function (one) {
    return certificateFromDer(one.cert.raw);
  }).filter(Boolean);
  if (!anchors.length || path.length === 1) {
    log.debug('Leaving verifySignerChain(). Incomplete.');
    return refuse('STS-PKI-0156', 'The chain of "' + leafName + '" in ' +
                  source + ' is incomplete: nothing registered with it ' +
                  'issued "' + oneLineName(top.cert.subject) + '" (its ' +
                  'issuer is "' + oneLineName(top.cert.issuer) + '"). A ' +
                  'certificate that is not this realm\'s must be registered ' +
                  'with its WHOLE chain, up to and including the ' +
                  'self-signed root, and the whole chain is validated every ' +
                  'time the key verifies a signature.',
                  { path: subjects });
  }
  const intermediates = registered.filter(function (one) {
    return !selfSignedCert(one.cert);
  }).map(function (one) {
    return one.cert.raw;
  });
  const foreign = await verifyPathToAnchors(leaf.cert.raw, intermediates,
                                          anchors, {});
  if (!foreign.ok) {
    const code = foreign.check === 'no-path' || foreign.check === 'exhausted'
      ? 'STS-PKI-0156'
      : (foreign.check === 'signature' || foreign.check === 'validity')
        ? 'STS-PKI-0157'
        : authorityCode({ check: foreign.check }, 'STS-PKI-0158');
    log.debug('Leaving verifySignerChain(). The path was refused (' +
              foreign.check + ').');
    return refuse(code, 'The chain of "' + leafName + '" in ' + source +
                  ' does not hold: ' + foreign.reason + '.',
                  { path: subjects });
  }
  const chainPems = foreign.chain.map(function (one) { return one.pem; });
  const chainSubjects = foreign.chain.map(function (one) {
    return oneLineName(one.x509.subject);
  });
  let links;
  try {
    links = await x509.verifyChain(chainPems);
  } catch (e) {
    log.debug("Caught in verifySignerChain(): " + ((e && e.message) || e));
    log.debug('Leaving verifySignerChain(). The path would not parse.');
    return refuse('STS-PKI-0161', 'The chain of "' + leafName + '" could not ' +
                  'be read: ' + e.message + '.', { path: chainSubjects });
  }
  // The foreign rule of `alternativeProblem()` (#68): wrong is refused.
  const altProblem = await alternativeProblem(path.map(function (one) {
    return one.pem;
  }), links, { required: false });
  if (altProblem) {
    log.debug('Leaving verifySignerChain(). A wrong alternative signature.');
    return refuse('STS-PKI-0201', alternativeSentence(altProblem,
                    subjects[altProblem.index]),
                  { links: links, path: subjects });
  }
  const signs = await signerProblem(leaf.pem, links);
  if (signs) {
    log.debug('Leaving verifySignerChain(). The leaf may not sign.');
    return refuse('STS-PKI-0159', signerSentence(signs, leafName),
                  { links: links, path: chainSubjects });
  }
  log.debug('Leaving verifySignerChain(). Anchored at a registered root.');
  return { ok: true, anchor: 'registered-root', links: links,
           path: chainSubjects, chain: chainPems };
}

// A short sentence for a door's log line and audit detail.
function signerChainSummary(verdict) {
  log.debug("Entering signerChainSummary().");
  if (!verdict) {
    log.debug("Leaving signerChainSummary(). No verdict.");
    return 'chain: not checked (no certificate)';
  }
  log.debug("Leaving signerChainSummary().");
  return verdict.ok
    ? 'chain: valid, anchored ' + ({ realm: 'in this realm',
                                     'registered-root':
                                       'at the registered root',
                                     pinned: 'as a pinned certificate' }
                                   [verdict.anchor] || verdict.anchor) +
      ' (' + (verdict.path || []).length + ' certificate(s))'
    : 'chain: refused — ' + verdict.why;
}

// ---------------------------------------------------------------------------
// THROW THE HIERARCHY AWAY. Destructive and it says so: every certificate
// issued from it stops chaining to anything the moment this returns, and this
// service holds no copy of what was issued, so nothing here can list what
// broke.
// ---------------------------------------------------------------------------
function clearChain(realmId) {
  log.debug('Entering clearChain().');
  const id = realmIdOf(realmId);
  const held = rawChainFor(id);
  if (!held) {
    log.debug('Leaving clearChain(). Nothing to clear.');
    return errorCodes.mark({ ok: false,
             errors: ['The "' + (id || 'default') + '" realm has no ' +
                      'certificate authority.'] }, 'STS-PKI-0008');
  }
  // THE OBJECT STORE SURVIVES THIS, which is the other half of what
  // `buildChain()` does with it. Removing the hierarchy is a statement about
  // the three tiers; a workbench object is somebody's own key pair, possibly
  // self-signed and owing nothing to those tiers at all, and taking them away
  // together would make one button mean two things. `saveRow()` removes the
  // row outright where nothing is left, so a realm with no objects behaves
  // exactly as it did before this store existed.
  // **THE BRANCH IS WHAT IS REMOVED, AND `tiers` IS NOT A STORED MEMBER SINCE
  // 2026-09-11** — it is composed on the way out of the service Root and this
  // scope's own Intermediate. Emptying it emptied a member nothing reads, so
  // the hierarchy came back on the next render; `tests/pki_authoring.js`
  // caught it.
  delete held.tiers;
  delete held.intermediate;
  delete held.issuing;
  // And the certificates under it, which is the honest half: a certificate
  // whose Issuing CA has been removed chains to nothing this service holds,
  // and reporting it as current would be the console vouching for a path it
  // can no longer build.
  delete held.certs;
  saveRow(id, held);
  log.warn('pki: the "' + id +
           '" realm\'s certificate authority was removed. ' +
           held.issuedCount + ' certificate(s) were issued from it and every ' +
           'one of them now chains to nothing. This service keeps no copy of ' +
           'what it issued, so none of them can be listed.');
  log.debug('Leaving clearChain(). Removed.');
  return { ok: true, issuedCount: held.issuedCount || 0 };
}

// ---------------------------------------------------------------------------
// SMALL THINGS, in one place so that two call sites cannot spell them
// differently.
// ---------------------------------------------------------------------------
function thumbprintOf(pem) {
  log.debug("Entering thumbprintOf().");
  log.debug("Leaving thumbprintOf().");
  return stsCrypto.certificateThumbprint(pem, { format: 'hex' });
}

// A certificate PEM as DER. Here rather than in one of the vendored modules
// because those are byte-identical to the parent project's and must stay so;
// `spiffe/spiffe_ca.ts` has the same three lines for the same reason.
function pemToDer(pem) {
  log.debug("Entering pemToDer().");
  log.debug("Leaving pemToDer().");
  return Buffer.from(String(pem).replace(/-----[^-]+-----/g, '')
    .replace(/\s+/g, ''), 'base64');
}

function publicJwkOf(publicPem) {
  log.debug("Entering publicJwkOf().");
  log.debug("Leaving publicJwkOf().");
  return nodeCrypto.createPublicKey(publicPem).export({ format: 'jwk' });
}

// The JWS `alg` a key of this kind signs with, so that the JWK this module
// hands out names one. The signature algorithm chosen for the CERTIFICATE
// decides the digest — an RSA key issued under a SHA-384 chain gets RS384 —
// which is what makes "the certificate and the assertion agree" true rather
// than approximately true.
function jwsAlgFor(keyDesc, sigAlgId) {
  log.debug('Entering jwsAlgFor(). sigAlg=' + sigAlgId);
  const sig = x509.sigAlg(sigAlgId) || {};
  const digit = /512/.test(sig.hash || '') ? '512'
    : (/384/.test(sig.hash || '') ? '384' : '256');
  if (keyDesc.kind === 'okp') {
    log.debug('Leaving jwsAlgFor(). EdDSA.');
    return 'EdDSA';
  }
  if (keyDesc.kind === 'ec') {
    // The CURVE decides an ECDSA alg and the certificate's digest does not:
    // RFC 7518 pins ES256 to P-256, ES384 to P-384 and ES512 to P-521, so a
    // P-256 key signed under a SHA-512 chain is still ES256 and naming it
    // ES512 would produce assertions nothing can verify.
    log.debug('Leaving jwsAlgFor(). ECDSA on ' + keyDesc.curve + '.');
    if (keyDesc.curve === 'P-384') {
      log.debug("Leaving jwsAlgFor().");
      return 'ES384';
    }
    if (keyDesc.curve === 'P-521') {
      log.debug("Leaving jwsAlgFor().");
      return 'ES512';
    }
    log.debug("Leaving jwsAlgFor().");
    return 'ES256';
  }
  if (keyDesc.kind === 'rsa') {
    log.debug('Leaving jwsAlgFor(). RSA.');
    return (sig.pss ? 'PS' : 'RS') + digit;
  }
  log.debug('Leaving jwsAlgFor(). No JWS algorithm for that key.');
  return null;
}


// ===========================================================================
// THE CERTIFICATE REGISTER: WHAT EACH ISSUING CA HAS CERTIFIED (2026-09-11).
//
// **A SLOT IS (use case, algorithm) AND NOT (use case, kid), WHICH IS THE ONE
// DECISION IN HERE.** A `kid` is derived from the certificate and changes
// whenever the key is regenerated; a slot has to survive that, because what an
// operator pins, reissues or overrides is *what signs my ES384*, not *the key
// that happened to be there on Tuesday*. So the handle is the algorithm — which
// is also the granularity the request asked for: "their own CAs and key pairs
// for each use case, each signing algorithm".
//
// **NO PRIVATE KEY IS STORED HERE FOR A KEY THIS SERVICE GENERATED.** The
// signing keys live in `keystore.js`'s key set and this holds their
// CERTIFICATES — one copy of a private key is the whole of this module's
// placement argument, and a second one under a certificate record would be a
// second thing to seal, purge and rotate. The exception is a PINNED pair,
// where the operator supplied key material this service has nowhere else to
// keep; those are marked and are the only records with a key in them.
// ===========================================================================

// A slot holds one certificate. **A KEY GENERATION HAS A SLOT OF ITS OWN**
// (2026-09-22, #42): `jose:RS256@<kid>` beside `jose:RS256`, so the `next`
// key published ahead of its promotion and a retired key still verifying each
// keep their certificate (and their `x5c`) while the current key keeps the
// plain slot every reader already asks for.
function slotKey(useCaseId, slot, kid) {
  log.debug("Entering slotKey().");
  log.debug("Leaving slotKey().");
  return String(useCaseId) + ':' + String(slot) + (kid ? '@' + String(kid)
                                                   : '');
}

// Every certificate this Issuing CA has minted, newest first.
function certificatesFor(scopeId, useCaseId) {
  log.debug("Entering certificatesFor().");
  const row = rawRowFor(scopeId);
  const held = (row && row.certs) || {};
  const prefix = String(useCaseId) + ':';
  log.debug("Leaving certificatesFor().");
  return Object.keys(held).filter(function (key) {
    return key.indexOf(prefix) === 0;
  }).map(function (key) {
    return held[key];
  }).sort(function (a, b) {
    return (b.createdAt || 0) - (a.createdAt || 0);
  });
}

// The key pairs `issueSigningKeyPair()` issued from one use case's Issuing CA,
// as the records that function keeps — serial, subject, expiry, who for, and
// no key. `pki_revocation.js`'s `issuedList()` is the reader.
function issuedKeyPairsFor(scopeId, useCaseId) {
  log.debug("Entering issuedKeyPairsFor().");
  const row = rawRowFor(scopeId);
  log.debug("Leaving issuedKeyPairsFor().");
  return ((row && row.issuedKeyPairs) || []).filter(function (one) {
    return one && one.useCase === String(useCaseId);
  });
}

// `kid`, where given, asks for that key generation's own slot first, and the
// plain slot only when the certificate there is over the same key — so a
// caller naming a key never gets a certificate over another one.
function certificateFor(scopeId, useCaseId, slot, kid) {
  log.debug("Entering certificateFor().");
  const row = rawRowFor(scopeId);
  const certs = (row && row.certs) || {};
  if (kid) {
    const own = certs[slotKey(useCaseId, slot, kid)];
    if (own) {
      log.debug("Leaving certificateFor(). The generation's own slot.");
      return own;
    }
    const plain = certs[slotKey(useCaseId, slot)];
    log.debug("Leaving certificateFor(). The plain slot, if it is this key.");
    return plain && plain.kid && plain.kid === String(kid) ? plain : null;
  }
  log.debug("Leaving certificateFor().");
  return certs[slotKey(useCaseId, slot)] || null;
}

// The public view of one certificate. A pinned record HAS a private key in it
// and this is where it is dropped, for `describeChain()`'s reason: one place,
// so a caller cannot leak an operator's own key by forgetting.
function describeCertificate(one) {
  log.debug("Entering describeCertificate().");
  if (!one) {
    log.debug("Leaving describeCertificate().");
    return null;
  }
  log.debug("Leaving describeCertificate().");
  return {
    slot: one.slot,
    useCase: one.useCase,
    label: one.label,
    alg: one.alg || '',
    keyAlg: one.keyAlg || '',
    signatureAlg: one.signatureAlg || '',
    subject: one.subject,
    serialHex: one.serialHex,
    notBefore: one.notBefore,
    notAfter: one.notAfter,
    expired: new Date(one.notAfter).getTime() < Date.now(),
    thumbprint: one.thumbprint,
    pinned: !!one.pinned,
    certificatePem: one.certificatePem,
    chainPem: (one.chainPem || []).slice(),
    createdAt: one.createdAt
  };
}

// ---------------------------------------------------------------------------
// CERTIFY ONE KEY PAIR FROM A USE CASE'S ISSUING CA.
//
// The caller owns the key and keeps it; this issues the certificate and
// records it. **It answers `{ ok: false }` rather than throwing when there is
// no Issuing CA**, because the callers are startup paths — a service that
// would not start because a certificate could not be minted for a key it
// already has would be trading a working mock for a cosmetic one.
// ---------------------------------------------------------------------------
// How many times `certify()` signs again when the authority it signed with was
// replaced during the signature — see the block above its `saveRow()`.
const CERTIFY_ISSUER_MOVED_RETRIES = 3;

async function certify(scopeId, useCaseId, spec) {
  log.debug('Entering certify(). scope=' + scopeId + ' use=' + useCaseId +
            ' slot=' + (spec && spec.slot));
  const id = String(scopeId);
  const uc = useCase(useCaseId);
  if (!uc) {
    log.debug('Leaving certify(). Unknown use case.');
    return errorCodes.mark({ ok: false,
             errors: ['"' + useCaseId + '" is not a use case this service ' +
                      'issues for. They are ' + USE_CASE_IDS.join(', ') +
                      '.'] }, 'STS-PKI-0022');
  }
  // ---------------------------------------------------------------------
  // **DOES THIS BRANCH STILL CHAIN TO THE ROOT WE WOULD PUBLISH?** (2026-09-11)
  //
  // It can stop doing. `buildRoot()` replaces the Root and leaves the branches
  // where they are — `pki_admin.js`'s Replace-the-Root control rebuilds them
  // afterwards, and a branch whose rebuild FAILS is logged and skipped, which
  // leaves exactly this state. So does any other path that gets a new Root
  // without getting new branches.
  //
  // Certifying from a stale branch is the worst available outcome, because
  // everything downstream looks right: the leaf is issued, the chain travels
  // with it, `/tls/server-certificate` publishes the current Root beside them
  // — and the Root does not sign the Intermediate, so no client can build a
  // path. The two Roots have the SAME SUBJECT, so every page, every log line
  // and every `openssl x509 -subject` agrees with itself. What it costs is
  // every node client (`unable to get local issuer certificate`), while curl
  // accepts it — so it is invisible from a shell and fatal to this
  // repository's whole test suite and to this service's own OpenID Connect
  // back channel.
  //
  // **SO IT IS REPAIRED HERE RATHER THAN GUARDED AGAINST FURTHER OUT.** This
  // is the one funnel every leaf in this service goes through, and it is the
  // only place that holds both the branch and the Root at once. Rebuilding is
  // safe and is what the operator asked for implicitly by replacing the Root:
  // the branch was already worthless.
  // ---------------------------------------------------------------------
  if (!scopeChainsToRoot(id)) {
    // -------------------------------------------------------------------
    // **UNLESS THE CALLER IS WAITING FOR ANOTHER PROCESS'S BRANCH
    // (2026-09-13).** `spec.repairBranch === false` is the front process of a
    // dispatched service reconciling its listener after a Root arrived from a
    // request worker. That worker is rebuilding every branch in the same act
    // (`pki_admin.js`'s `rebuildEveryScope()`), so the process branch is a
    // publish or two behind the Root — and rebuilding it HERE as well was two
    // processes building one branch at once over a last-write-wins channel,
    // which is the race "A BRANCH IS BUILT ONCE, IN ONE PROCESS" closed for a
    // realm's branch and left open for this one. Refused rather than rebuilt;
    // `tls_server.js` asks again when the branch arrives, and falls back to
    // the repair if it never does.
    // -------------------------------------------------------------------
    if (spec && spec.repairBranch === false) {
      log.info('pki: the "' + (id || 'default') + '" branch does not chain ' +
               'to this service\'s Root yet and this caller asked not to ' +
               'rebuild it, so "' + (spec.slot || '') + '" is not certified ' +
               'now — the process that replaced the Root publishes the ' +
               'branch next.');
      log.debug('Leaving certify(). Waiting for the branch.');
      return { ok: false, deferred: true,
               errors: ['The "' + (id || 'default') + '" branch does not ' +
                        'chain to this service\'s Root yet.'] };
    }
    log.warn('pki: the "' + (id || 'default') + '" branch does not chain to ' +
             'this service\'s Root CA — a Root was replaced without its ' +
             'branches being rebuilt. Rebuilding the branch before issuing, ' +
             'because a leaf issued from it would carry a chain nothing can ' +
             'verify against the Root this service publishes.');
    const rebuilt = await repairBranch(id);
    if (!rebuilt.ok) {
      log.error(errorCodes.tag('STS-PKI-0023') + 'pki: that branch could not ' +
                                                 'be rebuilt (' +
                (rebuilt.errors || []).join(' ') + '), so nothing was ' +
                'certified. Issuing from the stale branch would have ' +
                'produced a certificate that verifies against nothing this ' +
                'service publishes.');
      log.debug('Leaving certify(). The stale branch could not be rebuilt.');
      return errorCodes.mark({ ok: false, errors: rebuilt.errors },
                             'STS-PKI-0023');
    }
  }

  const row = rawRowFor(id);
  const ca = row && row.issuing ? row.issuing[uc.id] : null;
  if (!ca) {
    log.debug('Leaving certify(). No Issuing CA.');
    return errorCodes.mark({ ok: false,
             errors: ['The "' + (id || 'default') + '" scope has no ' +
                      uc.label + ' Issuing CA. Build the hierarchy on ' +
                      '/admin/pki first.'] }, 'STS-PKI-0009');
  }
  // ---------------------------------------------------------------------
  // **THE ALGORITHM THIS CA CAN SIGN WITH, NOT THE ONE IT WAS SIGNED WITH**
  // (2026-09-11). `ca.signatureAlg` is what the INTERMEDIATE used on this
  // authority's certificate — a property of the parent's key — and it was
  // being handed to the primitive as the algorithm to sign a LEAF with, using
  // this authority's own key. The two coincide exactly when every tier in the
  // branch is the same key family, which was true of every hierarchy this
  // service had ever built, so nothing could see it.
  //
  // It stopped being true the moment a use case was allowed a key algorithm of
  // its own: an EC SPIFFE Issuing CA under an RSA Intermediate carries
  // `signatureAlg: 'sha256-rsa'`, and `sha256-rsa` over an EC key is
  // `Invalid key type` out of Web Crypto, naming neither the tier nor the
  // algorithm. `signatureForIssuer()` answers the stored value when the key
  // can produce it and the right default when it cannot, so this is a repair
  // and not a new policy.
  // ---------------------------------------------------------------------
  const issuerDesc = keyMaterial.keyAlg(ca.keyAlg);
  const sigAlgId = signatureForIssuer(ca, ca.signatureAlg, ca.keyAlg);
  const days = Number(spec.days) > 0 ? Math.floor(Number(spec.days))
                                     : Number(config.value(
                                         'pki.leafLifetimeDays'));
  // Seconds and no finer, like the CA tiers above. A leaf is years rather than
  // decades out, so it is a UTCTime and carries no fractional part anyway — it
  // goes through the same helper so that there is ONE answer to "what does a
  // validity in this module look like" rather than one per lifetime.
  const notBefore = certificateInstant();
  const notAfter = certificateInstant(notBefore.getTime() + days * 86400000);
  const caEnds = new Date(ca.notAfter).getTime();
  if (notAfter.getTime() > caEnds) {
    notAfter.setTime(caEnds);
  }
  const organisation = (row && row.organisation) || DEFAULT_ORGANISATION;
  const subject = [{ name: 'CN', value: String(spec.commonName || spec.slot) },
                   { name: 'O', value: organisation }]
    .concat(row && row.country ? [{ name: 'C', value: row.country }] : []);
  let issued;
  try {
    issued = await x509.issueCertificate(Object.assign({
      subject: subject,
      subjectPublicKey: spec.publicKeyPem,
      // A HYBRID LEAF (#68): the subject's second key, a signer group's
      // ML-DSA partner, in subjectAltPublicKeyInfo — see
      // certifySignerGroups().
      subjectAltPublicKey: spec.altPublicKeyPem || undefined,
      signatureAlg: sigAlgId,
      profile: spec.profile || 'digital-signature',
      notBefore: notBefore.toISOString(),
      notAfter: notAfter.toISOString(),
      issuer: { certificatePem: ca.certificatePem,
                privateKeyPem: ca.privateKeyPem, keyAlg: ca.keyAlg },
      extensions: Object.assign({
        basicConstraints: { present: true, critical: true, ca: false },
        keyUsage: { present: true, critical: true,
                    usages: spec.keyUsage ||
                            ['digitalSignature', 'nonRepudiation'] },
        subjectKeyIdentifier: { present: true },
        authorityKeyIdentifier: { present: true }
      }, revocationExtensionsFor(id, uc.id), spec.extensions || {})
    }, alternativeSignatureBy(ca)));
  } catch (e) {
    log.error(errorCodes.tag('STS-PKI-0024') + 'pki: the ' + uc.label + ' ' +
        'certificate for "' + spec.slot +
              '" could not be issued: ' + e.message);
    log.debug('Leaving certify(). The encoder refused.');
    return errorCodes.mark({ ok: false,
             errors: ['That certificate could not be issued: ' + e.message] },
                           'STS-PKI-0024');
  }
  const record = {
    slot: String(spec.slot),
    useCase: uc.id,
    scope: id,
    label: String(spec.label || spec.slot),
    alg: String(spec.alg || ''),
    keyAlg: String(spec.keyAlg || ''),
    signatureAlg: sigAlgId,
    subject: issued.subject,
    serialHex: issued.serialHex,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    certificatePem: issued.pem,
    // LEAF-FIRST AND WITHOUT THE ROOT, which is what RFC 5246 section 7.4.2
    // asks of a TLS certificate_list and what every JWS `x5c` header does. The
    // Root is a trust anchor: sending it is harmless and relying on it having
    // been sent is the mistake.
    chainPem: [ca.certificatePem, row.intermediate.certificatePem],
    thumbprint: thumbprintOf(issued.pem),
    // **THE SUBJECT KEY, KEPT BESIDE THE CERTIFICATE (2026-09-13).** A renewal
    // used to read it back out of the certificate with node's OpenSSL, and
    // OpenSSL cannot read a composite ML-DSA key at all — so renewing the JOSE
    // Issuing CA would have failed for six of the eleven post-quantum
    // certificates with a message about decoding. Public, and small next to
    // the certificate that already carries it.
    subjectPublicKeyPem: String(spec.publicKeyPem),
    // The SHA-256 of that SubjectPublicKeyInfo, which is how
    // `certifyPqKeys()` tells "already certified" from "a different key".
    subjectKeyFingerprint: thumbprintOf(spec.publicKeyPem),
    // AND THE SECOND KEY OF A HYBRID LEAF (#68), for the same reason: a
    // renewal (`recertifyUseCase()`) re-issues from what is stored, and a
    // renewal that dropped this would turn a hybrid certificate classical.
    altPublicKeyPem: spec.altPublicKeyPem ? String(spec.altPublicKeyPem)
                                          : null,
    pinned: !!spec.pinned,
    createdAt: Date.now()
  };
  // THE HOLDER'S SUBJECT, where the caller knows one (2026-09-14): the slot
  // and the certificate name the holder as they were CALLED at issuance, and a
  // rename or a re-created name would otherwise move the certificate to
  // whoever holds that name now. See `tls_client_certificates.js`'s
  // `currentHolderOf()`.
  if (spec.holderSubject) {
    record.holderSubject = String(spec.holderSubject);
  }
  // HOW IT WAS ISSUED, where the caller said anything beyond the defaults
  // (2026-09-26, #230): the profile, the keyUsage and the extensions — a
  // subjectAltName above all. `recertifyUseCase()` renews from the record,
  // and a renewal that did not carry these re-minted a TLS listener's or the
  // OpenID4VP Verifier's certificate WITHOUT its names: a certificate over
  // the same key that no client could match to a host any more.
  if (spec.profile || spec.keyUsage || spec.extensions) {
    record.issuedAs = {
      profile: spec.profile ? String(spec.profile) : '',
      keyUsage: spec.keyUsage ? spec.keyUsage.slice() : null,
      extensions: spec.extensions ? JSON.parse(JSON.stringify(
        spec.extensions)) : null
    };
  }
  if (spec.pinned && spec.privateKeyPem) {
    // THE ONE RECORD SHAPE WITH A PRIVATE KEY IN IT — see the header. An
    // operator pasted this pair in and this service has nowhere else to keep
    // it; `describeCertificate()` drops it on the way out.
    record.privateKeyPem = spec.privateKeyPem;
    record.publicKeyPem = spec.publicKeyPem;
  }
  const fresh = rawRowFor(id) || {};
  // -------------------------------------------------------------------------
  // **THE AUTHORITY THIS WAS SIGNED BY MAY HAVE BEEN REPLACED WHILE IT WAS
  // BEING SIGNED (2026-09-15, #46).** The signature above is an await, and a
  // branch rebuild (`buildScopeNow()`) or a reissue of this use case can land
  // inside it — the realm watcher certifies a new realm's keys in the same
  // moment `POST /admin-api/pki/build` rebuilds that realm's branch, and the
  // rebuild's re-certification only re-mints what was recorded BEFORE it ran.
  // Recording this one would publish a certificate from a superseded Issuing
  // CA, with the superseded Intermediate as its chain, for as long as nothing
  // certifies that slot again.
  //
  // So it is signed again by the authority the row holds NOW. Nothing is
  // superseded: the certificate just made was never recorded, returned or
  // published, so no relying party can hold it. Bounded, because a branch
  // rebuilt faster than a certificate can be signed is a loop rather than a
  // race. No await between this read and `saveRow()`, so what is checked is
  // what is written over.
  // -------------------------------------------------------------------------
  const caNow = fresh.issuing ? fresh.issuing[uc.id] : null;
  const intermediateNow = fresh.intermediate || null;
  const moved = !!caNow &&
    (caNow.certificatePem !== ca.certificatePem ||
     (intermediateNow ? intermediateNow.certificatePem : '') !==
     (row.intermediate ? row.intermediate.certificatePem : ''));
  if (moved) {
    const attempts = Number(spec.issuerMovedAttempts) || 0;
    if (attempts < CERTIFY_ISSUER_MOVED_RETRIES) {
      log.info('pki: the ' + uc.label + ' Issuing CA of "' +
               (id || 'default') + '" was replaced while the certificate ' +
               'for "' + spec.slot + '" was being signed; signing it again ' +
               'from the authority the branch holds now.');
      log.debug('Leaving certify(). Signing again from the current CA.');
      return certify(scopeId, useCaseId,
                     Object.assign({}, spec,
                                   { issuerMovedAttempts: attempts + 1 }));
    }
    log.warn(errorCodes.tag('STS-PKI-0186') + 'pki: the ' + uc.label + ' ' +
             'Issuing CA of "' + (id || 'default') + '" was replaced ' +
             (attempts + 1) + ' times while the certificate for "' +
             spec.slot + '" was being signed, so it was not recorded.');
    log.debug('Leaving certify(). The authority kept moving.');
    return errorCodes.mark({ ok: false,
             errors: ['The ' + uc.label + ' Issuing CA was replaced while ' +
                      'the certificate was being signed, ' + (attempts + 1) +
                      ' times, so none was recorded. Try again.'] },
                           'STS-PKI-0186');
  }
  fresh.certs = Object.assign({}, fresh.certs || {});
  // THE KEY IT IS OVER, BY KID (#42): the plain slot names the current key,
  // and `spec.generationSlot` puts a standby key's certificate in a slot of
  // its own (`slotKey()`'s header).
  if (spec.kid) {
    record.kid = String(spec.kid);
  }
  const slotName = slotKey(uc.id, record.slot,
                           spec.generationSlot ? spec.kid : '');
  // THE CERTIFICATE THIS REPLACES STAYS KNOWN (2026-09-23, #185). A slot is
  // certified again whenever the key set changes — every rotation, promotion
  // and retirement re-certifies the set — and this issues a new certificate
  // for the SAME key each time. The record it replaced was dropped, so its
  // serial left the issued register: a relying party holding the certificate
  // the realm had published seconds before got `unknown` from its OCSP
  // responder, which a hard-fail client refuses (`sts_pki_distribution_points`,
  // with the hourly signing.retire in the middle). Its serial is kept in
  // `issuedKeyPairs`, as a cluster merge keeps one it displaced
  // (`pki_merge.js`), so the responder answers `good` until it expires — it
  // is a valid certificate for a key this service still holds — or `revoked`
  // once a retirement or an operator revokes it.
  const displaced = fresh.certs[slotName];
  if (displaced && displaced.serialHex &&
      pkiMerge.normalSerial(displaced.serialHex) !==
        pkiMerge.normalSerial(record.serialHex)) {
    const register = (fresh.issuedKeyPairs || []).slice();
    const wanted = pkiMerge.normalSerial(displaced.serialHex);
    if (!register.some(function (one) {
      return one && pkiMerge.normalSerial(one.serialHex) === wanted;
    })) {
      register.push(pkiMerge.displacedRecord(uc.id + ':' + record.slot,
                                             displaced));
      fresh.issuedKeyPairs = register;
    }
  }
  fresh.certs[slotName] = record;
  saveRow(id, fresh);
  log.debug('Leaving certify(). ' + record.subject);
  return { ok: true, certificate: describeCertificate(record), record: record };
}

// A slot the operator supplied key material for, or null. Read SYNCHRONOUSLY
// by `helpers.js` while it builds a key set, which is why it is a plain map
// lookup and issues nothing.
function pinnedKeyFor(scopeId, useCaseId, slot) {
  log.debug("Entering pinnedKeyFor().");
  const held = certificateFor(scopeId, useCaseId, slot);
  if (!held || !held.pinned || !held.privateKeyPem) {
    log.debug("Leaving pinnedKeyFor().");
    return null;
  }
  log.debug("Leaving pinnedKeyFor().");
  return { privateKeyPem: held.privateKeyPem,
           publicKeyPem: held.publicKeyPem,
           certificatePem: held.certificatePem,
           chainPem: (held.chainPem || []).slice() };
}

// The certificate a caller should PUBLISH for a slot, and the chain under it.
// Synchronous, for `pinnedKeyFor()`'s reason.
function publishedCertificateFor(scopeId, useCaseId, slot, kid) {
  log.debug("Entering publishedCertificateFor().");
  const held = certificateFor(scopeId, useCaseId, slot, kid);
  if (!held) {
    log.debug("Leaving publishedCertificateFor().");
    return null;
  }
  log.debug("Leaving publishedCertificateFor().");
  return { certificatePem: held.certificatePem,
           chainPem: (held.chainPem || []).slice() };
}

function forgetCertificate(scopeId, useCaseId, slot) {
  log.debug('Entering forgetCertificate().');
  const id = String(scopeId);
  const row = rawRowFor(id);
  const key = slotKey(useCaseId, slot);
  if (!row || !row.certs || !row.certs[key]) {
    log.debug('Leaving forgetCertificate(). Nothing there.');
    return errorCodes.mark({ ok: false,
             errors: ['There is no ' + useCaseId + ' certificate for "' +
                      slot + '" in that scope.'] }, 'STS-PKI-0025');
  }
  const was = row.certs[key];
  delete row.certs[key];
  saveRow(id, row);
  log.debug('Leaving forgetCertificate(). Removed.');
  return { ok: true, pinned: !!was.pinned };
}

// ===========================================================================
// A TLS SERVER KEY PAIR FOR SOMETHING THIS SERVICE DOES NOT RUN (2026-09-13):
// `issueTlsServerKeyPair()`.
//
// **THE ONE DOOR IN THIS MODULE THAT HANDS A SERVER PRIVATE KEY OUTSIDE THIS
// PROCESS.** Every other `serverAuth` certificate here is either the
// listener's own, certified over a key that never leaves `tls/tls_server.js`,
// or an enrolled one (`issueEnrolled()`) over a key this module is handed
// public — EST's `/serverkeygen` generates its pair in
// `common/cert_enrollment.ts`, not here. This one is for
// a remote XACML PEP's HTTPS listener (`pep-tls`, and `xacml/xacml_pep_tls.ts`
// is the caller): the key pair is GENERATED here, certified from the use
// case's Issuing CA, handed back ONCE, and forgotten — `certify()` records the
// certificate under a slot and no private key, exactly as it does for a key
// this service holds.
//
// **WHY `certify()` AND NOT `issueUnder()`.** `issueUnder()` records nothing,
// which is right for an X509-SVID re-minted every half-lifetime and wrong
// here: a listener certificate lives for months, names this authority's CRL
// and OCSP responder in `revocationExtensionsFor()`, and a responder with no
// record of its serial answers `unknown` about a certificate that sends a
// client there to ask. A slot per PEP is also what makes a reissue SUPERSEDE
// the certificate it replaces rather than leaving two valid ones.
//
// **THE KEY ALGORITHMS ARE THE ONES A TLS STACK SERVES**, which is a narrower
// list than `keyAlgorithms()`: node, and every client worth talking to, will
// negotiate an RSA or a NIST-curve ECDSA server certificate, and the Edwards
// and post-quantum keys this module can generate are either TLS 1.3-only in
// practice or not in TLS at all. A listener that starts and then fails every
// handshake is the worst version of this feature.
//
// **A CERTIFICATE WITH NO subjectAltName IS REFUSED** rather than issued with
// the CN alone: RFC 6125 section 6.4.4 lets a client fall back to the CN and
// node's `checkServerIdentity()` no longer does, so a SAN-less server
// certificate is one this service would issue and nothing would accept.
// ===========================================================================
const TLS_SERVER_KEY_ALGS = ['ec-p256', 'ec-p384', 'ec-p521', 'rsa-2048',
                             'rsa-3072', 'rsa-4096'];
const DEFAULT_TLS_SERVER_KEY_ALG = 'ec-p256';

// A DNS name a certificate may carry: labels of letters, digits and hyphens,
// with a single leading `*.` allowed (RFC 6125 section 6.4.3). Checked here
// rather than left to the encoder, which writes any string it is handed into an
// IA5String and produces a certificate whose name matches nothing.
function tlsDnsNameProblem(name) {
  log.debug("Entering tlsDnsNameProblem().");
  const text = String(name || '');
  const bare = text.indexOf('*.') === 0 ? text.slice(2) : text;
  const ok = bare.length > 0 && text.length <= 253 &&
    bare.split('.').every(function (label) {
      return /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label);
    });
  log.debug("Leaving tlsDnsNameProblem().");
  return ok ? '' : '"' + text + '" is not a DNS name a certificate can ' +
    'carry: labels of letters, digits and hyphens separated by dots, with ' +
    'an optional leading "*.".';
}

async function issueTlsServerKeyPair(scopeId, useCaseId, spec) {
  log.debug('Entering issueTlsServerKeyPair(). scope=' + scopeId + ' use=' +
            useCaseId);
  const net = require('net');
  const uc = useCase(useCaseId);
  if (!uc) {
    log.debug('Leaving issueTlsServerKeyPair(). Unknown use case.');
    return errorCodes.mark({ ok: false,
             errors: ['"' + useCaseId + '" is not a use case this service ' +
                      'issues for. They are ' + USE_CASE_IDS.join(', ') +
                      '.'] }, 'STS-PKI-0022');
  }
  const id = uc.scope === 'process' ? PROCESS_SCOPE : realmIdOf(scopeId);
  const s = spec || {};
  const slot = String(s.slot || '').trim();
  if (!slot) {
    log.debug('Leaving issueTlsServerKeyPair(). No slot.');
    return errorCodes.mark({ ok: false,
             errors: ['A listener certificate is issued TO something. Name ' +
                      'what it is for.'] }, 'STS-PKI-0165');
  }
  const unique = function (list) {
    log.debug("Entering unique().");
    const seen = Object.create(null);
    log.debug("Leaving unique().");
    return (list || []).map(function (one) {
      return String(one || '').trim();
    }).filter(function (one) {
      if (!one || seen[one.toLowerCase()]) {
        return false;
      }
      seen[one.toLowerCase()] = true;
      return true;
    });
  };
  const dnsNames = unique(s.dnsNames);
  const ipAddresses = unique(s.ipAddresses);
  const nameProblems = dnsNames.map(tlsDnsNameProblem).filter(Boolean)
    .concat(ipAddresses.filter(function (one) {
      return !net.isIP(one);
    }).map(function (one) {
      return '"' + one + '" is not an IPv4 or IPv6 address.';
    }));
  if (nameProblems.length) {
    log.debug('Leaving issueTlsServerKeyPair(). A name was refused.');
    return errorCodes.mark({ ok: false, errors: nameProblems },
                           'STS-PKI-0166');
  }
  if (!dnsNames.length && !ipAddresses.length) {
    log.debug('Leaving issueTlsServerKeyPair(). No subjectAltName.');
    return errorCodes.mark({ ok: false,
             errors: ['A server certificate needs at least one DNS name or ' +
                      'IP address in its subjectAltName. A client checks ' +
                      'the host it dialled against those and no longer ' +
                      'against the common name, so a certificate without ' +
                      'one would be issued and accepted by nothing.'] },
                           'STS-PKI-0166');
  }
  const keyAlgId = String(s.keyAlg || DEFAULT_TLS_SERVER_KEY_ALG);
  const keyDesc = keyMaterial.keyAlg(keyAlgId);
  if (!keyDesc || TLS_SERVER_KEY_ALGS.indexOf(keyAlgId) < 0) {
    log.debug('Leaving issueTlsServerKeyPair(). Key algorithm refused.');
    return errorCodes.mark({ ok: false,
             errors: ['"' + keyAlgId + '" is not a key algorithm a TLS ' +
                      'listener certificate is issued with here. It may be ' +
                      TLS_SERVER_KEY_ALGS.join(', ') + '.'] }, 'STS-PKI-0167');
  }

  // THE BRANCH, AND THE ISSUING CA IN IT. `ensureScope()` builds a branch that
  // is not there and tops up one built before this use case existed, so an
  // operator never meets "that realm has no Remote PEP listeners CA" on a
  // realm whose other authorities are working.
  const branch = await ensureScope(id);
  if (!branch.ok) {
    log.debug('Leaving issueTlsServerKeyPair(). No branch.');
    return branch;
  }

  const pair = await keyMaterial.generateKeyPair(keyAlgId);
  const was = certificateFor(id, uc.id, slot);
  const names = dnsNames.map(function (one) {
    return { kind: 'dns', value: one };
  }).concat(ipAddresses.map(function (one) {
    return { kind: 'ip', value: one };
  }));
  const made = await certify(id, uc.id, {
    slot: slot,
    label: String(s.label || slot),
    commonName: String(s.commonName || dnsNames[0] || slot),
    keyAlg: keyAlgId,
    publicKeyPem: pair.publicPem,
    profile: 'tls-server',
    days: s.days,
    // keyEncipherment only where the key can do it: an RSA key transports a
    // TLS 1.2 premaster secret, an EC key never does, and a KeyUsage asserting
    // a use the key cannot perform is one a strict client refuses.
    keyUsage: keyDesc.kind === 'rsa' ? ['digitalSignature', 'keyEncipherment']
                                     : ['digitalSignature'],
    extensions: {
      extKeyUsage: { present: true, critical: false, usages: ['serverAuth'] },
      subjectAltName: { present: true, critical: false, names: names }
    }
  });
  if (!made.ok) {
    log.debug('Leaving issueTlsServerKeyPair(). certify() refused.');
    return made;
  }
  // THE CERTIFICATE THIS REPLACES IS SUPERSEDED — `supersede()`'s rule. A
  // listener whose certificate was reissued because its key was lost must not
  // leave the old one valid for the rest of its year.
  if (was && normalSerialsDiffer(was.serialHex, made.record.serialHex)) {
    supersede(id, uc.id, was, 'replaced by a new ' + uc.label +
              ' certificate for "' + slot + '"');
  }
  const root = serviceRoot();
  log.info('pki: a ' + keyDesc.label + ' ' + uc.label + ' certificate was ' +
           'issued for "' + slot + '" in "' + (id || 'default') + '", naming ' +
           names.map(function (one) { return one.value; }).join(', ') +
           '; expires ' + made.record.notAfter + '. The private key was ' +
           'handed to the caller and is not kept here.');
  log.debug('Leaving issueTlsServerKeyPair().');
  return { ok: true,
           issued: Object.assign(describeCertificate(made.record), {
             scope: id,
             dnsNames: dnsNames,
             ipAddresses: ipAddresses,
             privateKeyPem: pair.privatePem,
             // THE ANCHOR A CLIENT OF THIS LISTENER INSTALLS: the service
             // Root, which the chain above deliberately leaves out.
             anchorPem: root ? root.certificatePem : '',
             replacedSerialHex: was ? was.serialHex : null
           }) };
}

// ===========================================================================
// THE OPENID4VP VERIFIER'S CERTIFICATE (2026-09-26, #230): what the
// `x509_san_dns` and `x509_hash` Client Identifier Prefixes (OpenID4VP 1.0
// section 5.9.3) sign a Request Object under.
//
// Both prefixes put a certificate chain in the Request Object's `x5c` header
// and have the wallet validate it to an anchor it trusts; `x509_san_dns`
// then requires the Client Identifier to be a dNSName in the leaf's
// subjectAltName, `x509_hash` requires it to be the SHA-256 of the leaf's
// DER. So the Verifier needs a certificate of its own, and this is where it
// comes from — the one funnel every leaf here goes through, per the root
// `CLAUDE.md` and rule 3w.
//
// **IT IS OVER A KEY THE REALM ALREADY HOLDS, NOT A NEW ONE.** The subject
// key is the realm's own JOSE signing key for the algorithm the Verifier
// signs with (`oid4vp.x509SigningAlgorithm`, ES256 by default) — the key
// `helpers.signJwt()` signs with and that its `jose:<alg>` slot already
// certifies. A key of its own would be a second private key per realm to
// seal, rotate and purge, which is what this module's placement argument
// refuses; and it would buy nothing a wallet can see, because the wallet
// trusts the CERTIFICATE (its chain and its name), never the key alone.
// When the realm's key rotates, the fingerprint no longer matches and the
// next request certifies the new key — the old certificate is superseded.
//
// **UNDER THE REALM'S JOSE ISSUING CA, AND NOT A USE CASE OF ITS OWN.** The
// JOSE authority is the one that certifies what this realm signs JWTs with,
// and a Request Object is a JWT this realm signs. A tenth Issuing CA would
// give a wallet a narrower anchor to pin — but wallets configure x509
// Verifiers by their anchor AND the Client Identifier, and a new use case
// makes every stored branch incomplete (the top-up `ensureScope()` exists
// for), for a boundary no wallet asks for.
//
// **THE PROFILE IS `digital-signature` NARROWED TO `digitalSignature`**:
// basicConstraints cA false, keyUsage digitalSignature alone (not
// nonRepudiation: a Request Object is a request, not a commitment to
// content), NO extKeyUsage, and a subjectAltName dNSName. Not `tls-server`:
// its serverAuth EKU would make this a certificate a TLS client accepts for
// the name, and the key behind it signs tokens, not handshakes. No EKU
// because OpenID4VP defines none — ISO 18013-5's mdoc reader-authentication
// EKU is for a different protocol, and a wallet that does not know an EKU
// may refuse the certificate for carrying one.
//
// **ONE SLOT PER DNS NAME** (`oid4vp-verifier:<name>`, and a nameless
// `oid4vp-verifier` for `x509_hash` where no name is known), bounded at
// MAX_VERIFIER_CERTIFICATES a realm: in development the name is the host a
// request arrived at, and a service reached as `localhost` and as `sts`
// would otherwise reissue one slot on every alternate request, superseding
// the certificate a wallet had just been handed. WHICH name may be
// certified is the Verifier's question (`oid4vc/vc_verifier.ts`), because
// only it knows whether the name came from configuration or a request.
// ===========================================================================
const VERIFIER_SLOT = 'oid4vp-verifier';
const MAX_VERIFIER_CERTIFICATES = 16;
// A certificate this close to its end is renewed before it is used, so a
// wallet is never handed one that expires while the request is in flight.
const VERIFIER_RENEW_BEFORE_MS = 86400000;

function verifierSlotFor(dnsName) {
  log.debug("Entering verifierSlotFor().");
  const name = String(dnsName || '').toLowerCase();
  log.debug("Leaving verifierSlotFor().");
  return name ? VERIFIER_SLOT + ':' + name : VERIFIER_SLOT;
}

// The Verifier's certificate for one DNS name ('' for the nameless one) in a
// realm, as { certificatePem, chainPem, anchorPem, dnsName, notAfter,
// subjectKeyFingerprint } — or null where there is none, it is over another
// key than `publicKeyPem` (when given), or it has expired. Synchronous: the
// Verifier builds its Request Object synchronously and asks this after
// `certifyVerifierKey()` has made sure.
function verifierCertificateFor(realmId, dnsName, publicKeyPem) {
  log.debug("Entering verifierCertificateFor().");
  const id = realmIdOf(realmId);
  const held = certificateFor(id, 'jose', verifierSlotFor(dnsName));
  if (!held) {
    log.debug("Leaving verifierCertificateFor(). None.");
    return null;
  }
  if (publicKeyPem && held.subjectKeyFingerprint !==
      thumbprintOf(publicKeyPem)) {
    log.debug("Leaving verifierCertificateFor(). Over another key.");
    return null;
  }
  if (new Date(held.notAfter).getTime() <= Date.now()) {
    log.debug("Leaving verifierCertificateFor(). Expired.");
    return null;
  }
  const root = serviceRoot();
  log.debug("Leaving verifierCertificateFor().");
  return {
    certificatePem: held.certificatePem,
    chainPem: (held.chainPem || []).slice(),
    anchorPem: root ? root.certificatePem : '',
    dnsName: String(dnsName || '').toLowerCase(),
    serialHex: held.serialHex,
    notBefore: held.notBefore,
    notAfter: held.notAfter,
    subject: held.subject,
    subjectKeyFingerprint: held.subjectKeyFingerprint
  };
}

// Certify the Verifier's signing key for a DNS name ('' for none), or answer
// the certificate already there when it is over that key and not about to
// expire. `spec`: { dnsName, publicKeyPem, alg, keyAlg }. Answers
// { ok: true, certificate, issued } or { ok: false, errors } with a code.
async function certifyVerifierKey(realmId, spec) {
  log.debug("Entering certifyVerifierKey().");
  const s = spec || {};
  const id = realmIdOf(realmId);
  const dnsName = String(s.dnsName || '').trim().toLowerCase();
  // A name, never a pattern: a Client Identifier names one host, and a
  // wildcard certificate would let the request name any host under it.
  const nameProblem = !dnsName ? '' :
    (dnsName.indexOf('*') >= 0
      ? '"' + dnsName + '" is a wildcard; the Verifier\'s certificate ' +
        'names one host.'
      : tlsDnsNameProblem(dnsName));
  if (nameProblem) {
    log.debug("Leaving certifyVerifierKey(). The name was refused.");
    return errorCodes.mark({ ok: false, errors: [nameProblem] },
                           'STS-PKI-0204');
  }
  if (!s.publicKeyPem) {
    log.debug("Leaving certifyVerifierKey(). No key.");
    return errorCodes.mark({ ok: false,
             errors: ['The Verifier\'s certificate is over its signing ' +
                      'key, and none was given.'] }, 'STS-PKI-0204');
  }
  const slot = verifierSlotFor(dnsName);
  const was = certificateFor(id, 'jose', slot);
  const wanted = thumbprintOf(s.publicKeyPem);
  if (was && was.subjectKeyFingerprint === wanted &&
      new Date(was.notAfter).getTime() - Date.now() >
        VERIFIER_RENEW_BEFORE_MS) {
    log.debug("Leaving certifyVerifierKey(). Already certified.");
    return { ok: true, issued: false,
             certificate: verifierCertificateFor(id, dnsName) };
  }
  if (!was) {
    const held = certificatesFor(id, 'jose').filter(function (one) {
      return one && (one.slot === VERIFIER_SLOT ||
                     String(one.slot).indexOf(VERIFIER_SLOT + ':') === 0);
    }).length;
    if (held >= MAX_VERIFIER_CERTIFICATES) {
      log.warn(errorCodes.tag('STS-PKI-0205') + 'pki: "' + (id || 'default') +
               '" already holds ' + held + ' OpenID4VP Verifier ' +
               'certificates, so none was issued for "' + dnsName + '". ' +
               'Set oid4vp.x509DnsName, or pin global.publicBaseUrl, so ' +
               'the Verifier stops certifying every host it is reached by.');
      log.debug("Leaving certifyVerifierKey(). Too many.");
      return errorCodes.mark({ ok: false,
               errors: ['This realm already holds ' + held + ' OpenID4VP ' +
                        'Verifier certificates, the most it keeps.'] },
                             'STS-PKI-0205');
    }
  }
  const branch = await ensureScope(id);
  if (!branch.ok) {
    log.debug("Leaving certifyVerifierKey(). No branch.");
    return branch;
  }
  const made = await certify(id, 'jose', {
    slot: slot,
    label: 'OpenID4VP Verifier' + (dnsName ? ' (' + dnsName + ')' : ''),
    commonName: dnsName || 'OpenID4VP Verifier',
    alg: String(s.alg || ''),
    keyAlg: String(s.keyAlg || ''),
    publicKeyPem: s.publicKeyPem,
    profile: 'digital-signature',
    keyUsage: ['digitalSignature'],
    extensions: dnsName ? {
      subjectAltName: { present: true, critical: false,
                        names: [{ kind: 'dns', value: dnsName }] }
    } : {}
  });
  if (!made.ok) {
    log.debug("Leaving certifyVerifierKey(). certify() refused.");
    return made;
  }
  if (was && normalSerialsDiffer(was.serialHex, made.record.serialHex)) {
    supersede(id, 'jose', was, 'replaced by a new OpenID4VP Verifier ' +
              'certificate for "' + (dnsName || '(no DNS name)') + '"');
  }
  log.info('pki: the OpenID4VP Verifier of "' + (id || 'default') + '" was ' +
           'certified' + (dnsName ? ' for ' + dnsName : ' with no DNS name') +
           ', ' + String(s.alg || '') + ', serial ' + made.record.serialHex +
           ', until ' + made.record.notAfter + '.');
  log.debug("Leaving certifyVerifierKey(). Issued.");
  return { ok: true, issued: true,
           certificate: verifierCertificateFor(id, dnsName) };
}

// ===========================================================================
// ISSUING SOMETHING THIS MODULE DOES NOT KEEP (2026-09-11): `issueUnder()`.
//
// **EVERY OTHER DOOR IN HERE RECORDS WHAT IT ISSUED, AND THAT IS EXACTLY WHY
// THIS ONE EXISTS.** `certify()` writes a row into the certificate register
// under a SLOT, which is right for the handful of long-lived keys this service
// holds — one per algorithm per use case, reissued when somebody presses a
// button. It is wrong for an X509-SVID: a SPIFFE agent holding `FetchX509SVID`
// open re-mints every half-lifetime, so one workload left running overnight
// would put several hundred rows in a sealed keystore row that exists to hold
// certificate AUTHORITIES. The register would stop being a register.
//
// So this signs and hands back, and the caller owns what comes out. What it
// still does is everything that must not be decided twice:
//
//   * **the signature algorithm is the ISSUER'S**, never the subject's. A
//     caller naming one is refused rather than obliged — `common/vendored/
//     x509.js`'s header spends a paragraph on what a certificate whose
//     declared algorithm and actual signature disagree costs to diagnose.
//   * **the validity is clamped to the Issuing CA's**, for `certify()`'s
//     reason: a leaf outliving its issuer is an identity that works until it
//     suddenly does not, with nothing in the failure naming the CA.
//   * **the chain travels with it**, leaf-first and WITHOUT the Root, which is
//     what RFC 5246 section 7.4.2 asks of a certificate_list and what the
//     Workload API's `x509_svid` field is. The Root is the trust anchor: it is
//     published in the bundle and relying on it having been sent is the
//     mistake.
//   * **a stale branch is repaired before anything is signed**, through the
//     same `scopeChainsToRoot()` check `certify()` makes and for the identical
//     reason — a leaf issued from a branch the current Root does not sign
//     looks perfect and builds no path.
//
// **AND IT CARRIES NO REVOCATION POINTERS, WHICH IS A DECISION AND NOT AN
// OMISSION.** Every certificate `certify()` and `issueCaTier()` produce names
// a CRL and an OCSP responder, because this service holds those certificates
// and can put one of their serials on a list. It does not hold these. A
// `cRLDistributionPoints` on an SVID would point a verifier at a list that
// structurally cannot ever contain it — the worst kind of pointer, because it
// resolves, parses, and answers "not revoked" about everything forever. SPIFFE
// answers the same question with SHORT LIFETIMES instead, which is the design
// rationale in its own specification, and `spiffe.svidTtl` is the knob.
// ===========================================================================
async function issueUnder(scopeId, useCaseId, spec) {
  log.debug('Entering issueUnder(). scope=' + scopeId + ' use=' + useCaseId);
  const id = String(scopeId);
  const uc = useCase(useCaseId);
  if (!uc) {
    log.debug('Leaving issueUnder(). Unknown use case.');
    return errorCodes.mark({ ok: false,
             errors: ['"' + useCaseId + '" is not a use case this service ' +
                      'issues for. They are ' + USE_CASE_IDS.join(', ') +
                      '.'] }, 'STS-PKI-0022');
  }
  if (!spec || !spec.publicKeyPem) {
    log.debug('Leaving issueUnder(). No subject public key.');
    return errorCodes.mark({ ok: false,
             errors: ['A certificate is issued OVER a public key. None was ' +
                      'given.'] }, 'STS-PKI-0026');
  }
  // The same repair `certify()` makes, for the same reason. See its header.
  if (!scopeChainsToRoot(id)) {
    log.warn('pki: the "' + (id || 'default') + '" branch does not chain to ' +
             'this service\'s Root CA, so it is being rebuilt before ' +
             'anything is issued from it.');
    const rebuilt = await repairBranch(id);
    if (!rebuilt.ok) {
      log.debug('Leaving issueUnder(). The stale branch could not be rebuilt.');
      return errorCodes.mark({ ok: false, errors: rebuilt.errors },
                             'STS-PKI-0023');
    }
  }
  const row = rawRowFor(id);
  const ca = row && row.issuing ? row.issuing[uc.id] : null;
  if (!ca || !row.intermediate) {
    log.debug('Leaving issueUnder(). No Issuing CA.');
    return errorCodes.mark({ ok: false,
             errors: ['The "' + (id || 'default') + '" scope has no ' +
                      uc.label + ' Issuing CA. Build the hierarchy on ' +
                      '/admin/pki first.'] }, 'STS-PKI-0009');
  }
  const notBefore = certificateInstant(spec.notBefore);
  let notAfter = certificateInstant(spec.notAfter);
  const caEnds = new Date(ca.notAfter).getTime();
  if (notAfter.getTime() > caEnds) {
    log.debug('issueUnder(): the lifetime asked for outlives the ' + uc.label +
              ' Issuing CA; shortening it to that CA\'s own notAfter.');
    notAfter = certificateInstant(caEnds);
  }
  let issued;
  try {
    issued = await x509.issueCertificate(Object.assign({
      // A STRING OR A LIST, both passed straight through. `spiffe.svidSubject`
      // is the string `C=US,O=SPIRE` and the vendored encoder parses one; the
      // realm's own tiers build a list. One parameter rather than two shapes
      // to reconcile here.
      subject: spec.subject,
      subjectPublicKey: spec.publicKeyPem,
      // The algorithm this CA's own key can produce — see `certify()`'s note
      // on why that is not `ca.signatureAlg`.
      signatureAlg: signatureForIssuer(ca, ca.signatureAlg, ca.keyAlg),
      profile: spec.profile || 'digital-signature',
      notBefore: notBefore.toISOString(),
      notAfter: notAfter.toISOString(),
      issuer: { certificatePem: ca.certificatePem,
                privateKeyPem: ca.privateKeyPem, keyAlg: ca.keyAlg },
      extensions: spec.extensions || {}
    }, alternativeSignatureBy(ca)));
  } catch (e) {
    log.error(errorCodes.tag('STS-PKI-0024') + 'pki: a ' + uc.label + ' ' +
        'certificate could not be issued: ' +
              e.message);
    log.debug('Leaving issueUnder(). The encoder refused.');
    return errorCodes.mark({ ok: false,
             errors: ['That certificate could not be issued: ' + e.message] },
                           'STS-PKI-0024');
  }
  const chainPem = [ca.certificatePem, row.intermediate.certificatePem];
  log.debug('Leaving issueUnder(). serial=' + issued.serialHex);
  return {
    ok: true,
    certificatePem: issued.pem,
    certificateDer: Buffer.from(issued.der),
    subject: issued.subject,
    serialHex: issued.serialHex,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    signatureAlg: ca.signatureAlg,
    // Leaf-first, Root excluded. See the header.
    chainPem: [issued.pem].concat(chainPem),
    issuerChainPem: chainPem,
    issuerChainDer: chainPem.map(pemToDer)
  };
}

// ===========================================================================
// ISSUE ONE ENROLLED CERTIFICATE (2026-09-13) — ACME, EST AND SCEP SIGN HERE.
//
// `issueUnder()` above is the right shape — a certificate over a PRESENTED
// public key, from one use case's Issuing CA — and the wrong bookkeeping: it
// records nothing, because an SVID answers revocation with a short lifetime
// instead. An enrolled certificate is the opposite case. It is handed to a
// device or a person for a year, ACME can revoke it, and an operator can revoke
// it from the console, so `/pki/ocsp` must be able to answer `good` about it
// and the CRL must be able to list it. So this door is `issueUnder()` plus
// three things:
//
//   * the profile's keyUsage, extKeyUsage and basicConstraints come from
//     `x509.defaultExtensions(profile)`, which is exactly what /admin/pki's
//     Apply the profile writes into the form — one table for both doors;
//   * CDP and AIA name the family CA, as every other leaf here does;
//   * the serial is RECORDED in `issuedKeyPairs` under the family's use case,
//     the list `pki_revocation.issuedList()` reads, so OCSP knows it.
//
// **WHAT GOES INTO THE CERTIFICATE IS DECIDED BY THE CALLER AND NOT HERE.**
// `common/cert_enrollment.ts` builds the subject and the subjectAltName from
// the directory entry and refuses a name the entry does not own; this module
// signs what it is handed, over the key it is handed, and never reads a CSR.
// That keeps the certificate authority ignorant of who a person is, which is
// the split `issueSigningKeyPair()` already keeps with SUBJECT_KINDS.
// ===========================================================================
async function issueEnrolled(scopeId, useCaseId, spec) {
  log.debug('Entering issueEnrolled(). scope=' + scopeId + ' use=' + useCaseId);
  const id = realmIdOf(scopeId);
  const uc = useCase(useCaseId);
  if (!uc || uc.scope !== 'realm') {
    log.debug('Leaving issueEnrolled(). Not a realm use case.');
    return errorCodes.mark({ ok: false,
             errors: ['"' + useCaseId + '" is not a realm use case this ' +
                      'service issues enrolled certificates from.'] },
                           'STS-PKI-0022');
  }
  const asked = spec || {};
  if (!asked.publicKeyPem || !asked.profile) {
    log.debug('Leaving issueEnrolled(). No public key or profile.');
    return errorCodes.mark({ ok: false,
             errors: ['An enrolled certificate is issued over a public key ' +
                      'and a profile, and one of them was not given.'] },
                           'STS-PKI-0026');
  }
  if (!hasRoot()) {
    log.debug('Leaving issueEnrolled(). No Root.');
    return errorCodes.mark({ ok: false,
             errors: ['This service has no Root CA, so nothing can be ' +
                      'issued. Build the hierarchy on /admin/pki first.'] },
                           'STS-PKI-0009');
  }
  // A branch built before this use case existed has every Issuing CA but this
  // one. `ensureScope()` tops it up under the existing Intermediate rather
  // than rebuilding — the realm's other certificates are untouched.
  let row = rawRowFor(id);
  if (!row || !row.intermediate || !row.issuing || !row.issuing[uc.id]) {
    const ensured = await ensureScope(id);
    if (!ensured || !ensured.ok) {
      log.debug('Leaving issueEnrolled(). The branch could not be completed.');
      return errorCodes.mark({ ok: false,
               errors: (ensured && ensured.errors) ||
                       ['The ' + uc.label + ' Issuing CA could not be made.'] },
                             'STS-PKI-0023');
    }
    row = rawRowFor(id);
  }
  const issued = await issueUnder(id, uc.id, {
    subject: asked.subject,
    publicKeyPem: asked.publicKeyPem,
    profile: asked.profile,
    notAfter: Date.now() + Math.max(1, Number(asked.days)) * 86400000,
    extensions: Object.assign({}, x509.defaultExtensions(asked.profile), {
      subjectKeyIdentifier: { present: true, critical: false },
      authorityKeyIdentifier: { present: true, critical: false,
                                includeIssuerAndSerial: false },
      subjectAltName: { present: !!(asked.subjectAltName || []).length,
                        critical: false,
                        names: (asked.subjectAltName || []).slice() }
    }, revocationExtensionsFor(id, uc.id))
  });
  if (!issued.ok) {
    log.debug('Leaving issueEnrolled(). issueUnder refused.');
    return issued;
  }
  // Recorded where OCSP and the CRL look. `issueUnder()` may have REBUILT a
  // stale branch before issuing, so the row is read again rather than reused.
  const current = rawRowFor(id) || row;
  const nowMs = Date.now();
  current.issuedKeyPairs = (current.issuedKeyPairs || []).filter(
    function (one) {
      return one && new Date(one.notAfter).getTime() > nowMs;
    }).concat([{
      serialHex: issued.serialHex,
      subject: issued.subject,
      notAfter: issued.notAfter,
      identifier: String(asked.identifier || ''),
      subjectKind: String(asked.subjectKind || ''),
      // The holder's subject, for `certify()`'s reason above.
      holderSubject: String(asked.holderSubject || ''),
      purpose: 'enrolled:' + String(asked.profile),
      useCase: uc.id,
      issuedAt: new Date(nowMs).toISOString()
    }]);
  current.issuedCount = (current.issuedCount || 0) + 1;
  saveRow(id, current);
  log.info('pki: a ' + asked.profile + ' certificate was issued from the "' +
           (id || 'default') + '" realm\'s ' + uc.label + ' Issuing CA for "' +
           String(asked.identifier || '') + '". serial=' + issued.serialHex +
           ', expires ' + issued.notAfter + '.');
  log.debug('Leaving issueEnrolled(). serial=' + issued.serialHex);
  return issued;
}

// ---------------------------------------------------------------------------
// WHAT ONE ISSUING CA IS, WITHOUT ITS KEY. For a module that signs through
// `issueUnder()` and has to REPORT what signed: the authority's own
// certificate, the chain above it, and the Root it ends at.
//
// **THE ROOT IS SEPARATE FROM THE CHAIN AND MUST STAY SO.** A caller that
// concatenated them would publish the anchor as though it travelled with the
// leaf, which is the confusion `issueUnder()`'s chain rule exists to prevent —
// and for SPIFFE specifically it is the difference between a bundle and a
// certificate list.
// ---------------------------------------------------------------------------
function describeIssuer(scopeId, useCaseId) {
  log.debug("Entering describeIssuer().");
  const id = String(scopeId);
  const row = rawRowFor(id);
  const ca = row && row.issuing ? row.issuing[useCaseId] : null;
  const root = serviceRoot();
  if (!ca || !row.intermediate || !root) {
    log.debug("Leaving describeIssuer().");
    return null;
  }
  log.debug("Leaving describeIssuer().");
  return {
    scope: id,
    useCase: String(useCaseId),
    subject: ca.subject,
    serialHex: ca.serialHex,
    keyAlg: ca.keyAlg,
    // WHAT THIS AUTHORITY SIGNS WITH, which is what a caller reporting on it
    // means — not `ca.signatureAlg`, which is what its parent signed IT with.
    signatureAlg: signatureForIssuer(ca, ca.signatureAlg, ca.keyAlg),
    signedWith: ca.signatureAlg,
    notBefore: ca.notBefore,
    notAfter: ca.notAfter,
    thumbprint: ca.thumbprint,
    imported: !!ca.imported,
    certificatePem: ca.certificatePem,
    // Leaf-first from the authority upward, Root excluded — the same order
    // `issueUnder()` hands back, so the two cannot disagree.
    chainPem: [ca.certificatePem, row.intermediate.certificatePem],
    intermediate: { subject: row.intermediate.subject,
                    notAfter: row.intermediate.notAfter,
                    thumbprint: row.intermediate.thumbprint,
                    certificatePem: row.intermediate.certificatePem },
    root: { subject: root.subject,
            serialHex: root.serialHex,
            notBefore: root.notBefore,
            notAfter: root.notAfter,
            thumbprint: root.thumbprint,
            certificatePem: root.certificatePem }
  };
}

// ===========================================================================
// THE OBJECT STORE (2026-09-10), which is what the Certificate & Key
// Configuration pane on `/admin/pki` issues INTO.
//
// **IT IS IN THE SAME ROW AS THE HIERARCHY AND THAT IS THE WHOLE OF THE
// PLACEMENT ARGUMENT.** This module's header says it keeps no store of its
// own, because a second place to put a private key is the one nobody
// remembers to seal, to purge with the realm, or to share with a request
// worker. An object authored on that pane is a private key this service
// generated — exactly what the three CA keys are — so it goes where they go:
// `keystore.attachPki()`'s `pki:<realm>` row, sealed under the same
// key-encryption key, read back by the same `start()`, forwarded to the
// worker pool by the same channel, and gone with the realm by the same purge.
//
// **THE DEBUGGER'S EQUIVALENT IS `localStorage` AND THIS IS DELIBERATELY NOT
// AN ANALOGUE OF IT.** That page holds the key in the browser because its
// whole claim is that the key never leaves it; this page's claim is the
// opposite — the private keys of a certificate authority belong in the
// process that signs — so the store is where the signing happens, and it
// inherits the mode: product keeps it, development loses it with the process,
// which is the rule the signing key already follows.
//
// An object is a key pair, its certificate, and what it took to make them.
// Nothing here interprets one — `common/pki_authoring.ts` does — so this is
// four accessors and a cap.
// ===========================================================================

// The most objects one realm may hold. A cap rather than unbounded growth for
// the reason `admin_stats.js` caps its lists: every one of these is sealed,
// written to the store and pushed to every request worker on change, so a page
// somebody leaves issuing in a loop would otherwise grow one row without
// limit.
//
// **A FULL STORE REFUSES THE NEXT OBJECT, AND UNTIL 2026-09-12 IT DISCARDED
// THE OLDEST.** The comment here said "the OLDEST goes, and the reply says so —
// silently dropping the thing somebody just made would be worse than
// refusing", which is true and was answering the wrong question: what went was
// not the thing somebody just made but a thing somebody made EARLIER and chose
// to keep — very often a CA key pair other objects were issued from, the one
// kind of object here that cannot be made again with the same identity. A
// reply saying so arrived on a page about a DIFFERENT object and was read by
// somebody who had not made the one that went. Refusing costs the person
// pressing Issue one sentence telling them to delete something; evicting cost
// somebody else a private key.
//
// `pki.maxStoredObjects` is the number, read per call. `MAX_OBJECTS` stays as
// the default it replaces and as a GETTER on this module's exports, so
// `common/pki_authoring.ts`'s view — which reads `pki.MAX_OBJECTS` — draws the
// live cap without being edited.
const MAX_OBJECTS = 200;

function maxObjects() {
  log.debug("Entering maxObjects().");
  const n = Number(config.value('pki.maxStoredObjects'));
  log.debug("Leaving maxObjects().");
  return isFinite(n) && n > 0 ? Math.floor(n) : MAX_OBJECTS;
}

// Is there room for one more object in this realm? A REPLACEMENT of an id
// already held always has room — it does not grow the row — which is why this
// takes the id rather than answering about the count alone. Exported so a
// caller can ask BEFORE it spends a key generation on an object it cannot
// keep.
function roomForObject(realmId, objectId) {
  log.debug("Entering roomForObject().");
  const held = objects(realmId);
  const wanted = String(objectId || '');
  if (wanted && held.some(function (one) { return one.id === wanted; })) {
    log.debug("Leaving roomForObject().");
    return true;
  }
  log.debug("Leaving roomForObject().");
  return held.length < maxObjects();
}

function objects(realmId) {
  log.debug("Entering objects().");
  const row = rawRowFor(realmId);
  log.debug("Leaving objects().");
  return ((row && row.objects) || []).slice();
}

function objectFor(realmId, objectId) {
  log.debug("Entering objectFor().");
  const wanted = String(objectId || '');
  if (!wanted) {
    log.debug("Leaving objectFor().");
    return null;
  }
  log.debug("Leaving objectFor().");
  return objects(realmId).filter(function (one) {
    return one.id === wanted;
  })[0] || null;
}

// Put one in, REPLACING any object with the same id. The row is read back
// through `rawRowFor()` on every call rather than held here, because a request
// worker's copy of it is replaced wholesale when another process writes — a
// cached reference would go on appending to a row nobody else has.
function putObject(realmId, object) {
  log.debug('Entering putObject(). id=' + (object && object.id));
  const id = realmIdOf(realmId);
  const row = rawRowFor(id) || { version: 1, realm: id, createdAt: Date.now() };
  const kept = ((row.objects) || []).filter(function (one) {
    return one.id !== object.id;
  });
  const cap = maxObjects();
  // REFUSED, NOT EVICTED — see the block above `MAX_OBJECTS`. `kept` has the
  // object's own id taken out already, so a replacement is never refused.
  if (kept.length >= cap) {
    log.warn(errorCodes.tag('STS-PKI-0027') + 'pki: the "' + id + '" realm ' +
        'already holds ' + kept.length +
             ' object(s), the most `pki.maxStoredObjects` allows (' + cap +
             '), so "' + (object && object.id) + '" was NOT stored. Nothing ' +
             'already stored was touched.');
    log.debug('Leaving putObject(). The store is full.');
    return errorCodes.mark({ ok: false, full: true, dropped: 0, object: object,
             errors: ['This realm\'s certificate store is full: it holds ' +
                      kept.length + ' object(s) and pki.maxStoredObjects is ' +
                      cap + '. Nothing was stored and nothing already stored ' +
                      'was discarded — an older object may carry a private ' +
                      'key somebody chose to keep. Delete objects that are ' +
                      'no longer wanted, or raise ' +
                      'pki.maxStoredObjects.'] }, 'STS-PKI-0027');
  }
  kept.push(object);
  row.objects = kept;
  row.realm = id;
  saveRow(id, row);
  log.debug('Leaving putObject(). ' + kept.length + ' object(s).');
  // `dropped` is kept on the reply, always 0, because a caller written when
  // the store evicted reads it to decide whether to say so.
  return { ok: true, dropped: 0, object: object };
}

function removeObject(realmId, objectId) {
  log.debug('Entering removeObject(). id=' + objectId);
  const id = realmIdOf(realmId);
  const row = rawRowFor(id);
  const before = ((row && row.objects) || []).length;
  if (!before) {
    log.debug('Leaving removeObject(). Nothing stored.');
    return errorCodes.mark({ ok: false, errors: ['There is nothing in this ' +
                                                 'realm\'s ' +
                                                 'store.'] }, 'STS-PKI-0028');
  }
  row.objects = row.objects.filter(function (one) {
    return one.id !== String(objectId || '');
  });
  if (row.objects.length === before) {
    log.debug('Leaving removeObject(). No such object.');
    return errorCodes.mark({ ok: false,
             errors: ['There is no object "' + objectId + '" in this ' +
                      'realm\'s store.'] }, 'STS-PKI-0029');
  }
  saveRow(id, row);
  log.debug('Leaving removeObject(). Removed.');
  return { ok: true };
}

function clearObjects(realmId) {
  log.debug('Entering clearObjects().');
  const id = realmIdOf(realmId);
  const row = rawRowFor(id);
  const count = ((row && row.objects) || []).length;
  if (!count) {
    log.debug('Leaving clearObjects(). Nothing stored.');
    return errorCodes.mark({ ok: false, errors: ['There is nothing in this ' +
                                                 'realm\'s ' +
                                                 'store.'] }, 'STS-PKI-0028');
  }
  row.objects = [];
  saveRow(id, row);
  log.warn('pki: the "' + id + '" realm\'s object store was emptied. ' +
           count + ' key pair(s) are gone; anything they signed is still a ' +
           'valid document and still chains to whatever signed IT.');
  log.debug('Leaving clearObjects(). ' + count + ' removed.');
  return { ok: true, removed: count };
}

// EVERY SCOPE THIS PROCESS HOLDS A BRANCH FOR. Read from the keystore rather
// than from the realm registry, because a branch can outlive the realm that
// asked for it — a row is what this module is about, and a scope with a row is
// a scope with authorities whose CRLs somebody may still be fetching.
// **`pkiAll()` ANSWERS AN ARRAY OF `{ realm, chain }` AND NOT A MAP**, which
// this function read as a map for a day: `Object.keys()` over an array gives
// `'0'`, `'1'`, `'2'` — three scope ids that name nothing — so every caller
// was handed a list of branches that do not exist while the ones that do were
// invisible. Nothing threw. `/pki/revocation` listed the Root and no
// Intermediate, and `issuedHere()` answered false for every serial this
// service had ever minted, which is an OCSP responder saying `unknown` about
// its own leaves.
function knownScopes() {
  log.debug("Entering knownScopes().");
  if (typeof keystore.pkiAll !== 'function') {
    log.debug("Leaving knownScopes().");
    return [];
  }
  log.debug("Leaving knownScopes().");
  return (keystore.pkiAll() || []).map(function (one) {
    return String(one && one.realm !== undefined ? one.realm : '');
  }).filter(function (id) { return id !== SERVICE_SCOPE; });
}

// ---------------------------------------------------------------------------
// WHAT MAY SIGN THE NEXT CERTIFICATE: the three tiers, then every stored
// object that is a CA. **Only ones whose private key is here**, which is the
// debugger page's rule word for word and for its reason — offering an issuer
// that cannot sign produces a Web Crypto error two clicks later naming neither
// the authority nor the missing key.
//
// It answers the SIGNING MATERIAL as well as the label, because every caller
// needs both and a second lookup by id is a second chance to hand one
// certificate the other's key.
// ---------------------------------------------------------------------------
function issuers(realmId) {
  log.debug('Entering issuers().');
  const chain = rawChainFor(realmId);
  const out = [];
  if (chain) {
    chain.tiers.forEach(function (tier) {
      out.push({ id: 'tier:' + tier.tier, label: tier.label + ' — ' +
                 tier.subject, tier: tier.tier, subject: tier.subject,
                 keyAlg: tier.keyAlg, notAfter: tier.notAfter,
                 certificatePem: tier.certificatePem,
                 privateKeyPem: tier.privateKeyPem,
                 altKeyAlg: tier.altKeyAlg || null,
                 altPrivateKeyPem: tier.altPrivateKeyPem || null });
    });
  }
  objects(realmId).forEach(function (one) {
    if (!one.ca || !one.privateKeyPem) {
      return;
    }
    out.push({ id: one.id, label: (one.profileLabel || 'CA') + ' — ' +
               one.subject, subject: one.subject, keyAlg: one.keyAlg,
               notAfter: one.notAfter, certificatePem: one.certificatePem,
               privateKeyPem: one.privateKeyPem,
               altKeyAlg: one.altKeyAlg || null,
               altPrivateKeyPem: one.altPrivateKeyPem || null });
  });
  log.debug('Leaving issuers(). ' + out.length + ' of them.');
  return out;
}

function issuerFor(realmId, issuerId) {
  log.debug("Entering issuerFor().");
  const wanted = String(issuerId || '');
  log.debug("Leaving issuerFor().");
  return issuers(realmId).filter(function (one) {
    return one.id === wanted;
  })[0] || null;
}


// ===========================================================================
// STARTUP: THE TREE IS BUILT BEFORE THE LISTENER BINDS, AND EVERY KEY THIS
// SERVICE HOLDS IS CERTIFIED UNDER IT (2026-09-11).
//
// **THIS REVERSES "THE HIERARCHY IS BUILT BY PRESSING A BUTTON", AND IT HAD
// TO.** A key pair can only be issued by a certificate authority that exists
// when the key is made, and the keys are made at startup — so a hierarchy that
// waited for an operator would mean every key in a default deployment is
// self-signed for ever, which is the state this change exists to end.
//
// **WHAT DID NOT CHANGE IS THE KEY GENERATION ITSELF**, which was the
// requirement: the same RSA key, the same six curve keys, the same eleven
// post-quantum keys made lazily, the same algorithms, in the same order, at
// the same moment. `makeStsKeys()` is untouched. What is added happens
// AFTERWARDS and only ever adds a certificate.
//
// ---------------------------------------------------------------------------
// WHY IT IS HERE AND NOT IN `helpers.js`, WHICH IS WHERE THE KEYS ARE MADE.
//
// Issuing a certificate is Web Crypto and therefore ASYNCHRONOUS, and
// `makeStsKeys()` is reached through a property read on a Proxy — it cannot
// await anything. That is the same constraint `keystore.js` has and it is
// solved the same way: **everything asynchronous happens in `start()`, before
// the listener binds, and what is left at read time is a map lookup.**
//
// A realm created at RUNTIME is the case that does not fit, and it is handled
// honestly rather than ignored: `realms.onChange()` certifies the new realm's
// keys on the spot, asynchronously, so there is a window of milliseconds in
// which that realm's key set has no CA-issued certificate and reports the
// self-signed one it was born with. Saying so beats a service that blocks a
// realm creation on nine signatures.
// ===========================================================================

// The JOSE slots a realm's key set fills, derived from the key set itself
// rather than written out — `helpers.js` decides which curves exist and a
// second list here would be the first thing to disagree with it.
function joseSlotsOf(keys) {
  log.debug("Entering joseSlotsOf().");
  const out = [{ slot: 'RS256', alg: 'RS256', keyAlg: 'rsa-2048',
                 publicKeyPem: null, label: 'RSA signing key' }];
  (keys.extraKeys || []).forEach(function (one) {
    const jwk = one.publicJwk || {};
    // The SLOT names the curve as well as the algorithm, because the two EdDSA
    // entries share an `alg` and a slot that did not tell them apart would
    // certify one of them twice and the other never. It is `kidOf()`'s own
    // reasoning, applied to a different handle.
    const slot = jwk.crv ? (one.alg + ':' + jwk.crv) : one.alg;
    out.push({ slot: slot, alg: one.alg, crv: jwk.crv || '',
               keyAlg: '', publicKeyPem: null,
               label: (jwk.crv || one.alg) + ' signing key' });
  });
  log.debug("Leaving joseSlotsOf().");
  return out;
}

// ===========================================================================
// THE ELEVEN POST-QUANTUM KEYS ARE LEAVES OF THIS TREE TOO (2026-09-13).
//
// **THIS REVERSES A SENTENCE THE PKI PAGE SAID IN A WARNING BOX**: *one family
// of key material in this service is deliberately NOT a leaf of this tree: the
// eleven post-quantum signing keys per realm … handing a key made by one to the
// other would be exactly the defect that independence exists to expose, so
// they carry no certificate at all and are published as bare AKP JWKs.* It was
// reversed by request, and what replaced it keeps the independence rather than
// arguing it away — which is the part to understand before changing anything
// below.
//
// ---------------------------------------------------------------------------
// WHAT CROSSES, AND WHAT DOES NOT.
//
// `common/vendored/CLAUDE.md` says DO NOT WIRE `pq_jose.js` TO THE CERTIFICATE
// ENCODER, and the danger it names is specific: a key GENERATED by this
// service's own reading of the constructions handed to a module that expects
// the vendored reading's BYTE LAYOUT. That is still not done. The key is still
// generated, held, signed with and published by `pq_jose.js` alone; the worker
// pool still runs that file; no private key of these eleven ever reaches a
// vendored module. **What a certificate needs is the PUBLIC key, and only the
// public key crosses** — out of the AKP JWK `/oauth2/jwks` already publishes,
// into a SubjectPublicKeyInfo.
//
// **THE ONE PLACE THE TWO READINGS DIFFER IS WRITTEN OUT HERE, NOT INFERRED.**
// For ML-DSA and SLH-DSA the JOSE `pub` and the X.509 BIT STRING are the same
// octets. For a composite with an ECDSA half they are not: JOSE carries the
// point as `x || y` (draft-ietf-jose-pq-composite-sigs) and X.509 keeps the
// 0x04 uncompressed prefix (draft-ietf-lamps-pq-composite-sigs section 4) —
// `pqc_x509.js`'s header lists it as the first of three one-line differences
// that "produce a signature nothing else will verify". So the translation is
// one explicit step, and a key whose traditional half is not the length that
// step expects is REFUSED rather than guessed at.
//
// **AND THE CROSSING IS WHERE THE TWO READINGS ARE CHECKED AGAINST EACH OTHER,
// WHICH IS THE INDEPENDENCE BEING USED RATHER THAN SPENT.** A signature made by
// `pq_jose.js` must verify under the vendored X.509 reading against the key in
// the certificate — `tests/pq_key_certification.js` asserts exactly that for
// every ML-DSA and composite algorithm here. A misunderstanding shared by both
// would still pass; a misunderstanding in EITHER is now a failure, where
// before this change a certificate simply did not exist to disagree with.
//
// ---------------------------------------------------------------------------
// WHERE IT IS ISSUED FROM, AND WHY THAT IS THE REALM BOUNDARY UNCHANGED.
//
// The realm's own JOSE Issuing CA — the use-case table above already said so
// ("and the eleven post-quantum keys when they are made"), and a separate
// Issuing CA for post-quantum keys would be the per-ALGORITHM split that table
// refuses. So each is a leaf of THIS REALM's Intermediate, `verifyLeaf()`
// refuses it in any other realm for the reason it refuses every other leaf, and
// no new rule was needed for realm isolation to hold: the certificate lands in
// the realm's own row and nowhere else.
//
// The Issuing CA's own key stays whatever the branch was built with (RSA by
// default): a classical authority certifying a post-quantum subject key is the
// ordinary shape of a migration, and a relying party that cannot yet read the
// subject key can still build and verify the path.
// ===========================================================================

// JOSE `alg` → the vendored registry's id for the same algorithm in X.509.
// `ecField` is set for the composites whose traditional half is ECDSA: the
// field length of the curve, so the JOSE `x || y` can be recognised and given
// its prefix. `tests/pq_key_certification.js` holds this table against
// `pq_jose.PQ_ALGS` in both directions and against both files' domain-separator
// labels, so a twelfth algorithm cannot arrive in one and not the other.
const PQ_JOSE_IN_X509 = {
  'ML-DSA-44': { id: 'ML-DSA-44' },
  'ML-DSA-65': { id: 'ML-DSA-65' },
  'ML-DSA-87': { id: 'ML-DSA-87' },
  'SLH-DSA-SHA2-128s': { id: 'SLH-DSA-SHA2-128s' },
  'SLH-DSA-SHAKE-128s': { id: 'SLH-DSA-SHAKE-128s' },
  'ML-DSA-44-ES256': { id: 'mldsa44-ecdsa-p256-sha256', ecField: 32 },
  'ML-DSA-65-ES256': { id: 'mldsa65-ecdsa-p256-sha512', ecField: 32 },
  'ML-DSA-87-ES384': { id: 'mldsa87-ecdsa-p384-sha512', ecField: 48 },
  'ML-DSA-44-Ed25519': { id: 'mldsa44-ed25519-sha512' },
  'ML-DSA-65-Ed25519': { id: 'mldsa65-ed25519-sha512' },
  'ML-DSA-87-Ed448': { id: 'mldsa87-ed448-shake256' }
};

// The SubjectPublicKeyInfo, as PEM, of one post-quantum JOSE key — from its
// PUBLIC JWK and nothing else. Throws, naming the algorithm, where the key
// cannot be written down honestly; `certifyPqKeys()` reports that per key.
function pqSubjectPublicKeyPem(alg, publicJwk) {
  log.debug("Entering pqSubjectPublicKeyPem(). alg=" + alg);
  const entry = PQ_JOSE_IN_X509[String(alg)];
  const x = entry ? pqcX509.alg(entry.id) : null;
  if (!entry || !x) {
    log.debug("Leaving pqSubjectPublicKeyPem(). Unknown algorithm.");
    throw new Error(alg + ' has no X.509 encoding this service knows, so it ' +
                    'cannot be certified.');
  }
  if (!publicJwk || publicJwk.kty !== 'AKP' || publicJwk.alg !== alg ||
      !publicJwk.pub) {
    log.debug("Leaving pqSubjectPublicKeyPem(). Not an AKP JWK for it.");
    throw new Error('the ' + alg + ' key is not an AKP JWK naming ' + alg +
                    ' with a "pub" member (RFC 9964 section 3).');
  }
  let pub = Buffer.from(String(publicJwk.pub), 'base64url');
  const composite = pqcX509.COMPOSITE_ALGS[entry.id];
  if (composite) {
    const mlLength = pqc.SIGNATURE_ALGS[composite.mldsa].lengths.publicKey;
    const trad = pub.subarray(mlLength);
    if (entry.ecField) {
      // THE ONE TRANSLATION. `x || y` in JOSE, `0x04 || x || y` in X.509.
      if (trad.length !== 2 * entry.ecField) {
        log.debug("Leaving pqSubjectPublicKeyPem(). EC half is the wrong " +
                  "length.");
        throw new Error('the ' + alg + ' key\'s ECDSA half is ' +
                        trad.length + ' bytes and a JOSE composite carries ' +
                        'x || y, which is ' + (2 * entry.ecField) +
                        ' for this curve. Refused rather than guessed at.');
      }
      pub = Buffer.concat([pub.subarray(0, mlLength), Buffer.from([0x04]),
                           trad]);
    }
  }
  const pem = pqcX509.publicPem(entry.id, pub);
  log.debug("Leaving pqSubjectPublicKeyPem().");
  return pem;
}

// ---------------------------------------------------------------------------
// CERTIFY A REALM'S POST-QUANTUM KEYS UNDER ITS JOSE ISSUING CA.
//
// `pqKeys` is the list `helpers.js` keeps on a key set — `{ alg, publicJwk }`
// is all that is read; a `privateKey` beside them is never touched.
//
// **IDEMPOTENT PER KEY**, and it has to be: it is reached from generation, from
// `certifyKeySet()` at startup and from a realm watcher, and the eleven keys
// are the same keys every time. A slot whose certificate is already over this
// key AND was issued by the Issuing CA that exists now is left alone; a slot
// over a DIFFERENT key is reissued and the old certificate is superseded at
// its issuer, because the key it vouched for is no longer the one this realm
// signs with.
//
// **IT ANSWERS AND DOES NOT THROW**, for `certify()`'s reason — a key that
// could not be certified still signs, and a startup path must not fail on it.
// ---------------------------------------------------------------------------
async function certifyPqKeys(realmId, pqKeys, keepKids) {
  log.debug('Entering certifyPqKeys(). realm=' + realmId);
  const id = realmIdOf(realmId);
  const list = Array.isArray(pqKeys) ? pqKeys : [];
  const row = rawRowFor(id);
  if (!row || !row.issuing || !row.issuing.jose) {
    log.debug('Leaving certifyPqKeys(). No branch for that realm.');
    return errorCodes.mark({ ok: false, certified: 0, unchanged: 0,
             errors: ['The "' + (id || 'default') + '" realm has no ' +
                      'certificate authority branch.'] }, 'STS-PKI-0008');
  }
  let certified = 0;
  let unchanged = 0;
  const failed = [];
  for (let i = 0; i < list.length; i++) {
    const one = list[i] || {};
    const alg = String(one.alg || '');
    let spkiPem = '';
    try {
      spkiPem = pqSubjectPublicKeyPem(alg, one.publicJwk);
    } catch (e) {
      failed.push('jose/' + alg + ': ' + e.message);
      continue;
    }
    const fingerprint = thumbprintOf(spkiPem);
    const pqKid = (one.publicJwk && one.publicJwk.kid) || '';
    // A key this slot displaced by a promotion keeps its certificate in its
    // own generation slot, and the promoted key's is adopted (#42).
    keepDisplacedCertificate(id, 'jose', alg, pqKid, keepKids);
    if (adoptGenerationCertificate(id, 'jose', alg, pqKid, spkiPem)) {
      unchanged += 1;
      continue;
    }
    const held = certificateFor(id, 'jose', alg);
    const issuingNow = (rawRowFor(id).issuing.jose || {}).certificatePem;
    if (held && !held.pinned && held.subjectKeyFingerprint === fingerprint &&
        (held.chainPem || [])[0] === issuingNow && scopeChainsToRoot(id)) {
      unchanged += 1;
      continue;
    }
    const done = await certify(id, 'jose', {
      slot: alg, alg: alg, kid: pqKid,
      keyAlg: PQ_JOSE_IN_X509[alg].id.toLowerCase(),
      label: alg + ' signing key',
      commonName: 'JOSE signing (' + alg + ')',
      publicKeyPem: spkiPem,
      // A SIGNATURE KEY AND NOTHING ELSE. No keyEncipherment: none of these
      // eleven can encrypt or establish a key, and a keyUsage claiming so
      // would be refused by a strict validator for the right reason.
      keyUsage: ['digitalSignature', 'nonRepudiation']
    });
    if (!done.ok) {
      failed.push('jose/' + alg + ': ' + done.errors.join(' '));
      continue;
    }
    certified += 1;
    if (held && held.subjectKeyFingerprint !== fingerprint) {
      supersede(id, 'jose', held, 'the ' + alg + ' key it certified was ' +
                'replaced');
    }
  }
  if (failed.length) {
    log.warn(errorCodes.tag('STS-PKI-0031') + 'pki: the "' + id + '" realm ' +
             'has ' + (certified + unchanged) + ' certified post-quantum ' +
             'key(s) and ' + failed.length + ' that could not be ' +
             'certified: ' + failed.join('; ') + '. Those keys still SIGN — ' +
             'what they lack is a certificate chaining to this service\'s ' +
             'Root.');
  } else if (certified) {
    log.info('pki: ' + certified + ' post-quantum signing key(s) of the "' +
             id + '" realm are certified under its own JOSE Issuing CA' +
             (unchanged ? ' (' + unchanged + ' already were)' : '') + '.');
  }
  const verdict = { ok: !failed.length, certified: certified,
                    unchanged: unchanged, failed: failed };
  log.debug('Leaving certifyPqKeys(). ' + certified + ' certified, ' +
            unchanged + ' unchanged.');
  return failed.length ? errorCodes.mark(verdict, 'STS-PKI-0031') : verdict;
}

// ===========================================================================
// THE SIGNER GROUPS' CERTIFICATES (2026-09-26, #68).
//
// `common/signer_groups.js` pairs each group's classical key with an ML-DSA
// key; this issues ONE certificate per pair — the classical key in
// subjectPublicKeyInfo, the ML-DSA key in subjectAltPublicKeyInfo (ITU-T
// X.509 (2019) clause 9.8) — and one plain certificate for the SLH-DSA key,
// from the group's Issuing CA (JOSE, or XML for the `xml` group), under the
// slot `<group>/<slot>`. The Issuing CA's own alternative signature is added
// by `certify()` as it is to every leaf (phase 1).
//
// An ML-DSA member that HAS a partner gets no certificate of its own: its
// certificate is its partner's, which is what "collapsing by signing
// algorithm" means for the certificate count. Its slot is looked up through
// `pairedSlot`.
//
// Unchanged when the slot already holds a certificate over the same classical
// key AND the same alternative key under the current Issuing CA —
// `certifyPqKeys()`'s test, over both keys, so regenerating either half
// re-issues.
// ===========================================================================
async function certifySignerGroups(realmId, members) {
  log.debug('Entering certifySignerGroups(). realm=' + realmId);
  const signerGroups = require('./signer_groups');
  const id = realmIdOf(realmId);
  const list = Array.isArray(members) ? members : [];
  // THE BRANCH FIRST. Group keys are made on a realm's first group signature,
  // which can come before its branch exists — a realm created at runtime and
  // switched at once — and a certification refused for want of an Issuing CA
  // is not retried by anything unless a later certifyKeySet() happens to run
  // after the keys arrived. `ensureScope()` builds it once, cluster-wide, or
  // answers at once when it is there.
  const before = rawRowFor(id);
  if (list.length && (!before || !before.issuing)) {
    try {
      await ensureScope(id);
    } catch (e) {
      log.debug('Caught in certifySignerGroups(): ' + ((e && e.message) || e));
      // The per-certificate refusals below say what is missing.
    }
  }
  const bySlot = {};
  list.forEach(function (one) {
    bySlot[one.slot] = one;
  });
  let certified = 0;
  let unchanged = 0;
  const failed = [];
  for (let i = 0; i < list.length; i++) {
    const one = list[i] || {};
    // A partnered ML-DSA key's certificate is its partner's — EXCEPT in the
    // XML group, where an XML signature's KeyInfo and the SAML metadata carry
    // an X.509 certificate whose subjectPublicKeyInfo must be the signing key,
    // so each gets a plain RFC 9881 certificate of its own (rcbj's D7).
    if (one.kind === 'pq' && one.pairedSlot && one.group !== 'xml') {
      continue;
    }
    const grp = signerGroups.group(one.group);
    const ucId = grp ? grp.pkiUseCase : 'jose';
    const row = rawRowFor(id);
    if (!row || !row.issuing || !row.issuing[ucId]) {
      failed.push(one.slot + ': the realm has no ' + ucId + ' Issuing CA');
      continue;
    }
    let spkiPem = '';
    let altPem = null;
    try {
      spkiPem = one.kind === 'pq'
        ? pqSubjectPublicKeyPem(one.alg, one.publicJwk)
        : String(nodeCrypto.createPublicKey({ key: one.publicJwk,
                                              format: 'jwk' })
                   .export({ type: 'spki', format: 'pem' }));
      // The ALTERNATIVE key is a classical key's ML-DSA partner; an ML-DSA
      // key's own certificate (D7) carries none.
      const partner = one.pairedSlot && one.kind !== 'pq'
        ? bySlot[one.pairedSlot] : null;
      if (one.pairedSlot && one.kind !== 'pq' && !partner) {
        failed.push(one.slot + ': its partner ' + one.pairedSlot +
                    ' is missing');
        continue;
      }
      altPem = partner
        ? pqSubjectPublicKeyPem(partner.alg, partner.publicJwk) : null;
    } catch (e) {
      failed.push(one.slot + ': ' + e.message);
      continue;
    }
    const kid = (one.publicJwk && one.publicJwk.kid) || '';
    const held = certificateFor(id, ucId, one.slot);
    const issuingNow = (row.issuing[ucId] || {}).certificatePem;
    if (held && !held.pinned &&
        held.subjectKeyFingerprint === thumbprintOf(spkiPem) &&
        (held.altPublicKeyPem || null) === altPem &&
        (held.chainPem || [])[0] === issuingNow && scopeChainsToRoot(id)) {
      unchanged += 1;
      continue;
    }
    const keyAlg = one.kind === 'pq'
      ? PQ_JOSE_IN_X509[one.alg].id.toLowerCase()
      : (signerGroups.PAIRS.filter(function (pair) {
          return signerGroups.slotOf(one.group, pair.slot) === one.slot;
        })[0] || {}).keyAlg;
    const done = await certify(id, ucId, {
      slot: one.slot, alg: one.alg, kid: kid, keyAlg: keyAlg,
      label: one.slot + ' signing key' + (altPem ? ' (hybrid)' : ''),
      commonName: (grp ? grp.label : one.group) + ' (' + one.alg +
                  (altPem && partner(one) ? ' + ' + partner(one).alg : '') +
                  ')',
      publicKeyPem: spkiPem,
      altPublicKeyPem: altPem,
      keyUsage: ['digitalSignature', 'nonRepudiation']
    });
    if (!done.ok) {
      failed.push(one.slot + ': ' + done.errors.join(' '));
      continue;
    }
    certified += 1;
    if (held && held.subjectKeyFingerprint !== thumbprintOf(spkiPem)) {
      supersede(id, ucId, held, 'the ' + one.slot + ' key it certified ' +
                'was replaced');
    }
  }
  function partner(one) {
    log.debug("Entering partner().");
    log.debug("Leaving partner().");
    return one.pairedSlot ? bySlot[one.pairedSlot] : null;
  }
  if (failed.length) {
    log.warn(errorCodes.tag('STS-PKI-0031') + 'pki: the "' + id + '" realm ' +
             'has ' + (certified + unchanged) + ' certified signer-group ' +
             'key(s) and ' + failed.length + ' that could not be ' +
             'certified: ' + failed.join('; ') + '. Those keys still SIGN.');
  } else if (certified) {
    log.info('pki: ' + certified + ' signer-group certificate(s) of the "' +
             id + '" realm were issued, each classical key with its ML-DSA ' +
             'partner (hybrid)' +
             (unchanged ? ' (' + unchanged + ' already were)' : '') + '.');
  }
  const verdict = { ok: !failed.length, certified: certified,
                    unchanged: unchanged, failed: failed };
  log.debug('Leaving certifySignerGroups(). ' + certified + ' certified, ' +
            unchanged + ' unchanged.');
  return failed.length ? errorCodes.mark(verdict, 'STS-PKI-0031') : verdict;
}

// Certify one realm's signing keys under its JOSE and XML Issuing CAs.
//
// **THE RSA KEY IS CERTIFIED TWICE, ON PURPOSE.** It signs JWTs and it signs
// XML documents, and those are two use cases with two Issuing CAs — so it gets
// a certificate from each, with the same public key in both. A relying party
// that trusts this service for SAML has not thereby said anything about its
// OAuth tokens, and two certificates is how that stays sayable. It is also why
// the slot is per USE CASE rather than per key.
// ---------------------------------------------------------------------------
// A PROMOTION WITHOUT A SECOND CERTIFICATE (2026-09-22, #42). When a `next`
// key becomes current, the certificate it has been published with since it
// was minted — in its own generation slot — is the one it goes on being
// published with, so the plain slot takes THAT record rather than a fresh
// one. And the record the plain slot held, over the key that was just
// retired, moves to THAT key's own generation slot first, so a retired key
// keeps the certificate (and the `x5c`) a relying party already holds.
// ---------------------------------------------------------------------------
//
// **ONLY A KEY THAT IS STILL A GENERATION IS KEPT** (`keepKids`, the set's
// standby kids). A key promoted over is RETIRED and goes on verifying, so its
// certificate moves to its own slot; a key REPLACED — a restore, a key put in
// the slot by hand — is gone, so its certificate is left where it is for
// `certify()` to supersede, as it always was (`tests/pq_key_certification.js`
// E holds that half).
function keepDisplacedCertificate(id, useCaseId, slot, currentKid, keepKids) {
  log.debug("Entering keepDisplacedCertificate(). " + useCaseId + ':' + slot);
  const row = rawRowFor(id);
  const plain = row && row.certs && row.certs[slotKey(useCaseId, slot)];
  if (!plain || !plain.kid || plain.kid === String(currentKid || '')) {
    log.debug("Leaving keepDisplacedCertificate(). Nothing displaced.");
    return false;
  }
  if ((keepKids || []).indexOf(plain.kid) < 0) {
    log.debug("Leaving keepDisplacedCertificate(). Not a generation: left " +
              "to be superseded.");
    return false;
  }
  const own = slotKey(useCaseId, slot, plain.kid);
  const fresh = Object.assign({}, row);
  fresh.certs = Object.assign({}, row.certs);
  if (!fresh.certs[own]) {
    fresh.certs[own] = plain;
  }
  delete fresh.certs[slotKey(useCaseId, slot)];
  saveRow(id, fresh);
  log.debug("Leaving keepDisplacedCertificate(). Moved to " + own + ".");
  return true;
}

function adoptGenerationCertificate(id, useCaseId, slot, kid, publicKeyPem) {
  log.debug("Entering adoptGenerationCertificate(). " + useCaseId + ':' +
            slot);
  if (!kid) {
    log.debug("Leaving adoptGenerationCertificate(). No kid.");
    return false;
  }
  const row = rawRowFor(id);
  const own = row && row.certs && row.certs[slotKey(useCaseId, slot, kid)];
  const issuingNow = ((row && row.issuing && row.issuing[useCaseId]) || {})
    .certificatePem;
  if (!own || own.subjectKeyFingerprint !== thumbprintOf(publicKeyPem) ||
      (own.chainPem || [])[0] !== issuingNow) {
    log.debug("Leaving adoptGenerationCertificate(). None to adopt.");
    return false;
  }
  const plainKey = slotKey(useCaseId, slot);
  if (row.certs[plainKey] && row.certs[plainKey].serialHex === own.serialHex) {
    log.debug("Leaving adoptGenerationCertificate(). Already there.");
    return true;
  }
  const fresh = Object.assign({}, row);
  fresh.certs = Object.assign({}, row.certs);
  fresh.certs[plainKey] = own;
  saveRow(id, fresh);
  log.debug("Leaving adoptGenerationCertificate(). Adopted.");
  return true;
}

// ---------------------------------------------------------------------------
// THE STANDBY KEY GENERATIONS (2026-09-22, #42): the `next` key of each unit,
// published before it is promoted, and each retired key still verifying. Each
// is certified under its unit's Issuing CA in a slot of its own
// (`slotKey()`'s header), ONCE — a slot already holding a certificate over
// the same key from the current Issuing CA is left alone, as
// `certifyPqKeys()` leaves its keys.
// ---------------------------------------------------------------------------
async function certifyStandbyKeys(realmId, keys, nodeCryptoModule) {
  log.debug('Entering certifyStandbyKeys(). realm=' + realmId);
  const id = realmIdOf(realmId);
  const nodeC = nodeCryptoModule || nodeCrypto;
  const standby = (keys && keys.generations && keys.generations.standby) || [];
  let certified = 0;
  const failed = [];
  for (let i = 0; i < standby.length; i++) {
    const one = standby[i];
    // A BBS key (#49 P5) is not an X.509 subject: nothing to certify.
    if (one.kind === 'bbs') {
      continue;
    }
    // A signer-group pair's `next` or retired generation (#68): ONE hybrid
    // certificate over both halves, issued for the primary key; the
    // partnered ML-DSA key has none of its own.
    if (one.kind === 'group') {
      if (one.memberKind === 'pq' && one.pairedSlot && one.group !== 'xml') {
        continue;
      }
      const groupDone = await certifyStandbyGroupEntry(id, one, standby,
                                                       nodeC);
      if (groupDone === true) {
        certified += 1;
      } else if (groupDone) {
        failed.push(groupDone);
      }
      continue;
    }
    let publicPem = '';
    try {
      publicPem = one.kind === 'pq'
        ? pqSubjectPublicKeyPem(one.alg, one.publicJwk)
        : one.kind === 'rsa'
          ? nodeC.createPublicKey(one.certPem)
              .export({ type: 'spki', format: 'pem' })
          : nodeC.createPublicKey({ key: one.publicJwk, format: 'jwk' })
              .export({ type: 'spki', format: 'pem' });
    } catch (e) {
      failed.push(one.unit + '@' + one.kid + ': ' + e.message);
      continue;
    }
    const row = rawRowFor(id) || {};
    const held = certificateFor(id, one.useCase, one.slot, one.kid);
    const issuingNow = ((row.issuing && row.issuing[one.useCase]) || {})
      .certificatePem;
    if (held && held.kid === one.kid &&
        held.subjectKeyFingerprint === thumbprintOf(publicPem) &&
        (held.chainPem || [])[0] === issuingNow && scopeChainsToRoot(id)) {
      continue;
    }
    const label = one.kind === 'rsa'
      ? (one.useCase === 'xml' ? 'XML signing (RS256)' : 'JOSE signing (RS256)')
      : (one.crv || one.alg) + ' signing key';
    const done = await certify(id, one.useCase, {
      slot: one.slot, alg: one.alg, crv: one.crv || '', kid: one.kid,
      generationSlot: true,
      keyAlg: one.kind === 'rsa' ? 'rsa-2048'
        : String(one.crv || one.alg).toLowerCase(),
      label: label + ', ' + one.role + ' generation',
      commonName: label, publicKeyPem: publicPem,
      keyUsage: one.kind === 'rsa'
        ? ['digitalSignature', 'nonRepudiation', 'keyEncipherment']
        : undefined
    });
    if (done.ok) {
      certified += 1;
    } else {
      failed.push(one.unit + '@' + one.kid + ': ' + done.errors.join(' '));
    }
  }
  log.debug('Leaving certifyStandbyKeys(). ' + certified + ' certified.');
  return { certified: certified, failed: failed };
}

// One signer-group standby entry's certificate (#68): the primary key in
// subjectPublicKeyInfo and, for a pair, the partner of the SAME generation
// (same unit, same role) in subjectAltPublicKeyInfo, in the entry's own
// generation slot. Resolves true when issued, null when already current, or
// a failure sentence.
async function certifyStandbyGroupEntry(id, one, standby, nodeC) {
  log.debug('Entering certifyStandbyGroupEntry(). ' + one.unit + '@' +
            one.kid);
  const signerGroups = require('./signer_groups');
  let publicPem = '';
  let altPem = null;
  try {
    publicPem = one.memberKind === 'pq'
      ? pqSubjectPublicKeyPem(one.alg, one.publicJwk)
      : String(nodeC.createPublicKey({ key: one.publicJwk, format: 'jwk' })
                 .export({ type: 'spki', format: 'pem' }));
    if (one.pairedSlot && one.memberKind !== 'pq') {
      const partner = standby.filter(function (other) {
        return other.unit === one.unit && other.role === one.role &&
               other.slot === one.pairedSlot;
      })[0];
      if (!partner) {
        log.debug('Leaving certifyStandbyGroupEntry(). No partner.');
        return one.unit + '@' + one.kid + ': its ' + one.role + ' partner ' +
               one.pairedSlot + ' is missing';
      }
      altPem = pqSubjectPublicKeyPem(partner.alg, partner.publicJwk);
    }
  } catch (e) {
    log.debug('Leaving certifyStandbyGroupEntry(). ' + e.message);
    return one.unit + '@' + one.kid + ': ' + e.message;
  }
  const row = rawRowFor(id) || {};
  const held = certificateFor(id, one.useCase, one.slot, one.kid);
  const issuingNow = ((row.issuing && row.issuing[one.useCase]) || {})
    .certificatePem;
  if (held && held.kid === one.kid &&
      held.subjectKeyFingerprint === thumbprintOf(publicPem) &&
      (held.altPublicKeyPem || null) === altPem &&
      (held.chainPem || [])[0] === issuingNow && scopeChainsToRoot(id)) {
    log.debug('Leaving certifyStandbyGroupEntry(). Already current.');
    return null;
  }
  const pairSpec = signerGroups.PAIRS.filter(function (pair) {
    return signerGroups.slotOf(one.group, pair.slot) === one.slot;
  })[0] || { keyAlg: '' };
  const done = await certify(id, one.useCase, {
    slot: one.slot, alg: one.alg, kid: one.kid, generationSlot: true,
    keyAlg: one.memberKind === 'pq'
      ? PQ_JOSE_IN_X509[one.alg].id.toLowerCase() : pairSpec.keyAlg,
    label: one.slot + ' signing key' + (altPem ? ' (hybrid)' : '') + ', ' +
           one.role + ' generation',
    commonName: one.slot + (altPem ? ' (hybrid)' : ''),
    publicKeyPem: publicPem, altPublicKeyPem: altPem,
    keyUsage: ['digitalSignature', 'nonRepudiation']
  });
  log.debug('Leaving certifyStandbyGroupEntry(). ok=' + done.ok);
  return done.ok ? true
    : one.unit + '@' + one.kid + ': ' + done.errors.join(' ');
}

async function certifyKeySet(realmId, keys, nodeCryptoModule) {
  log.debug('Entering certifyKeySet(). realm=' + realmId);
  const id = realmIdOf(realmId);
  const nodeC = nodeCryptoModule || nodeCrypto;
  if (!rawRowFor(id) || !rawRowFor(id).issuing) {
    log.debug('Leaving certifyKeySet(). No branch for that realm.');
    return errorCodes.mark({ ok: false, certified: 0,
             errors: ['The "' + (id || 'default') + '" realm has no ' +
                      'certificate authority branch.'] }, 'STS-PKI-0008');
  }
  let certified = 0;
  const failed = [];
  // The kids still generations of this set, whose certificates a promotion
  // moves aside rather than supersedes (`keepDisplacedCertificate()`).
  const keepKids = ((keys && keys.generations && keys.generations.standby) ||
                    []).map(function (one) {
    return String(one.kid);
  });

  // --- the RSA key, under JOSE and under XML -------------------------------
  let rsaPublicPem = '';
  try {
    rsaPublicPem = nodeC.createPublicKey(keys.privateKeyPem)
      .export({ type: 'spki', format: 'pem' });
  } catch (e) {
    log.error(errorCodes.tag('STS-PKI-0030') + 'pki: the "' + id + '" ' +
              'realm\'s signing key could not be read to certify ' +
              'it: ' + e.message);
    log.debug("Leaving certifyKeySet().");
    return errorCodes.mark({ ok: false, certified: 0, errors: [e.message] },
                           'STS-PKI-0030');
  }
  // THE XML USE CASE HAS A KEY OF ITS OWN SINCE 2026-09-22 (#42, D2): the
  // `xml` leaf is issued over `keys.xmlKey`, and over the RSA key above only
  // for a set that has none yet (it is backfilled on first use).
  let xmlPublicPem = rsaPublicPem;
  if (keys.xmlKey && keys.xmlKey.privateKeyPem) {
    try {
      xmlPublicPem = nodeC.createPublicKey(keys.xmlKey.privateKeyPem)
        .export({ type: 'spki', format: 'pem' });
    } catch (e) {
      log.debug("Caught in certifyKeySet(): " + ((e && e.message) || e));
      xmlPublicPem = rsaPublicPem;
    }
  }
  const rsaJobs = [
    { useCase: 'jose', slot: 'RS256', cn: 'JOSE signing (RS256)',
      publicKeyPem: rsaPublicPem, kid: keys.kid },
    { useCase: 'xml', slot: 'RS256', cn: 'XML signing (RS256)',
      publicKeyPem: xmlPublicPem,
      kid: keys.xmlKey && keys.xmlKey.kid ? keys.xmlKey.kid : keys.kid }
  ];
  for (let i = 0; i < rsaJobs.length; i++) {
    const job = rsaJobs[i];
    keepDisplacedCertificate(id, job.useCase, job.slot, job.kid, keepKids);
    if (adoptGenerationCertificate(id, job.useCase, job.slot, job.kid,
                                   job.publicKeyPem)) {
      certified += 1;
      continue;
    }
    const done = await certify(id, job.useCase, {
      slot: job.slot, alg: 'RS256', keyAlg: 'rsa-2048', kid: job.kid,
      label: job.cn, commonName: job.cn, publicKeyPem: job.publicKeyPem,
      // XML Signature and JWS are both DIGITAL SIGNATURES, and this key also
      // DECRYPTS — a JWE sent to this service, and an EncryptedID in a SAML
      // document — so it carries keyEncipherment as well. A certificate whose
      // keyUsage forbids the thing the key is actually used for is refused by
      // a strict validator and by nothing here, which is the worst of both.
      keyUsage: ['digitalSignature', 'nonRepudiation', 'keyEncipherment']
    });
    if (done.ok) {
      certified += 1;
    } else {
      failed.push(job.useCase + '/' + job.slot + ': ' + done.errors.join(' '));
    }
  }

  // --- the curve keys, under JOSE -----------------------------------------
  const extras = keys.extraKeys || [];
  for (let i = 0; i < extras.length; i++) {
    const one = extras[i];
    const jwk = one.publicJwk || {};
    const slot = jwk.crv ? (one.alg + ':' + jwk.crv) : one.alg;
    let publicPem = '';
    try {
      publicPem = nodeC.createPublicKey({ key: jwk, format: 'jwk' })
        .export({ type: 'spki', format: 'pem' });
    } catch (e) {
      failed.push('jose/' + slot + ': ' + e.message);
      continue;
    }
    keepDisplacedCertificate(id, 'jose', slot, jwk.kid, keepKids);
    if (adoptGenerationCertificate(id, 'jose', slot, jwk.kid, publicPem)) {
      certified += 1;
      continue;
    }
    const done = await certify(id, 'jose', {
      slot: slot, alg: one.alg, crv: jwk.crv || '', kid: jwk.kid,
      keyAlg: (jwk.crv || '').toLowerCase(),
      label: (jwk.crv || one.alg) + ' signing key',
      commonName: 'JOSE signing (' + (jwk.crv || one.alg) + ')',
      publicKeyPem: publicPem
    });
    if (done.ok) {
      certified += 1;
    } else {
      failed.push('jose/' + slot + ': ' + done.errors.join(' '));
    }
  }

  // --- the post-quantum keys, under JOSE, WHERE THEY EXIST ------------------
  // They are made on first use, so a key set being certified at generation
  // usually has none yet and `helpers.js` certifies them when it makes them.
  // What reaches this line with them present is a set RESTORED from the store
  // or from a sibling process — which is exactly the set whose certificates
  // may predate a rebuilt branch, and `certifyPqKeys()` leaves alone the ones
  // that are still current.
  if (Array.isArray(keys.pqKeys) && keys.pqKeys.length) {
    const pq = await certifyPqKeys(id, keys.pqKeys, keepKids);
    certified += pq.certified || 0;
    (pq.failed || []).forEach(function (one) {
      failed.push(one);
    });
  }

  // --- the signer groups, WHERE THEY EXIST (#68) ------------------------
  // Made lazily like the post-quantum keys, and for their reason here: a set
  // reaching this line with them is a restored one.
  const groupMembers = keys.signerGroups || [];
  if (groupMembers.length) {
    const groups = await certifySignerGroups(id, groupMembers);
    certified += groups.certified || 0;
    (groups.failed || []).forEach(function (one) {
      failed.push(one);
    });
  }

  // --- every STANDBY key generation, in a slot of its own (#42) -----------
  const standby = await certifyStandbyKeys(id, keys, nodeC);
  certified += standby.certified;
  standby.failed.forEach(function (one) {
    failed.push(one);
  });

  if (failed.length) {
    log.warn(errorCodes.tag('STS-PKI-0031') + 'pki: the "' + id +
             '" realm has ' + certified + ' ' +
             'certified signing key(s) ' +
             'and ' + failed.length + ' that could not be ' +
             'certified: ' + failed.join('; ') + '. Those keys still SIGN — ' +
             'what they lack is a certificate chaining to this service\'s ' +
             'Root.');
  } else {
    log.info('pki: the "' + id + '" realm\'s ' + certified + ' signing keys ' +
             'are certified under its own Intermediate CA — ' + extras.length +
             ' curve key(s) and the RSA key, which is certified twice ' +
             'because it signs both JWTs and XML documents.');
  }
  log.debug('Leaving certifyKeySet(). ' + certified + ' certified.');
  const verdict = { ok: !failed.length, certified: certified, failed: failed };
  log.debug("Leaving certifyKeySet().");
  return failed.length ? errorCodes.mark(verdict, 'STS-PKI-0031') : verdict;
}


// ---------------------------------------------------------------------------
// THE REVOCATION POINTERS EVERY CERTIFICATE THIS SERVICE MINTS CARRIES
// (2026-09-11): where its CRL is, over http and ldap, and where its OCSP
// responder is.
//
// **THE ADDRESSES NAME THE ISSUER AND NOT THE SUBJECT**, which is the thing to
// get right: a certificate's cRLDistributionPoints says where the list that
// would revoke IT is published, and that list belongs to whoever signed it. So
// a leaf under the JOSE Issuing CA points at the JOSE CA's CRL, and the JOSE
// CA's own certificate points at its parent's.
//
// **`common/pki_revocation.js` IS REQUIRED LAZILY AND THAT IS DELIBERATE.**
// That module requires THIS one, so a require at the top of this file would
// close a cycle (rule 2) — node answers one with a half-initialised module
// whose exports are `undefined`, and the symptom would arrive later as
// "distributionPoints is not a function" from inside an issue.
function revocationExtensionsFor(scopeId, caId) {
  log.debug("Entering revocationExtensionsFor().");
  let points = null;
  try {
    points = require('./pki_revocation').distributionPoints(scopeId, caId);
  } catch (e) {
    log.debug("Caught in revocationExtensionsFor(): " +
              ((e && e.message) || e));
    log.debug("Leaving revocationExtensionsFor().");
    // No revocation module in this process. A certificate with no pointers is
    // what this service minted for its whole life until this date, so it is
    // issued exactly as it was rather than refused.
    return {};
  }
  log.debug("Leaving revocationExtensionsFor().");
  return {
    // BOTH SCHEMES, as separate distribution points rather than two names in
    // one. RFC 5280 section 4.2.1.13 makes each DistributionPoint an
    // ALTERNATIVE — a client picks one it can reach — and several names inside
    // ONE point are meant to be different addresses of the SAME list, which is
    // a claim about equivalence this service would rather not make about a
    // list signed on demand and a copy refreshed on a timer.
    //
    // **`ldaps://` WAS A THIRD UNTIL 2026-09-13**, and the HTTP address was
    // https. RFC 5280 section 8 says a CA SHOULD NOT write either scheme into
    // an extension — `common/pki_revocation.js`'s `httpBase()` carries the
    // argument — so the HTTP address names the plain revocation listener and
    // LDAPS is not named at all.
    cRLDistributionPoints: {
      present: true, critical: false,
      urls: [points.http, points.ldap]
    },
    authorityInfoAccess: {
      present: true, critical: false,
      entries: [{ method: 'ocsp', url: points.ocsp },
                // caIssuers: where the certificate that SIGNED this one can be
                // fetched, for a client that was sent an incomplete chain.
                { method: 'caIssuers', url: points.caIssuers }]
    }
  };
}

// ---------------------------------------------------------------------------
// **ANYTHING THIS SERVICE REPLACES GOES ON THE LIST THAT REVOKES IT
// (2026-09-11).**
//
// A rotation that left the old certificate valid would be the most misleading
// thing this hierarchy could do: an operator presses *Reissue* precisely
// because they no longer want the old key trusted, and until this date the
// only thing that happened was that a new certificate appeared beside it. The
// old one went on chaining to the same Root, for its whole validity period,
// with nothing anywhere saying otherwise.
//
// **THE REASON IS ALWAYS `superseded`** (RFC 5280 code 4), which is what the
// word means: a replacement was issued. `keyCompromise` is a different claim
// and only a person can make it, which is why the console's revoke pane asks.
//
// **IT IS REVOKED AT THE ISSUER THAT SIGNED IT**, not at the one replacing it
// — a serial is only unique within one authority, so putting a leaf's serial
// on the Intermediate's list would be an entry no validator ever consults.
// Lazily required for `revocationExtensionsFor()`'s reason.
function supersede(scopeId, caId, tier, note) {
  log.debug("Entering supersede().");
  if (!tier || !tier.serialHex) {
    log.debug("Leaving supersede().");
    return false;
  }
  try {
    const revocation = require('./pki_revocation');
    const done = revocation.revoke(scopeId, caId, {
      serialHex: tier.serialHex,
      reason: 'superseded',
      subject: tier.subject || '',
      note: note || ''
    });
    log.debug("Leaving supersede().");
    return !!done.ok;
  } catch (e) {
    // No revocation module in this process, or it refused. The replacement
    // still happens — a rotation that could be stopped by a bookkeeping
    // failure would be worse than one whose old certificate is not listed.
    log.warn(errorCodes.tag('STS-PKI-0033') + 'pki: ' + (tier.subject || 'a ' +
        'certificate') + ' ' +
             'was replaced and could not be put on a revocation ' +
             'list: ' + e.message);
    log.debug("Leaving supersede().");
    return false;
  }
}

// A PEM somebody pasted, as a PEM every tool will accept. The trim is for the
// textarea it arrives from — browsers add whitespace — and the trailing
// newline is put BACK because a PEM without one is refused by several readers
// that are perfectly happy with everything else about it, and because what is
// stored should be byte-identical to what the same key exports as. Trimming
// and not restoring it was a one-character difference that
// `tests/pki_hierarchy.js` caught by comparing what it supplied with what came
// back.
function tidyPem(text) {
  log.debug("Entering tidyPem().");
  const body = String(text || '').trim();
  log.debug("Leaving tidyPem().");
  return body ? body + '\n' : '';
}

// ===========================================================================
// EDITING THE HIERARCHY (2026-09-11): reissue one authority, renew what hangs
// under it, or replace either with material an operator supplied.
//
// **THE FOUR ARE DELIBERATELY DIFFERENT ACTS AND THE PAGE NAMES THEM APART.**
// They are easy to confuse and the consequences are not alike:
//
//   reissueUseCase()   a NEW KEY for one Issuing CA. Everything it had signed
//                      chains to nothing, so it re-certifies in the same act.
//   recertifyUseCase() the SAME authorities and the same keys, fresh
//                      certificates. A renewal: nothing stops verifying.
//   importCa()         an authority this service did not generate.
//   pinKeyPair()       a LEAF key an operator supplied, used instead of the
//                      one this service would have made.
// ===========================================================================

// Re-mint everything one Issuing CA has certified, from whatever authority it
// now is. Shared by the reissue and the renewal, which differ only in whether
// the authority changed first.
async function recertifyUseCase(scopeId, useCaseId) {
  log.debug('Entering recertifyUseCase(). scope=' + scopeId + ' use=' +
            useCaseId);
  const id = String(scopeId);
  const uc = useCase(useCaseId);
  if (!uc) {
    log.debug("Leaving recertifyUseCase().");
    return errorCodes.mark({ ok: false,
             errors: ['"' + useCaseId + '" is not a use case. They are ' +
                      USE_CASE_IDS.join(', ') + '.'] }, 'STS-PKI-0022');
  }
  const held = certificatesFor(id, uc.id);
  let done = 0;
  const failed = [];
  for (let i = 0; i < held.length; i++) {
    const was = held[i];
    // **THE PUBLIC KEY COMES FROM THE CERTIFICATE THAT IS BEING REPLACED**,
    // which is what makes this a renewal rather than a regeneration: the
    // subject key is read back out of the old certificate, so the new one is
    // over the same key and everything that verifies against the published
    // JWKS goes on verifying.
    //
    // **THE STORED SUBJECT KEY FIRST, WHERE THE RECORD HAS ONE (2026-09-13).**
    // A composite ML-DSA key is one node's OpenSSL cannot read, so the parse
    // below fails for it; the record carries the SubjectPublicKeyInfo it was
    // issued over, which is the same key by construction. The parse stays as
    // the fallback for a record written before that field existed.
    let publicPem = was.subjectPublicKeyPem || '';
    if (!publicPem) {
      try {
        publicPem = new nodeCrypto.X509Certificate(was.certificatePem)
          .publicKey.export({ type: 'spki', format: 'pem' });
      } catch (e) {
        failed.push(was.slot + ': ' + e.message);
        continue;
      }
    }
    const made = await certify(id, uc.id, {
      slot: was.slot, alg: was.alg, keyAlg: was.keyAlg,
      label: was.label, commonName: subjectCnOf(was.subject) || was.slot,
      publicKeyPem: publicPem,
      // A hybrid leaf stays hybrid across a renewal (#68).
      altPublicKeyPem: was.altPublicKeyPem || null,
      pinned: was.pinned, privateKeyPem: was.privateKeyPem,
      publicKeyPemStored: was.publicKeyPem,
      // And a named leaf keeps its names (#230): see `issuedAs` in certify().
      profile: (was.issuedAs && was.issuedAs.profile) || undefined,
      keyUsage: (was.issuedAs && was.issuedAs.keyUsage) || undefined,
      extensions: (was.issuedAs && was.issuedAs.extensions) || undefined
    });
    if (made.ok) {
      done += 1;
      // **THE CERTIFICATE THAT WAS REPLACED IS SUPERSEDED**, even though the
      // KEY is the same one. That is the point: two certificates over one key
      // with different validity windows are two documents, and the older one
      // is no longer what this service publishes — a relying party holding it
      // should be told.
      if (normalSerialsDiffer(was.serialHex, made.record.serialHex)) {
        supersede(id, uc.id, was, 'renewed');
      }
    } else {
      failed.push(was.slot + ': ' + made.errors.join(' '));
    }
  }
  if (failed.length) {
    log.warn(errorCodes.tag('STS-PKI-0032') + 'pki: ' + failed.length + ' ' +
        'certificate(s) under the ' + uc.label +
             ' Issuing CA could not be re-minted: ' + failed.join('; '));
  }
  log.debug('Leaving recertifyUseCase(). ' + done + ' re-minted.');
  return { ok: true, recertified: done, failed: failed };
}

// ---------------------------------------------------------------------------
// A SLOT A MERGE LEFT UNDER AN ISSUING CA THE ROW NO LONGER HOLDS, CERTIFIED
// AGAIN FROM THE ONE IT DOES (2026-09-24). `keystore.js` calls this, through
// `onOrphanedCertificates()`, in the one process whose write merged the row;
// `pki_merge.js`'s orphanedSlots() argues how such a slot arises and why it is
// reported rather than dropped.
//
// **A RENEWAL IN `recertifyUseCase()`'S SENSE, ONE SLOT AT A TIME**: the same
// key, read from the record, and the same key usage, read from the certificate
// being replaced — `certifyKeySet()` gives the RSA key `keyEncipherment`, and
// a re-issue that dropped it would be refused by a strict validator for the
// decryption the key actually does. The kid and a key generation's own slot
// are kept, so the certificate lands where it was. **NOTHING IS REVOKED**: the
// certificate replaced was signed by an Issuing CA the rebuild already
// superseded, whose own list is where it belongs, and `certify()` keeps its
// serial in the issued register (#185).
//
// Asked again per slot before signing, because the slot may have been
// certified from the live CA since the merge — by the rebuild's own re-mint,
// or by a second report of the same merge.
// ---------------------------------------------------------------------------
async function recertifyOrphanedSlots(scopeId, slots) {
  log.debug('Entering recertifyOrphanedSlots(). scope=' + scopeId);
  const id = String(scopeId);
  let done = 0;
  const failed = [];
  for (let i = 0; i < (slots || []).length; i++) {
    const name = String(slots[i]);
    const row = rawRowFor(id) || {};
    const was = (row.certs || {})[name];
    const ca = was ? (row.issuing || {})[was.useCase] : null;
    if (!was || !ca || (was.chainPem || [])[0] === ca.certificatePem) {
      continue;
    }
    let publicPem = was.subjectPublicKeyPem || '';
    if (!publicPem) {
      try {
        publicPem = new nodeCrypto.X509Certificate(was.certificatePem)
          .publicKey.export({ type: 'spki', format: 'pem' });
      } catch (e) {
        failed.push(name + ': ' + e.message);
        continue;
      }
    }
    let usages = null;
    try {
      usages = await keyUsageOf({ pem: was.certificatePem });
    } catch (e) {
      log.debug("Caught in recertifyOrphanedSlots(): " +
                ((e && e.message) || e));
      usages = null;
    }
    const made = await certify(id, was.useCase, {
      slot: was.slot, alg: was.alg, keyAlg: was.keyAlg,
      kid: was.kid || '',
      generationSlot: name !== slotKey(was.useCase, was.slot),
      label: was.label, commonName: subjectCnOf(was.subject) || was.slot,
      publicKeyPem: publicPem,
      altPublicKeyPem: was.altPublicKeyPem || null,
      keyUsage: usages && usages.length ? usages : undefined,
      pinned: was.pinned, privateKeyPem: was.privateKeyPem,
      publicKeyPemStored: was.publicKeyPem
    });
    if (made.ok) {
      done += 1;
    } else {
      failed.push(name + ': ' + made.errors.join(' '));
    }
  }
  if (failed.length) {
    log.warn(errorCodes.tag('STS-PKI-0193') + 'pki: ' + failed.length +
             ' certificate(s) of "' + (id || 'default') + '" left under an ' +
             'Issuing CA it no longer holds could not be certified again: ' +
             failed.join('; '));
  } else if (done) {
    log.info('pki: ' + done + ' certificate(s) of "' + (id || 'default') +
             '" that a merge left under an Issuing CA it no longer holds ' +
             'were certified again from the live one.');
  }
  log.debug('Leaving recertifyOrphanedSlots(). ' + done + ' re-minted.');
  return { ok: !failed.length, recertified: done, failed: failed };
}

keystore.onOrphanedCertificates(function (scopeId, slots) {
  Promise.resolve(recertifyOrphanedSlots(scopeId, slots)).catch(function (e) {
    log.error(errorCodes.tag('STS-PKI-0193') + 'pki: the certificates of "' +
              (scopeId || 'default') + '" left under an Issuing CA it no ' +
              'longer holds could not be certified again: ' +
              ((e && e.message) || e));
  });
});

// Two serials that are not the same certificate. Written out because a renewal
// that produced an identical serial — which cannot happen, but a future
// caller-supplied serial could — would otherwise revoke the certificate it had
// just issued.
// The scope the ROOT's own revocation list lives in, which is the service row.
// A function rather than the constant inline so that the one place this is
// asked reads as a question about where a list lives.
function pki_rootScopeOf() {
  log.debug("Entering pki_rootScopeOf().");
  log.debug("Leaving pki_rootScopeOf().");
  return SERVICE_SCOPE;
}

function normalSerialsDiffer(a, b) {
  log.debug("Entering normalSerialsDiffer().");
  const tidy = function (one) {
    log.debug("Entering tidy().");
    log.debug("Leaving tidy().");
    return String(one || '').toLowerCase().replace(/[^0-9a-f]/g, '')
      .replace(/^0+/, '');
  };
  log.debug("Leaving normalSerialsDiffer().");
  return tidy(a) !== tidy(b);
}

// The CN out of a subject string, so a renewal keeps the name the certificate
// had rather than falling back to the slot.
function subjectCnOf(subject) {
  log.debug("Entering subjectCnOf().");
  const found = /CN=([^,\n]+)/.exec(String(subject || ''));
  log.debug("Leaving subjectCnOf().");
  return found ? found[1].trim() : '';
}

// A NEW KEY for one Issuing CA, and everything under it re-certified from it.
async function reissueUseCase(scopeId, useCaseId) {
  log.debug('Entering reissueUseCase(). scope=' + scopeId + ' use=' +
            useCaseId);
  const id = String(scopeId);
  const uc = useCase(useCaseId);
  if (!uc) {
    log.debug("Leaving reissueUseCase().");
    return errorCodes.mark({ ok: false,
             errors: ['"' + useCaseId + '" is not a use case. They are ' +
                      USE_CASE_IDS.join(', ') + '.'] }, 'STS-PKI-0022');
  }
  const row = rawRowFor(id);
  if (!row || !row.intermediate) {
    log.debug("Leaving reissueUseCase().");
    return errorCodes.mark({ ok: false,
             errors: ['That scope has no Intermediate CA to issue from. ' +
                      'Build its branch first.'] }, 'STS-PKI-0034');
  }
  if (useCasesFor(scopeKindOf(id)).every(function (
      one) { return one.id !== uc.id; })) {
    log.debug("Leaving reissueUseCase().");
    // Refused rather than built: a `tls` Issuing CA under a realm's
    // Intermediate would be a realm vouching for a socket every realm answers
    // on, which is the reason the use cases carry a scope at all.
    return errorCodes.mark({ ok: false,
             errors: ['The ' + uc.label + ' use case belongs to the ' +
                      uc.scope + ' scope and not to this one. ' +
                      (uc.scope === 'process'
                        ? 'It is under the process Intermediate, because the ' +
                          'sockets it certifies are shared by every realm.'
                        : 'It is under a realm\'s Intermediate.')] },
                           'STS-PKI-0035');
  }
  let made;
  try {
    made = await issueCaTier({
      tier: 'issuing', profile: 'issuing-ca', label: uc.label + ' CA',
      useCase: uc.id, scope: id,
      cn: (row.organisation || DEFAULT_ORGANISATION) + ' ' + uc.cn + ' (' +
          (scopeKindOf(id) === 'process' ? 'Process' : (id || 'default')) + ')',
      organisation: row.organisation || DEFAULT_ORGANISATION,
      country: row.country || '',
      // **THE ALGORITHM THIS AUTHORITY ALREADY HAD, not the branch's.** A
      // reissue replaces a key and nothing else; taking `row.keyAlg` here
      // would silently turn an EC SPIFFE authority into an RSA one on the
      // first rotation, which is a change of SVID signature algorithm that
      // nobody asked for and nothing would report.
      keyAlg: (row.issuing[uc.id] || {}).keyAlg || row.keyAlg,
      signatureAlg: (row.issuing[uc.id] || {}).signatureAlg ||
                    row.signatureAlg,
      // And the ALTERNATIVE algorithm it already had (#68), for the same
      // reason: null stays classical, a key stays the same family. A tier
      // built before the field existed takes the branch's, then the setting.
      altKeyAlg: ((row.issuing[uc.id] || {}).altKeyAlg !== undefined)
        ? row.issuing[uc.id].altKeyAlg : row.altKeyAlg,
      // The same `pathLen` the branch build gives it. Left off here for a day
      // and it is the kind of omission nothing reports: the reissued SPIFFE
      // authority came back at `pathLen: 0`, every SVID went on verifying, and
      // only `NewDownstreamX509CA` broke.
      pathLen: issuingPathLen(uc.id),
      parent: row.intermediate
    });
  } catch (e) {
    log.error(errorCodes.tag('STS-PKI-0036') + 'pki: the ' + uc.label + ' ' +
        'Issuing CA could not be re-issued: ' +
              e.message);
    log.debug("Leaving reissueUseCase().");
    return errorCodes.mark({ ok: false,
             errors: ['That Issuing CA could not be re-issued: ' + e.message] },
                           'STS-PKI-0036');
  }
  // THE OLD AUTHORITY IS SUPERSEDED, at the Intermediate that signed it — and
  // so is everything it had issued, at the old authority itself. Both are
  // done BEFORE the new one is stored, because `supersede()` reads the row and
  // the old certificates are what is being listed.
  supersede(id, 'intermediate', row.issuing[uc.id],
            'replaced by a reissue of the ' + uc.label + ' Issuing CA');
  certificatesFor(id, uc.id).forEach(function (one) {
    supersede(id, uc.id, one,
              'its issuing authority was reissued, so this certificate ' +
              'chains to an authority that no longer exists');
  });
  const fresh = rawRowFor(id);
  fresh.issuing = Object.assign({}, fresh.issuing || {});
  fresh.issuing[uc.id] = made;
  saveRow(id, fresh);
  const again = await recertifyUseCase(id, uc.id);
  log.info('pki: the ' + uc.label + ' Issuing CA in "' + (id || 'default') +
           '" was re-issued with a new key pair, and ' + again.recertified +
           ' certificate(s) under it were re-minted from it.');
  log.debug('Leaving reissueUseCase().');
  return { ok: true, recertified: again.recertified,
           ca: describeTier(made) };
}

// ---------------------------------------------------------------------------
// AN AUTHORITY THIS SERVICE DID NOT GENERATE.
//
// `useCaseId` of `root` replaces the service Root; anything else replaces one
// scope's Issuing CA. **Both are checked before anything is stored**: a CA
// whose certificate and key do not go together is a hierarchy that builds
// perfectly and issues certificates nothing can verify, and the failure would
// arrive at somebody else's relying party.
// ---------------------------------------------------------------------------
async function importCa(scopeId, useCaseId, material) {
  log.debug('Entering importCa(). scope=' + scopeId + ' use=' + useCaseId);
  const certificatePem = tidyPem((material || {}).certificatePem);
  const privateKeyPem = tidyPem((material || {}).privateKeyPem);
  if (!certificatePem || !privateKeyPem) {
    log.debug("Leaving importCa().");
    return errorCodes.mark({ ok: false,
             errors: ['Both the certificate and its private key are needed. ' +
                      'A certificate without its key is a trust anchor ' +
                      'rather than an authority — this service cannot issue ' +
                      'from it.'] }, 'STS-PKI-0037');
  }
  let cert;
  try {
    cert = new nodeCrypto.X509Certificate(certificatePem);
  } catch (e) {
    log.debug("Leaving importCa().");
    return errorCodes.mark({ ok: false,
             errors: ['That certificate could not be read: ' + e.message] },
                           'STS-PKI-0038');
  }
  let key;
  try {
    key = nodeCrypto.createPrivateKey(privateKeyPem);
  } catch (e) {
    log.debug("Leaving importCa().");
    return errorCodes.mark({ ok: false,
             errors: ['That private key could not be read: ' + e.message] },
                           'STS-PKI-0039');
  }
  // **THE PAIR HAS TO MATCH, AND THIS IS THE CHECK THAT MATTERS.** node
  // answers it directly, and without it an authority whose key belongs to a
  // different certificate would be stored, would issue, and would produce
  // certificates whose signature verifies against nothing.
  if (!cert.checkPrivateKey(key)) {
    log.debug("Leaving importCa().");
    return errorCodes.mark({ ok: false,
             errors: ['That private key does not belong to that certificate. ' +
                      'An authority whose key and certificate do not go ' +
                      'together issues certificates that verify nowhere, and ' +
                      'the failure arrives at somebody else\'s relying party.'] }, 'STS-PKI-0040');
  }
  if (!cert.ca) {
    log.debug("Leaving importCa().");
    return errorCodes.mark({ ok: false,
             errors: ['That certificate is not a CA — its basicConstraints ' +
                      'says cA:FALSE, so nothing it signs will be accepted ' +
                      'by a path validator. A leaf cannot be an issuing ' +
                      'authority.'] }, 'STS-PKI-0041');
  }
  const desc = await keyMaterial.describePublicPem(
    cert.publicKey.export({ type: 'spki', format: 'pem' }));
  const record = {
    tier: useCaseId === 'root' ? 'root' : 'issuing',
    useCase: useCaseId === 'root' ? null : useCaseId,
    label: useCaseId === 'root' ? 'Root CA'
                                : ((useCase(useCaseId) ||
                                    {}).label || useCaseId) + ' ' +
                                    'CA',
    scope: String(scopeId),
    keyAlg: (desc && desc.id) || '',
    signatureAlg: defaultSignatureAlgorithmFor((desc && desc.id) || ''),
    subject: cert.subject.replace(/\n/g, ', '),
    serialHex: cert.serialNumber,
    notBefore: new Date(cert.validFrom).toISOString(),
    notAfter: new Date(cert.validTo).toISOString(),
    certificatePem: certificatePem,
    privateKeyPem: privateKeyPem,
    publicKeyPem: cert.publicKey.export({ type: 'spki', format: 'pem' }),
    thumbprint: thumbprintOf(certificatePem),
    imported: true,
    createdAt: Date.now()
  };
  if (useCaseId === 'root') {
    const row = serviceRow() || {};
    keystore.attachPki(SERVICE_SCOPE, Object.assign({}, row, {
      version: 2, scope: SERVICE_SCOPE, root: record,
      organisation: row.organisation || DEFAULT_ORGANISATION,
      keyAlg: record.keyAlg, signatureAlg: record.signatureAlg,
      createdAt: Date.now()
    }));
    log.warn('pki: THE SERVICE ROOT WAS REPLACED BY AN IMPORTED CA — ' +
             record.subject + '. Every branch must be rebuilt under it or ' +
             'the tree does not chain to its own anchor.');
    log.debug("Leaving importCa().");
    return { ok: true, imported: describeTier(record),
             why: 'That CA is now this service\'s Root. **EVERY BRANCH MUST ' +
                  'BE REBUILT UNDER IT** — the Intermediates still hanging ' +
                  'from the old Root chain to nothing, and until they are ' +
                  'rebuilt every path check in this service fails. Press ' +
                  'Rebuild on each scope below.' };
  }
  const uc = useCase(useCaseId);
  if (!uc) {
    log.debug("Leaving importCa().");
    return errorCodes.mark({ ok: false,
             errors: ['"' + useCaseId + '" is not a use case, and `root` is ' +
                      'the only other thing that can be imported. The use ' +
                      'cases are ' + USE_CASE_IDS.join(', ') + '.'] },
                           'STS-PKI-0022');
  }
  const row = rawRowFor(scopeId);
  if (!row || !row.intermediate) {
    log.debug("Leaving importCa().");
    return errorCodes.mark({ ok: false,
             errors: ['That scope has no branch yet. Build it first — an ' +
                      'Issuing CA is imported INTO a branch.'] },
                           'STS-PKI-0034');
  }
  row.issuing = Object.assign({}, row.issuing || {});
  row.issuing[uc.id] = record;
  saveRow(scopeId, row);
  const again = await recertifyUseCase(scopeId, uc.id);
  log.warn('pki: the ' + uc.label + ' Issuing CA in "' +
           (String(scopeId) || 'default') + '" was REPLACED BY AN IMPORTED ' +
           'CA — ' + record.subject + '. ' + again.recertified +
           ' certificate(s) were re-minted from it.');
  log.debug('Leaving importCa(). Imported.');
  return { ok: true, imported: describeTier(record),
           why: 'That CA is now the ' + uc.label + ' authority for this ' +
                'scope, and ' + again.recertified + ' certificate(s) were ' +
                're-minted from it. **IT IS NOT UNDER THIS SERVICE\'S ROOT** ' +
                'unless you issued it from one — so what it signs chains to ' +
                'YOUR anchor, which is the point of importing one, and this ' +
                'service\'s own Root no longer covers those certificates.' };
}

// ---------------------------------------------------------------------------
// A LEAF KEY PAIR AN OPERATOR SUPPLIED, used instead of the one this service
// would have generated.
//
// **THE CERTIFICATE IS OPTIONAL AND THAT IS THE INTERESTING HALF.** With one,
// the pair is used exactly as it was handed over — key and certificate
// together, chaining wherever the operator's own authority chains. Without
// one, this service ISSUES a certificate over the supplied public key from the
// use case's Issuing CA, which is what somebody who wants their own key under
// this service's Root is asking for.
// ---------------------------------------------------------------------------
async function pinKeyPair(scopeId, useCaseId, slot, material) {
  log.debug('Entering pinKeyPair(). scope=' + scopeId + ' use=' + useCaseId +
            ' slot=' + slot);
  const uc = useCase(useCaseId);
  if (!uc) {
    log.debug("Leaving pinKeyPair().");
    return errorCodes.mark({ ok: false,
             errors: ['"' + useCaseId + '" is not a use case. They are ' +
                      USE_CASE_IDS.join(', ') + '.'] }, 'STS-PKI-0022');
  }
  if (!slot) {
    log.debug("Leaving pinKeyPair().");
    return errorCodes.mark({ ok: false,
             errors: ['Name the slot this key pair is for — the algorithm, ' +
                      'as it appears in the certified list (RS256, ' +
                      'ES256:P-256 and so on).'] }, 'STS-PKI-0042');
  }
  const privateKeyPem = tidyPem((material || {}).privateKeyPem);
  if (!privateKeyPem) {
    log.debug("Leaving pinKeyPair().");
    return errorCodes.mark({ ok: false, errors: ['A private key is needed.'] },
                           'STS-PKI-0043');
  }
  let key;
  let publicKeyPem;
  try {
    key = nodeCrypto.createPrivateKey(privateKeyPem);
    publicKeyPem = nodeCrypto.createPublicKey(key)
      .export({ type: 'spki', format: 'pem' });
  } catch (e) {
    log.debug("Leaving pinKeyPair().");
    return errorCodes.mark({ ok: false,
             errors: ['That private key could not be read: ' + e.message] },
                           'STS-PKI-0039');
  }
  const certificatePem = tidyPem((material || {}).certificatePem);
  if (certificatePem) {
    let cert;
    try {
      cert = new nodeCrypto.X509Certificate(certificatePem);
    } catch (e) {
      log.debug("Leaving pinKeyPair().");
      return errorCodes.mark({ ok: false,
               errors: ['That certificate could not be read: ' + e.message] },
                             'STS-PKI-0038');
    }
    if (!cert.checkPrivateKey(key)) {
      log.debug("Leaving pinKeyPair().");
      return errorCodes.mark({ ok: false,
               errors: ['That private key does not belong to that ' +
                        'certificate.'] }, 'STS-PKI-0040');
    }
    const row = rawRowFor(scopeId) || {};
    row.certs = Object.assign({}, row.certs || {});
    row.certs[slotKey(uc.id, slot)] = {
      slot: String(slot), useCase: uc.id, scope: String(scopeId),
      label: 'your ' + slot + ' key', alg: String(slot).split(':')[0],
      keyAlg: '', signatureAlg: '',
      subject: cert.subject.replace(/\n/g, ', '),
      serialHex: cert.serialNumber,
      notBefore: new Date(cert.validFrom).toISOString(),
      notAfter: new Date(cert.validTo).toISOString(),
      certificatePem: certificatePem,
      chainPem: [],
      thumbprint: thumbprintOf(certificatePem),
      pinned: true,
      privateKeyPem: privateKeyPem,
      publicKeyPem: publicKeyPem,
      createdAt: Date.now()
    };
    saveRow(scopeId, row);
    log.warn('pki: a key pair supplied by an operator is now the ' + uc.label +
             ' key for "' + slot + '" in "' + (String(scopeId) || 'default') +
             '", with a certificate they supplied too. It does NOT chain to ' +
             'this service\'s Root.');
    log.debug('Leaving pinKeyPair(). Pinned with a certificate.');
    return { ok: true,
             why: 'That key pair and its certificate are now what this ' +
                  'service uses for ' + uc.label + ' / ' + slot + '. **IT ' +
                  'DOES NOT CHAIN TO THIS SERVICE\'S ROOT** — it chains ' +
                  'wherever the certificate you supplied chains, which is ' +
                  'what supplying one means.' };
  }
  // No certificate: issue one over the supplied key from this scope's own
  // authority, which is what somebody who wants THEIR key under THIS service's
  // Root is asking for.
  const made = await certify(scopeId, uc.id, {
    slot: String(slot), alg: String(slot).split(':')[0],
    label: 'your ' + slot + ' key',
    commonName: uc.label + ' (' + slot + ', supplied key)',
    publicKeyPem: publicKeyPem,
    pinned: true, privateKeyPem: privateKeyPem, publicKeyPemStored: publicKeyPem
  });
  if (!made.ok) {
    log.debug('Leaving pinKeyPair(). The certification failed.');
    return made;
  }
  log.warn('pki: a key pair supplied by an operator is now the ' + uc.label +
           ' key for "' + slot + '" in "' + (String(scopeId) || 'default') +
           '", certified under this service\'s own ' + uc.label +
           ' Issuing CA.');
  log.debug('Leaving pinKeyPair(). Pinned and certified.');
  return { ok: true,
           why: 'That key pair is now what this service uses for ' + uc.label +
                ' / ' + slot + ', and it was CERTIFIED under this scope\'s ' +
                uc.label + ' Issuing CA — so it chains to this service\'s ' +
                'Root exactly as a key this service generated would.' };
}

// ---------------------------------------------------------------------------
// KEY MATERIAL THAT IS NOT A REALM'S KEY SET, AND HOW IT GETS CERTIFIED.
//
// The signing keys are handed to `certifyKeySet()` by the one module that owns
// them. Everything else this service generates belongs to a module of its own
// — the TLS server certificates `tls/tls_server.js` makes, and whatever comes
// after them — and those modules REGISTER what they have here rather than
// being reached into.
//
// **IT IS A REGISTRATION AND NOT A REQUIRE, and rule 3e's test is why.** A
// `require('../tls/tls_server')` from this module would drag every `/tls`
// route into the router at whatever position this file is first required from
// — which is inside `common/app.js`'s own requires (through
// `revocation_status.js`), above everything. This file is a LEAF and must
// stay one.
//
// A registration carries a `publicKeyPem` FUNCTION rather than a string,
// because the material it names may not exist when the module registers: the
// TLS certificate is made lazily and `start()` is what asks for it.
// ---------------------------------------------------------------------------
const certifiable = [];

function registerCertifiable(spec) {
  log.debug('Entering registerCertifiable(). ' + (spec && spec.useCase) + '/' +
            (spec && spec.slot));
  if (!spec || !useCase(spec.useCase) || !spec.slot ||
      typeof spec.publicKeyPem !== 'function') {
    log.error(errorCodes.tag('STS-PKI-0044') + 'pki: a key registration was ' +
              'refused — it needs a known use case, a slot and a ' +
              'publicKeyPem function. Got ' +
              JSON.stringify({ useCase: spec && spec.useCase,
                               slot: spec && spec.slot }) + '.');
    log.debug("Leaving registerCertifiable().");
    return false;
  }
  certifiable.push(spec);
  log.debug('Leaving registerCertifiable(). ' + certifiable.length +
            ' registration(s).');
  return true;
}

// Certify everything registered. Called from `start()`, before anything binds,
// which is what lets the main port and LDAPS open with a certificate that
// already chains to this service's Root rather than swapping one in afterwards.
//
// `opts.repairBranch === false` (2026-09-13) is handed to `certify()` for
// every registration: a branch that no longer chains to the Root is then left
// for the process rebuilding it rather than rebuilt here. See the block at the
// top of `certify()`; `tls_server.js`'s `reconcileWithHierarchy()` is the one
// caller that passes it.
async function certifyRegistered(opts) {
  log.debug('Entering certifyRegistered(). ' + certifiable.length +
            ' registration(s).');
  const repairBranch = !(opts && opts.repairBranch === false);
  let done = 0;
  for (let i = 0; i < certifiable.length; i++) {
    const one = certifiable[i];
    const scope = one.scope || PROCESS_SCOPE;
    let publicPem = '';
    try {
      publicPem = one.publicKeyPem();
    } catch (e) {
      log.error(errorCodes.tag('STS-PKI-0045') + 'pki: the ' + one.useCase +
          ' ' +
          'key "' + one.slot + '" ' +
                'could not be read to certify it: ' + e.message);
      continue;
    }
    if (!publicPem) {
      log.debug('certifyRegistered(): ' + one.slot + ' has no key yet.');
      continue;
    }
    const made = await certify(scope, one.useCase, {
      slot: one.slot,
      alg: one.alg || '',
      keyAlg: one.keyAlg || '',
      label: one.label || one.slot,
      commonName: one.commonName || one.slot,
      publicKeyPem: publicPem,
      profile: one.profile,
      keyUsage: one.keyUsage,
      extensions: one.extensions,
      repairBranch: repairBranch
    });
    if (!made.ok && made.deferred) {
      // Not a failure: `certify()` has said why at info, and the caller asks
      // again when the branch it is waiting for arrives.
      continue;
    }
    if (!made.ok) {
      log.error(errorCodes.tag('STS-PKI-0046') + 'pki: the ' + one.useCase +
          ' ' +
          'key "' + one.slot + '" ' +
                'could not be ' +
                'certified: ' + made.errors.join(' ') + ' It still ' +
                'works — what it lacks is a certificate chaining to this ' +
                'service\'s Root.');
      continue;
    }
    done += 1;
    if (typeof one.onCertified === 'function') {
      try {
        one.onCertified(made.record.certificatePem,
                        made.record.chainPem.slice());
      } catch (e) {
        log.error(errorCodes.tag('STS-PKI-0047') + 'pki: the ' + one.useCase +
            ' ' +
            'key "' + one.slot + '" ' +
                  'was certified and the module that owns it threw on being ' +
                  'told: ' +
                  e.message);
      }
    }
  }
  log.debug('Leaving certifyRegistered(). ' + done + ' certified.');
  return done;
}

// ---------------------------------------------------------------------------
// WHAT `common/service_state.ts` CALLS (for `server.js` and for a request
// worker alike), after `keystore.start()` and before anything binds.
//
// **IT IS NEVER FATAL.** `persistence.start()` is the one place in this
// repository where a failure to open something stops the process, and its own
// header argues why it is the only one: a service that cannot reach its store
// answers WRONGLY. A service whose certificate authority could not be built
// answers correctly with self-signed keys, which is what this service did for
// its whole life until today — so a failure here is logged loudly and the
// service starts.
// ---------------------------------------------------------------------------
// The key-set provider `start()` was given, kept so that the realm watcher
// below can certify a realm created at RUNTIME. It is not a second mechanism:
// it is the same function, remembered, because the watcher fires long after
// the call that supplied it. See the `keySetFor` note in `start()` for why
// this module does not simply require `helpers.js`.
let keySetProvider = null;
// ---------------------------------------------------------------------------
// AND "DOES THIS PROCESS ALREADY HOLD THAT REALM'S KEYS", WHICH IS A DIFFERENT
// QUESTION FROM "GIVE ME THEM" (2026-09-12).
//
// **THE WATCHER BELOW SAID IT ASKED THE FIRST AND ASKED THE SECOND**, and in a
// dispatched service that cost a measurable defect rather than a wasted key
// generation — see the block at the `realms.onChange()` handler. `keySetFor()`
// is `helpers.stsKeysFor.of()`, which MAKES a key set when there is none; this
// one answers whether there is one and makes nothing.
//
// Absent — a caller that supplied only `keySetFor` — the watcher certifies
// NOTHING at realm-creation time and leaves the whole job to `helpers.js`'s
// `certifyLater()`, which is the direction that cannot race. That is the safe
// default on purpose: the failure mode of not asking is a certificate arriving
// a few milliseconds later, and the failure mode of asking wrongly is four
// processes holding four different signing keys for one realm.
// ---------------------------------------------------------------------------
let keySetHeldProvider = null;

async function start(opts) {
  log.debug('Entering pki.start().');
  const options = opts || {};
  if (typeof options.keySetFor === 'function') {
    keySetProvider = options.keySetFor;
  }
  if (typeof options.keySetHeldFor === 'function') {
    keySetHeldProvider = options.keySetHeldFor;
  }
  if (config.value('pki.autoBuild') === false) {
    log.info('pki: `pki.autoBuild` is off, so no certificate authority is ' +
             'built at startup and this service\'s own keys are self-signed ' +
             'until somebody presses Build on /admin/pki. That is what this ' +
             'service did before 2026-09-11.');
    log.debug('Leaving pki.start(). Switched off.');
    return { ok: true, built: false };
  }
  const rooted = await ensureRoot({
    organisation: config.value('pki.organisation')
  });
  if (!rooted.ok) {
    log.error(errorCodes.tag('STS-PKI-0048') + 'pki: THE SERVICE HAS NO ROOT ' +
                                               'CA ' +
                                               '— ' + rooted.errors.join(' ') +
              ' Every key this service holds will be self-signed, which is ' +
              'what it did before 2026-09-11. Nothing else is affected.');
    log.debug('Leaving pki.start(). No Root.');
    return { ok: false, built: false, errors: rooted.errors };
  }
  // The process branch, for what belongs to no realm: TLS. (SPIFFE was here
  // too until its authority became realm-scoped.)
  const process = await ensureScope(PROCESS_SCOPE);
  if (!process.ok) {
    log.error(errorCodes.tag('STS-PKI-0049') + 'pki: the process branch ' +
                                               'could not be built — ' +
              (process.errors || []).join(' '));
  }
  // Every realm that exists NOW. A realm created later is caught by
  // `realms.onChange()`, which `helpers.js` wires up.
  const realmIds = (options.realmIds || []).slice();
  if (realmIds.indexOf('') < 0) {
    realmIds.unshift('');
  }
  let branches = 0;
  for (let i = 0; i < realmIds.length; i++) {
    const made = await ensureScope(realmIds[i]);
    if (made.ok) {
      branches += 1;
    } else {
      log.error(errorCodes.tag('STS-PKI-0050') + 'pki: the "' +
                (realmIds[i] || 'default') + '" ' +
                'realm\'s branch could not be built — ' +
                (made.errors || []).join(' '));
    }
  }
  // -------------------------------------------------------------------------
  // AND CERTIFY THE DEFAULT REALM'S KEYS HERE, BEFORE THE LISTENER BINDS.
  //
  // Every other realm's keys are certified when they are generated — lazily,
  // on first use, from `helpers.js`'s `certifyLater()`. The default realm is
  // the exception and it is the one worth making: it is the realm every
  // process has and every protocol answers in, so certifying it here means
  // there is no window at all in which this service publishes a self-signed
  // certificate to anybody.
  //
  // **A KEY-SET PROVIDER IS PASSED IN RATHER THAN REQUIRED**, because this
  // module must not require `helpers.js`: that file reaches for THIS one from
  // inside a property read (lazily, so there is no cycle), and a require in
  // the other direction at load time would put a certificate authority in
  // front of every in-process caller of helpers — the parent project's
  // Kerberos jobs among them.
  // -------------------------------------------------------------------------
  // Everything a module registered — the TLS server certificates, today.
  // Before the listener binds, so the socket opens with a certificate that
  // already chains rather than one swapped in afterwards.
  const registered = await certifyRegistered();
  let certified = registered;
  if (typeof options.keySetFor === 'function') {
    try {
      const keys = options.keySetFor('');
      if (keys) {
        const done = await certifyKeySet('', keys);
        certified += done.certified || 0;
      }
    } catch (e) {
      log.error(errorCodes.tag('STS-PKI-0051') + 'pki: the default realm\'s ' +
                'signing keys could not be ' +
                'certified: ' + e.message + '. They still SIGN — what they ' +
                'lack is a certificate chaining to this service\'s Root.');
    }
  }
  log.info('pki: the certificate authority is ready — one Root CA for the ' +
           'service, a process Intermediate, and ' + branches + ' realm ' +
           'branch(es). Every key pair this service generates is a leaf of ' +
           'it' +
           (certified ? ', and the default realm\'s ' + certified +
                        ' signing keys are certified under it' : '') + '.');
  // -------------------------------------------------------------------------
  // AND A REALM CREATED AFTERWARDS GETS A BRANCH TOO.
  //
  // `start()` builds what exists when it runs; a realm made at RUNTIME —
  // through `/admin/realms` or `POST /admin-api/realms/create` — appears after
  // it. Without this it would have no Intermediate, so its keys would be
  // certified by nothing and would publish the self-signed certificates they
  // were born with for ever, silently, while every realm created before it
  // chained correctly. That is exactly the kind of difference nobody looks
  // for.
  //
  // **IT IS SUBSCRIBED HERE AND NOT AT REQUIRE TIME**, which is the same
  // decision `persistence.js` makes about its own `realms.onChange()`
  // subscription read one way and the opposite the other: that module
  // subscribes when it is required, and this one when the SERVICE STARTS —
  // because `npm test`, the parent project's in-process Kerberos jobs and the
  // remote PEP container all require this file and none of them wants a
  // certificate authority built under a realm a test happened to create.
  // -------------------------------------------------------------------------
  watchRealms();
  // -------------------------------------------------------------------------
  // AND PUBLISH A CRL FOR EVERY AUTHORITY, INTO THE DIRECTORY, ONCE.
  //
  // Every certificate above names an `ldap://` distribution
  // point as well as an `http://` one, and a client that follows the `ldap://`
  // one reaches the embedded directory — where, until this line ran,
  // there was NO ENTRY AT ALL. An address published inside a certificate that
  // answers `LDAP_NO_SUCH_OBJECT` is worse than one that was never named: a
  // client configured to require a fresh CRL refuses the certificate, and the
  // reason it gives is about the directory rather than about revocation.
  //
  // The HTTP endpoint needs nothing of the kind — it builds on demand — and
  // that asymmetry is the point: a CRL is a DOCUMENT in LDAP and a RESPONSE
  // over HTTP, so one has to be put somewhere and the other does not.
  //
  // It is lazily required for `revocationExtensionsFor()`'s reason — that
  // module requires this one, so a require at load time would close a cycle
  // (rule 2) — and a failure is logged and never fatal: a service whose
  // directory would not take a CRL is a service that still issues.
  // -------------------------------------------------------------------------
  try {
    const published = await require('./pki_revocation')
      .publishAll([PROCESS_SCOPE].concat(realmIds));
    if (published) {
      log.info('pki: ' + published + ' certificate revocation ' +
               'list(s) were published into the directory, one per ' +
               'authority, at the `ldap://` address every ' +
               'certificate this service issues names.');
    }
    // ONCE was the word above and it was the defect: every list expires after
    // `pki.crlLifetimeMinutes`, and the directory copy was never replaced.
    // See `keepDirectoryCurrent()`.
    require('./pki_revocation').keepDirectoryCurrent();
  } catch (e) {
    log.error(errorCodes.tag('STS-PKI-0052') + 'pki: the revocation lists ' +
              'could not be published into the ' +
              'directory: ' + e.message + '. The HTTP distribution point ' +
              'still answers; the LDAP one does not.');
  }
  log.debug('Leaving pki.start(). ' + branches + ' realm branch(es), ' +
            certified + ' key(s) certified.');
  return { ok: true, built: true, branches: branches, certified: certified };
}

// Subscribe once. A second subscription would build a realm's branch twice —
// harmless, because `ensureScope()` is idempotent, and still two log lines
// saying a thing happened that happened once.
let watching = false;

function watchRealms() {
  log.debug("Entering watchRealms().");
  if (watching || typeof realms.onChange !== 'function') {
    log.debug("Leaving watchRealms().");
    return;
  }
  watching = true;
  // **THE ARGUMENTS ARE `(id, what)` AND NOT `(what, realm)`.** Written the
  // other way round it subscribes successfully, fires on every change and
  // matches nothing — a realm created at runtime gets no branch and there is
  // no error anywhere, which is the shape of defect this watcher exists to
  // prevent in the first place.
  realms.onChange(function (realmId, what, info) {
    if (what !== 'create' || !realmId) {
      return;
    }
    // -----------------------------------------------------------------
    // **A REALM THAT ARRIVED FROM ANOTHER PROCESS IS NOT BUILT HERE
    // (2026-09-12).** `persistence.js` restores a replicated realm through
    // `realms.create()`, so this watcher fired in EVERY process that learnt
    // of a new realm — and each built a branch of its own and published it,
    // last write winning. The process that created the realm had usually
    // issued from its branch by then, so the same "not signed by an Issuing
    // CA of that name" came back across processes that `oneBuildAtATime()`
    // removes within one. The branch is the creating process's to build;
    // the others adopt it over `keystore`'s PKI channel, which is immediate
    // where replication takes up to `persistence.pollInterval`. A process
    // that needs the branch before it arrives still gets one from
    // `ensureScope()` — an explicit ask, which is a different matter from a
    // watcher answering an event every process sees.
    // -----------------------------------------------------------------
    if (info && info.restored) {
      log.debug('pki: the "' + realmId + '" realm arrived from the store or ' +
                'another process; its branch is that process\'s to build.');
      return;
    }
    const id = realmId === realms.DEFAULT_ID ? '' : String(realmId);
    // ASYNCHRONOUS AND NOT AWAITED, for `helpers.js`'s `certifyLater()`
    // reason: a listener runs inside whatever act created the realm, and a
    // realm creation must not block on nine signatures. A failure is logged
    // by the builder and the realm exists either way — with self-signed keys,
    // which is what every realm had before this existed.
    Promise.resolve(ensureScope(id)).then(function (made) {
      if (!made.ok) {
        log.error(errorCodes.tag('STS-PKI-0053') + 'pki: the "' + id + '" ' +
                  'realm was created and its certificate authority branch ' +
                  'could not be built — ' +
                  (made.errors || []).join(' ') + ' Its keys will publish ' +
                  'the self-signed certificates they were born with.');
        return null;
      }
      if (made.existing || typeof keySetProvider !== 'function') {
        return null;
      }
      // ---------------------------------------------------------------
      // AND ITS KEYS — **IF THEY HAVE BEEN GENERATED ALREADY, WHICH IS
      // WHAT THIS COMMENT SAID WHILE THE LINE BELOW IT DID THE OPPOSITE
      // (2026-09-12).**
      //
      // `keySetProvider` is `helpers.stsKeysFor.of()`, and that MAKES a
      // key set when the process has none. So this line did not certify a
      // realm's keys, it CREATED them — in every process that saw the
      // realm appear, which in a dispatched service is the front process
      // and every request worker.
      //
      // **MEASURED, on a `--modes=dispatch` run of the whole suite:** a
      // realm created at 17:48:47.995 had FOUR key sets in four processes
      // within 95ms — kids 7223b2499bdb (pid 33), 5adaac82b8f3 (pid 40),
      // 2865074f6ea8 (pid 1) and ee9c19ca8208 (pid 34) — each generated,
      // each written to `sts_keys`, and each then arbitrated away by
      // `request_pool.js`'s first-generator-wins except the one that
      // happened to reach the front process first. They converge; what
      // they do not do is converge BEFORE answering, and every request
      // served inside that window carries a key set the service is about
      // to disown. It reached the suite as `sts_jwt_bearer_grant`
      // section 7 reading an RSA key from `/oauth2/jwks` on one worker
      // and posting an assertion encrypted to it to another: `oaep
      // decoding error`, which names nothing.
      //
      // **SO THIS ASKS AND DOES NOT TAKE.** Where a process already holds
      // the realm's keys — the one that created it, which generated them
      // on the way past — they are certified here. Where it does not,
      // nothing is made: the keys are built once, by whichever process
      // first has a REQUEST that needs them, published to the others, and
      // certified from the other direction by `helpers.js`'s
      // `certifyLater()`. The two are the same job reached from the two
      // directions a realm's keys and its branch can arrive in, and only
      // one of them can race.
      //
      // That also restores what `helpers.js` already says happens and had
      // stopped being true: *a realm created at runtime makes its keys on
      // first use*.
      // ---------------------------------------------------------------
      if (typeof keySetHeldProvider !== 'function' || !keySetHeldProvider(id)) {
        log.debug('pki: the "' + id + '" realm\'s branch is built and this ' +
                  'process holds no signing keys for it yet, so none are ' +
                  'certified here. certifyLater() does it when they are made.');
        return null;
      }
      return certifyKeySet(id, keySetProvider(id));
    }).then(function (done) {
      if (done && done.certified) {
        log.info('pki: the "' + id + '" realm was created, its branch was ' +
                 'built under the service Root, and its ' + done.certified +
                 ' signing keys were certified under it.');
      }
    }).catch(function (e) {
      log.error(errorCodes.tag('STS-PKI-0054') + 'pki: the "' + id + '" ' +
                'realm\'s certificate authority could not be set ' +
                'up: ' + e.message);
    });
  });
  log.debug('pki: watching for realms created at runtime.');
  log.debug("Leaving watchRealms().");
}

// A scope's branch, built only if it is not there. The counterpart of
// `ensureRoot()` and for its reason: rebuilding a branch that exists would
// invalidate every certificate under it, and a restart in PRODUCT mode — where
// the branch is read back from the store — must not do that.
async function ensureScope(scopeId, opts) {
  log.debug("Entering ensureScope().");
  log.debug("Leaving ensureScope().");
  // Looked for INSIDE the queue — see `oneBuildAtATime()`. Looking first and
  // queueing the build afterwards is the race it exists to remove.
  return oneBuildAtATime(String(scopeId), function () {
    const wanted = useCasesFor(scopeKindOf(String(scopeId)));
    const complete = function () {
      log.debug("Entering complete().");
      const held = rawRowFor(scopeId);
      log.debug("Leaving complete().");
      return (held && held.intermediate && held.issuing &&
              wanted.every(function (uc) {
                return !!held.issuing[uc.id];
              }))
        ? { ok: true, existing: true, scope: describeScope(scopeId) }
        : null;
    };
    // THE CLUSTER'S BUILD, where there is one to take part in — see
    // `oneBuildInTheCluster()`. Present here and complete: nothing to ask.
    const already = complete();
    if (already) {
      return already;
    }
    return oneBuildInTheCluster(String(scopeId), ['intermediate', 'issuing'],
                                complete,
                                function () {
                                  return ensureScopeNow(scopeId, opts,
                                                        wanted);
                                });
  });
}

async function ensureScopeNow(scopeId, opts, wanted) {
  log.debug("Entering ensureScopeNow(). scope=" + scopeId);
  const row = rawRowFor(scopeId);
  // -----------------------------------------------------------------------
  // **A BRANCH MISSING ONLY A USE CASE ADDED SINCE IT WAS BUILT IS TOPPED
  // UP, NOT REBUILT (2026-09-13).** This fell through to `buildScopeNow()`
  // for any incomplete branch, which was right while "incomplete" could only
  // mean a build that failed half way. It stopped being the only meaning the
  // day a use case was added to `USE_CASES` (`pep-tls`): every branch already
  // in a PRODUCT-mode store is then incomplete on the next start, and a
  // rebuild replaces its Intermediate — superseding every Issuing CA under it
  // and every certificate those issued, the realm's JOSE and XML signing
  // certificates included — to add one authority nobody had used yet. That
  // is a restart revoking a realm's published chain, which is the one thing
  // this function's header says a restart must not do.
  //
  // **ONLY WHERE THE EXISTING INTERMEDIATE CAN SIGN WHAT IS MISSING.** A
  // missing Issuing CA that carries `pathLen: 0` fits under any Intermediate
  // this service has built (they are all at least 1); one needing room
  // beneath it (the way `spiffe` does) may not fit the depth the stored
  // Intermediate was issued with, and a CA it cannot sign is a chain every
  // path builder refuses — so that case rebuilds, as it always did.
  // -----------------------------------------------------------------------
  const missing = wanted.filter(function (uc) {
    return !(row && row.issuing && row.issuing[uc.id]);
  });
  if (row && row.intermediate && row.issuing && missing.length &&
      missing.length < wanted.length &&
      missing.every(function (uc) { return issuingPathLen(uc.id) === 0; })) {
    log.debug("Leaving ensureScopeNow(). A top-up.");
    return topUpScopeNow(String(scopeId), missing);
  }
  log.debug("Leaving ensureScopeNow(). A build.");
  return buildScopeNow(scopeId, opts || {
    organisation: config.value('pki.organisation')
  });
}

// The Issuing CAs a branch is missing, issued under the Intermediate it
// already has — see `ensureScope()` for when. Nothing that exists is touched,
// so nothing is superseded. A failure stores nothing and is reported whole,
// because a branch topped up with two of three missing authorities is the
// half-built state "a branch in one act, or none" exists to refuse.
async function topUpScopeNow(scopeId, missing) {
  log.debug('Entering topUpScopeNow(). scope=' + scopeId + ' missing=' +
            missing.map(function (uc) { return uc.id; }).join(','));
  const id = String(scopeId);
  const row = rawRowFor(id);
  const kind = scopeKindOf(id);
  const organisation = row.organisation || DEFAULT_ORGANISATION;
  const named = kind === 'process' ? 'Process' : (id || 'default');
  const made = {};
  for (let i = 0; i < missing.length; i++) {
    const uc = missing[i];
    // The branch's own algorithms, narrowed by the use case's preference the
    // way a build narrows them — so a topped-up authority is the one a fresh
    // build of this branch would have made.
    const forThis = algorithmsForUseCase(uc,
      { keyAlg: row.keyAlg, signatureAlg: row.signatureAlg }, {});
    try {
      made[uc.id] = await issueCaTier({
        tier: 'issuing', profile: 'issuing-ca', label: uc.label + ' CA',
        useCase: uc.id, scope: id,
        cn: organisation + ' ' + uc.cn + ' (' + named + ')',
        organisation: organisation, country: row.country || '',
        keyAlg: forThis.keyAlg, signatureAlg: forThis.signatureAlg,
        // The branch's own choice; a row built before #68 has none, and
        // undefined is the setting (issueCaTier()).
        altKeyAlg: row.altKeyAlg,
        pathLen: issuingPathLen(uc.id),
        years: tierYearsFrom(undefined, 'issuing'),
        parent: row.intermediate
      });
    } catch (e) {
      log.error(errorCodes.tag('STS-PKI-0007') + 'pki: the "' +
                (id || 'default') + '" branch was missing its ' + uc.label +
                ' Issuing CA and it could not be added: ' + e.message +
                '. Nothing was stored.');
      log.debug('Leaving topUpScopeNow(). The ' + uc.id + ' CA failed.');
      return errorCodes.mark({ ok: false,
               errors: ['The ' + uc.label + ' Issuing CA could not be ' +
                        'added to this branch: ' + e.message + '. Nothing ' +
                        'was stored.'] }, 'STS-PKI-0007');
    }
  }
  // Read again rather than written from `row`: issuing a tier awaits, and a
  // certificate certified meanwhile under an authority this branch already had
  // must not be overwritten by the copy read before the first await.
  const fresh = rawRowFor(id);
  fresh.issuing = Object.assign({}, fresh.issuing || {}, made);
  saveRow(id, fresh);
  log.info('pki: the "' + (id || 'default') + '" branch was built before ' +
           Object.keys(made).length + ' use case(s) existed, so ' +
           Object.keys(made).join(', ') + ' was added under its existing ' +
           'Intermediate CA. Nothing already issued was replaced.');
  log.debug('Leaving topUpScopeNow().');
  return { ok: true, existing: true, toppedUp: Object.keys(made),
           scope: describeScope(id) };
}

// ---------------------------------------------------------------------------
// THE REPORT `/admin/crypto-metadata` DRAWS. Every table in it is read from the
// module that performs the algorithm — which for the encoding is the vendored
// x509 module and for the hashing is `crypto.js` — rather than written here.
// That is `crypto_metadata.js`'s own rule applied to its newest family.
// ---------------------------------------------------------------------------
function report(realmId) {
  log.debug('Entering report().');
  const chain = describe(realmId);
  const out = {
    tiers: TIERS.map(function (one) {
      return { id: one.id, label: one.label, profile: one.profile,
               what: one.what,
               pathLen: (x509.profile(one.profile) || {}).pathLen,
               keyUsage: (x509.profile(one.profile) || {}).keyUsage || [],
               years: (x509.profile(one.profile) || {}).years };
    }),
    keyAlgorithms: keyAlgorithms(),
    // The choices for a tier's alternative key (#68), and `none`.
    alternativeKeyAlgorithms: alternativeKeyAlgs().concat([ALTERNATIVE_NONE]),
    signatureAlgorithms: ['rsa', 'ec', 'okp'].reduce(function (all, kind) {
      return all.concat(x509.signatureAlgorithmsFor({ kind: kind })
        .map(function (id) {
          const spec = x509.sigAlg(id) || {};
          return { id: id, label: spec.label || id, weak: !!spec.weak,
                   kind: kind };
        }));
    }, []),
    encoder: 'common/vendored/x509.js — the parent project\'s own PKI code, ' +
             'byte-identical, over pkijs and asn1js. One encoder for this ' +
             'service and for that project\'s PKI / X.509 page.',
    // The two honest limits, said here so that every surface that draws this
    // report repeats them rather than each one deciding how to phrase it.
    // **THIS SENTENCE REVERSED ON 2026-09-11 AND THE OLD ONE IS WORTH KEEPING
    // IN VIEW**: it read *NONE. This service publishes no CRL and answers no
    // OCSP, so a certificate it issued is good until it expires.* Every
    // surface that draws this report repeated it, which is why it is one
    // string here rather than a paragraph on each page.
    //
    // What replaced it has to keep TWO CLAIMS APART that the old absence
    // made moot, and a reader who runs them together will draw the wrong
    // conclusion in the more dangerous direction: this service PUBLISHES
    // revocation, and it CONSULTS none.
    // **AND IT REVERSED A SECOND TIME ON 2026-09-12**, from *PUBLISHED, NOT
    // ENFORCED … WHAT THIS SERVICE DOES NOT DO IS CONSULT ONE … so a
    // certificate revoked here still gets in here*. The two claims are still
    // kept apart in the sentence — what is PUBLISHED and what is CONSULTED —
    // because they are still two pieces of work, and the second half is read
    // from `common/revocation_status.js` so it names the policy in force.
    revocation: 'PUBLISHED AND CONSULTED. Every certificate authority here ' +
             'signs a CRL (RFC 5280 section 5) and answers OCSP (RFC 6960), ' +
             'at /pki/crl/{scope}/{ca} and /pki/ocsp/{scope}/{ca}, and every ' +
             'certificate this service issues names its own over http and ' +
             'ldap. Anything replaced or rotated is put on ' +
             'the issuer\'s list as `superseded` automatically. WHAT A ' +
             'PRESENTED CERTIFICATE IS HELD TO: ' +
             require('./revocation_status').describePolicy().sentence +
             ' Removing the key pair from an application\'s entry is a THIRD ' +
             'thing again — it stops this service trusting an assertion ' +
             'signed with that key, and puts nothing on any list.',
    residency: keystore.persists()
      ? 'The CA private keys are in the persistence store, sealed under the ' +
        'same key-encryption key as the signing keys, and survive a restart.'
      : 'The CA private keys are held in memory only. This service is in ' +
        'development mode, where key material is generated per start — a ' +
        'hierarchy built now is gone when this process exits.',
    chain: chain
  };
  log.debug('Leaving report().');
  return out;
}

// ===========================================================================
// SOMEBODY ELSE'S CERTIFICATES (#40, 2026-09-21): A PATH TO A CALLER'S TRUST
// ANCHORS, AND OPENSSH CERTIFICATES.
//
// Everything above this section is about the authority THIS service keeps.
// SPIFFE's node attestors verify certificates from authorities it does not
// keep — an operator's CA (x509pop), a DevID CA and a TPM manufacturer
// (tpm_devid), an SSH host CA (sshpop) — against anchors configured on the
// realm. They were written beside their attestors on the first day and moved
// here the same day, at rcbj's direction: every certificate path this
// service checks is checked in this module, and every signature in
// `crypto.js`.
//
// **`verifyPathToAnchors()` IS GO'S `x509.Certificate.Verify()`** with
// caller-supplied roots and `ExtKeyUsageAny`, because SPIRE is what the
// attestors copy. Since #201 it BACKTRACKS over every issuer whose name
// matches and whose key verifies — it took the first name match and stopped,
// until x509-limbo's path-building cases — checks each signature with the
// vendored engine, which reads ML-DSA, SLH-DSA and composite signatures, and
// holds the path to `pathRuleProblem()` and `pathValidityProblem()`, the one
// set of RFC 5280 rules every path here is held to (see the section header
// above `pathRuleProblem()`). The path must end at a certificate in the
// anchors, which need not be self-signed (Go's roots are a pool, so a root's
// own signature is never asked about).
//
// **A CRITICAL EXTENSION THIS MODULE DOES NOT UNDERSTAND IS REFUSED** on any
// certificate — Go refuses those too — unless the caller names it
// (`opts.allowCritical`). **NAME CONSTRAINTS ARE EVALUATED since #201**; they
// were refused wholesale, which refused every legitimate constrained CA and
// was the one thing here that failed closed only because nothing was
// checked.
//
// **THE OPENSSH HALF** reads RFC 4251's wire types and OpenSSH's
// PROTOCOL.certkeys: ssh-rsa, ecdsa-sha2-nistp256/384/521, ssh-ed25519 and
// their -cert-v01 versions, an authorized_keys line, SHA-256 fingerprints,
// and `checkSshHostCertificate()`, which is `x/crypto/ssh`'s
// `CertChecker.CheckHostKey()`. The security-key (`sk-`) types and DSA are
// refused; OpenSSH defines no post-quantum signature.
// ===========================================================================

// One certificate from DER: `{ der, pem, x509, sha1 }`, `sha1` being SPIRE's
// fingerprint (SHA-1 of the DER, lowercase hex). null when it is not one.
function certificateFromDer(der) {
  log.debug("Entering certificateFromDer().");
  try {
    const x509cert = new nodeCrypto.X509Certificate(Buffer.from(der || []));
    log.debug("Leaving certificateFromDer().");
    return { der: Buffer.from(x509cert.raw), pem: x509cert.toString(),
             x509: x509cert,
             sha1: nodeCrypto.createHash('sha1').update(x509cert.raw)
               .digest('hex') };
  } catch (e) {
    log.debug("Caught in certificateFromDer(): " + ((e && e.message) || e));
    log.debug("Leaving certificateFromDer(). Not a certificate.");
    return null;
  }
}

// Every certificate in a PEM bundle. A block that does not parse is counted
// and skipped, never fatal, so one bad paste does not take the rest of an
// operator's anchors with it.
function certificateBundle(pemText) {
  log.debug("Entering certificateBundle().");
  const blocks = String(pemText || '').match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
  const certificates = [];
  let unreadable = 0;
  blocks.forEach(function (block) {
    const body = block.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    const one = certificateFromDer(Buffer.from(body, 'base64'));
    if (one) {
      certificates.push(one);
    } else {
      unreadable++;
    }
  });
  log.debug("Leaving certificateBundle(). " + certificates.length +
            " certificate(s), " + unreadable + " unreadable.");
  return { certificates: certificates, unreadable: unreadable };
}

// A certificate's SubjectPublicKeyInfo, read with pkijs so that a key node
// cannot read (a post-quantum one) is still there to describe —
// `stsCrypto.publicKeyFromSpki()` takes it. null when it cannot be read.
function spkiOf(one) {
  log.debug("Entering spkiOf().");
  try {
    const cert = pkijs.Certificate.fromBER(new Uint8Array(one.der));
    const der = Buffer.from(cert.subjectPublicKeyInfo.toSchema().toBER(false));
    log.debug("Leaving spkiOf().");
    return der;
  } catch (e) {
    log.debug("Caught in spkiOf(): " + ((e && e.message) || e));
    log.debug("Leaving spkiOf(). Unreadable.");
    return null;
  }
}

// The keyUsage bits a certificate states, by name, or null when it states
// none — Go's `KeyUsage` is zero then, which permits nothing.
async function keyUsageOf(one) {
  log.debug("Entering keyUsageOf().");
  const ku = (await extensionsOf(one)).filter(function (ext) {
    return ext.name === 'keyUsage';
  })[0];
  log.debug("Leaving keyUsageOf().");
  return ku && Array.isArray(ku.value) ? ku.value.slice(0) : null;
}

// The RSA modulus size of a certificate's key in bits; 0 for any other key.
function rsaKeyBits(one) {
  log.debug("Entering rsaKeyBits().");
  let bits = 0;
  try {
    const key = one.x509.publicKey;
    if (key.asymmetricKeyType === 'rsa' ||
        key.asymmetricKeyType === 'rsa-pss') {
      bits = Number((key.asymmetricKeyDetails || {}).modulusLength || 0);
    }
  } catch (e) {
    log.debug("Caught in rsaKeyBits(): " + ((e && e.message) || e));
  }
  log.debug("Leaving rsaKeyBits(). " + bits);
  return bits;
}

// The described extensions of one certificate, from the vendored engine.
async function extensionsOf(one) {
  log.debug("Entering extensionsOf().");
  const described = await x509.describeCertificate(one.pem);
  log.debug("Leaving extensionsOf().");
  return (described && described.extensions) || [];
}

// A certificate's subject as one line, for a reason. A certificate with an
// EMPTY subject — a TPM attestation key's (WebAuthn Level 3 section 8.3.1,
// #105), whose name is in its subjectAltName — has none at all as far as
// node's X509Certificate is concerned, so it is named by its SAN instead.
function subjectText(one) {
  log.debug("Entering subjectText().");
  const subject = String((one && one.x509 && one.x509.subject) || '');
  log.debug("Leaving subjectText().");
  return subject ? subject.replace(/\n/g, ', ')
    : 'the certificate with an empty subject' +
      (one && one.x509 && one.x509.subjectAltName
        ? ' (' + String(one.x509.subjectAltName) + ')' : '');
}

// Build and verify a path from `leafDer` through `intermediateDers` to one of
// `anchors` (certificateFromDer() answers). `opts.now` is milliseconds;
// `opts.skewMs` widens every validity window; `opts.allowCritical` names
// critical extensions not to refuse. Resolves `{ ok: true, chain }` — leaf
// first, the anchor last — or `{ ok: false, reason, check }`. Never rejects.
//
// **IT BACKTRACKS (#201).** Every issuer whose name matches and whose key
// verifies the certificate is a candidate, an anchor before an intermediate
// and one whose subjectKeyIdentifier matches the authorityKeyIdentifier
// before one that does not; a candidate path that fails a rule or the clock
// is abandoned for the next. The first version took the first issuer whose
// NAME matched and stopped there, so a cross-signed intermediate, a rolled
// key under the same name or an expired sibling refused a path that
// existed. Bounded by PATH_MAX_LENGTH and PATH_MAX_SIGNATURES, with no
// certificate — nor a second certificate with the same subject and key —
// used twice in one path, so a loop of cross-certificates ends.
/**
 * @returns {Promise<{ ok: boolean, chain?: any[], reason?: string,
 *                     check?: string, policies?: string[] }>}
 */
async function verifyPathToAnchors(leafDer, intermediateDers, anchors, opts) {
  log.debug("Entering verifyPathToAnchors().");
  const options = opts || {};
  const leaf = certificateFromDer(leafDer);
  if (!leaf) {
    log.debug("Leaving verifyPathToAnchors(). No leaf.");
    return { ok: false, check: 'unusable',
             reason: 'the leaf is not an X.509 certificate' };
  }
  const intermediates = [];
  for (let i = 0; i < (intermediateDers || []).length; i++) {
    const one = certificateFromDer(intermediateDers[i]);
    if (!one) {
      log.debug("Leaving verifyPathToAnchors(). A bad intermediate.");
      return { ok: false, check: 'unusable',
               reason: 'intermediate certificate ' + i +
                       ' is not an X.509 certificate' };
    }
    intermediates.push(one);
  }
  const roots = anchors || [];
  if (!roots.length) {
    log.debug("Leaving verifyPathToAnchors(). No anchors.");
    return { ok: false, check: 'no-anchor',
             reason: 'no trust anchor is configured' };
  }
  const now = options.now === undefined ? Date.now() : options.now;
  const isAnchor = function (one) {
    log.debug("Entering isAnchor().");
    log.debug("Leaving isAnchor().");
    return roots.some(function (root) { return root.der.equals(one.der); });
  };
  // What the path has to hold before it is accepted: the rules, then the
  // clock. The first failure met is kept for the refusal when nothing holds.
  let firstFailure = null;
  // The user-constrained-policy-set of the path accepted (RFC 5280 section
  // 6.1.6), for a caller that asked for policies.
  let acceptedPolicies = [];
  const accept = function (path) {
    log.debug("Entering accept(). " + path.length + " certificate(s).");
    const problem = pathRuleProblem(path, options) ||
                    pathValidityProblem(path, now, options.skewMs);
    if (problem) {
      firstFailure = firstFailure || problem;
      log.debug("Leaving accept(). " + problem.check);
      return false;
    }
    acceptedPolicies = pathPolicyOutcome(path, options.policy)
      .userConstrainedPolicySet;
    log.debug("Leaving accept().");
    return true;
  };
  // A leaf that IS one of the anchors verifies as itself, as in Go.
  if (isAnchor(leaf)) {
    const alone = accept([leaf]);
    log.debug("Leaving verifyPathToAnchors(). The leaf is an anchor.");
    return alone ? { ok: true, chain: [leaf], policies: acceptedPolicies }
                 : { ok: false, check: firstFailure.check,
                     reason: firstFailure.why };
  }
  let signatures = 0;
  let exhausted = false;
  let unsigned = '';
  const identityOf = function (one) {
    log.debug("Entering identityOf().");
    const facts = pathFactsOf(one);
    const spki = facts.pk ? Buffer.from(facts.pk.subjectPublicKeyInfo
      .toSchema().toBER(false)).toString('hex') : one.der.toString('hex');
    log.debug("Leaving identityOf().");
    return facts.subjectRdns.join(',') + '|' + spki;
  };
  // The issuers of `top` worth trying, best first.
  const candidatesFor = function (top, path) {
    log.debug("Entering candidatesFor().");
    const facts = pathFactsOf(top);
    const inPath = path.map(identityOf);
    const out = roots.map(function (one) {
      return { one: one, anchor: true };
    }).concat(intermediates.filter(function (one) {
      return !isAnchor(one);
    }).map(function (one) {
      return { one: one, anchor: false };
    })).filter(function (candidate) {
      const theirs = pathFactsOf(candidate.one);
      return !theirs.problem &&
             theirs.subjectRdns.join(',') === facts.issuerRdns.join(',') &&
             inPath.indexOf(identityOf(candidate.one)) < 0;
    });
    const rank = function (candidate) {
      log.debug("Entering rank().");
      const theirs = pathFactsOf(candidate.one);
      const keyed = facts.authorityKeyIdentifier && theirs.keyIdentifier &&
                    facts.authorityKeyIdentifier === theirs.keyIdentifier;
      log.debug("Leaving rank().");
      return (candidate.anchor ? 0 : 2) + (keyed ? 0 : 1);
    };
    out.sort(function (a, b) { return rank(a) - rank(b); });
    log.debug("Leaving candidatesFor(). " + out.length + ".");
    return out;
  };
  const extend = async function (path) {
    log.debug("Entering extend(). " + path.length + " certificate(s).");
    if (path.length >= PATH_MAX_LENGTH) {
      exhausted = true;
      log.debug("Leaving extend(). Too long.");
      return null;
    }
    const top = path[path.length - 1];
    const candidates = candidatesFor(top, path);
    for (let c = 0; c < candidates.length; c++) {
      if (signatures >= PATH_MAX_SIGNATURES) {
        exhausted = true;
        log.debug("Leaving extend(). Out of signature checks.");
        return null;
      }
      signatures++;
      const candidate = candidates[c];
      if (!(await pathSigned(top, candidate.one))) {
        unsigned = unsigned || 'the signature on "' + pathSubjectOf(top) +
                   '" does not verify under the key of "' +
                   pathSubjectOf(candidate.one) + '", the only certificate ' +
                   'that names itself as its issuer';
        continue;
      }
      const longer = path.concat([candidate.one]);
      if (candidate.anchor) {
        if (accept(longer)) {
          log.debug("Leaving extend(). Anchored.");
          return longer;
        }
        continue;
      }
      const found = await extend(longer);
      if (found) {
        log.debug("Leaving extend(). Found below.");
        return found;
      }
    }
    log.debug("Leaving extend(). Nothing from here.");
    return null;
  };
  let chain = null;
  try {
    chain = await extend([leaf]);
  } catch (e) {
    log.debug("Caught in verifyPathToAnchors(): " + ((e && e.message) || e));
    log.debug("Leaving verifyPathToAnchors(). The builder threw.");
    return { ok: false, check: 'unusable',
             reason: 'the path could not be built: ' +
                     ((e && e.message) || e) };
  }
  if (chain) {
    // A FOREIGN hybrid path (#68): a wrong alternative signature is refused;
    // an absent or uncheckable one is the issuer's business — see
    // `alternativeProblem()`. Asked of the path the builder accepted.
    const altPems = chain.map(function (one) {
      return one.pem;
    });
    const altProblem = await alternativeProblem(altPems,
      await x509.verifyChain(altPems), { required: false });
    if (altProblem) {
      log.debug("Leaving verifyPathToAnchors(). A wrong alternative " +
                "signature.");
      return { ok: false, check: 'alternative-signature',
               reason: alternativeSentence(altProblem,
                                           pathSubjectOf(chain[altProblem.index])) };
    }
    log.debug("Leaving verifyPathToAnchors(). " + chain.length +
              " certificate(s).");
    return { ok: true, chain: chain, policies: acceptedPolicies };
  }
  if (firstFailure) {
    log.debug("Leaving verifyPathToAnchors(). " + firstFailure.check);
    return { ok: false, check: firstFailure.check, reason: firstFailure.why };
  }
  const leafFacts = pathFactsOf(leaf);
  if (leafFacts.problem) {
    log.debug("Leaving verifyPathToAnchors(). An unusable leaf.");
    return { ok: false, check: 'unusable',
             reason: '"' + pathSubjectOf(leaf) + '" ' + leafFacts.problem };
  }
  log.debug("Leaving verifyPathToAnchors(). No path.");
  return { ok: false,
           check: exhausted ? 'exhausted' : (unsigned ? 'signature'
                                                      : 'no-path'),
           reason: exhausted
             ? 'no path to a configured trust anchor was found within ' +
               PATH_MAX_LENGTH + ' certificates and ' + PATH_MAX_SIGNATURES +
               ' signature checks'
             : (unsigned || 'no path from "' + pathSubjectOf(leaf) +
                            '" to a configured trust anchor') };
}

// ---------------------------------------------------------------------------
// THE CHAIN OPENSSL VERIFIED, HELD TO THE SAME RULES (#201).
//
// Two surfaces here let OpenSSL build and verify a path — the main port's
// client certificate (`socket.authorized`) and every outbound request
// (`common/outbound_tls.ts`) — and x509-limbo found OpenSSL accepting paths
// the rules above refuse: a nameConstraints on an end entity, an empty or
// malformed constraint, a malformed name under a constraint, a wildcard that
// reaches into an excluded subtree (CVE-2025-61727), a root with no
// basicConstraints. OpenSSL is not replaced — it still builds the path,
// checks every signature and the clock — and what it verified is then asked
// these rules too. `peer` is node's DETAILED peer certificate
// (`getPeerCertificate(true)`), whose `issuerCertificate` links are the chain
// node reports, ending at the anchor. Answers `pathRuleProblem()`'s verdict
// or null; a chain it cannot read is left to OpenSSL's answer.
// ---------------------------------------------------------------------------
function peerChainProblem(peer) {
  log.debug("Entering peerChainProblem().");
  const path = [];
  const seen = {};
  let current = peer;
  while (current && current.raw && path.length < PATH_MAX_LENGTH) {
    const key = String(current.fingerprint256 || path.length);
    if (seen[key]) {
      break;
    }
    seen[key] = true;
    const one = certificateFromDer(current.raw);
    if (!one) {
      log.debug("Leaving peerChainProblem(). Unreadable.");
      return null;
    }
    path.push(one);
    current = current.issuerCertificate;
  }
  if (!path.length) {
    log.debug("Leaving peerChainProblem(). No certificate.");
    return null;
  }
  const problem = pathRuleProblem(path, {});
  log.debug("Leaving peerChainProblem(). " +
            (problem ? problem.check : 'It holds.'));
  return problem;
}

// ---------------------------------------------------------------------------
// THE SYNCHRONOUS DOOR (#201): is `leaf` issued, directly, by one of
// `authorities`, and does the two-certificate path hold the rules above?
//
// For the doors that answer inside a synchronous handler and deliberately
// walk no chain — the SPIRE Server API's caller check (`spiffe_auth.ts`,
// whose SVIDs this service's Issuing CA signs directly) and an OpenID4VCI
// key attestation's `x5c` (`vc_issuer.ts`). They used node's
// `checkIssued()` and `verify()` and nothing else, so a leaf that was
// itself a CA, carried a critical extension nothing reads or sat outside a
// name constraint was accepted. The signature is node's, so an authority
// with a key OpenSSL cannot read (a post-quantum one) verifies nothing
// here; the asynchronous `verifyPathToAnchors()` is the door for those.
//
// `authorities` are `{ certificate: X509Certificate, ... }` or DER/PEM;
// `opts` as `verifyPathToAnchors()`. `{ ok: true, index }` — which authority
// — or `{ ok: false, check, reason }`.
// ---------------------------------------------------------------------------
function verifyIssuedDirectly(leafDer, authorities, opts) {
  log.debug("Entering verifyIssuedDirectly().");
  const options = opts || {};
  const leaf = certificateFromDer(leafDer);
  if (!leaf) {
    log.debug("Leaving verifyIssuedDirectly(). No leaf.");
    return { ok: false, check: 'unusable',
             reason: 'the certificate is not an X.509 certificate' };
  }
  let firstFailure = null;
  let signedByAny = false;
  const entryOf = function (given) {
    log.debug("Entering entryOf().");
    let entry = null;
    if (given && given.certificate && given.certificate.raw) {
      entry = certificateFromDer(given.certificate.raw);
    } else if (given && given.raw) {
      entry = certificateFromDer(given.raw);
    } else if (Buffer.isBuffer(given)) {
      entry = certificateFromDer(given);
    } else if (typeof given === 'string') {
      entry = certificateFromDer(pemToDer(given));
    }
    log.debug("Leaving entryOf().");
    return entry;
  };
  for (let i = 0; i < (authorities || []).length; i++) {
    const authority = entryOf(authorities[i]);
    if (!authority) {
      continue;
    }
    let signed = false;
    try {
      signed = leaf.x509.checkIssued(authority.x509) &&
               leaf.x509.verify(authority.x509.publicKey);
    } catch (e) {
      // `verify` throws for a key of the wrong type — the ordinary case when
      // the authorities hold an EC and an RSA key. It did not sign this.
      log.debug("Caught in verifyIssuedDirectly(): " +
                ((e && e.message) || e));
      signed = false;
    }
    if (!signed) {
      continue;
    }
    signedByAny = true;
    const path = [leaf, authority];
    const problem = pathRuleProblem(path, options) ||
                    pathValidityProblem(path, options.now === undefined
                      ? Date.now() : options.now, options.skewMs);
    if (!problem) {
      log.debug("Leaving verifyIssuedDirectly(). Authority " + i + ".");
      return { ok: true, index: i, chain: path };
    }
    firstFailure = firstFailure || problem;
  }
  if (firstFailure) {
    log.debug("Leaving verifyIssuedDirectly(). " + firstFailure.check);
    return { ok: false, check: firstFailure.check,
             reason: firstFailure.why };
  }
  log.debug("Leaving verifyIssuedDirectly(). Nothing signed it.");
  return { ok: false, check: signedByAny ? 'unusable' : 'no-path',
           reason: 'no authority given issued and signed "' +
                   pathSubjectOf(leaf) + '"' };
}


// ----- WebAuthn attestation certificates (#105) -----------------------------
//
// What `authn/webauthn_attestation.ts` asks of an attestation certificate —
// sections 8.2.1 (packed), 8.3.1 (tpm), 8.4.1 (android-key), 8.6
// (fido-u2f) and 8.8 (apple) of WebAuthn Level 3 — read here with pkijs
// because every certificate question this service asks is answered in this
// module (rcbj, 2026-09-21). The EXTENSION VALUES WebAuthn defines are
// decoded by `crypto.js`'s section 10; this answers only the certificate's
// own fields and hands the raw values over.

// Subject attribute types by OID, for the four section 8.2.1 names.
const SUBJECT_TYPES = { '2.5.4.6': 'C', '2.5.4.10': 'O', '2.5.4.11': 'OU',
                        '2.5.4.3': 'CN' };

// `{ version, subject: { C, O, OU, CN }, subjectEmpty, ca, eku: [oids],
// extensions: { oid: { critical, value } }, sanDirectoryTypes: [oids],
// publicKeyJwk, keyType, curve }` for a DER certificate, or null when it is
// not one. `version` is X.509's (3 for v3). `ca` is null when there is no
// basicConstraints. `sanDirectoryTypes` are the attribute types inside the
// directoryName entries of subjectAltName, which is where a TPM AIK
// certificate names its TPM (TCG EK Credential Profile section 3.2.9).
function attestationCertificateFacts(der) {
  log.debug("Entering attestationCertificateFacts().");
  let cert = null;
  let node = null;
  try {
    cert = pkijs.Certificate.fromBER(new Uint8Array(Buffer.from(der || [])));
    node = new nodeCrypto.X509Certificate(Buffer.from(der || []));
  } catch (e) {
    log.debug("Caught in attestationCertificateFacts(): " +
              ((e && e.message) || e));
    log.debug("Leaving attestationCertificateFacts(). Not a certificate.");
    return null;
  }
  const subject = {};
  (cert.subject.typesAndValues || []).forEach(function (tv) {
    const name = SUBJECT_TYPES[tv.type];
    if (name) {
      subject[name] = String(tv.value.valueBlock.value);
    }
  });
  const extensions = {};
  let ca = null;
  let eku = [];
  let sanDirectoryTypes = [];
  (cert.extensions || []).forEach(function (ext) {
    extensions[ext.extnID] = {
      critical: !!ext.critical,
      value: Buffer.from(ext.extnValue.valueBlock.valueHexView) };
    try {
      if (ext.extnID === '2.5.29.19') {
        ca = !!(ext.parsedValue && ext.parsedValue.cA);
      } else if (ext.extnID === '2.5.29.37') {
        eku = ((ext.parsedValue && ext.parsedValue.keyPurposes) || [])
          .map(String);
      } else if (ext.extnID === '2.5.29.17') {
        ((ext.parsedValue && ext.parsedValue.altNames) || [])
          .forEach(function (name) {
            if (name.type === 4 && name.value &&
                Array.isArray(name.value.typesAndValues)) {
              name.value.typesAndValues.forEach(function (tv) {
                sanDirectoryTypes.push(String(tv.type));
              });
            }
          });
      }
    } catch (e) {
      log.debug("Caught in attestationCertificateFacts(): " +
                ((e && e.message) || e));
      // An extension pkijs could not parse is reported as present, with no
      // parsed meaning; the caller's check then fails on what it needed.
    }
  });
  let publicKeyJwk = null;
  let keyType = '';
  let curve = '';
  try {
    keyType = String(node.publicKey.asymmetricKeyType || '');
    curve = String((node.publicKey.asymmetricKeyDetails || {}).namedCurve ||
                   '');
    publicKeyJwk = node.publicKey.export({ format: 'jwk' });
  } catch (e) {
    log.debug("Caught in attestationCertificateFacts(): " +
              ((e && e.message) || e));
    // A key node cannot export (a post-quantum one): no JWK, and a caller
    // comparing it with a credential's key finds no match.
  }
  log.debug("Leaving attestationCertificateFacts().");
  return { version: Number(cert.version) + 1, subject: subject,
           subjectEmpty: !(cert.subject.typesAndValues || []).length,
           ca: ca, eku: eku, extensions: extensions,
           sanDirectoryTypes: sanDirectoryTypes, publicKeyJwk: publicKeyJwk,
           keyType: keyType, curve: curve, pem: node.toString(),
           subjectText: String(node.subject || ''),
           subjectAltName: String(node.subjectAltName || '') };
}

// An attestation certificate's key identifier as the FIDO Metadata Service
// lists it (`attestationCertificateKeyIdentifiers`, FIDO Metadata Statement
// section 4): the hex SHA-1 of the subjectPublicKey BIT STRING's value,
// RFC 5280 section 4.2.1.2 method (1). How a fido-u2f authenticator, which
// has no AAGUID, is found in MDS. '' when the certificate cannot be read.
function attestationKeyIdentifier(der) {
  log.debug("Entering attestationKeyIdentifier().");
  try {
    const cert = pkijs.Certificate.fromBER(new Uint8Array(Buffer.from(der)));
    const bits = Buffer.from(cert.subjectPublicKeyInfo.subjectPublicKey
      .valueBlock.valueHexView);
    log.debug("Leaving attestationKeyIdentifier().");
    return nodeCrypto.createHash('sha1').update(bits).digest('hex');
  } catch (e) {
    log.debug("Caught in attestationKeyIdentifier(): " +
              ((e && e.message) || e));
    log.debug("Leaving attestationKeyIdentifier(). Unreadable.");
    return '';
  }
}

// ----- OpenSSH --------------------------------------------------------------

const SSH_CERT_SUFFIX = '-cert-v01@openssh.com';
// SSH_CERT_TYPE_HOST (PROTOCOL.certkeys).
const SSH_HOST_CERT = 2;
// Go's CertTimeInfinity, and the largest time Go treats as a time.
const SSH_FOREVER = BigInt('0xffffffffffffffff');
const SSH_LATEST = BigInt('0x7fffffffffffffff');
const SSH_CURVES = {
  'nistp256': { crv: 'P-256', node: 'prime256v1', hash: 'sha256', bytes: 32 },
  'nistp384': { crv: 'P-384', node: 'secp384r1', hash: 'sha384', bytes: 48 },
  'nistp521': { crv: 'P-521', node: 'secp521r1', hash: 'sha512', bytes: 66 }
};

// A reader over RFC 4251's types. Every read throws on a short buffer, and
// the parser's caller turns that into its refusal.
function sshReader(bytes) {
  log.debug("Entering sshReader().");
  const buf = Buffer.from(bytes || []);
  let at = 0;
  // A HOT PATH: the reader's methods carry no Entering/Leaving pair. They
  // run once per field of every key and certificate parsed, and a pair each
  // would drown the log in lines that say nothing the parser's own do not.
  const reader = {
    take: function (n) {
      if (n < 0 || at + n > buf.length) {
        // error-code: none — a parse failure, refused by the caller under
        // its own code
        throw new Error('the SSH structure is truncated');
      }
      const out = buf.subarray(at, at + n);
      at += n;
      return out;
    },
    uint32: function () {
      return reader.take(4).readUInt32BE(0);
    },
    uint64: function () {
      return reader.take(8).readBigUInt64BE(0);
    },
    string: function () {
      return reader.take(reader.uint32());
    },
    text: function () {
      return reader.string().toString('utf8');
    },
    // An mpint's magnitude, without the sign byte OpenSSH adds.
    mpint: function () {
      const raw = reader.string();
      let start = 0;
      while (start < raw.length - 1 && raw[start] === 0) start++;
      return raw.subarray(start);
    },
    position: function () {
      return at;
    },
    rest: function () {
      return reader.take(buf.length - at);
    },
    done: function () {
      return at === buf.length;
    }
  };
  log.debug("Leaving sshReader().");
  return reader;
}

// A key component as a JWK carries it.
function sshBase64Url(value) {
  log.debug("Entering sshBase64Url().");
  log.debug("Leaving sshBase64Url().");
  return Buffer.from(value).toString('base64url');
}

// The public fields of one SSH key type, as node key material.
function sshKeyFields(type, reader) {
  log.debug("Entering sshKeyFields(). type=" + type);
  const b64u = sshBase64Url;
  if (type === 'ssh-rsa') {
    const e = reader.mpint();
    const n = reader.mpint();
    log.debug("Leaving sshKeyFields(). RSA.");
    return { key: nodeCrypto.createPublicKey({ format: 'jwk',
      key: { kty: 'RSA', n: b64u(n), e: b64u(e) } }), curve: '' };
  }
  const ecdsa = /^ecdsa-sha2-(nistp256|nistp384|nistp521)$/.exec(type);
  if (ecdsa) {
    const curve = reader.text();
    const q = reader.string();
    const spec = SSH_CURVES[ecdsa[1]];
    if (curve !== ecdsa[1] || q[0] !== 4 || q.length !== 1 + 2 * spec.bytes) {
      log.debug("Leaving sshKeyFields(). A bad point.");
      // error-code: none — see sshReader()
      throw new Error('the ECDSA key is not an uncompressed ' + curve +
                      ' point');
    }
    log.debug("Leaving sshKeyFields(). ECDSA.");
    return { curve: ecdsa[1], key: nodeCrypto.createPublicKey({ format: 'jwk',
      key: { kty: 'EC', crv: spec.crv,
             x: b64u(q.subarray(1, 1 + spec.bytes)),
             y: b64u(q.subarray(1 + spec.bytes)) } }) };
  }
  if (type === 'ssh-ed25519') {
    const pk = reader.string();
    if (pk.length !== 32) {
      log.debug("Leaving sshKeyFields(). A bad Ed25519 key.");
      // error-code: none — see sshReader()
      throw new Error('an Ed25519 key is 32 bytes');
    }
    log.debug("Leaving sshKeyFields(). Ed25519.");
    return { key: nodeCrypto.createPublicKey({ format: 'jwk',
      key: { kty: 'OKP', crv: 'Ed25519', x: b64u(pk) } }), curve: '' };
  }
  log.debug("Leaving sshKeyFields(). Unsupported.");
  // error-code: none — see sshReader()
  throw new Error('the SSH key type ' + type + ' is not supported (ssh-rsa, ' +
                  'ecdsa-sha2-nistp256/384/521 and ssh-ed25519 are)');
}

// A packed list of name-value pairs (critical options, extensions).
function sshOptions(bytes) {
  log.debug("Entering sshOptions().");
  const reader = sshReader(bytes);
  const out = {};
  while (!reader.done()) {
    const name = reader.text();
    const data = reader.string();
    out[name] = data.length ? sshReader(data).text() : '';
  }
  log.debug("Leaving sshOptions().");
  return out;
}

// A public key blob or a certificate blob, as `ssh.ParsePublicKey()`. A key
// is `{ type, key, curve, blob }`; a certificate adds `certType`, `nonce`,
// `serial`, `kind`, `keyId`, `principals`, `validAfter`, `validBefore`,
// `criticalOptions`, `extensions`, `signatureKey`, `signature` and `signed`
// (the bytes the authority signed). Throws on anything unreadable.
function parseSshPublicKey(blob) {
  log.debug("Entering parseSshPublicKey().");
  const bytes = Buffer.from(blob || []);
  const reader = sshReader(bytes);
  const type = reader.text();
  if (type.slice(-SSH_CERT_SUFFIX.length) !== SSH_CERT_SUFFIX) {
    const fields = sshKeyFields(type, reader);
    if (!reader.done()) {
      log.debug("Leaving parseSshPublicKey(). Trailing bytes.");
      // error-code: none — see sshReader()
      throw new Error('trailing bytes after the SSH public key');
    }
    log.debug("Leaving parseSshPublicKey(). A key.");
    return { type: type, key: fields.key, curve: fields.curve, blob: bytes };
  }
  const keyType = type.slice(0, -SSH_CERT_SUFFIX.length);
  const nonce = reader.string();
  const fields = sshKeyFields(keyType, reader);
  const serial = reader.uint64();
  const kind = reader.uint32();
  const keyId = reader.text();
  const principalReader = sshReader(reader.string());
  const principals = [];
  while (!principalReader.done()) principals.push(principalReader.text());
  const validAfter = reader.uint64();
  const validBefore = reader.uint64();
  const criticalOptions = sshOptions(reader.string());
  const extensions = sshOptions(reader.string());
  reader.string();
  const signatureKeyBlob = reader.string();
  const signedLength = reader.position();
  const signatureReader = sshReader(reader.string());
  if (!reader.done()) {
    log.debug("Leaving parseSshPublicKey(). Trailing bytes.");
    // error-code: none — see sshReader()
    throw new Error('trailing bytes after the SSH certificate');
  }
  const signatureKey = parseSshPublicKey(signatureKeyBlob);
  if (signatureKey.certType) {
    log.debug("Leaving parseSshPublicKey(). A certificate signed one.");
    // error-code: none — see sshReader()
    throw new Error('a certificate\'s signature key cannot itself be a ' +
                    'certificate');
  }
  const format = signatureReader.text();
  const signatureBlob = signatureReader.string();
  const rest = signatureReader.rest();
  log.debug("Leaving parseSshPublicKey(). A certificate.");
  return {
    type: keyType, certType: type, key: fields.key, curve: fields.curve,
    blob: bytes, nonce: nonce, serial: serial, kind: kind, keyId: keyId,
    principals: principals, validAfter: validAfter, validBefore: validBefore,
    criticalOptions: criticalOptions, extensions: extensions,
    signatureKey: signatureKey,
    signature: { format: format, blob: signatureBlob, rest: rest },
    signed: bytes.subarray(0, signedLength)
  };
}

// One authorized_keys line — `[options] type base64 [comment]` — as a key,
// or null for a line that is not one.
function parseSshAuthorizedKey(line) {
  log.debug("Entering parseSshAuthorizedKey().");
  const text = String(line || '').trim();
  if (!text || text.charAt(0) === '#') {
    log.debug("Leaving parseSshAuthorizedKey(). Not a key.");
    return null;
  }
  const fields = text.match(/"(?:[^"\\]|\\.)*"|\S+/g) || [];
  for (let i = 0; i < fields.length - 1; i++) {
    if (!/^(ssh-|ecdsa-|sk-)/.test(fields[i]) &&
        fields[i].indexOf('@openssh.com') < 0) {
      continue;
    }
    try {
      const key = parseSshPublicKey(Buffer.from(fields[i + 1], 'base64'));
      if (key.type === fields[i] || key.certType === fields[i]) {
        log.debug("Leaving parseSshAuthorizedKey().");
        return key;
      }
    } catch (e) {
      log.debug("Caught in parseSshAuthorizedKey(): " +
                ((e && e.message) || e));
    }
  }
  log.debug("Leaving parseSshAuthorizedKey(). Unreadable.");
  return null;
}

// `ssh.FingerprintSHA256()` without its prefix: unpadded base64 of the
// SHA-256 of the key blob.
function sshFingerprint(key) {
  log.debug("Entering sshFingerprint().");
  log.debug("Leaving sshFingerprint().");
  return nodeCrypto.createHash('sha256').update(key.blob).digest('base64')
    .replace(/=+$/, '');
}

// Does `signature` (`{ format, blob }`) over `data` verify under the SSH key?
// The formats Go's `Verify()` accepts for each key type and no others:
// ssh-rsa (SHA-1), rsa-sha2-256 and rsa-sha2-512; the curve's own hash for
// ECDSA, whose blob is two mpints; ssh-ed25519.
async function verifySshSignature(key, data, signature) {
  log.debug("Entering verifySshSignature(). " + key.type + " / " +
            (signature && signature.format));
  if (!signature || !signature.blob) {
    log.debug("Leaving verifySshSignature(). No signature.");
    return false;
  }
  if (key.type === 'ssh-rsa') {
    const hash = { 'ssh-rsa': 'sha1', 'rsa-sha2-256': 'sha256',
                   'rsa-sha2-512': 'sha512' }[signature.format];
    const ok = !!hash && await stsCrypto.verifyRawSignature(
      { family: 'rsa-pkcs1', hash: hash }, key.key, data, signature.blob);
    log.debug("Leaving verifySshSignature(). RSA " + ok);
    return ok;
  }
  if (key.curve) {
    if (signature.format !== key.type) {
      log.debug("Leaving verifySshSignature(). Wrong format for the curve.");
      return false;
    }
    const spec = SSH_CURVES[key.curve];
    let raw = null;
    try {
      const inner = sshReader(signature.blob);
      raw = stsCrypto.ecdsaIntegersToP1363(spec.node, inner.mpint(),
                                           inner.mpint());
    } catch (e) {
      log.debug("Caught in verifySshSignature(): " + ((e && e.message) || e));
    }
    const ok = !!raw && await stsCrypto.verifyRawSignature(
      { family: 'ecdsa', hash: spec.hash, encoding: 'p1363' }, key.key, data,
      raw);
    log.debug("Leaving verifySshSignature(). ECDSA " + ok);
    return ok;
  }
  if (key.type === 'ssh-ed25519' && signature.format === 'ssh-ed25519') {
    const ok = await stsCrypto.verifyRawSignature({ family: 'eddsa' },
                                                  key.key, data,
                                                  signature.blob);
    log.debug("Leaving verifySshSignature(). Ed25519 " + ok);
    return ok;
  }
  log.debug("Leaving verifySshSignature(). Refused.");
  return false;
}

// `CertChecker.CheckHostKey(principal + ':22', …)`: resolves '' when the host
// certificate is acceptable, otherwise why not.
async function checkSshHostCertificate(cert, principal, authorities,
                                       nowSeconds) {
  log.debug("Entering checkSshHostCertificate().");
  if (cert.kind !== SSH_HOST_CERT) {
    log.debug("Leaving checkSshHostCertificate(). Not a host cert.");
    return 'ssh: certificate presented as a host key has type ' + cert.kind;
  }
  const authority = sshFingerprint(cert.signatureKey);
  if (!(authorities || []).some(function (one) {
    return sshFingerprint(one) === authority;
  })) {
    log.debug("Leaving checkSshHostCertificate(). Unknown authority.");
    return 'ssh: no authorities for hostname: ' + principal;
  }
  const options = Object.keys(cert.criticalOptions).filter(function (name) {
    return name !== 'source-address';
  });
  if (options.length) {
    log.debug("Leaving checkSshHostCertificate(). Critical option.");
    return 'ssh: unsupported critical option "' + options[0] +
           '" in certificate';
  }
  if (cert.principals.length && cert.principals.indexOf(principal) < 0) {
    log.debug("Leaving checkSshHostCertificate(). Principal.");
    return 'ssh: principal "' + principal + '" not in the set of valid ' +
           'principals for given certificate';
  }
  const now = BigInt(Math.floor(nowSeconds));
  if (cert.validAfter > SSH_LATEST || now < cert.validAfter) {
    log.debug("Leaving checkSshHostCertificate(). Not yet valid.");
    return 'ssh: cert is not yet valid';
  }
  if (cert.validBefore !== SSH_FOREVER &&
      (cert.validBefore > SSH_LATEST || now >= cert.validBefore)) {
    log.debug("Leaving checkSshHostCertificate(). Expired.");
    return 'ssh: cert has expired';
  }
  if (!(await verifySshSignature(cert.signatureKey, cert.signed,
                                 cert.signature))) {
    log.debug("Leaving checkSshHostCertificate(). Signature.");
    return 'ssh: certificate signature does not verify';
  }
  log.debug("Leaving checkSshHostCertificate(). Accepted.");
  return '';
}

// ----- The clouds' published signing certificates (#40 phase three) ---------
//
// `pki_cloud_anchors.json` is GENERATED from SPIRE's own embedded tables (its
// `_provenance` member says from which files): AWS's per-region certificates
// for instance identity documents, RSA-2048 (PKCS#7 signatures) and RSA-1024
// (the older raw signature, with one default for most regions), and the four
// roots Azure's attested documents chain to. They are public certificates,
// shipped the way SPIRE ships them, and never edited by hand.
//
// **AN AWS CERTIFICATE HERE IS A KEY HOLDER, NOT A PATH.** SPIRE verifies an
// identity document's signature with the region's certificate's public key
// and asks nothing about the certificate's own validity — AWS's default
// RSA-1024 certificate expired on 2024-06-05 and still verifies the older
// signature form in SPIRE — so `awsIidCertificate()` answers a certificate
// and the caller uses its key. Azure's roots ARE a path's anchors
// (`verifyPathToAnchors()`).
let cloudAnchors = null;
function cloudAnchorTable() {
  log.debug("Entering cloudAnchorTable().");
  if (!cloudAnchors) {
    cloudAnchors = require('./pki_cloud_anchors.json');
  }
  log.debug("Leaving cloudAnchorTable().");
  return cloudAnchors;
}

// The AWS certificate for `region` and `keyType` ('rsa2048' | 'rsa1024'), as
// certificateFromDer() answers, or null — RSA-2048 has no fallback and an
// unknown region is refused, RSA-1024 falls back to AWS's default, as SPIRE.
function awsIidCertificate(region, keyType) {
  log.debug("Entering awsIidCertificate(). " + region + "/" + keyType);
  const table = cloudAnchorTable();
  const pem = keyType === 'rsa2048'
    ? table.awsRsa2048[String(region || '')]
    : (table.awsRsa1024[String(region || '')] || table.awsRsa1024Default);
  log.debug("Leaving awsIidCertificate(). " + (pem ? 'found' : 'none'));
  return pem ? certificateBundle(pem).certificates[0] || null : null;
}

// The roots an Azure attested document's signing certificate must chain to.
function azureImdsRoots() {
  log.debug("Entering azureImdsRoots().");
  log.debug("Leaving azureImdsRoots().");
  return certificateBundle(cloudAnchorTable().azureRoots.join('\n'))
    .certificates;
}

// ----- The FIDO Metadata Service's BLOB (#62 P5, 2026-09-22) ----------------
//
// FIDO MDS3 (FIDO Metadata Service v3.0, section 3.1.8) publishes one signed
// JWT — the "BLOB" — whose payload lists every certified authenticator model
// and what is currently known about it: its certification level, and whether
// it has been REVOKED or its keys reported compromised. Section 3.1.8's steps,
// as this verifies them:
//
//   * the header's `x5c` is the signing chain, leaf first; it is required;
//   * the chain must end at the FIDO root — which FIDO documents as
//     GlobalSign Root CA - R3 — or at an anchor the operator configured
//     (`risk.mdsTrustAnchors`, a PEM bundle). **The root is not shipped**:
//     with no anchor configured it is found in node's own root store
//     (`tls.rootCertificates`, the bundle every HTTPS request here already
//     trusts), by name — so nothing FIDO-specific is in this repository;
//   * the signature must verify under the leaf's key, with one of the
//     algorithms section 3.1.7 allows, named here rather than read off the
//     token (`verifyCompactJws()`'s rule);
//   * revocation of every certificate in the chain (step 5) is the CALLER's
//     next step, through `revocation_status.verdictFor()` — it fetches, and
//     this does not;
//   * the payload's `no` and `nextUpdate` are answered for the caller's
//     rollback and staleness checks.
//
// Answers `{ ok: true, header, payload, chainPems }` or `{ ok: false,
// reason }`. Never rejects.
// ---------------------------------------------------------------------------
const MDS_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512',
                        'ES256', 'ES384', 'ES512', 'EdDSA'];

// The anchors a BLOB's chain must end at: the operator's, or FIDO's root out
// of node's own root store.
function fidoMdsRoots(anchorsPem) {
  log.debug("Entering fidoMdsRoots().");
  if (String(anchorsPem || '').trim()) {
    log.debug("Leaving fidoMdsRoots(). The operator's.");
    return certificateBundle(anchorsPem).certificates;
  }
  const system = certificateBundle(require('tls').rootCertificates.join('\n'))
    .certificates.filter(function (one) {
      return /CN=GlobalSign\b/.test(String(one.x509.subject)) &&
             /OU=GlobalSign Root CA - R3/.test(String(one.x509.subject));
    });
  log.debug("Leaving fidoMdsRoots(). " + system.length + " from node's " +
            "root store.");
  return system;
}

async function verifyFidoMdsBlob(token, opts) {
  log.debug("Entering verifyFidoMdsBlob().");
  const options = opts || {};
  const text = String(token || '').trim();
  const parts = text.split('.');
  if (parts.length !== 3) {
    log.debug("Leaving verifyFidoMdsBlob(). Not a JWT.");
    return { ok: false, reason: 'the BLOB is not a compact JWS (it has ' +
             parts.length + ' part(s), not 3)' };
  }
  let header = null;
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  } catch (e) {
    log.debug("Caught in verifyFidoMdsBlob(): " + ((e && e.message) || e));
    log.debug("Leaving verifyFidoMdsBlob(). Unreadable header.");
    return { ok: false, reason: 'the BLOB\'s header is not JSON' };
  }
  const x5c = Array.isArray(header && header.x5c) ? header.x5c : [];
  if (!x5c.length) {
    log.debug("Leaving verifyFidoMdsBlob(). No x5c.");
    return { ok: false, reason: 'the BLOB\'s header carries no x5c: MDS3 ' +
             'section 3.1.7 signs it with a certificate chain' };
  }
  const ders = x5c.map(function (one) {
    return Buffer.from(String(one), 'base64');
  });
  const anchors = fidoMdsRoots(options.anchorsPem);
  if (!anchors.length) {
    log.debug("Leaving verifyFidoMdsBlob(). No anchor.");
    return { ok: false, reason: 'no FIDO MDS trust anchor: none is ' +
             'configured (risk.mdsTrustAnchors) and GlobalSign Root CA - R3 ' +
             'is not in this node\'s root store' };
  }
  const path = await verifyPathToAnchors(ders[0], ders.slice(1), anchors,
                                         { now: options.now });
  if (!path.ok) {
    log.debug("Leaving verifyFidoMdsBlob(). No path.");
    return { ok: false, reason: 'the BLOB\'s signing chain does not verify: ' +
             path.reason };
  }
  const leaf = certificateFromDer(ders[0]);
  let verified = null;
  try {
    verified = stsCrypto.verifyCompactJws(text, leaf.pem,
                                          { algorithms: MDS_ALGORITHMS });
  } catch (e) {
    log.debug("Caught in verifyFidoMdsBlob(): " + ((e && e.message) || e));
    log.debug("Leaving verifyFidoMdsBlob(). Signature.");
    return { ok: false, reason: 'the BLOB\'s signature does not verify ' +
             'under its signing certificate: ' + ((e && e.message) || e) };
  }
  const payload = (verified && (verified.claims || verified.payload)) || null;
  if (!payload || typeof payload !== 'object' ||
      !Array.isArray(payload.entries) || !isFinite(Number(payload.no))) {
    log.debug("Leaving verifyFidoMdsBlob(). Not a BLOB payload.");
    return { ok: false, reason: 'the payload is not an MDS3 BLOB: it needs ' +
             'a serial number (no) and a list of entries' };
  }
  log.debug("Leaving verifyFidoMdsBlob(). Verified, no=" + payload.no + ".");
  return { ok: true, header: header, payload: payload,
           chainPems: ders.map(function (der) {
             return certificateFromDer(der).pem;
           }) };
}


// ----- sigstore signing certificates and their SCTs (#170) ----------------
//
// What `spiffe/spiffe_sigstore.ts` asks of a Fulcio (keyless cosign)
// signing certificate, answered here because every certificate question
// this service asks is answered in this module. The path itself is
// `verifyPathToAnchors()` above, at the certificate's own notBefore — cosign's
// `TrustedCert()`, which treats the certificate as trusted forever and checks
// instead that the SIGNATURE was made inside its window.

// Fulcio's extension OIDs (sigstore/fulcio docs/oid-info.md): the OIDC
// issuer, deprecated raw form and the DER UTF8String that replaced it.
const OID_FULCIO_ISSUER_V1 = '1.3.6.1.4.1.57264.1.1';
const OID_FULCIO_ISSUER_V2 = '1.3.6.1.4.1.57264.1.8';
// RFC 6962's embedded SignedCertificateTimestampList.
const OID_SCT_LIST = '1.3.6.1.4.1.11129.2.4.2';
const OID_CODE_SIGNING = '1.3.6.1.5.5.7.3.3';

// A signing certificate's facts: `{ subject, issuer, codeSigning, notBefore,
// notAfter, spki }`, `subject` being the first non-empty subjectAltName in
// the order sigstore's `GetSubjectAlternateNames()` lists them (DNS, email,
// IP, URI, then an otherName's value) — SPIRE's `extractSubject()` — and
// `issuer` the OIDC issuer extension, the UTF8String form first. null when
// the bytes are not a certificate.
function sigstoreSignerFacts(der) {
  log.debug("Entering sigstoreSignerFacts().");
  let cert = null;
  let node = null;
  try {
    cert = pkijs.Certificate.fromBER(new Uint8Array(Buffer.from(der || [])));
    node = new nodeCrypto.X509Certificate(Buffer.from(der || []));
  } catch (e) {
    log.debug("Caught in sigstoreSignerFacts(): " + ((e && e.message) || e));
    log.debug("Leaving sigstoreSignerFacts(). Not a certificate.");
    return null;
  }
  const names = { dns: [], email: [], ip: [], uri: [], other: [] };
  let issuerV1 = '';
  let issuerV2 = '';
  let codeSigning = false;
  (cert.extensions || []).forEach(function (ext) {
    try {
      if (ext.extnID === '2.5.29.17') {
        ((ext.parsedValue && ext.parsedValue.altNames) || [])
          .forEach(function (name) {
            if (name.type === 2) names.dns.push(String(name.value));
            if (name.type === 1) names.email.push(String(name.value));
            if (name.type === 6) names.uri.push(String(name.value));
            if (name.type === 7 && name.value && name.value.valueBlock) {
              const ip = Buffer.from(name.value.valueBlock.valueHexView);
              names.ip.push(ip.length === 4 ? Array.from(ip).join('.')
                                            : ip.toString('hex'));
            }
            if (name.type === 0 && name.value) {
              const inner = name.value.value;
              const block = inner && (inner.valueBlock ||
                                      (inner[0] && inner[0].valueBlock));
              if (block && typeof block.value === 'string') {
                names.other.push(block.value);
              }
            }
          });
      } else if (ext.extnID === '2.5.29.37') {
        codeSigning = ((ext.parsedValue && ext.parsedValue.keyPurposes) || [])
          .map(String).indexOf(OID_CODE_SIGNING) >= 0;
      } else if (ext.extnID === OID_FULCIO_ISSUER_V1) {
        issuerV1 = Buffer.from(ext.extnValue.valueBlock.valueHexView)
          .toString('utf8');
      } else if (ext.extnID === OID_FULCIO_ISSUER_V2) {
        const raw = Buffer.from(ext.extnValue.valueBlock.valueHexView);
        // asn1js declares `result` as the union of every block kind, most of
        // which have no string value; the check below is what narrows it.
        const read = /** @type {any} */ (asn1js.fromBER(new Uint8Array(raw)));
        if (read.offset !== -1 && read.result && read.result.valueBlock &&
            typeof read.result.valueBlock.value === 'string') {
          issuerV2 = read.result.valueBlock.value;
        }
      }
    } catch (e) {
      // An extension pkijs could not read contributes nothing, and the
      // caller's check fails on what it needed.
      log.debug("Caught in sigstoreSignerFacts(): " + ((e && e.message) || e));
    }
  });
  const subject = names.dns.concat(names.email, names.ip, names.uri,
                                   names.other).filter(Boolean)[0] || '';
  let spki = null;
  try {
    spki = Buffer.from(cert.subjectPublicKeyInfo.toSchema().toBER(false));
  } catch (e) {
    log.debug("Caught in sigstoreSignerFacts(): " + ((e && e.message) || e));
  }
  log.debug("Leaving sigstoreSignerFacts(). " + subject);
  return { subject: subject, issuer: issuerV2 || issuerV1,
           codeSigning: codeSigning,
           notBefore: Date.parse(node.validFrom),
           notAfter: Date.parse(node.validTo), spki: spki,
           pem: node.toString() };
}

// RFC 6962 section 3.2: the precertificate TBS an embedded SCT signs is the
// leaf's TBS without the SCT list extension. null when it cannot be built.
function precertificateTbs(cert) {
  log.debug("Entering precertificateTbs().");
  try {
    cert.extensions = (cert.extensions || []).filter(function (ext) {
      return ext.extnID !== OID_SCT_LIST;
    });
    const tbs = Buffer.from(cert.encodeTBS().toBER(false));
    log.debug("Leaving precertificateTbs().");
    return tbs;
  } catch (e) {
    log.debug("Caught in precertificateTbs(): " + ((e && e.message) || e));
    log.debug("Leaving precertificateTbs(). Unbuildable.");
    return null;
  }
}

// THE EMBEDDED SCTs OF A SIGNING CERTIFICATE (cosign's `VerifyEmbeddedSCT()`,
// sigstore-go's `VerifySignedCertificateTimestamp()` with a threshold of
// one): every SCT in the leaf's list is parsed, and the answer is ok when at
// least one is from a CT log in `logs` (`[{ logIdHex, spki, startMs,
// endMs }]`), was made inside that log key's window, and verifies over the
// precertificate entry — version 0, certificate_timestamp, the timestamp,
// precert_entry, SHA-256 of the ISSUER's SubjectPublicKeyInfo, the TBS
// without the list, the SCT's extensions. Resolves `{ ok, why }`.
async function verifyEmbeddedScts(leafDer, issuerDer, logs) {
  log.debug("Entering verifyEmbeddedScts().");
  let leaf = null;
  let issuer = null;
  try {
    leaf = pkijs.Certificate.fromBER(new Uint8Array(Buffer.from(leafDer)));
    issuer = pkijs.Certificate.fromBER(new Uint8Array(Buffer.from(issuerDer)));
  } catch (e) {
    log.debug("Caught in verifyEmbeddedScts(): " + ((e && e.message) || e));
    log.debug("Leaving verifyEmbeddedScts(). Unreadable.");
    return { ok: false, why: 'the certificate or its issuer could not be ' +
             'read' };
  }
  const ext = (leaf.extensions || []).filter(function (one) {
    return one.extnID === OID_SCT_LIST;
  })[0];
  if (!ext) {
    log.debug("Leaving verifyEmbeddedScts(). None.");
    return { ok: false, why: 'certificate does not include required ' +
             'embedded SCT' };
  }
  let list = null;
  try {
    // The same union as above; an OCTET STRING has the hex view, and any
    // other block throws here and is refused below.
    const read = /** @type {any} */ (asn1js.fromBER(new Uint8Array(
      Buffer.from(ext.extnValue.valueBlock.valueHexView))));
    list = Buffer.from(read.result.valueBlock.valueHexView);
  } catch (e) {
    log.debug("Caught in verifyEmbeddedScts(): " + ((e && e.message) || e));
  }
  if (!list || list.length < 2 || list.readUInt16BE(0) !== list.length - 2) {
    log.debug("Leaving verifyEmbeddedScts(). A malformed list.");
    return { ok: false, why: 'the embedded SCT list is malformed' };
  }
  const tbs = precertificateTbs(leaf);
  let issuerKeyHash = null;
  try {
    issuerKeyHash = nodeCrypto.createHash('sha256').update(Buffer.from(
      issuer.subjectPublicKeyInfo.toSchema().toBER(false))).digest();
  } catch (e) {
    log.debug("Caught in verifyEmbeddedScts(): " + ((e && e.message) || e));
  }
  if (!tbs || !issuerKeyHash) {
    log.debug("Leaving verifyEmbeddedScts(). No entry to verify.");
    return { ok: false, why: 'the precertificate entry could not be built' };
  }
  const tbsLength = Buffer.alloc(3);
  tbsLength.writeUIntBE(tbs.length, 0, 3);
  const problems = [];
  let at = 2;
  while (at + 2 <= list.length) {
    const size = list.readUInt16BE(at);
    const sct = list.subarray(at + 2, at + 2 + size);
    at += 2 + size;
    if (sct.length !== size || size < 47 || sct[0] !== 0) {
      problems.push('an SCT that is not version 1');
      continue;
    }
    const logId = sct.subarray(1, 33).toString('hex');
    const timestamp = Number(sct.readBigUInt64BE(33));
    const extLength = sct.readUInt16BE(41);
    const extensions = sct.subarray(43, 43 + extLength);
    let p = 43 + extLength;
    if (p + 4 > sct.length) {
      problems.push('a truncated SCT');
      continue;
    }
    const sigLength = sct.readUInt16BE(p + 2);
    const signature = sct.subarray(p + 4, p + 4 + sigLength);
    p += 4 + sigLength;
    if (p !== sct.length || signature.length !== sigLength) {
      problems.push('a truncated SCT signature');
      continue;
    }
    const trusted = (logs || []).filter(function (one) {
      return String(one.logIdHex || '').toLowerCase() === logId;
    })[0];
    if (!trusted) {
      problems.push('an SCT from a CT log not in the trust root (' + logId +
                    ')');
      continue;
    }
    if ((trusted.startMs && timestamp < trusted.startMs) ||
        (trusted.endMs && timestamp > trusted.endMs)) {
      problems.push('an SCT made outside its log key\'s validity');
      continue;
    }
    const time = Buffer.alloc(8);
    time.writeBigUInt64BE(BigInt(timestamp));
    const extLen = Buffer.alloc(2);
    extLen.writeUInt16BE(extensions.length);
    const signed = Buffer.concat([Buffer.from([0, 0]), time,
                                  Buffer.from([0, 1]), issuerKeyHash,
                                  tbsLength, tbs, extLen, extensions]);
    if (await stsCrypto.verifyWithPublicKey(trusted.spki, signed,
                                            signature)) {
      log.debug("Leaving verifyEmbeddedScts(). Verified by " + logId);
      return { ok: true, why: '' };
    }
    problems.push('an SCT whose signature does not verify under its log');
  }
  log.debug("Leaving verifyEmbeddedScts(). None verified.");
  return { ok: false, why: 'no embedded SCT verified: ' +
           (problems.join('; ') || 'the list is empty') };
}

module.exports = {
  // --- sigstore signing certificates (#170) ---
  sigstoreSignerFacts: sigstoreSignerFacts,
  verifyEmbeddedScts: verifyEmbeddedScts,
  // --- somebody else's certificates (#40) ---
  certificateFromDer: certificateFromDer,
  certificateBundle: certificateBundle,
  rsaKeyBits: rsaKeyBits,
  spkiOf: spkiOf,
  keyUsageOf: keyUsageOf,
  verifyPathToAnchors: verifyPathToAnchors,
  verifyIssuedDirectly: verifyIssuedDirectly,
  peerChainProblem: peerChainProblem,
  pathFactsOf: pathFactsOf,
  pathPolicyOutcome: pathPolicyOutcome,
  pathRuleProblem: pathRuleProblem,
  // --- WebAuthn attestation certificates (#105) ---
  attestationCertificateFacts: attestationCertificateFacts,
  attestationKeyIdentifier: attestationKeyIdentifier,
  // --- the FIDO MDS3 BLOB (#62 P5) ---
  fidoMdsRoots: fidoMdsRoots,
  verifyFidoMdsBlob: verifyFidoMdsBlob,
  SSH_HOST_CERT: SSH_HOST_CERT,
  parseSshPublicKey: parseSshPublicKey,
  parseSshAuthorizedKey: parseSshAuthorizedKey,
  sshFingerprint: sshFingerprint,
  verifySshSignature: verifySshSignature,
  checkSshHostCertificate: checkSshHostCertificate,
  awsIidCertificate: awsIidCertificate,
  azureImdsRoots: azureImdsRoots,
  TIERS: TIERS,
  TIER_IDS: TIER_IDS,
  // A GETTER, so a reader of `pki.MAX_OBJECTS` sees `pki.maxStoredObjects`.
  get MAX_OBJECTS() {
    log.debug("Entering MAX_OBJECTS().");
    log.debug("Leaving MAX_OBJECTS().");
    return maxObjects();
  },
  maxObjects: maxObjects,
  roomForObject: roomForObject,
  leafLifetimeDays: leafLifetimeDays,
  tierYearsFrom: tierYearsFrom,
  // The hierarchy's new shape (2026-09-11): one Root for the service, an
  // Intermediate per scope, and an Issuing CA per use case.
  SERVICE_SCOPE: SERVICE_SCOPE,
  PROCESS_SCOPE: PROCESS_SCOPE,
  USE_CASES: USE_CASES,
  USE_CASE_IDS: USE_CASE_IDS,
  useCase: useCase,
  useCasesFor: useCasesFor,
  scopeKindOf: scopeKindOf,
  serviceRoot: serviceRoot,
  hasRoot: hasRoot,
  // Whether a scope's Intermediate carries the current Root's signature, for
  // `tls_server.js`'s reconcile (2026-09-13): the front process of a dispatched
  // service waits for a branch that does not, rather than building one.
  scopeChainsToRoot: scopeChainsToRoot,
  buildRoot: buildRoot,
  ensureRoot: ensureRoot,
  buildScope: buildScope,
  repairBranch: repairBranch,
  ensureScope: ensureScope,
  describeScope: describeScope,
  describeTree: describeTree,
  describeTier: describeTier,
  // The certificate register.
  certify: certify,
  // Issue WITHOUT recording, for a caller that owns what comes out — see
  // `issueUnder()`'s header. `spiffe/spiffe_ca.ts` is the caller.
  issueUnder: issueUnder,
  // The door ACME, EST and SCEP sign through — `issueUnder()` plus the
  // profile's extensions, the family CA's CDP/AIA and a record OCSP reads.
  issueEnrolled: issueEnrolled,
  describeIssuer: describeIssuer,
  certifyKeySet: certifyKeySet,
  certifyStandbyKeys: certifyStandbyKeys,
  // The eleven post-quantum keys per realm, under its JOSE Issuing CA
  // (2026-09-13) — and the one translation that makes that possible, exported
  // so the test can hold it against both readings.
  certifyPqKeys: certifyPqKeys,
  PQ_JOSE_IN_X509: PQ_JOSE_IN_X509,
  pqSubjectPublicKeyPem: pqSubjectPublicKeyPem,
  registerCertifiable: registerCertifiable,
  certifyRegistered: certifyRegistered,
  // Editing the hierarchy: a new key for one authority, a renewal under the
  // same one, and the two doors for material an operator supplied.
  reissueUseCase: reissueUseCase,
  recertifyUseCase: recertifyUseCase,
  recertifyOrphanedSlots: recertifyOrphanedSlots,
  importCa: importCa,
  pinKeyPair: pinKeyPair,
  certificatesFor: certificatesFor,
  issuedKeyPairsFor: issuedKeyPairsFor,
  certificateFor: certificateFor,
  describeCertificate: describeCertificate,
  pinnedKeyFor: pinnedKeyFor,
  publishedCertificateFor: publishedCertificateFor,
  forgetCertificate: forgetCertificate,
  issueTlsServerKeyPair: issueTlsServerKeyPair,
  certifyVerifierKey: certifyVerifierKey,
  verifierCertificateFor: verifierCertificateFor,
  MAX_VERIFIER_CERTIFICATES: MAX_VERIFIER_CERTIFICATES,
  TLS_SERVER_KEY_ALGS: TLS_SERVER_KEY_ALGS,
  DEFAULT_TLS_SERVER_KEY_ALG: DEFAULT_TLS_SERVER_KEY_ALG,
  // Startup. `common/service_state.ts` calls it, for `server.js` and a
  // request worker, after `keystore.start()` and before anything binds.
  start: start,
  SUBJECT_KINDS: SUBJECT_KINDS,
  SUBJECT_KIND_IDS: SUBJECT_KIND_IDS,
  subjectKindFor: subjectKindFor,
  PURPOSES: PURPOSES,
  PURPOSE_IDS: PURPOSE_IDS,
  purposeFor: purposeFor,
  DEFAULT_KEY_ALG: DEFAULT_KEY_ALG,
  DEFAULT_SIG_ALG: DEFAULT_SIG_ALG,
  keyAlgorithms: keyAlgorithms,
  signatureAlgorithms: signatureAlgorithms,
  alternativeKeyAlgs: alternativeKeyAlgs,
  certifySignerGroups: certifySignerGroups,
  alternativeProblem: alternativeProblem,
  defaultSignatureAlgorithmFor: defaultSignatureAlgorithmFor,
  // What a build would sign with, decided before any key is made — exported
  // for `tests/mode_weak_settings.js` (#181), which asks it about SHA-1 in
  // each mode without building a hierarchy to find out.
  algorithmsFrom: algorithmsFrom,
  buildChain: buildChain,
  hasChain: hasChain,
  describe: describe,
  chainPemFor: chainPemFor,
  trustAnchorsFor: trustAnchorsFor,
  issueSigningKeyPair: issueSigningKeyPair,
  issueEncryptionKeyPair: issueEncryptionKeyPair,
  ENCRYPTION_KEY_ALGS: ENCRYPTION_KEY_ALGS,
  registerCertificate: registerCertificate,
  verifyLeaf: verifyLeaf,
  // The signer certificate's chain, validated wherever an RFC 7523 or RFC 7522
  // signature is (2026-09-13), and the one sentence a door logs about it.
  verifySignerChain: verifySignerChain,
  signerChainSummary: signerChainSummary,
  clearChain: clearChain,
  // The object store and the issuer list, which `common/pki_authoring.ts`
  // reads. They are here rather than there because the ROW is this module's —
  // see THE OBJECT STORE above.
  // The row accessors, for `common/pki_revocation.js`. They are exported
  // rather than that module keeping its own copy of the store for the reason
  // this file keeps no store of its own: two readers of one keystore row is
  // one reader too many, and the second is the one that goes stale.
  rawRowFor: rawRowFor,
  saveRow: saveRow,
  knownScopes: knownScopes,
  objects: objects,
  objectFor: objectFor,
  putObject: putObject,
  removeObject: removeObject,
  clearObjects: clearObjects,
  issuers: issuers,
  issuerFor: issuerFor,
  thumbprintOf: thumbprintOf,
  // THE CLUSTER'S BUILD AND READ (2026-09-14, #46), for a module that keeps
  // something in a scope's row which one node must make for all of them —
  // `scep/scep_ra.ts`'s RA certificate. `refreshScope()` lands this process's
  // queued writes of the row and takes what the store holds.
  oneBuildInTheCluster: oneBuildInTheCluster,
  refreshScope: function (scopeId) {
    log.debug("Entering refreshScope().");
    log.debug("Leaving refreshScope().");
    return typeof keystore.arbitrates === 'function' && keystore.arbitrates()
      ? keystore.refreshPki(String(scopeId))
      : Promise.resolve(null);
  },
  report: report
};

// DECLARED AT REQUIRE TIME (cluster/CLAUDE.md). The Root, the Intermediates
// and the Issuing CAs are built once for the cluster — one build of a scope at
// a time across nodes, the store read before and after the claim, a tier first
// writer wins in the merge — and a row another node wrote is adopted and
// reconciled with the listener (`keystore.applyStoredChange()`,
// `request_pool.js`'s `hierarchyArrived()`).
capabilities.provide('pki.agreement');
