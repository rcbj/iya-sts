'use strict';
//
// File: vc_did.js
//
// ---------------------------------------------------------------------------
// This issuer's DECENTRALIZED IDENTIFIER (W3C DID Core 1.0) and the two
// documents that make it discoverable and believable: the did:web document, and
// the DIF Well Known DID Configuration that links the DID to this origin.
//
// Kept apart from vc_issuer.js because it is asked about from both directions —
// the metadata advertises the DID, the credential builders name it, and the two
// documents here are served whether or not any credential uses one. It reads
// vc_configs.js to decide per configuration and is read by vc_issuer.js in
// turn, which is why the configuration registry is its own module: with the
// registry inside vc_issuer.js these two would require each other.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
const forge = require('node-forge');
// One signer and one verifier for the whole service since 2026-08-27.
const stsCrypto = require('../common/crypto');
const app = require('../common/app');
const bbs2023 = require('../common/vendored/bbs2023.js');
const { log, logArtifact, PORT, STS, baseUrlOf, bbsKeyPair, signingKeyFor,
        stsKeysFor } = require('../common/helpers');
// The identity registry, for ONE call at the generator endpoint below: a DID
// this service mints is an identity it has created, and this is the funnel the
// embedded directory grows an entry off. A library — it registers no route and
// nothing it requires reaches this module — so requiring it here cannot move a
// route or make a cycle.
const stats = require('../common/admin_stats');
// The configuration table, for the two DID flags below. A library like the
// others here: it registers no route and requires only two leaves
// (`config_file.js`, `error_codes.js`), so it cannot join a cycle wherever it
// is required from.
const config = require('../common/config');
// The error codes (common/error_codes.js). A LEAF that requires nothing; a code
// is marked on the response object and never written into a response.
const errorCodes = require('../common/error_codes');
const { VCI_CONFIGS } = require('./vc_configs');
// ---------------------------------------------------------------------------
// This issuer's DECENTRALIZED IDENTIFIER (W3C DID Core 1.0).
//
// did:web, because it is the only method with a document to serve: did:jwk and
// did:key resolve from the identifier itself and would make this endpoint
// pointless. The method-specific id is the host with its port percent-encoded,
// which is why a DID for localhost:8081 reads did:web:localhost%3A8081 — and
// why the document lives at /.well-known/did.json.
//
// The DID is always SERVED — the document and the domain linkage below cost
// nothing and are what make the DID discoverable. What is opt-in is naming
// CREDENTIALS by it, and there are two ways to ask, for two different reasons:
//
//   * the IdentityCredentialDid / IdentityCredentialLdpVcDid configurations,
//     which always do. A wallet asks for one by name, so both routes are live
//     in the same issuer at the same time and can be compared.
//   * the two startup flags below, which switch the PLAIN configurations over —
//     what a deployment that had gone to DIDs throughout would look like.
//
// The flags default OFF, and the reason is per format:
//
//   ldp_vc      VC Data Model 2.0 and Data Integrity are DID-native; naming the
//               issuer by DID is ordinary there. Off only because ldp_vc's
//               verificationMethod is an https URL that existing tests
//               dereference, and switching it to a DID URL silently breaks that.
//   dc+sd-jwt   draft-ietf-oauth-sd-jwt-vc defines NO DID-based issuer signature
//               mechanism — "A DID-based mechanism is not explicitly provided
//               herein but still possible via profile/extension" (-10 changelog).
//               So this is an extension, and the spec's own route
//               (/.well-known/jwt-vc-issuer) is what the plain configuration must
//               go on exercising.
// ---------------------------------------------------------------------------
// BOTH ARE READ FROM THE CONFIGURATION TABLE, and were `process.env` here until
// 2026-08-24. They were the last two environment variables in this service with
// no row in config.js, which cost two things: they could not be set in an
// appconfig file at all, and `didFlag()` compared against the literal 'true',
// so `OID4VCI_LDP_VC_ISSUER_DID=1` was silently false where every other boolean
// setting here takes 1/yes/on. `oid4vci.sdJwtIssuerDid` and
// `oid4vci.ldpVcIssuerDid` are those variables, unchanged in name and default.
//
// Still read ONCE, at require time, which is why the table marks them
// restart-only: the metadata below is built from what they said, and a value
// that changed underneath it would leave a credential and the document
// describing it disagreeing about how the issuer is named.
const SD_JWT_ISSUER_DID = config.value('oid4vci.sdJwtIssuerDid');

const LDP_VC_ISSUER_DID = config.value('oid4vci.ldpVcIssuerDid');

// did:web for whatever host this request arrived on, so the same container
// works at localhost:8081, sts:8081 and behind a published port without being
// told which it is.
//
// ---------------------------------------------------------------------------
// DERIVED FROM `baseUrlOf(req)` SINCE 2026-09-12, AND THE PATH IS PART OF IT.
//
// It read the raw Host header, which was wrong three ways at once:
//
//   * A TRUST REALM'S DID WAS THE DEFAULT REALM'S.
//     /realm/acme/.well-known/did.json published `did:web:host%3A8081` with
//     acme's keys in it, so resolving the DID a realm's credential names
//     fetched the DEFAULT realm's document and the signature failed against the
//     wrong key — or, worse, two realms claimed one DID.
//   * `global.publicBaseUrl` and `global.trustProxy` were ignored, so behind a
//     proxy the DID named the last hop while the issuer identifier beside it
//     named the public origin.
//   * A base URL WITH A PATH has a did:web of its own shape. The did:web method
//     specification turns path segments into `:`-separated components —
//     `did:web:example.com:realm:acme` — and resolves that to
//     `https://example.com/realm/acme/did.json`, NOT to a well-known path.
//
// So the host is `baseUrlOf()`'s host, its port colon percent-encoded as
// before, and every path segment of the base becomes a component. With no
// realm prefix and nothing pinned the base has no path, and the DID is
// byte-for-byte what the Host header produced — which is the compatibility
// line every existing caller rests on. The document for a path-ful DID is
// served at `<base>/did.json` below.
// ---------------------------------------------------------------------------
function stsDid(req) {
  log.debug("Entering stsDid().");
  if (!req || !req.get) {
    log.debug("Leaving stsDid().");
    return 'did:web:' + ('localhost:' + PORT).replace(/:/g, '%3A');
  }
  const parts = didWebPartsOf(baseUrlOf(req));
  log.debug("Leaving stsDid().");
  return 'did:web:' +
         [parts.host.replace(/:/g, '%3A')].concat(
             parts.segments.map(function (one) {
    return one.replace(/:/g, '%3A');
  })).join(':');
}

// A base URL as did:web sees it: the authority, and the path segments. Parsed
// by hand rather than through `new URL()`, which would drop a default port the
// Host header carried and change the DID for a caller who sent one.
function didWebPartsOf(base) {
  log.debug("Entering didWebPartsOf().");
  const rest = String(base || '').replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  const slash = rest.indexOf('/');
  log.debug("Leaving didWebPartsOf().");
  return {
    host: slash < 0 ? rest : rest.slice(0, slash),
    segments: slash < 0 ? [] : rest.slice(slash).split('/').filter(Boolean)
  };
}

// The algorithm and key this issuer's DID-named artefacts are signed with —
// `oid4vci.credentialSigningAlgorithm`, the same setting the credentials use,
// because a credential whose `iss` is this DID is verified against a key the
// DID document publishes, and the Domain Linkage Credential is the same DID
// signing. RS256 is the RSA key exactly as before.
function didSigner() {
  log.debug("Entering didSigner().");
  const alg = String(config.value('oid4vci.credentialSigningAlgorithm') ||
                     'RS256');
  if (alg === 'RS256') {
    log.debug("Leaving didSigner(). RS256.");
    return { alg: 'RS256', key: STS.privateKey, kid: STS.kid };
  }
  const signer = signingKeyFor(alg);
  log.debug("Leaving didSigner(). " + alg + ".");
  return { alg: alg, key: signer.key, kid: signer.kid };
}

// The DID Document. At least two verification methods, because this issuer
// signs two quite different things: JWTs (RS256 for every token, and for the
// SD-JWT VCs unless `oid4vci.credentialSigningAlgorithm` names another key —
// which is then a third method, below) and bbs-2023 Data Integrity proofs (the
// ldp_vc credentials). A BBS key has no
// registered JOSE kty, so it appears as a Multikey exactly as it does at
// /bbs/keys/1 rather than being forced into a publicKeyJwk it does not fit.
async function stsDidDocument(req) {
  log.debug("Entering stsDidDocument().");
  const did = stsDid(req);
  // The same RSA public key the JWKS publishes, read out of the certificate the
  // same way — one source of truth for what this issuer signs with, so a DID
  // document and a JWKS can never describe different keys.
  const pub = forge.pki.certificateFromPem(STS.certPem).publicKey;
  const b64uHex = function (hex) {
    log.debug("Entering b64uHex().");
    log.debug("Leaving b64uHex().");
    return Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex')
                 .toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const methods = [{
    id: did + '#' + STS.kid,
    type: 'JsonWebKey2020',
    controller: did,
    publicKeyJwk: {
      kty: 'RSA', use: 'sig', alg: 'RS256', kid: STS.kid,
      n: b64uHex(pub.n.toString(16)), e: b64uHex(pub.e.toString(16))
    }
  }];
  // THE CREDENTIAL KEY, WHERE IT IS NOT THE RSA ONE (2026-09-12). A realm whose
  // `oid4vci.credentialSigningAlgorithm` names a curve algorithm signs its
  // DID-named credentials and its Domain Linkage Credential with that curve
  // key, and a verifier resolving this DID must find it here. Its public JWK is
  // read off the realm's key set — the same object /oauth2/jwks publishes — so
  // the two documents cannot describe different keys. Nothing is added for
  // RS256, which keeps the document exactly as it was.
  const signer = didSigner();
  if (signer.alg !== 'RS256' && signer.kid !== STS.kid) {
    const extra = (stsKeysFor().extraKeys || []).filter(function (one) {
      return one.publicJwk && one.publicJwk.kid === signer.kid;
    })[0];
    if (extra) {
      methods.push({ id: did + '#' + signer.kid, type: 'JsonWebKey2020',
                     controller: did,
                     publicKeyJwk: extra.publicJwk });
    } else {
      log.error(errorCodes.tag('STS-VC-0043') +
                'the ' + signer.alg + ' key credentials are signed with is ' +
                'not in this realm\'s key set, so the DID document cannot ' +
                'publish it.');
    }
  }
  try {
    const keys = await bbsKeyPair();
    methods.push({
      id: did + '#bbs-1',
      type: 'Multikey',
      controller: did,
      // Same encoding as /bbs/keys/1: multibase base64url, which is "u" and
      // then the raw compressed bytes. A BBS key has no registered JOSE kty, so
      // it cannot be a publicKeyJwk however convenient that would be.
      publicKeyMultibase: 'u' + bbs2023.bytesToB64u(keys.publicKey)
    });
  } catch (e) {
    // The BBS half is optional here: an ldp_vc issued while it is unavailable
    // would fail earlier and louder than a missing verification method.
    log.error(errorCodes.tag('STS-VC-0044') +
              'the BBS key could not be published in the DID document: ' +
              e.message);
  }
  log.debug("Leaving stsDidDocument().");
  return {
    '@context': ['https://www.w3.org/ns/did/v1',
                 'https://w3id.org/security/suites/jws-2020/v1'],
    id: did,
    verificationMethod: methods,
    authentication: [methods[0].id],
    assertionMethod: methods.map(function (m) { return m.id; })
  };
}

// Is this request's DID one with a PATH — a trust realm, or a pinned base URL
// with a path in it? Such a DID resolves to `<base>/did.json` rather than to
// the well-known location.
function didHasPath(req) {
  log.debug("Entering didHasPath().");
  log.debug("Leaving didHasPath().");
  return didWebPartsOf(baseUrlOf(req)).segments.length > 0;
}

// did:web resolution is a plain GET of this document. no-store for the same
// reason the JWKS is: the keys it describes are regenerated on every start in
// development mode, so a cached copy outlives them — and every document that
// describes a key is no-store in either mode (root CLAUDE.md).
async function sendDidDocument(req, res) {
  log.debug("Entering the did:web document endpoint.");
  const doc = await stsDidDocument(req);
  logArtifact('DID Document', 'as served', doc);
  res.set('Cache-Control', 'no-store');
  res.status(200)
     .type('application/did+json')
     .send(JSON.stringify(doc, null, 2));
  log.debug("Leaving the did:web document endpoint. " +
      doc.verificationMethod.length + " " +
      "method(s).");
}

app.get('/.well-known/did.json', sendDidDocument);

// ---------------------------------------------------------------------------
// THE did:web LOCATION FOR A DID WITH A PATH (2026-09-12). The method
// specification resolves `did:web:example.com:realm:acme` to
// `https://example.com/realm/acme/did.json`, so a realm's DID — see stsDid() —
// is only resolvable if its document is there. The realm middleware strips
// the prefix, so this route is `/did.json` and it answers in the realm the
// request named.
//
// Where the DID has NO path this answers 404 with the location that does
// resolve, rather than serving the document at a second address: a DID of the
// bare-host shape is resolved at the well-known path and nowhere else, and a
// document served where no resolver looks is a document that disagrees with
// nothing until the day it does.
// ---------------------------------------------------------------------------
app.get('/did.json', async function (req, res) {
  log.debug("Entering the path-form did:web document endpoint.");
  if (!didHasPath(req)) {
    log.debug("Leaving the path-form did:web document endpoint. This DID has " +
              "no path.");
    res.set('Cache-Control', 'no-store');
    errorCodes.mark(res, 'STS-VC-0045');
    return res.status(404).type('application/json').send(JSON.stringify({
      error: 'not_found',
      error_description: 'This DID (' + stsDid(req) + ') has no path, so ' +
                                                      'did:web resolves it ' +
                                                      'at ' +
        baseUrlOf(req) + '/.well-known/did.json.'
    }, null, 2));
  }
  log.debug("Leaving the path-form did:web document endpoint. Handing over.");
  return sendDidDocument(req, res);
});

// ---------------------------------------------------------------------------
// Well Known DID Configuration (DIF) — /.well-known/did-configuration.json
//
// This is the document that answers the question the other two cannot. The DID
// document says "this DID has these keys". The credential says "I was issued by
// did:web:sts%3A8081". Neither says why anyone should believe that DID is the
// same entity as the https issuer the wallet discovered, and for did:web the
// circularity is the trap: the DID resolves by fetching the very origin whose
// claim is in question, so "the DID document says so" establishes nothing
// extra.
//
// A Domain Linkage Credential is the assertion in the other direction — the
// DID, signing with its own key, naming the origin — and it is checkable:
// resolve the issuer DID independently, verify the signature against its
// assertionMethod, and require that credentialSubject.origin is the origin the
// document came from. On success the origin's controller and the DID's
// controller are one entity.
//
// The JWT form rather than the Linked Data Proof form, for two reasons: this
// issuer signs RS256 JWTs everywhere else, so the same key and the same JWKS
// verify it; and the LD form would need a JsonWebSignature2020 over URDNA2015
// canonicalization, which is real work for no additional teaching.
//
// Two details of the JWT form are easy to get wrong and are asserted by
// tests/did_document.js, because both produce a document that looks right:
//
//   * the header MUST NOT carry typ, and jsonwebtoken adds typ: "JWT" unless
//     the header override explicitly sets it undefined;
//   * the payload permits no members beyond iss/sub/nbf/exp/vc, and
//     jsonwebtoken adds iat unless told noTimestamp.
//
// Note the origin here is whatever this container is reached at, http included.
// The spec assumes https; the stacks here are https by default, but one run
// with `STS_HTTPS=false` has no TLS, and the same deviation is already taken by
// did:web resolution over http.
// ---------------------------------------------------------------------------
const DID_CONFIGURATION_CONTEXT =
    'https://identity.foundation/.well-known/did-configuration/v1';

async function domainLinkageCredential(req) {
  log.debug("Entering domainLinkageCredential().");
  const did = stsDid(req);
  const origin = baseUrlOf(req);
  const now = Math.floor(Date.now() / 1000);
  // `oid4vci.domainLinkageLifetimeS`, a year by default (2026-09-12).
  const exp = now +
              (Number(config.value('oid4vci.domainLinkageLifetimeS')) ||
               365 * 24 * 3600);
  // issuer and credentialSubject.id are both the DID: a domain linkage
  // credential is self-issued by definition — nobody else is in a position to
  // say which origin a DID controls. `id` is deliberately absent at the
  // credential root, which the specification requires.
  const vc = {
    '@context': ['https://www.w3.org/2018/credentials/v1',
                 DID_CONFIGURATION_CONTEXT],
    issuer: did,
    issuanceDate: new Date(now * 1000).toISOString(),
    expirationDate: new Date(exp * 1000).toISOString(),
    type: ['VerifiableCredential', 'DomainLinkageCredential'],
    credentialSubject: { id: did, origin: origin }
  };
  logArtifact('Domain Linkage Credential', 'before signing', vc);
  // The configured credential algorithm — see didSigner() — with the kid still
  // a DID URL into this DID's own document, which is what the DIF specification
  // requires of the JWT form.
  const signer = didSigner();
  // certificate-header: none — the DIF specification allows exactly `alg`
  // and `kid` in this header, so an x5c or x5u would make the linkage
  // non-conformant (common/jose_certificate_header.js).
  const token = stsCrypto.signJws({ iss: did, sub: did, nbf: now, exp: exp,
                                    vc: vc }, signer.key, {
    algorithm: signer.alg,
    noTimestamp: true,
    header: { alg: signer.alg, kid: did + '#' + signer.kid, typ: undefined }
  });
  logArtifact('Domain Linkage Credential', 'after signing (JWT form)', token);
  log.debug("Leaving domainLinkageCredential(). did=" + did + ", origin=" +
            origin);
  return token;
}

app.get('/.well-known/did-configuration.json', async function (req, res) {
  log.debug("Entering the DID Configuration endpoint.");
  const doc = {
    '@context': DID_CONFIGURATION_CONTEXT,
    linked_dids: [await domainLinkageCredential(req)]
  };
  logArtifact('DID Configuration', 'as served', doc);
  // no-store for the same reason as the DID document: the key that signed this
  // is regenerated on every start in development mode, so a cached copy
  // verifies against nothing.
  res.set('Cache-Control', 'no-store');
  res.status(200).type('application/json').send(JSON.stringify(doc, null, 2));
  log.debug("Leaving the DID Configuration endpoint.");
});

// ---------------------------------------------------------------------------
// NON-SPEC, for tests and for trying the DID Tools page: generate a DID that
// can actually be VERIFIED.
//
// No specification defines this. It exists because a DID on its own proves
// nothing — the interesting checks are "does a key in this document verify
// something it signed" and "does an origin vouch for this DID" — and both need
// an artifact to check. Handing back a DID with no credential signed by it
// would make a test that could only assert the document parsed.
//
// Two methods, because they exercise genuinely different code in the wallet:
//
//   jwk  the identifier IS the key, so it resolves with NO network call. Generated
//        fresh per request from a new P-256 key, and the credential is signed with
//        that key (ES256) — so verifying it exercises the local-decode path end to
//        end and cannot pass by accident against this service's RSA key.
//   web  this service's own did:web, whose document is served at
//        /.well-known/did.json and whose domain linkage is at
//        /.well-known/did-configuration.json. The credential is signed with the
//        RS256 key that document publishes.
//
// did:key is deliberately absent: encoding one needs multicodec varints and
// base58btc, which live in the wallet (client/src/did.js) and would be a second
// implementation here — exactly the kind of duplication that lets two encoders
// agree with each other and with nobody else.
// ---------------------------------------------------------------------------
function generatedDidJwk() {
  log.debug("Entering generatedDidJwk().");
  const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const publicJwk = pair.publicKey.export({ format: 'jwk' });
  // The member order is the one a did:jwk is conventionally built from, and it
  // is not cosmetic: the identifier is the base64url of these exact bytes, so a
  // different order is a different DID for the same key.
  const ordered = { crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x,
                    y: publicJwk.y };
  const did = 'did:jwk:' +
              Buffer.from(JSON.stringify(ordered), 'utf8').toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const document = {
    '@context': ['https://www.w3.org/ns/did/v1',
                 'https://w3id.org/security/suites/jws-2020/v1'],
    id: did,
    verificationMethod: [{ id: did + '#0', type: 'JsonWebKey2020',
                           controller: did,
                           publicKeyJwk: ordered }],
    authentication: [did + '#0'],
    assertionMethod: [did + '#0']
  };
  log.debug("Leaving generatedDidJwk(). did=" + did.slice(0, 40) + "…");
  return { did: did, document: document, publicJwk: ordered,
           privateKeyPem: pair.privateKey.export(
               { type: 'pkcs8', format: 'pem' }) };
}

// An SD-JWT VC naming `issuerDid` as its iss and signed with the key that DID
// publishes. Minimal on purpose — one Disclosure and a cnf — because what is
// being tested is the SIGNATURE against a resolved document, not the
// credential's shape. `privateKey` is whatever jsonwebtoken will sign with: the
// ONE caller that names the STS key passes the parsed KeyObject that helpers.js
// holds, and the one that generates a throwaway did:jwk key passes that key's
// PEM, because it has never been parsed and is used exactly once. Both are
// valid here and the parameter is named for the pair rather than for either.
function credentialSignedBy(issuerDid, privateKey, alg, kid) {
  log.debug("Entering credentialSignedBy(). alg=" + alg);
  const now = Math.floor(Date.now() / 1000);
  const salt = crypto.randomBytes(16).toString('base64url');
  const disclosure = Buffer.from(JSON.stringify([salt, 'given_name', 'Ada']),
                                 'utf8')
    .toString('base64url');
  const digest = crypto.createHash('sha256')
                       .update(disclosure, 'ascii')
                       .digest('base64url');
  const holder = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const holderJwk = holder.publicKey.export({ format: 'jwk' });
  const payload = {
    iss: issuerDid, nbf: now,
    // `oid4vci.generatedDidCredentialLifetimeS`, an hour by default
    // (2026-09-12).
    exp: now +
         (Number(config.value('oid4vci.generatedDidCredentialLifetimeS')) ||
          3600),
    vct: 'urn:idptools:did-tools:generated',
    sub: 'urn:uuid:' + crypto.randomUUID(),
    cnf: { jwk: { kty: holderJwk.kty, crv: holderJwk.crv, x: holderJwk.x,
                  y: holderJwk.y } },
    _sd_alg: 'sha-256', _sd: [digest]
  };
  const header = { alg: alg, typ: 'dc+sd-jwt' };
  if (kid) header.kid = kid;
  logArtifact('generated SD-JWT VC', 'before signing',
              { header: header, payload: payload });
  // certificate-header: none — a key the request generated and nobody
  // certified, so there is no chain to name.
  const signed = stsCrypto.signJws(payload, privateKey,
                                   { algorithm: alg, header: header });
  logArtifact('generated SD-JWT VC', 'after signing', signed);
  log.debug("Leaving credentialSignedBy().");
  return signed + '~' + disclosure + '~';
}

app.get('/did/generate', async function (req, res) {
  log.debug("Entering the DID generator endpoint.");
  const method = String(req.query.method || 'jwk').toLowerCase();
  if (method !== 'jwk' && method !== 'web') {
    errorCodes.mark(res, 'STS-VC-0046');
    res.status(400).type('application/json').send(JSON.stringify({
      error: 'invalid_request',
      error_description: 'method must be jwk or web. did:key is not ' +
        'generated here: encoding one needs multicodec and base58btc, which ' +
        'live in the wallet, and a second implementation would be free to ' +
        'agree only with itself.'
    }, null, 2));
    log.debug("Leaving the DID generator endpoint. Refused method " + method +
              ".");
    return;
  }

  let body;
  if (method === 'jwk') {
    const generated = generatedDidJwk();
    // -------------------------------------------------------------------------
    // The DID this endpoint just minted, recorded — which is what gives it a
    // directory entry, through the observer admin_stats.js installs for
    // ldap_server.js.
    //
    // It is the weakest of the recording sites in this service and it is worth
    // being explicit about why it is here at all: nothing was PRESENTED and
    // nobody was authenticated. What happened is that this service created an
    // identity, which is the same act as seeding a Kerberos principal on first
    // sight, and an identity this service created that appears in no directory
    // is the gap this endpoint had. The method says plainly that it was
    // generated.
    //
    // The `web` branch below gets NO such call, and that is a difference rather
    // than an omission: the DID there is this service's OWN — the issuer's
    // identity, already published at /.well-known/did.json — and a directory
    // entry for it would file the issuer among the people, with an invented
    // given name and a fictional mailbox attached to the thing that signs every
    // credential.
    // -------------------------------------------------------------------------
    stats.recordAuthentication({
      presented: generated.did,
      protocol: 'W3C DID Core',
      method: 'did:jwk generated at /did/generate',
      note: 'Minted by this service on request. Nothing was presented and ' +
            'nobody was authenticated; the key pair behind it was generated ' +
            'here and is returned to the caller.'
    });
    body = {
      method: 'jwk',
      did: generated.did,
      document: generated.document,
      // The document resolves from the identifier itself, so there is nothing
      // to fetch and nothing for a caller to point a URL at.
      documentUrl: '',
      verificationMethod: generated.did + '#0',
      credential: credentialSignedBy(generated.did, generated.privateKeyPem,
                                     'ES256',
                                     generated.did + '#0')
    };
  } else {
    const did = stsDid(req);
    const signer = didSigner();
    body = {
      method: 'web',
      did: did,
      document: await stsDidDocument(req),
      // Where did:web actually resolves this DID: the well-known path for a
      // bare host, `<base>/did.json` for one with a path (a trust realm).
      documentUrl: baseUrlOf(req) +
                   (didHasPath(req) ? '/did.json' : '/.well-known/did.json'),
      didConfigurationUrl: baseUrlOf(req) +
                           '/.well-known/did-configuration.json',
      origin: baseUrlOf(req),
      verificationMethod: did + '#' + signer.kid,
      credential: credentialSignedBy(did, signer.key, signer.alg, signer.kid)
    };
  }
  logArtifact('generated DID', 'as returned',
              { method: body.method, did: body.did });
  // no-store for the same reason as every other document describing these keys:
  // a jwk DID is new on every call, and the web one describes a key regenerated
  // at each start in development mode.
  res.set('Cache-Control', 'no-store');
  res.status(200).type('application/json').send(JSON.stringify(body, null, 2));
  log.debug("Leaving the DID generator endpoint. method=" + body.method + ".");
});

// The DID this issuer should be named by for a given CONFIGURATION, or "" when
// it should keep the https identifier it has always used — in which case every
// builder behaves exactly as it did before any of this existed.
//
// Two ways to arrive at a DID, and they answer different questions. A
// configuration declared with issuerDid (IdentityCredentialDid,
// IdentityCredentialLdpVcDid) always uses one: that is the point of it, it is
// advertised in the metadata, and a wallet asks for it by name. The startup
// flags are the other way, and they apply to the PLAIN configurations: they are
// how a whole deployment says "name me by DID throughout", which is what a real
// issuer that had gone over to DIDs would look like. Off by default, because
// for dc+sd-jwt this is an extension and for ldp_vc it changes a
// verificationMethod that existing tests dereference as an https URL.
function issuerDidFor(configId, req) {
  log.debug("Entering issuerDidFor().");
  const config = VCI_CONFIGS[configId] || {};
  if (config.issuerDid) {
    log.debug("Leaving issuerDidFor().");
    return stsDid(req);
  }
  if (config.format === 'ldp_vc') {
    log.debug("Leaving issuerDidFor().");
    return LDP_VC_ISSUER_DID ? stsDid(req) : '';
  }
  log.debug("Leaving issuerDidFor().");
  return SD_JWT_ISSUER_DID ? stsDid(req) : '';
}

module.exports = {
  stsDid: stsDid,
  didWebPartsOf: didWebPartsOf,
  stsDidDocument: stsDidDocument,
  domainLinkageCredential: domainLinkageCredential,
  issuerDidFor: issuerDidFor,
  DID_CONFIGURATION_CONTEXT: DID_CONFIGURATION_CONTEXT,
  SD_JWT_ISSUER_DID: SD_JWT_ISSUER_DID,
  LDP_VC_ISSUER_DID: LDP_VC_ISSUER_DID
};
