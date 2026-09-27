'use strict';
//
// File: client_attestation.ts
//
// ===========================================================================
// OAUTH 2.0 ATTESTATION-BASED CLIENT AUTHENTICATION (#229, 2026-09-26),
// draft-ietf-oauth-attestation-based-client-auth-11 (3 September 2026), the
// latest revision when this was written. Section numbers below are that
// revision's.
//
// A CLIENT INSTANCE — a wallet on a telephone, typically — cannot keep a
// client secret, and its backend cannot sign a client assertion for it
// without learning which authorization server the instance is talking to.
// So the backend (the CLIENT ATTESTER) signs a Client Attestation JWT once,
// binding a key the instance holds (`cnf.jwk`), and the instance proves that
// key per request: with a Client Attestation PoP JWT (section 5.1, "normal
// mode", `attest_jwt_client_auth`) or with the DPoP proof it sends anyway
// (section 5.2, "combined mode", `attest_jwt_client_auth_dpop`). Both ride in
// HTTP header fields, `OAuth-Client-Attestation` and
// `OAuth-Client-Attestation-PoP`, which is why this is not RFC 7521's
// framework and not `client_assertion`.
//
// It is what the OpenID4VC High Assurance Interoperability Profile (HAIP 1.0
// section 4.4.1) calls Wallet Attestation, and the OpenID Foundation's HAIP
// issuer test plan authenticates every wallet with it.
//
// ---------------------------------------------------------------------------
// WHAT IS TRUSTED, AND WHY IT IS THE REALM'S SETTING RATHER THAN THE CLIENT'S
// ENTRY.
//
// Section 10.8 leaves trust management to the deployment and names two ways
// to resolve an attester's key: an `x5c` chain validated against a
// configured trust anchor, and a `kid` against pre-shared keys. Both are
// here, per trust realm:
//
//   oauth2.clientAttestationTrustAnchors  PEM certificates. An attestation
//                                         carrying `x5c` must chain to one
//                                         (`pki.verifyPathToAnchors()`, the
//                                         RFC 5280 path check); the leaf may
//                                         not be self-signed (HAIP section
//                                         4.4.1).
//   oauth2.clientAttestationTrustedKeys   a JWKS. An attestation without
//                                         `x5c` must verify under one of its
//                                         keys (the `kid` narrows).
//
// Empty both — the default — trusts nobody: the two methods are then not
// advertised, and a client that declared one is refused by name. The trust is
// the realm's because an attester vouches for a whole wallet PRODUCT (HAIP:
// "the subject ... MUST be a value that is shared by all Wallet instances"),
// not for one client entry; the client entry says only that this client
// authenticates THIS way.
//
// **A MAC-PROTECTED ATTESTATION (section 12.2) IS NOT ACCEPTED.** It needs a
// key shared with the attester, this service has no setting to hold one, and
// section 12.2 itself says to default to signatures. The algorithms accepted
// for both JWTs are `common/crypto.js`'s asymmetric JWS table, post-quantum
// ones included, which is also what the metadata says.
//
// ---------------------------------------------------------------------------
// FRESHNESS AND REPLAY (sections 6, 10.7, 12.1).
//
//   * A SERVER-PROVIDED CHALLENGE, required by default
//     (`oauth2.clientAttestationChallengeRequired`). Issued by
//     `POST /oauth2/challenge` (section 6.3) and in a fresh
//     `OAuth-Client-Attestation-Challenge` header on EVERY response to a
//     request that carried an attestation (section 6.2) — which is what lets
//     a challenge be single-use: the client always holds the one it was last
//     handed. A missing, unknown, expired or spent one is 400
//     `use_attestation_challenge` with a fresh one (section 6.1).
//   * THE PoP's `jti`, spent in `common/used_assertions.js` — the one
//     history every signed client document is spent against, persisted in
//     every store and claimed atomically on postgres — keyed by the client
//     instance key's thumbprint. The challenge is spent there too. Both are
//     RESERVED and kept only when the response is a success, the history's
//     rule: a PoP that bought nothing has not been used.
//   * `iat` of the PoP within `oauth2.clientAttestationPopMaxAgeS`, and the
//     attestation's `iat` within `oauth2.clientAttestationMaxAgeS`, past which
//     it is `use_fresh_attestation` (section 7.4).
//   * IN COMBINED MODE none of that applies to the DPoP proof (section 5.2):
//     RFC 9449's own `jti` history and nonce are its freshness, and the
//     challenge endpoint hands out a DPoP nonce too when nonces are on.
//
// ---------------------------------------------------------------------------
// WHERE IT IS ASKED.
//
// `client_auth.js`'s `verify()` hands a declared `attest_jwt_client_auth` or
// `attest_jwt_client_auth_dpop` client to `verifyRequest()`, so the token
// endpoint, `/oauth2/par`, introspection, revocation and CIBA all verify it
// through the ONE path every other method takes (RFC 9700 policy, then the
// observation). `requestRefusal()` is asked after that at the token and PAR
// endpoints: a client that DECLARED attestation is held to it in every mode —
// `mtls.declaredRefusal()`'s argument, a refusal the client asked for — and
// an attestation sent by any other client as section 7.6's additional
// security signal is verified and refused if it does not hold. Combined mode
// needs a DPoP proof the endpoint verified (`req.stsDpopJkt`), so it exists
// at the token and PAR endpoints only.
//
// Section 10.3's refresh token binding and section 10.4's code binding
// (through PAR) read `req.stsClientAttestation`, which a verification that
// succeeded leaves on the request.
//
// A LIBRARY (rule 3): it registers no route — `oauth2.ts` owns
// `POST /oauth2/challenge` and calls `issueChallenge()` — and requires
// `common/` modules only, none of which requires it back. `client_auth.js`
// requires it, and it must never require `client_auth.js`, `oauth2_bcp.js`
// or `dpop.ts` (which requires `oauth2_bcp.js`): that is a cycle.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
import stsCrypto = require('../common/crypto');
import pki = require('../common/pki');
import usedAssertions = require('../common/used_assertions');
import cacheRegistry = require('../common/cache_registry');

// A JSON-shaped value: a JWT header, a claims set, a refusal.
type Json = any;
// An express request and response, as far as this file reads them.
type Req = any;

interface ClientAttestationDeps {
  log: typeof helpers.log;
  config: typeof config;
  errorCodes: typeof errorCodes;
  stsCrypto: typeof stsCrypto;
  pki: typeof pki;
  usedAssertions: typeof usedAssertions;
}

const DRAFT = 'draft-ietf-oauth-attestation-based-client-auth-11';

// Section 15.6 and 15.7: the two token endpoint authentication methods.
const ATTEST = 'attest_jwt_client_auth';
const ATTEST_DPOP = 'attest_jwt_client_auth_dpop';
const METHODS = [ATTEST, ATTEST_DPOP];

// Section 15.8, lower case as node hands request header names over.
const HEADER = 'oauth-client-attestation';
const POP_HEADER = 'oauth-client-attestation-pop';
const CHALLENGE_HEADER = 'OAuth-Client-Attestation-Challenge';

// Sections 4 and 5.1.
const TYP = 'oauth-client-attestation+jwt';
const POP_TYP = 'oauth-client-attestation-pop+jwt';

// Section 15.5.2's proof-of-possession methods, as section 7.6's metadata
// names them.
const POP_METHODS = ['attestation_pop_jwt', 'dpop_combined'];

// RFC 9110 section 11.2's token68, which section 4 and 5.1 give both fields.
const TOKEN68 = /^[A-Za-z0-9\-._~+/]+=*$/;

// Members a JWK may carry only when it is PRIVATE (RFC 7518 section 6, and
// `priv` for the post-quantum AKP keys). Section 7.1 item 5: the cnf key "is
// not a private key".
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv'];

// A Symbol, so nothing serialises the per-request answers.
const ANSWERED = Symbol('sts.clientAttestation.answered');

// challenge -> the second it was issued. PER TRUST REALM AND PERSISTED with
// what is minted, `dpop.issuedNonces`' arrangement: a challenge handed out by
// one process is presented to another, and the barrier makes the write land
// before the retry can be asked about it.
const challenges = realms.map({ persist: 'oauth2.attestationChallenges',
                                retain: 'age' });

function challengeTtlS(): number {
  helpers.log.debug("Entering challengeTtlS().");
  const raw = Number(config.value('oauth2.clientAttestationChallengeTtlS'));
  helpers.log.debug("Leaving challengeTtlS().");
  return isFinite(raw) && raw > 0 ? Math.floor(raw) : 300;
}

// The issued challenges, described to `/admin/caches` (#74, rule 3ap). A
// challenge is SPENT in the used-assertion history, not here; what this
// store answers is only "did this realm hand it out, and how long ago".
const challengesCount = cacheRegistry.register({
  name: 'oauth2.attestation-challenges',
  title: 'Client attestation challenges',
  description: 'Challenges handed out for OAuth 2.0 Attestation-Based ' +
    'Client Authentication (' + DRAFT + ' section 6), so a Client ' +
    'Attestation PoP carrying one can be checked against what was issued.',
  owner: 'oauth-oidc/client_attestation.ts',
  scope: 'realm',
  kind: 'replay',
  persisted: true,
  hitMeaning: 'a challenge found current, so the PoP was accepted',
  settings: ['oauth2.clientAttestationChallengeTtlS',
             'oauth2.clientAttestationChallengeCacheSize'],
  maxEntries: function (): number {
    return Number(config.value('oauth2.clientAttestationChallengeCacheSize'));
  },
  bound: 'Enforced: oauth2.clientAttestationChallengeCacheSize per realm; ' +
    'the oldest challenge is dropped, and a client presenting it is handed ' +
    'a fresh one with use_attestation_challenge.',
  lifetime: function (): string {
    return 'oauth2.clientAttestationChallengeTtlS (' + challengeTtlS() +
      ' s) after it was issued.';
  },
  eject: cacheRegistry.realmMapEjector(realms, challenges,
    function (issuedS: unknown, challenge: unknown, now: number): boolean {
      return Number(issuedS) < Math.floor(now / 1000) - challengeTtlS();
    }),
  entries: function (): unknown[] {
    const ttl = challengeTtlS();
    return cacheRegistry.realmMapRows(realms, challenges,
      function (issuedS: unknown, challenge: unknown): Json {
        return { key: cacheRegistry.digestKey(challenge),
                 validUntil: (Number(issuedS) + ttl) * 1000 };
      });
  }
});

class ClientAttestation {
  static readonly DRAFT = DRAFT;
  static readonly ATTEST = ATTEST;
  static readonly ATTEST_DPOP = ATTEST_DPOP;
  static readonly METHODS = METHODS;
  static readonly CHALLENGE_HEADER = CHALLENGE_HEADER;
  static readonly POP_METHODS = POP_METHODS;

  constructor(private readonly deps: ClientAttestationDeps) {
    deps.log.debug("Entering ClientAttestation.constructor().");
    deps.log.debug("Leaving ClientAttestation.constructor().");
  }

  // What the composition root passes.
  static defaultDeps(): ClientAttestationDeps {
    helpers.log.debug("Entering ClientAttestation.defaultDeps().");
    helpers.log.debug("Leaving ClientAttestation.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      errorCodes: errorCodes,
      stsCrypto: stsCrypto,
      pki: pki,
      usedAssertions: usedAssertions
    };
  }

  // -------------------------------------------------------------------------
  // SETTINGS, read per request: every row is `runtime` and per trust realm.
  // -------------------------------------------------------------------------
  private seconds(key: string, dflt: number): number {
    const { log, config } = this.deps;
    log.debug("Entering ClientAttestation.seconds(). " + key);
    const raw = Number(config.value(key));
    log.debug("Leaving ClientAttestation.seconds().");
    return isFinite(raw) && raw >= 0 ? Math.floor(raw) : dflt;
  }

  private skewS(): number {
    const { log } = this.deps;
    log.debug("Entering ClientAttestation.skewS().");
    log.debug("Leaving ClientAttestation.skewS().");
    return this.seconds('oauth2.clientAssertionSkewS', 60);
  }

  challengeRequired(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering ClientAttestation.challengeRequired().");
    log.debug("Leaving ClientAttestation.challengeRequired().");
    return config.value('oauth2.clientAttestationChallengeRequired') === true;
  }

  // The configured trust anchors, as `pki.certificateFromDer()` answers.
  private anchors(): Json[] {
    const { log, config, pki, errorCodes } = this.deps;
    log.debug("Entering ClientAttestation.anchors().");
    const bundle = pki.certificateBundle(String(config.value(
      'oauth2.clientAttestationTrustAnchors') || ''));
    if (bundle.unreadable) {
      log.error(errorCodes.tag('STS-OAUTH-0750') + 'client attestation: ' +
                bundle.unreadable + ' certificate(s) in ' +
                'oauth2.clientAttestationTrustAnchors could not be read and ' +
                'are ignored.');
    }
    log.debug("Leaving ClientAttestation.anchors(). " +
              bundle.certificates.length + ".");
    return bundle.certificates;
  }

  // The configured attester keys: the public members of a JWKS, a key with
  // private material refused rather than used (a pasted key PAIR is a
  // mistake, and the private half must not become something this service
  // holds).
  private trustedKeys(): Json[] {
    const { log, config, errorCodes } = this.deps;
    log.debug("Entering ClientAttestation.trustedKeys().");
    const text = String(config.value('oauth2.clientAttestationTrustedKeys') ||
                        '').trim();
    if (!text) {
      log.debug("Leaving ClientAttestation.trustedKeys(). None.");
      return [];
    }
    let parsed: Json = null;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      log.debug("Caught in ClientAttestation.trustedKeys(): " +
                ((e && e.message) || e));
      parsed = null;
    }
    const keys = parsed && Array.isArray(parsed.keys) ? parsed.keys : null;
    if (!keys) {
      log.error(errorCodes.tag('STS-OAUTH-0750') + 'client attestation: ' +
                'oauth2.clientAttestationTrustedKeys is not a JWKS ' +
                '({"keys": [...]}) and is ignored.');
      log.debug("Leaving ClientAttestation.trustedKeys(). Unreadable.");
      return [];
    }
    const out = keys.filter(function (k: Json) {
      return k && typeof k === 'object' && typeof k.kty === 'string' &&
             k.kty !== 'oct' &&
             PRIVATE_MEMBERS.every(function (m) {
               return k[m] === undefined;
             });
    });
    if (out.length !== keys.length) {
      log.error(errorCodes.tag('STS-OAUTH-0750') + 'client attestation: ' +
                (keys.length - out.length) + ' key(s) in ' +
                'oauth2.clientAttestationTrustedKeys are symmetric, private ' +
                'or not keys, and are ignored.');
    }
    log.debug("Leaving ClientAttestation.trustedKeys(). " + out.length + ".");
    return out;
  }

  // Whether this realm trusts any attester at all. Nothing is advertised,
  // and no challenge is handed out, in a realm that trusts nobody.
  configured(): boolean {
    const { log } = this.deps;
    log.debug("Entering ClientAttestation.configured().");
    const yes = this.anchors().length > 0 || this.trustedKeys().length > 0;
    log.debug("Leaving ClientAttestation.configured(). " + yes);
    return yes;
  }

  isMethod(method: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering ClientAttestation.isMethod().");
    log.debug("Leaving ClientAttestation.isMethod().");
    return METHODS.indexOf(String(method || '')) >= 0;
  }

  // Whether this request carries the attestation header at all.
  presented(req: Req): boolean {
    const { log } = this.deps;
    log.debug("Entering ClientAttestation.presented().");
    log.debug("Leaving ClientAttestation.presented().");
    return !!(req && req.headers && req.headers[HEADER] !== undefined);
  }

  // THE ATTESTATION'S `sub`, READ UNVERIFIED, for the one purpose the token
  // endpoint reads a client assertion's `sub` unverified: choosing which
  // registered client to check the request AGAINST when nothing else names
  // one (section 7.5 lets a token request omit client_id). The attestation is
  // then verified with `sub` required to be that client — so a forged `sub`
  // selects a client it will not authenticate as.
  subjectOf(req: Req): string {
    const { log } = this.deps;
    log.debug("Entering ClientAttestation.subjectOf().");
    const raw = req && req.headers ? req.headers[HEADER] : undefined;
    if (typeof raw !== 'string' || raw.split('.').length !== 3) {
      log.debug("Leaving ClientAttestation.subjectOf(). None.");
      return '';
    }
    try {
      const claims = JSON.parse(Buffer.from(raw.split('.')[1], 'base64url')
        .toString('utf8'));
      log.debug("Leaving ClientAttestation.subjectOf().");
      return claims && typeof claims.sub === 'string' ? claims.sub : '';
    } catch (e) {
      log.debug("Caught in ClientAttestation.subjectOf(): " +
                ((e && e.message) || e));
      log.debug("Leaving ClientAttestation.subjectOf(). Unreadable.");
      return '';
    }
  }

  // -------------------------------------------------------------------------
  // CHALLENGES (section 6). 192 bits of CSPRNG output, base64url — the
  // conformance suite's own check asks for at least sixteen characters of
  // that alphabet, and 32 is what this makes.
  // -------------------------------------------------------------------------
  issueChallenge(): string {
    const { log, stsCrypto, config } = this.deps;
    log.debug("Entering ClientAttestation.issueChallenge().");
    const challenge = stsCrypto.randomBytes(24).toString('base64url');
    cacheRegistry.makeRoom(challenges, Number(config.value(
      'oauth2.clientAttestationChallengeCacheSize')),
      { counter: challengesCount });
    challenges.set(challenge, Math.floor(Date.now() / 1000));
    log.debug("Leaving ClientAttestation.issueChallenge().");
    return challenge;
  }

  // Whether a challenge is one this realm issued and still current. The
  // expiry is checked HERE, at the read, whenever the ejection job last ran:
  // an expired challenge is never answered as current.
  private challengeIssuedAt(challenge: string): number {
    const { log } = this.deps;
    log.debug("Entering ClientAttestation.challengeIssuedAt().");
    const issued = Number(challenges.get(challenge));
    if (!issued ||
        issued < Math.floor(Date.now() / 1000) - challengeTtlS()) {
      challengesCount.miss();
      log.debug("Leaving ClientAttestation.challengeIssuedAt(). No.");
      return 0;
    }
    challengesCount.hit();
    log.debug("Leaving ClientAttestation.challengeIssuedAt(). Current.");
    return issued;
  }

  // Section 6.2: a fresh challenge on the response to every request that
  // carried an attestation, so a single-use challenge never leaves a client
  // without one. Only where challenges are in use at all.
  private offerChallenge(req: Req): void {
    const { log } = this.deps;
    log.debug("Entering ClientAttestation.offerChallenge().");
    const res = req && req.res;
    if (res && typeof res.set === 'function' && !res.headersSent) {
      res.set(CHALLENGE_HEADER, this.issueChallenge());
    }
    log.debug("Leaving ClientAttestation.offerChallenge().");
  }

  // -------------------------------------------------------------------------
  // A REFUSAL, in the shape `client_auth.js`'s verifiers answer, with the
  // OAuth error and status this draft gives it (section 7.4) beside the
  // code: `invalid_client` 401 unless said otherwise.
  // -------------------------------------------------------------------------
  private refuse(errorCode: string, description: string,
                 error?: string, status?: number): Json {
    const { log } = this.deps;
    log.debug("Entering ClientAttestation.refuse(). " + errorCode);
    log.debug("Leaving ClientAttestation.refuse().");
    return { ok: false, errorCode: errorCode,
             error: error || 'invalid_client', status: status || 401,
             description: description + ' (' + DRAFT + ')' };
  }

  // Exactly one field of this name, in token68 syntax (sections 4, 5.1,
  // 7.1 item 1, 7.2 item 1). node JOINS a repeated unknown header with ", ",
  // so the raw list is what counts them.
  private oneField(req: Req, name: string): Json {
    const { log } = this.deps;
    log.debug("Entering ClientAttestation.oneField(). " + name);
    const raw: string[] = Array.isArray(req && req.rawHeaders)
      ? req.rawHeaders : [];
    let count = 0;
    for (let i = 0; i < raw.length; i += 2) {
      if (String(raw[i]).toLowerCase() === name) {
        count += 1;
      }
    }
    const value = req && req.headers ? req.headers[name] : undefined;
    if (value === undefined) {
      log.debug("Leaving ClientAttestation.oneField(). Absent.");
      return { present: false };
    }
    if (count > 1 || typeof value !== 'string' || !TOKEN68.test(value) ||
        value.split('.').length !== 3) {
      log.debug("Leaving ClientAttestation.oneField(). Malformed.");
      return { present: true, ok: false, count: count };
    }
    log.debug("Leaving ClientAttestation.oneField().");
    return { present: true, ok: true, value: value };
  }

  private decodeHeader(jwt: string): Json {
    const { log } = this.deps;
    log.debug("Entering ClientAttestation.decodeHeader().");
    try {
      const header = JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url')
        .toString('utf8'));
      log.debug("Leaving ClientAttestation.decodeHeader().");
      return header && typeof header === 'object' ? header : null;
    } catch (e) {
      log.debug("Caught in ClientAttestation.decodeHeader(): " +
                ((e && e.message) || e));
      log.debug("Leaving ClientAttestation.decodeHeader(). Unreadable.");
      return null;
    }
  }

  private algorithms(): string[] {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering ClientAttestation.algorithms().");
    log.debug("Leaving ClientAttestation.algorithms().");
    return stsCrypto.JWS_ASYMMETRIC_ALGS.slice(0);
  }

  // -------------------------------------------------------------------------
  // THE ATTESTER'S KEY (section 10.8). An `x5c` is believed only once its
  // path holds to a configured anchor; otherwise the configured keys are
  // tried, narrowed by `kid`. Answers `{ keys: [...] }` or a refusal.
  // -------------------------------------------------------------------------
  private async attesterKeys(header: Json): Promise<Json> {
    const { log, pki } = this.deps;
    log.debug("Entering ClientAttestation.attesterKeys().");
    const anchors = this.anchors();
    const trusted = this.trustedKeys();
    if (!anchors.length && !trusted.length) {
      log.debug("Leaving ClientAttestation.attesterKeys(). Nobody trusted.");
      return this.refuse('STS-OAUTH-0724', 'this realm trusts no client ' +
        'attester: oauth2.clientAttestationTrustAnchors and ' +
        'oauth2.clientAttestationTrustedKeys are both empty, so no Client ' +
        'Attestation can be verified here');
    }
    if (Array.isArray(header.x5c) && header.x5c.length && anchors.length) {
      let ders: Buffer[] = [];
      try {
        ders = header.x5c.map(function (one: unknown) {
          if (typeof one !== 'string') {
            throw new Error('an x5c member is not a string');
          }
          return Buffer.from(one, 'base64');
        });
      } catch (e) {
        log.debug("Caught in ClientAttestation.attesterKeys(): " +
                  ((e && e.message) || e));
        log.debug("Leaving ClientAttestation.attesterKeys(). Bad x5c.");
        return this.refuse('STS-OAUTH-0725', 'the Client Attestation\'s x5c ' +
          'cannot be read: ' + e.message);
      }
      const leaf = pki.certificateFromDer(ders[0]);
      if (!leaf) {
        log.debug("Leaving ClientAttestation.attesterKeys(). Bad leaf.");
        return this.refuse('STS-OAUTH-0725', 'the first certificate in the ' +
          'Client Attestation\'s x5c is not an X.509 certificate');
      }
      let selfSigned = false;
      try {
        selfSigned = leaf.x509.checkIssued(leaf.x509) &&
                     leaf.x509.verify(leaf.x509.publicKey);
      } catch (e) {
        log.debug("Caught in ClientAttestation.attesterKeys(): " +
                  ((e && e.message) || e));
        selfSigned = false;
      }
      if (selfSigned) {
        log.debug("Leaving ClientAttestation.attesterKeys(). Self-signed.");
        return this.refuse('STS-OAUTH-0725', 'the certificate that signs ' +
          'the Client Attestation is self-signed; it must be issued under a ' +
          'trust anchor in oauth2.clientAttestationTrustAnchors (HAIP 1.0 ' +
          'section 4.4.1: "MUST NOT be self-signed")');
      }
      const path = await pki.verifyPathToAnchors(ders[0], ders.slice(1),
        anchors, { skewMs: this.skewS() * 1000 });
      if (!path.ok) {
        log.debug("Leaving ClientAttestation.attesterKeys(). No path.");
        return this.refuse('STS-OAUTH-0725', 'the Client Attestation\'s x5c ' +
          'does not chain to a trust anchor in ' +
          'oauth2.clientAttestationTrustAnchors: ' + path.reason);
      }
      let key: Json = null;
      try {
        key = leaf.x509.publicKey;
      } catch (e) {
        log.debug("Caught in ClientAttestation.attesterKeys(): " +
                  ((e && e.message) || e));
        key = null;
      }
      if (!key) {
        log.debug("Leaving ClientAttestation.attesterKeys(). No key.");
        return this.refuse('STS-OAUTH-0725', 'the key in the Client ' +
          'Attestation\'s x5c leaf could not be read');
      }
      log.debug("Leaving ClientAttestation.attesterKeys(). The x5c leaf.");
      return { keys: [key], by: 'x5c' };
    }
    const kid = header.kid === undefined ? '' : String(header.kid);
    const named = kid ? trusted.filter(function (k: Json) {
      return String(k.kid || '') === kid;
    }) : trusted;
    if (!named.length) {
      log.debug("Leaving ClientAttestation.attesterKeys(). No key named.");
      return this.refuse('STS-OAUTH-0726', 'no trusted attester key ' +
        'verifies this Client Attestation: ' +
        (Array.isArray(header.x5c) && header.x5c.length
          ? 'it carries an x5c and oauth2.clientAttestationTrustAnchors is ' +
            'empty, and '
          : '') +
        (kid ? 'no key in oauth2.clientAttestationTrustedKeys has kid "' +
               kid + '"'
             : 'oauth2.clientAttestationTrustedKeys holds none'));
    }
    log.debug("Leaving ClientAttestation.attesterKeys(). " + named.length +
              " configured key(s).");
    return { keys: named, by: 'jwks' };
  }

  // -------------------------------------------------------------------------
  // SECTION 7.1 — THE CLIENT ATTESTATION JWT. Answers `{ ok, claims, jwk,
  // jkt, alg }` or a refusal.
  // -------------------------------------------------------------------------
  private async verifyAttestation(jwt: string,
                                  clientId: string): Promise<Json> {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering ClientAttestation.verifyAttestation().");
    const header = this.decodeHeader(jwt);
    if (!header) {
      log.debug("Leaving ClientAttestation.verifyAttestation(). No header.");
      return this.refuse('STS-OAUTH-0721', 'the OAuth-Client-Attestation ' +
        'header does not hold a readable JWT');
    }
    if (header.typ !== TYP) {
      log.debug("Leaving ClientAttestation.verifyAttestation(). typ.");
      return this.refuse('STS-OAUTH-0722', 'a Client Attestation\'s typ ' +
        'must be "' + TYP + '" (section 4), and this one is ' +
        JSON.stringify(header.typ === undefined ? null : header.typ));
    }
    const algs = this.algorithms();
    if (algs.indexOf(String(header.alg)) < 0) {
      log.debug("Leaving ClientAttestation.verifyAttestation(). alg.");
      return this.refuse('STS-OAUTH-0723', 'the Client Attestation is ' +
        'signed with ' + JSON.stringify(header.alg) + ', and this server ' +
        'accepts an asymmetric algorithm only (section 7.1 item 3; a MAC ' +
        'needs a key shared with the attester, which this service holds ' +
        'none of): ' + algs.join(', '));
    }
    const found = await this.attesterKeys(header);
    if (!found.keys) {
      log.debug("Leaving ClientAttestation.verifyAttestation(). No key.");
      return found;
    }
    let verified: Json = null;
    let last = '';
    for (let i = 0; i < found.keys.length && !verified; i++) {
      try {
        verified = await stsCrypto.verifyCompactJwsAsync(jwt, found.keys[i],
          { algorithms: [String(header.alg)] });
      } catch (e) {
        log.debug("Caught in ClientAttestation.verifyAttestation(): " +
                  ((e && e.message) || e));
        last = e.message;
      }
    }
    if (!verified || !verified.claims || typeof verified.claims !== 'object') {
      log.debug("Leaving ClientAttestation.verifyAttestation(). Signature.");
      return this.refuse('STS-OAUTH-0726', 'the Client Attestation\'s ' +
        'signature does not verify under the trusted attester key' +
        (found.by === 'x5c' ? ' in its x5c' : 's') +
        (last ? ': ' + last : ''));
    }
    const claims = verified.claims;
    const missing = ['sub', 'exp', 'cnf'].filter(function (name) {
      return claims[name] === undefined || claims[name] === null ||
             claims[name] === '';
    });
    if (missing.length || typeof claims.sub !== 'string' ||
        typeof claims.exp !== 'number' ||
        (claims.iat !== undefined && typeof claims.iat !== 'number') ||
        (claims.nbf !== undefined && typeof claims.nbf !== 'number')) {
      log.debug("Leaving ClientAttestation.verifyAttestation(). Claims.");
      return this.refuse('STS-OAUTH-0727', 'a Client Attestation carries ' +
        'sub (a string), exp (a number) and cnf (section 4)' +
        (missing.length ? '; this one has no ' + missing.join(', ')
                        : '; one of them, or iat or nbf, has the wrong type'));
    }
    const now = Math.floor(Date.now() / 1000);
    const skew = this.skewS();
    if (now > claims.exp + skew) {
      log.debug("Leaving ClientAttestation.verifyAttestation(). Expired.");
      return this.refuse('STS-OAUTH-0728', 'the Client Attestation ' +
        'expired at ' + new Date(claims.exp * 1000).toISOString() +
        ' (section 4, exp)');
    }
    if ((claims.nbf !== undefined && claims.nbf > now + skew) ||
        (claims.iat !== undefined && claims.iat > now + skew)) {
      log.debug("Leaving ClientAttestation.verifyAttestation(). Future.");
      return this.refuse('STS-OAUTH-0728', 'the Client Attestation is not ' +
        'valid yet: its ' + (claims.nbf !== undefined && claims.nbf >
          now + skew ? 'nbf' : 'iat') + ' is in the future (RFC 7519)');
    }
    const maxAge = this.seconds('oauth2.clientAttestationMaxAgeS', 86400);
    if (claims.iat !== undefined && now - claims.iat > maxAge + skew) {
      log.debug("Leaving ClientAttestation.verifyAttestation(). Stale.");
      return this.refuse('STS-OAUTH-0730', 'the Client Attestation was ' +
        'issued ' + (now - claims.iat) + ' seconds ago, and this server ' +
        'accepts one at most ' + maxAge + ' seconds old ' +
        '(oauth2.clientAttestationMaxAgeS; section 7.1 item 6). Obtain a ' +
        'fresh one from the attester', 'use_fresh_attestation', 400);
    }
    const jwk = claims.cnf && typeof claims.cnf === 'object'
      ? claims.cnf.jwk : null;
    const privateHeld = jwk && typeof jwk === 'object'
      ? PRIVATE_MEMBERS.filter(function (m) {
        return jwk[m] !== undefined;
      }) : [];
    if (!jwk || typeof jwk !== 'object' || typeof jwk.kty !== 'string' ||
        jwk.kty === 'oct' || privateHeld.length) {
      log.debug("Leaving ClientAttestation.verifyAttestation(). cnf.");
      return this.refuse('STS-OAUTH-0729', 'the Client Attestation\'s cnf ' +
        'must carry the client instance\'s PUBLIC key as a "jwk" (section ' +
        '4; section 7.1 item 5)' + (privateHeld.length
          ? ', and this one carries private key material (' +
            privateHeld.join(', ') + ')' : ''));
    }
    let jkt = '';
    try {
      jkt = stsCrypto.jwkThumbprint(jwk, {});
    } catch (e) {
      log.debug("Caught in ClientAttestation.verifyAttestation(): " +
                ((e && e.message) || e));
      jkt = '';
    }
    if (!jkt) {
      log.debug("Leaving ClientAttestation.verifyAttestation(). No jkt.");
      return this.refuse('STS-OAUTH-0729', 'the Client Attestation\'s ' +
        'cnf.jwk is not a key this server can take a thumbprint of');
    }
    if (clientId && claims.sub !== clientId) {
      log.debug("Leaving ClientAttestation.verifyAttestation(). sub.");
      return this.refuse('STS-OAUTH-0731', 'the Client Attestation is ' +
        'about client "' + claims.sub + '", and this request is client "' +
        clientId + '"; the two must be the same (sections 7.1 item 7 and ' +
        '7.5)');
    }
    log.debug("Leaving ClientAttestation.verifyAttestation(). Verified by " +
              found.by + ".");
    return { ok: true, claims: claims, jwk: jwk, jkt: jkt,
             alg: String(header.alg), by: found.by };
  }

  // -------------------------------------------------------------------------
  // SECTION 7.2 — THE CLIENT ATTESTATION PoP JWT, against the attested key.
  // -------------------------------------------------------------------------
  private async verifyPop(req: Req, pop: string, attested: Json,
                          issuer: string, clientId: string): Promise<Json> {
    const { log, stsCrypto, usedAssertions } = this.deps;
    log.debug("Entering ClientAttestation.verifyPop().");
    const header = this.decodeHeader(pop);
    if (!header || header.typ !== POP_TYP) {
      log.debug("Leaving ClientAttestation.verifyPop(). typ.");
      return this.refuse('STS-OAUTH-0733', 'a Client Attestation PoP\'s typ ' +
        'must be "' + POP_TYP + '" (section 5.1), and this one is ' +
        JSON.stringify(header ? (header.typ === undefined ? null : header.typ)
                              : 'unreadable'));
    }
    const algs = this.algorithms();
    if (algs.indexOf(String(header.alg)) < 0) {
      log.debug("Leaving ClientAttestation.verifyPop(). alg.");
      return this.refuse('STS-OAUTH-0733', 'the Client Attestation PoP is ' +
        'signed with ' + JSON.stringify(header.alg) + ', and it must be an ' +
        'asymmetric algorithm (section 5.1 rule 2): ' + algs.join(', '));
    }
    let verified: Json = null;
    try {
      verified = await stsCrypto.verifyCompactJwsAsync(pop, attested.jwk,
        { algorithms: [String(header.alg)] });
    } catch (e) {
      log.debug("Caught in ClientAttestation.verifyPop(): " +
                ((e && e.message) || e));
      log.debug("Leaving ClientAttestation.verifyPop(). Signature.");
      return this.refuse('STS-OAUTH-0734', 'the Client Attestation PoP ' +
        'does not verify under the key in the attestation\'s cnf (section ' +
        '7.2 item 4): ' + e.message);
    }
    const claims = verified && verified.claims;
    if (!claims || typeof claims !== 'object' ||
        typeof claims.jti !== 'string' || !claims.jti ||
        typeof claims.iat !== 'number' || claims.aud === undefined ||
        (claims.exp !== undefined && typeof claims.exp !== 'number') ||
        (claims.nbf !== undefined && typeof claims.nbf !== 'number') ||
        (claims.challenge !== undefined &&
         typeof claims.challenge !== 'string')) {
      log.debug("Leaving ClientAttestation.verifyPop(). Claims.");
      return this.refuse('STS-OAUTH-0735', 'a Client Attestation PoP ' +
        'carries aud, jti (a string) and iat (a number), and challenge is a ' +
        'string where present (section 5.1)');
    }
    const aud = Array.isArray(claims.aud) && claims.aud.length === 1
      ? claims.aud[0] : claims.aud;
    if (typeof aud !== 'string' || aud !== issuer) {
      log.debug("Leaving ClientAttestation.verifyPop(). aud.");
      return this.refuse('STS-OAUTH-0736', 'the Client Attestation PoP ' +
        'must name this authorization server\'s issuer identifier, "' +
        issuer + '", as its single audience (sections 5.1 and 7.2 item 7), ' +
        'and it names ' + JSON.stringify(claims.aud));
    }
    const now = Math.floor(Date.now() / 1000);
    const skew = this.skewS();
    const window = this.seconds('oauth2.clientAttestationPopMaxAgeS', 300);
    if (claims.iat > now + skew || now - claims.iat > window + skew ||
        (claims.exp !== undefined && now > claims.exp + skew) ||
        (claims.nbf !== undefined && claims.nbf > now + skew)) {
      log.debug("Leaving ClientAttestation.verifyPop(). Window.");
      return this.refuse('STS-OAUTH-0737', 'the Client Attestation PoP was ' +
        'made at ' + new Date(claims.iat * 1000).toISOString() + ', and ' +
        'this server accepts one made in the last ' + window + ' seconds ' +
        '(oauth2.clientAttestationPopMaxAgeS; section 7.2 item 6), unexpired ' +
        'and not dated in the future. Make a fresh one for each request');
    }
    // THE CHALLENGE (section 7.2 item 5), after every check of the document
    // itself: a PoP refused for anything else is told that, not asked to
    // fetch a challenge it would be refused again with.
    const required = this.challengeRequired();
    const challenge = claims.challenge === undefined ? ''
      : String(claims.challenge);
    if (!challenge && required) {
      log.debug("Leaving ClientAttestation.verifyPop(). No challenge.");
      return this.refuse('STS-OAUTH-0738', 'this authorization server ' +
        'requires a challenge in the Client Attestation PoP ' +
        '(oauth2.clientAttestationChallengeRequired; section 6.1). Use the ' +
        'one in this response\'s ' + CHALLENGE_HEADER + ' header, or POST ' +
        'to the challenge_endpoint', 'use_attestation_challenge', 400);
    }
    const issuedAt = challenge ? this.challengeIssuedAt(challenge) : 0;
    if (challenge && !issuedAt) {
      log.debug("Leaving ClientAttestation.verifyPop(). Unknown challenge.");
      return this.refuse('STS-OAUTH-0739', 'the challenge in the Client ' +
        'Attestation PoP is not one this authorization server issued in ' +
        'the last ' + challengeTtlS() + ' seconds ' +
        '(oauth2.clientAttestationChallengeTtlS). Use the one in this ' +
        'response\'s ' + CHALLENGE_HEADER + ' header',
        'use_attestation_challenge', 400);
    }
    // THE jti, keyed by the client instance key: a PoP is the instance's
    // document, and two instances of one client product may pick the same
    // jti without either replaying anything.
    const spent = await usedAssertions.claim({
      format: 'jwt', use: 'client-attestation-pop',
      issuer: stsCrypto.JWK_THUMBPRINT_URI_PREFIX + attested.jkt,
      identifier: String(claims.jti),
      clientId: clientId, subject: String(attested.claims.sub),
      expiresAt: (claims.iat + window + 2 * skew) * 1000,
      request: req
    });
    if (!spent.ok) {
      log.debug("Leaving ClientAttestation.verifyPop(). jti: " +
                spent.reason);
      return spent.reason === 'replay'
        ? this.refuse('STS-OAUTH-0740', 'this Client Attestation PoP has ' +
            'been used already (jti "' + claims.jti + '"; section 12.1). ' +
            'Make a fresh one for each request')
        : this.refuse(spent.reason === 'full' ? 'STS-OAUTH-0741'
                                              : 'STS-OAUTH-0742',
            'this authorization server could not record the Client ' +
            'Attestation PoP as used, so it is refused rather than ' +
            'accepted unrecorded. Retry shortly', 'invalid_client', 503);
    }
    if (challenge) {
      const used = await usedAssertions.claim({
        format: 'attestation-challenge', use: 'client-attestation-pop',
        issuer: 'challenge', identifier: challenge,
        clientId: clientId, subject: String(attested.claims.sub),
        expiresAt: (issuedAt + challengeTtlS() + skew) * 1000,
        request: req
      });
      if (!used.ok && used.reason === 'replay') {
        log.debug("Leaving ClientAttestation.verifyPop(). Spent challenge.");
        return this.refuse('STS-OAUTH-0739', 'the challenge in the Client ' +
          'Attestation PoP has been used already; each is good for one ' +
          'request. Use the one in this response\'s ' + CHALLENGE_HEADER +
          ' header', 'use_attestation_challenge', 400);
      }
      if (!used.ok) {
        log.debug("Leaving ClientAttestation.verifyPop(). History.");
        return this.refuse(used.reason === 'full' ? 'STS-OAUTH-0741'
                                                  : 'STS-OAUTH-0742',
          'this authorization server could not record the challenge as ' +
          'used, so it is refused rather than accepted unrecorded. Retry ' +
          'shortly', 'invalid_client', 503);
      }
    }
    log.debug("Leaving ClientAttestation.verifyPop(). Verified.");
    return { ok: true, jti: String(claims.jti) };
  }

  // -------------------------------------------------------------------------
  // THE ONE ENTRY POINT. `opts.method` is what the client's entry declares —
  // one of the two methods, or anything else for section 7.6's additional
  // signal, where either proof may be used. `opts.issuer` is the audience a
  // PoP must name. Answered ONCE per request: the token endpoint asks twice
  // (the RFC 9700 policy, then the observation), and a second verification
  // would find the first one's jti.
  // -------------------------------------------------------------------------
  verifyRequest(req: Req, opts: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering ClientAttestation.verifyRequest().");
    const o = opts || {};
    const key = [String(o.method || ''), String(o.clientId || ''),
                 String(o.issuer || ''),
                 String((req && req.headers && req.headers[HEADER]) || ''),
                 String((req && req.headers && req.headers[POP_HEADER]) || '')
                ].join('\n');
    if (req && typeof req === 'object') {
      let held = req[ANSWERED];
      if (!held) {
        held = new Map();
        req[ANSWERED] = held;
      }
      if (held.has(key)) {
        log.debug("Leaving ClientAttestation.verifyRequest(). Answered.");
        return held.get(key);
      }
      const answer = this.verifyOnce(req, o);
      held.set(key, answer);
      log.debug("Leaving ClientAttestation.verifyRequest(). Verifying.");
      return answer;
    }
    log.debug("Leaving ClientAttestation.verifyRequest(). No request.");
    return this.verifyOnce(req, o);
  }

  private async verifyOnce(req: Req, o: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering ClientAttestation.verifyOnce().");
    const method = String(o.method || '');
    const clientId = String(o.clientId || '');
    const issuer = String(o.issuer || '');
    const attestationField = this.oneField(req, HEADER);
    if (!attestationField.present) {
      log.debug("Leaving ClientAttestation.verifyOnce(). No attestation.");
      return this.refuse('STS-OAUTH-0751', 'this client authenticates with ' +
        (method || ATTEST) + ', so the request must carry an ' +
        'OAuth-Client-Attestation header (section 7.5)');
    }
    // Section 6.2, from here on: every response to a request that carried
    // an attestation hands the client a fresh challenge, refusals included.
    if (this.configured()) {
      this.offerChallenge(req);
    }
    if (!attestationField.ok) {
      log.debug("Leaving ClientAttestation.verifyOnce(). Malformed.");
      return this.refuse('STS-OAUTH-0720', 'the request must carry exactly ' +
        'one OAuth-Client-Attestation header holding a JWT in token68 ' +
        'syntax (sections 4 and 7.1 item 1)' +
        (attestationField.count > 1 ? '; it carries ' +
          attestationField.count : ''));
    }
    const popField = this.oneField(req, POP_HEADER);
    const dpopSent = !!(req && req.headers && req.headers.dpop !== undefined);
    // Section 7's three rules for telling the two methods apart, held to
    // what the client DECLARED where it declared one of them.
    const mode = popField.present ? 'pop' : (dpopSent ? 'dpop' : '');
    if (!mode) {
      log.debug("Leaving ClientAttestation.verifyOnce(). No proof.");
      return this.refuse('STS-OAUTH-0743', 'the request carries a Client ' +
        'Attestation and no proof of possession of its key: neither an ' +
        'OAuth-Client-Attestation-PoP header (section 5.1) nor a DPoP ' +
        'proof (section 5.2)');
    }
    if ((method === ATTEST && mode !== 'pop') ||
        (method === ATTEST_DPOP && mode !== 'dpop')) {
      log.debug("Leaving ClientAttestation.verifyOnce(). Wrong mode.");
      return this.refuse('STS-OAUTH-0746', 'this client declared ' +
        'token_endpoint_auth_method ' + method + ', which proves the ' +
        'attested key with ' + (method === ATTEST
          ? 'an OAuth-Client-Attestation-PoP header (section 5.1); the ' +
            'DPoP combined mode is ' + ATTEST_DPOP
          : 'the DPoP proof alone (section 5.2), so the request may not ' +
            'carry an OAuth-Client-Attestation-PoP header; that is ' +
            ATTEST));
    }
    const attested = await this.verifyAttestation(attestationField.value,
                                                  clientId);
    if (!attested.ok) {
      log.debug("Leaving ClientAttestation.verifyOnce(). Attestation.");
      return attested;
    }
    let jti = '';
    if (mode === 'pop') {
      if (!popField.ok) {
        log.debug("Leaving ClientAttestation.verifyOnce(). PoP malformed.");
        return this.refuse('STS-OAUTH-0732', 'the request must carry ' +
          'exactly one OAuth-Client-Attestation-PoP header holding a JWT in ' +
          'token68 syntax (sections 5.1 and 7.2 item 1)');
      }
      if (!issuer) {
        // Unreachable from the endpoints, which all name their issuer; a
        // PoP checked against no audience would be checked against nothing.
        log.debug("Leaving ClientAttestation.verifyOnce(). No issuer.");
        return this.refuse('STS-OAUTH-0736', 'this endpoint could not say ' +
          'which issuer identifier a Client Attestation PoP must name');
      }
      const popChecked = await this.verifyPop(req, popField.value, attested,
                                              issuer, clientId);
      if (!popChecked.ok) {
        log.debug("Leaving ClientAttestation.verifyOnce(). PoP.");
        return popChecked;
      }
      jti = popChecked.jti;
    } else {
      // SECTION 7.3 — COMBINED MODE. The endpoint verified the DPoP proof
      // under RFC 9449 before it asked about the client, and left the key's
      // thumbprint on the request; RFC 7638 thumbprints compare the required
      // members, which is item 4's comparison.
      const dpopJkt = String((req && req.stsDpopJkt) || '');
      if (!dpopJkt) {
        log.debug("Leaving ClientAttestation.verifyOnce(). DPoP unverified.");
        return this.refuse('STS-OAUTH-0744', 'the DPoP combined mode ' +
          '(section 5.2) needs a DPoP proof this endpoint verifies, which ' +
          'is the token and pushed authorization request endpoints; here, ' +
          'send an OAuth-Client-Attestation-PoP header instead');
      }
      if (dpopJkt !== attested.jkt) {
        log.debug("Leaving ClientAttestation.verifyOnce(). DPoP key.");
        return this.refuse('STS-OAUTH-0745', 'the DPoP proof is signed by ' +
          'key ' + dpopJkt + ' and the Client Attestation binds key ' +
          attested.jkt + '; in the combined mode they must be the same key ' +
          '(section 7.3 item 4)');
      }
    }
    const fact = { jkt: attested.jkt, sub: String(attested.claims.sub),
                   mode: mode, alg: attested.alg, by: attested.by };
    if (req && typeof req === 'object') {
      req.stsClientAttestation = fact;
    }
    log.info('client attestation: client "' + fact.sub + '" presented an ' +
             'attestation verified by ' + (fact.by === 'x5c'
               ? 'its x5c chain' : 'a configured attester key') +
             ', proved by ' + (mode === 'pop' ? 'a Client Attestation PoP'
                                               : 'its DPoP proof') +
             ' (instance key ' + fact.jkt + ').');
    log.debug("Leaving ClientAttestation.verifyOnce(). Verified.");
    return { ok: true, method: mode === 'pop' ? ATTEST : ATTEST_DPOP,
             alg: attested.alg, jti: jti, jkt: attested.jkt };
  }

  // -------------------------------------------------------------------------
  // AT THE TOKEN AND PAR ENDPOINTS, after the observation (see the header).
  // Answers a refusal `{ status, error, description, errorCode }` or null.
  // -------------------------------------------------------------------------
  async requestRefusal(opts: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering ClientAttestation.requestRefusal().");
    const o = opts || {};
    const registered = o.registered || {};
    const declared = String(registered.token_endpoint_auth_method || '');
    const observation = o.observation || {};
    if (this.isMethod(declared)) {
      if (observation.authenticated) {
        log.debug("Leaving ClientAttestation.requestRefusal(). Declared, " +
                  "authenticated.");
        return null;
      }
      log.debug("Leaving ClientAttestation.requestRefusal(). Declared, " +
                "refused.");
      return { status: observation.status || 401,
               error: observation.oauthError || 'invalid_client',
               errorCode: observation.errorCode || 'STS-OAUTH-0751',
               description: 'this client declared ' +
                 'token_endpoint_auth_method ' + declared + ', and ' +
                 (observation.why || 'it did not authenticate with it.') };
    }
    if (!this.presented(o.request) || !this.configured()) {
      log.debug("Leaving ClientAttestation.requestRefusal(). No signal.");
      return null;
    }
    const checked = await this.verifyRequest(o.request, {
      method: '', clientId: o.clientId, issuer: o.issuer });
    if (checked.ok) {
      log.debug("Leaving ClientAttestation.requestRefusal(). Signal holds.");
      return null;
    }
    log.debug("Leaving ClientAttestation.requestRefusal(). Signal refused.");
    return { status: checked.status || 401,
             error: checked.error || 'invalid_client',
             errorCode: checked.errorCode,
             description: 'the request carries a Client Attestation as an ' +
               'additional security signal (section 7.6), and ' +
               checked.description };
  }

  // -------------------------------------------------------------------------
  // SECTIONS 10.3 AND 10.4 — WHAT WAS BOUND TO THE INSTANCE KEY. `bound` is
  // the thumbprint a refresh token or an authorization code carries; the
  // request must have verified an attestation for that same key.
  // -------------------------------------------------------------------------
  bindingRefusal(req: Req, bound: unknown, what: string): Json {
    const { log } = this.deps;
    log.debug("Entering ClientAttestation.bindingRefusal(). " + what);
    const jkt = String(bound || '');
    if (!jkt) {
      log.debug("Leaving ClientAttestation.bindingRefusal(). Unbound.");
      return null;
    }
    const fact = req && req.stsClientAttestation;
    if (fact && fact.jkt === jkt) {
      log.debug("Leaving ClientAttestation.bindingRefusal(). Same key.");
      return null;
    }
    log.debug("Leaving ClientAttestation.bindingRefusal(). Refused.");
    return {
      errorCode: what === 'refresh token' ? 'STS-OAUTH-0748'
                                          : 'STS-OAUTH-0749',
      error: 'invalid_grant',
      description: 'this ' + what + ' was issued to the client instance ' +
        'whose attested key is ' + jkt + ', so it may be redeemed only ' +
        'with a Client Attestation binding that key (' + DRAFT + ' ' +
        (what === 'refresh token' ? 'section 10.3' : 'section 10.4') +
        '); this request ' + (fact ? 'attests key ' + fact.jkt
                                   : 'carries no verified attestation') + '.'
    };
  }

  // What the authorization server metadata says (section 8), or {} in a
  // realm that trusts no attester. `challengeEndpoint` is the URL.
  metadata(challengeEndpoint: string): Json {
    const { log } = this.deps;
    log.debug("Entering ClientAttestation.metadata().");
    if (!this.configured()) {
      log.debug("Leaving ClientAttestation.metadata(). Not configured.");
      return {};
    }
    const algs = this.algorithms();
    log.debug("Leaving ClientAttestation.metadata().");
    return {
      challenge_endpoint: challengeEndpoint,
      client_attestation_signing_alg_values_supported: algs,
      client_attestation_pop_signing_alg_values_supported: algs,
      // Section 7.6: both proofs are accepted, and a client that is not
      // attestation-authenticated may omit the attestation.
      client_attestation_pop_methods_supported: POP_METHODS.concat(['none'])
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — `par.ts`'s
// arrangement: `common/protocol_stack.ts` builds one and installs it, and the
// exports below are facades for the JavaScript that requires this module
// (`client_auth.js`, `oauth2_bcp.js`); a process without the root builds a
// default one when this loads.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<ClientAttestation>(
  'oauth-oidc/client_attestation',
  () => new ClientAttestation(ClientAttestation.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  ClientAttestation: ClientAttestation,
  installInstance: (instance: ClientAttestation): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  DRAFT: DRAFT,
  ATTEST: ATTEST,
  ATTEST_DPOP: ATTEST_DPOP,
  METHODS: METHODS,
  CHALLENGE_HEADER: CHALLENGE_HEADER,
  POP_METHODS: POP_METHODS,
  configured: slot.forward('configured'),
  isMethod: slot.forward('isMethod'),
  presented: slot.forward('presented'),
  subjectOf: slot.forward('subjectOf'),
  challengeRequired: slot.forward('challengeRequired'),
  issueChallenge: slot.forward('issueChallenge'),
  verifyRequest: slot.forward('verifyRequest'),
  requestRefusal: slot.forward('requestRefusal'),
  bindingRefusal: slot.forward('bindingRefusal'),
  metadata: slot.forward('metadata')
};
