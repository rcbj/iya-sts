'use strict';
//
// File: software_statement.ts
//
// ===========================================================================
// RFC 7591 SECTION 2.3: THE SOFTWARE STATEMENT.
//
// A software statement is a JWT whose claims are CLIENT METADATA — a
// `software_id`, `redirect_uris`, `grant_types`, whatever the issuer chooses to
// fix — signed by somebody who vouches for the software rather than for any one
// installation of it. A client registering at `POST /oauth2/register` presents
// it in `software_statement` beside its ordinary JSON members, and section
// 3.1.1 says what the server then does with it: **"If the same client metadata
// name is present in both locations and the software statement is trusted by
// the authorization server, the value of a claim in the software statement MUST
// take precedence."** Section 3.2.1 hands it back, unmodified, in the response.
//
// ---------------------------------------------------------------------------
// WHO IS TRUSTED, AND WHY THIS IS THE SAME SHAPE AS RFC 7523.
//
// Section 2.3 leaves the decision to the server — "the authorization server MAY
// ... determine whether it trusts the issuer" — and a server that trusted every
// signature would be trusting whoever holds any key at all. So an issuer is
// DECLARED, exactly as an RFC 7523 assertion issuer is:
//
//   THIS REALM ITSELF   a statement the console or `/admin-api` issued
//                       (`issue()` below), recognised by its `typ`, by an `iss`
//                       this process publishes at the address the request
//                       arrived on, and by this realm's own signature. Always
//                       trusted; nobody declares it.
//   AN APPLICATION      whose entry declares the `iss` in
//                       `oauthSoftwareStatementIssuer` — the software
//                       PUBLISHER. Its keys are the ones an assertion from it
//                       is verified with (`assertion_grant.keysForParty()`: the
//                       registered `jwks` and a key pair from /admin/pki), or
//                       an `x5c` that chains to this realm's CA and was issued
//                       to THAT application.
//
// **THE DECLARATION IS A SEPARATE ATTRIBUTE FROM `oauthAssertionIssuer`**, for
// the reason RFC 7522's is: a party trusted to say who a PERSON is has not
// thereby been trusted to say what a piece of SOFTWARE may register as, and an
// operator who declared one must not have silently declared the other. The KEYS
// are shared, because a key is the party's and a declaration is the decision.
//
// ---------------------------------------------------------------------------
// WHAT IS REFUSED, IN EVERY MODE, AND THE TWO ERRORS SECTION 3.2.2 GIVES IT.
//
//   `invalid_software_statement`    the document is wrong: not a JWS, unsigned
//                                   (section 2.3: it "MUST be digitally signed
//                                   or MACed"), no `iss`, a signature that does
//                                   not verify, expired, not yet valid, issued
//                                   in the future, addressed to somebody else.
//   `unapproved_software_statement` the document may be fine and its issuer is
//                                   not one this realm trusts.
//
// `oauth2.softwareStatementRequireTrustedIssuer` (ON) turns off the SECOND
// refusal and never the first. With it off, a statement from an undeclared
// issuer is accepted as UNVERIFIED — nobody holds a key to check it with — and
// the consequence is stated rather than hidden: its claims do NOT take
// precedence (section 3.1.1's precedence is for a TRUSTED statement), the
// registration records it as untrusted, and it never opens a closed
// registration endpoint.
//
// ---------------------------------------------------------------------------
// WHAT IS DELIBERATELY NOT CHECKED.
//
//   * **`jti` IS NOT SPENT.** Section 2.3 expects one statement to be "used by
//     multiple instances" of the same software — it is shipped WITH the
//     software — so the once-ever rule `used_assertions.js` holds an RFC 7523
//     assertion to would refuse the second installation of every product.
//   * **`exp` IS NOT REQUIRED.** RFC 7591 names no required claim but `iss`,
//     and a statement packaged into a release is commonly unexpiring. One that
//     carries an `exp` is held to it.
//   * **HMAC is refused**, not merely unsupported: section 2.3 allows a MAC,
//     and a MAC needs a key shared between this service and the publisher —
//     which does not exist here, and a client secret is not it (the client
//     presenting a statement has no secret yet; it is registering to get one).
//   * **`jwks_uri` on the publisher is not fetched**, for
//     `assertion_grant.js`'s reason: following a URL to find the key that
//     verifies a credential is a server-side request forgery with a citation
//     attached.
//
// ---------------------------------------------------------------------------
// A LIBRARY (rule 3). It registers no route. It requires `assertion_grant.js`
// and `jwt_access_token.ts` from this directory and libraries from `common/`,
// none of which requires it back; `oauth2.ts` (9),
// `admin-core/admin_actions.ts` and `admin-core/admin_views.ts` require it. It
// never touches `res` — what a refusal looks like on the wire is `oauth2.ts`'s.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `SoftwareStatement` takes every module it uses through its
// constructor (`SoftwareStatementDeps`, the helpers member by member as this
// module destructured them). The module still exports its old names, for
// `oauth2.ts`, `admin-core/` and the tests, which require it by those names
// — the functions, since R2, FACADES over the instance the composition root
// builds and installs; a process without the root builds a default one at
// load.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import stsCrypto = require('../common/crypto');
import pki = require('../common/pki');
import errorCodes = require('../common/error_codes');
import revocationStatus = require('../common/revocation_status');
import applications = require('../common/applications');
import validation = require('../common/validation');
import config = require('../common/config');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import assertionGrant = require('./assertion_grant');
import jwtAccessToken = require('./jwt_access_token');

// A loose JSON-shaped object: the claims, documents and results this file
// reads and answers. Their shapes are the libraries' own, and those libraries
// are being typed one at a time (#50).
type Json = any;

interface SoftwareStatementDeps {
  nodeCrypto: typeof nodeCrypto;
  stsCrypto: typeof stsCrypto;
  pki: typeof pki;
  errorCodes: typeof errorCodes;
  revocationStatus: typeof revocationStatus;
  applications: typeof applications;
  validation: typeof validation;
  config: typeof config;
  // `common/helpers.js`, member by member, as this module destructured it.
  log: typeof helpers.log;
  STS: typeof helpers.STS;
  signJwtAs: typeof helpers.signJwtAs;
  nowSec: typeof helpers.nowSec;
  randomId: typeof helpers.randomId;
  assertionGrant: typeof assertionGrant;
  jwtAccessToken: typeof jwtAccessToken;
}

// The `typ` this service puts on a statement IT issues (RFC 8725 section 3.11,
// explicit typing). It is how a statement signed with this realm's key is told
// apart from every other JWT signed with the same key — an ID Token presented
// as a software statement verifies under that key too, and without the type
// its `sub`, `aud` and `name` would be registered as client metadata.
const TYPE = 'software-statement+jwt';

// RFC 7519's registered claims. They describe the STATEMENT, not the client,
// and are never copied into the registration.
const JWT_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'];

// What the SERVER assigns (RFC 7591 section 3.2.1) or what carries the
// statement itself. A statement naming a `client_id` does not choose one, and
// a statement that carried a `software_statement` would be a statement inside
// a statement.
const SERVER_MEMBERS = ['client_id', 'client_secret', 'client_id_issued_at',
                        'client_secret_expires_at',
                        'registration_access_token',
                        'registration_client_uri', 'software_statement'];

const INVALID = 'invalid_software_statement';
const UNAPPROVED = 'unapproved_software_statement';

class SoftwareStatement {
  static readonly TYPE = TYPE;
  static readonly JWT_CLAIMS = JWT_CLAIMS;
  static readonly SERVER_MEMBERS = SERVER_MEMBERS;

  constructor(private readonly deps: SoftwareStatementDeps) {
    deps.log.debug("Entering SoftwareStatement.constructor().");
    deps.log.debug("Leaving SoftwareStatement.constructor().");
  }

  // What the composition root passes: the deps the module built its
  // own instance from before R2, from the same imports.
  static defaultDeps(): SoftwareStatementDeps {
    helpers.log.debug("Entering SoftwareStatement.defaultDeps().");
    helpers.log.debug("Leaving SoftwareStatement.defaultDeps().");
    return {
      nodeCrypto: nodeCrypto,
      stsCrypto: stsCrypto,
      pki: pki,
      errorCodes: errorCodes,
      revocationStatus: revocationStatus,
      applications: applications,
      validation: validation,
      config: config,
      log: helpers.log,
      STS: helpers.STS,
      signJwtAs: helpers.signJwtAs,
      nowSec: helpers.nowSec,
      randomId: helpers.randomId,
      assertionGrant: assertionGrant,
      jwtAccessToken: jwtAccessToken
    };
  }

  requiresTrustedIssuer(): Json {
    const { config, log } = this.deps;
    log.debug("Entering SoftwareStatement.requiresTrustedIssuer().");
    log.debug("Leaving SoftwareStatement.requiresTrustedIssuer().");
    return config.value('oauth2.softwareStatementRequireTrustedIssuer') !==
      false;
  }

  opensRegistration(): Json {
    const { config, log } = this.deps;
    log.debug("Entering SoftwareStatement.opensRegistration().");
    log.debug("Leaving SoftwareStatement.opensRegistration().");
    return config.value('oauth2.softwareStatementOpensRegistration') !== false;
  }

  required(): Json {
    const { config, log } = this.deps;
    log.debug("Entering SoftwareStatement.required().");
    log.debug("Leaving SoftwareStatement.required().");
    return config.value('oauth2.softwareStatementRequired') === true;
  }

  issuedLifetimeSeconds(): Json {
    const { config, log } = this.deps;
    log.debug("Entering SoftwareStatement.issuedLifetimeSeconds().");
    const seconds = Number(config.value('oauth2.softwareStatementLifetimeS'));
    log.debug("Leaving SoftwareStatement.issuedLifetimeSeconds().");
    return isFinite(seconds) && seconds > 0 ? Math.floor(seconds) : 0;
  }

  private skewSeconds(): Json {
    const { config, log } = this.deps;
    log.debug("Entering SoftwareStatement.skewSeconds().");
    log.debug("Leaving SoftwareStatement.skewSeconds().");
    // `assertion_grant.js`'s setting, for its reason: it answers how far out
    // somebody else's clock may be, and this service holds one opinion on that.
    return config.value('oauth2.clientAssertionSkewS');
  }

  private refusal(errorCode: Json, error: Json, description: Json): Json {
    const { log } = this.deps;
    log.debug("Entering SoftwareStatement.refusal(). code=" + errorCode);
    log.debug("Leaving SoftwareStatement.refusal().");
    return { ok: false, errorCode: errorCode, error: error,
             description: description };
  }

  // ---------------------------------------------------------------------------
  // THE APPLICATION THAT DECLARED THIS `iss`, or null. The first declaration in
  // list order wins, which is `assertion_grant.issuerEntry()`'s rule; two
  // entries declaring one issuer is a configuration somebody should see, and
  // the console shows the declaration on both.
  // ---------------------------------------------------------------------------
  declaringApplication(iss: Json): Json {
    const { applications, log } = this.deps;
    log.debug("Entering SoftwareStatement.declaringApplication(). iss=" + iss);
    const wanted = String(iss || '');
    if (!wanted) {
      log.debug("Leaving SoftwareStatement.declaringApplication(). No issuer.");
      return null;
    }
    const all = applications.list();
    for (let i = 0; i < all.length; i++) {
      const fields = all[i].fields || {};
      const declared = fields.oauthSoftwareStatementIssuer;
      const values = Array.isArray(declared) ? declared
        : (declared ? [String(declared)] : []);
      if (values.indexOf(wanted) >= 0) {
        log.debug("Leaving SoftwareStatement.declaringApplication(). " +
                  "" + all[i].identifier + ".");
        return { identifier: all[i].identifier, fields: fields };
      }
    }
    log.debug("Leaving SoftwareStatement.declaringApplication(). Nobody " +
              "declared it.");
    return null;
  }

  // Is `aud` addressed to an authorization server this process publishes at
  // `base` — its issuer, or its registration endpoint? RFC 7591 does not
  // require an `aud`; one that is present is held to it, because a statement
  // addressed to another server is not one this server was meant to act on.
  private addressedHere(aud: Json, base: Json): Json {
    const { log, jwtAccessToken } = this.deps;
    log.debug("Entering SoftwareStatement.addressedHere().");
    const values = Array.isArray(aud) ? aud : [aud];
    const suffix = '/oauth2/register';
    const here = values.some(function (one) {
      const text = String(one || '');
      if (jwtAccessToken.isHostedIssuer(text, base)) {
        return true;
      }
      if (text.length > suffix.length &&
          text.slice(-suffix.length) === suffix) {
        const prefix = text.slice(0, -suffix.length);
        return prefix === String(base || '') ||
               jwtAccessToken.isHostedIssuer(prefix, base);
      }
      return false;
    });
    log.debug("Leaving SoftwareStatement.addressedHere(). here=" + here);
    return here;
  }

  // ---------------------------------------------------------------------------
  // THE HEADER AND CLAIMS OF A COMPACT JWS, UNVERIFIED. Nothing is decided on
  // them but where to look for a key; see `verify()`.
  // ---------------------------------------------------------------------------
  private decode(statement: Json): Json {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SoftwareStatement.decode().");
    if (typeof statement !== 'string' || !statement) {
      log.debug("Leaving SoftwareStatement.decode(). Not a string.");
      return self.refusal('STS-OAUTH-0300', INVALID,
                          'software_statement must be a string holding the ' +
                          'entire signed JWT (RFC 7591 section 3.1.1).');
    }
    const parts = statement.split('.');
    if (parts.length === 5) {
      log.debug("Leaving SoftwareStatement.decode(). A JWE.");
      return self.refusal('STS-OAUTH-0300', INVALID,
                          'this software statement is a JWE. RFC 7591 ' +
                          'section 2.3 requires a statement to be signed or ' +
                          'MACed using JWS; an encrypted one is not defined, ' +
                          'and nothing in it is secret — it is shipped with ' +
                          'the software.');
    }
    if (parts.length !== 3) {
      log.debug("Leaving SoftwareStatement.decode(). Not a compact JWS.");
      return self.refusal('STS-OAUTH-0300', INVALID,
                          'software_statement is not a compact JWS (three ' +
                          'base64url segments separated by dots).');
    }
    let header = null;
    let claims = null;
    try {
      header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
      claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    } catch (e) {
      log.debug("Caught in SoftwareStatement.decode(): " +
                "" + ((e && e.message) || e));
      log.debug("Leaving SoftwareStatement.decode(). Not JSON.");
      return self.refusal('STS-OAUTH-0301', INVALID,
                          'the software statement\'s header or claims are ' +
                          'not ' +
                          'JSON: ' + e.message);
    }
    if (!header || typeof header !== 'object' || !claims ||
        typeof claims !== 'object' || Array.isArray(claims)) {
      log.debug("Leaving SoftwareStatement.decode(). Not objects.");
      return self.refusal('STS-OAUTH-0301', INVALID,
                          'the software statement\'s header and claims must ' +
                          'each be a JSON object.');
    }
    log.debug("Leaving SoftwareStatement.decode().");
    return { ok: true, header: header, claims: claims };
  }

  // The claims that are CLIENT METADATA, which is every claim but the JWT's own
  // and the members only the server assigns.
  private metadataFrom(claims: Json): Json {
    const { log } = this.deps;
    log.debug("Entering SoftwareStatement.metadataFrom().");
    const out: Json = {};
    Object.keys(claims || {}).forEach(function (name) {
      if (JWT_CLAIMS.indexOf(name) < 0 && SERVER_MEMBERS.indexOf(name) < 0) {
        out[name] = claims[name];
      }
    });
    log.debug("Leaving SoftwareStatement.metadataFrom(). " +
              "" + Object.keys(out).length +
              " member(s).");
    return out;
  }

  // ---------------------------------------------------------------------------
  // VERIFY ONE STATEMENT.
  //
  // `opts.base` is the address the request arrived on — what an issuer this
  // process publishes is compared against. The answer is `{ ok: true, trusted,
  // issuer, issuerKind, publisher, metadata, ... }` or a refusal carrying
  // `error` (one of section 3.2.2's two), `description` and `errorCode`.
  //
  // **THE SIGNATURE IS VERIFIED BEFORE ANY CLAIM IS BELIEVED**, which is
  // `assertion_grant.verify()`'s order for its reason: the unverified `iss` is
  // read only to find candidate keys.
  // ---------------------------------------------------------------------------
  async verify(statement: Json, opts: Json): Promise<Json> {
    const { stsCrypto, pki, errorCodes, revocationStatus, validation, log, STS,
            nowSec, assertionGrant, jwtAccessToken } = this.deps;
    const self = this;
    log.debug("Entering SoftwareStatement.verify().");
    const options = opts || {};
    const base = String(options.base || '');
    const decoded = self.decode(statement);
    if (!decoded.ok) {
      log.debug("Leaving SoftwareStatement.verify(). It would not decode.");
      return decoded;
    }
    const header = decoded.header;
    const unverified = decoded.claims;
    const alg = String(header.alg || '');
    if (alg === 'none') {
      log.debug("Leaving SoftwareStatement.verify(). alg=none.");
      return self.refusal('STS-OAUTH-0302', INVALID,
                          'this software statement says alg="none". RFC 7591 ' +
                          'section 2.3: a software statement "MUST be ' +
                          'digitally signed or MACed using JSON Web ' +
                          'Signature (JWS)".');
    }
    if (stsCrypto.JWS_ASYMMETRIC_ALGS.indexOf(alg) < 0) {
      log.debug("Leaving SoftwareStatement.verify(). An algorithm this " +
                "service does not take.");
      return self.refusal('STS-OAUTH-0303', INVALID,
                          'this software statement is signed "' + alg + '", ' +
                          'and this authorization server verifies statements ' +
                          'signed ' +
                          'with ' + stsCrypto.JWS_ASYMMETRIC_ALGS.join(', ') +
                          '. ' +
                          (stsCrypto.JWS_SIGNING_ALGS.indexOf(alg) >= 0
                            ? 'A MAC needs a key this service shares with ' +
                              'the publisher, and there is none: a client ' +
                              'presenting a statement has no secret yet — it ' +
                              'is registering to be given one.'
                            : ''));
    }
    const iss = String(unverified.iss || '');
    if (!iss) {
      log.debug("Leaving SoftwareStatement.verify(). No iss.");
      return self.refusal('STS-OAUTH-0304', INVALID,
                          'RFC 7591 section 2.3: a software statement "MUST ' +
                          'contain an "iss" (issuer) claim denoting the ' +
                          'party attesting to the claims". This one has none.');
    }

    // --- Which keys could have signed it -------------------------------------
    const hosted = jwtAccessToken.isHostedIssuer(iss, base);
    let issuerKind = '';
    let publisher = '';
    const candidates = [];
    if (hosted) {
      if (String(header.typ || '') !== TYPE) {
        // AN `iss` THIS PROCESS ANSWERS TO, ON A DOCUMENT IT DID NOT TYPE AS A
        // STATEMENT. Every statement `issue()` signs carries the type, so this
        // is some OTHER JWT from this realm — an ID Token, an access token —
        // and registering its claims as client metadata is the confusion the
        // type exists to prevent.
        log.debug("Leaving SoftwareStatement.verify(). This realm's issuer " +
                  "without the type.");
        return self.refusal('STS-OAUTH-0305', INVALID,
                            'this software statement names this ' +
                            'authorization ' +
                            'server ("' + iss + '") as its issuer and is not ' +
                            'typed ' +
                            '"' + TYPE + '". Every statement this service ' +
                            'issues carries that `typ`; a JWT without it is ' +
                            'one of this service\'s other tokens, and its ' +
                            'claims are not client metadata.');
      }
      issuerKind = 'realm';
      publisher = String(unverified.sub || '');
      // EVERY LIVE GENERATION of the realm's key (#42): a statement issued
      // before a rotation still verifies until that key's grace ends.
      helpers.ownRsaCertificates('jose').forEach(function (own: any): void {
        candidates.push({ kid: String(own.kid || ''), key: own.certPem,
                          source: 'realm' });
      });
    } else {
      const party = self.declaringApplication(iss);
      if (party) {
        issuerKind = 'application';
        publisher = party.identifier;
        const read = assertionGrant.keysForParty(party.fields, 'application');
        read.keys.forEach(function (one) {
          candidates.push(one);
        });
        const fromChain = await assertionGrant.keyFromChain(header);
        if (fromChain && fromChain.key) {
          if (fromChain.subjectKind === 'application' &&
              fromChain.subjectName === party.identifier) {
            candidates.push({ kid: header.kid ? String(header.kid) : '',
                              key: fromChain.key, source: 'x5c' });
          } else if (!candidates.length) {
            log.debug("Leaving SoftwareStatement.verify(). The x5c belongs " +
                      "to somebody else.");
            return self.refusal('STS-OAUTH-0306', UNAPPROVED,
                                'this software statement carries a ' +
                                'certificate that chains to this realm\'s ' +
                                'certificate authority and was issued to ' +
                                (fromChain.subjectKind
                                  ? 'the ' + fromChain.subjectKind + ' "' +
                                    fromChain.subjectName + '"'
                                  : 'something this service cannot name') +
                                ', not to "' + party.identifier + '", which ' +
                                'is the application that declared "' + iss +
                                '". A ' +
                                'certificate from this realm proves who it ' +
                                'was issued to, and that is not the ' +
                                'publisher.');
          }
        } else if (fromChain && fromChain.error && !candidates.length) {
          log.debug("Leaving SoftwareStatement.verify(). The x5c does not " +
                    "chain here.");
          return self.refusal(fromChain.errorCode || 'STS-OAUTH-0307',
                              UNAPPROVED, fromChain.error);
        }
        if (!candidates.length) {
          log.debug("Leaving SoftwareStatement.verify(). The publisher " +
                    "holds no key.");
          return self.refusal('STS-OAUTH-0307', UNAPPROVED,
                              '"' + iss + '" is declared by the application "' +
                              party.identifier + '", which holds no key this ' +
                              'service can verify a statement with' +
                              (read.problems.length
                                ? ' (' + read.problems.join('; ') + ')' : '') +
                              (read.jwksUriOnly
                                ? ' — it has a jwks_uri, which this service ' +
                                  'does ' +
                                  'not fetch' : '') +
                              '. Register its public keys by value as ' +
                              '`jwks`, or issue it a key pair from ' +
                              '/admin/pki.');
        }
      } else if (self.requiresTrustedIssuer()) {
        log.warn('software_statement: a software statement from "' + iss +
                 '" was refused — no application in this realm declares it ' +
                 'in oauthSoftwareStatementIssuer.');
        log.debug("Leaving SoftwareStatement.verify(). Nobody declared that " +
                  "issuer.");
        return self.refusal('STS-OAUTH-0308', UNAPPROVED,
                            'nothing in this realm trusts "' + iss + '" to ' +
                            'issue software statements. Declare it on the ' +
                            'publisher\'s application entry as ' +
                            '`oauthSoftwareStatementIssuer`, with a `jwks` ' +
                            'or a key pair issued from /admin/pki — or ' +
                            'present a statement this authorization server ' +
                            'issued itself, from the application\'s page. ' +
                            '`oauth2.softwareStatementRequireTrustedIssuer` ' +
                            'turns this refusal off; with it off the ' +
                            'statement is taken as unverified and its claims ' +
                            'do not take precedence.');
      } else {
        // THE SETTING IS OFF: accepted, and said to be UNVERIFIED everywhere it
        // is recorded. There is no key to try, so there is no signature to
        // check — which is precisely why its claims lose to the JSON.
        log.warn('software_statement: a software statement from the ' +
                 'undeclared issuer "' + iss + '" is accepted UNVERIFIED, ' +
                 'because oauth2.softwareStatementRequireTrustedIssuer is ' +
                 'off.');
        log.debug("Leaving SoftwareStatement.verify(). Accepted unverified.");
        return { ok: true, trusted: false, issuer: iss,
                 issuerKind: 'undeclared', publisher: '', alg: alg,
                 keySource: '', claims: unverified,
                 metadata: self.metadataFrom(unverified) };
      }
    }

    // --- The signature -------------------------------------------------------
    const narrowed = header.kid
      ? candidates.filter(function (one) {
        return one.kid === String(header.kid);
      })
      : candidates;
    const attempts = narrowed.length ? narrowed : candidates;
    let claims = null;
    let usedKey = null;
    let lastError = '';
    for (let i = 0; i < attempts.length && !claims; i++) {
      try {
        claims = await stsCrypto.verifyJwsAsync(statement, attempts[i].key, {
          algorithms: [alg],
          issuer: iss,
          clockTolerance: self.skewSeconds()
        });
        usedKey = attempts[i];
      } catch (e) {
        log.debug("Caught in SoftwareStatement.verify(): " +
                  "" + ((e && e.message) || e));
        lastError = e.message;
      }
    }
    if (!claims) {
      log.debug("Leaving SoftwareStatement.verify(). It did not verify.");
      return self.refusal('STS-OAUTH-0309', INVALID,
                          'the software statement did not verify: ' +
                          lastError +
                          '. It must be signed by a key ' +
                          (issuerKind === 'realm'
                            ? 'this realm holds now — a statement this ' +
                              'service issued stops verifying when the ' +
                              'realm\'s signing key is replaced, which in ' +
                              'development mode is every restart'
                            : 'held by the application "' + publisher + '"') +
                          ', and be unexpired.');
    }

    // --- A registered key's chain and revocation, now that it has been USED
    // --- `assertion_grant.verify()`'s two checks, for its reasons: a key out
    // of a JWKS that carries its certificate is believed only while that chain
    // holds and nothing on it is revoked. The realm's own key and an `x5c` path
    // were checked by other means.
    const usedX5c = usedKey && usedKey.jwk && Array.isArray(usedKey.jwk.x5c)
      ? usedKey.jwk.x5c : [];
    if (usedX5c.length) {
      const keyChain = await pki.verifySignerChain(undefined, {
        certificate: usedX5c[0], chain: usedX5c.slice(1), key: usedKey.jwk,
        source: 'the key "' + (usedKey.kid || '(no kid)') + '" in ' +
                usedKey.source + ' for "' + iss + '"'
      });
      if (!keyChain.ok) {
        log.debug("Leaving SoftwareStatement.verify(). The key's chain is " +
                  "refused.");
        return self.refusal(errorCodes.codeOf(keyChain) || 'STS-OAUTH-0310',
                            INVALID,
                            'the certificate of the key that verified this ' +
                            'software statement does not have a valid trust ' +
                            'chain: ' + keyChain.why);
      }
    }
    if (usedKey && usedKey.jwk) {
      const verdict = await revocationStatus.registeredKeyVerdictFor(
        usedKey.jwk,
        'the key "' + (usedKey.kid || '(no kid)') + '" in ' + usedKey.source +
        ' for "' + iss + '"');
      if (verdict && verdict.refused) {
        log.debug("Leaving SoftwareStatement.verify(). The key is revoked.");
        return self.refusal('STS-PKI-0129', INVALID,
                            'the key that verified this software statement ' +
                            'may no ' +
                            'longer be used: ' + verdict.why);
      }
    }

    const now = nowSec();
    if (claims.iat !== undefined && claims.iat !== null &&
        Number(claims.iat) > now + Number(self.skewSeconds() || 0)) {
      log.debug("Leaving SoftwareStatement.verify(). Issued in the future.");
      return self.refusal('STS-OAUTH-0311', INVALID,
                          'this software statement says it was issued at ' +
                          new Date(Number(claims.iat) * 1000).toISOString() +
                          ', which is in the future. One of the two clocks ' +
                          'is wrong (oauth2.clientAssertionSkewS allows ' +
                          self.skewSeconds() + ' seconds).');
    }
    if (claims.aud !== undefined && claims.aud !== null &&
        !self.addressedHere(claims.aud, base)) {
      log.debug("Leaving SoftwareStatement.verify(). Addressed to somebody " +
                "else.");
      return self.refusal('STS-OAUTH-0312', INVALID,
                          'this software statement is addressed to ' +
                          JSON.stringify(claims.aud) + ', which is not this ' +
                          'authorization server\'s issuer or registration ' +
                          'endpoint. RFC 7591 does not require an `aud`; one ' +
                          'that is present says whom the statement is for.');
    }
    const metadata = self.metadataFrom(claims);
    const checked = validation.checkDocument(metadata, 'software statement');
    if (!checked.ok) {
      log.debug("Leaving SoftwareStatement.verify(). The claims are refused " +
                "by the validator.");
      return self.refusal('STS-OAUTH-0313', INVALID, checked.detail);
    }

    log.info('software_statement: a software statement from "' + iss + '" (' +
             issuerKind + (publisher ? ' ' + publisher : '') + ') verified. ' +
             'alg=' + alg + ', key from ' + (usedKey ? usedKey.source : '?') +
             '.');
    log.debug("Leaving SoftwareStatement.verify(). Verified.");
    return { ok: true, trusted: true, issuer: iss, issuerKind: issuerKind,
             publisher: publisher, alg: alg,
             keySource: usedKey ? usedKey.source : '',
             softwareId: metadata.software_id === undefined ? ''
               : String(metadata.software_id),
             expiresAt: claims.exp ? Number(claims.exp) * 1000 : 0,
             claims: claims, metadata: checked.value };
  }

  // ---------------------------------------------------------------------------
  // A REGISTRATION DOCUMENT WITH ITS STATEMENT APPLIED.
  //
  // Used by the POST and by RFC 7592's PUT, which section 2.2 of that RFC makes
  // a whole registration too. The answer's `metadata` is what the rest of the
  // endpoint checks and stores: the statement's claims over the JSON when it is
  // TRUSTED (section 3.1.1), the JSON over them when it is not, and the
  // statement string itself kept unmodified for section 3.2.1's response.
  // `statement` is null when the document carried none.
  // ---------------------------------------------------------------------------
  async resolve(document: Json, opts: Json): Promise<Json> {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SoftwareStatement.resolve().");
    const given = document || {};
    const json = Object.assign({}, given);
    const presented = json.software_statement;
    delete json.software_statement;
    if (presented === undefined || presented === null || presented === '') {
      if (self.required()) {
        log.debug("Leaving SoftwareStatement.resolve(). A statement is " +
                  "required and absent.");
        return self.refusal('STS-OAUTH-0314', INVALID,
                            'this authorization server registers a client ' +
                            'only with a software statement (RFC 7591 ' +
                            'section 2.3), and this registration carries ' +
                            'none. `oauth2.softwareStatementRequired` is on.');
      }
      log.debug("Leaving SoftwareStatement.resolve(). No statement.");
      return { ok: true, metadata: json, statement: null };
    }
    const verified = await self.verify(presented, opts);
    if (!verified.ok) {
      log.debug("Leaving SoftwareStatement.resolve(). The statement is " +
                "refused.");
      return verified;
    }
    const merged = verified.trusted
      ? Object.assign({}, json, verified.metadata)
      : Object.assign({}, verified.metadata, json);
    merged.software_statement = presented;
    log.debug("Leaving SoftwareStatement.resolve(). " +
              "trusted=" + verified.trusted);
    return { ok: true, metadata: merged,
             statement: { trusted: verified.trusted, issuer: verified.issuer,
                          issuerKind: verified.issuerKind,
                          publisher: verified.publisher,
                          softwareId: verified.softwareId || '' } };
  }

  // ---------------------------------------------------------------------------
  // MAY THIS UPDATE REPLACE A REGISTRATION THAT A STATEMENT ADMITTED?
  //
  // A client let in ONLY because a trusted statement fixed its metadata — the
  // endpoint is closed to everybody else — must not be able to PUT that
  // metadata away afterwards: its `redirect_uris` would then be whatever the
  // holder of a registration access token says, which is the open registration
  // the operator did not turn on. So while `open` is false (the endpoint would
  // refuse a registration without a statement), an update of such a client must
  // carry a TRUSTED statement from the SAME issuer. `facts` is the entry's
  // record of how it registered (`applications.softwareStatementFactsOf()`).
  // ---------------------------------------------------------------------------
  updateProblem(facts: Json, resolved: Json, open: Json): Json {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SoftwareStatement.updateProblem().");
    if (open || !facts || !facts.trusted || !facts.issuer) {
      log.debug("Leaving SoftwareStatement.updateProblem(). Nothing binds " +
                "this registration.");
      return null;
    }
    const now = resolved && resolved.statement;
    if (now && now.trusted && now.issuer === facts.issuer) {
      log.debug("Leaving SoftwareStatement.updateProblem(). The same issuer " +
                "vouches again.");
      return null;
    }
    log.debug("Leaving SoftwareStatement.updateProblem(). Refused.");
    return self.refusal('STS-OAUTH-0315', UNAPPROVED,
                        'this client was registered on the strength of a ' +
                        'software ' +
                        'statement from "' + facts.issuer + '", at an ' +
                        'endpoint that registers nobody without one, so an ' +
                        'update must carry a trusted software statement from ' +
                        'that issuer too. ' +
                        (now
                          ? 'This one ' + (now.trusted
                            ? 'is from "' + now.issuer + '".'
                            : 'is not trusted.')
                          : 'This update carries none.'));
  }

  // ---------------------------------------------------------------------------
  // ISSUE A STATEMENT AS THIS REALM, for the publisher `opts.identifier`.
  //
  // `opts.metadata` is the client metadata the statement fixes; `opts.base` is
  // the address the console or API request arrived on, whose issuer becomes
  // `iss` — so a statement issued at one address is recognised at that address
  // (set `global.publicBaseUrl` for a service reached under several names).
  // `sub` names the publisher, `software_id` defaults to its identifier, and
  // the statement is written onto the entry as `oauthIssuedSoftwareStatement`.
  //
  // **NOTHING IN A STATEMENT IS SECRET, AND WHOEVER HOLDS ONE IS THE
  // SOFTWARE.** Section 2.3 expects it to ship with every copy. What it does
  // not fix, the registering client chooses — so a publisher that must not be
  // able to register a `client_credentials` client should be issued a statement
  // whose `grant_types` says so.
  // ---------------------------------------------------------------------------
  issue(opts: Json): Json {
    const { errorCodes, applications, validation, log, signJwtAs, nowSec,
            randomId, jwtAccessToken } = this.deps;
    const self = this;
    log.debug("Entering SoftwareStatement.issue().");
    const options = opts || {};
    const identifier = String(options.identifier || '').trim();
    const entry = identifier ? applications.get(identifier) : null;
    if (!entry) {
      log.debug("Leaving SoftwareStatement.issue(). No such application.");
      return errorCodes.mark({ ok: false,
               errors: ['There is no application called "' + identifier +
                        '" here to issue a software statement for.'] },
        'STS-ADMIN-0646');
    }
    let metadata = options.metadata;
    if (typeof metadata === 'string') {
      const text = metadata.trim();
      try {
        metadata = text ? JSON.parse(text) : {};
      } catch (e) {
        log.debug("Caught in SoftwareStatement.issue(): " +
                  "" + ((e && e.message) || e));
        log.debug("Leaving SoftwareStatement.issue(). The metadata is not " +
                  "JSON.");
        return errorCodes.mark({ ok: false,
                 errors: ['The client metadata is not JSON: ' +
                          e.message] }, 'STS-ADMIN-0647');
      }
    }
    if (metadata === undefined || metadata === null) {
      metadata = {};
    }
    if (typeof metadata !== 'object' || Array.isArray(metadata)) {
      log.debug("Leaving SoftwareStatement.issue(). The metadata is not an " +
                "object.");
      return errorCodes.mark({ ok: false,
               errors: ['The client metadata must be a JSON object of RFC ' +
                        '7591 members, such as {"redirect_uris": ' +
                        '["https://app.example/cb"]}.'] }, 'STS-ADMIN-0647');
    }
    const checked = validation.checkDocument(metadata, 'software statement');
    if (!checked.ok) {
      log.debug("Leaving SoftwareStatement.issue(). The validator refused " +
                "the metadata.");
      return errorCodes.mark({ ok: false,
               errors: [checked.detail] }, 'STS-ADMIN-0647');
    }
    const reserved = Object.keys(metadata).filter(function (name) {
      return JWT_CLAIMS.indexOf(name) >= 0 || SERVER_MEMBERS.indexOf(name) >= 0;
    });
    if (reserved.length) {
      log.debug("Leaving SoftwareStatement.issue(). Reserved members.");
      return errorCodes.mark({ ok: false,
               errors: ['A software statement cannot fix ' +
                        reserved.join(', ') + ': ' +
                        'the JWT claims are set by this service, and ' +
                        'client_id, the secret, the registration access ' +
                        'token and their times are assigned at registration ' +
                        '(RFC ' +
                        '7591 section 3.2.1).'] }, 'STS-ADMIN-0648');
    }
    const problem = applications.registrationUriProblem(metadata) ||
                    applications.introspectionResponseProblem(metadata);
    if (problem) {
      log.debug("Leaving SoftwareStatement.issue(). An unusable address or " +
                "algorithm.");
      return errorCodes.mark({ ok: false,
               errors: [problem.description] },
        problem.errorCode || 'STS-REG-0070');
    }
    const iss = jwtAccessToken.issuerFor(String(options.base || ''));
    if (!iss) {
      // No request address and no `oauth2.issuer` pin: a caller that did not
      // come through either admin route. A statement with an empty `iss` would
      // be one section 2.3 forbids and no registration could ever match.
      log.debug("Leaving SoftwareStatement.issue(). No issuer to name.");
      return errorCodes.mark({ ok: false,
        errors: ['There is no issuer to put in the statement: the request ' +
                 'address was not passed and oauth2.issuer is not set.'] },
        'STS-ADMIN-0650');
    }
    const issuedAt = nowSec();
    const lifetime = options.lifetimeSeconds === undefined ||
                     options.lifetimeSeconds === null ||
                     options.lifetimeSeconds === ''
      ? self.issuedLifetimeSeconds()
      : Math.max(0, Math.floor(Number(options.lifetimeSeconds) || 0));
    const claims = Object.assign({ software_id: identifier }, metadata, {
      iss: iss,
      sub: identifier,
      iat: issuedAt,
      jti: randomId(16)
    });
    if (lifetime > 0) {
      claims.exp = issuedAt + lifetime;
    }
    let statement;
    try {
      // certificate-header: none — a software statement is verified only by
      // this service, against its own key, so a certificate naming that key
      // tells no verifier anything it needs.
      statement = signJwtAs(claims, 'RS256', null,
                            { header: { typ: TYPE } });
    } catch (e) {
      log.error(errorCodes.tag('STS-ADMIN-0649') + 'software_statement: a ' +
                'statement for "' + identifier + '" could not be signed: ' +
                e.message);
      log.debug("Leaving SoftwareStatement.issue(). Signing failed.");
      return errorCodes.mark({ ok: false,
               errors: ['The statement could not be signed: ' +
                        e.message] }, 'STS-ADMIN-0649');
    }
    const written = applications.updateApplication(identifier, {
      mode: 'set', attribute: 'oauthIssuedSoftwareStatement', value: statement,
      actor: options.actor || ''
    });
    if (written && written.ok === false) {
      log.debug("Leaving SoftwareStatement.issue(). The entry refused it.");
      return errorCodes.mark(written, errorCodes.codeOf(written) ||
                                       'STS-ADMIN-0649');
    }
    log.info('software_statement: issued a software statement for "' +
             identifier + '" as ' + claims.iss + (claims.exp
               ? ', valid until ' + new Date(claims.exp * 1000).toISOString()
               : ', with no expiry') + '.');
    log.debug("Leaving SoftwareStatement.issue().");
    return { ok: true, softwareStatement: statement, claims: claims,
             application: applications.get(identifier),
             message: 'A software statement for "' + identifier + '" is ' +
                      'issued and on the entry as ' +
                      '`oauthIssuedSoftwareStatement`. A client presenting ' +
                      'it at POST /oauth2/register is registered with these ' +
                      'members fixed' + (claims.exp
                        ? ', until ' + new Date(claims.exp * 1000).toISOString()
                        : '') + '; whatever the statement does not fix, the ' +
                      'client chooses.' };
  }

  // ---------------------------------------------------------------------------
  // WHAT THE CONSOLE SAYS ABOUT THE STATEMENT ON AN ENTRY: its claims, and
  // whether it still verifies under this realm's key now. Synchronous and
  // never throws — a page is drawing it.
  // ---------------------------------------------------------------------------
  describe(statement: Json): Json {
    const { nodeCrypto, stsCrypto, log, STS } = this.deps;
    const self = this;
    log.debug("Entering SoftwareStatement.describe().");
    if (!statement) {
      log.debug("Leaving SoftwareStatement.describe(). None.");
      return null;
    }
    const decoded = self.decode(String(statement));
    if (!decoded.ok) {
      log.debug("Leaving SoftwareStatement.describe(). Unreadable.");
      return { readable: false, why: decoded.description };
    }
    let verifies = false;
    let why = '';
    try {
      helpers.verifyOwnJws(String(statement),
                           { algorithms: ['RS256'], clockTolerance: 0 });
      verifies = true;
    } catch (e) {
      log.debug("Caught in SoftwareStatement.describe(): " +
                "" + ((e && e.message) || e));
      why = e.message;
    }
    const claims = decoded.claims;
    log.debug("Leaving SoftwareStatement.describe(). verifies=" + verifies);
    return { readable: true, verifies: verifies, why: why,
             typed: String(decoded.header.typ || '') === TYPE,
             issuer: String(claims.iss || ''),
             issuedAt: claims.iat ? Number(claims.iat) * 1000 : 0,
             expiresAt: claims.exp ? Number(claims.exp) * 1000 : 0,
             metadata: self.metadataFrom(claims),
             thumbprint: nodeCrypto.createHash('sha256')
               .update(String(statement)).digest('base64url').slice(0, 16) };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<SoftwareStatement>(
  'oauth-oidc/software_statement',
  () => new SoftwareStatement(SoftwareStatement.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  SoftwareStatement: SoftwareStatement,
  installInstance: (instance: SoftwareStatement): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  TYPE: SoftwareStatement.TYPE,
  JWT_CLAIMS: SoftwareStatement.JWT_CLAIMS,
  SERVER_MEMBERS: SoftwareStatement.SERVER_MEMBERS,
  requiresTrustedIssuer: slot.forward('requiresTrustedIssuer'),
  opensRegistration: slot.forward('opensRegistration'),
  required: slot.forward('required'),
  issuedLifetimeSeconds: slot.forward('issuedLifetimeSeconds'),
  declaringApplication: slot.forward('declaringApplication'),
  verify: slot.forward('verify'),
  resolve: slot.forward('resolve'),
  updateProblem: slot.forward('updateProblem'),
  issue: slot.forward('issue'),
  describe: slot.forward('describe')
};
