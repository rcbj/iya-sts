'use strict';
//
// File: siop.ts
//
// ===========================================================================
// SELF-ISSUED OPENID PROVIDER v2 — THE RELYING PARTY'S HALF (#129,
// 2026-09-23).
//
// A wallet can answer an authorization request with an ID Token it signed
// ITSELF: `iss` and `sub` are the same value, and that value is a key — a DID
// whose document names it, or the RFC 7638 thumbprint of a JWK the token
// carries in `sub_jwk`. Nobody vouches for who holds the key. So the token
// proves one thing, and it is exactly the thing a password proves: whoever
// presented it holds a credential previously bound to an account.
//
// This file is that binding and the check of the token. Four things:
//
//   * **ENROLMENT.** A subject is enrolled on a person's entry
//     (`stsSelfIssuedSubject`, withheld from LDAP reads): by the person, from
//     a session they already hold, by answering a SIOPv2 request on
//     `/portal/self-issued` — so what is enrolled is a key they PROVED they
//     hold, never a string they were talked into pasting — or by an
//     administrator (`/admin/users`, `/admin-api`). One subject belongs to at
//     most one person in a realm.
//   * **VALIDATION** (SIOPv2 section 11.1): `iss` equals `sub`; the subject
//     resolves to a key — a JWK thumbprint subject must be the thumbprint of
//     `sub_jwk`, a DID subject's `kid` must be one of that DID's
//     authentication methods; the signature verifies with it, with an
//     algorithm this service accepts (never `none`, never a MAC); `aud` names
//     this Verifier's Client Identifier; `nonce` is the request's; `exp` is in
//     the future and `iat` no older than `oid4vp.siopIdTokenMaxAgeS`.
//   * **A did:web IS FETCHED ONLY WHEN IT IS ENROLLED.** `did:jwk` and
//     `did:key` resolve from the identifier (`vc_data_integrity.ts`); a
//     `did:web` resolves by fetching a document from the host it names, which
//     is the presenter's kind of URL, so it is looked up among enrolled
//     subjects FIRST and fetched only if a person or an administrator of this
//     realm put it there — through `federation_http.fetchPublished()`, which
//     brings the outbound kill switch, https, the internal-address refusal in
//     product mode and no redirect. The root CLAUDE.md's list of URLs this
//     service dials carries the row.
//   * **THE OUTCOME.** An enrolled subject signs in as its person; an
//     unenrolled one is refused IN BOTH MODES (rcbj, #129) — there is no
//     development relaxation, because the signature is the only thing a
//     self-issued token has, and "any key signs in" is no sign-in at all.
//
// Out of scope by decision (rcbj, #129): this service is never the
// Self-Issued OP — it holds no wallet.
//
// A LIBRARY (rule 3): it registers nothing. The verifier (`vc_verifier.ts`)
// asks it to check a token, the sign-in (`vc_signin.ts`) to decide whom it
// signs in, and the console, the API and the portal to enrol.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import credentials = require('../common/credentials');
import stsCrypto = require('../common/crypto');
import errorCodes = require('../common/error_codes');
import vcDataIntegrity = require('./vc_data_integrity');

// A loose JSON-shaped value: a token's claims, a DID document.
type Json = any;

// SIOPv2 section 8's `subject_syntax_types_supported`: the JWK Thumbprint
// syntax and the three DID methods this Verifier resolves.
const SUBJECT_SYNTAX_TYPES = Object.freeze([
  'urn:ietf:params:oauth:jwk-thumbprint', 'did:jwk', 'did:key', 'did:web']);

const THUMBPRINT_URI_PREFIX = 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:';

// A self-issued ID Token is signed with an asymmetric key: a MAC would need a
// secret this Verifier shares with nobody, and `none` signs nothing.
const ID_TOKEN_ALGS = stsCrypto.JWS_ASYMMETRIC_ALGS.slice();

// How many subjects one person may enrol. One entry value each.
const MAX_SUBJECTS = 10;

// Clock skew allowed on `exp` and on an `iat` in the future.
const SKEW_S = 60;

interface SiopDeps {
  log: typeof helpers.log;
  config: typeof config;
  credentials: typeof credentials;
  stsCrypto: typeof stsCrypto;
  errorCodes: typeof errorCodes;
  vcDataIntegrity: typeof vcDataIntegrity;
  fetchDocument: (url: string) => Promise<Json>;
  nowSec: () => number;
}

class Siop {
  static readonly SUBJECT_SYNTAX_TYPES = SUBJECT_SYNTAX_TYPES;
  static readonly ID_TOKEN_ALGS = ID_TOKEN_ALGS;
  static readonly MAX_SUBJECTS = MAX_SUBJECTS;

  constructor(private readonly deps: SiopDeps) {
    deps.log.debug("Entering Siop.constructor().");
    deps.log.debug("Leaving Siop.constructor().");
  }

  // What the composition root passes. `federation_http` is reached LAZILY,
  // for the one fetch, as `oauth-oidc/client_jwks.js` reaches it.
  static defaultDeps(): SiopDeps {
    helpers.log.debug("Entering Siop.defaultDeps().");
    helpers.log.debug("Leaving Siop.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      credentials: credentials,
      stsCrypto: stsCrypto,
      errorCodes: errorCodes,
      vcDataIntegrity: vcDataIntegrity,
      fetchDocument: function (url: string): Promise<Json> {
        helpers.log.debug("Entering fetchDocument().");
        const fedHttp = require('../federation/federation_http');
        helpers.log.debug("Leaving fetchDocument().");
        return fedHttp.fetchPublished(url, {
          accept: 'application/did+json, application/json' })
          .then(function (got: Json) {
            if (!got.ok) {
              throw new Error(got.why || ('HTTP ' + got.status));
            }
            return JSON.parse(got.body.toString('utf8'));
          });
      },
      nowSec: helpers.nowSec
    };
  }

  // -------------------------------------------------------------------------
  // SUBJECTS
  // -------------------------------------------------------------------------

  // One subject in the spelling this service keeps: a DID without a fragment,
  // or an RFC 9278 thumbprint URI. Accepts a bare base64url SHA-256
  // thumbprint and a public JWK (as JSON) as well, which is what an
  // administrator is likely to have in hand. '' for anything else.
  normalise(raw: unknown): string {
    const { log, stsCrypto, vcDataIntegrity } = this.deps;
    log.debug("Entering Siop.normalise().");
    const text = typeof raw === 'string' ? raw.trim() : '';
    if (/^did:(jwk|key|web):[A-Za-z0-9._%:-]+(#.*)?$/.test(text)) {
      log.debug("Leaving Siop.normalise(). A DID.");
      return text.replace(/#.*$/, '');
    }
    if (text.indexOf(THUMBPRINT_URI_PREFIX) === 0 &&
        /^[A-Za-z0-9_-]{43}$/.test(text.slice(THUMBPRINT_URI_PREFIX.length))) {
      log.debug("Leaving Siop.normalise(). A thumbprint URI.");
      return text;
    }
    if (/^[A-Za-z0-9_-]{43}$/.test(text)) {
      log.debug("Leaving Siop.normalise(). A bare thumbprint.");
      return THUMBPRINT_URI_PREFIX + text;
    }
    if (text.charAt(0) === '{') {
      try {
        const jwk = JSON.parse(text);
        if (jwk && jwk.d === undefined) {
          const uri = stsCrypto.jwkThumbprintUri(
            vcDataIntegrity.publicJwkOf(jwk));
          log.debug("Leaving Siop.normalise(). A JWK.");
          return uri;
        }
      } catch (e) {
        log.debug("Caught in Siop.normalise(): " + ((e && e.message) || e));
      }
    }
    log.debug("Leaving Siop.normalise(). Not a subject.");
    return '';
  }

  private parseValue(value: string): Json {
    const { log } = this.deps;
    log.debug("Entering Siop.parseValue().");
    try {
      const one = JSON.parse(value);
      if (one && typeof one.subject === 'string') {
        log.debug("Leaving Siop.parseValue().");
        return one;
      }
    } catch (e) {
      log.debug("Caught in Siop.parseValue(): " + ((e && e.message) || e));
    }
    log.debug("Leaving Siop.parseValue(). Unreadable; skipped.");
    return null;
  }

  // Every subject a person has enrolled, as { subject, label, enrolledAt,
  // by }. null where the directory holds no entry for them.
  list(username: unknown): Json[] | null {
    const { log, credentials } = this.deps;
    log.debug("Entering Siop.list(). user=" + username);
    const values = credentials.readSelfIssuedSubjects(String(username || ''));
    if (!Array.isArray(values)) {
      log.debug("Leaving Siop.list(). No entry.");
      return null;
    }
    const self = this;
    const out = values.map(function (value) {
      return self.parseValue(value);
    }).filter(Boolean);
    log.debug("Leaving Siop.list(). " + out.length + ".");
    return out;
  }

  // Whose subject this is in the current realm: a username, or ''.
  ownerOf(subject: unknown): string {
    const { log, credentials } = this.deps;
    const self = this;
    log.debug("Entering Siop.ownerOf().");
    const wanted = this.normalise(subject);
    if (!wanted) {
      log.debug("Leaving Siop.ownerOf(). Not a subject.");
      return '';
    }
    const owner = credentials.selfIssuedSubjectOwner(function (value: string) {
      const one = self.parseValue(value);
      return !!one && one.subject === wanted;
    });
    log.debug("Leaving Siop.ownerOf(). " + (owner || 'nobody'));
    return owner;
  }

  // Enrols a subject on a person. Returns { ok, enrolled } or { ok: false,
  // error }. The caller decides who may: the portal only after a SIOPv2
  // round trip proved the key, the console and the API for Admin Write.
  enrol(username: unknown, subject: unknown, label: unknown,
        by: unknown): Json {
    const { log, credentials } = this.deps;
    log.debug("Entering Siop.enrol(). user=" + username);
    const name = String(username || '').trim();
    const wanted = this.normalise(subject);
    if (!wanted) {
      log.debug("Leaving Siop.enrol(). Not a subject.");
      return { ok: false, error: 'not a self-issued subject: give a ' +
               'did:jwk, did:key or did:web, an RFC 9278 JWK thumbprint URI, ' +
               'a base64url SHA-256 JWK thumbprint, or a public JWK.' };
    }
    const held = this.list(name);
    if (!held) {
      log.debug("Leaving Siop.enrol(). No entry.");
      return { ok: false, error: 'there is no directory entry for "' + name +
                                 '" in this realm.' };
    }
    const owner = this.ownerOf(wanted);
    if (owner && owner.toLowerCase() !== name.toLowerCase()) {
      log.debug("Leaving Siop.enrol(). Somebody else's.");
      return { ok: false, error: 'that subject is already enrolled for ' +
               'another person in this realm; one key signs in one person.' };
    }
    if (owner) {
      log.debug("Leaving Siop.enrol(). Already theirs.");
      return { ok: false, error: 'that subject is already enrolled for ' +
                                 name + '.' };
    }
    if (held.length >= MAX_SUBJECTS) {
      log.debug("Leaving Siop.enrol(). Full.");
      return { ok: false, error: name + ' already has ' + MAX_SUBJECTS +
               ' self-issued subjects enrolled; remove one first.' };
    }
    const record = { subject: wanted,
                     label: String(label || '').trim().slice(0, 64),
                     enrolledAt: new Date().toISOString(),
                     by: String(by || '') };
    const written = credentials.writeSelfIssuedSubjects(name,
      held.concat([record]).map(function (one) {
        return JSON.stringify(one);
      }));
    if (written) {
      this.signalChange(name, 'create', record, by);
    }
    log.debug("Leaving Siop.enrol(). " + written);
    return written ? { ok: true, enrolled: record } :
      { ok: false, error: 'the directory did not store it.' };
  }

  // `by` is who removed it, as `enrol()` takes it: the person's own name
  // from the portal, an administrator's from the console and the API.
  remove(username: unknown, subject: unknown, by?: unknown): Json {
    const { log, credentials } = this.deps;
    log.debug("Entering Siop.remove(). user=" + username);
    const name = String(username || '').trim();
    const wanted = this.normalise(subject);
    const held = this.list(name) || [];
    const kept = held.filter(function (one) {
      return one.subject !== wanted;
    });
    if (!wanted || kept.length === held.length) {
      log.debug("Leaving Siop.remove(). Not enrolled.");
      return { ok: false, error: 'that subject is not enrolled for "' + name +
                                 '".' };
    }
    const written = credentials.writeSelfIssuedSubjects(name,
      kept.map(function (one) {
        return JSON.stringify(one);
      }));
    if (written) {
      const gone = held.filter(function (one) {
        return one.subject === wanted;
      })[0];
      this.signalChange(name, 'delete', gone, by);
    }
    log.debug("Leaving Siop.remove(). " + written);
    return written ? { ok: true, removed: wanted } :
      { ok: false, error: 'the directory did not store the change.' };
  }

  // CAEP `credential-change` FOR A SELF-ISSUED SUBJECT (#236, 2026-09-26).
  // `enrol()` and `remove()` are the only writers of the enrolment — the
  // wallet round trip, the portal, the console and `/admin-api` all come
  // here — so the event is sent here (the #145 rule). The type is this
  // service's own URN: the subject is a KEY the person proved, and CAEP
  // 1.0 section 3.3.1's `verifiable-credential` would say it is a
  // credential somebody issued (`ssf/account_signals.ts`). Required
  // LAZILY, and never allowed to undo a write already made.
  private signalChange(name: string, change: string, record: Json,
                       by: unknown): void {
    const { log } = this.deps;
    log.debug("Entering Siop.signalChange(). " + change);
    const actor = String(by || '');
    const byUser = actor.toLowerCase() === name.toLowerCase() ||
                   /^self\b/.test(actor);
    const label = record ? String(record.label || record.subject || '') : '';
    try {
      const signals = require('../ssf/account_signals');
      signals.credentialChanged({ username: name,
        credentialType: signals.SELF_ISSUED_KEY_CREDENTIAL_TYPE,
        changeType: change, initiatingEntity: byUser ? 'user' : 'admin',
        friendlyName: label, via: 'siop',
        reasonAdmin: (byUser ? name : 'An administrator') + ' ' +
          (change === 'create' ? 'enrolled' : 'removed') + ' a self-issued ' +
          'subject for ' + name + '.',
        reasonUser: 'A self-issued (wallet) key was ' +
          (change === 'create' ? 'enrolled on' : 'removed from') +
          ' your account.' });
    } catch (e) {
      log.debug("Caught in Siop.signalChange(): " + ((e && e.message) || e));
      // No Shared Signals facade in this process; the write stands.
    }
    log.debug("Leaving Siop.signalChange().");
  }

  // -------------------------------------------------------------------------
  // WHAT A REQUEST CARRIES (section 8): the RP metadata members a
  // self-issued request adds to `client_metadata`.
  // -------------------------------------------------------------------------
  clientMetadata(): Json {
    const { log } = this.deps;
    log.debug("Entering Siop.clientMetadata().");
    log.debug("Leaving Siop.clientMetadata().");
    return {
      subject_syntax_types_supported: SUBJECT_SYNTAX_TYPES.slice(0),
      id_token_signing_alg_values_supported: ID_TOKEN_ALGS.slice(0)
    };
  }

  // -------------------------------------------------------------------------
  // RESOLVING THE SUBJECT'S KEY
  // -------------------------------------------------------------------------

  // A did:web's document URL (DID Web Method section 3.2).
  static didWebUrl(did: string): string {
    helpers.log.debug("Entering Siop.didWebUrl().");
    const parts = did.slice('did:web:'.length).split(':')
      .map(decodeURIComponent);
    const host = parts.shift();
    helpers.log.debug("Leaving Siop.didWebUrl().");
    return 'https://' + host + (parts.length
      ? '/' + parts.join('/') + '/did.json' : '/.well-known/did.json');
  }

  // The key a DID names for `kid`, which must be one of its AUTHENTICATION
  // methods (SIOPv2 section 11.1). Throws with the reason.
  private async didKey(did: string, kid: string): Promise<Json> {
    const { log, vcDataIntegrity, fetchDocument } = this.deps;
    log.debug("Entering Siop.didKey(). " + did.slice(0, 12));
    const absolute = kid.charAt(0) === '#' ? did + kid : kid;
    if (absolute.split('#')[0] !== did) {
      log.debug("Leaving Siop.didKey(). The kid is another DID's.");
      throw new Error('the kid "' + kid + '" is not a verification method ' +
                      'of ' + did + '.');
    }
    if (!/^did:web:/.test(did)) {
      const resolved = vcDataIntegrity.resolveVerificationMethod(absolute);
      if (resolved.controller !== did) {
        log.debug("Leaving Siop.didKey(). Another controller.");
        throw new Error('the kid resolves to a key controlled by ' +
                        resolved.controller + ', not ' + did + '.');
      }
      log.debug("Leaving Siop.didKey(). Resolved from the identifier.");
      return resolved.jwk;
    }
    if (!this.ownerOf(did)) {
      log.debug("Leaving Siop.didKey(). An unenrolled did:web.");
      throw new Error(did + ' is not enrolled for anybody in this realm, ' +
                      'and a did:web is fetched only when it is.');
    }
    const doc = await fetchDocument(Siop.didWebUrl(did));
    if (!doc || doc.id !== did) {
      log.debug("Leaving Siop.didKey(). The document names another DID.");
      throw new Error('the did:web document fetched for ' + did + ' names ' +
                      'id "' + (doc && doc.id) + '".');
    }
    const full = function (id: unknown): string {
      const text = typeof id === 'string' ? id : '';
      return text.charAt(0) === '#' ? did + text : text;
    };
    const authenticates = (Array.isArray(doc.authentication)
      ? doc.authentication : []).some(function (one: Json) {
        return full(typeof one === 'string' ? one : one && one.id) ===
               absolute;
      });
    if (!authenticates) {
      log.debug("Leaving Siop.didKey(). Not an authentication method.");
      throw new Error(absolute + ' is not in the DID document\'s ' +
                      'authentication relationship.');
    }
    const methods = (Array.isArray(doc.verificationMethod)
      ? doc.verificationMethod : []).concat(
        (doc.authentication || []).filter(function (one: Json) {
          return one && typeof one === 'object';
        }));
    const method = methods.filter(function (one: Json) {
      return one && full(one.id) === absolute;
    })[0];
    if (!method || !method.publicKeyJwk) {
      log.debug("Leaving Siop.didKey(). No publicKeyJwk.");
      throw new Error(absolute + ' has no publicKeyJwk in the DID ' +
                      'document.');
    }
    log.debug("Leaving Siop.didKey(). Resolved by fetching.");
    return vcDataIntegrity.publicJwkOf(method.publicKeyJwk);
  }

  // -------------------------------------------------------------------------
  // THE SELF-ISSUED ID TOKEN (section 11.1). `expect` is { clientId, nonce }.
  // Returns { ok, checks, subject, jwk, claims }; never throws.
  // -------------------------------------------------------------------------
  async verifyIdToken(token: unknown, expect: Json): Promise<Json> {
    const { log, stsCrypto, vcDataIntegrity, config, nowSec } = this.deps;
    log.debug("Entering Siop.verifyIdToken().");
    const checks: Json[] = [];
    const check = function (name: string, ok: boolean, detail: string) {
      checks.push({ name: name, ok: !!ok, detail: detail });
      return !!ok;
    };
    const out: Json = { ok: false, checks: checks, subject: '', jwk: null,
                        claims: null };
    const text = typeof token === 'string' ? token.trim() : '';
    let header: Json = null;
    let claims: Json = null;
    try {
      const parts = text.split('.');
      header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
      claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    } catch (e) {
      log.debug("Caught in Siop.verifyIdToken(): " + ((e && e.message) || e));
    }
    if (!check('id_token', !!(header && claims && text.split('.').length ===
                              3), 'a compact JWS with a JSON header and ' +
               'payload')) {
      log.debug("Leaving Siop.verifyIdToken(). Unreadable.");
      return out;
    }
    const sub = typeof claims.sub === 'string' ? claims.sub : '';
    if (!check('iss equals sub', !!sub && claims.iss === sub,
               'iss "' + claims.iss + '", sub "' + sub + '" (a self-issued ' +
               'ID Token names itself)')) {
      log.debug("Leaving Siop.verifyIdToken(). iss is not sub.");
      return out;
    }
    let jwk: Json = null;
    let subject = '';
    try {
      if (/^did:/.test(sub)) {
        subject = this.normalise(sub);
        if (!subject || subject !== sub) {
          throw new Error('"' + sub + '" is not a did:jwk, did:key or ' +
                          'did:web this Verifier resolves.');
        }
        jwk = await this.didKey(sub, String(header.kid || ''));
      } else {
        const subJwk = claims.sub_jwk;
        if (!subJwk || typeof subJwk !== 'object' || subJwk.d !== undefined) {
          throw new Error('a JWK Thumbprint subject carries its public key ' +
                          'in sub_jwk, and this token carries ' +
                          (subJwk && subJwk.d !== undefined
                            ? 'a PRIVATE key there' : 'none') + '.');
        }
        jwk = vcDataIntegrity.publicJwkOf(subJwk);
        const thumbprint = stsCrypto.jwkThumbprint(jwk);
        if (sub !== thumbprint && sub !== THUMBPRINT_URI_PREFIX + thumbprint) {
          throw new Error('sub "' + sub + '" is not the SHA-256 JWK ' +
                          'thumbprint of sub_jwk (' + thumbprint + ').');
        }
        subject = THUMBPRINT_URI_PREFIX + thumbprint;
      }
    } catch (e) {
      check('subject key', false, (e && e.message) || String(e));
      log.debug("Leaving Siop.verifyIdToken(). No key.");
      return out;
    }
    check('subject key', true, subject);
    try {
      await stsCrypto.verifyCompactJwsAsync(text, jwk,
                                            { algorithms: ID_TOKEN_ALGS });
      check('signature', true, header.alg + ', by the subject\'s own key');
    } catch (e) {
      check('signature', false, (e && e.message) || String(e));
      log.debug("Leaving Siop.verifyIdToken(). Signature.");
      return out;
    }
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    const now = nowSec();
    const maxAge = Number(config.value('oid4vp.siopIdTokenMaxAgeS'));
    const exp = Number(claims.exp);
    const iat = Number(claims.iat);
    const allOk = [
      check('aud', aud.indexOf(expect.clientId) >= 0,
            'must name this Verifier, "' + expect.clientId + '"; it names ' +
            JSON.stringify(claims.aud)),
      check('nonce', typeof claims.nonce === 'string' &&
            stsCrypto.constantTimeEquals(claims.nonce, String(expect.nonce)),
            'must be this request\'s nonce'),
      check('exp', isFinite(exp) && exp + SKEW_S > now,
            'expires ' + claims.exp + ', now ' + now),
      check('iat', isFinite(iat) && iat <= now + SKEW_S &&
            now - iat <= maxAge,
            'issued ' + claims.iat + ', now ' + now + ', at most ' + maxAge +
            ' s old (oid4vp.siopIdTokenMaxAgeS)')
    ].every(Boolean);
    out.ok = allOk;
    out.subject = subject;
    out.jwk = jwk;
    out.claims = claims;
    log.debug("Leaving Siop.verifyIdToken(). ok=" + allOk);
    return out;
  }

  // -------------------------------------------------------------------------
  // A COMBINED RESPONSE (`vp_token id_token`): the ID Token's subject must be
  // the holder the presentation's key binding proved. Compared as RFC 7638
  // thumbprints, which is the one spelling both sides have.
  // -------------------------------------------------------------------------
  sameHolder(idTokenJwk: Json, holderJwk: Json): boolean {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering Siop.sameHolder().");
    let same = false;
    try {
      same = !!idTokenJwk && !!holderJwk &&
        stsCrypto.jwkThumbprint(idTokenJwk) ===
        stsCrypto.jwkThumbprint(holderJwk);
    } catch (e) {
      log.debug("Caught in Siop.sameHolder(): " + ((e && e.message) || e));
      same = false;
    }
    log.debug("Leaving Siop.sameHolder(). " + same);
    return same;
  }

  // -------------------------------------------------------------------------
  // WHOM A VERIFIED SELF-ISSUED ID TOKEN SIGNS IN: the person who enrolled
  // its subject, in both modes, and nobody otherwise. The shape of
  // `vc_verifier.ts`'s `signInOutcome()`.
  // -------------------------------------------------------------------------
  signInOutcome(verified: Json): Json {
    const { log } = this.deps;
    log.debug("Entering Siop.signInOutcome().");
    const refuse = function (code: string, reason: string): Json {
      log.debug("Leaving Siop.signInOutcome(). " + code);
      return { ok: false, errorCode: code, reason: reason, username: '',
               subject: '' };
    };
    if (!verified || !verified.ok) {
      return refuse('STS-VC-0090', 'The self-issued ID Token did not ' +
                    'verify, so it signs nobody in. The checks above say ' +
                    'which rule it broke.');
    }
    const username = this.ownerOf(verified.subject);
    if (!username) {
      return refuse('STS-VC-0091', 'The self-issued ID Token verified, and ' +
                    'its subject ' + verified.subject + ' is not enrolled ' +
                    'for anybody here. A self-issued key signs in only the ' +
                    'person who enrolled it — sign in another way and enrol ' +
                    'it on your portal\'s Self-issued IDs page.');
    }
    log.debug("Leaving Siop.signInOutcome(). " + username + ".");
    return { ok: true, errorCode: '', reason: '', username: username,
             subject: verified.subject, amr: ['swk'], acr: '1',
             format: 'siopv2', holderKey: (verified.jwk && verified.jwk.kty) ||
             '' };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `common/instance_slot.ts`. The exports below are FACADES for callers that
// reach this module through `require()`.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<Siop>(
  'oid4vc/siop',
  () => new Siop(Siop.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading a module always did.
slot.buildNowUnlessDeferred();

export = {
  Siop: Siop,
  installInstance: (instance: Siop): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  SUBJECT_SYNTAX_TYPES: SUBJECT_SYNTAX_TYPES,
  ID_TOKEN_ALGS: ID_TOKEN_ALGS,
  MAX_SUBJECTS: MAX_SUBJECTS,
  didWebUrl: Siop.didWebUrl,
  normalise: slot.forward('normalise'),
  list: slot.forward('list'),
  ownerOf: slot.forward('ownerOf'),
  enrol: slot.forward('enrol'),
  remove: slot.forward('remove'),
  clientMetadata: slot.forward('clientMetadata'),
  verifyIdToken: slot.forward('verifyIdToken'),
  sameHolder: slot.forward('sameHolder'),
  signInOutcome: slot.forward('signInOutcome')
};
