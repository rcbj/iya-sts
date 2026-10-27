// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
//   * **A did:web IS FETCHED ONLY WHEN IT IS ENROLLED — OR BEING ENROLLED.**
//     `did:jwk` and `did:key` resolve from the identifier
//     (`vc_data_integrity.ts`); a `did:web` resolves by fetching a document
//     from the host it names, which is the presenter's kind of URL, so it is
//     looked up among enrolled subjects FIRST and fetched only if a person or
//     an administrator of this realm put it there — through
//     `federation_http.fetchPublished()`, which brings the outbound kill
//     switch, https, the internal-address refusal in product mode and no
//     redirect. Since #693 two more callers may fetch one that is not yet
//     enrolled: a person's OWN ENROLMENT TRANSACTION (`expect.enrolment`),
//     once per transaction and only after every check of the token that
//     needs no key has passed, and an administrator's by-value enrolment
//     (`enrolByValue()`). `federation/CLAUDE.md`'s list of URLs this service
//     dials carries both rows (the twelfth and the nineteenth).
//   * **A did:web's KEY IS PINNED (#693).** Whoever controls the host later
//     holds the document, so the enrolment records the RFC 7638 thumbprint of
//     the key the proof was signed with (by value: of every `authentication`
//     key the document named then) in `pinnedKeys`, and a later token whose
//     key the pin does not name is refused (STS-VC-0126) and audited — a
//     changed document needs a fresh proof, which the portal's Enrol a wallet
//     gives (proving an enrolled subject again re-pins it). An enrolment from
//     before #693 carries no pin: development pins on first use, product
//     refuses (STS-VC-0127) — `mode.pinsSelfIssuedKeysOnFirstUse()`.
//     `did:jwk`, `did:key` and a thumbprint ARE their key, so nothing is
//     pinned for them.
//   * **PROVENANCE (#693).** Every enrolment says how it was made: `proof:
//     'wallet'` (the person proved the key) or `'admin'` (an administrator
//     enrolled it by value, unproven). A value from before #693 is read as
//     `wallet` when its `by` is the self path's (`self (SIOPv2)`) and
//     `admin` otherwise. `provenSubjectsOf()` is what releases or binds a
//     subject (#693's phase 2) asks; a sign-in reads neither.
//   * **THE PREFERRED DID (#693, phase 2).** A person may mark ONE proved
//     DID as preferred (`preferred: true` on its value; `setPreferred()`),
//     from the portal or an administrator's console and `/admin-api`. A
//     value enrolled by value is never preferred, whatever it says, and a
//     thumbprint is not a DID. `preferredSubjectOf()` is what the `did`
//     claim releases (`oauth-oidc/did_claim.ts`); removing the subject
//     removes the mark with it, and proving it again keeps it.
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
import mode = require('../common/mode');
import vcDataIntegrity = require('./vc_data_integrity');

// A loose JSON-shaped value: a token's claims, a DID document.
type Json = any;

// SIOPv2 section 8's `subject_syntax_types_supported`: the JWK Thumbprint
// syntax and the three DID methods this Verifier resolves.
/**
 * SIOPv2 section 8's `subject_syntax_types_supported`: the JWK Thumbprint
 * syntax, `did:jwk`, `did:key` and `did:web`.
 */
const SUBJECT_SYNTAX_TYPES = Object.freeze([
  'urn:ietf:params:oauth:jwk-thumbprint', 'did:jwk', 'did:key', 'did:web']);

const THUMBPRINT_URI_PREFIX = 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:';

// A self-issued ID Token is signed with an asymmetric key: a MAC would need a
// secret this Verifier shares with nobody, and `none` signs nothing.
/**
 * The algorithms a self-issued ID Token may be signed with: asymmetric only.
 */
const ID_TOKEN_ALGS = stsCrypto.JWS_ASYMMETRIC_ALGS.slice();

// How many subjects one person may enrol. One entry value each.
/**
 * How many self-issued subjects one person may enrol.
 */
const MAX_SUBJECTS = 10;

// Clock skew allowed on `exp` and on an `iat` in the future.
const SKEW_S = 60;

// HOW A SUBJECT WAS ENROLLED (#693): proved by the person's wallet, or given
// by an administrator's value.
/**
 * The provenance of a subject the person proved with their wallet.
 */
const PROOF_WALLET = 'wallet';
/**
 * The provenance of a subject an administrator enrolled by value, unproven.
 */
const PROOF_ADMIN = 'admin';

// The `by` the wallet enrolment writes, which is how a value from before
// #693 (no `proof` member) is told to have been proved.
const SELF_BY = /^self\b/;

// WHERE AN ENROLLED KEY CAME FROM (2026-10-20, rcbj on /portal/self-issued):
// `location` on the enrolment value, `{ kind, value }`. `web` is the web
// wallet whose link the person followed (`value` its configured address);
// `app` a wallet app answering the scheme link (`value` the name it gave in
// its User-Agent, or ''); `dc_api` the browser's Digital Credentials API
// (`value` the origin, or ''); `admin` an administrator's enrolment by value.
// A value from before it carries none, and the page says "not recorded".
const LOCATION_KINDS = ['web', 'app', 'dc_api', 'admin'];

// What a wallet's User-Agent may contribute to a page: RFC 9110 section
// 10.1.5's product tokens (`name` or `name/version`), never its comments,
// printable ASCII only, at most this many characters. It is the wallet's
// own say-so and is SHOWN, never trusted for anything.
const REPORTED_NAME_MAX = 80;
const PRODUCT_TOKEN =
  /^[A-Za-z0-9!#$%&'*+.^_`|~-]+(\/[A-Za-z0-9!#$%&'*+.^_`|~-]+)?$/;

interface SiopDeps {
  log: typeof helpers.log;
  config: typeof config;
  credentials: typeof credentials;
  stsCrypto: typeof stsCrypto;
  errorCodes: typeof errorCodes;
  mode: typeof mode;
  vcDataIntegrity: typeof vcDataIntegrity;
  fetchDocument: (url: string) => Promise<Json>;
  audit: (event: Json) => void;
  nowSec: () => number;
}

// What `verifyIdToken()` is told about the transaction the token answers.
// `enrolment` is set only for a person's own enrolment transaction
// (`vc_signin.ts`'s `tx.signIn.enrol`): `username` is whose it is, and
// `mayDial()` answers true once — the one did:web document that transaction
// may fetch — and marks the transaction as having fetched it.
interface IdTokenExpectation {
  clientId: string;
  nonce: string;
  enrolment?: { username: string; mayDial: () => boolean } | null;
}

// An Error carrying the code its refusal is recorded under.
const coded = function (code: string, message: string): Error {
  helpers.log.debug("Entering coded(). " + code);
  const e: Json = new Error(message);
  e.code = code;
  helpers.log.debug("Leaving coded().");
  return e;
};

/**
 * Self-Issued OpenID Provider v2, the relying party's half (#129): the
 * enrolment of a self-issued subject on a person's entry, the check of a
 * self-issued ID Token (section 11.1), and whom it signs in.
 *
 * An unenrolled subject signs nobody in, in either mode.
 */
class Siop {
  /**
   * The subject syntax types this Verifier supports (SIOPv2 section 8).
   */
  static readonly SUBJECT_SYNTAX_TYPES = SUBJECT_SYNTAX_TYPES;
  /**
   * The algorithms a self-issued ID Token may be signed with.
   */
  static readonly ID_TOKEN_ALGS = ID_TOKEN_ALGS;
  /**
   * How many self-issued subjects one person may enrol.
   */
  static readonly MAX_SUBJECTS = MAX_SUBJECTS;
  /**
   * The provenance of a subject the person proved with their wallet.
   */
  static readonly PROOF_WALLET = PROOF_WALLET;
  /**
   * The provenance of a subject an administrator enrolled by value.
   */
  static readonly PROOF_ADMIN = PROOF_ADMIN;
  /**
   * The kinds of place an enrolled key may have come from.
   */
  static readonly LOCATION_KINDS = LOCATION_KINDS;

  // THE NAME A WALLET GAVE ITSELF, made safe to show (2026-10-20): every
  // character outside printable ASCII becomes a space (so nothing is joined
  // that was apart), the parenthesised comments go, and what is left keeps
  // only its product tokens, whole, up to REPORTED_NAME_MAX characters. ''
  // where nothing usable arrived.
  /**
   * Returns the product tokens of a User-Agent, sanitised for display:
   * printable ASCII, no comments, at most 80 characters, or ''.
   *
   * @param value - the User-Agent as it arrived
   * @returns the name, or ''
   */
  static reportedName(value: unknown): string {
    helpers.log.debug("Entering Siop.reportedName().");
    let text = String(value === undefined || value === null ? '' : value)
      .slice(0, 4096).replace(/[^\x20-\x7e]/g, ' ');
    let was = '';
    while (was !== text) {
      was = text;
      text = text.replace(/\([^()]*\)/g, ' ');
    }
    let out = '';
    const tokens = text.split(/\s+/).filter(function (one) {
      return PRODUCT_TOKEN.test(one);
    });
    for (const one of tokens) {
      const next = out ? out + ' ' + one : one;
      if (next.length > REPORTED_NAME_MAX) {
        break;
      }
      out = next;
    }
    helpers.log.debug("Leaving Siop.reportedName(). " + out.length);
    return out;
  }

  // An enrolment's `location`, as `enrol()` stores it, or null: a kind this
  // service knows, and a value of the shape that kind holds — a web
  // wallet's http(s) address, an app's reported name (sanitised again, so a
  // caller cannot store what the fetch would not have), a browser origin,
  // or nothing for an administrator.
  /**
   * Returns a checked enrolment location, `{ kind, value }`, or null.
   *
   * @param value - the location a caller gave
   * @returns the location to store, or null
   */
  static locationOf(value: unknown): Json {
    helpers.log.debug("Entering Siop.locationOf().");
    const given: Json = value && typeof value === 'object' ? value : null;
    const kind = given ? String(given.kind || '') : '';
    if (LOCATION_KINDS.indexOf(kind) < 0) {
      helpers.log.debug("Leaving Siop.locationOf(). None.");
      return null;
    }
    const raw = String(given.value === undefined || given.value === null
      ? '' : given.value);
    let out = '';
    if (kind === 'web') {
      out = /^https?:\/\/[\x21-\x7e]+$/.test(raw) ? raw.slice(0, 2048) : '';
    } else if (kind === 'app') {
      out = Siop.reportedName(raw);
    } else if (kind === 'dc_api') {
      out = /^https?:\/\/[A-Za-z0-9.:\[\]-]+$/.test(raw) ? raw.slice(0, 256)
                                                         : '';
    }
    helpers.log.debug("Leaving Siop.locationOf(). " + kind);
    return { kind: kind, value: out };
  }

  /**
   * Builds the relying party half from the modules it reads.
   *
   * @param deps - the modules the composition root passes
   */
  constructor(private readonly deps: SiopDeps) {
    deps.log.debug("Entering Siop.constructor().");
    deps.log.debug("Leaving Siop.constructor().");
  }

  // What the composition root passes. `federation_http` is reached LAZILY,
  // for the one fetch, as `oauth-oidc/client_jwks.js` reaches it.
  /**
   * Returns the dependencies built from the real modules, with the fetcher
   * reached lazily.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): SiopDeps {
    helpers.log.debug("Entering Siop.defaultDeps().");
    helpers.log.debug("Leaving Siop.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      credentials: credentials,
      stsCrypto: stsCrypto,
      errorCodes: errorCodes,
      mode: mode,
      vcDataIntegrity: vcDataIntegrity,
      // `common/audit.js` LAZILY, as `signalChange()` reaches the signals:
      // it loads the persistence layer, which a library this low in the
      // require order has no business pulling forward. Recording never
      // fails the act it records.
      audit: function (event: Json): void {
        helpers.log.debug("Entering audit().");
        try {
          require('../common/audit').record(event);
        } catch (e) {
          helpers.log.debug("Caught in audit(): " + ((e && e.message) || e));
        }
        helpers.log.debug("Leaving audit().");
      },
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
  /**
   * Normalises a subject to the spelling this service keeps: a DID without a
   * fragment, or an RFC 9278 thumbprint URI. A bare thumbprint and a public JWK
   * as JSON are accepted too.
   *
   * @param raw - the subject as given
   * @returns the normalised subject, or '' for anything else
   */
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

  // HOW A VALUE WAS ENROLLED (#693): its `proof` where it says, and for a
  // value from before #693, which says nothing, the self path's `by` read as
  // proved and anything else as an administrator's — the conservative
  // reading, since a value nobody can show was proved must not be released
  // as though it had been.
  /**
   * Returns how an enrolled value was enrolled: `wallet` (proved) or `admin`
   * (by value, unproven).
   *
   * @param one - an enrolled value, as `list()` returns it
   * @returns `wallet` or `admin`
   */
  static provenanceOf(one: Json): string {
    helpers.log.debug("Entering Siop.provenanceOf().");
    const said = one && (one.proof === PROOF_WALLET ||
                         one.proof === PROOF_ADMIN) ? one.proof : '';
    const out = said || (one && SELF_BY.test(String(one.by || ''))
      ? PROOF_WALLET : PROOF_ADMIN);
    helpers.log.debug("Leaving Siop.provenanceOf(). " + out);
    return out;
  }

  // Every subject a person has enrolled, as { subject, label, enrolledAt,
  // by, proof, provedAt?, pinnedKeys?, location? }, `proof` filled in for a
  // value from before #693. null where the directory holds no entry for
  // them.
  /**
   * Returns every subject a person has enrolled.
   *
   * @param username - the person
   * @returns `{ subject, label, enrolledAt, by, proof, provedAt?,
   *   pinnedKeys?, location? }` rows, or null when the directory holds no
   *   entry for them
   */
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
    }).filter(Boolean).map(function (one: Json) {
      const proof = Siop.provenanceOf(one);
      // PREFERRED (#693) only where it was PROVED: a flag on a value an
      // administrator typed in is read as absent, whoever wrote it.
      return Object.assign({}, one, { proof: proof,
        preferred: proof === PROOF_WALLET && one.preferred === true });
    });
    log.debug("Leaving Siop.list(). " + out.length + ".");
    return out;
  }

  // THE SUBJECTS A PERSON PROVED (#693): what a release or a binding of a
  // subject reads — never one an administrator typed in. [] where they have
  // none or no entry.
  /**
   * Returns the subjects a person enrolled by proving them with a wallet,
   * never one an administrator enrolled by value.
   *
   * @param username - the person
   * @returns the proved rows, as `list()` returns them; [] for none
   */
  provenSubjectsOf(username: unknown): Json[] {
    const { log } = this.deps;
    log.debug("Entering Siop.provenSubjectsOf(). user=" + username);
    const out = (this.list(username) || []).filter(function (one: Json) {
      return one.proof === PROOF_WALLET;
    });
    log.debug("Leaving Siop.provenSubjectsOf(). " + out.length + ".");
    return out;
  }

  // THE PERSON'S PREFERRED DID (#693, phase 2): the one proved subject they
  // marked, and only while it is a DID — what the `did` claim releases
  // (`oauth-oidc/did_claim.ts`). null where none is marked, or the marked
  // one is a JWK thumbprint, which identifies a key and not a DID.
  /**
   * Returns the person's preferred subject: the one proved DID they marked,
   * or null.
   *
   * @param username - the person
   * @returns the row, as `list()` returns it, or null
   */
  preferredSubjectOf(username: unknown): Json {
    const { log } = this.deps;
    log.debug("Entering Siop.preferredSubjectOf(). user=" + username);
    const one = this.provenSubjectsOf(username).filter(function (row: Json) {
      return row.preferred === true && /^did:/.test(String(row.subject));
    })[0] || null;
    log.debug("Leaving Siop.preferredSubjectOf(). " +
              (one ? one.subject : 'none'));
    return one;
  }

  // MARKS ONE PROVED DID AS THE PERSON'S PREFERRED ONE (#693, phase 2), and
  // clears the mark from every other; '' as the subject clears it from all.
  // Only a subject the person PROVED qualifies (`provenSubjectsOf()`), and
  // only a DID: a thumbprint names a key, and a claim called `did` carrying
  // one would say something false. The caller decides who may: the person
  // from the portal, an administrator for Admin Write. Returns { ok,
  // preferred } (the subject, '' when cleared) or { ok: false, error, code }.
  /**
   * Marks one of a person's proved DIDs as their preferred one, or clears
   * the mark with an empty subject.
   *
   * @param username - the person
   * @param subject - the subject to prefer, or '' to clear
   * @returns `{ ok, preferred, was }`, or `{ ok: false, error, code }`
   */
  setPreferred(username: unknown, subject: unknown): Json {
    const { log, credentials } = this.deps;
    log.debug("Entering Siop.setPreferred(). user=" + username);
    const name = String(username || '').trim();
    const clearing = String(subject == null ? '' : subject).trim() === '';
    const wanted = clearing ? '' : this.normalise(subject);
    const held = this.list(name);
    if (!held) {
      log.debug("Leaving Siop.setPreferred(). No entry.");
      return { ok: false, code: 'not-found',
               error: 'there is no directory entry for "' + name +
                      '" in this realm.' };
    }
    const target = held.filter(function (one: Json) {
      return one.subject === wanted;
    })[0];
    if (!clearing && !target) {
      log.debug("Leaving Siop.setPreferred(). Not enrolled.");
      return { ok: false, code: 'not-enrolled',
               error: 'that subject is not enrolled for "' + name + '".' };
    }
    if (target && target.proof !== PROOF_WALLET) {
      log.debug("Leaving Siop.setPreferred(). Not proved.");
      return { ok: false, code: 'not-proved',
               error: 'only a subject the person proved with their wallet ' +
                      'may be preferred; ' + wanted + ' was enrolled by ' +
                      'value. The person proves it on /portal/self-issued.' };
    }
    if (target && !/^did:/.test(wanted)) {
      log.debug("Leaving Siop.setPreferred(). Not a DID.");
      return { ok: false, code: 'not-a-did',
               error: 'only a DID may be preferred; ' + wanted + ' is a JWK ' +
                      'thumbprint, which names a key and not a DID.' };
    }
    const was = (held.filter(function (one: Json) {
      return one.preferred === true;
    })[0] || { subject: '' }).subject;
    const next = held.map(function (one: Json) {
      const copy = Object.assign({}, one);
      delete copy.preferred;
      if (!clearing && one.subject === wanted) {
        copy.preferred = true;
      }
      return copy;
    });
    const written = was === wanted ? true :
      credentials.writeSelfIssuedSubjects(name, next.map(function (one) {
        return JSON.stringify(one);
      }));
    log.debug("Leaving Siop.setPreferred(). " + written);
    return written ? { ok: true, preferred: wanted, was: was } :
      { ok: false, code: 'not-stored',
        error: 'the directory did not store the change.' };
  }

  // Whose subject this is in the current realm: a username, or ''.
  /**
   * Returns whose subject this is in the current realm.
   *
   * @param subject - the subject
   * @returns the username, or ''
   */
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

  // Why `wanted` may not be enrolled for `name`, or '' — the checks every
  // enrolment makes before anything is fetched or written. `again` is true
  // when it is already theirs and this is a PROOF, which re-proves it (and
  // re-pins a did:web) rather than refusing (#693).
  private enrolProblem(name: string, wanted: string, proof: string): Json {
    const { log } = this.deps;
    log.debug("Entering Siop.enrolProblem().");
    if (!wanted) {
      log.debug("Leaving Siop.enrolProblem(). Not a subject.");
      return { error: 'not a self-issued subject: give a did:jwk, did:key ' +
               'or did:web, an RFC 9278 JWK thumbprint URI, a base64url ' +
               'SHA-256 JWK thumbprint, or a public JWK.' };
    }
    const held = this.list(name);
    if (!held) {
      log.debug("Leaving Siop.enrolProblem(). No entry.");
      return { error: 'there is no directory entry for "' + name +
                      '" in this realm.' };
    }
    const owner = this.ownerOf(wanted);
    if (owner && owner.toLowerCase() !== name.toLowerCase()) {
      log.debug("Leaving Siop.enrolProblem(). Somebody else's.");
      return { error: 'that subject is already enrolled for another ' +
                      'person in this realm; one key signs in one person.' };
    }
    if (owner && proof !== PROOF_WALLET) {
      log.debug("Leaving Siop.enrolProblem(). Already theirs.");
      return { error: 'that subject is already enrolled for ' + name + '.' };
    }
    if (!owner && held.length >= MAX_SUBJECTS) {
      log.debug("Leaving Siop.enrolProblem(). Full.");
      return { error: name + ' already has ' + MAX_SUBJECTS +
               ' self-issued subjects enrolled; remove one first.' };
    }
    log.debug("Leaving Siop.enrolProblem(). None.");
    return { error: '', held: held, again: !!owner };
  }

  // Enrols a subject on a person. Returns { ok, enrolled } or { ok: false,
  // error }. The caller decides who may: the portal only after a SIOPv2
  // round trip proved the key (`proof: 'wallet'`, with the key's thumbprint
  // in `pinnedKeys` for a did:web), the console and the API for Admin Write
  // (`proof: 'admin'`, the default; a did:web goes through
  // `enrolByValue()`, which fetches the keys to pin). A did:web with no key
  // to pin is refused: since #693 none is written without one.
  /**
   * Enrols a subject on a person. The caller decides who may: the portal after
   * a SIOPv2 round trip proved the key, the console and the API for Admin
   * Write.
   *
   * @param username - the person
   * @param subject - the subject
   * @param label - a label for it
   * @param by - who enrolled it
   * @param options - `proof` (`wallet` or `admin`, the default), for a
   *   did:web `pinnedKeys`: the RFC 7638 thumbprints its sign-ins may use,
   *   and for a proof `location`: where the key came from
   * @returns `{ ok, enrolled, again }`, or `{ ok: false, error }`
   */
  enrol(username: unknown, subject: unknown, label: unknown,
        by: unknown, options?: { proof?: string;
                                 pinnedKeys?: string[];
                                 location?: Json;
                                 keyAlg?: string }): Json {
    const { log, credentials } = this.deps;
    log.debug("Entering Siop.enrol(). user=" + username);
    const opts = options || {};
    const proof = opts.proof === PROOF_WALLET ? PROOF_WALLET : PROOF_ADMIN;
    const name = String(username || '').trim();
    const wanted = this.normalise(subject);
    const problem = this.enrolProblem(name, wanted, proof);
    if (problem.error) {
      log.debug("Leaving Siop.enrol(). " + problem.error);
      return { ok: false, error: problem.error };
    }
    const web = /^did:web:/.test(wanted);
    const pins = (Array.isArray(opts.pinnedKeys) ? opts.pinnedKeys : [])
      .filter(function (one) {
        return typeof one === 'string' && /^[A-Za-z0-9_-]{43}$/.test(one);
      });
    if (web && !pins.length) {
      log.debug("Leaving Siop.enrol(). A did:web with no key to pin.");
      return { ok: false, error: 'a did:web is enrolled with the key it ' +
               'signs in with pinned: by proving it with a wallet, or by ' +
               'value from a DID document that could be fetched.' };
    }
    const held: Json[] = problem.held;
    const before = held.filter(function (one) {
      return one.subject === wanted;
    })[0];
    const record: Json = {
      subject: wanted,
      label: String(label || (before && before.label) || '').trim()
        .slice(0, 64),
      enrolledAt: before ? before.enrolledAt : new Date().toISOString(),
      by: String(by || ''),
      proof: proof };
    if (proof === PROOF_WALLET) {
      record.provedAt = new Date().toISOString();
    }
    // THE KEY'S ALGORITHM (#1021), for the reports: a did:jwk and a did:key
    // spell their key, a did:web and a thumbprint do not, so the algorithm
    // the proof was signed with is kept on the value where a proof gave it.
    if (opts.keyAlg) {
      record.keyAlg = String(opts.keyAlg).slice(0, 32);
    }
    // WHERE IT CAME FROM (2026-10-20): what the proof's caller observed,
    // checked; an administrator's value says so. Written afresh on every
    // enrolment, so proving a subject again from another wallet says where
    // it was proved last.
    const location = proof === PROOF_ADMIN ? { kind: 'admin', value: '' }
                                           : Siop.locationOf(opts.location);
    if (location) {
      record.location = location;
    }
    // PROVING A SUBJECT AGAIN KEEPS IT PREFERRED (#693): the mark is the
    // person's choice, and re-pinning a did:web is not a change of mind.
    if (before && before.preferred === true && proof === PROOF_WALLET) {
      record.preferred = true;
    }
    if (web) {
      record.pinnedKeys = pins.filter(function (one, i) {
        return pins.indexOf(one) === i;
      });
    }
    const next = problem.again
      ? held.map(function (one) {
        return one.subject === wanted ? record : one;
      })
      : held.concat([record]);
    const written = credentials.writeSelfIssuedSubjects(name,
      next.map(function (one) {
        return JSON.stringify(one);
      }));
    if (written) {
      this.signalChange(name, problem.again ? 'update' : 'create', record,
                        by);
    }
    log.debug("Leaving Siop.enrol(). " + written);
    return written ? { ok: true, enrolled: record, again: !!problem.again } :
      { ok: false, error: 'the directory did not store it.' };
  }

  // AN ADMINISTRATOR'S ENROLMENT BY VALUE (#693). A did:jwk, did:key or
  // thumbprint is its key and is enrolled as given. A did:web is FETCHED
  // NOW — the administrator named it, under Admin Write, through the same
  // `fetchPublished()` a sign-in uses — and every `authentication` key its
  // document names with a `publicKeyJwk` is pinned; a document that cannot
  // be fetched, names another id or names no such key is REFUSED
  // (STS-ADMIN-0871) rather than enrolled unpinned, because an unpinned
  // did:web is exactly what #693 removed. The checks that need no fetch run
  // first, so a refusal for somebody else's subject or a full person dials
  // nothing. Never rejects.
  /**
   * Enrols a subject by value for an administrator: a did:web's document is
   * fetched and its authentication keys pinned, or the enrolment is refused.
   * Never rejects.
   *
   * @param username - the person
   * @param subject - the subject
   * @param label - a label for it
   * @param by - the administrator
   * @returns `{ ok, enrolled }`, or `{ ok: false, error, code? }`
   */
  async enrolByValue(username: unknown, subject: unknown, label: unknown,
                     by: unknown): Promise<Json> {
    const { log, fetchDocument } = this.deps;
    log.debug("Entering Siop.enrolByValue(). user=" + username);
    const name = String(username || '').trim();
    const wanted = this.normalise(subject);
    if (!/^did:web:/.test(wanted)) {
      log.debug("Leaving Siop.enrolByValue(). Not a did:web.");
      return this.enrol(name, wanted || subject, label, by,
                        { proof: PROOF_ADMIN });
    }
    const problem = this.enrolProblem(name, wanted, PROOF_ADMIN);
    if (problem.error) {
      log.debug("Leaving Siop.enrolByValue(). " + problem.error);
      return { ok: false, error: problem.error };
    }
    let pins: string[] = [];
    try {
      const doc = await fetchDocument(Siop.didWebUrl(wanted));
      pins = this.authenticationKeys(doc, wanted);
    } catch (e) {
      log.debug("Caught in Siop.enrolByValue(): " + ((e && e.message) || e));
      log.debug("Leaving Siop.enrolByValue(). No key to pin.");
      return { ok: false, code: 'STS-ADMIN-0871',
               error: 'the DID document of ' + wanted + ' gave no key to ' +
                      'pin: ' + ((e && e.message) || e) };
    }
    log.debug("Leaving Siop.enrolByValue(). " + pins.length + " key(s).");
    return this.enrol(name, wanted, label, by,
                      { proof: PROOF_ADMIN, pinnedKeys: pins });
  }

  // `by` is who removed it, as `enrol()` takes it: the person's own name
  // from the portal, an administrator's from the console and the API.
  /**
   * Removes an enrolled subject from a person.
   *
   * @param username - the person
   * @param subject - the subject
   * @param by - who removed it
   * @returns `{ ok: true, removed }`, or `{ ok: false, error }`
   */
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

  // CAEP `credential-change` FOR A SELF-ISSUED SUBJECT (#236, 2026-09-26;
  // `update` since #693, for a subject proved again, which re-pins it).
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
          (change === 'create' ? 'enrolled'
            : change === 'update' ? 'proved again' : 'removed') +
          ' a self-issued subject for ' + name + '.',
        reasonUser: 'A self-issued (wallet) key was ' +
          (change === 'create' ? 'enrolled on'
            : change === 'update' ? 'proved again on' : 'removed from') +
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
  /**
   * Returns the relying party metadata members a self-issued request adds to
   * `client_metadata` (section 8).
   *
   * @returns the members
   */
  clientMetadata(): Json {
    const { log } = this.deps;
    log.debug("Entering Siop.clientMetadata().");
    log.debug("Leaving Siop.clientMetadata().");
    return {
      subject_syntax_types_supported: SUBJECT_SYNTAX_TYPES.slice(0),
      // The classical ones alone while `keys.postQuantumSigning` is off
      // (2026-10-23); a post-quantum self-issued ID Token is refused at its
      // verification then too.
      id_token_signing_alg_values_supported:
        helpers.offeredJwsAlgs(ID_TOKEN_ALGS)
    };
  }

  // -------------------------------------------------------------------------
  // RESOLVING THE SUBJECT'S KEY
  // -------------------------------------------------------------------------

  // A did:web's document URL (DID Web Method section 3.2).
  /**
   * Returns a `did:web`'s document URL (DID Web Method section 3.2).
   *
   * @param did - the `did:web`
   * @returns the URL
   */
  static didWebUrl(did: string): string {
    helpers.log.debug("Entering Siop.didWebUrl().");
    const parts = did.slice('did:web:'.length).split(':')
      .map(decodeURIComponent);
    const host = parts.shift();
    helpers.log.debug("Leaving Siop.didWebUrl().");
    return 'https://' + host + (parts.length
      ? '/' + parts.join('/') + '/did.json' : '/.well-known/did.json');
  }

  // A did:web DOCUMENT, read: its id must be the DID, and `full()` makes a
  // relative method id absolute.
  private static fullId(did: string, id: unknown): string {
    helpers.log.debug("Entering Siop.fullId().");
    const text = typeof id === 'string' ? id : '';
    helpers.log.debug("Leaving Siop.fullId().");
    return text.charAt(0) === '#' ? did + text : text;
  }

  // The verification method `absolute` names in a did:web document, which
  // must be in its AUTHENTICATION relationship (SIOPv2 section 11.1), as a
  // public JWK. Throws with the reason.
  private didWebMethodKey(doc: Json, did: string, absolute: string): Json {
    const { log, vcDataIntegrity } = this.deps;
    log.debug("Entering Siop.didWebMethodKey().");
    if (!doc || doc.id !== did) {
      log.debug("Leaving Siop.didWebMethodKey(). Another DID's document.");
      throw new Error('the did:web document fetched for ' + did + ' names ' +
                      'id "' + (doc && doc.id) + '".');
    }
    const authenticates = (Array.isArray(doc.authentication)
      ? doc.authentication : []).some(function (one: Json) {
        return Siop.fullId(did, typeof one === 'string' ? one
                                                        : one && one.id) ===
               absolute;
      });
    if (!authenticates) {
      log.debug("Leaving Siop.didWebMethodKey(). Not an authentication " +
                "method.");
      throw new Error(absolute + ' is not in the DID document\'s ' +
                      'authentication relationship.');
    }
    const methods = (Array.isArray(doc.verificationMethod)
      ? doc.verificationMethod : []).concat(
        (Array.isArray(doc.authentication) ? doc.authentication : [])
          .filter(function (one: Json) {
            return one && typeof one === 'object';
          }));
    const method = methods.filter(function (one: Json) {
      return one && Siop.fullId(did, one.id) === absolute;
    })[0];
    if (!method || !method.publicKeyJwk) {
      log.debug("Leaving Siop.didWebMethodKey(). No publicKeyJwk.");
      throw new Error(absolute + ' has no publicKeyJwk in the DID ' +
                      'document.');
    }
    log.debug("Leaving Siop.didWebMethodKey().");
    return vcDataIntegrity.publicJwkOf(method.publicKeyJwk);
  }

  // EVERY KEY A did:web DOCUMENT AUTHENTICATES WITH, as RFC 7638
  // thumbprints: what an administrator's by-value enrolment pins (#693).
  // Throws when there is none, or the document is another DID's.
  /**
   * Returns the RFC 7638 thumbprints of every authentication method of a
   * did:web document that carries a `publicKeyJwk`.
   *
   * @param doc - the DID document
   * @param did - the did:web it was fetched for
   * @returns the thumbprints; throws when there is none
   */
  authenticationKeys(doc: Json, did: string): string[] {
    const { log, stsCrypto } = this.deps;
    const self = this;
    log.debug("Entering Siop.authenticationKeys().");
    if (!doc || doc.id !== did) {
      log.debug("Leaving Siop.authenticationKeys(). Another DID's document.");
      throw new Error('the did:web document fetched for ' + did + ' names ' +
                      'id "' + (doc && doc.id) + '".');
    }
    const out: string[] = [];
    (Array.isArray(doc.authentication) ? doc.authentication : [])
      .forEach(function (one: Json) {
        const absolute = Siop.fullId(did, typeof one === 'string' ? one
                                                          : one && one.id);
        try {
          const print = stsCrypto.jwkThumbprint(
            self.didWebMethodKey(doc, did, absolute));
          if (out.indexOf(print) < 0) {
            out.push(print);
          }
        } catch (e) {
          log.debug("Caught in Siop.authenticationKeys(): " +
                    ((e && e.message) || e));
          // One method without a usable key is skipped; none at all is the
          // refusal below.
        }
      });
    if (!out.length) {
      log.debug("Leaving Siop.authenticationKeys(). None.");
      throw new Error('the DID document names no authentication method ' +
                      'with a publicKeyJwk.');
    }
    log.debug("Leaving Siop.authenticationKeys(). " + out.length + ".");
    return out;
  }

  // The key a DID names for `kid`, which must be one of its AUTHENTICATION
  // methods (SIOPv2 section 11.1). Throws with the reason — a coded Error
  // where the refusal has a code of its own.
  //
  // A did:web is FETCHED only when it is enrolled, or for a person's own
  // enrolment (`enrolment`, #693) — and in either case only when `claimsOk`:
  // every check of the token that needs no key (aud, nonce, exp, iat; iss
  // and the DID's syntax are checked before this is called) has already
  // passed, so a token for another transaction, a replay or a stale one
  // makes this service dial nothing. An enrolment fetches at most once
  // (`mayDial()`), and a failed fetch there is STS-VC-0128.
  private async didKey(did: string, kid: string, claimsOk: boolean,
                       enrolment: IdTokenExpectation['enrolment']):
      Promise<Json> {
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
    if (!enrolment && !this.ownerOf(did)) {
      log.debug("Leaving Siop.didKey(). An unenrolled did:web.");
      throw new Error(did + ' is not enrolled for anybody in this realm, ' +
                      'and a did:web is fetched only when it is, or for ' +
                      'the enrolment of it.');
    }
    if (!claimsOk) {
      log.debug("Leaving Siop.didKey(). The other checks failed; not " +
                "fetched.");
      throw new Error('the DID document of ' + did + ' was not fetched, ' +
                      'because the ID Token\'s other checks (below) failed ' +
                      'and a did:web is fetched only for a token that ' +
                      'passed them.');
    }
    if (enrolment && !enrolment.mayDial()) {
      log.debug("Leaving Siop.didKey(). The enrolment already fetched one.");
      throw coded('STS-VC-0128', 'this enrolment has already fetched a DID ' +
                  'document, which is all one enrolment may; start it again.');
    }
    let doc: Json = null;
    try {
      doc = await fetchDocument(Siop.didWebUrl(did));
    } catch (e) {
      log.debug("Caught in Siop.didKey(): " + ((e && e.message) || e));
      log.debug("Leaving Siop.didKey(). Not fetched.");
      throw enrolment
        ? coded('STS-VC-0128', 'the DID document of ' + did + ' could not ' +
                'be fetched: ' + ((e && e.message) || e))
        : e;
    }
    const key = this.didWebMethodKey(doc, did, absolute);
    log.debug("Leaving Siop.didKey(). Resolved by fetching.");
    return key;
  }

  // THE PIN (#693): the key that verified a did:web subject's token must be
  // one its enrolment pinned. `{ ok, code, detail }`. An enrolment from
  // before #693 has no pin: `mode.pinsSelfIssuedKeysOnFirstUse()` pins this
  // key now (development), or the token is refused (product). A refusal is
  // AUDITED here, where the reason is known (`siop.key.refused`), and so is
  // a pin made on first use (`siop.key.pinned`).
  private pinCheck(subject: string, jwk: Json): Json {
    const { log, stsCrypto, credentials, mode, audit,
            errorCodes } = this.deps;
    log.debug("Entering Siop.pinCheck().");
    const owner = this.ownerOf(subject);
    const record = owner ? (this.list(owner) || []).filter(function (one) {
      return one.subject === subject;
    })[0] : null;
    if (!record) {
      // Not reached: the document is fetched only for an enrolled did:web
      // outside an enrolment.
      log.debug("Leaving Siop.pinCheck(). Not enrolled.");
      return { ok: false, code: '', detail: subject + ' is not enrolled.' };
    }
    const print = stsCrypto.jwkThumbprint(jwk);
    // `code` is one of the two below: STS-VC-0126 (a key the pin does not
    // name) or STS-VC-0127 (no pin, in product mode).
    const refuse = function (code: string, detail: string): Json {
      log.debug("Entering refuse(). " + code);
      audit({ category: 'authentication', action: 'siop.key.refused',
              errorCode: code, actor: owner, target: owner,
              outcome: 'refused',
              summary: 'a self-issued sign-in for ' + subject + ' was ' +
                       'refused: ' + detail,
              detail: { subject: subject, keyThumbprint: print,
                        pinnedKeys: (record.pinnedKeys || []).join(' ') } });
      log.info(errorCodes.tag(code) + 'siop: ' + detail);
      log.debug("Leaving refuse().");
      return { ok: false, code: code, detail: detail };
    };
    const pins = Array.isArray(record.pinnedKeys) ? record.pinnedKeys : [];
    if (pins.length) {
      const ok = pins.indexOf(print) >= 0;
      log.debug("Leaving Siop.pinCheck(). " + ok);
      return ok ? { ok: true, code: '', detail: print + ', pinned when ' +
                    subject + ' was enrolled' }
        : refuse('STS-VC-0126', 'the DID document of ' + subject + ' now ' +
                 'names a key (' + print + ') its enrolment did not pin, so ' +
                 'it signs nobody in. If the wallet\'s key really changed, ' +
                 'enrol the DID again by proving it on your portal\'s ' +
                 'Self-issued IDs page.');
    }
    if (!mode.pinsSelfIssuedKeysOnFirstUse()) {
      log.debug("Leaving Siop.pinCheck(). Unpinned, refused.");
      return refuse('STS-VC-0127', subject + ' was enrolled before keys ' +
                    'were pinned, and no key is pinned for it, so it signs ' +
                    'nobody in here: enrol it again by proving it on your ' +
                    'portal\'s Self-issued IDs page.');
    }
    // TRUST ON FIRST USE, development only: this key is pinned now. The
    // write replaces the one value; `enrol()` and `remove()` stay the only
    // writers of WHAT is enrolled.
    const written = credentials.writeSelfIssuedSubjects(owner,
      (this.list(owner) || []).map(function (one) {
        return JSON.stringify(one.subject === subject
          ? Object.assign({}, one, { pinnedKeys: [print] }) : one);
      }));
    if (!written) {
      log.error(errorCodes.tag('STS-VC-0129') + 'siop: the key of ' +
                subject + ' could not be pinned on first use; the sign-in ' +
                'stands and the pin is tried again at the next.');
    } else {
      log.info('siop: ' + subject + ' (' + owner + ') was enrolled with no ' +
               'pinned key; development mode pinned ' + print + ', the key ' +
               'it signed in with (trust on first use).');
      audit({ category: 'authentication', action: 'siop.key.pinned',
              actor: owner, target: owner, outcome: 'success',
              summary: 'pinned the key ' + print + ' of ' + subject +
                       ' on first use (development mode)',
              detail: { subject: subject, keyThumbprint: print } });
    }
    log.debug("Leaving Siop.pinCheck(). Pinned on first use.");
    return { ok: true, code: '', detail: print + ', pinned now on first ' +
             'use (development mode)' };
  }

  // -------------------------------------------------------------------------
  // THE SELF-ISSUED ID TOKEN (section 11.1). `expect` is { clientId, nonce,
  // enrolment? }. Returns { ok, checks, subject, jwk, keyThumbprint, claims,
  // errorCode, reason }; never throws. `errorCode` and `reason` are set only
  // where a refusal has a code of its own (the pin, an enrolment's fetch).
  // -------------------------------------------------------------------------
  /**
   * Verifies a self-issued ID Token (section 11.1). Never throws.
   *
   * @param token - the ID Token
   * @param expect - `{ clientId, nonce, enrolment? }`; `enrolment` only for
   *   a person's own enrolment transaction, which may fetch an unenrolled
   *   did:web once and is not held to a pin
   * @returns `{ ok, checks, subject, jwk, keyThumbprint, claims, errorCode,
   *   reason }`
   */
  async verifyIdToken(token: unknown, expect: IdTokenExpectation):
      Promise<Json> {
    const { log, stsCrypto, vcDataIntegrity, config, nowSec } = this.deps;
    log.debug("Entering Siop.verifyIdToken().");
    const checks: Json[] = [];
    const check = function (name: string, ok: boolean, detail: string) {
      checks.push({ name: name, ok: !!ok, detail: detail });
      return !!ok;
    };
    const out: Json = { ok: false, checks: checks, subject: '', jwk: null,
                        keyThumbprint: '', claims: null, errorCode: '',
                        reason: '', alg: '' };
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
    // THE CHECKS THAT NEED NO KEY, judged now and reported after the
    // signature as they always were: a did:web is fetched only when they
    // pass (#693), so nobody can make this service dial with a token for
    // another transaction or a stale one.
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    const now = nowSec();
    const maxAge = Number(config.value('oid4vp.siopIdTokenMaxAgeS'));
    const exp = Number(claims.exp);
    const iat = Number(claims.iat);
    const claimChecks = [
      { name: 'aud', ok: aud.indexOf(expect.clientId) >= 0,
        detail: 'must name this Verifier, "' + expect.clientId + '"; it ' +
                'names ' + JSON.stringify(claims.aud) },
      { name: 'nonce', ok: typeof claims.nonce === 'string' &&
        stsCrypto.constantTimeEquals(claims.nonce, String(expect.nonce)),
        detail: 'must be this request\'s nonce' },
      { name: 'exp', ok: isFinite(exp) && exp + SKEW_S > now,
        detail: 'expires ' + claims.exp + ', now ' + now },
      { name: 'iat', ok: isFinite(iat) && iat <= now + SKEW_S &&
        now - iat <= maxAge,
        detail: 'issued ' + claims.iat + ', now ' + now + ', at most ' +
                maxAge + ' s old (oid4vp.siopIdTokenMaxAgeS)' }
    ];
    const claimsOk = claimChecks.every(function (one) {
      return one.ok;
    });
    const reportClaims = function (): boolean {
      log.debug("Entering reportClaims().");
      const passed = claimChecks.map(function (one) {
        return check(one.name, one.ok, one.detail);
      }).every(Boolean);
      log.debug("Leaving reportClaims(). " + passed);
      return passed;
    };
    const enrolment = expect.enrolment || null;
    let jwk: Json = null;
    let subject = '';
    try {
      if (/^did:/.test(sub)) {
        subject = this.normalise(sub);
        if (!subject || subject !== sub) {
          throw new Error('"' + sub + '" is not a did:jwk, did:key or ' +
                          'did:web this Verifier resolves.');
        }
        jwk = await this.didKey(sub, String(header.kid || ''), claimsOk,
                                enrolment);
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
      if (e && e.code) {
        out.errorCode = e.code;
        out.reason = 'The self-issued ID Token\'s key could not be ' +
                     'resolved: ' + e.message;
      }
      reportClaims();
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
    let allOk = reportClaims();
    out.keyThumbprint = stsCrypto.jwkThumbprint(jwk);
    // THE PIN (#693), for a did:web outside its own enrolment — which is
    // where the pin is MADE, so it is not held to one.
    if (allOk && /^did:web:/.test(subject) && !enrolment) {
      const pinned = this.pinCheck(subject, jwk);
      allOk = check('pinned key', pinned.ok, pinned.detail);
      if (!pinned.ok && pinned.code) {
        out.errorCode = pinned.code;
        out.reason = pinned.detail;
      }
    }
    out.ok = allOk;
    out.subject = subject;
    out.jwk = jwk;
    // The algorithm the proof was signed with (#1021): what an enrolment
    // records as the key's, for a did:web whose key the DID does not spell.
    out.alg = String((header && header.alg) || '');
    out.claims = claims;
    log.debug("Leaving Siop.verifyIdToken(). ok=" + allOk);
    return out;
  }

  // -------------------------------------------------------------------------
  // A COMBINED RESPONSE (`vp_token id_token`): the ID Token's subject must be
  // the holder the presentation's key binding proved. Compared as RFC 7638
  // thumbprints, which is the one spelling both sides have.
  // -------------------------------------------------------------------------
  /**
   * Says whether a combined response's ID Token subject is the holder the
   * presentation's key binding proved, compared as RFC 7638 thumbprints.
   *
   * @param idTokenJwk - the ID Token's key
   * @param holderJwk - the presentation's holder key
   * @returns true when they are the same key
   */
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
  /**
   * Returns whom a verified self-issued ID Token signs in: the person who
   * enrolled its subject, and nobody otherwise.
   *
   * @param verified - `verifyIdToken()`'s result
   * @returns `{ ok, errorCode, reason, username, ... }`
   */
  signInOutcome(verified: Json): Json {
    const { log } = this.deps;
    log.debug("Entering Siop.signInOutcome().");
    const refuse = function (code: string, reason: string): Json {
      log.debug("Leaving Siop.signInOutcome(). " + code);
      return { ok: false, errorCode: code, reason: reason, username: '',
               subject: '' };
    };
    if (!verified || !verified.ok) {
      // A refusal with a code of its own (the pin, an enrolment's fetch,
      // #693) says so; any other is the token not verifying.
      return verified && verified.errorCode
        ? refuse(String(verified.errorCode), String(verified.reason || ''))
        : refuse('STS-VC-0090', 'The self-issued ID Token did not ' +
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

/**
 * Self-Issued OpenID Provider v2, the relying party's half: enrolment of
 * self-issued subjects and the check of a self-issued ID Token.
 *
 * @namespace
 */
export = {
  Siop: Siop,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: Siop): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin(),
  SUBJECT_SYNTAX_TYPES: SUBJECT_SYNTAX_TYPES,
  ID_TOKEN_ALGS: ID_TOKEN_ALGS,
  MAX_SUBJECTS: MAX_SUBJECTS,
  PROOF_WALLET: PROOF_WALLET,
  PROOF_ADMIN: PROOF_ADMIN,
  didWebUrl: Siop.didWebUrl,
  provenanceOf: Siop.provenanceOf,
  LOCATION_KINDS: LOCATION_KINDS,
  reportedName: Siop.reportedName,
  locationOf: Siop.locationOf,
  normalise: slot.forward('normalise'),
  list: slot.forward('list'),
  ownerOf: slot.forward('ownerOf'),
  enrol: slot.forward('enrol'),
  enrolByValue: slot.forward('enrolByValue'),
  provenSubjectsOf: slot.forward('provenSubjectsOf'),
  preferredSubjectOf: slot.forward('preferredSubjectOf'),
  setPreferred: slot.forward('setPreferred'),
  authenticationKeys: slot.forward('authenticationKeys'),
  remove: slot.forward('remove'),
  clientMetadata: slot.forward('clientMetadata'),
  verifyIdToken: slot.forward('verifyIdToken'),
  sameHolder: slot.forward('sameHolder'),
  signInOutcome: slot.forward('signInOutcome')
};
