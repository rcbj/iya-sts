// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: webauthn_ceremonies.ts
//
// ---------------------------------------------------------------------------
// WHAT A WEBAUTHN CEREMONY RECORDS, FOR THE MOVE TO POST-QUANTUM KEYS (#943,
// 2026-10-23).
//
// Until #943 a ceremony left a `session.start` row naming the algorithm a
// passkey signed with, an enrolment row naming the new key's, and a refusal
// row with an error code. None said what the CEREMONY offered, which client
// ran it, how the authenticator was reached, or why a browser gave up — and
// those are what somebody moving a realm to ML-DSA passkeys has to read: is
// ML-DSA offered first, does this browser make one when asked, did the
// person cancel or did the platform say NotSupportedError. So every
// registration and assertion at the doors that run one — the sign-in
// screen's passkey step, the usernameless sign-in, `/portal/keys`, a device
// link and an activation link (`credentials.confirmKeyEnrolment()`) — writes
// ONE audit
// row, `webauthn.ceremony`, successful or not, and a person who holds an
// ML-DSA passkey signing in with a classical one where post-quantum was not
// required writes a row of its own, `webauthn.algorithm-mismatch`.
//
// ---------------------------------------------------------------------------
// THE ROW, AND IT IS THE SHAPE A REPORT READS (the realm-wide passkey page).
// `action` `webauthn.ceremony`, category `authentication`, `actor` the
// person where known ('' before a usernameless handle names anybody),
// `outcome` `success` or `refused`, `errorCode` the code the door refused
// with, and `detail` — at most twelve fields, `audit.js`'s cap:
//
//   ceremony       `registration` or `assertion`
//   door           `sign-in-step`, `usernameless`, `portal` or `activation`
//   role           `primary`, `mfa` or ''
//   lane           `classical` or `pqc` (#643)
//   offered        the algorithms offered, IN ORDER, comma-separated: a
//                  registration's pubKeyCredParams as the verifier enforced
//                  them (`webauthn_policy.algorithmIds()` of the lane, the
//                  list `expectedAlgorithms` was checked against); for an
//                  assertion, which has no such list, the algorithms of the
//                  person's keys the ceremony could name, in key order
//   algorithm      the algorithm used (the new key's, or the asserting
//                  key's), '' where none was reached
//   postQuantum    whether that algorithm is RFC 9964's ML-DSA
//   client         the browser and the operating system, FAMILY AND MAJOR
//                  VERSION ONLY (`Chrome 141 on macOS 15`), read from the
//                  User-Agent and NEVER more — no build, no device model, no
//                  client hints; the header itself is not kept
//   transports     the transports the browser reported (`internal,hybrid`)
//   attachment     `platform`, `cross-platform` or ''
//   clientError    the DOMException NAME the page's script reported for a
//                  ceremony the browser did not complete (`NotAllowedError`
//                  — declined, timed out or no credential, which WebAuthn
//                  deliberately does not tell apart — `NotSupportedError`,
//                  `InvalidStateError`, `SecurityError`, `AbortError`, ...),
//                  one of `CLIENT_ERRORS` or `other`; NEVER its message,
//                  which is free text a page could fill with anything
//   capabilities   the true members of a fixed allowlist of client
//                  capabilities, where getClientCapabilities() is available
//   attestation    for a registration that recorded one, what its
//                  attestation was signed with (#941): the statement's
//                  algorithm, then the chain leaf to anchor, and `PQ` where
//                  every one is post-quantum
//
// `webauthn.algorithm-mismatch`: `actor` the person, `detail` { used — the
// classical algorithm that signed, held — the person's post-quantum
// algorithms, door, client }.
//
// ---------------------------------------------------------------------------
// NO LOG LINE PER CEREMONY, AND NONE PER FAILURE (rcbj's standing rule: log
// state changes and periodic summaries, never a line per failed attempt).
// These rows are written with `summarised: true`, so a refused one writes no
// service log line of its own: the HTTP call row of the same request
// already writes the one line its error code earns, and a second here would
// be a second line per attempt. The summary is the realm-wide passkey page,
// which counts these rows; the rows are the inspectable store.
//
// HOW THE CLIENT'S ERROR ARRIVES: through the ceremony's own endpoint. The
// sign-in surface's script (`authn/web_authn.ts`) and the portal's
// (`portal/web_portal_webauthn.ts`) post an allowlisted error name and the
// available client capabilities as the credential when the browser rejects
// the ceremony, to
// the same `/authn-api/...` or `/account-api/...` operation a credential
// goes to — CSRF-bound, behind the step or the person's token, and limited
// as those are — so no endpoint was added: a second, unauthenticated report
// door would be one more thing to rate-limit and one anybody could fill. The
// fallback UI reports the same way, leaving its pending step available.
//
// ---------------------------------------------------------------------------
// THIS IS RULE 3: A LIBRARY. It registers no route. It requires
// `common/helpers`, `common/audit` (a leaf), `common/passkey_policy` (a
// leaf, for `isPostQuantum()`), `./webauthn` (the verifier, for its COSE
// names) and `bowser` (MIT, which `risk/risk_engine.ts`
// reads the same header with) — never `common/credentials`, which requires
// THIS module: the caller hands over the keys' algorithms.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import audit = require('../common/audit');
import passkeyPolicy = require('../common/passkey_policy');
import bowser = require('bowser');
// The COSE names of the algorithms, from the verifier: a leaf over npm
// modules and `common/crypto`.
import webauthn = require('./webauthn');

const { log } = helpers;

type Json = any;

/**
 * The DOMException names a WebAuthn ceremony's rejection may carry (WebAuthn
 * Level 3 sections 5.1.3 and 5.1.4, and WebIDL's), and `TypeError` for an
 * options object the browser would not take. Any other value is `other`.
 */
const CLIENT_ERRORS: ReadonlyArray<string> = Object.freeze([
  'NotAllowedError', 'NotSupportedError', 'InvalidStateError',
  'SecurityError', 'AbortError', 'ConstraintError', 'UnknownError',
  'TimeoutError', 'OperationError', 'EncodingError', 'NotReadableError',
  'DataError', 'TypeError']);

/**
 * The doors a ceremony row may name.
 */
const DOORS: ReadonlyArray<string> = Object.freeze([
  'sign-in-step', 'usernameless', 'portal', 'activation']);

interface CeremonyEvent {
  ceremony: 'registration' | 'assertion';
  door: string;
  username?: string;
  role?: string;
  lane?: string;
  outcome: 'success' | 'refused';
  errorCode?: string;
  offered?: Array<string | number>;
  algorithm?: string;
  // The credential as the page posted it: its transports, attachment and
  // `error` are read, nothing else.
  posted?: Json;
  // The new key's attestation record (#941), for a registration.
  attestation?: Json;
  req?: Json;
}

interface WebauthnCeremoniesDeps {
  log: typeof helpers.log;
  audit: typeof audit;
}

/**
 * Writes the audit rows a WebAuthn ceremony leaves (#943): one per
 * registration or assertion, and one per algorithm mismatch.
 */
class WebauthnCeremonies {
  /**
   * The DOMException names a ceremony row may carry.
   */
  static readonly CLIENT_ERRORS = CLIENT_ERRORS;

  /**
   * The doors a ceremony row may name.
   */
  static readonly DOORS = DOORS;

  /**
   * Builds the recorder over the dependencies given.
   *
   * @param deps - the logger and the audit log
   */
  constructor(private readonly deps: WebauthnCeremoniesDeps) {
    deps.log.debug("Entering WebauthnCeremonies.constructor().");
    deps.log.debug("Leaving WebauthnCeremonies.constructor().");
  }

  /**
   * Returns the dependencies built from the real modules, as the composition
   * root passes them.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): WebauthnCeremoniesDeps {
    helpers.log.debug("Entering WebauthnCeremonies.defaultDeps().");
    helpers.log.debug("Leaving WebauthnCeremonies.defaultDeps().");
    return { log: helpers.log, audit: audit };
  }

  // -------------------------------------------------------------------------
  // THE CLIENT, FROM THE USER-AGENT AND NOTHING ELSE. Family and major
  // version of the browser and of the operating system — what tells "this
  // browser does not make ML-DSA passkeys yet" from "this one does" — and
  // nothing finer: a full User-Agent is close to an identifier, and a row a
  // person's every ceremony writes must not carry one. bowser throws on an
  // empty string, which a request with no header is, so that is answered
  // without it, as `risk_engine.ts`'s `deviceOf()` does.
  // -------------------------------------------------------------------------
  /**
   * Names the browser and operating system of a User-Agent, by family and
   * major version only: `Chrome 141 on macOS 15`.
   *
   * @param userAgent - the User-Agent header
   * @returns the name, or '' with no header
   */
  static clientOf(userAgent: unknown): string {
    log.debug("Entering WebauthnCeremonies.clientOf().");
    const ua = String(userAgent || '').slice(0, 512);
    if (!ua) {
      log.debug("Leaving WebauthnCeremonies.clientOf(). No User-Agent.");
      return '';
    }
    let parsed: Json = {};
    try {
      parsed = bowser.parse(ua) || {};
    } catch (e) {
      log.debug("Caught in WebauthnCeremonies.clientOf(): " +
                ((e && e.message) || e));
      // A header bowser cannot read names no client.
      parsed = {};
    }
    const major = function (version: unknown): string {
      log.debug("Entering clientOf() major().");
      const m = /^(\d{1,4})/.exec(String(version || ''));
      log.debug("Leaving clientOf() major().");
      return m ? ' ' + m[1] : '';
    };
    const word = function (name: unknown): string {
      log.debug("Entering clientOf() word().");
      log.debug("Leaving clientOf() word().");
      return String(name || '').replace(/[^A-Za-z0-9 .-]/g, '').slice(0, 32);
    };
    const b = parsed.browser || {};
    const o = parsed.os || {};
    const browser = b.name ? word(b.name) + major(b.version) : 'a browser';
    const os = o.name ? word(o.name) + major(o.version) : 'another system';
    log.debug("Leaving WebauthnCeremonies.clientOf().");
    return browser + ' on ' + os;
  }

  /**
   * The DOMException name a page reported, if it is one a WebAuthn
   * ceremony's rejection can carry; `other` for any other value, '' for
   * none. The message beside it is never read.
   *
   * @param raw - what the page posted as `error`
   * @returns the name, `other` or ''
   */
  static clientErrorName(raw: unknown): string {
    log.debug("Entering WebauthnCeremonies.clientErrorName().");
    if (raw === undefined || raw === null || raw === '') {
      log.debug("Leaving WebauthnCeremonies.clientErrorName(). None.");
      return '';
    }
    const name = String(raw);
    const out = CLIENT_ERRORS.indexOf(name) >= 0 ? name : 'other';
    log.debug("Leaving WebauthnCeremonies.clientErrorName(). " + out);
    return out;
  }

  // The algorithms offered, as names, in order and each once: a COSE id is
  // named by `webauthn.js`'s table, a name is kept if it looks like one.
  private static namesOf(list: unknown): string[] {
    log.debug("Entering WebauthnCeremonies.namesOf().");
    const cose: Json = (webauthn as Json).COSE_ALGS || {};
    const out: string[] = [];
    (Array.isArray(list) ? list : []).slice(0, 32).forEach(
      function (one: Json): void {
        const name = typeof one === 'number'
          ? String(cose[String(one)] || 'COSE ' + one)
          : String(one || '');
        if (/^[A-Za-z0-9 _.-]{1,40}$/.test(name) && out.indexOf(name) < 0) {
          out.push(name);
        }
      });
    log.debug("Leaving WebauthnCeremonies.namesOf(). " + out.length);
    return out;
  }

  // What a registration's attestation was signed with (#941), in a line.
  private static attestationText(rec: Json): string {
    log.debug("Entering WebauthnCeremonies.attestationText().");
    const a = rec && rec.algorithms;
    if (!a) {
      log.debug("Leaving WebauthnCeremonies.attestationText(). None.");
      return '';
    }
    const chain = (Array.isArray(a.certificates) ? a.certificates : [])
      .map(function (one: Json): string {
        return String((one && one.algorithm) || '');
      }).concat(a.anchor ? [String(a.anchor.algorithm || '')] : [])
      .filter(Boolean);
    const text = [String(a.statement || '')].concat(
      chain.length ? [chain.join(' > ')] : []).filter(Boolean).join('; ');
    log.debug("Leaving WebauthnCeremonies.attestationText().");
    return text ? text + (a.postQuantum === true ? ' (PQ)' : '') : '';
  }

  /**
   * Records one WebAuthn ceremony (#943): a registration or an assertion,
   * successful or not. Never throws: a row that cannot be written leaves
   * the ceremony as it was.
   *
   * @param event - what the door knows; see the header for the fields
   * @returns the row written, or null
   */
  record(event: CeremonyEvent): Json {
    const { log, audit } = this.deps;
    log.debug("Entering WebauthnCeremonies.record().");
    try {
      const e = event || ({} as CeremonyEvent);
      const posted = e.posted && typeof e.posted === 'object' ? e.posted : {};
      const response = posted.response && typeof posted.response === 'object'
        ? posted.response : {};
      const transports = (Array.isArray(response.transports)
        ? response.transports
        : (Array.isArray(posted.transports) ? posted.transports : []))
        .map(String).filter(function (t: string): boolean {
          return /^[a-z-]{1,20}$/.test(t);
        }).slice(0, 8);
      const attachment = ['platform', 'cross-platform'].indexOf(
        String(posted.authenticatorAttachment || '')) >= 0
        ? String(posted.authenticatorAttachment) : '';
      const req = e.req || audit.currentRequest() || null;
      const userAgent = req && req.headers ? req.headers['user-agent'] : '';
      const algorithm = String(e.algorithm || '').slice(0, 40);
      const ceremony = e.ceremony === 'registration' ? 'registration'
                                                     : 'assertion';
      const door = DOORS.indexOf(String(e.door)) >= 0 ? String(e.door)
                                                      : 'sign-in-step';
      const clientError = WebauthnCeremonies.clientErrorName(posted.error);
      const capabilityNames = ['conditionalCreate', 'conditionalGet',
        'hybridTransport', 'userVerifyingPlatformAuthenticator',
        'relatedOrigin', 'signalAllAcceptedCredentials',
        'signalCurrentUserDetails', 'signalUnknownCredential'];
      const capabilities = capabilityNames.filter(function (name: string) {
        return posted.capabilities &&
          posted.capabilities[name] === true;
      }).join(',');
      const refused = e.outcome !== 'success';
      const row = audit.audit({
        action: 'webauthn.ceremony', category: 'authentication',
        outcome: refused ? 'refused' : 'success',
        errorCode: refused ? String(e.errorCode || '') : '',
        // The HTTP call row of this request writes the one log line its
        // code earns; this row writes none (see the header).
        summarised: true,
        actor: String(e.username || ''), channel: 'http',
        protocol: 'WebAuthn',
        summary: 'a WebAuthn ' + ceremony + ' at the ' + door + ' door ' +
                 (refused ? 'did not complete' + (clientError
                   ? ' (the browser reported ' + clientError + ')' : '')
                          : 'completed') +
                 (algorithm ? ' with ' + algorithm : ''),
        detail: {
          ceremony: ceremony, door: door, role: String(e.role || ''),
          lane: String(e.lane || ''),
          offered: WebauthnCeremonies.namesOf(e.offered).join(','),
          algorithm: algorithm,
          postQuantum: passkeyPolicy.isPostQuantum(algorithm),
          client: WebauthnCeremonies.clientOf(userAgent),
          transports: transports.join(','), attachment: attachment,
          clientError: clientError,
          capabilities: capabilities,
          attestation: ceremony === 'registration'
            ? WebauthnCeremonies.attestationText(e.attestation) : ''
        }
      });
      log.debug("Leaving WebauthnCeremonies.record(). " + ceremony + ' ' +
                (refused ? 'refused' : 'completed'));
      return row;
    } catch (err) {
      // A ceremony row is evidence, not the ceremony: one that could not be
      // written must not turn a sign-in into an error page.
      log.debug("Caught in WebauthnCeremonies.record(): " +
                ((err && err.message) || err));
      log.debug("Leaving WebauthnCeremonies.record(). Not recorded.");
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // THE ALGORITHM MISMATCH (#943): a person who holds a post-quantum passkey
  // signed in with a classical one, where the passkey policy did not
  // require post-quantum — the case a migration most needs to see, because
  // it is invisible otherwise: the sign-in worked. Where post-quantum IS
  // required the classical key is refused instead (#718, STS-AUTHN-0356),
  // which has its own row, so the caller asks this only after that check.
  // A row of its own, not a field, so it can be counted without reading
  // every ceremony; no error code, as nothing failed.
  // -------------------------------------------------------------------------
  /**
   * Records a sign-in by a classical passkey from a person who holds a
   * post-quantum one (#943), where post-quantum was not required.
   *
   * @param input - `{ username, used, held, required, door, req }`: the
   *   algorithm that signed, the person's keys' algorithms, and whether the
   *   passkey policy required post-quantum at sign-in
   * @returns the row written, or null where there is no mismatch
   */
  algorithmMismatch(input: { username: string; used: string;
                             held: string[]; required?: boolean;
                             door?: string; req?: Json }): Json {
    const { log, audit } = this.deps;
    log.debug("Entering WebauthnCeremonies.algorithmMismatch().");
    try {
      const given = input || ({} as Json);
      const used = String(given.used || '');
      const pq = (Array.isArray(given.held) ? given.held : [])
        .map(String).filter(function (name: string): boolean {
          return passkeyPolicy.isPostQuantum(name);
        }).filter(function (name: string, at: number, all: string[]) {
          return all.indexOf(name) === at;
        });
      if (!used || passkeyPolicy.isPostQuantum(used) || !pq.length ||
          given.required === true) {
        log.debug("Leaving WebauthnCeremonies.algorithmMismatch(). None.");
        return null;
      }
      const req = given.req || audit.currentRequest() || null;
      const row = audit.audit({
        action: 'webauthn.algorithm-mismatch', category: 'authentication',
        outcome: 'success', actor: String(given.username || ''),
        channel: 'http', protocol: 'WebAuthn',
        summary: String(given.username || '') + ' holds a post-quantum ' +
                 'passkey (' + pq.join(', ') + ') and signed in with a ' +
                 'classical one (' + used + ')',
        detail: { used: used, held: pq.join(','),
                  door: String(given.door || ''),
                  client: WebauthnCeremonies.clientOf(
                    req && req.headers ? req.headers['user-agent'] : '') }
      });
      log.debug("Leaving WebauthnCeremonies.algorithmMismatch(). Recorded.");
      return row;
    } catch (err) {
      // As record(): evidence, never the sign-in.
      log.debug("Caught in WebauthnCeremonies.algorithmMismatch(): " +
                ((err && err.message) || err));
      log.debug("Leaving WebauthnCeremonies.algorithmMismatch(). Not " +
                "recorded.");
      return null;
    }
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2), with facades for
// the callers and the tests — `webauthn_attestation.ts`'s arrangement.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<WebauthnCeremonies>(
  'authn/webauthn_ceremonies',
  () => new WebauthnCeremonies(WebauthnCeremonies.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The audit rows a WebAuthn ceremony leaves (#943).
 * @namespace
 */
export = {
  WebauthnCeremonies: WebauthnCeremonies,
  installInstance: (instance: WebauthnCeremonies): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  record: slot.forward('record'),
  algorithmMismatch: slot.forward('algorithmMismatch'),
  clientOf: WebauthnCeremonies.clientOf,
  clientErrorName: WebauthnCeremonies.clientErrorName,
  CLIENT_ERRORS: CLIENT_ERRORS,
  DOORS: DOORS
};
