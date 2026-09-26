'use strict';
//
// File: caep.ts
//
// ---------------------------------------------------------------------------
// THE CAEP SESSION REGISTER, AND THE ONE THING IN THIS DIRECTORY THAT IS NOT
// VOCABULARY.
//
// `ssf_events.js` carries CAEP's eight event types, because that file is the
// VOCABULARY and the whole design of this family says a vocabulary is rows in
// its table. This file is the thing those rows are ABOUT: a session, what
// state CAEP thinks it is in, and how many events of which type have been sent
// concerning it.
//
// **WHY THAT IS A SEPARATE FILE AND NOT MORE ROWS.** A row says what an event
// MEANS. This says what has HAPPENED to one session — which is not a property
// of any event type, cannot be derived from the catalogue, and is the only
// thing on /admin/caep-sessions that a protocol trace cannot already tell you.
// Putting it in the catalogue would have made that table's shape specific to
// CAEP, which is the mistake `ssf_events.js`'s header spends a paragraph
// warning about, and RISC would have had to undo it.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3). IT REGISTERS NO ROUTE AND IT SENDS NOTHING.
//
// It requires `helpers`, `config`, `realms`, `audit`, `ssf_events`,
// `ssf_subjects` and the route-free `oauth-oidc/step_up.ts`, and nothing else,
// so it cannot join a cycle — and in particular it does NOT require `ssf.ts`,
// which requires IT. That is what decides the division of labour and it is
// worth stating plainly because it looks arbitrary from either side:
//
//   THIS FILE DECIDES WHAT AN EVENT WOULD BE. `observe()` takes a notice
//   about a session, updates the register, and ANSWERS with the event that
//   ought to go out — or with null.
//
//   `ssf.ts` DECIDES WHERE IT GOES. It holds `transmit()`, the streams and
//   the deliveries, so it takes that answer and sends it on every stream that
//   agreed to the type and whose subjects cover the session.
//
// A version of this file that sent the event itself would have had to require
// `ssf.ts`, and `ssf.ts` requires this one for the register — a cycle, and the
// second require would have moved every `/ssf` route. (Since #50's R1
// requiring `ssf.ts` registers no route — `common/protocol_stack.ts` does —
// so only the cycle is left, and it is reason enough.)
//
// ---------------------------------------------------------------------------
// THE REGISTER OUTLIVES THE SESSION, ON PURPOSE.
//
// `authn.js`'s session store forgets a session the moment it is signed out.
// This does not: a row whose state is `revoked` is the ONLY remaining evidence
// that the session existed and was revoked, and "did anything go out when I
// signed that person out?" is the entire question /admin/caep-sessions is
// there to answer. `caep.maxSessionsTracked` caps it and the OLDEST goes
// first, which is the same trade the api's push inbox makes for the same
// reason: whoever is reading wants what happened lately.
//
// **IT IS PER TRUST REALM, AND PERSISTED WHERE MINTED STATE IS, SINCE
// 2026-09-12.** This paragraph said it was in memory and died with the process
// "like everything else this service mints", which stopped being true of
// everything else in product mode on 2026-09-06 — the sessions it describes
// and the streams it counts against are both written down there — and it was
// one `new Map()` for the whole process, so `/realm/acme/admin/caep-sessions`
// listed every realm's sessions and a session id minted in one realm could be
// reset from another's console. `realms.map()` is the partition and
// `persistence/persistence_minted.js` carries it, `merge: 'replace'`: a row is
// whole-valued, the later write wins, and `touch()` below is what reports a row
// edited in place. In development nothing minted is written down, which is
// unchanged.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `CaepRegister` takes `helpers`, `config`, `audit`, the SSF
// vocabulary, the subject library and `step_up.js`'s level order through its
// constructor. The register itself stays a module-level `realms.map()`,
// declared at load as before, so it is still per realm and still persisted.
// The module still exports its old names as FACADES forwarding to the instance
// the composition root builds (#50, R2), for `ssf/ssf.ts`, the console and the
// tests. A process that loads this module without the root builds a default
// instance when the module loads.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
// The partition. A LEAF requiring `config` and the error-code registry and
// nothing else here.
import realms = require('../common/realms');
import audit = require('../common/audit');
import events = require('./ssf_events');
import subjects = require('./ssf_subjects');
// The ORDER of those levels is `oauth-oidc/step_up.ts`'s, required rather than
// written out again: RFC 9470's "a stronger authentication satisfies a request
// for a weaker one" and this file's `change_direction` are one ordering, and
// two copies would disagree the first time a level was added. step_up.js is a
// library over `common/` and registers no route, so the require moves nothing
// and closes no cycle.
import stepUp = require('../oauth-oidc/step_up');
// WHICH CLAIMS A DIRECTORY WRITE MOVED (#145): the catalogue that maps an LDAP
// attribute onto the claim it becomes, and the groups claim. Both are
// `common/` libraries loaded at 5 and 6, long before this file, and neither
// requires anything of SSF, so the requires close no cycle.
import claimAttributes = require('../common/claim_attributes');
// `fp_ua`'s fingerprint (#145). A leaf library.
import stsCrypto = require('../common/crypto');
import groupClaims = require('../common/group_claims');

// One register row. See `blankRow()`.
interface CaepRow {
  sessionId: string;
  sub: string;
  username: string;
  iss: string;
  deviceId: string;
  tenant: string;
  protocol: string;
  acr: string;
  amr: string[];
  establishedAt: string;
  updatedAt: string;
  state: string;
  assurance: { namespace: string; level: string; previousLevel: string };
  compliance: string;
  risk: { level: string; previousLevel: string; reason: string };
  claims: Record<string, unknown>;
  credentials: any[];
  counts: Record<string, number>;
  total: number;
  events: any[];
  streams: string[];
  notes: string[];
  [member: string]: any;
}

// What `applyToState()` answers.
interface Verdict {
  ok: boolean;
  errors: string[];
  warnings: string[];
  state?: string;
}

interface CaepRegisterDeps {
  helpers: {
    log: { debug(m: string): void; warn(m: string): void };
    nowSec(): number;
    iso(): string;
  };
  config: { value(key: string): any };
  audit: { audit(row: object): unknown };
  events: {
    CAEP_PREFIX: string;
    CAEP_EVENT_URIS: string[];
    CAEP_EVENTS: any[];
    EVENT_BY_URI: Record<string, any>;
  };
  subjects: { describeSubject(subject: unknown): string;
              complexSubject(members: Record<string, any>):
                Record<string, any> };
  stepUp: { LEVELS: string[] };
  claimAttributes: { CATALOGUE: ReadonlyArray<{ ldap: string;
                                                 claim: string[] }> };
  groupClaims: { groupsOf(username: unknown): { enabled?: boolean;
                                                claim: string;
                                                values: string[] } };
}

// The acts this service can actually OBSERVE, and their event types — three
// at first, eight now (the fourth to eighth are marked below), which is
// every one of CAEP's eight. Written as short names because that is what
// `caep.autoEmitTypes` holds — a setting whose values were 60-character URIs
// would be a setting nobody could type. A row naming anything else is
// dropped with a warning rather than producing an event nothing can cause.
const AUTO_ACTS: Record<string, string> = {
  established: 'session-established',
  presented: 'session-presented',
  revoked: 'session-revoked',
  // THE FOURTH (2026-09-13), and the first that is not about a session: an
  // administrator changing somebody's credentials from their /admin/users page
  // or /admin-api/users, or the person spending a password reset link. It goes
  // out through `ssf.ts`'s `emitCredentialChange()` rather than through
  // `observe()` below, because there is no session row to hang it on — the
  // subject names the PERSON — so `observe()` never sees this act.
  credential: 'credential-change',
  // THE FIFTH (2026-09-14): the same person re-authenticated on a session
  // they already held, and `acr` MOVED — a step-up or a step-down. It is not a
  // session event: nothing began and nothing ended, which is exactly what
  // `session-established` and `session-revoked` would have claimed, and what
  // this service used to send. A re-authentication that leaves `acr` where it
  // was emits nothing; `observe()` below decides. See `authn/CLAUDE.md`, *What
  // an authenticated identity is here*.
  reauthenticated: 'assurance-level-change',
  // THE SIXTH (#145, 2026-09-22): a directory write moved a claim of a person
  // who holds live tokens or assertions — an attribute the claim catalogue
  // maps, their own `memberOf`, or a group they joined, left or whose name
  // changed. `claimsChangeFor()` below reads the write; `ssf.ts` checks the
  // live issuance and sends it. GNAP's grant modification sends the same type
  // through `gnap/gnap_signals.ts`, unchanged.
  claims: 'token-claims-change',
  // THE SEVENTH (#62 P4, 2026-09-22): a person's risk level CHANGED — the
  // risk engine assessed a sign-in, a live session or a re-check of one, and
  // the `risk-response` policy permitted announcing it. Its subject names the
  // PERSON (`principal` USER): the standing moved, not one session. `ssf.ts`'s
  // `riskAutoEmit()` sends it.
  risk: 'risk-level-change',
  // THE EIGHTH (#164 phase 4, 2026-09-26): a registered device's compliance
  // CHANGED — set by an administrator, the MDM feed under
  // `device:compliance`, or development's test control (a received CAEP
  // event joins them with #153). `common/devices.ts`'s `setCompliance()` is
  // the funnel and `ssf.ts`'s `emitDeviceEvent()` sends it; the same act
  // name is not needed for the device's `risk-level-change` (act `risk`) or
  // its keys' `credential-change` (act `credential`), which ride the acts
  // above.
  compliance: 'device-compliance-change'
};

// THE SCALE THIS SERVICE'S OWN LEVELS ARE ON, and it is deliberately not
// `caep.assuranceNamespace` (NIST-AAL), which stays the default for an event
// emitted BY HAND. `0`, `1` and `mfa` are what `authn.js` records and what
// every token here carries in `acr`; mapping them onto NIST's AALs would
// assert a conformance nobody assessed. CAEP's namespace list is an open enum,
// so a private URN is carried with a warning at worst, and a receiver sees the
// level spelt exactly as the tokens it already holds spell it (rcbj's choice).
const ACR_NAMESPACE = 'urn:sts:acr';

// sessionId -> row. Insertion-ordered, which is what makes "the oldest goes"
// one `keys().next()` rather than a sort by a timestamp two rows can share.
//
// PER TRUST REALM — a session belongs to the realm that minted it, and so does
// what CAEP has said about it. The realm is the AMBIENT one: `observe()` is
// reached from `authn.js`'s session store inside the request or the
// realm-scoped expiry sweep, and `noteTransmitted()` from `ssf.ts`'s
// `transmit()`, whose streams are per realm already. `caep.maxSessionsTracked`
// caps each realm's partition rather than the process, which is what a cap
// read in a realm means.
const register = realms.map({ persist: 'caep.register' });

class CaepRegister {
  static readonly AUTO_ACTS = AUTO_ACTS;

  constructor(private readonly deps: CaepRegisterDeps) {
    deps.helpers.log.debug("Entering CaepRegister.constructor().");
    deps.helpers.log.debug("Leaving CaepRegister.constructor().");
  }

  // How many events one row remembers. It is a RING and not a total — the
  // total is on `counts`, which never forgets — because the list exists so
  // that a reader can see the last few `jti`s and the counts exist so that a
  // reader can see how many there have been, and conflating the two would
  // make a page that says "3 events" under a list of three when there were
  // nine.
  //
  // `caep.eventsPerSession` since 2026-09-12 (25, the old constant, is its
  // default); read per event. `caep.historyPerSession` is the same thing for
  // the credential-change list below, which was a literal 10.
  private eventsPerSession(): number {
    const { helpers: { log }, config } = this.deps;
    log.debug("Entering CaepRegister.eventsPerSession().");
    log.debug("Leaving CaepRegister.eventsPerSession().");
    return config.value('caep.eventsPerSession');
  }

  private historyPerSession(): number {
    const { helpers: { log }, config } = this.deps;
    log.debug("Entering CaepRegister.historyPerSession().");
    log.debug("Leaving CaepRegister.historyPerSession().");
    return config.value('caep.historyPerSession');
  }

  // A ROW EDITED IN PLACE, REPORTED TO THE JOURNAL. `realms.map()` journals a
  // `set()` and a `delete()`; almost everything this file does to a row is
  // `row.counts[uri] += 1` on an object already in the map, which nothing
  // sees. Re-setting the same key reports it — and keeps its place in the
  // map's insertion order, so "the oldest goes" still means the oldest. A row
  // trimmed out before the edit is NOT put back, and neither is a row another
  // process's write has since REPLACED — which is why this asks whether the
  // object it was handed is still the one held: the edit belongs to a row the
  // register has already let go.
  private touch(row: CaepRow | null): void {
    const { helpers: { log } } = this.deps;
    log.debug("Entering CaepRegister.touch().");
    if (!row || !row.sessionId) {
      log.debug("Leaving CaepRegister.touch().");
      return;
    }
    if (register.get(row.sessionId) === row) {
      register.set(row.sessionId, row);
    }
    log.debug("Leaving CaepRegister.touch().");
  }

  enabled(): boolean {
    const { helpers: { log }, config } = this.deps;
    log.debug("Entering CaepRegister.enabled().");
    const on = !!config.value('caep.enabled');
    log.debug("Leaving CaepRegister.enabled(). " + on);
    return on;
  }

  // The eight URIs, or none at all when the profile is off. `ssf.ts` unions
  // this with SSF's own two to decide what a stream may request — so turning
  // CAEP off narrows what this transmitter will agree to, which is what makes
  // a receiver's "you would not deliver the type I asked for" path reachable
  // without anybody editing ssf.eventsSupported by hand.
  supportedEventUris(): string[] {
    const { helpers: { log }, events } = this.deps;
    log.debug("Entering CaepRegister.supportedEventUris().");
    if (!this.enabled()) {
      log.debug("Leaving CaepRegister.supportedEventUris(). CAEP is off.");
      return [];
    }
    const out = events.CAEP_EVENT_URIS.slice();
    log.debug("Leaving CaepRegister.supportedEventUris(). " + out.length +
              ' type(s).');
    return out;
  }

  // Which of the five acts emit on their own. An entry naming an event this
  // service cannot cause is DROPPED WITH A WARNING rather than honoured: there
  // is no code path that would ever fire it, so honouring it would leave a
  // setting that reads as configured and does nothing.
  // -------------------------------------------------------------------------
  // THE CLAIMS A DIRECTORY WRITE MOVED (#145), from the directory's account
  // observer notice: `kind: 'updated'` with the person's attribute maps before
  // and after, or `kind: 'membership'` when a group they are in changed.
  // Answers `{ claims }` in CAEP token-claims-change's shape — each changed
  // claim with its NEW value, `null` for one that is gone — or null when
  // nothing a token carries moved. The claim NAMES are the catalogue's (a
  // nested claim nests: `address.locality` is `{ address: { locality } }`),
  // and the groups claim is whatever `group_claims.ts` names it, with the
  // person's groups as they are now.
  // -------------------------------------------------------------------------
  claimsChangeFor(notice?: Record<string, any> | null):
      { claims: Record<string, any> } | null {
    const { helpers: { log }, claimAttributes, groupClaims } = this.deps;
    log.debug("Entering CaepRegister.claimsChangeFor().");
    const asked = notice || {};
    const username = String(asked.username || '');
    if (!username) {
      log.debug("Leaving CaepRegister.claimsChangeFor(). Nobody named.");
      return null;
    }
    const claims: Record<string, any> = {};
    let groupsMoved = asked.kind === 'membership';
    if (asked.kind === 'updated') {
      const before = asked.before || {};
      const after = asked.after || {};
      const valuesAt = function (map: Record<string, any>, name: string) {
        return (map[name] || []).map(String);
      };
      claimAttributes.CATALOGUE.forEach(function (row) {
        const name = row.ldap.toLowerCase();
        const now = valuesAt(after, name);
        if (JSON.stringify(valuesAt(before, name)) === JSON.stringify(now)) {
          return;
        }
        let at = claims;
        row.claim.slice(0, -1).forEach(function (part) {
          at[part] = at[part] && typeof at[part] === 'object' ? at[part] : {};
          at = at[part];
        });
        at[row.claim[row.claim.length - 1]] = now.length === 0 ? null
          : now.length === 1 ? now[0] : now;
      });
      // A person's own `memberOf` is read live as their groups, so writing it
      // moves the groups claim exactly as a group's `member` does.
      groupsMoved = JSON.stringify(valuesAt(before, 'memberof')) !==
                    JSON.stringify(valuesAt(after, 'memberof'));
    }
    if (groupsMoved) {
      const groups = groupClaims.groupsOf(username);
      if (groups && groups.enabled !== false && groups.claim) {
        claims[groups.claim] = groups.values.slice(0);
      }
    }
    if (!Object.keys(claims).length) {
      log.debug("Leaving CaepRegister.claimsChangeFor(). No claim moved.");
      return null;
    }
    log.debug("Leaving CaepRegister.claimsChangeFor(). " +
              Object.keys(claims).join(', ') + ".");
    return { claims: claims };
  }

  autoEmitActs(): string[] {
    const { helpers: { log }, config, events } = this.deps;
    log.debug("Entering CaepRegister.autoEmitActs().");
    if (!this.enabled() || !config.value('caep.autoEmit')) {
      log.debug("Leaving CaepRegister.autoEmitActs(). Off.");
      return [];
    }
    const asked = config.value('caep.autoEmitTypes');
    const list = Array.isArray(asked) ? asked
                                      : String(asked || '').split(',');
    const names = {};
    Object.keys(AUTO_ACTS).forEach(function (act) {
      names[AUTO_ACTS[act]] = act;
    });
    const chosen = [];
    list.map(function (one) {
      return String(one).trim();
    }).filter(Boolean).forEach(function (name) {
      const short = name.indexOf(events.CAEP_PREFIX) === 0
        ? name.slice(events.CAEP_PREFIX.length) : name;
      if (!names[short]) {
        log.warn('caep.autoEmitTypes names "' + name + '", which is not ' +
                 'one of the ' + Object.keys(AUTO_ACTS).length + ' acts ' +
                 'this service can observe (' +
                 Object.keys(AUTO_ACTS).map(function (act) {
                   return AUTO_ACTS[act];
                 }).join(', ') + '). It is DROPPED — nothing here would ' +
                 'ever fire it, so honouring it would leave a setting that ' +
                 'reads as configured and does nothing. Emit that type by ' +
                 'hand from /admin/caep.');
        return;
      }
      if (chosen.indexOf(names[short]) < 0) {
        chosen.push(names[short]);
      }
    });
    log.debug("Leaving CaepRegister.autoEmitActs(). " + chosen.length +
              ' act(s).');
    return chosen;
  }

  // -------------------------------------------------------------------------
  // THE SUBJECT, AND WHY IT IS A COMPLEX ONE.
  //
  // SSF 1.0 section 4 lets a `sub_id` be an object whose members are each
  // themselves a subject identifier, and CAEP is the reason that exists: the
  // person is not revoked, ONE SESSION OF THEIRS IS. A subject naming only the
  // person asks a receiver to end every session they have, which is a
  // different and much larger instruction than the one that was meant.
  //
  // `user` is an issuer/subject pair because that is the identifier a
  // receiver already holds — it is what an ID Token's `iss` and `sub` say.
  // `session` is `opaque` because a session identifier has no shape anybody
  // else can parse and RFC 9493 says so by defining no rule for that format's
  // `id`.
  //
  // **`critical_subject_members` IS WHAT WOULD MAKE THIS SAFE, AND IT IS EMPTY
  // BY DEFAULT HERE.** Publishing `session` in that member of the transmitter
  // metadata promises something worth promising: a receiver that does not
  // understand the member MUST refuse the event rather than act on the person
  // named beside it, which is precisely the failure this shape invites — a
  // receiver that reads `user` and ignores `session` ends every session that
  // person has, from an event that named one. `ssf.criticalSubjectMembers`
  // publishes it and ships EMPTY, because turning it on makes every complex
  // subject refusable by a receiver that has not been told, and this is a
  // debugger whose job is to let both cases be seen. Set it to `session` to
  // find out whether a receiver under test honours it.
  // -------------------------------------------------------------------------
  subjectFor(row: Partial<CaepRow>): Record<string, any> {
    const { helpers: { log }, subjects } = this.deps;
    log.debug("Entering CaepRegister.subjectFor().");
    // `complexSubject()` adds the `"format": "complex"` SSF 1.0 final
    // requires, and drops a member with no value.
    const subject: Record<string, any> = subjects.complexSubject({
      user: { format: 'iss_sub', iss: String(row.iss || ''),
        sub: String(row.sub || '') },
      session: { format: 'opaque', id: String(row.sessionId || '') },
      // THE REGISTERED DEVICE THAT AUTHENTICATED THE SESSION (#164 phase 4),
      // named as the device register's own events name it — `iss_sub`, the
      // realm's issuer and the device's id (`ssf.ts`'s deviceSubjectOf()
      // argues the format) — so a receiver that added the device to its
      // stream is sent the session events of that device too.
      device: row.deviceId
        ? { format: 'iss_sub', iss: String(row.iss || ''),
            sub: String(row.deviceId) } : null,
      tenant: row.tenant ? { format: 'opaque', id: String(row.tenant) } : null
    });
    log.debug("Leaving CaepRegister.subjectFor(). " +
              subjects.describeSubject(subject));
    return subject;
  }

  // The session id out of a subject this service — or anybody else —
  // composed. It reads the COMPLEX shape only: a plain subject names a person
  // and this register is about sessions, so a plain one legitimately matches
  // nothing and the caller counts the event against the stream rather than
  // against a row.
  sessionIdOf(subject: unknown): string {
    const { helpers: { log } } = this.deps;
    log.debug("Entering CaepRegister.sessionIdOf().");
    const body = (subject && typeof subject === 'object' &&
                  !Array.isArray(subject)) ? subject as any : null;
    const session = body && body.session;
    const id = (session && typeof session === 'object' &&
                typeof session.id === 'string') ? session.id : '';
    log.debug("Leaving CaepRegister.sessionIdOf(). " + (id || '(none)'));
    return id;
  }

  // -------------------------------------------------------------------------
  // THE ROW.
  //
  // `state` is CAEP's view and NOT the session store's. They disagree on
  // purpose in one direction: a row stays `revoked` after `authn.js` has
  // forgotten the session entirely, because the row is the evidence. They can
  // also disagree the other way — a session this service still holds whose
  // row says `revoked` means somebody emitted a revocation by hand — and the
  // page says so rather than reconciling, since which of the two is wrong is
  // the question.
  // -------------------------------------------------------------------------
  private blankRow(seed?: Record<string, any>): CaepRow {
    const { helpers: { log, iso } } = this.deps;
    log.debug("Entering CaepRegister.blankRow().");
    const asked = seed || {};
    const row: CaepRow = {
      sessionId: String(asked.sessionId || ''),
      sub: String(asked.sub || ''),
      username: String(asked.username || ''),
      iss: String(asked.iss || ''),
      deviceId: String(asked.deviceId || ''),
      tenant: String(asked.tenant || ''),
      protocol: String(asked.protocol || ''),
      acr: String(asked.acr || ''),
      amr: Array.isArray(asked.amr) ? asked.amr.slice() : [],
      establishedAt: iso(),
      updatedAt: iso(),
      state: 'established',
      // Every one of these starts EMPTY rather than at a plausible default,
      // and that is the difference between "this service has not been told"
      // and "this service was told compliant". A page that showed `compliant`
      // for a device nothing has ever reported on would be inventing the one
      // fact a reader came to look up.
      assurance: { namespace: '', level: '', previousLevel: '' },
      compliance: '',
      risk: { level: '', previousLevel: '', reason: '' },
      claims: {},
      credentials: [],
      counts: {},
      total: 0,
      events: [],
      streams: [],
      notes: []
    };
    log.debug("Leaving CaepRegister.blankRow(). " + row.sessionId);
    return row;
  }

  private trim(): number {
    const { helpers: { log }, config } = this.deps;
    log.debug("Entering CaepRegister.trim().");
    const cap = Number(config.value('caep.maxSessionsTracked')) || 200;
    let dropped = 0;
    while (register.size > cap) {
      const oldest = register.keys().next();
      if (oldest.done) {
        break;
      }
      register.delete(oldest.value);
      dropped += 1;
    }
    log.debug("Leaving CaepRegister.trim(). " + dropped + ' dropped.');
    return dropped;
  }

  // Find the row, or make one. A CAEP event emitted by hand about a session
  // this service never held is legitimate — a debugger pointing at this
  // transmitter is entitled to name whatever subject it likes — so an unknown
  // id gets a row saying where it came from rather than being refused.
  rowFor(sessionId: unknown, seed?: Record<string, any>): CaepRow | null {
    const { helpers: { log } } = this.deps;
    log.debug("Entering CaepRegister.rowFor(). " + sessionId);
    const id = String(sessionId || '');
    if (!id) {
      log.debug("Leaving CaepRegister.rowFor(). No id.");
      return null;
    }
    let row = register.get(id);
    if (!row) {
      row = this.blankRow(Object.assign({ sessionId: id }, seed || {}));
      row.notes.push('This row was created by an event rather than by a ' +
          'sign-in, so nothing here has ever held this session.');
      register.set(id, row);
      this.trim();
    }
    log.debug("Leaving CaepRegister.rowFor(). " + id);
    return row;
  }

  get(sessionId: unknown): CaepRow | null {
    const { helpers: { log } } = this.deps;
    log.debug("Entering CaepRegister.get().");
    const row = register.get(String(sessionId || '')) || null;
    log.debug("Leaving CaepRegister.get(). " + (row ? 'found' : 'not found'));
    return row;
  }

  list(): CaepRow[] {
    const { helpers: { log } } = this.deps;
    log.debug("Entering CaepRegister.list().");
    const out = Array.from(register.values()) as CaepRow[];
    log.debug("Leaving CaepRegister.list(). " + out.length + ' row(s).');
    return out;
  }

  // -------------------------------------------------------------------------
  // THE FOUR COMMON CLAIMS (CAEP section 2).
  //
  // All four are OPTIONAL, and `event_timestamp` being optional is the fact
  // this whole block exists to make visible: a receiver deciding whether to
  // end a session wants it more than anything else in the payload, and a
  // conforming transmitter need not send one. `caep.omitEventTimestamp`
  // produces exactly that event on purpose.
  //
  // `reason_admin` and `reason_user` are OBJECTS KEYED BY A LANGUAGE TAG. That
  // is the commonest mistake in the profile and the one with no symptom: a
  // receiver indexing by language reads nothing from a string and reports no
  // error. This service always sends the object shape.
  // -------------------------------------------------------------------------
  commonClaims(options?: Record<string, any>): Record<string, any> {
    const { helpers: { log, nowSec }, config } = this.deps;
    log.debug("Entering CaepRegister.commonClaims().");
    const asked = options || {};
    const out: Record<string, any> = {};
    if (!config.value('caep.omitEventTimestamp')) {
      out.event_timestamp = typeof asked.eventTimestamp === 'number'
        ? asked.eventTimestamp : nowSec();
    }
    if (['admin', 'user', 'policy', 'system']
        .indexOf(asked.initiatingEntity) >= 0) {
      out.initiating_entity = asked.initiatingEntity;
    }
    const tag = String(config.value('caep.reasonLanguage') || 'en');
    if (config.value('caep.includeReasons')) {
      if (asked.reasonAdmin) {
        out.reason_admin = {};
        out.reason_admin[tag] = String(asked.reasonAdmin);
      }
      if (asked.reasonUser) {
        out.reason_user = {};
        out.reason_user[tag] = String(asked.reasonUser);
      }
    }
    log.debug("Leaving CaepRegister.commonClaims(). " +
              Object.keys(out).length + ' claim(s)');
    return out;
  }

  // A whole payload: the row's own generator, plus the four above. It is one
  // function so that the console form, the management API and the automatic
  // emission all produce the SAME shape — three builders would be three
  // chances for one of them to forget `event_timestamp`.
  buildPayload(uri: string, values?: Record<string, any>,
               options?: Record<string, any>): Record<string, any> {
    const { helpers: { log }, events } = this.deps;
    log.debug("Entering CaepRegister.buildPayload(). " + uri);
    const row = events.EVENT_BY_URI[uri];
    if (!row) {
      log.debug("Leaving CaepRegister.buildPayload(). Unknown type.");
      return {};
    }
    const payload = Object.assign({}, row.generate(values || {}),
                                  this.commonClaims(options));
    log.debug("Leaving CaepRegister.buildPayload(). " +
              Object.keys(payload).length + ' member(s).');
    return payload;
  }

  // -------------------------------------------------------------------------
  // THE STATE MACHINE.
  //
  // What each event type does to a row, and the two places it says NO.
  // Collected findings rather than a boolean, for the reason
  // `ssf_subjects.js` gives about a form: an event built by hand is usually
  // wrong in more than one way.
  //
  // **THE ONE HARD REFUSAL IS `session-presented` ON A REVOKED SESSION**, and
  // it is worth the strictness: that sentence says a session this transmitter
  // has already declared dead was just used and honoured, which is either a
  // transmitter contradicting itself or a receiver about to be told to trust
  // something it was told to stop trusting. Everything else that looks wrong
  // is a WARNING, because this is a mock and refusing to carry an
  // odd-looking event would remove the ability to reproduce one.
  //
  // `device-compliance-change` and `risk-level-change` both carry the
  // PREVIOUS value, and comparing it against what this register holds is the
  // check nothing else can make: a receiver holding "compliant" that gets an
  // event whose `previous_status` is "not-compliant" has missed one, and that
  // gap is invisible from either event on its own.
  // -------------------------------------------------------------------------
  applyToState(row: CaepRow, uri: string, payload?: any): Verdict {
    const { helpers: { log, iso }, events } = this.deps;
    log.debug("Entering CaepRegister.applyToState(). " + uri);
    const body = (payload && typeof payload === 'object') ? payload : {};
    const errors = [];
    const warnings = [];
    const short = uri.indexOf(events.CAEP_PREFIX) === 0
      ? uri.slice(events.CAEP_PREFIX.length) : '';

    if (!short) {
      log.debug("Leaving CaepRegister.applyToState(). Not a CAEP event.");
      return { ok: true, errors: errors, warnings: warnings };
    }

    if (short === 'session-established') {
      if (row.state === 'revoked') {
        warnings.push('This session was revoked and is being established ' +
            'again. That is legitimate — the same identifier can be reused ' +
            '— and a receiver that kept the revocation will ignore ' +
            'everything about it from here on, so it is worth seeing.');
      }
      row.state = 'established';
      if (typeof body.acr === 'string') {
        row.acr = body.acr;
      }
      if (Array.isArray(body.amr)) {
        row.amr = body.amr.slice();
      }
    } else if (short === 'session-presented') {
      if (row.state === 'revoked') {
        errors.push('This session is REVOKED, so it cannot have been ' +
            'presented and honoured. That sentence is either a transmitter ' +
            'contradicting itself or a receiver about to be told to trust ' +
            'something it was told to stop trusting, and it is the one ' +
            'thing this register refuses outright.');
      } else {
        row.state = 'presented';
      }
    } else if (short === 'session-revoked') {
      if (row.state === 'revoked') {
        warnings.push('This session was already revoked. A second ' +
            'revocation is harmless and a receiver should be idempotent ' +
            'about it, which is exactly the thing worth testing.');
      }
      row.state = 'revoked';
    } else if (short === 'token-claims-change') {
      if (row.state === 'revoked') {
        warnings.push('The claims behind a REVOKED session changed. Nothing ' +
            'is wrong with saying so and there is nothing left to apply it ' +
            'to, which is what makes it worth noticing.');
      }
      if (body.claims && typeof body.claims === 'object') {
        // MERGED and not replaced, which is what `claims` means: the member
        // carries only what moved, with its NEW value. A receiver that
        // replaced would drop every claim the event did not mention.
        Object.assign(row.claims, body.claims);
      }
    } else if (short === 'credential-change') {
      row.credentials.unshift({
        at: iso(),
        credentialType: String(body.credential_type || ''),
        changeType: String(body.change_type || ''),
        friendlyName: String(body.friendly_name || '')
      });
      row.credentials = row.credentials.slice(0, this.historyPerSession());
    } else if (short === 'assurance-level-change') {
      if (row.assurance.level && typeof body.previous_level === 'string' &&
          body.previous_level !== row.assurance.level) {
        warnings.push('This event says the previous assurance level was "' +
            body.previous_level + '" and this register holds "' +
            row.assurance.level + '". One event about this session has ' +
            'been missed, or two transmitters are talking about it.');
      }
      row.assurance = {
        namespace: String(body.namespace || row.assurance.namespace || ''),
        level: String(body.current_level || ''),
        previousLevel: String(body.previous_level ||
                              row.assurance.level || '')
      };
    } else if (short === 'device-compliance-change') {
      if (row.compliance && typeof body.previous_status === 'string' &&
          body.previous_status !== row.compliance) {
        warnings.push('This event says the device was "' +
            body.previous_status + '" and this register holds "' +
            row.compliance + '". THAT GAP IS INVISIBLE FROM EITHER EVENT ON ' +
            'ITS OWN, and it is the whole reason CAEP makes previous_status ' +
            'required.');
      }
      row.compliance = String(body.current_status || row.compliance || '');
    } else if (short === 'risk-level-change') {
      if (row.risk.level && typeof body.previous_level === 'string' &&
          body.previous_level !== row.risk.level) {
        warnings.push('This event says the previous risk level was "' +
            body.previous_level + '" and this register holds "' +
            row.risk.level + '". One event has been missed.');
      }
      row.risk = {
        level: String(body.current_level || ''),
        previousLevel: String(body.previous_level || row.risk.level || ''),
        reason: String(body.risk_reason || '')
      };
    }

    row.updatedAt = iso();
    this.touch(row);
    log.debug("Leaving CaepRegister.applyToState(). " + errors.length +
              ' error(s), ' + warnings.length + ' warning(s).');
    return { ok: errors.length === 0, errors: errors, warnings: warnings,
      state: row.state };
  }

  // -------------------------------------------------------------------------
  // COUNTING WHAT WENT OUT.
  //
  // Called from `ssf.ts`'s `transmit()` after the SET has been built, so the
  // counters are of things that were actually MINTED rather than of things
  // somebody meant to send. It reads the session out of the token's own
  // `sub_id`, which is what keeps `transmit()` from having to know anything
  // about this register — a transmit for a plain subject legitimately counts
  // against no row, and says so by returning null.
  //
  // **THE COUNT IS NOT THE LIST.** `counts` never forgets and `events` is a
  // ring of the last few, because "how many session-revoked have gone out
  // about this person" and "what were the last few jtis" are two different
  // questions and a page that answered the first from the second would say
  // three where there were nine.
  // -------------------------------------------------------------------------
  noteTransmitted(record: any, claims: any): CaepRow | null {
    const { helpers: { log, iso }, events } = this.deps;
    log.debug("Entering CaepRegister.noteTransmitted().");
    if (!this.enabled()) {
      log.debug("Leaving CaepRegister.noteTransmitted(). CAEP is off.");
      return null;
    }
    const uris = Object.keys((claims && claims.events) || {});
    const uri = uris[0] || '';
    if (uri.indexOf(events.CAEP_PREFIX) !== 0) {
      log.debug("Leaving CaepRegister.noteTransmitted(). Not a CAEP event.");
      return null;
    }
    const sessionId = this.sessionIdOf(claims && claims.sub_id);
    if (!sessionId) {
      log.debug("Leaving CaepRegister.noteTransmitted(). No session in the " +
                'subject.');
      return null;
    }
    const row = this.rowFor(sessionId, {
      iss: String((claims && claims.iss) || ''),
      sub: String((((claims && claims.sub_id) || {}).user || {}).sub || '')
    });
    const verdict = this.applyToState(row, uri, (claims.events || {})[uri]);
    row.counts[uri] = (row.counts[uri] || 0) + 1;
    row.total += 1;
    row.events.unshift({
      jti: String((claims && claims.jti) || ''),
      uri: uri,
      name: (events.EVENT_BY_URI[uri] || {}).name || uri,
      at: iso(),
      streamId: String((record && record.stream_id) || ''),
      warnings: verdict.warnings
    });
    row.events = row.events.slice(0, this.eventsPerSession());
    const streamId = String((record && record.stream_id) || '');
    if (streamId && row.streams.indexOf(streamId) < 0) {
      row.streams.push(streamId);
    }
    this.touch(row);
    log.debug("Leaving CaepRegister.noteTransmitted(). " + row.total +
              ' event(s) on ' + row.sessionId + '.');
    return row;
  }

  // -------------------------------------------------------------------------
  // A SESSION CHANGED, AND WHAT — IF ANYTHING — SHOULD GO OUT.
  //
  // `ssf.ts` installs this as `authn.setSessionObserver()`'s function and
  // sends what comes back. It updates the register EVEN WHEN NOTHING WILL BE
  // SENT, which is deliberate: a service with no streams agreed still has
  // sessions, and /admin/caep-sessions showing them with a count of zero is
  // how somebody finds out that the reason no event arrived is that nobody
  // asked for one.
  // -------------------------------------------------------------------------
  observe(notice?: Record<string, any> | null): {
    uri: string; payload: Record<string, any>;
    subject: Record<string, any>; row: CaepRow;
  } | null {
    const { helpers: { log, iso }, events, audit, stepUp } = this.deps;
    log.debug("Entering CaepRegister.observe().");
    const asked = notice || {};
    const act = String(asked.kind || '');
    const session = asked.session || {};
    const sessionId = String(session.id || '');
    if (!this.enabled() || !sessionId) {
      log.debug("Leaving CaepRegister.observe(). Off, or no session.");
      return null;
    }
    let row = register.get(sessionId);
    if (!row) {
      row = this.blankRow({
        sessionId: sessionId,
        sub: String((session.user || {}).sub || ''),
        username: String((session.user || {}).username ||
                         (session.user || {}).sub || ''),
        iss: String(asked.issuer || ''),
        protocol: String(asked.via || ''),
        acr: String(session.acr || ''),
        amr: session.amr || []
      });
      register.set(sessionId, row);
      this.trim();
    }
    if (asked.issuer && !row.iss) {
      row.iss = String(asked.issuer);
    }
    // THE DEVICE THE SESSION'S LATEST AUTHENTICATION CAME FROM (#164 phase
    // 4): `registeredDevice` on its newest event (`authn.registeredDeviceOf()`
    // reads the same). Read on every act, so a session a later
    // re-authentication proved from a registered device names it from then
    // on; one that never did carries no `device` member.
    const sessionEvents = Array.isArray(session.events) ? session.events : [];
    const latest = sessionEvents.length
      ? sessionEvents[sessionEvents.length - 1] : null;
    if (latest && latest.registeredDevice && latest.registeredDevice.id) {
      row.deviceId = String(latest.registeredDevice.id);
    }
    row.updatedAt = iso();
    // A RE-AUTHENTICATION MOVES WHAT THE ROW SAYS THE SESSION IS, whether or
    // not anything goes out — the register follows the ACT, as it does for a
    // revocation with emission off. And it is only an EVENT when `acr` moved:
    // an elapsed `max_age` answered with the same method is a fresh
    // `auth_time` and nothing a receiver's decision could turn on.
    let previousAcr = '';
    if (act === 'reauthenticated') {
      previousAcr = String(((asked.previous || {}).acr) || row.acr || '');
      row.acr = String(session.acr || '');
      row.amr = Array.isArray(session.amr) ? session.amr.slice() : [];
      if (previousAcr === row.acr) {
        this.touch(row);
        log.debug("Leaving CaepRegister.observe(). A re-authentication that " +
                  'left acr at "' + row.acr + '"; nothing to emit.');
        return null;
      }
    }
    this.touch(row);

    const short = AUTO_ACTS[act];
    if (!short) {
      log.debug('Leaving CaepRegister.observe(). Nothing to emit for "' +
                act + '".');
      return null;
    }
    if (this.autoEmitActs().indexOf(act) < 0) {
      // The register is still up to date — the state follows the ACT and not
      // the event — so a reader sees the session end even with emission off.
      if (act === 'revoked') {
        row.state = 'revoked';
      }
      if (act === 'established') {
        row.state = 'established';
      }
      row.notes.push('A ' + short + ' was NOT emitted for this act: ' +
          'caep.autoEmit or caep.autoEmitTypes excludes it.');
      row.notes = row.notes.slice(-5);
      this.touch(row);
      log.debug("Leaving CaepRegister.observe(). Emission is off for " + act +
                '.');
      return null;
    }

    const uri = events.CAEP_PREFIX + short;
    const values: Record<string, any> = {};
    // THE USER AGENT'S FINGERPRINT (#145), on the two events CAEP gives the
    // member to, where the act arrived with a request to read it from.
    const headers = (asked.req && asked.req.headers) || {};
    const fingerprint = stsCrypto.userAgentFingerprint(
      headers['user-agent'] || '');
    if (act === 'established') {
      values.acr = row.acr;
      values.amr = row.amr;
      values.ext_id = sessionId;
      if (fingerprint) {
        values.fp_ua = fingerprint;
      }
    }
    if (act === 'presented') {
      values.ext_id = sessionId;
      if (fingerprint) {
        values.fp_ua = fingerprint;
      }
    }
    if (act === 'reauthenticated') {
      values.namespace = ACR_NAMESPACE;
      values.current_level = row.acr;
      if (previousAcr) {
        values.previous_level = previousAcr;
      }
      // Said outright where both levels are on the scale, and omitted where
      // one is not: CAEP makes the member optional precisely so that a
      // transmitter never has to guess an order it does not have.
      const from = stepUp.LEVELS.indexOf(previousAcr);
      const to = stepUp.LEVELS.indexOf(row.acr);
      if (from >= 0 && to >= 0 && from !== to) {
        values.change_direction = to > from ? 'increase' : 'decrease';
      }
    }
    // WHO INITIATED IT, in CAEP section 2's four words.
    //
    // The notice's own answer wins where it has one, and the one caller that
    // gives one is the SESSION EXPIRY (2026-09-04), which is `policy`: nobody
    // initiated it — a lifetime this service configured ran out, which is
    // exactly what that word is for. Without this the choice was `admin` or
    // `user`, and an expiry would have gone out claiming a person signed out,
    // which is a receiver being told something false about a session rather
    // than merely something vague.
    const entity = ['admin', 'user', 'policy', 'system']
      .indexOf(String(asked.initiatingEntity || '')) >= 0
        ? String(asked.initiatingEntity)
        : (act === 'revoked' ? (asked.byAdmin ? 'admin' : 'user') : 'user');
    const payload = this.buildPayload(uri, values, {
      initiatingEntity: entity,
      reasonAdmin: asked.reason || this.reasonFor(act, asked),
      reasonUser: this.reasonForUser(act, asked)
    });
    audit.audit({ action: 'caep.event.auto', category: 'signals',
      protocol: 'CAEP', channel: 'http', target: sessionId,
      summary: 'A CAEP ' + short + ' is due for session ' + sessionId,
      detail: { type: uri, via: String(asked.via || '') } });
    log.debug("Leaving CaepRegister.observe(). " + short + ' is due.');
    return { uri: uri, payload: payload, subject: this.subjectFor(row),
             row: row };
  }

  // The administrative sentence, in words, for a person reading a log at the
  // far end. It says WHAT HAPPENED HERE rather than what the receiver should
  // do, which is the division CAEP draws: the transmitter reports, the
  // receiver decides.
  private reasonFor(act: string, notice?: Record<string, any>): string {
    const { helpers: { log } } = this.deps;
    log.debug("Entering CaepRegister.reasonFor(). " + act);
    const via = String((notice || {}).via || 'this service');
    let text = '';
    if (act === 'established') {
      text = 'A session was created at ' + via + '.';
    } else if (act === 'presented') {
      text = 'An existing session was presented at ' + via + ' and ' +
        'honoured without a new authentication.';
    } else if (act === 'reauthenticated') {
      text = 'The person re-authenticated at ' + via + ' on a session they ' +
        'already held, and its assurance changed. The session was not ended.';
    } else {
      text = 'The session was ended at ' + via + '.';
    }
    log.debug("Leaving CaepRegister.reasonFor().");
    return text;
  }

  private reasonForUser(act: string, notice?: Record<string, any>): string {
    const { helpers: { log } } = this.deps;
    log.debug("Entering CaepRegister.reasonForUser(). " + act);
    // AN EXPIRY IS NOT A SIGN-OUT AND THE PERSON HAS TO BE TOLD THE
    // DIFFERENCE. `reason_user` is the sentence a receiver may show them, and
    // "you have been signed out" for a session that simply ran out is the
    // wording that makes somebody go looking for who signed them out.
    if (act === 'revoked' && (notice || {}).expired) {
      log.debug("Leaving CaepRegister.reasonForUser(). Expired.");
      return 'Your session expired. Sign in again to carry on.';
    }
    let text = 'You are still signed in.';
    if (act === 'revoked') {
      text = 'You have been signed out.';
    } else if (act === 'established') {
      text = 'You signed in.';
    } else if (act === 'reauthenticated') {
      text = 'You confirmed who you are again, and you are still signed in.';
    }
    log.debug("Leaving CaepRegister.reasonForUser().");
    return text;
  }

  // Put one row back to where a fresh session starts, keeping the row. It is
  // a RESET rather than a delete because the identity and the sign-in instant
  // are still true — what is being thrown away is what CAEP has said about it
  // — and a delete would take the row off the page, which reads as the
  // session having gone.
  reset(sessionId: unknown): CaepRow | null {
    const { helpers: { log, iso }, audit } = this.deps;
    log.debug("Entering CaepRegister.reset(). " + sessionId);
    const row = register.get(String(sessionId || ''));
    if (!row) {
      log.debug("Leaving CaepRegister.reset(). No such row.");
      return null;
    }
    row.state = 'established';
    row.assurance = { namespace: '', level: '', previousLevel: '' };
    row.compliance = '';
    row.risk = { level: '', previousLevel: '', reason: '' };
    row.claims = {};
    row.credentials = [];
    row.counts = {};
    row.total = 0;
    row.events = [];
    row.streams = [];
    row.notes = ['Reset from the console; the sign-in itself is untouched.'];
    row.updatedAt = iso();
    this.touch(row);
    audit.audit({ action: 'caep.session.reset', category: 'signals',
      protocol: 'CAEP', channel: 'http', target: row.sessionId,
      summary: 'The CAEP state of session ' + row.sessionId + ' was reset' });
    log.debug("Leaving CaepRegister.reset(). Done.");
    return row;
  }

  clear(): number {
    const { helpers: { log }, audit } = this.deps;
    log.debug("Entering CaepRegister.clear().");
    const gone = register.size;
    register.clear();
    audit.audit({ action: 'caep.session.clear', category: 'signals',
      protocol: 'CAEP', channel: 'http', target: 'caep',
      summary: gone + ' CAEP session row(s) were dropped' });
    log.debug("Leaving CaepRegister.clear(). " + gone + ' dropped.');
    return gone;
  }

  // -------------------------------------------------------------------------
  // THE REPORT, drawn by /admin/caep-sessions and answered by GET
  // /admin-api/caep. ONE function, so the page and the API cannot come to
  // disagree about what this transmitter has said — which is rule 7's whole
  // subject.
  // -------------------------------------------------------------------------
  report(): Record<string, any> {
    const { helpers: { log }, config, events, subjects } = this.deps;
    log.debug("Entering CaepRegister.report().");
    const types = events.CAEP_EVENTS.map(function (row) {
      return { uri: row.uri, name: row.name,
        short: row.uri.slice(events.CAEP_PREFIX.length) };
    });
    const totals = {};
    types.forEach(function (type) {
      totals[type.uri] = 0;
    });
    const sessions = this.list().map((row) => {
      Object.keys(row.counts).forEach(function (uri) {
        totals[uri] = (totals[uri] || 0) + row.counts[uri];
      });
      return {
        sessionId: row.sessionId,
        sub: row.sub,
        username: row.username,
        iss: row.iss,
        protocol: row.protocol,
        establishedAt: row.establishedAt,
        updatedAt: row.updatedAt,
        state: row.state,
        acr: row.acr,
        amr: row.amr.slice(),
        assurance: Object.assign({}, row.assurance),
        compliance: row.compliance,
        risk: Object.assign({}, row.risk),
        claims: Object.assign({}, row.claims),
        credentials: row.credentials.slice(),
        counts: Object.assign({}, row.counts),
        total: row.total,
        events: row.events.slice(),
        streams: row.streams.slice(),
        notes: row.notes.slice(),
        subject: subjects.describeSubject(this.subjectFor(row))
      };
    }).reverse();
    const out = {
      enabled: this.enabled(),
      autoEmit: !!config.value('caep.autoEmit'),
      autoEmitActs: this.autoEmitActs().map(function (act) {
        return AUTO_ACTS[act];
      }),
      omitEventTimestamp: !!config.value('caep.omitEventTimestamp'),
      eventTypes: types,
      totals: totals,
      sessions: sessions,
      tracked: sessions.length,
      cap: Number(config.value('caep.maxSessionsTracked')) || 200
    };
    log.debug("Leaving CaepRegister.report(). " + out.tracked +
              ' session(s).');
    return out;
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before.
  static defaultDeps(): CaepRegisterDeps {
    helpers.log.debug("Entering CaepRegister.defaultDeps().");
    helpers.log.debug("Leaving CaepRegister.defaultDeps().");
    return {
      helpers: helpers,
      config: config,
      audit: audit,
      events: events,
      subjects: subjects,
      stepUp: stepUp,
      claimAttributes: claimAttributes,
      groupClaims: groupClaims
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<CaepRegister>(
  'ssf/caep',
  () => new CaepRegister(CaepRegister.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  CaepRegister: CaepRegister,
  installInstance: (instance: CaepRegister): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  AUTO_ACTS: CaepRegister.AUTO_ACTS,
  enabled: slot.forward('enabled'),
  supportedEventUris: slot.forward('supportedEventUris'),
  autoEmitActs: slot.forward('autoEmitActs'),
  claimsChangeFor: slot.forward('claimsChangeFor'),
  subjectFor: slot.forward('subjectFor'),
  sessionIdOf: slot.forward('sessionIdOf'),
  rowFor: slot.forward('rowFor'),
  get: slot.forward('get'),
  list: slot.forward('list'),
  commonClaims: slot.forward('commonClaims'),
  buildPayload: slot.forward('buildPayload'),
  applyToState: slot.forward('applyToState'),
  noteTransmitted: slot.forward('noteTransmitted'),
  observe: slot.forward('observe'),
  reset: slot.forward('reset'),
  clear: slot.forward('clear'),
  report: slot.forward('report')
};
