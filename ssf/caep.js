// @ts-check
'use strict';
//
// File: caep.js
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
// `ssf_subjects` and the route-free `oauth-oidc/step_up.js`, and nothing else,
// so it cannot join a cycle — and in particular it does NOT require `ssf.js`,
// which requires IT. That is what decides the division of labour and it is
// worth stating plainly because it looks arbitrary from either side:
//
//   THIS FILE DECIDES WHAT AN EVENT WOULD BE. `observe()` takes a notice
//   about a session, updates the register, and ANSWERS with the event that
//   ought to go out — or with null.
//
//   `ssf.js` DECIDES WHERE IT GOES. It holds `transmit()`, the streams and
//   the deliveries, so it takes that answer and sends it on every stream that
//   agreed to the type and whose subjects cover the session.
//
// A version of this file that sent the event itself would have had to require
// `ssf.js`, and `ssf.js` requires this one for the register — a cycle, and the
// second require would have moved every `/ssf` route.
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

const { log, nowSec, iso } = require('../common/helpers');
const config = require('../common/config');
// The partition. A LEAF requiring `config` and the error-code registry and
// nothing else here.
const realms = require('../common/realms');
const audit = require('../common/audit');
const events = require('./ssf_events');
const subjects = require('./ssf_subjects');

// The acts this service can actually OBSERVE, and their event types — three
// at first, five now (the fourth and fifth are marked below). Written as short
// names because that is what `caep.autoEmitTypes` holds — a setting whose
// values were 60-character URIs would be a setting nobody could type. The
// other three CAEP events are things nothing here observes on a sign-on
// session: no device reports compliance to this service and no risk engine
// talks to it (`token-claims-change` is sent only by GNAP, through
// `gnap/gnap_signals.js`), so they are emitted by hand and a row naming one of
// them is dropped with a warning rather than producing an event nothing can
// cause.
const AUTO_ACTS = {
  established: 'session-established',
  presented: 'session-presented',
  revoked: 'session-revoked',
  // THE FOURTH (2026-09-13), and the first that is not about a session: an
  // administrator changing somebody's credentials from their /admin/users page
  // or /admin-api/users, or the person spending a password reset link. It goes
  // out through `ssf.js`'s `emitCredentialChange()` rather than through
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
  reauthenticated: 'assurance-level-change'
};

// THE SCALE THIS SERVICE'S OWN LEVELS ARE ON, and it is deliberately not
// `caep.assuranceNamespace` (NIST-AAL), which stays the default for an event
// emitted BY HAND. `0`, `1` and `mfa` are what `authn.js` records and what
// every token here carries in `acr`; mapping them onto NIST's AALs would
// assert a conformance nobody assessed. CAEP's namespace list is an open enum,
// so a private URN is carried with a warning at worst, and a receiver sees the
// level spelt exactly as the tokens it already holds spell it (rcbj's choice).
const ACR_NAMESPACE = 'urn:sts:acr';

// The ORDER of those levels is `oauth-oidc/step_up.js`'s, required rather than
// written out again: RFC 9470's "a stronger authentication satisfies a request
// for a weaker one" and this file's `change_direction` are one ordering, and
// two copies would disagree the first time a level was added. step_up.js is a
// library over `common/` and registers no route, so the require moves nothing
// and closes no cycle.
const stepUp = require('../oauth-oidc/step_up');

// How many events one row remembers. It is a RING and not a total — the total
// is on `counts`, which never forgets — because the list exists so that a
// reader can see the last few `jti`s and the counts exist so that a reader can
// see how many there have been, and conflating the two would make a page that
// says "3 events" under a list of three when there were nine.
//
// `caep.eventsPerSession` since 2026-09-12 (25, the old constant, is its
// default); read per event. `caep.historyPerSession` is the same thing for the
// credential-change list below, which was a literal 10.
function eventsPerSession() {
  log.debug("Entering eventsPerSession().");
  log.debug("Leaving eventsPerSession().");
  return config.value('caep.eventsPerSession');
}

function historyPerSession() {
  log.debug("Entering historyPerSession().");
  log.debug("Leaving historyPerSession().");
  return config.value('caep.historyPerSession');
}

// sessionId -> row. Insertion-ordered, which is what makes "the oldest goes"
// one `keys().next()` rather than a sort by a timestamp two rows can share.
//
// PER TRUST REALM — a session belongs to the realm that minted it, and so does
// what CAEP has said about it. The realm is the AMBIENT one: `observe()` is
// reached from `authn.js`'s session store inside the request or the
// realm-scoped expiry sweep, and `noteTransmitted()` from `ssf.js`'s
// `transmit()`, whose streams are per realm already. `caep.maxSessionsTracked`
// caps each realm's partition rather than the process, which is what a cap read
// in a realm means.
const register = realms.map({ persist: 'caep.register' });

// A ROW EDITED IN PLACE, REPORTED TO THE JOURNAL. `realms.map()` journals a
// `set()` and a `delete()`; almost everything this file does to a row is
// `row.counts[uri] += 1` on an object already in the map, which nothing sees.
// Re-setting the same key reports it — and keeps its place in the map's
// insertion order, so "the oldest goes" still means the oldest. A row trimmed
// out before the edit is NOT put back, and neither is a row another process's
// write has since REPLACED — which is why this asks whether the object it was
// handed is still the one held: the edit belongs to a row the register has
// already let go.
function touch(row) {
  log.debug("Entering touch().");
  if (!row || !row.sessionId) {
    log.debug("Leaving touch().");
    return;
  }
  if (register.get(row.sessionId) === row) {
    register.set(row.sessionId, row);
  }
  log.debug("Leaving touch().");
}

function enabled() {
  log.debug('Entering enabled().');
  const on = !!config.value('caep.enabled');
  log.debug('Leaving enabled(). ' + on);
  return on;
}

// The eight URIs, or none at all when the profile is off. `ssf.js` unions this
// with SSF's own two to decide what a stream may request — so turning CAEP off
// narrows what this transmitter will agree to, which is what makes a
// receiver's "you would not deliver the type I asked for" path reachable
// without anybody editing ssf.eventsSupported by hand.
function supportedEventUris() {
  log.debug('Entering supportedEventUris().');
  if (!enabled()) {
    log.debug('Leaving supportedEventUris(). CAEP is off.');
    return [];
  }
  const out = events.CAEP_EVENT_URIS.slice();
  log.debug('Leaving supportedEventUris(). ' + out.length + ' type(s).');
  return out;
}

// Which of the five acts emit on their own. An entry naming an event this
// service cannot cause is DROPPED WITH A WARNING rather than honoured: there
// is no code path that would ever fire it, so honouring it would leave a
// setting that reads as configured and does nothing.
function autoEmitActs() {
  log.debug('Entering autoEmitActs().');
  if (!enabled() || !config.value('caep.autoEmit')) {
    log.debug('Leaving autoEmitActs(). Off.');
    return [];
  }
  const asked = config.value('caep.autoEmitTypes');
  const list = Array.isArray(asked) ? asked : String(asked || '').split(',');
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
      log.warn('caep.autoEmitTypes names "' + name + '", which is not one ' +
               'of the ' + Object.keys(AUTO_ACTS).length + ' acts this ' +
               'service can observe (' +
               Object.keys(AUTO_ACTS).map(function (act) {
                 return AUTO_ACTS[act];
               }).join(', ') + '). It is DROPPED — nothing here would ever ' +
               'fire it, so honouring it would leave a setting that reads ' +
               'as configured and does nothing. Emit that type by hand from ' +
               '/admin/caep.');
      return;
    }
    if (chosen.indexOf(names[short]) < 0) {
      chosen.push(names[short]);
    }
  });
  log.debug('Leaving autoEmitActs(). ' + chosen.length + ' act(s).');
  return chosen;
}

// ---------------------------------------------------------------------------
// THE SUBJECT, AND WHY IT IS A COMPLEX ONE.
//
// SSF 1.0 section 4 lets a `sub_id` be an object whose members are each
// themselves a subject identifier, and CAEP is the reason that exists: the
// person is not revoked, ONE SESSION OF THEIRS IS. A subject naming only the
// person asks a receiver to end every session they have, which is a different
// and much larger instruction than the one that was meant.
//
// `user` is an issuer/subject pair because that is the identifier a receiver
// already holds — it is what an ID Token's `iss` and `sub` say. `session` is
// `opaque` because a session identifier has no shape anybody else can parse
// and RFC 9493 says so by defining no rule for that format's `id`.
//
// **`critical_subject_members` IS WHAT WOULD MAKE THIS SAFE, AND IT IS EMPTY BY
// DEFAULT HERE.** Publishing `session` in that member of the transmitter
// metadata promises something worth promising: a receiver that does not
// understand the member MUST refuse the event rather than act on the person
// named beside it, which is precisely the failure this shape invites — a
// receiver that reads `user` and ignores `session` ends every session that
// person has, from an event that named one. `ssf.criticalSubjectMembers`
// publishes it and ships EMPTY, because turning it on makes every complex
// subject refusable by a receiver that has not been told, and this is a
// debugger whose job is to let both cases be seen. Set it to `session` to
// find out whether a receiver under test honours it.
// ---------------------------------------------------------------------------
function subjectFor(row) {
  log.debug('Entering subjectFor().');
  const subject = {
    user: { format: 'issuer_subject_id', iss: String(row.iss || ''),
      sub: String(row.sub || '') },
    session: { format: 'opaque', id: String(row.sessionId || '') }
  };
  if (row.deviceId) {
    subject.device = { format: 'opaque', id: String(row.deviceId) };
  }
  if (row.tenant) {
    subject.tenant = { format: 'opaque', id: String(row.tenant) };
  }
  log.debug('Leaving subjectFor(). ' + subjects.describeSubject(subject));
  return subject;
}

// The session id out of a subject this service — or anybody else — composed.
// It reads the COMPLEX shape only: a plain subject names a person and this
// register is about sessions, so a plain one legitimately matches nothing and
// the caller counts the event against the stream rather than against a row.
function sessionIdOf(subject) {
  log.debug('Entering sessionIdOf().');
  const body = (subject && typeof subject === 'object' &&
                !Array.isArray(subject)) ? subject : null;
  const session = body && body.session;
  const id = (session && typeof session === 'object' &&
              typeof session.id === 'string') ? session.id : '';
  log.debug('Leaving sessionIdOf(). ' + (id || '(none)'));
  return id;
}

// ---------------------------------------------------------------------------
// THE ROW.
//
// `state` is CAEP's view and NOT the session store's. They disagree on purpose
// in one direction: a row stays `revoked` after `authn.js` has forgotten the
// session entirely, because the row is the evidence. They can also disagree
// the other way — a session this service still holds whose row says `revoked`
// means somebody emitted a revocation by hand — and the page says so rather
// than reconciling, since which of the two is wrong is the question.
// ---------------------------------------------------------------------------
function blankRow(seed) {
  log.debug('Entering blankRow().');
  const asked = seed || {};
  const row = {
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
  log.debug('Leaving blankRow(). ' + row.sessionId);
  return row;
}

function trim() {
  log.debug('Entering trim().');
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
  log.debug('Leaving trim(). ' + dropped + ' dropped.');
  return dropped;
}

// Find the row, or make one. A CAEP event emitted by hand about a session this
// service never held is legitimate — a debugger pointing at this transmitter
// is entitled to name whatever subject it likes — so an unknown id gets a row
// saying where it came from rather than being refused.
function rowFor(sessionId, seed) {
  log.debug('Entering rowFor(). ' + sessionId);
  const id = String(sessionId || '');
  if (!id) {
    log.debug('Leaving rowFor(). No id.');
    return null;
  }
  let row = register.get(id);
  if (!row) {
    row = blankRow(Object.assign({ sessionId: id }, seed || {}));
    row.notes.push('This row was created by an event rather than by a ' +
        'sign-in, so nothing here has ever held this session.');
    register.set(id, row);
    trim();
  }
  log.debug('Leaving rowFor(). ' + id);
  return row;
}

function get(sessionId) {
  log.debug('Entering get().');
  const row = register.get(String(sessionId || '')) || null;
  log.debug('Leaving get(). ' + (row ? 'found' : 'not found'));
  return row;
}

function list() {
  log.debug('Entering list().');
  const out = Array.from(register.values());
  log.debug('Leaving list(). ' + out.length + ' row(s).');
  return out;
}

// ---------------------------------------------------------------------------
// THE FOUR COMMON CLAIMS (CAEP section 2).
//
// All four are OPTIONAL, and `event_timestamp` being optional is the fact this
// whole block exists to make visible: a receiver deciding whether to end a
// session wants it more than anything else in the payload, and a conforming
// transmitter need not send one. `caep.omitEventTimestamp` produces exactly
// that event on purpose.
//
// `reason_admin` and `reason_user` are OBJECTS KEYED BY A LANGUAGE TAG. That
// is the commonest mistake in the profile and the one with no symptom: a
// receiver indexing by language reads nothing from a string and reports no
// error. This service always sends the object shape.
// ---------------------------------------------------------------------------
function commonClaims(options) {
  log.debug('Entering commonClaims().');
  const asked = options || {};
  const out = {};
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
  log.debug('Leaving commonClaims(). ' + Object.keys(out).length + ' claim(s)');
  return out;
}

// A whole payload: the row's own generator, plus the four above. It is one
// function so that the console form, the management API and the automatic
// emission all produce the SAME shape — three builders would be three chances
// for one of them to forget `event_timestamp`.
function buildPayload(uri, values, options) {
  log.debug('Entering buildPayload(). ' + uri);
  const row = events.EVENT_BY_URI[uri];
  if (!row) {
    log.debug('Leaving buildPayload(). Unknown type.');
    return {};
  }
  const payload = Object.assign({}, row.generate(values || {}),
                                commonClaims(options));
  log.debug('Leaving buildPayload(). ' + Object.keys(payload).length +
            ' member(s).');
  return payload;
}

// ---------------------------------------------------------------------------
// THE STATE MACHINE.
//
// What each event type does to a row, and the two places it says NO. Collected
// findings rather than a boolean, for the reason `ssf_subjects.js` gives about
// a form: an event built by hand is usually wrong in more than one way.
//
// **THE ONE HARD REFUSAL IS `session-presented` ON A REVOKED SESSION**, and it
// is worth the strictness: that sentence says a session this transmitter has
// already declared dead was just used and honoured, which is either a
// transmitter contradicting itself or a receiver about to be told to trust
// something it was told to stop trusting. Everything else that looks wrong is
// a WARNING, because this is a mock and refusing to carry an odd-looking event
// would remove the ability to reproduce one.
//
// `device-compliance-change` and `risk-level-change` both carry the PREVIOUS
// value, and comparing it against what this register holds is the check
// nothing else can make: a receiver holding "compliant" that gets an event
// whose `previous_status` is "not-compliant" has missed one, and that gap is
// invisible from either event on its own.
// ---------------------------------------------------------------------------
function applyToState(row, uri, payload) {
  log.debug('Entering applyToState(). ' + uri);
  const body = (payload && typeof payload === 'object') ? payload : {};
  const errors = [];
  const warnings = [];
  const short = uri.indexOf(events.CAEP_PREFIX) === 0
    ? uri.slice(events.CAEP_PREFIX.length) : '';

  if (!short) {
    log.debug('Leaving applyToState(). Not a CAEP event.');
    return { ok: true, errors: errors, warnings: warnings };
  }

  if (short === 'session-established') {
    if (row.state === 'revoked') {
      warnings.push('This session was revoked and is being established ' +
          'again. That is legitimate — the same identifier can be reused — ' +
          'and a receiver that kept the revocation will ignore everything ' +
          'about it from here on, so it is worth seeing.');
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
          'something it was told to stop trusting, and it is the one thing ' +
          'this register refuses outright.');
    } else {
      row.state = 'presented';
    }
  } else if (short === 'session-revoked') {
    if (row.state === 'revoked') {
      warnings.push('This session was already revoked. A second revocation ' +
          'is harmless and a receiver should be idempotent about it, which ' +
          'is exactly the thing worth testing.');
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
    row.credentials = row.credentials.slice(0, historyPerSession());
  } else if (short === 'assurance-level-change') {
    if (row.assurance.level && typeof body.previous_level === 'string' &&
        body.previous_level !== row.assurance.level) {
      warnings.push('This event says the previous assurance level was "' +
          body.previous_level + '" and this register holds "' +
          row.assurance.level + '". One event about this session has been ' +
          'missed, or two transmitters are talking about it.');
    }
    row.assurance = {
      namespace: String(body.namespace || row.assurance.namespace || ''),
      level: String(body.current_level || ''),
      previousLevel: String(body.previous_level || row.assurance.level || '')
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
  touch(row);
  log.debug('Leaving applyToState(). ' + errors.length + ' error(s), ' +
            warnings.length + ' warning(s).');
  return { ok: errors.length === 0, errors: errors, warnings: warnings,
    state: row.state };
}

// ---------------------------------------------------------------------------
// COUNTING WHAT WENT OUT.
//
// Called from `ssf.js`'s `transmit()` after the SET has been built, so the
// counters are of things that were actually MINTED rather than of things
// somebody meant to send. It reads the session out of the token's own
// `sub_id`, which is what keeps `transmit()` from having to know anything
// about this register — a transmit for a plain subject legitimately counts
// against no row, and says so by returning null.
//
// **THE COUNT IS NOT THE LIST.** `counts` never forgets and `events` is a ring
// of the last few, because "how many session-revoked have gone out about this
// person" and "what were the last few jtis" are two different questions and a
// page that answered the first from the second would say three where there
// were nine.
// ---------------------------------------------------------------------------
function noteTransmitted(record, claims) {
  log.debug('Entering noteTransmitted().');
  if (!enabled()) {
    log.debug('Leaving noteTransmitted(). CAEP is off.');
    return null;
  }
  const uris = Object.keys((claims && claims.events) || {});
  const uri = uris[0] || '';
  if (uri.indexOf(events.CAEP_PREFIX) !== 0) {
    log.debug('Leaving noteTransmitted(). Not a CAEP event.');
    return null;
  }
  const sessionId = sessionIdOf(claims && claims.sub_id);
  if (!sessionId) {
    log.debug('Leaving noteTransmitted(). No session in the subject.');
    return null;
  }
  const row = rowFor(sessionId, {
    iss: String((claims && claims.iss) || ''),
    sub: String((((claims && claims.sub_id) || {}).user || {}).sub || '')
  });
  const verdict = applyToState(row, uri, (claims.events || {})[uri]);
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
  row.events = row.events.slice(0, eventsPerSession());
  const streamId = String((record && record.stream_id) || '');
  if (streamId && row.streams.indexOf(streamId) < 0) {
    row.streams.push(streamId);
  }
  touch(row);
  log.debug('Leaving noteTransmitted(). ' + row.total + ' event(s) on ' +
            row.sessionId + '.');
  return row;
}

// ---------------------------------------------------------------------------
// A SESSION CHANGED, AND WHAT — IF ANYTHING — SHOULD GO OUT.
//
// `ssf.js` installs this as `authn.setSessionObserver()`'s function and sends
// what comes back. It updates the register EVEN WHEN NOTHING WILL BE SENT,
// which is deliberate: a service with no streams agreed still has sessions,
// and /admin/caep-sessions showing them with a count of zero is how somebody
// finds out that the reason no event arrived is that nobody asked for one.
// ---------------------------------------------------------------------------
function observe(notice) {
  log.debug('Entering observe().');
  const asked = notice || {};
  const act = String(asked.kind || '');
  const session = asked.session || {};
  const sessionId = String(session.id || '');
  if (!enabled() || !sessionId) {
    log.debug('Leaving observe(). Off, or no session.');
    return null;
  }
  let row = register.get(sessionId);
  if (!row) {
    row = blankRow({
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
    trim();
  }
  if (asked.issuer && !row.iss) {
    row.iss = String(asked.issuer);
  }
  row.updatedAt = iso();
  // A RE-AUTHENTICATION MOVES WHAT THE ROW SAYS THE SESSION IS, whether or not
  // anything goes out — the register follows the ACT, as it does for a
  // revocation with emission off. And it is only an EVENT when `acr` moved:
  // an elapsed `max_age` answered with the same method is a fresh `auth_time`
  // and nothing a receiver's decision could turn on.
  let previousAcr = '';
  if (act === 'reauthenticated') {
    previousAcr = String(((asked.previous || {}).acr) || row.acr || '');
    row.acr = String(session.acr || '');
    row.amr = Array.isArray(session.amr) ? session.amr.slice() : [];
    if (previousAcr === row.acr) {
      touch(row);
      log.debug('Leaving observe(). A re-authentication that left acr at "' +
                row.acr + '"; nothing to emit.');
      return null;
    }
  }
  touch(row);

  const short = AUTO_ACTS[act];
  if (!short) {
    log.debug('Leaving observe(). Nothing to emit for "' + act + '".');
    return null;
  }
  if (autoEmitActs().indexOf(act) < 0) {
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
    touch(row);
    log.debug('Leaving observe(). Emission is off for ' + act + '.');
    return null;
  }

  const uri = events.CAEP_PREFIX + short;
  const values = {};
  if (act === 'established') {
    values.acr = row.acr;
    values.amr = row.amr;
    values.ext_id = sessionId;
  }
  if (act === 'presented') {
    values.ext_id = sessionId;
  }
  if (act === 'reauthenticated') {
    values.namespace = ACR_NAMESPACE;
    values.current_level = row.acr;
    if (previousAcr) {
      values.previous_level = previousAcr;
    }
    // Said outright where both levels are on the scale, and omitted where one
    // is not: CAEP makes the member optional precisely so that a transmitter
    // never has to guess an order it does not have.
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
  const payload = buildPayload(uri, values, {
    initiatingEntity: entity,
    reasonAdmin: asked.reason || reasonFor(act, asked),
    reasonUser: reasonForUser(act, asked)
  });
  audit.audit({ action: 'caep.event.auto', category: 'signals',
    protocol: 'CAEP', channel: 'http', target: sessionId,
    summary: 'A CAEP ' + short + ' is due for session ' + sessionId,
    detail: { type: uri, via: String(asked.via || '') } });
  log.debug('Leaving observe(). ' + short + ' is due.');
  return { uri: uri, payload: payload, subject: subjectFor(row), row: row };
}

// The administrative sentence, in words, for a person reading a log at the far
// end. It says WHAT HAPPENED HERE rather than what the receiver should do,
// which is the division CAEP draws: the transmitter reports, the receiver
// decides.
function reasonFor(act, notice) {
  log.debug('Entering reasonFor(). ' + act);
  const via = String((notice || {}).via || 'this service');
  let text = '';
  if (act === 'established') {
    text = 'A session was created at ' + via + '.';
  } else if (act === 'presented') {
    text = 'An existing session was presented at ' + via + ' and honoured ' +
      'without a new authentication.';
  } else if (act === 'reauthenticated') {
    text = 'The person re-authenticated at ' + via + ' on a session they ' +
      'already held, and its assurance changed. The session was not ended.';
  } else {
    text = 'The session was ended at ' + via + '.';
  }
  log.debug('Leaving reasonFor().');
  return text;
}

function reasonForUser(act, notice) {
  log.debug('Entering reasonForUser(). ' + act);
  // AN EXPIRY IS NOT A SIGN-OUT AND THE PERSON HAS TO BE TOLD THE DIFFERENCE.
  // `reason_user` is the sentence a receiver may show them, and "you have been
  // signed out" for a session that simply ran out is the wording that makes
  // somebody go looking for who signed them out.
  if (act === 'revoked' && (notice || {}).expired) {
    log.debug('Leaving reasonForUser(). Expired.');
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
  log.debug('Leaving reasonForUser().');
  return text;
}

// Put one row back to where a fresh session starts, keeping the row. It is a
// RESET rather than a delete because the identity and the sign-in instant are
// still true — what is being thrown away is what CAEP has said about it — and
// a delete would take the row off the page, which reads as the session having
// gone.
function reset(sessionId) {
  log.debug('Entering reset(). ' + sessionId);
  const row = register.get(String(sessionId || ''));
  if (!row) {
    log.debug('Leaving reset(). No such row.');
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
  touch(row);
  audit.audit({ action: 'caep.session.reset', category: 'signals',
    protocol: 'CAEP', channel: 'http', target: row.sessionId,
    summary: 'The CAEP state of session ' + row.sessionId + ' was reset' });
  log.debug('Leaving reset(). Done.');
  return row;
}

function clear() {
  log.debug('Entering clear().');
  const gone = register.size;
  register.clear();
  audit.audit({ action: 'caep.session.clear', category: 'signals',
    protocol: 'CAEP', channel: 'http', target: 'caep',
    summary: gone + ' CAEP session row(s) were dropped' });
  log.debug('Leaving clear(). ' + gone + ' dropped.');
  return gone;
}

// ---------------------------------------------------------------------------
// THE REPORT, drawn by /admin/caep-sessions and answered by GET
// /admin-api/caep. ONE function, so the page and the API cannot come to
// disagree about what this transmitter has said — which is rule 7's whole
// subject.
// ---------------------------------------------------------------------------
function report() {
  log.debug('Entering report().');
  const types = events.CAEP_EVENTS.map(function (row) {
    return { uri: row.uri, name: row.name,
      short: row.uri.slice(events.CAEP_PREFIX.length) };
  });
  const totals = {};
  types.forEach(function (type) {
    totals[type.uri] = 0;
  });
  const sessions = list().map(function (row) {
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
      subject: subjects.describeSubject(subjectFor(row))
    };
  }).reverse();
  const out = {
    enabled: enabled(),
    autoEmit: !!config.value('caep.autoEmit'),
    autoEmitActs: autoEmitActs().map(function (act) {
      return AUTO_ACTS[act];
    }),
    omitEventTimestamp: !!config.value('caep.omitEventTimestamp'),
    eventTypes: types,
    totals: totals,
    sessions: sessions,
    tracked: sessions.length,
    cap: Number(config.value('caep.maxSessionsTracked')) || 200
  };
  log.debug('Leaving report(). ' + out.tracked + ' session(s).');
  return out;
}

module.exports = {
  AUTO_ACTS: AUTO_ACTS,
  enabled: enabled,
  supportedEventUris: supportedEventUris,
  autoEmitActs: autoEmitActs,
  subjectFor: subjectFor,
  sessionIdOf: sessionIdOf,
  rowFor: rowFor,
  get: get,
  list: list,
  commonClaims: commonClaims,
  buildPayload: buildPayload,
  applyToState: applyToState,
  noteTransmitted: noteTransmitted,
  observe: observe,
  reset: reset,
  clear: clear,
  report: report
};
