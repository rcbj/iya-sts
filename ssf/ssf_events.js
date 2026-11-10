// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssf_events.js
//
// ---------------------------------------------------------------------------
// THE EVENT TYPES THIS TRANSMITTER SPEAKS, AND THE SECURITY EVENT TOKEN THEY
// TRAVEL IN (RFC 8417).
//
// The Shared Signals Framework is a PIPE. It defines how two parties agree a
// stream, who the events are about and how they get delivered, and it defines
// almost no events of its own — the vocabularies are CAEP (what happened to a
// session) and RISC (what happened to an account), which are separate
// specifications layered over this one.
//
// SSF 1.0 itself defines exactly two, and both are about the pipe rather than
// about the person:
//
//   verification     the receiver asked "is this stream alive?" and this is
//                    the answer travelling the ordinary delivery path. It is
//                    the ONLY end-to-end test of a stream that exists — a
//                    200 from the management API says the configuration was
//                    accepted and says nothing about whether an event can
//                    reach the receiver.
//   stream updated   the stream's own status changed, and the receiver is
//                    being told IN BAND rather than having to poll the status
//                    endpoint.
//
// **THIS FILE IS DELIBERATELY THE WHOLE OF THE VOCABULARY**, and it carries all
// three: SSF's two rows, CAEP's eight (2026-09-03) and RISC's fourteen
// (2026-09-04).
// The promise this header made while it had two rows in it was that adding a
// vocabulary would be rows in `EVENTS` below and nothing else, and that is
// what happened — the SET envelope, the subject grammar, the queues, the
// deliveries and the stream management were not touched, because none of them
// names an event type. Two things outside this file did change, and neither is
// vocabulary: `caep.js` holds the SESSION REGISTER, which is what a CAEP event
// is ABOUT, and `transmit()` gained the refusal for an event whose row says it
// must carry a subject. RISC, the third, cost this file's machinery nothing
// (see its section below); `risc.js` is its register.
//
// ---------------------------------------------------------------------------
// WHAT A SET IS, AND THE THREE THINGS IMPLEMENTATIONS GET WRONG.
//
// A SET is a JWT (RFC 8417) whose payload carries an `events` object — a map
// from event-type URI to that event's own payload. Not an array, and not a
// single event: the map is what lets one token carry a set of events that
// happened together, and it is why the media type says "secevent" rather than
// "event".
//
//   * **`typ` IS `secevent+jwt` AND IT MATTERS.** RFC 8417 section 2.2 makes
//     it a SHOULD, and a receiver that dispatches on it — several do — drops a
//     token without it on the floor with no error anybody sees.
//   * **THERE IS NO `exp` AND THAT IS NOT AN OVERSIGHT.** RFC 8417 section
//     4.1.4 says a SET MUST NOT be considered to expire: it records that
//     something HAPPENED, and a fact does not stop being true. An
//     implementation that adds one is asking receivers to discard history.
//   * **`sub` IS NOT THE SUBJECT.** RFC 8417 section 2.2 says the `sub` claim
//     is discouraged and SSF uses `sub_id` (RFC 9493) instead, because `sub`
//     is a string and the thing an event is about is a structured identifier
//     that may name a person, a device and a session at once. This service
//     emits `sub_id` and never `sub`, and `ssf.legacySubClaim` puts one back
//     for a client that has to be tested against a transmitter that gets this
//     wrong.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3). It registers no route. It requires `helpers.js`
// (for the logger and for `signJwtAs`, which is where every algorithm this
// service can sign with already lives), `config.js`, `common/crypto.js` (see
// below) and `ssf_subjects.js`, and nothing else here — so it cannot join a
// cycle.
//
// **THE SIGNATURE GOES THROUGH `helpers.signJwtAs()` AND NOT THROUGH A SIGNER
// OF ITS OWN**, which is what gives this family every algorithm the rest of
// the service has, POST-QUANTUM ONES INCLUDED, for no code at all: ML-DSA at
// three sizes, SLH-DSA at two and the six composite ML-DSA + traditional
// algorithms are already in that table because a client can ask for them on an
// ID Token. `ssf.signingAlgorithm` picks one. A SET is exactly the document
// where that matters most — it is a durable record of something that happened,
// so it is read long after it was written, which is the case a
// harvest-now-decrypt-later argument is actually about.
// ---------------------------------------------------------------------------

const { log, signJwtAs, signJwtAsAsync, randomId, nowSec, allSigningKeys,
  STS, kidNamesKey } = require('../common/helpers');
const config = require('../common/config');
// A leaf (it requires only `config` and `error_codes`): the two deliberate
// defects below are read through `mode.valueInForce()`, which answers the
// default in a product realm (#104).
const mode = require('../common/mode');
// THE ONE PLACE THIS SERVICE VERIFIES A SIGNATURE, `common/crypto.js`
// (2026-09-10). `verifySet()` below is what reads a SET back, and it goes
// through that module like every other verification here. It is a LEAF (rule
// 3r) — it requires npm packages, the vendored `xmldsig.js`, `config` and a
// few leaves of its own, none of which requires this file — so this stays a
// library that cannot join a cycle.
const stsCrypto = require('../common/crypto');
const subjects = require('./ssf_subjects');
// The catalogue, the lists and the common members (#1579).
const SsfModel = require('./ssf_model');
const errorCodes = require('../common/error_codes');

// The URI prefix every SSF-defined event type shares. Written once because the
// two rows below and the two vocabularies that come after it all hang off it,
// and a typo in one of them produces an event a receiver silently ignores.
/**
 * The URI prefix every SSF-defined event type shares.
 */
const SSF_PREFIX = 'https://schemas.openid.net/secevent/ssf/event-type/';

// The two VOCABULARY prefixes. Both have rows in the table below now — CAEP's
// eight since 2026-09-03 and RISC's fourteen since 2026-09-04 — and they are
// written once each because a prefix is the thing most likely to be typed
// from memory and got subtly wrong: there is no "unknown event type" error in
// this protocol, so a receiver silently ignores a type it does not recognise
// and nobody finds out.
/**
 * The URI prefix of CAEP's event types.
 */
const CAEP_PREFIX = 'https://schemas.openid.net/secevent/caep/event-type/';
/**
 * The URI prefix of RISC's event types.
 */
const RISC_PREFIX = 'https://schemas.openid.net/secevent/risc/event-type/';

// The `typ` of a Security Event Token (RFC 8417 section 2.3). It is the media
// type without the `application/` prefix, which is what a JWT header carries.
/**
 * The `typ` of a Security Event Token (RFC 8417 section 2.3), `secevent+jwt`.
 */
const SET_MEDIA_TYPE = 'secevent+jwt';

// ---------------------------------------------------------------------------
// THE CATALOGUE, AND IT IS THE MODEL'S (#1579).
//
// Every event type this service knows — SSF 1.0's own two, CAEP 1.0's eight,
// RISC 1.0's fourteen and this service's own — is a model in
// `models/ssf/ssf_events.tsp`, whose properties are its payload members and
// whose TypeSpec types are their shapes. The rows below are BUILT from the
// generated table; what this file still writes is what a row DOES:
//
//   uri        the event type, which is the KEY in the SET's `events` map
//   family     which specification defines it — 'ssf', 'caep', 'risc' or
//              'sts'
//   subject    'none' | 'optional' | 'required'. SSF'S TWO ARE THE ONLY ONES
//              IN ANY OF THE THREE VOCABULARIES WITH NO SUBJECT AT ALL, and
//              it is worth knowing why: they are about the STREAM, not about
//              anybody, so a receiver that insists on a subject cannot be
//              verified.
//   subjectFormats
//              WHICH RFC 9493 FORMATS THE SUBJECT MAY BE IN, where the
//              specification narrows it — only RISC's two identifier events,
//              whose identifier IS the message. A property of the ROW rather
//              than a branch naming an event type, which is what keeps
//              `subjectAdvice()` below from being the vocabulary leaking out
//              of this table.
//   deprecated the event type that replaces this one, where its own
//              specification deprecates it (RISC's `sessions-revoked`).
//   members    the payload's own members, each `{ name, required, type,
//              values?, what }`; `required` on the row lists the required
//              names.
//   generate   builds a payload from the values a caller supplied, filling
//              what it can — `GENERATORS` below, by URI, so that "send me one
//              of these" is one call from the console, the management API and
//              the debugger alike. A row with no member generates `{}`; the
//              key-rotation family's rows share one generator read off the
//              row's own members.
//
// **CAEP'S FOUR COMMON MEMBERS ARE WRITTEN ONCE** (`CaepCommon`, spread onto
// every CAEP row), because eight copies of four member descriptions is eight
// places for a spelling to drift and there is no "unknown member" error in
// this protocol. **RISC GIVES THREE OF THEM, NO `initiating_entity`, TO ONE
// ROW OF FOURTEEN** (`RiscCommon`), and a reader porting CAEP's across would
// attach members thirteen specifications do not define.
//
// **THE CREDENTIAL TYPES ARE ONE LIST FOR TWO SPECIFICATIONS**: RISC 1.0
// section 2.7 defines credential-compromise's `credential_type` by reference
// to CAEP's, so the model has one `CredentialType` union both rows name. It
// is OPEN in both places, so a value outside it is carried with a warning.
//
// `event_timestamp` IS NOT THE SET's `toe` AND IT IS NOT `iat`: RFC 8417's
// `toe` is a claim on the token, this is a member of the payload, and a
// receiver that reads only one from a transmitter that sends only the other
// reads nothing.
// ---------------------------------------------------------------------------

/**
 * The three stream statuses of SSF 1.0 section 8.1.2, in the order a stream
 * moves through them: `enabled`, `paused` and `disabled`.
 */
const STATUSES = SsfModel.list('stream-statuses');

/**
 * The credential types CAEP's `credential-change` registers; the list is open,
 * and another value is carried with a warning.
 */
const CREDENTIAL_TYPES = SsfModel.list('credential-types');

/**
 * The four members CAEP section 2 gives every CAEP event type:
 * `event_timestamp`, `initiating_entity`, `reason_admin` and `reason_user`.
 */
const CAEP_COMMON_MEMBERS = SsfModel.common('caep');

/**
 * The three members RISC gives the event types that define them:
 * `event_timestamp`, `reason_admin` and `reason_user`.
 */
const RISC_COMMON_MEMBERS = SsfModel.common('risc');

/**
 * The URN prefix of this service's own event types.
 */
const STS_PREFIX = 'urn:iya:sts:secevent:event-type:';

// WHAT EACH ROW DOES: its payload from what a caller supplied, by URI. A row
// with no member, and the key-rotation family, are not here (see rowOf()).
const GENERATORS = {
  [SSF_PREFIX + 'verification']: function (values) {
    log.debug("Entering generate().");
    const payload = {};
    if (values && typeof values.state === 'string' && values.state !== '') {
      payload.state = values.state;
    }
    log.debug("Leaving generate().");
    return payload;
  },
  [SSF_PREFIX + 'stream-updated']: function (values) {
    log.debug("Entering generate().");
    const asked = values || {};
    const payload = {
      status: STATUSES.indexOf(asked.status) >= 0 ? asked.status : 'enabled'
    };
    if (typeof asked.reason === 'string' && asked.reason !== '') {
      payload.reason = asked.reason;
    }
    log.debug("Leaving generate().");
    return payload;
  },
  [CAEP_PREFIX + 'session-established']: function (values) {
    log.debug("Entering generate().");
    const asked = values || {};
    const payload = {};
    if (typeof asked.fp_ua === 'string' && asked.fp_ua !== '') {
      payload.fp_ua = asked.fp_ua;
    }
    if (typeof asked.acr === 'string' && asked.acr !== '') {
      payload.acr = asked.acr;
    }
    if (Array.isArray(asked.amr) && asked.amr.length) {
      payload.amr = asked.amr.slice();
    }
    if (typeof asked.ext_id === 'string' && asked.ext_id !== '') {
      payload.ext_id = asked.ext_id;
    }
    log.debug("Leaving generate().");
    return payload;
  },
  [CAEP_PREFIX + 'session-presented']: function (values) {
    log.debug("Entering generate().");
    const asked = values || {};
    const payload = {};
    if (typeof asked.fp_ua === 'string' && asked.fp_ua !== '') {
      payload.fp_ua = asked.fp_ua;
    }
    if (typeof asked.ext_id === 'string' && asked.ext_id !== '') {
      payload.ext_id = asked.ext_id;
    }
    log.debug("Leaving generate().");
    return payload;
  },
  [CAEP_PREFIX + 'token-claims-change']: function (values) {
    log.debug("Entering generate().");
    const asked = values || {};
    const claims = (asked.claims && typeof asked.claims === 'object' &&
                    !Array.isArray(asked.claims))
      ? asked.claims
      : { groups: ['everyone'] };
    log.debug("Leaving generate().");
    return { claims: claims };
  },
  [CAEP_PREFIX + 'credential-change']: function (values) {
    log.debug("Entering generate().");
    const asked = values || {};
    const payload = {
      credential_type: typeof asked.credential_type === 'string' &&
        asked.credential_type !== '' ? asked.credential_type : 'password',
      change_type: ['create', 'revoke', 'update', 'delete']
        .indexOf(asked.change_type) >= 0 ? asked.change_type : 'update'
    };
    ['friendly_name', 'x509_issuer', 'x509_serial', 'fido2_aaguid']
      .forEach(function (name) {
        if (typeof asked[name] === 'string' && asked[name] !== '') {
          payload[name] = asked[name];
        }
      });
    log.debug("Leaving generate().");
    return payload;
  },
  [CAEP_PREFIX + 'assurance-level-change']: function (values) {
    log.debug("Entering generate().");
    const asked = values || {};
    const payload = {
      namespace: typeof asked.namespace === 'string' &&
        asked.namespace !== ''
        ? asked.namespace
        : String(config.value('caep.assuranceNamespace') || 'NIST-AAL'),
      current_level: typeof asked.current_level === 'string' &&
        asked.current_level !== '' ? asked.current_level : 'aal2'
    };
    if (typeof asked.previous_level === 'string' &&
        asked.previous_level !== '') {
      payload.previous_level = asked.previous_level;
    }
    if (['increase', 'decrease'].indexOf(asked.change_direction) >= 0) {
      payload.change_direction = asked.change_direction;
    }
    log.debug("Leaving generate().");
    return payload;
  },
  [CAEP_PREFIX + 'device-compliance-change']: function (values) {
    log.debug("Entering generate().");
    const asked = values || {};
    const allowed = ['compliant', 'not-compliant'];
    log.debug("Leaving generate().");
    return {
      previous_status: allowed.indexOf(asked.previous_status) >= 0
        ? asked.previous_status : 'compliant',
      current_status: allowed.indexOf(asked.current_status) >= 0
        ? asked.current_status : 'not-compliant'
    };
  },
  [CAEP_PREFIX + 'risk-level-change']: function (values) {
    log.debug("Entering generate().");
    const asked = values || {};
    const levels = ['LOW', 'MEDIUM', 'HIGH'];
    const payload = {
      principal: typeof asked.principal === 'string' &&
        asked.principal !== '' ? asked.principal : 'SESSION',
      current_level: levels.indexOf(asked.current_level) >= 0
        ? asked.current_level
        : String(config.value('caep.defaultRiskLevel') || 'MEDIUM')
    };
    if (levels.indexOf(asked.previous_level) >= 0) {
      payload.previous_level = asked.previous_level;
    }
    if (typeof asked.risk_reason === 'string' && asked.risk_reason !== '') {
      payload.risk_reason = asked.risk_reason;
    }
    log.debug("Leaving generate().");
    return payload;
  },
  [RISC_PREFIX + 'account-disabled']: function (values) {
    log.debug("Entering generate().");
    const asked = values || {};
    const payload = {};
    if (typeof asked.reason === 'string' && asked.reason !== '') {
      payload.reason = asked.reason;
    }
    log.debug("Leaving generate().");
    return payload;
  },
  [RISC_PREFIX + 'identifier-changed']: function (values) {
    log.debug("Entering generate().");
    const asked = values || {};
    const payload = {};
    // **IT READS THE SPECIFICATION'S SPELLING AND ONLY THAT ONE, AND
    // ACCEPTING `new_value` HERE WAS THE FIRST THING THIS ROW DID WRONG.**
    // Correcting the underscore silently makes the console kind to a caller
    // and useless to one: this service exists so that somebody can find out
    // what their own transmitter is sending, and a mock that quietly repairs
    // the commonest mistake in this event type is a mock that hides it.
    // `validateEvent()` warns about the near-miss by name instead, which
    // says what happened rather than making it not have happened.
    if (typeof asked['new-value'] === 'string' && asked['new-value']) {
      payload['new-value'] = asked['new-value'];
    }
    log.debug("Leaving generate().");
    return payload;
  },
  [RISC_PREFIX + 'credential-compromise']: function (values) {
    log.debug("Entering generate().");
    const asked = values || {};
    log.debug("Leaving generate().");
    return {
      credential_type: typeof asked.credential_type === 'string' &&
        asked.credential_type !== '' ? asked.credential_type : 'password'
    };
  },
  [STS_PREFIX + 'signing-key-rotated']: function (values) {
    log.debug("Entering generate().");
    const v = values || {};
    const reasons = ['scheduled', 'requested', 'emergency'];
    const payload = {
      realm: String(v.realm || 'default'),
      rotated: String(v.rotated || ''),
      reason: reasons.indexOf(v.reason) >= 0 ? v.reason : 'requested',
      event_timestamp: Number(v.event_timestamp) ||
                       Math.floor(Date.now() / 1000)
    };
    if (typeof v.jwks_uri === 'string' && v.jwks_uri) {
      payload.jwks_uri = v.jwks_uri;
    }
    if (typeof v.crypto_metadata_uri === 'string' && v.crypto_metadata_uri) {
      payload.crypto_metadata_uri = v.crypto_metadata_uri;
    }
    log.debug("Leaving generate().");
    return payload;
  },
  [STS_PREFIX + 'kerberos-tickets-invalidated']: function (values) {
    log.debug("Entering generate().");
    const v = values || {};
    const payload = {
      realm: String(v.realm || 'default'),
      kerberos_realm: String(v.kerberos_realm || ''),
      kvno: Number(v.kvno) || 0,
      reason: v.reason === 'nothing-retained' ? 'nothing-retained'
                                              : 'invalidated',
      event_timestamp: Number(v.event_timestamp) ||
                       Math.floor(Date.now() / 1000)
    };
    log.debug("Leaving generate().");
    return payload;
  },
  [STS_PREFIX + 'announcement']: function (values) {
    log.debug("Entering generate().");
    const v = values || {};
    const payload = {
      realm: String(v.realm || 'default'),
      message: String(v.message || ''),
      surfaces: (Array.isArray(v.surfaces) ? v.surfaces : [])
        .map(String),
      event_timestamp: Number(v.event_timestamp) ||
                       Math.floor(Date.now() / 1000)
    };
    log.debug("Leaving generate().");
    return payload;
  }
};

// The KEY-ROTATION FAMILY's generator (#245): every one keeps #42's shape —
// `realm`, `rotated` as "<unit> <from> -> <to>", `reason` from its own closed
// list, the one address a receiver fetches again (the member ending `_uri`),
// `event_timestamp` — and differs only in that address and any members of
// its own. All of it is read off the row's members, so a new sibling URN is
// a model and nothing here.
function keyEventGenerator(row) {
  log.debug("Entering keyEventGenerator(). " + row.uri);
  const SHARED = ['realm', 'rotated', 'reason', 'event_timestamp'];
  const reasons = (row.members.filter(function (member) {
    return member.name === 'reason';
  })[0] || { values: [] }).values;
  const uriMember = (row.members.filter(function (member) {
    return /_uri$/.test(member.name);
  })[0] || { name: '' }).name;
  const extra = row.members.filter(function (member) {
    return SHARED.indexOf(member.name) < 0 && member.name !== uriMember;
  });
  log.debug("Leaving keyEventGenerator().");
  return function (values) {
    log.debug("Entering generate().");
    const v = values || {};
    const payload = {
      realm: String(v.realm || 'default'),
      rotated: String(v.rotated || ''),
      reason: reasons.indexOf(v.reason) >= 0 ? v.reason : 'requested',
      event_timestamp: Number(v.event_timestamp) ||
                       Math.floor(Date.now() / 1000)
    };
    if (uriMember && typeof v[uriMember] === 'string' && v[uriMember]) {
      payload[uriMember] = v[uriMember];
    }
    extra.forEach(function (member) {
      const value = v[member.name];
      if (member.type === 'boolean' && typeof value === 'boolean') {
        payload[member.name] = value;
      } else if (member.type === 'string' && typeof value === 'string' &&
                 value) {
        payload[member.name] = value;
      }
    });
    log.debug("Leaving generate().");
    return payload;
  };
}

// One catalogue row from the model's: the required names, and its generator.
function rowOf(row) {
  log.debug("Entering rowOf(). " + row.uri);
  row.required = row.members.filter(function (member) {
    return member.required;
  }).map(function (member) {
    return member.name;
  });
  if (GENERATORS[row.uri]) {
    row.generate = GENERATORS[row.uri];
  } else if (row.family === 'sts' && row.members.some(function (member) {
    return member.name === 'rotated';
  })) {
    row.generate = keyEventGenerator(row);
  } else {
    row.generate = function () {
      log.debug("Entering generate().");
      log.debug("Leaving generate().");
      return {};
    };
  }
  log.debug("Leaving rowOf().");
  return row;
}

// THE FOUR VOCABULARIES IN ONE TABLE, in the model's order: SSF's own first,
// because they are about the pipe every one of the others travels on; then
// CAEP's eight about a SESSION, then RISC's fourteen about an ACCOUNT, then
// this service's own.
/**
 * Every event type this service knows, SSF's first, then CAEP's, RISC's and
 * this service's own.
 */
const EVENTS = SsfModel.events().map(rowOf);

function familyRows(family) {
  log.debug("Entering familyRows(). " + family);
  log.debug("Leaving familyRows().");
  return EVENTS.filter(function (row) {
    return row.family === family;
  });
}

/**
 * SSF 1.0's own two event types, `verification` and `stream-updated`.
 */
const SSF_EVENTS = familyRows('ssf');

/**
 * CAEP's eight event types, about a session.
 */
const CAEP_EVENTS = familyRows('caep');

/**
 * RISC's fourteen event types, about an account.
 */
const RISC_EVENTS = familyRows('risc');

/**
 * This service's own event types, about its keys and its people; none has a
 * subject.
 */
const STS_EVENTS = familyRows('sts');

/**
 * The URIs of CAEP's event types.
 */
const CAEP_EVENT_URIS = CAEP_EVENTS.map(function (row) {
  return row.uri;
});

/**
 * The URIs of RISC's event types.
 */
const RISC_EVENT_URIS = RISC_EVENTS.map(function (row) {
  return row.uri;
});

/**
 * Every catalogue row, keyed by its event type URI.
 */
const EVENT_BY_URI = {};
EVENTS.forEach(function (row) {
  EVENT_BY_URI[row.uri] = row;
});

/**
 * The URIs of every event type, in catalogue order.
 */
const EVENT_URIS = EVENTS.map(function (row) {
  return row.uri;
});

// ---------------------------------------------------------------------------
// WHICH EVENT TYPES THIS TRANSMITTER SUPPORTS, which is a CONFIGURATION
// question and not a code one.
//
// `ssf.eventsSupported` is a list, defaulting to every URI above, so that a
// deployment can advertise a narrower set and a client's "you offered me an
// event type you will not deliver" path becomes reachable. An entry naming an
// event this service does not implement is dropped with a warning rather than
// advertised — advertising one would produce a stream whose `events_delivered`
// promises something nothing can send.
// ---------------------------------------------------------------------------
/**
 * Returns the event types this transmitter supports: the configured SSF types,
 * CAEP's and RISC's when each is on, and this service's own, which are always
 * offered. A configured type this service does not implement is dropped with a
 * warning.
 *
 * @returns the URIs
 */
function supportedEventUris() {
  log.debug('Entering supportedEventUris().');
  const chosen = chooseFrom('ssf.eventsSupported', SSF_EVENTS,
                            'ssf.eventsSupported');
  const caep = config.value('caep.enabled')
    ? chooseFrom('caep.eventsSupported', CAEP_EVENTS, 'caep.eventsSupported')
    : [];
  const risc = config.value('risc.enabled')
    ? chooseFrom('risc.eventsSupported', RISC_EVENTS, 'risc.eventsSupported')
    : [];
  // This service's own (D4), ALWAYS offered: it is about the transmitter's
  // keys, which every receiver verifies SETs with, so there is no deployment
  // for which advertising it would be a promise nothing can keep.
  const own = STS_EVENTS.map(function (row) {
    return row.uri;
  });
  const out = chosen.concat(caep).concat(risc).concat(own);
  log.debug('Leaving supportedEventUris(). ' + out.length + ' type(s).');
  return out;
}

// One vocabulary's offered list, from the setting that governs THAT
// vocabulary. THREE settings rather than one, and the reason is the same one
// that put CAEP and RISC in groups of their own: `ssf.eventsSupported` is
// about the pipe's own two events, `caep.eventsSupported` is about the
// profile's eight and `risc.eventsSupported` about RISC's fourteen, so
// turning a profile off or narrowing it is a decision belonging to THAT
// profile. A single list would have made `caep.enabled` and `risc.enabled`
// unable to do anything a reader could see in the metadata.
//
// **AN ENTRY IS ACCEPTED AS A SHORT NAME AS WELL AS A FULL URI**, because
// these URIs are 60 characters long and a setting nobody can type is a setting
// nobody narrows. `session-revoked` and the whole URI mean the same thing
// here; a name that matches no row in this vocabulary is DROPPED WITH A
// WARNING rather than advertised — advertising one would agree a stream this
// service can never deliver on, and SSF has no refusal for that, so the
// receiver's only notice would be events that never arrive.
function chooseFrom(setting, rows, label) {
  log.debug('Entering chooseFrom(). ' + setting);
  const asked = config.value(setting);
  const list = Array.isArray(asked) ? asked : String(asked || '').split(',');
  const byUri = {};
  const byShort = {};
  rows.forEach(function (row) {
    byUri[row.uri] = row.uri;
    byShort[row.uri.slice(row.uri.lastIndexOf('/') + 1)] = row.uri;
  });
  const chosen = [];
  list.map(function (one) {
    return String(one).trim();
  }).filter(Boolean).forEach(function (name) {
    const uri = byUri[name] || byShort[name] || '';
    if (!uri) {
      log.warn(label + ' names "' + name + '", which is not an event type ' +
               'in that vocabulary. It is NOT advertised — a transmitter ' +
               'that offered it would agree a stream it can never deliver ' +
               'on, and SSF has no refusal for an event type a transmitter ' +
               'will not send, so the receiver would simply wait for ever.');
      return;
    }
    if (chosen.indexOf(uri) < 0) {
      chosen.push(uri);
    }
  });
  const out = chosen.length ? chosen : rows.map(function (row) {
    return row.uri;
  });
  log.debug('Leaving chooseFrom(). ' + out.length + ' type(s).');
  return out;
}

// ---------------------------------------------------------------------------
// VALIDATE ONE EVENT PAYLOAD AGAINST ITS CATALOGUE ROW.
//
// Collected errors again, and for the reason `ssf_subjects.js` gives: an event
// built on a form is usually wrong in more than one way.
//
// **AN UNRECOGNISED MEMBER IS A WARNING AND NOT AN ERROR, WHICH IS THE
// OPPOSITE OF THE SUBJECT RULE, AND THE DIFFERENCE IS THE
// SPECIFICATIONS' OWN.**
// RFC 9493 closes a Subject Identifier's member set because an unrecognised
// member might NARROW the subject. An event payload has no such rule — the
// vocabularies extend, and a receiver is expected to ignore what it does not
// know. Refusing here would make this service unable to carry a vendor's own
// extension, which is exactly what a debugger is for.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// ONE MEMBER'S VALUE AGAINST ITS ROW.
//
// It was three lines inside validateEvent() while every member was a string or
// a closed enum. CAEP needs four more shapes, and each of the four is a defect
// this service would otherwise carry silently to a receiver:
//
//   number    `event_timestamp` as the STRING "1757000000" is accepted by
//             every JSON parser and compared numerically by nobody.
//   strings   `amr` as a bare string. A session authenticated by a password
//             AND a security key has two values, and a receiver reading a
//             string sees one.
//   object    `claims`, which is the entire payload of token-claims-change.
//             An array here parses and means nothing.
//   langmap   `reason_admin` / `reason_user`. CAEP makes these objects keyed
//             by a BCP 47 language tag, and a plain string is the commonest
//             mistake in the whole profile — a receiver indexing by language
//             reads NOTHING from one and reports no error.
//
// **AND ONE THAT IS A WARNING RATHER THAN AN ERROR.** `openenum` is a list the
// specification says two parties may extend — `credential_type`, `namespace`,
// `principal` — so a value outside it is CARRIED and noted. Refusing would
// make this service unable to mock a vendor's own credential type, which is
// exactly what it is for. A closed `enum` is still refused.
// ---------------------------------------------------------------------------
function checkMember(member, value, errors, warnings) {
  log.debug('Entering checkMember(). ' + member.name);
  if (member.type === 'string' && typeof value !== 'string') {
    errors.push('"' + member.name + '" must be a string.');
    log.debug('Leaving checkMember(). Not a string.');
    return;
  }
  if (member.type === 'number' && typeof value !== 'number') {
    errors.push('"' + member.name + '" must be a NUMBER of seconds since ' +
        'the epoch, not a string. A quoted timestamp parses everywhere and ' +
        'is compared numerically nowhere.');
    log.debug('Leaving checkMember(). Not a number.');
    return;
  }
  // A true or false (#245's `bundle_changed`), never the string "true".
  if (member.type === 'boolean' && typeof value !== 'boolean') {
    errors.push('"' + member.name + '" must be true or false.');
    log.debug('Leaving checkMember(). Not a boolean.');
    return;
  }
  if (member.type === 'strings') {
    if (!Array.isArray(value) ||
        value.some(function (one) { return typeof one !== 'string'; })) {
      errors.push('"' + member.name + '" must be an ARRAY of strings. A ' +
          'bare string is refused rather than wrapped: a session ' +
          'authenticated two ways has two values, and wrapping would hide ' +
          'a sender that can only ever say one.');
    }
    log.debug('Leaving checkMember(). strings.');
    return;
  }
  if (member.type === 'object') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      errors.push('"' + member.name + '" must be a JSON object.');
    }
    log.debug('Leaving checkMember(). object.');
    return;
  }
  if (member.type === 'langmap') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      errors.push('"' + member.name + '" must be an OBJECT KEYED BY A ' +
          'LANGUAGE TAG — {"en": "..."} — and not a string. That is CAEP ' +
          'section 2, and a receiver indexing it by language reads nothing ' +
          'from a string and reports no error.');
      log.debug('Leaving checkMember(). Not a language map.');
      return;
    }
    Object.keys(value).forEach(function (tag) {
      if (typeof value[tag] !== 'string') {
        errors.push('"' + member.name + '.' + tag + '" must be a string.');
      }
      if (!/^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$/.test(tag)) {
        warnings.push('"' + tag + '" is not shaped like a BCP 47 language ' +
            'tag. It is carried — nothing here owns the registry — and a ' +
            'receiver looking for "en" will not find it.');
      }
    });
    log.debug('Leaving checkMember(). langmap.');
    return;
  }
  if (member.type === 'enum' && member.values.indexOf(value) < 0) {
    errors.push('"' + member.name + '" must be one of ' +
        member.values.join(', ') + '.');
    log.debug('Leaving checkMember(). Outside a closed enum.');
    return;
  }
  if (member.type === 'openenum' && member.values.indexOf(value) < 0) {
    warnings.push('"' + String(value) + '" is not one of the values CAEP ' +
        'lists for "' + member.name + '" (' + member.values.join(', ') +
        '). That list is OPEN — two parties may agree their own — so it is ' +
        'CARRIED rather than refused, and a receiver that has not been told ' +
        'about it will ignore the event.');
  }
  log.debug('Leaving checkMember(). ' + member.name + ' checked.');
}

// A member name that differs from one this row defines only by hyphen versus
// underscore. It is one comparison rather than a table of known typos, so it
// stays true for a vocabulary nobody has written yet.
function nearestMember(name, members) {
  log.debug('Entering nearestMember(). ' + name);
  const flat = String(name).replace(/[-_]/g, '_');
  let found = '';
  (members || []).forEach(function (member) {
    if (!found && member.name !== name &&
        String(member.name).replace(/[-_]/g, '_') === flat) {
      found = member.name;
    }
  });
  log.debug('Leaving nearestMember(). ' + (found || '(none)'));
  return found;
}

/**
 * Validates an event's payload against its catalogue row: the members it
 * requires and each member's value, collecting errors and warnings.
 *
 * @param uri - the event type URI
 * @param payload - the event's payload
 * @returns `{ ok, errors, warnings }`
 */
function validateEvent(uri, payload) {
  log.debug('Entering validateEvent(). ' + uri);
  const errors = [];
  const warnings = [];
  const row = EVENT_BY_URI[uri];
  if (!row) {
    errors.push('"' + uri + '" is not an event type this service knows. ' +
        'The ones it does are: ' + EVENT_URIS.join(', ') + '.');
    log.debug('Leaving validateEvent(). Unknown type.');
    return { ok: false, errors: errors, warnings: warnings };
  }
  const body = (payload && typeof payload === 'object' &&
                !Array.isArray(payload)) ? payload : null;
  if (!body) {
    errors.push('The payload of "' + uri + '" must be a JSON object. An ' +
        'event with nothing to say still carries {} — the event TYPE is the ' +
        'key in the events map and the payload is its value.');
    log.debug('Leaving validateEvent(). Not an object.');
    return { ok: false, errors: errors, warnings: warnings };
  }
  // A ROW THAT ITS OWN SPECIFICATION DEPRECATES SAYS SO, ON EVERY EVENT, AND
  // IT IS A WARNING RATHER THAN A REFUSAL. RISC 1.0 section 2.11 deprecates
  // `sessions-revoked` in favour of CAEP's `session-revoked`; a transmitter
  // that could not produce the deprecated one could not be used to find out
  // what a receiver does with it, and receivers in the field still send and
  // expect it. Written against `row.deprecated` rather than against the URI,
  // so the next deprecation is a field and not a branch.
  if (row.deprecated) {
    warnings.push('"' + uri + '" is DEPRECATED by its own specification, ' +
        'which says new implementations must use "' + row.deprecated + '" ' +
        'instead. It is still built and still sent — a transmitter that ' +
        'could not produce one could not be used to find out what a ' +
        'receiver does with it — and the two names differ by one letter and ' +
        'mean different things, so this is the pair to check when a ' +
        'receiver ends more sessions than anybody intended.');
  }
  const known = {};
  row.members.forEach(function (member) {
    known[member.name] = member;
  });
  row.required.forEach(function (name) {
    if (!Object.prototype.hasOwnProperty.call(body, name)) {
      errors.push('"' + uri + '" requires a "' + name + '" member.');
    }
  });
  Object.keys(body).forEach(function (name) {
    const member = known[name];
    if (!member) {
      // A NEAR MISS IS NAMED, and it is worth a sentence of its own rather
      // than the general one below. Every member in SSF and CAEP is
      // snake_case and exactly one in RISC is not — `identifier-changed`'s
      // `new-value` — so `new_value` typed from habit is an event that
      // validates, delivers, and tells the receiver nothing. It is written
      // against the ROW's own member names rather than against that one
      // spelling, so it catches the reverse mistake too and needs no
      // maintenance when a vocabulary adds a member.
      const nearMiss = nearestMember(name, row.members);
      warnings.push('"' + name + '" is not a member "' + uri + '" defines. ' +
          (nearMiss
            ? 'It differs from "' + nearMiss + '", which IS one, only in a ' +
              'hyphen or an underscore — and this is the one place in the ' +
              'three vocabularies where that matters, because ' +
              '"new-value" is the only hyphenated member name in any of ' +
              'them. What you sent is CARRIED as an extension and the ' +
              'member the specification defines is absent, so a conforming ' +
              'receiver reads nothing and reports no error. '
            : '') +
          'It is CARRIED rather than refused: an event vocabulary extends, ' +
          'and a receiver is expected to ignore what it does not know.');
      return;
    }
    const value = body[name];
    checkMember(member, value, errors, warnings);
  });
  log.debug('Leaving validateEvent(). ' + errors.length + ' problem(s).');
  return { ok: errors.length === 0, errors: errors, warnings: warnings };
}

// ---------------------------------------------------------------------------
// WHAT IS WRONG WITH THE SUBJECT OF ONE EVENT, WHERE THE ROW NARROWS IT.
//
// `transmit()` already refuses an event whose row says `subject: 'required'`
// and that carries none, and that refusal is MECHANICAL: there is nothing to
// match against a stream's subjects, so the event can be delivered to nobody
// or to everybody and neither is what was meant.
//
// **THIS IS THE OTHER KIND, AND IT IS A WARNING FOR EXACTLY THAT REASON.**
// RISC's two identifier events say the subject MUST be an email address or a
// phone number, because for those two the identifier IS the message — the
// subject carries the OLD value and the payload carries at most the new one.
// An `iss_sub` subject there is perfectly deliverable and merely wrong, and
// refusing to send one would remove the ability to find out what a receiver
// does with it, which is the whole reason this service exists.
//
// It is driven by `row.subjectFormats` rather than by the URI, so it is a
// property of the table and not a branch naming a vocabulary.
// ---------------------------------------------------------------------------
/**
 * Warns when an event's subject is not in a format its row narrows it to
 * (RISC's identifier events want an email address or a phone number).
 *
 * @param uri - the event type URI
 * @param subject - the event's subject
 * @returns the warnings; empty when there is nothing to say
 */
function subjectAdvice(uri, subject) {
  log.debug('Entering subjectAdvice(). ' + uri);
  const warnings = [];
  const row = EVENT_BY_URI[uri];
  if (!row || !Array.isArray(row.subjectFormats) || !subject) {
    log.debug('Leaving subjectAdvice(). Nothing to say.');
    return warnings;
  }
  const format = String((subject || {}).format || '');
  if (format === 'complex') {
    warnings.push('"' + uri + '" wants a subject in one of these formats: ' +
        row.subjectFormats.join(', ') + '. This one is a COMPLEX subject, ' +
        'which names a person and possibly a session, and this event is ' +
        'about an IDENTIFIER rather than about either.');
    log.debug('Leaving subjectAdvice(). Complex subject.');
    return warnings;
  }
  if (row.subjectFormats.indexOf(format) < 0) {
    warnings.push('"' + uri + '" says its subject MUST be one of ' +
        row.subjectFormats.join(' or ') + ' and this one is "' + format +
        '". It is SENT anyway — the event is perfectly deliverable and ' +
        'merely wrong, and refusing would remove the ability to find out ' +
        'what a receiver does with it. What is lost is the message itself: ' +
        'the subject of these two events carries the identifier that ' +
        'changed, so a subject naming the person instead says that ' +
        'something about them moved without saying what.');
  }
  log.debug('Leaving subjectAdvice(). ' + warnings.length + ' warning(s).');
  return warnings;
}

// ---------------------------------------------------------------------------
// BUILD THE CLAIM SET OF ONE SET.
//
// `stream` supplies `iss` and `aud`; the rest is the event. Returned UNSIGNED,
// because two callers want it that way for different reasons: the console
// shows what is about to be sent, and `signSet()` below signs it. A builder
// that only ever returned a signed token would make "show me what you are
// going to send" impossible without signing something nobody asked for.
//
// `jti` IS THE DEDUPLICATION KEY and it is what a poll acknowledgement names,
// so it is generated here and never taken from a caller: a transmitter that
// let somebody choose one could be made to overwrite an event a receiver had
// not read.
// ---------------------------------------------------------------------------
/**
 * Builds the claim set of one Security Event Token, unsigned, with a fresh
 * `jti`.
 *
 * @param options - `uri` and `payload` (the event), `issuer`, `audience`,
 * and optionally `subject` (the `sub_id`) and `txn`
 * @returns the claims
 */
function buildSet(options) {
  log.debug('Entering buildSet().');
  const asked = options || {};
  const events = {};
  events[asked.uri] = asked.payload || {};
  const claims = {
    iss: String(asked.issuer || ''),
    jti: randomId(16),
    iat: nowSec(),
    aud: asked.audience,
    events: events
  };
  if (asked.subject) {
    claims.sub_id = asked.subject;
  }
  if (asked.txn) {
    claims.txn = String(asked.txn);
  }
  if (typeof asked.toe === 'number') {
    // The Time Of Event (RFC 8417 section 2.2), which is NOT `iat`: a token
    // minted now may report something that happened an hour ago, and a
    // receiver deciding whether to end a session cares about the second one.
    claims.toe = asked.toe;
  }
  if (mode.valueInForce('ssf.legacySubClaim') && asked.subject &&
      typeof asked.subject.sub === 'string') {
    // The deliberate defect. RFC 8417 discourages `sub` on a SET and SSF uses
    // `sub_id`; a client written against a transmitter that emits `sub`
    // anyway will silently read nothing here, which is precisely the failure
    // worth being able to reproduce. See ssf.legacySubClaim. Development mode
    // only (#104): in a product realm the read answers false whatever is
    // stored.
    claims.sub = asked.subject.sub;
  }
  // HELD TO THE MODEL (#1579): every SET this service issues is built here,
  // and its claims are RFC 8417 section 2.2's as `models/ssf/ssf.tsp` names
  // them. What the model does not allow is recorded and the SET sent as it
  // was built — the model describes the wire, it does not reshape it.
  const problems = SsfModel.undeclared('set-claims', claims);
  if (problems.length > 0) {
    log.error(errorCodes.tag('STS-SSF-0161') + 'a SET\'s claims are not ' +
              'the model\'s (models/ssf/ssf.tsp): ' + problems.join('; ') +
              '.');
  }
  log.debug('Leaving buildSet(). jti=' + claims.jti);
  return claims;
}

// Which algorithm a SET is signed with. It is a setting rather than a
// constant because this is the document in this service most worth signing
// post-quantum: a SET is a durable record read long after it was written.
/**
 * Returns the algorithm SETs are signed with (`ssf.signingAlgorithm`, default
 * RS256).
 *
 * @returns the JWS algorithm
 */
function signingAlgorithm() {
  log.debug('Entering signingAlgorithm().');
  const alg = require('../common/helpers').usableSigningAlg(
    String(config.value('ssf.signingAlgorithm') || 'RS256'));
  log.debug('Leaving signingAlgorithm(). ' + alg);
  return alg;
}

// ---------------------------------------------------------------------------
// SIGN ONE SET.
//
// **IT IS ASYNCHRONOUS AND MUST STAY THAT WAY.** `ssf.signingAlgorithm` can
// name SLH-DSA, and an SLH-DSA-SHAKE-128s signature measured 14.6 seconds on
// this service's own thread — during which it answers nobody. `signJwtAsAsync`
// routes a post-quantum signature to libuv's thread pool and resolves an RS256
// one in place, so the cost is paid only where it is real. See
// common/pq_native.js.
//
// `ssf.breakSetSignature` is the deliberate defect for this family, the same
// device as `oauth2.breakIdTokenNonce`: it flips one byte of the signature
// AFTER signing, so a receiver that does not verify accepts an event that
// nothing signed. That path is unreachable against a correct transmitter,
// which is exactly why a debugger needs it. DEVELOPMENT MODE ONLY (#104,
// `mode.spoilsOnPurpose()`): read through `mode.valueInForce()` when the
// token is signed, so a realm switched to product stops breaking signatures
// at once, whatever is still stored.
// ---------------------------------------------------------------------------
/**
 * Signs a SET with `typ: secevent+jwt`, asynchronously so that a post-quantum
 * signature runs on libuv's thread pool.
 *
 * In development mode `ssf.breakSetSignature` flips a byte of the signature
 * after signing.
 *
 * @param claims - the SET's claims
 * @param options - `algorithm` (default `signingAlgorithm()`)
 * @returns a promise of the compact JWS
 */
function signSet(claims, options) {
  log.debug('Entering signSet().');
  const settings = options || {};
  const alg = settings.algorithm || signingAlgorithm();
  log.debug("Leaving signSet().");
  return signJwtAsAsync(claims, alg, null, {
    // RFC 8417 section 2.2's media type, and it is a SHOULD that behaves
    // like a MUST: a receiver that dispatches on `typ` — and several do —
    // drops a token without it with no error anybody sees. It is asked for
    // HERE rather than being a default in the signer, because everything
    // else this service mints is an ordinary JWT and would be wrong to
    // relabel.
    header: { typ: SET_MEDIA_TYPE },
    // `ssf.setCertificateHeader` decides the `x5c` / `x5u`.
    certificateHeader: 'ssf-set' })
    .then(function (token) {
      if (!mode.valueInForce('ssf.breakSetSignature')) {
        log.debug('Leaving signSet(). Signed with ' + alg + '.');
        return token;
      }
      log.debug('Leaving signSet(). Signed with ' + alg +
                ', then BROKEN on purpose.');
      return breakSignature(token);
    });
}

// Change one base64url character of the signature. It has to be a CHARACTER
// change rather than a truncation, because a truncated signature is refused by
// the base64url decode and never reaches the verify — a client would then
// report a MALFORMED TOKEN rather than a BAD SIGNATURE, and those are two
// different bugs for whoever is being tested.
//
// **IT IS THE FIRST CHARACTER AND NOT THE LAST, AND THAT IS NOT A STYLE
// CHOICE.** The last character of a base64url string usually carries PADDING
// BITS that the decoder discards: an RS256 signature is 256 bytes, which is
// 2048 bits in 342 base64url characters of 6 bits each, so the final character
// has four bits nothing reads. Changing `A` to `B` there produces a token that
// looks altered, decodes to THE SAME BYTES, and verifies perfectly — a
// deliberate defect that is not a defect, which is worse than none at all
// because a test would pass against it. The first character is always
// significant.
function breakSignature(token) {
  log.debug('Entering breakSignature().');
  const parts = String(token).split('.');
  if (parts.length !== 3 || !parts[2].length) {
    log.debug('Leaving breakSignature(). Nothing to break.');
    return token;
  }
  const first = parts[2].charAt(0);
  const replacement = first === 'A' ? 'B' : 'A';
  parts[2] = replacement + parts[2].slice(1);
  log.debug('Leaving breakSignature(). One character changed.');
  return parts.join('.');
}

// The synchronous signer, for the two places that cannot await: the console's
// preview and a test fixture. It refuses a post-quantum algorithm by name
// rather than blocking the thread for fifteen seconds, and says which call to
// use instead.
/**
 * Signs a SET synchronously, for the console's preview and test fixtures.
 *
 * @param claims - the SET's claims
 * @param options - `algorithm` (default `signingAlgorithm()`)
 * @returns the compact JWS
 * @throws when the algorithm is post-quantum; use `signSet()` for that
 */
function signSetSync(claims, options) {
  log.debug('Entering signSetSync().');
  const settings = options || {};
  const alg = settings.algorithm || signingAlgorithm();
  const token = signJwtAs(claims, alg, null,
                          { header: { typ: SET_MEDIA_TYPE },
                            certificateHeader: 'ssf-set' });
  log.debug('Leaving signSetSync(). ' + alg);
  return token;
}

// What a SET this service signed says about itself, for the pages that show
// one. It parses rather than verifies — the token was made here.
/**
 * Summarizes a SET this service signed for the pages that show one: `jti`,
 * `iat`, issuer, audience, event types, name and subject. It parses rather than
 * verifies.
 *
 * @param claims - the SET's claims
 * @returns the summary
 */
function describeSet(claims) {
  log.debug('Entering describeSet().');
  const uris = Object.keys((claims && claims.events) || {});
  const row = uris.length ? EVENT_BY_URI[uris[0]] : null;
  const out = {
    jti: String((claims && claims.jti) || ''),
    iat: Number((claims && claims.iat) || 0),
    issuer: String((claims && claims.iss) || ''),
    audience: (claims && claims.aud) || '',
    types: uris,
    name: row ? row.name : (uris[0] || '(no event)'),
    subject: (claims && claims.sub_id)
      ? subjects.describeSubject(claims.sub_id)
      : ''
  };
  log.debug('Leaving describeSet(). ' + out.name);
  return out;
}

// ---------------------------------------------------------------------------
// READING A SET BACK, AND VERIFYING IT. THE RECEIVER'S HALF OF THIS FILE.
//
// **THESE THREE WERE PRIVATE TO `ssf.js` UNTIL 2026-09-10 AND MOVED BECAUSE A
// SECOND RECEIVER ARRIVED.** `POST /ssf/receive` was the only endpoint in this
// service that ever read a Security Event Token it was handed; the admin
// console and the user portal are receivers of their own now, with a receive
// endpoint each, and three receivers reading a SET three ways would be three
// opinions about what arrived. One reading, in the file that owns the
// envelope, is the same argument `common/crypto.js` makes one layer down.
//
// It is deliberately NOT in `ssf_receivers.js`: building a SET and reading one
// back are the two directions of ONE format, and splitting them would put
// `buildSet()` and `readSet()` in different files with nothing keeping them
// honest about the same document.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// THE KEY A SET WAS SIGNED WITH, IF THIS SERVICE HOLDS IT.
//
// This service can only verify a signature made with a key IT HOLDS — it
// follows no `jwks_uri`, here or anywhere else, for the reason
// `applications.js` gives about `oauthJwksUri` and `federation_http.js`
// repeats: fetching a URL a caller supplied in order to verify a credential is
// a server-side request forgery with a specification citation attached. So the
// key is looked up in this realm's own key set, BY `kid` FIRST and by
// algorithm second.
//
// **BY kid FIRST IS THE PART THAT MATTERS.** Two of this service's keys share
// an `alg` — the Ed25519 and Ed448 pair, because RFC 8037 registers one
// algorithm value for both curves and puts the curve in the key — so an
// algorithm-only lookup would pick one of them and report a perfectly good
// Ed448 signature as not verifying.
//
// A SET signed by anybody else resolves to no key, and that is reported as NOT
// VERIFIABLE HERE rather than as invalid. Those are different sentences and
// conflating them would be a receiver blaming a transmitter for its own
// missing key.
// ---------------------------------------------------------------------------
/**
 * Finds the public key a SET was signed with among the ambient realm's own
 * signing keys, by `kid` first and by algorithm only where there is no `kid`.
 * It fetches nothing.
 *
 * @param header - the SET's protected header
 * @returns `{ key, pq }`, or null when this service holds no such key
 */
function publicKeyForHeader(header) {
  log.debug('Entering publicKeyForHeader().');
  const kid = String((header || {}).kid || '');
  const alg = String((header || {}).alg || '');
  // ---------------------------------------------------------------------
  // **ON THE `kid`, AND ON THE ALGORITHM ONLY WHERE THERE IS NO `kid`
  // (2026-09-12).** This read `alg === 'RS256' || kid === STS.kid`, so EVERY
  // RS256 SET — including one a foreign transmitter signed and labelled with
  // its own kid — was checked against this service's RSA key and reported
  // "invalid". That is a false statement about somebody else's signature: the
  // honest answer is the sentence `verifySet()` gives for a key this service
  // does not hold, *not verifiable here*, and a receiver page that says
  // "invalid" teaches whoever reads it that the other transmitter is broken. A
  // SET that names no kid is still tried against the RSA key, because that is
  // the only key it could be claiming.
  // ---------------------------------------------------------------------
  // **EITHER SPELLING OF THE `kid` (2026-09-13)**: this service's own name
  // for the key, or its RFC 9278 thumbprint URI, which is what a SET carries
  // under `keys.kidFormat: jwk-thumbprint-uri` — whatever the setting says now
  // (common/jose_kid.js).
  // EVERY LIVE GENERATION of the RSA key (#42): a SET signed a moment before
  // a rotation names the key that is now `retired`, and it is still ours.
  const ownRsa = require('../common/helpers').ownRsaCertificates('jose')
    .filter(function (one) {
      return kid ? kidNamesKey(kid, one.kid) : one.role === 'current';
    })[0];
  if (ownRsa && (kid || alg === 'RS256')) {
    // The RSA key is not in the list below — it is `STS.privateKey`/`STS.kid`,
    // where eight modules already read it — so it is resolved separately from
    // the certificate this service publishes for it.
    try {
      log.debug('Leaving publicKeyForHeader(). The service RSA key.');
      return { key: stsCrypto.publicKeyOf(ownRsa.certPem), pq: false };
    } catch (e) {
      log.debug('Leaving publicKeyForHeader(). The certificate would not ' +
                'load: ' + e.message);
      return null;
    }
  }
  // Every live generation of the other keys too (#42).
  const list = require('../common/helpers').allVerificationKeys();
  const found = list.filter(function (one) {
    return kid ? kidNamesKey(kid, one.publicJwk.kid) : one.alg === alg;
  })[0];
  if (!found) {
    log.debug('Leaving publicKeyForHeader(). No key of ours matches.');
    return null;
  }
  if (found.publicJwk.kty === 'AKP') {
    // A post-quantum key. `verifyCompactJws()` wants the raw public bytes,
    // which the AKP JWK carries in `pub`.
    log.debug('Leaving publicKeyForHeader(). A post-quantum key.');
    return { key: { pub: found.publicJwk.pub }, pq: true };
  }
  try {
    log.debug('Leaving publicKeyForHeader(). ' + found.alg + '.');
    return { key: stsCrypto.publicKeyFromJwk(found.publicJwk), pq: false };
  } catch (e) {
    log.debug('Leaving publicKeyForHeader(). The JWK would not load: ' +
              e.message);
    return null;
  }
}

// Whether the signature holds, as `{ verified, note }`. It NEVER throws: the
// whole point of a receiver endpoint is to say what arrived, and "it did not
// verify" IS what arrived.
/**
 * Verifies a SET's signature against this service's own keys. It never throws:
 * a SET signed with a key held nowhere here is reported as not verifiable here
 * rather than invalid.
 *
 * @param token - the compact JWS
 * @param header - its decoded protected header
 * @returns `{ verified, note }`
 */
function verifySet(token, header) {
  log.debug('Entering verifySet().');
  if (!header) {
    log.debug('Leaving verifySet(). No readable header.');
    return { verified: false,
      note: 'there is no readable protected header, so there is nothing to ' +
            'look a key up by' };
  }
  const resolved = publicKeyForHeader(header);
  if (!resolved) {
    log.debug('Leaving verifySet(). No key.');
    return { verified: false,
      note: 'not verifiable here: this service holds no key matching kid "' +
            String(header.kid || '(none)') + '" / alg "' +
            String(header.alg || '(none)') + '". It follows no jwks_uri — ' +
            'fetching a URL a caller supplied in order to verify a ' +
            'credential is the request forgery this repository refuses ' +
            'everywhere — so a SET signed by anybody else is UNVERIFIABLE ' +
            'here rather than invalid. Those are different sentences.' };
  }
  try {
    stsCrypto.verifyCompactJws(token, resolved.key,
      { algorithms: stsCrypto.JWS_ASYMMETRIC_ALGS });
    log.debug('Leaving verifySet(). Verified.');
    return { verified: true,
      note: 'verified against this service\'s own ' +
            String(header.alg) + ' key' };
  } catch (e) {
    // A signature that does not verify, or one this build cannot check. Both
    // are reported rather than thrown, for the reason above.
    log.debug('Leaving verifySet(). It did not verify.');
    return { verified: false,
      note: 'the signature did not verify against this service\'s own key: ' +
            e.message };
  }
}

// The header and the claims of a compact JWS, for display. It reports what is
// wrong rather than throwing, for `verifySet()`'s reason.
/**
 * Decodes a compact JWS's header and claims for display, reporting what is
 * wrong rather than throwing.
 *
 * @param token - the compact JWS
 * @returns `{ header, claims, problem }`
 */
function readSet(token) {
  log.debug('Entering readSet().');
  const parts = String(token || '').split('.');
  const out = { header: null, claims: null, problem: '' };
  if (parts.length !== 3) {
    out.problem = 'This is not a compact JWS — a Security Event Token has ' +
      'three dot-separated parts and this has ' + parts.length + '.';
    log.debug('Leaving readSet(). Not a compact JWS.');
    return out;
  }
  try {
    out.header = JSON.parse(Buffer.from(parts[0], 'base64url')
      .toString('utf8'));
    out.claims = JSON.parse(Buffer.from(parts[1], 'base64url')
      .toString('utf8'));
  } catch (e) {
    // Undecodable. Reported rather than thrown: the whole point of a receiver
    // is to say what arrived, and "it would not decode" IS what arrived.
    out.problem = 'The header or the payload would not decode as base64url ' +
      'JSON: ' + e.message;
  }
  log.debug('Leaving readSet(). ' + (out.problem || 'read'));
  return out;
}

/**
 * The Shared Signals event catalogue (SSF, CAEP, RISC and this service's own)
 * and the Security Event Token (RFC 8417) they travel in: building, signing,
 * reading and verifying one.
 *
 * @namespace
 */
module.exports = {
  SSF_PREFIX: SSF_PREFIX,
  CAEP_PREFIX: CAEP_PREFIX,
  RISC_PREFIX: RISC_PREFIX,
  EVENTS: EVENTS,
  SSF_EVENTS: SSF_EVENTS,
  CAEP_EVENTS: CAEP_EVENTS,
  CAEP_EVENT_URIS: CAEP_EVENT_URIS,
  CAEP_COMMON_MEMBERS: CAEP_COMMON_MEMBERS,
  RISC_EVENTS: RISC_EVENTS,
  RISC_EVENT_URIS: RISC_EVENT_URIS,
  RISC_COMMON_MEMBERS: RISC_COMMON_MEMBERS,
  CREDENTIAL_TYPES: CREDENTIAL_TYPES,
  subjectAdvice: subjectAdvice,
  EVENT_URIS: EVENT_URIS,
  EVENT_BY_URI: EVENT_BY_URI,
  STS_PREFIX: STS_PREFIX,
  STS_EVENTS: STS_EVENTS,
  /**
   * This service's event type for a rotation of a realm's signing keys.
   */
  SIGNING_KEY_ROTATED: STS_PREFIX + 'signing-key-rotated',
  /**
   * This service's event type for an administrator's announcement to the
   * people signed in to its own three applications (#1086).
   */
  ANNOUNCEMENT: STS_PREFIX + 'announcement',
  /**
   * This service's event type for a krbtgt key rotated with nothing kept, which
   * invalidates every ticket-granting ticket the realm issued.
   */
  KERBEROS_TICKETS_INVALIDATED: STS_PREFIX + 'kerberos-tickets-invalidated',
  /**
   * This service's event type for a rotation of an OpenID Federation entity
   * key.
   */
  FEDERATION_KEY_ROTATED: STS_PREFIX + 'federation-key-rotated',
  /**
   * This service's event type for a rotation of a SPIFFE authority.
   */
  SPIFFE_AUTHORITY_ROTATED: STS_PREFIX + 'spiffe-authority-rotated',
  /**
   * This service's event type for a change of the listener certificate.
   */
  TLS_CERTIFICATE_CHANGED: STS_PREFIX + 'tls-certificate-changed',
  STATUSES: STATUSES,
  supportedEventUris: supportedEventUris,
  validateEvent: validateEvent,
  buildSet: buildSet,
  signSet: signSet,
  signSetSync: signSetSync,
  signingAlgorithm: signingAlgorithm,
  describeSet: describeSet,
  readSet: readSet,
  verifySet: verifySet,
  publicKeyForHeader: publicKeyForHeader,
  SET_MEDIA_TYPE: SET_MEDIA_TYPE,
  STS: STS
};
