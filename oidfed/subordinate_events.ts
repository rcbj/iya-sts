'use strict';
//
// File: subordinate_events.ts
//
// ===========================================================================
// WHAT HAPPENED TO EACH SUBORDINATE, KEPT FOR GOOD (#137, 2026-09-24):
// OpenID Federation Subordinate Events Endpoint 1.0, draft 01.
//
// A Trust Anchor or an Intermediate publishes, for each of its Immediate
// Subordinates, the history of what it did about it — registered it, changed
// the keys, metadata or policy its statement carries, suspended it, revoked
// it — at `federation_subordinate_events_endpoint`, as a signed
// `entity-events-statement+jwt`. This file KEEPS that history; `oidfed.ts`
// serves it.
//
// **IT IS APPEND-ONLY AND OUTLIVES THE SUBORDINATE** (rcbj, 2026-09-24):
// removing a subordinate records its revocation and deletes nothing, and a
// subordinate registered again later carries its earlier history with it —
// which is the point of a transparency log. Each subordinate's events are the
// values of one `events` entry in the realm's `ou=oidfed` register
// (`oidfed_store.ts`), one JSON event per value, and `stsOidfedEvent` is
// merged by value across a cluster, so two nodes recording at once both keep
// theirs. Nothing in this service deletes one.
//
// ---------------------------------------------------------------------------
// THE EVENTS (the draft's six, and four of this service's own).
//
// The draft defines `registration`, `metadata_update`,
// `metadata_policy_update`, `jwks_update`, `revocation` and `suspension`, and
// says a federation operator MAY define more, documented where the operator
// documents its federation. Four more are recorded here, and `docs/oidfed.md`
// documents them:
//
//   reinstatement           a suspended subordinate reinstated — the draft
//                           has a way in to suspension and none out, and a
//                           reader of a history ending in `suspension` could
//                           not otherwise tell that it ended
//   constraints_update      the statement's `constraints` changed; the
//                           Extended Listing's `updated` counts it (draft 03,
//                           table 4), and the events draft has no name for it
//   trust_mark_issuance     this realm issued the subordinate a Trust Mark
//   trust_mark_revocation   this realm revoked one — the two the ticket asked
//                           for, which the draft does not name either
//
// **A REGISTRATION IS RECORDED ALONE.** The draft: "When a registration event
// is present, metadata_update, metadata_policy_update, and jwks_update events
// MUST NOT be provided at the same time, since the Entity registration is
// assumed to configure the initial configuration". So the act that registers
// records `registration` and nothing else, and an act that CHANGES a
// registered subordinate records one update event per part that changed —
// `updatesBetween()` compares them.
//
// ---------------------------------------------------------------------------
// A REALM OF THIS SERVICE IS KEYED BY ITS REALM ID, NOT ITS IDENTIFIER.
//
// In the default topology every realm is a subordinate of the default realm,
// and three things happen to it with no administrator's request in sight: it
// is CREATED (its registration), its own Federation Entity Key ROTATES on
// the scheduler (a `jwks_update` — its superior's statement reads its keys
// live), and it is DELETED (its revocation). A realm's Entity Identifier is
// its issuer as seen from the request's host (`oidfed/CLAUDE.md`), and a
// background job has no request, so none of those three could name the
// realm by identifier. They are keyed `realm:<id>` in the DEFAULT realm's
// register instead, and `oidfed.ts` maps an identifier to the key when it
// answers — for a live realm by asking which realm has it, for a deleted
// one by the address the realm WOULD have under this request's base.
//
// **CREATION AND DELETION ARE RECORDED ON EVERY NODE** that hears of them
// (`realms.onChange()` fires where the act was made and again where the
// change log replays it), so their events carry an id derived from the realm
// and the instant it was CREATED — the same on every node, so the copies are
// one event (`history()` keeps the earliest of a duplicated id).
//
// A LIBRARY OF STATIC METHODS: it holds nothing in memory. Every call but the
// three realm hooks is AMBIENT-REALM; the hooks enter the default realm.
// ===========================================================================

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import realms = require('../common/realms');
import OidfedStore = require('./oidfed_store');

type Json = any;

const log = helpers.log;

const EVENTS = Object.freeze({
  REGISTRATION: 'registration',
  METADATA_UPDATE: 'metadata_update',
  METADATA_POLICY_UPDATE: 'metadata_policy_update',
  JWKS_UPDATE: 'jwks_update',
  REVOCATION: 'revocation',
  SUSPENSION: 'suspension',
  // This service's own (see the header), documented in docs/oidfed.md.
  REINSTATEMENT: 'reinstatement',
  CONSTRAINTS_UPDATE: 'constraints_update',
  TRUST_MARK_ISSUANCE: 'trust_mark_issuance',
  TRUST_MARK_REVOCATION: 'trust_mark_revocation'
});

const KNOWN: string[] = Object.keys(EVENTS).map(function (k: string): string {
  return (EVENTS as Json)[k];
});

// The draft's Event Object: `iat` and `event` required, the other two
// optional — plus `id`, which this service uses to merge the copies a
// cluster makes, and never serves.
interface SubordinateEvent {
  id: string;
  iat: number;
  event: string;
  event_description?: string;
  information_uri?: string;
}

const REALM_PREFIX = 'realm:';

class SubordinateEvents {
  static readonly EVENTS = EVENTS;
  static readonly REALM_PREFIX = REALM_PREFIX;

  // The key a realm of this service is recorded under.
  static realmKey(realmId: string): string {
    log.debug("Entering SubordinateEvents.realmKey().");
    log.debug("Leaving SubordinateEvents.realmKey().");
    return REALM_PREFIX + String(realmId);
  }

  // The realm id a key names, or '' for a registered subordinate's.
  static realmOfKey(key: string): string {
    log.debug("Entering SubordinateEvents.realmOfKey().");
    const out = String(key).indexOf(REALM_PREFIX) === 0
      ? String(key).slice(REALM_PREFIX.length) : '';
    log.debug("Leaving SubordinateEvents.realmOfKey().");
    return out;
  }

  // An https (or http) URL, as the draft's `information_uri` may be; '' when
  // `value` is empty, and null when it is something else.
  static informationUriOf(value: Json): string | null {
    log.debug("Entering SubordinateEvents.informationUriOf().");
    const text = String(value === undefined || value === null ? ''
                                                              : value).trim();
    if (!text) {
      log.debug("Leaving SubordinateEvents.informationUriOf(). None.");
      return '';
    }
    let url: URL;
    try {
      url = new URL(text);
    } catch (e: any) {
      log.debug("Caught in SubordinateEvents.informationUriOf(): " +
                ((e && e.message) || e));
      log.debug("Leaving SubordinateEvents.informationUriOf(). Not a URL.");
      return null;
    }
    const ok = (url.protocol === 'https:' || url.protocol === 'http:') &&
               !url.username && !url.password && text.length <= 2048;
    log.debug("Leaving SubordinateEvents.informationUriOf(). " + ok);
    return ok ? text : null;
  }

  // -------------------------------------------------------------------------
  // RECORD ONE EVENT about the subordinate `key` (whose Entity Identifier,
  // where known, is `entityId`). `options`: `description`, `informationUri`,
  // `atMs` (default now) and `id` (default random). Resolves the event as
  // written, or null when the register could not be written — which is
  // logged, and never fails the act that caused it: the act happened.
  // -------------------------------------------------------------------------
  static record(key: string, entityId: string, event: string,
                options?: Json): SubordinateEvent | null {
    log.debug("Entering SubordinateEvents.record(). " + event);
    const o = options || {};
    if (KNOWN.indexOf(event) < 0) {
      log.debug("Leaving SubordinateEvents.record(). Not an event.");
      throw new Error('"' + event + '" is not a subordinate event.');
    }
    const atMs = Number.isFinite(Number(o.atMs)) && Number(o.atMs) > 0
      ? Number(o.atMs) : Date.now();
    const ev: SubordinateEvent = {
      id: String(o.id || nodeCrypto.randomBytes(12).toString('hex')),
      iat: Math.floor(atMs / 1000),
      event: event
    };
    const description = String(o.description || '').trim().slice(0, 1000);
    if (description) {
      ev.event_description = description;
    }
    const uri = SubordinateEvents.informationUriOf(o.informationUri);
    if (uri) {
      ev.information_uri = uri;
    }
    const ok = OidfedStore.appendEvent(String(key), String(entityId || ''),
                                       JSON.stringify(ev));
    if (!ok) {
      log.warn(errorCodes.tag('STS-OIDFED-0065') + 'oidfed: the ' +
               event + ' event of ' + key + ' could not be written to the ' +
               'register.');
      log.debug("Leaving SubordinateEvents.record(). Not written.");
      return null;
    }
    log.debug("Leaving SubordinateEvents.record(). " + ev.id);
    return ev;
  }

  // -------------------------------------------------------------------------
  // THE HISTORY of the subordinate `key`, oldest first: each event once (the
  // earliest copy of an id a cluster recorded twice), in the order recorded
  // where two share a second.
  // -------------------------------------------------------------------------
  static history(key: string): SubordinateEvent[] {
    log.debug("Entering SubordinateEvents.history().");
    const byId: Record<string, SubordinateEvent> = {};
    const order: string[] = [];
    OidfedStore.eventValues(String(key)).forEach(function (v: string): void {
      let ev: Json = null;
      try {
        ev = JSON.parse(v);
      } catch (e: any) {
        log.debug("Caught in SubordinateEvents.history(): " +
                  ((e && e.message) || e));
        ev = null;
      }
      if (!ev || typeof ev !== 'object' || !ev.id || !ev.event ||
          !Number.isFinite(Number(ev.iat))) {
        return;
      }
      const held = byId[ev.id];
      if (!held) {
        order.push(ev.id);
        byId[ev.id] = ev;
      } else if (Number(ev.iat) < Number(held.iat)) {
        byId[ev.id] = ev;
      }
    });
    const out = order.map(function (id: string): SubordinateEvent {
      return byId[id];
    });
    out.sort(function (a: SubordinateEvent, b: SubordinateEvent): number {
      return Number(a.iat) - Number(b.iat);
    });
    log.debug("Leaving SubordinateEvents.history(). " + out.length);
    return out;
  }

  // Whether anything was ever recorded about `key`.
  static known(key: string): boolean {
    log.debug("Entering SubordinateEvents.known().");
    const out = OidfedStore.eventValues(String(key)).length > 0;
    log.debug("Leaving SubordinateEvents.known(). " + out);
    return out;
  }

  // The keys of every realm of this service recorded in the ambient realm's
  // register — live or deleted — for mapping an identifier back to one.
  static realmKeys(): string[] {
    log.debug("Entering SubordinateEvents.realmKeys().");
    const out: string[] = [];
    OidfedStore.entries(OidfedStore.KINDS.EVENTS).forEach(function (e) {
      const key = String((e.data || {}).key || '');
      if (SubordinateEvents.realmOfKey(key) && out.indexOf(key) < 0) {
        out.push(key);
      }
    });
    log.debug("Leaving SubordinateEvents.realmKeys(). " + out.length);
    return out;
  }

  // A value as canonical JSON — members sorted at every level — so two
  // records that say the same thing compare equal however they were built.
  static canonical(value: Json): string {
    log.debug("Entering SubordinateEvents.canonical().");
    // No Entering/Leaving pair in walk(): it runs once per member of every
    // level of a JWK Set or a metadata document, and at debug the pairs
    // would drown the log.
    const walk = function (v: Json): Json {
      if (Array.isArray(v)) {
        return v.map(walk);
      }
      if (v && typeof v === 'object') {
        const out: Json = {};
        Object.keys(v).sort().forEach(function (k: string): void {
          if (v[k] !== undefined) {
            out[k] = walk(v[k]);
          }
        });
        return out;
      }
      return v === undefined ? null : v;
    };
    const out = JSON.stringify(walk(value === undefined ? null : value));
    log.debug("Leaving SubordinateEvents.canonical().");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE UPDATE EVENTS between two records of one registered subordinate
  // (`oidfed.ts`'s register record: jwks, metadata, metadataPolicy with its
  // crit, constraints) — one per part that changed, in the draft's order.
  // -------------------------------------------------------------------------
  static updatesBetween(before: Json, after: Json): string[] {
    log.debug("Entering SubordinateEvents.updatesBetween().");
    const b = before || {};
    const a = after || {};
    const same = function (x: Json, y: Json): boolean {
      log.debug("Entering same().");
      log.debug("Leaving same().");
      return SubordinateEvents.canonical(x) === SubordinateEvents.canonical(y);
    };
    const out: string[] = [];
    if (!same(b.metadataPolicy, a.metadataPolicy) ||
        !same(b.metadataPolicyCrit || [], a.metadataPolicyCrit || [])) {
      out.push(EVENTS.METADATA_POLICY_UPDATE);
    }
    if (!same(b.metadata, a.metadata)) {
      out.push(EVENTS.METADATA_UPDATE);
    }
    if (!same(b.jwks, a.jwks)) {
      out.push(EVENTS.JWKS_UPDATE);
    }
    if (!same(b.constraints, a.constraints)) {
      out.push(EVENTS.CONSTRAINTS_UPDATE);
    }
    log.debug("Leaving SubordinateEvents.updatesBetween(). " + out.length);
    return out;
  }

  // -------------------------------------------------------------------------
  // THE THREE REALM HOOKS (see the header): recorded in the DEFAULT realm's
  // register, and only while the default topology makes every realm its
  // subordinate — a realm that was never a subordinate has no history as
  // one.
  // -------------------------------------------------------------------------
  private static inDefaultTopology(realmId: string): boolean {
    log.debug("Entering SubordinateEvents.inDefaultTopology().");
    const out = !!realmId && String(realmId) !== String(realms.DEFAULT_ID) &&
      realms.run(realms.get(realms.DEFAULT_ID), function (): boolean {
        return config.value('oidfed.realmsAreSubordinates') !== false;
      });
    log.debug("Leaving SubordinateEvents.inDefaultTopology(). " + out);
    return out;
  }

  // The id of the one event a realm's creation or deletion is, the same on
  // every node that records it.
  private static realmEventId(realmId: string, event: string,
                              createdAt: Json): string {
    log.debug("Entering SubordinateEvents.realmEventId().");
    const out = OidfedStore.digest(REALM_PREFIX + realmId + ' ' + event + ' ' +
                                   String(Number(createdAt) || 0));
    log.debug("Leaving SubordinateEvents.realmEventId().");
    return out;
  }

  static realmCreated(realmId: string, createdAt: Json): void {
    log.debug("Entering SubordinateEvents.realmCreated(). " + realmId);
    if (!SubordinateEvents.inDefaultTopology(realmId)) {
      log.debug("Leaving SubordinateEvents.realmCreated(). Not a " +
                "subordinate.");
      return;
    }
    realms.run(realms.get(realms.DEFAULT_ID), function (): void {
      SubordinateEvents.record(SubordinateEvents.realmKey(realmId), '',
        EVENTS.REGISTRATION, {
          atMs: Number(createdAt) || Date.now(),
          id: SubordinateEvents.realmEventId(realmId, EVENTS.REGISTRATION,
                                             createdAt),
          description: 'The realm "' + realmId + '" was created, a ' +
                       'subordinate of the default realm.' });
    });
    log.debug("Leaving SubordinateEvents.realmCreated().");
  }

  static realmRemoved(realmId: string, createdAt: Json): void {
    log.debug("Entering SubordinateEvents.realmRemoved(). " + realmId);
    if (!SubordinateEvents.inDefaultTopology(realmId)) {
      log.debug("Leaving SubordinateEvents.realmRemoved(). Not a " +
                "subordinate.");
      return;
    }
    realms.run(realms.get(realms.DEFAULT_ID), function (): void {
      SubordinateEvents.record(SubordinateEvents.realmKey(realmId), '',
        EVENTS.REVOCATION, {
          id: SubordinateEvents.realmEventId(realmId, EVENTS.REVOCATION,
                                             createdAt),
          description: 'The realm "' + realmId + '" was deleted.' });
    });
    log.debug("Leaving SubordinateEvents.realmRemoved().");
  }

  // The ambient realm's Federation Entity Keys changed — a key published or
  // revoked (`federation_keys.ts`).
  static realmKeysChanged(realmId: string, what: string): void {
    log.debug("Entering SubordinateEvents.realmKeysChanged(). " + realmId);
    if (!SubordinateEvents.inDefaultTopology(realmId)) {
      log.debug("Leaving SubordinateEvents.realmKeysChanged(). Not a " +
                "subordinate.");
      return;
    }
    realms.run(realms.get(realms.DEFAULT_ID), function (): void {
      SubordinateEvents.record(SubordinateEvents.realmKey(realmId), '',
        EVENTS.JWKS_UPDATE, { description: what });
    });
    log.debug("Leaving SubordinateEvents.realmKeysChanged().");
  }
}

export = SubordinateEvents;
