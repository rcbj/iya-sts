// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: uma_store.ts
//
// ===========================================================================
// THE USER-MANAGED ACCESS STORES (#1168, phase 1): six per-realm, persisted
// `realms.map()` stores, GNAP's `gnap_store.ts` pattern, and the one
// module that writes any of them.
//
//   uma.resources      `_id` → a registered resource (Federated
//                      Authorization section 3): the resource server, the
//                      owner's subject and kind, `resource_scopes`, `name`,
//                      `type`, `description`, `icon_uri`, created and
//                      updated. Indexed by owner and by resource server.
//   uma.ownerPolicies  owner key → the owner's XACML document, its version
//                      and when it was last written (rcbj's decision 1 on
//                      #1168: a store of its own, never `ou=policies` —
//                      one per PERSON is not one per application, and
//                      `xacml.maxPolicies` was sized for a repository).
//   uma.tickets        digest → a permission ticket (the Grant
//                      specification section 3.2; Federated Authorization
//                      section 4): the resource server, the owner, the
//                      requested permissions, the client once one presented
//                      it, the gathered claims, and the state.
//   uma.pcts           digest → a persisted claims token's record: the
//                      requesting party, the claims, the client, expiry.
//   uma.rpts           jti → an RPT's permissions, resource server, owners,
//                      requesting party, client, expiry, `upgradedFrom`.
//                      Indexed by resource, owner and requesting party, so
//                      a revocation finds every token a change reaches.
//   uma.pending        id → an owner's approval waiting (`request_submitted`,
//                      phase 5). Indexed by owner.
//
// THE RULES THIS FILE HONOURS, each `persistence/CLAUDE.md`'s:
//
//   * a row is JSON. Nothing but strings, numbers, booleans and arrays of
//     them; a key object never reaches a row.
//   * an in-place edit is re-set: every mutation goes through a `save*()`
//     here, because the journal sees set/delete and nothing else.
//   * NO BEARER VALUE IS A KEY: a ticket and a PCT are stored by their
//     SHA-256 (`digestOf()`), so a dump of the store holds no working
//     handle. An RPT is a JWT the realm signed, keyed by its `jti` as
//     `admin_stats` keys every token.
//   * expiry is checked on READ, never only by a timer: a row past its
//     life reads as absent (`live*()`), and `realms.expiryField()` lets a
//     start's load and the sweep drop it. The sweep itself is a scheduler
//     job (phase 2), as rcbj's directive requires.
//   * A SINGLE-USE VALUE IS SPENT ONCE ACROSS THE CLUSTER (#46): `spend()`
//     is GNAP's, a `cluster_claims.claim()` in the scope `uma.<kind>` that
//     exactly one caller on any node wins, failing CLOSED when the claim
//     store cannot be asked (STS-UMA-0001).
//
// A LIBRARY (rule 3): no route, no slot, no require of a route module.
// Nothing here differs by mode.
//
// TYPESCRIPT, AS A CLASS (#50): `UmaStore` takes the logger, the stores,
// the cluster claims, the digest and the clock through its constructor;
// the stores stay module-level because a store becomes per realm at its
// DECLARATION (`tests/realm_isolation.js`). The exports are facades over
// the instance the composition root builds.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import realms = require('../common/realms');
import clusterClaims = require('../cluster/cluster_claims');
import errorCodes = require('../common/error_codes');
import config = require('../common/config');
import stsCrypto = require('../common/crypto');

const { log } = helpers;

type Json = any;

// The parts of a `realms.map()` store this module uses.
interface Store {
  has(key: string): boolean;
  get(key: string): Json;
  set(key: string, value: Json): unknown;
  delete(key: string): boolean;
  forEach(fn: (value: Json, key: string) => void): void;
  lookup(indexKey: string): string[];
}

interface UmaStores {
  resources: Store;
  ownerPolicies: Store;
  tickets: Store;
  pcts: Store;
  rpts: Store;
  pending: Store;
}

interface UmaStoreDeps {
  log: { debug(message: string): void; warn(message: string): void;
         error(message: string): void };
  nowSec(): number;
  randomId(bytes: number): string;
  digestOf(value: string): string;
  clusterClaims: { claim(ask: object): Promise<Json>;
                   release(handle: unknown): Json };
  errorCodes: { tag(code: string): string;
                mark(target: Json, code: string): Json };
  config: { value(key: string): Json };
  stores: UmaStores;
}

// The states of a permission ticket (#1168's decision 5).
const TICKET_STATES = Object.freeze(['issued', 'presented', 'needs-info',
                                     'submitted', 'granted', 'denied',
                                     'expired']);

// The lifetime a claim outlives the value it guards by, for clocks that
// disagree (GNAP's figure).
const CLAIM_SKEW_S = 120;

// How many dead rows one write prunes at most: bounded, so a backlog is
// cleaned over several writes rather than in one.
const PRUNE_BUDGET = 64;

// The index keys. A resource is filed under its owner and its resource
// server; an RPT under each resource, each owner and its requesting party.
const INDEX = {
  owner: function (key: unknown): string {
    return 'owner:' + String(key || '');
  },
  resourceServer: function (key: unknown): string {
    return 'rs:' + String(key || '');
  },
  resource: function (key: unknown): string {
    return 'resource:' + String(key || '');
  },
  requestingParty: function (key: unknown): string {
    return 'rp:' + String(key || '');
  }
};

const resources = realms.map({
  persist: 'uma.resources',
  // A hot path (every row a flush writes): no Entering/Leaving pair.
  indexBy: function (row: Json): string[] {
    if (!row || typeof row !== 'object') {
      return [];
    }
    return [INDEX.owner(row.owner), INDEX.resourceServer(row.resourceServer)];
  }
});
const ownerPolicies = realms.map({ persist: 'uma.ownerPolicies' });
const tickets = realms.map({ persist: 'uma.tickets', retain: 'age',
                             expiresAt: realms.expiryField('expiresAt',
                                                           1000) });
const pcts = realms.map({ persist: 'uma.pcts', retain: 'age',
                          expiresAt: realms.expiryField('expiresAt', 1000) });
const rpts = realms.map({
  persist: 'uma.rpts',
  expiresAt: realms.expiryField('exp', 1000),
  // A hot path: no Entering/Leaving pair.
  indexBy: function (row: Json): string[] {
    if (!row || typeof row !== 'object') {
      return [];
    }
    const keys: string[] = [INDEX.requestingParty(row.requestingParty)];
    (Array.isArray(row.permissions) ? row.permissions : [])
      .forEach(function (one: Json) {
        const key = INDEX.resource(one && one.resource_id);
        if (keys.indexOf(key) < 0) {
          keys.push(key);
        }
      });
    (Array.isArray(row.owners) ? row.owners : []).forEach(function (o: Json) {
      const key = INDEX.owner(o);
      if (keys.indexOf(key) < 0) {
        keys.push(key);
      }
    });
    return keys;
  }
});
const pending = realms.map({
  persist: 'uma.pending', retain: 'age',
  expiresAt: realms.expiryField('expiresAt', 1000),
  // A hot path: no Entering/Leaving pair.
  indexBy: function (row: Json): string[] {
    return row && typeof row === 'object' ? [INDEX.owner(row.owner)] : [];
  }
});

/**
 * The six User-Managed Access stores and the one way each is written.
 */
class UmaStore {
  /** The states a permission ticket moves through. */
  static readonly TICKET_STATES = TICKET_STATES;

  /**
   * Builds the store over its dependencies.
   *
   * @param deps - the logger, clock, ids, digest, cluster claims, error
   *   codes, settings and the six stores
   */
  constructor(private readonly deps: UmaStoreDeps) {
    deps.log.debug("Entering UmaStore.constructor().");
    deps.log.debug("Leaving UmaStore.constructor().");
  }

  /**
   * The dependencies built from the real modules.
   *
   * @returns the dependencies
   */
  static defaultDeps(): UmaStoreDeps {
    log.debug("Entering UmaStore.defaultDeps().");
    log.debug("Leaving UmaStore.defaultDeps().");
    return {
      log: log,
      nowSec: helpers.nowSec,
      randomId: helpers.randomId,
      digestOf: function (value: string): string {
        return stsCrypto.digest('sha256', String(value), 'hex');
      },
      clusterClaims: clusterClaims,
      errorCodes: errorCodes,
      config: config,
      stores: { resources: resources, ownerPolicies: ownerPolicies,
                tickets: tickets, pcts: pcts, rpts: rpts, pending: pending }
    };
  }

  // -------------------------------------------------------------------------
  // RESOURCES.
  // -------------------------------------------------------------------------

  /**
   * Writes a registered resource, as registered or as updated.
   *
   * @param row - the resource; `_id` is minted when absent
   * @returns the row as stored
   */
  saveResource(row: Json): Json {
    const { log, nowSec, randomId, stores } = this.deps;
    log.debug("Entering UmaStore.saveResource().");
    const kept = Object.assign({}, row || {});
    if (!kept._id) {
      kept._id = randomId(16);
      kept.createdAt = nowSec();
    }
    kept.updatedAt = nowSec();
    stores.resources.set(String(kept._id), kept);
    log.debug("Leaving UmaStore.saveResource(). " + kept._id);
    return kept;
  }

  /**
   * One registered resource.
   *
   * @param id - its `_id`
   * @returns the row, or null
   */
  resource(id: string): Json {
    const { log, stores } = this.deps;
    log.debug("Entering UmaStore.resource().");
    const found = stores.resources.get(String(id || '')) || null;
    log.debug("Leaving UmaStore.resource(). " + !!found);
    return found;
  }

  /**
   * Removes a registered resource.
   *
   * @param id - its `_id`
   * @returns true when it was there
   */
  deleteResource(id: string): boolean {
    const { log, stores } = this.deps;
    log.debug("Entering UmaStore.deleteResource().");
    const gone = stores.resources.delete(String(id || ''));
    log.debug("Leaving UmaStore.deleteResource(). " + gone);
    return gone;
  }

  // The rows an index names, in creation order, skipping any that vanished
  // between the index and the read.
  private indexed(store: Store, indexKey: string): Json[] {
    const { log } = this.deps;
    log.debug("Entering UmaStore.indexed(). " + indexKey);
    const out = store.lookup(indexKey).map(function (key: string) {
      return store.get(key);
    }).filter(function (row: Json) {
      return !!row;
    }).sort(function (a: Json, b: Json) {
      return (Number(a.createdAt) || 0) - (Number(b.createdAt) || 0);
    });
    log.debug("Leaving UmaStore.indexed(). " + out.length);
    return out;
  }

  /**
   * The resources an owner registered (through any resource server).
   *
   * @param owner - the owner's key
   * @returns the rows, oldest first
   */
  resourcesOf(owner: string): Json[] {
    const { log, stores } = this.deps;
    log.debug("Entering UmaStore.resourcesOf().");
    const out = this.indexed(stores.resources, INDEX.owner(owner));
    log.debug("Leaving UmaStore.resourcesOf(). " + out.length);
    return out;
  }

  /**
   * The resources a resource server registered.
   *
   * @param resourceServer - the application's identifier
   * @returns the rows, oldest first
   */
  resourcesOfServer(resourceServer: string): Json[] {
    const { log, stores } = this.deps;
    log.debug("Entering UmaStore.resourcesOfServer().");
    const out = this.indexed(stores.resources,
                             INDEX.resourceServer(resourceServer));
    log.debug("Leaving UmaStore.resourcesOfServer(). " + out.length);
    return out;
  }

  // -------------------------------------------------------------------------
  // OWNER POLICIES. The document is XACML XML as `xacml_xml.js` writes it;
  // whoever writes one has parsed it first (phase 3's `uma_owner_policy.ts`
  // does, through `xacml_store.parseDocument()`). The two bounds are held
  // HERE, at the one writer, so no door can exceed them.
  // -------------------------------------------------------------------------

  /**
   * An owner's document.
   *
   * @param owner - the owner's key
   * @returns `{ owner, document, version, updatedAt, createdAt }`, or null
   */
  ownerPolicy(owner: string): Json {
    const { log, stores } = this.deps;
    log.debug("Entering UmaStore.ownerPolicy().");
    const found = stores.ownerPolicies.get(String(owner || '')) || null;
    log.debug("Leaving UmaStore.ownerPolicy(). " + !!found);
    return found;
  }

  /**
   * Writes an owner's document, within `uma.maxOwnerPolicyBytes` and
   * `uma.maxOwnerRules`.
   *
   * @param owner - the owner's key
   * @param document - the XACML XML
   * @param facts - `version` (the document's), `rules` (its rule count)
   * @returns `{ ok: true, row }`, or `{ ok: false, code, why }`
   */
  saveOwnerPolicy(owner: string, document: string, facts: Json): Json {
    const { log, nowSec, stores, config, errorCodes } = this.deps;
    log.debug("Entering UmaStore.saveOwnerPolicy().");
    const key = String(owner || '');
    const text = String(document || '');
    const given = facts || {};
    const maxBytes = Number(config.value('uma.maxOwnerPolicyBytes'));
    const bytes = Buffer.byteLength(text, 'utf8');
    if (!key) {
      log.debug("Leaving UmaStore.saveOwnerPolicy(). No owner.");
      return errorCodes.mark({ ok: false, code: 'STS-UMA-0002',
        why: 'An owner document needs an owner.' }, 'STS-UMA-0002');
    }
    if (bytes > maxBytes) {
      log.warn(errorCodes.tag('STS-UMA-0002') + 'uma: the document of ' +
               'the owner "' + key + '" is ' + bytes + ' bytes, over ' +
               'uma.maxOwnerPolicyBytes (' + maxBytes + '); not written.');
      log.debug("Leaving UmaStore.saveOwnerPolicy(). Too large.");
      return errorCodes.mark({ ok: false, code: 'STS-UMA-0002',
        why: 'The document is ' + bytes + ' bytes, over this realm\'s ' +
             'uma.maxOwnerPolicyBytes (' + maxBytes + ').' },
        'STS-UMA-0002');
    }
    const maxRules = Number(config.value('uma.maxOwnerRules'));
    const rules = Number(given.rules);
    if (Number.isFinite(rules) && rules > maxRules) {
      log.warn(errorCodes.tag('STS-UMA-0003') + 'uma: the document of ' +
               'the owner "' + key + '" holds ' + rules + ' rules, over ' +
               'uma.maxOwnerRules (' + maxRules + '); not written.');
      log.debug("Leaving UmaStore.saveOwnerPolicy(). Too many rules.");
      return errorCodes.mark({ ok: false, code: 'STS-UMA-0003',
        why: 'The document holds ' + rules + ' rules, over this realm\'s ' +
             'uma.maxOwnerRules (' + maxRules + ').' }, 'STS-UMA-0003');
    }
    const was = stores.ownerPolicies.get(key);
    const row = { owner: key, document: text,
                  version: String(given.version || '1.0'),
                  rules: Number.isFinite(rules) ? rules : null,
                  createdAt: was ? was.createdAt : nowSec(),
                  updatedAt: nowSec() };
    stores.ownerPolicies.set(key, row);
    log.debug("Leaving UmaStore.saveOwnerPolicy(). Written.");
    return { ok: true, row: row };
  }

  /**
   * Removes an owner's document (with the person's account, phase 3).
   *
   * @param owner - the owner's key
   * @returns true when it was there
   */
  deleteOwnerPolicy(owner: string): boolean {
    const { log, stores } = this.deps;
    log.debug("Entering UmaStore.deleteOwnerPolicy().");
    const gone = stores.ownerPolicies.delete(String(owner || ''));
    log.debug("Leaving UmaStore.deleteOwnerPolicy(). " + gone);
    return gone;
  }

  // -------------------------------------------------------------------------
  // HANDLES: tickets and PCTs, stored by digest.
  // -------------------------------------------------------------------------

  /**
   * The key a handle is stored under: its SHA-256, so the store holds no
   * working value.
   *
   * @param value - the ticket or PCT value
   * @returns the key
   */
  handleKey(value: string): string {
    const { log, digestOf } = this.deps;
    log.debug("Entering UmaStore.handleKey().");
    const out = digestOf(String(value || ''));
    log.debug("Leaving UmaStore.handleKey().");
    return out;
  }

  // A row still inside its life, or null. `live()` rather than a sweep is
  // what answers a lookup (the header).
  private live(store: Store, key: string): Json {
    const { log, nowSec } = this.deps;
    log.debug("Entering UmaStore.live().");
    const row = store.get(key);
    if (!row) {
      log.debug("Leaving UmaStore.live(). Absent.");
      return null;
    }
    const until = Number(row.expiresAt);
    if (Number.isFinite(until) && until > 0 && until <= nowSec()) {
      log.debug("Leaving UmaStore.live(). Expired.");
      return null;
    }
    log.debug("Leaving UmaStore.live().");
    return row;
  }

  /**
   * Mints a permission ticket and stores its record (state `issued`).
   *
   * @param row - the resource server, the owner, the requested
   *   permissions and anything else the endpoint records
   * @param lifetimeS - `uma.ticketLifetimeS`
   * @returns `{ value, row }`: the value the client is handed, once
   */
  issueTicket(row: Json, lifetimeS: number): Json {
    const { log, nowSec, randomId, stores } = this.deps;
    log.debug("Entering UmaStore.issueTicket().");
    const value = randomId(32);
    const now = nowSec();
    const kept = Object.assign({}, row || {}, {
      key: this.handleKey(value),
      state: 'issued',
      issuedAt: now,
      updatedAt: now,
      expiresAt: now + Math.max(1, Number(lifetimeS) || 1)
    });
    stores.tickets.set(kept.key, kept);
    this.prune(stores.tickets);
    log.debug("Leaving UmaStore.issueTicket().");
    return { value: value, row: kept };
  }

  /**
   * A ticket's record, by its value, while it is live.
   *
   * @param value - the ticket
   * @returns the row, or null
   */
  ticket(value: string): Json {
    const { log, stores } = this.deps;
    log.debug("Entering UmaStore.ticket().");
    const found = value ? this.live(stores.tickets, this.handleKey(value))
                        : null;
    log.debug("Leaving UmaStore.ticket(). " + !!found);
    return found;
  }

  /**
   * Re-sets a ticket's record after a change (its state, the client, the
   * gathered claims).
   *
   * @param row - the record, `key` included
   * @returns the row
   */
  saveTicket(row: Json): Json {
    const { log, nowSec, stores } = this.deps;
    log.debug("Entering UmaStore.saveTicket().");
    const kept = Object.assign({}, row, { updatedAt: nowSec() });
    if (TICKET_STATES.indexOf(String(kept.state)) < 0) {
      kept.state = 'issued';
    }
    stores.tickets.set(String(kept.key), kept);
    log.debug("Leaving UmaStore.saveTicket(). " + kept.state);
    return kept;
  }

  /**
   * Rotates a ticket: the old record ends in `state`, a new value is
   * minted carrying the record forward (the Grant specification's MUST
   * NOT reuse a ticket value on `need_info` and `request_submitted`).
   *
   * @param row - the old record
   * @param state - the old record's final state
   * @param lifetimeS - the new ticket's lifetime
   * @returns `{ value, row }` of the new ticket
   */
  rotateTicket(row: Json, state: string, lifetimeS: number): Json {
    const { log, stores } = this.deps;
    log.debug("Entering UmaStore.rotateTicket(). " + state);
    const ended = Object.assign({}, row, {
      state: TICKET_STATES.indexOf(state) >= 0 ? state : 'expired',
      rotated: true });
    stores.tickets.set(String(ended.key), ended);
    const carried = Object.assign({}, row);
    delete carried.key;
    delete carried.state;
    delete carried.rotated;
    carried.rotatedFrom = String(row.key || '');
    const made = this.issueTicket(carried, lifetimeS);
    log.debug("Leaving UmaStore.rotateTicket().");
    return made;
  }

  /**
   * Mints a persisted claims token and stores its record.
   *
   * @param row - the requesting party, the claims, the client
   * @param lifetimeS - `uma.pctLifetimeS`
   * @returns `{ value, row }`
   */
  issuePct(row: Json, lifetimeS: number): Json {
    const { log, nowSec, randomId, stores } = this.deps;
    log.debug("Entering UmaStore.issuePct().");
    const value = randomId(32);
    const now = nowSec();
    const kept = Object.assign({}, row || {}, {
      key: this.handleKey(value), issuedAt: now, updatedAt: now,
      expiresAt: now + Math.max(1, Number(lifetimeS) || 1) });
    stores.pcts.set(kept.key, kept);
    this.prune(stores.pcts);
    log.debug("Leaving UmaStore.issuePct().");
    return { value: value, row: kept };
  }

  /**
   * A PCT's record, by its value, while it is live.
   *
   * @param value - the PCT
   * @returns the row, or null
   */
  pct(value: string): Json {
    const { log, stores } = this.deps;
    log.debug("Entering UmaStore.pct().");
    const found = value ? this.live(stores.pcts, this.handleKey(value))
                        : null;
    log.debug("Leaving UmaStore.pct(). " + !!found);
    return found;
  }

  /**
   * Ends a PCT (a revocation, a sign-out of everything, an account ending).
   *
   * @param value - the PCT, or its key when `byKey` is true
   * @param byKey - whether `value` is already the stored key
   * @returns true when it was there
   */
  deletePct(value: string, byKey?: boolean): boolean {
    const { log, stores } = this.deps;
    log.debug("Entering UmaStore.deletePct().");
    const gone = stores.pcts.delete(byKey ? String(value || '')
                                          : this.handleKey(value));
    log.debug("Leaving UmaStore.deletePct(). " + gone);
    return gone;
  }

  /**
   * Every live PCT record of a requesting party — for a sign-out of
   * everything and an account ending (phase 4).
   *
   * @param requestingParty - the person's subject
   * @returns the rows
   */
  pctsOf(requestingParty: string): Json[] {
    const { log, nowSec, stores } = this.deps;
    log.debug("Entering UmaStore.pctsOf().");
    const wanted = String(requestingParty || '');
    const now = nowSec();
    const out: Json[] = [];
    stores.pcts.forEach(function (row: Json) {
      if (row && String(row.requestingParty || '') === wanted &&
          !(Number(row.expiresAt) > 0 && Number(row.expiresAt) <= now)) {
        out.push(row);
      }
    });
    log.debug("Leaving UmaStore.pctsOf(). " + out.length);
    return out;
  }

  // -------------------------------------------------------------------------
  // RPTs: one record per issued token, by jti, indexed for revocation.
  // -------------------------------------------------------------------------

  /**
   * Records an issued RPT.
   *
   * @param row - `jti`, `permissions`, `resourceServer`, `owners`,
   *   `requestingParty`, `client`, `exp`, `upgradedFrom`
   * @returns the row
   */
  saveRpt(row: Json): Json {
    const { log, nowSec, stores } = this.deps;
    log.debug("Entering UmaStore.saveRpt().");
    const kept = Object.assign({ createdAt: nowSec() }, row || {},
                               { updatedAt: nowSec() });
    stores.rpts.set(String(kept.jti), kept);
    this.prune(stores.rpts, 'exp');
    log.debug("Leaving UmaStore.saveRpt(). " + kept.jti);
    return kept;
  }

  /**
   * An RPT's record.
   *
   * @param jti - the token's jti
   * @returns the row, or null
   */
  rpt(jti: string): Json {
    const { log, stores } = this.deps;
    log.debug("Entering UmaStore.rpt().");
    const found = stores.rpts.get(String(jti || '')) || null;
    log.debug("Leaving UmaStore.rpt(). " + !!found);
    return found;
  }

  /**
   * Removes an RPT's record (after its revocation is recorded where tokens
   * are revoked, `admin_stats.revoke()`).
   *
   * @param jti - the token's jti
   * @returns true when it was there
   */
  deleteRpt(jti: string): boolean {
    const { log, stores } = this.deps;
    log.debug("Entering UmaStore.deleteRpt().");
    const gone = stores.rpts.delete(String(jti || ''));
    log.debug("Leaving UmaStore.deleteRpt(). " + gone);
    return gone;
  }

  /**
   * The RPT records carrying a resource, held by an owner, or issued to a
   * requesting party.
   *
   * @param by - `resource`, `owner` or `requestingParty`
   * @param key - the resource's `_id`, the owner's key or the party's
   *   subject
   * @returns the rows
   */
  rptsBy(by: string, key: string): Json[] {
    const { log, stores } = this.deps;
    log.debug("Entering UmaStore.rptsBy(). " + by);
    const index = by === 'resource' ? INDEX.resource(key)
      : (by === 'owner' ? INDEX.owner(key)
        : (by === 'requestingParty' ? INDEX.requestingParty(key) : ''));
    const out = index ? this.indexed(stores.rpts, index) : [];
    log.debug("Leaving UmaStore.rptsBy(). " + out.length);
    return out;
  }

  // -------------------------------------------------------------------------
  // PENDING APPROVALS (phase 5 fills them).
  // -------------------------------------------------------------------------

  /**
   * Writes a pending approval.
   *
   * @param row - `owner`, `ticketKey`, `requestingParty`, `client`, the
   *   permissions asked, `expiresAt`; `id` minted when absent
   * @returns the row
   */
  savePending(row: Json): Json {
    const { log, nowSec, randomId, stores } = this.deps;
    log.debug("Entering UmaStore.savePending().");
    const kept = Object.assign({}, row || {});
    if (!kept.id) {
      kept.id = randomId(12);
      kept.createdAt = nowSec();
    }
    kept.updatedAt = nowSec();
    stores.pending.set(String(kept.id), kept);
    this.prune(stores.pending);
    log.debug("Leaving UmaStore.savePending(). " + kept.id);
    return kept;
  }

  /**
   * A pending approval, while it is live.
   *
   * @param id - its id
   * @returns the row, or null
   */
  pendingOne(id: string): Json {
    const { log, stores } = this.deps;
    log.debug("Entering UmaStore.pendingOne().");
    const found = this.live(stores.pending, String(id || ''));
    log.debug("Leaving UmaStore.pendingOne(). " + !!found);
    return found;
  }

  /**
   * The live pending approvals waiting for an owner.
   *
   * @param owner - the owner's key
   * @returns the rows, oldest first
   */
  pendingOf(owner: string): Json[] {
    const { log, nowSec, stores } = this.deps;
    log.debug("Entering UmaStore.pendingOf().");
    const now = nowSec();
    const out = this.indexed(stores.pending, INDEX.owner(owner))
      .filter(function (row: Json) {
        return !(Number(row.expiresAt) > 0 && Number(row.expiresAt) <= now);
      });
    log.debug("Leaving UmaStore.pendingOf(). " + out.length);
    return out;
  }

  /**
   * Removes a pending approval.
   *
   * @param id - its id
   * @returns true when it was there
   */
  deletePending(id: string): boolean {
    const { log, stores } = this.deps;
    log.debug("Entering UmaStore.deletePending().");
    const gone = stores.pending.delete(String(id || ''));
    log.debug("Leaving UmaStore.deletePending(). " + gone);
    return gone;
  }

  // -------------------------------------------------------------------------
  // SPENDING A SINGLE-USE VALUE ONCE ACROSS THE CLUSTER (#46): GNAP's
  // `spend()`, in the scope `uma.<kind>`. Resolves `{ ok: true, handle }`,
  // or `{ ok: false, reason, errorCode }` where `reason` is `used` (the
  // caller refuses with the protocol's own error and `usedCode`) or `store`
  // (STS-UMA-0001, fail closed). It never rejects.
  // -------------------------------------------------------------------------
  /**
   * Claims a value once across the cluster before acting on it.
   *
   * @param kind - what the value is (`ticket`, `pct`)
   * @param value - the value
   * @param lifetimeS - its lifetime, in seconds
   * @param usedCode - the error code of a value already spent
   * @returns `{ ok: true, handle }`, or `{ ok: false, reason, errorCode }`
   */
  spend(kind: string, value: unknown, lifetimeS: unknown,
        usedCode: string): Promise<Json> {
    const { log, clusterClaims, errorCodes } = this.deps;
    log.debug("Entering UmaStore.spend(). kind=" + kind);
    const seconds = Number(lifetimeS);
    const ttlS = (Number.isFinite(seconds) && seconds > 0 ? seconds
                                                          : 86400) +
                 CLAIM_SKEW_S;
    log.debug("Leaving UmaStore.spend(). Asking the claim store.");
    return clusterClaims.claim({ scope: 'uma.' + kind, value: value,
                                 ttlMs: ttlS * 1000 })
      .then(function (claimed: Json) {
        log.debug("Entering UmaStore.spend()'s answer.");
        if (claimed.ok) {
          log.debug("Leaving UmaStore.spend()'s answer. Spent here.");
          return claimed;
        }
        if (claimed.reason === 'used') {
          log.warn(errorCodes.tag(usedCode) + 'uma: a single-use value ' +
                   '("' + kind + '") this process still accepted was ' +
                   'ALREADY SPENT, on this node or another against the ' +
                   'same store. Refused.');
          log.debug("Leaving UmaStore.spend()'s answer. Used.");
          return { ok: false, reason: 'used', errorCode: usedCode };
        }
        log.error(errorCodes.tag('STS-UMA-0001') + 'uma: whether a ' +
                  'single-use value ("' + kind + '") was already spent ' +
                  'could not be asked of the claim store (' +
                  (claimed.why || 'no reason given') + '). It is refused.');
        log.debug("Leaving UmaStore.spend()'s answer. Store unavailable.");
        return { ok: false, reason: 'store', errorCode: 'STS-UMA-0001' };
      });
  }

  /**
   * Gives a claim back when what it guarded did not happen.
   *
   * @param handle - the claim's handle
   * @returns the release's result
   */
  unspend(handle: unknown): Json {
    const { log, clusterClaims } = this.deps;
    log.debug("Entering UmaStore.unspend().");
    log.debug("Leaving UmaStore.unspend().");
    return clusterClaims.release(handle);
  }

  // OPPORTUNISTIC PRUNE of rows past their life, bounded per call; the
  // scheduler's sweep (phase 2) does the rest.
  private prune(store: Store, field?: string): number {
    const { log, nowSec } = this.deps;
    log.debug("Entering UmaStore.prune().");
    const name = field || 'expiresAt';
    const now = nowSec();
    const dead: string[] = [];
    let seen = 0;
    store.forEach(function (row: Json, key: string) {
      seen += 1;
      if (dead.length >= PRUNE_BUDGET) {
        return;
      }
      const until = Number(row && row[name]);
      if (Number.isFinite(until) && until > 0 && until <= now) {
        dead.push(key);
      }
    });
    dead.forEach(function (key: string) {
      store.delete(key);
    });
    log.debug("Leaving UmaStore.prune(). " + dead.length + " of " + seen +
              " removed.");
    return dead.length;
  }

  /**
   * Removes every row past its life in the handle stores — the scheduler
   * job's body (phase 2), and a test's.
   *
   * @returns how many rows went, by store
   */
  sweep(): Json {
    const { log, stores } = this.deps;
    log.debug("Entering UmaStore.sweep().");
    const out = { tickets: 0, pcts: 0, pending: 0, rpts: 0 };
    let more = true;
    while (more) {
      const t = this.prune(stores.tickets);
      const p = this.prune(stores.pcts);
      const a = this.prune(stores.pending);
      const r = this.prune(stores.rpts, 'exp');
      out.tickets += t;
      out.pcts += p;
      out.pending += a;
      out.rpts += r;
      more = t === PRUNE_BUDGET || p === PRUNE_BUDGET ||
             a === PRUNE_BUDGET || r === PRUNE_BUDGET;
    }
    log.debug("Leaving UmaStore.sweep(). " + JSON.stringify(out));
    return out;
  }

  /**
   * Forgets every row of the ambient realm. For a test.
   */
  resetForTests(): void {
    const { log, stores } = this.deps;
    log.debug("Entering UmaStore.resetForTests().");
    [stores.resources, stores.ownerPolicies, stores.tickets, stores.pcts,
     stores.rpts, stores.pending].forEach(function (store) {
      const keys: string[] = [];
      store.forEach(function (value: Json, key: string) {
        keys.push(key);
      });
      keys.forEach(function (key: string) {
        store.delete(key);
      });
    });
    log.debug("Leaving UmaStore.resetForTests().");
  }
}

// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2); a process without
// the root builds a default when this module loads.
const slot = new InstanceSlot<UmaStore>(
  'uma/uma_store',
  () => new UmaStore(UmaStore.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The User-Managed Access stores (#1168).
 * @namespace
 */
export = {
  UmaStore: UmaStore,
  installInstance: (instance: UmaStore): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  TICKET_STATES: TICKET_STATES,
  saveResource: slot.forward('saveResource'),
  resource: slot.forward('resource'),
  deleteResource: slot.forward('deleteResource'),
  resourcesOf: slot.forward('resourcesOf'),
  resourcesOfServer: slot.forward('resourcesOfServer'),
  ownerPolicy: slot.forward('ownerPolicy'),
  saveOwnerPolicy: slot.forward('saveOwnerPolicy'),
  deleteOwnerPolicy: slot.forward('deleteOwnerPolicy'),
  handleKey: slot.forward('handleKey'),
  issueTicket: slot.forward('issueTicket'),
  ticket: slot.forward('ticket'),
  saveTicket: slot.forward('saveTicket'),
  rotateTicket: slot.forward('rotateTicket'),
  issuePct: slot.forward('issuePct'),
  pct: slot.forward('pct'),
  deletePct: slot.forward('deletePct'),
  pctsOf: slot.forward('pctsOf'),
  saveRpt: slot.forward('saveRpt'),
  rpt: slot.forward('rpt'),
  deleteRpt: slot.forward('deleteRpt'),
  rptsBy: slot.forward('rptsBy'),
  savePending: slot.forward('savePending'),
  pendingOne: slot.forward('pendingOne'),
  pendingOf: slot.forward('pendingOf'),
  deletePending: slot.forward('deletePending'),
  spend: slot.forward('spend'),
  unspend: slot.forward('unspend'),
  sweep: slot.forward('sweep'),
  resetForTests: slot.forward('resetForTests')
};
