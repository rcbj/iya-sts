// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap_revocation.ts
//
// ---------------------------------------------------------------------------
// WHAT ENDS A GNAP GRANT FROM OUTSIDE THE PROTOCOL (#432 phase 2, 2026-10-03).
//
// RFC 9635 gives a grant two ends of its own: the client instance revokes it
// (section 5.4) and its tokens through token management (section 6.2). Until
// this file nothing else did. A person signed out everywhere, disabled or
// deleted, an application entry deleted or stripped of its key, a device
// marked compromised and a federation partner's verified signal all left every
// grant and token live — `logout/` never referenced GNAP (#432's gap 3). This
// is the ONE place each of those acts ends a grant, so they cannot come to
// disagree about what ending one means:
//
//   * **`endGrant()` IS THE CLIENT'S OWN SECTION 5.4 ACT** performed for
//     somebody else: every live token revoked (`revokeTokens()`, the
//     management handle dropped, a JWT's jti put in the one revocation set),
//     the grant FINALIZED with its continuation dropped, the monitor counted,
//     one audit row, and CAEP `session-revoked` about the grant through
//     `gnap_signals.ts` with the initiating entity the caller states. What a
//     client sees next is exactly what it would see had it revoked the grant
//     itself, which is why it is not a delete.
//   * **WHO HOLDS A GRANT** is `holderKeyOf()`: the resource owner's name and
//     subject through `admin_stats.holderKeyOf()`, the rule every sign-out
//     uses, so a grant is found by the same key a person's sessions and tokens
//     are.
//   * **THE CHECK AT USE** (`endedProblem()`): a grant whose resource owner is
//     DISABLED, or whose client's application entry is gone or no longer names
//     the key the grant is bound to, is refused at its next continuation,
//     rotation, derivation, presentation and introspection — whatever door
//     changed the account or the entry, and on a node the change has not yet
//     reached a moment later (the replication delay #432 names). It writes
//     nothing: the act that changed the account or the entry is what ends the
//     grant, and a second node ending it again at use would be a second CAEP
//     event for one end.
//
// **A KEY ROTATED IS NOT A KEY REMOVED.** RFC 9635 section 6.1.1's rotation
// moves an ACCESS TOKEN to a new key and leaves the entry alone, and a mutual
// TLS client rotated at its authority has the new thumbprint written to
// `gnapKeyIdentity` (`placeMtlsCaller()`); both keep their grants, because the
// identities compared are the entry's `gnapKey`, `gnapKeyIdentity` and
// `gnapKeyReference` as they are NOW. A grant bound to a key REFERENCE the
// entry still names is kept whatever the reference resolves to: every proof
// is checked against what it resolves to at that moment, so a changed key or
// secret behind it is a rotation, not a removal.
//
// **NO APPLICATION IS "DISABLED" HERE**: the registry has no such state (an
// application is refused by the issuance policy, `account_state.ts` says, and
// that refuses new tokens rather than ending old ones). What ends a client's
// grants is its entry DELETED or its key REMOVED or REPLACED.
//
// A LIBRARY (rule 3): it registers no route. It requires nothing of
// `gnap_grants.ts` — that module requires THIS one, for `revokeTokens()` and
// the check at use — and the signals and the account state are reached
// lazily, through loaders, at the moment they are needed.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import stats = require('../common/admin_stats');
import applications = require('../common/applications');
import stsCrypto = require('../common/crypto');
import store = require('./gnap_store');
import keys = require('./gnap_keys');
import monitor = require('./gnap_monitor');

type Json = any;

// How a caller ends a grant: in its own words, and who it was.
interface EndHow {
  // The transition, on the grant's history and the audit row.
  why?: string;
  // Who did it — a person, an administrator, a relationship.
  actor?: string;
  // The door, in the caller's words.
  via?: string;
  // CAEP section 2's initiating entity: `user`, `admin`, `policy`, `system`.
  initiatingEntity?: string;
  // The request, where there is one, for the CAEP issuer.
  req?: unknown;
  // The audit row's action; `gnap.grant.revoke` by default.
  action?: string;
}

// What a grant or a token is refused at use for.
interface Problem {
  code: string;
  why: string;
}

interface GnapRevocationDeps {
  log: typeof helpers.log;
  nowSec(): number;
  config: { value(key: string): any };
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  stats: typeof stats;
  applications: typeof applications;
  stsCrypto: typeof stsCrypto;
  store: typeof store;
  keys: typeof keys;
  monitor: typeof monitor;
  // Lazy, each a loader called when it is needed.
  loadSignals(): any;
  loadAccountState(): any;
}

/**
 * What ends a GNAP grant from outside the protocol — a sign-out, a disabled
 * or deleted person, a deleted application or its key removed, a compromised
 * device, a received signal — and the check at use that refuses one whose
 * owner or client is gone.
 */
class GnapRevocation {
  /**
   * Builds the revocation over the modules it reads.
   *
   * @param deps - the modules the composition root passes
   */
  constructor(private readonly deps: GnapRevocationDeps) {
    deps.log.debug("Entering GnapRevocation.constructor().");
    deps.log.debug("Leaving GnapRevocation.constructor().");
  }

  /**
   * Returns the real modules and lazy loaders the default instance is built
   * from.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): GnapRevocationDeps {
    helpers.log.debug("Entering GnapRevocation.defaultDeps().");
    helpers.log.debug("Leaving GnapRevocation.defaultDeps().");
    return {
      log: helpers.log,
      nowSec: helpers.nowSec,
      config: config,
      errorCodes: errorCodes,
      audit: audit,
      stats: stats,
      applications: applications,
      stsCrypto: stsCrypto,
      store: store,
      keys: keys,
      monitor: monitor,
      loadSignals: function () {
        return require('./gnap_signals');
      },
      loadAccountState: function () {
        return require('../common/account_state');
      }
    };
  }

  // -------------------------------------------------------------------------
  // THE TOKENS OF A GRANT. Moved here from `gnap_grants.ts` (which forwards
  // to it) so every end of a grant revokes them the one way.
  // -------------------------------------------------------------------------
  /**
   * Revokes every live access token a grant issued, and each one's
   * management token; a JWT's jti also goes into the one revocation set.
   *
   * @param grant - the grant
   * @param why - the reason recorded on each token
   * @returns how many tokens this call revoked
   */
  revokeTokens(grant: Json, why: string): number {
    const { log, nowSec, stats, store } = this.deps;
    log.debug("Entering GnapRevocation.revokeTokens().");
    let revoked = 0;
    (grant.tokens || []).forEach(function (jti: string) {
      const record = store.tokenByJti(jti);
      if (record && !record.revoked) {
        record.revoked = true;
        record.revokedAt = nowSec();
        record.revokedWhy = why;
        store.dropManagement(record);
        store.saveToken(record);
        revoked += 1;
        if (/^jwt/.test(record.format)) {
          stats.revoke(record.jti, 'GNAP: ' + why, undefined, record.exp);
        }
      }
    });
    log.debug("Leaving GnapRevocation.revokeTokens(). " + revoked);
    return revoked;
  }

  /**
   * Ends a grant as the client's own section 5.4 revocation does: its
   * tokens revoked, the grant finalized, counted, audited, and CAEP
   * `session-revoked` sent about it. A finalized grant is left alone.
   *
   * @param grant - the grant
   * @param how - why, who, through which door and CAEP's initiating entity
   * @returns true when this call ended it
   */
  endGrant(grant: Json, how?: EndHow): boolean {
    const { log, store, monitor, audit, loadSignals } = this.deps;
    log.debug("Entering GnapRevocation.endGrant(). " + (grant && grant.id));
    const h = how || {};
    if (!grant || grant.state === store.STATE.FINALIZED) {
      log.debug("Leaving GnapRevocation.endGrant(). Already finalized.");
      return false;
    }
    const why = String(h.why || 'revoked');
    const tokens = this.revokeTokens(grant, why);
    grant.state = store.STATE.FINALIZED;
    store.dropContinuation(grant);
    store.saveGrant(grant, why + (h.actor ? ' (' + h.actor + ')' : ''));
    monitor.record(grant.client.identifier, 'grant.revoked', {});
    audit.audit({ action: h.action || 'gnap.grant.revoke',
      category: 'protocol', protocol: 'GNAP', channel: 'internal',
      outcome: 'success', actor: String(h.actor || ''),
      target: grant.client.identifier,
      summary: 'A GNAP grant was ended: ' + why,
      detail: { grant: grant.id, tokens: String(tokens),
                via: String(h.via || ''),
                initiatingEntity: String(h.initiatingEntity || '') } });
    try {
      loadSignals().grantRevoked(h.req || null, grant, why + '.',
                                 h.initiatingEntity || 'system');
    } catch (e) {
      log.debug("Caught in GnapRevocation.endGrant(): " +
                ((e && e.message) || e));
      // The grant is ended; a signal that could not be started is the
      // signals module's to log, and never undoes the end.
    }
    log.debug("Leaving GnapRevocation.endGrant(). Ended.");
    return true;
  }

  // -------------------------------------------------------------------------
  // WHO HOLDS A GRANT. The resource owner, by the rule every sign-out files a
  // person's things under. `ro.sub` where the grant recorded one, else the
  // subject its first token carries, so a renamed person is still found by
  // the entry; a grant with no resource owner is held by nobody.
  // -------------------------------------------------------------------------
  /**
   * Returns the identity key a grant's resource owner files under, or ''
   * for a grant with none.
   *
   * @param grant - the grant
   * @returns the key, or ''
   */
  holderKeyOf(grant: Json): string {
    const { log, stats, store } = this.deps;
    log.debug("Entering GnapRevocation.holderKeyOf().");
    if (!grant || !grant.ro || !grant.ro.username) {
      log.debug("Leaving GnapRevocation.holderKeyOf(). Nobody.");
      return '';
    }
    let sub = String(grant.ro.sub || '');
    if (!sub && (grant.tokens || []).length) {
      const first = store.tokenByJti(grant.tokens[0]);
      sub = String((first && first.sub) || '');
    }
    log.debug("Leaving GnapRevocation.holderKeyOf().");
    return String(stats.holderKeyOf(grant.ro.username, sub) || '');
  }

  /**
   * Says whether a grant is still live: not finalized.
   *
   * @param grant - the grant
   * @returns true when it is live
   */
  isLive(grant: Json): boolean {
    const { log, store } = this.deps;
    log.debug("Entering GnapRevocation.isLive().");
    log.debug("Leaving GnapRevocation.isLive().");
    return !!grant && grant.state !== store.STATE.FINALIZED;
  }

  /**
   * The live grants each identity holds, from ONE walk of the store (the
   * batch form `logout.ts` reads, #351's rule).
   *
   * @param keys - the identity keys
   * @returns a Map from each key to its live grants, newest first
   */
  grantsByKey(keys: string[]): Map<string, Json[]> {
    const { log, store } = this.deps;
    log.debug("Entering GnapRevocation.grantsByKey(). " +
              (keys || []).length + " key(s).");
    const out = new Map<string, Json[]>();
    (keys || []).forEach(function (key) {
      out.set(String(key || ''), []);
    });
    store.listGrants().forEach((grant: Json) => {
      if (!this.isLive(grant)) {
        return;
      }
      const list = out.get(this.holderKeyOf(grant));
      if (list) {
        list.push(grant);
      }
    });
    log.debug("Leaving GnapRevocation.grantsByKey().");
    return out;
  }

  /**
   * The live grants one identity holds.
   *
   * @param key - the identity key
   * @returns the grants, newest first
   */
  grantsHeldBy(key: string): Json[] {
    const { log } = this.deps;
    log.debug("Entering GnapRevocation.grantsHeldBy(). " + key);
    const wanted = String(key || '');
    const out = wanted ? (this.grantsByKey([wanted]).get(wanted) || []) : [];
    log.debug("Leaving GnapRevocation.grantsHeldBy(). " + out.length);
    return out;
  }

  /**
   * Every live grant of the realm, for `/admin/sessions`.
   *
   * @returns the live grants that have a resource owner, newest first
   */
  liveHeldGrants(): Json[] {
    const { log, store } = this.deps;
    log.debug("Entering GnapRevocation.liveHeldGrants().");
    const out = store.listGrants().filter((grant: Json) => {
      return this.isLive(grant) && !!(grant.ro && grant.ro.username);
    });
    log.debug("Leaving GnapRevocation.liveHeldGrants(). " + out.length);
    return out;
  }

  /**
   * The live tokens a grant issued: not revoked, not past their expiry.
   *
   * @param grant - the grant
   * @returns the token records
   */
  liveTokensOf(grant: Json): Json[] {
    const { log, store, nowSec } = this.deps;
    log.debug("Entering GnapRevocation.liveTokensOf().");
    const now = nowSec();
    const out = (grant.tokens || []).map(function (jti: string) {
      return store.tokenByJti(jti);
    }).filter(function (record: Json) {
      return record && !record.revoked && (!record.exp || record.exp > now);
    });
    log.debug("Leaving GnapRevocation.liveTokensOf(). " + out.length);
    return out;
  }

  // Ends every live grant a predicate picks; answers how many it ended.
  private endWhere(pick: (grant: Json) => boolean, how: EndHow): number {
    const { log, store, errorCodes } = this.deps;
    log.debug("Entering GnapRevocation.endWhere().");
    let ended = 0;
    store.listGrants().forEach((grant: Json) => {
      if (!this.isLive(grant) || !pick(grant)) {
        return;
      }
      try {
        if (this.endGrant(grant, how)) {
          ended += 1;
        }
      } catch (e) {
        log.warn(errorCodes.tag('STS-GNAP-0736') + 'gnap: grant ' + grant.id +
                 ' could not be ended (' + String(how.why || '') + '): ' +
                 ((e && e.message) || e));
      }
    });
    log.debug("Leaving GnapRevocation.endWhere(). " + ended);
    return ended;
  }

  /**
   * Ends every live grant a person holds.
   *
   * @param key - the person's identity key
   * @param how - why, who, the door and CAEP's initiating entity
   * @returns how many grants were ended
   */
  endForPerson(key: string, how: EndHow): number {
    const { log } = this.deps;
    log.debug("Entering GnapRevocation.endForPerson(). " + key);
    const wanted = String(key || '');
    const ended = wanted ? this.endWhere((grant) => {
      return this.holderKeyOf(grant) === wanted;
    }, how) : 0;
    log.debug("Leaving GnapRevocation.endForPerson(). " + ended);
    return ended;
  }

  /**
   * Ends every live grant a client application holds — its entry deleted.
   *
   * @param identifier - the application's identifier
   * @param how - why, who, the door and CAEP's initiating entity
   * @returns how many grants were ended
   */
  endForClient(identifier: string, how: EndHow): number {
    const { log } = this.deps;
    log.debug("Entering GnapRevocation.endForClient(). " + identifier);
    const wanted = String(identifier || '');
    const ended = wanted ? this.endWhere(function (grant) {
      return !!grant.client && grant.client.identifier === wanted;
    }, how) : 0;
    log.debug("Leaving GnapRevocation.endForClient(). " + ended);
    return ended;
  }

  // -------------------------------------------------------------------------
  // KEYS. A grant's key identity is the reference it was bound by (`ref:`)
  // or the thumbprint identity `gnap_keys.ts` gives a key by value (`jkt:`,
  // `x5t:`); an entry names the identities of its `gnapKey`, its
  // `gnapKeyIdentity` and its `gnapKeyReference`.
  // -------------------------------------------------------------------------
  /**
   * Returns the identity of a key as a grant holds it, or '' when it does not
   * describe.
   *
   * @param key - a key by value, or a reference string
   * @returns `ref:…`, `jkt:…` or `x5t:…`, or ''
   */
  keyIdentityOf(key: Json): string {
    const { log, keys } = this.deps;
    log.debug("Entering GnapRevocation.keyIdentityOf().");
    if (typeof key === 'string') {
      log.debug("Leaving GnapRevocation.keyIdentityOf(). A reference.");
      return key ? 'ref:' + key : '';
    }
    let described: Json = null;
    try {
      described = keys.describe(key, {});
    } catch (e) {
      log.debug("Caught in GnapRevocation.keyIdentityOf(): " +
                ((e && e.message) || e));
      described = null;
    }
    log.debug("Leaving GnapRevocation.keyIdentityOf().");
    return described && described.ok ? String(described.identity || '') : '';
  }

  // One value of an application field, as `gnap_grants.ts`'s `field()` reads
  // one: the first, as a string.
  private fieldOf(app: Json, name: string): string {
    const { log } = this.deps;
    log.debug("Entering GnapRevocation.fieldOf(). " + name);
    const raw = app && app.fields ? app.fields[name] : undefined;
    const value = Array.isArray(raw) ? raw[0] : raw;
    log.debug("Leaving GnapRevocation.fieldOf().");
    return value === undefined || value === null ? '' : String(value);
  }

  /**
   * The key identities an application entry names now.
   *
   * @param app - the application, as `applications.get()` answers it
   * @returns the identities
   */
  entryKeyIdentities(app: Json): string[] {
    const { log } = this.deps;
    log.debug("Entering GnapRevocation.entryKeyIdentities().");
    const out: string[] = [];
    const raw = this.fieldOf(app, 'gnapKey');
    if (raw) {
      try {
        const identity = this.keyIdentityOf(JSON.parse(raw));
        if (identity) {
          out.push(identity);
        }
      } catch (e) {
        log.debug("Caught in GnapRevocation.entryKeyIdentities(): " +
                  ((e && e.message) || e));
        // A gnapKey that is not JSON names no key; `gnap_grants.ts` logs it
        // (STS-GNAP-0652) where it is read to identify a caller.
      }
    }
    const identity = this.fieldOf(app, 'gnapKeyIdentity');
    if (identity) {
      out.push(identity);
    }
    const reference = this.fieldOf(app, 'gnapKeyReference');
    if (reference) {
      out.push('ref:' + reference);
    }
    log.debug("Leaving GnapRevocation.entryKeyIdentities(). " + out.length);
    return out;
  }

  /**
   * Ends every live grant of a client whose key its entry no longer names —
   * its `gnapKey`, `gnapKeyIdentity` or `gnapKeyReference` removed or
   * replaced. A grant bound to a reference the entry still names is kept.
   *
   * @param identifier - the application's identifier
   * @param how - why, who, the door and CAEP's initiating entity
   * @returns how many grants were ended
   */
  endForClientKeyChange(identifier: string, how: EndHow): number {
    const { log, applications } = this.deps;
    log.debug("Entering GnapRevocation.endForClientKeyChange(). " +
              identifier);
    const app = applications.get(String(identifier || ''));
    if (!app) {
      const gone = this.endForClient(identifier, how);
      log.debug("Leaving GnapRevocation.endForClientKeyChange(). Entry gone.");
      return gone;
    }
    const named = this.entryKeyIdentities(app);
    const ended = this.endWhere((grant) => {
      if (!grant.client || grant.client.identifier !== app.identifier) {
        return false;
      }
      const identity = this.keyIdentityOf(grant.client.key);
      return !!identity && named.indexOf(identity) < 0;
    }, how);
    log.debug("Leaving GnapRevocation.endForClientKeyChange(). " + ended);
    return ended;
  }

  /**
   * The thumbprints a key by value can be matched to a registered device's
   * keys by: its RFC 7638 JWK thumbprint and the SHA-256 of its
   * SubjectPublicKeyInfo, both base64url. A reference matches no device.
   *
   * @param key - a key by value
   * @returns the thumbprints, possibly none
   */
  deviceThumbprintsOf(key: Json): string[] {
    const { log, keys, stsCrypto } = this.deps;
    log.debug("Entering GnapRevocation.deviceThumbprintsOf().");
    const out: string[] = [];
    if (!key || typeof key !== 'object') {
      log.debug("Leaving GnapRevocation.deviceThumbprintsOf(). No key.");
      return out;
    }
    let described: Json = null;
    try {
      described = keys.describe(key, {});
    } catch (e) {
      log.debug("Caught in GnapRevocation.deviceThumbprintsOf(): " +
                ((e && e.message) || e));
      described = null;
    }
    if (!described || !described.ok) {
      log.debug("Leaving GnapRevocation.deviceThumbprintsOf(). Undescribed.");
      return out;
    }
    if (described.format === 'jwk' && described.thumbprint) {
      out.push(String(described.thumbprint));
    }
    if (described.publicKey) {
      try {
        // A certificate's key, matched to a device's `jwk` key too.
        if (described.format !== 'jwk') {
          out.push(stsCrypto.jwkThumbprint(
            described.publicKey.export({ format: 'jwk' })));
        }
        out.push(stsCrypto.publicKeySpkiThumbprint(described.publicKey));
      } catch (e) {
        log.debug("Caught in GnapRevocation.deviceThumbprintsOf(): " +
                  ((e && e.message) || e));
        // A key node cannot export as SPKI matches by its JWK thumbprint
        // alone.
      }
    }
    log.debug("Leaving GnapRevocation.deviceThumbprintsOf(). " + out.length);
    return out;
  }

  /**
   * Ends every live grant whose CLIENT KEY is one of a device's keys — the
   * device marked compromised (#164).
   *
   * @param thumbprints - the device's key thumbprints (JWK and SPKI)
   * @param how - why, who, the door and CAEP's initiating entity
   * @returns how many grants were ended
   */
  endForDeviceKeys(thumbprints: string[], how: EndHow): number {
    const { log } = this.deps;
    log.debug("Entering GnapRevocation.endForDeviceKeys(). " +
              (thumbprints || []).length);
    const held = (thumbprints || []).filter(Boolean).map(String);
    const ended = held.length ? this.endWhere((grant) => {
      return !!grant.client && this.deviceThumbprintsOf(grant.client.key)
        .some(function (one) {
          return held.indexOf(one) >= 0;
        });
    }, how) : 0;
    log.debug("Leaving GnapRevocation.endForDeviceKeys(). " + ended);
    return ended;
  }

  // -------------------------------------------------------------------------
  // THE CHECK AT USE — the header's third point. Synchronous, because
  // `gnap_rs.ts`'s `presentation()` is (`ssf/ssf_auth.ts` calls it that way),
  // and it writes nothing.
  // -------------------------------------------------------------------------
  /**
   * Says why a resource owner may no longer be acted for — their account is
   * disabled — or answers null.
   *
   * @param username - the resource owner's name, or nothing
   * @returns `{ code, why }`, or null
   */
  ownerProblem(username: unknown): Problem | null {
    const { log, loadAccountState } = this.deps;
    log.debug("Entering GnapRevocation.ownerProblem().");
    const name = String(username || '');
    if (!name) {
      log.debug("Leaving GnapRevocation.ownerProblem(). No owner.");
      return null;
    }
    let disabled = false;
    try {
      disabled = !!loadAccountState().isDisabled(name);
    } catch (e) {
      log.debug("Caught in GnapRevocation.ownerProblem(): " +
                ((e && e.message) || e));
      // No account state in this process (an in-process test of this
      // family): nobody is disabled here.
      disabled = false;
    }
    log.debug("Leaving GnapRevocation.ownerProblem(). " + disabled);
    return disabled ? { code: 'STS-GNAP-0730',
                        why: 'the resource owner\'s account is disabled' }
                    : null;
  }

  /**
   * Says why a client may no longer use what it holds — its application
   * entry is gone, or no longer names the key — or answers null. Asked only
   * where the registry is available: a process without a directory can say
   * nothing about an entry.
   *
   * @param identifier - the client's application identifier
   * @param key - the key the grant is bound to, or nothing to skip the key
   * @returns `{ code, why }`, or null
   */
  clientProblem(identifier: unknown, key?: Json): Problem | null {
    const { log, applications } = this.deps;
    log.debug("Entering GnapRevocation.clientProblem().");
    const id = String(identifier || '');
    if (!id || typeof applications.registryAvailable !== 'function' ||
        !applications.registryAvailable()) {
      log.debug("Leaving GnapRevocation.clientProblem(). Cannot say.");
      return null;
    }
    const app = applications.get(id);
    if (!app) {
      log.debug("Leaving GnapRevocation.clientProblem(). Entry gone.");
      return { code: 'STS-GNAP-0731',
               why: 'the client\'s application entry no longer exists' };
    }
    if (key !== undefined && key !== null) {
      const identity = this.keyIdentityOf(key);
      const named = this.entryKeyIdentities(app);
      if (identity && named.length && named.indexOf(identity) < 0) {
        log.debug("Leaving GnapRevocation.clientProblem(). Key replaced.");
        return { code: 'STS-GNAP-0731',
                 why: 'the client\'s application entry no longer names the ' +
                      'key this grant is bound to' };
      }
      if (identity && !named.length) {
        log.debug("Leaving GnapRevocation.clientProblem(). Key removed.");
        return { code: 'STS-GNAP-0731',
                 why: 'the client\'s application entry no longer carries a ' +
                      'GNAP key' };
      }
    }
    log.debug("Leaving GnapRevocation.clientProblem(). Live.");
    return null;
  }

  /**
   * The check at use for a grant: its resource owner disabled, or its
   * client's entry gone or no longer naming its key.
   *
   * @param grant - the grant
   * @returns `{ code, why }`, or null when it may be used
   */
  grantProblem(grant: Json): Problem | null {
    const { log } = this.deps;
    log.debug("Entering GnapRevocation.grantProblem().");
    if (!grant) {
      log.debug("Leaving GnapRevocation.grantProblem(). No grant.");
      return null;
    }
    const owner = this.ownerProblem(grant.ro && grant.ro.username);
    const problem = owner || (grant.client
      ? this.clientProblem(grant.client.identifier, grant.client.key) : null);
    log.debug("Leaving GnapRevocation.grantProblem(). " +
              (problem ? problem.code : 'live'));
    return problem;
  }

  /**
   * The check at use for a token: its resource owner disabled, or the
   * client its grant was issued to gone or no longer naming the grant's key.
   *
   * @param record - the token's record
   * @returns `{ code, why }`, or null when it may be used
   */
  tokenProblem(record: Json): Problem | null {
    const { log, store } = this.deps;
    log.debug("Entering GnapRevocation.tokenProblem().");
    if (!record) {
      log.debug("Leaving GnapRevocation.tokenProblem(). No record.");
      return null;
    }
    const grant = store.getGrant(record.grantId);
    const owner = this.ownerProblem(record.username ||
                                    (grant && grant.ro && grant.ro.username));
    const problem = owner || (grant && grant.client
      ? this.clientProblem(grant.client.identifier, grant.client.key)
      : this.clientProblem(record.instanceId));
    log.debug("Leaving GnapRevocation.tokenProblem(). " +
              (problem ? problem.code : 'live'));
    return problem;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) at 23d with the rest
// of the family; a process that never runs the root gets a default instance.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<GnapRevocation>(
  'gnap/gnap_revocation',
  () => new GnapRevocation(GnapRevocation.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as every module of this family does.
slot.buildNowUnlessDeferred();

/**
 * What ends a GNAP grant from outside the protocol, and the check at use.
 *
 * @namespace
 */
export = {
  GnapRevocation: GnapRevocation,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: GnapRevocation): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin(),
  revokeTokens: slot.forward('revokeTokens'),
  endGrant: slot.forward('endGrant'),
  holderKeyOf: slot.forward('holderKeyOf'),
  isLive: slot.forward('isLive'),
  grantsByKey: slot.forward('grantsByKey'),
  grantsHeldBy: slot.forward('grantsHeldBy'),
  liveHeldGrants: slot.forward('liveHeldGrants'),
  liveTokensOf: slot.forward('liveTokensOf'),
  endForPerson: slot.forward('endForPerson'),
  endForClient: slot.forward('endForClient'),
  endForClientKeyChange: slot.forward('endForClientKeyChange'),
  endForDeviceKeys: slot.forward('endForDeviceKeys'),
  keyIdentityOf: slot.forward('keyIdentityOf'),
  entryKeyIdentities: slot.forward('entryKeyIdentities'),
  deviceThumbprintsOf: slot.forward('deviceThumbprintsOf'),
  ownerProblem: slot.forward('ownerProblem'),
  clientProblem: slot.forward('clientProblem'),
  grantProblem: slot.forward('grantProblem'),
  tokenProblem: slot.forward('tokenProblem')
};
