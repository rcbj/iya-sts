'use strict';
//
// File: risk/risk_failures.ts
//
// ===========================================================================
// EVERY REFUSED PASSWORD, ATTRIBUTED (#62 P1, 2026-09-22).
//
// Risk scoring needs to know that one account was tried from forty networks
// in an hour, or that one network tried forty accounts — and nothing here
// could say either. The rate limiter's bucket is `{ count, until }`, keyed by
// one door, and CLEARED on a success; a failed sign-in-screen password left
// no audit row naming who it was about; an LDAP bind, the password grant and
// the sign-in screen each counted on their own. An attacker who rotates
// doors is invisible to every one of them.
//
// So every refused password is recorded ONCE, where every door already
// meets: `credentials.verify()` and `verifyAsync()` — the sign-in screen and
// its password factor, the OAuth password grant, an LDAP simple bind,
// WS-Trust's UsernameToken, SCIM and SSF Basic, EST. `common/credentials.ts`
// calls `recordFailure()` with the name as typed, the door (its `via`) and
// the refusal's code; the address is the audit log's ambient one.
//
// **WHAT IS KEPT, AND WHAT IS NOT** (#62's plan, §7):
//
//   * THE PERSON, as their `sub`, when the name resolves to a directory
//     entry; otherwise a KEYED DIGEST of the name (`keystore.keyedDigest()`),
//     never the name. People type their password into the username field,
//     and a failure log is where that would otherwise end up.
//   * THE NETWORK, as a /24 or /48 prefix SQL can group on, and the address
//     itself only SEALED under the key-encryption key.
//   * THE ASN, from the active dataset, when there is one.
//
// **IN THE DATABASE ONLY WHERE IT CAN BE SEALED.** With no key-encryption key
// — development mode, as a rule — a row is held in this process and says so.
// A record is never the reason a refusal is late or lost: `recordFailure()`
// is not awaited by anybody, and a store failure is logged (STS-RISK-0010)
// and the refusal stands.
//
// The door `via` is `verify()`'s own sentence ("an LDAP simple bind"), kept as
// it is, because that is what an operator reading the page wants to see.
// Kerberos is the one password door not here: a pre-authentication failure
// is decided inside the parent project's locked KDC codec, which does not
// call `verify()` (`kerberos/CLAUDE.md`).
//
// A LIBRARY (rule 3): no route. `credentials.ts` requires it lazily.
// ===========================================================================

import bunyan = require('bunyan');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');
import riskStore = require('./risk_store');

const log = bunyan.createLogger({ name: 'sts-risk-failures' });
config.registerLogger(log);

type Json = any;

// Deleted per statement by the retention job.
const PURGE_BATCH = 20000;
// The prefix a row with no address is kept under; see recordFailure().
const NO_ADDRESS = '0.0.0.0/0';

interface RiskFailuresDeps {
  log: { debug(m: string): void; info(m: string): void; warn(m: string): void };
  config: { value(key: string): any };
  store: typeof riskStore;
  now(): number;
  // Each LAZY: this file is required from `credentials.ts`, which loads
  // early, and none of these may be pulled in ahead of the root by it.
  keystore(): Json;
  audit(): Json;
  realms(): Json;
  subjectOf(name: string): string;
  asnOf(address: string, realm: string): Promise<number>;
}

class RiskFailures {
  constructor(private readonly deps: RiskFailuresDeps) {
    deps.log.debug("Entering RiskFailures.constructor().");
    deps.log.debug("Leaving RiskFailures.constructor().");
  }

  static defaultDeps(): RiskFailuresDeps {
    log.debug("Entering RiskFailures.defaultDeps().");
    log.debug("Leaving RiskFailures.defaultDeps().");
    return {
      log: log,
      config: config,
      store: riskStore,
      now: function (): number {
        return Date.now();
      },
      keystore: function (): Json {
        return require('../common/keystore');
      },
      audit: function (): Json {
        return require('../common/audit');
      },
      realms: function (): Json {
        return require('../common/realms');
      },
      // The person's `sub` (`urn:uuid:<entryUUID>`) where the directory has
      // an entry for the name, and '' where it has none. Asked through
      // `helpers.userFor()`, the one resolver every door uses.
      subjectOf: function (name: string): string {
        log.debug("Entering subjectOf().");
        try {
          const user = require('../common/helpers').userFor(name);
          log.debug("Leaving subjectOf().");
          return String((user && user.sub) || '');
        } catch (e) {
          log.debug("Caught in subjectOf(): " + ((e && e.message) || e));
          // An entry that cannot be read is treated as none: the row is
          // kept under the name's digest, which is still correlatable.
          log.debug("Leaving subjectOf(). Unreadable.");
          return '';
        }
      },
      asnOf: function (address: string, realm: string): Promise<number> {
        log.debug("Entering asnOf().");
        log.debug("Leaving asnOf().");
        return require('./risk_datasets').lookup(address, realm)
          .then(function (found: Json): number {
            return found && found.asn ? Number(found.asn.asn) || 0 : 0;
          });
      }
    };
  }

  // Whether rows go to the database: a database store AND a key to seal
  // under. See the header.
  sealing(): boolean {
    const { log, keystore } = this.deps;
    log.debug("Entering RiskFailures.sealing().");
    let sealed = false;
    try {
      sealed = !!keystore().sealed();
    } catch (e) {
      log.debug("Caught in RiskFailures.sealing(): " +
                ((e && e.message) || e));
      // No keystore loaded yet (a process still starting): not sealing.
      sealed = false;
    }
    log.debug("Leaving RiskFailures.sealing(). " + sealed);
    return sealed;
  }

  // -------------------------------------------------------------------------
  // RECORD ONE REFUSED PASSWORD. `name` is what was typed, `door` is
  // `verify()`'s `via`, `code` is the refusal's. Returns a promise nobody has
  // to wait for; it never rejects.
  // -------------------------------------------------------------------------
  recordFailure(name: string, door: string, code: string): Promise<string> {
    const { log, config, store, now, keystore, audit, realms, subjectOf,
            asnOf } = this.deps;
    log.debug("Entering RiskFailures.recordFailure(). door=" + door);
    if (config.value('risk.recordFailures') === false) {
      log.debug("Leaving RiskFailures.recordFailure(). Switched off.");
      return Promise.resolve('');
    }
    const self = this;
    let realm = '';
    let address = '';
    try {
      realm = String(realms().currentId() || '');
      address = String(audit().currentAddress() || '');
    } catch (e) {
      log.debug("Caught in RiskFailures.recordFailure(): " +
                ((e && e.message) || e));
      // Outside any request: no realm and no address, which the row says.
      realm = realm || '';
    }
    const typed = String(name || '').trim().toLowerCase();
    const subject = typed ? subjectOf(String(name).trim()) : '';
    const sealing = this.sealing();
    let nameHmac = '';
    if (!subject && typed) {
      nameHmac = (sealing && keystore().keyedDigest('risk-name', typed)) ||
        // No key: the row stays in this process (see the header), and a
        // plain digest there is compared, never stored.
        require('../common/crypto').credentialFingerprint('risk-name:' +
                                                          typed);
    }
    // `0.0.0.0/0` is NO ADDRESS: a refusal outside any request, or from a
    // source that named none. A cidr column cannot be empty, and /0 is the
    // one prefix no real address is recorded under.
    const prefix = riskStore.prefixOf(address) || NO_ADDRESS;
    const addressSealed = sealing && address
      ? String(keystore().seal(address, 'risk.address') || '') : '';
    log.debug("Leaving RiskFailures.recordFailure().");
    return asnOf(address, realm).catch(function (): number {
      return 0;
    }).then(function (asn: number): Promise<string> {
      return store.recordFailure({
        realm: realm, at: now(), door: String(door || 'unstated'),
        subject: subject, nameHmac: nameHmac, addressSealed: addressSealed,
        addressPrefix: prefix, asn: asn,
        errorCode: String(code || 'STS-AUTHN-0054')
      }, sealing);
    }).catch(function (e: Json): string {
      self.deps.log.warn(errorCodes.tag('STS-RISK-0010') + 'risk: a refused ' +
                         'password at ' + door + ' could not be recorded: ' +
                         ((e && e.message) || e) + '. The refusal stands.');
      return '';
    });
  }

  // A page of this realm's failures, newest first, for Monitoring → Risk
  // and GET /admin-api/risk/failures. Rows carry the prefix and never the
  // sealed address.
  list(realm: string, opts: Json): Promise<Json> {
    const { log, store } = this.deps;
    log.debug("Entering RiskFailures.list(). realm=" + realm);
    log.debug("Leaving RiskFailures.list().");
    return store.listFailures(String(realm || ''), opts || {}, this.sealing())
      .then(function (answer: Json): Json {
        return {
          total: answer.total,
          rows: answer.rows.map(function (row: Json): Json {
            return { id: row.id, at: row.at, door: row.door,
                     subject: row.subject,
                     name: row.subject ? '' : 'digest ' +
                       String(row.nameHmac || '').slice(0, 12),
                     prefix: row.addressPrefix, asn: row.asn,
                     errorCode: row.errorCode };
          })
        };
      });
  }

  // Failures past `risk.failureRetentionDays`, deleted a batch at a time.
  async purge(): Promise<number> {
    const { log, config, store, now } = this.deps;
    log.debug("Entering RiskFailures.purge().");
    const before = now() -
      Number(config.value('risk.failureRetentionDays')) * 86400000;
    const sealing = this.sealing();
    let total = 0;
    for (;;) {
      const gone = await store.purgeFailures(before, PURGE_BATCH, sealing);
      total += gone;
      if (gone < PURGE_BATCH) {
        break;
      }
    }
    log.debug("Leaving RiskFailures.purge(). " + total + ".");
    return total;
  }

  describe(): Json {
    const { log, store } = this.deps;
    log.debug("Entering RiskFailures.describe().");
    const database = store.failuresInDatabase(this.sealing());
    log.debug("Leaving RiskFailures.describe().");
    return {
      recording: this.deps.config.value('risk.recordFailures') !== false,
      database: database,
      why: database
        ? 'Held in the database, the address sealed under the ' +
          'key-encryption key.'
        : 'Held in this process: ' + (store.inDatabase()
          ? 'there is no key-encryption key to seal an address under, so ' +
            'nothing personal is written to the database.'
          : 'the store has no risk tables.')
    };
  }
}

const slot = new InstanceSlot<RiskFailures>(
  'risk/risk_failures',
  () => new RiskFailures(RiskFailures.defaultDeps()),
  null,
  log);

slot.buildNowUnlessDeferred();

export = {
  RiskFailures: RiskFailures,
  installInstance: (instance: RiskFailures): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  recordFailure: slot.forward('recordFailure'),
  list: slot.forward('list'),
  purge: slot.forward('purge'),
  describe: slot.forward('describe'),
  sealing: slot.forward('sealing')
};
