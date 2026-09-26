'use strict';
// ---------------------------------------------------------------------------
// ssf/service_signals.ts — WHAT THIS SERVICE'S OWN KEYS AND AUTHORITIES SAY
// OVER SHARED SIGNALS WHEN THEY MOVE (#244, #245, 2026-09-26).
//
// Two families of act, both about the ISSUER rather than about a person, and
// both with the same problem `account_signals.ts` has: the modules that do
// them load long before `ssf/ssf.ts`, and a require would close a cycle or
// run SSF's load-time work early. So this is a LIBRARY in that file's shape:
// `ssf.ts` is found in `require.cache` when an event is due, a process that
// never loaded it gets a no-op, and NOTHING HERE WAITS OR THROWS into the act
// that has already happened.
//
// ---------------------------------------------------------------------------
// 1. A KEY A RELYING PARTY PINS MOVED (#245): `keyChanged()`.
//
// A realm's OpenID Federation entity key (`oidfed/federation_keys.ts`), its
// SPIFFE X.509 and JWT authorities (`spiffe/spiffe_ca.ts`, and a rebuild of
// the hierarchy they hang from), and the listener certificate
// (`tls/tls_server.js`). Each is `ssf.serviceKeyChanged()` inside the realm
// it belongs to; the listener's is sent in EVERY realm, because the one port
// serves them all. `ssf_events.js` argues the sibling URNs.
//
// ---------------------------------------------------------------------------
// 2. THE CERTIFICATE HIERARCHY MOVED UNDER PEOPLE'S CERTIFICATES (#244).
//
// `/admin/pki`'s revoke of a LEAF already sends CAEP `credential-change`
// (x509, revoke) to its holder. The acts on the TIERS above a leaf reach many
// people at once and sent nothing:
//
//   * revoking an Issuing CA (on its Intermediate's list) or an Intermediate
//     (on the Root's) — `caRevoked()` walks DOWN the tiers to every person
//     holding a live leaf beneath it: `credential-change` (x509, revoke), and
//     RISC `credential-compromise` (x509) as well when the reason is
//     `keyCompromise` or `cACompromise`, through
//     `accountSignals.credentialCompromised()` — the one funnel #231 sends a
//     compromised leaf through, so a receiver hears one vocabulary;
//   * building a Root, rebuilding a branch, reissuing or renewing one Issuing
//     CA, or importing one — `snapshot()` before the act and
//     `hierarchyChanged()` after it compare, per person-held certificate,
//     what the tree held then with what it holds now.
//
// **WHAT IS RE-MINTED AND WHAT IS ORPHANED, SETTLED (#244's unverified
// question).** `pki.recertifyUseCase()` re-mints the certificates in the
// register's SLOTS (`certificatesFor()`), from the key the old certificate
// was over: a person's TLS client certificate (`person:<name>:<random>` under
// `tls-client`) is one, and a reissue, a renewal or an import sends it
// `update` naming the new certificate. The certificates in `issuedKeyPairs`
// — a person's RFC 7523 / 7522 key pair and every ACME, EST and SCEP
// enrolment (`pki.issueEnrolled()`) — are NEVER re-minted: this service keeps
// no key for them to re-certify, and the holder has the only copy. Their
// Issuing CA is superseded on its Intermediate's list (or its Root is gone),
// so the certificate chains to a revoked authority: `revoke`. And a branch
// rebuilt (`build`, `build-scope`, `build-root`) re-certifies only the
// realm's own signing keys (`recertifyScope()`), so a person's TLS client
// certificate is orphaned there too, and is sent `revoke`. The comparison
// decides each case from the tree itself rather than from which button was
// pressed, so a new act on the hierarchy is covered by calling the pair.
//
// **ONLY WHAT WAS LIVE UNDER THE CURRENT TREE COUNTS.** A slot whose chain
// no longer starts at its Issuing CA, a key pair issued before that CA was
// made, an expired certificate and one already on its authority's list were
// orphaned or revoked by an EARLIER act, which sent (or should have sent)
// their event then — telling a receiver again on every rebuild would make
// the event mean nothing.
//
// **THE FAN-OUT IS BATCHED.** A realm's Intermediate can have thousands of
// leaves beneath it. `fanOut()` sends `BATCH` people's events, waits for that
// batch to be handed to the queue (and, for push, to the per-process push cap,
// `ssf.pushConcurrency`), yields the event loop, and takes the next — so a
// rebuild never puts ten thousand SETs in flight at once, and the console's
// answer does not wait for any of it. A delay between batches of one act is
// not a periodic timer (root CLAUDE.md, *Anything periodic*).
//
// NOT A SLOT (rule 3e): there is no require of a route module here — `ssf.ts`
// is read from the cache, and `pki.js`, `tls_client_certificates.js`,
// `helpers.js` and `account_signals.ts` are libraries reached lazily.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');

type Json = any;

// People per batch of a hierarchy fan-out.
const BATCH = 50;
// The two RFC 5280 reasons that say the authority's key is not safe, and so
// that everything it vouched for may have been forged.
const COMPROMISE_REASONS = Object.freeze(['keyCompromise', 'cACompromise']);

interface Delivery {
  sent: number;
  streams: number;
  why?: string;
  [member: string]: unknown;
}

interface SsfEmitter {
  serviceKeyChanged?(kind: string, notice: object): Promise<Delivery>;
}

interface ServiceSignalsDeps {
  log: { debug(m: string): void; info(m: string): void;
         warn(m: string): void };
  // `ssf.ts`'s exports when that module is loaded in this process, else null.
  findSsf(): SsfEmitter | null;
  // Lazily, each: libraries this module reads and never loads early.
  realms(): Json;
  pki(): Json;
  revocation(): Json;
  tlsClient(): Json;
  accountSignals(): Json;
  crypto(): Json;
  nameForSubject(sub: string): string;
  // A turn of the event loop between two batches.
  yieldTurn(): Promise<void>;
  now(): number;
}

// One person-held certificate the tree held before an act.
interface Holding {
  scope: string;
  useCase: string;
  username: string;
  // 'slot' (re-mintable: in the register's slots) or 'pair' (issuedKeyPairs).
  kind: string;
  slotKey: string;
  serialHex: string;
  issuer: string;
  // The identity of the chain above it: the Issuing CA's, the
  // Intermediate's and the Root's serials.
  chain: string;
}

// One event of the fan-out.
interface Notice {
  scope: string;
  username: string;
  changeType: string;
  issuer: string;
  serialHex: string;
  compromised: boolean;
}

class ServiceSignals {
  static readonly BATCH = BATCH;
  static readonly COMPROMISE_REASONS = COMPROMISE_REASONS;

  constructor(private readonly deps: ServiceSignalsDeps) {
    deps.log.debug('Entering ServiceSignals.constructor().');
    deps.log.debug('Leaving ServiceSignals.constructor().');
  }

  static defaultDeps(): ServiceSignalsDeps {
    helpers.log.debug('Entering ServiceSignals.defaultDeps().');
    helpers.log.debug('Leaving ServiceSignals.defaultDeps().');
    return {
      log: helpers.log,
      findSsf: ServiceSignals.loadedSsf,
      realms: function (): Json {
        return require('../common/realms');
      },
      pki: function (): Json {
        return require('../common/pki');
      },
      revocation: function (): Json {
        return require('../common/pki_revocation');
      },
      tlsClient: function (): Json {
        return require('../common/tls_client_certificates');
      },
      accountSignals: function (): Json {
        return require('./account_signals');
      },
      crypto: function (): Json {
        return require('../common/crypto');
      },
      nameForSubject: function (sub: string): string {
        return helpers.nameForSubject(sub);
      },
      yieldTurn: function (): Promise<void> {
        return new Promise(function (resolve): void {
          setImmediate(resolve);
        });
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  // `ssf.ts` as loaded in THIS process, or null — `account_signals.ts`'s
  // lookup, for its reason.
  static loadedSsf(): SsfEmitter | null {
    const { log } = helpers;
    log.debug('Entering ServiceSignals.loadedSsf().');
    let id = '';
    try {
      id = require.resolve('./ssf');
    } catch (e) {
      log.debug('Caught in ServiceSignals.loadedSsf(): ' +
                ((e && e.message) || e));
      log.debug('Leaving ServiceSignals.loadedSsf(). Not resolvable.');
      return null;
    }
    const cached = require.cache[id];
    log.debug('Leaving ServiceSignals.loadedSsf(). ' +
              (cached ? 'Loaded.' : 'Not loaded.'));
    return cached && cached.exports ? cached.exports as SsfEmitter : null;
  }

  // The realm record a pki scope id names, or null for a scope that is not
  // a realm (`*service`, `*process`).
  private realmOf(scopeId: string): Json {
    const { log, realms } = this.deps;
    log.debug('Entering ServiceSignals.realmOf(). ' + scopeId);
    const r = realms();
    const id = String(scopeId || '');
    if (id.charAt(0) === '*') {
      log.debug('Leaving ServiceSignals.realmOf(). Not a realm.');
      return null;
    }
    const realm = r.get(id || r.DEFAULT_ID) || null;
    log.debug('Leaving ServiceSignals.realmOf(). ' + (realm ? 'Found.'
                                                            : 'No realm.'));
    return realm;
  }

  // ===========================================================================
  // 1. A KEY MOVED (#245).
  // ===========================================================================

  // `kind` is `federation`, `spiffe` or `tls`; `realmId` the realm the key
  // belongs to, or `*` for the listener, which is every realm's. `notice`:
  // `{ rotated: [{ unit, from, to }], reason, trustDomain?, bundleChanged? }`.
  // Resolves the number of SETs handed over; never rejects.
  keyChanged(kind: string, realmId: string, notice?: Json): Promise<number> {
    const { log, findSsf, realms } = this.deps;
    log.debug('Entering ServiceSignals.keyChanged(). ' + kind + ' in ' +
              realmId);
    const n = notice || {};
    if (!(n.rotated || []).length) {
      log.debug('Leaving ServiceSignals.keyChanged(). Nothing moved.');
      return Promise.resolve(0);
    }
    const ssf = findSsf();
    if (!ssf || typeof ssf.serviceKeyChanged !== 'function') {
      log.debug('Leaving ServiceSignals.keyChanged(). Shared Signals is not ' +
                'loaded in this process, so nothing is sent.');
      return Promise.resolve(0);
    }
    const r = realms();
    const targets = realmId === '*' ? r.list()
      : [r.get(String(realmId || r.DEFAULT_ID)) || r.get(r.DEFAULT_ID)];
    const work = targets.map(function (realm: Json): Promise<number> {
      let answer: Promise<Delivery>;
      try {
        answer = Promise.resolve(r.run(realm, function (): Promise<Delivery> {
          return (ssf.serviceKeyChanged as any)(kind,
            Object.assign({}, n, { realm: String(realm.id) }));
        }));
      } catch (e) {
        log.warn('service signals: the ' + kind + ' key event for the "' +
                 realm.id + '" realm threw and nothing was sent: ' +
                 ((e && e.message) || e));
        return Promise.resolve(0);
      }
      return answer.then(function (d: Delivery): number {
        return Number(d && d.sent) || 0;
      }, function (e: Json): number {
        log.warn('service signals: the ' + kind + ' key event for the "' +
                 realm.id + '" realm failed: ' + ((e && e.message) || e));
        return 0;
      });
    });
    log.debug('Leaving ServiceSignals.keyChanged(). ' + targets.length +
              ' realm(s).');
    return Promise.all(work).then(function (counts: number[]): number {
      return counts.reduce(function (a, b) {
        return a + b;
      }, 0);
    });
  }

  // ===========================================================================
  // 2. THE HIERARCHY MOVED UNDER PEOPLE'S CERTIFICATES (#244).
  // ===========================================================================

  // The serials of a scope's current tiers: `{ root, intermediate,
  // issuing: { <use case>: { serial, pem, createdAt } } }`.
  private tiersOf(scopeId: string): Json {
    const { log, pki } = this.deps;
    log.debug('Entering ServiceSignals.tiersOf(). ' + scopeId);
    const p = pki();
    const root = p.serviceRoot();
    const row = p.rawRowFor(scopeId) || {};
    const out: Json = {
      root: root ? String(root.serialHex || '') : '',
      intermediate: row.intermediate
        ? String(row.intermediate.serialHex || '') : '',
      issuing: {}
    };
    Object.keys(row.issuing || {}).forEach(function (useCaseId: string) {
      const tier = row.issuing[useCaseId] || {};
      out.issuing[useCaseId] = { serial: String(tier.serialHex || ''),
                                 pem: String(tier.certificatePem || ''),
                                 subject: String(tier.subject || ''),
                                 createdAt: Number(tier.createdAt) || 0 };
    });
    log.debug('Leaving ServiceSignals.tiersOf().');
    return out;
  }

  // An authority's subject as a certificate names its issuer: read from the
  // authority's own certificate, which is what signed the leaf.
  private issuerName(pem: string, fallback: string): string {
    const { log, crypto } = this.deps;
    log.debug('Entering ServiceSignals.issuerName().');
    let name = '';
    try {
      name = String(crypto().certificateIdentifiers(pem).subject || '');
    } catch (e) {
      log.debug('Caught in ServiceSignals.issuerName(): ' +
                ((e && e.message) || e));
      name = '';
    }
    log.debug('Leaving ServiceSignals.issuerName().');
    return name || String(fallback || '');
  }

  // Every certificate a PERSON holds that is live under a scope's current
  // tree, optionally narrowed to one use case. See the header for what
  // "live under the current tree" leaves out, and why.
  holdingsOf(scopeId: string, useCaseId?: string): Holding[] {
    const self = this;
    const { log, pki, revocation, tlsClient, nameForSubject, now } =
      this.deps;
    log.debug('Entering ServiceSignals.holdingsOf(). scope=' + scopeId +
              (useCaseId ? ' use=' + useCaseId : ''));
    const realm = this.realmOf(scopeId);
    if (!realm) {
      log.debug('Leaving ServiceSignals.holdingsOf(). Not a realm.');
      return [];
    }
    const p = pki();
    const rev = revocation();
    const row = p.rawRowFor(scopeId) || {};
    const tiers = this.tiersOf(scopeId);
    const at = now();
    const out: Holding[] = [];
    const nameOf = function (holderSubject: string, fallback: string): string {
      log.debug('Entering nameOf().');
      let name = '';
      if (holderSubject) {
        try {
          name = self.deps.realms().run(realm, function (): string {
            return String(nameForSubject(holderSubject) || '');
          });
        } catch (e) {
          log.debug('Caught in nameOf(): ' + ((e && e.message) || e));
          name = '';
        }
      }
      log.debug('Leaving nameOf().');
      return name || String(fallback || '');
    };
    const chainOf = function (uc: string): string {
      log.debug('Entering chainOf().');
      const tier = tiers.issuing[uc];
      log.debug('Leaving chainOf().');
      return [tier ? tier.serial : '', tiers.intermediate, tiers.root]
        .join('/');
    };
    const live = function (uc: string, serialHex: string,
                           notAfter: string): boolean {
      log.debug('Entering live().');
      const expires = Date.parse(String(notAfter || ''));
      const ok = !!serialHex && !(Number.isFinite(expires) && expires <= at) &&
                 !rev.isRevoked(scopeId, uc, serialHex);
      log.debug('Leaving live().');
      return ok;
    };
    // The register's slots: a person's TLS client certificates.
    const certs = row.certs || {};
    Object.keys(certs).forEach(function (key: string) {
      const one = certs[key] || {};
      const uc = String(one.useCase || '');
      if (useCaseId && uc !== useCaseId) {
        return;
      }
      const tier = tiers.issuing[uc];
      const person = tlsClient().holderOfSlot(one.slot);
      if (!person || !tier ||
          (one.chainPem || [])[0] !== tier.pem ||
          !live(uc, String(one.serialHex || ''), one.notAfter)) {
        return;
      }
      out.push({ scope: String(scopeId), useCase: uc,
                 username: nameOf(String(one.holderSubject || ''), person),
                 kind: 'slot', slotKey: key,
                 serialHex: rev.normalSerial(one.serialHex),
                 issuer: self.issuerName(tier.pem, tier.subject),
                 chain: chainOf(uc) });
    });
    // The issued register: key pairs and ACME, EST and SCEP enrolments.
    (row.issuedKeyPairs || []).forEach(function (one: Json) {
      if (!one || one.subjectKind !== 'person' || !one.identifier) {
        return;
      }
      const uc = String(one.useCase || '');
      if (useCaseId && uc !== useCaseId) {
        return;
      }
      const tier = tiers.issuing[uc];
      const issuedAt = Date.parse(String(one.issuedAt || ''));
      if (!tier || (Number.isFinite(issuedAt) && tier.createdAt &&
                    issuedAt < tier.createdAt) ||
          !live(uc, String(one.serialHex || ''), one.notAfter)) {
        return;
      }
      out.push({ scope: String(scopeId), useCase: uc,
                 username: nameOf(String(one.holderSubject || ''),
                                  String(one.identifier)),
                 kind: 'pair', slotKey: '',
                 serialHex: rev.normalSerial(one.serialHex),
                 issuer: self.issuerName(tier.pem, tier.subject),
                 chain: chainOf(uc) });
    });
    log.debug('Leaving ServiceSignals.holdingsOf(). ' + out.length + '.');
    return out;
  }

  // WHAT THE TREE HOLDS BEFORE AN ACT, for `hierarchyChanged()` to compare
  // with. `scopeIds` is every scope the act can reach (every realm, for a
  // Root); `useCaseId` narrows it to one Issuing CA. Never throws: a
  // snapshot that could not be taken is empty, and the act goes ahead.
  snapshot(scopeIds: string[], useCaseId?: string): Json {
    const self = this;
    const { log } = this.deps;
    log.debug('Entering ServiceSignals.snapshot(). ' +
              (scopeIds || []).length + ' scope(s).');
    const out: Json = { holdings: [], spiffe: {} };
    (scopeIds || []).forEach(function (scopeId: string) {
      try {
        out.holdings = out.holdings.concat(self.holdingsOf(scopeId,
                                                           useCaseId));
        out.spiffe[String(scopeId)] = self.spiffeChainOf(scopeId);
      } catch (e) {
        log.warn('service signals: the certificates of "' + scopeId +
                 '" could not be read before a change to the hierarchy, so ' +
                 'no credential-change is sent for them: ' +
                 ((e && e.message) || e));
      }
    });
    log.debug('Leaving ServiceSignals.snapshot(). ' + out.holdings.length +
              ' held.');
    return out;
  }

  // The SPIFFE Issuing CA's chain in a scope, as `tiersOf()` reads it, or ''
  // where the realm has none.
  private spiffeChainOf(scopeId: string): string {
    const { log } = this.deps;
    log.debug('Entering ServiceSignals.spiffeChainOf().');
    const tiers = this.tiersOf(scopeId);
    const tier = tiers.issuing.spiffe;
    log.debug('Leaving ServiceSignals.spiffeChainOf().');
    return tier ? [tier.serial, tiers.intermediate, tiers.root].join('/')
                : '';
  }

  // AFTER THE ACT: each certificate the snapshot held is unchanged, RE-MINTED
  // (a slot now holding a new certificate from the current tree — `update`)
  // or ORPHANED (anything else — `revoke`). Every realm whose SPIFFE Issuing
  // CA moved is told its authority rotated (#245). `ctx`: `{ via,
  // reasonAdmin, reason }`. Answers the counts at once; the events go on in
  // batches behind it.
  hierarchyChanged(before: Json, ctx?: Json): Json {
    const self = this;
    const { log, pki } = this.deps;
    log.debug('Entering ServiceSignals.hierarchyChanged().');
    const c = ctx || {};
    const notices: Notice[] = [];
    const tiersNow: Json = {};
    const tiersFor = function (scopeId: string): Json {
      log.debug('Entering tiersFor().');
      if (!tiersNow[scopeId]) {
        tiersNow[scopeId] = self.tiersOf(scopeId);
      }
      log.debug('Leaving tiersFor().');
      return tiersNow[scopeId];
    };
    let updated = 0;
    let revoked = 0;
    ((before && before.holdings) || []).forEach(function (h: Holding) {
      const tiers = tiersFor(h.scope);
      const tier = tiers.issuing[h.useCase];
      const chainNow = [tier ? tier.serial : '', tiers.intermediate,
                        tiers.root].join('/');
      if (h.kind === 'slot') {
        const row = pki().rawRowFor(h.scope) || {};
        const now = (row.certs || {})[h.slotKey];
        const serialNow = now ? String(now.serialHex || '') : '';
        const sameSerial = !!now && self.deps.revocation()
          .normalSerial(serialNow) === h.serialHex;
        if (sameSerial && chainNow === h.chain) {
          return;
        }
        if (now && !sameSerial && tier &&
            (now.chainPem || [])[0] === tier.pem) {
          updated += 1;
          notices.push({ scope: h.scope, username: h.username,
                         changeType: 'update',
                         issuer: self.issuerName(tier.pem, tier.subject),
                         serialHex: self.deps.revocation()
                           .normalSerial(serialNow),
                         compromised: false });
          return;
        }
      } else if (chainNow === h.chain) {
        return;
      }
      revoked += 1;
      notices.push({ scope: h.scope, username: h.username,
                     changeType: 'revoke', issuer: h.issuer,
                     serialHex: h.serialHex, compromised: false });
    });
    // SPIFFE (#245): a realm whose SPIFFE Issuing CA — or a tier above it —
    // is not the one it was. The bundle changed when the Root did.
    const spiffe = (before && before.spiffe) || {};
    const moved = Object.keys(spiffe).filter(function (scopeId: string) {
      return !!spiffe[scopeId] &&
             self.spiffeChainOf(scopeId) !== spiffe[scopeId];
    });
    moved.forEach(function (scopeId: string) {
      const was = String(spiffe[scopeId]).split('/');
      const now = self.spiffeChainOf(scopeId).split('/');
      const realm = self.realmOf(scopeId);
      if (!realm) {
        return;
      }
      self.keyChanged('spiffe', String(realm.id), {
        rotated: [{ unit: 'x509-authority', from: was[0] || 'none',
                    to: now[0] || 'none' }],
        reason: 'requested', bundleChanged: was[2] !== now[2] });
    });
    this.fanOut(notices, c);
    log.info('service signals: a change to the certificate hierarchy (' +
             String(c.via || 'an act') + ') re-minted ' + updated +
             ' and orphaned ' + revoked + ' certificate(s) held by people; ' +
             'a credential-change is going to each, and ' + moved.length +
             ' realm(s) are told their SPIFFE authority moved.');
    log.debug('Leaving ServiceSignals.hierarchyChanged().');
    return { updated: updated, revoked: revoked, spiffeRealms: moved.length };
  }

  // AN ISSUING CA OR AN INTERMEDIATE WAS REVOKED (#244): `caId` is the
  // authority whose list the serial went on — `intermediate` for one of the
  // scope's Issuing CAs, `root` for a scope's Intermediate. Every person
  // holding a live leaf beneath the revoked authority is told `revoke`, and
  // `credential-compromise` too for a compromise reason. A serial that is
  // not a CURRENT tier revokes nothing anybody here still holds, and a
  // leaf's serial is not this function's: the leaf revoke is already told.
  // Answers `{ tier, people }` at once; the events go on in batches.
  caRevoked(scopeId: string, caId: string, serialHex: string,
            reason: string, ctx?: Json): Json {
    const self = this;
    const { log, pki, revocation } = this.deps;
    log.debug('Entering ServiceSignals.caRevoked(). ' + caId + ' ' +
              serialHex);
    const rev = revocation();
    const wanted = rev.normalSerial(serialHex);
    const reaches: Json[] = [];
    if (caId === 'intermediate') {
      const tiers = this.tiersOf(scopeId);
      Object.keys(tiers.issuing).forEach(function (uc: string) {
        if (rev.normalSerial(tiers.issuing[uc].serial) === wanted) {
          reaches.push({ scope: String(scopeId), useCase: uc });
        }
      });
    } else if (caId === 'root') {
      const p = pki();
      const scopes = (p.knownScopes() || []).filter(function (one: string) {
        return !!self.realmOf(one);
      });
      scopes.forEach(function (one: string) {
        const row = p.rawRowFor(one) || {};
        if (row.intermediate &&
            rev.normalSerial(row.intermediate.serialHex) === wanted) {
          reaches.push({ scope: one, useCase: '' });
        }
      });
    }
    if (!reaches.length) {
      log.debug('Leaving ServiceSignals.caRevoked(). Not a current tier.');
      return { tier: '', people: 0 };
    }
    const compromised = COMPROMISE_REASONS.indexOf(String(reason)) >= 0;
    const notices: Notice[] = [];
    reaches.forEach(function (one: Json) {
      self.holdingsOf(one.scope, one.useCase || undefined)
        .forEach(function (h: Holding) {
          notices.push({ scope: h.scope, username: h.username,
                         changeType: 'revoke', issuer: h.issuer,
                         serialHex: h.serialHex, compromised: compromised });
        });
    });
    this.fanOut(notices, Object.assign({}, ctx || {}, { reason: reason }));
    const tier = caId === 'intermediate' ? 'issuing-ca' : 'intermediate-ca';
    log.info('service signals: a revoked ' + tier + ' (' + wanted + ', ' +
             reason + ') reaches ' + notices.length + ' certificate(s) held ' +
             'by people; a credential-change' +
             (compromised ? ' and a credential-compromise' : '') +
             ' is going to each.');
    log.debug('Leaving ServiceSignals.caRevoked().');
    return { tier: tier, people: notices.length };
  }

  // THE FAN-OUT, IN BATCHES OF `BATCH`, each inside its person's realm. Runs
  // behind the caller; resolves the number of events handed over (for a
  // test), never rejects.
  fanOut(notices: Notice[], ctx?: Json): Promise<number> {
    const self = this;
    const { log, yieldTurn } = this.deps;
    log.debug('Entering ServiceSignals.fanOut(). ' + notices.length + '.');
    const c = ctx || {};
    const run = async function (): Promise<number> {
      log.debug('Entering run().');
      let handed = 0;
      for (let i = 0; i < notices.length; i += BATCH) {
        const batch = notices.slice(i, i + BATCH);
        const counts = await Promise.all(batch.map(function (n: Notice) {
          return self.tellOne(n, c);
        }));
        handed += counts.reduce(function (a: number, b: number): number {
          return a + b;
        }, 0);
        if (i + BATCH < notices.length) {
          await yieldTurn();
        }
      }
      log.debug('Leaving run(). ' + handed + ' handed over.');
      return handed;
    };
    log.debug('Leaving ServiceSignals.fanOut().');
    return run().catch(function (e: Json): number {
      log.warn('service signals: a fan-out after a change to the ' +
               'certificate hierarchy stopped: ' + ((e && e.message) || e));
      return 0;
    });
  }

  // One person's events: CAEP credential-change, and RISC
  // credential-compromise where the authority's key was compromised.
  private tellOne(n: Notice, c: Json): Promise<number> {
    const { log, realms, accountSignals } = this.deps;
    log.debug('Entering ServiceSignals.tellOne(). ' + n.username);
    const realm = this.realmOf(n.scope);
    if (!realm || !n.username) {
      log.debug('Leaving ServiceSignals.tellOne(). Nobody to tell.');
      return Promise.resolve(0);
    }
    const signals = accountSignals();
    const reasonAdmin = String(c.reasonAdmin ||
      (n.changeType === 'update'
        ? 'The certificate authority that issued a certificate of ' +
          n.username + ' was replaced, and the certificate was re-issued ' +
          'from the new one.'
        : 'A certificate authority above a certificate of ' + n.username +
          ' was ' + (c.reason ? 'revoked (' + c.reason + ')' : 'replaced') +
          ', so the certificate no longer chains to anything this service ' +
          'vouches for.'));
    const reasonUser = n.changeType === 'update'
      ? 'A certificate of yours was re-issued by a new certificate authority.'
      : 'A certificate of yours no longer chains to a certificate ' +
        'authority this service vouches for.';
    let answer: Promise<number>;
    try {
      answer = realms().run(realm, function (): Promise<number> {
        const work = [signals.credentialChanged({ username: n.username,
          credentialType: 'x509', changeType: n.changeType,
          x509Issuer: n.issuer, x509Serial: n.serialHex,
          initiatingEntity: 'admin', via: String(c.via || '/admin/pki'),
          reasonAdmin: reasonAdmin, reasonUser: reasonUser })];
        if (n.compromised) {
          work.push(signals.credentialCompromised({ username: n.username,
            credentialType: 'x509', initiatingEntity: 'admin',
            via: String(c.via || '/admin/pki'), reasonAdmin: reasonAdmin,
            reasonUser: 'A certificate authority that vouched for a ' +
                        'certificate of yours was compromised.' }));
        }
        return Promise.all(work).then(function (): number {
          return work.length;
        });
      });
    } catch (e) {
      log.warn('service signals: the events about ' + n.username +
               ' could not be sent: ' + ((e && e.message) || e));
      return Promise.resolve(0);
    }
    log.debug('Leaving ServiceSignals.tellOne().');
    return Promise.resolve(answer).catch(function (e: Json): number {
      log.warn('service signals: the events about ' + n.username +
               ' failed: ' + ((e && e.message) || e));
      return 0;
    });
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2), with facades for the
// JavaScript that calls this module through `require()`.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<ServiceSignals>(
  'ssf/service_signals',
  () => new ServiceSignals(ServiceSignals.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  ServiceSignals: ServiceSignals,
  installInstance: (instance: ServiceSignals): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  BATCH: BATCH,
  COMPROMISE_REASONS: COMPROMISE_REASONS,
  keyChanged: slot.forward('keyChanged'),
  holdingsOf: slot.forward('holdingsOf'),
  snapshot: slot.forward('snapshot'),
  hierarchyChanged: slot.forward('hierarchyChanged'),
  caRevoked: slot.forward('caRevoked'),
  fanOut: slot.forward('fanOut')
};
