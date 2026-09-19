'use strict';
//
// File: vc_status.ts
//
// ---------------------------------------------------------------------------
// THE STATUS OF EVERY CREDENTIAL THIS ISSUER MINTS (2026-09-17, #38's
// follow-ups).
//
// The issuer published no status mechanism until this file, and `vc_issued.ts`
// said so: its register's expiry and a `forget()` were "the closest thing".
// A disown made here reached this service's own sign-in door and nothing
// else, so a verifier elsewhere went on accepting a credential its issuer had
// taken back. Two specifications close that, one per data model:
//
//   * **Token Status List** (draft-ietf-oauth-status-list-21) for the JOSE
//     formats. An SD-JWT VC and a `jwt_vc_json` credential carry
//     `status.status_list: { idx, uri }` (section 6.2), and the list at `uri`
//     is served as a Status List Token in JWT form (`application/
//     statuslist+jwt`, section 5.1) and CWT form (`application/
//     statuslist+cwt`, section 5.2), chosen by `Accept` (section 8.1). Two
//     bits per credential, so SUSPENDED (0x02) can be said as well as
//     INVALID (0x01). The aggregation endpoint (section 9) lists the one
//     list a realm has.
//   * **W3C Bitstring Status List v1.0** for the W3C formats. A `jwt_vc_json`
//     and an `ldp_vc` credential carry `credentialStatus`, two
//     `BitstringStatusListEntry` objects — one per purpose, `revocation` and
//     `suspension` — naming a `BitstringStatusListCredential` served here,
//     secured as a JWT (`application/vc+jwt`, VC-JOSE-COSE). A `jwt_vc_json`
//     credential is both a JWT and a W3C credential, so it carries both
//     mechanisms and a verifier may use either.
//
// **ONE INDEX PER CREDENTIAL, THE SAME IN EVERY LIST.** A credential is given
// one random index (draft section 13.2: an index that counts up says how many
// credentials came before), and that index is its position in the Token
// Status List and in both bitstrings. An index is taken through a cluster
// claim that lives as long as the credential, so two nodes cannot hand out
// the same one, and it is free again once the credential has expired
// (section 13.3's double-allocation rule is about live tokens).
//
// **WHAT A BIT SAYS IS COMPUTED, NOT STORED TWICE.** An entry keeps its
// explicit status — what `/admin/vc-status` or a disown (`vc_issued.ts`) set
// — and the issued register's handle. The published value is the explicit
// one, or INVALID when an administrator revoked the credential's row on
// `/admin/tokens` (read from `admin_stats.js` by handle, so a restore there
// clears the bit here). One answer to "is this credential still good",
// read by the lists, the Verifier and the sign-in door alike.
//
// **THE VERIFIER CONSULTS IT** (`checkPresented()`): a credential this realm
// signed is looked up here, in the realm's own entries, never fetched — and
// one that carries no reference is refused, because every credential this
// issuer mints carries one. A credential a TRUSTED FOREIGN issuer signed is
// resolved by fetching its list through `federation/federation_http.ts`'s
// `fetchPublished()`, verified against the very certificate that verified the
// credential, cached for its `ttl` (bounded), and refused when no statement
// can be made (section 8.3: "SHOULD be rejected").
//
// **CACHE-CONTROL.** The draft puts the caching instruction IN the token
// (`ttl`, `exp`) and tells a relying party to prefer it over HTTP headers
// (section 8.2), so the response says `max-age` equal to the `ttl` and
// nothing stronger: a list is not a key and the root rule for key documents
// does not apply to it.
//
// A ROUTE MODULE AND A LIBRARY, on the composition root's pattern: the
// issuer, the Verifier and `vc_issued.ts` require it; it requires
// `common/` libraries, `vc_status_codec.ts` and `federation_http.ts`, none
// of which requires anything in this directory.
// ---------------------------------------------------------------------------

import crypto = require('crypto');
import app = require('../common/app');
import helpers = require('../common/helpers');
import config = require('../common/config');
import realms = require('../common/realms');
import stsCrypto = require('../common/crypto');
import errorCodes = require('../common/error_codes');
import stats = require('../common/admin_stats');
import cacheRegistry = require('../common/cache_registry');
import InstanceSlot = require('../common/instance_slot');
import clusterClaims = require('../cluster/cluster_claims');
import fedHttp = require('../federation/federation_http');
import codec = require('./vc_status_codec');

type RouteApp = typeof app;

// The number of indexes in a list. The Bitstring Status List's minimum
// (131,072 bits, section 6.1 of that specification, so a list says nothing
// about how many credentials there are) and a Token Status List of the same
// length, so one index is one position in both.
const LIST_SIZE = 131072;
// Two bits: VALID, INVALID and SUSPENDED all fit (draft section 7.1).
const TSL_BITS = 2;
const VALID = 0;
const INVALID = 1;
const SUSPENDED = 2;
const STATUS_NAMES = { 0: 'VALID', 1: 'INVALID', 2: 'SUSPENDED' };

// The paths, under a realm's prefix.
const TSL_PATH = '/oid4vci/status-lists/1';
const AGGREGATION_PATH = '/oid4vci/status-lists';
const BITSTRING_PATH = '/oid4vci/status-lists/bitstring';
const PURPOSES = ['revocation', 'suspension'];

const JWT_TYPE = 'application/statuslist+jwt';
const CWT_TYPE = 'application/statuslist+cwt';
const VC_JWT_TYPE = 'application/vc+jwt';

// A claim outlives the credential by the skew the other single-use values
// allow.
const CLAIM_SKEW_MS = 60 * 1000;
// How long a failed fetch is remembered, so a partner that is down is not
// dialled on every presentation.
const NEGATIVE_CACHE_MS = 30 * 1000;
// How many foreign lists one process remembers.
const MAX_FETCHED = 256;

// idx -> { status, format, configId, artifactKey, expiresAt, allocatedAt,
//          changedAt, via }
// PER TRUST REALM, persisted: every process and node publishes the same list.
const entries = realms.map({ persist: 'vc_status.entries' });

// uri -> { ok, why, bits, bytes (base64url), kind, fetchedAt, until }
// PER PROCESS: a cache of what trusted foreign issuers published.
const fetched = new Map<string, any>();

// realm|kind -> { digest, token, signedAt }: the last token this process
// signed for a list, re-signed when the bytes change or it is half-way to its
// ttl. PER PROCESS.
const signedTokens = new Map<string, any>();
// A few documents per realm (one per kind of list), so the bound is only ever
// met by a process serving a great many realms; the oldest then goes and is
// signed again when it is next asked for (2026-09-18).
const MAX_SIGNED_TOKENS = 1024;

const entriesCount = cacheRegistry.register({
  name: 'oid4vci.status-entries',
  title: 'Credential status entries',
  description: 'Each issued credential\'s index in this realm\'s status ' +
    'lists and the status an administrator or a sign-out set for it.',
  owner: 'oid4vc/vc_status.ts',
  scope: 'realm',
  kind: 'replay',
  persisted: true,
  hitMeaning: 'a credential\'s status was found here',
  settings: ['oid4vci.credentialLifetimeS'],
  maxEntries: function (): number {
    return LIST_SIZE;
  },
  bound: 'Enforced: the status list holds ' + LIST_SIZE + ' indexes per ' +
    'realm; a list with no free index REFUSES to issue the credential ' +
    '(STS-VC-0075) rather than reuse a live one.',
  lifetime: function (): string {
    return 'as long as the credential it describes; its index is free ' +
      'again after that.';
  },
  entries: function (): unknown[] {
    return cacheRegistry.realmMapRows(realms, entries,
      function (row: any, idx: unknown): object {
        return { key: 'idx:' + String(idx),
                 validUntil: Number((row && row.expiresAt) || 0) || null };
      });
  }
});

const fetchedCount = cacheRegistry.register({
  name: 'oid4vp.status-lists-fetched',
  title: 'Fetched status lists',
  description: 'Status List Tokens and Bitstring Status List credentials a ' +
    'trusted foreign issuer published, fetched when one of its credentials ' +
    'was presented to the Verifier.',
  owner: 'oid4vc/vc_status.ts',
  scope: 'process',
  kind: 'cache',
  persisted: false,
  hitMeaning: 'a presented credential\'s status was answered without a ' +
    'fetch',
  settings: ['oid4vp.statusListMaxCacheS', 'federation.outbound'],
  maxEntries: function (): number {
    return MAX_FETCHED;
  },
  bound: 'Enforced: ' + MAX_FETCHED + ' fetched lists for the process, the ' +
    'oldest dropped and fetched again when next needed.',
  lifetime: function (): string {
    return 'the list\'s own ttl (and never past its exp), at most ' +
      'oid4vp.statusListMaxCacheS; a failed fetch 30 seconds.';
  },
  entries: function (): unknown[] {
    const out: unknown[] = [];
    fetched.forEach(function (row, uri) {
      out.push({ realm: null, key: cacheRegistry.clipKey(uri),
                 validUntil: row.until, basis: row.ok ? 'ttl' : 'failure' });
    });
    return out;
  }
});

const signedCount = cacheRegistry.register({
  name: 'oid4vci.status-list-tokens',
  title: 'Signed status lists',
  description: 'The last Status List Token and Bitstring Status List ' +
    'credential this process signed for each realm, reused while the list ' +
    'has not changed.',
  owner: 'oid4vc/vc_status.ts',
  scope: 'process',
  kind: 'cache',
  persisted: false,
  hitMeaning: 'a list was served without signing it again',
  settings: ['oid4vci.statusListTtlS'],
  maxEntries: function (): number {
    return MAX_SIGNED_TOKENS;
  },
  bound: 'Enforced: ' + MAX_SIGNED_TOKENS + ' signed documents for the ' +
    'process, the oldest dropped and signed again when next asked for.',
  lifetime: function (): string {
    return 'until the list changes, or half of oid4vci.statusListTtlS.';
  },
  entries: function (): unknown[] {
    const out: unknown[] = [];
    signedTokens.forEach(function (row, key) {
      out.push({ realm: String(key).split('|')[0], key: String(key),
                 validUntil: row.signedAt + row.ttlMs / 2 });
    });
    return out;
  }
});

interface VcStatusDeps {
  log: typeof helpers.log;
  config: { value(key: string): any };
  realms: typeof realms;
  stsCrypto: typeof stsCrypto;
  errorCodes: typeof errorCodes;
  artifactRevokedByKey: (key: string) => any;
  signingKeyForAsync: typeof helpers.signingKeyForAsync;
  publishedKidFor: typeof helpers.publishedKidFor;
  certificateHeaderFor: typeof helpers.certificateHeaderFor;
  STS: typeof helpers.STS;
  baseUrlOf: typeof helpers.baseUrlOf;
  clusterClaims: typeof clusterClaims;
  fetchPublished: (url: string, opts: any) => Promise<any>;
  entries: any;
  now: () => number;
}

class VcStatus {
  static readonly LIST_SIZE = LIST_SIZE;
  static readonly TSL_PATH = TSL_PATH;
  static readonly AGGREGATION_PATH = AGGREGATION_PATH;
  static readonly BITSTRING_PATH = BITSTRING_PATH;
  static readonly VALID = VALID;
  static readonly INVALID = INVALID;
  static readonly SUSPENDED = SUSPENDED;
  static readonly STATUS_NAMES = STATUS_NAMES;

  constructor(private readonly deps: VcStatusDeps) {
    deps.log.debug("Entering VcStatus.constructor().");
    deps.log.debug("Leaving VcStatus.constructor().");
  }

  static defaultDeps(): VcStatusDeps {
    helpers.log.debug("Entering VcStatus.defaultDeps().");
    helpers.log.debug("Leaving VcStatus.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      realms: realms,
      stsCrypto: stsCrypto,
      errorCodes: errorCodes,
      artifactRevokedByKey: stats.artifactRevokedByKey,
      signingKeyForAsync: helpers.signingKeyForAsync,
      publishedKidFor: helpers.publishedKidFor,
      certificateHeaderFor: helpers.certificateHeaderFor,
      STS: helpers.STS,
      baseUrlOf: helpers.baseUrlOf,
      clusterClaims: clusterClaims,
      fetchPublished: fedHttp.fetchPublished,
      entries: entries,
      now: function now(): number {
        return Date.now();
      }
    };
  }

  private ttlSeconds(): number {
    const { log, config } = this.deps;
    log.debug("Entering VcStatus.ttlSeconds().");
    const s = Number(config.value('oid4vci.statusListTtlS'));
    log.debug("Leaving VcStatus.ttlSeconds().");
    return isFinite(s) && s > 0 ? Math.floor(s) : 300;
  }

  private lifetimeSeconds(): number {
    const { log, config } = this.deps;
    log.debug("Entering VcStatus.lifetimeSeconds().");
    const s = Number(config.value('oid4vci.statusListLifetimeS'));
    log.debug("Leaving VcStatus.lifetimeSeconds().");
    return isFinite(s) && s > 0 ? Math.floor(s) : 86400;
  }

  private maxCacheMs(): number {
    const { log, config } = this.deps;
    log.debug("Entering VcStatus.maxCacheMs().");
    const s = Number(config.value('oid4vp.statusListMaxCacheS'));
    log.debug("Leaving VcStatus.maxCacheMs().");
    return (isFinite(s) && s >= 0 ? Math.floor(s) : 3600) * 1000;
  }

  // The URIs a credential issued under `base` (the credential issuer, realm
  // prefix included) names.
  tslUri(base: string): string {
    const { log } = this.deps;
    log.debug("Entering VcStatus.tslUri().");
    log.debug("Leaving VcStatus.tslUri().");
    return String(base).replace(/\/+$/, '') + TSL_PATH;
  }

  bitstringUri(base: string, purpose: string): string {
    const { log } = this.deps;
    log.debug("Entering VcStatus.bitstringUri().");
    log.debug("Leaving VcStatus.bitstringUri().");
    return String(base).replace(/\/+$/, '') + BITSTRING_PATH + '/' + purpose;
  }

  // ---------------------------------------------------------------------------
  // THE SIGNER, the same key and algorithm a credential is signed with
  // (`oid4vci.credentialSigningAlgorithm`), post-quantum included: a list
  // signed with a different key from the credentials it describes would make
  // a verifier resolve two keys for one issuer (draft section 11.3).
  // `vc_issuer.ts` asks this too, so there is one answer.
  // ---------------------------------------------------------------------------
  async signerAsync(): Promise<{ alg: string; key: any; kid: string;
                                 headerKid: string }> {
    const { log, config, STS, signingKeyForAsync, publishedKidFor } =
      this.deps;
    log.debug("Entering VcStatus.signerAsync().");
    const alg = String(config.value('oid4vci.credentialSigningAlgorithm') ||
                       'RS256');
    if (alg === 'RS256') {
      log.debug("Leaving VcStatus.signerAsync(). RS256.");
      return { alg: 'RS256', key: STS.privateKey, kid: STS.kid,
               headerKid: publishedKidFor(STS.kid) };
    }
    const signer = await signingKeyForAsync(alg);
    log.debug("Leaving VcStatus.signerAsync(). " + alg + ".");
    return { alg: alg, key: signer.key, kid: signer.kid,
             headerKid: publishedKidFor(signer.kid) };
  }

  // ---------------------------------------------------------------------------
  // ALLOCATE AN INDEX for a credential about to be built, and answer what the
  // credential carries. `base` is the credential issuer's URL.
  // ---------------------------------------------------------------------------
  async allocate(opts: { base: string; format: string; configId: string;
                         expiresAt: number }): Promise<any> {
    const { log, entries, clusterClaims, errorCodes, now } = this.deps;
    log.debug("Entering VcStatus.allocate(). format=" + opts.format);
    const expiresAt = Number(opts.expiresAt) || (now() + 365 * 86400000);
    for (let attempt = 0; attempt < 32; attempt++) {
      const idx = crypto.randomInt(0, LIST_SIZE);
      const held = entries.get(String(idx));
      if (held && (!held.expiresAt || held.expiresAt > now())) {
        continue;
      }
      const claimed = await clusterClaims.claim({
        scope: 'oid4vci.status-index', value: String(idx),
        ttlMs: Math.max(0, expiresAt - now()) + CLAIM_SKEW_MS });
      if (!claimed.ok) {
        if (claimed.reason !== 'used') {
          log.error(errorCodes.tag('STS-VC-0075') + 'vc_status: the claim ' +
                    'store could not be asked for a status-list index (' +
                    (claimed.why || 'no reason given') + ').');
          log.debug("Leaving VcStatus.allocate(). The store failed.");
          throw new Error('no status-list index could be allocated: the ' +
                          'claim store could not be asked');
        }
        continue;
      }
      entries.set(String(idx), {
        status: VALID, format: String(opts.format || ''),
        configId: String(opts.configId || ''), artifactKey: '',
        expiresAt: expiresAt, allocatedAt: now(), changedAt: 0, via: ''
      });
      const tslUri = this.tslUri(opts.base);
      const w3c = opts.format === 'jwt_vc_json' || opts.format === 'ldp_vc';
      const jose = opts.format === 'dc+sd-jwt' ||
                   opts.format === 'jwt_vc_json';
      const out = {
        key: String(idx),
        status: jose ? { status_list: { idx: idx, uri: tslUri } } : null,
        credentialStatus: w3c ? PURPOSES.map((purpose) => {
          const listUri = this.bitstringUri(opts.base, purpose);
          return codec.bitstringEntry({
            id: listUri + '#' + idx, statusPurpose: purpose,
            statusListIndex: idx, statusListCredential: listUri });
        }) : null
      };
      log.debug("Leaving VcStatus.allocate(). idx=" + idx + ".");
      return out;
    }
    log.error(errorCodes.tag('STS-VC-0075') + 'vc_status: no free ' +
              'status-list index was found in 32 attempts; the list of ' +
              LIST_SIZE + ' is nearly full.');
    log.debug("Leaving VcStatus.allocate(). Full.");
    throw new Error('no status-list index could be allocated: the list is ' +
                    'full');
  }

  // Records which issued-register row an entry is for, once the artifact
  // exists.
  attach(key: string, artifactKey: string): void {
    const { log, entries } = this.deps;
    log.debug("Entering VcStatus.attach().");
    const row = entries.get(String(key));
    if (row) {
      row.artifactKey = String(artifactKey || '');
      entries.set(String(key), row);
    }
    log.debug("Leaving VcStatus.attach().");
  }

  // THE EFFECTIVE STATUS OF ONE ENTRY: see the header. An unknown index is
  // INVALID — this realm never issued a credential there, or the credential
  // has expired and its index been forgotten.
  statusOf(key: unknown): number {
    const { log, entries, artifactRevokedByKey, now } = this.deps;
    log.debug("Entering VcStatus.statusOf().");
    const row = entries.get(String(key));
    if (!row) {
      entriesCount.miss();
      log.debug("Leaving VcStatus.statusOf(). No such entry.");
      return INVALID;
    }
    entriesCount.hit();
    if (row.expiresAt && row.expiresAt <= now()) {
      log.debug("Leaving VcStatus.statusOf(). Expired.");
      return INVALID;
    }
    if (row.status !== VALID) {
      log.debug("Leaving VcStatus.statusOf(). " + row.status + ".");
      return Number(row.status);
    }
    if (row.artifactKey && artifactRevokedByKey(row.artifactKey)) {
      log.debug("Leaving VcStatus.statusOf(). Revoked in the register.");
      return INVALID;
    }
    log.debug("Leaving VcStatus.statusOf(). Valid.");
    return VALID;
  }

  // Sets an entry's explicit status. INVALID is final (the draft's "revoked,
  // annulled"); VALID and SUSPENDED move freely between each other.
  setStatus(key: unknown, value: number, via: string): boolean {
    const { log, entries, now } = this.deps;
    log.debug("Entering VcStatus.setStatus(). " + key + " -> " + value);
    const row = entries.get(String(key));
    const wanted = Number(value);
    if (!row || [VALID, INVALID, SUSPENDED].indexOf(wanted) < 0) {
      log.debug("Leaving VcStatus.setStatus(). Refused.");
      return false;
    }
    if (row.status === INVALID && wanted !== INVALID) {
      log.debug("Leaving VcStatus.setStatus(). INVALID is final.");
      return false;
    }
    if (row.status === wanted) {
      log.debug("Leaving VcStatus.setStatus(). Unchanged.");
      return false;
    }
    row.status = wanted;
    row.changedAt = now();
    row.via = String(via || 'unstated');
    entries.set(String(key), row);
    log.info('vc_status: status-list index ' + key + ' is now ' +
             STATUS_NAMES[wanted] + ' (' + row.via + ').');
    log.debug("Leaving VcStatus.setStatus(). Changed.");
    return true;
  }

  // Every live entry of the ambient realm, for the console and the API.
  rows(): any[] {
    const { log, entries, now } = this.deps;
    log.debug("Entering VcStatus.rows().");
    const out: any[] = [];
    const t = now();
    entries.forEach((row: any, idx: string) => {
      if (row.expiresAt && row.expiresAt <= t) {
        return;
      }
      const effective = this.statusOf(idx);
      out.push({ idx: Number(idx), format: row.format,
                 configId: row.configId, artifactKey: row.artifactKey,
                 status: STATUS_NAMES[effective] || String(effective),
                 explicit: STATUS_NAMES[row.status] || String(row.status),
                 expiresAt: row.expiresAt, allocatedAt: row.allocatedAt,
                 changedAt: row.changedAt, via: row.via });
    });
    out.sort(function (a, b) {
      return b.allocatedAt - a.allocatedAt;
    });
    log.debug("Leaving VcStatus.rows(). " + out.length + ".");
    return out;
  }

  // What the console and the API draw: the lists, their sizes and counts.
  summary(req: any): any {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering VcStatus.summary().");
    const rows = this.rows();
    const count = function (name: string): number {
      return rows.filter(function (r) {
        return r.status === name;
      }).length;
    };
    const base = baseUrlOf(req);
    log.debug("Leaving VcStatus.summary().");
    return {
      size: LIST_SIZE, bits: TSL_BITS,
      tokenStatusList: this.tslUri(base),
      aggregation: base + AGGREGATION_PATH,
      bitstring: PURPOSES.map((p) => this.bitstringUri(base, p)),
      ttlS: this.ttlSeconds(), lifetimeS: this.lifetimeSeconds(),
      allocated: rows.length, valid: count('VALID'),
      invalid: count('INVALID'), suspended: count('SUSPENDED'),
      rows: rows
    };
  }

  // The packed values of the ambient realm's list.
  private tslBytes(): Buffer {
    const { log, entries } = this.deps;
    log.debug("Entering VcStatus.tslBytes().");
    const values: number[] = [];
    entries.forEach((row: any, idx: string) => {
      const v = this.statusOf(idx);
      if (v !== VALID) {
        values[Number(idx)] = v;
      }
    });
    const bytes = codec.packTsl(values, TSL_BITS, LIST_SIZE);
    log.debug("Leaving VcStatus.tslBytes().");
    return bytes;
  }

  private bitstringBytes(purpose: string): Buffer {
    const { log, entries } = this.deps;
    log.debug("Entering VcStatus.bitstringBytes(). " + purpose);
    const wanted = purpose === 'suspension' ? SUSPENDED : INVALID;
    const set: number[] = [];
    entries.forEach((row: any, idx: string) => {
      if (this.statusOf(idx) === wanted) {
        set.push(Number(idx));
      }
    });
    const bytes = codec.packBitstring(set, LIST_SIZE);
    log.debug("Leaving VcStatus.bitstringBytes(). " + set.length + " set.");
    return bytes;
  }

  // One cached signed document, or null when it must be signed again.
  private reuse(kind: string, bytes: Buffer): any {
    const { log, realms, now } = this.deps;
    log.debug("Entering VcStatus.reuse(). " + kind);
    const key = realms.currentId() + '|' + kind;
    const digest = crypto.createHash('sha256').update(bytes).digest('hex');
    const held = signedTokens.get(key);
    if (held && held.digest === digest &&
        now() - held.signedAt < held.ttlMs / 2) {
      signedCount.hit();
      log.debug("Leaving VcStatus.reuse(). Reused.");
      return held;
    }
    signedCount.miss();
    log.debug("Leaving VcStatus.reuse(). Sign again.");
    return { key: key, digest: digest, token: null };
  }

  private remember(slot: any, token: any): void {
    const { log, now } = this.deps;
    log.debug("Entering VcStatus.remember().");
    if (!signedTokens.has(slot.key)) {
      cacheRegistry.makeRoom(signedTokens, MAX_SIGNED_TOKENS,
                             { counter: signedCount });
    }
    signedTokens.set(slot.key, { digest: slot.digest, token: token,
                                 signedAt: now(),
                                 ttlMs: this.ttlSeconds() * 1000 });
    log.debug("Leaving VcStatus.remember().");
  }

  // The Status List Token, JWT form (section 5.1).
  async tslJwt(req: any): Promise<string> {
    const { log, stsCrypto, certificateHeaderFor, now } = this.deps;
    log.debug("Entering VcStatus.tslJwt().");
    const bytes = this.tslBytes();
    const slot = this.reuse('tsl-jwt', bytes);
    if (slot.token) {
      log.debug("Leaving VcStatus.tslJwt(). Reused.");
      return slot.token;
    }
    const signer = await this.signerAsync();
    const iat = Math.floor(now() / 1000);
    const payload = codec.statusListJwtPayload({
      sub: this.tslUri(this.deps.baseUrlOf(req)), iat: iat,
      exp: iat + this.lifetimeSeconds(), ttl: this.ttlSeconds(),
      bits: TSL_BITS, bytes: bytes,
      aggregationUri: this.deps.baseUrlOf(req) + AGGREGATION_PATH });
    const token = await stsCrypto.signJwsAsync(payload, signer.key, {
      algorithm: signer.alg,
      header: Object.assign(certificateHeaderFor('vci-credential',
                                                 signer.alg, signer.kid),
                            { alg: signer.alg, typ: 'statuslist+jwt',
                              kid: signer.headerKid })
    });
    this.remember(slot, token);
    log.debug("Leaving VcStatus.tslJwt().");
    return token;
  }

  // The Status List Token, CWT form (section 5.2).
  async tslCwt(req: any): Promise<Buffer> {
    const { log, now } = this.deps;
    log.debug("Entering VcStatus.tslCwt().");
    const bytes = this.tslBytes();
    const slot = this.reuse('tsl-cwt', bytes);
    if (slot.token) {
      log.debug("Leaving VcStatus.tslCwt(). Reused.");
      return slot.token;
    }
    const signer = await this.signerAsync();
    const iat = Math.floor(now() / 1000);
    const token = await codec.statusListCwtAsync({
      sub: this.tslUri(this.deps.baseUrlOf(req)), iat: iat,
      exp: iat + this.lifetimeSeconds(), ttl: this.ttlSeconds(),
      bits: TSL_BITS, bytes: bytes,
      aggregationUri: this.deps.baseUrlOf(req) + AGGREGATION_PATH,
      key: signer.key, alg: signer.alg, kid: signer.headerKid });
    this.remember(slot, token);
    log.debug("Leaving VcStatus.tslCwt().");
    return token;
  }

  // The BitstringStatusListCredential for one purpose, as a VC-JOSE-COSE
  // JWT whose payload is the credential itself.
  async bitstringJwt(req: any, purpose: string): Promise<string> {
    const { log, stsCrypto, certificateHeaderFor, baseUrlOf, now } =
      this.deps;
    log.debug("Entering VcStatus.bitstringJwt(). " + purpose);
    const bytes = this.bitstringBytes(purpose);
    const slot = this.reuse('bsl-' + purpose, bytes);
    if (slot.token) {
      log.debug("Leaving VcStatus.bitstringJwt(). Reused.");
      return slot.token;
    }
    const signer = await this.signerAsync();
    const base = baseUrlOf(req);
    const uri = this.bitstringUri(base, purpose);
    const t = now();
    const credential = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: uri,
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      issuer: base,
      validFrom: new Date(t).toISOString(),
      validUntil: new Date(t + this.lifetimeSeconds() * 1000).toISOString(),
      credentialSubject: codec.bitstringStatusListSubject({
        id: uri + '#list', statusPurpose: purpose,
        encodedList: codec.encodedList(bytes),
        ttl: this.ttlSeconds() * 1000 })
    };
    const token = await stsCrypto.signJwsAsync(
      Object.assign({ iat: Math.floor(t / 1000) }, credential), signer.key, {
        algorithm: signer.alg,
        header: Object.assign(certificateHeaderFor('vci-credential',
                                                   signer.alg, signer.kid),
                              { alg: signer.alg, typ: 'vc+jwt',
                                cty: 'vc', kid: signer.headerKid })
      });
    this.remember(slot, token);
    log.debug("Leaving VcStatus.bitstringJwt().");
    return token;
  }

  // ---------------------------------------------------------------------------
  // IS A PRESENTED CREDENTIAL STILL GOOD, BY ITS STATUS?
  //
  //   own      the credential verified against THIS realm's key
  //   format   the format it was presented in
  //   claims   the credential's JWT claims (JOSE formats) — for `ldp_vc` the
  //            caller passes `credentialStatus` entries it read from the
  //            disclosed statements, or none
  //   key      the key that verified a FOREIGN credential; its lists must be
  //            signed by the same one
  //
  // Answers `{ checked, ok, status, detail }`. `checked` false means there
  // was nothing to consult and nothing required one. It never rejects.
  // ---------------------------------------------------------------------------
  async checkPresented(opts: { own: boolean; format: string; claims?: any;
                               credentialStatus?: any[]; key?: any;
                               algs?: string[] }): Promise<any> {
    const { log } = this.deps;
    log.debug("Entering VcStatus.checkPresented(). own=" + opts.own +
              ", format=" + opts.format);
    const claims = opts.claims || {};
    let tsl = null;
    try {
      tsl = codec.referenceOf(claims);
    } catch (e) {
      log.debug("Caught in VcStatus.checkPresented(): " +
                ((e && e.message) || e));
      log.debug("Leaving VcStatus.checkPresented(). Malformed status.");
      return { checked: true, ok: false, status: '',
               detail: 'its status claim is malformed: ' + e.message };
    }
    const bitstrings = [].concat(opts.credentialStatus ||
      (claims.vc && claims.vc.credentialStatus) || [])
      .filter(function (one: any) {
        return !!one && one.type === 'BitstringStatusListEntry';
      });
    if (!tsl && !bitstrings.length) {
      log.debug("Leaving VcStatus.checkPresented(). No reference.");
      return opts.own
        ? { checked: true, ok: false, status: '',
            detail: 'it carries no status reference, and every credential ' +
                    'this realm issues carries one' }
        : { checked: false, ok: true, status: '',
            detail: 'the issuer publishes no status for it' };
    }
    const answers: any[] = [];
    if (tsl) {
      answers.push(opts.own ? this.ownTsl(tsl)
                            : await this.foreignTsl(tsl, opts));
    }
    for (let i = 0; i < bitstrings.length; i++) {
      answers.push(opts.own ? this.ownBitstring(bitstrings[i])
                            : await this.foreignBitstring(bitstrings[i],
                                                          opts));
    }
    const bad = answers.filter(function (a) {
      return !a.ok;
    });
    log.debug("Leaving VcStatus.checkPresented(). " + bad.length +
              " failed of " + answers.length + ".");
    return { checked: true, ok: !bad.length,
             status: bad.length ? bad[0].status : 'VALID',
             detail: answers.map(function (a) {
               return a.detail;
             }).join('; ') };
  }

  // A reference to this realm's own list: the path must be this realm's, and
  // the answer is the entry itself.
  private ownPathOk(uri: string, path: string): boolean {
    const { log, realms } = this.deps;
    log.debug("Entering VcStatus.ownPathOk().");
    let pathname = '';
    try {
      pathname = new URL(String(uri)).pathname;
    } catch (e) {
      log.debug("Caught in VcStatus.ownPathOk(): " + ((e && e.message) || e));
      pathname = '';
    }
    log.debug("Leaving VcStatus.ownPathOk().");
    return pathname === realms.currentPrefix() + path;
  }

  private ownTsl(ref: any): any {
    const { log } = this.deps;
    log.debug("Entering VcStatus.ownTsl().");
    if (!this.ownPathOk(ref.uri, TSL_PATH)) {
      log.debug("Leaving VcStatus.ownTsl(). Not this realm's list.");
      return { ok: false, status: '', detail: 'its Token Status List "' +
               ref.uri + '" is not one this realm publishes' };
    }
    const value = this.statusOf(ref.idx);
    const name = STATUS_NAMES[value] || String(value);
    log.debug("Leaving VcStatus.ownTsl(). " + name);
    return { ok: value === VALID, status: name,
             detail: 'Token Status List index ' + ref.idx + ' is ' + name };
  }

  private ownBitstring(entry: any): any {
    const { log } = this.deps;
    log.debug("Entering VcStatus.ownBitstring().");
    let read = null;
    try {
      read = codec.readBitstringEntry(entry);
    } catch (e) {
      log.debug("Caught in VcStatus.ownBitstring(): " +
                ((e && e.message) || e));
      log.debug("Leaving VcStatus.ownBitstring(). Malformed.");
      return { ok: false, status: '', detail: 'a credentialStatus entry is ' +
               'malformed: ' + e.message };
    }
    if (!this.ownPathOk(read.credential,
                        BITSTRING_PATH + '/' + read.statusPurpose)) {
      log.debug("Leaving VcStatus.ownBitstring(). Not this realm's list.");
      return { ok: false, status: '', detail: 'its ' + read.statusPurpose +
               ' list "' + read.credential + '" is not one this ' +
               'realm publishes' };
    }
    const value = this.statusOf(read.index);
    const hit = read.statusPurpose === 'suspension' ? value === SUSPENDED
                                                    : value === INVALID;
    log.debug("Leaving VcStatus.ownBitstring(). " + hit);
    // Each purpose answers for its own bit: a suspended credential's
    // revocation bit is clear, and the suspension entry beside it refuses.
    return { ok: !hit,
             status: hit ? (read.statusPurpose === 'suspension' ?
                            'SUSPENDED' : 'INVALID') : 'VALID',
             detail: 'Bitstring ' + read.statusPurpose + ' index ' +
                     read.index + (hit ? ' is set' : ' is clear') };
  }

  // A fetched list, from the cache or the network. `accept` names the form.
  private async fetchList(uri: string, accept: string,
                          parse: (body: Buffer, contentType: string)
                            => any): Promise<any> {
    const { log, fetchPublished, now } = this.deps;
    log.debug("Entering VcStatus.fetchList().");
    const cacheKey = accept + ' ' + uri;
    const held = fetched.get(cacheKey);
    if (held && held.until > now()) {
      fetchedCount.hit();
      log.debug("Leaving VcStatus.fetchList(). Cached.");
      return held;
    }
    fetchedCount.miss();
    const got = await fetchPublished(uri, { accept: accept });
    let row: any;
    if (!got.ok) {
      row = { ok: false, why: got.why || ('it answered ' + got.status),
              until: now() + NEGATIVE_CACHE_MS };
    } else {
      try {
        const parsed = parse(got.body, got.contentType);
        const ttlMs = Math.max(0, Number(parsed.ttlMs) || 0);
        let until = now() + Math.min(ttlMs || this.maxCacheMs(),
                                     this.maxCacheMs());
        if (parsed.expMs) {
          until = Math.min(until, parsed.expMs);
        }
        row = Object.assign({ ok: true, why: '', until: until }, parsed);
      } catch (e) {
        log.debug("Caught in VcStatus.fetchList(): " +
                  ((e && e.message) || e));
        row = { ok: false, why: e.message, until: now() + NEGATIVE_CACHE_MS };
      }
    }
    if (fetched.size >= MAX_FETCHED) {
      fetched.delete(fetched.keys().next().value);
    }
    fetched.set(cacheKey, row);
    log.debug("Leaving VcStatus.fetchList(). " + (row.ok ? "Fetched." :
                                                  row.why));
    return row;
  }

  private async foreignTsl(ref: any, opts: any): Promise<any> {
    const { log, stsCrypto, now } = this.deps;
    log.debug("Entering VcStatus.foreignTsl().");
    const list = await this.fetchList(ref.uri, JWT_TYPE,
      function (body: Buffer): any {
        const verified = stsCrypto.verifyCompactJws(body.toString('ascii'),
          opts.key, { algorithms: opts.algs });
        const read = codec.readStatusListJwtPayload(verified.header,
          verified.claims, { now: Math.floor(now() / 1000) });
        if (read.sub !== ref.uri) {
          throw new Error('the list\'s sub is "' + read.sub + '", not "' +
                          ref.uri + '"');
        }
        return { bits: read.bits, bytes: read.bytes,
                 ttlMs: (read.ttl || 0) * 1000,
                 expMs: read.exp ? read.exp * 1000 : 0 };
      });
    if (!list.ok) {
      log.debug("Leaving VcStatus.foreignTsl(). " + list.why);
      return { ok: false, status: '', detail: 'no statement about its ' +
               'status can be made: the Token Status List "' + ref.uri +
               '" could not be used (' + list.why + ')' };
    }
    let value = -1;
    try {
      value = codec.unpackTslValue(list.bytes, list.bits, ref.idx);
    } catch (e) {
      log.debug("Caught in VcStatus.foreignTsl(): " + ((e && e.message) || e));
      value = -1;
    }
    const name = value < 0 ? 'out of bounds' :
                 (STATUS_NAMES[value] || 'status ' + value);
    log.debug("Leaving VcStatus.foreignTsl(). " + name);
    return { ok: value === VALID, status: name,
             detail: 'the issuer\'s Token Status List says index ' + ref.idx +
                     ' is ' + name };
  }

  private async foreignBitstring(entry: any, opts: any): Promise<any> {
    const { log, stsCrypto, now } = this.deps;
    log.debug("Entering VcStatus.foreignBitstring().");
    let read = null;
    try {
      read = codec.readBitstringEntry(entry);
    } catch (e) {
      log.debug("Caught in VcStatus.foreignBitstring(): " +
                ((e && e.message) || e));
      log.debug("Leaving VcStatus.foreignBitstring(). Malformed.");
      return { ok: false, status: '', detail: 'a credentialStatus entry is ' +
               'malformed: ' + e.message };
    }
    const list = await this.fetchList(read.credential,
      VC_JWT_TYPE, function (body: Buffer): any {
        const verified = stsCrypto.verifyCompactJws(body.toString('ascii'),
          opts.key, { algorithms: opts.algs });
        const vc = verified.claims.vc || verified.claims;
        const subject = vc.credentialSubject || {};
        if (subject.type !== 'BitstringStatusList' ||
            subject.statusPurpose !== read.statusPurpose) {
          throw new Error('the list is not a BitstringStatusList for ' +
                          read.statusPurpose);
        }
        const until = Date.parse(vc.validUntil || '') || 0;
        if (until && until <= now()) {
          throw new Error('the status list credential has expired');
        }
        return { bytes: codec.decodeEncodedList(subject.encodedList),
                 ttlMs: Number(subject.ttl) || 0, expMs: until };
      });
    if (!list.ok) {
      log.debug("Leaving VcStatus.foreignBitstring(). " + list.why);
      return { ok: false, status: '', detail: 'no statement about its ' +
               'status can be made: the ' + read.statusPurpose + ' list "' +
               read.credential + '" could not be used (' +
               list.why + ')' };
    }
    let bit = -1;
    try {
      bit = codec.bitstringValue(list.bytes, read.index);
    } catch (e) {
      log.debug("Caught in VcStatus.foreignBitstring(): " +
                ((e && e.message) || e));
      bit = -1;
    }
    log.debug("Leaving VcStatus.foreignBitstring(). " + bit);
    return { ok: bit === 0,
             status: bit === 0 ? 'VALID' : bit < 0 ? 'out of bounds' :
               (read.statusPurpose === 'suspension' ? 'SUSPENDED' :
                'INVALID'),
             detail: 'the issuer\'s ' + read.statusPurpose + ' list has ' +
                     'index ' + read.index +
                     (bit === 0 ? ' clear' : bit < 0 ? ' out of bounds' :
                      ' set') };
  }

  // Forgets the fetched lists, for the console's cache page and the tests.
  forgetFetched(): number {
    const { log } = this.deps;
    log.debug("Entering VcStatus.forgetFetched().");
    const n = fetched.size;
    fetched.clear();
    log.debug("Leaving VcStatus.forgetFetched(). " + n);
    return n;
  }

  // ---------------------------------------------------------------------------
  // THE ROUTES.
  // ---------------------------------------------------------------------------
  private failed(res: any, e: any): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering VcStatus.failed().");
    log.error(errorCodes.tag('STS-VC-0076') + 'vc_status: a status list ' +
              'could not be served: ' + ((e && (e.stack || e.message)) || e));
    if (!res.headersSent) {
      errorCodes.mark(res, 'STS-VC-0076');
      res.status(500).type('text/plain').send('The status list could not ' +
                                              'be built.\n');
    }
    log.debug("Leaving VcStatus.failed().");
  }

  // `time` (section 8.4) asks for a historical list, which this issuer does
  // not keep: 501, as the draft says a server that does not support it
  // SHOULD answer.
  private historical(req: any, res: any): boolean {
    const { log, errorCodes } = this.deps;
    log.debug("Entering VcStatus.historical().");
    if (req.query && req.query.time !== undefined) {
      errorCodes.mark(res, 'STS-VC-0077');
      res.status(501).type('text/plain').send('This issuer keeps no ' +
        'historical status lists (draft-ietf-oauth-status-list section ' +
        '8.4).\n');
      log.debug("Leaving VcStatus.historical(). Refused.");
      return true;
    }
    log.debug("Leaving VcStatus.historical().");
    return false;
  }

  registerRoutes(app: RouteApp): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering VcStatus.registerRoutes().");
    app.get(TSL_PATH, function (req, res) {
      log.debug('Entering GET ' + TSL_PATH + '.');
      if (self.historical(req, res)) {
        log.debug('Leaving GET ' + TSL_PATH + '. Historical.');
        return;
      }
      const accept = String(req.headers.accept || '');
      const cwt = accept.indexOf(CWT_TYPE) >= 0 &&
        (accept.indexOf(JWT_TYPE) < 0 ||
         accept.indexOf(CWT_TYPE) < accept.indexOf(JWT_TYPE));
      const work = cwt ? self.tslCwt(req) : self.tslJwt(req);
      work.then(function (token: any) {
        res.status(200).set('Content-Type', cwt ? CWT_TYPE : JWT_TYPE)
          .set('Cache-Control', 'max-age=' + self.ttlSeconds())
          .set('Vary', 'Accept')
          .send(token);
        log.debug('Leaving GET ' + TSL_PATH + '.');
      }).catch(function (e: any) {
        log.debug("Caught in VcStatus.registerRoutes(): " +
                  ((e && e.message) || e));
        self.failed(res, e);
      });
    });
    app.get(AGGREGATION_PATH, function (req, res) {
      log.debug('Entering GET ' + AGGREGATION_PATH + '.');
      res.status(200).type('application/json')
        .set('Cache-Control', 'max-age=' + self.ttlSeconds())
        .send(JSON.stringify({
          status_lists: [self.tslUri(self.deps.baseUrlOf(req))] }));
      log.debug('Leaving GET ' + AGGREGATION_PATH + '.');
    });
    app.get(BITSTRING_PATH + '/:purpose', function (req, res) {
      log.debug('Entering GET ' + BITSTRING_PATH + '/:purpose.');
      const purpose = String(req.params.purpose || '');
      if (PURPOSES.indexOf(purpose) < 0) {
        self.deps.errorCodes.mark(res, 'STS-VC-0078');
        res.status(404).type('text/plain').send('This issuer publishes ' +
          'Bitstring Status Lists for ' + PURPOSES.join(' and ') + '.\n');
        log.debug('Leaving GET ' + BITSTRING_PATH + '/:purpose. Unknown.');
        return;
      }
      self.bitstringJwt(req, purpose).then(function (token: string) {
        res.status(200).set('Content-Type', VC_JWT_TYPE)
          .set('Cache-Control', 'max-age=' + self.ttlSeconds())
          .send(token);
        log.debug('Leaving GET ' + BITSTRING_PATH + '/:purpose.');
      }).catch(function (e: any) {
        log.debug("Caught in VcStatus.registerRoutes(): " +
                  ((e && e.message) || e));
        self.failed(res, e);
      });
    });
    log.debug("Leaving VcStatus.registerRoutes().");
  }
}

const slot = new InstanceSlot<VcStatus>(
  'oid4vc/vc_status',
  () => new VcStatus(VcStatus.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  VcStatus: VcStatus,
  installInstance: (instance: VcStatus): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  registerRoutes: slot.forward('registerRoutes'),
  LIST_SIZE: LIST_SIZE,
  TSL_PATH: TSL_PATH,
  AGGREGATION_PATH: AGGREGATION_PATH,
  BITSTRING_PATH: BITSTRING_PATH,
  VALID: VALID,
  INVALID: INVALID,
  SUSPENDED: SUSPENDED,
  STATUS_NAMES: STATUS_NAMES,
  JWT_TYPE: JWT_TYPE,
  CWT_TYPE: CWT_TYPE,
  VC_JWT_TYPE: VC_JWT_TYPE,
  signerAsync: slot.forward('signerAsync'),
  allocate: slot.forward('allocate'),
  attach: slot.forward('attach'),
  statusOf: slot.forward('statusOf'),
  setStatus: slot.forward('setStatus'),
  rows: slot.forward('rows'),
  summary: slot.forward('summary'),
  tslUri: slot.forward('tslUri'),
  bitstringUri: slot.forward('bitstringUri'),
  checkPresented: slot.forward('checkPresented'),
  forgetFetched: slot.forward('forgetFetched')
};
