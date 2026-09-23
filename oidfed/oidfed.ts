'use strict';
//
// File: oidfed.ts
//
// ===========================================================================
// THIS REALM AS AN OPENID FEDERATION ENTITY (OpenID Federation 1.1, #132 and
// #133, 2026-09-23): its Entity Configuration, the federation endpoints of
// section 8, and the acts behind the console page and `/admin-api`.
//
// rcbj's answers on #132 (2026-09-23), which this file is built on:
//
//   1. EVERY ROLE, PER REALM. A realm is a Trust Anchor when it names no
//      superior, an Intermediate when it names one and vouches for somebody,
//      a Leaf otherwise — the role follows from the realm's register rather
//      than from a setting that could contradict it. By default the default
//      realm is a Trust Anchor and every other realm is its Subordinate
//      (`oidfed.realmsAreSubordinates`), so one container is a whole test
//      federation; foreign entities join as registered Subordinates and
//      Trust Anchors.
//   2. TRUST MARKS IN FULL: a realm issues marks of the types it registers,
//      revokes them, answers their status, lists them and hands them out;
//      it carries marks issued TO it; and as a Trust Anchor it says who may
//      issue a type and who owns it.
//   3. A FEDERATION ENTITY KEY OF ITS OWN (`federation_keys.ts`).
//   6. RESOLUTION WALKS ONLY TOWARDS A CONFIGURED TRUST ANCHOR, bounded
//      (`trust_chain.ts` argues the fetches). And the resolve ENDPOINT —
//      which anybody may call — answers only from what is already resolved
//      or what this service is itself (18.1): a walk is started by an
//      administrator's act or, in branch 2, by an automatic registration.
//   8. THE 1.1 TEXT, with 1.0's wire formats where 1.1 did not change them.
//
// ---------------------------------------------------------------------------
// THE ENTITY IDENTIFIER IS THE REALM'S ISSUER.
//
// OpenID Federation for OpenID Connect 1.1 section 5.1.2: the `issuer` of the
// `openid_provider` metadata "MUST match the Federation Entity Identifier".
// So a realm's Entity Identifier is exactly the issuer its discovery
// documents name — `oauth2.ts`'s `issuerOf()` over the realm's base URL,
// which honours a pinned `oauth2.issuer` — and its configuration endpoint is
// that identifier plus `/.well-known/openid-federation`, served per realm
// under the realm's own prefix. The federation ENDPOINTS are under the
// realm's base URL (`/oidfed/…`), which is where its routes are; nothing
// requires them to live under the identifier.
//
// ---------------------------------------------------------------------------
// WHERE THIS MODULE SITS: after `oauth2` (whose metadata the Entity
// Configuration carries) and after the verifier (whose `openid_credential_
// verifier` metadata it carries, and whose #129 stub of this document it
// replaced). Both are reached LAZILY, when a document is built, so the
// require order constrains nothing but the routes.
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
import cacheRegistry = require('../common/cache_registry');
import InstanceSlot = require('../common/instance_slot');
import EntityStatement = require('./entity_statement');
import MetadataPolicy = require('./metadata_policy');
import TrustChain = require('./trust_chain');
import OidfedStore = require('./oidfed_store');
import federationKeys = require('./federation_keys');

type Json = any;
type Req = any;
type Res = any;

const KINDS = OidfedStore.KINDS;
const TYP = EntityStatement.TYP;
const PATHS = Object.freeze({
  configuration: '/.well-known/openid-federation',
  fetch: '/oidfed/fetch',
  list: '/oidfed/list',
  resolve: '/oidfed/resolve',
  trustMark: '/oidfed/trust-mark',
  trustMarkStatus: '/oidfed/trust-mark-status',
  trustMarkList: '/oidfed/trust-mark-list',
  historicalKeys: '/oidfed/historical-keys',
  // Connect 1.1's federation_registration_endpoint (#134).
  register: '/oidfed/register'
});

// Resolutions this process has made, per realm, keyed `<sub> <anchor>`. A
// CACHE and not a register — a chain is re-derivable from its statements,
// and it expires with them (10.4) — so it is per process, unpersisted, and
// described to `/admin/caches`.
const resolutions = realms.map();
const resolutionCount = cacheRegistry.register({
  name: 'oidfed.resolutions',
  title: 'OpenID Federation resolutions',
  description: 'Trust Chains this realm resolved — by an administrator\'s ' +
    'act, or in process for its own realms — with the resolved metadata ' +
    'and the verified Trust Marks, so the resolve endpoint can answer ' +
    'without walking the federation for an unauthenticated caller (18.1).',
  owner: 'oidfed/oidfed.ts',
  scope: 'realm',
  kind: 'cache',
  maxEntries: function (): number {
    return Math.max(1, Number(config.value('oidfed.resolveCacheMax')));
  },
  bound: 'Enforced: oidfed.resolveCacheMax per realm, the oldest evicted ' +
    'first.',
  lifetime: function (): string {
    return 'Until the chain expires (its least exp, 10.4), and at most ' +
      'oidfed.resolveCacheS.';
  },
  eject: cacheRegistry.realmMapEjector(realms, resolutions,
    function (value: Json, key: unknown, now: number): boolean {
      return !value || Number(value.expMs) <= now;
    }),
  entries: function (): unknown[] {
    return cacheRegistry.realmMapRows(realms, resolutions,
      function (value: Json, key: unknown): object {
        return { key: cacheRegistry.digestKey(key),
                 validUntil: Number(value && value.expMs) || 0 };
      });
  }
});

interface OidfedDeps {
  log: typeof helpers.log;
  config: typeof config;
  realms: typeof realms;
  errorCodes: typeof errorCodes;
  baseUrlOf: (req: Req) => string;
  store: typeof OidfedStore;
  keys: typeof federationKeys;
  // Lazily, each: the authorization server, the verifier, the outbound
  // requester, the audit log and the scheduler load around this module.
  oauth2: () => Json;
  verifier: () => Json;
  fedHttp: () => Json;
  audit: () => Json;
  scheduler: () => Json;
  // Client registration through the federation (#134), which reads this
  // module back.
  registration: () => Json;
  relyingParty: () => Json;
  now: () => number;
}

interface Outcome {
  ok: boolean;
  code?: string;
  why?: string;
  error?: string;
  status?: number;
  [key: string]: Json;
}

class Oidfed {
  static readonly PATHS = PATHS;

  constructor(private readonly deps: OidfedDeps) {
    deps.log.debug("Entering Oidfed.constructor().");
    deps.log.debug("Leaving Oidfed.constructor().");
  }

  static defaultDeps(): OidfedDeps {
    helpers.log.debug("Entering Oidfed.defaultDeps().");
    helpers.log.debug("Leaving Oidfed.defaultDeps().");
    return {
      log: helpers.log, config: config, realms: realms,
      errorCodes: errorCodes, baseUrlOf: helpers.baseUrlOf,
      store: OidfedStore, keys: federationKeys,
      oauth2: function (): Json {
        return require('../oauth-oidc/oauth2');
      },
      verifier: function (): Json {
        return require('../oid4vc/vc_verifier');
      },
      fedHttp: function (): Json {
        return require('../federation/federation_http');
      },
      audit: function (): Json {
        return require('../common/audit');
      },
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      },
      registration: function (): Json {
        return require('./oidfed_registration');
      },
      relyingParty: function (): Json {
        return require('./oidfed_rp');
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  private nowSec(): number {
    this.deps.log.debug("Entering Oidfed.nowSec().");
    this.deps.log.debug("Leaving Oidfed.nowSec().");
    return Math.floor(this.deps.now() / 1000);
  }

  private refuse(code: string, why: string, error: string,
                 status: number): Outcome {
    this.deps.log.debug("Entering Oidfed.refuse(). " + code);
    this.deps.log.debug("Leaving Oidfed.refuse().");
    return { ok: false, code: code, why: why, error: error, status: status };
  }

  // ===========================================================================
  // WHO THIS REALM IS, AND WHO IT KNOWS
  // ===========================================================================

  // The realm's Entity Identifier: its issuer (see the header).
  entityId(req: Req): string {
    const { log, oauth2, baseUrlOf } = this.deps;
    log.debug("Entering Oidfed.entityId().");
    const out = String(oauth2().issuerOf(baseUrlOf(req)));
    log.debug("Leaving Oidfed.entityId(). " + out);
    return out;
  }

  // A request as another realm would have received it: the same headers and
  // connection — so the same host, and the same pinned or forwarded base —
  // read inside that realm, whose prefix `baseUrlOf()` then adds.
  private requestIn(req: Req): Req {
    this.deps.log.debug("Entering Oidfed.requestIn().");
    const out = Object.create(req || {});
    out.url = PATHS.configuration;
    out.originalUrl = PATHS.configuration;
    out.params = {};
    out.query = {};
    this.deps.log.debug("Leaving Oidfed.requestIn().");
    return out;
  }

  // Run `fn` inside the realm `realm`, with the request re-read there.
  private inRealm<T>(realm: Json, req: Req, fn: (r: Req) => T): T {
    const { log, realms } = this.deps;
    log.debug("Entering Oidfed.inRealm(). " + realm.id);
    const self = this;
    const out = realms.run(realm, function (): T {
      return fn(self.requestIn(req));
    });
    log.debug("Leaving Oidfed.inRealm().");
    return out;
  }

  // The realm of this service whose Entity Identifier `entityId` is, or null.
  localRealmOf(entityId: string, req: Req): Json {
    const { log, realms } = this.deps;
    log.debug("Entering Oidfed.localRealmOf().");
    const self = this;
    const hit = realms.list().filter(function (realm: Json): boolean {
      return self.inRealm(realm, req, function (r: Req): string {
        return self.entityId(r);
      }) === entityId;
    })[0] || null;
    log.debug("Leaving Oidfed.localRealmOf(). " + (hit ? hit.id : 'none'));
    return hit;
  }

  private implicitTopology(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering Oidfed.implicitTopology().");
    log.debug("Leaving Oidfed.implicitTopology().");
    return config.value('oidfed.realmsAreSubordinates') !== false;
  }

  private defaultRealm(): Json {
    const { log, realms } = this.deps;
    log.debug("Entering Oidfed.defaultRealm().");
    log.debug("Leaving Oidfed.defaultRealm().");
    return realms.get(realms.DEFAULT_ID);
  }

  // The default realm's Entity Identifier, as seen from this request.
  private defaultEntityId(req: Req): string {
    const { log } = this.deps;
    log.debug("Entering Oidfed.defaultEntityId().");
    const self = this;
    const out = this.inRealm(this.defaultRealm(), req, function (r: Req) {
      return self.entityId(r);
    });
    log.debug("Leaving Oidfed.defaultEntityId().");
    return out;
  }

  private isDefaultRealm(): boolean {
    const { log, realms } = this.deps;
    log.debug("Entering Oidfed.isDefaultRealm().");
    log.debug("Leaving Oidfed.isDefaultRealm().");
    return String(realms.current().id) === String(realms.DEFAULT_ID);
  }

  // -------------------------------------------------------------------------
  // THE SUPERIORS THIS REALM NAMES (`authority_hints`, 3.1.2): the ones set in
  // `oidfed.authorityHints`, and — in the default topology, for every realm
  // but the default — the default realm. None makes the realm a Trust Anchor.
  // -------------------------------------------------------------------------
  authorityHints(req: Req): string[] {
    const { log, config } = this.deps;
    log.debug("Entering Oidfed.authorityHints().");
    const out: string[] = [];
    if (this.implicitTopology() && !this.isDefaultRealm()) {
      out.push(this.defaultEntityId(req));
    }
    (config.value('oidfed.authorityHints') || []).forEach(function (v: Json) {
      const hint = String(v).trim();
      if (hint && out.indexOf(hint) < 0) {
        out.push(hint);
      }
    });
    log.debug("Leaving Oidfed.authorityHints(). " + out.length);
    return out;
  }

  // -------------------------------------------------------------------------
  // THE SUBORDINATES THIS REALM VOUCHES FOR: every registered one, and — in
  // the default topology, for the default realm — every other realm, whose
  // keys are read live from that realm rather than pinned, since they are
  // this service's to rotate. Each carries what its Subordinate Statement
  // says about it.
  // -------------------------------------------------------------------------
  subordinates(req: Req): Json[] {
    const { log, store, realms } = this.deps;
    log.debug("Entering Oidfed.subordinates().");
    const self = this;
    const out: Json[] = store.entries(KINDS.SUBORDINATE).map(function (e) {
      return Object.assign({}, e.data || {}, { entityId: e.entityId,
        localRealm: '', createdAt: e.createdAt, updatedAt: e.updatedAt });
    });
    if (this.implicitTopology() && this.isDefaultRealm()) {
      realms.list().filter(function (realm: Json): boolean {
        return String(realm.id) !== String(realms.DEFAULT_ID);
      }).forEach(function (realm: Json): void {
        const id = self.inRealm(realm, req, function (r: Req): string {
          return self.entityId(r);
        });
        if (out.some(function (one: Json): boolean {
          return one.entityId === id;
        })) {
          return;
        }
        out.push({ entityId: id, localRealm: String(realm.id),
                   createdAt: Date.parse(String(realm.createdAt || '')) || 0,
                   updatedAt: 0, implicit: true });
      });
    }
    log.debug("Leaving Oidfed.subordinates(). " + out.length);
    return out;
  }

  // The keys a Subordinate Statement pins for a subordinate: the register's,
  // or a local realm's own federation keys, read inside it.
  private subordinateJwks(sub: Json, req: Req): Json {
    const { log, realms, keys } = this.deps;
    log.debug("Entering Oidfed.subordinateJwks().");
    if (sub.localRealm) {
      const realm = realms.get(sub.localRealm);
      const out = realm ? this.inRealm(realm, req, function (): Json {
        return keys.jwks();
      }) : { keys: [] };
      log.debug("Leaving Oidfed.subordinateJwks(). Local.");
      return out;
    }
    log.debug("Leaving Oidfed.subordinateJwks(). Registered.");
    return sub.jwks || { keys: [] };
  }

  // -------------------------------------------------------------------------
  // THE TRUST ANCHORS THIS REALM TRUSTS: every registered one with its pinned
  // keys; in the default topology, the default realm (for every other realm);
  // and the realm itself when it IS a Trust Anchor, so it can resolve what it
  // vouches for. A local anchor's keys are read live.
  // -------------------------------------------------------------------------
  anchors(req: Req): Json[] {
    const { log, store, keys } = this.deps;
    log.debug("Entering Oidfed.anchors().");
    const self = this;
    const out: Json[] = store.entries(KINDS.ANCHOR).map(function (e) {
      return { entityId: e.entityId, jwks: (e.data || {}).jwks,
               localRealm: '' };
    });
    const add = function (entityId: string, realm: Json): void {
      log.debug("Entering add(). " + entityId);
      if (out.some(function (a: Json): boolean {
        return a.entityId === entityId;
      })) {
        log.debug("Leaving add(). Registered already.");
        return;
      }
      out.push({ entityId: entityId, localRealm: String(realm.id),
                 jwks: self.inRealm(realm, req, function (): Json {
                   return keys.jwks();
                 }) });
      log.debug("Leaving add().");
    };
    if (this.implicitTopology() && !this.isDefaultRealm()) {
      add(this.defaultEntityId(req), this.defaultRealm());
    }
    if (!this.authorityHints(req).length) {
      add(this.entityId(req), this.deps.realms.current());
    }
    log.debug("Leaving Oidfed.anchors(). " + out.length);
    return out;
  }

  // Which role the realm plays, as the page and the API say it.
  roleOf(req: Req): string {
    const { log } = this.deps;
    log.debug("Entering Oidfed.roleOf().");
    const hints = this.authorityHints(req).length;
    const subs = this.subordinates(req).length;
    const out = !hints ? 'trust anchor' : subs ? 'intermediate' : 'leaf';
    log.debug("Leaving Oidfed.roleOf(). " + out);
    return out;
  }

  // ===========================================================================
  // THE ENTITY CONFIGURATION (3, 9)
  // ===========================================================================

  // A metadata object with every `null` or `undefined` member dropped (5:
  // "the use of null is prohibited").
  private withoutNulls(value: Json): Json {
    this.deps.log.debug("Entering Oidfed.withoutNulls().");
    const out: Json = {};
    Object.keys(value || {}).forEach(function (k: string): void {
      if (value[k] !== null && value[k] !== undefined) {
        out[k] = value[k];
      }
    });
    this.deps.log.debug("Leaving Oidfed.withoutNulls().");
    return out;
  }

  // The Trust Mark types this realm issues, from its register.
  markTypes(): Json[] {
    const { log, store } = this.deps;
    log.debug("Entering Oidfed.markTypes().");
    const out = store.entries(KINDS.MARK_TYPE).map(function (e) {
      return Object.assign({}, e.data || {});
    });
    log.debug("Leaving Oidfed.markTypes(). " + out.length);
    return out;
  }

  // The `federation_entity` metadata (5.1.1): the endpoints this realm
  // serves in the roles it plays, and the informational parameters (5.2.2).
  private federationEntity(req: Req): Json {
    const { log, config, baseUrlOf } = this.deps;
    log.debug("Entering Oidfed.federationEntity().");
    const base = baseUrlOf(req);
    const fe: Json = {
      federation_resolve_endpoint: base + PATHS.resolve,
      federation_historical_keys_endpoint: base + PATHS.historicalKeys
    };
    // 5.1.1: Intermediates and Trust Anchors MUST publish fetch and list,
    // and Leaf Entities MUST NOT — "has subordinates" is exactly that line.
    if (this.subordinates(req).length) {
      fe.federation_fetch_endpoint = base + PATHS.fetch;
      fe.federation_list_endpoint = base + PATHS.list;
    }
    if (this.markTypes().length) {
      fe.federation_trust_mark_status_endpoint = base + PATHS.trustMarkStatus;
      fe.federation_trust_mark_list_endpoint = base + PATHS.trustMarkList;
      fe.federation_trust_mark_endpoint = base + PATHS.trustMark;
    }
    const text = function (key: string): string {
      log.debug("Entering text(). " + key);
      log.debug("Leaving text().");
      return String(config.value(key) || '').trim();
    };
    const informational: [string, string][] = [
      ['organization_name', 'oidfed.organizationName'],
      ['logo_uri', 'oidfed.logoUri'], ['policy_uri', 'oidfed.policyUri'],
      ['organization_uri', 'oidfed.organizationUri']];
    informational.forEach(function (pair: [string, string]): void {
      if (text(pair[1])) {
        fe[pair[0]] = text(pair[1]);
      }
    });
    const contacts = (config.value('oidfed.contacts') || [])
      .map(function (c: Json): string {
        return String(c).trim();
      }).filter(Boolean);
    if (contacts.length) {
      fe.contacts = contacts;
    }
    log.debug("Leaving Oidfed.federationEntity().");
    return fe;
  }

  // The protocol entity types (OpenID Federation for OpenID Connect 1.1,
  // 5.1): the realm's OpenID Provider and OAuth authorization server
  // documents, and the OpenID4VP verifier's metadata.
  private protocolMetadata(req: Req): Json {
    const { log, oauth2, verifier } = this.deps;
    log.debug("Entering Oidfed.protocolMetadata().");
    const out: Json = {};
    const self = this;
    const documents = oauth2().federationMetadata(req) || {};
    Object.keys(documents).forEach(function (type: string): void {
      out[type] = self.withoutNulls(documents[type]);
    });
    // CLIENT REGISTRATION THROUGH THE FEDERATION (Connect 1.1, 5.1.2 and 12,
    // #134): the types this realm's OP accepts, and where an Explicit
    // Registration is sent. Beside the OpenID Provider metadata ONLY here —
    // the discovery document is for a client that already registered.
    if (out.openid_provider) {
      const types = this.registrationTypes();
      out.openid_provider.client_registration_types_supported = types;
      if (types.indexOf('explicit') >= 0) {
        out.openid_provider.federation_registration_endpoint =
          this.deps.baseUrlOf(req) + PATHS.register;
      }
      // How an automatic registration proves the RP holds its key (Connect
      // 1.1, 5.1.2, 12.1.1): a request object at either endpoint, or a
      // private_key_jwt at PAR — what oidfed_registration.ts accepts.
      if (types.indexOf('automatic') >= 0) {
        out.openid_provider.request_authentication_methods_supported = {
          authorization_endpoint: ['request_object'],
          pushed_authorization_request_endpoint: ['request_object',
                                                  'private_key_jwt']
        };
        out.openid_provider
          .request_authentication_signing_alg_values_supported =
          EntityStatement.acceptedAlgorithms();
      }
    }
    // THIS REALM AS A RELYING PARTY (#134): published only where a
    // federation relationship discovers its OP through a Trust Chain.
    const rp = this.deps.relyingParty().relyingPartyMetadata(req);
    if (rp) {
      out.openid_relying_party = rp;
    }
    const v = verifier();
    if (v && typeof v.federationVerifierMetadata === 'function') {
      out.openid_credential_verifier =
        this.withoutNulls(v.federationVerifierMetadata(req));
    }
    log.debug("Leaving Oidfed.protocolMetadata(). " +
              Object.keys(out).join(', '));
    return out;
  }

  // The client registration types this realm's OP accepts through the
  // federation (`oidfed.clientRegistrationTypes`, Connect 1.1, 12).
  registrationTypes(): string[] {
    const { log, config } = this.deps;
    log.debug("Entering Oidfed.registrationTypes().");
    const out = (config.value('oidfed.clientRegistrationTypes') || [])
      .map(function (t: Json): string {
        return String(t).trim();
      }).filter(function (t: string): boolean {
        return t === 'automatic' || t === 'explicit';
      });
    log.debug("Leaving Oidfed.registrationTypes(). " + out.join(','));
    return out;
  }

  // The Trust Marks this realm carries (3.1.2): the ones issued TO it, while
  // they have not expired.
  heldMarks(): Json[] {
    const { log, store } = this.deps;
    log.debug("Entering Oidfed.heldMarks().");
    const now = this.nowSec();
    const out = store.entries(KINDS.HELD_MARK).map(function (e) {
      return Object.assign({ id: e.cn }, e.data || {});
    }).filter(function (m: Json): boolean {
      return !(Number(m.exp) > 0 && Number(m.exp) <= now);
    });
    log.debug("Leaving Oidfed.heldMarks(). " + out.length);
    return out;
  }

  // As a Trust Anchor: `trust_mark_issuers` and `trust_mark_owners` (3.1.2),
  // from the realm's mark policies, and every type the realm issues itself
  // (its own issuer) where no policy names the type.
  markPolicyClaims(req: Req): Json {
    const { log, store } = this.deps;
    log.debug("Entering Oidfed.markPolicyClaims().");
    const issuers: Json = {};
    const owners: Json = {};
    store.entries(KINDS.MARK_POLICY).forEach(function (e): void {
      const p = e.data || {};
      issuers[p.type] = Array.isArray(p.issuers) ? p.issuers.slice() : [];
      if (p.owner && p.owner.sub && p.owner.jwks) {
        owners[p.type] = { sub: p.owner.sub, jwks: p.owner.jwks };
      }
    });
    const self = this.entityId(req);
    this.markTypes().forEach(function (t: Json): void {
      if (!issuers[t.type]) {
        issuers[t.type] = [self];
      }
    });
    log.debug("Leaving Oidfed.markPolicyClaims().");
    return { issuers: issuers, owners: owners };
  }

  // -------------------------------------------------------------------------
  // BUILD AND SIGN THE REALM'S ENTITY CONFIGURATION. `{ ok, jwt, claims }`,
  // or `{ ok: false }` when the realm has no key to sign with (a cluster
  // node that lost the race to mint one, until the directory catches up).
  // -------------------------------------------------------------------------
  async configuration(req: Req): Promise<Outcome> {
    const { log, config, keys } = this.deps;
    log.debug("Entering Oidfed.configuration().");
    const signer = await keys.signer();
    if (!signer) {
      log.debug("Leaving Oidfed.configuration(). No key.");
      return this.refuse('STS-OIDFED-0043', 'this realm holds no ' +
                         'Federation Entity Key it can sign with yet.',
                         'temporarily_unavailable', 503);
    }
    const id = this.entityId(req);
    const now = this.nowSec();
    const lifetime = Math.max(60, Number(config.value(
      'oidfed.statementLifetimeS')));
    const metadata = Object.assign({ federation_entity:
                                       this.federationEntity(req) },
                                   this.protocolMetadata(req));
    const claims: Json = { iss: id, sub: id, iat: now, exp: now + lifetime,
                           jwks: keys.jwks(), metadata: metadata };
    const hints = this.authorityHints(req);
    if (hints.length) {
      claims.authority_hints = hints;
    } else {
      const policy = this.markPolicyClaims(req);
      if (Object.keys(policy.issuers).length) {
        claims.trust_mark_issuers = policy.issuers;
      }
      if (Object.keys(policy.owners).length) {
        claims.trust_mark_owners = policy.owners;
      }
    }
    const marks = this.heldMarks().filter(function (m: Json): boolean {
      return m.sub === id;
    }).map(function (m: Json): Json {
      return { trust_mark_type: m.type, trust_mark: m.jwt };
    });
    if (marks.length) {
      claims.trust_marks = marks;
    }
    const jwt = EntityStatement.sign(claims, TYP.ENTITY_STATEMENT, signer);
    log.debug("Leaving Oidfed.configuration(). " + id);
    return { ok: true, jwt: jwt, claims: claims };
  }

  // -------------------------------------------------------------------------
  // THE SUBORDINATE STATEMENT ABOUT `sub` (3.1.3, 8.1.2): its keys, and the
  // metadata, policy and constraints the register holds for it.
  // -------------------------------------------------------------------------
  async subordinateStatement(req: Req, subId: string): Promise<Outcome> {
    const { log, config, keys, baseUrlOf } = this.deps;
    log.debug("Entering Oidfed.subordinateStatement(). " + subId);
    const id = this.entityId(req);
    if (!subId) {
      log.debug("Leaving Oidfed.subordinateStatement(). No sub.");
      return this.refuse('STS-OIDFED-0032', 'the sub parameter is ' +
                         'required (8.1.1).', 'invalid_request', 400);
    }
    if (subId === id) {
      log.debug("Leaving Oidfed.subordinateStatement(). Itself.");
      return this.refuse('STS-OIDFED-0032', 'sub names this entity ' +
                         'itself, which is no subordinate of its own ' +
                         '(8.1.2).', 'invalid_request', 400);
    }
    const sub = this.subordinates(req).filter(function (s: Json): boolean {
      return s.entityId === subId;
    })[0];
    if (!sub) {
      log.debug("Leaving Oidfed.subordinateStatement(). Not ours.");
      return this.refuse('STS-OIDFED-0033', subId + ' is not a subordinate ' +
                         'of this entity.', 'not_found', 404);
    }
    const signer = await keys.signer();
    if (!signer) {
      log.debug("Leaving Oidfed.subordinateStatement(). No key.");
      return this.refuse('STS-OIDFED-0043', 'this realm holds no ' +
                         'Federation Entity Key it can sign with yet.',
                         'temporarily_unavailable', 503);
    }
    const now = this.nowSec();
    const lifetime = Math.max(60, Number(config.value(
      'oidfed.statementLifetimeS')));
    const claims: Json = { iss: id, sub: subId, iat: now, exp: now + lifetime,
                           jwks: this.subordinateJwks(sub, req),
                           source_endpoint: baseUrlOf(req) + PATHS.fetch };
    ['metadata', 'metadata_policy', 'metadata_policy_crit',
     'constraints'].forEach(function (name: string): void {
      const held = sub[name === 'metadata_policy' ? 'metadataPolicy'
                     : name === 'metadata_policy_crit' ? 'metadataPolicyCrit'
                     : name];
      if (held !== undefined && held !== null &&
          !(typeof held === 'object' && !Object.keys(held).length)) {
        claims[name] = held;
      }
    });
    const jwt = EntityStatement.sign(claims, TYP.ENTITY_STATEMENT, signer);
    log.debug("Leaving Oidfed.subordinateStatement().");
    return { ok: true, jwt: jwt, claims: claims };
  }

  // ===========================================================================
  // RESOLUTION (10, 8.3)
  // ===========================================================================

  // The entity `entityId` as this process answers for it: a realm of this
  // service, whose statements are built in process (never fetched).
  private localEntity(entityId: string, req: Req): Json {
    const { log } = this.deps;
    log.debug("Entering Oidfed.localEntity().");
    const realm = this.localRealmOf(entityId, req);
    if (!realm) {
      log.debug("Leaving Oidfed.localEntity(). Not local.");
      return null;
    }
    const self = this;
    log.debug("Leaving Oidfed.localEntity(). " + realm.id);
    return {
      configuration: function (): Promise<string> {
        return self.inRealm(realm, req, function (r: Req) {
          return self.configuration(r);
        }).then(function (out: Outcome): string {
          return out.ok ? String(out.jwt) : '';
        });
      },
      subordinateStatement: function (sub: string): Promise<string | null> {
        return self.inRealm(realm, req, function (r: Req) {
          return self.subordinateStatement(r, sub);
        }).then(function (out: Outcome): string | null {
          return out.ok ? String(out.jwt) : null;
        });
      }
    };
  }

  // -------------------------------------------------------------------------
  // A TRUST CHAIN RESOLVER for this request. `discover` lets it FETCH from
  // other entities — an administrator's act, never an unauthenticated
  // resolve request (18.1); without it every entity outside this service is
  // refused before a request is made.
  // -------------------------------------------------------------------------
  chainResolver(req: Req, discover: boolean): TrustChain {
    const { log, config, fedHttp } = this.deps;
    log.debug("Entering Oidfed.chainResolver(). discover=" + discover);
    const self = this;
    const tc = new TrustChain({
      log: log,
      nowSec: function (): number {
        return self.nowSec();
      },
      skewSec: function (): number {
        return Math.max(0, Number(config.value('oidfed.clockSkewS')));
      },
      limits: function (): Json {
        return {
          maxHints: Math.max(1, Number(config.value(
            'oidfed.maxAuthorityHints'))),
          maxDepth: Math.max(2, Number(config.value('oidfed.maxChainDepth'))),
          maxFetches: Math.max(1, Number(config.value(
            'oidfed.maxFetchesPerResolution')))
        };
      },
      local: function (entityId: string): Json {
        return self.localEntity(entityId, req);
      },
      fetch: function (url: string, accept: string): Promise<Json> {
        if (!discover) {
          return Promise.resolve({ ok: false, status: 0, body: '',
            contentType: '', why: 'this resolution may not fetch from ' +
              'other entities (an unauthenticated resolve answers only ' +
              'from what is already resolved, 18.1)' });
        }
        return fedHttp().fetchPublished(url, {
          accept: accept,
          timeoutMs: Math.max(100, Number(config.value(
            'oidfed.fetchTimeoutMs'))),
          maxBytes: Math.max(1024, Number(config.value(
            'oidfed.fetchMaxBytes')))
        }).then(function (answer: Json): Json {
          return { ok: answer.ok, status: answer.status,
                   body: answer.body ? answer.body.toString('utf8') : '',
                   contentType: answer.contentType, why: answer.why };
        });
      }
    });
    log.debug("Leaving Oidfed.chainResolver().");
    return tc;
  }

  // The Trust Marks of a resolved subject that the anchor's federation trusts
  // (7.3, 8.3.2): each issuer established through its own chain to the SAME
  // anchor first, then the mark validated against its keys — and, where this
  // realm issued it, its revocation read from the register.
  private async verifiedMarks(resolved: Json, tc: TrustChain,
                              anchor: Json, req: Req): Promise<Json[]> {
    const { log } = this.deps;
    log.debug("Entering Oidfed.verifiedMarks().");
    const subject = resolved.chain[0];
    const marks = Array.isArray(subject.trust_marks) ? subject.trust_marks
                                                     : [];
    if (!marks.length) {
      log.debug("Leaving Oidfed.verifiedMarks(). None presented.");
      return [];
    }
    const last = resolved.chain[resolved.chain.length - 1];
    let anchorClaims = last.iss === last.sub ? last : null;
    if (!anchorClaims) {
      const ec = await tc.configurationOf(anchor.entityId,
        { seen: {}, fetches: 0, exhausted: false, problems: [] });
      anchorClaims = ec.ok ? ec.claims : {};
    }
    const out: Json[] = [];
    const selfId = this.entityId(req);
    for (let i = 0; i < marks.length; i++) {
      const read = EntityStatement.decode(marks[i].trust_mark);
      if (!read.ok) {
        continue;
      }
      const issuer = read.claims.iss;
      let issuerJwks: Json = null;
      if (issuer === anchor.entityId) {
        issuerJwks = anchor.jwks;
      } else {
        const chain = await tc.resolve(issuer, [anchor]);
        if (chain.ok && chain.chain!.length > 1) {
          issuerJwks = chain.chain![1].jwks;
        }
      }
      if (!issuerJwks) {
        continue;
      }
      const valid = tc.validateTrustMark(marks[i].trust_mark, subject.sub,
                                         anchorClaims, issuerJwks, true);
      if (!valid.ok) {
        log.debug("Oidfed.verifiedMarks(): " + valid.why);
        continue;
      }
      if (issuer === selfId && this.markStatusOf(marks[i].trust_mark) !==
                                 'active') {
        continue;
      }
      out.push({ trust_mark_type: marks[i].trust_mark_type,
                 trust_mark: marks[i].trust_mark,
                 exp: Number.isFinite(read.claims.exp) ? read.claims.exp
                                                       : undefined });
    }
    log.debug("Leaving Oidfed.verifiedMarks(). " + out.length);
    return out;
  }

  // -------------------------------------------------------------------------
  // RESOLVE `sub` TO ONE OF `anchorIds` (the realm's anchors when empty):
  // from the cache while the chain lives, otherwise by walking — in process
  // only, unless `discover`. Caches what it resolves. `{ ok, resolved,
  // marks, anchor }` or a refusal in the section 8.9 vocabulary.
  // -------------------------------------------------------------------------
  async resolve(req: Req, sub: string, anchorIds: string[],
                discover: boolean): Promise<Outcome> {
    const { log, config, now } = this.deps;
    log.debug("Entering Oidfed.resolve(). " + sub);
    const configured = this.anchors(req);
    const wanted = anchorIds.length ? configured.filter(function (a: Json) {
      return anchorIds.indexOf(a.entityId) >= 0;
    }) : configured;
    if (!wanted.length) {
      log.debug("Leaving Oidfed.resolve(). No such anchor.");
      return this.refuse('STS-OIDFED-0035', 'none of ' +
                         (anchorIds.join(', ') || 'the anchors') + ' is a ' +
                         'Trust Anchor this realm is configured with.',
                         'invalid_trust_anchor', 404);
    }
    const map = resolutions;
    const at = now();
    for (let i = 0; i < wanted.length; i++) {
      const hit = map.get(sub + ' ' + wanted[i].entityId);
      if (hit && Number(hit.expMs) > at) {
        resolutionCount.hit();
        log.debug("Leaving Oidfed.resolve(). From the cache.");
        return { ok: true, resolved: hit.resolved, marks: hit.marks,
                 anchor: hit.anchor };
      }
    }
    resolutionCount.miss();
    const tc = this.chainResolver(req, discover);
    const resolved: Json = await tc.resolve(sub, wanted);
    if (!resolved.ok) {
      log.debug("Leaving Oidfed.resolve(). " + resolved.why);
      const notFetched = !discover && !this.localRealmOf(sub, req);
      return this.refuse(notFetched ? 'STS-OIDFED-0036' :
                         (resolved.code || 'STS-OIDFED-0027'),
                         notFetched ? sub + ' has not been resolved by this ' +
                           'entity, and an unauthenticated resolve request ' +
                           'does not start one (18.1). ' + resolved.why
                         : String(resolved.why),
                         notFetched ? 'not_found' : String(resolved.error ||
                                                    'invalid_trust_chain'),
                         notFetched ? 404 : 400);
    }
    const anchor = wanted.filter(function (a: Json): boolean {
      return a.entityId === resolved.anchor;
    })[0];
    const marks = await this.verifiedMarks(resolved, tc, anchor, req);
    const capMs = Math.max(0, Number(config.value('oidfed.resolveCacheS'))) *
                  1000;
    const expMs = Math.min(Number(resolved.exp) * 1000, at + capMs);
    if (expMs > at) {
      cacheRegistry.makeRoom(map, Math.max(1, Number(config.value(
        'oidfed.resolveCacheMax'))), { counter: resolutionCount,
                                       expired: function (v: Json): boolean {
                                         return Number(v && v.expMs) <= at;
                                       } });
      map.set(sub + ' ' + resolved.anchor, { resolved: resolved,
        marks: marks, anchor: anchor, expMs: expMs });
    }
    log.debug("Leaving Oidfed.resolve(). " + resolved.chain.length +
              " statements.");
    return { ok: true, resolved: resolved, marks: marks, anchor: anchor };
  }

  // The resolve response (8.3.2), signed.
  async resolveResponse(req: Req, sub: string, anchorIds: string[],
                        entityTypes: string[]): Promise<Outcome> {
    const { log, keys } = this.deps;
    log.debug("Entering Oidfed.resolveResponse(). " + sub);
    const got = await this.resolve(req, sub, anchorIds, false);
    if (!got.ok) {
      log.debug("Leaving Oidfed.resolveResponse(). Unresolved.");
      return got;
    }
    const signer = await keys.signer();
    if (!signer) {
      log.debug("Leaving Oidfed.resolveResponse(). No key.");
      return this.refuse('STS-OIDFED-0043', 'this realm holds no ' +
                         'Federation Entity Key it can sign with yet.',
                         'temporarily_unavailable', 503);
    }
    const metadata: Json = {};
    Object.keys(got.resolved.metadata || {}).forEach(function (type) {
      if (!entityTypes.length || entityTypes.indexOf(type) >= 0) {
        metadata[type] = got.resolved.metadata[type];
      }
    });
    const exp = got.marks.reduce(function (min: number, m: Json): number {
      return Number.isFinite(m.exp) ? Math.min(min, m.exp) : min;
    }, Number(got.resolved.exp));
    const claims: Json = { iss: this.entityId(req), sub: sub,
                           iat: this.nowSec(), exp: exp, metadata: metadata,
                           trust_chain: got.resolved.jwts };
    if (got.marks.length) {
      claims.trust_marks = got.marks.map(function (m: Json): Json {
        return { trust_mark_type: m.trust_mark_type,
                 trust_mark: m.trust_mark };
      });
    }
    const jwt = EntityStatement.sign(claims, TYP.RESOLVE_RESPONSE, signer);
    log.debug("Leaving Oidfed.resolveResponse().");
    return { ok: true, jwt: jwt, claims: claims };
  }

  // ===========================================================================
  // TRUST MARKS THIS REALM ISSUES (7, 8.4 - 8.6)
  // ===========================================================================

  private issuedMarks(): Json[] {
    const { log, store } = this.deps;
    log.debug("Entering Oidfed.issuedMarks().");
    const out = store.entries(KINDS.ISSUED_MARK).map(function (e) {
      return Object.assign({ id: e.cn }, e.data || {});
    });
    log.debug("Leaving Oidfed.issuedMarks(). " + out.length);
    return out;
  }

  // The status of a mark this realm issued (8.4.2): active, expired, revoked
  // — or '' when this realm did not issue it (a 404, 8.4.2).
  markStatusOf(jwt: string): string {
    const { log, store } = this.deps;
    log.debug("Entering Oidfed.markStatusOf().");
    const held = store.get(KINDS.ISSUED_MARK, String(jwt || ''));
    if (!held || !held.data || held.data.jwt !== jwt) {
      log.debug("Leaving Oidfed.markStatusOf(). Not ours.");
      return '';
    }
    const d = held.data;
    const out = d.revokedAt ? 'revoked'
      : (Number(d.exp) > 0 && Number(d.exp) <= this.nowSec()) ? 'expired'
      : 'active';
    log.debug("Leaving Oidfed.markStatusOf(). " + out);
    return out;
  }

  // The marks of `type` this realm issued that are still valid, optionally
  // for one subject.
  validIssued(type: string, sub?: string): Json[] {
    const { log } = this.deps;
    log.debug("Entering Oidfed.validIssued(). " + type);
    const now = this.nowSec();
    const out = this.issuedMarks().filter(function (m: Json): boolean {
      return (!type || m.type === type) && (!sub || m.sub === sub) &&
             !m.revokedAt && !(Number(m.exp) > 0 && Number(m.exp) <= now);
    });
    log.debug("Leaving Oidfed.validIssued(). " + out.length);
    return out;
  }

  // The status response (8.4.2), signed.
  async markStatusResponse(req: Req, jwt: string): Promise<Outcome> {
    const { log, keys } = this.deps;
    log.debug("Entering Oidfed.markStatusResponse().");
    if (!jwt) {
      log.debug("Leaving Oidfed.markStatusResponse(). No mark.");
      return this.refuse('STS-OIDFED-0037', 'the trust_mark parameter is ' +
                         'required (8.4.1).', 'invalid_request', 400);
    }
    const status = this.markStatusOf(jwt);
    if (!status) {
      log.debug("Leaving Oidfed.markStatusResponse(). Unknown.");
      return this.refuse('STS-OIDFED-0039', 'this entity did not issue ' +
                         'that Trust Mark (8.4.2).', 'not_found', 404);
    }
    const signer = await keys.signer();
    if (!signer) {
      log.debug("Leaving Oidfed.markStatusResponse(). No key.");
      return this.refuse('STS-OIDFED-0043', 'this realm holds no ' +
                         'Federation Entity Key it can sign with yet.',
                         'temporarily_unavailable', 503);
    }
    const out = EntityStatement.sign({ iss: this.entityId(req),
                                       iat: this.nowSec(), trust_mark: jwt,
                                       status: status },
                                     TYP.TRUST_MARK_STATUS, signer);
    log.debug("Leaving Oidfed.markStatusResponse(). " + status);
    return { ok: true, jwt: out, markStatus: status };
  }

  // The historical keys (8.7.2), signed.
  async historicalKeysResponse(req: Req): Promise<Outcome> {
    const { log, keys } = this.deps;
    log.debug("Entering Oidfed.historicalKeysResponse().");
    const signer = await keys.signer();
    if (!signer) {
      log.debug("Leaving Oidfed.historicalKeysResponse(). No key.");
      return this.refuse('STS-OIDFED-0043', 'this realm holds no ' +
                         'Federation Entity Key it can sign with yet.',
                         'temporarily_unavailable', 503);
    }
    const out = EntityStatement.sign({ iss: this.entityId(req),
                                       iat: this.nowSec(),
                                       keys: keys.historical() },
                                     TYP.JWK_SET, signer);
    log.debug("Leaving Oidfed.historicalKeysResponse().");
    return { ok: true, jwt: out };
  }

  // -------------------------------------------------------------------------
  // THE SUBORDINATE LISTING (8.2): the Immediate Subordinates, filtered by
  // entity type (every one named must be held), by a still-valid mark this
  // realm issued (of a type, or any), and by being an Intermediate. A
  // subordinate's entity types are the register's for a registered one, and
  // read off its configuration for a realm of this service.
  // -------------------------------------------------------------------------
  async listing(req: Req, query: Json): Promise<Outcome> {
    const { log } = this.deps;
    log.debug("Entering Oidfed.listing().");
    const bool = function (v: Json): boolean | null | undefined {
      log.debug("Entering bool().");
      if (v === undefined) {
        log.debug("Leaving bool(). Absent.");
        return undefined;
      }
      log.debug("Leaving bool().");
      return v === 'true' ? true : v === 'false' ? false : null;
    };
    const trustMarked = bool(query.trust_marked);
    const intermediate = bool(query.intermediate);
    if (trustMarked === null || intermediate === null) {
      log.debug("Leaving Oidfed.listing(). A boolean that is not one.");
      return this.refuse('STS-OIDFED-0044', 'trust_marked and intermediate ' +
                         'are true or false (8.2.1).', 'invalid_request', 400);
    }
    const types: string[] = [].concat(query.entity_type || [])
      .map(String).filter(Boolean);
    const markType = query.trust_mark_type ? String(query.trust_mark_type)
                                           : '';
    const self = this;
    const subs = this.subordinates(req);
    const out: string[] = [];
    for (let i = 0; i < subs.length; i++) {
      const s = subs[i];
      let held: string[] = Array.isArray(s.entityTypes) ? s.entityTypes : [];
      let isIntermediate = !!s.intermediate;
      if (s.localRealm) {
        const realm = this.deps.realms.get(s.localRealm);
        const ec: Outcome = realm ? await this.inRealm(realm, req,
          function (r: Req) {
            return self.configuration(r);
          }) : { ok: false };
        held = ec.ok ? Object.keys(ec.claims.metadata || {}) : [];
        isIntermediate = !!(ec.ok && ec.claims.metadata.federation_entity &&
          ec.claims.metadata.federation_entity.federation_fetch_endpoint);
      }
      if (types.length && !types.every(function (t: string): boolean {
        return held.indexOf(t) >= 0;
      })) {
        continue;
      }
      if (intermediate !== undefined && isIntermediate !== intermediate) {
        continue;
      }
      if ((trustMarked === true || markType) &&
          !this.validIssued(markType, s.entityId).length) {
        continue;
      }
      out.push(s.entityId);
    }
    log.debug("Leaving Oidfed.listing(). " + out.length);
    return { ok: true, list: out };
  }

  // ===========================================================================
  // THE ROUTES (8, 9)
  // ===========================================================================

  private sendError(res: Res, out: Outcome): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Oidfed.sendError(). " + out.code);
    // error-code: none — the refusal's own code, held in `out.code`
    errorCodes.mark(res, String(out.code || 'STS-OIDFED-0050'));
    res.status(out.status || 400).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify({ error: out.error || 'invalid_request',
                              error_description: String(out.why || '') }));
    log.debug("Leaving Oidfed.sendError().");
  }

  // A typed JWT, as its media type with NO parameters (15: "No parameters
  // are used with this media type") — sent as bytes, because Express's
  // send() of a string appends `; charset=utf-8` to any type it is given.
  private sendJwt(res: Res, type: string, jwt: string): void {
    this.deps.log.debug("Entering Oidfed.sendJwt(). " + type);
    res.status(200).set('Content-Type', 'application/' + type)
       .set('Cache-Control', 'no-store').send(Buffer.from(jwt, 'ascii'));
    this.deps.log.debug("Leaving Oidfed.sendJwt().");
  }

  // One endpoint's handler, with the unexpected failure answered as 8.9's
  // server_error rather than Express's HTML page.
  private endpoint(name: string,
                   body: (req: Req, res: Res) => Promise<void>) {
    const { log, errorCodes } = this.deps;
    const self = this;
    return function (req: Req, res: Res): void {
      log.debug("Entering the OpenID Federation " + name + " endpoint.");
      body(req, res).catch(function (e: any): void {
        log.error(errorCodes.tag('STS-OIDFED-0050') + 'oidfed: the ' + name +
                  ' endpoint failed: ' + ((e && e.stack) || e));
        self.sendError(res, { ok: false, code: 'STS-OIDFED-0050',
                              why: 'the ' + name + ' endpoint failed.',
                              error: 'server_error', status: 500 });
      });
      log.debug("Leaving the OpenID Federation " + name + " endpoint.");
    };
  }

  registerRoutes(app: Json): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Oidfed.registerRoutes().");
    app.get(PATHS.configuration, this.endpoint('configuration',
      async function (req: Req, res: Res): Promise<void> {
        const out = await self.configuration(req);
        if (!out.ok) {
          self.sendError(res, out);
          return;
        }
        self.sendJwt(res, 'entity-statement+jwt', String(out.jwt));
      }));
    app.get(PATHS.fetch, this.endpoint('fetch',
      async function (req: Req, res: Res): Promise<void> {
        const out = await self.subordinateStatement(req,
          String(req.query.sub || ''));
        if (!out.ok) {
          self.sendError(res, out);
          return;
        }
        self.sendJwt(res, 'entity-statement+jwt', String(out.jwt));
      }));
    app.get(PATHS.list, this.endpoint('list',
      async function (req: Req, res: Res): Promise<void> {
        const out = await self.listing(req, req.query || {});
        if (!out.ok) {
          self.sendError(res, out);
          return;
        }
        res.status(200).type('application/json')
           .set('Cache-Control', 'no-store').send(JSON.stringify(out.list));
      }));
    app.get(PATHS.resolve, this.endpoint('resolve',
      async function (req: Req, res: Res): Promise<void> {
        const q = req.query || {};
        const anchors: string[] = [].concat(q.trust_anchor || [])
          .map(String).filter(Boolean);
        if (!q.sub || !anchors.length) {
          self.sendError(res, self.refuse('STS-OIDFED-0034', 'sub and ' +
            'trust_anchor are required (8.3.1).', 'invalid_request', 400));
          return;
        }
        const types: string[] = [].concat(q.entity_type || []).map(String)
          .filter(Boolean);
        const out = await self.resolveResponse(req, String(q.sub), anchors,
                                               types);
        if (!out.ok) {
          self.sendError(res, out);
          return;
        }
        self.sendJwt(res, 'resolve-response+jwt', String(out.jwt));
      }));
    app.get(PATHS.trustMark, this.endpoint('trust mark',
      async function (req: Req, res: Res): Promise<void> {
        const q = req.query || {};
        if (!q.trust_mark_type || !q.sub) {
          self.sendError(res, self.refuse('STS-OIDFED-0037',
            'trust_mark_type and sub are required (8.6.1).',
            'invalid_request', 400));
          return;
        }
        const held = self.validIssued(String(q.trust_mark_type),
                                      String(q.sub));
        if (!held.length) {
          self.sendError(res, self.refuse('STS-OIDFED-0038', String(q.sub) +
            ' holds no valid Trust Mark of that type from this entity ' +
            '(8.6.2).', 'not_found', 404));
          return;
        }
        held.sort(function (a: Json, b: Json): number {
          return Number(b.iat) - Number(a.iat);
        });
        self.sendJwt(res, 'trust-mark+jwt', String(held[0].jwt));
      }));
    app.post(PATHS.trustMarkStatus, this.endpoint('trust mark status',
      async function (req: Req, res: Res): Promise<void> {
        const body = helpers.parseBody(req) || {};
        const out = await self.markStatusResponse(req,
          String(body.trust_mark || ''));
        if (!out.ok) {
          self.sendError(res, out);
          return;
        }
        self.sendJwt(res, 'trust-mark-status-response+jwt', String(out.jwt));
      }));
    app.get(PATHS.trustMarkList, this.endpoint('trust mark list',
      async function (req: Req, res: Res): Promise<void> {
        const q = req.query || {};
        if (!q.trust_mark_type) {
          self.sendError(res, self.refuse('STS-OIDFED-0037',
            'trust_mark_type is required (8.5.1).', 'invalid_request', 400));
          return;
        }
        const list = self.validIssued(String(q.trust_mark_type),
                                      q.sub ? String(q.sub) : undefined)
          .map(function (m: Json): string {
            return m.sub;
          }).filter(function (sub: string, i: number, all: string[]) {
            return all.indexOf(sub) === i;
          });
        res.status(200).type('application/json')
           .set('Cache-Control', 'no-store').send(JSON.stringify(list));
      }));
    app.get(PATHS.historicalKeys, this.endpoint('historical keys',
      async function (req: Req, res: Res): Promise<void> {
        const out = await self.historicalKeysResponse(req);
        if (!out.ok) {
          self.sendError(res, out);
          return;
        }
        self.sendJwt(res, 'jwk-set+jwt', String(out.jwt));
      }));
    // Explicit Registration (OpenID Federation for OpenID Connect 1.1,
    // 12.2, #134): the body is the RP's Entity Configuration or a Trust
    // Chain, which app.js's text parser hands over as the string sent.
    app.post(PATHS.register, this.endpoint('registration',
      async function (req: Req, res: Res): Promise<void> {
        const out = await self.deps.registration().explicit(req,
          String(req.get('content-type') || ''),
          typeof req.body === 'string' ? req.body : '');
        if (!out.ok) {
          self.sendError(res, { ok: false, code: out.code,
                                why: out.description, error: out.error,
                                status: out.status });
          return;
        }
        self.sendJwt(res, 'explicit-registration-response+jwt',
                     String(out.jwt));
      }));
    log.debug("Leaving Oidfed.registerRoutes().");
  }

  // ===========================================================================
  // THE ACTS (the console page and /admin-api, rule 7)
  // ===========================================================================

  // A JSON field of a form or an API body: an object as given, or text
  // parsed; undefined when absent or empty.
  private jsonField(v: Json): Json {
    this.deps.log.debug("Entering Oidfed.jsonField().");
    if (v === undefined || v === null || v === '') {
      this.deps.log.debug("Leaving Oidfed.jsonField(). Absent.");
      return undefined;
    }
    if (typeof v === 'object') {
      this.deps.log.debug("Leaving Oidfed.jsonField(). An object.");
      return v;
    }
    const out = JSON.parse(String(v));
    this.deps.log.debug("Leaving Oidfed.jsonField(). Parsed.");
    return out;
  }

  private list(v: Json): string[] {
    this.deps.log.debug("Entering Oidfed.list().");
    const out = (Array.isArray(v) ? v : String(v || '').split(/[\s,]+/))
      .map(function (one: Json): string {
        return String(one).trim();
      }).filter(Boolean);
    this.deps.log.debug("Leaving Oidfed.list(). " + out.length);
    return out;
  }

  private audited(ctx: Json, action: string, target: string,
                  summary: string, errorCode?: string): void {
    const { log, realms } = this.deps;
    log.debug("Entering Oidfed.audited(). " + action);
    try {
      this.deps.audit().record({
        category: 'admin', action: action,
        actor: String((ctx && ctx.actor) || ''), target: target,
        outcome: errorCode ? 'refused' : 'success',
        errorCode: errorCode || '',
        summary: summary + ' (realm "' + String(realms.current().id) + '", ' +
                 'via ' + String((ctx && ctx.via) || 'console') + ').' });
    } catch (e: any) {
      log.debug("Caught in Oidfed.audited(): " + ((e && e.message) || e));
    }
    log.debug("Leaving Oidfed.audited().");
  }

  private refused(code: string, message: string): Outcome {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Oidfed.refused(). " + code);
    log.debug("Leaving Oidfed.refused().");
    // error-code: none — the caller's code, handed in as `code`
    return errorCodes.mark({ ok: false, errors: [message] }, code);
  }

  // The keys of an entity: as given, or — `fetchJwks` — read from its own
  // Entity Configuration, verified by itself (the administrator is the one
  // vouching for them, which is what registering it means). A realm of this
  // service is read in process.
  private async jwksFor(entityId: string, given: Json, fetch: boolean,
                        req: Req): Promise<Outcome> {
    const { log } = this.deps;
    log.debug("Entering Oidfed.jwksFor(). " + entityId);
    if (!fetch) {
      const problem = EntityStatement.jwksProblem(given);
      log.debug("Leaving Oidfed.jwksFor(). Given: " + (problem || 'fine'));
      return problem ? { ok: false, why: 'jwks ' + problem + '.' }
                     : { ok: true, jwks: given };
    }
    const tc = this.chainResolver(req, true);
    const ec = await tc.configurationOf(entityId,
      { seen: {}, fetches: 0, exhausted: false, problems: [] });
    log.debug("Leaving Oidfed.jwksFor(). Fetched: " + ec.ok);
    return ec.ok ? { ok: true, jwks: ec.claims.jwks, claims: ec.claims }
                 : { ok: false, why: String(ec.why) };
  }

  // -------------------------------------------------------------------------
  // ONE ACT. `body.action` names it; `ctx` is `{ via, actor, req }`.
  // Resolves `{ ok, message, … }` or `{ ok: false, errors }` carrying its
  // error code.
  // -------------------------------------------------------------------------
  async act(body: Json, ctx: Json): Promise<Outcome> {
    const { log, store, keys, scheduler, realms } = this.deps;
    const b = body || {};
    const req = ctx && ctx.req;
    const action = String(b.action || '');
    log.debug("Entering Oidfed.act(). " + action);
    const self = this;
    const bad = function (why: string): Outcome {
      log.debug("Entering bad().");
      self.audited(ctx, 'oidfed.act-refused', action, why,
                   'STS-OIDFED-0045');
      log.debug("Leaving bad().");
      return self.refused('STS-OIDFED-0045', why);
    };
    let json: Json;
    try {
      json = {
        jwks: this.jsonField(b.jwks),
        metadata: this.jsonField(b.metadata),
        metadataPolicy: this.jsonField(b.metadataPolicy),
        constraints: this.jsonField(b.constraints),
        ownerJwks: this.jsonField(b.ownerJwks)
      };
    } catch (e: any) {
      log.debug("Caught in Oidfed.act(): " + ((e && e.message) || e));
      log.debug("Leaving Oidfed.act(). Unreadable JSON.");
      return bad('a JSON field could not be read: ' + ((e && e.message) || e));
    }
    const entityId = String(b.entityId || b.sub || '').trim();
    if (action === 'add-subordinate' || action === 'add-trust-anchor') {
      if (!EntityStatement.isEntityId(entityId)) {
        log.debug("Leaving Oidfed.act(). Not an entity id.");
        return bad('"' + entityId + '" is not an Entity Identifier (an ' +
                   'https URL with no query or fragment).');
      }
      if (entityId === this.entityId(req)) {
        log.debug("Leaving Oidfed.act(). Itself.");
        return bad('an entity is neither its own subordinate nor its own ' +
                   'anchor.');
      }
      const got = await this.jwksFor(entityId, json.jwks,
        b.fetchJwks === true || b.fetchJwks === 'true' || b.fetchJwks === 'on',
        req);
      if (!got.ok) {
        log.debug("Leaving Oidfed.act(). No keys.");
        this.audited(ctx, 'oidfed.act-refused', entityId, String(got.why),
                     'STS-OIDFED-0049');
        return this.refused('STS-OIDFED-0049', 'the keys of ' + entityId +
                            ': ' + got.why);
      }
      if (action === 'add-trust-anchor') {
        store.put(KINDS.ANCHOR, entityId, entityId, { jwks: got.jwks });
        this.forgetResolutions();
        this.audited(ctx, 'oidfed.anchor-set', entityId,
                     'Trust Anchor ' + entityId + ' configured');
        log.debug("Leaving Oidfed.act(). An anchor.");
        return { ok: true, message: entityId + ' is a Trust Anchor of this ' +
                 'realm.', jwks: got.jwks };
      }
      const record: Json = { jwks: got.jwks };
      if (json.metadata !== undefined) {
        const problem = EntityStatement.metadataProblem(json.metadata);
        if (problem) {
          return bad(problem + '.');
        }
        record.metadata = json.metadata;
      }
      const crit = this.list(b.metadataPolicyCrit);
      if (json.metadataPolicy !== undefined) {
        const valid = MetadataPolicy.validate(json.metadataPolicy, crit);
        if (!valid.ok) {
          return bad(String(valid.why));
        }
        record.metadataPolicy = json.metadataPolicy;
      }
      if (crit.length) {
        if (crit.some(function (op: string): boolean {
          return MetadataPolicy.OPERATORS.indexOf(op) >= 0;
        })) {
          return bad('metadata_policy_crit names additional operators, ' +
                     'never the standard seven (3.1.3).');
        }
        record.metadataPolicyCrit = crit;
      }
      if (json.constraints !== undefined) {
        const problem = MetadataPolicy.constraintsProblem(json.constraints);
        if (problem) {
          return bad(problem + '.');
        }
        record.constraints = json.constraints;
      }
      record.entityTypes = this.list(b.entityTypes);
      if (!record.entityTypes.length && got.claims) {
        record.entityTypes = Object.keys(got.claims.metadata || {});
      }
      record.intermediate = b.intermediate === true ||
        b.intermediate === 'true' || b.intermediate === 'on';
      store.put(KINDS.SUBORDINATE, entityId, entityId, record);
      this.forgetResolutions();
      this.audited(ctx, 'oidfed.subordinate-set', entityId,
                   entityId + ' registered as a subordinate');
      log.debug("Leaving Oidfed.act(). A subordinate.");
      return { ok: true, message: entityId + ' is a subordinate of this ' +
               'realm.', subordinate: Object.assign({ entityId: entityId },
                                                    record) };
    }
    if (action === 'remove-subordinate' || action === 'remove-trust-anchor') {
      const kind = action === 'remove-subordinate' ? KINDS.SUBORDINATE
                                                   : KINDS.ANCHOR;
      if (!store.remove(kind, entityId)) {
        log.debug("Leaving Oidfed.act(). Nothing to remove.");
        return this.refused('STS-OIDFED-0046', 'this realm has no ' +
                            (kind === KINDS.ANCHOR ? 'Trust Anchor '
                                                   : 'subordinate ') +
                            entityId + '.');
      }
      this.forgetResolutions();
      this.audited(ctx, kind === KINDS.ANCHOR ? 'oidfed.anchor-removed'
                                              : 'oidfed.subordinate-removed',
                   entityId, entityId + ' removed');
      log.debug("Leaving Oidfed.act(). Removed.");
      return { ok: true, message: entityId + ' was removed.' };
    }
    if (action === 'add-mark-type') {
      const type = String(b.type || '').trim();
      if (!/^https:\/\//.test(type)) {
        return bad('a Trust Mark type identifier is a URL naming the ' +
                   'federation or framework (7.1): https://…');
      }
      const lifetimeS = b.lifetimeS === undefined || b.lifetimeS === ''
        ? Number(this.deps.config.value('oidfed.trustMarkLifetimeS'))
        : Number(b.lifetimeS);
      if (!Number.isInteger(lifetimeS) || lifetimeS < 60) {
        return bad('lifetimeS is a whole number of seconds, at least 60.');
      }
      const record: Json = { type: type, lifetimeS: lifetimeS };
      ['logoUri', 'ref'].forEach(function (k: string): void {
        if (b[k]) {
          record[k] = String(b[k]).trim();
        }
      });
      if (b.delegation) {
        const read = EntityStatement.decode(String(b.delegation).trim());
        if (!read.ok || read.header.typ !== TYP.TRUST_MARK_DELEGATION ||
            read.claims.trust_mark_type !== type ||
            read.claims.sub !== this.entityId(req)) {
          return bad('the delegation must be a trust-mark-delegation+jwt ' +
                     'for this type, delegating to this entity (7.2.1).');
        }
        record.delegation = String(b.delegation).trim();
      }
      store.put(KINDS.MARK_TYPE, type, '', record);
      this.audited(ctx, 'oidfed.mark-type-set', type,
                   'Trust Mark type ' + type + ' registered');
      log.debug("Leaving Oidfed.act(). A mark type.");
      return { ok: true, message: 'This realm issues ' + type + '.',
               markType: record };
    }
    if (action === 'remove-mark-type' || action === 'remove-mark-policy') {
      const type = String(b.type || '').trim();
      const kind = action === 'remove-mark-type' ? KINDS.MARK_TYPE
                                                 : KINDS.MARK_POLICY;
      if (!store.remove(kind, type)) {
        return this.refused('STS-OIDFED-0046', 'nothing is registered for ' +
                            type + '.');
      }
      this.audited(ctx, 'oidfed.' + action, type, type + ' removed');
      log.debug("Leaving Oidfed.act(). Removed " + kind + ".");
      return { ok: true, message: type + ' was removed.' };
    }
    if (action === 'set-mark-policy') {
      const type = String(b.type || '').trim();
      if (!type) {
        return bad('type is required.');
      }
      const issuers = this.list(b.issuers);
      if (!issuers.every(EntityStatement.isEntityId)) {
        return bad('issuers are Entity Identifiers.');
      }
      const record: Json = { type: type, issuers: issuers };
      const ownerSub = String(b.ownerSub || '').trim();
      if (ownerSub || json.ownerJwks) {
        const problem = EntityStatement.jwksProblem(json.ownerJwks);
        if (!EntityStatement.isEntityId(ownerSub) || problem) {
          return bad('an owner is an Entity Identifier with a JWK Set (' +
                     (problem || 'the sub is not one') + ').');
        }
        record.owner = { sub: ownerSub, jwks: json.ownerJwks };
      }
      store.put(KINDS.MARK_POLICY, type, '', record);
      this.forgetResolutions();
      this.audited(ctx, 'oidfed.mark-policy-set', type,
                   'the policy for ' + type + ' set');
      log.debug("Leaving Oidfed.act(). A mark policy.");
      return { ok: true, message: 'The policy for ' + type + ' is set.',
               markPolicy: record };
    }
    if (action === 'issue-trust-mark') {
      const type = String(b.type || '').trim();
      const markType = this.markTypes().filter(function (t: Json): boolean {
        return t.type === type;
      })[0];
      if (!markType) {
        return this.refused('STS-OIDFED-0047', 'this realm does not issue ' +
                            'Trust Marks of the type "' + type + '".');
      }
      if (!EntityStatement.isEntityId(entityId)) {
        return bad('sub is not an Entity Identifier.');
      }
      const signer = await keys.signer();
      if (!signer) {
        return this.refused('STS-OIDFED-0043', 'this realm holds no ' +
                            'Federation Entity Key it can sign with yet.');
      }
      const iat = this.nowSec();
      const claims: Json = { iss: this.entityId(req), sub: entityId,
                             trust_mark_type: type, iat: iat,
                             exp: iat + Number(markType.lifetimeS) };
      if (markType.logoUri) {
        claims.logo_uri = markType.logoUri;
      }
      if (markType.ref) {
        claims.ref = markType.ref;
      }
      if (markType.delegation) {
        claims.delegation = markType.delegation;
      }
      const jwt = EntityStatement.sign(claims, TYP.TRUST_MARK, signer);
      store.put(KINDS.ISSUED_MARK, jwt, entityId, { jwt: jwt, type: type,
        sub: entityId, iat: iat, exp: claims.exp, revokedAt: 0,
        revokedReason: '' });
      // A MARK FOR A REALM OF THIS SERVICE is also handed to it, so its
      // Entity Configuration carries it at once (3.1.2) — what a foreign
      // subject does by fetching it from the Trust Mark endpoint.
      const local = this.localRealmOf(entityId, req);
      if (local) {
        realms.run(local, function (): void {
          store.put(KINDS.HELD_MARK, jwt, claims.iss, { jwt: jwt, type: type,
            sub: entityId, iss: claims.iss, exp: claims.exp });
        });
      }
      this.forgetResolutions();
      this.audited(ctx, 'oidfed.mark-issued', entityId,
                   'Trust Mark ' + type + ' issued to ' + entityId);
      log.debug("Leaving Oidfed.act(). A mark issued.");
      return { ok: true, message: 'A Trust Mark of ' + type + ' was issued ' +
               'to ' + entityId + (local ? ' and handed to its realm.' : '.'),
               trustMark: jwt, id: OidfedStore.cnOf(KINDS.ISSUED_MARK, jwt) };
    }
    if (action === 'revoke-trust-mark') {
      const id = String(b.id || '').trim();
      const held = this.issuedMarks().filter(function (m: Json): boolean {
        return m.id === id;
      })[0];
      if (!held) {
        return this.refused('STS-OIDFED-0046', 'this realm issued no Trust ' +
                            'Mark "' + id + '".');
      }
      held.revokedAt = this.nowSec();
      held.revokedReason = String(b.reason || 'unspecified');
      store.put(KINDS.ISSUED_MARK, held.jwt, held.sub, { jwt: held.jwt,
        type: held.type, sub: held.sub, iat: held.iat, exp: held.exp,
        revokedAt: held.revokedAt, revokedReason: held.revokedReason });
      this.forgetResolutions();
      this.audited(ctx, 'oidfed.mark-revoked', held.sub, 'Trust Mark ' +
                   held.type + ' of ' + held.sub + ' revoked');
      log.debug("Leaving Oidfed.act(). A mark revoked.");
      return { ok: true, message: 'The Trust Mark was revoked; its status ' +
               'is now "revoked" (8.4).' };
    }
    if (action === 'add-held-mark') {
      const jwt = String(b.trustMark || '').trim();
      const read = EntityStatement.decode(jwt);
      const self2 = this.entityId(req);
      if (!read.ok || read.header.typ !== TYP.TRUST_MARK ||
          read.claims.sub !== self2 ||
          typeof read.claims.trust_mark_type !== 'string' ||
          !EntityStatement.isEntityId(read.claims.iss)) {
        this.audited(ctx, 'oidfed.held-mark-added', '', 'refused',
                     'STS-OIDFED-0048');
        return this.refused('STS-OIDFED-0048', 'a Trust Mark this realm ' +
                            'carries is a trust-mark+jwt issued TO it (sub ' +
                            '= ' + self2 + ').');
      }
      store.put(KINDS.HELD_MARK, jwt, read.claims.iss, { jwt: jwt,
        type: read.claims.trust_mark_type, sub: read.claims.sub,
        iss: read.claims.iss, exp: read.claims.exp });
      this.audited(ctx, 'oidfed.held-mark-added', read.claims.iss,
                   'a Trust Mark of ' + read.claims.trust_mark_type +
                   ' from ' + read.claims.iss + ' carried');
      log.debug("Leaving Oidfed.act(). A mark held.");
      return { ok: true, message: 'This realm\'s Entity Configuration ' +
               'carries the mark.' };
    }
    if (action === 'remove-held-mark') {
      const id = String(b.id || '').trim();
      const held = this.heldMarks().filter(function (m: Json): boolean {
        return m.id === id;
      })[0];
      if (!held || !store.remove(KINDS.HELD_MARK, held.jwt)) {
        return this.refused('STS-OIDFED-0046', 'this realm carries no Trust ' +
                            'Mark "' + id + '".');
      }
      this.audited(ctx, 'oidfed.held-mark-removed', held.iss || '',
                   'a carried Trust Mark removed');
      log.debug("Leaving Oidfed.act(). A held mark removed.");
      return { ok: true, message: 'The mark is no longer carried.' };
    }
    if (action === 'resolve') {
      if (!EntityStatement.isEntityId(entityId)) {
        return bad('sub is not an Entity Identifier.');
      }
      const anchorIds = this.list(b.trustAnchor);
      this.forgetResolution(entityId);
      const got = await this.resolve(req, entityId, anchorIds, true);
      this.audited(ctx, 'oidfed.resolved', entityId, got.ok
        ? entityId + ' resolved to ' + got.resolved.anchor
        : entityId + ' did not resolve: ' + got.why,
                   got.ok ? '' : got.code);
      if (!got.ok) {
        log.debug("Leaving Oidfed.act(). Unresolved.");
        return this.refused(String(got.code || 'STS-OIDFED-0027'),
                            String(got.why));
      }
      log.debug("Leaving Oidfed.act(). Resolved.");
      return { ok: true, message: entityId + ' resolved to ' +
               got.resolved.anchor + ' through ' + got.resolved.chain.length +
               ' statements.', resolution: this.resolutionView(got) };
    }
    if (action === 'rotate-key') {
      const emergency = b.emergency === true || b.emergency === 'true' ||
                        b.emergency === 'on';
      if (emergency && String(b.confirm || '') !== 'compromised') {
        return bad('an emergency rotation revokes the current and next keys ' +
                   'as compromised; confirm it by sending confirm: ' +
                   '"compromised".');
      }
      const answer = scheduler().requestRun(federationKeys.ROTATE_NOW_JOB, {
        realm: String(realms.current().id || ''),
        params: { emergency: emergency, reason: emergency ? 'emergency'
                                                          : 'by hand' },
        requestedBy: String((ctx && ctx.actor) || ''),
        via: String((ctx && ctx.via) || 'console'),
        channel: String((ctx && ctx.via) || 'console') });
      if (!answer.ok) {
        return this.refused(String(answer.errorCode || 'STS-OIDFED-0045'),
                            String(answer.why));
      }
      log.debug("Leaving Oidfed.act(). A rotation queued.");
      return { ok: true, message: 'The rotation is queued as run ' +
               answer.runId + ' of ' + federationKeys.ROTATE_NOW_JOB + '.',
               runId: answer.runId };
    }
    if (action === 'revoke-key') {
      const answer = keys.revoke(String(b.kid || ''), String(b.reason || ''));
      if (!answer.ok) {
        return this.refused(String(answer.code), String(answer.why));
      }
      this.audited(ctx, 'oidfed.key-revoked', String(b.kid),
                   'Federation Entity Key ' + b.kid + ' revoked: ' +
                   answer.reason);
      log.debug("Leaving Oidfed.act(). A key revoked.");
      return { ok: true, message: 'The key ' + b.kid + ' is revoked (' +
               answer.reason + ').' };
    }
    log.debug("Leaving Oidfed.act(). Unknown action.");
    return this.refused('STS-OIDFED-0046', '"' + action + '" is not an ' +
                        'OpenID Federation action.');
  }

  // Drop the cached resolutions of the realm — its register changed, so a
  // chain resolved before may no longer be the one it would resolve now.
  private forgetResolutions(): void {
    this.deps.log.debug("Entering Oidfed.forgetResolutions().");
    const keysNow: string[] = [];
    resolutions.forEach(function (v: Json, k: string): void {
      keysNow.push(k);
    });
    keysNow.forEach(function (k: string): void {
      resolutions.delete(k);
    });
    this.deps.log.debug("Leaving Oidfed.forgetResolutions().");
  }

  private forgetResolution(sub: string): void {
    this.deps.log.debug("Entering Oidfed.forgetResolution().");
    const keysNow: string[] = [];
    resolutions.forEach(function (v: Json, k: string): void {
      if (k.indexOf(sub + ' ') === 0) {
        keysNow.push(k);
      }
    });
    keysNow.forEach(function (k: string): void {
      resolutions.delete(k);
    });
    this.deps.log.debug("Leaving Oidfed.forgetResolution().");
  }

  // A resolution as a page or the API shows it.
  resolutionView(got: Json): Json {
    this.deps.log.debug("Entering Oidfed.resolutionView().");
    const r = got.resolved;
    this.deps.log.debug("Leaving Oidfed.resolutionView().");
    return {
      subject: r.subject, anchor: r.anchor,
      expiresAt: new Date(Number(r.exp) * 1000).toISOString(),
      chain: r.chain.map(function (c: Json): Json {
        return { iss: c.iss, sub: c.sub, exp: c.exp };
      }),
      metadata: r.metadata,
      trustMarks: (got.marks || []).map(function (m: Json): Json {
        return m.trust_mark_type;
      })
    };
  }

  // -------------------------------------------------------------------------
  // THE VIEW: everything the console page draws and GET /admin-api/oidfed
  // answers, from one call (rule 7). Never a private key.
  // -------------------------------------------------------------------------
  async view(req: Req): Promise<Json> {
    const { log, keys, baseUrlOf, config } = this.deps;
    log.debug("Entering Oidfed.view().");
    const base = baseUrlOf(req);
    const ec = await this.configuration(req);
    const self = this;
    const iso = function (ms: Json): string | null {
      log.debug("Entering iso().");
      log.debug("Leaving iso().");
      return Number(ms) > 0 ? new Date(Number(ms)).toISOString() : null;
    };
    const cached: Json[] = [];
    resolutions.forEach(function (v: Json): void {
      cached.push(self.resolutionView(v));
    });
    const out = {
      entityId: this.entityId(req),
      role: this.roleOf(req),
      configurationUrl: EntityStatement.configurationUrlOf(
        this.entityId(req)),
      endpoints: Object.keys(PATHS).reduce(function (acc: Json, k: string) {
        acc[k] = k === 'configuration'
          ? EntityStatement.configurationUrlOf(self.entityId(req))
          : base + (PATHS as Json)[k];
        return acc;
      }, {}),
      authorityHints: this.authorityHints(req),
      realmsAreSubordinates: this.implicitTopology(),
      signingAlg: keys.algorithm(),
      keys: keys.view(),
      subordinates: this.subordinates(req).map(function (s: Json): Json {
        return { entityId: s.entityId, localRealm: s.localRealm || null,
                 implicit: !!s.implicit, entityTypes: s.entityTypes || [],
                 intermediate: !!s.intermediate,
                 metadataPolicy: s.metadataPolicy || null,
                 constraints: s.constraints || null,
                 createdAt: iso(s.createdAt), updatedAt: iso(s.updatedAt),
                 kids: ((s.jwks && s.jwks.keys) || []).map(function (k: Json) {
                   return k.kid;
                 }) };
      }),
      trustAnchors: this.anchors(req).map(function (a: Json): Json {
        return { entityId: a.entityId, localRealm: a.localRealm || null,
                 kids: ((a.jwks && a.jwks.keys) || []).map(function (k: Json) {
                   return k.kid;
                 }) };
      }),
      markTypes: this.markTypes(),
      markPolicies: this.deps.store.entries(KINDS.MARK_POLICY)
        .map(function (e): Json {
          return { type: (e.data || {}).type, issuers: (e.data || {}).issuers,
                   owner: (e.data || {}).owner ? (e.data || {}).owner.sub
                                                : null };
        }),
      issuedMarks: this.issuedMarks().map(function (m: Json): Json {
        return { id: m.id, type: m.type, sub: m.sub,
                 issuedAt: iso(Number(m.iat) * 1000),
                 expiresAt: iso(Number(m.exp) * 1000),
                 status: self.markStatusOf(m.jwt),
                 revokedReason: m.revokedReason || null };
      }),
      heldMarks: this.heldMarks().map(function (m: Json): Json {
        return { id: m.id, type: m.type, iss: m.iss,
                 expiresAt: iso(Number(m.exp) * 1000) };
      }),
      resolutions: cached,
      entityConfiguration: ec.ok ? ec.claims : null,
      entityConfigurationProblem: ec.ok ? null : ec.why,
      statementLifetimeS: Number(config.value('oidfed.statementLifetimeS'))
    };
    log.debug("Leaving Oidfed.view().");
    return out;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<Oidfed>(
  'oidfed/oidfed',
  () => new Oidfed(Oidfed.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  Oidfed: Oidfed,
  installInstance: (instance: Oidfed): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  PATHS: PATHS,
  registerRoutes: slot.forward('registerRoutes'),
  entityId: slot.forward('entityId'),
  registrationTypes: slot.forward('registrationTypes'),
  configuration: slot.forward('configuration'),
  subordinateStatement: slot.forward('subordinateStatement'),
  resolve: slot.forward('resolve'),
  resolveResponse: slot.forward('resolveResponse'),
  chainResolver: slot.forward('chainResolver'),
  anchors: slot.forward('anchors'),
  subordinates: slot.forward('subordinates'),
  authorityHints: slot.forward('authorityHints'),
  roleOf: slot.forward('roleOf'),
  markStatusOf: slot.forward('markStatusOf'),
  markStatusResponse: slot.forward('markStatusResponse'),
  historicalKeysResponse: slot.forward('historicalKeysResponse'),
  listing: slot.forward('listing'),
  view: slot.forward('view'),
  act: slot.forward('act')
};
