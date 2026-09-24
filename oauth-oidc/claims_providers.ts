'use strict';
//
// File: claims_providers.ts
//
// ===========================================================================
// OPENID CONNECT CLAIMS AGGREGATION (#147, 2026-09-24): AGGREGATED AND
// DISTRIBUTED CLAIMS (OpenID Connect Core 1.0 section 5.6.2, and the Claims
// Aggregation draft), IN BOTH DIRECTIONS.
//
// rcbj's answers on #147, every one the recommendation:
//
//   1. BOTH SIDES. This service as an OpenID Provider that fetches claims
//      from registered CLAIMS PROVIDERS for a person who linked one and hands
//      them to a relying party as aggregated or distributed claims; AND
//      `federation/federation_sp.ts` consuming `_claim_sources` from an
//      upstream OP, each source verified against its provider's keys.
//   2. AGGREGATED OR DISTRIBUTED is a setting of each provider, aggregated by
//      default.
//   3. A PERSON'S TOKENS AT A PROVIDER are sealed on the person's own
//      directory entry, one JSON value (`stsClaimSourceTokens`), withheld from
//      every read — the directory replicates and dies with the person.
//   4. THE SETUP PHASE is the person's: "Connected claim sources" on the
//      portal runs an authorization code flow (PKCE) to the provider, and an
//      unlink; an administrator sees and revokes links on the console and
//      `/admin-api`.
//   5. THE LATEST TEXT, with Core 5.6.2 — no shims.
//
// ---------------------------------------------------------------------------
// THE REGISTER is `ou=claimproviders` in the realm's own directory tree
// (`ldap/ldap_server.js`), one `stsClaimProvider` entry per provider, its
// record one JSON value and its client secret a second attribute, sealed where
// keys persist and withheld from reads. The directory rather than a map, for
// `oidfed/oidfed_store.ts`'s reason: it is a REGISTER an administrator
// writes, and the directory is the store every backend persists and every
// node shares.
//
// EVERY URL DIALLED IS ONE AN ADMINISTRATOR CONFIGURED on a provider — its
// authorization, token, claims (UserInfo) and JWKS endpoints — through
// `federation_http.requestConfigured()`, which keeps the outbound kill switch,
// the URL policy (https only in product) and the outbound TLS policy. A
// relying party's request names claims, never a URL; and on the consuming
// side a source is honoured only when it names a provider THIS REALM
// REGISTERED, so nothing in a foreign token chooses where this service dials
// (the root `CLAUDE.md`'s index of what is dialled).
//
// ---------------------------------------------------------------------------
// WHEN A SOURCE IS SENT. A relying party asks with OIDC Core 5.5's `claims`
// request — the `id_token` member for the ID Token, `userinfo` for UserInfo.
// A requested claim that the person's own entry does not answer, and that a
// provider the person linked declares (`claims`), is referenced to that
// provider: `_claim_names` maps it to the provider's id, and
// `_claim_sources[<id>]` carries
//
//   aggregated    { "JWT": <the provider's signed UserInfo response> }, fetched
//                 now with the person's access token and VERIFIED against the
//                 provider's keys, its `iss` the provider's and its `sub` the
//                 subject recorded at linking — and only the names that JWT
//                 actually carries are referenced;
//   distributed   { "endpoint": <the provider's claims endpoint>,
//                   "access_token": <the person's token at that provider> },
//                 which hands the relying party a credential of the person's
//                 at another party. That is what the provider's setting says
//                 the operator chose, and why aggregated is the default.
//
// A value the entry holds is never replaced by a source: Core 5.6 has a claim
// either normal or referenced, and this service's own directory is the one it
// vouches for. Scope-default claims are never referenced — a source is sent
// only when a relying party ASKED for a claim a provider declares.
//
// A PROVIDER THAT FAILS leaves its claims out, with a log line naming it; the
// ID Token and UserInfo are answered all the same (5.5.1: a claim that cannot
// be supplied is omitted).
//
// ---------------------------------------------------------------------------
// TOKEN LIFETIME. An expired access token is refreshed where it is needed,
// once, and the `oauth2.claim-sources-refresh` job (#49) refreshes every token
// within five minutes of expiring and drops setup flows older than ten.
// A token that cannot be refreshed stays on the entry marked `stale` and is
// never sent; the person links again.
// ===========================================================================

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
import stsCrypto = require('../common/crypto');
import credentials = require('../common/credentials');

type Json = any;
type Req = any;

const REFRESH_JOB = 'oauth2.claim-sources-refresh';
const FLOW_TTL_MS = 10 * 60 * 1000;
const REFRESH_AHEAD_MS = 5 * 60 * 1000;
const DELIVERY = Object.freeze(['aggregated', 'distributed']);
const AUTH_METHODS = Object.freeze(['client_secret_basic',
                                    'client_secret_post', 'none']);
// The portal path the provider sends the person back to.
const CALLBACK_PATH = '/portal/claim-sources/callback';
const ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,39}$/;
const JWT_PATTERN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;

// Setup flows in progress: state -> { username, provider, verifier, at }.
// PERSISTED: the provider may send the person back to another node.
const flows = realms.map({ persist: 'oauth2.claimSourceFlows',
                           retain: 'age' });

interface Provider {
  id: string;
  name: string;
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  claimsEndpoint: string;
  jwksUri: string;
  clientId: string;
  authMethod: string;
  scope: string;
  claims: string[];
  delivery: string;
  createdAt: number;
  updatedAt: number;
}

interface Link {
  access_token: string;
  refresh_token?: string;
  expires_at?: number;
  sub: string;
  linked_at: number;
  stale?: boolean;
}

interface ClaimsProvidersDeps {
  log: typeof helpers.log;
  config: typeof config;
  errorCodes: typeof errorCodes;
  // Lazily: these load around this module.
  http: () => Json;
  keystore: () => Json;
  scheduler: () => Json;
  audit: () => Json;
  now: () => number;
}

class ClaimsProviders {
  static readonly REFRESH_JOB = REFRESH_JOB;
  static readonly CALLBACK_PATH = CALLBACK_PATH;
  static readonly DELIVERY = DELIVERY;
  static readonly AUTH_METHODS = AUTH_METHODS;

  constructor(private readonly deps: ClaimsProvidersDeps) {
    deps.log.debug("Entering ClaimsProviders.constructor().");
    deps.log.debug("Leaving ClaimsProviders.constructor().");
  }

  static defaultDeps(): ClaimsProvidersDeps {
    helpers.log.debug("Entering ClaimsProviders.defaultDeps().");
    helpers.log.debug("Leaving ClaimsProviders.defaultDeps().");
    return {
      log: helpers.log, config: config, errorCodes: errorCodes,
      http: function (): Json {
        return require('../federation/federation_http');
      },
      keystore: function (): Json {
        return require('../common/keystore');
      },
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      },
      audit: function (): Json {
        return require('../common/audit');
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  private store(operation: string, args: any[]): Json {
    return credentials.claimsAggregationStore(operation, args);
  }

  // ===========================================================================
  // SEALING: `keystore.seal()` where keys outlive the process, and the value
  // as written where they do not — development's key is regenerated at every
  // start, so a sealed value would be unreadable after it (the rule
  // `common/person_assertions.js` argues). Either way the attribute is
  // withheld from every directory read.
  // ===========================================================================
  private seal(plain: string, label: string): string | null {
    const { log, keystore } = this.deps;
    log.debug("Entering ClaimsProviders.seal(). " + label);
    const ks = keystore();
    if (!ks.persists()) {
      log.debug("Leaving ClaimsProviders.seal(). Keys do not persist.");
      return plain;
    }
    const sealed = ks.seal(plain, label);
    log.debug("Leaving ClaimsProviders.seal(). " + (sealed ? 'Sealed.' :
                                                             'No key.'));
    return sealed || null;
  }

  private open(stored: string, label: string): string {
    const { log, keystore } = this.deps;
    log.debug("Entering ClaimsProviders.open(). " + label);
    if (!/^\$aesgcm\$/.test(String(stored || ''))) {
      log.debug("Leaving ClaimsProviders.open(). Not sealed.");
      return String(stored || '');
    }
    const opened = keystore().open(String(stored), label);
    log.debug("Leaving ClaimsProviders.open(). " + (opened !== null ?
                                                    'Opened.' : 'Unopenable.'));
    return opened === null || opened === undefined ? '' : String(opened);
  }

  // ===========================================================================
  // THE REGISTER.
  // ===========================================================================
  private readEntry(stored: Json): Provider | null {
    const { log } = this.deps;
    log.debug("Entering ClaimsProviders.readEntry().");
    const a = stored.attributes || {};
    const raw = String((a.stsclaimproviderdata || [])[0] || '');
    let record: Json = null;
    try {
      record = JSON.parse(raw);
    } catch (e: any) {
      log.debug("Caught in ClaimsProviders.readEntry(): " +
                ((e && e.message) || e));
      // An entry an ldapmodify left unreadable is not a provider.
      record = null;
    }
    log.debug("Leaving ClaimsProviders.readEntry().");
    return record && record.id ? record as Provider : null;
  }

  list(): Provider[] {
    const { log } = this.deps;
    log.debug("Entering ClaimsProviders.list().");
    const self = this;
    const out = (this.store('listClaimProviderEntries', []) || [])
      .map(function (stored: Json): Provider | null {
        return self.readEntry(stored);
      }).filter(Boolean) as Provider[];
    out.sort(function (a: Provider, b: Provider): number {
      return a.id < b.id ? -1 : (a.id > b.id ? 1 : 0);
    });
    log.debug("Leaving ClaimsProviders.list(). " + out.length + ".");
    return out;
  }

  get(id: string): Provider | null {
    const { log } = this.deps;
    log.debug("Entering ClaimsProviders.get(). " + id);
    const found = this.list().filter(function (p: Provider): boolean {
      return p.id === String(id || '');
    })[0] || null;
    log.debug("Leaving ClaimsProviders.get(). " + (found ? 'Found.' :
                                                           'Not here.'));
    return found;
  }

  // The provider whose issuer is `issuer`, for the consuming side.
  byIssuer(issuer: string): Provider | null {
    const { log } = this.deps;
    log.debug("Entering ClaimsProviders.byIssuer().");
    const found = this.list().filter(function (p: Provider): boolean {
      return p.issuer === String(issuer || '');
    })[0] || null;
    log.debug("Leaving ClaimsProviders.byIssuer().");
    return found;
  }

  private secretOf(id: string): string {
    const { log } = this.deps;
    log.debug("Entering ClaimsProviders.secretOf().");
    const stored = (this.store('listClaimProviderEntries', []) || [])
      .filter(function (e: Json): boolean {
        return String(((e.attributes || {}).cn || [])[0] || '') === id;
      })[0];
    const raw = stored ? String(((stored.attributes || {})
      .stsclaimprovidersecret || [])[0] || '') : '';
    log.debug("Leaving ClaimsProviders.secretOf().");
    return raw ? this.open(raw, 'claims-provider-secret') : '';
  }

  // What is wrong with a provider as submitted, or ''.
  problemOf(p: Json): string {
    const { log, http } = this.deps;
    log.debug("Entering ClaimsProviders.problemOf().");
    const urls = ['authorizationEndpoint', 'tokenEndpoint', 'claimsEndpoint',
                  'jwksUri'];
    let problem = '';
    if (!ID_PATTERN.test(String(p.id || ''))) {
      problem = 'the id must be 1 to 40 lower-case letters, digits and ' +
                'hyphens, starting with a letter or digit';
    } else if (!/^https?:\/\/\S+$/.test(String(p.issuer || ''))) {
      problem = 'the issuer must be an http(s) URL';
    } else if (!String(p.clientId || '')) {
      problem = 'a client_id at the provider is required';
    } else if (AUTH_METHODS.indexOf(String(p.authMethod)) < 0) {
      problem = 'the client authentication method must be one of ' +
                AUTH_METHODS.join(', ');
    } else if (DELIVERY.indexOf(String(p.delivery)) < 0) {
      problem = 'delivery must be aggregated or distributed';
    } else if (!Array.isArray(p.claims) || !p.claims.length) {
      problem = 'name at least one claim the provider supplies';
    } else {
      for (const name of urls) {
        const why = http().urlProblem(String(p[name] || ''));
        if (why) {
          problem = name + ': ' + why;
          break;
        }
      }
    }
    log.debug("Leaving ClaimsProviders.problemOf(). " + (problem || 'None.'));
    return problem;
  }

  // Writes a provider; `secret` undefined keeps the one held. Returns '' or
  // why it was not written.
  save(p: Json, secret?: string): string {
    const { log, now } = this.deps;
    log.debug("Entering ClaimsProviders.save(). " + p.id);
    const existing = this.get(String(p.id || ''));
    const record: Provider = {
      id: String(p.id || ''), name: String(p.name || p.id || ''),
      issuer: String(p.issuer || ''),
      authorizationEndpoint: String(p.authorizationEndpoint || ''),
      tokenEndpoint: String(p.tokenEndpoint || ''),
      claimsEndpoint: String(p.claimsEndpoint || ''),
      jwksUri: String(p.jwksUri || ''),
      clientId: String(p.clientId || ''),
      authMethod: String(p.authMethod || 'client_secret_basic'),
      scope: String(p.scope || 'openid'),
      claims: (Array.isArray(p.claims) ? p.claims :
               String(p.claims || '').split(/[\s,]+/))
        .map(function (c: Json): string {
          return String(c).trim();
        }).filter(Boolean),
      delivery: String(p.delivery || 'aggregated'),
      createdAt: existing ? existing.createdAt : now(),
      updatedAt: now()
    };
    const problem = this.problemOf(record);
    if (problem) {
      log.debug("Leaving ClaimsProviders.save(). " + problem);
      return problem;
    }
    const attributes: Json = {
      objectClass: ['top', 'stsClaimProvider'], cn: record.id,
      stsClaimProviderData: JSON.stringify(record)
    };
    const held = secret === undefined ? (existing ? this.secretOf(record.id) :
                                         '') : String(secret || '');
    if (held) {
      const sealed = this.seal(held, 'claims-provider-secret');
      if (sealed === null) {
        log.debug("Leaving ClaimsProviders.save(). No key to seal with.");
        return 'the client secret cannot be sealed: no key-encryption key ' +
               'is configured';
      }
      attributes.stsClaimProviderSecret = sealed;
    }
    const written = !!this.store('writeClaimProviderEntry',
                                 [record.id, attributes]);
    log.debug("Leaving ClaimsProviders.save(). " + written);
    return written ? '' : 'the directory refused the entry';
  }

  remove(id: string): boolean {
    const { log } = this.deps;
    log.debug("Entering ClaimsProviders.remove(). " + id);
    const gone = !!this.store('deleteClaimProviderEntry', [String(id)]);
    log.debug("Leaving ClaimsProviders.remove(). " + gone);
    return gone;
  }

  // An OpenID Provider's discovery document, for filling the four endpoints
  // from an issuer. Resolves { ok, metadata } or { ok: false, why }.
  async discover(issuer: string): Promise<Json> {
    const { log, http } = this.deps;
    log.debug("Entering ClaimsProviders.discover().");
    const where = String(issuer || '').replace(/\/+$/, '') +
                  '/.well-known/openid-configuration';
    const got = await http().requestConfigured(where, { method: 'GET' });
    if (!got.ok) {
      log.debug("Leaving ClaimsProviders.discover(). " + got.why);
      return { ok: false, why: got.why || ('HTTP ' + got.status) };
    }
    let metadata: Json = null;
    try {
      metadata = JSON.parse(got.body.toString('utf8'));
    } catch (e: any) {
      log.debug("Caught in ClaimsProviders.discover(): " +
                ((e && e.message) || e));
      metadata = null;
    }
    if (!metadata || metadata.issuer !== String(issuer)) {
      log.debug("Leaving ClaimsProviders.discover(). Not its document.");
      return { ok: false, why: 'the discovery document is not JSON naming ' +
               'that issuer (OpenID Connect Discovery section 4.3)' };
    }
    log.debug("Leaving ClaimsProviders.discover().");
    return { ok: true, metadata: metadata };
  }

  // ===========================================================================
  // A PERSON'S LINKS.
  // ===========================================================================
  private linksRaw(username: string): Record<string, Link> {
    const { log } = this.deps;
    log.debug("Entering ClaimsProviders.linksRaw().");
    const stored = String(this.store('readClaimSourceTokens',
                                     [String(username)]) || '');
    let map: Json = {};
    if (stored) {
      try {
        map = JSON.parse(this.open(stored, 'claim-source-tokens')) || {};
      } catch (e: any) {
        log.warn(errorCodes.tag('STS-OAUTH-0687') + 'claims: the Claims ' +
                 'Provider tokens on "' + username + '" could not be read: ' +
                 ((e && e.message) || e));
        map = {};
      }
    }
    log.debug("Leaving ClaimsProviders.linksRaw().");
    return map;
  }

  private writeLinks(username: string, map: Record<string, Link>): boolean {
    const { log } = this.deps;
    log.debug("Entering ClaimsProviders.writeLinks().");
    const plain = Object.keys(map).length ? JSON.stringify(map) : '';
    const sealed = plain ? this.seal(plain, 'claim-source-tokens') : '';
    if (sealed === null) {
      log.warn(errorCodes.tag('STS-OAUTH-0687') + 'claims: no key to seal ' +
               'the Claims Provider tokens of "' + username + '" with.');
      log.debug("Leaving ClaimsProviders.writeLinks(). No key.");
      return false;
    }
    const written = !!this.store('writeClaimSourceTokens',
                                 [String(username), sealed]);
    log.debug("Leaving ClaimsProviders.writeLinks(). " + written);
    return written;
  }

  // What a person, the portal and the console may see of a person's links:
  // never a token.
  linksOf(username: string): Json[] {
    const { log } = this.deps;
    log.debug("Entering ClaimsProviders.linksOf().");
    const map = this.linksRaw(username);
    const out = Object.keys(map).sort().map(function (id: string): Json {
      const one = map[id];
      return { provider: id, sub: one.sub, linkedAt: one.linked_at,
               expiresAt: one.expires_at || 0,
               refreshable: !!one.refresh_token, stale: !!one.stale };
    });
    log.debug("Leaving ClaimsProviders.linksOf(). " + out.length + ".");
    return out;
  }

  // Every person's links, for the console.
  allLinks(): Json[] {
    const { log } = this.deps;
    log.debug("Entering ClaimsProviders.allLinks().");
    const self = this;
    const out: Json[] = [];
    (this.store('claimSourceTokenHolders', []) || [])
      .forEach(function (holder: Json): void {
        self.linksOf(holder.username).forEach(function (link: Json): void {
          out.push(Object.assign({ username: holder.username }, link));
        });
      });
    log.debug("Leaving ClaimsProviders.allLinks(). " + out.length + ".");
    return out;
  }

  unlink(username: string, id: string): boolean {
    const { log } = this.deps;
    log.debug("Entering ClaimsProviders.unlink(). " + id);
    const map = this.linksRaw(username);
    if (!map[id]) {
      log.debug("Leaving ClaimsProviders.unlink(). Not linked.");
      return false;
    }
    delete map[id];
    const done = this.writeLinks(username, map);
    log.debug("Leaving ClaimsProviders.unlink(). " + done);
    return done;
  }

  // ===========================================================================
  // THE SETUP PHASE: an authorization code flow with PKCE to the provider.
  // ===========================================================================
  beginLink(username: string, id: string, base: string): Json {
    const { log, now } = this.deps;
    log.debug("Entering ClaimsProviders.beginLink(). " + id);
    const provider = this.get(id);
    if (!provider) {
      log.debug("Leaving ClaimsProviders.beginLink(). No such provider.");
      return { ok: false, code: 'STS-OAUTH-0680',
               why: 'this realm has no Claims Provider "' + id + '"' };
    }
    const state = nodeCrypto.randomBytes(24).toString('base64url');
    const verifier = nodeCrypto.randomBytes(32).toString('base64url');
    const challenge = nodeCrypto.createHash('sha256').update(verifier)
      .digest('base64url');
    const redirectUri = base + CALLBACK_PATH;
    flows.set(state, { username: String(username), provider: id,
                       verifier: verifier, redirectUri: redirectUri,
                       at: now() });
    const target = new URL(provider.authorizationEndpoint);
    target.searchParams.set('response_type', 'code');
    target.searchParams.set('client_id', provider.clientId);
    target.searchParams.set('redirect_uri', redirectUri);
    target.searchParams.set('scope', provider.scope);
    target.searchParams.set('state', state);
    target.searchParams.set('code_challenge', challenge);
    target.searchParams.set('code_challenge_method', 'S256');
    log.debug("Leaving ClaimsProviders.beginLink().");
    return { ok: true, location: target.toString() };
  }

  // The provider sent the person back. Resolves { ok, provider } or
  // { ok: false, code, why }.
  async finishLink(username: string, query: Json): Promise<Json> {
    const { log, now } = this.deps;
    log.debug("Entering ClaimsProviders.finishLink().");
    const state = String(query.state || '');
    const flow = state ? flows.get(state) : null;
    if (flow) {
      flows.delete(state);
    }
    if (!flow || now() - Number(flow.at || 0) > FLOW_TTL_MS ||
        flow.username !== String(username)) {
      log.debug("Leaving ClaimsProviders.finishLink(). No such flow.");
      return { ok: false, code: 'STS-OAUTH-0681',
               why: 'this link request is unknown, expired or another ' +
                    'person\'s — start it again from this page' };
    }
    if (query.error) {
      log.debug("Leaving ClaimsProviders.finishLink(). The provider refused.");
      return { ok: false, code: 'STS-OAUTH-0682',
               why: 'the provider answered ' + String(query.error) +
                    (query.error_description ? ': ' +
                     String(query.error_description) : '') };
    }
    const provider = this.get(flow.provider);
    if (!provider || !query.code) {
      log.debug("Leaving ClaimsProviders.finishLink(). No provider or code.");
      return { ok: false, code: 'STS-OAUTH-0680',
               why: 'the provider is gone, or sent no code' };
    }
    const tokens = await this.tokenRequest(provider, {
      grant_type: 'authorization_code', code: String(query.code),
      redirect_uri: flow.redirectUri, code_verifier: flow.verifier });
    if (!tokens.ok) {
      log.debug("Leaving ClaimsProviders.finishLink(). " + tokens.why);
      return { ok: false, code: 'STS-OAUTH-0682', why: tokens.why };
    }
    // Who the person is AT THE PROVIDER, from a signed claims response the
    // provider's keys verify: every aggregated source is later held to it.
    const fetched = await this.fetchClaims(provider, tokens.json.access_token,
                                           '');
    if (!fetched.ok) {
      log.debug("Leaving ClaimsProviders.finishLink(). " + fetched.why);
      return { ok: false, code: 'STS-OAUTH-0683', why: fetched.why };
    }
    const map = this.linksRaw(username);
    map[provider.id] = this.linkFrom(tokens.json, fetched.claims.sub, now());
    if (!this.writeLinks(username, map)) {
      log.debug("Leaving ClaimsProviders.finishLink(). Not written.");
      return { ok: false, code: 'STS-OAUTH-0687',
               why: 'the link could not be recorded on your entry' };
    }
    log.debug("Leaving ClaimsProviders.finishLink(). Linked.");
    return { ok: true, provider: provider.id };
  }

  private linkFrom(json: Json, sub: string, at: number): Link {
    this.deps.log.debug("Entering ClaimsProviders.linkFrom().");
    const link: Link = { access_token: String(json.access_token || ''),
                         sub: String(sub || ''), linked_at: at };
    if (json.refresh_token) {
      link.refresh_token = String(json.refresh_token);
    }
    if (Number(json.expires_in) > 0) {
      link.expires_at = at + Number(json.expires_in) * 1000;
    }
    this.deps.log.debug("Leaving ClaimsProviders.linkFrom().");
    return link;
  }

  // A token request to the provider, authenticated as its method says.
  private async tokenRequest(provider: Provider, form: Json): Promise<Json> {
    const { log, http } = this.deps;
    log.debug("Entering ClaimsProviders.tokenRequest(). " + form.grant_type);
    const secret = this.secretOf(provider.id);
    const body = new URLSearchParams(form);
    const headers: Json = {
      'Content-Type': 'application/x-www-form-urlencoded' };
    if (provider.authMethod === 'client_secret_basic') {
      headers.Authorization = 'Basic ' + Buffer.from(
        encodeURIComponent(provider.clientId) + ':' +
        encodeURIComponent(secret)).toString('base64');
    } else {
      body.set('client_id', provider.clientId);
      if (provider.authMethod === 'client_secret_post') {
        body.set('client_secret', secret);
      }
    }
    const got = await http().requestConfigured(provider.tokenEndpoint, {
      method: 'POST', headers: headers, body: body.toString() });
    let json: Json = null;
    try {
      json = JSON.parse(got.body.toString('utf8'));
    } catch (e: any) {
      log.debug("Caught in ClaimsProviders.tokenRequest(): " +
                ((e && e.message) || e));
      json = null;
    }
    if (!got.ok || !json || !json.access_token) {
      const why = (json && json.error) ? 'the token endpoint answered ' +
        json.error + (json.error_description ? ': ' +
        json.error_description : '') : (got.why || 'HTTP ' + got.status);
      log.debug("Leaving ClaimsProviders.tokenRequest(). " + why);
      return { ok: false, why: why };
    }
    log.debug("Leaving ClaimsProviders.tokenRequest().");
    return { ok: true, json: json };
  }

  // The provider's key set, fetched from its configured jwks_uri.
  private async keysOf(provider: Provider): Promise<Json[]> {
    const { log, http } = this.deps;
    log.debug("Entering ClaimsProviders.keysOf().");
    const got = await http().requestConfigured(provider.jwksUri,
                                               { method: 'GET' });
    let keys: Json[] = [];
    try {
      keys = got.ok ? (JSON.parse(got.body.toString('utf8')).keys || []) : [];
    } catch (e: any) {
      log.debug("Caught in ClaimsProviders.keysOf(): " +
                ((e && e.message) || e));
      keys = [];
    }
    log.debug("Leaving ClaimsProviders.keysOf(). " + keys.length + ".");
    return Array.isArray(keys) ? keys : [];
  }

  // A JWT the provider signed, verified against its keys, its `iss` the
  // provider's; `sub` checked where one is given. { ok, claims } or
  // { ok: false, why }.
  async verifyFrom(provider: Provider, jwt: string,
                   sub: string): Promise<Json> {
    const { log, config } = this.deps;
    log.debug("Entering ClaimsProviders.verifyFrom().");
    if (!JWT_PATTERN.test(String(jwt || ''))) {
      log.debug("Leaving ClaimsProviders.verifyFrom(). Not a JWS.");
      return { ok: false, why: 'the provider did not answer with a signed ' +
               'JWT (its client must register userinfo_signed_response_alg)' };
    }
    let header: Json = null;
    try {
      header = JSON.parse(Buffer.from(String(jwt).split('.')[0], 'base64url')
        .toString('utf8'));
    } catch (e: any) {
      log.debug("Caught in ClaimsProviders.verifyFrom(): " +
                ((e && e.message) || e));
      header = null;
    }
    const alg = String((header && header.alg) || '');
    if (!alg || alg.toLowerCase() === 'none' || /^HS/i.test(alg)) {
      log.debug("Leaving ClaimsProviders.verifyFrom(). alg " + alg);
      return { ok: false, why: 'the JWT is signed with "' + alg + '", which ' +
               'a provider\'s public keys cannot verify' };
    }
    const kid = String((header && header.kid) || '');
    const keys = (await this.keysOf(provider)).filter(function (k: Json) {
      return !kid || !k.kid || k.kid === kid;
    });
    let why = 'no key in the provider\'s set verified it';
    for (const jwk of keys) {
      try {
        const key = nodeCrypto.createPublicKey({ key: jwk, format: 'jwk' });
        const claims = stsCrypto.verifyJws(String(jwt), key, {
          // THE FAMILY FROM THE KEY, never the token's word alone.
          algorithms: [alg], issuer: provider.issuer,
          clockTolerance: Number(config.value('oauth2.clockSkewS')) || 0
        });
        if (sub && String(claims.sub || '') !== sub) {
          log.debug("Leaving ClaimsProviders.verifyFrom(). Another sub.");
          return { ok: false, why: 'the JWT is about "' + claims.sub +
                   '", and the person linked "' + sub + '"' };
        }
        log.debug("Leaving ClaimsProviders.verifyFrom(). Verified.");
        return { ok: true, claims: claims };
      } catch (e: any) {
        log.debug("Caught in ClaimsProviders.verifyFrom(): " +
                  ((e && e.message) || e));
        why = String((e && e.message) || e);
      }
    }
    log.debug("Leaving ClaimsProviders.verifyFrom(). " + why);
    return { ok: false, why: why };
  }

  // The provider's claims endpoint, with the person's token: the signed JWT
  // and what it verified to. { ok, jwt, claims } or { ok: false, why }.
  private async fetchClaims(provider: Provider, token: string,
                            sub: string): Promise<Json> {
    const { log, http } = this.deps;
    log.debug("Entering ClaimsProviders.fetchClaims(). " + provider.id);
    const got = await http().requestConfigured(provider.claimsEndpoint, {
      method: 'GET', headers: { Authorization: 'Bearer ' + token,
                                Accept: 'application/jwt' } });
    if (!got.ok) {
      log.debug("Leaving ClaimsProviders.fetchClaims(). " + got.why);
      return { ok: false, status: got.status,
               why: 'the claims endpoint answered ' +
                    (got.why || 'HTTP ' + got.status) };
    }
    const jwt = got.body.toString('utf8').trim();
    const verified = await this.verifyFrom(provider, jwt, sub);
    log.debug("Leaving ClaimsProviders.fetchClaims(). " + verified.ok);
    return verified.ok ? { ok: true, jwt: jwt, claims: verified.claims }
                       : verified;
  }

  // A link's access token, refreshed first when it has expired. The link is
  // written back when it changed. '' when there is none to use.
  private async usableToken(username: string, provider: Provider,
                            map: Record<string, Link>,
                            force: boolean): Promise<string> {
    const { log, now } = this.deps;
    log.debug("Entering ClaimsProviders.usableToken(). " + provider.id);
    const link = map[provider.id];
    if (!link || link.stale) {
      log.debug("Leaving ClaimsProviders.usableToken(). None usable.");
      return '';
    }
    const expired = !!link.expires_at && link.expires_at <= now();
    if (!expired && !force) {
      log.debug("Leaving ClaimsProviders.usableToken(). Current.");
      return link.access_token;
    }
    if (!link.refresh_token) {
      log.debug("Leaving ClaimsProviders.usableToken(). Expired.");
      return '';
    }
    const got = await this.tokenRequest(provider, {
      grant_type: 'refresh_token', refresh_token: link.refresh_token });
    if (!got.ok) {
      log.warn(errorCodes.tag('STS-OAUTH-0686') + 'claims: the token of "' +
               username + '" at Claims Provider "' + provider.id + '" could ' +
               'not be refreshed, and is marked stale: ' + got.why);
      link.stale = true;
      this.writeLinks(username, map);
      log.debug("Leaving ClaimsProviders.usableToken(). Stale.");
      return '';
    }
    // linkFrom() times the expiry from the moment given; a refresh is now.
    const renewed = this.linkFrom(got.json, link.sub, now());
    renewed.linked_at = link.linked_at;
    if (!renewed.refresh_token) {
      renewed.refresh_token = link.refresh_token;
    }
    map[provider.id] = renewed;
    this.writeLinks(username, map);
    log.debug("Leaving ClaimsProviders.usableToken(). Refreshed.");
    return renewed.access_token;
  }

  // ===========================================================================
  // THE DELIVERY PHASE. `wanted` is the claim names a relying party asked for
  // that the person's entry did not answer. Resolves the two members to merge
  // into an ID Token or UserInfo response, or null.
  // ===========================================================================
  async sourcesFor(username: string, wanted: string[]): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering ClaimsProviders.sourcesFor().");
    const asked = (wanted || []).map(String).filter(function (n: string) {
      return n && n !== 'sub' && n.charAt(0) !== '_';
    });
    if (!asked.length || !username) {
      log.debug("Leaving ClaimsProviders.sourcesFor(). Nothing asked.");
      return null;
    }
    const map = this.linksRaw(username);
    const names: Json = {};
    const sources: Json = {};
    for (const provider of this.list()) {
      const offered = asked.filter(function (n: string): boolean {
        return provider.claims.indexOf(n) >= 0 && names[n] === undefined;
      });
      if (!offered.length || !map[provider.id] || map[provider.id].stale) {
        continue;
      }
      let token = await this.usableToken(username, provider, map, false);
      if (!token) {
        continue;
      }
      if (provider.delivery === 'distributed') {
        sources[provider.id] = { endpoint: provider.claimsEndpoint,
                                 access_token: token };
        offered.forEach(function (n: string): void {
          names[n] = provider.id;
        });
        continue;
      }
      let fetched = await this.fetchClaims(provider, token,
                                           map[provider.id].sub);
      if (!fetched.ok && fetched.status === 401 &&
          map[provider.id].refresh_token) {
        // Revoked or expired early at the provider: one refresh, one retry.
        token = await this.usableToken(username, provider, map, true);
        fetched = token ? await this.fetchClaims(provider, token,
                                                 map[provider.id].sub)
                        : fetched;
      }
      if (!fetched.ok) {
        log.warn(errorCodes.tag('STS-OAUTH-0684') + 'claims: Claims Provider ' +
                 '"' + provider.id + '" gave nothing for "' + username +
                 '": ' + fetched.why + '. Its claims are left out.');
        continue;
      }
      const carried = offered.filter(function (n: string): boolean {
        return fetched.claims[n] !== undefined;
      });
      if (!carried.length) {
        continue;
      }
      sources[provider.id] = { JWT: fetched.jwt };
      carried.forEach(function (n: string): void {
        names[n] = provider.id;
      });
    }
    log.debug("Leaving ClaimsProviders.sourcesFor(). " +
              Object.keys(sources).length + " source(s).");
    return Object.keys(sources).length
      ? { _claim_names: names, _claim_sources: sources } : null;
  }

  // ===========================================================================
  // THE CONSUMING SIDE: `_claim_names` / `_claim_sources` in a claim set an
  // upstream OP sent, resolved to values. A source is honoured only when it
  // names a provider this realm REGISTERED — an aggregated JWT by its `iss`,
  // a distributed one by an endpoint equal to that provider's claims
  // endpoint — and a JWT only when that provider's keys verify it. Resolves
  // { claims, notes }: what could be taken, and a sentence for each source
  // that could not.
  // ===========================================================================
  async resolve(bag: Json): Promise<Json> {
    const { log, http } = this.deps;
    log.debug("Entering ClaimsProviders.resolve().");
    const names = (bag && typeof bag._claim_names === 'object')
      ? bag._claim_names : {};
    const sources = (bag && typeof bag._claim_sources === 'object')
      ? bag._claim_sources : {};
    const claims: Json = {};
    const notes: string[] = [];
    for (const src of Object.keys(sources)) {
      const source = sources[src] || {};
      const mine = Object.keys(names).filter(function (n: string): boolean {
        return names[n] === src;
      });
      if (!mine.length) {
        continue;
      }
      let jwt = typeof source.JWT === 'string' ? source.JWT : '';
      let provider: Provider | null = null;
      if (jwt) {
        let payload: Json = null;
        try {
          payload = JSON.parse(Buffer.from(String(jwt).split('.')[1] || '',
            'base64url').toString('utf8'));
        } catch (e: any) {
          log.debug("Caught in ClaimsProviders.resolve(): " +
                    ((e && e.message) || e));
          payload = null;
        }
        provider = payload ? this.byIssuer(String(payload.iss || '')) : null;
        if (!provider) {
          notes.push('source "' + src + '" is signed by an issuer this ' +
                     'realm has not registered as a Claims Provider');
          continue;
        }
      } else if (typeof source.endpoint === 'string') {
        provider = this.list().filter(function (p: Provider): boolean {
          return p.claimsEndpoint === String(source.endpoint);
        })[0] || null;
        if (!provider || !source.access_token) {
          notes.push('source "' + src + '" names an endpoint no registered ' +
                     'Claims Provider has, or no access token');
          continue;
        }
        const got = await http().requestConfigured(provider.claimsEndpoint, {
          method: 'GET', headers: {
            Authorization: 'Bearer ' + String(source.access_token),
            Accept: 'application/jwt' } });
        jwt = got.ok ? got.body.toString('utf8').trim() : '';
        if (!jwt) {
          notes.push('source "' + src + '": the endpoint answered ' +
                     (got.why || 'HTTP ' + got.status));
          continue;
        }
      } else {
        notes.push('source "' + src + '" is neither aggregated nor ' +
                   'distributed');
        continue;
      }
      const verified = await this.verifyFrom(provider, jwt, '');
      if (!verified.ok) {
        notes.push('source "' + src + '" (' + provider.id + '): ' +
                   verified.why);
        continue;
      }
      mine.forEach(function (n: string): void {
        if (verified.claims[n] !== undefined) {
          claims[n] = verified.claims[n];
        }
      });
    }
    if (notes.length) {
      log.warn(errorCodes.tag('STS-OAUTH-0685') + 'claims: ' +
               notes.join('; ') + '.');
    }
    log.debug("Leaving ClaimsProviders.resolve(). " +
              Object.keys(claims).length + " claim(s).");
    return { claims: claims, notes: notes };
  }

  // ===========================================================================
  // THE REFRESH JOB (#49): every token within five minutes of expiring, and
  // setup flows older than ten.
  // ===========================================================================
  async refreshDue(): Promise<Json> {
    const { log, now } = this.deps;
    log.debug("Entering ClaimsProviders.refreshDue().");
    let refreshed = 0;
    let dropped = 0;
    const cutoff = now() - FLOW_TTL_MS;
    flows.forEach(function (flow: Json, state: string): void {
      if (Number((flow && flow.at) || 0) < cutoff) {
        flows.delete(state);
        dropped++;
      }
    });
    const providers = this.list();
    for (const holder of (this.store('claimSourceTokenHolders', []) || [])) {
      const map = this.linksRaw(holder.username);
      for (const provider of providers) {
        const link = map[provider.id];
        if (!link || link.stale || !link.refresh_token || !link.expires_at ||
            link.expires_at - now() > REFRESH_AHEAD_MS) {
          continue;
        }
        if (await this.usableToken(holder.username, provider, map, true)) {
          refreshed++;
        }
      }
    }
    log.debug("Leaving ClaimsProviders.refreshDue(). " + refreshed + ".");
    return { summary: refreshed + ' Claims Provider token(s) refreshed, ' +
             dropped + ' abandoned link request(s) dropped' };
  }

  scheduleJobs(): void {
    const { log, scheduler } = this.deps;
    const self = this;
    log.debug("Entering ClaimsProviders.scheduleJobs().");
    const s = scheduler();
    if (s.job(REFRESH_JOB)) {
      log.debug("Leaving ClaimsProviders.scheduleJobs(). Registered.");
      return;
    }
    s.register({
      id: REFRESH_JOB,
      title: 'Claims Providers: refresh linked tokens',
      describe: 'Refreshes each person\'s token at a Claims Provider they ' +
                'linked before it expires, and drops link requests nobody ' +
                'finished (#147).',
      owner: 'oauth-oidc/claims_providers.ts',
      kind: 'cluster', scope: 'realm', everyMs: function (): number {
        return 60000;
      },
      manual: true,
      run: function (): Promise<Json> {
        return self.refreshDue();
      }
    });
    log.debug("Leaving ClaimsProviders.scheduleJobs(). On the scheduler.");
  }

  // ===========================================================================
  // THE CONSOLE AND /admin-api: the register and every link, never a secret
  // or a token; and the acts.
  // ===========================================================================
  view(): Json {
    const { log } = this.deps;
    log.debug("Entering ClaimsProviders.view().");
    const self = this;
    const out = {
      callbackPath: CALLBACK_PATH,
      providers: this.list().map(function (p: Provider): Json {
        return Object.assign({}, p, { hasSecret: !!self.secretOf(p.id) });
      }),
      links: this.allLinks()
    };
    log.debug("Leaving ClaimsProviders.view().");
    return out;
  }

  // One act from the console or `/admin-api`. Resolves { ok, message } or
  // { ok: false, code, error }.
  async act(body: Json, context: Json): Promise<Json> {
    const { log, audit } = this.deps;
    log.debug("Entering ClaimsProviders.act(). " + body.action);
    const action = String(body.action || '');
    const via = String((context && context.via) || 'console');
    const actor = String((context && context.actor) || '');
    const refuse = function (code: string, error: string): Json {
      log.debug("Leaving ClaimsProviders.act(). " + error);
      return { ok: false, code: code, error: error };
    };
    let message = '';
    if (action === 'add-provider' || action === 'update-provider') {
      const exists = !!this.get(String(body.id || ''));
      if (action === 'add-provider' && exists) {
        return refuse('STS-OAUTH-0688', 'a Claims Provider "' + body.id +
                      '" is already registered');
      }
      if (action === 'update-provider' && !exists) {
        return refuse('STS-OAUTH-0688', 'there is no Claims Provider "' +
                      body.id + '"');
      }
      const record = Object.assign({}, action === 'update-provider'
        ? this.get(String(body.id)) : {}, body);
      if (String(body.discover || '') === 'true' || body.discover === true) {
        const found = await this.discover(String(record.issuer || ''));
        if (!found.ok) {
          return refuse('STS-OAUTH-0689', 'discovery at ' + record.issuer +
                        ' failed: ' + found.why);
        }
        record.authorizationEndpoint = record.authorizationEndpoint ||
          found.metadata.authorization_endpoint;
        record.tokenEndpoint = record.tokenEndpoint ||
          found.metadata.token_endpoint;
        record.claimsEndpoint = record.claimsEndpoint ||
          found.metadata.userinfo_endpoint;
        record.jwksUri = record.jwksUri || found.metadata.jwks_uri;
      }
      const problem = this.save(record, body.clientSecret === undefined ||
                                body.clientSecret === '' ? undefined :
                                String(body.clientSecret));
      if (problem) {
        return refuse('STS-OAUTH-0688', problem);
      }
      message = 'Claims Provider "' + body.id + '" ' +
                (action === 'add-provider' ? 'registered' : 'updated') + '.';
    } else if (action === 'remove-provider') {
      if (!this.remove(String(body.id || ''))) {
        return refuse('STS-OAUTH-0688', 'there is no Claims Provider "' +
                      body.id + '"');
      }
      message = 'Claims Provider "' + body.id + '" removed. Links to it ' +
                'stay on each entry and are never used.';
    } else if (action === 'revoke-link') {
      if (!this.unlink(String(body.username || ''),
                       String(body.provider || ''))) {
        return refuse('STS-OAUTH-0688', '"' + body.username + '" has no ' +
                      'link to "' + body.provider + '"');
      }
      message = 'The link of "' + body.username + '" to "' + body.provider +
                '" was revoked.';
    } else {
      return refuse('STS-OAUTH-0688', 'unknown action "' + action + '": ' +
                    'add-provider, update-provider, remove-provider, ' +
                    'revoke-link');
    }
    try {
      audit().record({ category: 'admin',
                       action: 'oauth2.claims-providers.' + action,
                       actor: actor, target: String(body.id ||
                                                    body.provider || ''),
                       outcome: 'success', summary: message + ' (' + via +
                       ')' });
    } catch (e: any) {
      log.debug("Caught in ClaimsProviders.act(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving ClaimsProviders.act(). " + message);
    return { ok: true, message: message };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<ClaimsProviders>(
  'oauth-oidc/claims_providers',
  () => new ClaimsProviders(ClaimsProviders.defaultDeps()),
  function (instance: ClaimsProviders): void {
    instance.scheduleJobs();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  ClaimsProviders: ClaimsProviders,
  installInstance: (instance: ClaimsProviders): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  REFRESH_JOB: REFRESH_JOB,
  CALLBACK_PATH: CALLBACK_PATH,
  DELIVERY: DELIVERY,
  AUTH_METHODS: AUTH_METHODS,
  list: slot.forward('list'),
  get: slot.forward('get'),
  byIssuer: slot.forward('byIssuer'),
  save: slot.forward('save'),
  remove: slot.forward('remove'),
  discover: slot.forward('discover'),
  linksOf: slot.forward('linksOf'),
  allLinks: slot.forward('allLinks'),
  unlink: slot.forward('unlink'),
  beginLink: slot.forward('beginLink'),
  finishLink: slot.forward('finishLink'),
  verifyFrom: slot.forward('verifyFrom'),
  sourcesFor: slot.forward('sourcesFor'),
  resolve: slot.forward('resolve'),
  refreshDue: slot.forward('refreshDue'),
  view: slot.forward('view'),
  act: slot.forward('act')
};
