'use strict';
//
// File: provider_commands.ts
//
// ===========================================================================
// OPENID PROVIDER COMMANDS 1.0 (DRAFT 02) — THIS SERVICE AS THE OPENID
// PROVIDER THAT TELLS ITS RELYING PARTIES WHAT TO DO WITH AN ACCOUNT
// (#151, 2026-09-26).
//
// A relying party that registered a `command_endpoint` is POSTed a signed
// Command Token (`typ: command+jwt`) naming a COMMAND: an ACCOUNT command
// about one person (`activate`, `maintain`, `suspend`, `reactivate`,
// `archive`, `restore`, `delete`, `audit`, `invalidate`, `migrate`, each
// with an `_async` variant answered 202 and finished by a callback), or a
// TENANT command about everybody (`metadata`, and five whose answer is a
// Server-Sent Events stream: `audit_tenant`, `suspend_tenant`,
// `archive_tenant`, `delete_tenant`, `invalidate_tenant`). rcbj's answers on
// #151 were every recommendation, and this file is their shape:
//
// **1. AN ACCOUNT COMMAND AND `metadata` ARE DELIVERIES OF THE SHARED QUEUE**
// (`outbound_delivery.ts`, answer 1a): a persisted row, a claimed attempt
// with a fence, retries of what is worth retrying (a 5xx, a timeout),
// dead letters an operator retries — the machinery back-channel logout and
// CIBA use, not a fourth copy of it. `judge()` reads the answer: 200 with
// `{ sub, account_state }`, 204, 202 for an `_async` command, and the
// section 3 errors — `incompatible_state` (409), `unsupported_command`,
// `unrecognized_provider` (401), `access_denied` and
// `authentication_not_transferable` — each a dead letter with its own code,
// since none is made right by repeating it.
//
// **2. A TENANT COMMAND'S STREAM IS READ BY `federation_http.streamEvents()`**
// (answer 3a): each `account-state` event updates the register below, and
// `command-complete` ends the run; a stream that drops before it is resumed
// with `Last-Event-ID`, up to `oauth2.commandStreamResumes` times. A RUN is
// one operation started by an administrator, not periodic work, and its
// progress is a row (`oauth2.tenantCommandRuns`) every node's console reads.
//
// **3. THE ACCOUNT-STATE REGISTER** (`oauth2.commandAccounts`, per realm and
// persisted): what each relying party last said about each person —
// `unknown`, `active`, `suspended` or `archived` — keyed by the client and
// the `sub` it knows (pairwise where the client registered pairwise), with
// the person's name where this service knows it. It is what the relying
// party SAID, never what this service assumed: a command that was not
// answered leaves it as it was.
//
// **4. AUTOMATIC COMMANDS** (answer 2a): a disable sends `suspend`, an enable
// `reactivate`, a directory or SCIM delete `delete`, an attribute or group
// change `maintain`, and an administrator's global sign-out of a person
// `invalidate` — ONLY to a relying party whose learned `commands_supported`
// (from `metadata`) lists the command, and only where the person has an
// account there by the register or has been issued a token for that client.
// `oauth2.commandAutomatic` turns the whole of it off.
//
// **5. `tenant` IS THE REALM ID AND `aud_sub` IS #148's** (answer 4): the
// value recorded per person per client (`credentials.audSubsOf()`), sent
// when known, and LEARNED from an answer that carries one.
//
// **6. THE ISSUER.** A Command Token's `iss` must be the issuer the relying
// party knows from its ID Tokens. A command started from a request uses that
// request's issuer, and remembers it for the realm; an automatic one uses a
// pinned `oauth2.issuer` or `global.publicBaseUrl`, else the remembered one,
// else it is a dead letter saying so (STS-OAUTH-0735).
//
// **7. THE CALLBACK** — `POST /oauth2/commands/callback`, Bearer the
// `callback_token` this service put in the Command Token (stored hashed, one
// per command, for `oauth2.commandCallbackTtlS`): an `_async` result
// `{ sub, account_state }`, or a relying party's request for a fresh
// `metadata` or `audit_tenant` (`{ command_requested }`). RFC 6750's errors.
//
// It is a LIBRARY with one route (the callback), which
// `common/protocol_stack.ts` registers after `oauth2`'s.
// ===========================================================================

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import realms = require('../common/realms');
import applications = require('../common/applications');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import mode = require('../common/mode');
import fedHttp = require('../federation/federation_http');
import clusterClaims = require('../cluster/cluster_claims');
import outbound = require('./outbound_delivery');

type Json = any;
type Req = import('express').Request;
type Res = import('express').Response;

const TOKEN_TYPE = 'command+jwt';
const ADDRESS_ATTRIBUTE = 'oauthCommandEndpoint';
const ATTEMPT_SCOPE = 'oauth2.command-attempt';
const SWEEP_JOB = 'oauth2.command-sweep';
const CALLBACK_PATH = '/oauth2/commands/callback';

// Section 6, the account commands.
const ACCOUNT_COMMANDS = Object.freeze(['activate', 'maintain', 'suspend',
  'reactivate', 'archive', 'restore', 'delete', 'audit', 'invalidate',
  'migrate']);
// Section 7: `metadata` answers JSON, the rest a stream.
const STREAM_COMMANDS = Object.freeze(['audit_tenant', 'suspend_tenant',
  'archive_tenant', 'delete_tenant', 'invalidate_tenant']);
const TENANT_COMMANDS = Object.freeze(['metadata'].concat(STREAM_COMMANDS));
const STATES = Object.freeze(['unknown', 'active', 'suspended', 'archived']);

// The standard claims an `activate` or `maintain` carries (section 6.1: "the
// Claims the OP has for the account").
const ACCOUNT_CLAIMS = ['name', 'given_name', 'family_name', 'email',
                       'preferred_username'];

// Which states an automatic command is sent from (section 6's table).
const AUTOMATIC_FROM = {
  suspend: ['active'],
  reactivate: ['suspended'],
  delete: ['active', 'suspended', 'archived'],
  maintain: ['active'],
  invalidate: ['active']
};

// The section 3 errors a relying party answers, and this service's codes.
const ERROR_CODES = {
  invalid_request: 'STS-OAUTH-0736',
  unrecognized_provider: 'STS-OAUTH-0737',
  unsupported_command: 'STS-OAUTH-0738',
  incompatible_state: 'STS-OAUTH-0739',
  access_denied: 'STS-OAUTH-0740',
  authentication_not_transferable: 'STS-OAUTH-0741'
};

// The deliveries (the shared queue's rows), the register, what each client
// said it supports, the issuer the realm last used, the callback tokens and
// the tenant runs. Per realm at their declarations, and persisted.
const deliveries = realms.map({ persist: 'oauth2.commandDeliveries',
                                tombstone: true,
                                mergeRow: outbound.mergeRow });
const accounts = realms.map({ persist: 'oauth2.commandAccounts' });
const learned = realms.map({ persist: 'oauth2.commandMetadata' });
const callbacks = realms.map({ persist: 'oauth2.commandCallbacks',
                               retain: 'age' });
const runs = realms.map({ persist: 'oauth2.tenantCommandRuns' });

interface ProviderCommandsDeps {
  log: typeof helpers.log;
  signJwtAsAsync: typeof helpers.signJwtAsAsync;
  nowSec: typeof helpers.nowSec;
  randomId: typeof helpers.randomId;
  config: typeof config;
  realms: typeof realms;
  applications: typeof applications;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  mode: typeof mode;
  fedHttp: typeof fedHttp;
  claims: typeof clusterClaims;
  now: () => number;
  later: (fn: () => void, ms: number) => void;
  // Lazily, for cycles: `credentials` (aud_sub), `claim_attributes`, the
  // pairwise subjects, the token register and the directory.
  credentials: () => Json;
  claimAttributes: () => Json;
  pairwise: () => Json;
  stats: () => Json;
  directory: () => Json;
}

class ProviderCommands {
  static readonly TOKEN_TYPE = TOKEN_TYPE;
  static readonly ACCOUNT_COMMANDS = ACCOUNT_COMMANDS;
  static readonly TENANT_COMMANDS = TENANT_COMMANDS;
  static readonly STREAM_COMMANDS = STREAM_COMMANDS;
  static readonly STATES = STATES;
  static readonly CALLBACK_PATH = CALLBACK_PATH;
  private readonly outbox: InstanceType<typeof outbound.OutboundDelivery>;

  constructor(private readonly deps: ProviderCommandsDeps) {
    deps.log.debug("Entering ProviderCommands.constructor().");
    const self = this;
    this.outbox = new outbound.OutboundDelivery({
      label: 'OpenID Provider Commands',
      store: deliveries,
      attemptScope: ATTEMPT_SCOPE,
      attribute: ADDRESS_ATTRIBUTE,
      body: 'form',
      keepBody: true,
      settings: {
        attempts: 'oauth2.commandAttempts',
        timeoutMs: 'oauth2.commandTimeoutMs',
        backoffMs: 'oauth2.commandBackoffMs',
        leaseMs: 'oauth2.commandLeaseMs',
        retentionS: 'oauth2.commandRetentionS',
        maxRows: 'oauth2.commandMaxRows',
        concurrency: 'oauth2.commandConcurrency',
        summaryS: 'oauth2.commandSummaryS'
      },
      codes: {
        outboundOff: 'STS-OAUTH-0722', url: 'STS-OAUTH-0723',
        internal: 'STS-OAUTH-0724', unresolved: 'STS-OAUTH-0725',
        redirect: 'STS-OAUTH-0726', build: 'STS-OAUTH-0727',
        timeout: 'STS-OAUTH-0728', network: 'STS-OAUTH-0729',
        status400: 'STS-OAUTH-0736', status: 'STS-OAUTH-0730',
        deferred: 'STS-OAUTH-0731', stale: 'STS-OAUTH-0732',
        summary: 'STS-OAUTH-0733', sweepFailed: 'STS-OAUTH-0734',
        retry: 'STS-OAUTH-0742'
      },
      deadLetterHint: 'Dead letters are listed on /admin/commands and ' +
        '/admin/deliveries, and retried from there.',
      prepare: function (row: Json): Promise<Json> {
        return self.prepare(row);
      },
      judge: function (result: Json, row: Json): Json {
        return self.judge(result, row);
      },
      onFinish: function (row: Json, state: string, code: string,
                          why: string): void {
        self.finished(row, state, code, why);
      },
      onRetry: function (row: Json): Json {
        const endpoint = self.deps.applications.commandEndpointOf(
          row.clientId);
        return endpoint ? { patch: { uri: endpoint } }
          : { problem: row.clientId + ' has no command_endpoint now, so a ' +
                       'retry would fail the same way.' };
      },
      viewExtra: function (row: Json): Json {
        return { command: row.command, username: row.username || '',
                 sub: row.sub || '', trigger: row.trigger || '',
                 accountState: row.accountState || '',
                 awaitingCallback: !!row.awaitingCallback };
      },
      searchText: function (row: Json): string {
        return [row.command, row.username, row.sub].join(' ');
      },
      sweepJob: {
        id: SWEEP_JOB,
        title: 'OpenID Provider Commands sweep',
        describe: 'Sends every Command Token delivery that is due — a retry ' +
                  'whose backoff has passed, a lease that lapsed, a row ' +
                  'restored after a restart — dead-letters any still ' +
                  'pending past oauth2.commandRetentionS, and drops expired ' +
                  'callback tokens and finished tenant runs.',
        owner: 'oauth-oidc/provider_commands.ts',
        everySetting: 'oauth2.commandSweepS'
      },
      onSweepRealm: function (): Json {
        return self.sweepRealm();
      }
    }, {
      log: deps.log, config: deps.config, realms: deps.realms,
      errorCodes: deps.errorCodes, fedHttp: deps.fedHttp,
      claims: deps.claims, now: deps.now, later: deps.later
    });
    deps.log.debug("Leaving ProviderCommands.constructor().");
  }

  static defaultDeps(): ProviderCommandsDeps {
    helpers.log.debug("Entering ProviderCommands.defaultDeps().");
    helpers.log.debug("Leaving ProviderCommands.defaultDeps().");
    return {
      log: helpers.log, signJwtAsAsync: helpers.signJwtAsAsync,
      nowSec: helpers.nowSec, randomId: helpers.randomId,
      config: config, realms: realms, applications: applications,
      errorCodes: errorCodes, audit: audit, mode: mode, fedHttp: fedHttp,
      claims: clusterClaims,
      now: function (): number {
        return Date.now();
      },
      later: outbound.OutboundDelivery.later,
      credentials: function (): Json {
        return require('../common/credentials');
      },
      claimAttributes: function (): Json {
        return require('../common/claim_attributes');
      },
      pairwise: function (): Json {
        return require('./pairwise_subjects');
      },
      stats: function (): Json {
        return require('../common/admin_stats');
      },
      directory: function (): Json {
        // Never a require: `ldap_server.js` is a JavaScript route module,
        // and loading it from here would register its routes out of order.
        const found = require.cache[require.resolve('../ldap/ldap_server')];
        return found ? found.exports : null;
      }
    };
  }

  enabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering ProviderCommands.enabled().");
    log.debug("Leaving ProviderCommands.enabled().");
    return !!config.value('oauth2.providerCommands');
  }

  private setting(key: string): number {
    const { log, config } = this.deps;
    log.debug("Entering ProviderCommands.setting(). " + key);
    log.debug("Leaving ProviderCommands.setting().");
    return Number(config.value(key));
  }

  static isAccountCommand(command: string): boolean {
    helpers.log.debug("Entering ProviderCommands.isAccountCommand().");
    const base = String(command || '').replace(/_async$/, '');
    helpers.log.debug("Leaving ProviderCommands.isAccountCommand().");
    return ACCOUNT_COMMANDS.indexOf(base) >= 0;
  }

  // The digest a callback token is stored under.
  static digest(token: string): string {
    helpers.log.debug("Entering ProviderCommands.digest().");
    helpers.log.debug("Leaving ProviderCommands.digest().");
    return nodeCrypto.createHash('sha256').update(String(token))
      .digest('base64url');
  }

  // -------------------------------------------------------------------------
  // THE ISSUER (header point 6). `base`, when a request gave one, decides
  // and is remembered for the realm.
  // -------------------------------------------------------------------------
  issuer(base?: string): string {
    const { log, config } = this.deps;
    log.debug("Entering ProviderCommands.issuer().");
    const jwtAccessToken = require('./jwt_access_token');
    if (base) {
      const iss = jwtAccessToken.issuerFor(String(base));
      learned.set('\u0000issuer', { issuer: iss });
      log.debug("Leaving ProviderCommands.issuer(). From the request.");
      return iss;
    }
    const pinned = String(config.value('global.publicBaseUrl') || '').trim()
      .replace(/\/+$/, '');
    if (config.value('oauth2.issuer') || pinned) {
      log.debug("Leaving ProviderCommands.issuer(). Pinned.");
      return jwtAccessToken.issuerFor(pinned + realms.currentPrefix());
    }
    const remembered = learned.get('\u0000issuer');
    log.debug("Leaving ProviderCommands.issuer(). " +
              (remembered ? 'Remembered.' : 'None.'));
    return remembered ? String(remembered.issuer) : '';
  }

  // The `sub` this client knows the person by: public or pairwise. An
  // ephemeral subject (#149) names one authentication, not an account, so a
  // client that registered it is sent no account command (''), and a
  // person with no entry has no subject ('').
  subjectFor(clientId: string, username: string): string {
    const { log, applications } = this.deps;
    log.debug("Entering ProviderCommands.subjectFor(). " + clientId);
    const local = helpers.subjectForName(String(username || ''));
    const cfg: Json = applications.clientConfigOf(String(clientId)) || {};
    if (!local || cfg.subject_type === 'ephemeral') {
      log.debug("Leaving ProviderCommands.subjectFor(). None.");
      return '';
    }
    let sub = '';
    try {
      sub = String(this.deps.pairwise().subjectFor(String(clientId), local) ||
                   '');
    } catch (e) {
      log.debug("Caught in ProviderCommands.subjectFor(): " +
                ((e && e.message) || e));
      sub = '';
    }
    log.debug("Leaving ProviderCommands.subjectFor().");
    return sub;
  }

  // What a client said it supports (from `metadata`), or null when it has
  // not been asked.
  learnedFor(clientId: string): Json {
    const { log } = this.deps;
    log.debug("Entering ProviderCommands.learnedFor(). " + clientId);
    const held = learned.get(String(clientId));
    log.debug("Leaving ProviderCommands.learnedFor(). " + !!held);
    return held ? Object.assign({}, held) : null;
  }

  // The register row for (client, sub), or null.
  accountFor(clientId: string, sub: string): Json {
    const { log } = this.deps;
    log.debug("Entering ProviderCommands.accountFor().");
    const held = accounts.get(String(clientId) + ' ' + String(sub));
    log.debug("Leaving ProviderCommands.accountFor(). " + !!held);
    return held ? Object.assign({}, held) : null;
  }

  // WRITE WHAT A RELYING PARTY SAID about an account (header point 3).
  private noteAccount(clientId: string, sub: string, username: string,
                      state: string, command: string, extra?: Json): void {
    const { log, now } = this.deps;
    log.debug("Entering ProviderCommands.noteAccount(). " + state);
    if (STATES.indexOf(state) < 0 || !sub) {
      log.debug("Leaving ProviderCommands.noteAccount(). Not a state.");
      return;
    }
    const key = String(clientId) + ' ' + String(sub);
    const held = accounts.get(key) || {};
    accounts.set(key, Object.assign({}, held, extra || {}, {
      clientId: String(clientId), sub: String(sub),
      username: String(username || held.username || ''),
      state: state, lastCommand: String(command || ''), updatedAt: now()
    }));
    // THE aud_sub A RELYING PARTY GAVE (header point 5), recorded where
    // #148 keeps it — once, and only for a person this service knows.
    const audSub = extra && extra.audSub;
    const who = String(username || held.username || '');
    if (audSub && who) {
      try {
        const creds = this.deps.credentials();
        const prefix = String(clientId) + ' ';
        const values = (creds.audSubsOf(who) || []).filter(function (v: Json) {
          return String(v).indexOf(prefix) !== 0;
        });
        values.push(prefix + String(audSub));
        creds.writeAudSubs(who, values);
      } catch (e) {
        log.debug("Caught in ProviderCommands.noteAccount(): " +
                  ((e && e.message) || e));
      }
    }
    log.debug("Leaving ProviderCommands.noteAccount().");
  }

  // The aud_sub recorded for this person and client (#148), or ''.
  private audSubFor(username: string, clientId: string): string {
    const { log } = this.deps;
    log.debug("Entering ProviderCommands.audSubFor().");
    const prefix = String(clientId) + ' ';
    let found = '';
    try {
      found = String((this.deps.credentials().audSubsOf(String(username)) ||
        []).filter(function (v: Json) {
          return String(v).indexOf(prefix) === 0;
        })[0] || '');
    } catch (e) {
      log.debug("Caught in ProviderCommands.audSubFor(): " +
                ((e && e.message) || e));
      found = '';
    }
    log.debug("Leaving ProviderCommands.audSubFor().");
    return found ? found.slice(prefix.length) : '';
  }

  // A callback token, minted and stored hashed with what it answers for.
  private mintCallback(fields: Json): string {
    const { log, now } = this.deps;
    log.debug("Entering ProviderCommands.mintCallback().");
    const token = nodeCrypto.randomBytes(32).toString('base64url');
    callbacks.set(ProviderCommands.digest(token), Object.assign({
      expiresAt: now() + this.setting('oauth2.commandCallbackTtlS') * 1000
    }, fields));
    log.debug("Leaving ProviderCommands.mintCallback().");
    return token;
  }

  // What this service tells a relying party in `metadata` (section 7.1).
  opMetadata(): Json {
    const { log, realms } = this.deps;
    log.debug("Entering ProviderCommands.opMetadata().");
    const iss = this.issuer();
    const realm: Json = realms.current() || {};
    const out: Json = {
      callback_endpoint: iss ? iss.replace(/\/+$/, '') + CALLBACK_PATH : '',
      claims_supported: ['sub', 'aud_sub'].concat(ACCOUNT_CLAIMS)
    };
    if (!out.callback_endpoint) {
      delete out.callback_endpoint;
    }
    const domain = String(realm.domain || config.value('global.domain') ||
                          '');
    if (domain) {
      out.domains = [domain];
    }
    const directory = this.deps.directory();
    if (directory && typeof directory.allGroupEntries === 'function') {
      try {
        const cap = this.setting('oauth2.commandMetadataMaxGroups');
        out.groups = directory.allGroupEntries().slice(0, cap)
          .map(function (group: Json) {
            const a = group.attributes || {};
            const first = function (name: string): string {
              const v = a[name];
              return String((Array.isArray(v) ? v[0] : v) || '');
            };
            const one: Json = { id: first('cn') || String(group.dn),
                                display: first('displayName') || first('cn') ||
                                         String(group.dn) };
            if (first('description')) {
              one.description = first('description');
            }
            return one;
          });
      } catch (e) {
        log.debug("Caught in ProviderCommands.opMetadata(): " +
                  ((e && e.message) || e));
      }
    }
    log.debug("Leaving ProviderCommands.opMetadata().");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE COMMAND TOKEN'S CLAIMS (section 5): the required baseline, `sub`
  // only for an account command, `aud_sub` when known, `callback_token`
  // where one was minted, `metadata` only in `metadata`,
  // `authentication_provider` only in `migrate`, the account's claims in
  // `activate` and `maintain`, and never `nonce`.
  // -------------------------------------------------------------------------
  claimsFor(row: Json): Json {
    const { log, nowSec, randomId } = this.deps;
    log.debug("Entering ProviderCommands.claimsFor(). " + row.command);
    const iat = nowSec();
    const claims: Json = {
      iss: row.iss, aud: row.clientId, client_id: row.clientId,
      iat: iat,
      exp: iat + Math.min(120, this.setting('oauth2.commandTokenTtlS')),
      jti: String(row.jti || '') || randomId(16),
      command: row.command, tenant: row.tenant
    };
    if (ProviderCommands.isAccountCommand(row.command)) {
      claims.sub = row.sub;
      if (row.audSub) {
        claims.aud_sub = row.audSub;
      }
      const base = String(row.command).replace(/_async$/, '');
      if ((base === 'activate' || base === 'maintain') && row.username) {
        try {
          const built = this.deps.claimAttributes()
            .requestedClaimsFor(row.username, ACCOUNT_CLAIMS);
          Object.keys((built && built.claims) || {}).forEach(function (k) {
            const v = built.claims[k];
            if (v !== undefined && v !== null && v !== '') {
              claims[k] = v;
            }
          });
        } catch (e) {
          log.debug("Caught in ProviderCommands.claimsFor(): " +
                    ((e && e.message) || e));
        }
      }
      if (base === 'migrate') {
        claims.authentication_provider = row.authenticationProvider ||
                                         row.iss;
      }
    }
    if (row.command === 'metadata') {
      claims.metadata = row.opMetadata || this.opMetadata();
    }
    if (row.callbackToken) {
      claims.callback_token = row.callbackToken;
    }
    log.debug("Leaving ProviderCommands.claimsFor().");
    return claims;
  }

  // Signed like the client's ID Token (section 9), `typ: command+jwt`.
  async signedToken(row: Json): Promise<Json> {
    const { log, applications, signJwtAsAsync, errorCodes } = this.deps;
    log.debug("Entering ProviderCommands.signedToken(). " + row.clientId);
    const registered: Json = applications.registrationOf(row.clientId) || {};
    const alg = String(registered.id_token_signed_response_alg || 'RS256');
    if (alg === 'none') {
      log.debug("Leaving ProviderCommands.signedToken(). alg none.");
      throw errorCodes.mark(new Error('this client registered ' +
        'id_token_signed_response_alg "none", and a Command Token MUST be ' +
        'signed'), 'STS-OAUTH-0727');
    }
    const claims = this.claimsFor(row);
    const token = await signJwtAsAsync(claims, alg,
      String(registered.client_secret || '') || undefined,
      { header: { typ: TOKEN_TYPE }, certificateHeader: 'id-token',
        session: row.sub || row.clientId });
    log.debug("Leaving ProviderCommands.signedToken(). alg=" + alg);
    return { token: token, exp: claims.exp, jti: claims.jti };
  }

  // The body: the Command Token, signed again (same jti) when it would
  // expire before this attempt reached the relying party — its lifetime is
  // at most two minutes, so a retry after a backoff usually re-signs.
  private async prepare(row: Json): Promise<Json> {
    const { log, now } = this.deps;
    log.debug("Entering ProviderCommands.prepare(). " + row.command);
    if (!row.iss) {
      log.debug("Leaving ProviderCommands.prepare(). No issuer.");
      throw errorCodes.mark(new Error('no issuer is known for this realm — ' +
        'set global.publicBaseUrl, or send a command from the console once ' +
        'so its address is learned'), 'STS-OAUTH-0735');
    }
    if (row.token && Number(row.tokenExp) - 5 > Math.floor(now() / 1000)) {
      log.debug("Leaving ProviderCommands.prepare(). The token stands.");
      return { body: { command_token: row.token } };
    }
    const made = await this.signedToken(row);
    log.debug("Leaving ProviderCommands.prepare(). Signed.");
    return { body: { command_token: made.token },
             patch: { token: made.token, tokenExp: made.exp, jti: made.jti } };
  }

  // -------------------------------------------------------------------------
  // THE ANSWER (sections 3 and 4). Null leaves it to the shared classifier
  // (a 5xx, a timeout — retried).
  // -------------------------------------------------------------------------
  private judge(result: Json, row: Json): Json {
    const { log } = this.deps;
    log.debug("Entering ProviderCommands.judge(). " + result.status);
    const status = Number(result.status) || 0;
    let body: Json = null;
    try {
      body = result.body ? JSON.parse(String(result.body)) : null;
    } catch (e) {
      log.debug("Caught in ProviderCommands.judge(): " +
                ((e && e.message) || e));
      body = null;
    }
    const isAccount = ProviderCommands.isAccountCommand(row.command);
    if (status === 202 && /_async$/.test(String(row.command))) {
      log.debug("Leaving ProviderCommands.judge(). Accepted; a callback.");
      return { ok: true, patch: { awaitingCallback: true } };
    }
    if (status === 200 || status === 204) {
      if (row.command === 'metadata') {
        if (!body || !Array.isArray(body.commands_supported) ||
            body.commands_supported.indexOf('metadata') < 0 ||
            !body.context || body.context.iss !== row.iss ||
            String(body.context.tenant) !== String(row.tenant)) {
          log.debug("Leaving ProviderCommands.judge(). A bad metadata answer.");
          return { ok: false, retry: false, code: 'STS-OAUTH-0743',
                   why: 'the metadata answer is not section 7.1\'s: it ' +
                        'needs commands_supported (listing metadata) and a ' +
                        'context naming this iss and tenant' };
        }
        log.debug("Leaving ProviderCommands.judge(). Metadata.");
        return { ok: true, patch: { metadataAnswer: body } };
      }
      if (isAccount) {
        if (body && (String(body.sub || '') !== String(row.sub) ||
                     STATES.indexOf(String(body.account_state)) < 0)) {
          log.debug("Leaving ProviderCommands.judge(). A bad answer.");
          return { ok: false, retry: false, code: 'STS-OAUTH-0743',
                   why: 'the answer does not name the same sub and an ' +
                        'account_state of ' + STATES.join(', ') };
        }
        log.debug("Leaving ProviderCommands.judge(). Done.");
        return { ok: true, patch: {
          accountState: body ? String(body.account_state) : '',
          answeredAudSub: body && body.aud_sub ? String(body.aud_sub) : '' } };
      }
      log.debug("Leaving ProviderCommands.judge(). Done.");
      return { ok: true };
    }
    if (body && ERROR_CODES[body.error]) {
      log.debug("Leaving ProviderCommands.judge(). " + body.error);
      return { ok: false, retry: false, code: ERROR_CODES[body.error],
               why: 'the relying party answered ' + status + ' ' +
                    body.error + (body.error_description
                      ? ' (' + String(body.error_description).slice(0, 200) +
                        ')' : ''),
               patch: STATES.indexOf(String(body.account_state)) >= 0
                 ? { accountState: String(body.account_state) } : undefined };
    }
    log.debug("Leaving ProviderCommands.judge(). The shared classifier.");
    return null;
  }

  // A delivery finished: the register learns what the relying party said,
  // `metadata` records what it supports, and one audit row.
  private finished(row: Json, state: string, code: string, why: string): void {
    const { log, audit } = this.deps;
    log.debug("Entering ProviderCommands.finished(). " + state);
    if (row.accountState && ProviderCommands.isAccountCommand(row.command)) {
      this.noteAccount(row.clientId, row.sub, row.username, row.accountState,
                       row.command, { audSub: row.answeredAudSub || '' });
    }
    if (state === 'sent' && row.command === 'metadata' && row.metadataAnswer) {
      const a = row.metadataAnswer;
      learned.set(String(row.clientId), {
        clientId: row.clientId,
        commandsSupported: a.commands_supported.map(String),
        commandEndpoint: String(a.command_endpoint || ''),
        audSubRequired: a.aud_sub_required === true,
        roles: Array.isArray(a.roles) ? a.roles.slice(0, 200) : [],
        context: a.context, learnedAt: this.deps.now()
      });
    }
    audit.audit({
      action: 'oauth2.command',
      outcome: state === 'sent' ? 'success' : 'error',
      errorCode: state === 'sent' ? '' : code,
      summarised: true,
      actor: row.actor || '',
      protocol: 'OAuth 2.0 / OIDC', channel: 'internal',
      target: row.clientId,
      summary: state === 'sent'
        ? 'the OpenID Provider Command ' + row.command + ' was accepted by ' +
          row.clientId + (row.accountState ? ' (account_state ' +
          row.accountState + ')' : '') + (row.awaitingCallback
            ? ', a callback to follow' : '')
        : 'the OpenID Provider Command ' + row.command + ' to ' +
          row.clientId + ' is a dead letter: ' + why,
      detail: { delivery: row.id, command: row.command, username:
                row.username || '', sub: row.sub || '', uri: row.uri,
                trigger: row.trigger || '', attempts: String(row.attempts),
                accountState: row.accountState || '' }
    });
    log.debug("Leaving ProviderCommands.finished().");
  }

  // -------------------------------------------------------------------------
  // SEND ONE COMMAND to one relying party: an account command about
  // `username`, or `metadata`. `{ ok, row, message }`, or a refusal
  // `{ ok: false, message }` with its code. `opts.base` is the request's
  // base (the issuer), `opts.actor`, `opts.trigger` for the console.
  // -------------------------------------------------------------------------
  send(clientId: string, command: string, username: string,
       opts?: Json): Json {
    const { log, applications, errorCodes, realms } = this.deps;
    log.debug("Entering ProviderCommands.send(). " + clientId + " " +
              command);
    const o = opts || {};
    const refuse = function (code: string, message: string): Json {
      log.debug("Entering refuse(). " + code);
      log.debug("Leaving refuse().");
      return errorCodes.mark({ ok: false, message: message }, code);
    };
    if (!this.enabled()) {
      log.debug("Leaving ProviderCommands.send(). Off.");
      return refuse('STS-OAUTH-0744', 'OpenID Provider Commands are off in ' +
                    'this realm (oauth2.providerCommands).');
    }
    const cmd = String(command || '');
    const isAccount = ProviderCommands.isAccountCommand(cmd);
    if (!isAccount && cmd !== 'metadata') {
      log.debug("Leaving ProviderCommands.send(). Unknown.");
      return refuse('STS-OAUTH-0744', 'Unknown command "' + cmd + '". ' +
        'An account command is one of ' + ACCOUNT_COMMANDS.join(', ') +
        ' (or its _async variant); a tenant command is one of ' +
        TENANT_COMMANDS.join(', ') + '.');
    }
    const endpoint = applications.commandEndpointOf(clientId);
    if (!endpoint) {
      log.debug("Leaving ProviderCommands.send(). No endpoint.");
      return refuse('STS-OAUTH-0744', 'Client "' + clientId + '" registered ' +
                    'no command_endpoint.');
    }
    const fields: Json = {
      clientId: String(clientId), uri: endpoint, command: cmd,
      tenant: String(realms.currentId() || 'default'),
      iss: this.issuer(o.base), actor: String(o.actor || ''),
      trigger: String(o.trigger || 'an administrator'),
      username: '', sub: '', audSub: '', callbackToken: '',
      jti: '', token: '', tokenExp: 0
    };
    if (isAccount) {
      const sub = this.subjectFor(clientId, username);
      if (!sub) {
        log.debug("Leaving ProviderCommands.send(). No subject.");
        return refuse('STS-OAUTH-0744', 'There is no subject for "' +
          String(username || '') + '" at ' + clientId + ': the person has ' +
          'no entry here, or the client registered ephemeral subjects, ' +
          'which name an authentication rather than an account.');
      }
      fields.username = String(username);
      fields.sub = sub;
      fields.audSub = this.audSubFor(username, clientId);
      const known = this.learnedFor(clientId);
      if (known && known.audSubRequired && !fields.audSub) {
        log.debug("Leaving ProviderCommands.send(). aud_sub required.");
        return refuse('STS-OAUTH-0744', clientId + ' said aud_sub_required, ' +
          'and no aud_sub is recorded for ' + username + ' there (#148).');
      }
      if (/_async$/.test(cmd)) {
        fields.callbackToken = this.mintCallback({
          purpose: 'result', clientId: String(clientId), command: cmd,
          sub: sub, username: String(username) });
      }
      if (cmd.replace(/_async$/, '') === 'migrate') {
        fields.authenticationProvider = String(o.authenticationProvider ||
                                               fields.iss);
      }
    } else {
      fields.opMetadata = this.opMetadata();
      fields.callbackToken = this.mintCallback({
        purpose: 'refresh', clientId: String(clientId), command: cmd });
    }
    const queued = this.outbox.queue(fields);
    this.outbox.dispatch([queued.row]).catch(function (e) {
      log.debug("Caught in ProviderCommands.send(): " +
                ((e && e.message) || e));
    });
    log.debug("Leaving ProviderCommands.send(). Queued " + queued.row.id);
    return { ok: true, row: this.outbox.view(queued.row),
             message: 'The ' + cmd + ' command to ' + clientId + ' was ' +
                      'queued; it is sent after this answer, and the list ' +
                      'shows what the relying party said.' };
  }

  // -------------------------------------------------------------------------
  // A TENANT COMMAND WHOSE ANSWER IS A STREAM (section 7): a run row, then
  // the stream read in the background. `{ ok, run }` or a refusal.
  // -------------------------------------------------------------------------
  startTenant(clientId: string, command: string, opts?: Json): Json {
    const { log, applications, errorCodes, realms, now, randomId,
            audit } = this.deps;
    const self = this;
    log.debug("Entering ProviderCommands.startTenant(). " + command);
    const o = opts || {};
    const cmd = String(command || '');
    if (cmd === 'metadata') {
      log.debug("Leaving ProviderCommands.startTenant(). Metadata.");
      return this.send(clientId, cmd, '', o);
    }
    if (!this.enabled() || STREAM_COMMANDS.indexOf(cmd) < 0) {
      log.debug("Leaving ProviderCommands.startTenant(). Refused.");
      return errorCodes.mark({ ok: false, message: !this.enabled()
        ? 'OpenID Provider Commands are off in this realm ' +
          '(oauth2.providerCommands).'
        : 'Unknown tenant command "' + cmd + '". The ' +
          TENANT_COMMANDS.length + ' are: ' + TENANT_COMMANDS.join(', ') +
          '.' }, 'STS-OAUTH-0744');
    }
    const endpoint = applications.commandEndpointOf(clientId);
    if (!endpoint) {
      log.debug("Leaving ProviderCommands.startTenant(). No endpoint.");
      return errorCodes.mark({ ok: false, message: 'Client "' + clientId +
        '" registered no command_endpoint.' }, 'STS-OAUTH-0744');
    }
    const run: Json = {
      id: randomId(16), realm: realms.currentId(), clientId: String(clientId),
      uri: endpoint, command: cmd, tenant: String(realms.currentId() ||
                                                  'default'),
      iss: this.issuer(o.base), actor: String(o.actor || ''),
      state: 'running', events: 0, accounts: 0, totalAccounts: null,
      lastEventId: '', resumes: 0, errors: [], why: '', startedAt: now(),
      finishedAt: 0, jti: randomId(16), holder: outbound.HOLDER
    };
    if (cmd === 'audit_tenant') {
      run.callbackToken = this.mintCallback({ purpose: 'refresh',
        clientId: String(clientId), command: cmd });
    }
    runs.set(run.id, run);
    const realm = realms.current();
    setImmediate(function () {
      realms.run(realm, function () {
        return self.executeRun(run.id).catch(function (e) {
          log.debug("Caught in ProviderCommands.startTenant(): " +
                    ((e && e.message) || e));
        });
      });
    });
    audit.audit({
      action: 'oauth2.command.tenant', actor: run.actor,
      protocol: 'OAuth 2.0 / OIDC', channel: 'http', target: run.clientId,
      summary: 'the tenant command ' + cmd + ' was started for ' +
               run.clientId, detail: { run: run.id, command: cmd }
    });
    log.debug("Leaving ProviderCommands.startTenant(). " + run.id);
    return { ok: true, run: this.runView(run),
             message: 'The ' + cmd + ' command to ' + clientId + ' is ' +
                      'running; the list shows each account as the ' +
                      'relying party reports it.' };
  }

  // THE STREAM of one run, resumed with Last-Event-ID when it drops.
  async executeRun(id: string): Promise<Json> {
    const { log, fedHttp, now, signJwtAsAsync, applications,
            errorCodes } = this.deps;
    const self = this;
    log.debug("Entering ProviderCommands.executeRun(). " + id);
    const run: Json = runs.get(id);
    if (!run || run.state !== 'running') {
      log.debug("Leaving ProviderCommands.executeRun(). Not running.");
      return run;
    }
    const save = function (): void {
      runs.set(run.id, Object.assign({}, run));
    };
    const fail = function (code: string, why: string): Json {
      log.debug("Entering fail(). " + code);
      run.state = 'failed';
      run.errorCode = code;
      run.why = why;
      run.finishedAt = now();
      save();
      log.warn(errorCodes.tag(code) + 'provider commands: the ' +
               run.command + ' run to ' + run.clientId + ' failed: ' + why);
      log.debug("Leaving fail().");
      return run;
    };
    if (!run.iss) {
      log.debug("Leaving ProviderCommands.executeRun(). No issuer.");
      return fail('STS-OAUTH-0735', 'no issuer is known for this realm');
    }
    const registered: Json = applications.registrationOf(run.clientId) || {};
    const alg = String(registered.id_token_signed_response_alg || 'RS256');
    const maxResumes = this.setting('oauth2.commandStreamResumes');
    let token = '';
    let tokenExp = 0;
    for (;;) {
      if (!token || tokenExp - 5 <= Math.floor(now() / 1000)) {
        try {
          const claims = this.claimsFor(run);
          const signed = await signJwtAsAsync(claims, alg,
            String(registered.client_secret || '') || undefined,
            { header: { typ: TOKEN_TYPE }, certificateHeader: 'id-token',
              session: run.clientId });
          token = signed;
          tokenExp = claims.exp;
        } catch (e) {
          log.debug("Caught in ProviderCommands.executeRun(): " +
                    ((e && e.message) || e));
          log.debug("Leaving ProviderCommands.executeRun(). Not signed.");
          return fail('STS-OAUTH-0727', 'the Command Token could not be ' +
                      'signed: ' + ((e && e.message) || e));
        }
      }
      const record = { id: run.clientId };
      record[ADDRESS_ATTRIBUTE] = run.uri;
      const result: Json = await fedHttp.streamEvents(record,
        ADDRESS_ATTRIBUTE, { command_token: token }, {
          idleMs: this.setting('oauth2.commandStreamIdleMs'),
          maxEvents: this.setting('oauth2.commandStreamMaxEvents'),
          lastEventId: run.lastEventId || undefined,
          onEvent: function (event: Json): void {
            self.onStreamEvent(run, event);
          }
        });
      run.lastEventId = String(result.lastEventId || run.lastEventId || '');
      if (run.state !== 'running') {
        save();
        log.debug("Leaving ProviderCommands.executeRun(). " + run.state);
        return run;
      }
      if (!result.ok && result.status && result.status !== 200) {
        let body: Json = null;
        try {
          body = result.body ? JSON.parse(String(result.body)) : null;
        } catch (e) {
          log.debug("Caught in ProviderCommands.executeRun(): " +
                    ((e && e.message) || e));
          body = null;
        }
        const error = body && body.error ? String(body.error) : '';
        log.debug("Leaving ProviderCommands.executeRun(). HTTP " +
                  result.status);
        return fail(ERROR_CODES[error] ||
                    (error === 'last-event-id-unavailable'
                      ? 'STS-OAUTH-0745' : 'STS-OAUTH-0730'),
                    'the relying party answered ' + result.status +
                    (error ? ' ' + error : ''));
      }
      if (result.ok && !result.ended) {
        // A JSON answer to a streaming command: not section 7.2's.
        log.debug("Leaving ProviderCommands.executeRun(). Not a stream.");
        return fail('STS-OAUTH-0743', 'the answer was not a ' +
                    'text/event-stream');
      }
      // The stream ended, or dropped, without command-complete: resume.
      if (run.resumes >= maxResumes) {
        log.debug("Leaving ProviderCommands.executeRun(). Out of resumes.");
        return fail('STS-OAUTH-0746', 'the stream ended without ' +
                    'command-complete after ' + run.resumes + ' resumption' +
                    (run.resumes === 1 ? '' : 's') + ' (' +
                    String(result.why || 'it closed') + ')');
      }
      run.resumes++;
      save();
      log.debug("ProviderCommands.executeRun(): resuming after " +
                (run.lastEventId || 'nothing') + ".");
    }
  }

  // One event of a run's stream (section 7.2).
  private onStreamEvent(run: Json, event: Json): void {
    const { log, now } = this.deps;
    log.debug("Entering ProviderCommands.onStreamEvent(). " + event.event);
    let data: Json = null;
    try {
      data = JSON.parse(String(event.data || 'null'));
    } catch (e) {
      log.debug("Caught in ProviderCommands.onStreamEvent(): " +
                ((e && e.message) || e));
      data = null;
    }
    run.events++;
    if (event.event === 'account-state' && data && data.sub &&
        STATES.indexOf(String(data.account_state)) >= 0) {
      const held = this.accountFor(run.clientId, String(data.sub));
      this.noteAccount(run.clientId, String(data.sub),
                       held ? held.username : '',
                       String(data.account_state), run.command,
                       data.last_access ? { lastAccess: data.last_access }
                                        : undefined);
      run.accounts++;
    } else if (event.event === 'command-complete') {
      run.totalAccounts = data && Number.isInteger(data.total_accounts)
        ? data.total_accounts : null;
      run.state = 'complete';
      run.finishedAt = now();
    } else if (event.event === 'error') {
      if (run.errors.length < 20) {
        run.errors.push(String((data && data.error_description) ||
                               event.data || '').slice(0, 300));
      }
    }
    if (run.events % 50 === 0 || run.state !== 'running') {
      runs.set(run.id, Object.assign({}, run));
    }
    log.debug("Leaving ProviderCommands.onStreamEvent().");
  }

  runView(run: Json): Json {
    const { log } = this.deps;
    log.debug("Entering ProviderCommands.runView().");
    const iso = function (ms: unknown): string {
      log.debug("Entering iso().");
      log.debug("Leaving iso().");
      return Number(ms) ? new Date(Number(ms)).toISOString() : '';
    };
    log.debug("Leaving ProviderCommands.runView().");
    return { id: run.id, clientId: run.clientId, command: run.command,
             uri: run.uri, state: run.state, events: run.events,
             accounts: run.accounts, totalAccounts: run.totalAccounts,
             resumes: run.resumes, lastEventId: run.lastEventId || '',
             errors: (run.errors || []).slice(0), why: run.why || '',
             errorCode: run.errorCode || '', actor: run.actor || '',
             startedAt: iso(run.startedAt), finishedAt: iso(run.finishedAt) };
  }

  // -------------------------------------------------------------------------
  // THE CALLBACK (section 6.2 and 7.1): Bearer a `callback_token`, a JSON
  // body. `{ status, error?, description?, challenge? }` for the route.
  // -------------------------------------------------------------------------
  acceptCallback(bearer: string, body: Json, base?: string): Json {
    const { log, now } = this.deps;
    log.debug("Entering ProviderCommands.acceptCallback().");
    const key = bearer ? ProviderCommands.digest(bearer) : '';
    const held: Json = key ? callbacks.get(key) : null;
    if (!held || Number(held.expiresAt) <= now()) {
      log.debug("Leaving ProviderCommands.acceptCallback(). Invalid token.");
      return { status: 401, error: 'invalid_token', code: 'STS-OAUTH-0747',
               description: 'The callback token is unknown or expired.' };
    }
    const b = body || {};
    if (held.purpose === 'refresh' && b.command_requested) {
      const asked = String(b.command_requested);
      if (asked !== 'metadata' && asked !== 'audit_tenant') {
        log.debug("Leaving ProviderCommands.acceptCallback(). Unknown ask.");
        return { status: 400, error: 'invalid_request',
                 code: 'STS-OAUTH-0748', description: 'command_requested ' +
                 'must be metadata or audit_tenant.' };
      }
      const started = asked === 'metadata'
        ? this.send(held.clientId, 'metadata', '', { base: base,
            trigger: 'the relying party asked' })
        : this.startTenant(held.clientId, 'audit_tenant', { base: base,
            actor: '', trigger: 'the relying party asked' });
      log.debug("Leaving ProviderCommands.acceptCallback(). Requested " +
                asked);
      return started.ok ? { status: 204 }
        : { status: 400, error: 'invalid_request', code: 'STS-OAUTH-0748',
            description: String(started.message || '') };
    }
    if (held.purpose === 'result' &&
        String(b.sub || '') === String(held.sub) &&
        STATES.indexOf(String(b.account_state)) >= 0) {
      this.noteAccount(held.clientId, held.sub, held.username,
                       String(b.account_state), held.command,
                       { audSub: b.aud_sub ? String(b.aud_sub) : '' });
      // Once: the result is in.
      callbacks.delete(key);
      log.debug("Leaving ProviderCommands.acceptCallback(). A result.");
      return { status: 204 };
    }
    log.debug("Leaving ProviderCommands.acceptCallback(). Malformed.");
    return { status: 400, error: 'invalid_request', code: 'STS-OAUTH-0748',
             description: held.purpose === 'result'
               ? 'An async result names the command\'s sub and an ' +
                 'account_state of ' + STATES.join(', ') + '.'
               : 'This callback token asks for command_requested.' };
  }

  private callbackRoute(req: Req, res: Res): unknown {
    const { log, errorCodes } = this.deps;
    log.debug("Entering ProviderCommands.callbackRoute().");
    res.set('Cache-Control', 'no-store');
    const auth = String(req.headers.authorization || '');
    const bearer = /^Bearer\s+(\S+)$/i.exec(auth);
    let body: Json = (req as Json).body;
    if (typeof body === 'string' || Buffer.isBuffer(body)) {
      try {
        body = JSON.parse(String(body));
      } catch (e) {
        log.debug("Caught in ProviderCommands.callbackRoute(): " +
                  ((e && e.message) || e));
        body = null;
      }
    }
    const answer = this.enabled()
      ? this.acceptCallback(bearer ? bearer[1] : '', body || {},
                            helpers.baseUrlOf(req))
      : { status: 404, error: 'invalid_request', code: 'STS-OAUTH-0744',
          description: 'OpenID Provider Commands are off.' };
    if (answer.status === 204) {
      log.debug("Leaving ProviderCommands.callbackRoute(). 204.");
      res.status(204).end();
      return undefined;
    }
    errorCodes.mark(res, answer.code);
    if (answer.status === 401) {
      res.set('WWW-Authenticate', 'Bearer error="invalid_token", ' +
              'error_description="' + answer.description + '"');
    }
    log.debug("Leaving ProviderCommands.callbackRoute(). " + answer.status);
    res.status(answer.status).json({ error: answer.error,
                                     error_description: answer.description });
    return undefined;
  }

  registerRoutes(app: Json): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering ProviderCommands.registerRoutes().");
    app.post(CALLBACK_PATH, function (req: Req, res: Res) {
      return self.callbackRoute(req, res);
    });
    log.debug("Leaving ProviderCommands.registerRoutes().");
  }

  // -------------------------------------------------------------------------
  // AUTOMATIC COMMANDS (header point 4): `command` for `username` to every
  // relying party that supports it and where the person has an account.
  // Never throws: it is called from inside a directory write.
  // -------------------------------------------------------------------------
  automatic(username: string, command: string, trigger: string): number {
    const { log, config, applications } = this.deps;
    const self = this;
    log.debug("Entering ProviderCommands.automatic(). " + command + " " +
              username);
    let sent = 0;
    try {
      if (!this.enabled() || !config.value('oauth2.commandAutomatic') ||
          !username) {
        log.debug("Leaving ProviderCommands.automatic(). Off.");
        return 0;
      }
      const used = this.clientsIssuedTo(username);
      applications.commandClients().forEach(function (client: Json) {
        const known = self.learnedFor(client.clientId);
        if (!known || known.commandsSupported.indexOf(command) < 0) {
          return;
        }
        const sub = self.subjectFor(client.clientId, username);
        if (!sub) {
          return;
        }
        const held = self.accountFor(client.clientId, sub);
        const allowed = AUTOMATIC_FROM[command] || [];
        const state = held ? String(held.state)
                           : (used[client.clientId] ? 'active' : 'unknown');
        if (allowed.indexOf(state) < 0) {
          return;
        }
        const done = self.send(client.clientId, command, username,
                               { trigger: trigger });
        if (done.ok) {
          sent++;
        }
      });
    } catch (e) {
      log.debug("Caught in ProviderCommands.automatic(): " +
                ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-OAUTH-0749') + 'provider commands: the ' +
               'automatic ' + command + ' for ' + username + ' could not ' +
               'be queued: ' + ((e && e.message) || e));
    }
    log.debug("Leaving ProviderCommands.automatic(). " + sent + " queued.");
    return sent;
  }

  // The clients this person has been issued a token for (the token register).
  private clientsIssuedTo(username: string): Json {
    const { log } = this.deps;
    log.debug("Entering ProviderCommands.clientsIssuedTo().");
    const out: Json = {};
    try {
      const stats = this.deps.stats();
      const key = String(stats.identityKeyOf(username) || username);
      stats.tokenList().forEach(function (record: Json) {
        const who = String(record.username || record.subject || '');
        const client = String(record.clientId || record.client_id || '');
        if (client && who && (who === username ||
            String(stats.identityKeyOf(who) || who) === key)) {
          out[client] = true;
        }
      });
    } catch (e) {
      log.debug("Caught in ProviderCommands.clientsIssuedTo(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving ProviderCommands.clientsIssuedTo(). " +
              Object.keys(out).length);
    return out;
  }

  // THE DIRECTORY'S EVENTS (ldap_server's account observers): a lock set is
  // `suspend`, a lock cleared `reactivate`, a delete `delete`, any other
  // change to the person or their groups `maintain`.
  directoryChanged(change: Json): void {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering ProviderCommands.directoryChanged(). " +
              (change && change.kind));
    if (!change || !change.username || !this.enabled()) {
      log.debug("Leaving ProviderCommands.directoryChanged(). Nothing.");
      return;
    }
    const kind = String(change.kind || '');
    const lock = function (attrs: Json): string {
      const v = (attrs || {}).pwdAccountLockedTime;
      return String((Array.isArray(v) ? v[0] : v) || '');
    };
    let command = '';
    if (kind.indexOf('deleted') === 0) {
      command = 'delete';
    } else if (kind === 'membership') {
      command = 'maintain';
    } else if (kind === 'updated') {
      const was = lock(change.before);
      const now = lock(change.after);
      command = !was && now ? 'suspend' : (was && !now ? 'reactivate'
                                                        : 'maintain');
    }
    if (!command) {
      log.debug("Leaving ProviderCommands.directoryChanged(). No command.");
      return;
    }
    const realm = realms.get(change.realm) || realms.current();
    realms.run(realm, function () {
      self.automatic(String(change.username), command,
                     'the directory (' + kind + ')');
    });
    log.debug("Leaving ProviderCommands.directoryChanged(). " + command);
  }

  // Become one of the directory's account observers (`addAccountObserver`,
  // beside Shared Signals'). Built after `ldap/ldap_server` (21), whose
  // module is found in the cache and never required from here.
  observeDirectory(): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering ProviderCommands.observeDirectory().");
    const directory = this.deps.directory();
    if (!directory || typeof directory.addAccountObserver !== 'function') {
      log.debug("Leaving ProviderCommands.observeDirectory(). No directory.");
      return;
    }
    directory.addAccountObserver(function (change: Json): void {
      self.directoryChanged(change);
    });
    log.debug("Leaving ProviderCommands.observeDirectory().");
  }

  // An administrator's global sign-out of a person: `invalidate`.
  personSignedOut(username: string): void {
    const { log } = this.deps;
    log.debug("Entering ProviderCommands.personSignedOut().");
    this.automatic(String(username || ''), 'invalidate',
                   'a global sign-out of the person');
    log.debug("Leaving ProviderCommands.personSignedOut().");
  }

  // The retention work of a realm's sweep: expired callback tokens, and
  // finished runs past the delivery retention.
  private sweepRealm(): Json {
    const { log, now } = this.deps;
    log.debug("Entering ProviderCommands.sweepRealm().");
    const at = now();
    const keepMs = this.setting('oauth2.commandRetentionS') * 1000;
    let dropped = 0;
    const gone: string[] = [];
    callbacks.forEach(function (row: Json, key: string) {
      if (!row || Number(row.expiresAt) <= at) {
        gone.push(key);
      }
    });
    gone.forEach(function (key) {
      callbacks.delete(key);
      dropped++;
    });
    const old: string[] = [];
    runs.forEach(function (run: Json, key: string) {
      if (run && run.state !== 'running' &&
          at - Number(run.finishedAt || run.startedAt) > keepMs) {
        old.push(key);
      }
    });
    old.forEach(function (key) {
      runs.delete(key);
      dropped++;
    });
    log.debug("Leaving ProviderCommands.sweepRealm(). " + dropped);
    return { callbacksAndRunsDropped: dropped };
  }

  scheduleSweep(): void {
    const { log } = this.deps;
    log.debug("Entering ProviderCommands.scheduleSweep().");
    this.outbox.scheduleSweep();
    log.debug("Leaving ProviderCommands.scheduleSweep().");
  }

  sweep(): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering ProviderCommands.sweep().");
    log.debug("Leaving ProviderCommands.sweep().");
    return this.outbox.sweep();
  }

  retryDelivery(id: string, actor?: string): Json {
    const { log } = this.deps;
    log.debug("Entering ProviderCommands.retryDelivery(). " + id);
    const done = this.outbox.retry(id, actor || '', 'OpenID Provider Command',
      { jti: '', token: '', tokenExp: 0, accountState: '',
        awaitingCallback: false });
    log.debug("Leaving ProviderCommands.retryDelivery(). " + done.ok);
    return done.ok ? { ok: true, row: this.outbox.view(done.row),
                       message: 'The ' + done.row.command + ' command to ' +
                         done.row.clientId + ' was queued again.' }
                   : done;
  }

  // -------------------------------------------------------------------------
  // WHAT THE CONSOLE AND /admin-api SHOW: every client with a command
  // endpoint and what it said, the register, the deliveries and the runs.
  // -------------------------------------------------------------------------
  report(options?: Json): Json {
    const { log, applications, config } = this.deps;
    const self = this;
    log.debug("Entering ProviderCommands.report().");
    const o = options || {};
    const accountRows: Json[] = [];
    accounts.forEach(function (row: Json) {
      if (row && (!o.clientId || row.clientId === o.clientId)) {
        accountRows.push(Object.assign({}, row, {
          updatedAt: row.updatedAt ? new Date(row.updatedAt).toISOString()
                                   : '' }));
      }
    });
    accountRows.sort(function (a, b) {
      return String(b.updatedAt).localeCompare(String(a.updatedAt));
    });
    const runRows: Json[] = [];
    runs.forEach(function (run: Json) {
      if (run) {
        runRows.push(self.runView(run));
      }
    });
    runRows.sort(function (a, b) {
      return String(b.startedAt).localeCompare(String(a.startedAt));
    });
    const out = {
      enabled: this.enabled(),
      automatic: !!config.value('oauth2.commandAutomatic'),
      issuer: this.issuer(),
      clients: applications.commandClients().map(function (c: Json) {
        const known = self.learnedFor(c.clientId);
        return { clientId: c.clientId, name: c.name, endpoint: c.endpoint,
                 learned: known ? {
                   commandsSupported: known.commandsSupported,
                   audSubRequired: known.audSubRequired, roles: known.roles,
                   learnedAt: new Date(known.learnedAt).toISOString() }
                   : null };
      }),
      accounts: accountRows.slice(0, Number(o.limit) || 500),
      deliveries: this.outbox.rows({ state: o.state, q: o.q })
        .slice(0, Number(o.limit) || 500)
        .map(function (row: Json) {
          return self.outbox.view(row);
        }),
      counts: this.outbox.counts(),
      runs: runRows.slice(0, 100),
      accountCommands: ACCOUNT_COMMANDS.slice(0),
      tenantCommands: TENANT_COMMANDS.slice(0)
    };
    log.debug("Leaving ProviderCommands.report().");
    return out;
  }

  deliveryRows(options?: Json): Json[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering ProviderCommands.deliveryRows().");
    log.debug("Leaving ProviderCommands.deliveryRows().");
    return this.outbox.rows(options).map(function (row: Json) {
      return self.outbox.view(row);
    });
  }

  deliveryCounts(): Json {
    const { log } = this.deps;
    log.debug("Entering ProviderCommands.deliveryCounts().");
    log.debug("Leaving ProviderCommands.deliveryCounts().");
    return this.outbox.counts();
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). The wire step
// registers the sweep's scheduler job and becomes a directory observer.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<ProviderCommands>(
  'oauth-oidc/provider_commands',
  () => new ProviderCommands(ProviderCommands.defaultDeps()),
  function (instance: ProviderCommands): void {
    instance.scheduleSweep();
    instance.observeDirectory();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  ProviderCommands: ProviderCommands,
  installInstance: (instance: ProviderCommands): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  TOKEN_TYPE: TOKEN_TYPE,
  ACCOUNT_COMMANDS: ACCOUNT_COMMANDS,
  TENANT_COMMANDS: TENANT_COMMANDS,
  STREAM_COMMANDS: STREAM_COMMANDS,
  STATES: STATES,
  CALLBACK_PATH: CALLBACK_PATH,
  SWEEP_JOB: SWEEP_JOB,
  isAccountCommand: ProviderCommands.isAccountCommand,
  enabled: slot.forward('enabled'),
  issuer: slot.forward('issuer'),
  subjectFor: slot.forward('subjectFor'),
  learnedFor: slot.forward('learnedFor'),
  accountFor: slot.forward('accountFor'),
  opMetadata: slot.forward('opMetadata'),
  claimsFor: slot.forward('claimsFor'),
  signedToken: slot.forward('signedToken'),
  send: slot.forward('send'),
  startTenant: slot.forward('startTenant'),
  executeRun: slot.forward('executeRun'),
  acceptCallback: slot.forward('acceptCallback'),
  registerRoutes: slot.forward('registerRoutes'),
  automatic: slot.forward('automatic'),
  directoryChanged: slot.forward('directoryChanged'),
  personSignedOut: slot.forward('personSignedOut'),
  sweep: slot.forward('sweep'),
  retryDelivery: slot.forward('retryDelivery'),
  report: slot.forward('report'),
  deliveryRows: slot.forward('deliveryRows'),
  deliveryCounts: slot.forward('deliveryCounts'),
  runView: slot.forward('runView')
};
