'use strict';
//
// File: command_mock_rp.ts
//
// ===========================================================================
// A MOCK RELYING PARTY'S COMMAND ENDPOINT (#151, answer 5a) —
// `POST /oauth2/commands/mock-rp`. NON-SPEC, and here for WS-Federation's
// mock relying party's reason: it makes OpenID Provider Commands testable
// from one service. A client registered with this address as its
// `command_endpoint` is a relying party that answers every command the way
// section 3 to 7 say one does.
//
// **WHAT IT CHECKS, as a relying party must (section 9)**: the Command
// Token's signature (this realm's own keys — it is in the same process), the
// header `typ: command+jwt`, `iss` (this realm's issuer at the address the
// request reached — `unrecognized_provider` otherwise), `exp`, `jti` once,
// no `nonce`, `aud` equal to `client_id`, `tenant` present, `sub` only in an
// account command, `metadata` only in `metadata`, `authentication_provider`
// only in `migrate`.
//
// **WHAT IT KEEPS**: an account state per (client, sub) in a per-realm store
// of its own, moved by section 6's table — `incompatible_state` (409) where
// the table says so — and an `aud_sub` it invents for each account and
// returns, so the provider learns one.
//
// **ASYNC AND STREAMS**: an `_async` command is answered 202 and its result
// handed to the provider's callback IN PROCESS (`acceptCallback()`, with the
// token's own `callback_token`) — the mock is the provider's own test
// double, and a loopback HTTP request would test nothing the unit tests do
// not. A streaming tenant command answers `text/event-stream`: an
// `account-state` event per account, then `command-complete`, event ids
// `1`, `2`, … and `Last-Event-ID` honoured.
//
// **TEST KNOBS ON THE REGISTERED URL'S QUERY**: `?fail=N` answers 503 to the
// first N requests (a retry test), `?drop=K` closes a stream after K events
// once (a resumption test), `?audsub=1` says `aud_sub_required`.
//
// **OFF IN PRODUCT** (`mode.opensTestControls()`): a 404.
// ===========================================================================

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import realms = require('../common/realms');
import mode = require('../common/mode');
import errorCodes = require('../common/error_codes');

type Json = any;
type Req = import('express').Request;
type Res = import('express').Response;

const MOCK_PATH = '/oauth2/commands/mock-rp';

// Per realm: the mock's accounts, `jti`s seen, and its test knobs' counters.
const mockAccounts = realms.map({ persist: 'oauth2.commandMockAccounts' });
const seenJtis = realms.map({ persist: 'oauth2.commandMockJtis',
                              retain: 'age' });
const knobs = realms.map({ persist: 'oauth2.commandMockKnobs' });

// Section 6's table: the states each command may start from, and where it
// leaves the account ('' — unchanged).
const TABLE = {
  activate: { from: ['unknown'], to: 'active' },
  maintain: { from: ['active'], to: 'active' },
  suspend: { from: ['active'], to: 'suspended' },
  reactivate: { from: ['suspended'], to: 'active' },
  archive: { from: ['active', 'suspended'], to: 'archived' },
  restore: { from: ['archived'], to: 'active' },
  delete: { from: ['active', 'suspended', 'archived'], to: 'unknown' },
  audit: { from: null, to: '' },
  invalidate: { from: ['active'], to: 'active' },
  migrate: { from: null, to: '' }
};

// What a streaming tenant command does to every account.
const TENANT_MOVES = {
  audit_tenant: null,
  suspend_tenant: { from: ['active'], to: 'suspended' },
  archive_tenant: { from: ['active', 'suspended'], to: 'archived' },
  delete_tenant: { from: ['active', 'suspended', 'archived'], to: 'unknown' },
  invalidate_tenant: null
};

interface MockDeps {
  log: typeof helpers.log;
  realms: typeof realms;
  mode: typeof mode;
  errorCodes: typeof errorCodes;
  now: () => number;
  // Lazily: the provider this mock answers.
  commands: () => Json;
}

class CommandMockRp {
  static readonly MOCK_PATH = MOCK_PATH;

  constructor(private readonly deps: MockDeps) {
    deps.log.debug("Entering CommandMockRp.constructor().");
    deps.log.debug("Leaving CommandMockRp.constructor().");
  }

  static defaultDeps(): MockDeps {
    helpers.log.debug("Entering CommandMockRp.defaultDeps().");
    helpers.log.debug("Leaving CommandMockRp.defaultDeps().");
    return { log: helpers.log, realms: realms, mode: mode,
             errorCodes: errorCodes,
             now: function (): number {
               return Date.now();
             },
             commands: function (): Json {
               return require('./provider_commands');
             } };
  }

  // The aud_sub this mock gives an account: stable, and not the sub.
  static audSubOf(clientId: string, sub: string): string {
    helpers.log.debug("Entering CommandMockRp.audSubOf().");
    helpers.log.debug("Leaving CommandMockRp.audSubOf().");
    return 'rp-' + nodeCrypto.createHash('sha256')
      .update(String(clientId) + '\n' + String(sub)).digest('hex')
      .slice(0, 16);
  }

  private stateOf(clientId: string, sub: string): string {
    const { log } = this.deps;
    log.debug("Entering CommandMockRp.stateOf().");
    const held = mockAccounts.get(String(clientId) + ' ' + String(sub));
    log.debug("Leaving CommandMockRp.stateOf().");
    return held ? String(held.state) : 'unknown';
  }

  private setState(clientId: string, sub: string, state: string,
                   claims?: Json): void {
    const { log, now } = this.deps;
    log.debug("Entering CommandMockRp.setState(). " + state);
    const key = String(clientId) + ' ' + String(sub);
    if (state === 'unknown') {
      mockAccounts.delete(key);
    } else {
      const held = mockAccounts.get(key) || {};
      mockAccounts.set(key, Object.assign({}, held, {
        clientId: String(clientId), sub: String(sub), state: state,
        claims: claims || held.claims || {}, lastAccess: now() }));
    }
    log.debug("Leaving CommandMockRp.setState().");
  }

  // One of the query's knobs, counted down once per request that uses it.
  private knob(req: Req, name: string): number {
    const { log } = this.deps;
    log.debug("Entering CommandMockRp.knob(). " + name);
    const asked = Number((req.query as Json)[name]) || 0;
    if (!asked) {
      log.debug("Leaving CommandMockRp.knob(). Not asked.");
      return 0;
    }
    const key = name + ' ' + String(req.originalUrl || req.url);
    const used = Number(knobs.get(key) || 0);
    log.debug("Leaving CommandMockRp.knob().");
    return used < asked ? asked : 0;
  }

  private spendKnob(req: Req, name: string): void {
    const { log } = this.deps;
    log.debug("Entering CommandMockRp.spendKnob(). " + name);
    const key = name + ' ' + String(req.originalUrl || req.url);
    knobs.set(key, Number(knobs.get(key) || 0) + 1);
    log.debug("Leaving CommandMockRp.spendKnob().");
  }

  private error(res: Res, status: number, error: string, description: string,
                extra?: Json): unknown {
    const { log, errorCodes } = this.deps;
    log.debug("Entering CommandMockRp.error(). " + error);
    errorCodes.mark(res, 'STS-OAUTH-0750');
    res.set('Cache-Control', 'no-store');
    log.debug("Leaving CommandMockRp.error().");
    return res.status(status).json(Object.assign({ error: error,
      error_description: description }, extra || {}));
  }

  // -------------------------------------------------------------------------
  // THE COMMAND ENDPOINT.
  // -------------------------------------------------------------------------
  private handle(req: Req, res: Res): unknown {
    const { log, mode, now } = this.deps;
    const self = this;
    log.debug("Entering CommandMockRp.handle().");
    if (!mode.opensTestControls()) {
      log.debug("Leaving CommandMockRp.handle(). Product.");
      return this.error(res, 404, 'invalid_request', 'The mock relying ' +
                        'party is a development test control.');
    }
    if (this.knob(req, 'fail')) {
      this.spendKnob(req, 'fail');
      log.debug("Leaving CommandMockRp.handle(). A 503, as asked.");
      res.set('Cache-Control', 'no-store');
      this.deps.errorCodes.mark(res, 'STS-OAUTH-0750');
      res.status(503).json({ error: 'temporarily_unavailable' });
      return undefined;
    }
    const body: Json = helpers.parseBody(req) || {};
    const token = String(body.command_token || '');
    if (!token) {
      log.debug("Leaving CommandMockRp.handle(). No command_token.");
      return this.error(res, 400, 'invalid_request', 'command_token is ' +
                        'required (section 3).');
    }
    let verified: Json = null;
    try {
      // The algorithms named, never taken from the token (RFC 8725 section
      // 3.1): the asymmetric ones a relying party verifies with the keys.
      verified = helpers.verifyOwnCompactJws(token, {
        algorithms: require('../common/crypto').JWS_ASYMMETRIC_ALGS });
    } catch (e) {
      log.debug("Caught in CommandMockRp.handle(): " +
                ((e && e.message) || e));
      log.debug("Leaving CommandMockRp.handle(). Signature.");
      return this.error(res, 400, 'invalid_request', 'The Command Token ' +
                        'does not verify: ' + ((e && e.message) || e));
    }
    const header = verified.header || {};
    const c = verified.claims || {};
    const cmd = String(c.command || '');
    const commands = this.deps.commands();
    const isAccount = commands.isAccountCommand(cmd);
    const expected = commands.issuer(helpers.baseUrlOf(req));
    const problem =
      header.typ !== 'command+jwt' ? 'typ is not command+jwt' :
      !(Number(c.exp) > Math.floor(now() / 1000)) ? 'the token expired' :
      c.nonce !== undefined ? 'a Command Token carries no nonce' :
      !c.jti ? 'no jti' :
      c.aud !== c.client_id ? 'aud is not client_id' :
      !c.tenant ? 'no tenant' :
      isAccount && !c.sub ? 'an account command names a sub' :
      !isAccount && (c.sub !== undefined || c.aud_sub !== undefined)
        ? 'a tenant command names no sub or aud_sub' :
      (cmd === 'metadata') !== (c.metadata !== undefined)
        ? 'metadata is in the metadata command and nowhere else' :
      (cmd.replace(/_async$/, '') === 'migrate') !==
        (c.authentication_provider !== undefined)
        ? 'authentication_provider is in migrate and nowhere else' : null;
    if (c.iss !== expected) {
      log.debug("Leaving CommandMockRp.handle(). An unknown issuer.");
      return this.error(res, 401, 'unrecognized_provider', 'This relying ' +
                        'party does not know the issuer "' + String(c.iss) +
                        '" (it expected ' + expected + ').');
    }
    if (problem) {
      log.debug("Leaving CommandMockRp.handle(). " + problem);
      return this.error(res, 400, 'invalid_request', problem + '.');
    }
    if (seenJtis.get(String(c.jti)) && !req.headers['last-event-id']) {
      log.debug("Leaving CommandMockRp.handle(). A replay.");
      return this.error(res, 400, 'invalid_request', 'jti ' + c.jti +
                        ' was already used.');
    }
    seenJtis.set(String(c.jti), { at: now() });
    const clientId = String(c.client_id);
    if (cmd === 'metadata') {
      log.debug("Leaving CommandMockRp.handle(). Metadata.");
      res.set('Cache-Control', 'no-store');
      res.status(200).json({
        context: { iss: c.iss, tenant: c.tenant },
        commands_supported: Object.keys(TABLE)
          .concat(Object.keys(TABLE).map(function (k) {
            return k + '_async';
          })).concat(['metadata']).concat(Object.keys(TENANT_MOVES)),
        command_endpoint: helpers.baseUrlOf(req) + MOCK_PATH,
        client_id: clientId,
        aud_sub_required: String((req.query as Json).audsub || '') === '1',
        roles: [{ id: 'reader', display: 'Reader' },
                { id: 'editor', display: 'Editor',
                  description: 'May change things' }]
      });
      return undefined;
    }
    if (Object.prototype.hasOwnProperty.call(TENANT_MOVES, cmd)) {
      log.debug("Leaving CommandMockRp.handle(). A stream.");
      return this.stream(req, res, clientId, cmd);
    }
    const base = cmd.replace(/_async$/, '');
    const rule = TABLE[base];
    if (!rule) {
      log.debug("Leaving CommandMockRp.handle(). Unsupported.");
      return this.error(res, 400, 'unsupported_command', '"' + cmd +
                        '" is not a command this relying party supports.');
    }
    const sub = String(c.sub);
    const before = this.stateOf(clientId, sub);
    if (rule.from && rule.from.indexOf(before) < 0) {
      log.debug("Leaving CommandMockRp.handle(). Incompatible.");
      return this.error(res, 409, 'incompatible_state', 'The account is ' +
                        before + '; ' + base + ' needs ' +
                        rule.from.join(' or ') + '.',
                        { sub: sub, account_state: before });
    }
    if (rule.to) {
      const claims: Json = {};
      ['email', 'name', 'given_name', 'family_name', 'preferred_username']
        .forEach(function (k) {
          if (c[k] !== undefined) {
            claims[k] = c[k];
          }
        });
      this.setState(clientId, sub, rule.to, claims);
    }
    const after = this.stateOf(clientId, sub);
    const answer: Json = { sub: sub, account_state: after };
    if (after !== 'unknown') {
      answer.aud_sub = CommandMockRp.audSubOf(clientId, sub);
    }
    res.set('Cache-Control', 'no-store');
    if (/_async$/.test(cmd)) {
      // Section 6.2: 202 now, the result through the callback after.
      const realm = this.deps.realms.current();
      const callbackToken = String(c.callback_token || '');
      setImmediate(function () {
        self.deps.realms.run(realm, function () {
          commands.acceptCallback(callbackToken, answer);
        });
      });
      log.debug("Leaving CommandMockRp.handle(). 202.");
      res.status(202).end();
      return undefined;
    }
    log.debug("Leaving CommandMockRp.handle(). " + after);
    res.status(200).json(answer);
    return undefined;
  }

  // A streaming tenant command (section 7.2), resumable by Last-Event-ID.
  private stream(req: Req, res: Res, clientId: string, cmd: string): unknown {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CommandMockRp.stream(). " + cmd);
    const move = TENANT_MOVES[cmd];
    const rows: Json[] = [];
    mockAccounts.forEach(function (row: Json) {
      if (row && row.clientId === clientId) {
        rows.push(row);
      }
    });
    rows.sort(function (a, b) {
      return String(a.sub).localeCompare(String(b.sub));
    });
    const after = Number(req.headers['last-event-id'] || 0) || 0;
    const drop = this.knob(req, 'drop');
    if (drop) {
      this.spendKnob(req, 'drop');
    }
    res.set('Content-Type', 'text/event-stream');
    res.set('Cache-Control', 'no-cache');
    res.status(200);
    let sent = 0;
    let n = 0;
    for (const row of rows) {
      n++;
      if (n <= after) {
        continue;
      }
      if (move && move.from.indexOf(String(row.state)) >= 0) {
        self.setState(clientId, row.sub, move.to);
      }
      const state = self.stateOf(clientId, row.sub);
      res.write('id: ' + n + '\nevent: account-state\ndata: ' +
                JSON.stringify({ sub: row.sub, account_state: state }) +
                '\n\n');
      sent++;
      if (drop && sent >= drop) {
        log.debug("Leaving CommandMockRp.stream(). Dropped, as asked.");
        res.end();
        return undefined;
      }
    }
    res.write('id: ' + (n + 1) + '\nevent: command-complete\ndata: ' +
              JSON.stringify({ total_accounts: rows.length }) + '\n\n');
    res.end();
    log.debug("Leaving CommandMockRp.stream(). " + sent + " event(s).");
    return undefined;
  }

  // The mock's accounts, for a test to read.
  accountsOf(clientId: string): Json[] {
    const { log } = this.deps;
    log.debug("Entering CommandMockRp.accountsOf().");
    const out: Json[] = [];
    mockAccounts.forEach(function (row: Json) {
      if (row && row.clientId === String(clientId)) {
        out.push({ sub: row.sub, state: row.state, claims: row.claims });
      }
    });
    log.debug("Leaving CommandMockRp.accountsOf(). " + out.length);
    return out;
  }

  registerRoutes(app: Json): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CommandMockRp.registerRoutes().");
    app.post(MOCK_PATH, function (req: Req, res: Res) {
      return self.handle(req, res);
    });
    // What the mock holds, for a test (development only, as the endpoint).
    app.get(MOCK_PATH, function (req: Req, res: Res) {
      if (!self.deps.mode.opensTestControls()) {
        return self.error(res, 404, 'invalid_request', 'The mock relying ' +
                          'party is a development test control.');
      }
      res.set('Cache-Control', 'no-store');
      return res.json({ accounts: self.accountsOf(
        String((req.query as Json).client_id || '')) });
    });
    log.debug("Leaving CommandMockRp.registerRoutes().");
  }
}

const slot = new InstanceSlot<CommandMockRp>(
  'oauth-oidc/command_mock_rp',
  () => new CommandMockRp(CommandMockRp.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  CommandMockRp: CommandMockRp,
  installInstance: (instance: CommandMockRp): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  MOCK_PATH: MOCK_PATH,
  audSubOf: CommandMockRp.audSubOf,
  registerRoutes: slot.forward('registerRoutes'),
  accountsOf: slot.forward('accountsOf')
};
