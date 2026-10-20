// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_api.ts
//
// ---------------------------------------------------------------------------
// `/account-api`: THE USER PORTAL'S ONLY DOOR (#568, 2026-10-12).
//
// The portal became a static application in the browser on #568, on the
// admin console's pattern (#446): a PUBLIC client, `sts-user-portal`, that
// signs in with PKCE, holds its tokens in memory bound to a DPoP key it
// cannot export, and draws every page from an answer of this API and sends
// every form here. `rust/DESIGN.md` section 5.2 planned this API as
// `/account-api`; rcbj's decisions on #568 are that it is that, and built on
// the Node service now.
//
// THREE THINGS ARE THIS FILE'S, AND NOTHING ELSE IS:
//
//   * THE GATE. An operation marked `person` takes an OAuth 2.0 access token
//     issued by THIS realm's authorization server to a client that declares
//     `account:manage`, audienced to this realm's `/account-api`, DPoP-bound
//     and presented with its proof, whose sign-on session is still live and
//     whose person is not disabled — and then the access policy is asked,
//     as the server-rendered portal asked it (`user-portal`, `read` or
//     `manage-own`, the owner the subject). **THE PERSON IS THE TOKEN'S
//     SUBJECT AND NOTHING ELSE**: no operation takes a username, an id or a
//     DN naming whose account it acts on — the portal's rule (OWASP A01,
//     `portal/CLAUDE.md`), held now at the API.
//   * THE TABLE. Each operation is contributed by the module that owns the
//     page it is the door of (`PROVIDERS`), declares the zod schemas its
//     query and body are checked against, and names the portal page or form
//     it mirrors — rule 7's twin: a portal control has an operation here.
//     The wrapper checks the schemas before a handler runs, so a handler
//     reads values that already passed them.
//   * THE DOCUMENT. `GET /account-api/openapi.json`, built from the same
//     table by `account_api_spec.ts`, and `GET /account-api`, the index.
//
// AN OPERATION MARKED `link` takes no token: it spends the single-use secret
// of an activation or reset link it carries, exactly as those pages did. One
// marked `public` takes nothing and spends nothing (the index, the document,
// the forgot-password form and the language data a page for nobody is drawn
// in).
//
// PER REALM, as the portal always was: the token is verified with the
// AMBIENT realm's key and must name the ambient realm's issuer and API. A
// person in `acme` has `acme`'s portal and `acme`'s account API, and a token
// from another realm is believed in neither (STS-ACCOUNT-0002).
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import validation = require('../common/validation');
import websecurity = require('../common/websecurity');
import accessGate = require('../common/access_gate');
import i18n = require('../common/i18n');
import PageLocale = require('../common/page_locale');
import version = require('../common/version');
import mode = require('../common/mode');
import AccountApiSpec = require('./account_api_spec');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountCaller = import('../types/account-api').AccountCaller;
type AccountContext = import('../types/account-api').AccountContext;

/**
 * The account API's base path.
 */
const BASE = '/account-api';
const PORTAL = '/portal';
/**
 * The one scope this API takes.
 */
const SCOPE = 'account:manage';
/**
 * The portal's client.
 */
const PORTAL_CLIENT = 'sts-user-portal';

// WHO CONTRIBUTES OPERATIONS, in the order the portal's column lists their
// pages. Each module exports `accountOperations(ctx)`; each is required when
// the table is built, which is when the routes are registered — after every
// one of them was built by the composition root.
const PROVIDERS: Array<() => Json> = [
  function () {
    return require('../portal/account_overview');
  },
  function () {
    return require('../portal/portal_sign_ins');
  },
  function () {
    return require('../portal/portal_consents');
  },
  function () {
    return require('../portal/portal_gnap');
  },
  function () {
    return require('../portal/portal_mail');
  },
  // #604: Resources I own, the section after Your account.
  function () {
    return require('../portal/portal_owned');
  },
  function () {
    return require('../portal/account_password');
  },
  function () {
    return require('../portal/account_keys');
  },
  function () {
    return require('../portal/account_mfa');
  },
  function () {
    return require('../portal/account_signing_key');
  },
  function () {
    return require('../portal/portal_certificates');
  },
  function () {
    return require('../portal/portal_app_passwords');
  },
  function () {
    return require('../portal/portal_kerberos');
  },
  function () {
    return require('../portal/portal_delegate');
  },
  function () {
    return require('../portal/portal_self_issued');
  },
  // #589: /portal/wallet, a credential about the person into their wallet.
  function () {
    return require('../portal/portal_wallet');
  },
  function () {
    return require('../portal/portal_devices');
  },
  function () {
    return require('../portal/portal_ciba');
  },
  function () {
    return require('../portal/portal_device');
  },
  function () {
    return require('../portal/portal_claim_sources');
  },
  // #565: /portal/connected-accounts, a consumer provider connected to the
  // person's own account.
  function () {
    return require('../portal/portal_connected_accounts');
  },
  function () {
    return require('../portal/account_activation');
  },
  function () {
    return require('../portal/account_reset');
  }
];

interface AccountApiDeps {
  log: typeof helpers.log;
  config: typeof config;
  realms: typeof realms;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  validation: typeof validation;
  websecurity: typeof websecurity;
  accessGate: typeof accessGate;
  parseBody(req: Json): Json;
  baseUrlOf(req: Json): string;
  // The modules the gate asks, each reached when a request arrives: they
  // are built later in the require order than this one (`oauth2` at 9).
  lazy: {
    oauth2(): Json;
    stats(): Json;
    accountState(): Json;
    jwtAccessToken(): Json;
    dpop(): Json;
    senderConstraints(): Json;
    mtls(): Json;
    scopePolicy(): Json;
    applications(): Json;
    authn(): Json;
    // The sign-out model (#722), built second to last (23a).
    logout(): Json;
  };
}

/**
 * The account API: the user portal's only door.
 */
class AccountApi {
  private table: AccountOperation[] | null = null;

  /**
   * Builds the API over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: AccountApiDeps) {
    deps.log.debug("Entering AccountApi.constructor().");
    deps.log.debug("Leaving AccountApi.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): AccountApiDeps {
    helpers.log.debug("Entering AccountApi.defaultDeps().");
    helpers.log.debug("Leaving AccountApi.defaultDeps().");
    return {
      log: helpers.log, config: config, realms: realms,
      errorCodes: errorCodes, audit: audit, validation: validation,
      websecurity: websecurity, accessGate: accessGate,
      parseBody: helpers.parseBody, baseUrlOf: helpers.baseUrlOf,
      lazy: {
        oauth2: function () {
          return require('../oauth-oidc/oauth2');
        },
        stats: function () {
          return require('../common/admin_stats');
        },
        accountState: function () {
          return require('../common/account_state');
        },
        jwtAccessToken: function () {
          return require('../oauth-oidc/jwt_access_token');
        },
        dpop: function () {
          return require('../oauth-oidc/dpop');
        },
        senderConstraints: function () {
          return require('../oauth-oidc/sender_constraints');
        },
        mtls: function () {
          return require('../oauth-oidc/mtls');
        },
        scopePolicy: function () {
          return require('../common/scope_policy');
        },
        applications: function () {
          return require('../common/applications');
        },
        authn: function () {
          return require('../authn/authn');
        },
        logout: function () {
          return require('../logout/logout');
        }
      }
    };
  }

  // -------------------------------------------------------------------------
  // WHAT A PROVIDER IS HANDED.
  // -------------------------------------------------------------------------
  /**
   * The helpers every operation's provider is handed.
   *
   * @returns the context
   */
  context(): AccountContext {
    const { log, config, validation, errorCodes, audit, websecurity,
            accessGate, baseUrlOf, parseBody } = this.deps;
    const self = this;
    log.debug("Entering AccountApi.context().");
    const ctx: AccountContext = {
      BASE: BASE, PORTAL: PORTAL, log: log, validation: validation,
      errorCodes: errorCodes, audit: audit, websecurity: websecurity,
      accessGate: accessGate, config: config, baseUrlOf: baseUrlOf,
      parseBody: parseBody,
      translatorFor: function (username?: string): Json {
        return self.translatorFor(username || '');
      },
      json: function (res: Json, status: number, body: Json): unknown {
        return self.json(res, status, body);
      },
      refuse: function (res: Json, status: number, code: string,
                        errors: string | string[], extra?: Json): unknown {
        // error-code: none — the code is the caller's, passed in `code`.
        return self.refuse(res, status, code, errors, extra);
      },
      endFactorSessions: function (username: string, factor: Json,
                                   what: string): Json {
        return self.endFactorSessions(username, factor, what);
      }
    };
    log.debug("Leaving AccountApi.context().");
    return ctx;
  }

  // THE PORTAL'S TRANSLATOR (#539): the portal's own application, so a
  // locale policy profile naming `sts-user-portal` applies, and the person,
  // whose own language ranks above the browser's.
  /**
   * The translator a person's answers are worded in.
   *
   * @param username - the person, or '' for nobody
   * @returns the translator
   */
  translatorFor(username: string): Json {
    const { log } = this.deps;
    log.debug("Entering AccountApi.translatorFor().");
    const t = PageLocale.forPage({ application: PORTAL_CLIENT,
                                   username: String(username || '') });
    log.debug("Leaving AccountApi.translatorFor(). " + t.locale);
    return t;
  }

  // ---------------------------------------------------------------------------
  // THE SESSIONS A CREDENTIAL THE PERSON REMOVED SIGNED IN (#722): ended
  // through the sign-out model's `endFactorSessions()`, for the portal's
  // three removals — a passkey (`account_keys.ts`), the authenticator app
  // and the emailed second factor (`account_mfa.ts`). HERE, on the context,
  // so the three doors share one call, one initiating entity (`user`: the
  // person removed it) and one sentence. The answer's `sentence` is in the
  // person's language and empty when nothing ended. A sign-out model that
  // cannot be loaded ends nothing (STS-PORTAL-0600) and never undoes the
  // removal, which the caller has already written and signalled.
  // ---------------------------------------------------------------------------
  /**
   * Ends the sessions a credential the person just removed signed in.
   *
   * @param username - the person
   * @param factor - what was removed, as `authn.sessionNamesFactor()` names
   *   it
   * @param what - the credential, in a few words, for the audit row
   * @returns `{ ok, sessionsEnded, failed, sentence }`
   */
  endFactorSessions(username: string, factor: Json, what: string): Json {
    const { log, errorCodes, lazy } = this.deps;
    log.debug("Entering AccountApi.endFactorSessions(). " + username);
    let ended: Json = null;
    try {
      ended = lazy.logout().endFactorSessions(username, factor, {
        actor: username, channel: 'http', initiatingEntity: 'user',
        by: username + ' removing ' + what + ' at /portal' });
    } catch (e) {
      log.error(errorCodes.tag('STS-PORTAL-0600') + 'portal: ' + what +
                ' of "' + username + '" was removed and the sessions it ' +
                'signed in could not be ended: ' + ((e && e.stack) || e));
      ended = null;
    }
    const n = Number((ended && ended.sessionsEnded) || 0);
    const t = this.translatorFor(username);
    const sentence = !n ? ''
      : (n === 1 ? t.text('portal.done.sessionsEndedOne')
                 : t.text('portal.done.sessionsEndedMany', { n: n }));
    log.debug("Leaving AccountApi.endFactorSessions(). " + n + " ended.");
    return { ok: !!ended && ended.ok !== false, sessionsEnded: n,
             failed: ended ? Number(ended.failed || 0) : 0,
             sentence: sentence };
  }

  /**
   * Answers JSON, never stored.
   *
   * @param res - the response
   * @param status - the HTTP status
   * @param body - the answer
   * @returns nothing
   */
  json(res: Json, status: number, body: Json): unknown {
    const { log } = this.deps;
    log.debug("Entering AccountApi.json(). " + status);
    // `no-store` on every answer: this is a person's own account, and it is
    // read from a shared browser as often as not.
    res.status(status).set('Cache-Control', 'no-store')
       .type('application/json').send(JSON.stringify(body));
    log.debug("Leaving AccountApi.json().");
    return undefined;
  }

  /**
   * Answers a refusal: `{ ok: false, errors, ...extra }`, with its code
   * recorded.
   *
   * @param res - the response
   * @param status - the HTTP status
   * @param code - the error code
   * @param errors - what went wrong
   * @param extra - anything else the answer carries (a `view`, a `stepUp`)
   * @returns nothing
   */
  // error-code: none — the code is the caller's, passed in `code`.
  refuse(res: Json, status: number, code: string, errors: string | string[],
         extra?: Json): unknown {
    const { log, errorCodes } = this.deps;
    log.debug("Entering AccountApi.refuse(). " + code);
    errorCodes.mark(res, code);
    const said = Array.isArray(errors) ? errors : [String(errors)];
    log.debug("Leaving AccountApi.refuse().");
    return this.json(res, status, Object.assign({ ok: false, errors: said },
                                                extra || {}));
  }

  // -------------------------------------------------------------------------
  // THE TABLE.
  // -------------------------------------------------------------------------
  /**
   * Every operation: this file's own and every provider's.
   *
   * @returns the table
   */
  operations(): AccountOperation[] {
    const { log } = this.deps;
    log.debug("Entering AccountApi.operations().");
    if (!this.table) {
      const ctx = this.context();
      let rows: AccountOperation[] = this.ownOperations();
      PROVIDERS.forEach(function (load) {
        const mod = load();
        if (mod && typeof mod.accountOperations === 'function') {
          rows = rows.concat(mod.accountOperations(ctx) || []);
        }
      });
      this.table = rows;
    }
    log.debug("Leaving AccountApi.operations(). " + this.table.length);
    return this.table;
  }

  /**
   * The document, for the realm the request is in.
   *
   * @param req - the request
   * @returns the OpenAPI document
   */
  document(req: Json): Json {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering AccountApi.document().");
    const doc = AccountApiSpec.document(this.operations(), {
      baseUrl: baseUrlOf(req), version: version.load().version });
    log.debug("Leaving AccountApi.document().");
    return doc;
  }

  // THE LANGUAGE DATA a page is drawn with in the browser: the portal's
  // catalogs and the chooser's, along the negotiated chain, and the locales
  // the chooser offers — `PageLocale.consoleData()`'s shape, for this
  // application.
  /**
   * The language data for a person, or for nobody.
   *
   * @param username - the person, or ''
   * @returns `{ negotiated, catalogs, offered }`
   */
  localeData(username: string): Json {
    const { log } = this.deps;
    log.debug("Entering AccountApi.localeData().");
    const t = this.translatorFor(username);
    const portal = i18n.catalogData(t.negotiated, 'portal');
    const chooser = i18n.catalogData(t.negotiated, 'chooser');
    const catalogs: Json = {};
    Object.keys(portal.catalogs).forEach(function (tag) {
      catalogs[tag] = Object.assign({}, portal.catalogs[tag],
                                    chooser.catalogs[tag] || {});
    });
    log.debug("Leaving AccountApi.localeData(). " + t.locale);
    return { negotiated: portal.negotiated, catalogs: catalogs,
             offered: i18n.offered() };
  }

  /**
   * The build, as every page's foot says it.
   *
   * @returns `{ version, buildInfo }`
   */
  versionData(): Json {
    const { log } = this.deps;
    log.debug("Entering AccountApi.versionData().");
    const v = version.load();
    log.debug("Leaving AccountApi.versionData().");
    return { version: v.version, buildInfo: version.buildInfo(v) };
  }

  /**
   * This file's own operations: the index, the document, who is signed in
   * and the language data for a page drawn for nobody.
   *
   * @returns the operations
   */
  ownOperations(): AccountOperation[] {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering AccountApi.ownOperations().");
    const z = validation.z;
    const rows: AccountOperation[] = [
      { method: 'GET', path: BASE, operationId: 'getIndex', tag: 'API',
        access: 'public',
        summary: 'Lists every operation of this API',
        description: 'Each operation\'s method, path, access and the portal ' +
          'page or form it is the door of. The portal reads it to know ' +
          'which operation a form goes to.',
        handler: function (req: Json, res: Json): unknown {
          return self.json(res, 200, {
            api: 'IYA STS Account API', document: BASE + '/openapi.json',
            operations: self.operations().map(function (op) {
              return { method: op.method, path: op.path,
                       operationId: op.operationId, tag: op.tag,
                       access: op.access, mirrors: op.mirrors || null,
                       summary: op.summary };
            }) });
        } },
      { method: 'GET', path: BASE + '/openapi.json',
        operationId: 'getOpenApi', tag: 'API', access: 'public',
        summary: 'This API\'s OpenAPI 3.1 document',
        description: 'Built from the operation table at the moment it is ' +
          'asked, for the realm it is asked in. It carries no secret.',
        handler: function (req: Json, res: Json): unknown {
          return self.json(res, 200, self.document(req));
        } },
      // NOT A PAGE'S DOOR, so it mirrors nothing: the Overview's is
      // `/account-api/overview`, and a lookup by `mirrors` must find one.
      { method: 'GET', path: BASE + '/me', operationId: 'getMe', tag: 'API',
        access: 'person',
        summary: 'Who is signed in, and what every page is drawn with',
        description: 'The person (from the token, never the request), the ' +
          'realm, the language data — the negotiation, the portal\'s ' +
          'catalogs and the locales offered — and the build. The portal ' +
          'draws its frame from it.',
        handler: function (req: Json, res: Json,
                           caller: AccountCaller | null): unknown {
          const who = caller as AccountCaller;
          return self.json(res, 200, {
            user: { username: who.username, sub: who.sub,
                    name: String((who.session.user || {}).name || ''),
                    email: String((who.session.user || {}).email || '') },
            realm: { id: realms.currentId(), prefix: realms.currentPrefix() },
            client: who.clientId, expiresAt: who.expiresAt,
            mode: mode.current(),
            locale: self.localeData(who.username),
            version: self.versionData() });
        } },
      { method: 'GET', path: BASE + '/locale', operationId: 'getLocale',
        tag: 'API', access: 'public',
        query: z.object({}),
        summary: 'The language data a page for nobody is drawn with',
        description: 'For the pages a person reaches with no sign-in — an ' +
          'activation or reset link, the forgot-password form, an address ' +
          'verification: the negotiation from the browser alone, the ' +
          'portal\'s catalogs, the offered locales and the build.',
        handler: function (req: Json, res: Json): unknown {
          return self.json(res, 200, { locale: self.localeData(''),
                                       version: self.versionData() });
        } }
    ];
    log.debug("Leaving AccountApi.ownOperations().");
    return rows;
  }

  // -------------------------------------------------------------------------
  // THE GATE.
  // -------------------------------------------------------------------------
  /**
   * The access token a request presents, and in which scheme.
   *
   * @param req - the request
   * @returns `{ token, scheme }`, both '' when none is presented
   */
  presentedTokenOf(req: Json): Json {
    const { log } = this.deps;
    log.debug("Entering AccountApi.presentedTokenOf().");
    const said = String((req.headers && req.headers.authorization) || '');
    const matched = /^(Bearer|DPoP)\s+(\S+)\s*$/i.exec(said);
    log.debug("Leaving AccountApi.presentedTokenOf().");
    return matched ? { token: matched[2], scheme: matched[1].toLowerCase() }
                   : { token: '', scheme: '' };
  }

  // A 401 with its challenge: DPoP, because every token this API takes from
  // the portal's client is DPoP-bound.
  /**
   * Refuses a request with 401 and the challenge.
   *
   * @param res - the response
   * @param code - the error code
   * @param error - the RFC 6750 error, or '' for none presented
   * @param why - the sentence
   * @returns null, so the gate can return it
   */
  unauthorized(res: Json, code: string, error: string, why: string): null {
    const { log } = this.deps;
    log.debug("Entering AccountApi.unauthorized(). " + code);
    res.set('WWW-Authenticate', 'DPoP realm="' + BASE + '"' +
            (error ? ', error="' + error + '"' : '') +
            ', scope="' + SCOPE + '", algs="ES256 PS256 RS256 EdDSA"');
    // error-code: none — the code is the caller's, passed in `code`.
    this.refuse(res, 401, code, why, { error: error || 'unauthorized' });
    log.debug("Leaving AccountApi.unauthorized().");
    return null;
  }

  /**
   * Decides who is calling an operation that takes a token, or refuses.
   *
   * @param req - the request
   * @param res - the response
   * @param op - the operation
   * @returns the caller, or null when the request was answered
   */
  authenticate(req: Json, res: Json, op: AccountOperation):
      AccountCaller | null {
    const { log, realms, accessGate, baseUrlOf } = this.deps;
    const lazy = this.deps.lazy;
    log.debug("Entering AccountApi.authenticate(). " + op.operationId);
    const presentation = this.presentedTokenOf(req);
    if (!presentation.token) {
      log.debug("Leaving AccountApi.authenticate(). Nothing presented.");
      return this.unauthorized(res, 'STS-ACCOUNT-0001', '',
        'This API takes an OAuth 2.0 access token issued to the user ' +
        'portal (`' + PORTAL_CLIENT + '`, scope `' + SCOPE + '`, resource ' +
        baseUrlOf(req) + BASE + '), DPoP-bound, sent as `Authorization: ' +
        'DPoP <token>` with its proof.');
    }
    // VERIFIED WITH THIS REALM'S KEY, and only this realm's: the portal is a
    // person's own account in the realm they are in, and its token comes
    // from that realm's authorization server. Any generation of it (#42).
    let claims: Json = null;
    try {
      claims = helpers.verifyOwnJws(presentation.token);
    } catch (e) {
      log.debug("Caught in AccountApi.authenticate(): " +
                ((e && e.message) || e));
      claims = null;
    }
    if (!claims) {
      log.debug("Leaving AccountApi.authenticate(). Does not verify.");
      return this.unauthorized(res, 'STS-ACCOUNT-0002', 'invalid_token',
        'That access token was not issued by this realm\'s authorization ' +
        'server, or its signature does not verify.');
    }
    const now = Math.floor(Date.now() / 1000);
    if (claims.exp && Number(claims.exp) <= now) {
      log.debug("Leaving AccountApi.authenticate(). Expired.");
      return this.unauthorized(res, 'STS-ACCOUNT-0003', 'invalid_token',
        'That access token expired at ' +
        new Date(Number(claims.exp) * 1000).toISOString() + '.');
    }
    // RFC 9068 SECTION 4, in its order: the type, the issuer, the audience.
    const jwtAccessToken = lazy.jwtAccessToken();
    const typ = jwtAccessToken.typOf(presentation.token);
    if (!jwtAccessToken.isAccessTokenType(typ)) {
      log.debug("Leaving AccountApi.authenticate(). Not an access token.");
      return this.unauthorized(res, 'STS-ACCOUNT-0004', 'invalid_token',
        'RFC 9068 section 4: an access token\'s typ header must be ' +
        '"at+jwt", and this token\'s is ' + (typ ? '"' + typ + '"'
                                                  : 'absent') + '.');
    }
    const base = baseUrlOf(req);
    if (!jwtAccessToken.isHostedIssuer(claims.iss, base)) {
      log.debug("Leaving AccountApi.authenticate(). Another issuer.");
      return this.unauthorized(res, 'STS-ACCOUNT-0005', 'invalid_token',
        'RFC 9068 section 4: the iss claim must be an issuer this realm ' +
        'publishes at ' + base + ', and this token names ' +
        JSON.stringify(claims.iss || null) + '.');
    }
    const audiences = Array.isArray(claims.aud) ? claims.aud
      : (claims.aud === undefined || claims.aud === null ? [] : [claims.aud]);
    if (audiences.map(String).indexOf(base + BASE) < 0) {
      log.debug("Leaving AccountApi.authenticate(). Another audience.");
      this.refuse(res, 403, 'STS-ACCOUNT-0006',
        'That access token is for ' + JSON.stringify(claims.aud || null) +
        ', and this API answers to "' + base + BASE + '". Ask the token ' +
        'endpoint with resource=' + base + BASE + '.',
        { error: 'invalid_token' });
      return null;
    }
    // REVOKED, DISOWNED, A DISABLED PERSON, OR A SIGN-ON SESSION THAT HAS
    // ENDED (the admin API's three checks, #36 and #446): each is a
    // credential that stopped being one.
    const stats = lazy.stats();
    const person = String(claims.username ||
                          helpers.nameForSubject(claims.sub) || '');
    if ((claims.jti && stats.isRevoked(String(claims.jti))) ||
        (person && lazy.accountState().isDisabled(person))) {
      log.debug("Leaving AccountApi.authenticate(). Revoked or disabled.");
      return this.unauthorized(res, 'STS-ACCOUNT-0007', 'invalid_token',
        'That access token has been revoked, or the account it was issued ' +
        'to is disabled.');
    }
    const sid = claims.jti ? String(stats.sessionIdOfJti(String(claims.jti)) ||
                                    '') : '';
    if (sid && !lazy.oauth2().sessionIsLive(sid)) {
      log.debug("Leaving AccountApi.authenticate(). Session ended.");
      return this.unauthorized(res, 'STS-ACCOUNT-0008', 'invalid_token',
        'That access token was issued on a sign-on session that has since ' +
        'ended, by a sign-out or by running out. Sign in again.');
    }
    // RFC 8705 SECTION 3.1: a certificate-bound token only on a connection
    // made with its certificate.
    const mtls = lazy.mtls();
    const certificateProblem = mtls.checkBinding(claims, req, true);
    if (certificateProblem) {
      log.debug("Leaving AccountApi.authenticate(). Certificate binding.");
      return this.unauthorized(res, 'STS-ACCOUNT-0009', 'invalid_token',
        certificateProblem.description);
    }
    // RFC 9449 SECTION 7: a token carrying `cnf.jkt` only with a proof by
    // that key, and never as a Bearer token.
    const dpop = lazy.dpop();
    const boundJkt = dpop.jktOf(claims);
    let proofOk = false;
    if (boundJkt) {
      if (presentation.scheme !== 'dpop') {
        log.debug("Leaving AccountApi.authenticate(). Bound, sent as Bearer.");
        return this.unauthorized(res, 'STS-ACCOUNT-0010', 'invalid_token',
          'That access token is DPoP-bound (it carries cnf.jkt), so it must ' +
          'be sent as "Authorization: DPoP <token>" with a DPoP proof.');
      }
      const checked = dpop.verifyProof(req.headers['dpop'], {
        htm: req.method, htu: dpop.htuOf(req),
        accessToken: presentation.token, expectedJkt: boundJkt, req: req });
      if (!checked.ok) {
        if (checked.needNonce) {
          res.set('DPoP-Nonce', dpop.issueNonce());
          res.set('WWW-Authenticate', 'DPoP error="use_dpop_nonce"');
          log.debug("Leaving AccountApi.authenticate(). Nonce wanted.");
          this.refuse(res, 401, checked.errorCode || 'STS-ACCOUNT-0011',
                      checked.description, { error: 'use_dpop_nonce' });
          return null;
        }
        log.debug("Leaving AccountApi.authenticate(). Proof refused.");
        return this.unauthorized(res, checked.errorCode || 'STS-ACCOUNT-0011',
                                 'invalid_dpop_proof', checked.description);
      }
      proofOk = true;
    }
    // THE PORTAL AS A PUBLIC CLIENT IS DPoP-BOUND, ALWAYS (#568, the
    // console's #446 rule): `sender_constraints.js` names both clients. And
    // #34's two settings, asked of this door as of every other.
    const senderConstraints = lazy.senderConstraints();
    const issuedTo = String(claims.client_id || '');
    let entry: Json = {};
    try {
      entry = lazy.applications().clientConfigOf(issuedTo) || {};
    } catch (e) {
      log.debug("Caught in AccountApi.authenticate(): " +
                ((e && e.message) || e));
      entry = {};
    }
    const clientBound = senderConstraints.dpopBoundPublicClient(
      issuedTo, entry.token_endpoint_auth_method);
    const required = senderConstraints.accessTokenRefusal({
      where: 'the account API', clientBound: clientBound,
      boundJkt: boundJkt, proofOk: proofOk,
      boundThumbprint: mtls.boundThumbprintOf(claims),
      certificate: !!mtls.peerCertificate(req),
      certificateMatches: !!mtls.boundThumbprintOf(claims) &&
        mtls.peerVerified(req) &&
        mtls.presentedThumbprint(req) === mtls.boundThumbprintOf(claims),
      mtlsAvailable: mtls.available() });
    if (required) {
      log.debug("Leaving AccountApi.authenticate(). Sender constraint.");
      return this.unauthorized(res, required.errorCode, required.error,
                               required.description);
    }
    // A PERSON'S TOKEN, never a client's own: this API is about somebody's
    // account, and a client on client_credentials has none.
    if (!person || String(claims.sub || '') === issuedTo) {
      log.debug("Leaving AccountApi.authenticate(). No person.");
      this.refuse(res, 403, 'STS-ACCOUNT-0012',
        'That access token names no person: this API acts on the signed-in ' +
        'person\'s own account, and a token a client holds for itself ' +
        'has none.', { error: 'forbidden' });
      return null;
    }
    const carried = String(claims.scope || '').split(/\s+/).filter(Boolean);
    if (carried.indexOf(SCOPE) < 0) {
      log.debug("Leaving AccountApi.authenticate(). No account:manage.");
      res.set('WWW-Authenticate', 'DPoP error="insufficient_scope", scope="' +
              SCOPE + '"');
      this.refuse(res, 403, 'STS-ACCOUNT-0013',
        'That access token does not carry "' + SCOPE + '", which every ' +
        'operation of this API takes.', { error: 'insufficient_scope' });
      return null;
    }
    // THE CLIENT MUST STILL DECLARE IT (#110's rule, asked again on every
    // call): an allowance taken off a client stops the tokens it holds.
    if (!lazy.scopePolicy().declares(issuedTo, SCOPE)) {
      log.debug("Leaving AccountApi.authenticate(). Undeclared.");
      this.refuse(res, 403, 'STS-ACCOUNT-0014',
        'The client this token was issued to, ' + JSON.stringify(issuedTo) +
        ', no longer declares "' + SCOPE + '" in its oauthAllowedScope.',
        { error: 'forbidden' });
      return null;
    }
    // AND THE POLICY (OWASP A01, decided by the PDP), as the portal asked it:
    // the owner is the subject, written as a comparison of two attributes so
    // a deployment that wants a helpdesk role adds a rule rather than code.
    const signOn = sid ? lazy.authn().sessionById(sid) : null;
    const answer = accessGate.check({
      resource: accessGate.RESOURCE.PORTAL,
      action: op.action ||
        (op.method === 'GET' ? accessGate.ACTION.READ
                             : accessGate.ACTION.MANAGE_OWN),
      subject: { name: person, authenticated: true, sessionId: sid || null },
      owner: person,
      context: { method: req.method, path: req.originalUrl || req.url }
    });
    if (!answer.allowed) {
      log.info('account-api: the access policy refused ' + req.method + ' ' +
               (req.originalUrl || req.url) + ' for ' + person + '. ' +
               answer.why);
      log.debug("Leaving AccountApi.authenticate(). Policy refused.");
      this.refuse(res, 403, 'STS-ACCOUNT-0015',
        'The access policy refused this request. ' + answer.why,
        { error: 'forbidden' });
      return null;
    }
    const user = (signOn && signOn.user) || {};
    const caller: AccountCaller = {
      username: person,
      sub: String(claims.sub || ''),
      realm: realms.currentId(),
      clientId: issuedTo,
      scopes: carried,
      expiresAt: claims.exp ? Number(claims.exp) : null,
      sessionId: sid,
      signOn: signOn,
      // THE SESSION A MOVED HANDLER READS, in the server-rendered portal's
      // shape: the SIGN-ON session's id, which is what CSRF bound to there
      // and what a risk answer or a CIBA approval names.
      session: { id: sid, authenticated: true,
                 expires: signOn ? signOn.expires : null,
                 risk: signOn ? signOn.risk : null,
                 user: Object.assign({}, user, {
                   username: person, sub: String(claims.sub || '') }) }
    };
    // FOR AN AUDIT ROW: who the HTTP row names (`common/audit.js` reads it).
    res.locals.accountCaller = caller;
    log.debug("Leaving AccountApi.authenticate(). " + person);
    return caller;
  }

  // -------------------------------------------------------------------------
  // THE ROUTES.
  // -------------------------------------------------------------------------
  /**
   * The fields a body carries that its operation's schema does not declare:
   * none where the schema is not an object or admits any member.
   *
   * @param schema - the operation's zod body schema
   * @param body - the parsed body
   * @returns the unknown field names, sorted
   */
  static unknownFields(schema: Json, body: Json): string[] {
    helpers.log.debug("Entering AccountApi.unknownFields().");
    const shape = schema && schema.shape;
    const def = schema && schema._zod && schema._zod.def;
    if (!shape || typeof shape !== 'object' || (def && def.catchall &&
        def.catchall._zod && def.catchall._zod.def &&
        def.catchall._zod.def.type !== 'never')) {
      helpers.log.debug("Leaving AccountApi.unknownFields(). Not a closed " +
                        "object.");
      return [];
    }
    const unknown = Object.keys(body && typeof body === 'object' ? body : {})
      .filter(function (name) {
        return !Object.prototype.hasOwnProperty.call(shape, name);
      }).sort();
    helpers.log.debug("Leaving AccountApi.unknownFields().");
    return unknown;
  }

  /**
   * Runs one operation: the gate where it takes a token, the query and body
   * checked against its schemas, then its handler.
   *
   * @param op - the operation
   * @param req - the request
   * @param res - the response
   * @returns what the handler returns
   */
  async run(op: AccountOperation, req: Json, res: Json): Promise<unknown> {
    const { log, validation, parseBody } = this.deps;
    log.debug("Entering AccountApi.run(). " + op.operationId);
    let caller: AccountCaller | null = null;
    if (op.access === 'person') {
      caller = this.authenticate(req, res, op);
      if (!caller) {
        log.debug("Leaving AccountApi.run(). Refused at the gate.");
        return undefined;
      }
    }
    const input = { query: req.query || {}, body: {} };
    if (op.query) {
      const asked = validation.check(req, 'query', op.query);
      if (!asked.ok) {
        log.debug("Leaving AccountApi.run(). Query refused.");
        return this.refuse(res, 400, 'STS-ACCOUNT-0016',
                           asked.detail || 'The query did not validate.');
      }
      input.query = asked.value;
    }
    if (op.method !== 'GET') {
      // THE MEDIA TYPE IS EXACT, AND ASKED OF EVERY BODY-CARRYING REQUEST
      // (2026-10-12), `/authn-api`'s test: `application/json`, with or
      // without parameters. It matched /json/i anywhere, and only where the
      // operation declared a body that was non-empty, so a page on another
      // site could reach an operation that takes no token (an activation, a
      // reset, a forgotten password) with a CORS-safelisted
      // `text/plain; x=json` and no preflight. A request with no body at
      // all sends no type and is not refused for it.
      const type = String((req.headers && req.headers['content-type']) || '');
      const sent = req.body !== undefined && req.body !== null &&
        (typeof req.body === 'string' ? req.body.length > 0
          : (Buffer.isBuffer(req.body) ? req.body.length > 0
            : Object.keys(req.body).length > 0));
      if ((type || sent) && !/^application\/json\s*(;|$)/i.test(type)) {
        log.debug("Leaving AccountApi.run(). Not JSON.");
        return this.refuse(res, 415, 'STS-ACCOUNT-0017',
          'This API takes a JSON request body (Content-Type: ' +
          'application/json).');
      }
      const parsed = parseBody(req) || {};
      if (op.body) {
        // A FIELD THE OPERATION DOES NOT TAKE IS REFUSED, NOT DROPPED
        // (2026-10-12), as `/authn-api`, `/gnap-api` and `/admin-api` refuse
        // one: a caller that sends a field it believes does something must
        // be told it does nothing. Asked of the operation's declared object
        // shape; a schema that is not an object, or one that admits any
        // member (`passthrough`), is left to itself.
        const unknown = AccountApi.unknownFields(op.body, parsed);
        if (unknown.length) {
          log.debug("Leaving AccountApi.run(). An unknown field.");
          return this.refuse(res, 400, 'STS-ACCOUNT-0018',
            'body: ' + unknown.map(function (name) {
              return '"' + name + '"';
            }).join(', ') + (unknown.length === 1 ? ' is not a field'
                                                  : ' are not fields') +
            ' this operation takes.');
        }
        const checked = validation.checkParsed(parsed, 'body', op.body);
        if (!checked.ok) {
          log.debug("Leaving AccountApi.run(). Body refused.");
          return this.refuse(res, 400, 'STS-ACCOUNT-0018',
                             checked.detail || 'The body did not validate.');
        }
        input.body = checked.value;
      } else {
        input.body = parsed;
      }
    }
    try {
      const out = await op.handler(req, res, caller, input);
      log.debug("Leaving AccountApi.run().");
      return out;
    } catch (e) {
      log.error(errorCodes.tag('STS-ACCOUNT-0019') + 'account-api: ' +
                op.operationId + ' threw: ' + ((e && e.stack) || e));
      if (!res.headersSent) {
        this.refuse(res, 500, 'STS-ACCOUNT-0019',
                    'That could not be done: the service failed.');
      }
      log.debug("Leaving AccountApi.run(). Threw.");
      return undefined;
    }
  }

  // ---------------------------------------------------------------------------
  // THE ACCOUNT API IS SERVED AT THE PERSON'S HOME (#98), as the portal was:
  // it manages a person's own entry, which only their home cell holds. The
  // person is the token's — its claims READ here only to route, never
  // trusted: the home cell verifies the token as any cell would — or, on an
  // operation that takes none, the person an activation, reset or
  // verification link names. Relayed whole, before the gate, so nothing is
  // read or spent in the wrong cell. `common/cell_placement.ts` is the table.
  // ---------------------------------------------------------------------------
  /**
   * Relays an account API request to the home cell of its person.
   *
   * @param req - the request
   * @param res - the response
   * @returns a promise of true when the request was relayed
   */
  async placeRequest(req: Json, res: Json): Promise<boolean> {
    const { log, realms, parseBody } = this.deps;
    log.debug("Entering AccountApi.placeRequest().");
    const cells = require('../common/cells');
    if (!cells.isMulti() || req.stsCellRelay) {
      log.debug("Leaving AccountApi.placeRequest(). Here.");
      return false;
    }
    const placement = require('../common/cell_placement');
    let named = '';
    const token = this.presentedTokenOf(req).token;
    const parts = String(token || '').split('.');
    if (parts.length === 3) {
      try {
        const claims = JSON.parse(Buffer.from(parts[1], 'base64url')
                                    .toString('utf8'));
        named = String(claims.username ||
                       helpers.nameForSubject(claims.sub) || '');
      } catch (e) {
        // Not a JWT this cell can read: answered here, where the gate says
        // why it is no token.
        log.debug("Caught in AccountApi.placeRequest(): " +
                  ((e && e.message) || e));
        named = '';
      }
    }
    if (!named) {
      const body = String(req.method || 'GET') === 'POST'
        ? (parseBody(req) || {}) : {};
      named = String((req.query && req.query.user) || body.user || '').trim();
    }
    log.debug("Leaving AccountApi.placeRequest(). " +
              (named ? 'Placed by its person.' : 'Nobody named.'));
    return named ? placement.relayToHome(req, res, realms.currentId(), 'name',
                                         named, 'account-api')
                 : false;
  }

  /**
   * Registers every operation of the table as an express route.
   *
   * @param app - the shared express app
   * @returns nothing
   */
  registerRoutes(app: Json): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AccountApi.registerRoutes().");
    app.use(BASE, function (req: Json, res: Json, next: () => void) {
      log.debug("Entering the account API's cell placement.");
      self.placeRequest(req, res).then(function (relayed) {
        log.debug("Leaving the account API's cell placement. " +
                  (relayed ? 'Relayed.' : 'Here.'));
        if (!relayed) {
          next();
        }
      }, function (e) {
        log.debug("Caught in the account API's cell placement: " +
                  ((e && e.message) || e));
        next();
      });
    });
    this.operations().forEach(function (op) {
      const route = function (req: Json, res: Json): unknown {
        return self.run(op, req, res);
      };
      if (op.method === 'GET') {
        app.get(op.path, route);
      } else {
        app.post(op.path, route);
      }
    });
    log.debug("Leaving AccountApi.registerRoutes(). " +
              this.operations().length + " operation(s).");
  }

  /**
   * The paths this API answers, for `sts_metadata.ts`.
   *
   * @returns the paths
   */
  paths(): string[] {
    const { log } = this.deps;
    log.debug("Entering AccountApi.paths().");
    const out: string[] = [];
    this.operations().forEach(function (op) {
      if (out.indexOf(op.path) < 0) {
        out.push(op.path);
      }
    });
    log.debug("Leaving AccountApi.paths().");
    return out;
  }
}

const slot = new InstanceSlot<AccountApi>(
  'account-api/account_api',
  () => new AccountApi(AccountApi.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The account API, `/account-api`: the user portal's only door (#568).
 * @namespace
 */
export = {
  AccountApi: AccountApi,
  BASE: BASE,
  SCOPE: SCOPE,
  installInstance: (instance: AccountApi): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  registerRoutes: slot.forward('registerRoutes'),
  operations: slot.forward('operations'),
  document: slot.forward('document'),
  paths: slot.forward('paths')
};
