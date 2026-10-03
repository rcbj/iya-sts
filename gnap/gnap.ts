// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap.ts
//
// ---------------------------------------------------------------------------
// GNAP: THE GRANT NEGOTIATION AND AUTHORIZATION PROTOCOL (RFC 9635) AND ITS
// RESOURCE SERVER CONNECTIONS (RFC 9767), AS ROUTES.
//
// This module holds every GNAP endpoint — registered by its exported
// `registerRoutes(app)`, which `common/protocol_stack.ts` calls (#50, R1) —
// and it requires `gnap_interact.ts` (the pages a resource owner sees) and
// `gnap_admin.ts`, so this family has ONE require in the stack the way XACML's
// does, followed by three `register()` calls: this module's, then
// `gnap_interact`'s, then `gnap_admin`'s, the order they registered in when
// requiring them did. Every decision
// is `gnap_grants.ts`'s and `gnap_rs.ts`'s; what is here is transport: which
// path, which method, which JSON and which HTTP status.
//
// ---------------------------------------------------------------------------
// THE ENDPOINTS, AND WHERE THE AUTHORIZATION SERVER CONCEPT COMES IN.
//
//   POST    /gnap, /:as/gnap          the grant endpoint (section 2)
//   OPTIONS /gnap, /:as/gnap          discovery (section 9)
//   POST|PATCH|DELETE /gnap/continue/:grant   continuation (section 5)
//   POST|DELETE /gnap/token/:handle   token management (section 6)
//   GET     /.well-known/gnap-as-rs[/:as]     RS-facing discovery (RFC 9767
//                                             3.1)
//   POST    /gnap/introspect          introspection (RFC 9767 3.3)
//   POST    /gnap/resource            resource set registration (RFC 9767 3.4)
//   GET     /gnap/keys                token-format verification material
//   GET     /gnap/zcap/controller     the ZCAP-LD controller document
//   GET     /gnap/biscuit/revocations the revocation identifiers of revoked
//                                     biscuits (#432; this service's own)
//   GET|POST /gnap/rs/resource        the demonstration resource server
//
// **A NAMED AUTHORIZATION SERVER IS THE OAUTH SUBSYSTEM'S, NOT A SECOND ONE.**
// `/:as/gnap` selects the same profile `/:as/oauth2/*` does
// (`oauth-oidc/authorization_servers.ts`), created on first sight exactly as
// that module's `ensure()` does for OAuth, and that profile's GNAP members
// (section 9's discovery fields) are what the grant endpoint enforces. A grant
// made at one authorization server records it, its tokens' `iss` is that
// server's grant endpoint (RFC 9767 section 3.3: "Grant endpoint URL of the AS
// that issued this token"), and the interaction hash (section 4.2.3) is
// computed over THAT URI — so a client that talks to two named servers gets two
// distinguishable authorization servers, which is section 11.12's defence
// against mix-up attacks.
//
// **THE ONE PATH THAT NEEDED A GUARD IS `/:as/gnap`.** It is two segments where
// OAuth's prefixed routes are three, so it would match `POST /admin/gnap` and
// create an authorization server named "admin" on sight. A reserved first
// segment falls through (`next()`) to whatever else would have answered — in
// the worst case express's own 404, which `tests/vendored/sts_metadata.js`
// reads as unrouted, which it is.
//
// ---------------------------------------------------------------------------
// ERROR RESPONSES (section 3.6, RFC 9767 section 3.5).
//
// `{ "error": { "code", "description" } }`, with `continue` beside it where the
// grant can still be continued (section 3.6 allows it and section 5.1's example
// shows it for `user_denied`). The HTTP status is not specified by either RFC;
// this service uses 401 where the caller failed to authenticate (a key proof, a
// continuation or management token), 403 where an authenticated request was
// refused by the resource owner or policy, 404 where a feature is switched
// off, and 400 for the rest — and RFC 9767 section 3.5 says 400 for every
// RS-facing error, which is what those routes send. The STS error code is on
// the response object (errorCodes.mark) and NEVER in the body.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape, for a module that registers routes (rule 1): `GnapRoutes` takes the
// grant engine, the resource server judge and the rest through its
// constructor, and its `registerRoutes(app)` holds every route in its old
// order. The composition root builds the instance (#50, R2) and calls its
// `registerRoutes(app)` at this module's old point in the route order (#50,
// R1); the exports are FACADES for the JavaScript callers, and a process
// without the root builds a default when this module loads. Loading it still
// requires the resource-owner pages and the console pages (which register
// nothing when required either); installing the SSF scope is the `wire`
// step, run once for whichever instance is installed. `gnap_access` and
// `gnap_monitor` stay LAZY, as they were, through
// the two loaders in `GnapRoutesDeps`. The module still exports `DEMO_TYPE`,
// `DEMO_REFERENCE` and `gnapError`.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import config = require('../common/config');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');
import validation = require('../common/validation');
import authorizationServers = require('../oauth-oidc/authorization_servers');
import grants = require('./gnap_grants');
import gnapRights = require('./gnap_rights');
import rs = require('./gnap_rs');
import tokens = require('./gnap_tokens');
import zcap = require('./token_zcap');
import signals = require('./gnap_signals');
import gnapCells = require('./gnap_cells');

type Req = import('express').Request;
type Res = import('express').Response;
type Next = import('express').NextFunction;
type Handler = (req: Req, res: Res, next?: Next) => unknown;

// The two parts of other GNAP modules this one reaches for only when a
// demonstration request needs them.
interface AccessCovers {
  accessCovers(held: unknown, required: unknown): boolean;
}
interface EventCounter {
  record(identifier: unknown, event: string, detail?: object): void;
}

interface GnapRoutesDeps {
  config: typeof config;
  log: typeof helpers.log;
  errorCodes: typeof errorCodes;
  validation: typeof validation;
  authorizationServers: typeof authorizationServers;
  grants: typeof grants;
  rs: typeof rs;
  tokens: typeof tokens;
  zcap: typeof zcap;
  // Required at the moment they are needed, never at load.
  loadAccess(): AccessCovers;
  loadMonitor(): EventCounter;
  loadStore(): { biscuitRevocationIds(): string[] };
  loadStatusList(): { aggregationUri(base: string): string };
  // #432 phase 5: the demonstration resource server's running totals, and
  // the body reader its spend operation shares with every GNAP endpoint.
  loadSpend(): any;
  loadProof(): any;
}

// The routes' own table of what an express app offers.
interface RouteTable {
  get(path: string, ...handlers: Handler[]): unknown;
  post(path: string, ...handlers: Handler[]): unknown;
  options(path: string, ...handlers: Handler[]): unknown;
  patch(path: string, ...handlers: Handler[]): unknown;
  delete(path: string, ...handlers: Handler[]): unknown;
}

// What `asFrom()` answers.
interface AsSelection {
  answered?: boolean;
  fallThrough?: boolean;
  id?: string;
}

const vz = validation.z;
const vt = validation.types;

const AS_PARAMS = vz.object({ as: vt.opt(vt.identifier) });
const GRANT_PARAMS = vz.object({ grant: vt.base64url });
// The demonstration spend operation's body (#432 phase 5): flat, so each
// member is a scalar the shared validator reads as it reads every body.
const SPEND_BODY = vz.object({
  amount: vz.string().max(40).optional(),
  currency: vz.string().max(8).optional(),
  receiver: vz.string().max(512).optional(),
  simulateFailure: vz.boolean().optional()
});
const HANDLE_PARAMS = vz.object({ handle: vt.base64url });

const STATUS_FOR: Record<string, number> = {
  invalid_client: 401,
  invalid_resource_server: 400,
  user_denied: 403,
  request_denied: 403,
  unknown_user: 403
};

// ---------------------------------------------------------------------------
// THE DEMONSTRATION RESOURCE SERVER'S NAMES — see `demoResource()`.
// ---------------------------------------------------------------------------
// One spelling, the catalogue's (#432 phase 4): `gnap_rights.ts` builds it
// in while the demonstration resource server is on.
const DEMO_TYPE = gnapRights.DEMO_TYPE;
// The revoked biscuits' identifiers (#432).
const BISCUIT_REVOCATIONS_PATH = '/gnap/biscuit/revocations';
const DEMO_REFERENCE = 'iya-sts-gnap-demo';

/**
 * GNAP's HTTP surface: the grant, continuation, token management, discovery,
 * RS-facing and demonstration resource server routes (RFC 9635, RFC 9767).
 *
 * Transport only: every decision is `gnap_grants.ts`'s and `gnap_rs.ts`'s.
 */
class GnapRoutes {
  /**
   * The access type the demonstration resource server at `/gnap/rs/resource`
   * protects.
   */
  static readonly DEMO_TYPE = DEMO_TYPE;
  /**
   * The registered reference the demonstration resource server's RS-first
   * challenge hands out for its access.
   */
  static readonly DEMO_REFERENCE = DEMO_REFERENCE;

  /**
   * Builds the routes from the modules they read.
   *
   * @param deps - the modules the composition root passes
   */
  constructor(private readonly deps: GnapRoutesDeps) {
    deps.log.debug("Entering GnapRoutes.constructor().");
    deps.log.debug("Leaving GnapRoutes.constructor().");
  }

  /**
   * Sends a GNAP error response: `{ error: { code, description } }` with the
   * given status, marked `no-store`.
   *
   * @param res - the response to answer on
   * @param status - the HTTP status
   * @param code - the GNAP error code
   * @param description - the human-readable description
   * @param extra - further members merged into the body
   */
  // error-code: none — the helper's definition, not a call to it.
  gnapError(res: Res, status: number, code: string, description: string,
            extra?: object): void {
    const { log } = this.deps;
    // error-code: none — the helper's trace line, not a call to it.
    log.debug("Entering GnapRoutes.gnapError(). status=" + status +
              ", error=" + code);
    const body = Object.assign({ error: { code: code,
                                          description: description } },
                               extra || {});
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(body));
    // error-code: none — the helper's trace line, not a call to it.
    log.debug("Leaving GnapRoutes.gnapError().");
  }

  private sendResult(res: Res, result: any): void {
    const { log } = this.deps;
    log.debug("Entering GnapRoutes.sendResult().");
    if (result.status === 204) {
      res.status(204).set('Cache-Control', 'no-store').end();
      log.debug("Leaving GnapRoutes.sendResult().");
      return;
    }
    res.status(result.status || 200)
       .type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(result.body));
    log.debug("Leaving GnapRoutes.sendResult().");
  }

  // A refusal from the engine, in GNAP's shape. The engine has already marked
  // the result with its code; the response object is marked from it.
  // error-code: none — the helper's definition, not a call to it.
  private refuse(res: Res, result: any, fallbackCode: string,
                 rsFacing?: boolean): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering GnapRoutes.refuse().");
    errorCodes.mark(res,
                    errorCodes.codeOf(result) || result.errorCode ||
                    fallbackCode);
    const status = rsFacing ? (result.status === 404 ? 404 : 400)
      : (result.status || STATUS_FOR[result.gnapError] || 400);
    log.debug("Leaving GnapRoutes.refuse().");
    // error-code: none — the response was marked on the first line of refuse() with the result's own code or the caller's fallback.
    return this.gnapError(res, status, result.gnapError || 'invalid_request',
                          result.why, result.extra);
  }

  // Every async handler goes through here, so a thrown defect is a coded 500
  // and never an unhandled rejection (which ends the process under some node
  // flags).
  private guarded(name: string, handler: Handler): Handler {
    const self = this;
    const { log, errorCodes } = this.deps;
    log.debug("Entering GnapRoutes.guarded().");
    log.debug("Leaving GnapRoutes.guarded().");
    return function (req, res, next) {
      Promise.resolve().then(function () {
        return handler(req, res, next);
      }).catch(function (e) {
        log.debug("Caught in GnapRoutes.guarded(): " + ((e && e.message) || e));
        log.error(errorCodes.tag('STS-GNAP-0160') + 'gnap: ' + name +
                  ' failed: ' + (e && e.stack || e));
        if (!res.headersSent) {
          errorCodes.mark(res, 'STS-GNAP-0160');
          self.gnapError(res, 500, 'request_denied', 'The authorization ' +
                         'server could not process this request.');
        }
      });
    };
  }

  private offCheck(res: Res): boolean {
    const { log, config, errorCodes } = this.deps;
    log.debug("Entering GnapRoutes.offCheck().");
    if (config.value('gnap.enabled') === false) {
      errorCodes.mark(res, 'STS-GNAP-0161');
      this.gnapError(res, 404, 'request_denied', 'GNAP is turned off in ' +
                     'this trust realm (gnap.enabled).');
      log.debug("Leaving GnapRoutes.offCheck().");
      return true;
    }
    log.debug("Leaving GnapRoutes.offCheck().");
    return false;
  }

  // The authorization server a `/:as` path names, or `null` to fall through.
  private asFrom(req: Req, res: Res): AsSelection {
    const { log, validation, errorCodes, grants,
            authorizationServers } = this.deps;
    log.debug("Entering GnapRoutes.asFrom().");
    const named = validation.checkParsed({ as: req.params.as }, 'params',
                                         AS_PARAMS);
    if (!named.ok) {
      errorCodes.mark(res, 'STS-GNAP-0162');
      this.gnapError(res, 400, 'invalid_request', named.detail);
      log.debug("Leaving GnapRoutes.asFrom().");
      return { answered: true };
    }
    const id = String(named.value.as || '');
    if (grants.RESERVED_AS_NAMES.indexOf(id) >= 0) {
      log.debug("Leaving GnapRoutes.asFrom().");
      return { fallThrough: true };
    }
    authorizationServers.ensure(id, { autoCreated: true, seen: true });
    log.debug("Leaving GnapRoutes.asFrom().");
    return { id: id };
  }

  // -------------------------------------------------------------------------
  // SECTION 2: THE GRANT ENDPOINT.
  // -------------------------------------------------------------------------
  private grantEndpoint(named: boolean): Handler {
    const self = this;
    const { log, grants } = this.deps;
    log.debug("Entering GnapRoutes.grantEndpoint().");
    log.debug("Leaving GnapRoutes.grantEndpoint().");
    return this.guarded('the grant endpoint',
                        async function (req, res, next) {
      log.debug("Entering the grant endpoint.");
      let asId = null;
      if (named) {
        const selected = self.asFrom(req, res);
        if (selected.answered) {
          log.debug("Leaving the grant endpoint. Bad authorization server " +
                    "name.");
          return undefined;
        }
        if (selected.fallThrough) {
          log.debug("Leaving the grant endpoint. Reserved segment; falling " +
                    "through.");
          return next();
        }
        asId = selected.id;
      }
      if (self.offCheck(res)) {
        log.debug("Leaving the grant endpoint. Off.");
        return undefined;
      }
      // WHICH CELL (#98): before the caller's key proof is verified or its
      // nonce spent — the owning cell does both (`gnap_cells.ts`). A named
      // authorization server was `ensure()`d above, which every cell does
      // alike and which is configuration, not the request's.
      if (await gnapCells.placeGrantRequest(req, res)) {
        log.debug("Leaving the grant endpoint. Relayed to its cell.");
        return undefined;
      }
      const result: any = await grants.createGrant(req, asId);
      if (!result.ok) {
        log.debug("Leaving the grant endpoint. Refused: " + result.why);
        return self.refuse(res, result, 'STS-GNAP-0163');
      }
      self.sendResult(res, result);
      log.debug("Leaving the grant endpoint.");
      return undefined;
    });
  }

  // SECTION 9: DISCOVERY, by OPTIONS to the grant endpoint.
  private discovery(named: boolean): Handler {
    const self = this;
    const { log, grants } = this.deps;
    log.debug("Entering GnapRoutes.discovery().");
    log.debug("Leaving GnapRoutes.discovery().");
    return function (req, res, next) {
      log.debug("Entering GNAP discovery.");
      let asId = null;
      if (named) {
        const selected = self.asFrom(req, res);
        if (selected.answered) {
          log.debug("Leaving GNAP discovery. Bad name.");
          return undefined;
        }
        if (selected.fallThrough) {
          log.debug("Leaving GNAP discovery. Reserved segment.");
          return next();
        }
        asId = selected.id;
      }
      if (self.offCheck(res)) {
        log.debug("Leaving GNAP discovery. Off.");
        return undefined;
      }
      res.status(200).type('application/json')
         .set('Cache-Control', 'no-store')
         .send(JSON.stringify(grants.capabilities(req, asId), null, 2));
      log.debug("Leaving GNAP discovery.");
      return undefined;
    };
  }

  // -------------------------------------------------------------------------
  // RFC 9767: THE RESOURCE-SERVER-FACING API.
  // -------------------------------------------------------------------------
  private rsDiscovery(named: boolean): Handler {
    const self = this;
    const { log, grants, config } = this.deps;
    log.debug("Entering GnapRoutes.rsDiscovery().");
    log.debug("Leaving GnapRoutes.rsDiscovery().");
    return function (req, res, next) {
      log.debug("Entering RS-facing discovery.");
      let asId = null;
      if (named) {
        const selected = self.asFrom(req, res);
        if (selected.answered) {
          log.debug("Leaving RS-facing discovery. Bad name.");
          return undefined;
        }
        if (selected.fallThrough) {
          log.debug("Leaving RS-facing discovery. Reserved segment.");
          return next();
        }
        asId = selected.id;
      }
      if (self.offCheck(res)) {
        log.debug("Leaving RS-facing discovery. Off.");
        return undefined;
      }
      const caps: any = grants.capabilities(req, asId);
      const base = grants.realmBase(req);
      const document: any = {
        grant_request_endpoint: caps.grant_request_endpoint };
      if (config.value('gnap.introspection') !== false) {
        document.introspection_endpoint = base + '/gnap/introspect';
      }
      if (caps.token_formats_supported) {
        document.token_formats_supported = caps.token_formats_supported;
      }
      if (config.value('gnap.resourceRegistration') !== false) {
        document.resource_registration_endpoint = base + '/gnap/resource';
      }
      if (caps.key_proofs_supported) {
        document.key_proofs_supported = caps.key_proofs_supported;
      }
      // WHERE A RESOURCE SERVER THAT CHECKS TOKENS ON ITS OWN LEARNS OF A
      // REVOCATION (#432; RFC 9767 section 6.3 offers it nothing but
      // introspection). Neither member is in RFC 9767 section 10's registry;
      // both are this service's own, and an RS that does not know them
      // ignores them. `status_list_aggregation_endpoint` is the name
      // draft-ietf-oauth-status-list section 9.1 gives the same document in
      // an OAuth authorization server's metadata — the realm's ONE
      // access-token list, which GNAP's two JWT formats share with OAuth.
      document.status_list_aggregation_endpoint =
        self.deps.loadStatusList().aggregationUri(base);
      document.biscuit_revocation_endpoint = base + BISCUIT_REVOCATIONS_PATH;
      res.status(200).type('application/json')
         .set('Cache-Control', 'no-store')
         .send(JSON.stringify(document, null, 2));
      log.debug("Leaving RS-facing discovery.");
      return undefined;
    };
  }

  // -------------------------------------------------------------------------
  // THE DEMONSTRATION RESOURCE SERVER (RFC 9635 sections 7.2 and 9.1).
  //
  // A GET needs `read` and a POST needs `write` on the type
  // `urn:iya-sts:gnap:demo` — or the registered reference its RS-first
  // challenge hands out. With no token it answers 401 with the RS-FIRST
  // challenge of section 9.1: `WWW-Authenticate: GNAP
  // as_uri=…;access=…;referrer=…`, which is how a client that knows only a
  // resource URL discovers where to ask.
  // -------------------------------------------------------------------------
  private demoResource(req: Req, res: Res): void {
    const self = this;
    const { log, config, errorCodes, grants, rs, loadAccess,
            loadMonitor } = this.deps;
    log.debug("Entering GnapRoutes.demoResource().");
    log.debug("Leaving GnapRoutes.demoResource().");
    this.guarded('the demonstration resource server', async function () {
      log.debug("Entering the demonstration RS. method=" + req.method);
      if (self.offCheck(res)) {
        log.debug("Leaving the demonstration RS. Off.");
        return;
      }
      if (config.value('gnap.demoResourceServer') === false) {
        errorCodes.mark(res, 'STS-GNAP-0550');
        self.gnapError(res, 404, 'invalid_request', 'The demonstration ' +
                       'resource server is turned off ' +
                       '(gnap.demoResourceServer).');
        log.debug("Leaving the demonstration RS. Turned off.");
        return;
      }
      const base = grants.realmBase(req);
      const selfUri = base + '/gnap/rs/resource';
      const action = req.method === 'GET' ? 'read' : 'write';
      const challenge = 'GNAP as_uri="' + grants.grantEndpointOf(req, null) +
          '", ' +
          'access="' +
        DEMO_REFERENCE + '", referrer="' + selfUri + '"';
      if (!req.headers.authorization) {
        errorCodes.mark(res, 'STS-GNAP-0551');
        res.status(401)
           .set('WWW-Authenticate', challenge)
           .set('Cache-Control', 'no-store')
           .type('application/json')
           .send(JSON.stringify({ error: 'invalid_token',
             error_description: 'This resource needs a GNAP access token; ' +
             'ask the authorization server named in WWW-Authenticate.' }));
        log.debug("Leaving the demonstration RS. RS-first challenge.");
        return;
      }
      // WHICH CELL (#98): the one holding the token — before its key proof
      // is verified and its nonce spent. A `jwt-signed` token was placed at
      // the edge already; the other formats are found here.
      const presented = /^GNAP\s+(\S+)$/i.exec(
        String(req.headers.authorization).trim());
      if (presented && await gnapCells.placeToken(req, res, presented[1],
                                                  'gnap:resource')) {
        log.debug("Leaving the demonstration RS. Relayed to its cell.");
        return;
      }
      const required = [{ type: DEMO_TYPE, actions: [action] }];
      const judged: any = await rs.authenticate(req, { audience: selfUri,
                                                       base: base });
      if (!judged.ok) {
        errorCodes.mark(res, errorCodes.codeOf(judged) || 'STS-GNAP-0552');
        res.status(judged.status || 401)
           .set('WWW-Authenticate', challenge + ', ' +
            'error="' +
          judged.gnapError + '"').set('Cache-Control', 'no-store').type(
              'application/json')
           .send(JSON.stringify({ error: judged.gnapError,
                                  error_description: judged.why }));
        log.debug("Leaving the demonstration RS. Refused: " + judged.why);
        return;
      }
      const covers = loadAccess().accessCovers(judged.model.access,
                                               required) ||
        (judged.model.access || []).indexOf(DEMO_REFERENCE) >= 0;
      if (!covers) {
        errorCodes.mark(res, 'STS-GNAP-0553');
        res.status(403).set('WWW-Authenticate', challenge + ', ' +
            'error="insufficient_scope"')
           .set('Cache-Control', 'no-store').type('application/json')
           .send(JSON.stringify({ error: 'insufficient_scope',
                                  error_description: 'The ' +
             'token does not grant ' + action + ' on ' + DEMO_TYPE + '.' }));
        log.debug("Leaving the demonstration RS. Access not covered.");
        return;
      }
      loadMonitor().record(judged.record.instanceId, 'rs.presented',
                           {});
      res.status(200).type('application/json')
         .set('Cache-Control', 'no-store')
         .send(JSON.stringify({ ok: true, action: action,
                                format: judged.format,
                                method: judged.method,
                                token: judged.model }, null, 2));
      log.debug("Leaving the demonstration RS. Allowed.");
    })(req, res);
  }

  // -------------------------------------------------------------------------
  // THE DEMONSTRATION RESOURCE SERVER SPENDS (#432 phase 5).
  //
  // `POST /gnap/rs/spend`, body `{ amount, currency, receiver,
  // simulateFailure }` (each optional): an operation that SPENDS — a
  // payment, say — and so is what a right's limits are for. It needs the
  // action `spend` on `urn:iya-sts:gnap:demo`, and is then checked against
  // the limits of the first right that covers it (`gnap_spend.ts`: the
  // window, the interval, the receiver, the currency, then the totals per
  // grant, atomically across the cluster). A covering right with NO limits
  // allows it unaccounted, because no limit was asked for. With
  // `simulateFailure` the operation fails AFTER its spend was counted and
  // the spend is refunded — the reference for an operation that fails.
  // -------------------------------------------------------------------------
  private demoSpend(req: Req, res: Res): void {
    const self = this;
    const { log, config, errorCodes, grants, rs, loadAccess,
            loadMonitor } = this.deps;
    log.debug("Entering GnapRoutes.demoSpend().");
    log.debug("Leaving GnapRoutes.demoSpend().");
    this.guarded('the demonstration spend', async function () {
      log.debug("Entering the demonstration spend.");
      if (self.offCheck(res)) {
        log.debug("Leaving the demonstration spend. Off.");
        return;
      }
      if (config.value('gnap.demoResourceServer') === false) {
        errorCodes.mark(res, 'STS-GNAP-0550');
        self.gnapError(res, 404, 'invalid_request', 'The demonstration ' +
                       'resource server is turned off ' +
                       '(gnap.demoResourceServer).');
        log.debug("Leaving the demonstration spend. Turned off.");
        return;
      }
      const base = grants.realmBase(req);
      // The same resource server as `/gnap/rs/resource`, so the same
      // audience: one token reads, writes and spends there.
      const selfUri = base + '/gnap/rs/resource';
      const challenge = 'GNAP as_uri="' + grants.grantEndpointOf(req, null) +
        '", access="' + DEMO_REFERENCE + '", referrer="' + base +
        '/gnap/rs/spend"';
      const answer = function (status: number, code: string, error: string,
                               why: string): void {
        log.debug("Entering answer(). " + code);
        errorCodes.mark(res, code);
        res.status(status).set('Cache-Control', 'no-store');
        if (status === 401 || status === 403) {
          res.set('WWW-Authenticate', challenge + ', error="' + error + '"');
        }
        res.type('application/json')
           .send(JSON.stringify({ error: error, error_description: why }));
        log.debug("Leaving answer().");
      };
      if (!req.headers.authorization) {
        answer(401, 'STS-GNAP-0551', 'invalid_token', 'This operation ' +
               'needs a GNAP access token.');
        log.debug("Leaving the demonstration spend. RS-first challenge.");
        return;
      }
      const presented = /^GNAP\s+(\S+)$/i.exec(
        String(req.headers.authorization).trim());
      if (presented && await gnapCells.placeToken(req, res, presented[1],
                                                  'gnap:resource')) {
        log.debug("Leaving the demonstration spend. Relayed to its cell.");
        return;
      }
      const judged: any = await rs.authenticate(req, { audience: selfUri,
                                                       base: base });
      if (!judged.ok) {
        answer(judged.status || 401,
               errorCodes.codeOf(judged) || 'STS-GNAP-0552',
               judged.gnapError || 'invalid_token', judged.why);
        log.debug("Leaving the demonstration spend. Refused: " + judged.why);
        return;
      }
      const body = self.deps.loadProof().readBody(req);
      const posted: any = body.ok
        ? self.deps.validation.checkParsed(body.json || {}, 'body',
                                           SPEND_BODY)
        : { ok: false, detail: body.why };
      if (!posted.ok) {
        answer(400, 'STS-GNAP-0874', 'invalid_request', 'The operation ' +
               'is not readable: ' + String(posted.detail || posted.why ||
                                            ''));
        log.debug("Leaving the demonstration spend. Malformed.");
        return;
      }
      const op = posted.value;
      // THE RIGHT THAT COVERS IT: of the demonstration type, allowing
      // `spend` (an absent `actions` is every action, `gnap_access.ts`).
      const access = loadAccess();
      const covering = (judged.model.access || []).filter(function (r: any) {
        return r && typeof r === 'object' &&
          access.accessCovers([r], [{ type: DEMO_TYPE, actions: ['spend'] }]);
      });
      if (!covering.length) {
        answer(403, 'STS-GNAP-0553', 'insufficient_scope', 'The token does ' +
               'not grant spend on ' + DEMO_TYPE + '.');
        log.debug("Leaving the demonstration spend. Not covered.");
        return;
      }
      const limited = covering.filter(function (r: any) {
        return r.limits !== undefined;
      });
      const grant = judged.model.grant || judged.record.grantId || '';
      const operation = { receiver: op.receiver, amount: op.amount,
                          currency: op.currency };
      let spent: any = null;
      let refused: any = null;
      if (limited.length === covering.length) {
        // EVERY covering right is limited: the first one whose limits take
        // this operation is the one spent against.
        const spend = self.deps.loadSpend();
        for (let i = 0; i < limited.length && !spent; i++) {
          const tried = await spend.spend({
            grant: grant, right: limited[i], operation: operation,
            expiresAt: judged.record.grantExpiresAt || judged.record.exp });
          if (tried.ok) {
            spent = tried;
          } else if (!refused || tried.code === 'STS-GNAP-0875') {
            refused = tried;
          }
        }
        if (!spent) {
          answer(refused.status, refused.code, refused.error, refused.why);
          log.debug("Leaving the demonstration spend. " + refused.code);
          return;
        }
      }
      if (op.simulateFailure === true) {
        const refunded = spent
          ? await self.deps.loadSpend().refund(spent.spent) : false;
        errorCodes.mark(res, 'STS-GNAP-0876');
        res.status(502).set('Cache-Control', 'no-store')
           .type('application/json')
           .send(JSON.stringify({ error: 'operation_failed',
             error_description: 'The demonstration operation failed after ' +
             'its spend was counted' + (spent ? (refunded
               ? '; the spend was refunded.'
               : '; the spend could not be refunded.') : '.'),
             refunded: refunded }));
        log.debug("Leaving the demonstration spend. Failed and refunded.");
        return;
      }
      loadMonitor().record(judged.record.instanceId, 'rs.presented', {});
      res.status(200).type('application/json')
         .set('Cache-Control', 'no-store')
         .send(JSON.stringify({
           ok: true, action: 'spend', format: judged.format,
           grant_id: grant,
           limited: !!spent,
           totals: spent ? spent.totals : undefined,
           remaining: spent ? spent.remaining : undefined,
           period: spent ? spent.period : undefined }, null, 2));
      log.debug("Leaving the demonstration spend. Spent.");
    })(req, res);
  }

  // Every route, in the order this file has always registered them.
  /**
   * Registers every GNAP route, in the order this file always registered them.
   *
   * Called by `common/protocol_stack.ts`; requiring this module registers
   * nothing.
   *
   * @param app - the shared express application
   */
  registerRoutes(app: RouteTable): void {
    const self = this;
    const { log, validation, errorCodes, grants, rs, tokens,
            zcap } = this.deps;
    log.debug("Entering GnapRoutes.registerRoutes().");

    app.post('/gnap', self.grantEndpoint(false));
    app.options('/gnap', self.discovery(false));
    app.post('/:as/gnap', self.grantEndpoint(true));
    app.options('/:as/gnap', self.discovery(true));

    // -----------------------------------------------------------------------
    // SECTION 5: CONTINUATION.
    // -----------------------------------------------------------------------
    const continuation = self.guarded('the continuation endpoint',
                                      async function (req, res) {
      log.debug("Entering the continuation endpoint. method=" + req.method);
      if (self.offCheck(res)) {
        log.debug("Leaving the continuation endpoint. Off.");
        return;
      }
      const params = validation.checkParsed({ grant: req.params.grant },
                                            'params', GRANT_PARAMS);
      if (!params.ok) {
        log.debug("Leaving the continuation endpoint. Bad URI.");
        errorCodes.mark(res, 'STS-GNAP-0164');
        self.gnapError(res, 401, 'invalid_continuation', 'The continuation ' +
                       'URI does not identify a grant request.');
        return;
      }
      // WHICH CELL (#98): the grant's, before the continuation token or the
      // key proof is checked there.
      if (await gnapCells.placeContinuation(req, res, params.value.grant)) {
        log.debug("Leaving the continuation endpoint. Relayed to its cell.");
        return;
      }
      const result: any = await grants.continueGrant(req,
                                                     params.value.grant);
      if (!result.ok) {
        log.debug("Leaving the continuation endpoint. Refused: " +
                  result.why);
        self.refuse(res, result, 'STS-GNAP-0165');
        return;
      }
      self.sendResult(res, result);
      log.debug("Leaving the continuation endpoint.");
    });

    app.post('/gnap/continue/:grant', continuation);
    app.patch('/gnap/continue/:grant', continuation);
    app.delete('/gnap/continue/:grant', continuation);

    // -----------------------------------------------------------------------
    // SECTION 6: TOKEN MANAGEMENT.
    // -----------------------------------------------------------------------
    const management = self.guarded('the token management endpoint',
                                    async function (req, res) {
      log.debug("Entering the token management endpoint. method=" +
                req.method);
      if (self.offCheck(res)) {
        log.debug("Leaving the token management endpoint. Off.");
        return;
      }
      const params = validation.checkParsed({ handle: req.params.handle },
                                            'params', HANDLE_PARAMS);
      if (!params.ok) {
        log.debug("Leaving the token management endpoint. Bad URI.");
        errorCodes.mark(res, 'STS-GNAP-0166');
        self.gnapError(res, 401,
                       req.method === 'DELETE' ? 'invalid_request' :
                         'invalid_rotation',
                       'The token management URI does not identify a token.');
        return;
      }
      const result: any = await grants.manageToken(req, params.value.handle);
      if (!result.ok) {
        log.debug("Leaving the token management endpoint. Refused: " +
                  result.why);
        self.refuse(res, result, 'STS-GNAP-0167');
        return;
      }
      self.sendResult(res, result);
      log.debug("Leaving the token management endpoint.");
    });

    app.post('/gnap/token/:handle', management);
    app.delete('/gnap/token/:handle', management);

    app.get('/.well-known/gnap-as-rs', self.rsDiscovery(false));
    app.get('/.well-known/gnap-as-rs/:as', self.rsDiscovery(true));

    app.post('/gnap/introspect',
             self.guarded('the introspection endpoint',
                          async function (req, res) {
      log.debug("Entering the introspection endpoint.");
      if (self.offCheck(res)) {
        log.debug("Leaving the introspection endpoint. Off.");
        return;
      }
      // WHICH CELL (#98): the one holding the token, before the resource
      // server's proof is verified.
      if (await gnapCells.placeIntrospection(req, res)) {
        log.debug("Leaving the introspection endpoint. Relayed to its cell.");
        return;
      }
      const result = await rs.introspect(req);
      if (!result.ok) {
        log.debug("Leaving the introspection endpoint. Refused: " +
                  result.why);
        self.refuse(res, result, 'STS-GNAP-0168', true);
        return;
      }
      self.sendResult(res, result);
      log.debug("Leaving the introspection endpoint.");
    }));

    app.post('/gnap/resource',
             self.guarded('the resource registration endpoint',
                          async function (req, res) {
      log.debug("Entering the resource registration endpoint.");
      if (self.offCheck(res)) {
        log.debug("Leaving the resource registration endpoint. Off.");
        return;
      }
      // WHICH CELL (#98): the one holding the resource server's instance,
      // when it names itself by one.
      if (gnapCells.placeResourceServer(req, res)) {
        log.debug("Leaving the resource registration endpoint. Relayed to " +
                  "its cell.");
        return;
      }
      const result = await rs.register(req);
      if (!result.ok) {
        log.debug("Leaving the resource registration endpoint. Refused: " +
                  result.why);
        self.refuse(res, result, 'STS-GNAP-0169', true);
        return;
      }
      self.sendResult(res, result);
      log.debug("Leaving the resource registration endpoint.");
    }));

    // -----------------------------------------------------------------------
    // VERIFICATION MATERIAL for the self-contained formats. Public keys only;
    // a document that publishes a key is served `no-store` (root CLAUDE.md,
    // *Signing keys, and any document that publishes one*) — both of these
    // do.
    // -----------------------------------------------------------------------
    app.get('/gnap/keys', function (req, res) {
      log.debug("Entering GET /gnap/keys.");
      if (self.offCheck(res)) {
        log.debug("Leaving GET /gnap/keys. Off.");
        return;
      }
      res.status(200).type('application/json')
         .set('Cache-Control', 'no-store')
         .send(JSON.stringify(tokens.publicMaterial(grants.realmBase(req)),
                              null, 2));
      log.debug("Leaving GET /gnap/keys.");
    });

    app.get('/gnap/zcap/controller',
            self.guarded('the ZCAP controller document',
                         async function (req, res) {
      log.debug("Entering GET /gnap/zcap/controller.");
      if (self.offCheck(res)) {
        log.debug("Leaving GET /gnap/zcap/controller. Off.");
        return;
      }
      const document = await zcap.controllerDocument(
          await tokens.zcapKeys(grants.realmBase(req)));
      res.status(200).type('application/json')
         .set('Cache-Control', 'no-store')
         .send(JSON.stringify(document, null, 2));
      log.debug("Leaving GET /gnap/zcap/controller.");
    }));

    // -----------------------------------------------------------------------
    // THE REVOKED BISCUITS (#432). A biscuit carries its own revocation
    // identifiers — one per block, the signature that sealed it — and the
    // format's own answer to revocation is a list of revoked identifiers its
    // verifier checks a token's against. No GNAP or biscuit document says
    // where such a list is published, so this is THIS SERVICE'S OWN, named
    // in the RS-facing discovery document and on /gnap/keys. JSON, unsigned
    // (it is fetched over the same TLS as the keys that verify the
    // biscuits), and an identifier stays on it until its token's own `exp`.
    // Cache-Control is max-age = `oauth2.accessTokenStatusListTtlS`, the
    // access-token list's ttl: the same promise about the same tokens.
    // -----------------------------------------------------------------------
    app.get(BISCUIT_REVOCATIONS_PATH, function (req, res) {
      log.debug("Entering GET " + BISCUIT_REVOCATIONS_PATH + ".");
      if (self.offCheck(res)) {
        log.debug("Leaving GET " + BISCUIT_REVOCATIONS_PATH + ". Off.");
        return;
      }
      let ids: string[] = [];
      try {
        ids = self.deps.loadStore().biscuitRevocationIds();
      } catch (e) {
        log.debug("Caught in GET " + BISCUIT_REVOCATIONS_PATH + ": " +
                  ((e && e.message) || e));
        log.error(errorCodes.tag('STS-GNAP-0751') + 'gnap: the revoked ' +
                  'biscuits could not be listed: ' + ((e && e.message) || e));
        errorCodes.mark(res, 'STS-GNAP-0751');
        res.status(500).type('text/plain')
           .send('The revocation list could not be built.\n');
        log.debug("Leaving GET " + BISCUIT_REVOCATIONS_PATH + ". Failed.");
        return;
      }
      const ttl =
        Number(self.deps.config.value('oauth2.accessTokenStatusListTtlS')) ||
        60;
      res.status(200).type('application/json')
         .set('Cache-Control', 'max-age=' + ttl)
         .send(JSON.stringify({ revocation_ids: ids, ttl: ttl }, null, 2));
      log.debug("Leaving GET " + BISCUIT_REVOCATIONS_PATH + ". " +
                ids.length + ".");
    });

    app.get('/gnap/rs/resource', function (req, res) {
      return self.demoResource(req, res);
    });
    app.post('/gnap/rs/resource', function (req, res) {
      return self.demoResource(req, res);
    });
    app.post('/gnap/rs/spend', function (req, res) {
      return self.demoSpend(req, res);
    });

    log.debug("Leaving GnapRoutes.registerRoutes().");
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before.
  /**
   * Returns the real modules the instance was built from before the composition
   * root (#50, R2) passed them.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): GnapRoutesDeps {
    helpers.log.debug("Entering GnapRoutes.defaultDeps().");
    helpers.log.debug("Leaving GnapRoutes.defaultDeps().");
    return {
      config: config,
      log: helpers.log,
      errorCodes: errorCodes,
      validation: validation,
      authorizationServers: authorizationServers,
      grants: grants,
      rs: rs,
      tokens: tokens,
      zcap: zcap,
      loadAccess: function () {
        return require('./gnap_access');
      },
      loadMonitor: function () {
        return require('./gnap_monitor');
      },
      loadStore: function () {
        return require('./gnap_store');
      },
      loadStatusList: function () {
        return require('../oauth-oidc/access_token_status');
      },
      loadSpend: function () {
        return require('./gnap_spend');
      },
      loadProof: function () {
        return require('./gnap_proof');
      }
    };
  }

  // What loading this module did with its instance's family before R2 (#50):
  // install GNAP's subject scope on the SSF streams. Run once, for whichever
  // instance is installed; the scope is `gnap_signals`' and needs nothing of
  // the instance itself.
  /**
   * Installs GNAP's subject scope on the Shared Signals streams, once, for
   * whichever instance is installed.
   *
   * @param _instance - the installed instance (unused)
   */
  static wire(_instance: GnapRoutes): void {
    helpers.log.debug("Entering GnapRoutes.wire().");
    signals.install();
    helpers.log.debug("Leaving GnapRoutes.wire().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<GnapRoutes>(
  'gnap/gnap',
  () => new GnapRoutes(GnapRoutes.defaultDeps()),
  GnapRoutes.wire,
  helpers.log);
// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// The pages a resource owner sees, the two console pages, and the scope hook
// on the SSF streams. The two requires register nothing (#50, R1); they are
// here so the family is one require, and `common/protocol_stack.ts` registers
// their routes after this module's. `signals.install()`, which came after
// them, is the `wire` step (#50, R2).
require('./gnap_interact');
require('./gnap_admin');

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * GNAP (RFC 9635) and its resource server connections (RFC 9767), as routes.
 *
 * This family is one require in the stack: it requires `gnap_interact.ts` and
 * `gnap_admin.ts`, and the composition root registers the three in turn.
 *
 * @namespace
 */
export = {
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: GnapRoutes): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin(),
  registerRoutes: slot.forward('registerRoutes'),
  GnapRoutes: GnapRoutes,
  DEMO_TYPE: GnapRoutes.DEMO_TYPE,
  DEMO_REFERENCE: GnapRoutes.DEMO_REFERENCE,
  gnapError: slot.forward('gnapError')
};
