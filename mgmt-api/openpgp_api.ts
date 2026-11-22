// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: openpgp_api.ts
//
// ---------------------------------------------------------------------------
// `/admin-api/openpgp` (#1955 P6): Directory → OpenPGP keys, for a machine
// (rule 7, the console/API parity rule) — and, since the console is a
// static application over `/admin-api` (#446), the operations the page is
// drawn from and posts to. Every act the portal's `/portal/openpgp` offers a
// person, an administrator may perform for them:
//
//   * `GET /admin-api/openpgp?user=<name>` — one person's OpenPGP key, its
//     pending challenge, its Web Key Directory publication, their S/MIME
//     certificate and mail encryption choice; with no `user`, only what the
//     realm's directory serves.
//   * `POST /admin-api/openpgp/<action>` with `{ user, ... }` — `challenge`,
//     `register` (`publicKey`, `signed`), `remove`, `publish`, `withdraw`,
//     `mail-encryption` (`choice`) and `smime` (`certificate`).
//
// **AN ADMINISTRATOR'S REGISTRATION IS STILL THE PERSON'S PROOF.** The
// challenge is issued for the person and names them; the administrator
// hands it over, the person signs it with their own key (their card), and
// the administrator pastes what comes back. Nothing here lets an
// administrator store a key nobody proved — the same `register()` as the
// portal's. **THE ACTOR IS THE TOKEN'S SUBJECT, NEVER THE BODY'S** (#1579);
// `user` names whom the act is for.
//
// No OpenPGP key is a way in (there is no "sign in with OpenPGP"), so none
// of these acts changes how a person authenticates, and none is a security
// operation (`common/security_operations.ts`).
// ---------------------------------------------------------------------------

import ApiRows = require('../common/api_rows');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');
import config = require('../common/config');

type Json = any;

interface OpenPgpApiDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  config: typeof config;
  // The module, lazily: it is only asked inside a handler.
  loadKeys(): Json;
}

const BASE = '/admin-api';

/** The acts, as the portal's. */
const ACTIONS = ['challenge', 'register', 'remove', 'publish', 'withdraw',
                 'mail-encryption', 'smime'];

/**
 * The `/admin-api/openpgp` operations: one person's view and the seven
 * acts.
 */
class OpenPgpApi {
  /**
   * Builds the module from its dependencies.
   *
   * @param deps - the logger, body parser, error codes and a loader of the
   *   module
   */
  constructor(private readonly deps: OpenPgpApiDeps) {
    deps.log.debug("Entering OpenPgpApi.constructor().");
    deps.log.debug("Leaving OpenPgpApi.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): OpenPgpApiDeps {
    helpers.log.debug("Entering OpenPgpApi.defaultDeps().");
    helpers.log.debug("Leaving OpenPgpApi.defaultDeps().");
    return {
      log: helpers.log, parseBody: helpers.parseBody,
      errorCodes: errorCodes, config: config,
      loadKeys: function (): Json {
        return require('../common/openpgp_keys');
      }
    };
  }

  /**
   * Builds the route table for the installed instance.
   *
   * @param instance - the instance installed
   */
  static wire(instance: OpenPgpApi): void {
    helpers.log.debug("Entering OpenPgpApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving OpenPgpApi.wire().");
  }

  /**
   * Sends a JSON body with `Cache-Control: no-store`.
   *
   * @param res - the response
   * @param status - the HTTP status
   * @param body - the body, serialised with indentation
   */
  sendJson<R, S extends number>(res: R, status: S,
           body: IyaApi.AnswerOf<R, S>): void;
  sendJson(res: any, status: number, body: any): void {
    const { log } = this.deps;
    log.debug("Entering OpenPgpApi.sendJson(). status=" + status);
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(body, null, 2));
    log.debug("Leaving OpenPgpApi.sendJson().");
  }

  /**
   * What the page draws: the realm's directory, and one person's state when
   * `user` names one.
   *
   * @param query - `user`
   * @returns `{ user, found, person, wkd: { enabled, domains } }`
   */
  view(query: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OpenPgpApi.view().");
    const keys = this.deps.loadKeys();
    const user = String((query && query.user) || '').trim().slice(0, 256);
    const one = user ? keys.view(user) : null;
    const person = one && one.ok ? {
      username: String(one.username), mail: String(one.mail),
      key: one.key, challenge: one.challenge, wkd: one.wkd,
      mailEncryption: one.mailEncryption } : null;
    // The realm's switch and domains, whoever is asked about.
    const out = { user: user, found: !!person, person: person,
                  wkd: { enabled: !!this.deps.config.value('openpgp.wkd'),
                         domains: keys.wkdDomains() } };
    log.debug("Leaving OpenPgpApi.view(). " + out.found);
    return out;
  }

  /**
   * Builds the operations' route table.
   *
   * @returns the route rows
   */
  buildRoutes(): Json[] {
    const { log, parseBody, errorCodes: codes } = this.deps;
    const self = this;
    log.debug("Entering OpenPgpApi.buildRoutes().");
    const ROUTES: IyaApi.AdminRow[] = [
      { method: 'GET', path: BASE + '/openpgp',
        tag: 'Directory', operationId: 'getOpenPgpKeys',
        mirrors: 'GET /admin/openpgp',
        parameters: [
          { name: 'user', in: 'query', required: false,
            schema: { type: 'string', maxLength: 256,
                      examples: ['alice'] },
            description: 'The person whose OpenPGP key, publication and ' +
                         'mail encryption to draw; empty for the realm\'s ' +
                         'Web Key Directory alone.' }
        ],
        handler: function (req, res): void {
          log.debug("Entering the management API OpenPGP endpoint.");
          try {
            self.sendJson(res, 200, self.view(req.query || {}));
          } catch (e) {
            log.error(codes.tag('STS-OPENPGP-0025') + 'openpgp: the view ' +
                      'could not be drawn: ' + ((e && e.message) || e));
            codes.mark(res, 'STS-OPENPGP-0025');
            self.sendJson(res, 500, { ok: false, errors: [
              'The OpenPGP keys could not be read.'] });
          }
          log.debug("Leaving the management API OpenPGP endpoint.");
        } },

      ApiRows.actions({ method: 'POST', route: BASE + '/openpgp/:action',
        tag: 'Directory', mirrors: 'POST /admin/openpgp',
        handler: function (req, res): void {
          log.debug("Entering the management API OpenPGP action.");
          const body = parseBody(req) || {};
          const action = String(req.params.action || '');
          // THE CALLER is the subject of the token the gate verified, never
          // the body's (#1579).
          const caller = res.locals && res.locals.apiCaller;
          const actor = String((caller && caller.name) || '');
          const user = String(body.user || '').trim();
          if (ACTIONS.indexOf(action) < 0) {
            codes.mark(res, 'STS-OPENPGP-0014');
            self.sendJson(res, 400, { ok: false, errors: [
              'Unknown action "' + action.slice(0, 64) + '". The actions ' +
              'are: ' + ACTIONS.join(', ') + '.'] });
            log.debug("Leaving the management API OpenPGP action. " +
                      "Unknown.");
            return;
          }
          const where = { actor: actor, via: 'api' };
          Promise.resolve().then(function (): Json {
            const keys = self.deps.loadKeys();
            switch (action) {
              case 'challenge':
                return keys.issueChallenge(user, where);
              case 'register':
                return keys.register(user, {
                  publicKey: String(body.publicKey || ''),
                  signed: String(body.signed || '') }, where);
              case 'remove':
                return keys.removeKey(user, where);
              case 'publish':
              case 'withdraw':
                return keys.setPublication(user, action === 'publish', where);
              case 'mail-encryption':
                return keys.setMailEncryption(user, String(body.choice || ''),
                                              where);
              default:
                return keys.setSmimeCertificate(user,
                  String(body.certificate || ''), where);
            }
          }).then(function (result: Json): void {
            if (!result || !result.ok) {
              const code = codes.codeOf(result) || 'STS-OPENPGP-0025';
              // error-code: none — the act's own code, read off the result
              codes.mark(res, code);
              self.sendJson(res, code === 'STS-OPENPGP-0019' ||
                code === 'STS-OPENPGP-0020' ? 500
                : (code === 'STS-OPENPGP-0013' ? 404 : 400), { ok: false,
                  errors: (result && result.errors) ||
                    [String((result && result.error) || 'Refused.')] });
              log.debug("Leaving the management API OpenPGP action. " +
                        "Refused.");
              return;
            }
            self.sendJson(res, 200, {
              ok: true,
              message: OpenPgpApi.sentence(action, user, result),
              challenge: result.challenge || null,
              view: self.view({ user: user })
            });
            log.debug("Leaving the management API OpenPGP action. Done.");
          }, function (e: any): void {
            log.error(codes.tag('STS-OPENPGP-0025') + 'openpgp: the ' +
                      action + ' act threw: ' + ((e && e.message) || e));
            codes.mark(res, 'STS-OPENPGP-0025');
            self.sendJson(res, 500, { ok: false, errors: [
              'The ' + action + ' could not be done.'] });
            log.debug("Leaving the management API OpenPGP action. Threw.");
          });
        },
        actions: [
          { action: 'challenge', operationId: 'issueOpenPgpChallenge' },
          { action: 'register', operationId: 'registerOpenPgpKey' },
          { action: 'remove', operationId: 'removeOpenPgpKey' },
          { action: 'publish', operationId: 'publishOpenPgpKey' },
          { action: 'withdraw', operationId: 'withdrawOpenPgpKey' },
          { action: 'mail-encryption',
            operationId: 'setMailEncryption' },
          { action: 'smime', operationId: 'setSmimeCertificate' }
        ] })
    ];
    log.debug("Leaving OpenPgpApi.buildRoutes().");
    return ROUTES;
  }

  /**
   * The English sentence an act's answer carries.
   *
   * @param action - the act
   * @param user - whom it was for
   * @param result - its result
   * @returns the sentence
   */
  static sentence(action: string, user: string, result: Json): string {
    helpers.log.debug("Entering OpenPgpApi.sentence(). " + action);
    const who = user || 'the person';
    let out = '';
    switch (action) {
      case 'challenge':
        out = 'A challenge was issued for ' + who + '. Hand it to them to ' +
          'sign with gpg --clearsign; it lapses at ' +
          String((result.challenge && result.challenge.expiresAt) || '') +
          '.';
        break;
      case 'register':
        out = 'The OpenPGP key ' + String(result.fingerprint) + ' is ' +
          'registered for ' + who + (result.replaced ? ', replacing ' +
          String(result.replaced) : '') + '.';
        break;
      case 'remove':
        out = 'The OpenPGP key of ' + who + ' was removed.';
        break;
      case 'publish':
        out = 'The OpenPGP key of ' + who + ' is published in the Web Key ' +
          'Directory, where the realm serves its domain.';
        break;
      case 'withdraw':
        out = 'The OpenPGP key of ' + who + ' is no longer published.';
        break;
      case 'mail-encryption':
        out = 'Mail to ' + who + ' is now ' + (result.choice === 'none'
          ? 'not encrypted' : 'encrypted with ' + (result.choice ===
            'openpgp' ? 'OpenPGP' : 'S/MIME')) + '.';
        break;
      default:
        out = result.removed ? 'The S/MIME certificate of ' + who +
          ' was removed.' : 'The S/MIME certificate of ' + who +
          ' is set (' + String(result.serial || '') + ').';
        break;
    }
    helpers.log.debug("Leaving OpenPgpApi.sentence().");
    return out;
  }
}

let routes: Json[] = [];

const slot = new InstanceSlot<OpenPgpApi>(
  'mgmt-api/openpgp_api',
  () => new OpenPgpApi(OpenPgpApi.defaultDeps()),
  OpenPgpApi.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The OpenPGP operations of `/admin-api` (#1955 P6), mirroring Directory →
 * OpenPGP keys. It registers no route: the management API spreads `ROUTES`
 * into its table.
 *
 * @namespace
 */
export = {
  OpenPgpApi: OpenPgpApi,
  ACTIONS: ACTIONS,
  installInstance: (instance: OpenPgpApi): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  get ROUTES(): Json[] {
    helpers.log.debug("Entering ROUTES().");
    slot.get();
    helpers.log.debug("Leaving ROUTES().");
    return routes;
  }
};
