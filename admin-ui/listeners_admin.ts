// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: listeners_admin.ts
//
// ===========================================================================
// SERVER CONFIGURATION → LISTENERS (#423, 2026-10-02, rcbj: "Put all the
// listener configuration, including TLS on its own page under Server
// Settings->Listeners. Each realm will have its own listener configuration or
// if the realm uses the default listeners, just present those.").
//
// `GET /admin/listeners` is every socket this process answers on and what each
// one is held to:
//   * the port and whether it is TLS;
//   * for a TLS listener, the policy in force: TLS 1.2 on or off, the TLS 1.3
//     suites in order, post-quantum only, the groups, and whether it asks for
//     a client certificate, requires one, or neither — `tls_server.js`'s
//     `policyFor()`, the same function the listener was keyed from;
//   * the settings that decide all of it, drawn here (SETTING_HOMES sends the
//     Listeners, TLS and Custom listeners groups to this page).
//
// **AND THE CUSTOM LISTENERS, AND WHICH APPLICATION IS ON WHICH (#472,
// 2026-10-07).** The listeners an administrator defined — the service's
// (`listeners.custom`) and, in a realm, the realm's own (`listeners.realm`,
// what #99's realm listener became) — each with its address, certificate,
// client authentication, state on this node and policy in force; the hosted
// applications, the listeners each is on and the one it is advertised on,
// and whether the realm or the service decided (`listeners.applications`);
// and what is wrong or worth a warning (`common/listener_map.js`'s
// `health()`). Two writes, `set-listeners` and `set-applications`, take the
// JSON a person edits on the page; `confirm` is the one way to take the
// management API off the listener the write arrives on (rcbj's D6).
//
// The built-in listeners' settings are the process's: drawn read-only in a
// realm (a realm may carry none of them: they are `perProcess`), edited in
// the default realm.
//
// **ANSWERED BY THE FRONT PROCESS** (`request_pool.js`'s NEVER_DISPATCHED): the
// listeners and their state are that process's, and a request worker binds no
// socket.
//
// Rule 7: `GET /admin-api/listeners` answers `listenersView()`, the function
// the page's `?format=json` answers.
//
// TYPESCRIPT, AS A CLASS (#50): `mode_admin.ts`'s shape — dependencies through
// the constructor, `registerRoutes(app)` called by `common/protocol_stack.ts`
// (18k-iii), facades for the JavaScript callers.
// ===========================================================================

import admin = require('./admin');
import helpers = require('../common/helpers');
import config = require('../common/config');
import realms = require('../common/realms');
import InstanceSlot = require('../common/instance_slot');
// The custom listeners and the mapping (#472). A LEAF.
import listenerMap = require('../common/listener_map');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import ListenersPage = require('./web_listeners');

type Req = any;
type Res = any;
type Json = any;

/**
 * The console path of Server configuration → Listeners.
 */
const PAGE = '/admin/listeners';

// EVERY SOCKET THE PROCESS OWNS, by the setting that names its port. `kind`
// is `tls_server.js`'s policy kind for a TLS listener and null for one that is
// not TLS; `clientAuth`, where the protocol fixes it, says how.
const LISTENERS = [
  { id: 'main', name: 'Main port', setting: 'global.port', kind: 'main',
    http: 'main',
    group: 'Listener: Main port',
    tlsWhen: 'global.https',
    what: 'Every HTTP protocol, the console and the portal.' },
  { id: 'ldap', name: 'LDAP', setting: 'ldap.port', kind: null,
    what: 'The embedded directory, in the clear.' },
  { id: 'ldaps', name: 'LDAPS', setting: 'ldap.tlsPort', kind: 'ldaps',
    group: 'Listener: LDAPS',
    what: 'The embedded directory over TLS.' },
  { id: 'debugger', name: 'Protocol debugger', setting: 'debugger.port',
    kind: 'debugger', tlsWhen: 'global.https', http: 'debugger',
    group: 'Listener: Protocol debugger',
    what: 'The embedded protocol debugger, where one is embedded.' },
  { id: 'kdc', name: 'Kerberos KDC', setting: 'krb5.kdcPort', kind: null,
    what: 'TCP and UDP 88; Kerberos messages, not TLS.' },
  { id: 'krb5-service', name: 'Kerberos test service',
    setting: 'krb5.servicePort', kind: null,
    what: 'The SPNEGO-protected test service.' },
  { id: 'revocation', name: 'Revocation (plain HTTP)',
    setting: 'pki.httpPort', kind: null, http: 'revocation',
    group: 'Listener: Revocation (plain HTTP)',
    what: 'CRLs and OCSP over plain HTTP, as RFC 5280 section 8 asks.' },
  { id: 'spiffe-workload', name: 'SPIFFE Workload API (TCP)',
    setting: 'spiffe.workloadPort', kind: null,
    what: 'Not TLS: the specification\'s transport is the caller\'s ' +
          'network, which product serves only where it is declared ' +
          'authenticated.' },
  { id: 'spiffe-server', name: 'SPIRE Server API', setting: 'spiffe.serverPort',
    kind: 'spiffeServer', group: 'Listener: SPIRE Server API',
    clientAuth: 'asked for, not required: an agent with no SVID yet must ' +
                'reach AttestAgent (the protocol\'s)',
    what: 'Mutual TLS under each realm\'s trust domain.' },
  { id: 'spiffe-broker', name: 'SPIFFE Broker API', setting: 'spiffe.brokerPort',
    kind: 'spiffeBroker', group: 'Listener: SPIFFE Broker API',
    clientAuth: 'required: a broker\'s X509-SVID (the protocol\'s)',
    what: 'Mutual TLS for the brokers in spiffe.brokers.' },
  { id: 'cell', name: 'Channel between cells', setting: 'cells.port',
    kind: 'cell', group: 'Listener: Channel between cells',
    clientAuth: 'required: another cell\'s certificate (the protocol\'s)',
    what: 'Mutual TLS between the cells of one service; TLS 1.3 always.' }
];

interface ListenersAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  config: typeof config;
  realms: typeof realms;
  // Lazily: `tls/tls_server.js` is a JavaScript route module, and
  // `tls/listeners.js` belongs to the front process.
  tlsServer: () => any;
  customListeners: () => any;
}

/**
 * Server configuration → Listeners: every socket the process answers on, the
 * TLS policy and client authentication each is held to, the custom listeners
 * and which hosted application is on which, and the settings that decide
 * them.
 */
class ListenersAdmin {
  /**
   * See the module's `PAGE`.
   */
  static readonly PAGE = PAGE;

  /**
   * Builds an instance over the modules it depends on.
   *
   * @param deps - the logger, the console, the settings, the realms and the
   *   two TLS modules
   */
  constructor(private readonly deps: ListenersAdminDeps) {
    deps.log.debug("Entering ListenersAdmin.constructor().");
    deps.log.debug("Leaving ListenersAdmin.constructor().");
  }

  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): ListenersAdminDeps {
    helpers.log.debug("Entering ListenersAdmin.defaultDeps().");
    helpers.log.debug("Leaving ListenersAdmin.defaultDeps().");
    return {
      log: helpers.log, admin: admin, config: config, realms: realms,
      tlsServer: function (): any {
        return require('../tls/tls_server');
      },
      customListeners: function (): any {
        return require('../tls/listeners');
      }
    };
  }

  // A policy as the page and the API show it: what `policyFor()` decided and
  // what `protocolOptions()` makes of it, which is what the listener has.
  private described(policy: Json): Json {
    const { log, tlsServer } = this.deps;
    log.debug("Entering ListenersAdmin.described().");
    const options = tlsServer().protocolOptions(policy);
    const tls12 = String(options.ciphers || '').split(':')
      .filter(function (one: string): boolean {
        return one !== '' && !/^TLS_/.test(one);
      });
    const suites = tlsServer().TLS13_SUITES;
    log.debug("Leaving ListenersAdmin.described().");
    return {
      minVersion: options.minVersion,
      tls12: !policy.disableTls12,
      tls13Suites: policy.tls13Suites.map(function (name: string): Json {
        return { name: name,
                 postQuantum: !!(suites[name] && suites[name].postQuantum) };
      }),
      tls12Ciphers: tls12,
      pqcOnly: !!policy.pqcOnly,
      groups: options.ecdhCurve || '(node default)',
      signatureAlgorithms: options.sigalgs || '(OpenSSL default)',
      sessionTimeoutS: policy.sessionTimeoutS,
      sessionCacheSize: policy.sessionCacheSize,
      truststore: policy.kind === 'spiffeServer' ||
                  policy.kind === 'spiffeBroker' || policy.kind === 'cell'
        ? '(the protocol\'s own trust bundle)'
        : (policy.trustAnchorsFile ? 'its own file ' + policy.trustAnchorsFile
                                   : 'the service\'s anchors') +
          (policy.trustIssued ? ' and the service Root' : ''),
      clientAuth: policy.clientAuth
    };
  }

  /**
   * Answers the page's JSON and `GET /admin-api/listeners`: the realm the
   * page is read in, the built-in listeners, the custom listeners this realm
   * sees, the hosted applications and where each is, and what is wrong.
   *
   * @returns the view
   */
  listenersView(): Json {
    const { log, config, realms, tlsServer, customListeners,
            admin } = this.deps;
    const self = this;
    log.debug("Entering ListenersAdmin.listenersView().");
    const realm = realms.current();
    const realmId = realm ? realm.id : realms.DEFAULT_ID;
    const isDefault = realmId === realms.DEFAULT_ID;
    const https = config.value('global.https') === true;
    const listeners = LISTENERS.map(function (row: Json): Json {
      let port: unknown = null;
      try {
        port = (config as any).processValue(row.setting);
      } catch (e) {
        log.debug("Caught in ListenersAdmin.listenersView(): " +
                  ((e && e.message) || e));
      }
      const isTls = !!row.kind && (!row.tlsWhen || https);
      const policy = isTls ? tlsServer().policyFor(row.kind) : null;
      const described = policy ? self.described(policy) : null;
      if (described && row.clientAuth) {
        described.clientAuth = row.clientAuth;
      }
      if (described && row.kind === 'cell') {
        described.minVersion = 'TLSv1.3';
        described.tls12 = false;
        described.tls12Ciphers = [];
      }
      return { id: row.id, name: row.name, setting: row.setting,
               port: port, tls: isTls, what: row.what, group: row.group || null,
               policy: described,
               // HTTP connection pooling (#429), for an HTTP listener.
               http: row.http ? tlsServer().httpPolicyFor(row.http) : null };
    });
    // THE CUSTOM LISTENERS (#472) this realm can see: the service's, and its
    // own — every realm's own, in the default realm, which administers them
    // all. Each with what THIS node holds of it.
    let held: Json[] = [];
    try {
      held = customListeners().status();
    } catch (e) {
      log.debug("Caught in ListenersAdmin.listenersView(): " +
                ((e && e.message) || e));
    }
    const custom = listenerMap.allListeners().filter(function (one: Json) {
      return !one.builtin && (isDefault || one.owner === realms.DEFAULT_ID ||
                              one.owner === realmId);
    }).map(function (one: Json): Json {
      const here = held.filter(function (h: Json): boolean {
        return h.id === one.id;
      })[0] || null;
      return {
        id: one.id, label: one.label, owner: one.owner, port: one.port,
        publicBaseUrl: one.publicBaseUrl, hostnames: one.hostnames,
        clientAuth: one.clientAuth,
        certificateSource: one.certificateFile ? 'file' : 'issued',
        tls: one.tls,
        state: here ? here.state : 'not bound on this node',
        why: here ? here.why : '', code: here ? here.code : '',
        certificate: here ? here.certificate : null,
        policy: self.described(tlsServer().policyFor('custom', one.id)),
        http: tlsServer().httpPolicyFor('custom', one.id)
      };
    });
    const live = (function (): Json[] {
      try {
        return tlsServer().listenerPolicies().map(function (one: Json): Json {
          return { label: one.label, kind: one.kind, realm: one.realm };
        });
      } catch (e) {
        log.debug("Caught in ListenersAdmin.listenersView(): " +
                  ((e && e.message) || e));
        return [];
      }
    })();
    const health = listenerMap.health();
    const raw = function (key: string, own: boolean): string {
      log.debug("Entering raw(). " + key);
      if (own) {
        const o = (realm && realm.overrides) || {};
        log.debug("Leaving raw(). The realm's own.");
        return Object.prototype.hasOwnProperty.call(o, key)
          ? String(o[key] || '') : '';
      }
      log.debug("Leaving raw(). The process's.");
      return String((config as any).processValue(key) || '');
    };
    const view = {
      realm: realmId,
      listeners: listeners,
      custom: custom,
      applications: listenerMap.mappingView(),
      // What the two writes edit, as the JSON a person reads and changes:
      // the listeners this realm defines (the service's in the default
      // realm), and the mapping it states — its own entries in a realm, the
      // service's below them.
      definitions: {
        listeners: raw(isDefault ? listenerMap.SERVICE_SETTING
                                 : listenerMap.REALM_SETTING, !isDefault),
        applications: raw(listenerMap.MAP_SETTING, !isDefault),
        serviceApplications: isDefault ? ''
          : raw(listenerMap.MAP_SETTING, false),
        cookieDomain: String(config.value(listenerMap.COOKIE_SETTING) || '')
      },
      rescue: (config as any).processValue(listenerMap.RESCUE_SETTING) ===
              true,
      problem: health.problem,
      warnings: health.warnings,
      process: self.described(tlsServer().policyFor()),
      live: live,
      // The settings the page's tabs draw, as every page that owns settings
      // answers them (#446): the page is drawn from this view alone.
      settings: admin.configSettingsJson(PAGE)
    };
    log.debug("Leaving ListenersAdmin.listenersView(). " + custom.length);
    return view;
  }

  /**
   * The page's two writes, and `POST /admin-api/listeners/{action}`'s:
   * `set-listeners` replaces the listeners the ambient realm defines (the
   * service's in the default realm), and `set-applications` its mapping of
   * applications to listeners; `value` is the JSON, empty to clear. A
   * mapping that takes the management API off the listener the request
   * arrived on needs `confirm` (rcbj's D6).
   *
   * @param req - the request, `action` on it
   * @param body - `{ value, confirm }`
   * @returns `{ ok, errors }`, carrying its error code when refused
   */
  listenersAction(req: Req, body: Json): Json {
    const { log, config, realms } = this.deps;
    log.debug("Entering ListenersAdmin.listenersAction().");
    const action = String((req && req.params && req.params.action) ||
                          (body && body.action) || '');
    const realm = realms.current();
    const isDefault = !realm || realm.id === realms.DEFAULT_ID;
    let key = '';
    if (action === 'set-listeners') {
      key = isDefault ? listenerMap.SERVICE_SETTING
                      : listenerMap.REALM_SETTING;
    } else if (action === 'set-applications') {
      key = listenerMap.MAP_SETTING;
    } else {
      log.debug("Leaving ListenersAdmin.listenersAction(). Unknown.");
      return (require('../common/error_codes') as any).mark({ ok: false,
        errors: ['No such action "' + action + '": set-listeners or ' +
                 'set-applications.'] }, 'STS-CORE-0153');
    }
    const given = body ? body.value : undefined;
    const text = given === undefined || given === null ? ''
      : typeof given === 'string' ? given.trim() : JSON.stringify(given);
    const confirm = !!(body && (body.confirm === true ||
                                body.confirm === 'true' ||
                                body.confirm === 'on'));
    // Read by `listener_map.js`'s rule through the ambient request: the one
    // door through which the management API may leave the listener it was
    // reached on.
    if (req) {
      req.stsListenerChangeConfirmed = confirm;
    }
    // AN EMPTY VALUE IS WRITTEN, NEVER A RESET: a reset drops the override
    // without asking the rules a write is held to, and a mapping left naming
    // a listener just removed is the state they exist to refuse. Empty means
    // none, here and in the realm (whose own empty mapping inherits the
    // service's).
    let result: Json;
    try {
      result = isDefault ? config.setOverride(key, text)
                         : realms.setOverride(realm.id, key, text);
    } finally {
      if (req) {
        req.stsListenerChangeConfirmed = false;
      }
    }
    log.debug("Leaving ListenersAdmin.listenersAction(). " +
              !!(result && result.ok));
    return result;
  }

  // DRAWN BY `web_listeners.ts` (#446): this page is converted for the static
  // console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  private html(json: Json): string {
    const { log } = this.deps;
    log.debug("Entering ListenersAdmin.html().");
    const drawn = ListenersPage.render(JSON.parse(JSON.stringify(json)));
    log.debug("Leaving ListenersAdmin.html().");
    return drawn;
  }

  /**
   * Registers `GET /admin/listeners`.
   *
   * @param app - the shared express app
   */
  registerRoutes(app: { get: Function }): void {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering ListenersAdmin.registerRoutes().");
    log.debug("Leaving ListenersAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<ListenersAdmin>(
  'admin-ui/listeners_admin',
  () => new ListenersAdmin(ListenersAdmin.defaultDeps()),
  null,
  helpers.log);
slot.buildNowUnlessDeferred();

/**
 * Server configuration → Listeners, `/admin/listeners`: every socket the
 * process answers on with its TLS policy and client authentication, or a
 * realm's own listener, and the settings that decide them.
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  ListenersAdmin: ListenersAdmin,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: ListenersAdmin): void => slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE,
  // For `mgmt-api/admin_api.ts` (rule 7).
  listenersView: slot.forward('listenersView'),
  listenersAction: slot.forward('listenersAction')
};
