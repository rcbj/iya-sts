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
//     Listeners, TLS and Realm listener groups to this page).
//
// **WHICH LISTENERS DEPENDS ON THE REALM THE PAGE IS READ IN.** A realm with a
// listener of its own (#99, `listener.port`) is shown THAT listener — its
// address, certificate, state and policy — with its `listener.*` rows; a
// realm without one is served on the default listeners, and is shown those,
// with the process's settings drawn read-only (a realm may carry none of them:
// they are `perProcess`). The default realm is shown the default listeners and
// edits them.
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
  // `tls/realm_listeners.js` belongs to the front process.
  tlsServer: () => any;
  realmListeners: () => any;
}

/**
 * Server configuration → Listeners: every socket the process answers on, the
 * TLS policy and client authentication each is held to, and the settings that
 * decide them — or, in a realm with a listener of its own, that listener.
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
      realmListeners: function (): any {
        return require('../tls/realm_listeners');
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
   * page is read in, whether it is served on a listener of its own, and
   * either that listener or the default listeners, each with its policy.
   *
   * @returns the view
   */
  listenersView(): Json {
    const { log, config, realms, tlsServer, realmListeners,
            admin } = this.deps;
    const self = this;
    log.debug("Entering ListenersAdmin.listenersView().");
    const realm = realms.current();
    const realmId = realm ? realm.id : realms.DEFAULT_ID;
    const isDefault = realmId === realms.DEFAULT_ID;
    let own: Json = null;
    if (!isDefault && Number(config.value('listener.port')) > 0) {
      let state: Json = null;
      try {
        state = realmListeners().status(realmId)[0] || null;
      } catch (e) {
        log.debug("Caught in ListenersAdmin.listenersView(): " +
                  ((e && e.message) || e));
      }
      own = {
        port: Number(config.value('listener.port')),
        publicBaseUrl: String(config.value('listener.publicBaseUrl') || ''),
        state: state ? state.state : 'not bound on this node',
        why: state ? state.why : '',
        certificate: state ? state.certificate : null,
        policy: self.described(tlsServer().policyFor('realm', realmId)),
        http: tlsServer().httpPolicyFor('realm', realmId)
      };
    }
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
    const view = {
      realm: realmId,
      servedOn: own ? 'own' : 'default',
      ownListener: own,
      listeners: own ? [] : listeners,
      process: self.described(tlsServer().policyFor()),
      live: live,
      // The settings the page's tabs draw, as every page that owns settings
      // answers them (#446): the page is drawn from this view alone.
      settings: admin.configSettingsJson(PAGE)
    };
    log.debug("Leaving ListenersAdmin.listenersView(). " + view.servedOn);
    return view;
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
    app.get(PAGE, function (req: Req, res: Res): void {
      log.debug('Entering GET ' + PAGE + '.');
      const json = self.listenersView();
      admin.respond(req, res, json, 'Listeners', PAGE,
                    admin.messagesOf(req) + self.html(json));
      log.debug('Leaving GET ' + PAGE + '.');
    });
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
  listenersView: slot.forward('listenersView')
};
