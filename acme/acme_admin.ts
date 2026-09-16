'use strict';
//
// File: acme_admin.ts
//
// ---------------------------------------------------------------------------
// THE TWO ACME CONSOLE PAGES: Protocols -> ACME and Monitoring -> ACME
// enrollments.
//
// Drawn here, in the console's shell through `admin.respond()`, the way
// `gnap/gnap_admin.ts` draws GNAP's. Every fact on either page comes out of ONE
// call to `acme_console.ts`, which is the same call `/admin-api/acme` and
// `/admin-api/acme/monitor` answer with (rule 7).
//
// **WHERE EACH IS FILED IS DECIDED BY THE QUESTION IT ANSWERS.** `/admin/acme`
// is what the server IS — its directory, its Issuing CA, the profiles, the EAB
// keys, the accounts, the certificates, the host names an entry may be issued
// for, and the `acme.*` settings. `/admin/acme/monitor` is what it has DONE,
// and carries no control: a console that could zero its own monitoring would
// make every number on it one somebody might have zeroed.
//
// **ONE ACTION ANSWERS A PAGE AND NOT A REDIRECT: `create-eab`.** Its reply
// holds the HMAC key, which a client cannot be configured without and which is
// never shown again — and `respondToAction()` answers a 303 whose message rides
// on the query string, which is the browser history, the access log and the
// next request's Referer. So that one action renders a 200 page with
// `Cache-Control: no-store` (through `admin.respond()`), and every other action
// goes through `respondToAction()`.
//
// No script, like every page of this console but one: paging is links and each
// control is a form the console gate checks CSRF and Admin Write on.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `AcmeAdmin` takes the modules it uses through its constructor
// (`AcmeAdminDeps`), and the module still exports its old names from a
// TRANSITIONAL instance built from the real modules, for the callers that
// are not converted. `AcmeAdmin` is exported beside them for the
// composition root.
//
// **THE ROUTES ARE REGISTERED BY `registerRoutes()`**, which the
// transitional code calls at load where the first route used to be
// registered, so rule 1's order is unchanged.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import helpers = require('../common/helpers');
const { log, parseBody } = helpers;
import errorCodes = require('../common/error_codes');
import validation = require('../common/validation');
import admin = require('../admin-ui/admin');
import consoleModel = require('./acme_console');

const esc = admin.esc;
const vz = validation.z;
const vt = validation.types;

const PAGE_QUERY = vz.looseObject({
  per: vt.opt(vt.integer(1, 1000)),
  page: vt.opt(vt.integer(1, 1000000)),
  certificatesPage: vt.opt(vt.integer(1, 1000000)),
  credentialsPage: vt.opt(vt.integer(1, 1000000)),
  accountsPage: vt.opt(vt.integer(1, 1000000)),
  hostNamesPage: vt.opt(vt.integer(1, 1000000)),
  format: vt.opt(vt.oneOf(['json', 'JSON', 'html']))
});

const ACTION_FORM = vz.looseObject({
  action: vt.token,
  csrf_token: vt.opt(vt.token)
});

// What `AcmeAdmin` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface AcmeAdminDeps {
  log: typeof log;
  parseBody: typeof parseBody;
  errorCodes: typeof errorCodes;
  validation: typeof validation;
  admin: typeof admin;
  consoleModel: typeof consoleModel;
  esc: typeof esc;
}

type RouteApp = typeof app;

class AcmeAdmin {
  constructor(private readonly deps: AcmeAdminDeps) {
    deps.log.debug("Entering AcmeAdmin.constructor().");
    deps.log.debug("Leaving AcmeAdmin.constructor().");
  }

  queryRefused(req, res) {
    const { log, validation, errorCodes } = this.deps;
    log.debug("Entering AcmeAdmin.queryRefused().");
    const query = validation.check(req, 'query', PAGE_QUERY);
    if (!query.ok) {
      errorCodes.mark(res, 'STS-ACME-0097');
      res.status(400)
         .type('text/plain')
         .set('Cache-Control', 'no-store')
         .send(query.detail);
      log.debug("Leaving AcmeAdmin.queryRefused(). Refused.");
      return true;
    }
    log.debug("Leaving AcmeAdmin.queryRefused().");
    return false;
  }

  code(value) {
    const { log, esc } = this.deps;
    log.debug("Entering AcmeAdmin.code().");
    log.debug("Leaving AcmeAdmin.code().");
    return value ? '<code>' + esc(value) + '</code>'
                 : '<span class="sub">—</span>';
  }

  nav(req, list, param) {
    const { log, admin } = this.deps;
    log.debug("Entering AcmeAdmin.nav(). param=" + param);
    log.debug("Leaving AcmeAdmin.nav().");
    return admin.pageNavPair('/admin/acme', req.query,
                             Object.assign({}, list.paging,
                                           { param: param, noun: 'rows' }));
  }

  hidden(name, value) {
    const { log, esc } = this.deps;
    log.debug("Entering AcmeAdmin.hidden().");
    log.debug("Leaving AcmeAdmin.hidden().");
    return '<input type="hidden" name="' + esc(name) + '" value="' +
           esc(value) + '">';
  }

  kindSelect() {
    const { log } = this.deps;
    log.debug("Entering AcmeAdmin.kindSelect().");
    log.debug("Leaving AcmeAdmin.kindSelect().");
    return '<select name="kind"><option value="person">person</option>' +
           '<option value="application">application</option></select>';
  }

  // ---------------------------------------------------------------------------
  // THE SECTIONS OF /admin/acme.
  // ---------------------------------------------------------------------------
  endpointsHtml(json) {
    const { log, esc } = this.deps;
    log.debug("Entering AcmeAdmin.endpointsHtml().");
    log.debug("Leaving AcmeAdmin.endpointsHtml().");
    return '<table class="kv">' + Object.keys(json.endpoints).map(
      function (name) {
        return '<tr><th>' + esc(name) + '</th><td><code>' +
               esc(json.endpoints[name]) + '</code></td></tr>';
      }).join('') + '</table>';
  }

  authorityHtml(json) {
    const { log, admin, esc } = this.deps;
    log.debug("Entering AcmeAdmin.authorityHtml().");
    const a = json.authority;
    if (!a.present) {
      log.debug("Leaving AcmeAdmin.authorityHtml(). None.");
      return admin.warn(esc(a.note));
    }
    log.debug("Leaving AcmeAdmin.authorityHtml().");
    return '<table class="kv"><tr><th>Subject</th><td>' + this.code(a.subject) +
      '</td></tr><tr><th>Serial</th><td>' + this.code(a.serialHex) +
      '</td></tr>' +
      '<tr><th>Key / signs with</th><td>' + this.code(a.keyAlg) + ' / ' +
      this.code(a.signatureAlg) + '</td></tr><tr><th>Valid until</th><td>' +
      esc(a.notAfter) + '</td></tr><tr><th>Under</th><td>' +
      this.code(a.intermediate) + ' &larr; ' + this.code(a.root) +
      '</td></tr></table>' +
      '<p class="sub">A certificate is served with this Issuing CA and the ' +
      'realm Intermediate, never the Root. <a href="/admin/pki">PKI</a> ' +
      'manages the hierarchy; the CRL is ' +
      '<code>/pki/crl/{realm}/acme</code>.</p>';
  }

  profilesHtml(json) {
    const { log, esc } = this.deps;
    log.debug("Entering AcmeAdmin.profilesHtml().");
    const rows = json.profiles.map(function (p) {
      return '<tr><td><code>' + esc(p.id) + '</code>' +
        (p.isDefault ? ' <span class="sub">default</span>' : '') + '</td><td>' +
        esc(p.description) + '</td><td>' + (p.needs ? esc(p.needs) :
                                             '<span class="sub">—</span>') +
        '</td><td>' + (p.allowed ? 'yes' : '<strong>no</strong> ' +
                       '<span class="sub">not in acme.allowedProfiles</span>') +
        '</td></tr>';
    }).join('');
    const refused = json.refusedProfiles.map(function (p) {
      return '<tr><td><code>' + esc(p.id) + '</code></td><td colspan="3">' +
             '<strong>never issued over ACME.</strong> ' + esc(p.why) +
             '</td></tr>';
    }).join('');
    log.debug("Leaving AcmeAdmin.profilesHtml().");
    return '<table><thead><tr><th>Profile</th><th>What</th><th>Needs</th>' +
           '<th>Allowed here</th></tr></thead><tbody>' + rows + refused +
           '</tbody></table><p class="sub">An order names one in its ' +
           '<code>profile</code> member (draft-ietf-acme-profiles); the ' +
           'directory advertises the allowed ones in ' +
           '<code>meta.profiles</code>.</p>';
  }

  eabHtml(req, json) {
    const { log, esc } = this.deps;
    const self = this;
    log.debug("Entering AcmeAdmin.eabHtml().");
    const list = json.eabKeys;
    const pager = this.nav(req, list, 'credentialsPage');
    const rows = list.rows.length ? list.rows.map(function (k) {
      return '<tr><td><code>' + esc(k.kid) + '</code></td><td>' +
        self.code(k.entryUri) + '</td><td>' + esc(k.status) + '</td><td>' +
        esc(k.createdAt) + '<div class="sub">by ' + esc(k.createdBy || '—') +
        '</div></td><td>' + esc(k.expiresAt) + '</td><td>' +
        self.code(k.boundAccount) + '</td><td><form method="post" ' +
        'action="/admin/acme">' + self.hidden('action', 'delete-eab') +
        self.hidden('kid', k.kid) +
        '<button type="submit" class="danger">Delete' +
        '</button></form></td></tr>';
    }).join('') : '<tr><td colspan="7" class="sub">No External Account ' +
                  'Binding key has been issued in this realm.</td></tr>';
    log.debug("Leaving AcmeAdmin.eabHtml().");
    return '<form method="post" action="/admin/acme" class="inline">' +
      this.hidden('action', 'create-eab') + '<label>For ' + this.kindSelect() +
      '</label> <label>identifier <input name="identifier" size="24" ' +
      'required></label> <label>lifetime (s) <input name="lifetimeS" ' +
      'size="8" placeholder="' + esc(String(json.eabLifetimeS || '')) +
      '"></label> <button type="submit">Create EAB key</button></form>' +
      '<p class="sub">The key is shown once, on the page that answers this ' +
      'form, with a ready-to-paste certbot line. It binds ONE account, which ' +
      'is bound to that entry for life.</p>' + pager.head +
      '<table id="list-credentialsPage"><thead><tr><th>Key id</th><th>Entry' +
      '</th><th>Status</th><th>Created</th><th>Expires</th><th>Bound account' +
      '</th><th></th></tr></thead><tbody>' + rows + '</tbody></table>' +
      pager.foot;
  }

  accountsHtml(req, json) {
    const { log, esc } = this.deps;
    const self = this;
    log.debug("Entering AcmeAdmin.accountsHtml().");
    const list = json.accounts;
    const pager = this.nav(req, list, 'accountsPage');
    const rows = list.rows.length ? list.rows.map(function (a) {
      return '<tr><td><code>' + esc(a.id) + '</code></td><td>' +
        self.code(a.entryUri) + '</td><td>' + esc(a.status) + '</td><td>' +
        self.code(a.eabKid) + '</td><td>' + esc((a.contact || []).join(', ') ||
                                          '—') + '</td><td class="num">' +
        a.orders + '</td><td>' + esc(a.createdAt) + '</td><td>' +
        (a.status === 'valid' ? '<form method="post" action="/admin/acme">' +
         self.hidden('action', 'deactivate-account') +
         self.hidden('account', a.id) +
         '<button type="submit" class="danger">Deactivate</button></form>'
                              : '<span class="sub">' + esc(a.status) +
                                '</span>') + '</td></tr>';
    }).join('') : '<tr><td colspan="8" class="sub">No ACME account exists in ' +
                  'this realm.</td></tr>';
    log.debug("Leaving AcmeAdmin.accountsHtml().");
    return pager.head + '<table id="list-accountsPage"><thead><tr><th>Account' +
      '</th><th>Bound to</th><th>Status</th><th>EAB key</th><th>Contact</th>' +
      '<th>Orders</th><th>Created</th><th></th></tr></thead><tbody>' + rows +
      '</tbody></table>' + pager.foot;
  }

  certificatesHtml(req, json) {
    const { log, esc } = this.deps;
    const self = this;
    log.debug("Entering AcmeAdmin.certificatesHtml().");
    const list = json.certificates;
    const pager = this.nav(req, list, 'certificatesPage');
    const reasons = json.revocationReasons.map(function (r) {
      return '<option value="' + esc(r) + '">' + esc(r) + '</option>';
    }).join('');
    const rows = list.rows.length ? list.rows.map(function (c) {
      const control = c.revoked
        ? '<span class="sub">revoked ' + esc(c.revoked.at || '') + ' (' +
          esc(c.revoked.reason || '') + ')</span>'
        : '<form method="post" action="/admin/acme">' +
          self.hidden('action', 'revoke-certificate') +
          self.hidden('serial', c.serialHex) +
          '<select name="reason">' + reasons + '</select> <button ' +
          'type="submit" class="danger">Revoke</button></form>';
      return '<tr><td><code>' + esc(c.serialHex) + '</code></td><td>' +
        self.code(c.profile) + '</td><td>' + self.code(c.entryUri) +
        '<div class="sub">' +
        esc((c.names || []).join(', ')) + '</div></td><td>' + esc(c.status) +
        '</td><td>' + esc(c.notAfter) + '</td><td>' + self.code(c.account) +
        '</td><td>' + control + '</td></tr>';
    }).join('') : '<tr><td colspan="7" class="sub">No certificate has been ' +
                  'issued over ACME in this realm.</td></tr>';
    log.debug("Leaving AcmeAdmin.certificatesHtml().");
    return pager.head + '<table id="list-certificatesPage"><thead><tr><th>' +
      'Serial</th><th>Profile</th><th>Entry and names</th><th>Status</th><th>' +
      'Expires</th><th>Account</th><th></th></tr></thead><tbody>' + rows +
      '</tbody></table>' + pager.foot;
  }

  hostNamesHtml(req, json) {
    const { log, esc } = this.deps;
    const self = this;
    log.debug("Entering AcmeAdmin.hostNamesHtml().");
    const list = json.hostNames;
    const pager = this.nav(req, list, 'hostNamesPage');
    const rows = list.rows.length ? list.rows.map(function (h) {
      return '<tr><td>' + self.code(h.entryUri) + '</td><td>' +
        h.hostNames.map(function (name) {
          return '<form method="post" action="/admin/acme" class="inline">' +
            self.hidden('action', 'remove-host-name') +
            self.hidden('kind', h.entry.kind) +
            self.hidden('identifier', h.entry.id) +
            self.hidden('hostName', name) +
            '<code>' + esc(name) + '</code> <button type="submit" ' +
            'class="danger">Remove</button></form>';
        }).join(' ') + '</td></tr>';
    }).join('') : '<tr><td colspan="2" class="sub">No host name is ' +
                  'registered on any entry in this realm.</td></tr>';
    log.debug("Leaving AcmeAdmin.hostNamesHtml().");
    return '<form method="post" action="/admin/acme" class="inline">' +
      this.hidden('action', 'add-host-name') + '<label>On ' +
      this.kindSelect() +
      '</label> <label>identifier <input name="identifier" size="20" ' +
      'required></label> <label>host name or address <input name="hostName" ' +
      'size="28" required></label> <button type="submit">Register</button>' +
      '</form><p class="sub">A dns or ip identifier is authorized for an ' +
      'account only when it is registered on the entry the account is bound ' +
      'to. Nothing is ever fetched to prove control of a name.</p>' +
      pager.head + '<table id="list-hostNamesPage"><thead><tr><th>Entry</th>' +
      '<th>Registered host names</th></tr></thead><tbody>' + rows +
      '</tbody></table>' + pager.foot;
  }

  // The page that answers `create-eab`: the key, once.
  createdEabPage(req, res, result) {
    const { log, admin, esc } = this.deps;
    log.debug("Entering AcmeAdmin.createdEabPage().");
    const inner = admin.warn('<strong>Copy the HMAC key now.</strong> It is ' +
        'stored sealed on the entry and is never shown again; this page is ' +
        'not cached.') +
      '<table class="kv"><tr><th>For</th><td>' + this.code(result.targetUri) +
      '</td></tr><tr><th>Directory</th><td>' + this.code(result.directory) +
      '</td></tr><tr><th>Key id (--eab-kid)</th><td>' + this.code(result.kid) +
      '</td></tr><tr><th>HMAC key (--eab-hmac-key)</th><td>' +
      this.code(result.hmacKey) + '</td></tr><tr><th>MAC</th><td>' +
      this.code(result.alg) + '</td></tr><tr><th>Unused until</th><td>' +
      esc(result.expiresAt) + '</td></tr></table>' +
      '<h2>certbot</h2><pre>' + esc(result.certbot) + '</pre>' +
      '<p class="links"><a href="/admin/acme#eab">Back to ACME</a></p>';
    admin.respond(req, res, result, 'ACME — EAB key', '/admin/acme', inner);
    log.debug("Leaving AcmeAdmin.createdEabPage().");
  }

  // ---------------------------------------------------------------------------
  // GET /admin/acme/monitor
  // ---------------------------------------------------------------------------
  countsTable(title, rows) {
    const { log, esc } = this.deps;
    log.debug("Entering AcmeAdmin.countsTable().");
    log.debug("Leaving AcmeAdmin.countsTable().");
    return '<h2>' + esc(title) + '</h2><table><thead><tr><th>Name</th><th>' +
      'Count</th></tr></thead><tbody>' + (rows.length ? rows.map(function (r) {
        return '<tr><td><code>' + esc(r.name) + '</code></td><td class="num">' +
               r.count + '</td></tr>';
      }).join('') : '<tr><td colspan="2" class="sub">none</td></tr>') +
      '</tbody></table>';
  }

  // THE ROUTES, registered where they always were: the transitional
  // code below calls this at load, at the point the first of them
  // used to be registered, so the route order is unchanged (rule 1).
  registerRoutes(app: RouteApp): void {
    const { log, consoleModel, admin, esc, parseBody, validation,
            errorCodes } = this.deps;
    const self = this;
    log.debug("Entering AcmeAdmin.registerRoutes().");
    // -------------------------------------------------------------------------
    // GET /admin/acme
    // -------------------------------------------------------------------------
    app.get('/admin/acme', function (req, res) {
      log.debug("Entering the admin ACME page.");
      if (self.queryRefused(req, res)) {
        log.debug("Leaving the admin ACME page. Bad query.");
        return;
      }
      const json = consoleModel.acmeView(req);
      const inner =
        admin.note('<strong>ACME (RFC 8555), one server per trust ' +
          'realm.</strong> A client registers an account with an External ' +
          'Account Binding issued for one person or application, orders ' +
          'certificates for identifiers that ' +
          'entry owns, and finalizes with a ' +
          'CSR. The directory is <a href="' + esc(json.directory) + '"><code>' +
          esc(json.directory) + '</code></a>.' +
          (json.enabled ? '' : ' <strong>ACME is turned off in this realm.' +
                               '</strong>')) +
        admin.warn('<strong>No challenge dials out.</strong> An ' +
                   'authorization is ' +
          'created valid, with one <code>' + esc(json.challengeType) +
          '</code> challenge, for an identifier the bound entry owns — a ' +
          'registered host name, the person\'s mail, the entry itself — and ' +
          'an identifier it does not own is refused at newOrder with ' +
          'rejectedIdentifier. EAB MACs are verified in every mode.') +
        '<h2>Directory</h2><p><code>' + esc(json.directory) + '</code></p>' +
        '<h2>Endpoints</h2>' + self.endpointsHtml(json) +
        '<h2>ACME Issuing CA</h2>' + self.authorityHtml(json) +
        '<h2>Profiles</h2>' + self.profilesHtml(json) +
        '<h2 id="eab">External Account Binding keys</h2>' +
        self.eabHtml(req, json) +
        '<h2>Accounts</h2>' + self.accountsHtml(req, json) +
        '<h2>Certificates issued over ACME</h2>' +
        self.certificatesHtml(req, json) +
        '<h2>Registered host names</h2>' + self.hostNamesHtml(req, json) +
        '<h2>Mode</h2>' + admin.note('<strong>' + esc(json.mode.current) +
          '</strong>: ' + esc(json.mode.inForce) + '<div class="sub">' +
          'Development: ' + esc(json.mode.development) + '</div><div ' +
          'class="sub">Product: ' + esc(json.mode.product) + '</div>') +
        '<h2>Settings</h2>' + admin.configFormsFor('/admin/acme') +
        '<p class="links"><a href="/admin/acme?format=json">JSON</a> · ' +
        '<code>GET /admin-api/acme</code> · <a ' +
        'href="/admin/acme/monitor">ACME enrollments (monitoring)</a> · <a ' +
        'href="/admin/pki">PKI</a> · <a href="/admin/error-codes">Error ' +
        'codes</a></p>';
      admin.respond(req, res, json, 'ACME', '/admin/acme', inner);
      log.debug("Leaving the admin ACME page.");
    });

    // -------------------------------------------------------------------------
    // POST /admin/acme
    // -------------------------------------------------------------------------
    app.post('/admin/acme', function (req, res) {
      log.debug("Entering the admin ACME action.");
      const body = parseBody(req);
      const posted = validation.checkParsed({ action: body.action,
                                              csrf_token: body.csrf_token },
                                            'body', ACTION_FORM);
      if (!posted.ok) {
        log.debug("Leaving the admin ACME action. Malformed.");
        const result = errorCodes.mark({ ok: false, errors: [posted.detail] },
                                       'STS-ACME-0091');
        return admin.respondToAction(req, res, '/admin/acme', result);
      }
      const actor = consoleModel.consoleActorOf(req);
      Promise.resolve(consoleModel.acmeAction(body, { via: 'console',
                                                     actor: actor, req: req }))
        .then(function (result) {
          if (result.ok && body.action === 'create-eab') {
            return self.createdEabPage(req, res, result);
          }
          return admin.respondToAction(req, res, '/admin/acme', result);
        }).catch(function (e) {
          log.error(errorCodes.tag('STS-ACME-0095') + 'acme console action ' +
                    'threw: ' + ((e && e.stack) || e));
          admin.respondToAction(req, res, '/admin/acme',
                                errorCodes.mark({ ok: false, errors: ['The ' +
                                  'action could not be completed.'] },
                                                'STS-ACME-0095'));
        });
      log.debug("Leaving the admin ACME action.");
      return undefined;
    });

    app.get('/admin/acme/monitor', function (req, res) {
      log.debug("Entering the admin ACME monitor page.");
      if (self.queryRefused(req, res)) {
        log.debug("Leaving the admin ACME monitor page. Bad query.");
        return;
      }
      const json = consoleModel.acmeMonitorView(req);
      const t = json.totals;
      const pager = admin.pageNavPair('/admin/acme/monitor', req.query,
                                      Object.assign({}, json.paging,
                                                    { param: 'page',
                                                      noun: 'requests' }));
      const recent = json.recent.length ? json.recent.map(function (r) {
        return '<tr><td>' + esc(r.at) + '</td><td><code>' + esc(r.operation) +
          '</code></td><td>' + esc(r.outcome) + '</td><td class="num">' +
          esc(r.status || '') + '</td><td>' + self.code(r.profile) +
          '</td><td>' +
          self.code(r.principal) + '</td><td>' + self.code(r.target) +
          '</td><td>' +
          self.code(r.errorCode) + '</td><td>' + self.code(r.serialHex) +
          '</td></tr>';
      }).join('') : '<tr><td colspan="9" class="sub">Nothing has been asked ' +
                    'of the ACME server in this realm since the process ' +
                    'started.</td></tr>';
      const inner =
        admin.note('<strong>What the ACME server has done</strong> ' +
          'in this realm since ' + esc(json.since) + ', across ' +
          esc(json.processes) + ' process(es).') +
        '<div class="tiles">' + admin.tile(t.requests, 'requests') +
        admin.tile(t.issued, 'certificates issued') +
        admin.tile(t.revoked, 'revoked') + admin.tile(t.refused, 'refused') +
        admin.tile(t.accountsBound, 'accounts bound') +
        admin.tile(t.accounts, 'accounts held') +
        admin.tile(t.certificatesHeld, 'certificates held') + '</div>' +
        self.countsTable('By operation', json.operations) +
        self.countsTable('By profile', json.profiles) +
        self.countsTable('Refusals by error code', json.errorCodes) +
        self.countsTable('By HTTP status', json.statuses) +
        self.countsTable('Who asked', json.principals) +
        '<h2 id="list-page">Recent requests</h2>' + pager.head +
        '<table><thead><tr><th>At</th><th>Operation</th><th>Outcome</th><th>' +
        'Status</th><th>Profile</th><th>Principal</th><th>Entry</th><th>Code' +
        '</th><th>Serial</th></tr></thead><tbody>' + recent +
        '</tbody></table>' +
        pager.foot +
        admin.note('There is no reset. The durable record of each act is the ' +
                   '<a href="/admin/audit">Audit log</a>.') +
        '<p class="links"><a href="/admin/acme/monitor?format=json">JSON</a> ' +
        '· <code>GET /admin-api/acme/monitor</code> · <a ' +
        'href="/admin/acme">ACME</a></p>';
      admin.respond(req, res, json, 'ACME enrollments', '/admin/acme/monitor',
                    inner);
      log.debug("Leaving the admin ACME monitor page.");
    });
    log.debug("Leaving AcmeAdmin.registerRoutes().");
  }
}

// THE TRANSITIONAL INSTANCE (#50): built from the real modules, as the
// composition root will build one, and the source of every name this
// module exports. It goes when that root exists.
const acmeAdmin = new AcmeAdmin({
  log: log,
  parseBody: parseBody,
  errorCodes: errorCodes,
  validation: validation,
  admin: admin,
  consoleModel: consoleModel,
  esc: esc
});

acmeAdmin.registerRoutes(app);

export = { AcmeAdmin: AcmeAdmin };
