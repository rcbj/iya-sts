'use strict';
//
// File: est_admin.ts
//
// ---------------------------------------------------------------------------
// THE TWO EST CONSOLE PAGES: Protocols -> EST and Monitoring -> EST enrollments
// (2026-09-13).
//
// Drawn here, in the console's shell through `admin.respond()`, the way
// `gnap/gnap_admin.ts` draws GNAP's. Every fact on either page comes out of ONE
// call to `est_console.ts`, which is the call `/admin-api/est` and
// `/admin-api/est/monitor` answer with, so the page and the operation cannot
// disagree (rule 7).
//
// **WHERE EACH IS FILED IS DECIDED BY THE QUESTION IT ANSWERS.** `/admin/est`
// is what the EST server IS and how it is configured, so it carries the `est.*`
// settings and the four controls; `/admin/est/monitor` is what it has DONE and
// carries no control and no reset.
//
// **THE ONE ACTION THAT DOES NOT REDIRECT** is "issue a certificate with a
// server-generated key": its answer includes a private key, and
// `respondToAction()` answers a form with a 303 carrying the message on the
// query string — a private key there is a private key in the browser history,
// the access log and the next request's Referer. It answers a 200 page with
// `Cache-Control: no-store` instead, and the key is on that page once.
//
// No script: every control is a form and every list pages with links.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `EstAdmin` takes the modules it uses through its constructor
// (`EstAdminDeps`), and the module still exports its old names from a
// TRANSITIONAL instance built from the real modules, for the callers that
// are not converted. `EstAdmin` is exported beside them for the
// composition root.
//
// **THE ROUTES ARE REGISTERED BY `registerRoutes()`**, which the module
// exports and `common/protocol_stack.ts` calls (#50, R1) at the point in the
// route order where requiring this module used to register them, so rule 1's
// order is unchanged. Requiring the module registers nothing.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import helpers = require('../common/helpers');
const { log, parseBody } = helpers;
import errorCodes = require('../common/error_codes');
import validation = require('../common/validation');
import admin = require('../admin-ui/admin');
import consoleModel = require('./est_console');

const esc = admin.esc;
const vz = validation.z;
const vt = validation.types;

const PAGE_QUERY = vz.looseObject({
  certificatesPage: vt.opt(vt.integer(1, 1000000)),
  page: vt.opt(vt.integer(1, 1000000)),
  per: vt.opt(vt.integer(1, 1000)),
  format: vt.opt(vt.oneOf(['json', 'JSON', 'html'])),
  notice: vt.opt(vt.message),
  error: vt.opt(vt.message)
});

// What `EstAdmin` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface EstAdminDeps {
  log: typeof log;
  parseBody: typeof parseBody;
  errorCodes: typeof errorCodes;
  validation: typeof validation;
  admin: typeof admin;
  consoleModel: typeof consoleModel;
  esc: typeof esc;
}

type RouteApp = typeof app;

class EstAdmin {
  constructor(private readonly deps: EstAdminDeps) {
    deps.log.debug("Entering EstAdmin.constructor().");
    deps.log.debug("Leaving EstAdmin.constructor().");
  }

  queryRefused(req, res) {
    const { log, validation, errorCodes } = this.deps;
    log.debug("Entering EstAdmin.queryRefused().");
    const query = validation.check(req, 'query', PAGE_QUERY);
    if (!query.ok) {
      errorCodes.mark(res, 'STS-EST-0030');
      res.status(400)
         .type('text/plain')
         .set('Cache-Control', 'no-store')
         .send(query.detail);
      log.debug("Leaving EstAdmin.queryRefused(). Refused.");
      return true;
    }
    log.debug("Leaving EstAdmin.queryRefused().");
    return false;
  }

  messages(req) {
    const { log, admin } = this.deps;
    log.debug("Entering EstAdmin.messages().");
    log.debug("Leaving EstAdmin.messages().");
    return typeof admin.messagesOf === 'function' ? admin.messagesOf(req) : '';
  }

  options(values, selected) {
    const { log, esc } = this.deps;
    log.debug("Entering EstAdmin.options().");
    log.debug("Leaving EstAdmin.options().");
    return values.map(function (one) {
      return '<option value="' + esc(one) + '"' +
             (one === selected ? ' selected' : '') + '>' + esc(one) +
             '</option>';
    }).join('');
  }

  yesNo(flag) {
    const { log } = this.deps;
    log.debug("Entering EstAdmin.yesNo().");
    log.debug("Leaving EstAdmin.yesNo().");
    return flag ? 'yes' : '<span class="sub">no</span>';
  }

  hidden(name, value) {
    const { log, esc } = this.deps;
    log.debug("Entering EstAdmin.hidden().");
    log.debug("Leaving EstAdmin.hidden().");
    return '<input type="hidden" name="' + esc(name) + '" value="' +
           esc(value) + '">';
  }

  entryLink(entry) {
    const { log, esc } = this.deps;
    log.debug("Entering EstAdmin.entryLink().");
    if (!entry) {
      log.debug("Leaving EstAdmin.entryLink(). None.");
      return '<span class="sub">—</span>';
    }
    const href = entry.kind === 'person'
      ? '/admin/users?user=' + encodeURIComponent(entry.id)
      : '/admin/applications?application=' + encodeURIComponent(entry.id);
    log.debug("Leaving EstAdmin.entryLink().");
    return '<a href="' + esc(href) + '"><code>' + esc(entry.kind + ':' +
           entry.id) + '</code></a>';
  }

  // ---------------------------------------------------------------------------
  // The body of /admin/est, from the view.
  // ---------------------------------------------------------------------------
  estPageBody(req, json) {
    const { log, esc, admin } = this.deps;
    const self = this;
    log.debug("Entering EstAdmin.estPageBody().");
    const endpointRows = json.endpoints.map(function (one) {
      return '<tr><td><code>' + esc(one.method) + '</code></td><td><code>' +
             esc(one.url) + '</code></td><td>' + esc(one.what) +
             '</td><td>RFC 7030 ' + esc(one.section) + '</td></tr>';
    }).join('');
    const authority = json.hierarchy.authority;
    const caBlock = json.hierarchy.built && authority
      ? '<table class="kv"><tr><th>Subject</th><td><code>' +
        esc(authority.subject) + '</code></td></tr><tr><th>Serial</th><td>' +
        '<code>' + esc(authority.serialHex) + '</code></td></tr><tr><th>Key' +
        '</th><td>' + esc(authority.keyAlg) + '</td></tr><tr><th>Valid' +
        '</th><td>' + esc(authority.notBefore) + ' — ' +
        esc(authority.notAfter) + '</td></tr><tr><th>SHA-256</th><td><code>' +
        esc(authority.thumbprint) + '</code></td></tr><tr><th>Chain</th><td>' +
        json.hierarchy.chainPem.length + ' certificate(s): the EST Issuing ' +
        'CA, this realm\'s Intermediate and the service Root — what ' +
        '<code>/cacerts</code> returns</td></tr></table>'
      : admin.warn(esc(json.hierarchy.note));
    const profileRows = json.profiles.map(function (one) {
      return '<tr><td><code>' + esc(one.id) + '</code>' +
             (one.isDefault ? ' <span class="sub">(unlabelled)</span>' : '') +
             '</td><td>' + self.yesNo(one.allowed) + '</td><td>' +
             (one.needs ? esc(one.needs) : '<span class="sub">nothing ' +
              'beyond the identity rule</span>') + '</td><td><code>' +
             esc(one.urls.simpleenroll) + '</code><div class="sub">' +
             esc(one.urls.simplereenroll) + '<br>' +
             esc(one.urls.serverkeygen) + '<br>' + esc(one.urls.csrattrs) +
             '</div></td></tr>';
    }).join('');
    const refusedRows = json.refusedProfiles.map(function (one) {
      return '<tr><td><code>' + esc(one.id) + '</code></td><td>' +
             esc(one.why) + '</td></tr>';
    }).join('');
    const credentialRows = json.authentication.credentials.map(function (one) {
      return '<tr><td>' + esc(one.kind) + '</td><td>' + esc(one.what) +
             '</td><td><a href="' + esc(one.managedAt) + '">' +
             esc(one.managedAt) + '</a></td></tr>';
    }).join('');
    const allowedProfiles = json.profiles.filter(function (one) {
      return one.allowed;
    }).map(function (one) {
      return one.id;
    });
    const issueForm = '<form method="post" action="/admin/est">' +
      this.hidden('action', 'issue-server-key') +
      '<table class="kv"><tr><th>For</th><td><select name="kind">' +
      this.options(['person', 'application'], 'person') + '</select> ' +
      '<input type="text" name="identifier" required maxlength="256" ' +
      'placeholder="username or application identifier"></td></tr>' +
      '<tr><th>Profile</th><td><select name="profile">' +
      this.options(allowedProfiles, json.defaultProfile) +
      '</select></td></tr>' +
      '<tr><th>Key algorithm</th><td><select name="keyAlg">' +
      this.options(json.keyAlgorithms, 'ec-p256') +
      '</select></td></tr></table><button type="submit">Issue with a ' +
      'server-generated key</button></form>';
    const hostRows = json.hostNames.length ? json.hostNames.map(function (row) {
      return '<tr><td>' + self.entryLink(row.entry) + '</td><td>' +
        row.hostNames.map(function (name) {
          return '<form method="post" action="/admin/est" class="inline">' +
            self.hidden('action', 'remove-host-name') +
            self.hidden('kind', row.entry.kind) +
            self.hidden('identifier', row.entry.id) +
            self.hidden('hostName', name) + '<code>' + esc(name) + '</code> ' +
            '<button type="submit" class="danger">Remove</button></form>';
        }).join(' ') + '</td></tr>';
    }).join('') : '<tr><td colspan="2" class="sub">No entry in this realm ' +
                  'has ' +
      'a certificate host name registered, so no tls-server or ' +
      'tls-server-client certificate can be issued.</td></tr>';
    const hostForm = '<form method="post" action="/admin/est">' +
      this.hidden('action', 'add-host-name') + '<select name="kind">' +
      this.options(['person', 'application'], 'application') + '</select> ' +
      '<input type="text" name="identifier" required maxlength="256" ' +
      'placeholder="identifier"> <input type="text" name="hostName" required ' +
      'maxlength="253" placeholder="host.example.com or 192.0.2.1"> ' +
      '<button type="submit">Register</button></form>';
    const nav = admin.pageNavPair('/admin/est', req.query,
      Object.assign({}, json.certificates.paging,
                    { param: 'certificatesPage' }));
    const certificateRows = json.certificates.rows.length
      ? json.certificates.rows.map(function (one) {
        const control = one.status === 'revoked'
          ? '<span class="sub">revoked ' + esc(one.revoked ? one.revoked.reason
                                                            : '') + '</span>'
          : '<form method="post" action="/admin/est">' +
            self.hidden('action', 'revoke-certificate') +
            self.hidden('serialHex', one.serialHex) + '<select name="reason">' +
            self.options(json.revocationReasons, 'unspecified') + '</select> ' +
            '<button type="submit" class="danger">Revoke</button></form>';
        return '<tr><td><code>' + esc(one.serialHex) + '</code></td><td>' +
          self.entryLink(one.entry) + '</td><td><code>' + esc(one.profile) +
          '</code><div class="sub">' + esc(one.keyAlg || '') + ' · key from ' +
          esc(one.keySource) + '</div></td><td>' + one.names.map(function (n) {
            return '<code>' + esc(n) + '</code>';
          }).join('<br>') + '</td><td>' + esc(one.status) + '</td><td>' +
          esc(one.notAfter) + '</td><td>' + esc(one.requestedBy
            ? one.requestedBy.kind + ':' + one.requestedBy.id : '') +
          '</td><td>' + control + '</td></tr>';
      }).join('')
      : '<tr><td colspan="8" class="sub">Nothing has been enrolled over EST ' +
        'in this realm.</td></tr>';
    const html = this.messages(req) +
      admin.note('<strong>Enrollment over Secure Transport (RFC 7030, with ' +
        'RFC 8951).</strong> A client authenticates with a password, a ' +
        'client secret or a TLS client certificate this realm issued, sends ' +
        'a base64 PKCS#10 request, and receives a certificate from this ' +
        'realm\'s EST Issuing CA. A person may enroll only for themselves, ' +
        'an application only for itself, and a holder of Admin Write for any ' +
        'entry in the realm. ' + (json.enabled ? '' :
          '<strong>EST is turned off in this realm.</strong>')) +
      admin.warn('<strong>Mode: ' + esc(json.mode.current) + '.</strong> ' +
        'Development: ' + esc(json.mode.development) + ' Product: ' +
        esc(json.mode.product)) +
      '<h2>Endpoints</h2><table><thead><tr><th>Method</th><th>URL</th><th>' +
      'What</th><th>Section</th></tr></thead><tbody>' + endpointRows +
      '</tbody></table>' +
      '<h2>EST Issuing CA</h2>' + caBlock +
      '<h2>Profiles</h2><p class="sub">A label in the path names the ' +
      'certificate profile ' +
      '(<code>/.well-known/est/&lt;profile&gt;/…</code>); ' +
      'the unlabelled path issues <code>' + esc(json.defaultProfile) +
      '</code>.</p><table><thead><tr><th>Profile</th><th>Allowed</th><th>' +
      'Needs</th><th>Labelled URLs</th></tr></thead><tbody>' + profileRows +
      '</tbody></table>' +
      '<h3>Never issued over ' +
      'EST</h3><table><thead><tr><th>Profile</th><th>Why' +
      '</th></tr></thead><tbody>' + refusedRows + '</tbody></table>' +
      '<h2>Credentials</h2><p class="sub">EST has no credential of its own: ' +
      'Basic ' + this.yesNo(json.authentication.basic) +
      ', client certificates ' +
      this.yesNo(json.authentication.certificate) + ', /serverkeygen ' +
      this.yesNo(json.authentication.serverKeyGeneration) +
      '.</p><table><thead><tr><th>Credential</th><th>What</th><th>Managed ' +
      'at</th></tr></thead><tbody>' + credentialRows + '</tbody></table>' +
      '<h2>Issue a certificate with a server-generated key</h2><p ' +
      'class="sub">The console\'s /serverkeygen: the private key is shown ' +
      'once on the next page and a sealed copy is kept on the entry.</p>' +
      issueForm +
      '<h2>Certificate host names</h2><p class="sub">A dNSName or iPAddress ' +
      'is issued only when it is registered on the entry.</p><table><thead>' +
      '<tr><th>Entry</th><th>Host names</th></tr></thead><tbody>' + hostRows +
      '</tbody></table>' + hostForm +
      '<h2 id="list-certificatesPage">Enrolled certificates</h2>' + nav.head +
      '<table><thead><tr><th>Serial</th><th>Entry</th><th>Profile</th><th>' +
      'Names</th><th>Status</th><th>Expires</th><th>Requested by</th><th>' +
      '</th></tr></thead><tbody>' + certificateRows + '</tbody></table>' +
      nav.foot +
      '<h2>Settings</h2>' + admin.configFormsFor('/admin/est') +
      '<p class="links"><a href="/admin/est?format=json">JSON</a> · ' +
      '<code>GET /admin-api/est</code> · <a href="/admin/est/monitor">EST ' +
      'enrollments (monitoring)</a> · <a href="/admin/pki">PKI</a> · <a ' +
      'href="/admin/error-codes">Error codes</a></p>';
    log.debug("Leaving EstAdmin.estPageBody().");
    return html;
  }

  // The one-time page for a server-generated key.
  issuedKeyPage(result) {
    const { log, admin, esc } = this.deps;
    log.debug("Entering EstAdmin.issuedKeyPage().");
    log.debug("Leaving EstAdmin.issuedKeyPage().");
    return admin.warn('<strong>' + esc(result.message) + '</strong> Copy the ' +
      'private key now: this page is not stored, and nothing on this console ' +
      'will show it again.') +
      '<h2>Private key (PKCS#8)</h2><pre>' + esc(result.privateKeyPem) +
      '</pre><h2>Certificate</h2><table class="kv"><tr><th>Serial</th><td>' +
      '<code>' + esc(result.record.serialHex) + '</code></td></tr><tr><th>' +
      'Profile</th><td>' + esc(result.record.profile) + '</td></tr><tr><th>' +
      'Names</th><td>' + result.record.names.map(function (n) {
        return '<code>' + esc(n) + '</code>';
      }).join('<br>') + '</td></tr><tr><th>Expires</th><td>' +
      esc(result.record.notAfter) + '</td></tr></table><pre>' +
      esc(result.certificatePem) + '</pre><h3>Chain</h3><pre>' +
      esc((result.chainPem || []).join('')) + '</pre>' +
      '<p class="links"><a href="/admin/est">Back to EST</a></p>';
  }

  // ---------------------------------------------------------------------------
  // GET /admin/est/monitor
  // ---------------------------------------------------------------------------
  countTable(title, rows) {
    const { log, esc } = this.deps;
    log.debug("Entering EstAdmin.countTable().");
    log.debug("Leaving EstAdmin.countTable().");
    return '<h3>' + esc(title) + '</h3><table><tbody>' + (rows.length
      ? rows.map(function (row) {
        return '<tr><td><code>' + esc(row.name) + '</code></td><td ' +
               'class="num">' + row.count + '</td></tr>';
      }).join('')
      : '<tr><td class="sub">none yet</td></tr>') + '</tbody></table>';
  }

  // THE ROUTES, registered where they always were: the module exports
  // this, and `common/protocol_stack.ts` calls it (#50, R1) at the point
  // where requiring the module used to register them, so the route order
  // is unchanged (rule 1). Nothing calls it at load.
  registerRoutes(app: RouteApp): void {
    const { log, consoleModel, admin, parseBody, errorCodes, esc } = this.deps;
    const self = this;
    log.debug("Entering EstAdmin.registerRoutes().");
    // -------------------------------------------------------------------------
    // GET /admin/est
    // -------------------------------------------------------------------------
    app.get('/admin/est', function (req, res) {
      log.debug("Entering the admin EST page.");
      if (self.queryRefused(req, res)) {
        log.debug("Leaving the admin EST page. Bad query.");
        return;
      }
      const json = consoleModel.estView(req);
      admin.respond(req, res, json, 'EST', '/admin/est',
                    self.estPageBody(req, json));
      log.debug("Leaving the admin EST page.");
    });

    // -------------------------------------------------------------------------
    // POST /admin/est
    // -------------------------------------------------------------------------
    app.post('/admin/est', function (req, res) {
      log.debug("Entering the admin EST action.");
      const body = parseBody(req);
      consoleModel.estAction(body, { via: 'console', req: req })
        .then(function (result) {
          if (result && result.ok && result.privateKeyPem) {
            admin.respond(req, res, result, 'EST — a server-generated key',
                          '/admin/est', self.issuedKeyPage(result));
            log.debug("Leaving the admin EST action. A one-time key page.");
            return;
          }
          if (result && !result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-EST-0031');
          }
          admin.respondToAction(req, res, '/admin/est', result);
          log.debug("Leaving the admin EST action. ok=" + !!(result &&
                                                             result.ok));
        }, function (e) {
          log.error(errorCodes.tag('STS-EST-0020') +
                    'est console: the action failed: ' + ((e && e.stack) || e));
          const failed = errorCodes.mark({ ok: false, errors: ['The action ' +
            'could not be completed.'] }, 'STS-EST-0020');
          admin.respondToAction(req, res, '/admin/est', failed);
          log.debug("Leaving the admin EST action. Threw.");
        });
    });

    app.get('/admin/est/monitor', function (req, res) {
      log.debug("Entering the admin EST monitor page.");
      if (self.queryRefused(req, res)) {
        log.debug("Leaving the admin EST monitor page. Bad query.");
        return;
      }
      const json = consoleModel.estMonitorView(req);
      const t = json.totals;
      const tiles = '<div class="tiles">' +
        admin.tile(t.requests, 'requests') + admin.tile(t.issued, 'issued') +
        admin.tile(t.refused, 'refused') + admin.tile(t.revoked, 'revoked') +
        admin.tile(json.certificates.valid, 'valid certificates') +
        admin.tile(json.certificates.revoked, 'revoked certificates') +
        '</div>';
      const nav = admin.pageNavPair('/admin/est/monitor', req.query,
        Object.assign({}, json.paging, { param: 'page' }));
      const recentRows = json.recent.length ? json.recent.map(function (row) {
        return '<tr><td>' + esc(row.at) + '</td><td><code>' +
               esc(row.operation) + '</code></td><td>' + esc(row.outcome) +
               '</td><td class="num">' + esc(row.status || '') + '</td><td>' +
               esc(row.profile || '') + '</td><td>' + esc(row.principal || '') +
               '</td><td>' + esc(row.target || '') + '</td><td>' +
               (row.errorCode ? '<code>' + esc(row.errorCode) + '</code>' :
                '') +
               '</td><td><code>' + esc(row.serialHex || '') +
               '</code></td></tr>';
      }).join('') : '<tr><td colspan="9" class="sub">No EST request has been ' +
        'answered in this realm since the process started.</td></tr>';
      const inner = self.messages(req) +
        admin.note('<strong>What the EST server has done</strong> in this ' +
                   'trust ' +
          'realm since ' + esc(json.since || 'the process started') +
          ', across ' +
          json.processes +
          ' process(es). Every request is counted, issued or ' +
          'refused; the durable record of each is the <a ' +
          'href="/admin/audit">Audit log</a>.') + tiles +
        self.countTable('By operation', json.operations) +
        self.countTable('By profile', json.profiles) +
        self.countTable('By principal', json.principals) +
        self.countTable('Refusals by error code', json.errorCodes) +
        self.countTable('By HTTP status', json.statuses) +
        '<h2 id="list-page">Recent requests</h2>' + nav.head +
        '<table><thead><tr><th>At</th><th>Operation</th><th>Outcome</th><th>' +
        'Status</th><th>Profile</th><th>Principal</th><th>Target</th><th>Code' +
        '</th><th>Serial</th></tr></thead><tbody>' + recentRows +
        '</tbody></table>' + nav.foot +
        admin.note('There is no reset. The counters are per realm and start ' +
          'with the process.') +
        '<p class="links"><a href="/admin/est/monitor?format=json">JSON</a> ' +
        '· <code>GET /admin-api/est/monitor</code> · <a ' +
        'href="/admin/est">EST</a></p>';
      admin.respond(req, res, json, 'EST enrollments', '/admin/est/monitor',
                    inner);
      log.debug("Leaving the admin EST monitor page.");
    });
    log.debug("Leaving EstAdmin.registerRoutes().");
  }
}

// THE TRANSITIONAL INSTANCE (#50): built from the real modules, as the
// composition root will build one, and the source of every name this
// module exports. It goes when that root exists.
const estAdmin = new EstAdmin({
  log: log,
  parseBody: parseBody,
  errorCodes: errorCodes,
  validation: validation,
  admin: admin,
  consoleModel: consoleModel,
  esc: esc
});

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

export = {
  registerRoutes: (target: any): void => estAdmin.registerRoutes(target),
  EstAdmin: EstAdmin
};
