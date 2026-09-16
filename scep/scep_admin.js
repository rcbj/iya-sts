// @ts-check
'use strict';
//
// File: scep_admin.js
//
// ---------------------------------------------------------------------------
// THE TWO SCEP CONSOLE PAGES: Protocols -> SCEP and Monitoring -> SCEP
// enrollments (2026-09-13).
//
// Drawn here, in the console's shell through `admin.respond()`, the way
// `gnap/gnap_admin.js` draws GNAP's. Every fact on either page comes out of ONE
// call to `scep_console.js`, which is the same call `/admin-api/scep` and
// `/admin-api/scep/monitor` answer with (rule 7).
//
// **ONE ACTION IS NOT A REDIRECT, AND IT IS THE ONE THAT MAKES A SECRET.**
// `respondToAction()` answers a form with a 303 carrying its message on the
// query string, which is right for "the host name was added" and wrong for a
// challenge password: a secret on a query string is a secret in the browser
// history, the access log and the next request's Referer. So a created
// challenge is answered with a 200 PAGE, `Cache-Control: no-store` (which
// `admin.respond()` sets), showing it ONCE with the `sscep` commands that use
// it. Nothing stores it to show it again — the entry holds a SHA-256 of it.
//
// No script, like every page of this console but one: paging is links and
// every control is a form.
// ---------------------------------------------------------------------------

const app = require('../common/app');
const { log, parseBody } = require('../common/helpers');
const errorCodes = require('../common/error_codes');
const admin = require('../admin-ui/admin');
const core = require('../common/cert_enrollment');
const consoleModel = require('./scep_console');

const esc = admin.esc;

function queryRefused(req, res) {
  log.debug("Entering queryRefused().");
  const query = consoleModel.queryOf(req);
  if (!query.ok) {
    errorCodes.mark(res, 'STS-SCEP-0060');
    res.status(400)
       .type('text/plain')
       .set('Cache-Control', 'no-store')
       .send(query.detail);
    log.debug("Leaving queryRefused(). Refused.");
    return true;
  }
  log.debug("Leaving queryRefused().");
  return false;
}

function code(value) {
  log.debug("Entering code().");
  log.debug("Leaving code().");
  return '<code>' + esc(value == null ? '' : value) + '</code>';
}

function none(text) {
  log.debug("Entering none().");
  log.debug("Leaving none().");
  return '<span class="sub">' + esc(text || 'none') + '</span>';
}

function hidden(name, value) {
  log.debug("Entering hidden().");
  log.debug("Leaving hidden().");
  return '<input type="hidden" name="' + esc(name) + '" value="' +
         esc(value) + '">';
}

function entryLink(entry) {
  log.debug("Entering entryLink().");
  if (!entry) {
    log.debug("Leaving entryLink(). None.");
    return none('none');
  }
  const href = entry.kind === 'person'
    ? '/admin/users?user=' + encodeURIComponent(entry.id)
    : '/admin/applications?application=' + encodeURIComponent(entry.id);
  log.debug("Leaving entryLink().");
  return '<a href="' + esc(href) + '">' + code(core.entryUri(entry)) + '</a>';
}

function kindSelect() {
  log.debug("Entering kindSelect().");
  log.debug("Leaving kindSelect().");
  return '<select name="kind"><option value="person">person</option>' +
         '<option value="application">application</option></select>';
}

function sectionEndpoints(json) {
  log.debug("Entering sectionEndpoints().");
  const rows = Object.keys(json.endpoints).map(function (name) {
    return '<tr><th>' + esc(name) + '</th><td>' +
           code(json.endpoints[name]) + '</td></tr>';
  }).join('');
  log.debug("Leaving sectionEndpoints().");
  return '<h2>Endpoints</h2><table class="kv">' + rows +
    '<tr><th>GetCACaps answers</th><td>' +
    json.capabilities.map(code).join(' ') + '</td></tr>' +
    '<tr><th>Messages answered</th><td>' +
    Object.keys(json.messageTypes).filter(function (n) {
      return n !== '3';
    }).map(function (n) {
      return code(json.messageTypes[n] + ' (' + n + ')');
    }).join(' ') + '</td></tr></table>';
}

function sectionAuthority(json) {
  log.debug("Entering sectionAuthority().");
  const a = json.authority;
  const r = json.ra;
  const authority = a
    ? '<table class="kv"><tr><th>Subject</th><td>' + code(a.subject) +
      '</td></tr><tr><th>Serial</th><td>' + code(a.serialHex) +
      '</td></tr><tr><th>Key</th><td>' + esc(a.keyAlg) + ', signs ' +
      esc(a.signatureAlg) + '</td></tr><tr><th>Valid until</th><td>' +
      esc(a.notAfter) + '</td></tr><tr><th>Chain</th><td>' +
      (a.intermediate ? code(a.intermediate.subject) : '') + ' → ' +
      (a.root ? code(a.root.subject) : '') + '</td></tr></table>'
    : admin.warn(esc(json.authorityNote));
  const raTable = r.present
    ? '<table class="kv"><tr><th>Subject</th><td>' + code(r.subject) +
      '</td></tr><tr><th>Serial</th><td>' + code(r.serialHex) +
      '</td></tr><tr><th>Key</th><td>' + esc(r.keyAlgorithm) +
      (r.keyAlgorithm !== r.wantedKeyAlgorithm
        ? ' <span class="sub">(scep.raKeyAlgorithm is ' +
          esc(r.wantedKeyAlgorithm) + ')</span>' : '') +
      '</td></tr><tr><th>Valid until</th><td>' + esc(r.notAfter) +
      '</td></tr><tr><th>Status</th><td>' + esc(r.status) +
      '</td></tr></table>'
    : '<p class="sub">No RA certificate yet; the first GetCACert or ' +
      'PKIOperation issues one (' + esc(r.keyAlgorithm) + ').</p>';
  log.debug("Leaving sectionAuthority().");
  return '<h2>SCEP Issuing CA</h2>' + authority +
    '<h2>RA certificate</h2>' +
    admin.note('The certificate a client encrypts its request to and ' +
      'verifies a CertRep with. RSA whatever the Issuing CA is, because ' +
      'SCEP key transport is RSA; a leaf of the SCEP Issuing CA, re-issued ' +
      'when it is missing, expires within thirty days, or is not the size ' +
      '<code>scep.raKeyAlgorithm</code> names.') + raTable +
    '<form method="post" action="/admin/scep">' +
    hidden('action', 'reissue-ra') +
    '<button type="submit">Re-issue the RA certificate</button></form>';
}

function sectionProfiles(json) {
  log.debug("Entering sectionProfiles().");
  const rows = json.profiles.map(function (p) {
    return '<tr><td>' + code(p.id) + '</td><td>' +
      (p.allowed ? 'yes' : '<strong>no</strong>') + '</td><td>' +
      (p.needs ? esc(p.needs) : none('nothing beyond the entry')) +
      '</td><td>' + esc(p.keys) + '</td><td>' + code(p.url) + '</td></tr>';
  }).join('');
  const refused = json.refusedProfiles.map(function (p) {
    return '<tr><td>' + code(p.id) + '</td><td>' + esc(p.why) + '</td></tr>';
  }).join('');
  log.debug("Leaving sectionProfiles().");
  return '<h2>Profiles</h2><table><thead><tr><th>Profile</th><th>Allowed ' +
    'here</th><th>Needs</th><th>Keys</th><th>SCEP URL</th></tr></thead>' +
    '<tbody>' + rows + '</tbody></table>' +
    '<h3>Never issued over an enrollment protocol</h3><table><thead><tr>' +
    '<th>Profile</th><th>Why</th></tr></thead><tbody>' + refused +
    '</tbody></table>';
}

function sectionChallenges(req, json) {
  log.debug("Entering sectionChallenges().");
  const nav = admin.pageNavPair('/admin/scep', req.query,
    Object.assign({}, json.challenges.paging, { param: 'credentialsPage' }));
  const rows = json.challenges.rows.length
    ? json.challenges.rows.map(function (c) {
      return '<tr><td>' + code(c.id) + '</td><td>' + entryLink(c.entry) +
        '</td><td>' + code(c.profile) + '</td><td>' + esc(c.status) +
        '</td><td>' + esc(c.expiresAt) + '</td><td>' +
        esc(c.createdBy || '—') + '</td><td><form method="post" ' +
        'action="/admin/scep">' + hidden('action', 'delete-challenge') +
        hidden('id', c.id) + '<button type="submit" class="danger">Delete' +
        '</button></form></td></tr>';
    }).join('')
    : '<tr><td colspan="7" class="sub">No challenge passwords in this ' +
      'realm.</td></tr>';
  const options = json.profiles.filter(function (p) {
    return p.allowed;
  }).map(function (p) {
    return '<option value="' + esc(p.id) + '"' +
      (p.id === json.defaultProfile ? ' selected' : '') + '>' + esc(p.id) +
      '</option>';
  }).join('');
  log.debug("Leaving sectionChallenges().");
  return '<h2 id="list-credentialsPage">Challenge passwords</h2>' +
    admin.note('A challenge authorizes ONE enrollment for ONE entry and ONE ' +
      'profile, and whoever redeems it is issued a certificate AS that ' +
      'entry. It is shown once when it is made and kept only as a digest.') +
    '<form method="post" action="/admin/scep" class="inline">' +
    hidden('action', 'create-challenge') + kindSelect() +
    ' <input name="identifier" placeholder="username or application" ' +
    'required> <select name="profile">' + options + '</select> ' +
    '<input name="lifetimeS" type="number" min="60" placeholder="lifetime ' +
    '(seconds)"> <button type="submit">Create a challenge</button></form>' +
    nav.head + '<table><thead><tr><th>Id</th><th>For</th><th>Profile</th>' +
    '<th>Status</th><th>Expires</th><th>Created by</th><th></th></tr>' +
    '</thead><tbody>' + rows + '</tbody></table>' + nav.foot;
}

function sectionHostNames(json) {
  log.debug("Entering sectionHostNames().");
  const rows = json.hostNames.length
    ? json.hostNames.map(function (h) {
      return '<tr><td>' + entryLink(h.entry) + '</td><td>' +
        h.hostNames.map(function (name) {
          return code(name) + ' <form method="post" action="/admin/scep" ' +
            'class="inline">' + hidden('action', 'remove-host-name') +
            hidden('kind', h.entry.kind) + hidden('identifier', h.entry.id) +
            hidden('hostName', name) + '<button type="submit" ' +
            'class="danger">Remove</button></form>';
        }).join('<br>') + '</td></tr>';
    }).join('')
    : '<tr><td colspan="2" class="sub">No entry in this realm has a ' +
      'registered host name.</td></tr>';
  log.debug("Leaving sectionHostNames().");
  return '<h2>Registered host names</h2>' +
    admin.note('A dNSName or iPAddress is issued only when it is registered ' +
      'on the entry the certificate is for. This service never proves ' +
      'control of a name by dialling it.') +
    '<form method="post" action="/admin/scep" class="inline">' +
    hidden('action', 'add-host-name') + kindSelect() +
    ' <input name="identifier" placeholder="username or application" ' +
    'required> <input name="hostName" placeholder="host.example.com" ' +
    'required> <button type="submit">Register</button></form>' +
    '<table><thead><tr><th>Entry</th><th>Host names</th></tr></thead>' +
    '<tbody>' + rows + '</tbody></table>';
}

function sectionCertificates(req, json) {
  log.debug("Entering sectionCertificates().");
  const nav = admin.pageNavPair('/admin/scep', req.query,
    Object.assign({}, json.certificates.paging,
                  { param: 'certificatesPage' }));
  const reasons = json.revokeReasons.map(function (r) {
    return '<option value="' + esc(r) + '">' + esc(r) + '</option>';
  }).join('');
  const rows = json.certificates.rows.length
    ? json.certificates.rows.map(function (c) {
      const control = c.status === 'revoked'
        ? none('revoked ' + ((c.revoked && c.revoked.reason) || ''))
        : '<form method="post" action="/admin/scep" class="inline">' +
          hidden('action', 'revoke-certificate') +
          hidden('serial', c.serialHex) + '<select name="reason">' +
          reasons + '</select> <button type="submit" class="danger">' +
          'Revoke</button></form>';
      return '<tr><td>' + code(c.serialHex) + '</td><td>' +
        entryLink(c.entry) + '</td><td>' + code(c.profile) + '</td><td>' +
        esc(c.keyAlg) + '</td><td>' + esc(c.status) + '</td><td>' +
        esc(c.notAfter) + '</td><td>' + control + '</td></tr>';
    }).join('')
    : '<tr><td colspan="7" class="sub">Nothing has been issued over SCEP ' +
      'in this realm.</td></tr>';
  log.debug("Leaving sectionCertificates().");
  return '<h2 id="list-certificatesPage">Enrolled certificates</h2>' +
    nav.head + '<table><thead><tr><th>Serial</th><th>For</th><th>Profile' +
    '</th><th>Key</th><th>Status</th><th>Expires</th><th></th></tr></thead>' +
    '<tbody>' + rows + '</tbody></table>' + nav.foot;
}

function sectionExceptions(json) {
  log.debug("Entering sectionExceptions().");
  const rows = json.exceptions.map(function (x) {
    return '<tr><th>' + esc(x.what) + '</th><td>' + esc(x.why) + '</td></tr>';
  }).join('');
  const m = json.mode;
  log.debug("Leaving sectionExceptions().");
  return '<h2>What SCEP here does not do</h2><table class="kv">' + rows +
    '</table><h2>Mode</h2>' +
    admin.note('<strong>This realm is in ' + esc(m.mode) + ' mode.</strong> ' +
      esc(m.scep) +
      (m.requirement ? ' Development: ' + esc(m.requirement.development) +
       ' Product: ' + esc(m.requirement.product) : ''));
}

// ---------------------------------------------------------------------------
// GET /admin/scep
// ---------------------------------------------------------------------------
function drawScep(req, res, extraTop) {
  log.debug("Entering drawScep().");
  const json = consoleModel.scepView(req);
  const inner = (extraTop || '') +
    (typeof admin.messagesOf === 'function' ? admin.messagesOf(req) : '') +
    admin.note('<strong>SCEP (RFC 8894) for this trust realm.</strong> A ' +
      'device gets the RA and CA certificates with GetCACert, and sends a ' +
      'PKCS#10 request signed and encrypted in CMS, carrying a challenge ' +
      'password made below or on the user portal. ' +
      (json.enabled ? '' : '<strong>SCEP is turned off in this realm.' +
       '</strong>')) +
    sectionEndpoints(json) + sectionAuthority(json) + sectionProfiles(json) +
    sectionChallenges(req, json) + sectionHostNames(json) +
    sectionCertificates(req, json) + sectionExceptions(json) +
    admin.configFormsFor('/admin/scep') +
    '<p class="links"><a href="/admin/scep?format=json">JSON</a> · ' +
    '<code>GET /admin-api/scep</code> · <a href="/admin/scep/monitor">SCEP ' +
    'enrollments (monitoring)</a> · <a href="/admin/pki">PKI</a> · ' +
    '<a href="/admin/error-codes">Error codes</a></p>';
  admin.respond(req, res, json, 'SCEP', '/admin/scep', inner);
  log.debug("Leaving drawScep().");
}

app.get('/admin/scep', function (req, res) {
  log.debug("Entering the admin SCEP page.");
  if (queryRefused(req, res)) {
    log.debug("Leaving the admin SCEP page. Bad query.");
    return;
  }
  drawScep(req, res, '');
  log.debug("Leaving the admin SCEP page.");
});

// ---------------------------------------------------------------------------
// POST /admin/scep
// ---------------------------------------------------------------------------
app.post('/admin/scep', function (req, res) {
  log.debug("Entering the admin SCEP action.");
  const body = parseBody(req);
  consoleModel.scepAction(body, { via: 'console',
                                  actor: consoleModel.actorOf(req),
                                  req: req })
    .then(function (result) {
      const json = /json/i.test(String(req.headers['content-type'] || ''));
      if (result.ok && result.challenge && !json) {
        // THE ONE-TIME SECRET, on a 200 page — see the header.
        const shown = admin.warn('<strong>The challenge password for ' +
          esc(result.entryUri) + ' (' + esc(result.profile) + '). It is ' +
          'shown once and cannot be shown again.</strong>') +
          '<table class="kv"><tr><th>Challenge</th><td>' +
          code(result.challenge) + '</td></tr><tr><th>Expires</th><td>' +
          esc(result.expiresAt) + '</td></tr><tr><th>SCEP URL</th><td>' +
          code(result.url) + '</td></tr></table><h3>With sscep</h3><pre>' +
          esc(result.hint) + '</pre>';
        drawScep(req, res, shown);
        log.debug("Leaving the admin SCEP action. A challenge shown once.");
        return;
      }
      admin.respondToAction(req, res, '/admin/scep', result);
      log.debug("Leaving the admin SCEP action. ok=" + result.ok);
    })
    .catch(function (e) {
      log.error(errorCodes.tag('STS-SCEP-0061') + 'scep: a console action ' +
                'failed: ' + ((e && e.stack) || e));
      admin.respondToAction(req, res, '/admin/scep', errorCodes.mark(
        { ok: false, errors: ['The action could not be completed.'] },
        'STS-SCEP-0061'));
    });
  log.debug("Leaving the admin SCEP action handler.");
});

// ---------------------------------------------------------------------------
// GET /admin/scep/monitor
// ---------------------------------------------------------------------------
function table(title, counts) {
  log.debug("Entering table().");
  const keys = Object.keys(counts || {}).sort(function (a, b) {
    return counts[b] - counts[a];
  });
  log.debug("Leaving table().");
  return '<h2>' + esc(title) + '</h2>' + (keys.length
    ? '<table><tbody>' + keys.map(function (k) {
      return '<tr><td>' + code(k) + '</td><td class="num">' + counts[k] +
             '</td></tr>';
    }).join('') + '</tbody></table>'
    : '<p class="sub">None yet.</p>');
}

app.get('/admin/scep/monitor', function (req, res) {
  log.debug("Entering the admin SCEP monitor page.");
  if (queryRefused(req, res)) {
    log.debug("Leaving the admin SCEP monitor page. Bad query.");
    return;
  }
  const json = consoleModel.scepMonitorView(req);
  const t = json.totals;
  const nav = admin.pageNavPair('/admin/scep/monitor', req.query,
                                json.paging);
  const rows = json.recent.length ? json.recent.map(function (r) {
    return '<tr><td>' + esc(r.at) + '</td><td>' + code(r.operation) +
      '</td><td>' + esc(r.outcome) + '</td><td>' + esc(r.failInfo || '') +
      '</td><td>' + esc(r.profile || '') + '</td><td>' +
      esc(r.principal || '') + '</td><td>' + esc(r.target || '') +
      '</td><td>' + esc(r.errorCode || '') + '</td><td>' +
      esc(r.serialHex || '') + '</td></tr>';
  }).join('') : '<tr><td colspan="9" class="sub">No SCEP request in this ' +
    'realm yet.</td></tr>';
  const inner = admin.note('<strong>What the SCEP server has done in this ' +
      'realm</strong>, counted since ' + esc(json.since) + ' across ' +
      esc(json.processes) + ' process(es). A refused PKIOperation is an ' +
      'HTTP 200 CertRep FAILURE, so it is counted by its failInfo.') +
    '<div class="tiles">' + admin.tile(t.requests, 'requests') +
    admin.tile(t.issued, 'issued') + admin.tile(t.refused, 'refused') +
    admin.tile(t.revoked, 'revoked') +
    admin.tile(t.challengesCreated, 'challenges created') +
    admin.tile(json.issuedCertificates, 'certificates held') + '</div>' +
    table('By operation', json.operations) +
    table('By failInfo', json.failInfo) +
    table('Refusals by error code', json.errorCodes) +
    table('By profile', json.profiles) +
    table('By principal', json.principals) +
    '<h2 id="list-page">Recent</h2>' + nav.head + '<table><thead><tr>' +
    '<th>At</th><th>Operation</th><th>Outcome</th><th>failInfo</th>' +
    '<th>Profile</th><th>Principal</th><th>Target</th><th>Code</th>' +
    '<th>Serial</th></tr></thead><tbody>' + rows + '</tbody></table>' +
    nav.foot +
    admin.note('There is no reset; the durable record of each act is the ' +
      '<a href="/admin/audit">Audit log</a>.') +
    '<p class="links"><a href="/admin/scep/monitor?format=json">JSON</a> · ' +
    '<code>GET /admin-api/scep/monitor</code> · <a href="/admin/scep">SCEP' +
    '</a></p>';
  admin.respond(req, res, json, 'SCEP enrollments', '/admin/scep/monitor',
                inner);
  log.debug("Leaving the admin SCEP monitor page.");
});

module.exports = {};
