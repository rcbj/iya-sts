// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/wstrust_subtab_simple_view.js
//
// ---------------------------------------------------------------------------
// wstrustAppliesTo IS ALWAYS IN THE WS-TRUST SUB-TAB'S SIMPLIFIED VIEW
// (rcbj, 2026-11-23, #2046).
//
// An application page moves a primary name whose only value is the
// application's identifier into the advanced view (#393). rcbj: the WS-Trust
// sub-tab's AppliesTo stays in the simplified view whatever it holds. What
// is held, drawn from a real application's page model in a child process:
//
//   A. An application whose wstrustAppliesTo is its identifier draws that
//      cell in the WS-Trust sub-tab's simplified view (no `fg-adv`), with
//      wstrustJwtScope beside it, and no "folded" note.
//   B. The rule is otherwise unchanged: on an OAuth application whose
//      oauthClientId is its identifier, that cell is still advanced.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'wstrust_subtab_simple_view',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Runs in a child, so the whole stack loads in a process of its own.
function childMain() {
  const ROOT = process.env.WSV_ROOT;
  const OUT = process.env.WSV_OUT;
  const fs = require('fs');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const realms = require(ROOT + '/common/realms');
    const applications = require(ROOT + '/common/applications');
    const views = require(ROOT + '/admin-core/admin_views');
    const page = require(ROOT + '/admin-ui/web_applications');
    const WebKit = require(ROOT + '/admin-ui/web_kit');
    const stamp = String(Date.now()).slice(-6);
    const realm = realms.create({ id: 'wsv-' + stamp, name: 'wsv' }).realm;
    const request = { query: {}, headers: { host: 'localhost:8081' },
                      protocol: 'https', get: function () { return ''; } };
    // The opening tag of one field's cell, its class and id in any order.
    const cellTag = function (html, attribute) {
      const at = html.indexOf('id="fgc-' + attribute + '"');
      if (at < 0) {
        return '';
      }
      return html.slice(html.lastIndexOf('<div', at),
                        html.indexOf('>', at) + 1);
    };
    // One sub-tab's panel, so a cell is read where that sub-tab draws it.
    const panel = function (html, group) {
      const at = html.indexOf('<div class="subpanel" id="cfg-' + group +
                              '"');
      if (at < 0) {
        return '';
      }
      const next = html.indexOf('<div class="subpanel"', at + 10);
      return html.slice(at, next < 0 ? html.length : next);
    };
    await realms.run(realm, async function () {
      // --- A. WS-Trust --------------------------------------------------
      const made = applications.createApplication({ identifier: 'wsv-rp',
        protocols: ['wstrust'],
        fields: { wstrustAppliesTo: ['wsv-rp'] } });
      note(made.ok, 'A0. a WS-Trust application whose AppliesTo is its ' +
                    'identifier', JSON.stringify(made.errors || ''));
      const json = views.applicationDetailJson(request, 'wsv-rp').json;
      const section = page.applicationFieldsSection(
        WebKit.context({}, true), json, '');
      const wstrust = panel(section, 'wstrust');
      const applies = cellTag(wstrust, 'wstrustAppliesTo');
      const scope = cellTag(wstrust, 'wstrustJwtScope');
      note(/fg-cell/.test(applies) && !/fg-adv/.test(applies),
           'A1. wstrustAppliesTo is in the simplified view though it is ' +
           'the identifier', applies);
      note(/fg-cell/.test(scope) && !/fg-adv/.test(scope),
           'A2. wstrustJwtScope is beside it', scope);
      note(/value="simple"[^>]*checked/.test(wstrust) &&
           /fg-adv/.test(cellTag(wstrust, 'wstrustSignRequestElements')),
           'A3. the sub-tab opens on the simplified view, the signing ' +
           'fields advanced');

      // --- B. The rule elsewhere ----------------------------------------
      const oauth = applications.createApplication({ identifier: 'wsv-web',
        protocols: ['oauth2', 'oidc'],
        fields: { oauthClientId: 'wsv-web' } });
      const json2 = views.applicationDetailJson(request, 'wsv-web').json;
      const section2 = page.applicationFieldsSection(
        WebKit.context({}, true), json2, '');
      const clientId = cellTag(panel(section2, 'oauth'), 'oauthClientId');
      note(oauth.ok && /fg-adv/.test(clientId),
           'B1. an OAuth client_id equal to the identifier is still folded ' +
           'into the advanced view', clientId);
    });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'wstrust-subtab-simple-' + process.pid +
                        '-' + require('crypto').randomBytes(8)
                          .toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', WSV_ROOT: ROOT,
                           WSV_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died before writing one, reported below with its
    // exit status and stderr.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ws-trust sub-tab simplified view',
  describe: 'wstrustAppliesTo stays in the WS-Trust sub-tab\'s simplified ' +
            'view even when it is the identifier; other primary names ' +
            'still fold (#2046)',
  run: run
};
