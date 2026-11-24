// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: person_token_subtabs.js
//
// ===========================================================================
// A PERSON'S TOKEN AND KEY SUB-TABS ON DIRECTORY → USERS (#2052).
//
// rcbj, 2026-11-23: "I also want it to be a tab on individual user objects.
// Reuse the code for these pages." The person's Credentials tab grows six
// sub-tabs — Hardware tokens, OATH tokens, YubiKey OTP, PIV, SSH user
// certificates, OpenPGP and S/MIME — each drawn by the central Directory
// page's own functions with the person fixed, from the central pages'
// operations composed into the users drill.
//
//   A. the drill composes the three central operations, asked for the
//      person, and draws the six sub-tabs in order;
//   B. each sub-tab's forms post to the central page, so they reach the
//      same /admin-api operation (rule 7), and carry the person;
//   C. the central pages still draw what they drew: the tokens table and
//      the OpenPGP person bodies are the same functions;
//   D. a reader who may not write gets no form on any of them.
//
// In a child process, `risk_user_badge.js`'s arrangement: it loads the
// protocol stack, so the directory, the hardware-token and OpenPGP surfaces
// are the running service's.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'person_token_subtabs',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Runs in the child, from its own source text; it logs nothing of its own
// (a `node -e` child), and carries every failure on the findings it writes.
function childMain() {
  const ROOT = process.env.PT_ROOT;
  const OUT = process.env.PT_OUT;
  const findings = [];
  const t = {
    check: function (ok, what, detail) {
      findings.push({ ok: !!ok, what: what,
                      detail: detail === undefined ? '' : String(detail) });
    }
  };
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const WebPages = require(ROOT + '/admin-ui/web_pages');
    const WebKit = require(ROOT + '/admin-ui/web_kit');
    const HardwareTokensPage = require(ROOT + '/admin-ui/web_hardware_tokens');
    const OpenPgpPage = require(ROOT + '/admin-ui/web_openpgp');
    const drawer = require(ROOT + '/tests/tools/console_page.js')
      .consolePage(ROOT);
    const NAME = 'pts-erin';
    ldap.createUser(NAME, { invent: false });

    // --- A. composed, and six sub-tabs ----------------------------------
    const page = WebPages.pageFor('/admin/users');
    const asked = WebPages.composeRequests(page, { user: NAME });
    const byMember = {};
    asked.forEach(function (one) { byMember[one.member] = one; });
    t.check(asked.length === 3 &&
            byMember.personTokens &&
            byMember.personTokens.operation === '/admin-api/hardware-tokens' &&
            byMember.personTokens.params.q === NAME &&
            byMember.personOath &&
            byMember.personOath.operation ===
              '/admin-api/hardware-tokens/oath' &&
            byMember.personOath.params.oq === NAME &&
            byMember.personOpenpgp &&
            byMember.personOpenpgp.operation === '/admin-api/openpgp' &&
            byMember.personOpenpgp.params.user === NAME,
            'A1. the drill asks the three central operations for the person',
            JSON.stringify(asked));
    t.check(WebPages.composeRequests(page, {}).length === 0,
            'A2. and the list of people asks none of them');
    const drawn = await drawer.draw('/admin/users', { user: NAME });
    const html = drawn.html || '';
    const ids = ['ucred-hardware-tokens', 'ucred-oath-tokens',
                 'ucred-yubiotp', 'ucred-piv', 'ucred-ssh', 'ucred-openpgp'];
    const at = ids.map(function (id) {
      return html.indexOf('href="#' + id + '"');
    });
    t.check(drawn.status === 200 && at.every(function (n, i) {
      return n >= 0 && (i === 0 || n > at[i - 1]);
    }) && html.indexOf('href="#ucred-kerberos"') < at[0],
            'A3. the Credentials tab draws Hardware tokens, OATH tokens, ' +
            'YubiKey OTP, PIV, SSH user certificates and OpenPGP and S/MIME, ' +
            'in that order, after Kerberos', JSON.stringify(at));
    const panel = function (id) {
      const start = html.indexOf('id="' + id + '"');
      if (start < 0) {
        return '';
      }
      const next = html.indexOf('<div class="subpanel', start + 1);
      return html.slice(start, next < 0 ? html.length : next);
    };
    t.check(/>OpenPGP and S\/MIME</.test(html) &&
            />SSH user certificates</.test(html),
            'A4. the sub-tabs are named as the central pages are');

    // --- B. the forms are the central pages' --------------------------------
    const piv = panel('ucred-piv');
    const pgp = panel('ucred-openpgp');
    const oath = panel('ucred-oath-tokens');
    const yubi = panel('ucred-yubiotp');
    const fixed = '<input type="hidden" name="username" value="' + NAME + '">';
    t.check(drawn.json && drawn.json.personTokens &&
            Array.isArray(drawn.json.personTokens.tokens),
            'B1. the composed answer is the central page\'s',
            JSON.stringify(Object.keys(drawn.json || {})));
    t.check(piv.indexOf('value="enrol-piv"') >= 0 &&
            piv.indexOf('action="/admin/hardware-tokens"') >= 0 &&
            piv.indexOf(fixed) >= 0 && piv.indexOf('id="hwt-user"') < 0,
            'B2. PIV enrolment posts to the central page with the person ' +
            'fixed (no person box)', piv.slice(0, 600));
    t.check(oath.indexOf('value="assign-oath"') >= 0 &&
            oath.indexOf(fixed) >= 0 &&
            yubi.indexOf('value="assign-yubiotp"') >= 0 &&
            yubi.indexOf(fixed) >= 0,
            'B3. OATH and YubiKey OTP assign to the person on the central ' +
            'page\'s operations', oath.slice(0, 400) + ' | ' +
            yubi.slice(0, 400));
    t.check(pgp.indexOf('action="/admin/openpgp"') >= 0 &&
            pgp.indexOf('value="challenge"') >= 0 &&
            pgp.indexOf('name="user" value="' + NAME + '"') >= 0 &&
            pgp.indexOf('data-tab=') < 0,
            'B4. OpenPGP and S/MIME draws the central page\'s person and ' +
            'registration bodies, without its tab headings',
            pgp.slice(0, 600));

    // --- C. the central pages are unchanged ---------------------------------
    const ctx = WebKit.context({}, true);
    const sample = [{ key: 'yubico/1', vendor: 'yubico', model: 'YubiKey 5',
                      holder: NAME, status: 'active',
                      evidenceSources: ['piv-attestation'],
                      credentials: [] }];
    const central = HardwareTokensPage.render({ tokens: sample,
      paging: { pages: 1 } }, ctx);
    t.check(central.indexOf(HardwareTokensPage.tokensTable(ctx.t, sample,
                                                           ctx)) >= 0 &&
            panel('ucred-hardware-tokens').length > 0,
            'C1. the tokens tab and the person\'s sub-tab draw one table');
    const person = drawn.json && drawn.json.personOpenpgp &&
                   drawn.json.personOpenpgp.person;
    t.check(!!person &&
            OpenPgpPage.personTab(ctx.t, person, true) ===
              '<h2 data-tab="person">' + WebKit.esc(person.username) +
              '</h2>' + OpenPgpPage.personBody(ctx.t, person, true),
            'C2. Directory → OpenPGP keys\' person tab is its heading over ' +
            'the same body');

    // --- D. read-only -----------------------------------------------------
    const UsersPage = require(ROOT + '/admin-ui/web_users');
    const readOnly = UsersPage.detail(WebKit.context({ user: NAME }, false),
                                      drawn.json);
    const tabsOf = function (whole, id) {
      const start = whole.indexOf('id="' + id + '"');
      const next = whole.indexOf('<div class="subpanel', start + 1);
      return start < 0 ? '' : whole.slice(start, next < 0 ? whole.length
                                                          : next);
    };
    t.check(ids.every(function (id) {
      return tabsOf(readOnly, id).indexOf('<form method="post"') < 0;
    }),
            'D1. a reader who may not write gets no form on any sub-tab');
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'person-token-subtabs-' + process.pid +
                        '-' + require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', 'const fs = require("fs");\n(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', PT_ROOT: ROOT, PT_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died first. Reported below with its stderr.
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
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'person_token_subtabs',
  describe: 'a person\'s Credentials sub-tabs for hardware tokens, OATH, ' +
            'YubiKey OTP, PIV, SSH and OpenPGP/S-MIME, drawn by the central ' +
            'pages\' own functions with the person fixed (#2052)',
  run: run
};
