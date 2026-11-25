// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/group_claims_cap.js
//
// ===========================================================================
// THE GROUPS CLAIM'S CAP, AND WHAT A RELYING PARTY SEES PAST IT (#2247, ASVS
// 5.0.0 4.2.5).
//
// The whole stack in a child process, with the directory's groups answered
// by the test (`group_claims.setDirectory()`, the slot `ldap_server.js`
// fills):
//
//   A. Below `groups.claimMaxBytes` (4096 by default) nothing changes: the
//      access token and the ID Token carry the whole list, as before.
//   B. Past it both carry OpenID Connect Core section 5.6.2's
//      `_claim_names` / `_claim_sources` instead, pointing at the realm's
//      /oauth2/groups, and never a shorter list; UserInfo and a SAML
//      assertion's attribute still carry the whole list.
//   C. /oauth2/groups answers the whole list as a signed JWT for the access
//      token's subject; no token, and a client_credentials token, are 401.
//   D. 0 turns the cap off; a typed claim of the same name is never cut; a
//      context with no base URL is left whole; another source's
//      `_claim_names` is kept beside this one.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'group_claims_cap',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The child's whole program, serialised with toString() and run by `node -e`
// — exempt from the Entering/Leaving rule (root CLAUDE.md, Code style), and it
// carries its errors on the result it writes.
function childMain() {
  const ROOT = process.env.GC_ROOT;
  const OUT = process.env.GC_OUT;
  const http = require('http');
  const fs = require('fs');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      const body = o.form ? new URLSearchParams(o.form).toString() : '';
      const headers = Object.assign({}, o.headers || {});
      if (method !== 'GET') {
        headers['content-type'] = 'application/x-www-form-urlencoded';
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers,
                                 agent: false },
                               function (res) {
        let text = '';
        res.on('data', function (chunk) { text += chunk; });
        res.on('end', function () {
          let parsed = null;
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            // No logger in a `node -e` child; the reason travels on the
            // result.
            parsed = { parseError: e.message };
          }
          resolve({ status: res.statusCode, text: text, json: parsed,
                    headers: res.headers });
        });
      });
      req.end(body);
    });
  }

  function claimsOf(token) {
    return JSON.parse(Buffer.from(String(token).split('.')[1], 'base64url')
                            .toString('utf8'));
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');
    const config = require(ROOT + '/common/config');
    const stats = require(ROOT + '/common/admin_stats');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const groupClaims = require(ROOT + '/common/group_claims');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    config.setOverride('oauth2.consentRequired', false);

    // Everybody's groups, answered here: SMALL is in three, LARGE in four
    // hundred, which is about 13 KiB of claim.
    const SMALL = 'gc-small';
    const LARGE = 'gc-large';
    ldap.createUser(SMALL, { invent: false });
    ldap.createUser(LARGE, { invent: false });
    const groupsFor = function (name, count) {
      const out = [];
      for (let i = 0; i < count; i++) {
        const cn = name + '-group-' + String(i).padStart(4, '0');
        out.push({ dn: 'cn=' + cn + ',ou=groups,dc=example,dc=com', cn: cn,
                   via: ['member'] });
      }
      return out;
    };
    groupClaims.setDirectory({
      groupsOfUser: function (key) {
        const who = String(key || '').toLowerCase();
        const count = who.indexOf(LARGE) >= 0 ? 400
          : (who.indexOf(SMALL) >= 0 ? 3 : 0);
        return { dn: 'uid=' + who + ',ou=users,dc=example,dc=com',
                 entryFound: true, groups: groupsFor(who, count) };
      }
    });
    applications.createApplication({ identifier: 'gc-web',
      protocols: ['oauth2', 'oidc'],
      fields: { oauthClientId: 'gc-web', oauthTokenEndpointAuthMethod: 'none',
                oauthAllowedScope: ['openid'],
                oauthGrantType: ['password'],
                oauthRedirectUri: 'https://gc-web.example/cb' } });
    const grant = async function (who) {
      const got = await request(port, 'POST', '/oauth2/token', {
        form: { grant_type: 'password', username: who, password: 'anything',
                client_id: 'gc-web', scope: 'openid' } });
      return got.json || {};
    };

    // --- A. Below the cap ---------------------------------------------------
    note(groupClaims.maxBytes() === 4096,
         'A0. groups.claimMaxBytes is 4096 by default', groupClaims.maxBytes());
    const small = await grant(SMALL);
    const smallAt = small.access_token ? claimsOf(small.access_token) : {};
    const smallId = small.id_token ? claimsOf(small.id_token) : {};
    note(Array.isArray(smallAt.groups) && smallAt.groups.length === 3 &&
         Array.isArray(smallId.groups) && smallId.groups.length === 3 &&
         smallAt._claim_names === undefined &&
         smallId._claim_names === undefined,
         'A1. below the cap the access token and the ID Token carry the ' +
         'whole list, as before',
         JSON.stringify([small.error, smallAt.groups, smallId.groups]));

    // --- B. Past it ---------------------------------------------------------
    const large = await grant(LARGE);
    const largeAt = large.access_token ? claimsOf(large.access_token) : {};
    const largeId = large.id_token ? claimsOf(large.id_token) : {};
    const reference = function (claims) {
      const source = claims._claim_names && claims._claim_names.groups;
      const where = source && claims._claim_sources &&
        claims._claim_sources[source];
      return where ? String(where.endpoint || '') : '';
    };
    note(largeAt.groups === undefined && largeId.groups === undefined &&
         /\/oauth2\/groups$/.test(reference(largeAt)) &&
         /\/oauth2\/groups$/.test(reference(largeId)) &&
         reference(largeId).indexOf('http') === 0 &&
         largeId._claim_sources[groupClaims.GROUPS_SOURCE].access_token ===
           undefined,
         'B1. past the cap both carry a section 5.6.2 distributed claim ' +
         'pointing at /oauth2/groups, never a shorter list, and no ' +
         'access_token inside the token',
         JSON.stringify([large.error, largeAt._claim_names,
                         largeAt._claim_sources, largeId._claim_sources]));
    note(large.access_token && large.access_token.length < 8192,
         'B2. so the access token fits an 8 KiB header',
         large.access_token && large.access_token.length);
    const ui = await request(port, 'GET', '/oauth2/userinfo',
      { headers: { authorization: 'Bearer ' + large.access_token } });
    note(ui.status === 200 && Array.isArray(ui.json.groups) &&
         ui.json.groups.length === 400,
         'B3. UserInfo, a response body, still carries the whole list',
         ui.status + ' ' + ui.text.slice(0, 200));
    const saml = stats.samlAttributes('saml2', { username: LARGE });
    const samlGroups = saml.filter(function (one) {
      return one.name === 'groups';
    })[0];
    note(samlGroups && samlGroups.values.length === 400,
         'B4. a SAML assertion\'s attribute still carries the whole list',
         samlGroups && samlGroups.values.length);

    // --- C. The source ------------------------------------------------------
    const source = await request(port, 'GET', '/oauth2/groups',
      { headers: { authorization: 'Bearer ' + large.access_token } });
    const answered = source.status === 200 ? claimsOf(source.text) : {};
    note(source.status === 200 &&
         /application\/jwt/.test(String(source.headers['content-type'])) &&
         /no-store/.test(String(source.headers['cache-control'])) &&
         Array.isArray(answered.groups) && answered.groups.length === 400 &&
         answered.sub === largeId.sub && answered.aud === 'gc-web' &&
         answered.iss === largeId.iss && answered.exp > answered.iat,
         'C1. /oauth2/groups answers the whole list for the token\'s ' +
         'subject as a signed JWT: iss, sub, aud, iat, exp',
         source.status + ' ' + source.text.slice(0, 200));
    const bare = await request(port, 'GET', '/oauth2/groups');
    note(bare.status === 401 &&
         /Bearer|DPoP/.test(String(bare.headers['www-authenticate'] || '')),
         'C2. with no token it is 401 with a challenge', bare.status);
    const forged = await request(port, 'GET', '/oauth2/groups',
      { headers: { authorization: 'Bearer ' + small.access_token
        .split('.').slice(0, 2).join('.') + '.AAAA' } });
    note(forged.status === 401, 'C3. a token whose signature does not ' +
         'verify is 401', forged.status);
    note(!/STS-[A-Z]+-\d{4}/.test(bare.text + forged.text),
         'C4. and no error code is sent');

    // --- D. The edges -------------------------------------------------------
    const values = groupsFor('x', 400).map(function (g) {
      return g.cn;
    });
    const ctx = { username: LARGE, base_url: 'https://sts.example' };
    const cut = function (claims, produced, context, setId) {
      groupClaims.overage(setId || 'access_token', context || ctx, claims,
                          produced);
      return claims;
    };
    config.setOverride('groups.claimMaxBytes', '0');
    const off = { groups: values };
    note(cut(off, off).groups === values && off._claim_names === undefined,
         'D1. 0 turns the cap off');
    config.clearOverride('groups.claimMaxBytes');
    const typed = { groups: ['typed'] };
    note(cut(typed, { groups: values }).groups[0] === 'typed',
         'D2. a typed claim of the same name won over the groups layer and ' +
         'is never cut');
    const nowhere = { groups: values };
    note(cut(nowhere, nowhere, { username: LARGE }).groups === values,
         'D3. a context with no base URL (the console\'s preview, a ' +
         'WS-Trust JWT) is left whole');
    const info = { groups: values };
    note(cut(info, info, ctx, 'userinfo').groups === values,
         'D4. the UserInfo set is never capped');
    const both = { groups: values, _claim_names: { email: 'cp' },
                   _claim_sources: { cp: { JWT: 'x.y.z' } } };
    cut(both, { groups: values.slice(0) });
    note(both.groups === values,
         'D5. (a control: an array that is not the layer\'s own is left)');
    const merged = { groups: values, _claim_names: { email: 'cp' },
                     _claim_sources: { cp: { JWT: 'x.y.z' } } };
    cut(merged, merged);
    note(merged._claim_names.email === 'cp' &&
         merged._claim_names.groups === groupClaims.GROUPS_SOURCE &&
         merged._claim_sources.cp.JWT === 'x.y.z',
         'D6. another source\'s _claim_names and _claim_sources are kept ' +
         'beside this one', JSON.stringify(merged._claim_names));

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child threw',
                    detail: String((e && e.stack) || e) });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(1);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'gc-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  GC_ROOT: ROOT, GC_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
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
  name: 'group_claims_cap',
  describe: 'the groups claim\'s cap (groups.claimMaxBytes, #2247): whole ' +
            'below it; past it an OpenID Connect Core 5.6.2 distributed ' +
            'claim pointing at /oauth2/groups in the access token and ID ' +
            'Token, while UserInfo and SAML carry the whole list',
  run: run
};
