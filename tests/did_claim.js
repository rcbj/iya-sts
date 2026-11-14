// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: did_claim.js
//
// ===========================================================================
// THE PREFERRED DID AND THE `did` CLAIM (#693, phase 2). rcbj approved the
// plan on #693: a person marks one PROVED DID as preferred, and it is
// released as the `did` claim behind its own scope, its own consent and the
// pairwise rule, off by default.
//
// Asserted in a CHILD PROCESS that loads the whole stack and listens on a
// loopback port, against the real directory:
//
//   P. the preferred DID: only a proved DID (never a by-value entry, never a
//      thumbprint), at most one, a by-value entry's own `preferred` ignored,
//      kept when proved again, cleared by removal; from the portal's door
//      (the identity is the token's) and the console's / `/admin-api`'s
//      act, each audited and refused under its code;
//   C. the claim in the ID Token and UserInfo: released when every
//      condition holds, and absent when any one fails — the setting off,
//      the scope not asked for, the scope not declared, no consent of the
//      person's own (a global one does not count), no preferred DID, a
//      disabled account, a pairwise client without the opt-in (present with
//      it); the discovery document advertising it only while it is on;
//   B. no way round it: a claims request (OIDC Core 5.5) naming `did`, and a
//      configured claim called `did`, are removed unless the rules release
//      it, and then the rules' value wins.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'did_claim',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.DC_ROOT;
  const OUT = process.env.DC_OUT;
  const http = require('http');
  const nodeCrypto = require('crypto');
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
                                 method: method, headers: headers },
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
          resolve({ status: res.statusCode, text: text, json: parsed });
        });
      });
      req.end(body);
    });
  }

  function claimsOf(token) {
    return JSON.parse(Buffer.from(String(token).split('.')[1], 'base64url')
                            .toString('utf8'));
  }

  function didJwk() {
    const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = pair.publicKey.export({ format: 'jwk' });
    return 'did:jwk:' + Buffer.from(JSON.stringify({ kty: jwk.kty,
      crv: jwk.crv, x: jwk.x, y: jwk.y })).toString('base64url');
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');
    const config = require(ROOT + '/common/config');
    const audit = require(ROOT + '/common/audit');
    const consent = require(ROOT + '/common/consent');
    const credentials = require(ROOT + '/common/credentials');
    const accountState = require(ROOT + '/common/account_state');
    const stats = require(ROOT + '/common/admin_stats');
    const helpers = require(ROOT + '/common/helpers');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const siop = require(ROOT + '/oid4vc/siop');
    const didClaim = require(ROOT + '/oauth-oidc/did_claim');
    const oauth2 = require(ROOT + '/oauth-oidc/oauth2');
    const actions = require(ROOT + '/admin-core/admin_actions');
    const portalSelfIssued = require(ROOT + '/portal/portal_self_issued');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;

    config.setOverride('oauth2.consentRequired', false);
    const ALICE = 'dc-alice';
    const BOB = 'dc-bob';
    ldap.createUser(ALICE, { invent: false });
    ldap.createUser(BOB, { invent: false });
    const client = function (id, scopes, fields) {
      applications.createApplication({ identifier: id,
        protocols: ['oauth2', 'oidc'],
        fields: Object.assign({ oauthClientId: id,
                                oauthTokenEndpointAuthMethod: 'none',
                                oauthAllowedScope: scopes,
                                oauthGrantType: ['password'],
                                oauthRedirectUri: 'https://' + id +
                                  '.example/cb' }, fields || {}) });
    };
    client('dc-web', ['openid', 'did']);
    client('dc-undeclared', ['openid']);
    client('dc-pairwise', ['openid', 'did'], { oauthSubjectType: 'pairwise' });
    client('dc-global', ['openid', 'did'], { oauthGlobalConsent: ['did'] });

    // --- P. The preferred DID ------------------------------------------
    const proved = didJwk();
    const proved2 = didJwk();
    const typed = didJwk();
    const thumb = 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:' +
      'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';
    const e1 = siop.enrol(ALICE, proved, 'phone', 'self (SIOPv2)',
                          { proof: 'wallet' });
    const e2 = siop.enrol(ALICE, proved2, 'laptop', 'self (SIOPv2)',
                          { proof: 'wallet' });
    const e3 = siop.enrol(ALICE, typed, 'typed', 'dc-admin',
                          { proof: 'admin' });
    const e4 = siop.enrol(ALICE, thumb, 'key', 'self (SIOPv2)',
                          { proof: 'wallet' });
    note(e1.ok && e2.ok && e3.ok && e4.ok,
         'P0. (a control: two proved DIDs, one by value and a proved ' +
         'thumbprint are enrolled)', JSON.stringify([e1, e2, e3, e4]));
    const byValue = siop.setPreferred(ALICE, typed);
    const ofThumb = siop.setPreferred(ALICE, thumb);
    const nobody = siop.setPreferred(ALICE, didJwk());
    note(!byValue.ok && byValue.code === 'not-proved' &&
         !ofThumb.ok && ofThumb.code === 'not-a-did' &&
         !nobody.ok && nobody.code === 'not-enrolled' &&
         siop.preferredSubjectOf(ALICE) === null,
         'P1. a by-value DID, a thumbprint and an unenrolled DID cannot be ' +
         'preferred', JSON.stringify([byValue, ofThumb, nobody]));
    const first = siop.setPreferred(ALICE, proved);
    const second = siop.setPreferred(ALICE, proved2);
    const marked = (siop.list(ALICE) || []).filter(function (one) {
      return one.preferred;
    });
    note(first.ok && second.ok && second.was === proved &&
         marked.length === 1 && marked[0].subject === proved2 &&
         siop.preferredSubjectOf(ALICE).subject === proved2,
         'P2. a proved DID is preferred, and preferring another moves the ' +
         'one mark', JSON.stringify(marked));
    siop.setPreferred(ALICE, proved);
    const reproved = siop.enrol(ALICE, proved, '', 'self (SIOPv2)',
                                { proof: 'wallet' });
    note(reproved.ok && reproved.again &&
         siop.preferredSubjectOf(ALICE).subject === proved,
         'P3. proving the preferred DID again keeps the mark');
    // A by-value row carrying `preferred: true`, written by hand, is read
    // as not preferred.
    credentials.writeSelfIssuedSubjects(BOB, [JSON.stringify({
      subject: typed.replace(/.$/, 'A'), label: '', by: 'dc-admin',
      proof: 'admin', enrolledAt: new Date().toISOString(),
      preferred: true })]);
    note(siop.preferredSubjectOf(BOB) === null &&
         (siop.list(BOB) || [])[0] && (siop.list(BOB) || [])[0].preferred ===
           false,
         'P4. a by-value entry\'s own `preferred` is ignored',
         JSON.stringify(siop.list(BOB)));

    // The portal's door: the identity is the token's.
    const ctx = {
      BASE: '/account-api', PORTAL: '/portal',
      audit: audit,
      refuse: function (res, status, code, error) {
        res.status = status;
        res.code = code;
        res.body = { error: error };
        return res;
      },
      json: function (res, status, body) {
        res.status = status;
        res.body = body;
        return res;
      },
      translatorFor: function () {
        return { text: function (key) { return key; } };
      }
    };
    const post = portalSelfIssued.accountOperations(ctx).filter(function (op) {
      return op.method === 'POST';
    })[0];
    const getOp = portalSelfIssued.accountOperations(ctx).filter(function (op) {
      return op.method === 'GET';
    })[0];
    const portal = function (who, body) {
      const res = {};
      post.handler({}, res, { username: who }, { body: body });
      return res;
    };
    const bobTries = portal(BOB, { action: 'prefer', subject: proved2 });
    const aliceTyped = portal(ALICE, { action: 'prefer', subject: typed });
    const alicePrefers = portal(ALICE, { action: 'prefer', subject: proved2 });
    const portalRows = audit.list().filter(function (row) {
      return row.action === 'portal.siop.prefer';
    });
    const viewed = {};
    getOp.handler({}, viewed, { username: ALICE }, { query: {} });
    note(bobTries.status === 400 && bobTries.code === 'STS-PORTAL-0615' &&
         aliceTyped.status === 400 && alicePrefers.status === 200 &&
         siop.preferredSubjectOf(ALICE).subject === proved2 &&
         siop.preferredSubjectOf(BOB) === null &&
         portalRows.length >= 3 &&
         portalRows.some(function (row) {
           return row.errorCode === 'STS-PORTAL-0615' && row.actor === BOB;
         }) &&
         viewed.body.subjects.filter(function (one) {
           return one.preferred;
         }).length === 1,
         'P5. the portal: a person prefers only their own proved DID — ' +
         'another\'s subject and a by-value one are refused ' +
         '(STS-PORTAL-0615) — audited, and the view says which',
         JSON.stringify([bobTries, aliceTyped, alicePrefers.status,
                         portalRows.length]));
    const cleared = portal(ALICE, { action: 'unprefer', subject: '' });
    note(cleared.status === 200 && siop.preferredSubjectOf(ALICE) === null,
         'P6. the portal clears the mark');

    // The console's and `/admin-api`'s act.
    const adminSet = await actions.usersAction({
      action: 'set-preferred-self-issued-subject', user: ALICE,
      subject: proved }, { actor: 'dc-admin', via: 'api' });
    const adminTyped = await actions.usersAction({
      action: 'set-preferred-self-issued-subject', user: ALICE,
      subject: typed }, { actor: 'dc-admin', via: 'api' });
    const adminRows = audit.list().filter(function (row) {
      return row.action === 'admin.siop.preferred';
    });
    note(adminSet && adminSet.ok && adminSet.preferred === proved &&
         adminTyped && !adminTyped.ok &&
         require(ROOT + '/common/error_codes').codeOf(adminTyped) ===
           'STS-ADMIN-0872' &&
         siop.preferredSubjectOf(ALICE).subject === proved &&
         adminRows.length >= 2,
         'P7. the console and /admin-api: a proved DID is preferred, a ' +
         'by-value one refused (STS-ADMIN-0872), each audited',
         JSON.stringify([adminSet, adminTyped, adminRows.length]));

    // --- C. The claim ---------------------------------------------------
    const grant = async function (clientId, scope, extra) {
      const got = await request(port, 'POST', '/oauth2/token', {
        form: Object.assign({ grant_type: 'password', username: ALICE,
                              password: 'anything', client_id: clientId,
                              scope: scope }, extra || {}) });
      return got.json || {};
    };
    const userinfo = async function (token, query) {
      const r = await request(port, 'GET', '/oauth2/userinfo' +
                              (query ? '?' + query : ''),
        { headers: { authorization: 'Bearer ' + token } });
      return r.json || {};
    };
    const both = async function (clientId, scope, extra) {
      const set = await grant(clientId, scope, extra);
      const id = set.id_token ? claimsOf(set.id_token) : {};
      const ui = set.access_token ? await userinfo(set.access_token) : {};
      return { id: id, ui: ui, set: set };
    };
    const decide = function (clientId, scope, who) {
      return didClaim.decide({ username: who || ALICE, clientId: clientId,
                               scope: scope });
    };
    consent.record(ALICE, 'dc-web', ['did'], ALICE);
    consent.record(ALICE, 'dc-undeclared', ['did'], ALICE);
    consent.record(ALICE, 'dc-pairwise', ['did'], ALICE);
    const discovery = async function () {
      const r = await request(port, 'GET',
                              '/.well-known/openid-configuration');
      const d = r.json || {};
      return (d.scopes_supported || []).indexOf('did') >= 0 &&
        (d.claims_supported || []).indexOf('did') >= 0;
    };

    const off = await both('dc-web', 'openid did');
    note(off.set.id_token && off.id.did === undefined &&
         off.ui.did === undefined && !(await discovery()) &&
         decide('dc-web', 'openid did').code === '',
         'C1. oauth2.didClaim off (the default): no claim, and the scope ' +
         'and claim are not advertised', JSON.stringify([off.id, off.ui]));

    config.setOverride('oauth2.didClaim', true);
    const on = await both('dc-web', 'openid did');
    note(on.id.did === proved && on.ui.did === proved && (await discovery()),
         'C2. every condition holds: the preferred, proved DID in the ID ' +
         'Token and the UserInfo response, and both advertised',
         JSON.stringify([on.id.did, on.ui.did, on.set.error]));

    const notAsked = await both('dc-web', 'openid');
    note(notAsked.id.did === undefined && notAsked.ui.did === undefined,
         'C3. the scope not asked for: absent');

    const undeclared = await both('dc-undeclared', 'openid did');
    note(undeclared.id.did === undefined && undeclared.ui.did === undefined &&
         decide('dc-undeclared', 'openid did').code === 'STS-OAUTH-0972',
         'C4. a client that does not declare did (granted it anyway in ' +
         'development): absent, STS-OAUTH-0972',
         JSON.stringify([undeclared.set.scope, undeclared.id.did]));

    const global = await both('dc-global', 'openid did');
    note(global.id.did === undefined && global.ui.did === undefined &&
         decide('dc-global', 'openid did').code === 'STS-OAUTH-0973',
         'C5. only a global consent: absent, STS-OAUTH-0973');

    const heldToken = on.set.access_token;
    consent.revoke(ALICE, 'dc-web', 'did', ALICE);
    const withdrawn = await userinfo(heldToken);
    const afterWithdraw = await both('dc-web', 'openid did');
    note(withdrawn.did === undefined && withdrawn.error === 'invalid_token' &&
         afterWithdraw.id.did === undefined &&
         decide('dc-web', 'openid did').code === 'STS-OAUTH-0973',
         'C6. consent withdrawn: the token issued before is revoked with it ' +
         '(withdrawn means withdrawn), and the next ID Token has no claim',
         JSON.stringify(withdrawn));
    consent.record(ALICE, 'dc-web', ['did'], ALICE);

    const beforeClear = await both('dc-web', 'openid did');
    siop.setPreferred(ALICE, '');
    const heldAfterClear = await userinfo(beforeClear.set.access_token);
    const unpreferred = await both('dc-web', 'openid did');
    note(beforeClear.ui.did === proved && heldAfterClear.sub &&
         heldAfterClear.did === undefined &&
         unpreferred.id.did === undefined && unpreferred.ui.did === undefined &&
         decide('dc-web', 'openid did').code === 'STS-OAUTH-0975',
         'C7. no preferred DID: absent, STS-OAUTH-0975 — from UserInfo for ' +
         'a token issued while it was marked, too',
         JSON.stringify(heldAfterClear));
    // Only an administrator's by-value DID: still nothing to release.
    consent.record(BOB, 'dc-web', ['did'], BOB);
    note(decide('dc-web', 'openid did', BOB).code === 'STS-OAUTH-0975',
         'C8. only a by-value DID (marked preferred by hand): absent, ' +
         'STS-OAUTH-0975');
    siop.setPreferred(ALICE, proved);
    siop.remove(ALICE, proved, ALICE);
    note(siop.preferredSubjectOf(ALICE) === null &&
         decide('dc-web', 'openid did').code === 'STS-OAUTH-0975',
         'C9. removing the preferred DID clears it: absent');
    siop.enrol(ALICE, proved, 'phone', 'self (SIOPv2)', { proof: 'wallet' });
    siop.setPreferred(ALICE, proved);

    const pairwise = await both('dc-pairwise', 'openid did');
    note(pairwise.set.id_token && pairwise.id.did === undefined &&
         pairwise.ui.did === undefined &&
         decide('dc-pairwise', 'openid did').code === 'STS-OAUTH-0974',
         'C10. a pairwise client without oauthDidClaimWithPairwise: ' +
         'absent, STS-OAUTH-0974', JSON.stringify(pairwise.id));
    const optIn = applications.updateApplication('dc-pairwise',
      { mode: 'set', attribute: 'oauthDidClaimWithPairwise', value: 'TRUE' });
    const pairwiseIn = await both('dc-pairwise', 'openid did');
    note(optIn.ok && pairwiseIn.id.did === proved &&
         pairwiseIn.ui.did === proved && pairwiseIn.id.sub !== on.id.sub,
         'C11. with the opt-in: present, and the sub is still pairwise',
         JSON.stringify([optIn.errors, pairwiseIn.id.did]));

    const disabled = accountState.setDisabled(ALICE, true,
                                              { actor: 'dc-admin' });
    note(disabled.ok && decide('dc-web', 'openid did').code ===
           'STS-OAUTH-0976',
         'C12. a disabled account: absent, STS-OAUTH-0976',
         JSON.stringify(disabled));
    accountState.setDisabled(ALICE, false, { actor: 'dc-admin' });

    // --- B. No way round it ---------------------------------------------
    const base = 'https://sts.test';
    const user = helpers.userFor(ALICE);
    const asked = { id_token: { did: null }, userinfo: { did: null } };
    const viaRequest = claimsOf(await oauth2.idToken(base, {
      client_id: 'dc-web', username: ALICE, user: user, scope: 'openid',
      claims: asked }));
    note(viaRequest.did === undefined,
         'B1. a claims request naming did, without the scope: absent',
         JSON.stringify(viaRequest));
    const plain = await grant('dc-web', 'openid');
    const viaRequestUi = await userinfo(plain.access_token,
      'claims=' + encodeURIComponent(JSON.stringify({
        userinfo: { did: null } })));
    note(plain.access_token && viaRequestUi.sub &&
         viaRequestUi.did === undefined,
         'B2. the same claims request at UserInfo: absent',
         JSON.stringify(viaRequestUi));
    stats.setClaimSet('id_token', [{ name: 'did',
                                     value: 'did:example:typed' }]);
    const typedNoScope = claimsOf(await oauth2.idToken(base, {
      client_id: 'dc-web', username: ALICE, user: user, scope: 'openid' }));
    const typedScope = claimsOf(await oauth2.idToken(base, {
      client_id: 'dc-web', username: ALICE, user: user,
      scope: 'openid did' }));
    stats.setClaimSet('id_token', []);
    note(typedNoScope.did === undefined && typedScope.did === proved,
         'B3. a configured claim called did is removed, and the rules\' ' +
         'value wins where they release one',
         JSON.stringify([typedNoScope.did, typedScope.did]));

    config.clearOverride('oauth2.didClaim');
    server.close();
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'did-claim-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', DC_ROOT: ROOT, DC_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'did_claim',
  describe: 'the preferred DID and the did claim (#693): only a proved DID ' +
            'may be preferred, from the portal and the console; released ' +
            'in the ID Token and UserInfo only behind the setting, the ' +
            'declared and granted scope, the person\'s own consent, a ' +
            'public subject or the opt-in, and an enabled account; never ' +
            'through a claims request or a configured claim',
  run: run
};
