// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: launch.js
//
// ===========================================================================
// ONE IDENTITY-PROVIDER-INITIATED SIGN-IN LINK PER APPLICATION (#426, #713).
//
// `GET /launch/{app}` chooses a protocol, checks the application's switch
// and hands the browser to that protocol's own endpoint — or, for OpenID
// Connect, signs the person in, records the launch and sends them to the
// client's initiate_login_uri. `launch/CLAUDE.md` argues it. Held here, in a
// child process on an ephemeral loopback port, over HTTP with a cookie jar:
//
//   a. an unknown application is 404 (STS-LAUNCH-0001); a protocol that is
//      not one of the four is 400 (0002), one the application is not
//      declared for 404 (0003);
//   b. the switch is off by default (403, 0005), and an entry's TRUE opens
//      it: SAML 2.0 goes to /saml2/unsolicited/{sp} with target as
//      RelayState, SAML 1.1 to /saml11/sso/{rp} with providerId and TARGET,
//      WS-Federation to /wsfed/initiate/{rp} with wctx;
//   c. nowhere registered to send it is 409 (0006);
//   d. two protocols on and no preference is 409 (0004); ?protocol= picks,
//      and appLaunchProtocol picks when the link does not;
//   e. OpenID Connect: no session goes to the sign-in screen and back; then
//      303 to initiate_login_uri with iss, login_hint, tenant and the
//      target_link_uri, and the launch is on the session;
//   f. /oauth2/authorize for that client, whose own start is off, is not
//      refused within the window, and is refused unauthorized_client
//      (STS-OAUTH-0959) with no launch on the session or one older than the
//      window; a client whose own start is on is not touched;
//   g. the console's view (`LaunchLinks.linksFor()`) carries the URL, the
//      switch and what is missing for each protocol, and the portal's
//      Applications view offers a Sign in link only where the switch is on.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'launch',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Run in a child process as a string (`node -e`), so it carries no
// Entering/Leaving pairs: the code style exempts a `node -e` child.
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.LA_ROOT;
  const OUT = process.env.LA_OUT;
  const http = require('http');
  const crypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const sleep = function (ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  };

  function browser(port) {
    const jar = {};
    const go = function (method, urlPath) {
      return new Promise(function (resolve) {
        const headers = {};
        if (Object.keys(jar).length) {
          headers.cookie = Object.keys(jar).map(function (k) {
            return k + '=' + jar[k];
          }).join('; ');
        }
        const req = http.request({ host: '127.0.0.1', port: port,
                                   path: String(urlPath).replace(
                                     /^https?:\/\/[^/]+/, ''),
                                   method: method, headers: headers },
                                 function (res) {
          let text = '';
          (res.headers['set-cookie'] || []).forEach(function (line) {
            const pair = line.split(';')[0];
            const eq = pair.indexOf('=');
            jar[pair.slice(0, eq)] = pair.slice(eq + 1);
          });
          res.on('data', function (c) { text += c; });
          res.on('end', function () {
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text });
          });
        });
        req.end();
      });
    };
    return { go: go, jar: jar };
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const authnScreen = require(ROOT + '/tests/tools/authn_screen');
    const app = require(ROOT + '/common/app');
    const audit = require(ROOT + '/common/audit');
    const config = require(ROOT + '/common/config');
    const applications = require(ROOT + '/common/applications');
    const authn = require(ROOT + '/authn/authn');
    const LaunchLinks = require(ROOT + '/common/launch_links');
    const overview = require(ROOT + '/portal/account_overview');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    config.setOverride('oauth2.consentRequired', false);

    // INVENTED FIXTURES: the identifiers, the addresses and the username
    // below name nothing outside this test.
    const SP2 = 'urn:launch:saml2';
    const SP2_OFF = 'urn:launch:saml2-off';
    const SP2_NOACS = 'urn:launch:saml2-no-acs';
    const RP11 = 'urn:launch:saml11';
    const RP_WS = 'urn:launch:wsfed';
    const BOTH = 'urn:launch:both';
    const PREFERS = 'urn:launch:prefers';
    const RP_CLIENT = 'launch-rp';
    const PLAIN_CLIENT = 'launch-plain';
    const ACS = 'https://sp.launch.example/acs';
    const REPLY = 'https://rp.launch.example/wsfed';
    const INITIATE = 'https://rp.launch.example/login';
    const HOME = 'https://rp.launch.example/home';
    const REDIRECT = 'https://rp.launch.example/cb';
    const USER = 'launch-alice';

    const made = [
      applications.createApplication({ identifier: SP2, protocols: ['saml2'],
        fields: { samlEntityId: SP2, samlAssertionConsumerService: [ACS],
                  saml2IdpInitiatedSso: 'TRUE' } }),
      applications.createApplication({ identifier: SP2_OFF,
        protocols: ['saml2'],
        fields: { samlEntityId: SP2_OFF,
                  samlAssertionConsumerService: [ACS] } }),
      applications.createApplication({ identifier: SP2_NOACS,
        protocols: ['saml2'],
        fields: { samlEntityId: SP2_NOACS, saml2IdpInitiatedSso: 'TRUE' } }),
      applications.createApplication({ identifier: RP11,
        protocols: ['saml11'],
        fields: { samlEntityId: RP11, samlAssertionConsumerService: [ACS],
                  saml11IdpInitiatedSso: 'TRUE' } }),
      applications.createApplication({ identifier: RP_WS,
        protocols: ['wsfed'],
        fields: { wsfedRealm: [RP_WS], wsfedReplyUrl: [REPLY],
                  wsfedIdpInitiatedSso: 'TRUE' } }),
      applications.createApplication({ identifier: BOTH,
        protocols: ['saml2', 'wsfed'],
        fields: { samlEntityId: BOTH, samlAssertionConsumerService: [ACS],
                  wsfedRealm: [BOTH], wsfedReplyUrl: [REPLY],
                  saml2IdpInitiatedSso: 'TRUE',
                  wsfedIdpInitiatedSso: 'TRUE' } }),
      applications.createApplication({ identifier: PREFERS,
        protocols: ['saml2', 'wsfed'],
        fields: { samlEntityId: PREFERS, samlAssertionConsumerService: [ACS],
                  wsfedRealm: [PREFERS], wsfedReplyUrl: [REPLY],
                  saml2IdpInitiatedSso: 'TRUE',
                  wsfedIdpInitiatedSso: 'TRUE',
                  appLaunchProtocol: 'wsfed' } }),
      applications.createApplication({ identifier: RP_CLIENT,
        protocols: ['oauth2', 'oidc'],
        fields: { oauthClientId: RP_CLIENT, oauthRedirectUri: [REDIRECT],
                  oauthGrantType: ['authorization_code'],
                  oauthAllowedScope: ['openid'],
                  oauthTokenEndpointAuthMethod: 'none',
                  appHomePageUrl: HOME,
                  oauthInitiateLoginUri: INITIATE,
                  oauthThirdPartyInitiatedLogin: 'TRUE',
                  oauthSpInitiatedSso: 'FALSE' } }),
      applications.createApplication({ identifier: PLAIN_CLIENT,
        protocols: ['oauth2', 'oidc'],
        fields: { oauthClientId: PLAIN_CLIENT, oauthRedirectUri: [REDIRECT],
                  oauthGrantType: ['authorization_code'],
                  oauthAllowedScope: ['openid'],
                  oauthTokenEndpointAuthMethod: 'none' } })
    ];
    note(made.every(function (one) { return one && one.ok !== false; }),
         '0. (the nine applications are registered)',
         JSON.stringify(made).slice(0, 600));

    const link = function (identifier, query) {
      const q = new URLSearchParams(query || {}).toString();
      return '/launch/' + encodeURIComponent(identifier) + (q ? '?' + q : '');
    };
    const refusedWith = async function (code) {
      await sleep(50);
      return audit.list().some(function (row) {
        return row.errorCode === code;
      });
    };
    const where = function (r) {
      return String(r.headers.location || '').replace(/^https?:\/\/[^/]+/,
                                                      '');
    };

    // --- a. what the link names --------------------------------------------
    const anon = browser(port);
    let r = await anon.go('GET', link('urn:launch:nobody'));
    note(r.status === 404 && await refusedWith('STS-LAUNCH-0001'),
         'a1. an application this realm does not have is 404 ' +
         '(STS-LAUNCH-0001)', r.status);
    r = await anon.go('GET', link(SP2, { protocol: 'kerberos' }));
    note(r.status === 400 && await refusedWith('STS-LAUNCH-0002'),
         'a2. a protocol that is not one of the four is 400 (0002)',
         r.status);
    r = await anon.go('GET', link(SP2, { protocol: 'wsfed' }));
    note(r.status === 404 && await refusedWith('STS-LAUNCH-0003'),
         'a3. a protocol the application is not declared for is 404 (0003)',
         r.status);

    // --- b. the switch, and where each protocol goes -------------------------
    r = await anon.go('GET', link(SP2_OFF));
    note(r.status === 403 && await refusedWith('STS-LAUNCH-0005'),
         'b1. an application with no override is refused 403: ' +
         'identity-provider-initiated sign-in is off by default (0005)',
         r.status);
    r = await anon.go('GET', link(SP2, { target: '/after?x=1' }));
    note(r.status === 303 && where(r) === '/saml2/unsolicited/' +
           encodeURIComponent(SP2) + '?target=' +
           encodeURIComponent('/after?x=1'),
         'b2. SAML 2.0 goes to /saml2/unsolicited/{sp} with the target as ' +
         'RelayState', r.status + ' ' + where(r));
    r = await anon.go('GET', link(RP11, { target: 'https://rp/t' }));
    note(r.status === 303 && where(r) === '/saml11/sso/' +
           encodeURIComponent(RP11) + '?providerId=' +
           encodeURIComponent(RP11) + '&TARGET=' +
           encodeURIComponent('https://rp/t'),
         'b3. SAML 1.1 goes to /saml11/sso/{rp} with providerId and TARGET',
         r.status + ' ' + where(r));
    r = await anon.go('GET', link(RP_WS, { target: 'ctx' }));
    note(r.status === 303 && where(r) === '/wsfed/initiate/' +
           encodeURIComponent(RP_WS) + '?wctx=ctx',
         'b4. WS-Federation goes to /wsfed/initiate/{rp} with the target as ' +
         'wctx', r.status + ' ' + where(r));

    // --- c. nowhere to send it -----------------------------------------------
    r = await anon.go('GET', link(SP2_NOACS));
    note(r.status === 409 && await refusedWith('STS-LAUNCH-0006'),
         'c1. no registered assertion consumer service is 409 (0006)',
         r.status);

    // --- d. more than one protocol -------------------------------------------
    r = await anon.go('GET', link(BOTH));
    note(r.status === 409 && await refusedWith('STS-LAUNCH-0004'),
         'd1. two protocols switched on and no preference is 409 (0004)',
         r.status);
    r = await anon.go('GET', link(BOTH, { protocol: 'wsfed' }));
    note(r.status === 303 && where(r).indexOf('/wsfed/initiate/') === 0,
         'd2. ?protocol= picks one', r.status + ' ' + where(r));
    r = await anon.go('GET', link(PREFERS));
    note(r.status === 303 && where(r).indexOf('/wsfed/initiate/') === 0,
         'd3. appLaunchProtocol picks when the link does not',
         r.status + ' ' + where(r));

    // --- e. OpenID Connect Core section 4 ------------------------------------
    const alice = browser(port);
    const first = await alice.go('GET', link(RP_CLIENT));
    const toScreen = String(first.headers.location || '');
    note(first.status === 303 && /\/authn\/login/.test(toScreen),
         'e1. with no session the OpenID Connect launch goes to the sign-in ' +
         'screen', first.status + ' ' + toScreen);
    const sent = await authnScreen.submit({ port: port, jar: alice.jar,
      at: toScreen, fields: { action: 'login', username: USER,
                              password: 'anything' } });
    const back = String(sent.location || '').replace(/^https?:\/\/[^/]+/, '');
    note(back.indexOf(link(RP_CLIENT)) === 0,
         'e2. the sign-in returns to the launch link', back);
    r = await alice.go('GET', back || link(RP_CLIENT));
    let to = null;
    try {
      to = new URL(String(r.headers.location || ''));
    } catch (e) {
      to = null;
    }
    note(r.status === 303 && to && to.origin + to.pathname === INITIATE &&
         !!to.searchParams.get('iss') &&
         to.searchParams.get('login_hint') === USER &&
         !!to.searchParams.get('tenant') &&
         to.searchParams.get('target_link_uri') === HOME,
         'e3. then 303 to the client\'s initiate_login_uri with iss, ' +
         'login_hint, tenant and the home page as target_link_uri',
         r.status + ' ' + String(r.headers.location || ''));
    const session = authn.sessionsOf(USER)[0];
    note(session && session.launches &&
         Number(session.launches[RP_CLIENT]) > 0,
         'e4. the launch is recorded on the session',
         JSON.stringify(session && session.launches));

    // --- f. the client's own start, at the authorization endpoint ------------
    const authorize = async function (client) {
      const verifier = crypto.randomBytes(32).toString('base64url');
      const challenge = crypto.createHash('sha256').update(verifier)
        .digest('base64url');
      return alice.go('GET', '/oauth2/authorize?' + new URLSearchParams({
        client_id: client, response_type: 'code', redirect_uri: REDIRECT,
        scope: 'openid', state: 's', code_challenge: challenge,
        code_challenge_method: 'S256', nonce: 'n1' }).toString());
    };
    r = await authorize(RP_CLIENT);
    const fresh = String(r.headers.location || '');
    note(fresh.indexOf('error=unauthorized_client') < 0 &&
         fresh.indexOf(REDIRECT) === 0 && /[?&]code=/.test(fresh),
         'f1. within the window, the launched client\'s authorization ' +
         'request is answered', r.status + ' ' + fresh.slice(0, 200));
    note(!(session.launches || {})[RP_CLIENT],
         'f2. and the launch is spent once the response went out',
         JSON.stringify(session.launches));
    r = await authorize(RP_CLIENT);
    note(String(r.headers.location || '')
           .indexOf('error=unauthorized_client') > 0 &&
         await refusedWith('STS-OAUTH-0959'),
         'f3. with no launch on the session it is refused ' +
         'unauthorized_client (STS-OAUTH-0959)',
         r.status + ' ' + String(r.headers.location || '').slice(0, 200));
    LaunchLinks.noteLaunch(session, RP_CLIENT, Math.floor(Date.now() / 1000) -
      Number(config.value('oauth2.launchWindowS')) - 5);
    r = await authorize(RP_CLIENT);
    note(String(r.headers.location || '')
           .indexOf('error=unauthorized_client') > 0,
         'f4. a launch older than oauth2.launchWindowS does not count',
         r.status);
    r = await authorize(PLAIN_CLIENT);
    note(String(r.headers.location || '')
           .indexOf('error=unauthorized_client') < 0,
         'f5. a client whose own start is on (the default) is not touched',
         r.status + ' ' + String(r.headers.location || '').slice(0, 200));

    // --- g. the console's links and the portal's -----------------------------
    const links = LaunchLinks.linksFor(applications.get(SP2_NOACS), base);
    note(links.saml2 && links.saml2.url === base + link(SP2_NOACS,
           { protocol: 'saml2' }) && links.saml2.enabled === true &&
         links.saml2.missing.join() === 'samlAssertionConsumerService' &&
         !links.wsfed,
         'g1. the console\'s view carries the URL, the switch and what is ' +
         'missing, for the protocols the application has',
         JSON.stringify(links));
    const off = LaunchLinks.linksFor(applications.get(SP2_OFF), base);
    note(off.saml2 && off.saml2.enabled === false &&
         off.saml2.endpoint === base + '/saml2/unsolicited/' +
           encodeURIComponent(SP2_OFF),
         'g2. a switched-off one is drawn too, with the protocol\'s own ' +
         'endpoint', JSON.stringify(off));
    const portal = new overview.AccountOverview(
      overview.AccountOverview.defaultDeps());
    const view = portal.applicationsView({ username: USER }, 1, base);
    const rowOf = function (id) {
      return (view.rows || []).filter(function (row) {
        return row.identifier === id;
      })[0] || null;
    };
    const offered = rowOf(SP2);
    const notOffered = rowOf(SP2_OFF);
    note(offered && offered.launches.length === 1 &&
         offered.launches[0].url === base + link(SP2, { protocol: 'saml2' }) &&
         notOffered && notOffered.launches.length === 0,
         'g3. the portal offers a Sign in link where the switch is on and ' +
         'none where it is off', JSON.stringify([offered, notOffered]));
    const client = rowOf(RP_CLIENT);
    note(client && client.launches.length === 1 &&
         client.launches[0].protocol === 'oidc' &&
         client.launches[0].url.indexOf('/launch/') > 0,
         'g4. the OpenID Connect link goes through the door, not straight ' +
         'to initiate_login_uri', JSON.stringify(client));

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'launch-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', LA_ROOT: ROOT, LA_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'launch',
  describe: 'IdP-initiated sign-in: /launch/{app} chooses the protocol, ' +
            'obeys the per-application switch (off by default), hands each ' +
            'protocol to its endpoint, records an OpenID Connect launch that ' +
            '/oauth2/authorize honours for a client whose own start is off, ' +
            'and is the link the console and the portal draw',
  run: run
};
