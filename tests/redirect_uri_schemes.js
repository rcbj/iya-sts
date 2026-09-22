'use strict';
//
// File: redirect_uri_schemes.js
//
// ===========================================================================
// WHICH ADDRESSES AN OAUTH REDIRECT MAY BE, IN EVERY MODE (2026-09-13).
//
// Native applications' private-use schemes (RFC 8252 section 7.1, OAuth 2.1
// section 8.4.3) are accepted as a redirect_uri in every mode since this date,
// and accepting them turned a blocklist of five executable schemes into an
// allowlist — because the blocklist, once the `^https?://` test at the call
// site was gone, would have let every protocol handler an operating system
// registers through. So what is asserted here is the RULE, and above all its
// refusals, in the three places it is applied without a request:
//
//   * the allowlist itself (`common/validation.js`), including the two inputs
//     that are plausible typing mistakes rather than attacks — `localhost:3000`
//     with no `http://`, and `https:/cb` with one slash;
//   * the application register's writes (`common/applications.js`) — create,
//     update and both RFC 7591 routes — with a remove of a legacy value still
//     allowed, because an `ldapmodify` may have put one there;
//   * the front-channel logout page's READ of a stored URI, which is the only
//     guard for a value that arrived by `ldapmodify`.
//
// What is asserted over HTTP instead — a private-use redirect answered, form
// post to one refused, the registration endpoint's 400 — is the parent's
// `oauth2_sts_endpoints.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const crypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'redirect_uri_schemes',
  level: process.env.LOG_LEVEL || 'info' });

function withMode(config, value, fn) {
  log.debug("Entering withMode().");
  try {
    config.setOverride('global.mode', value);
    log.debug("Leaving withMode().");
    return fn();
  } finally {
    config.clearOverride('global.mode');
  }
}

// ---------------------------------------------------------------------------
// A. The allowlist.
// Mutants: the period rule removed (myapp:, localhost:3000 accepted); http(s)
// with no host accepted (https:/cb); the blocklist put back (ms-msdt:); the
// fragment rule removed.
// ---------------------------------------------------------------------------
function allowlist(t) {
  log.debug("Entering allowlist().");
  t.log.info('=== A. the redirect allowlist ===');
  const validation = require('../common/validation');
  const ACCEPTED = [
    'https://client.example/cb',
    'http://127.0.0.1:51004/oauth2redirect',
    'http://[::1]:61023/cb',
    'http://localhost:3000/cb',
    'com.example.app:/oauth2redirect/example-provider',
    'com.example.app://callback',
    'net.example-client.app+beta:/cb'
  ];
  const REFUSED = [
    ['localhost:3000/cb', 'typed without http:// — parses as scheme localhost'],
    ['myapp:/cb', 'a private-use scheme with no period'],
    ['javascript:alert(1)', 'an executable scheme'],
    ['data:text/html,<script>', 'an executable scheme'],
    ['ms-msdt:/id', 'a protocol handler on no blocklist'],
    ['intent://x#Intent;end', 'a protocol handler, and a fragment'],
    ['https:/cb', 'https with one slash — the parser invents a host'],
    ['https:///cb', 'https with no host'],
    ['https://client.example/cb#frag', 'a fragment'],
    ['not a uri', 'not an absolute URI'],
    ['', 'empty']
  ];
  ACCEPTED.forEach(function (uri) {
    t.equal(validation.redirectUriProblem(uri), null,
            'accepted as a redirect URI: ' + uri);
  });
  REFUSED.forEach(function (pair) {
    t.check(typeof validation.redirectUriProblem(pair[0]) === 'string',
            'refused as a redirect URI: ' + JSON.stringify(pair[0]) + ' (' +
            pair[1] + ')', validation.redirectUriProblem(pair[0]));
  });
  t.check(validation.redirectUriProblem('com.example.app:/cb',
                                        { privateUse: false }) !== null,
          'the http(s)-only reading refuses a private-use scheme');
  t.check(validation.isPrivateUseRedirect('com.example.app:/cb') &&
          !validation.isPrivateUseRedirect('https://client.example/cb'),
          'isPrivateUseRedirect tells the two shapes apart');
  t.check(validation.frontchannelUriProblem('com.example.app:/logout') !==
            null &&
          validation.frontchannelUriProblem('https://rp.example/fc') === null,
          'a front-channel logout URI is http(s) only — a browser frames it');

  const z = validation.z;
  const SCHEMA = z.object({ u: validation.types.redirectUri });
  const good = SCHEMA.safeParse({ u: 'com.example.app:/cb' });
  const bad = SCHEMA.safeParse({ u: 'myapp:/cb' });
  t.check(good.success, 'the zod type accepts what the function accepts');
  t.check(!bad.success && /period/.test(bad.error.issues[0].message),
          'and refuses with the function\'s own reason, not one sentence for ' +
          'every way to be wrong', bad.success ? '' : bad.error.issues[0]);
  t.check(z.object({ u: validation.types.uri })
             .safeParse({ u: 'openid-credential-offer://x' }).success,
          '`uri` itself is NOT narrowed — a wallet\'s own scheme has no ' +
          'period');
  log.debug("Leaving allowlist().");
}

// ---------------------------------------------------------------------------
// B. The application register's writes.
// Mutants: addressProblem() always null; the update check removed; the remove
// of a legacy value refused; register() writing a refused document.
// ---------------------------------------------------------------------------
function registerWrites(t) {
  log.debug("Entering registerWrites().");
  t.log.info('=== B. what the register refuses to store ===');
  const config = require('../common/config');
  require('../ldap/ldap_server');
  const applications = require('../common/applications');
  const errorCodes = require('../common/error_codes');
  const suffix = crypto.randomBytes(4).toString('hex');

  const problem = applications.registrationUriProblem({
    redirect_uris: ['https://ok.example/cb', 'javascript:alert(1)'] });
  t.check(problem && problem.error === 'invalid_redirect_uri' &&
          problem.errorCode === 'STS-REG-0070',
          'a registration naming javascript: among its redirect_uris is ' +
          'refused as invalid_redirect_uri', problem);
  const frontchannel = applications.registrationUriProblem({
    redirect_uris: ['com.example.app:/cb'],
    frontchannel_logout_uri: 'com.example.app:/fc' });
  t.check(frontchannel && frontchannel.error === 'invalid_client_metadata',
          'a private-use redirect_uri is fine and a private-use ' +
          'frontchannel_logout_uri is not', frontchannel);
  t.equal(applications.registrationUriProblem({
    redirect_uris: ['com.example.app:/cb'],
    post_logout_redirect_uris: ['com.example.app:/bye'] }), null,
          'a native app may register private-use redirect and sign-out ' +
          'addresses');

  const refusedId = 'rus-refused-' + suffix;
  t.equal(applications.register(refusedId,
            { redirect_uris: ['javascript:alert(1)'], client_secret: 's' }),
          null, 'register() refuses the document rather than storing it');
  t.check(!applications.get(refusedId),
          'and nothing was written under that client_id');

  const created = applications.createApplication({
    identifier: 'rus-bad-create-' + suffix, kind: 'oauth2-client',
    fields: { oauthClientId: 'rus-bad-create-' + suffix,
              oauthRedirectUri: ['myapp:/cb'] } });
  t.check(created && !created.ok &&
          errorCodes.codeOf(created) === 'STS-REG-0071',
          'a console create with an unusable redirect URI is refused',
          created);

  const id = 'rus-client-' + suffix;
  withMode(config, 'development', function () {
    applications.createApplication({
      identifier: id, kind: 'oauth2-client',
      fields: { oauthClientId: id,
                oauthRedirectUri: ['https://rus.example/cb'] } });
    // A LEGACY value, written the way only a sighting or an ldapmodify can —
    // not through a door that checks.
    applications.seen({ identifier: id, kind: 'oauth2-client', counts: false,
                        fields: { oauthRedirectUri: 'myapp:/legacy' } });
  });
  const legacyHeld = [].concat(((applications.get(id) || {}).fields || {})
                                 .oauthRedirectUri || []);
  t.check(legacyHeld.indexOf('myapp:/legacy') >= 0,
          'fixture: a legacy unusable address sits on the entry', legacyHeld);

  const addBad = applications.updateApplication(id,
    { attribute: 'oauthRedirectUri', mode: 'add', value: 'ms-msdt:/x' });
  t.check(!addBad.ok && errorCodes.codeOf(addBad) === 'STS-REG-0071',
          'an ADD of an unusable address is refused', addBad);
  const addGood = applications.updateApplication(id,
    { attribute: 'oauthRedirectUri', mode: 'add',
      value: 'com.example.rus:/cb' });
  t.check(addGood.ok,
          'an add of a usable address succeeds although a legacy value is on ' +
          'the entry — only what is being added is checked', addGood);
  const removeLegacy = applications.updateApplication(id,
    { attribute: 'oauthRedirectUri', mode: 'remove', value: 'myapp:/legacy' });
  t.check(removeLegacy.ok,
          'and the legacy value can still be REMOVED — the one door that ' +
          'tidies up is never shut', removeLegacy);
  const frontBad = applications.updateApplication(id,
    { attribute: 'oauthFrontchannelLogoutUri', mode: 'set',
      value: 'com.example.rus:/fc' });
  t.check(!frontBad.ok, 'a private-use front-channel logout URI is refused ' +
                        'at the console door too', frontBad);
  applications.deleteApplication(id);
  log.debug("Leaving registerWrites().");
}

// ---------------------------------------------------------------------------
// C. The front-channel logout page's read of a stored URI.
// Mutant: the read guard removed, so a stored javascript: is drawn and framed.
// ---------------------------------------------------------------------------
function frontchannelRead(t) {
  log.debug("Entering frontchannelRead().");
  t.log.info('=== C. a stored front-channel URI is checked when it is ' +
             'read ===');
  const config = require('../common/config');
  require('../ldap/ldap_server');
  const applications = require('../common/applications');
  const frontchannel = require('../oauth-oidc/frontchannel_logout');
  const suffix = crypto.randomBytes(4).toString('hex');
  const bad = 'rus-fc-bad-' + suffix;
  const good = 'rus-fc-good-' + suffix;
  withMode(config, 'development', function () {
    // A redirect URI on the front-channel URI's origin, which Front-Channel
    // Logout section 2 requires of it (#122).
    [bad, good].forEach(function (id) {
      applications.createApplication({ identifier: id, kind: 'oauth2-client',
        fields: { oauthClientId: id,
                  oauthRedirectUri: 'https://rp.example/cb' } });
    });
    // Planted past every write check, as an ldapmodify would.
    applications.seen({ identifier: bad, kind: 'oauth2-client', counts: false,
                        fields: { oauthFrontchannelLogoutUri:
                                  'javascript:alert(1)' } });
  });
  const offOrigin = applications.updateApplication(good,
    { attribute: 'oauthFrontchannelLogoutUri', mode: 'set',
      value: 'https://elsewhere.example/fc' });
  t.check(!offOrigin.ok &&
          require('../common/error_codes').codeOf(offOrigin) ===
            'STS-REG-0171',
          'a front-channel URI on no redirect URI\'s origin is refused ' +
          '(Front-Channel Logout section 2, #122)', offOrigin);
  const goodSet = applications.updateApplication(good,
    { attribute: 'oauthFrontchannelLogoutUri', mode: 'set',
      value: 'https://rp.example/fc' });
  t.check(goodSet.ok, 'fixture: the usable value is written', goodSet);
  const stored = ((applications.get(bad) || {}).fields || {})
                   .oauthFrontchannelLogoutUri;
  t.check(String(stored || '').indexOf('javascript:') === 0,
          'fixture: the unusable value is on the entry', stored);
  // A SET OF THE VALUE ALREADY THERE is not an addition: it is what a console
  // form posting its whole state back does, and refusing it would make every
  // later save of that entry fail over a value nobody is trying to write.
  const resaved = applications.updateApplication(bad,
    { attribute: 'oauthFrontchannelLogoutUri', mode: 'set',
      value: 'javascript:alert(1)' });
  t.check(resaved.ok,
          'a SET of the value already on the entry is not refused — only a ' +
          'value being added is checked', resaved);
  const session = {};
  frontchannel.noteClient(session, bad);
  frontchannel.noteClient(session, good);
  const rows = frontchannel.notificationsFor(session, 'https://sts.example');
  const badRow = rows.filter(function (row) {
    return row.clientId === bad;
  })[0] || {};
  const goodRow = rows.filter(function (row) {
    return row.clientId === good;
  })[0] || {};
  t.check(badRow.url === '' && /cannot be framed/.test(badRow.why || ''),
          'the stored javascript: is not notified, and the row says why',
          badRow);
  t.equal(goodRow.url, 'https://rp.example/fc',
          'and a usable one beside it is notified as before');
  t.check(frontchannel.contentSecurityPolicyFor(rows)
            .indexOf('javascript') < 0,
          'and the page\'s frame-src names nothing of the refused value');
  applications.deleteApplication(bad);
  applications.deleteApplication(good);
  log.debug("Leaving frontchannelRead().");
}

function run(t) {
  log.debug("Entering run().");
  allowlist(t);
  registerWrites(t);
  frontchannelRead(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'redirect_uri_schemes',
  describe: 'which addresses an OAuth redirect may be, in every mode',
  run: run
};
