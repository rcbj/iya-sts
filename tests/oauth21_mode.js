'use strict';
//
// File: oauth21_mode.js
//
// ===========================================================================
// OAUTH 2.1 MODE (draft-ietf-oauth-v2-1-16), DECIDED IN PROCESS.
//
// `oauth-oidc/oauth21.js` decides and `oauth2.js` answers, so every decision
// the mode makes can be asked here with no port: the two places RFC 9700 mode
// steps aside, the refusals 2.1 adds, the ones it adds to RFC 9700 mode's
// existing checks, and the setting's two properties that are about the
// process rather than a request — that it implies RFC 9700 mode, and that it
// moves `global.https` for the process and not for a realm.
//
// What is asked over HTTP instead is `tests/vendored/sts_oauth21.js`: the
// endpoints answering these decisions, which nothing here can show.
//
// Each section names the mutant it is there to catch.
// ===========================================================================

delete process.env.CONFIG_FILE;

const crypto = require('crypto');
const { EventEmitter } = require('events');

const config = require('../common/config');
const realms = require('../common/realms');

const log = require('bunyan').createLogger({ name: 'oauth21_mode',
  level: process.env.LOG_LEVEL || 'info' });

// THE REALMS ARE CREATED, not merely handed to realms.run(): the realm layer
// reads a realm's overrides out of the REGISTRY, so a record nobody created
// carries none — and a mode test run in a realm that is silently in no mode
// passes every "outside the mode" assertion and fails the rest for the wrong
// reason, which is how this file's first run went.
const LISTED = 'https://listed.example/cb';
const NATIVE = 'com.example.app:/signed-out';
const SUFFIX = crypto.randomBytes(4).toString('hex');
const REALMS = {
  OFF: { id: 'o21-off-' + SUFFIX, overrides: {} },
  BCP: { id: 'o21-bcp-' + SUFFIX, overrides: { 'oauth2.rfc9700': true } },
  V21: { id: 'o21-on-' + SUFFIX, overrides: { 'oauth2.oauth21': true } },
  BCP_LIST: { id: 'o21-bcpl-' + SUFFIX, overrides: {
    'oauth2.rfc9700': true, 'oauth2.redirectUris': [LISTED, NATIVE] } },
  V21_LIST: { id: 'o21-onl-' + SUFFIX, overrides: {
    'oauth2.oauth21': true, 'oauth2.redirectUris': [LISTED] } },
  V21_NOWILD: { id: 'o21-onw-' + SUFFIX, overrides: {
    'oauth2.oauth21': true, 'oauth2.loopbackPortWildcard': false } }
};
const OFF = REALMS.OFF;
const BCP = REALMS.BCP;
const V21 = REALMS.V21;

function createRealms(t) {
  log.debug("Entering createRealms().");
  let all = true;
  Object.keys(REALMS).forEach(function (name) {
    const made = realms.create({ id: REALMS[name].id, name: REALMS[name].id,
                                 description: 'Created by ' + __filename,
                                 overrides: REALMS[name].overrides });
    if (!made.ok) {
      all = false;
      t.bad('could not create the realm ' + REALMS[name].id,
            (made.errors || []).join(' '));
    }
  });
  log.debug("Leaving createRealms().");
  return all;
}

function removeRealms() {
  log.debug("Entering removeRealms().");
  Object.keys(REALMS).forEach(function (name) {
    realms.remove(REALMS[name].id);
  });
  log.debug("Leaving removeRealms().");
}

function inRealm(realm, fn) {
  log.debug("Entering inRealm().");
  log.debug("Leaving inRealm().");
  return realms.run(realms.get(realm.id), fn);
}

function withEnv(name, value, fn) {
  log.debug("Entering withEnv(). " + name);
  const had = Object.prototype.hasOwnProperty.call(process.env, name);
  const was = process.env[name];
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
  try {
    log.debug("Leaving withEnv().");
    return fn();
  } finally {
    if (had) {
      process.env[name] = was;
    } else {
      delete process.env[name];
    }
  }
}

function fakeRequest() {
  log.debug("Entering fakeRequest().");
  const res = new EventEmitter();
  res.statusCode = 200;
  log.debug("Leaving fakeRequest().");
  return { res: res };
}

function hs256(secret, claims) {
  log.debug("Entering hs256().");
  const b64u = function (value) {
    return Buffer.from(JSON.stringify(value)).toString('base64url');
  };
  const head = b64u({ alg: 'HS256', typ: 'JWT' });
  const body = b64u(claims);
  const sig = crypto.createHmac('sha256', secret).update(head + '.' + body)
    .digest('base64url');
  log.debug("Leaving hs256().");
  return head + '.' + body + '.' + sig;
}

// ---------------------------------------------------------------------------
// A. THE SETTING — implies RFC 9700 mode, per realm, and the socket.
// Mutants: enabled() reading only oauth2.rfc9700; global.https reading only
// oauth2.rfc9700; the derivation reading through the realm layer.
// ---------------------------------------------------------------------------
function theSetting(t) {
  log.debug("Entering theSetting().");
  t.log.info('=== A. the setting ===');
  const oauth21 = require('../oauth-oidc/oauth21');
  const bcp = require('../oauth-oidc/oauth2_bcp');
  inRealm(OFF, function () {
    t.check(!oauth21.enabled() && !bcp.enabled(),
            'off by default, and RFC 9700 mode with it');
  });
  const processHttps = config.value('global.https');
  inRealm(V21, function () {
    t.check(oauth21.enabled(), 'a realm may carry oauth2.oauth21');
    t.check(bcp.enabled(),
            'AND IT IMPLIES RFC 9700 MODE: bcp.enabled() is true with ' +
            'oauth2.rfc9700 unset');
    t.equal(bcp.state().enabled_by, 'oauth2.oauth21',
            'and /oauth2/rfc9700 says which flag turned it on');
    t.equal(config.value('global.https'), processHttps,
            'a realm carrying it does not move global.https — the scheme ' +
            'belongs to the socket the PROCESS bound');
  });
  inRealm(BCP, function () {
    t.check(bcp.enabled() && !oauth21.enabled(),
            'RFC 9700 mode alone does not turn OAuth 2.1 mode on');
    t.equal(bcp.state().enabled_by, 'oauth2.rfc9700', 'enabled_by names it');
  });
  withEnv('STS_HTTPS', undefined, function () {
    withEnv('STS_OAUTH2_RFC9700', undefined, function () {
      withEnv('STS_OAUTH2_OAUTH21', 'true', function () {
        t.equal(config.value('global.https'), true,
                'for the PROCESS, oauth2.oauth21 makes global.https default ' +
                'on — the same socket consequence as oauth2.rfc9700');
      });
    });
  });
  log.debug("Leaving theSetting().");
}

// ---------------------------------------------------------------------------
// B. PKCE at the authorization endpoint.
// Mutants: the nonce exemption not requiring a credential on file; not
// requiring openid; not requiring a nonce; a missing method read as plain;
// the RFC 9700 log-only branch left in force in 2.1 mode.
// ---------------------------------------------------------------------------
function pkce(t) {
  log.debug("Entering pkce().");
  t.log.info('=== B. PKCE ===');
  const bcp = require('../oauth-oidc/oauth2_bcp');
  const withSecret = { known: true, token_endpoint_auth_method:
                       'client_secret_basic', client_secret: 's' };
  const nothingOnFile = { known: true, token_endpoint_auth_method:
                          'client_secret_basic', client_secret: '' };
  const ask = function (client, query) {
    return bcp.checkAuthorizationRequest({ query: query, types: ['code'],
                                           client: client });
  };
  inRealm(BCP, function () {
    t.check(ask(withSecret, { scope: 'openid' }).ok,
            'RFC 9700 mode answers a confidential client with no PKCE (a ' +
            'SHOULD, logged)');
  });
  inRealm(V21, function () {
    const refused = ask(withSecret, { scope: 'openid' });
    t.check(!refused.ok && refused.errorCode === 'STS-OAUTH-0275',
            'OAuth 2.1 refuses a confidential client with no PKCE and no ' +
            'nonce', refused);
    const exempt = ask(withSecret, { scope: 'openid profile', nonce: 'n' });
    t.check(exempt.ok,
            'the OpenID Connect nonce exemption: confidential, credential on ' +
            'file, openid and a nonce', exempt);
    const noCredential = ask(nothingOnFile, { scope: 'openid', nonce: 'n' });
    t.check(!noCredential.ok && noCredential.errorCode === 'STS-OAUTH-0275',
            'but a confidential METHOD with nothing on file is no assurance',
            noCredential);
    const notOidc = ask(withSecret, { scope: 'profile', nonce: 'n' });
    t.check(!notOidc.ok, 'and a request that is not OpenID Connect is not ' +
                         'exempt', notOidc);
    const noMethod = ask(withSecret, {
      code_challenge: crypto.randomBytes(32).toString('base64url') });
    t.check(!noMethod.ok && noMethod.errorCode === 'STS-OAUTH-0276',
            'a challenge with no method is refused AS MISSING THE METHOD',
            noMethod);
    t.check(ask({ known: false }, {
      code_challenge: crypto.randomBytes(32).toString('base64url'),
      code_challenge_method: 'S256' }).ok,
            'and a public client with S256 PKCE is answered');
  });
  log.debug("Leaving pkce().");
}

// ---------------------------------------------------------------------------
// C. THE TOKEN REQUEST — the row that makes this a mode of its own.
// Mutants: 0147 still enforced in 2.1 mode; the exempt code no longer needing
// redirect_uri; tokenCodeRefusal accepting an exempt code unauthenticated.
// ---------------------------------------------------------------------------
function tokenRequest(t) {
  log.debug("Entering tokenRequest().");
  t.log.info('=== C. the token request ===');
  const bcp = require('../oauth-oidc/oauth2_bcp');
  const oauth21 = require('../oauth-oidc/oauth21');
  const pkceCode = { client_id: 'c', redirect_uri: 'https://c.example/cb',
                     code_challenge: 'x', pkce_exempt: '' };
  const exemptCode = { client_id: 'c', redirect_uri: 'https://c.example/cb',
                       pkce_exempt: 'oidc-nonce' };
  const noRedirect = { client_id: 'c' };
  inRealm(BCP, function () {
    const refused = bcp.checkTokenRequest({ record: pkceCode, body: noRedirect,
                                            client: { client_id: 'c' } });
    t.check(!refused.ok && refused.errorCode === 'STS-OAUTH-0147',
            'RFC 9700 mode requires redirect_uri at the token endpoint',
            refused);
  });
  inRealm(V21, function () {
    t.check(bcp.checkTokenRequest({ record: pkceCode, body: noRedirect,
                                    client: { client_id: 'c' } }).ok,
            'OAUTH 2.1 ACCEPTS A TOKEN REQUEST WITH NO redirect_uri (section ' +
            '10.2) when PKCE binds the code');
    const exempt = bcp.checkTokenRequest({ record: exemptCode,
      body: noRedirect, client: { client_id: 'c' } });
    t.check(!exempt.ok && exempt.errorCode === 'STS-OAUTH-0147',
            'but still requires it of a code minted under the nonce ' +
            'exemption, which has no PKCE', exempt);
    const noChallenge = oauth21.tokenCodeRefusal({
      record: { client_id: 'c' }, authenticated: true });
    t.check(noChallenge && noChallenge.errorCode === 'STS-OAUTH-0277',
            'a code with no challenge and no exemption is refused',
            noChallenge);
    const unauth = oauth21.tokenCodeRefusal({ record: exemptCode,
                                              authenticated: false });
    t.check(unauth && unauth.errorCode === 'STS-OAUTH-0277',
            'an exempt code redeemed without client authentication is refused',
            unauth);
    t.equal(oauth21.tokenCodeRefusal({ record: exemptCode,
                                       authenticated: true }), null,
            'and an exempt code redeemed by the authenticated client is not');
    t.equal(oauth21.codeRecordFields({ scope: 'openid', nonce: 'n' },
                                     ['code']).pkce_exempt, 'oidc-nonce',
            'a code minted with no challenge in this mode is marked exempt');
    t.equal(oauth21.codeTtlMs(3600000), 600000,
            'and a code lives at most ten minutes');
  });
  inRealm(OFF, function () {
    t.equal(oauth21.codeTtlMs(3600000), 3600000,
            'outside the mode the configured lifetime stands');
    t.equal(oauth21.tokenCodeRefusal({ record: { client_id: 'c' },
                                       authenticated: false }), null,
            'and nothing about PKCE is refused at the token endpoint');
  });
  log.debug("Leaving tokenRequest().");
}

// ---------------------------------------------------------------------------
// D. THE CLIENT at the token endpoint, and the `declared` predicate.
// Mutants: declared true for a sighted entry; the pre-authorized code grant not
// exempt; a presented-but-unverified credential accepted; client_credentials
// from a public client accepted; saml2_bearer accepted; two methods accepted.
// ---------------------------------------------------------------------------
function tokenClient(t) {
  log.debug("Entering tokenClient().");
  t.log.info('=== D. the client at the token endpoint ===');
  const oauth21 = require('../oauth-oidc/oauth21');
  require('../ldap/ldap_server');
  const applications = require('../common/applications');
  const suffix = crypto.randomBytes(4).toString('hex');
  const sighted = 'o21-sighted-' + suffix;
  const declaredId = 'o21-declared-' + suffix;
  applications.seen({ identifier: sighted, kind: 'oauth2-client',
                      protocol: 'OAuth 2.0 / OIDC', counts: false,
                      fields: { oauthClientId: sighted, oauthScope: ['openid'],
                                oauthGrantType: 'authorization_code',
                                appRedirectUriObserved:
                                    'https://sighted.example/cb' } });
  const sightedConfig = applications.clientConfigOf(sighted);
  t.check(sightedConfig.known && sightedConfig.declared === false,
          'an entry written only by a SIGHTING declares nothing',
          sightedConfig);
  const created = applications.createApplication({
    identifier: declaredId, kind: 'oauth2-client',
    fields: { oauthClientId: declaredId,
              oauthRedirectUri: ['https://declared.example/cb'] } });
  t.check(created && created.ok, 'a fixture client with a redirect URI',
          JSON.stringify(created && created.errors));
  t.check(applications.clientConfigOf(declaredId).declared === true,
          'and one given a redirect URI of its own declares something');
  t.check(applications.clientConfigOf('o21-never-' + suffix).declared === false,
          'a client_id never seen declares nothing');

  inRealm(V21, function () {
    const refused = oauth21.tokenClientDeclarationRefusal({
      grant: 'authorization_code', clientId: sighted,
      registered: sightedConfig, presented: {} });
    t.check(refused && refused.errorCode === 'STS-OAUTH-0278' &&
            refused.error === 'invalid_client',
            'a token request naming the sighted client is refused', refused);
    t.equal(oauth21.tokenClientDeclarationRefusal({
      grant: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      clientId: sighted, registered: sightedConfig, presented: {} }), null,
            'the OpenID4VCI pre-authorized code grant is exempt');
    t.equal(oauth21.tokenClientDeclarationRefusal({
      grant: 'authorization_code', clientId: declaredId,
      registered: { known: true, declared: true }, presented: {} }), null,
            'a declared client is not refused');
    const saml = oauth21.tokenClientDeclarationRefusal({
      grant: 'client_credentials', clientId: declaredId,
      registered: { known: true, declared: true,
                    token_endpoint_auth_method: 'saml2_bearer' },
      presented: {} });
    t.check(saml && saml.errorCode === 'STS-OAUTH-0282',
            'SAML bearer client authentication is refused', saml);

    const presentedUnverified = oauth21.tokenClientAuthenticationRefusal({
      grant: 'authorization_code', presented: { bodySecret: true },
      observation: { authenticated: false, why: 'it is a public client.' } });
    t.check(presentedUnverified &&
            presentedUnverified.errorCode === 'STS-OAUTH-0280',
            'a credential that was presented and did not verify is refused',
            presentedUnverified);
    const cc = oauth21.tokenClientAuthenticationRefusal({
      grant: 'client_credentials', presented: {},
      observation: { authenticated: false } });
    t.check(cc && cc.errorCode === 'STS-OAUTH-0279',
            'client_credentials from an unauthenticated client is refused', cc);
    t.equal(oauth21.tokenClientAuthenticationRefusal({
      grant: 'authorization_code', presented: {},
      observation: { authenticated: false } }), null,
            'a public client presenting nothing for a code is not refused');
    const two = oauth21.multipleMethodsRefusal({ basic: true,
                                                bodySecret: true });
    t.check(two && two.errorCode === 'STS-OAUTH-0281',
            'two client authentication methods are refused', two);
    t.equal(oauth21.multipleMethodsRefusal({ assertion: true }), null,
            'one is not');
  });
  inRealm(OFF, function () {
    t.equal(oauth21.tokenClientDeclarationRefusal({
      grant: 'authorization_code', clientId: sighted,
      registered: sightedConfig, presented: {} }), null,
            'outside the mode a sighted client is untouched');
  });
  applications.deleteApplication(sighted);
  applications.deleteApplication(declaredId);
  log.debug("Leaving tokenClient().");
}

// ---------------------------------------------------------------------------
// E. REDIRECT URIs — registered-client-required, the default, the loopback.
// Mutants: the oauth2.redirectUris fallback left in force in 2.1 mode; the
// unconfirmed case reported as none at all; the default chosen with several
// registered; the loopback wildcard setting honoured in 2.1 mode.
// ---------------------------------------------------------------------------
function redirects(t) {
  log.debug("Entering redirects().");
  t.log.info('=== E. redirect URIs ===');
  const bcp = require('../oauth-oidc/oauth2_bcp');
  const oauth21 = require('../oauth-oidc/oauth21');
  inRealm(REALMS.BCP_LIST, function () {
    t.check(bcp.checkRedirectUri({ redirectUri: LISTED,
                                   client: { known: false, redirect_uris: [] },
                                   clientId: 'x' }).ok,
            'RFC 9700 mode falls back to oauth2.redirectUris');
  });
  inRealm(REALMS.V21_LIST, function () {
    const refused = bcp.checkRedirectUri({ redirectUri: LISTED,
      client: { known: false, redirect_uris: [] }, clientId: 'x' });
    t.check(!refused.ok && refused.errorCode === 'STS-OAUTH-0271',
            'OAUTH 2.1 DOES NOT: a client with no redirect URI of its own is ' +
            'refused even when the URI is on the service-wide list', refused);
    const withheld = bcp.checkRedirectUri({ redirectUri: LISTED,
      client: { known: true, redirect_uris: [],
                unconfirmed_redirect_uris: [LISTED] }, clientId: 'x' });
    t.check(!withheld.ok && withheld.errorCode === 'STS-OAUTH-0272' &&
            withheld.description.indexOf(LISTED) >= 0,
            'and one holding only unconfirmed addresses is told so, by name',
            withheld);
  });
  inRealm(V21, function () {
    const one = oauth21.defaultRedirectUri({ redirect_uris: [LISTED] }, 'x');
    t.check(one.ok && one.uri === LISTED,
            'the default is the one registered URI', one);
    const several = oauth21.defaultRedirectUri({ redirect_uris: [LISTED,
      'https://other.example/cb'] }, 'x');
    t.check(!several.ok && several.errorCode === 'STS-OAUTH-0273',
            'with several registered the request must name one', several);
  });
  inRealm(REALMS.V21_NOWILD, function () {
    t.check(bcp.checkRedirectUri({
      redirectUri: 'http://127.0.0.1:5555/cb',
      client: { known: true, redirect_uris: ['http://127.0.0.1:1234/cb'] },
      clientId: 'x' }).ok,
            'a loopback redirect may use any port in OAuth 2.1 mode, ' +
            'whatever ' +
            'oauth2.loopbackPortWildcard says');
  });
  log.debug("Leaving redirects().");
}

// ---------------------------------------------------------------------------
// F. SIGN-OUT RETURN ADDRESSES.
// Mutants: a private-use address believed off the service-wide list; the 2.1
// mode fallback left in force.
// ---------------------------------------------------------------------------
function postLogout(t) {
  log.debug("Entering postLogout().");
  t.log.info('=== F. post-logout redirect URIs ===');
  const bcp = require('../oauth-oidc/oauth2_bcp');
  inRealm(REALMS.BCP_LIST, function () {
    const refused = bcp.checkPostLogoutRedirectUri({ target: NATIVE,
      client: { known: false, post_logout_redirect_uris: [] } });
    t.check(!refused.ok && refused.errorCode === 'STS-OAUTH-0290',
            'a private-use sign-out address is not believed off the ' +
            'service-wide list', refused);
    t.check(bcp.checkPostLogoutRedirectUri({ target: NATIVE,
      client: { known: true, post_logout_redirect_uris: [NATIVE] } }).ok,
            'but is when the client registered it');
    t.check(bcp.checkPostLogoutRedirectUri({ target: LISTED,
      client: { known: false, post_logout_redirect_uris: [] } }).ok,
            'and an unregistered https address still is in development ' +
            '(#118\'s rule, #124); oauth2.redirectUris is not read');
  });
  inRealm(REALMS.V21_LIST, function () {
    const refused = bcp.checkPostLogoutRedirectUri({ target: LISTED,
      client: { known: false, post_logout_redirect_uris: [] } });
    t.check(!refused.ok && refused.errorCode === 'STS-OAUTH-0286',
            'in OAuth 2.1 mode no address is believed off the list', refused);
  });
  log.debug("Leaving postLogout().");
}

// ---------------------------------------------------------------------------
// G. WHAT EVERY ENDPOINT SHARES — repetition, the description, registration,
// metadata.
// Mutants: resource refused as repeated; the sanitiser active outside the mode;
// saml2_bearer still advertised; the registration mirrors missing.
// ---------------------------------------------------------------------------
function shared(t) {
  log.debug("Entering shared().");
  t.log.info('=== G. repetition, descriptions, registration, metadata ===');
  const bcp = require('../oauth-oidc/oauth2_bcp');
  const oauth21 = require('../oauth-oidc/oauth21');
  t.equal(JSON.stringify(oauth21.repeatedNames(
            { scope: ['a', 'b'], state: 's' }, null)), '["scope"]',
          'a repeated query parameter is found');
  t.equal(JSON.stringify(oauth21.repeatedNames(null,
            'grant_type=x&resource=a&resource=b&code=1&code=2')),
          '["resource","code"]', 'and a repeated form parameter');
  inRealm(V21, function () {
    const refused = oauth21.repeatedParameterRefusal(['resource', 'code'],
                                                     'token request');
    t.check(refused && refused.errorCode === 'STS-OAUTH-0285' &&
            refused.description.indexOf('resource') < 0,
            'code is refused as repeated and resource is not', refused);
    const clean = oauth21.sanitizeDescription('a "quoted" \\ — naïve');
    t.check(/^[\x20\x21\x23-\x5B\x5D-\x7E]*$/.test(clean),
            'an error_description leaves only the grammar\'s characters',
            clean);
    const saml = bcp.checkClientRegistration({
      token_endpoint_auth_method: 'saml2_bearer' });
    t.check(!saml.ok && saml.errorCode === 'STS-OAUTH-0287',
            'registration refuses saml2_bearer', saml);
    const publicCc = bcp.checkClientRegistration({
      token_endpoint_auth_method: 'none',
      grant_types: ['client_credentials'] });
    t.check(!publicCc.ok && publicCc.errorCode === 'STS-OAUTH-0289',
            'and a public client registering for client_credentials', publicCc);
    const metadata = bcp.applyToMetadata({
      token_endpoint_auth_methods_supported: ['client_secret_basic',
                                              'saml2_bearer'] });
    t.equal(metadata.token_endpoint_auth_methods_supported.indexOf(
              'saml2_bearer'), -1, 'and the metadata stops advertising it');
    t.check(oauth21.state().enabled === true &&
            oauth21.state().draft === 'draft-ietf-oauth-v2-1-16',
            'the report names the draft it follows');
  });
  inRealm(OFF, function () {
    t.equal(oauth21.sanitizeDescription('a "q" \u2014 b'), 'a \'q\' - b',
            'outside the mode too: the set is RFC 6749\'s (#176)');
  });
  log.debug("Leaving shared().");
}

// ---------------------------------------------------------------------------
// H. THE CLIENT ASSERTION'S AUDIENCE, through client_auth.js itself.
// Mutants: the sole-audience check removed; an array containing the issuer
// accepted; the strict flag left out of verifiedOnce()'s key.
// ---------------------------------------------------------------------------
async function audience(t) {
  log.debug("Entering audience().");
  t.log.info('=== H. the client assertion audience ===');
  const clientAuth = require('../oauth-oidc/client_auth');
  const ISSUER = 'https://o21.example';
  const TOKEN = ISSUER + '/oauth2/token';
  const SECRET = 'o21-client-assertion-secret-0123456789';
  const now = Math.floor(Date.now() / 1000);
  const assertionFor = function (aud) {
    return hs256(SECRET, { iss: 'o21-client', sub: 'o21-client', aud: aud,
      iat: now, exp: now + 60,
      jti: 'o21-' + crypto.randomBytes(8).toString('hex') });
  };
  const ask = function (assertion, strict, request) {
    return clientAuth.verify({
      method: 'client_secret_jwt', clientId: 'o21-client',
      clientSecret: SECRET, assertionType: clientAuth.ASSERTION_TYPE,
      audiences: [TOKEN, ISSUER], strictAudience: strict ? ISSUER : '',
      assertion: assertion, request: request || fakeRequest()
    });
  };
  await inRealm(V21, async function () {
    t.check((await ask(assertionFor(ISSUER), true)).ok,
            'the issuer as the sole audience is accepted');
    const endpoint = await ask(assertionFor(TOKEN), true);
    t.check(!endpoint.ok && endpoint.errorCode === 'STS-OAUTH-0283',
            'THE TOKEN ENDPOINT URL IS REFUSED, BY NAME, for its audience',
            endpoint);
    const both = await ask(assertionFor([ISSUER, 'https://other.example']),
                           true);
    t.check(!both.ok && both.errorCode === 'STS-OAUTH-0283',
            'and an array naming the issuer beside something else', both);
    t.check((await ask(assertionFor(TOKEN), false)).ok,
            'outside the rule the token endpoint URL is accepted');
    const req = fakeRequest();
    const shared = assertionFor(TOKEN);
    const lenient = await ask(shared, false, req);
    const strict = await ask(shared, true, req);
    t.check(lenient.ok && !strict.ok,
            'ONE REQUEST ASKED WITH TWO POLICIES GETS TWO ANSWERS: the ' +
            'strictness is in verifiedOnce()\'s key, so the first answer ' +
            'cannot silently decide the second', [lenient, strict]);
  });
  log.debug("Leaving audience().");
}

async function run(t) {
  log.debug("Entering run().");
  if (!createRealms(t)) {
    removeRealms();
    log.debug("Leaving run(). The realms could not be created.");
    return;
  }
  try {
    theSetting(t);
    pkce(t);
    tokenRequest(t);
    tokenClient(t);
    redirects(t);
    postLogout(t);
    shared(t);
    await audience(t);
  } finally {
    removeRealms();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oauth21_mode',
  describe: 'OAuth 2.1 mode: every decision oauth21.js makes, in process',
  run: run
};
