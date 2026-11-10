// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/asvs_protocol_rules.js
//
// Product mode's stricter reading of what callers send, and what it withholds
// from them. Each check asks the rule itself; the settings are put back.

const path = require('path');

delete process.env.CONFIG_FILE;

const ROOT = path.join(__dirname, '..');

async function run(t) {
  const config = require(ROOT + '/common/config');
  const mode = require(ROOT + '/common/mode');
  const oauth21 = require(ROOT + '/oauth-oidc/oauth21');
  const address = require(ROOT + '/common/client_address');
  const inProduct = function (fn) {
    config.setOverride('global.mode', 'product');
    try {
      return fn();
    } finally {
      config.clearOverride('global.mode');
    }
  };
  t.equal(oauth21.repeatedParameterRefusal(['grant_type'], 'token request'),
          null, 'the refusal is off without OAuth 2.1 mode');
  const repeated = oauth21.repeatedParameterRefusal(['grant_type'],
                                                    'token request', true);
  t.equal(repeated && repeated.error, 'invalid_request',
          'a repeated parameter is refused when asked to be');
  t.equal(mode.refusesRepeatedTokenParameters(), false,
          'development does not ask');
  t.equal(inProduct(function () {
    return mode.refusesRepeatedTokenParameters();
  }), true, 'product does');
  t.equal(inProduct(function () {
    return config.value('oauth2.refreshTokenMaxChainS');
  }), 2592000, 'product caps a refresh chain at 30 days');
  t.equal(config.value('oauth2.refreshTokenMaxChainS'), 0,
          'development has no cap');
  t.equal(inProduct(function () {
    return config.value('totp.window');
  }), 0, 'product accepts one TOTP step');
  t.equal(config.value('totp.window'), 1, 'development forgives one either side');
  t.equal(inProduct(function () {
    return mode.requiresTypedLogoutToken();
  }), true, 'product needs a typed Logout Token');
  config.setOverride('federation.allowUntypedLogoutToken', 'true');
  t.equal(inProduct(function () {
    return mode.requiresTypedLogoutToken();
  }), false, 'unless the setting allows it');
  config.clearOverride('federation.allowUntypedLogoutToken');
  t.equal(inProduct(function () {
    return mode.hidesFailureDetail();
  }), true, 'product hides an internal error\'s text');
  const http = require(ROOT + '/federation/federation_http');
  const vet = async function (host) {
    config.setOverride('global.mode', 'product');
    try {
      return await http.vetHost(host);
    } finally {
      config.clearOverride('global.mode');
    }
  };
  config.setOverride('security.outboundAllowedHosts',
                     'idp.example.test,.partner.example');
  t.equal((await vet('elsewhere.example')).ok, false,
          'a host off the list is refused');
  t.equal(/outboundAllowedHosts/.test((await vet('elsewhere.example')).why),
          true, 'and the refusal names the setting');
  t.equal(/outboundAllowedHosts/.test(
    (await vet('a.partner.example')).why || ''), false,
          'a host under a listed domain passes the list');
  // #1577: the list holds in development too, as revocation_status.js's
  // hostAllowed() always did; development still dials an internal address.
  const devOff = await http.vetHost('elsewhere.example');
  t.equal(devOff.ok, false, 'development refuses a host off the list too');
  t.equal(/outboundAllowedHosts/.test(devOff.why || ''), true,
          'naming the setting');
  t.equal((await http.vetHost('a.partner.example')).ok, true,
          'and passes a listed one');
  config.setOverride('security.outboundAllowedHosts', '127.0.0.1');
  const devInternal = await http.vetHost('127.0.0.1');
  t.equal(devInternal.ok && devInternal.address === '', true,
          'development still dials a listed internal address, unpinned');
  t.equal((await vet('127.0.0.1')).ok, false,
          'which product still refuses, listed or not');
  config.clearOverride('security.outboundAllowedHosts');
  t.equal((await http.vetHost('elsewhere.example')).ok, true,
          'and with no list development dials any host, as before');
  t.equal(inProduct(function () {
    return mode.refusesPlainSyslog();
  }), true, 'product refuses plain syslog');
  // A client writes the left-most hop.
  const forwarded = { headers: { 'x-forwarded-for': '192.0.2.1' },
                      socket: { remoteAddress: '203.0.113.9' } };
  config.setOverride('global.trustProxy', 'true');
  t.equal(address.clientAddressOf(forwarded), '192.0.2.1',
          'development believes the header with no list');
  t.equal(inProduct(function () {
    return address.clientAddressOf(forwarded);
  }), '203.0.113.9', 'product uses the socket with no list');
  config.clearOverride('global.trustProxy');
  const helpers = require(ROOT + '/common/helpers');
  t.equal(inProduct(function () {
    return helpers.signingAlgListed('ES256K');
  }), false, 'product does not sign with ES256K unless it is listed');
  t.equal(inProduct(function () {
    return helpers.signingAlgListed('ES256');
  }), true, 'and does sign with an approved curve');
  t.equal(inProduct(function () {
    return config.value('security.hstsIncludeSubDomains');
  }), true, 'product applies HSTS to subdomains');
  // The browser applications' checks.
  const SpaClient = require(ROOT + '/common/web_spa_client');
  const spa = SpaClient.SpaClient || SpaClient;
  const jwt = function (claims) {
    return 'e30.' + Buffer.from(JSON.stringify(claims)).toString('base64') +
      '.s';
  };
  const client = {
    clientId: 'sts-user-portal', metadata: { issuer: 'https://idp.test' },
    nonceFor: async function () {
      return 'n';
    },
    asMetadata: async function () {
      return { issuer: 'https://idp.test' };
    }
  };
  const good = { nonce: 'n', aud: 'sts-user-portal', iss: 'https://idp.test' };
  const check = function (claims) {
    return spa.prototype.nonceMatches.call(client, jwt(claims), 'v');
  };
  t.equal(await check(good), true, 'a browser application accepts its own token');
  t.equal(await check(Object.assign({}, good, { aud: 'another' })), false,
          'and refuses one for another client');
  t.equal(await check(Object.assign({}, good, { iss: 'https://evil.test' })),
          false, 'or from another server');
  t.equal(await spa.prototype.issuerMatches.call(client,
    { iss: 'https://evil.test' }), false,
          'an authorization response naming another server is refused');
  t.equal(await spa.prototype.issuerMatches.call(client, {}), true,
          'and one naming none is allowed');
  // ASVS 5.0.0 3.7.2: a browser reads `/\\host` as another host.
  const fedSp = require(ROOT + '/federation/federation_sp');
  const returnToOf = function (value) {
    return fedSp.FederationSp.prototype.returnToOf.call(
      { deps: { log: require('bunyan').createLogger({ name: 'test', level: 60 }) } },
      value);
  };
  t.equal(returnToOf('/portal/ok'), '/portal/ok', 'a path on this service is kept');
  t.equal(returnToOf('/\\evil.example'), '', 'a backslash path is refused');
  t.equal(returnToOf('//evil.example'), '', 'and so is a protocol-relative one');
  // #1538: an administrator's credential changes need a recent sign-in.
  const adminApi = require(ROOT + '/mgmt-api/admin_api');
  const owed = function (caller, action) {
    return adminApi.AdminApi.prototype.reauthenticationOwed.call(
      { deps: { log: require('bunyan').createLogger({ name: 't', level: 60 }) } },
      { locals: { apiCaller: caller } }, action);
  };
  const nowS = Math.floor(Date.now() / 1000);
  const stale = { kind: 'person', authTime: nowS - 7200 };
  t.equal(owed(stale, 'clear-totp'), false, 'development does not ask');
  config.setOverride('account.recentAuthMinutes', '15');
  t.equal(owed(stale, 'clear-totp'), true, 'a stale sign-in is asked');
  t.equal(owed(stale, 'list'), false, 'but not for anything else');
  // #1577: the two acts that clear every factor at once ask it too.
  t.equal(owed(stale, 'disable-mfa'), true,
          'disabling every second factor asks it');
  t.equal(owed(stale, 'disable-primary-keys'), true,
          'and so does disabling every passkey');
  t.equal(owed({ kind: 'person', authTime: nowS - 60 }, 'disable-mfa'), false,
          'which a recent sign-in passes');
  t.equal(owed({ kind: 'person', authTime: nowS - 60 }, 'set-mail'), false,
          'a recent sign-in is not asked');
  t.equal(owed({ kind: 'application' }, 'clear-totp'), false,
          'and a program, with nobody to ask, is not');
  config.clearOverride('account.recentAuthMinutes');
  t.equal(inProduct(function () {
    return config.value('security.passwordHashP');
  }), 3, 'product stores scrypt at p=3');
  t.equal(inProduct(function () {
    return mode.refusesAssertionWithoutAudience();
  }), true, 'product needs an assertion to name its audience');
  const scheduler = require(ROOT + '/cluster/scheduler');
  const Sched = scheduler.Scheduler || scheduler;
  Sched.noteClockSkew(Date.now() + 60000);
  t.equal(Sched.clockFar, true, 'a clock a minute off the database is noted');
  Sched.noteClockSkew(Date.now());
  t.equal(Sched.clockFar, false, 'and its return');
  // The audit checksum: a row altered after it was written is found.
  const auditLog = require(ROOT + '/common/audit');
  const keystore = require(ROOT + '/common/keystore');
  const realKeyed = keystore.keyedDigest;
  keystore.keyedDigest = function (label, text) {
    return require('crypto').createHmac('sha256', 'k').update(label + text)
      .digest('hex');
  };
  auditLog.audit({ category: 'admin', action: 'admin.test', summary: 'mac' });
  const held = auditLog.list()[0];
  t.check(!!held.mac, 'an audit row carries a checksum');
  t.equal(auditLog.verifyIntegrity().altered.length, 0, 'and it verifies');
  const honest = held.summary;
  held.summary = 'rewritten';
  t.equal(auditLog.verifyIntegrity().altered.indexOf(held.seq) >= 0, true,
          'a row rewritten afterwards is reported');
  held.summary = honest;
  // The chain (16.4.2): a row taken from the middle, or the newest ones, is
  // found, and the oldest leaving at the cap is not a finding.
  ['one', 'two', 'three'].forEach(function (n) {
    auditLog.audit({ category: 'admin', action: 'admin.test', summary: n });
  });
  // Only this check's own four rows: others in the ring were written by
  // earlier jobs, some under the real key.
  const rows = auditLog.list().slice(0, 4);
  const whole = auditLog.verifyIntegrity(rows);
  t.equal(whole.missing.length + whole.altered.length, 0,
          'a whole chain verifies');
  t.equal(whole.head, 'intact', 'and its newest row is there');
  t.equal(rows[0].prev, rows[1].mac,
          'each row names the checksum of the one before it');
  const gap = auditLog.verifyIntegrity(rows.slice(0, 1).concat(rows.slice(2)));
  t.equal(gap.missing.length === 1 && gap.missing[0].before === rows[0].seq &&
          gap.missing[0].after === rows[2].seq, true,
          'a row deleted from the middle is reported between its neighbours');
  t.equal(auditLog.verifyIntegrity(rows.slice(1)).head, 'truncated',
          'deleting the newest row is reported');
  const oldestGone = auditLog.verifyIntegrity(rows.slice(0, rows.length - 1));
  t.equal(oldestGone.missing.length === 0 && oldestGone.head === 'intact',
          true, 'and the oldest leaving, as the cap does, is not');
  keystore.keyedDigest = realKeyed;
  // A realm id defined again is purged first (2.3.3): a store that refused
  // to purge when the realm was removed must not hand its rows to the new one.
  const realmsMod = require(ROOT + '/common/realms');
  let refuse = true;
  const purgedFor = [];
  realmsMod.onRemove(function (id) {
    if (id !== 'asvs-reused') {
      return;
    }
    purgedFor.push(refuse ? 'refused' : 'purged');
    if (refuse) {
      refuse = false;
      throw new Error('refused for the test');
    }
  });
  realmsMod.create({ id: 'asvs-reused' });
  realmsMod.remove('asvs-reused');
  realmsMod.create({ id: 'asvs-reused' });
  t.equal(purgedFor.join(','), 'refused,purged',
          'a realm id defined again after a refused purge is purged again ' +
          'before it is defined');
  realmsMod.remove('asvs-reused');
  // A partner's sign-in time counts (#1554).
  const authn = require(ROOT + '/authn/authn');
  const fedProto = fedSp.FederationSp.prototype;
  const quiet = require('bunyan').createLogger({ name: 'q', level: 60 });
  const asked = Math.floor(Date.now() / 1000);
  const ignored = function (askedAt, partnerAt) {
    return fedProto.partnerIgnoredFreshSignIn.call({ deps: { log: quiet } },
      { locals: { fedReauthAskedAt: askedAt, fedPartnerAuthAt: partnerAt } });
  };
  t.equal(ignored(asked, asked - 3600), true,
          'a partner answering a fresh sign-in with an old one is refused');
  t.equal(ignored(asked, asked + 2), false, 'a fresh answer is not');
  t.equal(ignored(asked, 0), false, 'nor one that gives no time');
  t.equal(ignored(0, asked - 3600), false,
          'and an old time is fine when nothing fresh was asked');
  const repeats = require(ROOT + '/common/protocol_repeats');
  t.equal(repeats.repeatedIn({ a: ['1', '2'] }, null), 'a',
          'a parameter repeated in the query is found');
  t.equal(repeats.repeatedIn({ a: '1' }, { a: '2' }), 'a',
          'and one given in both places');
  t.equal(repeats.repeatedIn({ a: '1' }, { b: '2' }), '', 'and others pass');
  const passwordPolicy = require(ROOT + '/common/password_policy');
  const scryptP = function () {
    return passwordPolicy.hashSpec({ hashAlgorithm: 'scrypt', scryptLogN: 15,
      scryptBlockSize: 8, scryptParallelism: 1 }).p;
  };
  t.equal(scryptP(), 1, 'development hashes at the profile\'s p');
  t.equal(inProduct(scryptP), 3, 'product hashes at p=3 at the least');
  const budget = require(ROOT + '/common/request_budget');
  const at = Date.now();
  t.equal(budget.allowed('198.51.100.7', 2, at), true, 'a first request passes');
  t.equal(budget.allowed('198.51.100.7', 2, at), true, 'and a second');
  t.equal(budget.allowed('198.51.100.7', 2, at), false, 'a third is over');
  t.equal(budget.allowed('198.51.100.8', 2, at), true,
          'another address has its own count');
  t.equal(budget.allowed('198.51.100.7', 2, at + 61000), true,
          'and the next minute starts again');
  t.equal(inProduct(function () {
    return config.value('security.requestsPerAddressPerMinute');
  }), 6000, 'product has a ceiling');
  t.equal(inProduct(function () {
    return config.value('oauth2.consentAlwaysForPublicClients');
  }), true, 'product always asks consent for a public client');
  // Only this service's own clients are exempt, by exact name (10.7.1): a
  // registered client's `sts-client-` id is a third party like any other.
  const ConsentClass = require(ROOT + '/common/consent').Consent;
  const asks = function (clientId) {
    return inProduct(function () {
      return ConsentClass.prototype.alwaysAsks.call({ deps: {
        log: { debug: function () {} },
        applications: { HOSTED_SURFACE_CLIENT_IDS: ['sts-user-portal'],
                        clientConfigOf: function () {
                          return { token_endpoint_auth_method: 'none' };
                        } } } }, clientId);
    });
  };
  // 16.2.5: a token logged at debug in product is its size and digest.
  const helpersMod = require(ROOT + '/common/helpers');
  const seen = [];
  // THROUGH THE SETTING, not log.level(): config.js re-applies
  // global.logLevel to the shared logger whenever a setting changes, and
  // switching to product mode is one.
  helpersMod.log.addStream({ type: 'raw', level: 'debug',
                             stream: { write: function (rec) {
                               if (rec && rec.artifact === 'JWT') {
                                 seen.push(rec);
                               }
                             } } });
  config.setOverride('global.logLevel', 'debug');
  try {
    inProduct(function () {
      helpersMod.logArtifact('JWT', 'after signing', 'eyJhbGciOi.secret.sig');
    });
    helpersMod.logArtifact('JWT', 'after signing', 'eyJhbGciOi.dev.sig');
  } finally {
    config.clearOverride('global.logLevel');
  }
  const logged = seen.filter(function (rec) {
    return rec.artifact === 'JWT';
  });
  t.check(logged.length === 2 && logged[0].value === undefined &&
          logged[0].length === 21 && /^[0-9a-f]{16}$/.test(logged[0].sha256) &&
          JSON.stringify(logged[0]).indexOf('secret') < 0,
          'product logs a signed token by size and digest, never its text',
          JSON.stringify(logged[0]));
  t.equal(logged[1] && logged[1].value, 'eyJhbGciOi.dev.sig',
          'development still logs it whole');
  // 16.5.1: /KdcProxy keeps an internal error's text in the log in product.
  const kdcSource = require('fs').readFileSync(ROOT + '/kerberos/krb5_kdc.js',
                                               'utf8');
  t.check(/mode\.hidesFailureDetail\(\)\s*\?\s*'the KDC could not answer\.'/
            .test(kdcSource),
          '/KdcProxy answers a failure without its text in product');
  // An XML signature naming a transform outside the list is refused before
  // anything is digested (1.2.7, the allowlist).
  const xmldsig = require(ROOT + '/common/crypto_impl/xmldsig.js');
  const DS = 'http://www.w3.org/2000/09/xmldsig#';
  const signed = function (transform) {
    return '<r ID="a"><ds:Signature xmlns:ds="' + DS + '"><ds:SignedInfo>' +
      '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/' +
      'xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/' +
      '2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#a">' +
      '<ds:Transforms><ds:Transform Algorithm="' + transform + '"/>' +
      '</ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/' +
      '04/xmlenc#sha256"/><ds:DigestValue>AA==</ds:DigestValue>' +
      '</ds:Reference></ds:SignedInfo><ds:SignatureValue>AA==' +
      '</ds:SignatureValue></ds:Signature></r>';
  };
  const allowed = [xmldsig.TRANSFORM_ENVELOPED,
                   'http://www.w3.org/2001/10/xml-exc-c14n#'];
  const xpath = xmldsig.verifyXml(
    signed('http://www.w3.org/TR/1999/REC-xpath-19991116'),
    { allowedTransforms: allowed });
  t.equal(xpath.valid === false && xpath.transformRefused,
          'http://www.w3.org/TR/1999/REC-xpath-19991116',
          'an XPath transform is refused by name before any digest');
  const enveloped = xmldsig.verifyXml(signed(xmldsig.TRANSFORM_ENVELOPED),
                                      { allowedTransforms: allowed });
  t.equal(enveloped.transformRefused, undefined,
          'and enveloped-signature is not');
  // 7.6.2: single sign-on asks, per protocol and per application.
  const SsoConsent = require(ROOT + '/common/sso_consent');
  const appsMod = require(ROOT + '/common/applications');
  const consentMod = require(ROOT + '/common/consent');
  const realSettingFor = appsMod.settingFor;
  const realOutstanding = consentMod.outstanding;
  let switchedOn = true;
  let agreed = false;
  appsMod.settingFor = function (application, key) {
    return key === 'saml2.ssoConsent' ? switchedOn : realSettingFor
      .apply(appsMod, arguments);
  };
  consentMod.outstanding = function (request) {
    const rows = agreed ? [] : [{ scope: request.scope, signsIn: true }];
    return { outstanding: rows, names: rows.map(function (one) {
      return one.scope;
    }) };
  };
  const step = function (extra) {
    return SsoConsent.check(Object.assign({ setting: 'saml2.ssoConsent',
      application: 'https://sp.example/metadata', username: 'alice' },
    extra || {}));
  };
  try {
    t.equal(step().action, 'ask',
            'a person not yet agreed is asked before single sign-on');
    t.equal(step().decision.outstanding[0].scope,
            consentMod.SSO_SIGN_IN_SCOPE, 'under the sign-in scope');
    const passive = step({ passive: true });
    t.equal(passive.action === 'refuse' && passive.passive, true,
            'a passive request is refused rather than shown the screen');
    t.equal(step({ denied: true }).action, 'refuse',
            'a Deny is a refusal');
    agreed = true;
    t.equal(step().action, 'proceed', 'an earlier Allow answers it');
    agreed = false;
    switchedOn = false;
    t.equal(step().action, 'proceed',
            'and the setting, or the application\'s own value, turns it off');
    t.equal(step({ username: '' }).action, 'proceed',
            'nobody signed in is nobody to ask');
  } finally {
    appsMod.settingFor = realSettingFor;
    consentMod.outstanding = realOutstanding;
  }
  t.equal(asks('sts-client-3f9a'), true,
          'a dynamically registered public client is always asked');
  t.equal(asks('sts-user-portal'), false,
          'and this service\'s own portal is not');
  if (address.peerIsTrustedProxy) {
    const req = { socket: { remoteAddress: '203.0.113.9' } };
    t.equal(address.peerIsTrustedProxy(req), true,
            'development believes any peer with no list');
    t.equal(inProduct(function () {
      return address.peerIsTrustedProxy(req);
    }), false, 'product believes no peer with no list');
  }
}

module.exports = {
  name: 'asvs_protocol_rules',
  describe: 'product mode\'s stricter reading of protocol input',
  run: run
};
