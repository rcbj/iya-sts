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
  config.clearOverride('security.outboundAllowedHosts');
  t.equal(inProduct(function () {
    return mode.refusesPlainSyslog();
  }), true, 'product refuses plain syslog');
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
