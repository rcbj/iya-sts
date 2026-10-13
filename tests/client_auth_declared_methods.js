// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: client_auth_declared_methods.js
//
// ---------------------------------------------------------------------------
// A CLIENT THAT PRESENTED NO SECRET IS TOLD EVERY METHOD IT MAY USE
// (2026-10-02).
//
// An application may declare several token endpoint authentication methods
// (c4797e03). When a request presents no credential at all,
// `client_auth.methodFor()` falls back to the FIRST declared method, and the
// refusal named that one alone: rcbj0002, declaring client_secret_basic and
// client_secret_post, was told "Send it by client_secret_basic (an
// Authorization: Basic header)" — which reads as the post method being
// refused. The refusal now names every declared method, and the RFC 9700
// sentence in front of it says `token_endpoint_auth_methods a, b`.
//
//   1. declaredMethodsOf() reads the list, the single older member, and
//      nothing;
//   2. a single-method client's refusal is unchanged;
//   3. a two-method client's refusal names both, with how each is sent;
//   4. oauth2_bcp's RFC 9700 refusal names both methods, through
//      checkClientAuthentication(), the function the token endpoint calls.
//
// In process: the sentence is what is under test, and nothing over HTTP can
// choose which methods an entry declares without a whole application.
// ---------------------------------------------------------------------------
delete process.env.CONFIG_FILE;
const clientAuth = require('../oauth-oidc/client_auth');
const bcp = require('../oauth-oidc/oauth2_bcp');
const realms = require('../common/realms');
const log = require('bunyan').createLogger({
  name: 'client_auth_declared_methods',
  level: process.env.LOG_LEVEL || 'info' });

/**
 * Runs the checks.
 *
 * @param t - the harness
 * @returns a promise
 */
async function run(t) {
  log.debug("Entering run().");

  // 1. The declared list.
  t.equal(JSON.stringify(clientAuth.declaredMethodsOf({
    token_endpoint_auth_methods: ['client_secret_basic', 'client_secret_post'],
    token_endpoint_auth_method: 'client_secret_basic' })),
  JSON.stringify(['client_secret_basic', 'client_secret_post']),
  'declaredMethodsOf() reads token_endpoint_auth_methods in order');
  t.equal(JSON.stringify(clientAuth.declaredMethodsOf({
    token_endpoint_auth_method: 'private_key_jwt' })),
  JSON.stringify(['private_key_jwt']),
  'declaredMethodsOf() reads the single member where there is no list');
  t.equal(clientAuth.declaredMethodsOf(null).length, 0,
          'declaredMethodsOf() answers nothing for no entry');

  // 2. One method: the sentence it always was.
  const one = await clientAuth.verify({
    method: 'client_secret_basic', clientId: 'probe-one',
    presentedSecret: '', declaredMethods: ['client_secret_basic'] });
  t.equal(one.ok, false, 'a single-method client with no secret is refused');
  t.equal(one.errorCode, 'STS-OAUTH-0019', 'with STS-OAUTH-0019');
  t.check(/Send it by client_secret_basic \(an Authorization: Basic header\)/
    .test(one.description) && !/client_secret_post/.test(one.description),
  'a single-method refusal names that method alone', one.description);

  // 3. Two methods: both named, each with how it is sent.
  const two = await clientAuth.verify({
    method: 'client_secret_basic', clientId: 'probe-two',
    presentedSecret: '',
    declaredMethods: ['client_secret_basic', 'client_secret_post'] });
  t.equal(two.errorCode, 'STS-OAUTH-0019',
          'a two-method client with no secret is refused STS-OAUTH-0019');
  t.check(/client_secret_basic \(an Authorization: Basic header\)/
    .test(two.description) &&
    /client_secret_post \(a client_secret form parameter\)/
      .test(two.description) &&
    /declares 2 methods; authenticate with one of them/.test(two.description),
  'a two-method refusal names both methods and how each is sent',
  two.description);
  const mixed = await clientAuth.verify({
    method: 'client_secret_post', clientId: 'probe-mixed',
    presentedSecret: '',
    declaredMethods: ['client_secret_post', 'private_key_jwt',
                      'tls_client_auth'] });
  t.check(/client_secret_post \(a client_secret form parameter\), private_key_jwt \(a client_assertion signed with a registered key\) or tls_client_auth \(a client certificate\)/
    .test(mixed.description),
  'three declared methods are listed in order, the last after "or"',
  mixed.description);

  // 4. The RFC 9700 sentence the token endpoint sends, in a realm of its own
  // (oauth2.rfc9700 is restart-only for the process and settable on a realm).
  const realmId = 'cadm-' + process.pid;
  const made = realms.create({ id: realmId, name: realmId,
                               description: 'Created by ' + __filename,
                               overrides: { 'oauth2.rfc9700': true } });
  let refused = null;
  try {
    if (!made.ok) {
      t.bad('could not create the realm ' + realmId,
            (made.errors || []).join(' '));
    }
    refused = await realms.run(realms.get(realmId), function () {
      return bcp.checkClientAuthentication({
        clientId: 'probe-bcp', clientSecret: '', request: null,
        registered: {
          known: true, client_id: 'probe-bcp',
          client_secret: 'a-secret-on-file',
          client_secrets: [{ id: 'x', secret: 'a-secret-on-file',
                             expiresAt: 0 }],
          token_endpoint_auth_method: 'client_secret_basic',
          token_endpoint_auth_methods: ['client_secret_basic',
                                        'client_secret_post'] } });
    });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    refused = { ok: true, description: 'threw: ' + e.message };
  } finally {
    realms.remove(realmId);
  }
  t.equal(refused && refused.ok, false,
          'RFC 9700 mode refuses the two-method client that sent no secret');
  t.check(/declares token_endpoint_auth_methods client_secret_basic, client_secret_post/
    .test((refused && refused.description) || '') &&
    /client_secret_post \(a client_secret form parameter\)/
      .test((refused && refused.description) || ''),
  'the RFC 9700 refusal names both declared methods',
  refused && refused.description);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'client_auth_declared_methods',
  describe: 'a client that sent no secret is told every method it declares',
  run: run
};
