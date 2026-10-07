// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/console_dpop.js
//
// ---------------------------------------------------------------------------
// A DPoP KEY FOR AN IN-PROCESS TEST THAT CALLS /admin-api AS THE CONSOLE
// (#446, the cutover).
//
// `sts-admin-console` is a public client since the cutover, and every token
// issued to it is DPoP-bound: `/admin-api` refuses one that carries no
// `cnf.jkt`, or one sent as Bearer, or one without its proof (STS-OAUTH-0944).
// A test that minted a console token with `oauth2.accessTokenAsync()` and sent
// it as Bearer now mints it bound — `jkt: kit.jkt` — and sends
// `kit.headers(method, url, token)`. One key per kit, as one browser holds one.
//
// A tool of the in-process half: it is required inside a test's own process
// (or child) from the service's root, and it asserts nothing.
// ---------------------------------------------------------------------------

/**
 * Makes a DPoP key and what a request with it carries.
 *
 * @param root - the service's root directory, as the test requires it from
 * @returns `jkt` (the key's RFC 7638 thumbprint, for `cnf.jkt`) and
 *   `headers(method, url, token)` (`authorization` and `dpop`)
 */
function consoleDpop(root) {
  const oidcRp = require(root + '/common/oidc_rp');
  const dpop = require(root + '/oauth-oidc/dpop');
  const key = oidcRp.dpopKey();
  return {
    jkt: dpop.thumbprint(key.publicJwk),
    headers: function (method, url, token) {
      return {
        authorization: 'DPoP ' + token,
        dpop: oidcRp.dpopProof(key, method, url, { accessToken: token })
      };
    }
  };
}

module.exports = { consoleDpop: consoleDpop };
