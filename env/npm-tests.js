// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: env/npm-tests.js
// The in-process suite's layer: `local.js`, with the higher rate limits this
// suite needs since `local.js` stopped setting them (#1482).
const local = require('./local');

module.exports = Object.assign({}, local, {
  authn: Object.assign({}, local.authn, { allowOptionalSecondFactor: true }),
  admin: Object.assign({}, local.admin, { logBootstrapPassword: true }),
  oauth2: Object.assign({}, local.oauth2, { allowConfidentialWithoutPkce: true }),
  security: Object.assign({}, local.security, {
    rateLimitPerIdentity: 100,
    rateLimitPerAddress: 500
  })
});
