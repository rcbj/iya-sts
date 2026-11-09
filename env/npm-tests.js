// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: env/npm-tests.js
// The in-process suite's layer: `local.js`, with the higher rate limits this
// suite needs since `local.js` stopped setting them (#1482).
const local = require('./local');

module.exports = Object.assign({}, local, {
  security: Object.assign({}, local.security, {
    rateLimitPerIdentity: 100,
    rateLimitPerAddress: 500
  })
});
