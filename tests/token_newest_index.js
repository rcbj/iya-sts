// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: token_newest_index.js
//
// ===========================================================================
// THE TOKEN REGISTER'S NEWEST FIRST, FROM ITS OWN INDEX KEYS (2026-10-22,
// #820).
//
// Monitoring → Tokens asked `minted.newest`, which ordered `sts_minted` by
// `written_at`: a sort of the whole store, 13 s a page view on 8081. A btree
// on that column would make every update of the table non-HOT, so the order
// is an index key of the register (`n:` and the issue time), filed in
// `sts_minted_index`.
//
//   N1. a record is filed under `n:` and its `iat`, zero-padded so the text
//       sorts as the number does; a record with no `iat` is not;
//   N2. `minted.newest` scans those keys backwards and joins the rows,
//       never ordering `sts_minted` by `written_at`.
// ===========================================================================

const log = require('bunyan').createLogger({
  name: 'token_newest_index',
  level: process.env.LOG_LEVEL || 'info' });

function run(t) {
  log.debug("Entering run().");
  const realms = require('../common/realms');
  require('../common/admin_stats');
  const queries = require('../persistence/minted_queries');
  const handle = realms.handleFor('admin_stats.tokens');
  const lookups = handle && handle.lookupsOf;
  const keys = typeof lookups === 'function'
    ? lookups({ jti: 'j', username: 'alice', iat: 1761100000 }) : [];
  const early = typeof lookups === 'function'
    ? lookups({ jti: 'j', username: 'alice', iat: 99 }) : [];
  const none = typeof lookups === 'function'
    ? lookups({ jti: 'j', username: 'alice' }) : [];
  t.check(keys.indexOf('n:001761100000') >= 0 &&
          early.indexOf('n:000000000099') >= 0 &&
          'n:000000000099' < 'n:001761100000' &&
          !none.some(function (key) {
            return key.indexOf('n:') === 0;
          }),
          'N1. a record is filed under n: and its zero-padded iat',
          JSON.stringify({ keys: keys, early: early, none: none }));
  const built = queries.build('minted.newest',
                              ['admin_stats.tokens', 'default', 1, 50]);
  t.check(/FROM sts_minted_index i/.test(built.text) &&
          /index_key >= 'n:' AND i\.index_key < 'n;'/.test(built.text) &&
          /ORDER BY i\.index_key DESC/.test(built.text) &&
          !/ORDER BY written_at/.test(built.text) &&
          built.values[0] === 'admin_stats.tokens' && built.values[4] === 50,
          'N2. newest scans the n: keys backwards, not written_at',
          built.text);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'token_newest_index',
  describe: 'the token register is listed newest first from its own n: ' +
            'index keys, not a sort of the store (#820)',
  run: run
};
