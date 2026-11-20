// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: oauth_model_hold.js
//
// ---------------------------------------------------------------------------
// A REAL ANSWER HELD TO THE OAUTH MODEL, AND THE SAME ANSWER HELD TO THE
// MODEL WITH ONE OF ITS MEMBERS TAKEN OUT (#1579's gap scan).
//
// `oauth-oidc/oauth_model.ts` records an answer that is not the model's under
// STS-OAUTH-1005 and changes nothing, so a member the service sends and the
// model does not name shows only in the service log — which is what
// `tests/tools/model-gap-scan.js` reads after a stack run. A test that holds
// a real answer here finds it in process instead.
//
// `hold()` answers both halves: the problems with the answer as it is (none,
// for an answer that is the model's), and the problems with `member` removed
// from the member set for the length of the call. The second must name that
// member, or the first proves nothing about it: it is the mutation test, made
// on the loaded set rather than on the TypeSpec, and the set is restored
// whatever happens.
// ---------------------------------------------------------------------------

const log = require('bunyan').createLogger({
  name: 'oauth_model_hold',
  level: process.env.LOG_LEVEL || 'info'
});

/**
 * Holds `value` to the member set `id`, as it is and without `member`.
 *
 * @param OAuthModel - `oauth-oidc/oauth_model`, as the caller loaded it
 * @param id - the member set's id (`token-response`, ...)
 * @param value - the answer
 * @param member - the member to take out for the mutation half
 * @returns `{ gaps, mutated, caught }`: the problems as it is, the problems
 *   without `member`, and whether those name `member` as not a member
 */
function hold(OAuthModel, id, value, member) {
  log.debug("Entering hold().");
  const gaps = OAuthModel.undeclared(id, value || {});
  const set = OAuthModel.members(id);
  const kept = set.list;
  let mutated = [];
  try {
    set.list = kept.filter(function (one) {
      return one.name !== member;
    });
    mutated = OAuthModel.undeclared(id, value || {});
  } finally {
    set.list = kept;
  }
  const caught = mutated.indexOf(member + ' is not a member of ' + id) >= 0;
  log.debug("Leaving hold().");
  return { gaps: gaps, mutated: mutated, caught: caught };
}

module.exports = { hold: hold };
