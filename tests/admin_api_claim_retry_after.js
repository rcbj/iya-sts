// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin_api_claim_retry_after.js
//
// ===========================================================================
// A FAIL-CLOSED create 503 CARRIES Retry-After, THE 409 DOES NOT (#1356).
//
// `runClaimed()` wraps the create endpoints (`/admin-api/{users,groups}/create`
// and the rest): a create that can race another node claims its name first,
// through `ldap_server.claimCreate()`. When the create-claims coordination
// store CANNOT BE ASKED, that answers `{ ok:false, reason:'store',
// code:'STS-LDAP-0093' }` and `runClaimed()` answers 503 — fail closed, and
// transient (the store is momentarily unreachable). The #1299 fuzz gate read
// that 503 as an UNCAUGHT server error because it carried no `Retry-After`,
// where `answerDirectoryFailure()`'s unreadable-store 503 sets one. So the 503
// now carries `Retry-After`, and a name genuinely held by another create
// (`reason` anything but `'store'`) still answers 409 with NONE — a 409 is not
// a transient store failure and a client must not retry it as one.
//
// WHY THIS DRIVES `runClaimed()` DIRECTLY over the exported `AdminApi`, rather
// than the full path: the fail-closed shape (`reason:'store'`) is
// `ldap_server.claimCreate()`'s to produce, from a claim store whose COMMIT
// fails on demand — the arrangement `directory_create_cluster_claims.js` builds
// one layer down (its `fakeDatabase().failNextClaimCommit`). Routing it through
// the require-cache/ldap_server/store path adds nothing to the one assertion
// this file exists for — 503-with-Retry-After versus 409-without — and that
// path is unreachable in a calm single-node run, which is why the fuzz gate
// could not hold the regression and this file does. It exercises exactly the
// branch the fix changed; dropping the `setHeader('Retry-After', …)` line turns
// the first assertion red.
//
// IN PROCESS: `admin_api_kinds.js`, `admin_api_lazy_validators.js` and
// `admin_api_document_security.js` all require this module in process already.
// ===========================================================================

const adminApi = require('../mgmt-api/admin_api');
const AdminApi = adminApi.AdminApi;

// A response that records only what `runClaimed()` sets.
function fakeRes() {
  log();
  return {
    headers: {},
    status: null,
    body: null,
    setHeader: function (name, value) {
      this.headers[String(name).toLowerCase()] = value;
    }
  };
}

function log() {}

// Drives `runClaimed()` with a `this` carrying only what it reads: the deps it
// destructures, a `claimForCreate()` that answers the given claim result, and a
// `sendJson()` that records the status and body. Returns the response and the
// promise `runClaimed()` returns.
function drive(held) {
  const res = fakeRes();
  const self = {
    deps: {
      log: { debug: function () {}, error: function () {} },
      errorCodes: {
        mark: function () {},
        tag: function (code) { return '[' + code + '] '; }
      },
      createClaims: {
        active: function () { return true; },
        refusalMessage: function () {
          return 'the create-claims store could not be asked';
        }
      }
    },
    claimForCreate: function () { return Promise.resolve(held); },
    sendJson: function (response, status, body) {
      response.status = status;
      response.body = body;
    }
  };
  const ran = AdminApi.prototype.runClaimed.call(
    self, res, 'cn=example,ou=groups,dc=example,dc=com', function () {});
  return { res: res, ran: ran };
}

function run(t) {
  // The fail-closed store failure: 503 WITH Retry-After.
  const store = drive({ ok: false, reason: 'store', code: 'STS-LDAP-0093' });
  return Promise.resolve(store.ran).then(function () {
    t.equal(store.res.status, 503,
            'a create whose claim store could not be asked answers 503');
    t.equal(store.res.headers['retry-after'], '5',
            'the fail-closed 503 carries Retry-After, so the #1299 gate does ' +
            'not read it as an uncaught server error');

    // A name another create holds: 409, and deliberately NO Retry-After.
    const taken = drive({ ok: false, reason: 'claimed', code: 'STS-LDAP-0092' });
    return Promise.resolve(taken.ran).then(function () {
      t.equal(taken.res.status, 409,
              'a name another create already holds answers 409');
      t.ok(taken.res.headers['retry-after'] === undefined,
           'the 409 sets no Retry-After — it is not a transient store ' +
           'failure and must not be retried as one');
    });
  });
}

module.exports = {
  name: 'admin_api_claim_retry_after',
  describe: 'a fail-closed create 503 carries Retry-After and the 409 does ' +
            'not (#1356)',
  run: run
};
