// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// ===========================================================================
// tests/tools/container-smoke.js — SIGN IN TO THE CONSOLE AND READ
// /admin-api/sts-metadata, FOR THE BUILD-CONTAINER WORKFLOW'S SMOKE TEST.
//
// `.github/workflows/build-container.yml` starts the image it just built and
// asks `/admin/sts-metadata` for the endpoint list, because that page is built
// by walking the live router and so answers only once every module has
// registered its routes. It used to reach the page with a bare `curl` and
// `ADMIN_AUTH_REQUIRED=false`. That setting was REMOVED on 2026-09-06 — the
// console gate cannot be turned off in either mode — so the container quietly
// ignored it, the curl got a 303 to `/oauth2/authorize`, and every merge to
// main from 2026-09-09 on failed at that step while every local run passed,
// because no local path makes an anonymous request to the console.
//
// **SIGNING IN IS THE FIX, AND IT IS NOT WRITTEN HERE.** The five-hop walk is
// `tests/vendored/console_signin.js`'s, which five jobs already share, and
// the token it needs to create its account is `tools/admin-api-token.js`'s
// (minted by the workflow and handed over as `STS_ADMIN_API_TOKEN`). A third
// copy of either would agree on the day it was written and report a broken
// console the first time the flow gained a hop.
//
// **IT IS A TOOL AND NOT A TEST**, for `tools/`'s stated reason: `run.js`
// discovers a test as any `.js` file in `tests/`, and nothing in here is on
// that path.
//
// Usage: STS_ADMIN_API_TOKEN=<token> node tests/tools/container-smoke.js <base>
// Exits 0 when the page's operation answered 200 with an endpoint list, 1
// otherwise.
// ===========================================================================

'use strict';

// FIRST, before anything makes a request: the preload that presents the token
// on `/admin-api` calls. `console_signin.js` creates its console account
// through that API with no Authorization header of its own, exactly as it
// does under `run-report.js`, which attaches this same file with `--require`.
require('./attach-admin-token.js');

const consoleSignIn = require('../vendored/console_signin.js');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the sign-in helper's logger reads.
const log = require('bunyan').createLogger({ name: 'container-smoke',
  level: process.env.LOG_LEVEL || 'info' });

// A name and not a credential: the helper derives the password from it. It is
// distinctive so that a row in /admin/audit says which caller made it.
const CONSOLE_USER = 'container-smoke';

// The endpoint count below which the router was plainly not walked. The
// vendored `sts_metadata.js` job asks for more than twenty; this is a smoke
// test, so it asks the same and leaves the exact list to that job.
const MINIMUM_ENDPOINTS = 20;

async function main(base) {
  log.debug("Entering main().");
  if (!process.env.STS_ADMIN_API_TOKEN) {
    // Without it the sign-in helper's account create is refused 401, and the
    // failure would name the user create rather than the missing token.
    log.debug("Leaving main().");
    throw new Error('STS_ADMIN_API_TOKEN is empty. Mint one with ' +
                    'tests/tools/admin-api-token.js first.');
  }
  // `grant: 'read'`, as the vendored `sts_metadata.js` job asks: a fresh
  // container's empty roster admits anybody, and a role given first keeps
  // that from being what this step depends on.
  const session = await consoleSignIn.signInToTheConsole(base, CONSOLE_USER,
                                                         log,
                                                         { grant: 'read' });
  if (!session) {
    // `signInToTheConsole()` asserts its own walk and answers a client; a
    // null here would mean the helper changed under this tool.
    log.debug("Leaving main().");
    throw new Error('console_signin.js answered no console client.');
  }
  // THE PAGE'S OPERATION, since the #446 cutover made `/admin` a static
  // application: every `/admin/*` path answers the console's shell, so
  // `?format=json` there is HTML and lists nothing — which is how this step
  // failed on the first build after the cutover. The console draws the page
  // from `GET /admin-api/sts-metadata`, the same JSON `?format=json` was, and
  // the client the sign-in answers holds that console's DPoP-bound token. It
  // is asked with `api()` and not `get()`, because `get()` also DRAWS the
  // page with `admin-ui/console.bundle.js`, which only an image build makes
  // and a workflow's checkout does not have.
  const reply = await session.api('GET', '/admin-api/sts-metadata');
  console.log('sts-metadata: ' + reply.status);
  if (reply.status !== 200) {
    log.debug("Leaving main().");
    throw new Error('GET /admin-api/sts-metadata answered ' + reply.status +
                    ' with the console\'s token: ' +
                    String(reply.text || '').slice(0, 300));
  }
  const doc = reply.json;
  const text = String(reply.text || '');
  const count = doc && Array.isArray(doc.endpoints) ? doc.endpoints.length : 0;
  if (count <= MINIMUM_ENDPOINTS) {
    log.debug("Leaving main().");
    throw new Error('/admin-api/sts-metadata listed ' + count +
                    ' endpoint(s), so the router was not walked: ' +
                    text.slice(0, 300));
  }
  console.log('sts-metadata lists ' + count + ' endpoints.');
  log.debug("Leaving main().");
}

if (require.main === module) {
  const base = String(process.argv[2] || 'https://localhost:8081')
    .replace(/\/+$/, '');
  main(base).catch(function (e) {
    log.debug("Caught in the entry point: " + ((e && e.message) || e));
    process.stderr.write('container-smoke: ' + ((e && e.message) || e) +
                         '\n');
    process.exit(1);
  });
}
