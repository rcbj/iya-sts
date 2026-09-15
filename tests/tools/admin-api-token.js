// ===========================================================================
// tests/tools/admin-api-token.js — MINT THE MANAGEMENT API'S ACCESS TOKEN.
//
// `/admin-api` requires an OAuth 2.0 access token since 2026-09-09: audienced
// to this API, carrying `admin:read` for a read and `admin:write` for anything
// that changes state. Every job that drives it therefore needs one, and this is
// the ONE place a run obtains it — both launchers call it and hand the result
// to `run-report.js` as `STS_ADMIN_API_TOKEN`.
//
// **IT IS A TOOL AND NOT A TEST**, for `tools/`'s stated reason: `run.js`
// discovers a test as any `.js` file in `tests/`, and everything in here is
// deliberately out of that path.
//
// THE CLIENT IS SEEDED, WHICH IS WHY THIS IS SHORT. `applications.js` puts
// `sts-management-api` in the registry at startup — `client_credentials`,
// `client_secret_basic`, `scope: 'admin:read admin:write'` — so a run does not
// register anything. What it cannot know is the SECRET, which is minted per
// start, so that is read back through `/admin-api/applications`… which is
// itself gated. The way in is `adminApi.authRequired`: a launcher reads the
// secret while the service is still open, or is given it. See the note on
// `secretFor()`.
// ===========================================================================

'use strict';

const https = require('https');
const http = require('http');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'admin-api-token',
  level: process.env.LOG_LEVEL || 'info' });

function request(url, options, body) {
  log.debug("Entering request().");
  log.debug("Leaving request().");
  return new Promise(function (resolve, reject) {
    const u = new URL(url);
    const mod = u.protocol === 'http:' ? http : https;
    const opts = Object.assign({
      hostname: u.hostname, port: u.port,
      path: u.pathname + u.search, method: 'GET',
      // The certificate is regenerated on every start and the anchor is the
      // run's own; `tools/trust.js` hands the JOBS a real anchor, and this
      // runs before that is established.
      rejectUnauthorized: false
    }, options || {});
    const r = mod.request(opts, function (res) {
      let text = '';
      res.on('data', function (c) { text += c; });
      res.on('end', function () {
        resolve({ status: res.statusCode, text: text });
      });
    });
    r.on('error', reject);
    if (body) { r.write(body); }
    r.end();
  });
}

// The seeded client's secret, read from the running service. `/admin-api` is
// gated, so this asks the LDAP-backed applications view through the console's
// own JSON door — which is open to a caller holding the console session — and
// falls back to the environment where a deployment has been given one.
async function secretFor(base) {
  log.debug("Entering secretFor().");
  if (process.env.STS_ADMIN_API_CLIENT_SECRET) {
    log.debug("Leaving secretFor().");
    return process.env.STS_ADMIN_API_CLIENT_SECRET;
  }
  const reply = await request(base + '/admin-api/applications?identifier=' +
                              encodeURIComponent('sts-management-api'));
  if (reply.status !== 200) {
    log.debug("Leaving secretFor().");
    return '';
  }
  try {
    const body = JSON.parse(reply.text);
    const rows = body.applications ||
                 (body.application ? [body.application] : []);
    const row = rows.filter(function (one) {
      return one && one.identifier === 'sts-management-api';
    })[0];
    log.debug("Leaving secretFor().");
    return (row && row.registration && row.registration.client_secret) || '';
  } catch (e) {
    log.debug("Caught in secretFor(): " + ((e && e.message) || e));
    log.debug("Leaving secretFor().");
    return '';
  }
}

// The audience `/admin-api` answers to, which is what a token has to carry.
// Empty configuration means "this service's own /admin-api under the host the
// request arrived on", so the launcher asks for exactly the base it is driving.
function audienceFor(base) {
  log.debug("Entering audienceFor().");
  log.debug("Leaving audienceFor().");
  return String(base).replace(/\/+$/, '') + '/admin-api';
}

// `options` is for the ONE caller that wants a token this run's jobs would not
// otherwise be given: `tests/vendored/sts_admin_api_auth.js`, which asserts the
// gate's refusals and therefore needs a token with ONE scope, or with an
// audience naming somebody else. Both default to what every other caller wants,
// so nothing that was written before this parameter existed changed.
//
// It is a parameter here rather than a second token endpoint call written out
// in that job for the reason this whole file exists: the client id, the grant,
// the authentication scheme and the shape of the form are one fact, and a test
// that restated them would go on passing against a service that had changed
// any of them.
async function mint(base, secret, options) {
  log.debug("Entering mint().");
  const wanted = options || {};
  const audience = wanted.audience || audienceFor(base);
  const scope = wanted.scope === undefined ? 'admin:read admin:write'
                                           : wanted.scope;
  const form = 'grant_type=client_credentials' +
    '&scope=' + encodeURIComponent(scope) +
    '&resource=' + encodeURIComponent(audience);
  const reply = await request(base + '/oauth2/token', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'content-length': Buffer.byteLength(form),
      authorization: 'Basic ' +
        Buffer.from('sts-management-api:' + secret).toString('base64')
    }
  }, form);
  if (reply.status !== 200) {
    throw new Error('the token endpoint answered ' + reply.status + ' ' +
                    reply.text.slice(0, 300));
  }
  const body = JSON.parse(reply.text);
  if (!body.access_token) {
    throw new Error('the token endpoint answered 200 with no access_token: ' +
                    reply.text.slice(0, 300));
  }
  log.debug("Leaving mint().");
  return body.access_token;
}

async function tokenFor(base, options) {
  log.debug("Entering tokenFor().");
  const secret = await secretFor(base);
  if (!secret) {
    throw new Error('could not read the sts-management-api client secret from ' +
                    base + '. Set STS_ADMIN_API_CLIENT_SECRET, or start the ' +
                    'service with adminApi.authRequired=false to read it.');
  }
  log.debug("Leaving tokenFor().");
  return mint(base, secret, options);
}

module.exports = { tokenFor: tokenFor, audienceFor: audienceFor, mint: mint };

if (require.main === module) {
  const base = process.argv[2] || process.env.WSTRUST_STS_URL ||
    'https://localhost:8081';
  tokenFor(base).then(function (token) {
    process.stdout.write(token + '\n');
  }).catch(function (e) {
    process.stderr.write('admin-api-token: ' + e.message + '\n');
    process.exit(1);
  });
}
