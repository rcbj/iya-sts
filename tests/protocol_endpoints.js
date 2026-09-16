'use strict';
//
// File: protocol_endpoints.js
//
// ===========================================================================
// EVERY PROTOCOLS PAGE LISTS THE ENDPOINTS OF THE REALM IT IS READ IN.
//
// `admin-core/protocol_endpoints.ts` is a table from console page to route, and
// `admin.respond()` and the management API's `sendJson()` add what it computes
// to a page and to the operation mirroring it. Three things about that can go
// wrong with nothing on any page looking broken, and each is a check here:
//
//   A. A Protocols page with no row — added to `SECTIONS` tomorrow — gets no
//      section and says nothing about its absence; and a row naming a page
//      that moved or was renamed is a list nobody draws.
//   B. A route in the table that the router does not have (a rename) is a URL
//      printed as though it answered, and one `sts_metadata.js` does not
//      describe is a row named by its own path.
//   C. The URLs are CONCRETE only if they carry the realm: a list that reads
//      the default realm's addresses under `/realm/acme/admin/...` is the one
//      failure a reader copying a URL cannot see.
//
// WHY IN PROCESS: B needs the router and the ENDPOINTS table of one process
// side by side, and C needs a realm and a named authorization server created
// without a console session. The pages themselves are driven over HTTP by
// `tests/vendored/sts_admin_console.js`; this is the half nothing there asks.
//
// It runs in a CHILD, `jose_certificate_header.js`'s arrangement, because it
// loads the whole protocol stack and a stack loaded into the runner would be
// shared with every file after this one.
// ===========================================================================

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');
const log = require('bunyan').createLogger({ name: 'protocol_endpoints',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// The child. Everything it needs is required inside, so the function can be
// shipped as source with `node -e`.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.PE_ROOT;
  const OUT = process.env.PE_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function fakeReq(pagePath, query) {
    return { path: pagePath, originalUrl: pagePath, query: query || {},
             protocol: 'https', headers: { host: 'endpoints.test' },
             get: function (name) {
               return String(name).toLowerCase() === 'host' ?
                      'endpoints.test' : undefined;
             } };
  }
  function fakeRes() {
    const res = { headers: {}, body: null, statusCode: 200, locals: {} };
    res.set = function (k, v) {
      res.headers[k] = v;
      return res;
    };
    res.status = function (code) {
      res.statusCode = code;
      return res;
    };
    res.type = function () {
      return res;
    };
    res.send = function (body) {
      res.body = body;
      return res;
    };
    return res;
  }
  function fetchJson(port, urlPath) {
    return new Promise(function (resolve, reject) {
      http.get({ host: '127.0.0.1', port: port, path: urlPath },
               function (res) {
        const chunks = [];
        res.on('data', function (c) { chunks.push(c); });
        res.on('error', reject);
        res.on('end', function () {
          let json = null;
          let parseError = null;
          try {
            json = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          } catch (e) {
            // Not JSON; the finding below reports the status, and the reason
            // travels on the result because this child has no logger.
            parseError = e.message;
          }
          resolve({ status: res.statusCode, json: json,
                    parseError: parseError });
        });
      }).on('error', reject);
    });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    await require(ROOT_DIR + '/common/service_state').start();
    const realms = require(ROOT_DIR + '/common/realms');
    const admin = require(ROOT_DIR + '/admin-ui/admin');
    const table = require(ROOT_DIR + '/admin-core/protocol_endpoints');
    const servers = require(ROOT_DIR + '/oauth-oidc/authorization_servers');

    // --- A. the table and SECTIONS agree ------------------------------------
    const drift = admin.protocolEndpointDrift();
    note(drift.unlisted.length === 0,
         'every page under Protocols has a row in the endpoint table or an ' +
         'exemption', 'unlisted: ' + (drift.unlisted.join(', ') || 'none'));
    note(drift.stray.length === 0,
         'and every row names a page that is under Protocols',
         'stray: ' + (drift.stray.join(', ') || 'none'));

    // --- B. every route is registered and described -------------------------
    const base = 'https://endpoints.test';
    const undescribed = [];
    const unregistered = [];
    const notConcrete = [];
    const empty = [];
    table.pages().forEach(function (page) {
      const rows = table.forPage(fakeReq(page), page);
      const http = rows.filter(function (row) { return row.route; });
      if (!rows.length && ['/admin/authorization-servers',
                           '/admin/spiffe/entries'].indexOf(page) < 0) {
        empty.push(page);
      }
      http.forEach(function (row) {
        if (row.registered === false) {
          unregistered.push(page + ' ' + row.route);
        }
        if (row.name === row.route) {
          undescribed.push(page + ' ' + row.route);
        }
        if (row.url.indexOf(base + '/') !== 0 || /\/:/.test(row.url)) {
          notConcrete.push(page + ' ' + row.url);
        }
      });
    });
    note(unregistered.length === 0,
         'every route a Protocols page lists is registered on the router',
         unregistered.join(', ') || 'all registered');
    note(undescribed.length === 0,
         'and is described in sts_metadata.js, so it is named by that ' +
         'description rather than by its path',
         undescribed.join(', ') || 'all described');
    note(notConcrete.length === 0,
         'every HTTP row is an absolute URL under this request\'s base, with ' +
         'a variable segment written {name}', notConcrete.join(', ') || 'ok');
    note(empty.length === 0,
         'no page lists nothing in the default realm (bar the two whose rows ' +
         'depend on what exists)', empty.join(', ') || 'none empty');
    note(table.forPage(fakeReq('/admin/users'), '/admin/users') === null,
         'a page that is not in the table gets null, not an empty list');

    // Every route above IS registered, so the flag a rename would raise has
    // not been shown to rise. One route is taken off THIS CHILD's router —
    // what a rename leaves the table naming — and put back straight after.
    const router = app._router || app.router;
    const at = router.stack.findIndex(function (layer) {
      return layer.route && layer.route.path === '/sts/cert';
    });
    const removed = at >= 0 ? router.stack.splice(at, 1) : [];
    const renamed = table.forPage(fakeReq('/admin/wstrust'), '/admin/wstrust')
                         .filter(function (row) {
      return row.route === '/sts/cert';
    })[0];
    router.stack.splice(at, 0, ...removed);
    note(removed.length === 1 && renamed && renamed.registered === false,
         'a route the router no longer has is listed as not registered, ' +
         'rather than as a URL that answers',
         JSON.stringify(renamed || null));

    // --- C. the realm is in every URL ---------------------------------------
    const REALM = 'endpointsrealm';
    realms.create({ id: REALM });
    const realm = realms.get(REALM);
    realms.run(realm, function () {
      servers.create({ id: 'tenantpe', label: 'Endpoints test' });
      const prefix = base + '/realm/' + REALM + '/';
      const outside = [];
      table.pages().forEach(function (page) {
        table.forPage(fakeReq(page), page).forEach(function (row) {
          if (row.route && row.url.indexOf(prefix) !== 0) {
            outside.push(page + ' ' + row.url);
          }
        });
      });
      note(outside.length === 0,
           'under a realm every HTTP row carries that realm\'s prefix',
           outside.slice(0, 5).join(', ') || 'all prefixed');

      const named = table.forPage(fakeReq('/admin/authorization-servers'),
                                  '/admin/authorization-servers');
      // Eleven since 2026-09-13: RFC 9126's /:as/oauth2/par joined the ten.
      note(named.length === 11 && named.every(function (row) {
        return /tenantpe/.test(row.url) && /tenantpe$/.test(row.name);
      }), 'a named authorization server is listed by its id, once per route',
           named.map(function (row) { return row.url; }).join(', '));
      note(named.some(function (row) {
        return row.url === prefix +
               '.well-known/oauth-authorization-server/tenantpe';
      }) && named.some(function (row) {
        return row.url === prefix + 'tenantpe/.well-known/openid-configuration';
      }), 'and both of its discovery documents are at their own addresses');

      const ldap = table.forPage(fakeReq('/admin/ldap'), '/admin/ldap');
      note(ldap.length > 0 && ldap.every(function (row) {
        return /^ldaps?:\/\/endpoints\.test:\d+\/.*dc=endpointsrealm/.test(
            row.url);
      }), 'the directory listeners are listed at the realm\'s own base DN',
           ldap.map(function (row) { return row.url; }).join(', '));

      // ONE ROW SINCE 2026-09-16, AND IT IS THE MAIN PORT. It was two — the
      // 8443 and 9443 listeners — and both were deleted; a client certificate
      // is now presented to the port everything else answers on, which asks
      // for one and requires none. The claim being kept is the same one: a
      // TLS handshake has no path to carry a realm in, so this row is the
      // same under every prefix.
      const tls = table.forPage(fakeReq('/admin/tls'), '/admin/tls')
                       .filter(function (row) { return !row.route; });
      note(tls.length === 1 && tls.every(function (row) {
        return /^https:\/\/endpoints\.test:\d+\/$/.test(row.url);
      }), 'the client-certificate row carries no realm, because a handshake ' +
          'has nowhere to put one', tls.map(function (row) {
        return row.url;
      }).join(', '));

      // --- D. respond() adds the member only for the page itself ------------
      const res = fakeRes();
      admin.respond(fakeReq('/admin/saml2', { format: 'json' }), res,
                    { page: '/admin/saml2' }, 'SAML 2.0', '/admin/saml2', '');
      const answered = JSON.parse(res.body);
      note(Array.isArray(answered.protocolEndpoints) &&
           answered.protocolEndpoints.length > 0 &&
           answered.protocolEndpoints[0].url.indexOf(prefix) === 0,
           'the console\'s JSON for a Protocols page carries ' +
           'protocolEndpoints, in the realm it was read in',
           (answered.protocolEndpoints || []).length + ' row(s)');
      const other = fakeRes();
      admin.respond(fakeReq('/admin/kerberos/keytab', { format: 'json' }),
                    other, { page: 'keytab' }, 'Kerberos keytab',
                    '/admin/kerberos/principals', '');
      note(!('protocolEndpoints' in JSON.parse(other.body)),
           'and not for a page drawn under that page\'s tab with a path of ' +
           'its own');
    });

    // --- E. the management API's mirror answers the same --------------------
    const server = http.createServer(app);
    await new Promise(function (resolve) {
      server.listen(0, '127.0.0.1', resolve);
    });
    const port = server.address().port;
    const mirrored = await fetchJson(port, '/admin-api/saml2');
    const expected = table.forPage({ path: '/admin/saml2', query: {},
      protocol: 'http', headers: {}, get: function () {
        return '127.0.0.1:' + port;
      } }, '/admin/saml2');
    note(mirrored.status === 200 && mirrored.json &&
         JSON.stringify(mirrored.json.protocolEndpoints) ===
         JSON.stringify(expected),
         'GET /admin-api/saml2, which mirrors the page, answers the same ' +
         'protocolEndpoints', 'status ' + mirrored.status + ' ' +
         (mirrored.parseError || ''));
    const plain = await fetchJson(port, '/admin-api/users');
    note(plain.status === 200 && plain.json &&
         !('protocolEndpoints' in plain.json),
         'and an operation mirroring a page outside Protocols does not',
         'status ' + plain.status);
    server.close();

    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child threw',
                    detail: e && e.stack ? e.stack : String(e) });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'pe-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  ADMIN_API_AUTH_REQUIRED: 'false',
                                  PE_ROOT: ROOT, PE_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died before writing one; reported below.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'protocol_endpoints',
  describe: 'every Protocols page lists the concrete endpoints of the realm ' +
            'it is read in — each route registered and described, each URL ' +
            'carrying the realm — and the management API mirror answers the ' +
            'same list',
  run: run
};
