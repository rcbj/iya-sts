// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/admin_api_gate_warm.js
// ===========================================================================
// THE CONSOLE GATE DOES NOT READ THE STORE SYNCHRONOUSLY ONCE WARM (#880).
//
// The token register, the sign-on session and the person used to be read
// on the event loop, inside the gate, before any page was built. The gate
// now asks those rows off the loop first. This child turns the two stores
// that can still block on:
//
//   * the directory window (postgres-lru, with no database: the window
//     object exists at require, and persistence.start() is not called),
//     behind a bridge that counts each synchronous query and answers the
//     same rows asynchronously without counting them as synchronous;
//   * the token register's on-demand reader, active only for
//     admin_stats.tokens, so a miss is a synchronous read() and a warm is
//     readMany().
//
// The person is created, the token is minted, and both are then dropped
// from memory: the person's slot is forgotten after the row has been
// copied into the bridge, and the token's jti is pushed out of the
// register by a flood of newer records. A gate that did not warm would
// read both synchronously on the first request. The second request must
// add no synchronous directory query and no further readMany.
//
// The session itself stays in authn's memory map. warmSessionAsync() is
// recorded; the session bridge is not armed. 8081 is not measured here.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'admin_api_gate_warm',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.AG_ROOT;
  let dpopKit = null;
  const DPOP = {
    get jkt() {
      dpopKit = dpopKit || require(ROOT_DIR + '/tests/tools/console_dpop')
        .consoleDpop(ROOT_DIR);
      return dpopKit.jkt;
    },
    headers: function (method, url, token) {
      dpopKit = dpopKit || require(ROOT_DIR + '/tests/tools/console_dpop')
        .consoleDpop(ROOT_DIR);
      return dpopKit.headers(method, url, token);
    }
  };
  const BOUND = {};
  const OUT = process.env.AG_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function call(port, method, urlPath, token) {
    return new Promise(function (resolve, reject) {
      const headers = { accept: 'application/json' };
      if (token && BOUND[token]) {
        Object.assign(headers, DPOP.headers(method, 'http://127.0.0.1:' +
                                            port + urlPath.split('?')[0],
                                            token));
      } else if (token) {
        headers.authorization = 'Bearer ' + token;
      }
      const req = http.request({ host: '127.0.0.1', port: port,
                                 path: urlPath, method: method,
                                 headers: headers }, function (res) {
        let raw = '';
        res.on('data', function (d) { raw += d; });
        res.on('end', function () {
          let json = null;
          try {
            json = JSON.parse(raw);
          } catch (e) {
            // Not JSON; the finding reports the text.
            json = null;
          }
          resolve({ status: res.statusCode, text: raw, json: json });
        });
      });
      req.on('error', reject);
      req.end();
    });
  }
  function settle() {
    return new Promise(function (res) { setTimeout(res, 40); });
  }
  function payloadOf(token) {
    const part = String(token || '').split('.')[1] || '';
    const pad = part + '='.repeat((4 - (part.length % 4)) % 4);
    const text = Buffer.from(pad.replace(/-/g, '+').replace(/_/g, '/'),
                              'base64').toString('utf8');
    return JSON.parse(text);
  }
  function uuidsOf(row) {
    return (row.attrs.entryuuid || [])
      .concat(row.attrs.stsentryuuidalias || [])
      .map(function (v) { return String(v).toLowerCase(); });
  }
  function countingBridge(rows) {
    const queries = require(ROOT_DIR + '/persistence/directory_queries');
    const syncNames = [];
    const asyncNames = [];
    function answer(name, args) {
      const realm = args && args[0];
      const list = [];
      rows.forEach(function (row) {
        if (row.realm === realm) {
          list.push(JSON.parse(JSON.stringify(row)));
        }
      });
      if (name === 'byKeys') {
        const keys = (args && args[1]) || [];
        return list.filter(function (row) {
          return keys.indexOf(row.dn_key) >= 0;
        }).map(queries.rowOf);
      }
      if (name === 'byUuid') {
        const wanted = String((args && args[1]) || '').toLowerCase();
        return list.filter(function (row) {
          return uuidsOf(row).indexOf(wanted) >= 0;
        }).map(queries.rowOf);
      }
      if (name === 'withUuids') {
        const wanted = {};
        ((args && args[1]) || []).forEach(function (v) {
          wanted[String(v).toLowerCase()] = true;
        });
        return list.filter(function (row) {
          return uuidsOf(row).some(function (u) { return wanted[u]; });
        }).map(queries.rowOf);
      }
      if (name === 'byName') {
        const base = String((args && args[1]) || '');
        const who = String((args && args[2]) || '').toLowerCase();
        return list.filter(function (row) {
          const rest = row.dn_key.slice(row.dn_key.indexOf(',') + 1);
          if (rest !== base) {
            return false;
          }
          const names = (row.attrs.uid || [])
            .concat(row.attrs.stspseudonym || []);
          return names.some(function (v) {
            return String(v).toLowerCase() === who;
          });
        }).map(queries.rowOf);
      }
      if (name === 'classesUnder') {
        return [];
      }
      if (name === 'count' || name === 'realmCount' ||
          name === 'rdnCount') {
        return 0;
      }
      if (name === 'hasChild' || name === 'anyWithAttribute') {
        return false;
      }
      if (name === 'countHolding') {
        return { n: 0, holding: 0 };
      }
      return [];
    }
    const syncWhere = [];
    function asked(name, args) {
      if (name === 'byKeys') {
        return ((args && args[1]) || []).join('|');
      }
      if (name === 'byName') {
        return String((args && args[2]) || '');
      }
      if (name === 'withAttribute') {
        return String((args && args[2]) || '') + '@' +
          String((args && args[1]) || '');
      }
      return '';
    }
    return {
      syncNames: syncNames,
      syncWhere: syncWhere,
      asyncNames: asyncNames,
      query: function (name, args) {
        syncNames.push(name);
        syncWhere.push(name + ' ' + asked(name, args));
        return answer(name, args);
      },
      queryAsync: function (name, args) {
        asyncNames.push(name);
        return Promise.resolve(answer(name, args));
      }
    };
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const realms = require(ROOT_DIR + '/common/realms');
    const rbac = require(ROOT_DIR + '/admin-ui/admin_rbac');
    const oauth2 = require(ROOT_DIR + '/oauth-oidc/oauth2');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const audit = require(ROOT_DIR + '/common/audit');
    const authn = require(ROOT_DIR + '/authn/authn');
    const stats = require(ROOT_DIR + '/common/admin_stats');
    const fsLocal = require('fs');

    note(!!ldap.directoryWindow,
         'precondition: the directory window is on',
         ldap.directoryWindow ? 'on' : 'null');
    if (!ldap.directoryWindow) {
      fsLocal.writeFileSync(OUT, JSON.stringify(findings));
      process.exit(0);
    }

    const stamp = String(process.pid);
    const WRITER = 'agw-' + stamp;
    const inDefault = function (fn) {
      return realms.run(realms.DEFAULT_REALM, fn);
    };
    const made = inDefault(function () {
      return ldap.createUser(WRITER, { invent: false });
    });
    inDefault(function () {
      rbac.grant(WRITER, 'write', { via: 'test' });
    });
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    const fakeRes = function () {
      const out = {};
      out.set = function () { return out; };
      out.append = function () { return out; };
      return out;
    };
    const session = inDefault(function () {
      return authn.startSession(fakeRes(), WRITER, ['pwd'], '1',
                                'password', {});
    });
    const token = await inDefault(function () {
      return oauth2.accessTokenAsync(base, {
        audience: base + '/admin-api',
        scope: 'admin:read admin:write',
        client_id: 'sts-admin-console',
        username: WRITER,
        jkt: DPOP.jkt,
        session_id: session && session.id
      });
    });
    BOUND[token] = true;
    const claims = payloadOf(token);
    const personUuid = made && made.entry
      ? ldap.entryUuidOf(made.entry) : '';
    note(!!made && made.ok && !!personUuid && !!claims.jti &&
         String(claims.sub || '') === 'urn:uuid:' + personUuid &&
         !!session && !!session.id,
         'precondition: a live session and a token whose subject is the ' +
         'person\'s entryUUID',
         JSON.stringify({
           ok: !!(made && made.ok),
           sub: claims && claims.sub,
           uuid: personUuid,
           jti: !!(claims && claims.jti),
           sid: !!(session && session.id)
         }));

    const rows = new Map();
    const realmId = inDefault(function () { return realms.currentId(); });
    const dnKey = ldap.normalizeDn(made.entry.dn);
    rows.set(realmId + '\n' + dnKey, {
      realm: realmId,
      dn_key: dnKey,
      dn: made.entry.dn,
      attrs: JSON.parse(JSON.stringify(made.entry.attributes || {})),
      origin: made.entry.origin || 'test',
      created_at: made.entry.createdAt || '1',
      modified_at: made.entry.modifiedAt || made.entry.createdAt || '1'
    });
    const bridge = countingBridge(rows);
    ldap.directoryWindow.attach(bridge);
    const forgot = inDefault(function () {
      return ldap.directoryWindow.forget(realmId, dnKey);
    });
    note(!!forgot,
         'precondition: the person\'s window slot was forgotten after the ' +
         'row was copied into the bridge',
         String(forgot));

    const store = new Map();
    store.set(String(claims.jti), { sessionId: session.id });
    const tokenSync = { n: 0 };
    const tokenAsync = { n: 0 };
    const tokenAsyncKeys = [];
    realms.setOnDemandReader({
      active: function (handle) {
        return handle === 'admin_stats.tokens';
      },
      journalled: function () {
        return false;
      },
      digestOf: function (handle, realm, key) {
        return 'd:' + key;
      },
      read: function (handle, realm, key) {
        tokenSync.n += 1;
        if (store.has(key)) {
          return { present: true, value: store.get(key) };
        }
        return { present: false };
      },
      readMany: function (handle, realm, keys) {
        tokenAsync.n += 1;
        (keys || []).forEach(function (key) {
          tokenAsyncKeys.push(String(key));
        });
        const out = new Map();
        (keys || []).forEach(function (key) {
          if (store.has(key)) {
            out.set(key, store.get(key));
          }
        });
        return Promise.resolve(out);
      }
    });
    inDefault(function () {
      for (let i = 0; i < 20000; i++) {
        stats.recordJwt({ jti: 'flood-' + stamp + '-' + i, typ: 'at+jwt' },
                         '', { kind: 'access' });
      }
    });

    const warmSids = [];
    const warmSession = authn.warmSessionAsync;
    authn.warmSessionAsync = function (id) {
      warmSids.push(String(id || ''));
      return warmSession(id);
    };

    function snap() {
      return {
        sync: bridge.syncNames.length,
        where: bridge.syncWhere.length,
        asyncN: bridge.asyncNames.length,
        tokenSync: tokenSync.n,
        tokenAsync: tokenAsync.n,
        tokenKeys: tokenAsyncKeys.length
      };
    }
    function since(mark) {
      return {
        sync: bridge.syncNames.slice(mark.sync),
        where: bridge.syncWhere.slice(mark.where),
        asyncN: bridge.asyncNames.slice(mark.asyncN),
        tokenSync: tokenSync.n - mark.tokenSync,
        tokenAsync: tokenAsync.n - mark.tokenAsync,
        tokenKeys: tokenAsyncKeys.slice(mark.tokenKeys)
      };
    }
    const ME = '/admin-api/me';
    const before = snap();
    let r = await call(port, 'GET', ME, token);
    const first = since(before);
    const syncBad = first.sync.filter(function (name) {
      return name !== 'classesUnder';
    });
    const asyncPerson = first.asyncN.filter(function (name) {
      return name === 'withUuids' || name === 'byKeys';
    });
    note(r.status === 200 && r.json && r.json.caller &&
         r.json.caller.name === WRITER && r.json.caller.kind === 'person',
         '1a. the first request is accepted for the person',
         r.status + ' ' + String(r.text || '').slice(0, 240));
    note(first.tokenSync === 0,
         '1b. the token row was not read synchronously',
         'sync ' + first.tokenSync + ' async ' + first.tokenAsync);
    note(first.tokenAsync >= 1 &&
         first.tokenKeys.indexOf(String(claims.jti)) >= 0,
         '1c. the token row was warmed, including this jti',
         first.tokenKeys.slice(0, 8).join(','));
    note(syncBad.length === 0,
         '1d. no synchronous directory read except the group index',
         (first.where || []).join(' || ') || '(none)');
    note(asyncPerson.length >= 1,
         '1e. the person was asked off the loop',
         first.asyncN.join(',') || '(none)');
    note(warmSids.indexOf(session.id) >= 0,
         '1f. the session was warmed by id',
         warmSids.join(',') || '(none)');

    const mid = snap();
    r = await call(port, 'GET', ME, token);
    const second = since(mid);
    note(r.status === 200 && second.sync.length === 0 &&
         second.tokenSync === 0 && second.tokenAsync === 0,
         '2. the next request adds no synchronous directory query and no ' +
         'further token read',
         r.status + ' sync ' + ((second.where || []).join(' || ') ||
         '(none)') +
         ' tokenSync ' + second.tokenSync +
         ' tokenAsync ' + second.tokenAsync);

    const ended = inDefault(function () {
      return authn.endSessionById(session.id, 'a test signing out', 'admin');
    });
    const coded = function (code) {
      return audit.list().filter(function (event) {
        return event.errorCode === code;
      }).length;
    };
    const was = coded('STS-API-0126');
    r = await call(port, 'GET', ME, token);
    await settle();
    note(!!ended && r.status === 401 && r.json &&
         r.json.error === 'invalid_token' &&
         coded('STS-API-0126') === was + 1,
         '3a. an ended session still refuses the token, under STS-API-0126',
         !!ended + ' ' + r.status + ' ' + String(r.text || '').slice(0, 200));
    note(String(r.text || '').indexOf('STS-API-') < 0,
         '3b. and the refusal carries no error code on the wire',
         String(r.text || '').slice(0, 200));

    server.close();
    fsLocal.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'agw-' + process.pid + '-' +
                        Date.now() + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, {
        LOG_LEVEL: 'fatal',
        STS_LOG_LEVEL: 'fatal',
        STS_REQUEST_WORKER: '1',
        LDAP_WORKER_DIRECTORY: 'postgres-lru',
        STS_PERSISTENCE_MODE: 'postgres',
        LDAP_WORKER_CACHE_ENTRIES: '100',
        AG_ROOT: ROOT,
        AG_OUT: out
      }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
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
  name: 'admin_api_gate_warm',
  describe: 'the console gate warms the token, the session and the person ' +
            'before its synchronous checks (#880)',
  run: run
};
