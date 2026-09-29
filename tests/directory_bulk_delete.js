// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: directory_bulk_delete.js
//
// ===========================================================================
// DELETING PEOPLE IN BULK IS ONE BATCH, AND A PERSON HOLDING NOTHING COSTS
// NOTHING (#351, 2026-09-29).
//
// One SCIM Bulk of a hundred DELETE /Users held a request worker on testidp
// for about a minute: per person, a DN-less directory touch (every cached
// listing and index dropped, so the RISC event after it walked the realm),
// two folds of the token register and a walk of the sessions to read what
// they held, and then a selective sign-out of the one thing everybody holds
// and nothing can end — the `krb5` family's "no such principal" row — which
// ended "0 of 1 live item(s)" and was audited refused (`STS-LOGOUT-0007`).
//
// What is asserted:
//
//   A. the root cause: a person holding nothing holds NO ids
//      (`logout.heldIds()` lists only what a sign-out can end), and deleting
//      them writes no `logout.selective` row at all — let alone a refused one;
//   B. a SCIM Bulk of deletes is ONE batch: `directoryDeletedMany()` is handed
//      every deleted person once, each person's account observers are told
//      once (RISC `account-purged`), each holder's session is ended, and each
//      operation still has its own status in the BulkResponse, in order — a
//      missing id 404, a person the same Bulk already deleted 404 — as RFC
//      7644 section 3.7 requires;
//   C. operations stay in order across a batch: a DELETE of a name followed
//      by a POST of the same name (bulkId) makes a NEW person, who is not
//      signed out by the delete before them, and a later operation that
//      references the POST by `bulkId:` resolves to it;
//   D. a batch larger than a chunk (500) hands its sign-outs over at the chunk
//      boundary as well as at the end, and the event loop turns inside it;
//   E. the directory's indexes follow a delete instead of being rebuilt:
//      a deleted person's `urn:uuid:` and name answer "nobody" and a re-made
//      name answers the new entry, with no rebuild of the UUID index for the
//      misses;
//   F. a person with an entry beneath them is still refused (not a leaf) in
//      a batch, and a delete in the same batch that empties the parent lets
//      the parent go.
//
// In a child process on an ephemeral loopback port, `account_delete.js`'s
// arrangement.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'directory_bulk_delete',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.DBD_ROOT;
  const OUT = process.env.DBD_OUT;
  const fs = require('fs');
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const sleep = function (ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  };
  function go(port, method, p, headers, json) {
    return new Promise(function (resolve) {
      const body = json ? JSON.stringify(json) : '';
      const h = Object.assign({}, headers);
      if (json) {
        h['content-type'] = 'application/scim+json';
        h['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: p,
        method: method, headers: h }, function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let parsed = null;
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            parsed = { parseError: e.message, text: text };
          }
          resolve({ status: res.statusCode, json: parsed });
        });
      });
      req.end(body);
    });
  }
  function fakeRes() {
    return { cookie: function () {}, setHeader: function () {},
             getHeader: function () { return undefined; },
             clearCookie: function () {}, locals: {} };
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const authn = require(ROOT + '/authn/authn');
    const audit = require(ROOT + '/common/audit');
    const accountState = require(ROOT + '/common/account_state');
    const logout = require(ROOT + '/logout/logout');
    const cacheRegistry = require(ROOT + '/common/cache_registry');
    const ldap = require(ROOT + '/ldap/ldap_server');
    config.setOverride('scim.bulkMaxOperations', 2000);
    config.setOverride('scim.bulkMaxPayloadSize', 4 * 1024 * 1024);
    config.setOverride('ldap.maxEntries', 5000);

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    ldap.createUser('dbd-scim-caller', { invent: false });
    const auth = { authorization: 'Basic ' +
      Buffer.from('dbd-scim-caller:anything').toString('base64') };
    const bulk = function (operations) {
      return go(port, 'POST', '/scim/v2/Bulk', auth, {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:BulkRequest'],
        Operations: operations });
    };
    const make = function (name) {
      ldap.createUser(name, { invent: false });
      const dn = ldap.objectFor(name).dn;
      return { name: name, dn: dn, id: ldap.resourceIdOfDn(dn) };
    };
    const signIn = function (name) {
      return authn.startSession(fakeRes(), name, ['pwd'], '', 'bulk-test',
        { request: { headers: {}, ip: '127.0.0.1', socket: {} } });
    };
    const selectiveFor = function (name) {
      return audit.list().filter(function (row) {
        return row.action === 'logout.selective' &&
               String(row.target || '') === name;
      });
    };

    // What the account observers and account_state are told.
    const told = [];
    ldap.addAccountObserver(function (event) {
      if (String(event.kind).indexOf('deleted:') === 0) {
        told.push(event.username);
      }
    });
    const handed = [];
    const realMany = accountState.directoryDeletedMany;
    accountState.directoryDeletedMany = function (changes) {
      handed.push(changes.map(function (c) { return c.username; }));
      return realMany(changes);
    };

    // --- A. a person holding nothing holds no ids ------------------------
    const idle = make('dbd-idle');
    note(Array.isArray(logout.heldIds('dbd-idle')) &&
         logout.heldIds('dbd-idle').length === 0,
         'A1. a person with no session, token or credential holds NO ids — ' +
         'the krb5 family\'s "no such principal" row is not a thing held',
         JSON.stringify(logout.heldIds('dbd-idle')));
    const idleGone = await go(port, 'DELETE', '/scim/v2/Users/' + idle.id,
                              auth);
    await sleep(100);
    note(idleGone.status === 204 && selectiveFor('dbd-idle').length === 0,
         'A2. deleting them writes no selective sign-out at all — it used to ' +
         'write one that ended 0 of 1 and was audited refused ' +
         '(STS-LOGOUT-0007)',
         idleGone.status + ' ' + JSON.stringify(selectiveFor('dbd-idle')));

    // --- B. one Bulk of deletes is one batch ------------------------------
    handed.length = 0;
    told.length = 0;
    const people = [];
    for (let i = 0; i < 12; i++) {
      people.push(make('dbd-b' + i));
    }
    const holders = people.slice(0, 3).map(function (p) {
      return signIn(p.name);
    });
    note(holders.every(Boolean) &&
         logout.heldIds('dbd-b0').length >= 1,
         'B0. three of them hold a sign-on session (held ids listed)',
         JSON.stringify(logout.heldIds('dbd-b0')));
    const ops = people.slice(0, 6).map(function (p) {
      return { method: 'DELETE', path: '/Users/' + p.id };
    }).concat([
      { method: 'DELETE', path: '/Users/00000000-0000-4000-8000-00000000dead' },
      { method: 'DELETE', path: '/Users/' + people[0].id }
    ]).concat(people.slice(6).map(function (p) {
      return { method: 'DELETE', path: '/Users/' + p.id };
    }));
    const b = await bulk(ops);
    await sleep(200);
    const statuses = ((b.json && b.json.Operations) || []).map(function (o) {
      return String(o.status);
    });
    note(b.status === 200 &&
         statuses.join(',') ===
           '204,204,204,204,204,204,404,404,204,204,204,204,204,204',
         'B1. every operation has its own status, in order: twelve 204s, ' +
         'a missing id 404, and a person the same Bulk already deleted 404',
         b.status + ' ' + statuses.join(','));
    note(handed.length === 1 && handed[0].length === 12,
         'B2. account_state is handed the twelve deleted people ONCE, as ' +
         'one batch',
         JSON.stringify(handed.map(function (h) { return h.length; })));
    note(told.length === 12 && new Set(told).size === 12,
         'B3. and the account observers (RISC account-purged) were told ' +
         'once per person', told.length);
    note(people.slice(0, 3).every(function (p) {
      return authn.sessionsOf(p.name).length === 0;
    }), 'B4. every holder\'s sign-on session was ended');
    note(people.every(function (p) {
      return selectiveFor(p.name).every(function (row) {
        return row.outcome !== 'refused';
      });
    }) && people.slice(3).every(function (p) {
      return selectiveFor(p.name).length === 0;
    }), 'B5. the nine who held nothing had no sign-out, and nobody\'s was ' +
        'refused');
    note(people.every(function (p) {
      return !ldap.existingUserEntry(p.name);
    }), 'B6. and every one of them is gone from the directory');

    // --- C. order across the batch, and bulkId references ----------------
    const carol = make('dbd-carol');
    signIn('dbd-carol');
    const c = await bulk([
      { method: 'DELETE', path: '/Users/' + carol.id },
      { method: 'POST', path: '/Users', bulkId: 'again',
        data: { schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
                userName: 'dbd-carol' } },
      { method: 'POST', path: '/Groups', bulkId: 'grp',
        data: { schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
                displayName: 'dbd-carols',
                members: [{ value: 'bulkId:again' }] } }
    ]);
    const cs = ((c.json && c.json.Operations) || []).map(function (o) {
      return String(o.status);
    });
    // Signed in again right after the Bulk, before the deferred sign-out of
    // the old carol runs: the new person's session must survive it.
    const newCarol = signIn('dbd-carol');
    await sleep(200);
    const again = ldap.existingUserEntry('dbd-carol');
    note(cs.join(',') === '204,201,201' && again &&
         ldap.resourceIdOfDn(again.dn) !== carol.id,
         'C1. DELETE then POST of the same name, in order: a NEW entry ' +
         '(another id), and the Group POST after it was made too',
         cs.join(',') + ' ' + (again && ldap.resourceIdOfDn(again.dn)));
    const group = (c.json.Operations[2] || {}).location || '';
    const members = group
      ? (await go(port, 'GET', '/scim/v2/Groups/' + group.split('/').pop(),
                  auth)).json.members || []
      : [];
    note(members.some(function (m) {
      return again && m.value === ldap.resourceIdOfDn(again.dn);
    }), 'C2. and its `bulkId:again` reference resolved to the new person',
         JSON.stringify(members));
    note(!!newCarol && authn.sessionsOf('dbd-carol').some(function (s) {
      return s.id === newCarol.id;
    }), 'C3. the new person\'s session is not ended by the delete of the ' +
        'person before them');

    // --- D. a batch larger than a chunk -----------------------------------
    handed.length = 0;
    const many = [];
    for (let i = 0; i < 520; i++) {
      many.push(make('dbd-m' + i));
    }
    let ticks = 0;
    const ticker = setInterval(function () { ticks += 1; }, 0);
    const d = await bulk(many.map(function (p) {
      return { method: 'DELETE', path: '/Users/' + p.id };
    }));
    clearInterval(ticker);
    await sleep(200);
    const ds = ((d.json && d.json.Operations) || []).filter(function (o) {
      return String(o.status) === '204';
    }).length;
    note(ds === 520, 'D1. 520 deletes in one Bulk, each answered 204', ds);
    note(handed.length === 2 && handed[0].length === 500 &&
         handed[1].length === 20,
         'D2. handed over at the chunk boundary (500) and at the end (20)',
         JSON.stringify(handed.map(function (h) { return h.length; })));
    note(ticks > 0, 'D3. and the event loop turned while the Bulk ran',
         ticks);

    // --- E. the indexes follow the deletes --------------------------------
    const erin = make('dbd-erin');
    const erinUuid = erin.id;
    ldap.entryByUuid(erinUuid);
    const report = function () {
      return (cacheRegistry.report() || []).filter(function (r) {
        return r.name === 'ldap.entryuuid-index';
      })[0] || {};
    };
    ldap.deletePerson(erin.dn);
    const before = report().misses;
    const lookedUp = ldap.entryByUuid(erinUuid);
    const after = report().misses;
    note(lookedUp === null && before === after,
         'E1. the deleted person\'s UUID answers nobody, from the index ' +
         'as the delete left it — no rebuild', before + ' ' + after);
    note(!ldap.existingUserEntry('dbd-erin'),
         'E2. and their name answers nobody');
    const erin2 = make('dbd-erin');
    note(ldap.existingUserEntry('dbd-erin') &&
         ldap.entryByUuid(erin2.id) &&
         ldap.entryByUuid(erin2.id).dn === erin2.dn,
         'E3. a person made again under the name is found by name and by ' +
         'their new UUID');

    // --- F. not a leaf, in a batch -----------------------------------------
    const frank = make('dbd-frank');
    const childDn = 'cn=dbd-child,' + frank.dn;
    // A child entry under the person, placed straight in the store.
    let childMade = false;
    try {
      ldap.entries.set(ldap.normalizeDn(childDn),
        { dn: childDn, attributes: { objectclass: ['device'],
                                     cn: ['dbd-child'] },
          createdAt: '', modifiedAt: '' });
      childMade = true;
    } catch (e) {
      note(false, 'F0. a child entry could be placed under a person',
           e.message);
    }
    if (childMade) {
      const f = ldap.inPersonBatch(function () {
        return [ldap.deletePerson(frank.dn)];
      }, { door: 'a test' });
      note(f[0] && f[0].ok === false && f[0].reason === 'notLeaf',
           'F1. a person with an entry beneath them is refused in a batch ' +
           '(not a leaf)', JSON.stringify(f[0]));
      ldap.entries.delete(ldap.normalizeDn(childDn));
      const g = ldap.inPersonBatch(function () {
        return [ldap.deletePerson(frank.dn)];
      }, { door: 'a test' });
      note(g[0] && g[0].ok === true,
           'F2. and once it is gone, deleted', JSON.stringify(g[0]));
    }

    accountState.directoryDeletedMany = realMany;
    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'directory-bulk-delete-' + process.pid +
                        '-' + require('crypto').randomBytes(8)
                          .toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', DBD_ROOT: ROOT,
                           DBD_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'directory_bulk_delete',
  describe: 'Deleting people in bulk (#351): a person holding nothing holds ' +
            'no ids and gets no sign-out (the STS-LOGOUT-0007 root cause), ' +
            'a SCIM Bulk of deletes is one batch with per-operation ' +
            'statuses in order, bulkId references and chunked yields, and ' +
            'the directory indexes follow a delete without a rebuild',
  run: run
};
