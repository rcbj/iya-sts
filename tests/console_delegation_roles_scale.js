// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: console_delegation_roles_scale.js
//
// ===========================================================================
// THREE CONSOLE PAGES THAT WALKED THE WHOLE POPULATION, BOUNDED (2026-10-22,
// #820).
//
// On 8081 — about 470,000 signed-in people and a million tokens — three
// pages did work in proportion to everybody on every view:
//
//   * Delegation built `userGraph.userList()`, a row for every identity, to
//     fill a chooser that shows ten;
//   * Roles built every key (`allUserKeys()`) to mark which candidates have
//     signed in, then compared each row against every key;
//   * Grants counted each grant's tokens by walking every token row, and
//     built the grant resource for every grant before paging.
//
// What is held here:
//
//   H. held whole (no on-demand register), nothing changes: the catalogue is
//      the whole list and a substring search, and the roles candidates are
//      the union of the directory and the people seen;
//   D. on demand, the delegation catalogue builds no row of the register's
//      — the delegation's identities and the one person a search names
//      EXACTLY (as typed, in lower case), and the answer says so;
//   R. on demand, /admin/rbac builds no key set, and "seen" is asked of the
//      names on the page;
//   G. the grants list counts tokens in one pass, and /admin-api/grants
//      builds the grant resource for the page's rows only.
//
// In a child process: it loads the whole stack and installs a stand-in
// on-demand reader.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'console_delegation_roles_scale',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.CDR_OUT;
  const ROOT = process.env.CDR_ROOT;
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const realms = require(ROOT + '/common/realms');
    const stats = require(ROOT + '/common/admin_stats');
    const views = require(ROOT + '/admin-core/admin_views');
    const userGraph = require(ROOT + '/common/user_graph');
    const delegation = require(ROOT + '/common/delegation');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const gm = require(ROOT + '/oauth-oidc/grant_management');
    const gmApi = require(ROOT + '/oauth-oidc/grant_management_api');
    const now = Math.floor(Date.now() / 1000);
    const inRealm = function (fn) {
      return realms.run(realms.get(realms.currentId()), fn);
    };
    // Counts the calls of a module function for the length of `fn`, and puts
    // it back whatever happens.
    const counting = async function (names, fn) {
      const real = {};
      const calls = {};
      names.forEach(function (name) {
        real[name] = stats[name];
        calls[name] = 0;
        stats[name] = function () {
          calls[name]++;
          return real[name].apply(this, arguments);
        };
      });
      try {
        const value = await fn();
        return { value: value, calls: calls };
      } finally {
        names.forEach(function (name) {
          stats[name] = real[name];
        });
      }
    };
    const record = function (name, jti) {
      stats.recordJwt({ jti: jti, sub: 'urn:uuid:' + name, username: name,
                        iat: now, exp: now + 3600, typ: 'Bearer' },
                      'signed', { kind: 'access_token' });
    };

    // =================================================================
    // H. HELD WHOLE: NOTHING CHANGES
    // =================================================================
    const heldWhole = inRealm(function () {
      return stats.userKeyTest();
    });
    note(heldWhole === null,
         'H0. precondition: the register is held whole before the reader',
         JSON.stringify(heldWhole));
    await inRealm(async function () {
      record('cdr-h1', 'cdr-h1-1');
      const cat = userGraph.userCatalogue('');
      const whole = userGraph.userList();
      note(cat.complete === true && cat.search === 'contains' &&
           cat.entries.length === whole.length &&
           cat.entries.some(function (e) { return e.key === 'cdr-h1'; }),
           'H1. held whole, the catalogue is the whole list, searched by ' +
           'any part', JSON.stringify({ complete: cat.complete,
             search: cat.search, n: cat.entries.length, whole: whole.length }));
      const chooser = views.delegationChooser('user', { userq: 'h1' }, cat,
                                              {});
      note(chooser.complete === true && chooser.search === 'contains' &&
           chooser.entries.some(function (e) { return e.key === 'cdr-h1'; }),
           'H2. held whole, a part of a name finds the person',
           JSON.stringify(chooser.slice));
      const listed = await counting(['userKeys'], function () {
        return Promise.resolve(views.rbacListJson({
          query: { personq: 'cdr-h' }, headers: {} }));
      });
      const row = (listed.value.candidates || []).filter(function (c) {
        return c.username === 'cdr-h1';
      })[0];
      note(listed.calls.userKeys >= 1 && row && row.seen === true &&
           row.inDirectory === false,
           'H3. held whole, the roles candidates are still the union: ' +
           'somebody seen with no entry is offered, marked seen',
           JSON.stringify({ calls: listed.calls, row: row }));
    });

    // =================================================================
    // THE REGISTER ON DEMAND
    // =================================================================
    let live = true;
    realms.setOnDemandReader({
      active: function () {
        return live;
      },
      read: function () {
        return { present: false };
      },
      byIndex: function () {
        return [];
      },
      digestOf: function (handle, realmId, key) {
        return 'd:' + key;
      },
      journalled: function () {
        return false;
      }
    });
    await inRealm(async function () {
      for (let i = 0; i < 30; i++) {
        record('cdr-u' + i, 'cdr-u' + i + '-1');
      }
      const kind = delegation.TYPES[0];
      delegation.record({
        protocol: kind.protocol, type: kind.type,
        outcome: delegation.OUTCOMES[0],
        initial: { presented: 'cdr-alice' },
        intermediary: { presented: 'cdr-front', application: 'cdr-front' },
        target: { presented: 'cdr-api', application: 'cdr-api' },
        authorizedBy: 'a test', note: 'recorded by a test' });
      ldap.createUser('cdr-u5', { invent: false });
      ldap.createUser('cdr-nobody', { invent: false });
    });
    note(inRealm(function () {
      return typeof stats.userKeyTest() === 'function';
    }), 'D0. precondition: the register is on demand');

    // =================================================================
    // D. THE DELEGATION CATALOGUE
    // =================================================================
    await inRealm(async function () {
      const empty = await counting(['userRows', 'userKeys'], function () {
        return userGraph.userCatalogue('');
      });
      const cat = empty.value;
      const keys = cat.entries.map(function (e) { return e.key; });
      note(empty.calls.userRows === 0 && empty.calls.userKeys === 0 &&
           cat.complete === false && cat.search === 'exact' &&
           keys.indexOf('cdr-alice') >= 0 && keys.indexOf('cdr-u5') < 0,
           'D1. on demand, the catalogue builds no row of the register: ' +
           'the delegation\'s identities, said to be partial',
           JSON.stringify({ calls: empty.calls, keys: keys,
                            complete: cat.complete }));
      const named = await counting(['userRows', 'userKeys'], function () {
        return userGraph.userCatalogue('cdr-u5');
      });
      const hit = named.value.entries.filter(function (e) {
        return e.key === 'cdr-u5';
      })[0];
      note(named.calls.userRows === 0 && named.value.exactKey === 'cdr-u5' &&
           hit && hit.tokens && hit.tokens.issued >= 1,
           'D2. a search naming a person exactly finds them, with their ' +
           'tokens, and builds no other row',
           JSON.stringify({ calls: named.calls, hit: hit }));
      const upper = userGraph.userCatalogue('CDR-U5');
      note(upper.exactKey === 'cdr-u5',
           'D3. the exact search folds case', upper.exactKey);
      const part = userGraph.userCatalogue('u5');
      note(part.exactKey === null &&
           !part.entries.some(function (e) { return e.key === 'cdr-u5'; }),
           'D4. on demand, a part of a name finds nobody outside the ' +
           'delegation register', JSON.stringify(part.entries.length));
      const chooser = views.delegationChooser('user', { userq: 'CDR-U5' },
                                              upper, {});
      note(chooser.search === 'exact' && chooser.complete === false &&
           chooser.entries.length >= 1 &&
           chooser.entries[0].key === 'cdr-u5',
           'D5. the chooser says it searched exactly, and offers the person',
           JSON.stringify({ search: chooser.search, slice: chooser.slice,
                            first: chooser.entries[0] &&
                              chooser.entries[0].key }));
      const user = await counting(['userRows', 'userKeys'], function () {
        return views.delegationUserModel({ user: 'cdr-u5' },
                                         { links: true });
      });
      note(user.calls.userRows === 0 && user.calls.userKeys === 0 &&
           user.value.user && user.value.user.key === 'cdr-u5' &&
           user.value.usersComplete === false &&
           user.value.chooser && user.value.chooser.complete === false,
           'D6. /admin/delegation/user builds no row of the register, and ' +
           'says its list is partial',
           JSON.stringify({ calls: user.calls,
                            usersComplete: user.value.usersComplete }));
      const page = await counting(['userRows', 'userKeys'], function () {
        return views.delegationPageModel({});
      });
      note(page.calls.userRows === 0 && page.calls.userKeys === 0 &&
           page.value.userChooser &&
           page.value.userChooser.search === 'exact',
           'D7. /admin/delegation builds no row of the register',
           JSON.stringify({ calls: page.calls }));
      const map = await counting(['userRows', 'userKeys'], function () {
        return views.delegationMapModel({});
      });
      note(map.calls.userRows === 0 && map.calls.userKeys === 0 &&
           map.value.userChooser &&
           map.value.userChooser.complete === false,
           'D8. /admin/delegation/map builds no row of the register',
           JSON.stringify({ calls: map.calls }));
    });

    // =================================================================
    // R. /admin/rbac
    // =================================================================
    await inRealm(async function () {
      const listed = await counting(['userKeys', 'userRows'], function () {
        return Promise.resolve(views.rbacListJson({
          query: { personq: 'cdr-' }, headers: {} }));
      });
      const rows = listed.value.candidates || [];
      const seen = rows.filter(function (r) {
        return r.username === 'cdr-u5';
      })[0];
      // Every row's mark is the register's own answer for its name (as
      // typed, in lower case, or as the register normalises it).
      const test = stats.userKeyTest();
      const askedOf = function (name) {
        return !!(test(name) || test(String(name).toLowerCase()) ||
                  test(stats.identityKeyOf(name)));
      };
      const disagree = rows.filter(function (r) {
        return !!r.seen !== askedOf(r.username);
      }).map(function (r) { return r.username; });
      note(listed.calls.userKeys === 0 && listed.calls.userRows === 0 &&
           rows.length >= 2 && seen && seen.seen === true &&
           disagree.length === 0,
           'R1. on demand, the roles candidates build no key set, and ' +
           '"seen" is asked of each name',
           JSON.stringify({ calls: listed.calls, seen: seen,
                            rows: rows.length, disagree: disagree }));
      const picked = await counting(['userKeys'], function () {
        return Promise.resolve(views.rbacListJson({
          query: { person: 'CDR-U5' }, headers: {} }));
      });
      const asked = picked.value.json && picked.value.json.picked;
      const pick = asked && asked.candidate;
      note(picked.calls.userKeys === 0 && pick &&
           pick.username === 'cdr-u5' && pick.seen === true,
           'R2. a picked person is found and marked seen without the key ' +
           'set', JSON.stringify({ calls: picked.calls, pick: pick }));
    });
    live = false;

    // =================================================================
    // G. GRANTS
    // =================================================================
    await inRealm(async function () {
      const GRANTS = 40;
      for (let i = 0; i < GRANTS; i++) {
        const planned = gm.planFor({
          params: { grant_management_action: 'create' },
          clientId: 'cdr-client' + (i % 3), sub: 'urn:uuid:cdr-g' + i,
          scope: 'openid' });
        const plan = planned.plan;
        for (let k = 0; k < 3; k++) {
          gm.noteIssued(plan.id, 1, 'cdr-g' + i + '-' + k, 'access_token',
                        now + 3600);
        }
        gm.apply(plan);
      }
      const realForEach = Map.prototype.forEach;
      let walks = 0;
      Map.prototype.forEach = function () {
        walks++;
        return realForEach.apply(this, arguments);
      };
      let decorated;
      try {
        decorated = gm.list();
      } finally {
        Map.prototype.forEach = realForEach;
      }
      const ours = decorated.filter(function (g) {
        return /^urn:uuid:cdr-g/.test(String(g.subject));
      });
      note(ours.length === GRANTS && ours.every(function (g) {
        return g.tokens === 3;
      }) && walks < 10,
           'G1. each grant\'s tokens are counted in one pass, not one walk ' +
           'of the tokens per grant',
           JSON.stringify({ grants: ours.length, walks: walks }));
      const bare = gm.list(undefined, { bare: true });
      const same = bare.length === decorated.length &&
        bare.every(function (row, i) {
          return JSON.stringify(gm.decorate(row)) ===
            JSON.stringify(decorated[i]);
        });
      note(same, 'G2. a bare row decorated is the row the list answers, in ' +
           'the same order', bare.length + ' ' + decorated.length);
      const proto = gm.GrantManagement.prototype;
      const realResource = proto.resourceOf;
      let built = 0;
      proto.resourceOf = function () {
        built++;
        return realResource.apply(this, arguments);
      };
      let answer;
      try {
        const api = new gmApi.GrantManagementApi(
          gmApi.GrantManagementApi.defaultDeps());
        answer = api.grantsView({ per: '5' });
      } finally {
        proto.resourceOf = realResource;
      }
      note(answer.grants.length === 5 && built === 5 &&
           answer.total >= GRANTS &&
           Array.isArray(answer.grants[0].scopes) &&
           answer.grants[0].created_at > 0,
           'G3. /admin-api/grants builds the grant resource for the page ' +
           'only', JSON.stringify({ shown: answer.grants.length,
             built: built, total: answer.total }));
    });
  })().catch(function (e) {
    note(false, 'the child threw', (e && e.stack) || e);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-cdr-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { CDR_OUT: out, CDR_ROOT: root, LOG_LEVEL: 'fatal',
                       STS_LOG_LEVEL: 'fatal' });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 180000 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'console_delegation_roles_scale',
  describe: 'the delegation, roles and grants pages do work in proportion ' +
            'to what they show, not to everybody (#820)',
  run: run
};
