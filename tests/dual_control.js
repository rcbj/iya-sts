// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: dual_control.js
//
// ===========================================================================
// TWO-PERSON APPROVAL FOR HIGH-RISK ADMINISTRATOR ACTS (#2166, ASVS 5.0.0
// 2.3.5), in process.
//
// The management API's POST step (`holdForSecondAdministrator()`, the one
// the route wrapper runs before every handler) and its decision door
// (`decideHeld()`) are driven with a request and a stand-in response, the
// way `admin_api_action_actor.js` drives handlers, with the locals the gate
// writes for a person's token. The act is a real one — granting Admin Write
// through `POST /admin-api/rbac/grant` — so "the act runs" is observed on the
// roster, not inferred.
//
//   A. the setting off: nothing is held, and the act runs at once
//   B. on: the act is held (202, an id, a Location), and does not run
//   C. the requester cannot approve it (STS-ADMIN-0957), an application
//      cannot (STS-ADMIN-0958), a person without the authority cannot
//      (STS-ADMIN-0959)
//   D. a second administrator approves it: the act runs, and the audit row
//      names both
//   E. refuse and withdraw; withdraw by somebody else (STS-ADMIN-0967); a
//      decided act cannot be decided again (STS-ADMIN-0964)
//   F. expiry, at the read and by the job, with a clock of the test's own
//   G. the single-administrator rule: nobody else holds the authority, and
//      the act runs, recorded as STS-ADMIN-0962
//   H. an approval asks for a recent sign-in (RFC 9470's answer, 401)
//   I. parity: every row of the table is a management API POST that mirrors
//      a console page; the decision operations mirror /admin/approvals; the
//      console draws /admin/approvals from GET /admin-api/approvals
//   J. the control's own off switch is held
// ===========================================================================

delete process.env.CONFIG_FILE;

const crypto = require('crypto');

const log = require('bunyan').createLogger({
  name: 'dual_control',
  level: process.env.LOG_LEVEL || 'info' });

const ldap = require('../ldap/ldap_server');
const audit = require('../common/audit');
const config = require('../common/config');
const rbac = require('../admin-ui/admin_rbac');
const adminApi = require('../mgmt-api/admin_api');
const dualControl = require('../admin-core/dual_control');

const RBAC_ROUTE = '/admin-api/rbac/:action';

function entryFor(route) {
  log.debug("Entering entryFor(). " + route);
  const found = (adminApi.ROUTES || []).filter(function (entry) {
    return entry.method === 'POST' &&
      String(entry.route || entry.path || '') === route;
  })[0] || null;
  log.debug("Leaving entryFor(). " + !!found);
  return found;
}

// The locals the gate writes for a person's token.
function callerOf(name, roles, authTime) {
  log.debug("Entering callerOf(). " + name);
  log.debug("Leaving callerOf().");
  return { kind: 'person', name: name, sub: name,
           clientId: 'sts-admin-console', realm: 'default',
           authTime: authTime || Math.floor(Date.now() / 1000),
           scopes: ['admin:write'], roles: roles || ['ADMIN_WRITE'] };
}

function requestOf(action, payload) {
  log.debug("Entering requestOf(). " + action);
  log.debug("Leaving requestOf().");
  return { method: 'POST', params: { action: action }, query: {},
           headers: { 'content-type': 'application/json' },
           body: JSON.stringify(payload), path: '',
           originalUrl: '/admin-api/x/' + action };
}

function responseFor(req, caller) {
  log.debug("Entering responseFor().");
  const captured = { status: 0, text: '', headers: {} };
  const res = {
    req: req,
    locals: { apiCaller: caller },
    status: function status(code) {
      log.debug("Entering status().");
      captured.status = code;
      log.debug("Leaving status().");
      return res;
    },
    type: function type() {
      log.debug("Entering type().");
      log.debug("Leaving type().");
      return res;
    },
    set: function set(name, value) {
      log.debug("Entering set().");
      if (typeof name === 'string') {
        captured.headers[name.toLowerCase()] = value;
      }
      log.debug("Leaving set().");
      return res;
    },
    send: function send(text) {
      log.debug("Entering send().");
      captured.text = String(text || '');
      log.debug("Leaving send().");
      return res;
    }
  };
  log.debug("Leaving responseFor().");
  return { res: res, captured: captured };
}

function parsed(captured) {
  log.debug("Entering parsed().");
  let body = {};
  try {
    body = JSON.parse(captured.text || '{}');
  } catch (e) {
    log.debug("Caught in parsed(): " + ((e && e.message) || e));
    body = { raw: captured.text };
  }
  log.debug("Leaving parsed().");
  return { status: captured.status, body: body,
           headers: captured.headers };
}

// The POST wrapper's step for a grant: whether it answered (held), and the
// answer.
function tryGrant(caller, username) {
  log.debug("Entering tryGrant(). " + username);
  const req = requestOf('grant', { username: username, role: 'write' });
  const built = responseFor(req, caller);
  const answered = adminApi.holdForSecondAdministrator(
    entryFor(RBAC_ROUTE), RBAC_ROUTE, req, built.res);
  log.debug("Leaving tryGrant(). " + answered);
  return { answered: answered, got: parsed(built.captured) };
}

// A decision through the decision door.
async function decide(caller, action, id, reason) {
  log.debug("Entering decide(). " + action);
  const req = requestOf(action, { id: id, reason: reason });
  const built = responseFor(req, caller);
  const result = await adminApi.decideHeld(req, built.res,
    { action: action, id: id, reason: reason || '' });
  log.debug("Leaving decide().");
  return { result: result, got: parsed(built.captured) };
}

function holdsWrite(username) {
  log.debug("Entering holdsWrite(). " + username);
  const out = !!rbac.rolesOf(username).write;
  log.debug("Leaving holdsWrite(). " + out);
  return out;
}

function lastSeq() {
  log.debug("Entering lastSeq().");
  let top = 0;
  audit.list().forEach(function (row) {
    top = Math.max(top, Number(row.seq) || 0);
  });
  log.debug("Leaving lastSeq(). " + top);
  return top;
}

function rowsSince(seq, action) {
  log.debug("Entering rowsSince(). " + action);
  const out = audit.list().filter(function (row) {
    return (Number(row.seq) || 0) > seq && row.action === action;
  });
  log.debug("Leaving rowsSince(). " + out.length);
  return out;
}

// A store of the test's own, with the parts the library uses.
function memoryStore() {
  log.debug("Entering memoryStore().");
  const map = new Map();
  log.debug("Leaving memoryStore().");
  return {
    get: function get(key) {
      log.debug("Entering get().");
      log.debug("Leaving get().");
      return map.get(key);
    },
    set: function set(key, value) {
      log.debug("Entering set().");
      map.set(key, value);
      log.debug("Leaving set().");
      return this;
    },
    delete: function del(key) {
      log.debug("Entering del().");
      log.debug("Leaving del().");
      return map.delete(key);
    },
    forEach: function forEach(fn) {
      log.debug("Entering forEach().");
      map.forEach(fn);
      log.debug("Leaving forEach().");
    }
  };
}

async function run(t) {
  log.debug("Entering run().");
  const stamp = crypto.randomBytes(3).toString('hex');
  const alice = 'dc2166a' + stamp;
  const bob = 'dc2166b' + stamp;
  const carol = 'dc2166c' + stamp;
  const dave = 'dc2166d' + stamp;
  const erin = 'dc2166e' + stamp;
  [alice, bob, carol, dave, erin].forEach(function (name) {
    ldap.createUser(name, { invent: false });
  });
  rbac.grant(alice, 'write', { via: 'test' });
  rbac.grant(bob, 'write', { via: 'test' });
  const before = config.value('admin.dualControl');
  try {
    // A. OFF
    dualControl.resetForTests();
    config.setOverride('admin.dualControl', false);
    const seqA = lastSeq();
    const off = tryGrant(callerOf(alice), carol);
    t.check(off.answered === false &&
            rowsSince(seqA, 'admin.dual-control.held').length === 0 &&
            dualControl.list().length === 0,
            'A. with admin.dualControl off nothing is held: the wrapper ' +
            'hands the act to its handler and stores nothing',
            JSON.stringify(off));

    // B. ON: held
    config.setOverride('admin.dualControl', true);
    const seqB = lastSeq();
    const held = tryGrant(callerOf(alice), carol);
    const id = held.got.body && held.got.body.approval &&
      held.got.body.approval.id;
    t.check(held.answered === true && held.got.status === 202 &&
            held.got.body.pending === true && /^dc_/.test(String(id)) &&
            String(held.got.headers.location || '').indexOf(
              '/admin-api/approvals?id=' + id) >= 0 &&
            !holdsWrite(carol) &&
            rowsSince(seqB, 'admin.dual-control.held').length === 1,
            'B. on, the grant is held: 202, pending, an id, a Location, ' +
            'one audit row, and carol does not hold Admin Write',
            JSON.stringify(held.got).slice(0, 600));
    const view = adminApi.approvalsView({ query: { id: id } },
                                        { locals: { apiCaller:
                                          callerOf(bob) } });
    t.check(view.request && view.request.status === 'pending' &&
            view.request.requester === alice &&
            view.request.authority === 'ADMIN_WRITE' &&
            view.state.on === true &&
            (view.state.authorities || []).some(function (one) {
              return one.authority === 'ADMIN_WRITE' && one.inForce &&
                one.holders >= 2;
            }),
            'B2. GET /admin-api/approvals names it pending, asked by alice, ' +
            'needing ADMIN_WRITE, and the control on and in force for ' +
            'Admin Write',
            JSON.stringify(view.state));

    // C. who may not decide
    const self = await decide(callerOf(alice), 'approve', id);
    t.check(self.result && self.result.errorCode === 'STS-ADMIN-0957' &&
            self.result.status === 403 && !holdsWrite(carol),
            'C1. the requester cannot approve their own act (STS-ADMIN-0957)',
            JSON.stringify(self.result));
    const machine = await decide({ kind: 'application', name: 'sts-api-client',
                                   roles: ['ADMIN_WRITE'] }, 'approve', id);
    t.check(machine.result && machine.result.errorCode === 'STS-ADMIN-0958',
            'C2. an application cannot approve one (STS-ADMIN-0958)',
            JSON.stringify(machine.result));
    const reader = await decide(callerOf(dave, ['ADMIN_READ']), 'approve', id);
    t.check(reader.result && reader.result.errorCode === 'STS-ADMIN-0959' &&
            !holdsWrite(carol),
            'C3. a person without Admin Write cannot approve it ' +
            '(STS-ADMIN-0959)', JSON.stringify(reader.result));

    // D. a second administrator approves: the act runs
    const seqD = lastSeq();
    const approved = await decide(callerOf(bob), 'approve', id);
    const rows = rowsSince(seqD, 'admin.dual-control.approved');
    const row = rows[0] || {};
    t.check(approved.result && approved.result.ok === true &&
            approved.result.approval.status === 'done' &&
            holdsWrite(carol) && rows.length === 1 &&
            row.actor === alice && row.detail &&
            row.detail.approvedBy === bob && row.detail.requestedBy === alice,
            'D. bob approves it, the grant runs as alice\'s act, carol holds ' +
            'Admin Write, and the audit row names both',
            JSON.stringify({ result: approved.result && {
              ok: approved.result.ok, errors: approved.result.errors,
              status: approved.result.approval &&
                approved.result.approval.status },
                             row: row.detail }).slice(0, 700));
    const again = await decide(callerOf(bob), 'approve', id);
    t.check(again.result && again.result.errorCode === 'STS-ADMIN-0964' &&
            again.result.status === 409,
            'E1. a decided act cannot be decided again (STS-ADMIN-0964)',
            JSON.stringify(again.result));

    // E. refuse and withdraw
    rbac.revoke(carol, 'write', { via: 'test' });
    const second = tryGrant(callerOf(alice), dave).got.body.approval.id;
    const refused = await decide(callerOf(bob), 'refuse', second, 'no');
    t.check(refused.result && refused.result.ok === true &&
            refused.result.approval.status === 'refused' &&
            refused.result.approval.decidedBy === bob && !holdsWrite(dave),
            'E2. bob refuses a held grant: refused, by bob, and nothing ran',
            JSON.stringify(refused.result));
    const third = tryGrant(callerOf(alice), dave).got.body.approval.id;
    const notYours = await decide(callerOf(bob), 'withdraw', third);
    t.check(notYours.result && notYours.result.errorCode === 'STS-ADMIN-0967',
            'E3. only the requester may withdraw (STS-ADMIN-0967)',
            JSON.stringify(notYours.result));
    const withdrawn = await decide(callerOf(alice), 'withdraw', third);
    t.check(withdrawn.result && withdrawn.result.ok === true &&
            withdrawn.result.approval.status === 'withdrawn' &&
            !holdsWrite(dave),
            'E4. alice withdraws her own: withdrawn, and nothing ran',
            JSON.stringify(withdrawn.result));
    const unknown = await decide(callerOf(bob), 'approve', 'dc_nothing');
    t.check(unknown.result && unknown.result.errorCode === 'STS-ADMIN-0956' &&
            unknown.result.status === 404,
            'E5. an unknown id is 404 (STS-ADMIN-0956)',
            JSON.stringify(unknown.result));

    // H. the approver's recent sign-in
    const fourth = tryGrant(callerOf(alice), dave).got.body.approval.id;
    const recent = config.value('account.recentAuthMinutes');
    config.setOverride('account.recentAuthMinutes', 15);
    try {
      const stale = await decide(
        callerOf(bob, ['ADMIN_WRITE'],
                 Math.floor(Date.now() / 1000) - 3600), 'approve', fourth);
      t.check(stale.result === null && stale.got.status === 401 &&
              /insufficient_user_authentication/.test(
                String(stale.got.headers['www-authenticate'] || '')) &&
              !holdsWrite(dave) &&
              dualControl.get(fourth).status === 'pending',
              'H. an approver whose sign-in is an hour old is asked to sign ' +
              'in again (401 insufficient_user_authentication), and the ' +
              'act stays pending', JSON.stringify(stale.got).slice(0, 400));
    } finally {
      config.setOverride('account.recentAuthMinutes', recent);
    }
    await decide(callerOf(alice), 'withdraw', fourth);

    // G. the single-administrator rule
    rbac.revoke(bob, 'write', { via: 'test' });
    const seqG = lastSeq();
    const alone = tryGrant(callerOf(alice), erin);
    t.check(alone.answered === false &&
            rowsSince(seqG, 'admin.dual-control.proceeded').some(
              function (one) {
                return one.errorCode === 'STS-ADMIN-0962';
              }) &&
            dualControl.state().inForce === false &&
            /fewer than two/.test(dualControl.state().why),
            'G. with nobody but alice holding Admin Write the act is not ' +
            'held — it runs, recorded STS-ADMIN-0962 — and the state says ' +
            'the control is not in force', JSON.stringify(alone));
    rbac.grant(bob, 'write', { via: 'test' });

    // J. the control's own off switch
    const settingEntry = (adminApi.ROUTES || []).filter(function (entry) {
      return entry.method === 'POST' && (entry.actions || []).some(
        function (one) {
          return one.operationId === 'setSetting';
        });
    })[0];
    const offReq = requestOf('set', { key: 'admin.dualControl',
                                      value: false });
    const offRes = responseFor(offReq, callerOf(alice));
    const offHeld = adminApi.holdForSecondAdministrator(
      settingEntry, String(settingEntry.route || settingEntry.path), offReq,
      offRes.res);
    const otherReq = requestOf('set', { key: 'saml.organizationName',
                                        value: 'X' });
    const otherRes = responseFor(otherReq, callerOf(alice));
    const otherHeld = adminApi.holdForSecondAdministrator(
      settingEntry, String(settingEntry.route || settingEntry.path),
      otherReq, otherRes.res);
    t.check(offHeld === true && offRes.captured.status === 202 &&
            otherHeld === false && config.value('admin.dualControl') === true,
            'J. turning admin.dualControl off is held itself; another ' +
            'setting is not', JSON.stringify({ offHeld: offHeld,
                                               otherHeld: otherHeld }));
  } finally {
    config.setOverride('admin.dualControl', before === true);
    dualControl.resetForTests();
  }

  // F. EXPIRY, with a library of the test's own clock and store.
  let now = Date.now();
  const deps = Object.assign(dualControl.DualControl.defaultDeps(), {
    requests: memoryStore(),
    now: function clock() {
      log.debug("Entering clock().");
      log.debug("Leaving clock().");
      return now;
    }
  });
  const lib = new dualControl.DualControl(deps);
  const heldF = lib.hold({ row: lib.rowOf('rotateKek'),
                           operationId: 'rotateKek',
                           route: '/admin-api/encryption/:action',
                           action: 'rotate-kek', body: {},
                           caller: callerOf(alice),
                           authority: 'ADMIN_WRITE' });
  const idF = heldF.request && heldF.request.id;
  now += (lib.lifetimeS() + 5) * 1000;
  const late = await lib.approve(idF, callerOf(bob), function () {
    return Promise.resolve({ status: 200, body: { ok: true } });
  });
  t.check(heldF.held === true && late.errorCode === 'STS-ADMIN-0960' &&
          lib.get(idF).status === 'expired',
          'F1. an act past its deadline is expired at the read, and an ' +
          'approval of it is refused (STS-ADMIN-0960) and runs nothing',
          JSON.stringify({ held: heldF.held, late: late }));
  const heldF2 = lib.hold({ row: lib.rowOf('rotateKek'),
                            operationId: 'rotateKek',
                            route: '/admin-api/encryption/:action',
                            action: 'rotate-kek', body: {},
                            caller: callerOf(alice),
                            authority: 'ADMIN_WRITE' });
  now += (lib.lifetimeS() + 5) * 1000;
  const swept = lib.sweep();
  t.check(heldF2.held === true && /1 held act\(s\) expired/.test(
            String(swept.summary)),
          'F2. the job moves a pending act past its deadline to expired',
          JSON.stringify(swept));
  now += 8 * 86400 * 1000;
  const cleared = lib.sweep();
  t.check(/removed/.test(String(cleared.summary)) && !lib.get(idF),
          'F3. a finished act is removed after its retention',
          JSON.stringify(cleared));

  // I. PARITY
  const operations = {};
  (adminApi.ROUTES || []).forEach(function (entry) {
    (entry.actions || []).forEach(function (one) {
      operations[one.operationId] = { method: entry.method,
                                      mirrors: entry.mirrors };
    });
    if (entry.operationId) {
      operations[entry.operationId] = { method: entry.method,
                                        mirrors: entry.mirrors };
    }
  });
  const unpaired = dualControl.HELD.filter(function (row) {
    const op = operations[row.operationId];
    return !op || op.method !== 'POST' ||
      !/POST \/admin/.test(String(op.mirrors || ''));
  }).map(function (row) {
    return row.operationId;
  });
  t.check(unpaired.length === 0,
          'I1. every held act is a management API POST that mirrors a ' +
          'console page, so the console and a program meet the one check',
          JSON.stringify(unpaired));
  const decisions = ['approveHeldAct', 'refuseHeldAct', 'withdrawHeldAct']
    .filter(function (name) {
      const op = operations[name];
      return !op || op.method !== 'POST' ||
        String(op.mirrors || '').indexOf('POST /admin/approvals') < 0;
    });
  const list = operations.getApprovals;
  const pages = require('../admin-ui/web_pages');
  const drawn = (pages.PAGES || []).some(function (one) {
    return one.path === '/admin/approvals' &&
      one.operation === '/admin-api/approvals';
  });
  t.check(decisions.length === 0 && list && list.method === 'GET' &&
          String(list.mirrors).indexOf('GET /admin/approvals') >= 0 && drawn,
          'I2. approve, refuse and withdraw mirror POST /admin/approvals, ' +
          'and the console draws /admin/approvals from GET ' +
          '/admin-api/approvals', JSON.stringify({ decisions: decisions,
                                                   drawn: drawn }));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'dual_control',
  describe: 'two-person approval for high-risk administrator acts: held, ' +
            'decided by a second administrator, refused, withdrawn, ' +
            'expired, and the single-administrator rule (#2166)',
  run: run
};
