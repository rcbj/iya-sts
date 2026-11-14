// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: registers-vectors.js
//
// ---------------------------------------------------------------------------
// THE REGISTERS OVER THE DIRECTORY (#444, phase 4): what the Node service's
// registers answer, refusal by refusal and code by code, for the Rust crate
// `sts-registers` to reproduce. Called by `tests/tools/crypto-vectors.js`'s
// `registers-node.json` row, in a process of its own.
//
// THE METHOD IS A RECORDING OF EVERY PORT. The registers sit over the
// directory, the settings, the audit log and one another, and the Rust crate
// reaches each of those through a small trait of its own (the directory is
// another slice's crate, written at the same time). So each step drives the
// REAL Node module, over the real in-memory directory `ldap/ldap_server.js`
// builds, with every dependency the Rust crate takes as a port wrapped in a
// recorder: each call is written down with its arguments and its answer.
// The Rust test replays those answers to its own register and checks two
// things — that it made the same calls with the same arguments (the
// directory writes above all: an entry Rust writes is the entry Node
// writes), and that it gave the same answer, sentence and code.
//
// A call made from inside another recorded call is not recorded: it is the
// port's own business. Settings are recorded as `settings.value` calls and
// replayed by key.
// ---------------------------------------------------------------------------

const path = require('path');

/**
 * A JSON copy of what crossed a port: functions dropped, `undefined` dropped
 * from objects and `null` in arrays, as JSON.stringify does.
 *
 * @param {any} value - anything
 * @returns {any} its JSON image
 */
function clone(value) {
  if (value === undefined) {
    return null;
  }
  const seen = new WeakSet();
  const text = JSON.stringify(value, function (key, v) {
    if (typeof v === 'bigint') {
      return String(v);
    }
    if (v && typeof v === 'object') {
      if (seen.has(v)) {
        return '[cycle]';
      }
      seen.add(v);
    }
    return v;
  });
  return text === undefined ? null : JSON.parse(text);
}

/**
 * The recorder every wrapped port writes to.
 *
 * @param {any} errorCodes - common/error_codes.js
 * @returns {any} the recorder
 */
function recorder(errorCodes) {
  const rec = { calls: null, depth: 0 };
  rec.codeOf = function (value) {
    if (!value || typeof value !== 'object') {
      return null;
    }
    return errorCodes.codeOf(value) || null;
  };
  rec.fn = function (port, method, f) {
    return function () {
      const args = Array.prototype.slice.call(arguments);
      if (!rec.calls || rec.depth > 0) {
        return f.apply(this, args);
      }
      rec.depth += 1;
      let answer;
      let threw = null;
      try {
        answer = f.apply(this, args);
      } catch (e) {
        threw = e;
      } finally {
        rec.depth -= 1;
      }
      const row = { port: port, method: method, args: clone(args) };
      if (threw) {
        row.threw = String((threw && threw.message) || threw);
        rec.calls.push(row);
        throw threw;
      }
      row.answer = clone(answer);
      const code = rec.codeOf(answer);
      if (code) {
        row.code = code;
      }
      rec.calls.push(row);
      return answer;
    };
  };
  rec.object = function (port, target, only) {
    return new Proxy(target, {
      get: function (t, key) {
        const v = t[key];
        if (typeof key !== 'string' || (only && only.indexOf(key) < 0)) {
          return v;
        }
        if (typeof v === 'function') {
          return rec.fn(port, key, v.bind(t));
        }
        if (rec.calls && rec.depth === 0 && v !== undefined &&
            Object.prototype.hasOwnProperty.call(t, key)) {
          rec.calls.push({ port: port, method: key, args: [],
                           answer: clone(v) });
        }
        return v;
      }
    });
  };
  rec.step = function (steps, register, op, input, run) {
    rec.calls = [];
    let answer;
    let threw = null;
    try {
      answer = run();
    } catch (e) {
      threw = String((e && e.message) || e);
    }
    const calls = rec.calls;
    rec.calls = null;
    const row = { register: register, op: op, input: clone(input),
                  answer: clone(answer), code: rec.codeOf(answer),
                  calls: calls };
    if (threw) {
      row.threw = threw;
    }
    steps.push(row);
    return answer;
  };
  return rec;
}

/**
 * Builds the vectors.
 *
 * @param {string} ROOT - the repository root
 * @returns {Promise<any>} the vector document
 */
async function build(ROOT) {
  const req = function (rel) {
    return require(path.join(ROOT, rel));
  };
  const errorCodes = req('common/error_codes');
  const rec = recorder(errorCodes);
  const config = req('common/config');
  const realValue = config.value;
  config.value = rec.fn('settings', 'value', realValue);

  // The slots the directory fills at its require, wrapped before it is
  // required so that what it installs is recorded.
  const roles = req('common/roles');
  const adminRbacModule = req('admin-ui/admin_rbac');
  const realRolesSet = roles.setDirectory;
  roles.setDirectory = function (hooks) {
    return realRolesSet(hooks ? rec.object('roles.directory', hooks) : hooks);
  };
  const realRbacSet = adminRbacModule.setDirectory;
  adminRbacModule.setDirectory = function (view) {
    const wrapped = Object.assign({}, view);
    if (typeof view.forRealm === 'function') {
      wrapped.forRealm = function (id) {
        const inner = view.forRealm(id);
        return inner ? rec.object('rbac.directory', inner) : inner;
      };
    }
    return realRbacSet(rec.object('rbac.directory', wrapped));
  };
  const ldap = req('ldap/ldap_server');
  const applications = req('common/applications');
  const audit = req('common/audit');
  const helpers = req('common/helpers');

  // A fixed population, made before anything is recorded.
  ['dora', 'emil'].forEach(function (name) {
    ldap.createUser(name, { origin: 'seed', note: 'vectors', invent: false,
                            attributes: {} });
  });
  ldap.createGroup('g-staff', { origin: 'seed', members: ['dora'] });
  applications.createApplication({
    identifier: 'app-res', protocols: ['oauth2'],
    fields: { oauthPermissionBaseUri: 'https://api.example',
              oauthPermission: ['write|Write things', 'read'],
              oauthRoleGatedPermission: ['write'] } });
  applications.createApplication({
    identifier: 'app-cli', protocols: ['oauth2'],
    fields: { oauthScope: ['openid'] } });

  const steps = [];
  const auditPort = rec.object('audit', audit,
                               ['audit', 'record', 'failure']);
  const appsPort = rec.object('applications', applications);
  const AdminActions = req('admin-core/admin_actions').AdminActions;
  const AdminRbac = adminRbacModule.AdminRbac;
  const bootstrapName = req('common/bootstrap_name');
  bootstrapName.current = rec.fn('bootstrap', 'current',
                                 bootstrapName.current.bind(bootstrapName));
  const rbac = new AdminRbac(Object.assign(AdminRbac.defaultDeps(),
    { audit: auditPort,
      mode: rec.object('mode', req('common/mode')) }));
  const actions = new AdminActions(Object.assign(AdminActions.defaultDeps(),
    { auditLog: auditPort, applications: appsPort, roles: roles,
      rbac: rbac }));

  // ---- the role register (common/roles.js, rule 3u) -------------------
  const role = function (op, input, run) {
    rec.step(steps, 'roles', op, input, run);
  };
  ['', 'EVERYBODY', 'bad/name', 'ok name', 'x'.repeat(65), ' padded ']
    .forEach(function (name) {
      role('checkName', { name: name }, function () {
        return { problem: roles.checkName(name) };
      });
    });
  const write = function (name, record) {
    role('write', { name: name, record: record }, function () {
      return roles.write(name, record);
    });
  };
  write('staff', { description: 'The staff', users: ['dora'],
                   groups: ['g-staff'], displayName: ' Staff ' });
  write('bad/name', {});
  write('reader@app-res', { application: 'app-res' });
  write('reader', { application: 'app-res' });
  write('EVERYBODY@app-res', { application: 'app-res' });
  write('ADMIN_READ', { users: ['dora'] });
  write('robots', { memberTypes: 'robot user' });
  write('ADMIN_READ', { memberTypes: ['user'] });
  write('apps-only', { memberTypes: ['application'], users: ['dora'] });
  write('ADMIN_WRITE', { conferredBy: ['app-cli'] });
  write('apps-conf', { memberTypes: ['application'],
                       conferredBy: ['app-cli'] });
  write('nul-desc', { description: 'a\u0000b' });
  write('code-desc', { description: 'see STS-ADMIN-0001' });
  write('apps', { memberTypes: 'application, USER', applications: ['app-cli'],
                  permissions: ['https://api.example/write'],
                  conferredBy: ['app-cli', 'app-cli', ' '] });
  role('read', { name: 'staff' }, function () {
    return roles.read('staff');
  });
  role('read', { name: 'nosuch' }, function () {
    return roles.read('nosuch');
  });
  role('all', {}, function () {
    return roles.all();
  });
  role('catalogue', {}, function () {
    return roles.catalogue();
  });
  const owner = function (op, name, who) {
    role(op, { name: name, owner: who }, function () {
      return op === 'addOwner' ? roles.addOwner(name, who)
        : roles.removeOwner(name, who);
    });
  };
  owner('addOwner', 'nosuch', 'dora');
  owner('addOwner', 'staff', '');
  owner('addOwner', 'staff', 'nobody-at-all');
  owner('addOwner', 'staff', 'dora');
  owner('addOwner', 'staff', 'dora');
  owner('addOwner', 'staff', 'g-staff');
  owner('removeOwner', 'staff', 'emil');
  owner('removeOwner', 'nosuch', 'emil');
  role('setOwnerProtected', { name: 'staff', flag: true }, function () {
    return roles.setOwnerProtected('staff', true);
  });
  role('setOwnerProtected', { name: 'staff', flag: true }, function () {
    return roles.setOwnerProtected('staff', true);
  });
  role('setOwnerProtected', { name: 'nosuch', flag: true }, function () {
    return roles.setOwnerProtected('nosuch', true);
  });
  role('seedNativeRoles', {}, function () {
    return { made: roles.seedNativeRoles() };
  });
  ['admin:read', 'https://api.example/write', 'nothing'].forEach(function (p) {
    role('rolesAuthorizing', { permission: p }, function () {
      return roles.rolesAuthorizing(p);
    });
  });
  ['sts-admin-console', 'app-cli', ''].forEach(function (c) {
    role('conferredBy', { clientId: c }, function () {
      return roles.conferredBy(c);
    });
  });
  const contexts = [
    { kind: 'user', name: 'dora', authenticated: true },
    { kind: 'user', name: 'dora', authenticated: false },
    { kind: 'user', name: 'emil', authenticated: true,
      groups: ['g-staff', 'remote-peps'] },
    { kind: 'application', name: 'app-cli', authenticated: true },
    { kind: 'application', name: 'APP-CLI' },
    { kind: 'user', name: 'dora', authenticated: true, ids: true },
    { kind: 'user', name: 'dora', authenticated: true,
      application: 'app-res' },
    { kind: 'user', name: 'x', crossRealm: true, sids: ['g-staff'] },
    { kind: 'user', name: 'dora', authenticated: true, owns: true },
    {}
  ];
  contexts.forEach(function (who) {
    role('rolesOf', { who: who }, function () {
      return roles.rolesOf(who);
    });
    role('claimFor', { who: who }, function () {
      return roles.claimFor(who);
    });
  });
  [{ roles: ['a', ' b '] }, { roles: 'a, b  c' }, { roles: 7 }, {}, null,
   { roles: null }].forEach(function (claims) {
    role('rolesInClaims', { claims: claims }, function () {
      return roles.rolesInClaims(claims);
    });
  });

  // ---- the role actions (admin-core/admin_actions.ts rolesAction) -----
  const act = function (body) {
    rec.step(steps, 'roleActions', 'rolesAction', { body: body }, function () {
      return actions.rolesAction(body, { actor: 'vectors' });
    });
  };
  act({ action: 'create-role', role: 'a@b' });
  act({ action: 'create-role', role: 'r', application: 'nosuch-app' });
  act({ action: 'create-role', role: 'staff' });
  act({ action: 'create-role', role: 'bad/name' });
  act({ action: 'create-role', role: 'editors', description: 'Edit',
        displayName: 'Editors', memberTypes: 'user' });
  act({ action: 'create-role', role: 'viewer', application: 'app-res' });
  act({ action: 'describe-role', role: 'nosuch' });
  act({ action: 'describe-role', role: 'editors', description: 'New',
        memberTypes: [] });
  act({ action: 'add-member', role: 'editors', kind: 'robot',
        member: 'x' });
  act({ action: 'add-member', role: 'editors', kind: 'user' });
  act({ action: 'add-member', role: 'EVERYBODY', kind: 'user',
        member: 'dora' });
  act({ action: 'add-member', role: 'nosuch', kind: 'user',
        member: 'dora' });
  act({ action: 'add-member', role: 'editors', kind: 'user',
        member: 'dora' });
  act({ action: 'add-member', role: 'editors', kind: 'user',
        member: 'DORA' });
  act({ action: 'add-member', role: 'editors', kind: 'application',
        member: 'app-cli' });
  act({ action: 'remove-member', role: 'editors', kind: 'group',
        member: 'g-staff' });
  act({ action: 'remove-member', role: 'editors', kind: 'user',
        member: 'Dora' });
  act({ action: 'add-permission', role: 'nosuch' });
  act({ action: 'add-permission', role: 'EVERYBODY' });
  act({ action: 'add-permission', role: 'ADMIN_READ',
        permission: 'x' });
  act({ action: 'add-permission', role: 'editors' });
  act({ action: 'add-permission', role: 'editors',
        permission: 'admin:write' });
  act({ action: 'add-permission', role: 'editors',
        permission: 'https://nowhere.example/x' });
  act({ action: 'add-permission', role: 'editors',
        permission: 'https://api.example/write' });
  act({ action: 'add-permission', role: 'editors',
        permission: 'https://api.example/write' });
  act({ action: 'add-permission', role: 'editors',
        permission: 'https://api.example/read' });
  act({ action: 'remove-permission', role: 'editors',
        permission: 'https://api.example/nope' });
  act({ action: 'remove-permission', role: 'editors',
        permission: 'https://api.example/read' });
  act({ action: 'add-conferring-client', role: 'nosuch', client: 'app-cli' });
  act({ action: 'add-conferring-client', role: 'editors' });
  act({ action: 'add-conferring-client', role: 'editors',
        client: 'nosuch-app' });
  act({ action: 'add-conferring-client', role: 'editors', client: 'app-cli' });
  act({ action: 'add-conferring-client', role: 'editors', client: 'app-cli' });
  act({ action: 'remove-conferring-client', role: 'editors',
        client: 'app-res' });
  act({ action: 'remove-conferring-client', role: 'editors',
        client: 'app-cli' });
  act({ action: 'add-owner', role: 'editors', owner: 'emil' });
  act({ action: 'add-owner', role: 'editors', owner: 'emil' });
  act({ action: 'add-owner', role: 'editors', owner: '' });
  act({ action: 'remove-owner', role: 'editors', owner: 'nobody' });
  act({ action: 'remove-owner', role: 'editors', owner: 'emil' });
  act({ action: 'delete-role', role: 'EVERYBODY' });
  act({ action: 'delete-role', role: 'SSF_READ' });
  act({ action: 'delete-role', role: 'nosuch' });
  act({ action: 'delete-role', role: 'editors' });
  act({ action: 'bogus' });

  // ---- the console roster (admin-ui/admin_rbac.ts, rbac/grant) --------
  const grant = function (body) {
    rec.step(steps, 'rbac', 'rbacAction', { body: body }, function () {
      return actions.rbacAction(body, { actor: 'vectors', via: 'api' });
    });
  };
  grant({ action: 'grant', username: 'dora', role: 'nosuch' });
  grant({ action: 'grant', username: '', role: 'read' });
  grant({ action: 'grant', username: 'a,b', role: 'read' });
  grant({ action: 'grant', username: 'nobody-here', role: 'read' });
  grant({ action: 'grant', username: 'dora', role: 'READ' });
  grant({ action: 'grant', username: 'dora', role: 'read' });
  grant({ action: 'grant', username: 'emil', role: 'security' });
  grant({ action: 'revoke', username: '', role: 'read' });
  grant({ action: 'revoke', username: 'dora', role: 'nosuch' });
  grant({ action: 'revoke', username: 'emil', role: 'read' });
  grant({ action: 'revoke', username: 'dora', role: 'read' });
  grant({ action: 'revoke', username: 'emil', role: 'security' });
  grant({ action: 'promote' });

  config.value = realValue;
  void helpers;
  return { steps: steps };
}

module.exports = { build: build, recorder: recorder, clone: clone };
