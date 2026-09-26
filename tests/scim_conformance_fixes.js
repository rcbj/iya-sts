'use strict';
//
// File: tests/scim_conformance_fixes.js
//
// ---------------------------------------------------------------------------
// THE REGRESSION CHECKS FOR WHAT THE TWO SCIM HARNESSES FOUND (#206).
//
// tests/vendored/sts_scim_conformance.js runs python-scim's scim2-tester and
// scim2/test-suite against a running service; this holds each defect they
// found, in process and over HTTP to /scim/v2 of the default realm, so that a
// change to scim/ that brings one back fails `npm test` without either
// harness installed. One check per fix, named for what it holds:
//
//   S. the published schemas say what the directory holds (no nickName,
//      roles …, no members.display, the canonical types), and `schemas` is
//      returned under `?attributes=`;
//   M. a manager goes out as an id with a $ref, never as a DN;
//   G. a Group member has a $ref and no DN `display`, and a removed
//      `members` is left out rather than sent as [];
//   D. a duplicate email is stored once; a `home` email is refused;
//      `primary` is not invented;
//   F. a filter ignores case where the attribute does, and ordering a
//      boolean is refused invalidFilter (STS-SCIM-0082);
//   P. If-Match on a write is 412 (STS-SCIM-0081) and `*` is not;
//   U. an unknown path under /scim/v2 is a SCIM 404 (STS-SCIM-0080);
//   X. a PATCH on a whole extension: a value naming its own schema, and a
//      remove of every attribute;
//   I. scim.inventOnCreate: on, a development-mode create is filled in;
//      off, it holds only what was sent.
//
// A CHILD PROCESS, as tests/stable_subject.js runs one: the protocol stack
// and a listener are loaded once, fresh, and nothing leaks into the runner.
// ---------------------------------------------------------------------------

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'scim_conformance_fixes',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The child's whole program, serialised with toString() and run by `node -e`
// — so it may use nothing from this file's scope, and (root CLAUDE.md, Code
// style) it is exempt from the Entering/Leaving rule and carries its errors
// on the result it writes.
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.SC_ROOT;
  const OUT = process.env.SC_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      const body = o.json !== undefined ? JSON.stringify(o.json) : '';
      const headers = Object.assign({}, o.headers || {});
      if (o.json !== undefined) {
        headers['content-type'] = 'application/scim+json';
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let text = '';
        res.on('data', function (c) {
          text += c;
        });
        res.on('end', function () {
          let parsed = null;
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            parsed = { parseError: e.message };
          }
          resolve({ status: res.statusCode, text: text, json: parsed,
                    type: String(res.headers['content-type'] || '') });
        });
      });
      req.end(body);
    });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const audit = require(ROOT + '/common/audit');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const USER = 'urn:ietf:params:scim:schemas:core:2.0:User';
    const GROUP = 'urn:ietf:params:scim:schemas:core:2.0:Group';
    const ENT = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
    const PATCH = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
    const lastCode = function (target) {
      const row = audit.list().filter(function (event) {
        return String(event.target || '').indexOf(target) >= 0 &&
               event.errorCode;
      })[0];
      return row ? row.errorCode : '';
    };

    await realms.run(realms.DEFAULT_REALM, async function () {
      ldap.createUser('sc-client', { invent: false });
      const auth = { authorization: 'Basic ' +
        Buffer.from('sc-client:whatever').toString('base64') };
      const scim = function (method, p, json, extra) {
        return request(port, method, '/scim/v2' + p, {
          json: json,
          headers: Object.assign({}, auth, extra || {}) });
      };
      config.setOverride('scim.inventOnCreate', 'false');

      // S. THE SCHEMAS
      let r = await scim('GET', '/Schemas/' + USER);
      const names = ((r.json && r.json.attributes) || []).map(function (a) {
        return a.name;
      });
      const sub = function (attr, name) {
        const one = ((r.json && r.json.attributes) || []).filter(function (a) {
          return a.name === attr;
        })[0];
        return one && (one.subAttributes || []).filter(function (a) {
          return a.name === name;
        })[0];
      };
      note(names.indexOf('userName') >= 0 &&
           ['nickName', 'locale', 'timezone', 'ims', 'photos', 'roles',
            'entitlements', 'x509Certificates'].every(function (n) {
             return names.indexOf(n) < 0;
           }),
           'S1. /Schemas lists no User attribute the directory cannot hold',
           names.join(','));
      const emailType = sub('emails', 'type');
      note(emailType && JSON.stringify(emailType.canonicalValues) ===
           '["work"]' && !sub('emails', 'primary') &&
           !sub('emails', 'display') && !sub('name', 'middleName'),
           'S2. emails.type offers only "work", and no primary, display or ' +
           'middleName is published',
           JSON.stringify(emailType));
      r = await scim('GET', '/Schemas/' + GROUP);
      const members = ((r.json && r.json.attributes) || []).filter(
        function (a) {
          return a.name === 'members';
        })[0];
      note(members && !(members.subAttributes || []).some(function (a) {
        return a.name === 'display';
      }), 'S3. a Group member has no display in /Schemas (RFC 7643 8.7.1)',
      JSON.stringify(members && members.subAttributes.map(function (a) {
        return a.name;
      })));

      // M. THE MANAGER
      r = await scim('POST', '/Users', { schemas: [USER],
                                         userName: 'sc-manager' });
      const managerId = r.json && r.json.id;
      r = await scim('POST', '/Users', { schemas: [USER, ENT],
        userName: 'sc-report', [ENT]: { manager: { value: managerId } } });
      const reportId = r.json && r.json.id;
      const manager = r.json && r.json[ENT] && r.json[ENT].manager;
      note(r.status === 201 && manager && manager.value === managerId &&
           /\/scim\/v2\/Users\//.test(String(manager.$ref)),
           'M1. a manager goes out as the manager\'s id, with a $ref, and ' +
           'never as a DN', r.status + ' ' + JSON.stringify(manager));

      // S4. `schemas` under ?attributes=
      r = await scim('GET', '/Users/' + reportId + '?attributes=userName');
      note(r.status === 200 && Array.isArray(r.json.schemas) &&
           r.json.userName === 'sc-report',
           'S4. ?attributes=userName still returns schemas',
           r.status + ' ' + r.text.slice(0, 200));

      // G. GROUP MEMBERS
      r = await scim('POST', '/Groups', { schemas: [GROUP],
        displayName: 'sc-group', members: [{ value: reportId }] });
      const groupId = r.json && r.json.id;
      const member = r.json && r.json.members && r.json.members[0];
      note(r.status === 201 && member && member.value === reportId &&
           member.display === undefined && member.type === 'User' &&
           /\/scim\/v2\/Users\//.test(String(member.$ref)),
           'G1. a member carries a $ref and no DN display',
           r.status + ' ' + JSON.stringify(member));
      r = await scim('PATCH', '/Groups/' + groupId, { schemas: [PATCH],
        Operations: [{ op: 'remove', path: 'members' }] });
      note(r.status === 200 && r.json && r.json.members === undefined,
           'G2. a removed members is left out, not sent as []',
           r.status + ' ' + r.text.slice(0, 300));

      // D. MULTI-VALUED MEMBERS
      r = await scim('POST', '/Users', { schemas: [USER],
        userName: 'sc-dup', emails: [
          { value: 'dup@example.test', type: 'work' },
          { value: 'DUP@example.test', type: 'work' }],
        phoneNumbers: [{ value: '+1 555 0100', type: 'work',
                         primary: false }] });
      note(r.status === 201 && (r.json.emails || []).length === 1 &&
           r.json.phoneNumbers && r.json.phoneNumbers[0].primary === undefined,
           'D1. a duplicate email is stored once, and primary is not ' +
           'invented', r.status + ' ' + JSON.stringify(r.json &&
             [r.json.emails, r.json.phoneNumbers]));
      r = await scim('POST', '/Users', { schemas: [USER],
        userName: 'sc-home', emails: [{ value: 'h@example.test',
                                        type: 'home' }] });
      note(r.status === 400 && r.json && r.json.scimType === 'invalidValue',
           'D2. an email of a type the directory cannot hold is refused',
           r.status + ' ' + r.text.slice(0, 200));

      // F. FILTERS
      r = await scim('GET', '/Users?filter=' +
        encodeURIComponent('userName eq "SC-REPORT"'));
      note(r.status === 200 && r.json.totalResults === 1,
           'F1. userName (caseExact false) matches without regard to case',
           r.status + ' ' + r.text.slice(0, 200));
      r = await scim('GET', '/Users?filter=' +
        encodeURIComponent('id eq "' + reportId.toUpperCase() + '"'));
      note(r.status === 200 && r.json.totalResults === 0,
           'F2. id (caseExact true) still compares exactly',
           r.status + ' ' + r.text.slice(0, 200));
      r = await scim('GET', '/Users?filter=' +
        encodeURIComponent('active gt true'));
      note(r.status === 400 && r.json.scimType === 'invalidFilter' &&
           lastCode('/scim/v2/Users') === 'STS-SCIM-0082',
           'F3. ordering a boolean is refused invalidFilter, STS-SCIM-0082',
           r.status + ' ' + lastCode('/scim/v2/Users') + ' ' +
           r.text.slice(0, 200));

      // P. IF-MATCH
      r = await scim('PUT', '/Users/' + reportId, { schemas: [USER],
        userName: 'sc-report' }, { 'if-match': 'W/"1"' });
      note(r.status === 412 && lastCode('/scim/v2/Users/') ===
           'STS-SCIM-0081',
           'P1. If-Match on a write is 412, STS-SCIM-0081',
           r.status + ' ' + lastCode('/scim/v2/Users/'));
      r = await scim('PUT', '/Users/' + reportId, { schemas: [USER],
        userName: 'sc-report' }, { 'if-match': '*' });
      note(r.status === 200, 'P2. If-Match: * is performed', r.status);

      // U. UNKNOWN PATHS
      r = await scim('GET', '/NoSuchThing');
      note(r.status === 404 && /scim\+json/.test(r.type) && r.json &&
           Array.isArray(r.json.schemas) &&
           lastCode('/scim/v2/NoSuchThing') === 'STS-SCIM-0080',
           'U1. an unknown path under /scim/v2 is a SCIM 404, STS-SCIM-0080',
           r.status + ' ' + r.type + ' ' + r.text.slice(0, 120));

      // X. WHOLE-EXTENSION PATCH
      r = await scim('PATCH', '/Users/' + reportId, { schemas: [PATCH],
        Operations: [{ op: 'add', path: ENT, value: { schemas: [ENT],
          employeeNumber: '42' } }] });
      note(r.status === 200 && r.json[ENT] &&
           r.json[ENT].employeeNumber === '42',
           'X1. an extension value naming its own schema is applied',
           r.status + ' ' + r.text.slice(0, 200));
      r = await scim('PATCH', '/Users/' + reportId, { schemas: [PATCH],
        Operations: [{ op: 'remove', path: ENT }] });
      note(r.status === 200 && r.json[ENT] === undefined,
           'X2. removing a whole extension removes every attribute of it',
           r.status + ' ' + r.text.slice(0, 200));

      // I. scim.inventOnCreate
      r = await scim('POST', '/Users', { schemas: [USER],
                                         userName: 'sc-plain' });
      note(r.status === 201 && r.json.emails === undefined &&
           r.json.name === undefined,
           'I1. off, a create holds only what was sent',
           r.status + ' ' + r.text.slice(0, 200));
      config.setOverride('scim.inventOnCreate', 'true');
      r = await scim('POST', '/Users', { schemas: [USER],
                                         userName: 'sc-invented' });
      note(r.status === 201 && Array.isArray(r.json.emails),
           'I2. on (the default), a development-mode create is filled in',
           r.status + ' ' + r.text.slice(0, 200));
    });
    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify({ findings: findings }));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify({ findings: findings }));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'scim-conformance-fixes-' +
                        process.pid + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|SCIM_|OAUTH2_|LDAP_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', SC_ROOT: ROOT, SC_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
    });
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    report = null;
  }
  if (t.check(!!report, 'the child process reported',
              'exit ' + result.status + ' ' +
              String(result.stderr || '').slice(-800))) {
    report.findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'scim_conformance_fixes',
  describe: 'what the SCIM conformance harnesses found (#206): the published ' +
            'schemas, the manager id, member $ref, duplicates and canonical ' +
            'types, case-insensitive filters and invalidFilter, If-Match ' +
            '412, the SCIM 404, whole-extension PATCH, scim.inventOnCreate',
  run: run
};
