// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/scim_realm_schema.js
//
// ---------------------------------------------------------------------------
// WHAT /Schemas SAYS OF ONE REALM (#699), over HTTP to /scim/v2 of three
// realms in one process: a product realm with an attribute policy and three
// custom attributes, a development realm with one custom attribute of its
// own, and the default realm.
//
//   S. THE DOCUMENTS. In the product realm /Schemas marks `required` from
//      the policy: `name` and `name.familyName` (sn, always), `name.givenName`,
//      `emails`, `phoneNumbers` with a note naming the type, and the custom
//      attribute it requires; `displayName` (cn, derived) is not marked; a
//      required attribute no SCIM member carries is named in the User
//      schema's description; the CustomAttributes extension lists the
//      realm's attributes with their types; /ResourceTypes marks that
//      extension required. The development realm and the default realm
//      mark nothing, and neither sees another realm's custom attributes.
//   W. THE WRITES, in the product realm. A create without a required custom
//      value is refused (STS-LDAP-0162); a value its syntax refuses is
//      400 invalidValue (STS-SCIM-0087); a complete create stores each
//      value in the directory in its normal form and answers it back; a PUT
//      that leaves the extension out leaves the values alone; a PATCH
//      replaces one and removes another; a PUT that names the extension
//      replaces every value; a PUT taking a required one away is refused
//      (STS-LDAP-0164); a filter on a custom attribute finds the person.
//   D. The development realm takes a custom value with nothing required.
//
// A CHILD PROCESS, as tests/scim_conformance_fixes.js runs one: the protocol
// stack and a listener are loaded once, fresh, and nothing leaks into the
// runner.
// ---------------------------------------------------------------------------

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'scim_realm_schema',
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
  const crypto = require('crypto');
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
          resolve({ status: res.statusCode, text: text, json: parsed });
        });
      });
      req.end(body);
    });
  }
  const find = function (list, name) {
    return (list || []).filter(function (one) {
      return String(one && one.name).toLowerCase() === name.toLowerCase();
    })[0] || null;
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const realms = require(ROOT + '/common/realms');
    const audit = require(ROOT + '/common/audit');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const credentials = require(ROOT + '/common/credentials');
    const attributePolicy = require(ROOT + '/common/attribute_policy');
    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const USER = 'urn:ietf:params:scim:schemas:core:2.0:User';
    const CUSTOM =
      'urn:ietf:params:scim:schemas:extension:iya-sts:2.0:CustomAttributes';
    const PATCH = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
    const tag = crypto.randomBytes(3).toString('hex');
    const made = [];
    const coded = function (code) {
      return audit.list().some(function (event) {
        return event.errorCode === code;
      });
    };
    try {
      const product = realms.create({ id: 'srsp-' + tag, name: 'srsp-' + tag,
        description: 'Created by tests/scim_realm_schema.js',
        overrides: { 'global.mode': 'product' } });
      const dev = realms.create({ id: 'srsd-' + tag, name: 'srsd-' + tag,
        description: 'Created by tests/scim_realm_schema.js' });
      made.push(product.realm ? product.realm.id : '',
                dev.realm ? dev.realm.id : '');
      note(product.ok !== false && dev.ok !== false,
           'precondition: two realms were made',
           JSON.stringify([product.errors, dev.errors]));
      const P = '/realm/' + product.realm.id + '/scim/v2';
      const D = '/realm/' + dev.realm.id + '/scim/v2';

      // THE PRODUCT REALM'S CALLER, its policy and its three attributes.
      const PASSWORD = 'Srs-' + crypto.randomBytes(6).toString('hex') +
                       '-Correct.Horse.Battery.Staple.42';
      let auth = {};
      await realms.run(product.realm, async function () {
        ldap.createUser('srs-client', { invent: false,
          attributes: { givenName: ['Srs'], sn: ['Client'],
                        mail: ['srs-client@example.test'] } });
        const set = credentials.setPassword('srs-client', PASSWORD);
        note(set && set.ok !== false,
             'precondition: the caller has a password', JSON.stringify(set));
        auth = { authorization: 'Basic ' +
          Buffer.from('srs-client:' + PASSWORD).toString('base64') };
        const defined = [
          attributePolicy.define({ name: 'costCentreCode', label: 'Cost ' +
            'centre', syntax: 'integer', description: 'Finance\'s code.' }),
          attributePolicy.define({ name: 'badgeIds', label: 'Badges',
                                   syntax: 'string', multiValued: true }),
          attributePolicy.define({ name: 'hiredOn', label: 'Hired on',
                                   syntax: 'date' })];
        note(defined.every(function (one) {
          return one && one.ok;
        }), 'precondition: three custom attributes are defined',
             JSON.stringify(defined.map(function (one) {
               return one.errors || one.ok;
             })));
        const saved = attributePolicy.save('default', { requiredAttributes:
          ['givenName', 'mail', 'telephoneNumber', 'roomNumber',
           'costCentreCode'] });
        note(saved && saved.ok,
             'precondition: the policy requires givenName, mail, ' +
             'telephoneNumber, roomNumber and costCentreCode',
             JSON.stringify(saved && (saved.errors || saved.ok)));
      });
      await realms.run(dev.realm, async function () {
        const one = attributePolicy.define({ name: 'deskCode',
                                            label: 'Desk', syntax: 'string' });
        note(one && one.ok, 'precondition: the development realm defines ' +
             'deskCode', JSON.stringify(one && (one.errors || one.ok)));
      });
      const scim = function (base, method, p, json) {
        return request(port, method, base + p,
                       { json: json, headers: auth });
      };

      // S. THE DOCUMENTS
      let r = await scim(P, 'GET', '/Schemas/' + USER);
      const at = (r.json && r.json.attributes) || [];
      const name = find(at, 'name');
      const sub = function (n) {
        return find(name && name.subAttributes, n);
      };
      note(r.status === 200 && name && name.required === true &&
           sub('familyName') && sub('familyName').required === true &&
           sub('givenName') && sub('givenName').required === true &&
           sub('formatted') && sub('formatted').required !== true,
           'S1. the product realm marks name, name.familyName and ' +
           'name.givenName required, and not name.formatted',
           r.status + ' ' + JSON.stringify(name));
      const emails = find(at, 'emails');
      const phones = find(at, 'phoneNumbers');
      note(emails && emails.required === true && phones &&
           phones.required === true &&
           /type "work" \(telephoneNumber\)/.test(phones.description),
           'S2. emails and phoneNumbers are required, and phoneNumbers ' +
           'says which type',
           JSON.stringify([emails && emails.required,
                           phones && phones.description]));
      note(find(at, 'displayName') &&
           find(at, 'displayName').required !== true &&
           find(at, 'userName').required === true,
           'S3. displayName (cn, derived) is not marked, and userName stays ' +
           'required', JSON.stringify(find(at, 'displayName')));
      note(/also requires roomNumber, which no SCIM member carries/
             .test(String(r.json && r.json.description)),
           'S4. a required attribute no SCIM member carries is named in ' +
           'the User schema\'s description', r.json && r.json.description);
      r = await scim(P, 'GET', '/Schemas');
      const custom = ((r.json && r.json.Resources) || []).filter(
        function (one) {
          return one.id === CUSTOM;
        })[0];
      const cc = find(custom && custom.attributes, 'costCentreCode');
      const badges = find(custom && custom.attributes, 'badgeIds');
      const hired = find(custom && custom.attributes, 'hiredOn');
      note(r.status === 200 && custom && cc && cc.type === 'integer' &&
           cc.required === true && badges && badges.multiValued === true &&
           badges.type === 'string' && hired && hired.required !== true &&
           !find(custom.attributes, 'deskCode'),
           'S5. /Schemas lists the CustomAttributes extension with the ' +
           'realm\'s three attributes, typed, the required one marked, ' +
           'and not another realm\'s',
           r.status + ' ' + JSON.stringify(custom));
      r = await scim(P, 'GET', '/ResourceTypes/User');
      const ext = ((r.json && r.json.schemaExtensions) || []).filter(
        function (one) {
          return one.schema === CUSTOM;
        })[0];
      note(r.status === 200 && ext && ext.required === true,
           'S6. /ResourceTypes marks the extension required where a ' +
           'custom attribute is', r.status + ' ' + JSON.stringify(ext));
      r = await scim(D, 'GET', '/Schemas/' + USER);
      const dname = find(r.json && r.json.attributes, 'name');
      note(r.status === 200 && dname && dname.required !== true &&
           find(dname.subAttributes, 'familyName').required !== true &&
           find(r.json.attributes, 'emails').required !== true,
           'S7. the development realm marks nothing: its policy is not ' +
           'enforced', JSON.stringify(dname));
      r = await scim(D, 'GET', '/Schemas/' + CUSTOM);
      note(r.status === 200 &&
           (r.json.attributes || []).map(function (one) {
             return one.name;
           }).join(',') === 'deskCode',
           'S8. the development realm\'s extension is its own deskCode',
           r.status + ' ' + JSON.stringify(r.json && r.json.attributes));
      r = await request(port, 'GET', '/scim/v2/Schemas/' + CUSTOM, {});
      note(r.status === 200 && Array.isArray(r.json.attributes) &&
           r.json.attributes.length === 0,
           'S9. the default realm defines none, and sees no other realm\'s',
           r.status + ' ' + JSON.stringify(r.json && r.json.attributes));
      r = await request(port, 'GET', '/scim/v2/ResourceTypes/User', {});
      const dext = ((r.json && r.json.schemaExtensions) || []).filter(
        function (one) {
          return one.schema === CUSTOM;
        })[0];
      note(r.status === 200 && dext && dext.required === false,
           'S10. the default realm\'s User type lists the extension, not ' +
           'required', JSON.stringify(dext));

      // W. THE WRITES, under a policy SCIM can meet: roomNumber, which no
      // SCIM member carries (S4), would refuse every create.
      await realms.run(product.realm, async function () {
        const saved = attributePolicy.save('default', { requiredAttributes:
          ['givenName', 'mail', 'telephoneNumber', 'costCentreCode'] });
        note(saved && saved.ok, 'precondition: the policy no longer ' +
             'requires roomNumber', JSON.stringify(saved && saved.errors));
      });
      const person = function (userName, extra) {
        return Object.assign({
          schemas: [USER, CUSTOM], userName: userName,
          name: { givenName: 'Wanda', familyName: 'Writer' },
          emails: [{ value: userName + '@example.test', type: 'work' }],
          phoneNumbers: [{ value: '+46 8 123 456', type: 'work' }]
        }, extra || {});
      };
      r = await scim(P, 'POST', '/Users', person('srs-wanda'));
      note(r.status === 400 && r.json.scimType === 'invalidValue' &&
           /costCentreCode/.test(String(r.json.detail)),
           'W1. a create without the required custom value is refused',
           r.status + ' ' + r.text.slice(0, 300));
      r = await scim(P, 'POST', '/Users', person('srs-wanda', {
        [CUSTOM]: { costCentreCode: 42, hiredOn: '2026-13-45' } }));
      let refusedCode = false;
      await realms.run(product.realm, async function () {
        refusedCode = coded('STS-SCIM-0087');
      });
      note(r.status === 400 && r.json.scimType === 'invalidValue' &&
           /hiredOn/.test(String(r.json.detail)) && refusedCode,
           'W2. a date its syntax refuses is 400 invalidValue ' +
           '(STS-SCIM-0087), and nobody is created',
           r.status + ' ' + r.text.slice(0, 300) + ' coded=' + refusedCode);
      r = await scim(P, 'POST', '/Users', person('srs-wanda', {
        [CUSTOM]: { costCentreCode: 42, badgeIds: ['b-1', 'b-2'],
                    hiredOn: '2026-01-31' } }));
      const id = r.json && r.json.id;
      const back = r.json && r.json[CUSTOM];
      note(r.status === 201 && back && back.costCentreCode === 42 &&
           JSON.stringify(back.badgeIds) === '["b-1","b-2"]' &&
           back.hiredOn === '2026-01-31' &&
           (r.json.schemas || []).indexOf(CUSTOM) >= 0,
           'W3. a complete create answers each custom value back',
           r.status + ' ' + r.text.slice(0, 400));
      const stored = async function () {
        let attrs = {};
        await realms.run(product.realm, async function () {
          const view = ldap.objectFor('srs-wanda');
          const raw = (view && view.entry && view.entry.attributes) || {};
          Object.keys(raw).forEach(function (key) {
            attrs[key.toLowerCase()] = [].concat(raw[key]).map(String);
          });
        });
        return attrs;
      };
      let held = await stored();
      note(JSON.stringify(held.costcentrecode) === '["42"]' &&
           JSON.stringify(held.hiredon) === '["20260131"]' &&
           (held.badgeids || []).length === 2,
           'W4. the directory holds each value in its normal form ' +
           '(the date as YYYYMMDD)',
           JSON.stringify([held.costcentrecode, held.hiredon,
                           held.badgeids]));
      r = await scim(P, 'PUT', '/Users/' + id, person('srs-wanda',
        { schemas: [USER] }));
      held = await stored();
      note(r.status === 200 && JSON.stringify(held.costcentrecode) ===
             '["42"]' && (held.badgeids || []).length === 2,
           'W5. a PUT that leaves the extension out leaves the values alone',
           r.status + ' ' + JSON.stringify([held.costcentrecode,
                                            held.badgeids]));
      r = await scim(P, 'PATCH', '/Users/' + id, { schemas: [PATCH],
        Operations: [
          { op: 'replace', path: CUSTOM + ':costCentreCode', value: 7 },
          { op: 'remove', path: CUSTOM + ':badgeIds' }] });
      held = await stored();
      note(r.status === 200 && JSON.stringify(held.costcentrecode) ===
             '["7"]' && !(held.badgeids || []).length &&
           JSON.stringify(held.hiredon) === '["20260131"]',
           'W6. a PATCH replaces one value and removes another, and leaves ' +
           'the third', r.status + ' ' + r.text.slice(0, 300) + ' ' +
           JSON.stringify([held.costcentrecode, held.badgeids,
                           held.hiredon]));
      r = await scim(P, 'PUT', '/Users/' + id, person('srs-wanda', {
        [CUSTOM]: { costCentreCode: 9 } }));
      held = await stored();
      note(r.status === 200 && JSON.stringify(held.costcentrecode) ===
             '["9"]' && !(held.hiredon || []).length,
           'W7. a PUT that names the extension replaces every value',
           r.status + ' ' + JSON.stringify([held.costcentrecode,
                                            held.hiredon]));
      r = await scim(P, 'PUT', '/Users/' + id, person('srs-wanda', {
        [CUSTOM]: { badgeIds: ['b-3'] } }));
      held = await stored();
      note(r.status === 400 && r.json.scimType === 'invalidValue' &&
           JSON.stringify(held.costcentrecode) === '["9"]',
           'W8. a PUT taking the required custom value away is refused, ' +
           'and nothing changes', r.status + ' ' + r.text.slice(0, 300));
      r = await scim(P, 'GET', '/Users?filter=' + encodeURIComponent(
        CUSTOM + ':costCentreCode eq 9'));
      note(r.status === 200 && r.json.totalResults === 1 &&
           r.json.Resources[0].userName === 'srs-wanda',
           'W9. a filter on a custom attribute finds the person',
           r.status + ' ' + r.text.slice(0, 300));

      // D. THE DEVELOPMENT REALM
      r = await scim(D, 'POST', '/Users', { schemas: [USER, CUSTOM],
        userName: 'srs-dee', [CUSTOM]: { deskCode: 'D-12' } });
      note(r.status === 201 && r.json[CUSTOM] &&
           r.json[CUSTOM].deskCode === 'D-12',
           'D1. the development realm takes a custom value, with nothing ' +
           'else required', r.status + ' ' + r.text.slice(0, 300));
    } finally {
      made.filter(Boolean).forEach(function (one) {
        realms.remove(one);
      });
    }
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
  const out = path.join(os.tmpdir(), 'scim-realm-schema-' +
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
  name: 'scim_realm_schema',
  describe: 'SCIM /Schemas per realm (#699): required attributes from the ' +
            'realm\'s attribute policy, and its custom attributes as the ' +
            'CustomAttributes extension, read and written',
  run: run
};
