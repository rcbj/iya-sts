// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/scim_model_wire.js
//
// ---------------------------------------------------------------------------
// WHAT /scim/v2 ANSWERS, HELD BYTE FOR BYTE (#1579 item 6).
//
// SCIM's schemas, resource types and attribute mapping are generated from
// `models/scim/scim.tsp` since #1579. Before the switch they were written by
// hand in `scim/scim_map.ts` and `scim/scim.ts`, over scimmy's own
// definitions, and the switch was to change NOTHING a client sees. So this
// records what the hand-written version answered, in
// `tests/scim_model_wire.snapshot.json`, and holds every later build to it:
//
//   D. every published definition, attribute by attribute: what /Schemas
//      draws (scimmy's toJSON()) and what the coercion reads besides
//      (`direction`, `shadow`), the common attributes included;
//   M. the mapping as the console and /admin-api publish it, the schema
//      URNs and the scimmap prose;
//   C. the four conversions, entry to resource and back, on fixed inputs;
//   W. a scripted conversation with /scim/v2 over HTTP: discovery, a full
//      User and Group through create, read, filter, PUT, PATCH and delete,
//      and the refusals (each status, scimType and detail).
//
// Values that differ from run to run (an entryUUID, an instant, a port, an
// ETag) are replaced by a placeholder, an entryUUID's numbered in order of
// appearance, so the comparison is of everything else, exactly.
//
// `SCIM_WIRE_PRINT=1 node tests/scim_model_wire.js` prints the snapshot
// instead of comparing it; that is how the file was written, from the image
// of the tree before the switch, and how it is rewritten when the wire is
// MEANT to change.
//
// A CHILD PROCESS, as tests/scim_conformance_fixes.js runs one: the protocol
// stack and a listener are loaded once, fresh, and nothing leaks into the
// runner.
// ---------------------------------------------------------------------------

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'scim_model_wire',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const SNAPSHOT = path.join(__dirname, 'scim_model_wire.snapshot.json');

// The child's whole program, serialised with toString() and run by `node -e`
// — so it may use nothing from this file's scope, and (root CLAUDE.md, Code
// style) it is exempt from the Entering/Leaving rule and carries its errors
// on the result it writes.
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.SC_ROOT;
  const OUT = process.env.SC_OUT;
  const http = require('http');
  const record = { definitions: [], mapping: null, conversions: {},
                   wire: [], problems: [] };

  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      const body = o.raw !== undefined ? o.raw
        : (o.json !== undefined ? JSON.stringify(o.json) : '');
      const headers = Object.assign({}, o.headers || {});
      if (o.raw !== undefined || o.json !== undefined) {
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
            parsed = text ? JSON.parse(text) : null;
          } catch (e) {
            parsed = { unparsed: text };
          }
          resolve({ status: res.statusCode, json: parsed,
                    type: String(res.headers['content-type'] || ''),
                    location: res.headers.location || null,
                    etag: res.headers.etag || null });
        });
      });
      req.end(body);
    });
  }

  // One attribute of a definition, as /Schemas draws it and as the
  // coercion reads it.
  function attributeOf(attribute) {
    if (!attribute || typeof attribute.toJSON !== 'function') {
      return { extension: attribute && attribute.id,
               required: attribute && attribute.required };
    }
    const drawn = JSON.parse(JSON.stringify(attribute));
    delete drawn.subAttributes;
    return {
      drawn: drawn,
      direction: attribute.config.direction,
      shadow: attribute.config.shadow === true,
      subAttributes: (attribute.subAttributes || []).map(attributeOf)
    };
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const scimMap = require(ROOT + '/scim/scim_map');
    const SCIMMY = require('scimmy');

    // D. THE DEFINITIONS.
    SCIMMY.Schemas.declared().forEach(function (definition) {
      record.definitions.push({
        id: definition.id, name: definition.name,
        description: definition.description,
        attributes: definition.attributes.map(attributeOf)
      });
    });

    // M. THE MAPPING.
    record.mapping = {
      described: scimMap.describeMapping(),
      urns: [scimMap.USER_SCHEMA, scimMap.GROUP_SCHEMA,
             scimMap.ENTERPRISE_SCHEMA, scimMap.IYA_STS_USER_SCHEMA],
      prose: scimMap.prose()
    };

    // C. THE CONVERSIONS, on fixed inputs.
    const ENT = scimMap.ENTERPRISE_SCHEMA;
    const IYA = scimMap.IYA_STS_USER_SCHEMA;
    const entry = { dn: 'uid=fixed,ou=users,dc=example,dc=com',
      createdAt: '20260101000000Z', modifiedAt: '20260102000000Z',
      attributes: {
        uid: ['fixed'], entryUUID: ['00000000-0000-4000-8000-000000000001'],
        scimExternalId: ['ext-fixed'], cn: ['Fixed Person'], sn: ['Person'],
        givenName: ['Fixed'], displayName: ['Fixie'], title: ['Engineer'],
        schacPersonalTitle: ['Dr'], employeeType: ['Contractor'],
        preferredLanguage: ['en-GB'], labeledURI: ['https://example.com/f'],
        pwdAccountLockedTime: ['000001010000Z'],
        mail: ['f@example.com', 'g@example.com'],
        telephoneNumber: ['+1 555 0100'], mobile: ['+1 555 0101'],
        street: ['1 Main St'], l: ['Town'], st: ['ST'], postalCode: ['12345'],
        c: ['US'], postalAddress: ['1 Main St$Town$US'],
        employeeNumber: ['42'], departmentNumber: ['R&D'], o: ['Org'],
        ou: ['Div'], manager: ['uid=boss,ou=users,dc=example,dc=com'],
        salutation: ['Ms'], birthFamilyName: ['Born'],
        birthGivenName: ['Fixa'], birthMiddleName: ['M'],
        alsoKnownAs: ['Fix'], placeOfBirthCountry: ['US'],
        placeOfBirthRegion: ['CA'], placeOfBirthLocality: ['SF'],
        federationLink: ['rel|iss|sub'], objectClass: ['inetOrgPerson'],
        entryDN: ['uid=fixed,ou=users,dc=example,dc=com'],
        createTimestamp: ['20260101000000Z'],
        modifyTimestamp: ['20260102000000Z'],
        schacDateOfBirth: ['19700101'] } };
    const context = { location: 'https://h/scim/v2/Users/',
      locations: { User: 'https://h/scim/v2/Users/',
                   Group: 'https://h/scim/v2/Groups/' },
      rdnName: 'fixed',
      groups: [{ id: 'g-1', dn: 'cn=g1,ou=groups', cn: 'g1' },
               { dn: 'cn=g2,ou=groups', cn: 'g2' }] };
    const user = scimMap.toScimUser(entry, context);
    record.conversions.toScimUser = user;
    record.conversions.pruned = scimMap.prune(user);
    record.conversions.noUid = scimMap.prune(scimMap.toScimUser(
      { dn: 'cn=cert,ou=users', attributes: {} }, { rdnName: 'cert' }));
    const resource = { schemas: [scimMap.USER_SCHEMA, ENT, IYA],
      userName: ' fixed ', externalId: 'ext-2', displayName: 'New',
      name: { formatted: 'A B', familyName: 'B', givenName: 'A',
              honorificPrefix: 'Sir' },
      title: '', userType: 'Employee', preferredLanguage: 'fr',
      profileUrl: 'https://example.com/n', active: true,
      emails: [{ value: 'x@example.com', type: 'work' },
               { value: 'X@example.com' }, { value: 'h@example.com',
                                             type: 'home' }],
      phoneNumbers: [{ value: '1', type: 'work' }, { value: '2' },
                     { value: '3', type: 'mobile' }],
      addresses: [{ formatted: 'a\nb', streetAddress: 's', locality: 'l',
                    region: 'r', postalCode: 'p', country: 'c',
                    type: 'work' }],
      [ENT]: { employeeNumber: '7', department: 'D', organization: 'O',
               division: 'V', manager: { value: 'uid=m,ou=users' } },
      [IYA]: { salutation: 'Mx', birthFamilyName: 'F', birthGivenName: 'G',
               birthMiddleName: 'H', alsoKnownAs: 'K',
               placeOfBirthCountry: 'FR', placeOfBirthRegion: 'R',
               placeOfBirthLocality: 'L' } };
    record.conversions.fromScimUser = scimMap.fromScimUser(resource,
                                                           entry.attributes);
    record.conversions.fromScimUserCreate = scimMap.fromScimUser(
      { schemas: [scimMap.USER_SCHEMA], active: false }, {});
    record.conversions.fromScimUserUnlock = scimMap.fromScimUser(
      { userName: 'u', active: 'true' },
      { uid: ['u'], pwdAccountLockedTime: ['000001010000Z'] });
    const group = { dn: 'cn=g,ou=groups,dc=example,dc=com',
      attributes: { cn: ['g'],
                    entryUUID: ['00000000-0000-4000-8000-000000000002'],
                    scimExternalId: ['gx'], member: ['uid=a,ou=users'],
                    memberUid: ['b'], objectClass: ['groupOfNames'],
                    createTimestamp: ['20260101000000Z'] } };
    record.conversions.toScimGroup = scimMap.toScimGroup(group, {
      location: 'https://h/scim/v2/Groups/', locations: context.locations,
      members: [{ id: 'm-1', dn: 'uid=a,ou=users', present: true },
                { dn: 'uid=gone,ou=users', present: false },
                { id: 'g-2', dn: 'cn=sub,ou=groups', kind: 'group' }] });
    record.conversions.fromScimGroup = scimMap.fromScimGroup(
      { displayName: ' g2 ', externalId: 'gy',
        members: [{ value: 'uid=a,ou=users' }, { value: ' ' }] },
      group.attributes);
    record.conversions.fromScimGroupEmpty = scimMap.fromScimGroup({}, {});

    // W. THE WIRE.
    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const USER = scimMap.USER_SCHEMA;
    const GROUP = scimMap.GROUP_SCHEMA;
    const PATCH = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
    const SEARCH = 'urn:ietf:params:scim:api:messages:2.0:SearchRequest';

    await realms.run(realms.DEFAULT_REALM, async function () {
      ldap.createUser('wire-client', { invent: false });
      config.setOverride('scim.inventOnCreate', 'false');
      const auth = { authorization: 'Basic ' +
        Buffer.from('wire-client:whatever').toString('base64') };
      const step = async function (name, method, p, opts) {
        const o = opts || {};
        const r = await request(port, method, '/scim/v2' + p, {
          json: o.json, raw: o.raw,
          headers: Object.assign({}, auth, o.headers || {}) });
        record.wire.push({ step: name, method: method, path: p,
                           status: r.status, type: r.type,
                           location: r.location, etag: r.etag,
                           body: r.json });
        return r;
      };

      await step('spc', 'GET', '/ServiceProviderConfig');
      await step('resource types', 'GET', '/ResourceTypes');
      await step('resource type User', 'GET', '/ResourceTypes/User');
      await step('resource type Group', 'GET', '/ResourceTypes/Group');
      await step('resource type unknown', 'GET', '/ResourceTypes/Nope');
      await step('schemas', 'GET', '/Schemas');
      const urns = [USER, GROUP, ENT, IYA,
        'urn:ietf:params:scim:schemas:extension:iya-sts:2.0:CustomAttributes',
        'urn:ietf:params:scim:schemas:core:2.0:Nope'];
      for (let i = 0; i < urns.length; i++) {
        await step('schema ' + urns[i], 'GET', '/Schemas/' + urns[i]);
      }

      let r = await step('create the manager', 'POST', '/Users',
        { json: { schemas: [USER], userName: 'wire-boss',
                  displayName: 'Boss' } });
      const bossId = r.json && r.json.id;
      r = await step('create the full user', 'POST', '/Users', { json: {
        schemas: [USER, ENT, IYA], userName: 'wire-alice',
        externalId: 'ext-1',
        name: { formatted: 'Alice A', familyName: 'A', givenName: 'Alice',
                honorificPrefix: 'Dr', middleName: 'Dropped' },
        displayName: 'Alice', nickName: 'Dropped', title: 'Eng',
        userType: 'Employee', preferredLanguage: 'en',
        profileUrl: 'https://example.com/alice', active: true,
        password: 'not-stored',
        emails: [{ value: 'a@example.com', type: 'work' },
                 { value: 'A@example.com' }, { value: 'b@example.com' }],
        phoneNumbers: [{ value: '+1 555', type: 'work' },
                       { value: '+1 666', type: 'mobile' },
                       { value: '+1 777' }],
        addresses: [{ streetAddress: '1 Main', locality: 'Town',
                      region: 'ST', postalCode: '12345', country: 'US',
                      formatted: '1 Main\nTown', type: 'work' }],
        [ENT]: { employeeNumber: '42', department: 'R&D',
                 organization: 'Org', division: 'Div',
                 manager: { value: bossId } },
        [IYA]: { salutation: 'Ms', birthFamilyName: 'B',
                 birthGivenName: 'Al', birthMiddleName: 'M',
                 alsoKnownAs: 'Ali', placeOfBirthCountry: 'US',
                 placeOfBirthRegion: 'CA', placeOfBirthLocality: 'SF' } } });
      const aliceId = r.json && r.json.id;
      await step('read the user', 'GET', '/Users/' + aliceId);
      await step('read with attributes', 'GET', '/Users/' + aliceId +
                 '?attributes=userName,emails');
      await step('read with excludedAttributes', 'GET', '/Users/' + aliceId +
                 '?excludedAttributes=name,' + ENT);
      await step('filter userName sw', 'GET', '/Users?filter=' +
                 encodeURIComponent('userName sw "wire-"'));
      await step('filter emails.value co', 'GET', '/Users?filter=' +
                 encodeURIComponent('emails.value co "example.com"'));
      await step('filter enterprise', 'GET', '/Users?filter=' +
                 encodeURIComponent(ENT + ':department eq "r&d"'));
      await step('filter manager', 'GET', '/Users?filter=' +
                 encodeURIComponent(ENT + ':manager.value eq "' + bossId +
                                    '"'));
      await step('search', 'POST', '/Users/.search', { json: {
        schemas: [SEARCH], filter: 'displayName eq "alice"',
        attributes: ['userName', 'displayName'] } });
      await step('patch the user', 'PATCH', '/Users/' + aliceId, { json: {
        schemas: [PATCH], Operations: [
          { op: 'replace', path: 'displayName', value: 'Alice P' },
          { op: 'add', path: 'emails', value: [{ value: 'c@example.com',
                                                 type: 'work' }] },
          { op: 'remove', path: 'title' },
          { op: 'replace', path: 'active', value: false },
          { op: 'replace', path: ENT + ':department', value: 'Ops' },
          { op: 'remove', path: IYA + ':alsoKnownAs' },
          { op: 'replace', path: 'name.givenName', value: 'Alicia' }] } });
      await step('patch a whole extension away', 'PATCH', '/Users/' + aliceId,
        { json: { schemas: [PATCH], Operations: [
          { op: 'remove', path: IYA }] } });
      await step('put the user', 'PUT', '/Users/' + aliceId, { json: {
        schemas: [USER], userName: 'wire-alice', displayName: 'Alice2',
        active: true, phoneNumbers: [{ value: '+1 888' }] } });

      r = await step('create the group', 'POST', '/Groups', { json: {
        schemas: [GROUP], displayName: 'wire-group', externalId: 'g-ext',
        members: [{ value: aliceId }, { value: bossId, type: 'User' }] } });
      const groupId = r.json && r.json.id;
      await step('read the group', 'GET', '/Groups/' + groupId);
      await step('the user names the group', 'GET', '/Users/' + aliceId +
                 '?attributes=groups');
      await step('patch a member out', 'PATCH', '/Groups/' + groupId,
        { json: { schemas: [PATCH], Operations: [
          { op: 'remove', path: 'members[value eq "' + bossId + '"]' }] } });
      await step('patch a member in', 'PATCH', '/Groups/' + groupId,
        { json: { schemas: [PATCH], Operations: [
          { op: 'add', path: 'members', value: [{ value: bossId }] }] } });
      await step('put the group', 'PUT', '/Groups/' + groupId, { json: {
        schemas: [GROUP], displayName: 'wire-group', members: [] } });
      await step('filter groups', 'GET', '/Groups?filter=' +
                 encodeURIComponent('displayName eq "wire-group"'));

      // THE REFUSALS.
      const nobody = '00000000-0000-4000-8000-00000000dead';
      await step('no schemas', 'POST', '/Users', { json: {
        userName: 'wire-x' } });
      await step('no userName', 'POST', '/Users', { json: {
        schemas: [USER] } });
      await step('the refused userName', 'POST', '/Users', { json: {
        schemas: [USER], userName: 'invalid' } });
      await step('a duplicate userName', 'POST', '/Users', { json: {
        schemas: [USER], userName: 'wire-alice' } });
      await step('a home email', 'POST', '/Users', { json: {
        schemas: [USER], userName: 'wire-home',
        emails: [{ value: 'h@example.com', type: 'home' }] } });
      await step('a fax number', 'POST', '/Users', { json: {
        schemas: [USER], userName: 'wire-fax',
        phoneNumbers: [{ value: '1', type: 'fax' }] } });
      await step('emails not a list', 'POST', '/Users', { json: {
        schemas: [USER], userName: 'wire-x', emails: 'x@example.com' } });
      await step('active not a boolean', 'POST', '/Users', { json: {
        schemas: [USER], userName: 'wire-x', active: 'maybe' } });
      await step('name not complex', 'POST', '/Users', { json: {
        schemas: [USER], userName: 'wire-x', name: 'x' } });
      await step('userName not a string', 'POST', '/Users', { json: {
        schemas: [USER], userName: { a: 1 } } });
      await step('profileUrl not a reference', 'POST', '/Users', { json: {
        schemas: [USER], userName: 'wire-x', profileUrl: 5 } });
      await step('a groups write', 'POST', '/Users', { json: {
        schemas: [USER], userName: 'wire-groups',
        groups: [{ value: groupId }] } });
      await step('an undeclared extension', 'POST', '/Users', { json: {
        schemas: [USER, 'urn:ietf:params:scim:schemas:extension:x:2.0:User'],
        userName: 'wire-x' } });
      await step('an unknown link', 'POST', '/Users', { json: {
        schemas: [USER, IYA], userName: 'wire-link',
        [IYA]: { federationLinks: [{ relationship: 'nope',
                                     subject: 's' }] } } });
      await step('a link without a subject', 'POST', '/Users', { json: {
        schemas: [USER, IYA], userName: 'wire-link2',
        [IYA]: { federationLinks: [{ relationship: 'nope' }] } } });
      await step('a home cell', 'POST', '/Users', { json: {
        schemas: [USER, IYA], userName: 'wire-cell',
        [IYA]: { homeCell: 'elsewhere' } } });
      await step('read nobody', 'GET', '/Users/' + nobody);
      await step('put nobody', 'PUT', '/Users/' + nobody, { json: {
        schemas: [USER], userName: 'wire-nobody' } });
      await step('a bad op', 'PATCH', '/Users/' + aliceId, { json: {
        schemas: [PATCH], Operations: [{ op: 'frob', path: 'title',
                                         value: 'x' }] } });
      await step('a patch with no schemas', 'PATCH', '/Users/' + aliceId,
        { json: { Operations: [{ op: 'replace', path: 'title',
                                 value: 'x' }] } });
      await step('a patch of an unknown path', 'PATCH', '/Users/' + aliceId,
        { json: { schemas: [PATCH], Operations: [
          { op: 'replace', path: 'nickName', value: 'x' }] } });
      await step('a patch of id', 'PATCH', '/Users/' + aliceId,
        { json: { schemas: [PATCH], Operations: [
          { op: 'replace', path: 'id', value: 'x' }] } });
      await step('a bad filter', 'GET', '/Users?filter=' +
                 encodeURIComponent('userName zz "x"'));
      await step('a filter on an unknown attribute', 'GET', '/Users?filter=' +
                 encodeURIComponent('nickName eq "x"'));
      await step('a group with no displayName', 'POST', '/Groups', { json: {
        schemas: [GROUP] } });
      await step('a member of a bad type', 'POST', '/Groups', { json: {
        schemas: [GROUP], displayName: 'wire-bad',
        members: [{ value: aliceId, type: 'Robot' }] } });
      await step('a proto member', 'POST', '/Users', { raw:
        '{"schemas":["' + USER + '"],"userName":"wire-proto",' +
        '"__proto__":{"polluted":true}}' });
      await step('a malformed body', 'POST', '/Users', { raw: '{"schemas":' });

      await step('delete the group', 'DELETE', '/Groups/' + groupId);
      await step('delete the user', 'DELETE', '/Users/' + aliceId);
      await step('delete the manager', 'DELETE', '/Users/' + bossId);
      await step('read the deleted user', 'GET', '/Users/' + aliceId);
    });
    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(record));
    process.exit(0);
  })().catch(function (e) {
    record.problems.push(String(e && e.stack));
    require('fs').writeFileSync(OUT, JSON.stringify(record));
    process.exit(0);
  });
}

// The run-to-run values, each replaced by a placeholder, a UUID's numbered in
// order of first appearance, so that two runs of one tree record the same
// text.
function normalise(record) {
  log.debug("Entering normalise().");
  const seen = new Map();
  const PATTERNS = [
    ['uuid', /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi],
    ['time', /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z/g],
    ['gtime', /\b\d{14}(\.\d+)?Z\b/g],
    ['port', /127\.0\.0\.1:\d+/g],
    ['etag', /W\/"[^"]*"/g]
  ];
  const text = JSON.stringify(record, null, 1);
  let out = text;
  PATTERNS.forEach(function (pair) {
    out = out.replace(pair[1], function (value) {
      // The fixed inputs of section C are not run-to-run values.
      if (pair[0] === 'gtime' && /^2026010[12]000000Z$/.test(value)) {
        return value;
      }
      if (pair[0] === 'uuid' && /^00000000-0000-4000-8000-/.test(value)) {
        return value;
      }
      // An instant or an ETag is not numbered: two of them falling in one
      // second is chance, and an identity is all a number would show.
      if (pair[0] !== 'uuid') {
        return '<' + pair[0] + '>';
      }
      const key = pair[0] + ':' + value;
      if (!seen.has(key)) {
        seen.set(key, '<' + pair[0] + '#' + (seen.size + 1) + '>');
      }
      return seen.get(key);
    });
  });
  log.debug("Leaving normalise().");
  return JSON.parse(out);
}

// Runs the child and answers its record, normalised, or null.
function capture() {
  log.debug("Entering capture().");
  const out = path.join(os.tmpdir(), 'scim-model-wire-' + process.pid +
                        '.json');
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
  let record = null;
  try {
    record = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in capture(): " + ((e && e.message) || e));
    log.debug("Leaving capture(). No record: exit " + result.status + " " +
              String(result.stderr || '').slice(-800));
    return null;
  }
  log.debug("Leaving capture().");
  return normalise(record);
}

// The first place two values differ, as a dotted path, or null.
function firstDifference(a, b, where) {
  log.debug("Entering firstDifference().");
  if (JSON.stringify(a) === JSON.stringify(b)) {
    log.debug("Leaving firstDifference(). Equal.");
    return null;
  }
  if (a && b && typeof a === 'object' && typeof b === 'object') {
    const keys = Array.from(new Set(Object.keys(a).concat(Object.keys(b))));
    for (let i = 0; i < keys.length; i++) {
      const inner = firstDifference(a[keys[i]], b[keys[i]],
                                    where + '.' + keys[i]);
      if (inner) {
        log.debug("Leaving firstDifference().");
        return inner;
      }
    }
  }
  log.debug("Leaving firstDifference().");
  return where + ': ' + JSON.stringify(b).slice(0, 300) + ' where ' +
    JSON.stringify(a).slice(0, 300) + ' was recorded';
}

function run(t) {
  log.debug("Entering run().");
  const now = capture();
  if (!t.check(!!now, 'the child process reported')) {
    log.debug("Leaving run().");
    return;
  }
  t.check(now.problems.length === 0, 'the child ran to the end',
          now.problems.join('\n'));
  let recorded = null;
  try {
    recorded = JSON.parse(fs.readFileSync(SNAPSHOT, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    recorded = null;
  }
  if (!t.check(!!recorded, 'the recorded wire is in the tree', SNAPSHOT)) {
    log.debug("Leaving run().");
    return;
  }
  [['definitions', 'D. every published definition is as recorded'],
   ['mapping', 'M. the mapping, its URNs and its prose are as ' +
               'recorded'],
   ['conversions', 'C. the four conversions answer as recorded']]
    .forEach(function (pair) {
      t.check(firstDifference(recorded[pair[0]], now[pair[0]],
                              pair[0]) === null, pair[1],
              firstDifference(recorded[pair[0]], now[pair[0]], pair[0]));
    });
  t.check(recorded.wire.length === now.wire.length,
          'W. the conversation has as many steps as recorded',
          now.wire.length + ' vs ' + recorded.wire.length);
  recorded.wire.forEach(function (one, i) {
    t.check(firstDifference(one, now.wire[i], 'wire') === null,
            'W. ' + one.step + ': ' + one.method + ' answers as recorded (' +
            one.status + ')', firstDifference(one, now.wire[i], 'wire'));
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env.SCIM_WIRE_PRINT) {
  process.stdout.write(JSON.stringify(capture(), null, 1) + '\n');
}

module.exports = {
  name: 'scim_model_wire',
  describe: 'what /scim/v2 answers, byte for byte, against the record made ' +
            'before the SCIM schemas and mapping came from the model ' +
            '(#1579): every definition, the mapping, the conversions, and ' +
            'a scripted conversation with its refusals',
  run: run
};
