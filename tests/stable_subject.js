'use strict';
//
// File: stable_subject.js
//
// ===========================================================================
// A PERSON'S `sub` IS THEIR ENTRY'S `entryUUID`, AND A SCIM ID IS TOO
// (2026-09-14).
//
// `authn/CLAUDE.md`, *What an authenticated identity is here*, is the design.
// Until this date `sub` was `urn:sts:user:<username>`: a rename changed it,
// and a person deleted and re-created under the same name INHERITED it, which
// is the account-recycling hole a relying party linking on `sub` falls into.
// It is `urn:uuid:<entryUUID>` now, in both modes, and everybody moved (rcbj's
// choice). This file is the contract, in six parts:
//
//   A. THE DIRECTORY. An entry is given an `entryUUID` when it is created and
//      keeps it through an overwrite and a rename; a delete and re-create gets
//      a new one; a seeded entry's is deterministic across processes; a row
//      read back without one is backfilled the same way on every path; a
//      client cannot write one in either mode; a search returns it only when
//      asked; and `deleteOldRdn` finally removes the old name.
//   B. THE SUBJECT. `userFor()` gives `urn:uuid:<entryUUID>`; `identityOf()`
//      and `nameForSubject()` resolve it back; the legacy form is still read;
//      a subject naming nobody creates no phantom entry.
//   C. SESSIONS. No signed-in session without an entry, with the three
//      exemptions; the same person is told apart by subject, not by an empty
//      string.
//   D. THE TOKEN ENDPOINT, over HTTP. A token's `sub` is the UUID; a refresh
//      follows a rename and is refused once the person is deleted — and still
//      refused after somebody is re-created under the same name; a password
//      grant for somebody with no entry is refused.
//   E. SCIM, over HTTP. The id is the UUID, a DN still resolves, a member is
//      sent as an id and stored as a DN.
//   F. FEDERATION. A partner's `urn:uuid:` subject becomes a local name of its
//      own and is never looked up in this directory.
//
// WHY A CHILD PROCESS: it loads the whole protocol stack and serves it on a
// loopback port, and it flips `ldap.autocreateUsers`; and part A's determinism
// is a claim about TWO processes, so the child runs twice and the seeded and
// backfilled values are compared between the runs.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'stable_subject',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.SS_ROOT;
  const OUT = process.env.SS_OUT;
  const http = require('http');
  const findings = [];
  const values = {};
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      const body = o.json !== undefined ? JSON.stringify(o.json)
        : (o.form ? new URLSearchParams(o.form).toString() : '');
      const headers = Object.assign({}, o.headers || {});
      if (method !== 'GET') {
        headers['content-type'] = o.json !== undefined
          ? (o.contentType || 'application/json')
          : 'application/x-www-form-urlencoded';
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
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
  function payloadOf(jwt) {
    return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url')
                            .toString('utf8'));
  }
  const V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  const V5 = /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

  (async function () {
    // The restore hooks, caught on their way into the persistence slot, so
    // the backfill can be driven without a store.
    const persistence = require(ROOT + '/persistence/persistence');
    const originalSetDirectory = persistence.setDirectory;
    let hooks = null;
    persistence.setDirectory = function (given) {
      hooks = given;
      return originalSetDirectory(given);
    };
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const helpers = require(ROOT + '/common/helpers');
    const stats = require(ROOT + '/common/admin_stats');
    const audit = require(ROOT + '/common/audit');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const authn = require(ROOT + '/authn/authn');
    const applications = require(ROOT + '/common/applications');
    const federationMap = require(ROOT + '/federation/federation_map');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const fakeRes = function () {
      return { set: function () {}, req: null };
    };
    const uuidOfName = function (name) {
      const found = ldap.objectFor(name);
      return found && found.entry ? ldap.entryUuidOf(ldap.entries.get(
        ldap.normalizeDn(found.entry.dn))) : '';
    };
    const lastCode = function (target, action) {
      const row = audit.list().filter(function (event) {
        return (!target || event.target === target) &&
               (!action || event.action === action) && event.errorCode;
      })[0];
      return row ? row.errorCode : '';
    };

    await realms.run(realms.DEFAULT_REALM, async function () {
      // ====================================================================
      // A. THE DIRECTORY
      // ====================================================================
      const aliceUuid = uuidOfName('alice');
      values.seededAlice = aliceUuid;
      note(V5.test(aliceUuid), 'A1. a SEEDED entry (alice) has a name-based ' +
           '(version 5) entryUUID', aliceUuid);

      ldap.createUser('ss-bob', { invent: false });
      const bobUuid = uuidOfName('ss-bob');
      note(V4.test(bobUuid), 'A2. an entry a door created has a random ' +
           '(version 4) entryUUID', bobUuid);
      const bobDn = ldap.objectFor('ss-bob').entry.dn;

      ldap.writePerson(bobDn, { objectClass: ['top', 'inetOrgPerson'],
        uid: 'ss-bob', cn: 'Bob', sn: 'Builder',
        entryUUID: '00000000-0000-4000-8000-000000000000' });
      note(uuidOfName('ss-bob') === bobUuid,
           'A3. an OVERWRITE that rebuilds the attributes — and even hands ' +
           'an entryUUID of its own — keeps the entry\'s value',
           uuidOfName('ss-bob'));

      let r = ldap.performOperation('add', {
        dn: 'uid=ss-forged,' + ldap.usersDn(), boundDn: '', channel: 'ldaps',
        attributes: [{ type: 'objectClass', values: ['inetOrgPerson'] },
                     { type: 'uid', values: ['ss-forged'] },
                     { type: 'entryUUID', values: [bobUuid] }] });
      note(r.ok === false && lastCode('uid=ss-forged,' + ldap.usersDn()) ===
           'STS-LDAP-0076',
           'A4. DEVELOPMENT mode: an LDAP add naming entryUUID is refused ' +
           '(STS-LDAP-0076) — it is somebody\'s subject',
           JSON.stringify({ ok: r.ok, error: r.errorName }));
      r = ldap.performOperation('modify', {
        dn: bobDn, boundDn: '', channel: 'ldaps',
        changes: [{ operation: 'replace', modification: {
          type: 'entryUUID', values: [aliceUuid] } }] });
      note(r.ok === false && uuidOfName('ss-bob') === bobUuid,
           'A5. and a modify naming it is refused, leaving the value',
           JSON.stringify({ ok: r.ok, error: r.errorName }));
      r = ldap.performOperation('modify', {
        dn: bobDn, boundDn: '', channel: 'ldaps',
        changes: [{ operation: 'replace', modification: {
          type: 'title', values: ['Foreman'] } }] });
      note(r.ok !== false && uuidOfName('ss-bob') === bobUuid,
           'A6. while a modify of anything else keeps it',
           JSON.stringify({ ok: r.ok, error: r.error }));

      r = ldap.performOperation('search', {
        dn: bobDn, boundDn: '', channel: 'ldaps', scope: 0,
        filter: '(objectClass=*)', attributes: [] });
      const plain = JSON.stringify((r.entries || [])[0] || {});
      r = ldap.performOperation('search', {
        dn: bobDn, boundDn: '', channel: 'ldaps', scope: 0,
        filter: '(objectClass=*)', attributes: ['*', 'entryUUID'] });
      const asked = JSON.stringify((r.entries || [])[0] || {});
      note(plain.indexOf(bobUuid) === -1 && asked.indexOf(bobUuid) >= 0,
           'A7. a search returns entryUUID only when asked for by name (RFC ' +
           '4511 4.5.1.8, operational)', plain.slice(0, 160) + ' | ' +
           asked.slice(0, 200));

      ldap.performOperation('modifyDN', {
        dn: bobDn, boundDn: '', channel: 'ldaps', newRdn: 'uid=ss-robert',
        newSuperior: '', deleteOldRdn: true });
      const robert = ldap.objectFor('ss-robert');
      const robertEntry = robert && robert.entry ? ldap.entries.get(
        ldap.normalizeDn(robert.entry.dn)) : null;
      note(robertEntry && ldap.entryUuidOf(robertEntry) === bobUuid,
           'A8. a RENAME keeps the entryUUID', robertEntry && robertEntry.dn);
      note(robertEntry && (robertEntry.attributes.uid || []).indexOf('ss-bob')
           === -1 && !ldap.existingUserEntry('ss-bob'),
           'A9. and deleteOldRdn REMOVES the old uid, so the old name no ' +
           'longer resolves to the renamed person',
           robertEntry && JSON.stringify(robertEntry.attributes.uid));

      ldap.createUser('ss-carol', { invent: false });
      const carolUuid = uuidOfName('ss-carol');
      ldap.deletePerson(ldap.objectFor('ss-carol').entry.dn);
      ldap.createUser('ss-carol', { invent: false });
      note(uuidOfName('ss-carol') && uuidOfName('ss-carol') !== carolUuid,
           'A10. a person DELETED and RE-CREATED under the same name is a ' +
           'NEW entryUUID — the account-recycling case',
           uuidOfName('ss-carol'));

      const rowKey = 'uid=ss-restored,' + ldap.usersDn().toLowerCase();
      hooks.applyEntry(realms.DEFAULT_ID, rowKey, {
        dn: 'uid=ss-restored,' + ldap.usersDn(),
        // Shaped as a store writes a row — timestamps included — minus the
        // one attribute a row written before 2026-09-14 lacks.
        attributes: { objectclass: ['top', 'inetOrgPerson'],
                      uid: ['ss-restored'], sn: ['Restored'],
                      createtimestamp: ['20260101000000Z'],
                      modifytimestamp: ['20260101000000Z'] },
        createdAt: '20260101000000Z', modifiedAt: '20260101000000Z' });
      const applied = ldap.entryUuidOf(ldap.entries.get(rowKey));
      values.backfilled = applied;
      note(V5.test(applied), 'A11. a replicated row with no entryUUID is ' +
           'backfilled with a name-based value', applied);
      r = ldap.performOperation('modify', {
        dn: 'uid=ss-restored,' + ldap.usersDn(), boundDn: '', channel: 'ldaps',
        changes: [{ operation: 'replace', modification: {
          type: 'title', values: ['x'] } }] });
      note(ldap.entryUuidOf(ldap.entries.get(rowKey)) === applied,
           'A12. and keeps it once written through');

      // A ROW WITH NO TIMESTAMPS AT ALL — one imported, or written by hand —
      // written through once. The modify used to give it
      // `createtimestamp: undefined`, and every SCIM list after that threw
      // (E1b below).
      const bareKey = 'uid=ss-bare,' + ldap.usersDn().toLowerCase();
      hooks.applyEntry(realms.DEFAULT_ID, bareKey, {
        dn: 'uid=ss-bare,' + ldap.usersDn(),
        attributes: { objectclass: ['inetOrgPerson'], uid: ['ss-bare'] } });
      const bareStored = ldap.entries.get(bareKey);
      delete bareStored.createdAt;
      delete bareStored.modifiedAt;
      ldap.performOperation('modify', {
        dn: 'uid=ss-bare,' + ldap.usersDn(), boundDn: '', channel: 'ldaps',
        changes: [{ operation: 'replace', modification: {
          type: 'title', values: ['x'] } }] });
      const bareAttributes = ldap.entries.get(bareKey).attributes;
      note(!('createtimestamp' in bareAttributes) &&
           Array.isArray(bareAttributes.modifytimestamp),
           'A13. a modify of a row with no createTimestamp writes none, ' +
           'rather than an undefined value', JSON.stringify(bareAttributes));

      // TWO PROCESSES CREATE ONE PERSON AT ONCE (#2). This process made
      // ss-race; another made the same DN a moment later with its own random
      // UUID, and its row arrives through the replication applier.
      const settle = function () {
        return new Promise(function (resolve) {
          setImmediate(resolve);
        });
      };
      const journalled = [];
      const originalChanged = persistence.directoryChanged;
      persistence.directoryChanged = function (dn) {
        journalled.push(dn);
        return originalChanged.apply(this, arguments);
      };
      try {
        ldap.createUser('ss-race', { invent: false });
        const raceKey = 'uid=ss-race,' + ldap.usersDn().toLowerCase();
        const mine = ldap.entryUuidOf(ldap.entries.get(raceKey));
        const theirs = require('crypto').randomUUID();
        const theirRow = JSON.parse(JSON.stringify(ldap.entries.get(raceKey)));
        theirRow.attributes.entryuuid = [theirs];
        const mineRow = JSON.parse(JSON.stringify(ldap.entries.get(raceKey)));
        const primary = mine < theirs ? mine : theirs;
        // What the OTHER process computes, holding its own entry and
        // receiving this one's row — asked of the rule directly, since one
        // process cannot hold both stores. Asked before the apply, which
        // keeps the row it is handed.
        const there = ldap.mergeCreateRace(theirRow, mineRow);
        const here = ldap.mergeCreateRace(mineRow, theirRow);
        const alias = mine < theirs ? theirs : mine;
        // Only what happens AFTER the apply is this process's own write: the
        // replication applier suppresses the journal around the apply itself,
        // and a test calling the hook directly cannot.
        hooks.applyEntry(realms.DEFAULT_ID, raceKey, theirRow);
        journalled.length = 0;
        await settle();
        let raced = ldap.entries.get(raceKey);
        note(ldap.entryUuidOf(raced) === primary &&
             JSON.stringify(raced.attributes.stsentryuuidalias) ===
               JSON.stringify([alias]),
             'A14. a create that raced another process\'s keeps the lower ' +
             'UUID and the other as an alias',
             JSON.stringify(raced.attributes));
        note(there && here && there.uuid === here.uuid &&
             there.uuid === primary &&
             JSON.stringify(there.aliases) === JSON.stringify(here.aliases),
             'A14b. both processes reach the SAME answer on their first ' +
             'sight of the other\'s row', JSON.stringify([here, there]));
        note(helpers.nameForSubject('urn:uuid:' + mine) === 'ss-race' &&
             helpers.nameForSubject('urn:uuid:' + theirs) === 'ss-race' &&
             helpers.subjectForName('ss-race') === 'urn:uuid:' + primary,
             'A15. so the tokens BOTH processes issued still name the person, ' +
             'and a new one carries the primary');
        note(journalled.indexOf(raceKey) >= 0,
             'A16. and the reconciled entry is written back, so the store ' +
             'converges', JSON.stringify(journalled));
        // The other process applies THIS process's original row.
        delete mineRow.attributes.stsentryuuidalias;
        hooks.applyEntry(realms.DEFAULT_ID, raceKey, mineRow);
        await settle();
        raced = ldap.entries.get(raceKey);
        note(ldap.entryUuidOf(raced) === primary &&
             JSON.stringify(raced.attributes.stsentryuuidalias) ===
               JSON.stringify([alias]),
             'A17. in either order of arrival the answer is the same',
             JSON.stringify(raced.attributes));
        ldap.performOperation('modify', {
          dn: 'uid=ss-race,' + ldap.usersDn(), boundDn: '', channel: 'ldaps',
          changes: [{ operation: 'replace', modification: {
            type: 'title', values: ['raced'] } }] });
        ldap.writePerson('uid=ss-race,' + ldap.usersDn(), {
          objectClass: ['top', 'inetOrgPerson'], uid: 'ss-race',
          sn: 'Race', title: 'replaced' });
        raced = ldap.entries.get(raceKey);
        note(ldap.entryUuidOf(raced) === primary &&
             JSON.stringify(raced.attributes.stsentryuuidalias) ===
               JSON.stringify([alias]) &&
             String(raced.attributes.title) === 'replaced',
             'A17b. and an LDAP modify and a whole-entry replace both keep ' +
             'the alias', JSON.stringify(raced.attributes));
        hooks.applyEntry(realms.DEFAULT_ID, raceKey,
                         JSON.parse(JSON.stringify(raced)));
        journalled.length = 0;
        await settle();
        note(journalled.indexOf(raceKey) < 0,
             'A18. and a row already carrying that answer writes nothing ' +
             'back', JSON.stringify(journalled));
        const later = JSON.parse(JSON.stringify(raced));
        const recreated = require('crypto').randomUUID();
        later.attributes.entryuuid = [recreated];
        delete later.attributes.stsentryuuidalias;
        later.createdAt = '20990101000000Z';
        hooks.applyEntry(realms.DEFAULT_ID, raceKey, later);
        await settle();
        raced = ldap.entries.get(raceKey);
        note(ldap.entryUuidOf(raced) === recreated &&
             !raced.attributes.stsentryuuidalias &&
             helpers.nameForSubject('urn:uuid:' + primary) === '',
             'A19. a RE-CREATE (created long after) is a new subject and ' +
             'inherits no alias', JSON.stringify(raced.attributes));
        r = ldap.performOperation('modify', {
          dn: 'uid=ss-race,' + ldap.usersDn(), boundDn: '', channel: 'ldaps',
          changes: [{ operation: 'add', modification: {
            type: 'stsEntryUuidAlias', values: [primary] } }] });
        note(r && r.ok === false,
             'A20. and no client may write an alias', JSON.stringify(r));
      } finally {
        persistence.directoryChanged = originalChanged;
      }

      // ====================================================================
      // B. THE SUBJECT
      // ====================================================================
      const robertSub = helpers.userFor('ss-robert').sub;
      note(robertSub === 'urn:uuid:' + bobUuid,
           'B1. userFor() gives urn:uuid:<entryUUID>', robertSub);
      note(stats.identityKeyOf(robertSub) === 'ss-robert' &&
           helpers.nameForSubject(robertSub) === 'ss-robert',
           'B2. and it resolves back to the person\'s CURRENT name',
           stats.identityKeyOf(robertSub));
      note(helpers.nameForSubject('urn:sts:user:someone') === 'someone' &&
           stats.identityKeyOf('urn:sts:user:someone') === 'someone',
           'B3. the legacy urn:sts:user: form is still read');
      note(helpers.userFor('ss-nobody-here').sub === '',
           'B4. somebody with no entry has NO subject, not a name-derived one');
      const stranger = 'urn:uuid:11111111-2222-4333-8444-555555555555';
      const strangerIdentity = stats.identityOf ? stats.identityOf(stranger)
                                                : { key: stranger };
      stats.recordAuthentication({ presented: stranger, protocol: 'Test',
                                   method: 'probe' });
      note(strangerIdentity.key === stranger &&
           !ldap.entryByUuid(stranger) &&
           !ldap.existingUserEntry(stranger),
           'B5. a subject naming nobody here is its own key and creates NO ' +
           'phantom entry named after it', JSON.stringify(strangerIdentity));
      const refusedCreate = ldap.createUser(stranger, { invent: false });
      note(refusedCreate.ok === false,
           'B6. and a person cannot be created under a subject identifier',
           JSON.stringify(refusedCreate.errors || []));

      // ====================================================================
      // C. SESSIONS
      // ====================================================================
      const fresh = authn.startSession(fakeRes(), 'ss-dave', ['pwd'], '1',
                                       'Test', {});
      note(fresh && /^urn:uuid:/.test(fresh.user.sub) &&
           fresh.user.sub === helpers.userFor('ss-dave').sub,
           'C1. a sign-in creates the entry FIRST, so the session is given ' +
           'its subject', fresh && fresh.user.sub);
      config.setOverride('ldap.autocreateUsers', 'false');
      const refused = authn.startSession(fakeRes(), 'ss-erin', ['pwd'], '1',
                                         'Test', {});
      note(refused === null && lastCode('', 'session.refuse') ===
           'STS-AUTHN-0180' && !ldap.existingUserEntry('ss-erin'),
           'C2. with ldap.autocreateUsers OFF, a sign-in for somebody with ' +
           'no entry is REFUSED (STS-AUTHN-0180) and nothing is created',
           lastCode('', 'session.refuse'));
      const existing = authn.startSession(fakeRes(), 'ss-dave', ['pwd'], '1',
                                          'Test', {});
      note(existing && existing.user.sub === fresh.user.sub,
           'C3. while somebody who HAS an entry signs in as ever');
      const keyed = authn.startSession(fakeRes(), 'ss-api-client', ['pwd'],
        '1', 'SCIM', { key: 'fingerprint-ss', cookie: false });
      note(!!keyed, 'C4. a keyed API caller is not refused — it is not a ' +
           'person');
      const anonymous = authn.startSession(fakeRes(), 'ss-declined', [], '0',
        'Test', { authenticated: false });
      note(!!anonymous, 'C5. and an UNAUTHENTICATED session is not refused');
      config.clearOverride('ldap.autocreateUsers');

      // ====================================================================
      // D. THE TOKEN ENDPOINT
      // ====================================================================
      const SECRET = 'ss-client-secret-0123456789abcdef';
      applications.createApplication({ identifier: 'ss-client',
        protocols: ['oauth2'],
        fields: { oauthClientId: 'ss-client', oauthClientSecret: SECRET,
                  oauthTokenEndpointAuthMethod: 'client_secret_post',
                  oauthGrantType: ['password', 'refresh_token'] } });
      const client = { client_id: 'ss-client', client_secret: SECRET };
      ldap.createUser('ss-frank', { invent: false });
      const frankSub = helpers.userFor('ss-frank').sub;
      const grant = function () {
        return request(port, 'POST', '/oauth2/token', { form: Object.assign({
          grant_type: 'password', username: 'ss-frank', password: 'x',
          scope: 'openid offline_access' }, client) });
      };
      let first = await grant();
      let second = await grant();
      const idt = first.json && first.json.id_token
        ? payloadOf(first.json.id_token) : {};
      const at = first.json && first.json.access_token
        ? payloadOf(first.json.access_token) : {};
      note(idt.sub === frankSub && at.sub === frankSub,
           'D1. the ID Token and access token carry sub = ' +
           'urn:uuid:<entryUUID>', first.status + ' ' + idt.sub + ' ' + at.sub);
      note(!!(first.json && first.json.refresh_token &&
              second.json && second.json.refresh_token),
           'D2. two refresh tokens to spend', first.text.slice(0, 160));

      ldap.performOperation('modifyDN', {
        dn: ldap.objectFor('ss-frank').entry.dn, boundDn: '', channel: 'ldaps',
        newRdn: 'uid=ss-francis', newSuperior: '', deleteOldRdn: true });
      r = await request(port, 'POST', '/oauth2/token', { form: Object.assign({
        grant_type: 'refresh_token',
        refresh_token: first.json && first.json.refresh_token }, client) });
      const renewed = r.json && r.json.access_token
        ? payloadOf(r.json.access_token) : {};
      note(r.status === 200 && renewed.sub === frankSub,
           'D3. a refresh after a RENAME is issued with the SAME sub',
           r.status + ' ' + r.text.slice(0, 160));

      ldap.deletePerson(ldap.objectFor('ss-francis').entry.dn);
      ldap.createUser('ss-frank', { invent: false });
      r = await request(port, 'POST', '/oauth2/token', { form: Object.assign({
        grant_type: 'refresh_token',
        refresh_token: second.json && second.json.refresh_token }, client) });
      note(r.status === 400 && r.json && r.json.error === 'invalid_grant',
           'D4. once the person is DELETED — and somebody RE-CREATED under ' +
           'the old name — the refresh is refused invalid_grant: the new ' +
           'entry is a different subject',
           r.status + ' ' + r.text.slice(0, 160));

      config.setOverride('ldap.autocreateUsers', 'false');
      r = await request(port, 'POST', '/oauth2/token', { form: Object.assign({
        grant_type: 'password', username: 'ss-george', password: 'x' },
        client) });
      note(r.status === 400 && r.json && r.json.error === 'invalid_grant' &&
           !ldap.existingUserEntry('ss-george'),
           'D5. a password grant for somebody with no entry (autocreate off) ' +
           'is refused invalid_grant rather than minting an empty sub',
           r.status + ' ' + r.text.slice(0, 160));
      const wstrust = require(ROOT + '/ws-trust/wstrust');
      const jwtRst = function (who) {
        return '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ' +
          'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/' +
          'oasis-200401-wss-wssecurity-secext-1.0.xsd"><s:Header>' +
          '<wsse:Security><wsse:UsernameToken><wsse:Username>' + who +
          '</wsse:Username><wsse:Password>x</wsse:Password>' +
          '</wsse:UsernameToken></wsse:Security></s:Header><s:Body>' +
          '<wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/' +
          'ws-sx/ws-trust/200512"><wst:RequestType>http://docs.oasis-open.org/' +
          'ws-sx/ws-trust/200512/Issue</wst:RequestType><wst:TokenType>' +
          'urn:ietf:params:oauth:token-type:jwt</wst:TokenType>' +
          '</wst:RequestSecurityToken></s:Body></s:Envelope>';
      };
      const nobodyRst = wstrust.handleRst(jwtRst('ss-nemo'),
                                          'application/soap+xml');
      note(nobodyRst.status === 400 &&
           nobodyRst.errorCode === 'STS-WSTRUST-0017' &&
           !/BinarySecurityToken/.test(nobodyRst.body),
           'D5b. a WS-Trust JWT for somebody with no entry is refused rather ' +
           'than issued with a bare-name sub',
           nobodyRst.status + ' ' + nobodyRst.errorCode);
      config.clearOverride('ldap.autocreateUsers');

      // A token issued by the worker that LOST a create race: its `sub` is
      // the value the directory now keeps as an alias.
      ldap.createUser('ss-ivy', { invent: false });
      const ivySub = helpers.userFor('ss-ivy').sub;
      const ivyGrant = await request(port, 'POST', '/oauth2/token', {
        form: Object.assign({ grant_type: 'password', username: 'ss-ivy',
          password: 'x', scope: 'openid offline_access' }, client) });
      const ivyKey = 'uid=ss-ivy,' + ldap.usersDn().toLowerCase();
      const ivyRow = JSON.parse(JSON.stringify(ldap.entries.get(ivyKey)));
      ivyRow.attributes.entryuuid = ['00000000-0000-4000-8000-000000000000'];
      hooks.applyEntry(realms.DEFAULT_ID, ivyKey, ivyRow);
      await new Promise(function (resolve) {
        setImmediate(resolve);
      });
      r = await request(port, 'POST', '/oauth2/token', { form: Object.assign({
        grant_type: 'refresh_token',
        refresh_token: ivyGrant.json && ivyGrant.json.refresh_token }, client) });
      const ivyRenewed = r.json && r.json.id_token
        ? payloadOf(r.json.id_token) : {};
      note(helpers.subjectForName('ss-ivy') !== ivySub && r.status === 200 &&
           ivyRenewed.sub === ivySub,
           'D6. a refresh token issued under a subject that became an ALIAS ' +
           'still refreshes, and keeps the sub its relying party holds',
           r.status + ' ' + ivyRenewed.sub + ' ' + r.text.slice(0, 160));
      // A browser session made under the aliased subject: the same person
      // signing in again on it is a RE-AUTHENTICATION, not somebody else.
      ldap.createUser('ss-jack', { invent: false });
      const jackLines = [];
      const jackRes = { set: function (n, v) {
        jackLines.push(String(v));
      }, req: null };
      const jackSession = authn.startSession(jackRes, 'ss-jack', ['pwd'], '1',
                                             'OAuth 2.0 / OIDC', {});
      const jackKey = 'uid=ss-jack,' + ldap.usersDn().toLowerCase();
      const jackRow = JSON.parse(JSON.stringify(ldap.entries.get(jackKey)));
      jackRow.attributes.entryuuid = ['00000000-0000-4000-8000-000000000001'];
      hooks.applyEntry(realms.DEFAULT_ID, jackKey, jackRow);
      await new Promise(function (resolve) {
        setImmediate(resolve);
      });
      const jackCookie = (jackLines.join(';').match(
        /sts_session=([^;]+)/) || [])[1] || '';
      const jackAgain = authn.startSession({ set: function () {}, req: null },
        'ss-jack', ['pwd', 'otp'], 'mfa', 'OAuth 2.0 / OIDC',
        { request: { headers: { cookie: 'sts_session=' + jackCookie },
                     query: {} } });
      note(jackSession && jackAgain && jackAgain.id === jackSession.id &&
           helpers.subjectForName('ss-jack') !== jackSession.user.sub,
           'D8. a session under a subject that became an alias is still that ' +
           'person\'s, and signing in again adds to it',
           (jackSession && jackSession.id) + ' ' + (jackAgain && jackAgain.id));
      // A RENAME KEEPS ONE ROW: the identity register, the tokens filed
      // under the person, and the RISC register.
      ldap.createUser('ss-lou', { invent: false });
      const louGrant = await request(port, 'POST', '/oauth2/token', {
        form: Object.assign({ grant_type: 'password', username: 'ss-lou',
          password: 'x', scope: 'openid' }, client) });
      const louUuid = uuidOfName('ss-lou');
      const risc = require(ROOT + '/ssf/risc');
      risc.observe({ kind: 'updated', username: 'ss-lou',
                     dn: ldap.objectFor('ss-lou').entry.dn, realm: 'default',
                     before: { entryuuid: [louUuid] },
                     after: { entryuuid: [louUuid], title: ['x'] } });
      ldap.performOperation('modifyDN', {
        dn: ldap.objectFor('ss-lou').entry.dn, boundDn: '', channel: 'ldaps',
        newRdn: 'uid=ss-louis', newSuperior: '', deleteOldRdn: true });
      const louRows = stats.userRows().filter(function (row) {
        return row.key === 'ss-lou' || row.key === 'ss-louis';
      });
      note(louGrant.status === 200 && louRows.length === 1 &&
           louRows[0].key === 'ss-louis' && louRows[0].authentications >= 1 &&
           louRows[0].tokens.issued >= 1,
           'D11. after a rename /admin/users has ONE row for the person, ' +
           'holding the sign-ins and tokens from before it',
           JSON.stringify(louRows.map(function (row) {
             return { key: row.key, authentications: row.authentications,
                      tokens: row.tokens };
           })));
      const louDetail = stats.userDetail('ss-louis');
      note(louDetail && louDetail.tokens && louDetail.tokens.length >= 1,
           'D12. and the renamed person\'s page lists the token issued ' +
           'under the old name', louDetail && louDetail.tokens &&
           louDetail.tokens.length);
      const louRisc = risc.get('ss-louis');
      note(!risc.get('ss-lou') && louRisc &&
           (louRisc.formerIdentifiers || []).indexOf('ss-lou') >= 0,
           'D13. and the RISC register moves the account to its new name, ' +
           'keeping the old one as a former identifier',
           JSON.stringify(louRisc && { id: louRisc.accountId,
                                       former: louRisc.formerIdentifiers }));

      // GNAP's opaque subject identifier and user reference follow the entry.
      const gnapSubject = require(ROOT + '/gnap/gnap_subject');
      ldap.createUser('ss-kim', { invent: false });
      const kimOpaque = gnapSubject.opaqueIdFor('ss-kim');
      ldap.performOperation('modifyDN', {
        dn: ldap.objectFor('ss-kim').entry.dn, boundDn: '', channel: 'ldaps',
        newRdn: 'uid=ss-kimberly', newSuperior: '', deleteOldRdn: true });
      const kimByRef = gnapSubject.resolveUser({ reference: kimOpaque }, {});
      note(gnapSubject.opaqueIdFor('ss-kimberly') === kimOpaque &&
           kimByRef.ok && kimByRef.username === 'ss-kimberly',
           'D9. a GNAP opaque subject identifier survives a rename, and the ' +
           'reference names the renamed person', JSON.stringify(kimByRef));
      ldap.deletePerson(ldap.objectFor('ss-kimberly').entry.dn);
      ldap.createUser('ss-kim', { invent: false });
      const kimGone = gnapSubject.resolveUser({ reference: kimOpaque }, {});
      note(!kimGone.ok && gnapSubject.opaqueIdFor('ss-kim') !== kimOpaque,
           'D10. and a person re-created under the old name has a different ' +
           'one, while the old reference names nobody',
           JSON.stringify(kimGone));
      const personAssertions = require(ROOT + '/common/person_assertions');
      note(personAssertions.subjectIsSelf({ username: 'ss-ivy' }, ivySub,
                                          'jwt'),
           'D7. and an assertion a person signs about that subject is about ' +
           'themselves');

      // ====================================================================
      // E. SCIM
      // ====================================================================
      const scimAuth = { authorization: 'Basic ' +
        Buffer.from('ss-scim:whatever').toString('base64') };
      ldap.createUser('ss-scim', { invent: false });
      ldap.createUser('ss-hank', { invent: false });
      const hankUuid = uuidOfName('ss-hank');
      r = await request(port, 'GET', '/scim/v2/Users?filter=' +
        encodeURIComponent('userName eq "ss-hank"'), { headers: scimAuth });
      const listed = r.json && r.json.Resources && r.json.Resources[0];
      note(listed && listed.id === hankUuid,
           'E1. a SCIM User\'s id is its entryUUID', r.status + ' ' +
           (listed && listed.id) + ' ' + r.text.slice(0, 300));
      r = await request(port, 'GET', '/scim/v2/Users?count=1000',
                        { headers: scimAuth });
      const bareListed = r.json && (r.json.Resources || []).filter(
        function (one) {
          return one.userName === 'ss-bare';
        })[0];
      note(r.status === 200 && !!bareListed,
           'E1b. a SCIM list holding that row answers, and lists it',
           r.status + ' ' + r.text.slice(0, 200));
      r = await request(port, 'GET', '/scim/v2/Users/' + hankUuid,
                        { headers: scimAuth });
      note(r.status === 200 && r.json && r.json.userName === 'ss-hank',
           'E2. and GET /Users/<that id> finds them', r.status);
      r = await request(port, 'GET', '/scim/v2/Users/' +
        encodeURIComponent(ldap.objectFor('ss-hank').entry.dn),
        { headers: scimAuth });
      note(r.status === 200 && r.json && r.json.id === hankUuid,
           'E3. a DN stored by a client before the change still resolves, ' +
           'and answers with the new id', r.status);
      r = await request(port, 'POST', '/scim/v2/Groups', {
        headers: scimAuth, contentType: 'application/scim+json',
        json: { schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
                displayName: 'ss-crew', members: [{ value: hankUuid }] } });
      const group = r.json || {};
      const stored = group.id ? ldap.readGroupEntry(group.id) : null;
      const storedMembers = stored
        ? JSON.stringify(stored.attributes.member || []) : '';
      note(r.status === 201 && (group.members || [])[0] &&
           group.members[0].value === hankUuid &&
           storedMembers.indexOf(ldap.objectFor('ss-hank').entry.dn) >= 0,
           'E4. a member sent as an id is STORED as its DN and returned as ' +
           'the id again', r.status + ' ' + storedMembers + ' ' +
           r.text.slice(0, 200));

      // ====================================================================
      // F. FEDERATION
      // ====================================================================
      const mapped = federationMap.usernameFor({ fedId: 'ss-partner' }, {},
        'urn:uuid:' + aliceUuid);
      note(mapped.username === 'sub-' + aliceUuid,
           'F1. a partner\'s urn:uuid: subject becomes a local name of its ' +
           'own — never resolved in THIS directory, even when it happens to ' +
           'be a local person\'s', mapped.username);
    });

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify({ findings: findings,
                                                      values: values }));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify({ findings: findings,
                                                      values: values }));
    process.exit(0);
  });
}

function inAChild(t, label) {
  log.debug("Entering inAChild(). " + label);
  const out = path.join(os.tmpdir(), 'stable-subject-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', SS_ROOT: ROOT, SS_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
    });
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    report = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(!!report, 'the ' + label + ' child process reported',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving inAChild().");
    return null;
  }
  log.debug("Leaving inAChild().");
  return report;
}

function run(t) {
  log.debug("Entering run().");
  const first = inAChild(t, 'first');
  if (first) {
    first.findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  t.log.info('=== a second process, for the determinism claims ===');
  const second = inAChild(t, 'second');
  if (first && second) {
    t.check(!!first.values.seededAlice &&
            first.values.seededAlice === second.values.seededAlice,
            'A13. a seeded entry has the SAME entryUUID in a second process — ' +
            'alice\'s sub does not change on a restart',
            first.values.seededAlice + ' / ' + second.values.seededAlice);
    t.check(!!first.values.backfilled &&
            first.values.backfilled === second.values.backfilled,
            'A14. and a backfilled row gets the same value in every process, ' +
            'so none has to write it back first',
            first.values.backfilled + ' / ' + second.values.backfilled);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'stable_subject',
  describe: 'sub is urn:uuid:<entryUUID>: assigned, kept through overwrite ' +
            'and rename, new on re-create, deterministic when seeded, ' +
            'unwritable by a client; resolved both ways; no session or grant ' +
            'without an entry; refresh follows a rename and not a re-create; ' +
            'SCIM ids; a partner subject never resolved locally',
  run: run
};
