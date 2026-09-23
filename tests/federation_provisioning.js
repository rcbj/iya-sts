'use strict';
//
// File: federation_provisioning.js
//
// ===========================================================================
// FEDERATED SIGN-IN WITH DYNAMIC PROVISIONING, AND WITH PRE-PROVISIONING
// (2026-09-14).
//
// rcbj wants both shapes on the service-provider side of every federation
// relationship, each a switch on the relationship's page:
//
//   * DYNAMIC PROVISIONING (`fedAutocreateUsers`, on by default): the first
//     sign-in creates the person's directory entry, so no SCIM is needed.
//   * PRE-PROVISIONING (the same switch off): the entry must already exist —
//     created through SCIM or by hand — and a sign-in for somebody who does
//     not is REFUSED. Until this date OFF meant "a session and no entry", which
//     a stable subject (`sub = urn:uuid:<entryUUID>`) cannot support: a
//     session needs an entry to be the subject of.
//   * ATTRIBUTE REFRESH (`fedUpdateUserAttributes`, on by default): whether a
//     returning person's attributes are overwritten from the latest assertion,
//     or written only when the sign-in created the entry.
//
// WHAT IS DRIVEN IS A REAL FEDERATED SIGN-IN, over HTTP, in one process: the
// DEFAULT realm is the identity provider (its own OpenID Provider) and a trust
// realm of this file's own is the service provider, federated to it by an OIDC
// relationship — the code flow, PKCE, the back-channel token request, the ID
// Token verified against the partner's published keys, the username mapped
// from `preferred_username` and the `email` claim mapped onto `mail`. People
// are pre-provisioned through `POST /scim/v2/Users` in the service provider's
// realm. Nothing is called behind the protocol's back.
//
// SINCE #109 (2026-09-22) the relationship is under `fedSubjectPolicy`'s
// default, link-at-first-sign-in: a pre-provisioned person meets the service
// provider's own sign-in screen once, as themselves, before their account is
// linked to the partner (development checks no password there), and an entry
// a sign-in CREATES is named `<relationship>~<name>`. Which people a partner
// may assert is `tests/federation_subject_policy.js`'s.
//
// WHY A CHILD PROCESS: it loads the whole protocol stack, serves it on a
// loopback port, creates a realm and flips four settings.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'federation_provisioning', level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.FP_ROOT;
  const OUT = process.env.FP_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const audit = require(ROOT + '/common/audit');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const federation = require(ROOT + '/federation/federation');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    const SP = 'fpsp';
    const REL = 'fp-oidc';

    // --- a cookie jar, and a request that keeps it --------------------------
    let jar = {};
    function cookieHeader() {
      return Object.keys(jar).map(function (k) {
        return k + '=' + jar[k];
      }).join('; ');
    }
    function request(method, target, opts) {
      const o = opts || {};
      const url = new URL(target, base);
      return new Promise(function (resolve) {
        const body = o.json !== undefined ? JSON.stringify(o.json)
          : (o.form ? new URLSearchParams(o.form).toString() : '');
        const headers = Object.assign({ cookie: cookieHeader() },
                                      o.headers || {});
        if (method !== 'GET') {
          headers['content-type'] = o.json !== undefined
            ? 'application/scim+json' : 'application/x-www-form-urlencoded';
          headers['content-length'] = Buffer.byteLength(body);
        }
        const req = http.request({ host: '127.0.0.1', port: port,
          path: url.pathname + url.search, method: method, headers: headers },
        function (res) {
          [].concat(res.headers['set-cookie'] || []).forEach(function (line) {
            const pair = String(line).split(';')[0];
            const i = pair.indexOf('=');
            if (i > 0) {
              const name = pair.slice(0, i).trim();
              const value = pair.slice(i + 1).trim();
              if (value) {
                jar[name] = value;
              } else {
                delete jar[name];
              }
            }
          });
          let text = '';
          res.on('data', function (c) { text += c; });
          res.on('end', function () {
            let json = null;
            try {
              json = JSON.parse(text);
            } catch (e) {
              json = { parseError: e.message };
            }
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text, json: json, path: url.pathname });
          });
        });
        req.end(body);
      });
    }

    // THE WHOLE FEDERATED SIGN-IN, redirect by redirect. Returns the final
    // answer: the service provider's signed-in page, or its refusal.
    async function federatedSignIn(username) {
      jar = {};
      let r = await request('GET', '/realm/' + SP + '/federation/login/' + REL);
      for (let hop = 0; hop < 20; hop += 1) {
        if (r.status >= 300 && r.status < 400 && r.headers.location) {
          r = await request('GET', r.headers.location);
          continue;
        }
        const authnId = /name="authn_id" value="([^"]+)"/.exec(r.text);
        if (r.status === 200 && authnId) {
          // THE SCREEN'S OWN REALM (#109): the partner's, or — for a person
          // who already exists here and is not linked yet — the service
          // provider's own linking sign-in (link-at-first-sign-in, the
          // default), where the name is fixed and development checks no
          // password.
          const realmPrefix = r.path.indexOf('/realm/' + SP + '/') === 0
            ? '/realm/' + SP : '';
          r = await request('POST', realmPrefix + '/authn/login', { form: {
            authn_id: authnId[1], username: username, password: 'x',
            action: 'login' } });
          continue;
        }
        return r;
      }
      return r;
    }

    async function inSp(fn) {
      return realms.run(realms.get(SP), fn);
    }
    function entryOf(name) {
      const found = ldap.existingUserEntry(name);
      return found || null;
    }
    function attr(entry, name) {
      return entry ? (entry.attributes[name.toLowerCase()] || []) : [];
    }

    // --- the partner, and the relationship to it ----------------------------
    config.setOverride('federation.outboundAllowInsecure', 'true');
    config.setOverride('oauth2.consentRequired', 'false');
    const discovery = await request('GET',
                                    '/.well-known/openid-configuration');
    realms.create({ id: SP });
    const created = await inSp(function () {
      const made = federation.create({ fedId: REL,
        fedRole: 'service-provider', fedProtocol: 'oidc' });
      const set = function (field, value) {
        return federation.update(REL, { field: field, value: value });
      };
      set('fedPeer', discovery.json.issuer);
      set('fedSsoUrl', discovery.json.authorization_endpoint);
      set('fedTokenUrl', discovery.json.token_endpoint);
      // OIDC Core section 5.4 (#118): the code flow's ID Token carries no
      // profile claims, so the name and address come from UserInfo.
      set('fedUserinfoUrl', discovery.json.userinfo_endpoint);
      set('fedJwksUri', discovery.json.jwks_uri);
      set('fedClientId', 'fp-sp-client');
      set('fedScope', 'openid profile email');
      set('fedUsernameSource', 'preferred_username');
      const enabled = set('fedEnabled', 'TRUE');
      return { made: made, enabled: enabled, record: federation.get(REL) };
    });
    note(created.made.ok && created.enabled.ok,
         '0a. an OIDC service-provider relationship to this service\'s own ' +
         'OpenID Provider is created and enabled',
         JSON.stringify(created.enabled.errors || created.made.errors || []));
    note(created.record && created.record.fedAutocreateUsers === 'TRUE' &&
         created.record.fedUpdateUserAttributes === 'TRUE',
         '0b. a new relationship has BOTH provisioning switches on by default',
         created.record && JSON.stringify({
           a: created.record.fedAutocreateUsers,
           u: created.record.fedUpdateUserAttributes }));
    const setRel = function (field, value) {
      return inSp(function () {
        return federation.update(REL, { field: field, value: value });
      });
    };

    // =======================================================================
    // 1. DYNAMIC PROVISIONING: the first sign-in creates the entry
    // =======================================================================
    let r = await federatedSignIn('fp-dyn');
    // #109: an entry a sign-in CREATES is namespaced to the relationship.
    const dyn = await inSp(function () { return entryOf(REL + '~fp-dyn'); });
    note(r.status === 200 && dyn,
         '1a. DYNAMIC: a person nobody provisioned signs in through the ' +
         'partner, and the service provider CREATES their entry — ' +
         'namespaced to the relationship since #109',
         r.status + ' ' + r.text.replace(/\s+/g, ' ').slice(0, 200));
    note(dyn && attr(dyn, 'entryUUID').length === 1,
         '1b. and it has an entryUUID — the subject of the session',
         dyn && JSON.stringify(attr(dyn, 'entryUUID')));
    note(dyn && /@/.test(attr(dyn, 'mail')[0] || ''),
         '1c. with the partner\'s email claim mapped onto mail',
         dyn && JSON.stringify(attr(dyn, 'mail')));
    note(dyn && attr(dyn, 'federationRelationship').indexOf(REL) >= 0,
         '1d. and a record of the relationship it came through');
    note(dyn && attr(dyn, 'federationLink').length === 1 &&
         attr(dyn, 'federationLink')[0].indexOf(REL + ' ') === 0,
         '1e. and the link to the partner\'s subject, made at creation',
         dyn && JSON.stringify(attr(dyn, 'federationLink')));

    // =======================================================================
    // 2. PRE-PROVISIONING, NOBODY PROVISIONED: refused
    // =======================================================================
    await setRel('fedAutocreateUsers', 'FALSE');
    r = await federatedSignIn('fp-absent');
    const absent = await inSp(function () {
      return entryOf('fp-absent') || entryOf(REL + '~fp-absent');
    });
    // The SERVICE PROVIDER's audit log: a realm's rows are its own.
    const refusedCodes = (await inSp(function () {
      return audit.list();
    })).filter(function (event) {
      return event.errorCode === 'STS-AUTHN-0180' ||
             event.errorCode === 'STS-FED-0090';
    }).map(function (event) { return event.errorCode; });
    note(r.status === 403 && /not been provisioned/.test(r.text) && !absent,
         '2a. PRE-PROVISIONED ONLY: a sign-in for somebody with no entry is ' +
         'REFUSED 403 "has not been provisioned", and nothing is created',
         r.status + ' ' + r.text.replace(/\s+/g, ' ').slice(0, 240));
    note(refusedCodes.indexOf('STS-AUTHN-0180') >= 0,
         '2b. recorded as STS-AUTHN-0180 (no entry, so no subject)',
         JSON.stringify(refusedCodes));

    // =======================================================================
    // 3. PRE-PROVISIONED THROUGH SCIM: signs in onto that entry
    // =======================================================================
    await inSp(function () {
      ldap.createUser('fp-scim-caller', { invent: false });
    });
    const scimAuth = { authorization: 'Basic ' +
      Buffer.from('fp-scim-caller:anything').toString('base64') };
    const provisioned = await request('POST', '/realm/' + SP +
                                      '/scim/v2/Users', {
      headers: scimAuth, json: {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
        userName: 'fp-pre', emails: [{ value: 'pre@scim.example',
                                       primary: true }] } });
    note(provisioned.status === 201 && provisioned.json.id,
         '3a. a person is PRE-PROVISIONED through SCIM in the service ' +
         'provider\'s realm', provisioned.status + ' ' +
         provisioned.text.slice(0, 200));
    r = await federatedSignIn('fp-pre');
    const pre = await inSp(function () { return entryOf('fp-pre'); });
    note(r.status === 200 && pre &&
         attr(pre, 'entryUUID')[0] === provisioned.json.id,
         '3b. with provisioning OFF, their federated sign-in SUCCEEDS onto ' +
         'the SCIM-created entry — the same entryUUID SCIM returned as its id',
         r.status + ' ' + (pre && attr(pre, 'entryUUID')[0]) + ' / ' +
         provisioned.json.id);
    note(pre && attr(pre, 'federationRelationship').indexOf(REL) >= 0,
         '3c. and the entry records the relationship it came through');

    // =======================================================================
    // 4. ATTRIBUTE REFRESH ON: the partner's values overwrite the entry's
    // =======================================================================
    note(pre && (attr(pre, 'mail')[0] || '') !== 'pre@scim.example' &&
         /@/.test(attr(pre, 'mail')[0] || ''),
         '4a. REFRESH ON (the default): the returning person\'s mail is ' +
         'overwritten with the partner\'s latest email claim',
         pre && JSON.stringify(attr(pre, 'mail')));

    // =======================================================================
    // 5. ATTRIBUTE REFRESH OFF: the directory keeps what it says
    // =======================================================================
    await setRel('fedUpdateUserAttributes', 'FALSE');
    const kept = await request('POST', '/realm/' + SP + '/scim/v2/Users', {
      headers: scimAuth, json: {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
        userName: 'fp-keep', emails: [{ value: 'keep@scim.example',
                                        primary: true }] } });
    r = await federatedSignIn('fp-keep');
    const keep = await inSp(function () { return entryOf('fp-keep'); });
    note(kept.status === 201 && r.status === 200 && keep &&
         JSON.stringify(attr(keep, 'mail')) === '["keep@scim.example"]',
         '5a. REFRESH OFF: a pre-provisioned person signs in and their ' +
         'directory mail is LEFT as SCIM wrote it',
         r.status + ' ' + (keep && JSON.stringify(attr(keep, 'mail'))));
    note(keep && attr(keep, 'federationRelationship').indexOf(REL) >= 0,
         '5b. while where they came from is still recorded');

    await setRel('fedAutocreateUsers', 'TRUE');
    r = await federatedSignIn('fp-new-noupdate');
    const NEW_NOUPDATE = REL + '~fp-new-noupdate';
    const fresh = await inSp(function () {
      return entryOf(NEW_NOUPDATE);
    });
    note(r.status === 200 && fresh && /@/.test(attr(fresh, 'mail')[0] || ''),
         '5c. REFRESH OFF with provisioning ON: an entry the sign-in CREATES ' +
         'still takes the partner\'s attributes — "off" is about returning ' +
         'people', fresh && JSON.stringify(attr(fresh, 'mail')));
    await inSp(function () {
      ldap.writePerson(ldap.existingUserEntry(NEW_NOUPDATE).dn,
        Object.assign({}, ldap.existingUserEntry(NEW_NOUPDATE).attributes,
                      { mail: ['edited@directory.example'] }));
    });
    r = await federatedSignIn('fp-new-noupdate');
    const again = await inSp(function () {
      return entryOf(NEW_NOUPDATE);
    });
    note(r.status === 200 &&
         JSON.stringify(attr(again, 'mail')) === '["edited@directory.example"]',
         '5d. and on that person\'s NEXT sign-in an edit made in the ' +
         'directory survives', again && JSON.stringify(attr(again, 'mail')));

    // =======================================================================
    // 6. THE SAME SWITCHES, TURNED BACK ON
    // =======================================================================
    await setRel('fedUpdateUserAttributes', 'TRUE');
    r = await federatedSignIn('fp-new-noupdate');
    const refreshed = await inSp(function () {
      return entryOf(NEW_NOUPDATE);
    });
    note(r.status === 200 &&
         (attr(refreshed, 'mail')[0] || '') !== 'edited@directory.example',
         '6a. and with REFRESH back ON the next sign-in overwrites it again',
         refreshed && JSON.stringify(attr(refreshed, 'mail')));

    // =======================================================================
    // 7. THIS SERVICE CREATES NOBODY — product mode's rule, and
    //    `ldap.autocreateUsers` off — AND A PROVISIONED ENTRY STILL RECORDS
    //    THE SIGN-IN (2026-09-18). `autoCreateUser()` returned before its
    //    lookup whenever creation was off, so in product mode a
    //    pre-provisioned person never recorded `federationRelationship` and
    //    never took the partner's attributes. `tests/vendored/
    //    sts_federation_realms.js` found it against a product-mode deployment.
    // =======================================================================
    // In the SERVICE PROVIDER's realm only (set while it is ambient): the
    // identity provider is the default realm, which still creates the people
    // who sign in to it.
    await inSp(function () {
      config.setOverride('ldap.autocreateUsers', 'false');
    });
    const off = await request('POST', '/realm/' + SP + '/scim/v2/Users', {
      headers: scimAuth, json: {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
        userName: 'fp-nocreate', emails: [{ value: 'nocreate@scim.example',
                                            primary: true }] } });
    r = await federatedSignIn('fp-nocreate');
    const recorded = await inSp(function () {
      return entryOf('fp-nocreate');
    });
    note(off.status === 201 && r.status === 200 && recorded &&
         attr(recorded, 'federationRelationship').indexOf(REL) >= 0,
         '7a. CREATION OFF: a provisioned person signs in and the entry ' +
         'records the relationship it came through',
         r.status + ' ' + (recorded &&
           JSON.stringify(attr(recorded, 'federationRelationship'))));
    note(recorded && (attr(recorded, 'mail')[0] || '') !==
         'nocreate@scim.example' && /@/.test(attr(recorded, 'mail')[0] || ''),
         '7b. and, with refresh on, takes the partner\'s mail',
         recorded && JSON.stringify(attr(recorded, 'mail')));
    r = await federatedSignIn('fp-nocreate-nobody');
    const nobody = await inSp(function () {
      return entryOf('fp-nocreate-nobody') ||
             entryOf(REL + '~fp-nocreate-nobody');
    });
    note(r.status === 403 && !nobody,
         '7c. while somebody nobody provisioned is still refused and ' +
         'nothing is created', r.status + ' ' + !!nobody);
    await inSp(function () {
      config.clearOverride('ldap.autocreateUsers');
    });

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'federation-provisioning-' + process.pid +
                        '-' + Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  // UNDER COVERAGE THE PARTNER'S FIRST JWKS IS SLOWER THAN THE BACK CHANNEL
  // WAITS (2026-09-15). The child inherits NODE_V8_COVERAGE, and that first
  // read — the one that makes the realm's keys — took 17.6s instrumented
  // against 1.6s plain, past federation.outboundTimeoutMs's 15s, so every
  // sign-in below was refused "did not answer within 15000ms" in the
  // coverage job only. Set after the filter above, which would strip it,
  // and to the setting's maximum; tests/tools/service.js does the same for
  // the throwaway service.
  if (process.env.NODE_V8_COVERAGE) {
    clean.STS_FEDERATION_OUTBOUND_TIMEOUT_MS = '60000';
  }
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', FP_ROOT: ROOT, FP_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
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
  if (t.check(Array.isArray(findings), 'the child process reported',
              'exit ' + result.status + ' ' +
              String(result.stderr || '').slice(-800))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'federation_provisioning',
  describe: 'a real OIDC federated sign-in between two realms: dynamic ' +
            'provisioning creates the entry, pre-provisioning (SCIM) is ' +
            'required when it is off and refuses somebody unprovisioned, and ' +
            'fedUpdateUserAttributes decides whether a returning person\'s ' +
            'attributes are overwritten',
  run: run
};
