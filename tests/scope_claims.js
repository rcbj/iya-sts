// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: scope_claims.js
//
// ---------------------------------------------------------------------------
// WHICH CLAIMS A SCOPE COVERS, WHERE THEY GO, AND HOW TWO SETS OF CLAIMS ARE
// COMBINED (#395).
//
// Asserted, in a CHILD PROCESS that loads the stack, through the functions
// the token endpoint calls (`common/scope_claims.ts`, `admin_stats.jwtClaims()`
// and `oauth2.tokenSet()`):
//
//   A. the library: the gate, the two combines, the intersection of several
//      resource servers' declarations and the mode they agree on;
//   B. the realm's typed rows against an application's own, under each of
//      the four realm-vs-application modes and unset;
//   C. the realm's ticked attributes against an application's selection,
//      likewise;
//   D. a resource server's declared access-token claims: released only
//      when their scope was GRANTED, `preferred_username` no longer on every
//      person's token, combined with the client's under each of the four
//      modes, intersected across two resource servers, and the refusals at
//      the write;
//   E. the gate in the ID Token: a configured section 5.4 claim only when
//      its scope was granted.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'scope_claims',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.SC_ROOT;
  const OUT = process.env.SC_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const realms = require(ROOT + '/common/realms');
    const applications = require(ROOT + '/common/applications');
    const stats = require(ROOT + '/common/admin_stats');
    const claimAttributes = require(ROOT + '/common/claim_attributes');
    const scopeClaims = require(ROOT + '/common/scope_claims');
    const oauth2 = require(ROOT + '/oauth-oidc/oauth2');
    const actions = require(ROOT + '/admin-core/admin_actions');
    const errorCodes = require(ROOT + '/common/error_codes');
    const BASE = 'https://sts.test';
    const keys = function (o) {
      return Object.keys(o || {}).sort().join(',');
    };
    const claimsOf = function (token) {
      return JSON.parse(Buffer.from(String(token).split('.')[1],
                                    'base64url').toString('utf8'));
    };

    // --- A. The library ------------------------------------------------
    const gated = scopeClaims.gate({ name: 'n', email: 'e', address: {},
                                     groups: ['g'], tenant: 't' },
                                   'openid profile', 'test');
    note(keys(gated) === 'groups,name,tenant',
         'A1. the gate keeps a claim whose scope was granted and every ' +
         'claim no scope covers, and drops the rest', keys(gated));
    const realmNames = ['a', 'b'];
    const own = ['b', 'c'];
    note(scopeClaims.combineNames(realmNames, own, 'application').join() ===
           'b,c' &&
         scopeClaims.combineNames(realmNames, own, 'union').join() ===
           'a,b,c' &&
         scopeClaims.combineNames(realmNames, own, 'intersection')
           .join() === 'b' &&
         scopeClaims.combineNames(realmNames, own, 'realm').join() ===
           'a,b' &&
         scopeClaims.combineNames(realmNames, null, 'application')
           .join() === 'a,b',
         'A2. realm against application: the four modes, and holding ' +
         'nothing is the realm\'s');
    const client = { name: 'client', dept: 'd' };
    const resource = { name: 'resource', email: 'e' };
    note(keys(scopeClaims.combineResource(client, resource, 'union')) ===
           'dept,email,name' &&
         scopeClaims.combineResource(client, resource, 'union').name ===
           'client' &&
         keys(scopeClaims.combineResource(client, resource,
                                          'intersection')) === 'name' &&
         keys(scopeClaims.combineResource(client, resource, 'client')) ===
           'dept,name' &&
         keys(scopeClaims.combineResource(client, resource, 'resource')) ===
           'email,name',
         'A3. client against resource server: the four modes, the ' +
         'client\'s value kept on a name both carry');
    note(scopeClaims.intersectDeclared([['name', 'email'], ['name']])
           .join() === 'name' &&
         scopeClaims.intersectDeclared([['name'], []]).length === 0 &&
         scopeClaims.agreedResourceMode(['union', 'union']) === 'union' &&
         scopeClaims.agreedResourceMode(['union', 'resource']) ===
           'intersection',
         'A4. several resource servers: only what every one declared, and ' +
         'intersection when their modes disagree');

    const stamp = String(Date.now()).slice(-6);
    const realm = realms.create({ id: 'sc-' + stamp, name: 'sc' }).realm;
    await realms.run(realm, async function () {
      const act = function (body) {
        return actions.applicationsAction(body, [], {});
      };
      const setField = function (app, attribute, value) {
        return applications.updateApplication(app,
          { mode: 'set', attribute: attribute, value: value });
      };
      const code = function (answer) {
        return errorCodes.codeOf(answer);
      };
      applications.createApplication({ identifier: 'sc-web',
        protocols: ['oauth2', 'oidc'], fields: {} });
      applications.createApplication({ identifier: 'sc-api',
        protocols: ['oauth2'],
        fields: { oauthAudience: ['https://api.sc.test'] } });
      applications.createApplication({ identifier: 'sc-api2',
        protocols: ['oauth2'],
        fields: { oauthAudience: ['https://api2.sc.test'] } });

      // --- B. Typed rows: the realm's against the application's ----------
      stats.setClaimSet('id_token', [{ name: 'dept', value: 'realm' },
                                     { name: 'team', value: 'realm' }]);
      act({ action: 'set-custom-claim', application: 'sc-web',
            set: 'id_token', name: 'team', value: 'app' });
      act({ action: 'set-custom-claim', application: 'sc-web',
            set: 'id_token', name: 'code', value: 'app' });
      const rows = function () {
        const out = {};
        stats.effectiveClaimSet('id_token', { client_id: 'sc-web' })
          .forEach(function (row) { out[row.name] = row.value; });
        return out;
      };
      const unset = rows();
      const modes = {};
      ['application', 'union', 'intersection', 'realm']
        .forEach(function (mode) {
          const set = setField('sc-web', 'oauthClaimsCombineIdToken', mode);
          modes[mode] = set.ok ? rows() : { refused: set.errors };
        });
      note(keys(unset) === 'code,dept,team' && unset.team === 'app',
           'B1. unset: the application\'s rows added, winning by name',
           JSON.stringify(unset));
      note(keys(modes.application) === 'code,team' &&
           keys(modes.union) === 'code,dept,team' &&
           modes.union.team === 'app' &&
           keys(modes.intersection) === 'team' &&
           modes.intersection.team === 'app' &&
           keys(modes.realm) === 'dept,team' && modes.realm.team === 'realm',
           'B2. application, union, intersection and realm',
           JSON.stringify(modes));
      const badMode = setField('sc-web', 'oauthClaimsCombineIdToken',
                               'bogus');
      note(code(badMode) === 'STS-REG-0203',
           'B3. a mode outside the four is refused at the write',
           JSON.stringify([code(badMode), badMode.errors]));
      setField('sc-web', 'oauthClaimsCombineIdToken', '');
      stats.setClaimSet('id_token', []);

      // --- C. Ticked attributes: the realm's against the application's ----
      claimAttributes.setSelection('userinfo', ['mail', 'givenName']);
      act({ action: 'set-claim-attributes', application: 'sc-web',
            set: 'userinfo', attributes: ['givenName', 'sn'] });
      const ticked = function () {
        return claimAttributes.effectiveRows('userinfo',
                                             applications.get('sc-web'))
          .map(function (row) { return row.ldap; }).sort().join(',');
      };
      const selections = { unset: ticked() };
      ['application', 'union', 'intersection', 'realm']
        .forEach(function (mode) {
          setField('sc-web', 'oauthClaimsCombineUserinfo', mode);
          selections[mode] = ticked();
        });
      note(selections.unset === 'givenName,sn' &&
           selections.application === 'givenName,sn' &&
           selections.union === 'givenName,mail,sn' &&
           selections.intersection === 'givenName' &&
           selections.realm === 'givenName,mail',
           'C1. unset replaces (#495); application, union, intersection ' +
           'and realm', JSON.stringify(selections));
      claimAttributes.setSelection('userinfo', []);

      // --- D. A resource server's access-token claims ---------------------
      const person = { username: 'sc-alice', sub: 'urn:uuid:sc-alice',
                       name: 'Alice Person', given_name: 'Alice',
                       preferred_username: 'sc-alice',
                       email: 'alice@sc.test' };
      const issue = async function (scope, audience, client) {
        const body = await oauth2.tokenSet(BASE, {
          client_id: client || 'sc-web', grant: 'authorization_code',
          scope: scope, audience: audience, username: 'sc-alice',
          user: person });
        return claimsOf(body.access_token);
      };
      const before = await issue('openid profile email',
                                 ['https://api.sc.test']);
      note(before.preferred_username === undefined &&
           before.name === undefined && before.email === undefined &&
           before.username === 'sc-alice',
           'D1. a resource server that declares nothing gets no section 5.4 ' +
           'claim, preferred_username included; username stays',
           JSON.stringify(before));
      const declare = { ok: true, errors: [] };
      ['email', 'name', 'preferred_username'].forEach(function (claim) {
        const added = applications.updateApplication('sc-api',
          { mode: 'add', attribute: 'oauthAccessTokenClaim', value: claim });
        declare.ok = declare.ok && added.ok;
        declare.errors = declare.errors.concat(added.errors || []);
      });
      const profileOnly = await issue('openid profile',
                                      ['https://api.sc.test']);
      note(declare.ok && profileOnly.name === 'Alice Person' &&
           profileOnly.preferred_username === 'sc-alice' &&
           profileOnly.email === undefined,
           'D2. declared and granted: name and preferred_username in; ' +
           'email declared but not granted, out',
           JSON.stringify([declare.errors, profileOnly]));
      const withEmail = await issue('openid profile email',
                                    ['https://api.sc.test']);
      note(withEmail.email === 'alice@sc.test' &&
           String(withEmail.scope || '').indexOf('email') < 0,
           'D3. email granted: in, although RFC 9068\'s plan took the ' +
           'OpenID Connect scopes off the token\'s scope claim',
           JSON.stringify(withEmail));
      const own = await issue('openid profile email');
      note(own.name === undefined && own.preferred_username === undefined,
           'D4. a token for this service\'s own resource server carries ' +
           'none: those claims are UserInfo\'s', JSON.stringify(own));

      act({ action: 'set-custom-claim', application: 'sc-web',
            set: 'access_token', name: 'name', value: 'Client Name' });
      act({ action: 'set-custom-claim', application: 'sc-web',
            set: 'access_token', name: 'dept', value: 'd' });
      const combined = {};
      for (const mode of ['', 'union', 'intersection', 'client',
                          'resource']) {
        setField('sc-api', 'oauthAccessTokenClaimsCombine', mode);
        const token = await issue('openid profile', ['https://api.sc.test']);
        combined[mode || 'unset'] = {
          keys: ['dept', 'name', 'preferred_username', 'email']
            .filter(function (n) { return token[n] !== undefined; }).join(),
          name: token.name };
      }
      note(combined.unset.keys === 'dept,name,preferred_username' &&
           combined.unset.name === 'Client Name' &&
           combined.union.keys === 'dept,name,preferred_username' &&
           combined.intersection.keys === 'name' &&
           combined.intersection.name === 'Client Name' &&
           combined.client.keys === 'dept,name' &&
           combined.resource.keys === 'name,preferred_username' &&
           combined.resource.name === 'Alice Person',
           'D5. client against resource server: unset is union, then ' +
           'intersection, client and resource', JSON.stringify(combined));
      setField('sc-api', 'oauthAccessTokenClaimsCombine', '');
      const notGranted = await issue('openid', ['https://api.sc.test']);
      note(notGranted.name === undefined &&
           notGranted.preferred_username === undefined &&
           notGranted.dept === 'd',
           'D6. profile not granted: the client\'s typed `name` is held ' +
           'back too, and a claim no scope covers is not',
           JSON.stringify(notGranted));
      act({ action: 'remove-custom-claim', application: 'sc-web',
            set: 'access_token', name: 'name' });
      act({ action: 'remove-custom-claim', application: 'sc-web',
            set: 'access_token', name: 'dept' });

      applications.updateApplication('sc-api2',
        { mode: 'add', attribute: 'oauthAccessTokenClaim', value: 'name' });
      const both = await issue('openid profile email',
                               ['https://api.sc.test', 'https://api2.sc.test']);
      note(both.name === 'Alice Person' && both.email === undefined &&
           both.preferred_username === undefined,
           'D7. two resource servers: only the claim both declared',
           JSON.stringify(both));
      const badClaim = applications.updateApplication('sc-api',
        { mode: 'add', attribute: 'oauthAccessTokenClaim',
          value: 'groups' });
      const badCombine = setField('sc-api', 'oauthAccessTokenClaimsCombine',
                                  'everything');
      note(code(badClaim) === 'STS-REG-0203' &&
           code(badCombine) === 'STS-REG-0203',
           'D8. a claim outside section 5.4 and an unknown mode are refused',
           JSON.stringify([code(badClaim), code(badCombine)]));

      // --- E. The ID Token ------------------------------------------------
      stats.setClaimSet('id_token', [{ name: 'email', value: 'set@sc.test' },
                                     { name: 'site', value: 'sc' }]);
      const idOf = async function (scope) {
        const body = await oauth2.tokenSet(BASE, {
          client_id: 'sc-web', grant: 'authorization_code', scope: scope,
          username: 'sc-alice', user: person, nonce: 'n' });
        return claimsOf(body.id_token);
      };
      const noEmail = await idOf('openid');
      const yesEmail = await idOf('openid email');
      note(noEmail.email === undefined && noEmail.site === 'sc' &&
           yesEmail.email === 'set@sc.test',
           'E1. a configured email reaches the ID Token only with email ' +
           'granted; a claim no scope covers always',
           JSON.stringify([noEmail, yesEmail]));
      stats.setClaimSet('id_token', []);
    });
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'scope-claims-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', SC_ROOT: ROOT, SC_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
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

function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'scope_claims',
  describe: 'which claims a scope covers and where they go (#395): the ' +
            'gate, the realm-vs-application and client-vs-resource-server ' +
            'combine modes, a resource server\'s declared access-token ' +
            'claims and the ID Token',
  run: run
};
