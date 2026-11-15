// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: applications-vectors.js
//
// ---------------------------------------------------------------------------
// THE APPLICATION REGISTER AS NODE ANSWERS IT (#444, phase 4, the
// `applications` slice), for `sts-registers`' port of `common/applications.js`
// (rule 3g) and `sts-mgmt-api`'s `/admin-api/applications` operations.
// Called by `tests/tools/crypto-vectors.js`'s `applications-node.json` row;
// the work runs in a child process of its own, because the clock is frozen
// before anything is required.
//
// THE METHOD. The real register, over the real in-memory directory
// `ldap/ldap_server.js` builds, is driven through a list of steps — every
// protocol kind's sighting and registration, every refusal, the owners, the
// secrets, the provenance pair, renames and deletes, the lookups, and
// `admin_actions.ts`'s `applicationsAction()` and `admin_views.ts`'s
// `applicationsListJson()` for the `/admin-api` operations. Each step
// records:
//
//   * its answer and the code marked on it;
//   * every entry under `ou=applications` after it, as the store holds it;
//   * what it set off elsewhere — the audit rows, the CAEP credential and
//     certificate changes, the GNAP grants ended, the claims fan-outs;
//   * the random bytes it drew, which the Rust test hands back in order.
//
// What the register reads outside itself — settings, the mode's
// predicates, `config.parseAs()`, `mode.inForce()`, the other families'
// answers — is recorded once, as the maps the Rust test's environment
// answers from. The directory the run started from is recorded whole, so
// the Rust directory starts where Node's did.
//
// The other way round, `checkRust()` adopts every entry Rust's register
// wrote into a fresh Node directory and asks Node's own register for it: an
// entry Rust writes is an entry Node reads (the compatible-upgrade rule).
// ---------------------------------------------------------------------------

const fs = require('fs');
const os = require('os');
const path = require('path');

/** The instant the run starts at, milliseconds. */
const START = Date.UTC(2026, 10, 14, 12, 0, 0);

/**
 * A JSON copy: functions and undefined dropped, as JSON.stringify does.
 *
 * @param {any} value - anything
 * @returns {any} its JSON image
 */
function clone(value) {
  if (value === undefined) {
    return null;
  }
  return JSON.parse(JSON.stringify(value, function (k, v) {
    return typeof v === 'bigint' ? String(v) : v;
  }));
}

/**
 * The child: drives the register and writes the vectors.
 *
 * @param {string} ROOT - the repository root
 * @param {string} outFile - where to write
 * @returns {Promise<void>} when written
 */
async function child(ROOT, outFile) {
  // THE CLOCK, frozen before anything is required: every `Date.now()` and
  // every `new Date()` with no argument is the step's instant.
  const RealDate = Date;
  let now = START;
  /** The frozen Date. */
  class FrozenDate extends RealDate {
    /**
     * @param {...any} args - as Date takes them
     */
    constructor(...args) {
      if (args.length === 0) {
        super(now);
      } else {
        // @ts-ignore
        super(...args);
      }
    }

    /** @returns {number} the frozen instant */
    static now() {
      return now;
    }
  }
  // @ts-ignore
  global.Date = FrozenDate;
  const req = function (rel) {
    return require(path.join(ROOT, rel));
  };
  req('common/protocol_stack');
  const config = req('common/config');
  const mode = req('common/mode');
  const errorCodes = req('common/error_codes');
  const stsCrypto = req('common/crypto');
  const audit = req('common/audit');
  const ldap = req('ldap/ldap_server');
  const applications = req('common/applications');
  const adminActions = req('admin-core/admin_actions');
  const adminViews = req('admin-core/admin_views');
  const signals = req('ssf/account_signals');
  const scopePolicy = req('common/scope_policy');

  // ---- what the register reads, recorded once --------------------------
  const settings = {};
  const realValue = config.value;
  config.value = function (key) {
    const v = realValue.apply(this, arguments);
    if (typeof key === 'string' && !(key in settings)) {
      settings[key] = clone(v);
    }
    return v;
  };
  const modes = {};
  Object.keys(mode).forEach(function (name) {
    const f = mode[name];
    if (typeof f !== 'function' || name === 'inForce' ||
        name === 'allowsValue' || name === 'writeRefusalReason') {
      return;
    }
    mode[name] = function () {
      const v = f.apply(this, arguments);
      if (arguments.length === 0 && typeof v === 'boolean') {
        modes[name] = v;
      }
      return v;
    };
  });
  const parses = [];
  const realParse = config.parseAs;
  config.parseAs = function (key, raw) {
    const v = realParse.apply(this, arguments);
    parses.push({ key: key, raw: String(raw), answer: clone(v) });
    return v;
  };
  const inForce = [];
  const realInForce = mode.inForce;
  mode.inForce = function (key, value) {
    const v = realInForce.apply(this, arguments);
    inForce.push({ key: key, value: clone(value), answer: clone(v) });
    return v;
  };
  const allows = [];
  const realAllows = mode.allowsValue;
  mode.allowsValue = function (key, value) {
    const v = realAllows.apply(this, arguments);
    allows.push({ key: key, value: clone(value), answer: !!v });
    return v;
  };
  const scopeKept = [];
  const realJudge = scopePolicy.judge;
  scopePolicy.judge = function (scope, identifier) {
    const v = realJudge.apply(this, arguments);
    scopeKept.push({ scope: String(scope), identifier: String(identifier),
                     kept: (v.kept || []).indexOf(scope) >= 0 });
    return v;
  };

  // ---- what a step sets off and draws, recorded per step ---------------
  let effects = null;
  let random = null;
  const note = function (row) {
    if (effects) {
      effects.push(clone(row));
    }
  };
  // An application entry's removal is announced by the directory
  // (`noteApplicationRemoved()`): the RISC account-purged row it sets off is
  // recorded as that one notice, which is what the Rust register hands its
  // effects port.
  const realAudit = audit.audit;
  audit.audit = function (row) {
    if (row && row.action === 'risc.event.auto' &&
        String(row.target || '').indexOf('application:') === 0) {
      note({ kind: 'applicationRemoved',
             identifier: String(row.target).slice('application:'.length),
             dn: String((row.detail || {}).dn || ''),
             via: 'the application registry' });
    } else {
      note({ kind: 'audit', row: row });
    }
    return realAudit.apply(this, arguments);
  };
  const realFailure = audit.failure;
  audit.failure = function (code, row) {
    note({ kind: 'failure', code: String(code), row: row });
    return realFailure.apply(this, arguments);
  };
  ['credentialChanged', 'certificateChanged'].forEach(function (name) {
    signals[name] = function (notice) {
      note({ kind: name, notice: notice });
    };
  });
  signals.claimsFanOut = function (spec) {
    note({ kind: 'claimsFanOut', reasonAdmin: spec.reasonAdmin });
  };
  // THE FGA LIFECYCLE SLOT (#564), filled by the XACML family when the
  // stack loads: a recorder stands in, as the Rust test's does, so a
  // create and a delete are seen to call it and nothing else of the XACML
  // family enters the vectors.
  applications.setFgaLifecycle({
    created: function (identifier, actor, policy) {
      note({ kind: 'fga', which: 'created', identifier: identifier,
             actor: actor, policy: policy });
      return { ok: true };
    },
    deleted: function (identifier, actor, policy) {
      note({ kind: 'fga', which: 'deleted', identifier: identifier,
             actor: actor, policy: policy });
      return { ok: true };
    }
  });
  const realRandom = stsCrypto.randomBytes;
  stsCrypto.randomBytes = function (n) {
    const out = realRandom.apply(this, arguments);
    if (random) {
      random.push(Buffer.from(out).toString('hex'));
    }
    return out;
  };

  // ---- the directory the run starts from -------------------------------
  const base = ldap.baseDn();
  const person = function (name) {
    const made = ldap.createUser(name, { invent: false, attributes: {
      cn: name, sn: name, givenName: name, mail: name + '@example.test' } });
    if (!made || made.ok === false) {
      throw new Error(name + ' was not made: ' + JSON.stringify(made));
    }
  };
  person('olive');
  person('pavel');
  const group = ldap.createGroup('app-owners', {});
  if (group && group.ok === false) {
    throw new Error('the group was not made: ' + JSON.stringify(group));
  }
  const entryOf = function (stored) {
    const attributes = {};
    Object.keys(stored.attributes).forEach(function (name) {
      attributes[name] = stored.attributes[name].slice(0);
    });
    const out = { dn: stored.dn, attributes: attributes };
    ['origin', 'createdAt', 'modifiedAt'].forEach(function (key) {
      if (stored[key] !== undefined) {
        out[key] = String(stored[key]);
      }
    });
    return out;
  };
  const everything = function () {
    const out = [];
    for (const pair of ldap.entries.realmMap('default')) {
      out.push(entryOf(pair[1]));
    }
    return out;
  };
  const container = String(ldap.applicationsDn()).toLowerCase();
  const registered = function () {
    return everything().filter(function (one) {
      const dn = one.dn.toLowerCase();
      return dn !== container && dn.endsWith(',' + container);
    });
  };
  const initial = everything();

  // ---- the steps -------------------------------------------------------
  const steps = [];
  const step = function (op, args, run) {
    effects = [];
    random = [];
    let answer;
    let threw = null;
    try {
      answer = run();
      // The credential changes a write queued for the end of the turn,
      // announced now so that they are this step's.
      applications.flushCredentialWrites();
    } catch (e) {
      threw = String((e && e.message) || e);
    }
    const row = { op: op, args: clone(args), now: now,
                  answer: answer === undefined ? null : clone(answer),
                  code: (answer && typeof answer === 'object' &&
                         errorCodes.codeOf(answer)) || null,
                  effects: effects, random: random, entries: registered() };
    if (threw) {
      row.threw = threw;
    }
    effects = null;
    random = null;
    steps.push(row);
    now += 1000;
    return answer;
  };
  const seen = function (detail) {
    return step('seen', [detail], function () {
      return applications.seen(detail);
    });
  };
  const create = function (detail) {
    return step('create', [detail], function () {
      return applications.createApplication(detail);
    });
  };
  const update = function (identifier, change) {
    return step('update', [identifier, change], function () {
      return applications.updateApplication(identifier, change);
    });
  };
  const call = function (op, args) {
    return step(op, args, function () {
      return applications[op].apply(applications, args);
    });
  };
  const act = function (body, protocols) {
    return step('action', [body, protocols === undefined ? null : protocols],
      function () {
        return adminActions.applicationsAction(Object.assign({}, body),
          protocols, { via: 'api', actor: 'vector-admin',
                       authorizationServers: [], base: 'https://sts.test' });
      });
  };
  const listJson = function (query) {
    return step('listJson', [query], function () {
      return adminViews.applicationsListJson({ query: query }).json;
    });
  };

  // SIGHTINGS, every protocol kind (development mode files on sight).
  seen({ identifier: 'web-client', kind: ['oauth2-client',
         'oidc-relying-party'], protocol: 'OAuth 2.0 / OIDC',
         fields: { oauthClientId: 'web-client',
                   oauthRedirectUri: 'https://web.example/cb' },
         user: 'olive', sessionId: 'sid-1' });
  seen({ identifier: 'web-client', kind: 'oauth2-client',
         protocol: 'OAuth 2.0 / OIDC', user: 'pavel', sessionId: 'sid-2',
         fields: { oauthRedirectUri: 'https://web.example/other' } });
  seen({ identifier: 'web-client', kind: 'oauth2-client', counts: false });
  seen({ identifier: 'https://sp.example/saml', kind: 'saml2-service-provider',
         protocol: 'SAML 2.0', name: 'A SAML SP',
         fields: { samlEntityId: 'https://sp.example/saml',
                   samlAssertionConsumerService: 'https://sp.example/acs' },
         note: 'first seen at /saml2' });
  seen({ identifier: 'urn:rp:saml11', kind: 'saml11-relying-party',
         protocol: 'SAML 1.1' });
  seen({ identifier: 'urn:wsfed:realm', kind: 'wsfed-relying-party',
         protocol: 'WS-Federation',
         fields: { wsfedRealm: 'urn:wsfed:realm',
                   wsfedReplyUrl: 'https://wsfed.example/reply' } });
  seen({ identifier: 'https://wstrust.example/service',
         kind: 'wstrust-relying-party', protocol: 'WS-Trust',
         fields: { wstrustAppliesTo: 'https://wstrust.example/service' } });
  seen({ identifier: 'HTTP/host.example.test@EXAMPLE.TEST',
         kind: 'kerberos-service', protocol: 'Kerberos',
         fields: { krb5ServicePrincipalName:
                     'HTTP/host.example.test@EXAMPLE.TEST' } });
  seen({ identifier: 'gnap-instance-1', kind: 'gnap-client',
         protocol: 'GNAP' });
  seen({ identifier: 'https://idp.partner.example', protocol: 'SAML 2.0',
         kind: 'federation-identity-provider' });
  seen({ identifier: 'verifier-1', kind: 'oid4vp-verifier',
         protocol: 'OpenID4VP' });
  seen({ identifier: 'odd-kind', kind: 'not-a-kind', protocol: 'x' });
  seen({ identifier: '' });
  seen({ identifier: 'x'.repeat(80), kind: 'oauth2-client' });

  // REGISTRATIONS, every family, and every refusal of a create.
  create({ identifier: 'reg-oauth', name: 'Registered OAuth', kind:
           'oauth2-client', protocols: ['oauth2', 'oidc'],
           fields: { oauthRedirectUri: ['https://reg.example/cb'],
                     oauthClientSecret: 'a-typed-secret',
                     oauthPostLogoutRedirectUri: 'https://reg.example/out',
                     appHomePageUrl: 'https://reg.example/',
                     appCorsOrigin: ['https://REG.example:443'],
                     oauthAllowedScope: ['openid', 'profile'] },
           lifetimeDays: 30, actor: 'vector-admin' });
  create({ identifier: 'reg-saml2', kind: 'saml2-service-provider',
           protocols: 'saml2', fields: {
             samlAssertionConsumerService: 'https://saml.example/acs' } });
  create({ identifier: 'reg-saml11', protocols: ['saml11'] });
  create({ identifier: 'urn:reg:wsfed', protocols: ['wsfed'], fields: {
             wsfedReplyUrl: 'https://wsfed.reg.example/' } });
  create({ identifier: 'https://wstrust.reg.example/', protocols:
           ['wstrust'] });
  create({ identifier: 'HTTP/reg.example.test@EXAMPLE.TEST',
           protocols: ['krb5'] });
  create({ identifier: 'reg-spiffe', protocols: ['spiffe'], fields: {
             spiffeWorkloadId: 'spiffe://example.test/workload' } });
  create({ identifier: 'reg-ldap', protocols: ['ldap'], fields: {
             ldapBindDn: 'cn=reg-ldap,' + base } });
  create({ identifier: 'reg-scim', protocols: 'scim' });
  create({ identifier: 'reg-mtls', protocols: ['mtls', 'oauth2'] });
  create({ identifier: 'reg-ssf', protocols: ['ssf'] });
  create({ identifier: 'reg-gnap', protocols: ['gnap'] });
  create({ identifier: 'reg-many', protocols: 'uma acme,est scep did ' +
           'secret-destination scim-client oid4vci oid4vp federation' });
  create({ identifier: 'reg-api', name: 'An API', kind:
           'oauth2-resource-server', protocols: ['oauth2'], fields: {
             oauthAudience: 'https://api.example/',
             oauthPermissionBaseUri: 'https://api.example/',
             oauthPermission: ['read|Read things', 'write'],
             oauthRoleGatedPermission: 'write' } });
  create({ identifier: '' });
  create({ identifier: 'y'.repeat(513) });
  create({ identifier: 'line\nbreak' });
  create({ identifier: 'reg-oauth' });
  create({ identifier: 'reg-kind', kind: 'no-such-kind' });
  create({ identifier: 'reg-proto', protocols: ['oauth2', 'pigeon', 'owl'] });
  create({ identifier: 'reg-unknown', fields: { notAnAttribute: 'x' } });
  create({ identifier: 'reg-derived', fields: { appAuthentications: '9' } });
  create({ identifier: 'reg-two', protocols: ['oauth2'], fields: {
             oauthTokenEndpointAuthMethod: ['a', 'b'],
             appName: ['one', 'two'] } });
  create({ identifier: 'reg-family', fields: {
             oauthRedirectUri: 'https://family.example/cb' } });
  create({ identifier: 'reg-redirect', protocols: ['oauth2'], fields: {
             oauthRedirectUri: 'not a url' } });
  create({ identifier: 'reg-home', fields: { appHomePageUrl: 'ftp://x' } });
  create({ identifier: 'reg-cors', fields: { appCorsOrigin: 'nope' } });
  create({ identifier: 'reg-scope', protocols: ['oauth2'], fields: {
             oauthAllowedScope: 'has space' } });
  create({ identifier: 'reg-perm', protocols: ['oauth2'], fields: {
             oauthPermission: 'read' } });
  create({ identifier: 'reg-perm2', protocols: ['oauth2'], fields: {
             oauthPermissionBaseUri: 'https://p2.example/',
             oauthPermission: ['read', 'read|again'] } });
  create({ identifier: 'reg-gated', protocols: ['oauth2'], fields: {
             oauthPermissionBaseUri: 'https://p3.example/',
             oauthPermission: 'read', oauthRoleGatedPermission: 'write' } });
  create({ identifier: 'reg-life', protocols: ['oauth2'], lifetimeDays: 'x' });
  create({ identifier: 'reg-life2', protocols: ['oauth2'], lifetimeDays: 7 });
  create({ identifier: 'reg-conf', protocols: ['oauth2'], fields: {
             oauthConfidential: 'maybe' } });
  create({ identifier: 'reg-conf2', protocols: ['oauth2'], fields: {
             oauthConfidential: 'TRUE',
             oauthTokenEndpointAuthMethod: 'none' } });
  create({ identifier: 'reg-backchannel', protocols: ['oauth2', 'oidc'],
           fields: { oauthBackchannelLogoutUri: 'http://rp.example/bc',
                     oauthTokenEndpointAuthMethod: 'none' } });

  // ONE ATTRIBUTE AT A TIME: sets, adds and removes, and every refusal.
  update('reg-oauth', { attribute: 'appName', mode: 'set',
                        value: 'Renamed OAuth' });
  update('reg-oauth', { attribute: 'description', mode: 'set',
                        value: 'described' });
  update('reg-oauth', { attribute: 'oauthRedirectUri', mode: 'add',
                        value: 'https://reg.example/cb2' });
  update('reg-oauth', { attribute: 'oauthRedirectUri', mode: 'add',
                        value: 'https://reg.example/cb2' });
  update('reg-oauth', { attribute: 'oauthRedirectUri', mode: 'remove',
                        value: 'https://reg.example/cb' });
  update('reg-oauth', { attribute: 'appHomePageUrl', mode: 'set',
                        value: '' });
  update('reg-oauth', { attribute: 'appCorsOrigin', mode: 'add',
                        value: 'https://Other.example' });
  update('reg-oauth', { attribute: 'appCorsOrigin', mode: 'remove',
                        value: 'https://other.example:443' });
  update('reg-oauth', { attribute: 'oauthTokenEndpointAuthMethod',
                        mode: 'add', value: 'private_key_jwt' });
  update('reg-oauth', { attribute: 'oauthResponseType', mode: 'add',
                        value: 'token code' });
  update('nobody-here', { attribute: 'appName', mode: 'set', value: 'x' });
  update('reg-oauth', { attribute: 'noSuchAttribute', mode: 'set',
                        value: 'x' });
  update('reg-oauth', { attribute: 'appAuthentications', mode: 'set',
                        value: '3' });
  update('reg-oauth', { attribute: 'appName', mode: 'add', value: 'x' });
  update('reg-oauth', { attribute: 'oauthRedirectUri', mode: 'set',
                        value: 'x' });
  update('reg-oauth', { attribute: 'oauthRedirectUri', mode: 'add',
                        value: '' });
  update('reg-oauth', { attribute: 'oauthScope', mode: 'add',
                        value: 'openid' });
  update('reg-oauth', { attribute: 'oauthRedirectUri', mode: 'add',
                        value: 'javascript:alert(1)' });
  update('reg-saml11', { attribute: 'oauthRedirectUri', mode: 'add',
                         value: 'https://x.example/cb' });
  update('reg-oauth', { attribute: 'appAllowedProtocol', mode: 'add',
                        value: 'carrier-pigeon' });
  update('reg-oauth', { attribute: 'appAllowedProtocol', mode: 'add',
                        value: 'saml2' });
  update('reg-oauth', { attribute: 'oauthAssertionKeySource', mode: 'set',
                        value: 'stolen' });
  update('reg-oauth', { attribute: 'oauthGlobalConsent', mode: 'add',
                        value: 'openid' });
  update('reg-oauth', { attribute: 'oauthGlobalConsent', mode: 'remove',
                        value: 'openid' });
  update('reg-oauth', { attribute: 'oauthGlobalConsent', mode: 'add',
                        value: 'two words' });
  update('reg-oauth', { attribute: 'oauthAllowedScope', mode: 'add',
                        value: 'bad"scope' });
  update('reg-oauth', { attribute: 'oauthAllowedScope', mode: 'remove',
                        value: 'profile' });
  update('reg-oauth', { attribute: 'oauthDelegatedPermission', mode: 'add',
                        value: 'https://api.example/read' });
  update('reg-oauth', { attribute: 'oauthDelegatedPermission', mode: 'add',
                        value: 'https://api.example/none' });
  update('reg-api', { attribute: 'oauthDelegatedPermission', mode: 'add',
                      value: 'https://api.example/read' });
  update('reg-oauth', { attribute: 'oauthDelegatedPermission',
                        mode: 'remove', value: 'https://api.example/read' });
  update('reg-api', { attribute: 'oauthPermission', mode: 'add',
                      value: 'admin|Administer' });
  update('reg-api', { attribute: 'oauthPermission', mode: 'add',
                      value: 'read|Again' });
  update('reg-api', { attribute: 'oauthPermission', mode: 'add',
                      value: 'bad name' });
  update('reg-api', { attribute: 'oauthPermission', mode: 'remove',
                      value: 'admin|Administer' });
  update('reg-api', { attribute: 'oauthRoleGatedPermission', mode: 'add',
                      value: 'nothing' });
  update('reg-saml11', { attribute: 'oauthPermission', mode: 'add',
                         value: 'read' });
  update('reg-oauth', { attribute: 'appMayAct', mode: 'add',
                        value: 'cn=reg-oauth,' + ldap.applicationsDn() });
  update('reg-oauth', { attribute: 'appOwner', mode: 'add',
                        value: 'uid=olive,ou=users,' + base });
  update('reg-oauth', { attribute: 'oauthConfidential', mode: 'add',
                        value: 'TRUE' });
  update('reg-oauth', { attribute: 'oauthConfidential', mode: 'set',
                        value: '' });
  update('reg-oauth', { attribute: 'oauthConfidential', mode: 'set',
                        value: 'FALSE' });
  update('reg-oauth', { attribute: 'oauthConfidential', mode: 'set',
                        value: 'TRUE' });
  update('reg-oauth', { attribute: 'oauthClientSecret', mode: 'set',
                        value: 'another-typed-secret' });

  // THE RETURN-ADDRESS PROVENANCE PAIR, and a sighting's observed mark.
  call('confirmReturnAddress', ['web-client', {
    attribute: 'oauthRedirectUri', value: 'https://web.example/cb' }]);
  call('discardReturnAddress', ['web-client', {
    attribute: 'oauthRedirectUri', value: 'https://web.example/other' }]);
  call('confirmReturnAddress', ['web-client', {
    attribute: 'oauthRedirectUri', value: 'https://web.example/cb' }]);
  call('discardReturnAddress', ['web-client', {
    attribute: 'notAnAddress', value: 'x' }]);
  call('discardReturnAddress', ['web-client', {
    attribute: 'oauthRedirectUri', value: '' }]);
  call('confirmReturnAddress', ['nobody', { attribute: 'oauthRedirectUri',
                                            value: 'x' }]);

  // THE OWNERS.
  call('addOwner', ['reg-saml2', 'olive']);
  call('addOwner', ['reg-saml2', 'uid=olive,ou=users,' + base]);
  call('addOwner', ['reg-saml2', 'app-owners']);
  call('addOwner', ['reg-saml2', 'nobody-at-all']);
  call('addOwner', ['reg-saml2', '']);
  call('addOwner', ['no-app', 'olive']);
  call('removeOwner', ['reg-saml2', 'UID=Olive, ou=users,' + base]);
  call('removeOwner', ['reg-saml2', 'pavel']);
  call('ownerProtected', ['reg-saml2']);
  call('setOwnerProtected', ['reg-saml2', true]);
  call('setOwnerProtected', ['reg-saml2', true]);
  call('ownerProtected', ['reg-saml2']);
  call('setOwnerProtected', ['reg-saml2', false]);
  call('renameOwner', ['cn=app-owners,ou=groups,' + base,
                       'cn=owners-renamed,ou=groups,' + base]);
  call('forgetOwner', ['cn=owners-renamed,ou=groups,' + base]);

  // THE CLIENT SECRETS.
  call('addClientSecret', ['reg-oauth', { description: 'second',
                                          lifetimeDays: 10,
                                          actor: 'vector-admin' }]);
  call('addClientSecret', ['reg-oauth', { lifetimeDays: 'forever' }]);
  call('addClientSecret', ['nobody', {}]);
  call('rotateClientSecret', ['reg-oauth', { actor: 'vector-admin' }]);
  call('regenerateClientSecret', ['reg-saml2', {}]);
  call('regenerateClientSecret', ['reg-oauth', {}]);
  call('removeClientSecret', ['reg-oauth', { id: 'cs-nothing' }]);

  // THE FGA STATE.
  call('setFgaState', ['reg-oauth', { policy: 'urn:fga:reg-oauth',
                                      enforced: true },
                       { actor: 'vector-admin' }]);
  call('setFgaState', ['reg-oauth', { enforced: true }, {}]);
  call('setFgaState', ['nobody', { enforced: true }, {}]);
  call('fgaStateOf', ['reg-oauth']);
  call('applicationsEnforcingFga', []);

  // THE LOOKUPS: a client id, an audience, an AppliesTo or entityID, an
  // SPN, a permission, a WS-Federation realm (its identifier), a setting.
  call('get', ['urn:wsfed:realm']);
  call('get', ['not-registered']);
  call('forClientId', ['web-client']);
  call('forClientId', ['  ']);
  call('everyForClientId', ['web-client']);
  call('forAudience', ['https://api.example/']);
  call('forAppliesTo', ['https://wstrust.example/service']);
  call('forAppliesTo', ['https://sp.example/saml']);
  call('forServicePrincipal', ['HTTP/host.example.test@EXAMPLE.TEST']);
  call('forPermission', ['https://api.example/read']);
  call('roleGatingFor', ['https://api.example/write']);
  call('holdsPermission', ['reg-oauth', 'https://api.example/read']);
  call('allowedScopesOf', ['reg-oauth']);
  call('isResourceServer', ['reg-api']);
  call('requiredRolesOf', ['reg-oauth']);
  call('applicationsNamingPolicy', ['appAuthnPolicy', 'strict']);
  call('applicationsDeclaredFor', ['oauth2']);
  call('ownerValues', []);
  call('count', []);
  call('list', []);
  call('isInternalIdentifier', ['sts-admin-console']);

  // THE /admin-api ACTS.
  act({ action: 'create', identifier: 'api-made', name: 'Made by the API',
        'field.oauthRedirectUri.0': 'https://api-made.example/cb',
        'field.oauthRedirectUri.1': 'https://api-made.example/cb2',
        'field.appHomePageUrl': 'https://api-made.example/' },
      ['oauth2', 'oidc']);
  act({ action: 'create', identifier: 'api-empty-box',
        'field.oauthRedirectUri.0': '' }, ['oauth2']);
  act({ action: 'create', identifier: 'api-bare' }, []);
  act({ action: 'create', identifier: 'api-made' }, []);
  act({ action: 'set', application: 'api-made', attribute: 'appName',
        value: 'Renamed by the API' });
  act({ action: 'add', application: 'api-made',
        attribute: 'oauthRedirectUri', value: 'https://api-made.example/3' });
  act({ action: 'remove', application: 'api-made',
        attribute: 'oauthRedirectUri', value: 'https://api-made.example/3' });
  act({ action: 'set', attribute: 'appName', value: 'x' });
  act({ action: 'update-fields', application: 'api-made',
        fields: { appName: 'Grid name', oauthRedirectUri:
                  ['https://api-made.example/cb', 'https://grid.example/'],
                  appHomePageUrl: '' } });
  act({ action: 'update-fields', application: 'api-made' });
  act({ action: 'update-fields', application: 'api-made',
        protocols: ['oauth2', 'oidc', 'saml2'], protocolsPresent: true });
  act({ action: 'update-fields', application: 'nobody' , fields: {} });
  act({ action: 'add-owner', application: 'api-made', owner: 'pavel' });
  act({ action: 'add-owner', application: 'api-made', owner: 'nobody-x' });
  act({ action: 'remove-owner', application: 'api-made', owner: 'pavel' });
  act({ action: 'add-secret', application: 'api-made',
        description: 'via the API' });
  act({ action: 'rotate-secret', application: 'api-made' });
  act({ action: 'regenerate-secret', application: 'api-made' });
  act({ action: 'remove-secret', application: 'api-made', secret: 'cs-0' });
  act({ action: 'confirm-address', application: 'api-made',
        attribute: 'oauthRedirectUri', value: 'x' });
  act({ action: 'discard-address', application: 'web-client',
        attribute: 'oauthRedirectUri', value: 'https://web.example/cb' });
  act({ action: 'teleport', application: 'api-made' });
  act({ action: 'forget', application: 'api-bare' });
  act({ action: 'forget', application: 'api-bare' });

  // THE LIST, as getApplications answers it.
  listJson({});
  listJson({ q: 'REG' });
  listJson({ kind: 'oauth2-client', per: '2', page: '2' });
  listJson({ exclude: ['reg-oauth', 'reg-api'], q: 'reg' });

  // A RENAME OUTSIDE THE REGISTER (an ldapmodrdn), found by appIdentifier,
  // and THE DELETES.
  step('rename', ['reg-saml11'], function () {
    const old = ldap.normalizeDn('cn=reg-saml11,' + ldap.applicationsDn());
    const stored = ldap.entries.get(old);
    const attributes = {};
    Object.keys(stored.attributes).forEach(function (name) {
      attributes[name] = stored.attributes[name].slice(0);
    });
    ldap.entries.delete(old);
    const dn = 'cn=renamed-saml11,' + ldap.applicationsDn();
    ldap.adoptEntry(dn, attributes, stored.origin);
    return { dn: dn };
  });
  call('get', ['reg-saml11']);
  update('reg-saml11', { attribute: 'appName', mode: 'set',
                         value: 'Found after a rename' });
  call('deleteApplication', ['reg-saml11', { actor: 'vector-admin' }]);
  call('deleteApplication', ['reg-saml11', {}]);
  call('deleteApplication', ['web-client', {}]);
  seen({ identifier: 'web-client', kind: 'oauth2-client',
         protocol: 'OAuth 2.0 / OIDC' });

  const overrides = {};
  applications.SCHEMA.attributes.forEach(function (row) {
    if (!row.overrides) {
      return;
    }
    const setting = config.SETTINGS.filter(function (one) {
      return one.key === row.overrides;
    })[0];
    overrides[row.overrides] = mode.writeRefusalReason(
      setting ? setting.onlyWhile : '');
  });
  fs.writeFileSync(outFile, JSON.stringify({
    base: base, start: START, initial: initial,
    settings: settings, modes: modes, parses: parses, inForce: inForce,
    allows: allows, scopeKept: scopeKept, refusalReasons: overrides,
    persists: !!req('common/keystore').persists(),
    steps: steps
  }));
}

/**
 * Builds the vectors in a process of its own.
 *
 * @param {string} ROOT - the repository root
 * @returns {any} the vector document
 */
function build(ROOT) {
  const childProcess = require('child_process');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'applications-vectors-'));
  const outFile = path.join(dir, 'applications.json');
  const run = childProcess.spawnSync(process.execPath,
    [__filename, '--child', ROOT, outFile],
    { env: Object.assign({}, process.env, { STS_LOG_LEVEL: 'fatal',
                                            LOG_LEVEL: 'fatal' }),
      stdio: ['ignore', 'ignore', 'inherit'] });
  if (run.status !== 0) {
    throw new Error('the application vector builder failed (' +
      (run.status === null ? run.signal : run.status) + ')');
  }
  const out = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  fs.rmSync(dir, { recursive: true, force: true });
  return out;
}

/**
 * What Rust wrote, read by Node (`tests/rust_crypto_vectors.js`): every
 * entry under `ou=applications` Rust's register ended with is adopted into
 * Node's directory, and Node's own register must find it by its identifier
 * and see in it what Rust's register saw — the name, the kinds, the
 * declared families and every field.
 *
 * @param {any} t - the runner's check collector
 * @param {any} v - applications-rust.json
 */
function checkRust(t, v) {
  const ROOT = path.join(__dirname, '..', '..');
  const req = function (rel) {
    return require(path.join(ROOT, rel));
  };
  const ldap = req('ldap/ldap_server');
  const applications = req('common/applications');
  let read = 0;
  (v.entries || []).forEach(function (row) {
    const dn = row.dn.replace(/,ou=applications,.*$/i,
                              ',' + ldap.applicationsDn());
    const attributes = {};
    Object.keys(row.attributes).forEach(function (name) {
      attributes[name.toLowerCase()] = row.attributes[name].slice(0);
    });
    const stored = { dn: dn, attributes: attributes,
                     origin: row.origin || 'application',
                     createdAt: row.createdAt, modifiedAt: row.modifiedAt };
    ldap.entries.set(ldap.normalizeDn(dn), stored);
    const view = applications.get(row.identifier);
    t.check(!!view, 'applications: Node finds the entry Rust wrote for "' +
                    row.identifier + '"');
    if (!view) {
      return;
    }
    const same = function (what, a, b) {
      t.check(JSON.stringify(a) === JSON.stringify(b),
        'applications: Node reads the ' + what + ' Rust wrote for "' +
        row.identifier + '"', JSON.stringify(a) + ' vs ' + JSON.stringify(b));
    };
    same('name', view.name, row.view.name);
    same('kinds', view.kinds, row.view.kinds);
    same('declared families', view.allowedProtocols,
         row.view.allowedProtocols);
    same('registration', view.registeredBy, row.view.registeredBy);
    same('counters', [view.authentications, view.sessions, view.users],
         [row.view.authentications, row.view.sessions, row.view.users]);
    same('fields', view.fields, row.view.fields);
    ldap.entries.delete(ldap.normalizeDn(dn));
    read++;
  });
  t.check(read > 0, 'applications: Rust wrote ' + read + ' entr(y/ies) ' +
                    'for Node to read');
}

if (require.main === module && process.argv[2] === '--child') {
  child(process.argv[3], process.argv[4]).then(function () {
    process.exit(0);
  }, function (e) {
    console.error((e && e.stack) || e);
    process.exit(1);
  });
}

module.exports = { build: build, checkRust: checkRust };
