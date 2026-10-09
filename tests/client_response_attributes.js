// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/client_response_attributes.js
//
// ---------------------------------------------------------------------------
// HOW A RESPONSE TO A CLIENT IS SIGNED AND ENCRYPTED, AND ITS REQUEST
// DEFAULTS, ARE ATTRIBUTES (#290, 2026-10-08).
//
// Eleven members of OpenID Connect Registration section 2 and JARM section 3
// lived only in `appRegistrationJson`, so neither the console nor
// `/admin-api` could set them. `common/CLAUDE.md` argues the change; what is
// held here:
//
//   1. THE GRAMMAR AT EVERY DOOR: a create, a set and the field grid's
//      `update-fields` refuse what a registration refuses (`none` for an ID
//      Token, a symmetric UserInfo encryption, an `enc` with no `alg`, a
//      negative max age, a malformed acr), with STS-REG-0340, and take a
//      usable value; a registration refuses a symmetric UserInfo encryption
//      (STS-REG-0339). The closed sets are offered as choices.
//   2. REGISTRATION MAPS AND REPLACES: an RFC 7591 registration writes each
//      member to its attribute, `registrationOf()` hands them back from the
//      attributes, and an RFC 7592 update that leaves a member out CLEARS it.
//   3. THE READERS HONOUR A CONSOLE-SET VALUE: `clientConfigOf()` carries
//      them for a client nobody registered, and JARM, the ID Token's
//      encryption and step-up's defaults read them from there; the readers
//      in `oauth2.ts`, the Logout and Command Tokens and the `jwks_uri`
//      prefetch take `clientConfigOf()`, not `registrationOf()`.
//
// The ID Token's own signature is held over HTTP by
// `tests/vendored/sts_oidc_core.js` (section b2), which creates a client
// through `/admin-api` with `oauthIdTokenSignedResponseAlg: ES256`.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const applications = require('../common/applications');
require('../ldap/ldap_server');
const adminActions = require('../admin-core/admin_actions');

const log = require('bunyan').createLogger({
  name: 'client_response_attributes',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const CONSOLE_ID = 'resp-attrs-console-' + process.pid;
const DCR_ID = 'resp-attrs-dcr-' + process.pid;
const REDIRECT = 'https://rp.resp-attrs.example/cb';

function rowOf(rows, name) {
  log.debug("Entering rowOf(). " + name);
  log.debug("Leaving rowOf().");
  return rows.filter(function (one) { return one.attribute === name; })[0];
}

function fieldOf(identifier, name) {
  log.debug("Entering fieldOf(). " + name);
  const entry = applications.get(identifier);
  const value = entry && entry.fields ? entry.fields[name] : undefined;
  log.debug("Leaving fieldOf().");
  return value === undefined ? undefined : [].concat(value)[0];
}

// --- 1. The grammar at every door ----------------------------------------
function grammar(t) {
  log.debug("Entering grammar().");
  const rows = applications.applicationFields();
  const idAlg = rowOf(rows, 'oauthIdTokenSignedResponseAlg');
  const uiAlg = rowOf(rows, 'oauthUserinfoSignedResponseAlg');
  const jarmEnc = rowOf(rows, 'oauthAuthorizationEncryptedResponseAlg');
  t.check(idAlg && (idAlg.choices || []).indexOf('ES256') >= 0 &&
          idAlg.choices.indexOf('none') < 0 &&
          uiAlg && uiAlg.choices.indexOf('none') >= 0 &&
          jarmEnc && jarmEnc.choices.indexOf('RSA-OAEP-256') >= 0 &&
          jarmEnc.choices.indexOf('A128KW') < 0,
          '1a. the algorithms are offered as choices, from the lists the ' +
          'registration grammar checks (no none for an ID Token, no ' +
          'symmetric key wrap)',
          JSON.stringify({ id: idAlg && idAlg.choices,
                           jarm: jarmEnc && jarmEnc.choices }));

  const refusedCreate = applications.createApplication({
    identifier: CONSOLE_ID + '-bad', kind: 'oauth2-client',
    protocols: ['oauth2', 'oidc'],
    fields: { oauthClientId: [CONSOLE_ID + '-bad'],
              oauthIdTokenSignedResponseAlg: 'none' } });
  t.check(refusedCreate && refusedCreate.ok === false &&
          /oauthIdTokenSignedResponseAlg/.test(
            (refusedCreate.errors || []).join(' ')),
          '1b. a create naming an unsigned ID Token is refused, by the ' +
          'attribute\'s name', JSON.stringify(refusedCreate.errors));

  const made = applications.createApplication({
    identifier: CONSOLE_ID, kind: 'oauth2-client',
    protocols: ['oauth2', 'oidc'],
    fields: { oauthClientId: [CONSOLE_ID],
              oauthRedirectUri: [REDIRECT],
              oauthIdTokenSignedResponseAlg: 'ES256',
              oauthAuthorizationSignedResponseAlg: 'PS256',
              oauthDefaultAcrValues: 'mfa 1',
              oauthDefaultMaxAge: '300' } });
  t.check(made && made.ok === true &&
          fieldOf(CONSOLE_ID, 'oauthIdTokenSignedResponseAlg') === 'ES256',
          '1c. a create with usable values stores them',
          JSON.stringify(made && (made.errors || made.ok)));

  const cases = [
    ['oauthUserinfoEncryptedResponseAlg', 'A128KW',
     'a symmetric UserInfo encryption'],
    ['oauthUserinfoEncryptedResponseEnc', 'A256GCM',
     'a UserInfo enc with no alg on the entry'],
    ['oauthIdTokenEncryptedResponseEnc', 'A256GCM',
     'an ID Token enc with no alg on the entry'],
    ['oauthAuthorizationSignedResponseAlg', 'none',
     'an unsigned JARM response'],
    ['oauthIdTokenSignedResponseAlg', 'XX512', 'an unknown algorithm'],
    ['oauthDefaultMaxAge', '-5', 'a negative max age'],
    ['oauthDefaultMaxAge', 'soon', 'a max age that is not a number'],
    ['oauthDefaultAcrValues', 'mfa "x', 'a malformed acr value']
  ];
  cases.forEach(function (one) {
    const r = applications.updateApplication(CONSOLE_ID, {
      mode: 'set', attribute: one[0], value: one[1] });
    t.check(r && r.ok === false &&
            (r.errors || []).join(' ').indexOf(one[0]) >= 0,
            '1d. a set of ' + one[2] + ' is refused, naming ' + one[0],
            JSON.stringify(r && r.errors));
  });

  const viaGrid = adminActions.applicationsAction({ action: 'update-fields',
    application: CONSOLE_ID,
    fields: { oauthUserinfoSignedResponseAlg: 'NOPE256' } }, []);
  t.check(viaGrid && viaGrid.ok === false &&
          /oauthUserinfoSignedResponseAlg/.test(
            (viaGrid.errors || []).join(' ')),
          '1e. the field grid\'s update-fields refuses the same value',
          JSON.stringify(viaGrid && viaGrid.errors));

  const paired = adminActions.applicationsAction({ action: 'update-fields',
    application: CONSOLE_ID,
    fields: { oauthUserinfoSignedResponseAlg: 'RS256',
              oauthUserinfoEncryptedResponseAlg: 'RSA-OAEP-256' } }, []);
  const enc = applications.updateApplication(CONSOLE_ID, {
    mode: 'set', attribute: 'oauthUserinfoEncryptedResponseEnc',
    value: 'A256GCM' });
  t.check(paired && paired.ok === true && enc && enc.ok === true,
          '1f. an alg and then its enc are taken',
          JSON.stringify({ paired: paired && (paired.errors || paired.ok),
                           enc: enc && (enc.errors || enc.ok) }));

  const reg = applications.userinfoEncryptionMetadataProblem({
    userinfo_encrypted_response_alg: 'A128KW' });
  t.check(reg && reg.errorCode === 'STS-REG-0339' &&
          reg.error === 'invalid_client_metadata',
          '1g. a registration naming a symmetric UserInfo encryption is ' +
          'refused invalid_client_metadata', JSON.stringify(reg));
  t.check(applications.clientResponseMetadataProblem({
    id_token_signed_response_alg: 'ES256', default_max_age: 0,
    default_acr_values: ['mfa'],
    authorization_encrypted_response_alg: 'RSA-OAEP-256',
    authorization_encrypted_response_enc: 'A256GCM' }) === null,
          '1h. and a usable set of the eleven is not');
  log.debug("Leaving grammar().");
}

// --- 2. Registration maps and replaces -----------------------------------
function registration(t) {
  log.debug("Entering registration().");
  const first = applications.register(DCR_ID, {
    client_name: DCR_ID, redirect_uris: [REDIRECT],
    grant_types: ['authorization_code'], response_types: ['code'],
    token_endpoint_auth_method: 'client_secret_basic',
    client_secret: 'resp-attrs-secret-' + process.pid,
    id_token_signed_response_alg: 'ES384',
    userinfo_signed_response_alg: 'PS256',
    authorization_signed_response_alg: 'ES256',
    default_acr_values: ['mfa', '1'], default_max_age: 120 });
  t.check(!!first &&
          fieldOf(DCR_ID, 'oauthIdTokenSignedResponseAlg') === 'ES384' &&
          fieldOf(DCR_ID, 'oauthUserinfoSignedResponseAlg') === 'PS256' &&
          fieldOf(DCR_ID, 'oauthAuthorizationSignedResponseAlg') === 'ES256' &&
          fieldOf(DCR_ID, 'oauthDefaultAcrValues') === 'mfa 1' &&
          fieldOf(DCR_ID, 'oauthDefaultMaxAge') === '120',
          '2a. a registration writes each member to its attribute, the acr ' +
          'values in order in one value',
          JSON.stringify(applications.get(DCR_ID) &&
                         applications.get(DCR_ID).fields));

  // An operator's edit: the family first (familyRefusal()), then the value.
  applications.updateApplication(DCR_ID, { mode: 'add',
    attribute: 'appAllowedProtocol', value: 'oidc' });
  const edited = applications.updateApplication(DCR_ID, { mode: 'set',
    attribute: 'oauthIdTokenSignedResponseAlg', value: 'EdDSA' });
  t.check(edited && edited.ok === true,
          '2b. an operator may change a registered client\'s algorithm',
          JSON.stringify(edited && (edited.errors || edited.ok)));
  const read = applications.registrationOf(DCR_ID) || {};
  t.check(read.id_token_signed_response_alg === 'EdDSA' &&
          JSON.stringify(read.default_acr_values) === '["mfa","1"]' &&
          read.default_max_age === 120,
          '2b. the RFC 7592 read hands them back from the attributes — an ' +
          'operator\'s edit included', JSON.stringify(read));

  applications.updateRegistration(DCR_ID, {
    client_name: DCR_ID, redirect_uris: [REDIRECT],
    grant_types: ['authorization_code'], response_types: ['code'],
    token_endpoint_auth_method: 'client_secret_basic',
    id_token_signed_response_alg: 'ES256' });
  const after = applications.registrationOf(DCR_ID) || {};
  t.check(fieldOf(DCR_ID, 'oauthIdTokenSignedResponseAlg') === 'ES256' &&
          fieldOf(DCR_ID, 'oauthUserinfoSignedResponseAlg') === undefined &&
          fieldOf(DCR_ID, 'oauthAuthorizationSignedResponseAlg') ===
            undefined &&
          fieldOf(DCR_ID, 'oauthDefaultAcrValues') === undefined &&
          fieldOf(DCR_ID, 'oauthDefaultMaxAge') === undefined &&
          after.userinfo_signed_response_alg === undefined &&
          after.default_max_age === undefined,
          '2c. an RFC 7592 update that leaves a member out clears it',
          JSON.stringify(after));

  const refused = applications.register(DCR_ID + '-bad', {
    redirect_uris: [REDIRECT],
    userinfo_encrypted_response_enc: 'A256GCM' });
  t.check(refused === null,
          '2d. register()\'s backstop refuses an enc with no alg');
  log.debug("Leaving registration().");
}

// --- 3. The readers honour a console-set value ---------------------------
function readers(t) {
  log.debug("Entering readers().");
  const config = applications.clientConfigOf(CONSOLE_ID);
  t.check(applications.registrationOf(CONSOLE_ID) === null &&
          config.id_token_signed_response_alg === 'ES256' &&
          config.userinfo_signed_response_alg === 'RS256' &&
          config.userinfo_encrypted_response_alg === 'RSA-OAEP-256' &&
          config.userinfo_encrypted_response_enc === 'A256GCM' &&
          JSON.stringify(config.default_acr_values) === '["mfa","1"]' &&
          config.default_max_age === 300,
          '3a. clientConfigOf() carries them for a client nobody registered',
          JSON.stringify(config));

  const jarm = require('../oauth-oidc/jarm');
  const protection = jarm.protectionFor(config);
  t.check(protection && protection.ok && protection.signAlg === 'PS256',
          '3b. JARM signs with the console-set algorithm',
          JSON.stringify(protection));

  const stepUp = require('../oauth-oidc/step_up');
  const need = stepUp.requirementOf({}, config);
  t.check(need.present && need.acrValues.join(' ') === 'mfa 1' &&
          need.maxAge === 300,
          '3c. step-up applies the console-set default_acr_values and ' +
          'default_max_age', JSON.stringify(need));

  applications.updateApplication(CONSOLE_ID, { mode: 'set',
    attribute: 'oauthIdTokenEncryptedResponseAlg', value: 'RSA-OAEP' });
  const idTokenEncryption = require('../oauth-oidc/id_token_encryption');
  const sealed = idTokenEncryption.protectionFor(
    applications.clientConfigOf(CONSOLE_ID));
  t.check(sealed && sealed.ok && sealed.alg === 'RSA-OAEP' &&
          sealed.enc === 'A128CBC-HS256',
          '3d. the ID Token is encrypted as the console says, the default ' +
          'enc applied', JSON.stringify(sealed));

  // THE READERS TAKE clientConfigOf(). registrationOf() answers null for a
  // client nobody registered, so a reader left on it would ignore every
  // value above — read as a statement, for tests/error_codes.js's reason.
  const sources = [
    ['oauth-oidc/oauth2.ts',
     [/const registered(?::\s*Json)?\s*=\s*applications\.registrationOf\(/,
      /requirementOf\(q,\s*(?:this\.deps\.)?applications\.registrationOf\(/]],
    ['oauth-oidc/backchannel_logout.ts',
     [/registered\s*=\s*applications\.registrationOf\(/]],
    ['oauth-oidc/provider_commands.ts',
     [/registered(?::\s*Json)?\s*=\s*applications\.registrationOf\(/]],
    ['oauth-oidc/client_jwks.js',
     [/registered\s*=\s*applications\.registrationOf\(/]]
  ];
  sources.forEach(function (one) {
    const file = path.join(ROOT, one[0]);
    if (!fs.existsSync(file)) {
      t.check(true, '3e. ' + one[0] + ' is not in this tree (stripped)');
      return;
    }
    const text = fs.readFileSync(file, 'utf8');
    const found = one[1].filter(function (re) { return re.test(text); });
    t.check(found.length === 0 && /clientConfigOf\(/.test(text),
            '3e. ' + one[0] + ' reads a client\'s response members through ' +
            'clientConfigOf(), not registrationOf()',
            found.map(String).join(', '));
  });
  log.debug("Leaving readers().");
}

function run(t) {
  log.debug("Entering run().");
  try {
    grammar(t);
    registration(t);
    readers(t);
  } finally {
    [CONSOLE_ID, DCR_ID].forEach(function (id) {
      adminActions.applicationsAction({ action: 'forget', application: id });
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'client response attributes',
  describe: '#290: the ID Token, UserInfo and JARM response members and the ' +
            'request defaults as attributes — one grammar at every door, ' +
            'replaced by a registration, read through clientConfigOf()',
  run: run
};
