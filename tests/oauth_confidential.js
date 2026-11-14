// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/oauth_confidential.js
//
// ---------------------------------------------------------------------------
// oauthConfidential FOLLOWS THE TOKEN ENDPOINT AUTHENTICATION METHOD (#466).
//
// Found on 2026-10-06: a create wrote the flag TRUE on an entry whose only
// method was `none`. RFC 9700 reads the method (`oauth2_bcp.js`'s
// `isConfidential()`). The attribute is the registry's record of that
// answer. What is held here, through the doors the console and
// `/admin-api` post to:
//
//   1. A hand-create of an OAuth application infers the method and writes
//      the flag that method makes. `none` and a hand-create with no method
//      are FALSE; a secret is `client_secret_basic` and TRUE; a JWK Set is
//      `private_key_jwt` and TRUE.
//   2. A stated value is kept when it is that determination, including a
//      different case, and refused `STS-REG-0363` when it is not, before
//      anything is created. A bad token is the same code. Two values are
//      `STS-REG-0008`.
//   3. Changing the method rewrites the flag. Setting the flag itself is
//      refused unless the value is the determination, which heals a stale
//      one. A clear, an add and a remove name the method
//      (`STS-REG-0363`), and the generic derived-attribute refusal is not
//      what answers.
//   4. `update-fields` judges the flag against the methods that body
//      leaves. A disagreement writes nothing else in the body. An
//      agreement is written from the methods, so a stale flag heals.
//   5. Adding a secret to a client whose method is `none` replaces `none`
//      with `client_secret_basic` and records TRUE.
//   6. Forgetting a registration recomputes the flag from the methods that
//      remain. An omitted registration method is `client_secret_basic` and
//      TRUE.
//   7. A SAML application gains the attribute only when the caller stated
//      a value that agrees. OpenID4VCI alone is recorded FALSE and is not
//      given an inferred method.
//   8. The field grid does not draw the attribute.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const applications = require('../common/applications');
require('../ldap/ldap_server');
const adminActions = require('../admin-core/admin_actions');
const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({
  name: 'oauth_confidential',
  level: process.env.LOG_LEVEL || 'info' });

const ID = 'oauth-conf-' + process.pid;
const JWKS = '{"keys":[]}';

function create(id, protocols, fields) {
  log.debug("Entering create().");
  const result = adminActions.applicationsAction({
    action: 'create', identifier: id, fields: fields || {}
  }, protocols);
  log.debug("Leaving create().");
  return result;
}

function act(body) {
  log.debug("Entering act().");
  const result = adminActions.applicationsAction(body);
  log.debug("Leaving act().");
  return result;
}

function drop(id) {
  log.debug("Entering drop().");
  if (applications.get(id)) {
    applications.deleteApplication(id);
  }
  log.debug("Leaving drop().");
}

function held(id) {
  log.debug("Entering held().");
  const entry = applications.get(id);
  const fields = entry && entry.fields ? entry.fields : {};
  const raw = fields.oauthTokenEndpointAuthMethod;
  const methods = [].concat(raw === undefined ? [] : raw).map(
    function (one) {
      return String(one);
    });
  const out = {
    present: !!entry,
    flag: fields.oauthConfidential === undefined ? ''
      : String(fields.oauthConfidential),
    methods: methods,
    registered: !!(entry && entry.registered),
    description: entry && entry.description ? String(entry.description) : ''
  };
  log.debug("Leaving held().");
  return out;
}

function code(result) {
  log.debug("Entering code().");
  const marked = errorCodes.codeOf(result);
  log.debug("Leaving code().");
  return marked;
}

function sentence(result) {
  log.debug("Entering sentence().");
  const text = ((result && result.errors) || []).join(' ');
  log.debug("Leaving sentence().");
  return text;
}

// An ldapmodify past the registry: the whole attribute set, with the flag
// replaced, so a later read sees the lie the method does not make.
function plant(id, flag) {
  log.debug("Entering plant().");
  let wrote = false;
  try {
    const store = applications.directoryInstalled();
    const entry = store.readApplication(id);
    const attrs = Object.assign({}, entry.attributes);
    attrs.oauthConfidential = [flag];
    wrote = !!store.writeApplication(id, attrs);
  } catch (e) {
    // The plant stands in for ldapmodify. A throw is this helper's result,
    // so the assertion that asked for the lie reports the failure.
    log.debug("Caught in plant(): " + ((e && e.message) || e));
    wrote = false;
  }
  log.debug("Leaving plant().");
  return wrote;
}

function run(t) {
  log.debug("Entering run().");
  const made = [];
  const keep = function (id) {
    log.debug("Entering keep().");
    made.push(id);
    log.debug("Leaving keep().");
  };

  // --- 1. The create infers the method and writes its flag ---------------
  const plain = ID + '-plain';
  keep(plain);
  const created = create(plain, ['oauth2'], {});
  let row = held(plain);
  t.check(created && created.ok === true &&
          JSON.stringify(row.methods) === '["none"]' && row.flag === 'FALSE',
          '1a. an OAuth create with no method and no credential is none ' +
          'and FALSE',
          JSON.stringify({ code: code(created), row: row,
                           errors: created && created.errors }));

  const secretId = ID + '-secret';
  keep(secretId);
  const withSecret = create(secretId, ['oauth2'], {
    oauthClientSecret: 'secret-' + process.pid });
  row = held(secretId);
  t.check(withSecret && withSecret.ok === true &&
          JSON.stringify(row.methods) === '["client_secret_basic"]' &&
          row.flag === 'TRUE',
          '1b. a secret and no method is client_secret_basic and TRUE',
          JSON.stringify({ code: code(withSecret), row: row }));

  const jwksId = ID + '-jwks';
  keep(jwksId);
  const withKeys = create(jwksId, ['oauth2'], { oauthJwks: JWKS });
  row = held(jwksId);
  t.check(withKeys && withKeys.ok === true &&
          JSON.stringify(row.methods) === '["private_key_jwt"]' &&
          row.flag === 'TRUE',
          '1c. a JWK Set and no method is private_key_jwt and TRUE',
          JSON.stringify({ code: code(withKeys), row: row,
                           errors: withKeys && withKeys.errors }));

  // --- 2. A stated flag is kept when it agrees, and refused when not -----
  const lied = ID + '-lied';
  const lie = create(lied, ['oauth2'], {
    oauthTokenEndpointAuthMethod: 'none', oauthConfidential: 'TRUE' });
  t.check(lie && lie.ok === false && code(lie) === 'STS-REG-0363' &&
          /does not match/.test(sentence(lie)) && !applications.get(lied),
          '2a. none with TRUE is refused STS-REG-0363 and creates nothing',
          sentence(lie) + ' ' + code(lie));

  const pub = ID + '-pub';
  keep(pub);
  const statedFalse = create(pub, ['oauth2'], {
    oauthTokenEndpointAuthMethod: 'none', oauthConfidential: 'FALSE' });
  row = held(pub);
  t.check(statedFalse && statedFalse.ok === true && row.flag === 'FALSE' &&
          JSON.stringify(row.methods) === '["none"]',
          '2b. none with FALSE is stored FALSE',
          JSON.stringify(row));

  const omitted = ID + '-omitted';
  keep(omitted);
  t.check(create(omitted, ['oauth2'], {
            oauthTokenEndpointAuthMethod: 'none' }).ok === true &&
          held(omitted).flag === 'FALSE',
          '2c. an omitted flag on a public client is FALSE');

  const basicLie = ID + '-basic-lie';
  const basicRefused = create(basicLie, ['oauth2'], {
    oauthTokenEndpointAuthMethod: 'client_secret_basic',
    oauthConfidential: 'FALSE' });
  t.check(basicRefused && basicRefused.ok === false &&
          code(basicRefused) === 'STS-REG-0363' &&
          !applications.get(basicLie),
          '2d. client_secret_basic with FALSE is refused and creates nothing',
          sentence(basicRefused) + ' ' + code(basicRefused));

  const basic = ID + '-basic';
  keep(basic);
  const basicOk = create(basic, ['oauth2'], {
    oauthTokenEndpointAuthMethod: 'client_secret_basic',
    oauthClientSecret: 'secret-' + process.pid,
    oauthConfidential: 'true' });
  row = held(basic);
  t.check(basicOk && basicOk.ok === true && row.flag === 'TRUE' &&
          JSON.stringify(row.methods) === '["client_secret_basic"]',
          '2e. client_secret_basic with "true" is stored TRUE',
          JSON.stringify({ row: row, errors: basicOk && basicOk.errors }));

  const secretLie = ID + '-secret-lie';
  const secretRefused = create(secretLie, ['oauth2'], {
    oauthClientSecret: 'secret-' + process.pid,
    oauthConfidential: 'FALSE' });
  t.check(secretRefused && secretRefused.ok === false &&
          code(secretRefused) === 'STS-REG-0363' &&
          !applications.get(secretLie),
          '2f. a secret whose inferred method is confidential, stated ' +
          'FALSE, is refused before anything is created',
          sentence(secretRefused));

  const maybe = ID + '-maybe';
  const bad = create(maybe, ['oauth2'], {
    oauthTokenEndpointAuthMethod: 'none', oauthConfidential: 'maybe' });
  t.check(bad && bad.ok === false && code(bad) === 'STS-REG-0363' &&
          /neither/.test(sentence(bad)) && !applications.get(maybe),
          '2g. a value that is not TRUE or FALSE is refused STS-REG-0363',
          sentence(bad) + ' ' + code(bad));

  const two = ID + '-two';
  const doubled = create(two, ['oauth2'], {
    oauthConfidential: ['TRUE', 'FALSE'] });
  t.check(doubled && doubled.ok === false &&
          code(doubled) === 'STS-REG-0008' && !applications.get(two),
          '2h. two values are refused STS-REG-0008',
          sentence(doubled) + ' ' + code(doubled));

  // --- 3. The method rewrites the flag; the flag is not edited alone -----
  const moved = act({
    action: 'update-fields', application: plain,
    fields: { oauthTokenEndpointAuthMethod: 'client_secret_basic' }
  });
  row = held(plain);
  t.check(moved && moved.ok === true &&
          JSON.stringify(row.methods) === '["client_secret_basic"]' &&
          row.flag === 'TRUE',
          '3a. changing the method from none to client_secret_basic writes ' +
          'TRUE without a flag in the body',
          JSON.stringify({ code: code(moved), row: row,
                           errors: moved && moved.errors }));

  const disagree = act({
    action: 'set', application: pub, attribute: 'oauthConfidential',
    value: 'TRUE' });
  t.check(disagree && disagree.ok === false &&
          code(disagree) === 'STS-REG-0363' &&
          /does not match/.test(sentence(disagree)) &&
          held(pub).flag === 'FALSE' &&
          sentence(disagree).indexOf('is not editable here') < 0,
          '3b. a disagreeing set is refused STS-REG-0363 and the flag stays',
          sentence(disagree) + ' ' + code(disagree));

  t.check(plant(pub, 'TRUE') && held(pub).flag === 'TRUE',
          '3c. a flag planted past the registry is what the entry now says',
          JSON.stringify(held(pub)));
  const heal = act({
    action: 'set', application: pub, attribute: 'oauthConfidential',
    value: 'false' });
  t.check(heal && heal.ok === true && held(pub).flag === 'FALSE',
          '3d. an agreeing set heals the planted flag and stores FALSE',
          JSON.stringify({ code: code(heal), row: held(pub),
                           errors: heal && heal.errors }));

  const cleared = act({
    action: 'set', application: pub, attribute: 'oauthConfidential',
    value: '' });
  t.check(cleared && cleared.ok === false &&
          code(cleared) === 'STS-REG-0363' &&
          /cannot be cleared/.test(sentence(cleared)) &&
          held(pub).flag === 'FALSE',
          '3e. clearing the flag is refused, and the flag stays',
          sentence(cleared) + ' ' + code(cleared));

  const added = act({
    action: 'add', application: pub, attribute: 'oauthConfidential',
    value: 'TRUE' });
  const removed = act({
    action: 'remove', application: pub, attribute: 'oauthConfidential',
    value: 'FALSE' });
  t.check(added && added.ok === false && removed && removed.ok === false &&
          code(added) === 'STS-REG-0363' && code(removed) === 'STS-REG-0363' &&
          /not added to or removed/.test(sentence(added)) &&
          /not added to or removed/.test(sentence(removed)) &&
          held(pub).flag === 'FALSE',
          '3f. an add and a remove are refused STS-REG-0363',
          sentence(added) + ' | ' + sentence(removed));

  t.check(plant(pub, 'TRUE') && held(pub).flag === 'TRUE',
          '3g. the flag can be planted TRUE again',
          JSON.stringify(held(pub)));
  const same = act({
    action: 'add', application: pub,
    attribute: 'oauthTokenEndpointAuthMethod', value: 'none' });
  row = held(pub);
  t.check(same && same.ok === true &&
          JSON.stringify(row.methods) === '["none"]' && row.flag === 'FALSE',
          '3h. adding the method the entry already holds heals the flag',
          JSON.stringify({ code: code(same), row: row,
                           errors: same && same.errors }));

  // --- 4. update-fields judges the flag against the methods it leaves ----
  const batchOk = act({
    action: 'update-fields', application: pub,
    fields: {
      oauthTokenEndpointAuthMethod: 'none',
      oauthConfidential: 'FALSE'
    }
  });
  t.check(batchOk && batchOk.ok === true && held(pub).flag === 'FALSE',
          '4a. update-fields keeps a flag that matches the method',
          JSON.stringify({ code: code(batchOk),
                           errors: batchOk && batchOk.errors }));

  t.check(plant(pub, 'TRUE') && held(pub).flag === 'TRUE',
          '4b. planted TRUE with method none',
          JSON.stringify(held(pub)));
  const batchHeal = act({
    action: 'update-fields', application: pub,
    fields: { oauthConfidential: 'FALSE' }
  });
  row = held(pub);
  t.check(batchHeal && batchHeal.ok === true && row.flag === 'FALSE' &&
          (batchHeal.changed || []).indexOf('oauthConfidential') >= 0,
          '4c. an agreeing FALSE on a stale TRUE heals the flag',
          JSON.stringify({ code: code(batchHeal), changed: batchHeal &&
                           batchHeal.changed, row: row }));

  // 3a already moved `plain` to client_secret_basic, so FALSE disagrees
  // with the determination TRUE. The console create's description is the
  // default sentence, and a refusal leaves that sentence where it was.
  const before = held(plain);
  const batchNo = act({
    action: 'update-fields', application: plain,
    fields: {
      description: 'must-not-land',
      oauthConfidential: 'FALSE'
    }
  });
  row = held(plain);
  t.check(batchNo && batchNo.ok === false &&
          code(batchNo) === 'STS-REG-0363' &&
          /does not match/.test(sentence(batchNo)) &&
          row.flag === before.flag && row.flag === 'TRUE' &&
          JSON.stringify(row.methods) === JSON.stringify(before.methods) &&
          JSON.stringify(row.methods) === '["client_secret_basic"]' &&
          row.description === before.description &&
          row.description !== 'must-not-land',
          '4d. a disagreeing flag refuses the body and writes nothing else',
          JSON.stringify({ code: code(batchNo), row: row,
                           errors: batchNo && batchNo.errors }));

  const together = act({
    action: 'update-fields', application: pub,
    fields: {
      oauthTokenEndpointAuthMethod: 'client_secret_basic',
      oauthConfidential: 'TRUE'
    }
  });
  row = held(pub);
  t.check(together && together.ok === true &&
          JSON.stringify(row.methods) === '["client_secret_basic"]' &&
          row.flag === 'TRUE',
          '4e. a method change and the flag that method makes are saved',
          JSON.stringify({ code: code(together), row: row,
                           errors: together && together.errors }));

  const stuck = held(pub);
  const back = act({
    action: 'update-fields', application: pub,
    fields: {
      oauthTokenEndpointAuthMethod: 'none',
      oauthConfidential: 'TRUE'
    }
  });
  row = held(pub);
  t.check(back && back.ok === false && code(back) === 'STS-REG-0363' &&
          JSON.stringify(row.methods) === JSON.stringify(stuck.methods) &&
          row.flag === stuck.flag,
          '4f. none with TRUE is refused and the entry is unchanged',
          JSON.stringify({ code: code(back), row: row,
                           errors: back && back.errors }));

  // --- 5. A secret replaces `none` and the flag becomes TRUE -------------
  // 4e left `pub` on client_secret_basic, so the replacement is a fresh
  // public client whose method is still `none`.
  const secretPublic = ID + '-secret-public';
  keep(secretPublic);
  const publicMade = create(secretPublic, ['oauth2'], {
    oauthTokenEndpointAuthMethod: 'none' });
  row = held(secretPublic);
  t.check(publicMade && publicMade.ok === true &&
          JSON.stringify(row.methods) === '["none"]' &&
          row.flag === 'FALSE',
          '5a. the client a secret is added to is still method none',
          JSON.stringify({ code: code(publicMade), row: row }));
  const minted = applications.addClientSecret(secretPublic, {});
  row = held(secretPublic);
  t.check(minted && minted.ok === true &&
          JSON.stringify(row.methods) === '["client_secret_basic"]' &&
          row.methods.indexOf('none') < 0 && row.flag === 'TRUE' &&
          /was none and is now client_secret_basic/.test(
            String(minted.message || '')),
          '5b. adding a secret to a public client replaces none with ' +
          'client_secret_basic and records TRUE',
          JSON.stringify({ code: code(minted), row: row,
                           message: minted && minted.message,
                           errors: minted && minted.errors }));

  // --- 6. Registration and forgetting it ---------------------------------
  const regBasic = ID + '-reg-basic';
  keep(regBasic);
  const registered = applications.register(regBasic, {
    redirect_uris: ['https://' + regBasic + '.example/cb'],
    token_endpoint_auth_method: 'client_secret_basic',
    client_secret: 'secret-' + process.pid });
  row = held(regBasic);
  t.check(!!registered && row.registered === true &&
          JSON.stringify(row.methods) === '["client_secret_basic"]' &&
          row.flag === 'TRUE',
          '6a. a registration of client_secret_basic records TRUE',
          JSON.stringify(row));
  t.check(applications.forgetRegistration(regBasic) === true, '6b. forgotten');
  row = held(regBasic);
  t.check(row.registered === false &&
          JSON.stringify(row.methods) === '["client_secret_basic"]' &&
          row.flag === 'TRUE',
          '6c. forgetting the registration leaves the method and TRUE',
          JSON.stringify(row));

  const regNone = ID + '-reg-none';
  keep(regNone);
  applications.register(regNone, {
    redirect_uris: ['https://' + regNone + '.example/cb'],
    token_endpoint_auth_method: 'none' });
  t.check(applications.forgetRegistration(regNone) === true &&
          held(regNone).flag === 'FALSE' &&
          JSON.stringify(held(regNone).methods) === '["none"]',
          '6d. forgetting a public registration leaves none and FALSE',
          JSON.stringify(held(regNone)));

  const regOmit = ID + '-reg-omit';
  keep(regOmit);
  applications.register(regOmit, {
    redirect_uris: ['https://' + regOmit + '.example/cb'] });
  row = held(regOmit);
  t.check(row.registered === true &&
          JSON.stringify(row.methods) === '["client_secret_basic"]' &&
          row.flag === 'TRUE',
          '6e. an omitted registration method is client_secret_basic and TRUE',
          JSON.stringify(row));

  t.check(applications.oauthConfidentialOf(
            { registered: true, fields: {} }) === 'TRUE' &&
          applications.oauthConfidentialOf(
            { registered: false, fields: {} }) === 'FALSE' &&
          applications.oauthConfidentialOf({ registered: true, fields: {
            oauthTokenEndpointAuthMethod: 'none' } }) === 'FALSE',
          '6f. an empty method is confidential only on a registered client, ' +
          'and none is FALSE');

  // --- 7. Who the attribute is written onto -------------------------------
  const saml = ID + '-saml';
  keep(saml);
  const samlMade = create(saml, ['saml2'], {});
  t.check(samlMade && samlMade.ok === true && held(saml).flag === '' &&
          held(saml).methods.length === 0,
          '7a. a SAML application created with no flag has none',
          JSON.stringify(held(saml)));

  const samlTrue = ID + '-saml-true';
  const samlRefused = create(samlTrue, ['saml2'], {
    oauthConfidential: 'TRUE' });
  t.check(samlRefused && samlRefused.ok === false &&
          code(samlRefused) === 'STS-REG-0363' &&
          !applications.get(samlTrue),
          '7b. a SAML create stating TRUE is refused',
          sentence(samlRefused) + ' ' + code(samlRefused));

  const samlFalse = ID + '-saml-false';
  keep(samlFalse);
  const samlOk = create(samlFalse, ['saml2'], { oauthConfidential: 'FALSE' });
  t.check(samlOk && samlOk.ok === true && held(samlFalse).flag === 'FALSE',
          '7c. a SAML create stating FALSE stores FALSE',
          JSON.stringify({ code: code(samlOk), row: held(samlFalse) }));

  const wallet = ID + '-wallet';
  keep(wallet);
  const walletMade = create(wallet, ['oid4vci'], {});
  row = held(wallet);
  t.check(walletMade && walletMade.ok === true && row.flag === 'FALSE' &&
          row.methods.length === 0,
          '7d. OpenID4VCI alone, with no method, is FALSE and infers none',
          JSON.stringify({ code: code(walletMade), row: row,
                           errors: walletMade && walletMade.errors }));

  // --- 8. The grid does not draw it --------------------------------------
  const drawn = applications.applicationFields().map(function (one) {
    return one.attribute;
  });
  t.check(drawn.indexOf('oauthConfidential') < 0 &&
          applications.SIMPLE_FIELD_ATTRIBUTES.indexOf(
            'oauthConfidential') < 0 &&
          applications.BOOLEAN_ATTRIBUTES.indexOf('oauthConfidential') < 0,
          '8. the field grid, the simple view and the booleans omit ' +
          'oauthConfidential',
          JSON.stringify(drawn.filter(function (one) {
            return one.indexOf('Confidential') >= 0;
          })));

  made.forEach(function (id) {
    drop(id);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oauth confidential flag',
  describe: 'oauthConfidential is the determination the token endpoint ' +
            'authentication method makes: derived on write, refused when ' +
            'a supplied value disagrees, and absent from the field grid ' +
            '(#466)',
  run: run
};
