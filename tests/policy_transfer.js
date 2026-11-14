// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/policy_transfer.js
//
// ===========================================================================
// POLICY EXPORT AND IMPORT (#1713, `admin-core/policy_transfer.ts`).
//
// rcbj's issue, held clause by clause:
//
//   A. THE EXPORT IS JSON AND SIGNED: a JWS in the flattened JSON
//      serialization, typ policy-export+json, carrying only what the realm
//      STORES, signed by a fresh key under the realm's new `policy-signing`
//      Issuing CA, with the ENTIRE chain — leaf, Issuing CA, Intermediate,
//      service Root — in x5c.
//   B. ITS OWN REALM IS TRUSTED without a question, and the import goes
//      through each kind's own save: a profile changed after the export is
//      put back, a named policy recreated.
//   C. A DOCUMENT THAT IS NOT ONE, OR WAS ALTERED, IS REFUSED by name.
//   D. ANOTHER REALM IS ASKED ABOUT: refused with `needsTrust` until the yes
//      names the Issuing CA it was shown; a yes for another chain is refused;
//      the yes adds the whole CA chain to the signer truststore for
//      policy-signer alone, and the next import is `trusted`.
//   E. THE YES IS ABOUT ONE REALM: a third realm of the same service shares
//      the Root and is STILL asked about, because the Issuing CA is pinned;
//      and a fourth realm, which said nothing, still asks about the first.
//   F. FULL PARANOID VALIDATION: forced in development while
//      pki.paranoidPolicySigner is on, the master's alone when it is off; a
//      revoked signer is refused.
//   G. THE ALGORITHM IS CONFIGURABLE: every pki.policyExportAlgorithm value
//      exports and verifies, with that `alg` in the header.
//   H. THE ACTION LAYER answers export, inspect and import, refuses an
//      unknown action, and audits the export, the trust and the import.
//   I. THE CONSOLE draws the tab and asks the question.
//   J. THE VIEW (`GET /admin-api/policies/transfer`): the algorithm in force,
//      the paranoid row, the realm's Policy Export Signing CA (the certificate
//      an export carries in x5c, its fingerprint and x5t#S256), the signers a
//      yes added, no private key, the policies an export may select, and an
//      answer that meets its closed model.
//   K. A SELECTION (rcbj, 2026-11-14: "import / export individual
//      policies"): an export of one policy and of two, each verifying and
//      imported into another realm after the yes, writing only those; a
//      name the realm does not store refused with its code before a key is
//      made; inspect listing every profile with `replaces`; an import of a
//      selection writing only what it names; a name the document does not
//      carry refused before the trust question; a whole export importing
//      exactly as before; the audit rows naming the selection; each answer
//      against its closed model; and the console's checklists.
// ===========================================================================

delete process.env.CONFIG_FILE;

require('../ldap/ldap_server');
const realms = require('../common/realms');
const config = require('../common/config');
const pki = require('../common/pki');
const audit = require('../common/audit');
const stsCrypto = require('../common/crypto');
const errorCodes = require('../common/error_codes');
const revocation = require('../common/pki_revocation');
const signers = require('../common/signer_truststore');
const passwordPolicy = require('../common/password_policy');
const authnPolicy = require('../common/authn_policy');
const transfer = require('../admin-core/policy_transfer');
const adminActions = require('../admin-core/admin_actions');
const adminViews = require('../admin-core/admin_views');

const log = require('bunyan').createLogger({ name: 'policy_transfer',
  level: process.env.LOG_LEVEL || 'info' });

/**
 * Runs a function in a realm.
 *
 * @param id - the realm's id
 * @param fn - the function
 * @returns what it returns
 */
function inRealm(id, fn) {
  log.debug('Entering inRealm(). ' + id);
  log.debug('Leaving inRealm().');
  return realms.run(realms.get(id), fn);
}

/**
 * The fields of the default password profile, with one changed.
 *
 * @param minLength - the minimum length to save
 * @returns the save's body
 */
function passwordBody(minLength) {
  log.debug('Entering passwordBody().');
  const current = passwordPolicy.read('default');
  const body = {};
  passwordPolicy.FIELDS.forEach(function (field) {
    body[field.key] = current[field.key];
  });
  body.minLength = minLength;
  log.debug('Leaving passwordBody().');
  return body;
}

/**
 * The protected header of a document.
 *
 * @param doc - the flattened JWS
 * @returns the header
 */
function headerOf(doc) {
  log.debug('Entering headerOf().');
  log.debug('Leaving headerOf().');
  return JSON.parse(Buffer.from(doc.protected, 'base64url').toString('utf8'));
}

/**
 * The signed content of a document.
 *
 * @param doc - the flattened JWS
 * @returns the payload
 */
function payloadOf(doc) {
  log.debug('Entering payloadOf().');
  log.debug('Leaving payloadOf().');
  return JSON.parse(Buffer.from(doc.payload, 'base64url').toString('utf8'));
}

/**
 * A certificate in x5c, as PEM.
 *
 * @param b64 - the base64 DER
 * @returns the PEM
 */
function pemOf(b64) {
  log.debug('Entering pemOf().');
  log.debug('Leaving pemOf().');
  return '-----BEGIN CERTIFICATE-----\n' +
    b64.match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----\n';
}

/**
 * The SHA-256 fingerprint of a PEM, in the signer truststore's spelling.
 *
 * @param pem - the certificate
 * @returns upper hex, no colons
 */
function fingerprintOf(pem) {
  log.debug('Entering fingerprintOf().');
  log.debug('Leaving fingerprintOf().');
  return String(stsCrypto.parseCertificate(pem).fingerprint256)
    .replace(/:/g, '').toUpperCase();
}

/**
 * The names of a kind's profiles a realm stores, sorted.
 *
 * @param module - the kind's module (`passwordPolicy`)
 * @returns the names
 */
function storedNames(module) {
  log.debug('Entering storedNames().');
  const out = module.list().filter(function (one) {
    return one.stored === true;
  }).map(function (one) {
    return String(one.name);
  }).sort();
  log.debug('Leaving storedNames().');
  return out;
}

/**
 * The names of the authentication policy's named policies, sorted.
 *
 * @returns the names
 */
function namedAuthn() {
  log.debug('Entering namedAuthn().');
  const out = authnPolicy.named().map(function (one) {
    return String(one.name);
  }).sort();
  log.debug('Leaving namedAuthn().');
  return out;
}

/**
 * K. A SELECTION: export and import of individual policies.
 *
 * @param t - the harness
 * @param ctx - `{ A, E, F, document, Ajv }`: the exporting realm (which
 *   stores password `default` and `strict` and the named authentication
 *   policy `keys-only`), a realm that stores nothing yet and will be
 *   imported into, a realm that is never answered, and the Management API
 *   OpenAPI document
 */
async function selections(t, ctx) {
  log.debug('Entering selections().');
  const A = ctx.A;
  const E = ctx.E;
  const F = ctx.F;
  t.log.info('K. a selection');
  const ajv = new ctx.Ajv({ strict: false, allErrors: true });
  const validators = {};
  const meets = function (op, status, body) {
    log.debug('Entering meets(). ' + op + ' ' + status);
    const key = op + ' ' + status;
    if (!validators[key]) {
      const operation = ctx.document.paths['/admin-api/policies/transfer/' +
                                            op].post;
      validators[key] = ajv.compile({
        allOf: [operation.responses[String(status)]
          .content['application/json'].schema],
        components: ctx.document.components });
    }
    const ok = validators[key](JSON.parse(JSON.stringify(body)));
    log.debug('Leaving meets().');
    return ok ? '' : JSON.stringify(validators[key].errors);
  };
  const exportOp = ctx.document.paths['/admin-api/policies/transfer/export']
    .post;
  const importOp = ctx.document.paths['/admin-api/policies/transfer/import']
    .post;
  const requestOf = function (operation) {
    log.debug('Entering requestOf().');
    log.debug('Leaving requestOf().');
    return ajv.compile({
      allOf: [operation.requestBody.content['application/json'].schema],
      components: ctx.document.components });
  };
  const exportRequest = requestOf(exportOp);
  const importRequest = requestOf(importOp);
  t.check(exportRequest({ policies: [{ kind: 'password', name: 'strict' }] })
          && exportRequest({}) &&
          !exportRequest({ policies: [] }) &&
          !exportRequest({ policies: [{ kind: 'password' }] }) &&
          !exportRequest({ policies: [{ kind: 'password', name: 'x',
                                        stray: 1 }] }),
          'K. the export request model takes a selection of {kind, name}, ' +
          'closed, at least one', JSON.stringify(exportRequest.errors));
  t.check(importRequest({ document: {}, policies: [{ kind: 'password',
                                                    name: 'strict' }] }),
          'K. and the import request model takes one too',
          JSON.stringify(importRequest.errors));
  const keysMade = [];
  const counting = new transfer.PolicyTransfer(Object.assign(
    transfer.PolicyTransfer.defaultDeps(), {
      makeKey: function (alg) {
        keysMade.push(alg);
        return transfer.PolicyTransfer.makeKey(alg);
      }
    }));

  // K1. ONE POLICY.
  const one = await inRealm(A, function () {
    return counting.exportPolicies({ actor: 'alice',
      policies: [{ kind: 'password', name: 'strict' }] });
  });
  t.check(one.ok, 'K1. one policy exports', JSON.stringify(one.errors));
  const onePayload = payloadOf(one.document);
  t.check(onePayload.kinds.length === 1 &&
          onePayload.kinds[0].id === 'password' &&
          onePayload.kinds[0].profiles.length === 1 &&
          onePayload.kinds[0].profiles[0].name === 'strict' &&
          onePayload.kinds[0].profiles[0].body.precedence === 40,
          'K1. it carries that one profile and nothing else',
          JSON.stringify(onePayload.kinds));
  t.check(onePayload.format === 'iya-sts.policy-export' &&
          onePayload.version === 1 && headerOf(one.document).x5c.length === 4,
          'K1. in the same format, with the whole chain', '');
  t.equal(JSON.stringify(onePayload.selection),
          JSON.stringify([{ kind: 'password', name: 'strict' }]),
          'K1. and records that it is a selection');
  t.equal(JSON.stringify(one.selection),
          JSON.stringify([{ kind: 'password', name: 'strict' }]),
          'K1. the answer names the selection');
  t.check(one.filename.indexOf('policy-' + A + '-password-strict-') === 0,
          'K1. the file is named for the one policy', one.filename);
  t.equal(meets('export', 200, one), '', 'K1. the answer meets its model');
  const oneSeen = await inRealm(A, function () {
    return transfer.inspect(one.document);
  });
  t.check(oneSeen.ok && oneSeen.origin === 'own',
          'K1. and verifies in its own realm', JSON.stringify(oneSeen.errors));

  // K2. TWO POLICIES, OF TWO KINDS, ONE OF THEM NAMED.
  const two = await inRealm(A, function () {
    return transfer.exportPolicies({ policies: [
      { kind: 'password', name: 'default' },
      { kind: 'authn', name: 'keys-only' },
      { kind: 'password', name: 'default' }] });
  });
  t.check(two.ok, 'K2. two policies export', JSON.stringify(two.errors));
  const twoPayload = payloadOf(two.document);
  const carried = twoPayload.kinds.map(function (kind) {
    return kind.id + ':' + kind.profiles.map(function (p) {
      return p.name;
    }).concat((kind.named || []).map(function (n) {
      return 'named ' + n.name;
    })).join('+');
  }).sort().join(',');
  t.equal(carried, 'authn:named keys-only,password:default',
          'K2. it carries exactly those two, and the kinds holding them');
  t.equal(twoPayload.selection.length, 2,
          'K2. a policy named twice is selected once');

  // K3. A NAME THE REALM DOES NOT STORE.
  keysMade.length = 0;
  const unknown = await inRealm(A, function () {
    return counting.exportPolicies({ policies: [
      { kind: 'password', name: 'strict' },
      { kind: 'password', name: 'no-such-policy' }] });
  });
  t.equal(!unknown.ok && errorCodes.codeOf(unknown), 'STS-ADMIN-0937',
          'K3. an export naming a policy the realm does not store is ' +
          'refused with its code');
  t.check(unknown.document === undefined && unknown.files === undefined &&
          keysMade.length === 0,
          'K3. and nothing is exported: no document, no key made',
          JSON.stringify(keysMade));
  t.check(Array.isArray(unknown.missing) && unknown.missing.length === 1 &&
          unknown.missing[0].name === 'no-such-policy',
          'K3. the refusal names what is missing',
          JSON.stringify(unknown.missing));
  t.equal(meets('export', 400, unknown), '',
          'K3. the refusal meets its model');
  const inherited = await inRealm(A, function () {
    return transfer.exportPolicies({ policies: [
      { kind: 'authn', name: 'default' }] });
  });
  t.equal(errorCodes.codeOf(inherited), 'STS-ADMIN-0937',
          'K3. an inherited policy is not the realm\'s to export');
  const noKind = await inRealm(A, function () {
    return transfer.exportPolicies({ policies: [
      { kind: 'no-such-kind', name: 'default' }] });
  });
  t.equal(errorCodes.codeOf(noKind), 'STS-ADMIN-0937',
          'K3. nor a kind this service does not have');
  const empty = await inRealm(A, function () {
    return transfer.exportPolicies({ policies: [] });
  });
  const shapeless = await inRealm(A, function () {
    return transfer.exportPolicies({ policies: [{ kind: 'password' }] });
  });
  t.check(errorCodes.codeOf(empty) === 'STS-ADMIN-0937' &&
          errorCodes.codeOf(shapeless) === 'STS-ADMIN-0937',
          'K3. an empty selection and one without a name are refused', '');

  // K4. INSPECT LISTS EVERY PROFILE, WITH `replaces`.
  inRealm(E, function () {
    return passwordPolicy.save('strict', Object.assign(passwordBody(12),
      { precedence: 50 }));
  });
  const whole = await inRealm(A, function () {
    return transfer.exportPolicies({ actor: 'alice' });
  });
  t.check(whole.ok && whole.selection === undefined &&
          payloadOf(whole.document).selection === undefined,
          'K4. a whole export carries no selection, as before', '');
  const atE = await inRealm(E, function () {
    return transfer.inspect(whole.document);
  });
  const listed = function (seen) {
    log.debug('Entering listed().');
    const out = {};
    (seen.profiles || []).forEach(function (one) {
      out[one.kind + '/' + one.name] = one;
    });
    log.debug('Leaving listed().');
    return out;
  };
  const atEList = listed(atE);
  t.check(atE.ok && atE.origin === 'foreign' &&
          Object.keys(atEList).sort().join(',') ===
            'authn/keys-only,password/default,password/strict',
          'K4. inspect lists every profile the export carries',
          JSON.stringify(atE.profiles));
  t.check(atEList['password/strict'].replaces === true &&
          atEList['password/default'].replaces === false &&
          atEList['authn/keys-only'].replaces === false &&
          atEList['authn/keys-only'].named === true &&
          atEList['password/default'].named === false,
          'K4. marking the one this realm already stores by that name as ' +
          'replacing it', JSON.stringify(atE.profiles));
  t.equal(meets('inspect', 200, transfer.publicView(atE)), '',
          'K4. the inspection meets its model');
  const oneAtE = await inRealm(E, function () {
    return transfer.inspect(one.document);
  });
  t.equal(JSON.stringify(oneAtE.selection),
          JSON.stringify([{ kind: 'password', name: 'strict' }]),
          'K4. and says what a selection\'s document was asked to hold');

  // K5. A NAME THE DOCUMENT DOES NOT CARRY, REFUSED BEFORE THE QUESTION.
  const notCarried = await inRealm(F, function () {
    return transfer.importPolicies(one.document, { trustSigner: true,
      issuerFingerprint: atE.issuerFingerprint,
      policies: [{ kind: 'password', name: 'default' }] });
  });
  t.equal(errorCodes.codeOf(notCarried), 'STS-ADMIN-0938',
          'K5. an import naming a profile the export does not carry is ' +
          'refused with its code');
  t.check(!notCarried.needsTrust && notCarried.missing.length === 1 &&
          notCarried.missing[0].name === 'default',
          'K5. before the trust question, naming what is missing',
          JSON.stringify(notCarried.missing));
  t.check(inRealm(F, function () {
    return signers.list().length === 0 &&
           storedNames(passwordPolicy).length === 0;
  }), 'K5. nothing was trusted and nothing written', '');
  t.equal(meets('import', 400, notCarried), '',
          'K5. the refusal meets its model');

  // K6. ONE POLICY INTO ANOTHER REALM, AFTER THE YES.
  const asked = await inRealm(E, function () {
    return transfer.importPolicies(one.document, {
      policies: [{ kind: 'password', name: 'strict' }] });
  });
  t.check(errorCodes.codeOf(asked) === 'STS-ADMIN-0929' && asked.needsTrust,
          'K6. a selection from another realm is still asked about first',
          JSON.stringify(asked.errors));
  t.equal(inRealm(E, function () {
    return passwordPolicy.read('strict').minLength;
  }), 12, 'K6. and nothing is written until it is answered');
  const yes = await inRealm(E, function () {
    return transfer.importPolicies(one.document, { trustSigner: true,
      issuerFingerprint: asked.inspection.issuerFingerprint,
      actor: 'erin' });
  });
  t.check(yes.ok && yes.origin === 'foreign' && yes.trustAdded.length === 3,
          'K6. the yes imports the one-policy document',
          JSON.stringify(yes.errors));
  t.equal(meets('import', 200, yes), '', 'K6. the answer meets its model');
  t.check(inRealm(E, function () {
    return storedNames(passwordPolicy).join(',') === 'strict' &&
           passwordPolicy.read('strict').minLength === 19 &&
           namedAuthn().length === 0;
  }), 'K6. writing only that policy: E\'s strict is A\'s, its default is ' +
      'still not stored, and no authentication policy arrived', '');

  const twoAtF = await inRealm(F, function () {
    return transfer.importPolicies(two.document, { trustSigner: true,
      issuerFingerprint: asked.inspection.issuerFingerprint, actor: 'fay' });
  });
  t.check(twoAtF.ok && twoAtF.origin === 'foreign',
          'K6. the two-policy document imports into a third realm after ' +
          'its yes', JSON.stringify(twoAtF.errors));
  t.check(inRealm(F, function () {
    return storedNames(passwordPolicy).join(',') === 'default' &&
           passwordPolicy.read('default').minLength === 17 &&
           namedAuthn().join(',') === 'keys-only';
  }), 'K6. writing those two and not A\'s strict', '');

  // K7. A SELECTION OF A WHOLE EXPORT.
  const picked = await inRealm(E, function () {
    return transfer.importPolicies(whole.document, {
      policies: [{ kind: 'authn', name: 'keys-only' }] });
  });
  t.check(picked.ok && picked.origin === 'trusted' &&
          JSON.stringify(picked.imported) ===
            JSON.stringify([{ kind: 'authn', names: ['keys-only'] }]),
          'K7. an import of a selection writes only what it names',
          JSON.stringify(picked.imported || picked.errors));
  t.equal(JSON.stringify(picked.selection),
          JSON.stringify([{ kind: 'authn', name: 'keys-only' }]),
          'K7. and its answer names the selection');
  t.check(inRealm(E, function () {
    return namedAuthn().join(',') === 'keys-only' &&
           storedNames(passwordPolicy).join(',') === 'strict';
  }), 'K7. leaving the rest of the export unwritten', '');

  // K8. A WHOLE EXPORT IMPORTS EXACTLY AS BEFORE.
  const all = await inRealm(E, function () {
    return transfer.importPolicies(whole.document, {});
  });
  const writtenNames = (all.imported || []).map(function (one) {
    return one.kind + ':' + one.names.slice().sort().join('+');
  }).sort().join(',');
  t.check(all.ok && all.selection === undefined &&
          writtenNames === 'authn:keys-only,password:default+strict',
          'K8. a whole export, imported with no selection, writes every ' +
          'profile, as before', writtenNames);
  t.check(inRealm(E, function () {
    return storedNames(passwordPolicy).join(',') === 'default,strict' &&
           passwordPolicy.read('default').minLength === 17;
  }), 'K8. E now holds A\'s default too', '');

  // K9. THE ACTION LAYER RECORDS THE SELECTION ON THE AUDIT ROWS.
  const viaAction = await inRealm(A, function () {
    return adminActions.policyTransferAction({ action: 'export',
      policies: [{ kind: 'password', name: 'strict' }] },
                                             { via: 'api', actor: 'alice' });
  });
  t.check(viaAction.ok && payloadOf(viaAction.document).kinds.length === 1,
          'K9. the action layer passes an export\'s selection on',
          JSON.stringify(viaAction.errors));
  const refusedAction = await inRealm(A, function () {
    return adminActions.policyTransferAction({ action: 'export',
      policies: [{ kind: 'password', name: 'nope' }] },
                                             { via: 'api', actor: 'alice' });
  });
  t.equal(errorCodes.codeOf(refusedAction), 'STS-ADMIN-0937',
          'K9. and its refusal');
  const importAction = await inRealm(E, function () {
    return adminActions.policyTransferAction({ action: 'import',
      document: viaAction.document,
      policies: [{ kind: 'password', name: 'strict' }] },
                                             { via: 'api', actor: 'erin' });
  });
  t.check(importAction.ok && importAction.imported.length === 1,
          'K9. and an import\'s', JSON.stringify(importAction.errors));
  const rowOf = function (id, action) {
    log.debug('Entering rowOf(). ' + id + ' ' + action);
    const out = inRealm(id, function () {
      return audit.list().filter(function (row) {
        return row.action === action;
      })[0];
    });
    log.debug('Leaving rowOf().');
    return out;
  };
  const exportRow = rowOf(A, 'admin.policies.export');
  const importRow = rowOf(E, 'admin.policies.import');
  t.check(!!exportRow && exportRow.detail.selection === 'password/strict' &&
          /1 of this realm/.test(exportRow.summary),
          'K9. the export\'s audit row names the policy selected',
          JSON.stringify(exportRow && exportRow.detail));
  t.check(!!importRow && importRow.detail.selection === 'password/strict',
          'K9. and the import\'s', JSON.stringify(importRow &&
                                                  importRow.detail));

  // K10. THE CONSOLE.
  const page = require('../admin-ui/web_policies');
  const kit = require('../admin-ui/web_kit');
  const WebAnswers = require('../admin-ui/web_answers');
  const tr = kit.context({}, true).t;
  const viewA = inRealm(A, function () {
    return adminViews.policyTransferJson();
  });
  const tab = page.transferSection({ state: {}, transfer: viewA }, tr);
  const strictValue = kit.esc(JSON.stringify({ kind: 'password',
                                               name: 'strict' }));
  t.check(tab.indexOf('name="policies" value="' + strictValue + '"') >= 0 &&
          /data-check-all="policies"/.test(tab) &&
          /name="action" value="export"/.test(tab),
          'K10. the tab draws a box per stored policy and Select all, in ' +
          'the export\'s form', tab.slice(0, 400));
  const oneForm = page.exportOneForm('password', 'strict', tr);
  t.check(/name="action" value="export"/.test(oneForm) &&
          oneForm.indexOf('name="policies" value="' + strictValue + '"') >= 0,
          'K10. a policy\'s own Export button posts it alone', oneForm);
  const redrawn = WebAnswers.redraw('/admin/policies', 'inspect',
    { action: 'inspect', document: JSON.stringify(whole.document) },
    transfer.publicView(atE), { state: {} }, tr);
  const checklist = page.transferSection(redrawn.json, tr);
  t.check(checklist.indexOf('replaces an existing policy') >= 0 &&
          checklist.indexOf('name="policies" value="' + strictValue +
                            '" checked') >= 0 &&
          /name="trustSigner" value="true"/.test(checklist),
          'K10. after Inspect the file\'s policies are a ticked checklist, ' +
          'one marked as replacing, in the form whose yes imports them',
          checklist.slice(0, 400));
  const ConsoleRuntime = require('../admin-ui/web_runtime');
  const runtime = new ConsoleRuntime({ location: { pathname: '/admin' } });
  runtime.spec = ctx.document;
  const shaped = runtime.shapeFields({ action: 'export', policies: [
    JSON.stringify({ kind: 'password', name: 'strict' }),
    JSON.stringify({ kind: 'authn', name: 'keys-only' })] },
  runtime.deref(exportOp.requestBody.content['application/json'].schema));
  t.equal(JSON.stringify(shaped.policies), JSON.stringify([
    { kind: 'password', name: 'strict' },
    { kind: 'authn', name: 'keys-only' }]),
          'K10. the console sends the ticked boxes as the operation\'s ' +
          '`policies`, each a {kind, name}');
  const single = runtime.shapeFields({ action: 'export',
    policies: JSON.stringify({ kind: 'password', name: 'strict' }) },
  runtime.deref(exportOp.requestBody.content['application/json'].schema));
  t.equal(JSON.stringify(single.policies), JSON.stringify([
    { kind: 'password', name: 'strict' }]),
          'K10. and one policy\'s button as a list of one');
  log.debug('Leaving selections().');
}

async function run(t) {
  log.debug('Entering run().');
  const tag = stsCrypto.randomBytes(3).toString('hex');
  const A = 'ptx-a-' + tag;
  const B = 'ptx-b-' + tag;
  const C = 'ptx-c-' + tag;
  const D = 'ptx-d-' + tag;
  const E = 'ptx-e-' + tag;
  const F = 'ptx-f-' + tag;
  [A, B, C, D, E, F].forEach(function (id) {
    realms.create({ id: id, name: id, domain: id + '.example.net',
                    description: 'Created by ' + __filename });
  });
  try {
    // A. THE EXPORT.
    t.log.info('A. the export');
    const exported = await inRealm(A, async function () {
      t.check(passwordPolicy.save('default', passwordBody(17)).ok,
              'A. realm A stores its own default password profile', '');
      const strict = passwordPolicy.save('strict',
        Object.assign(passwordBody(19),
                      { precedence: 40, description: 'For admins' }));
      t.check(strict.ok, 'A. and a named one', JSON.stringify(strict.errors));
      t.check(authnPolicy.saveNamed('keys-only',
        { mechanisms: ['webauthn'], secondFactors: [], precedence: 30,
          description: 'Passwordless' }).ok,
              'A. and a named authentication policy', '');
      return transfer.exportPolicies({ actor: 'alice' });
    });
    t.check(exported.ok, 'A. it exports', JSON.stringify(exported.errors));
    const doc = exported.document;
    t.check(typeof doc.protected === 'string' &&
            typeof doc.payload === 'string' &&
            typeof doc.signature === 'string' &&
            Object.keys(doc).length === 3,
            'A. as a flattened JWS: protected, payload, signature', '');
    const text = JSON.stringify(doc);
    t.check(JSON.parse(text).signature === doc.signature,
            'A. which is JSON', '');
    const header = headerOf(doc);
    t.equal(header.typ, 'policy-export+json', 'A. its typ');
    t.equal(header.alg, 'RS256',
            'A. RS256 by default, the realm\'s JOSE default');
    t.equal(header.x5c.length, 4,
            'A. x5c is the whole chain: leaf, Issuing CA, Intermediate, Root');
    const chain = header.x5c.map(pemOf);
    const issuer = inRealm(A, function () {
      return pki.describeIssuer(A, 'policy-signing');
    });
    t.check(!!issuer, 'A. realm A has a Policy Export Signing CA', '');
    t.equal(fingerprintOf(chain[1]), fingerprintOf(issuer.certificatePem),
            'A. the leaf\'s issuer is that CA');
    t.equal(fingerprintOf(chain[3]),
            fingerprintOf(pki.serviceRoot().certificatePem),
            'A. and the chain ends at the service Root');
    t.check(/Policy Export Signing CA/.test(
      stsCrypto.certificateFacts(chain[1]).subject),
            'A. the CA is named for what it is',
            stsCrypto.certificateFacts(chain[1]).subject);
    const payload = payloadOf(doc);
    t.equal(payload.format, 'iya-sts.policy-export', 'A. its format');
    t.equal(payload.realm, A, 'A. the realm it came from');
    t.equal(payload.exportedBy, 'alice', 'A. who exported it');
    const password = payload.kinds.filter(function (k) {
      return k.id === 'password';
    })[0];
    t.equal(password.profiles.map(function (p) {
      return p.name;
    }).sort().join(','), 'default,strict',
            'A. the password kind carries what A stores, default and named');
    t.equal(password.profiles.filter(function (p) {
      return p.name === 'strict';
    })[0].body.precedence, 40, 'A. a named profile keeps its precedence');
    const authn = payload.kinds.filter(function (k) {
      return k.id === 'authn';
    })[0];
    t.equal(authn.profiles.length, 0,
            'A. what A inherits (its authentication default) is left out');
    t.equal(authn.named.map(function (n) {
      return n.name;
    }).join(','), 'keys-only',
            'A. the named authentication policy is carried');
    t.check(!JSON.stringify(payload).match(/PRIVATE KEY/),
            'A. no private key anywhere in the document', '');

    // B. ITS OWN REALM.
    t.log.info('B. its own realm');
    const ownSeen = await inRealm(A, function () {
      return transfer.inspect(text);
    });
    t.check(ownSeen.ok && ownSeen.origin === 'own' && ownSeen.trusted,
            'B. realm A trusts its own export without a question',
            JSON.stringify(ownSeen.errors || ownSeen.origin));
    t.equal(ownSeen.verdict.inForce, true,
            'B. held to the full paranoid checks, in development');
    const ownImport = await inRealm(A, async function () {
      passwordPolicy.save('default', passwordBody(9));
      authnPolicy.act('delete-named-authn-policy', { name: 'keys-only' });
      const done = await transfer.importPolicies(doc);
      return { done: done,
               min: passwordPolicy.read('default').minLength,
               named: authnPolicy.namedPolicy('keys-only') };
    });
    t.check(ownImport.done.ok && ownImport.done.origin === 'own',
            'B. and imports it', JSON.stringify(ownImport.done.errors));
    t.equal(ownImport.min, 17,
            'B. a profile changed since the export is put back');
    t.check(!!ownImport.named && ownImport.named.precedence === 30,
            'B. a named policy deleted since is made again',
            JSON.stringify(ownImport.named));
    t.equal(ownImport.done.trustAdded.length, 0,
            'B. its own realm adds nothing to the truststore');

    // C. NOT ONE, OR ALTERED.
    t.log.info('C. refusals');
    const refusedWith = async function (input, code, what) {
      log.debug('Entering refusedWith(). ' + what);
      const out = await inRealm(A, function () {
        return transfer.inspect(input);
      });
      t.equal(!out.ok && errorCodes.codeOf(out), code, 'C. ' + what);
      log.debug('Leaving refusedWith().');
    };
    await refusedWith('not json', 'STS-ADMIN-0926', 'not JSON');
    await refusedWith('{"a":1}', 'STS-ADMIN-0926', 'not a JWS');
    const altered = Object.assign({}, doc, {
      payload: Buffer.from(JSON.stringify(Object.assign({}, payload,
        { realm: 'somebody-else' }))).toString('base64url') });
    await refusedWith(altered, 'STS-ADMIN-0927', 'a payload altered after ' +
                      'it was signed');
    const noChain = Object.assign({}, header, { x5c: [header.x5c[0]] });
    await refusedWith(Object.assign({}, doc, { protected: Buffer.from(
      JSON.stringify(noChain)).toString('base64url') }), 'STS-ADMIN-0926',
                      'a header without the chain');

    // D. ANOTHER REALM IS ASKED.
    t.log.info('D. another realm');
    const asked = await inRealm(B, function () {
      return transfer.importPolicies(doc, {});
    });
    t.equal(errorCodes.codeOf(asked), 'STS-ADMIN-0929',
            'D. realm B refuses until it is answered');
    t.check(asked.needsTrust && asked.inspection.origin === 'foreign' &&
            asked.inspection.chain.length === 4 &&
            asked.inspection.realm === A,
            'D. and says what the question is about',
            JSON.stringify(asked.inspection && asked.inspection.origin));
    t.equal(asked.inspection.payload, undefined,
            'D. without the signed content');
    t.equal(inRealm(B, function () {
      return passwordPolicy.read('default').minLength;
    }) === 17, false, 'D. nothing was written');
    const wrong = await inRealm(B, function () {
      return transfer.importPolicies(doc, { trustSigner: true,
        issuerFingerprint: 'AB'.repeat(32) });
    });
    t.equal(errorCodes.codeOf(wrong), 'STS-ADMIN-0930',
            'D. a yes about another chain is no yes');
    t.equal(inRealm(B, function () {
      return signers.list().length;
    }), 0, 'D. and trusts nothing');
    const bBefore = inRealm(B, function () {
      return transfer.view();
    });
    const colons = asked.inspection.issuerFingerprint.match(/../g).join(':')
      .toLowerCase();
    const yes = await inRealm(B, function () {
      return transfer.importPolicies(doc, { trustSigner: true,
        issuerFingerprint: colons, actor: 'bob' });
    });
    t.check(yes.ok && yes.origin === 'foreign',
            'D. the yes imports it', JSON.stringify(yes.errors));
    t.equal(yes.trustAdded.length, 3,
            'D. and adds the chain\'s three CAs to the signer truststore');
    const held = inRealm(B, function () {
      return signers.list();
    });
    const bAfterYes = inRealm(B, function () {
      return adminViews.policyTransferJson();
    });
    t.check(held.length === 3 && held.every(function (row) {
      return row.purposes.length === 1 && row.purposes[0] === 'policy-signer';
    }), 'D. for policy-signer and nothing else', JSON.stringify(held.map(
      function (row) {
        return row.purposes;
      })));
    t.equal(held.filter(function (row) {
      return row.kind === 'anchor';
    }).length, 1, 'D. the Root as the anchor, the rest intermediates');
    t.equal(inRealm(B, function () {
      return passwordPolicy.read('default').minLength;
    }), 17, 'D. B now holds A\'s password profile');
    const again = await inRealm(B, function () {
      return transfer.importPolicies(doc, {});
    });
    t.check(again.ok && again.origin === 'trusted',
            'D. the next import from A is trusted without a question',
            JSON.stringify(again.errors || again.origin));

    // E. THE YES IS ABOUT ONE REALM.
    t.log.info('E. the yes names one realm');
    const fromC = await inRealm(C, function () {
      return transfer.exportPolicies({});
    });
    t.equal(fromC.ok, true, 'E. realm C exports');
    const cAtB = await inRealm(B, function () {
      return transfer.inspect(fromC.document);
    });
    t.check(cAtB.ok && cAtB.origin === 'foreign',
            'E. B still asks about C, whose Root it already holds',
            JSON.stringify(cAtB.errors || cAtB.origin));
    const aAtD = await inRealm(D, function () {
      return transfer.inspect(doc);
    });
    t.equal(aAtD.origin, 'foreign',
            'E. and D, which said nothing, still asks about A');

    // F. PARANOID VALIDATION.
    t.log.info('F. paranoid validation');
    realms.setOverride(A, 'pki.paranoidPolicySigner', false);
    const loose = await inRealm(A, function () {
      return transfer.inspect(doc);
    });
    realms.clearOverride(A, 'pki.paranoidPolicySigner');
    t.check(loose.ok && loose.verdict.inForce === false,
            'F. with the row off, the master (off in development) decides',
            JSON.stringify(loose.verdict));
    const leafSerial = stsCrypto.parseCertificate(chain[0]).serialNumber;
    const revoked = revocation.revoke(A, 'policy-signing',
      { serialHex: leafSerial, reason: 'keyCompromise', note: 'test' });
    t.check(revoked.ok, 'F. the signer is revoked', JSON.stringify(revoked));
    const afterRevoke = await inRealm(A, function () {
      return transfer.inspect(doc);
    });
    t.equal(errorCodes.codeOf(afterRevoke), 'STS-ADMIN-0928',
            'F. and its export is refused by the door');
    t.check(afterRevoke.verdict && afterRevoke.verdict.checks.revocation ===
            'failed', 'F. for its revocation',
            JSON.stringify(afterRevoke.verdict));

    // G. THE ALGORITHM.
    t.log.info('G. the algorithm');
    const ALGS = ['PS256', 'ES256', 'ES384', 'ES512', 'EdDSA', 'ML-DSA-44',
                  'ML-DSA-65', 'ML-DSA-87'];
    t.check(ALGS.concat(['RS256']).every(function (alg) {
      return config.SETTINGS.filter(function (row) {
        return row.key === 'pki.policyExportAlgorithm';
      })[0].enumValues.indexOf(alg) !== -1;
    }), 'G. every algorithm here is a value of the setting', '');
    for (const alg of ALGS) {
      realms.setOverride(C, 'pki.policyExportAlgorithm', alg);
      const signed = await inRealm(C, function () {
        return transfer.exportPolicies({});
      });
      const seen = signed.ok ? await inRealm(C, function () {
        return transfer.inspect(signed.document);
      }) : signed;
      t.check(signed.ok && headerOf(signed.document).alg === alg &&
              seen.ok && seen.origin === 'own',
              'G. ' + alg + ' exports and verifies',
              JSON.stringify(seen.errors || seen.verdict));
    }
    realms.clearOverride(C, 'pki.policyExportAlgorithm');

    // H. THE ACTION LAYER.
    t.log.info('H. the action layer');
    const viaAction = await inRealm(D, function () {
      return adminActions.policyTransferAction({ action: 'export' },
                                               { via: 'api', actor: 'dora' });
    });
    t.equal(viaAction.ok, true, 'H. export');
    const inspected = await inRealm(D, function () {
      return adminActions.policyTransferAction({ action: 'inspect',
        document: JSON.stringify(viaAction.document) }, { via: 'api' });
    });
    t.check(inspected.ok && inspected.origin === 'own' &&
            inspected.payload === undefined && inspected.pems === undefined,
            'H. inspect, without the signed content or the PEMs',
            JSON.stringify(Object.keys(inspected)));
    const intoB = await inRealm(B, function () {
      return adminActions.policyTransferAction({ action: 'import',
        document: viaAction.document, trustSigner: 'true',
        issuerFingerprint: inspected.issuerFingerprint },
                                               { via: 'api', actor: 'bob' });
    });
    t.check(intoB.ok && intoB.origin === 'foreign',
            'H. import, with the yes', JSON.stringify(intoB.errors));
    const unknown = await adminActions.policyTransferAction(
      { action: 'delete' }, {});
    t.equal(errorCodes.codeOf(unknown), 'STS-ADMIN-0934',
            'H. an unknown action is refused');
    // A REALM'S AUDIT LOG IS ITS OWN: the export is D's, the trust and the
    // import are B's.
    const actionsIn = function (id) {
      log.debug('Entering actionsIn(). ' + id);
      log.debug('Leaving actionsIn().');
      return inRealm(id, function () {
        return audit.list().slice(0, 50).map(function (row) {
          return row.action;
        });
      });
    };
    t.check(actionsIn(D).indexOf('admin.policies.export') !== -1,
            'H. audited: the export, in the realm exported', '');
    ['admin.policies.trust-signer', 'admin.policies.import']
      .forEach(function (action) {
        t.check(actionsIn(B).indexOf(action) !== -1,
                'H. audited: ' + action + ', in the realm imported into', '');
      });

    // I. THE CONSOLE: the tab, and the question.
    t.log.info('I. the console');
    const page = require('../admin-ui/web_policies');
    const kit = require('../admin-ui/web_kit');
    const WebAnswers = require('../admin-ui/web_answers');
    const tr = kit.context({}, true).t;
    const bare = page.transferSection({ state: {} }, tr);
    t.check(/name="action" value="export"/.test(bare) &&
            /name="document"/.test(bare) &&
            /name="action" value="import"/.test(bare) &&
            /name="action" value="inspect"/.test(bare),
            'I. the tab has Export, a box for the document, Check and ' +
            'Import', bare.slice(0, 300));
    const redrawn = WebAnswers.redraw('/admin/policies', 'import',
      { action: 'import', document: text }, asked, { state: {} }, tr);
    t.check(!!redrawn && redrawn.json.state.transfer.inspection.origin ===
            'foreign' && redrawn.banner === '',
            'I. an import that asks first redraws the page with the ' +
            'inspection and no refusal banner', JSON.stringify(redrawn &&
              redrawn.json.state));
    const question = page.transferSection(redrawn.json, tr);
    t.check(question.indexOf(asked.inspection.issuerFingerprint) >= 0 &&
            /name="trustSigner" value="true"/.test(question) &&
            /name="issuerFingerprint"/.test(question) &&
            question.indexOf(A) >= 0,
            'I. the page asks whether to trust that realm\'s chain, naming ' +
            'its Issuing CA, and the yes posts it back',
            question.slice(0, 300));
    const ownDrawn = page.transferSection({ state: { transfer: {
      document: text, inspection: transfer.publicView(ownSeen) } } }, tr);
    t.check(!/name="trustSigner"/.test(ownDrawn) &&
            /name="action" value="import"/.test(ownDrawn),
            'I. its own realm\'s export is offered without a question', '');
    const refusedDrawn = page.transferSection({ state: { transfer: {
      document: text, inspection: afterRevoke } } }, tr);
    t.check(!/name="trustSigner"/.test(refusedDrawn) &&
            refusedDrawn.indexOf('refused by PKI validation') >= 0,
            'I. a refused chain is shown refused, with nothing to answer',
            '');

    // J. THE VIEW: `GET /admin-api/policies/transfer`, the read beside the
    // three acts.
    t.log.info('J. the transfer view');
    const viewA = inRealm(A, function () {
      return adminViews.policyTransferJson();
    });
    t.equal(viewA.realm, A, 'J. the view is about the realm it is read in');
    t.equal(viewA.algorithm, 'RS256',
            'J. it names the algorithm in force, RS256 by default');
    t.check(viewA.algorithms.indexOf('ML-DSA-65') !== -1 &&
            viewA.algorithms.indexOf('RS256') !== -1,
            'J. and every algorithm the setting may take',
            viewA.algorithms.join(','));
    t.equal(viewA.paranoidPolicySigner, true,
            'J. pki.paranoidPolicySigner is on by default');
    const ca = viewA.issuingCa;
    t.check(!!ca, 'J. realm A\'s Policy Export Signing CA is answered', '');
    t.equal(fingerprintOf(ca.certificatePem), fingerprintOf(chain[1]),
            'J. it is the certificate the export carries second in x5c');
    t.equal(ca.fingerprint256, fingerprintOf(chain[1]),
            'J. its fingerprint256 is that certificate\'s SHA-256, in the ' +
            'signer truststore\'s spelling');
    t.equal(ca.fingerprint256, asked.inspection.issuerFingerprint,
            'J. and the fingerprint an inspection asks another realm about');
    t.equal(ca['x5t#S256'], stsCrypto.certificateThumbprint(chain[1]),
            'J. x5t#S256 is the base64url SHA-256 of the same DER');
    t.check(ca.chainPem.length === 2 &&
            fingerprintOf(ca.chainPem[0]) === fingerprintOf(chain[1]) &&
            fingerprintOf(ca.chainPem[1]) === fingerprintOf(chain[2]),
            'J. the chain is the Issuing CA and the Intermediate, as in x5c',
            String(ca.chainPem.length));
    t.check(ca.chainPem.every(function (pem) {
      return fingerprintOf(pem) !== fingerprintOf(chain[3]);
    }) && ca.root.fingerprint256 === fingerprintOf(chain[3]),
            'J. the Root is named apart and is not in the chain', '');
    t.check(/Policy Export Signing CA/.test(ca.subject) &&
            Date.parse(ca.notAfter) > Date.now() &&
            Date.parse(ca.notBefore) <= Date.now(),
            'J. with its subject and validity', ca.subject + ' ' +
            ca.notBefore + ' ' + ca.notAfter);
    t.equal(viewA.trustedSigners.length, 0,
            'J. realm A has trusted no other realm');
    const noSecret = function (one) {
      log.debug('Entering noSecret().');
      const text = JSON.stringify(one);
      log.debug('Leaving noSecret().');
      return !/PRIVATE KEY|privateKey|"d":/.test(text);
    };
    t.check(noSecret(viewA), 'J. no private key anywhere in the view', '');
    t.equal(bBefore.trustedSigners.length, 0,
            'J. before its yes, realm B lists no trusted signer');
    const viewB = bAfterYes;
    const bPrints = viewB.trustedSigners.map(function (one) {
      return one.fingerprint256;
    });
    t.check(viewB.trustedSigners.length === 3 &&
            bPrints.indexOf(ca.fingerprint256) !== -1 &&
            bPrints.indexOf(fingerprintOf(chain[2])) !== -1 &&
            bPrints.indexOf(fingerprintOf(chain[3])) !== -1,
            'J. after the yes, realm B lists A\'s Issuing CA, Intermediate ' +
            'and Root as trusted signers', JSON.stringify(bPrints));
    t.check(viewB.trustedSigners.every(function (one) {
      return one.purposes.join(',') === 'policy-signer' &&
             one.addedBy === 'bob' && one.source === 'runtime';
    }), 'J. each for policy-signer, added by the one who said yes',
            JSON.stringify(viewB.trustedSigners.map(function (one) {
              return [one.purposes, one.addedBy, one.source];
            })));
    t.check(noSecret(viewB), 'J. and still no private key', '');
    const dIssuer = inRealm(D, function () {
      return adminViews.policyTransferJson().issuingCa;
    });
    const bLater = inRealm(B, function () {
      return adminViews.policyTransferJson();
    });
    t.check(!!dIssuer && bLater.trustedSigners.some(function (one) {
      return one.fingerprint256 === dIssuer.fingerprint256;
    }) && bLater.trustedSigners.length > viewB.trustedSigners.length,
            'J. the yes to D\'s export (H) added D\'s Issuing CA to B\'s list',
            JSON.stringify(bLater.trustedSigners.map(function (one) {
              return one.fingerprint256;
            })));
    realms.setOverride(C, 'pki.policyExportAlgorithm', 'ES384');
    realms.setOverride(C, 'pki.paranoidPolicySigner', false);
    const viewC = inRealm(C, function () {
      return adminViews.policyTransferJson();
    });
    realms.clearOverride(C, 'pki.policyExportAlgorithm');
    realms.clearOverride(C, 'pki.paranoidPolicySigner');
    t.check(viewC.algorithm === 'ES384' &&
            viewC.paranoidPolicySigner === false,
            'J. a realm\'s own algorithm and paranoid row are its own',
            viewC.algorithm + ' ' + viewC.paranoidPolicySigner);
    // THE ANSWER MEETS ITS CLOSED MODEL: what `/admin-api` holds every
    // answer to, so a member the model lacks is a 500 (STS-API-0139).
    const document = require('../common/model_tables')
      .file('openapi.management.json');
    const op = document.paths['/admin-api/policies/transfer'] &&
      document.paths['/admin-api/policies/transfer'].get;
    t.check(!!op && op.operationId === 'getPolicyTransfer',
            'J. the Management API OpenAPI document has the operation', '');
    const Ajv = require('ajv');
    const validate = new Ajv({ strict: false, allErrors: true }).compile({
      allOf: [op.responses['200'].content['application/json'].schema],
      components: document.components });
    [['A', viewA], ['B', viewB], ['C', viewC]].forEach(function (pair) {
      t.check(validate(JSON.parse(JSON.stringify(pair[1]))),
              'J. realm ' + pair[0] + '\'s view meets its model',
              JSON.stringify(validate.errors || []));
    });
    t.check(!validate(Object.assign({ stray: 1 }, viewA)) &&
            !validate(Object.assign({}, viewA, { issuingCa: Object.assign(
              { privateKeyPem: 'x' }, viewA.issuingCa) })),
            'J. and the model is closed, the CA\'s members too', '');
    const drawn = page.transferSection({ state: {}, transfer: viewB }, tr);
    t.check(drawn.indexOf(viewB.trustedSigners[0].fingerprint256) >= 0 &&
            drawn.indexOf('id="transfer-trusted"') >= 0 &&
            drawn.indexOf('RS256') >= 0,
            'J. the tab draws the algorithm and the trusted signers',
            drawn.slice(0, 300));
    const drawnA = page.transferSection({ state: {}, transfer: viewA }, tr);
    t.check(drawnA.indexOf(ca.fingerprint256) >= 0 &&
            drawnA.indexOf(ca['x5t#S256']) >= 0,
            'J. and this realm\'s Issuing CA with its fingerprint', '');
    t.check(page.transferSection({ state: {}, transfer: Object.assign({},
      viewA, { issuingCa: null }) }, tr).indexOf('first export builds it') >=
            0, 'J. a realm with no CA yet is told the first export builds it',
            '');
    t.check(Array.isArray(viewA.policies) &&
            viewA.policies.some(function (one) {
              return one.kind === 'password' && one.name === 'strict' &&
                     one.named === false;
            }) && viewA.policies.some(function (one) {
              return one.kind === 'authn' && one.name === 'keys-only' &&
                     one.named === true;
            }) && !viewA.policies.some(function (one) {
              return one.kind === 'authn' && one.name === 'default';
            }),
            'J. the view lists what may be selected: every stored policy, ' +
            'and not an inherited one', JSON.stringify(viewA.policies));

    await selections(t, { A: A, E: E, F: F, document: document,
                          validate: validate, Ajv: Ajv });
  } finally {
    [A, B, C, D, E, F].forEach(function (id) {
      if (realms.get(id)) {
        realms.remove(id);
      }
    });
  }
  log.debug('Leaving run().');
}

module.exports = {
  name: 'policy_transfer',
  describe: 'policy export and import (#1713): a signed JSON document with ' +
            'its whole chain, its own realm trusted, another realm asked ' +
            'about and pinned by its Issuing CA, full paranoid validation, ' +
            'a configurable algorithm',
  run: run
};
