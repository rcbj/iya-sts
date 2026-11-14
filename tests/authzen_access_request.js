// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/authzen_access_request.js
//
// ---------------------------------------------------------------------------
// THE AUTHZEN ACCESS REQUEST AND APPROVAL PROFILE (#1180), IN PROCESS, OVER
// REAL HANDSHAKES.
//
// `authzen_evaluation.js`'s arrangement: the whole stack in a child
// process, a listener with the main port's posture over the client
// truststore, and a throwaway realm whose root policy this file wrote — a
// read is permitted only with a verified approval, and otherwise denied
// with the access-request advice naming the group `azapprovers`. What it
// holds:
//
//   R. THE REQUESTABLE DENIAL: a read is false with context.access_request
//      (expires_at, endpoint, a binding_token that verifies as the realm's)
//      and evaluation_id; a delete, denied without the advice, is a plain
//      false; the metadata names the endpoint, jwks_uri and the capability.
//   S. THE SUBMISSION: no denial (not_requestable), a changed tuple and
//      another caller (invalid_denial_binding), a callback nobody
//      registered, then 202 with a Task Handle and Location; the same
//      Idempotency-Key and body is the same task, another body 409.
//   T. THE STATUS: pending with Retry-After for its caller, unknown_task
//      for another.
//   A. THE APPROVAL: who is eligible and listed, the policy refusing
//      somebody not named and the request's own subject (who is in the
//      group), an approver approving through the portal's door; the task
//      approved with its result; a re-evaluation carrying the approval
//      true, another tuple out_of_scope with a fresh denial, another
//      caller approval_unverifiable; a revocation and approval_expired.
//   C. CANCELLATION, and a finished task 409.
//   X. AN ADMINISTRATOR'S DENIAL through the console's door, as one the
//      advice did not name, holding ADMIN_WRITE.
//   E. EXPIRY by the scheduler job's sweep, and the audit row.
//   M. EMERGENCY ACCESS: refused without a justification, granted at once
//      (201) with one.
//   B. A REGISTERED CALLBACK accepted, and its delivery recorded.
//   O. OFF: authzen.accessRequests off answers 501 and no denial is
//      requestable.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const https = require('https');
const nodeCrypto = require('crypto');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_AUTHZEN_ACCESS_REQUEST_CHILD';
const MARK = 'AUTHZEN-ACCESS-REQUEST-CHILD ';
const REALM = 'azarq';
const PREFIX = '/realm/' + REALM;
const ADVICE = 'urn:sts:xacml:advice:access-request';

const CA_PEM = { value: '' };

const log = require('bunyan').createLogger({ name: 'authzen_access_request',
  level: process.env.LOG_LEVEL || 'info' });

// THE ROOT POLICY: a read with a verified approval is permitted; any other
// read is denied with the access-request advice; a delete is denied with
// none.
const POLICY = [
  'namespace azarq {',
  '    attribute act { category = actionCat',
  '        id = "urn:oasis:names:tc:xacml:1.0:action:action-id"',
  '        type = string }',
  '    attribute protocol { category = environmentCat',
  '        id = "urn:sts:xacml:protocol" type = string }',
  '    attribute approval { category = environmentCat',
  '        id = "urn:sts:xacml:authzen:approval-id" type = string }',
  '    policy azarqRoot {',
  '        id = "urn:test:azarq-root"',
  '        apply firstApplicable',
  '        target clause protocol == "authzen"',
  '        rule approvedRead {',
  '            permit',
  '            target clause act == "read"',
  '            condition integerGreaterThan(stringBagSize(approval), 0)',
  '        }',
  '        rule requestableRead {',
  '            deny',
  '            target clause act == "read"',
  '            on deny {',
  '                advice "' + ADVICE + '" {',
  '                    "' + ADVICE + ':approver-group" = "azapprovers"',
  '                    "' + ADVICE + ':max-approval-seconds" = "3600"',
  '                    "' + ADVICE + ':emergency" = "true"',
  '                }',
  '            }',
  '        }',
  '        rule plainDelete {',
  '            deny',
  '            target clause act == "delete"',
  '        }',
  '    }',
  '}'
].join('\n');

function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? '' : String(detail) });
      log.debug("Leaving check().");
    }
  };
}

function request(port, method, urlPath, cred, body, headers) {
  log.debug("Entering request().");
  log.debug("Leaving request().");
  return new Promise(function (resolve) {
    const text = body === undefined ? ''
      : (typeof body === 'string' ? body : JSON.stringify(body));
    const sent = Object.assign({ 'content-type': 'application/json',
                                 'content-length': Buffer.byteLength(text) },
                               headers || {});
    const req = https.request({ host: '127.0.0.1', port: port,
      path: urlPath, method: method, headers: sent, ca: CA_PEM.value,
      cert: cred ? cred.certPem : undefined,
      key: cred ? cred.keyPem : undefined, agent: false }, function (res) {
      let raw = '';
      res.on('data', function (chunk) {
        raw += chunk;
      });
      res.on('end', function () {
        let json = null;
        try {
          json = JSON.parse(raw);
        } catch (e) {
          log.debug("Caught in request(): " + e.message);
          json = null;
        }
        resolve({ status: res.statusCode, headers: res.headers, text: raw,
                  json: json });
      });
    });
    req.on('error', function (e) {
      log.debug("Caught in request(): " + e.message);
      resolve({ status: 0, headers: {}, text: '', json: null,
                error: e.message });
    });
    req.end(text);
  });
}

// One evaluation of azalice's, and whatever `extra` replaces.
function evaluation(extra) {
  log.debug("Entering evaluation().");
  const out = Object.assign({
    subject: { type: 'user', id: 'azalice' },
    action: { name: 'read' },
    resource: { type: 'document', id: 'doc-1' },
    context: { application: 'todo-app' }
  }, extra || {});
  log.debug("Leaving evaluation().");
  return out;
}

// The submission a PEP makes from a requestable denial.
function submission(denied, extra) {
  log.debug("Entering submission().");
  const ar = denied.context.access_request;
  const out = Object.assign({
    subject: { type: 'user', id: 'azalice' },
    action: { name: 'read' },
    resource: { type: 'document', id: 'doc-1' },
    context: { application: 'todo-app' },
    denial: { expires_at: ar.expires_at, binding_token: ar.binding_token,
              evaluation_id: denied.context.evaluation_id,
              reason: denied.context.reason }
  }, extra || {});
  log.debug("Leaving submission().");
  return out;
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require(ROOT + '/common/protocol_stack');
  const app = require(ROOT + '/common/app');
  const keystore = require(ROOT + '/common/keystore');
  const pki = require(ROOT + '/common/pki');
  const helpers = require(ROOT + '/common/helpers');
  const realms = require(ROOT + '/common/realms');
  const config = require(ROOT + '/common/config');
  const errorCodes = require(ROOT + '/common/error_codes');
  const audit = require(ROOT + '/common/audit');
  const gate = require(ROOT + '/common/access_gate');
  const tls = require(ROOT + '/tls/tls_server');
  const ldap = require(ROOT + '/ldap/ldap_server');
  const adminActions = require(ROOT + '/admin-core/admin_actions');
  const store = require(ROOT + '/xacml/xacml_store');
  const xml = require(ROOT + '/xacml/xacml_xml');
  const alfa = require(ROOT + '/xacml/xacml_alfa');
  const requests = require(ROOT + '/authzen/authzen_access_request');
  const authzenAdmin = require(ROOT + '/authzen/authzen_admin');
  const testCa = require('./protocol/outbound_test_ca');
  const outsideCa = require('./tools/pep-credential.js');

  const marks = [];
  const mark = errorCodes.mark;
  errorCodes.mark = function (res, code) {
    marks.push(code);
    return mark.apply(this, arguments);
  };
  const markedSince = function (since, code) {
    log.debug("Entering markedSince().");
    log.debug("Leaving markedSince().");
    return marks.slice(since).indexOf(code) >= 0;
  };

  await keystore.start();
  if (!realms.get(REALM)) {
    realms.create({ id: REALM, name: REALM });
  }
  await pki.start({ realmIds: ['', REALM],
    keySetFor: function (id) {
      log.debug("Entering keySetFor().");
      log.debug("Leaving keySetFor().");
      return helpers.stsKeysFor.of(id);
    },
    keySetHeldFor: function () {
      log.debug("Entering keySetHeldFor().");
      log.debug("Leaving keySetHeldFor().");
      return false;
    } });
  const inRealm = function (fn) {
    log.debug("Entering inRealm().");
    log.debug("Leaving inRealm().");
    return realms.run(realms.get(REALM), fn);
  };

  // THE PEOPLE: azalice is the subject (and, to test self-approval, in the
  // approvers' group too); azbob an approver; azcarol nobody; azpep and
  // azpep2 two PEPs, both in authzen-peps and scoped to todo-app.
  const mint = function (subject) {
    log.debug("Entering mint().");
    log.debug("Leaving mint().");
    return outsideCa.mint({ subject: subject, crlBase: '' });
  };
  const pepCred = await mint('CN=azarqpep,O=Outside');
  const pep2Cred = await mint('CN=azarqpep2,O=Outside');
  const added = tls.addAnchors([pepCred, pep2Cred].map(function (one) {
    return one.anchorPem;
  }).join(''));
  t.check(added && added.added === 2,
          'setup: the outside Root CAs are in the client truststore',
          JSON.stringify(added));
  const derOf = function (minted) {
    log.debug("Entering derOf().");
    log.debug("Leaving derOf().");
    return new nodeCrypto.X509Certificate(minted.leaf.pem).raw;
  };
  const pepGroup = String(config.value('roles.authzenPepGroup'));
  inRealm(function () {
    ['azalice', 'azbob', 'azcarol', 'azpep', 'azpep2'].forEach(
      function (name) {
        ldap.createUser(name, { invent: false });
      });
    ldap.changeStoredCertificate('person', 'azpep', { add: derOf(pepCred) });
    ldap.changeStoredCertificate('person', 'azpep2',
                                 { add: derOf(pep2Cred) });
    ['azpep', 'azpep2'].forEach(function (name) {
      adminActions.groupsAction({ action: 'add-member', group: pepGroup,
                                  member: name });
      ldap.locateEntry(name).stored.attributes.stsauthzenapplication =
        ['todo-app'];
    });
    ldap.createGroup('azapprovers', { members: [] });
    ['azbob', 'azalice'].forEach(function (name) {
      adminActions.groupsAction({ action: 'add-member', group: 'azapprovers',
                                  member: name });
    });
    store.write('azarq-root', xml.writePolicy(alfa.parse(POLICY)),
                { enabled: true, isRoot: true });
  });

  const serverCa = await testCa.makeCa();
  const serverLeaf = await testCa.listenerCertificate(serverCa, '127.0.0.1');
  CA_PEM.value = serverCa.certPem;
  const listener = https.createServer(Object.assign({
    cert: serverLeaf.cert, key: serverLeaf.key,
    ca: tls.clientTruststoreOptions().ca,
    requestCert: true, rejectUnauthorized: false
  }, tls.protocolOptions()), app);
  tls.trustClientCertificatesOn(listener,
    'the authzen_access_request listener', function () {
      log.debug("Entering the listener's certificateOf().");
      log.debug("Leaving the listener's certificateOf().");
      return { key: serverLeaf.key, cert: serverLeaf.cert };
    });
  await new Promise(function (ok) {
    listener.listen(0, '127.0.0.1', ok);
  });
  const port = listener.address().port;
  const own = 'https://127.0.0.1:' + port + PREFIX;
  const EVAL = PREFIX + '/access/v1/evaluation';
  const SUBMIT = PREFIX + '/access/v1/access-requests';
  const brief = function (r) {
    log.debug("Entering brief().");
    log.debug("Leaving brief().");
    return r.status + ' ' + String(r.text || '').slice(0, 400);
  };
  const problemOf = function (r) {
    log.debug("Entering problemOf().");
    log.debug("Leaving problemOf().");
    return /application\/problem\+json/.test(
      String(r.headers['content-type'] || '')) && r.json
      ? String(r.json.type || '') : '';
  };
  const pathOf = function (url) {
    log.debug("Entering pathOf().");
    log.debug("Leaving pathOf().");
    return String(url || '').replace(/^https?:\/\/[^/]+/, '');
  };

  // -------------------------------------------------------------------------
  // R. THE REQUESTABLE DENIAL
  // -------------------------------------------------------------------------
  let r = await request(port, 'POST', EVAL, pepCred, evaluation());
  const denied = r.json || {};
  const ar = (denied.context || {}).access_request || {};
  t.check(r.status === 200 && denied.decision === false && ar.expires_at &&
          ar.endpoint === own + '/access/v1/access-requests' &&
          ar.binding_token && /^eval_/.test(denied.context.evaluation_id) &&
          denied.context.reason === 'approval_required',
          'R1. a read the policy marked requestable is false with ' +
          'context.access_request, evaluation_id and reason', brief(r));
  let claims = null;
  try {
    claims = inRealm(function () {
      return helpers.verifyOwnJws(String(ar.binding_token || ''));
    });
  } catch (e) {
    log.debug("Caught in childBody(): " + ((e && e.message) || e));
    claims = null;
  }
  t.check(!!claims && claims.iss === own &&
          [].concat(claims.aud).indexOf(ar.endpoint) >= 0 &&
          claims.resource && claims.resource.id === 'doc-1' &&
          claims.denial_expires_at === ar.expires_at,
          'R2. the binding_token is the realm\'s JWS over the denied tuple, ' +
          'audienced to the access request endpoint', JSON.stringify(claims));
  r = await request(port, 'POST', EVAL, pepCred,
                    evaluation({ action: { name: 'delete' } }));
  t.check(r.status === 200 && r.json && r.json.decision === false &&
          !(r.json.context && r.json.context.access_request),
          'R3. a denial without the advice is a plain false', brief(r));
  r = await request(port, 'GET',
                    '/.well-known/authzen-configuration' + PREFIX, null);
  const doc = r.json || {};
  t.check(r.status === 200 &&
          doc.access_request_endpoint === own + '/access/v1/access-requests' &&
          Array.isArray(doc.capabilities) &&
          doc.capabilities.indexOf(
            'urn:openid:authzen:capability:access-request') >= 0 &&
          /\/oauth2\/jwks$/.test(String(doc.jwks_uri || '')),
          'R4. the metadata names access_request_endpoint, jwks_uri and the ' +
          'capability', brief(r));

  // -------------------------------------------------------------------------
  // S. THE SUBMISSION
  // -------------------------------------------------------------------------
  let since = marks.length;
  r = await request(port, 'POST', SUBMIT, pepCred,
                    { subject: { type: 'user', id: 'azalice' },
                      action: { name: 'read' },
                      resource: { type: 'document', id: 'doc-1' } });
  t.check(r.status === 400 && /not_requestable$/.test(problemOf(r)) &&
          markedSince(since, 'STS-AUTHZEN-0072'),
          'S1. no denial is not_requestable (STS-AUTHZEN-0072), as ' +
          'problem+json', brief(r));
  since = marks.length;
  r = await request(port, 'POST', SUBMIT, pepCred, submission(denied,
    { resource: { type: 'document', id: 'doc-2' } }));
  t.check(r.status === 400 && /invalid_denial_binding$/.test(problemOf(r)) &&
          markedSince(since, 'STS-AUTHZEN-0074'),
          'S2. another resource than the denied one is ' +
          'invalid_denial_binding (STS-AUTHZEN-0074)', brief(r));
  since = marks.length;
  r = await request(port, 'POST', SUBMIT, pep2Cred, submission(denied));
  t.check(r.status === 400 && /invalid_denial_binding$/.test(problemOf(r)) &&
          markedSince(since, 'STS-AUTHZEN-0074'),
          'S3. another caller than the one denied is invalid_denial_binding',
          brief(r));
  since = marks.length;
  r = await request(port, 'POST', SUBMIT, pepCred, submission(denied,
    { callback: { endpoint: 'https://pep.example.com/cb' } }));
  t.check(r.status === 400 && markedSince(since, 'STS-AUTHZEN-0079'),
          'S4. a callback nobody registered for the caller is refused ' +
          '(STS-AUTHZEN-0079)', brief(r));
  r = await request(port, 'POST', SUBMIT, pepCred, submission(denied),
                    { 'idempotency-key': 'azarq-key-1' });
  const task = (r.json || {}).task || {};
  t.check(r.status === 202 && task.status === 'pending' &&
          /^arq_/.test(task.id) &&
          task.status_endpoint === own + '/access/v1/access-requests/' +
            task.id &&
          r.headers.location === task.status_endpoint &&
          task.links && task.links.cancel === task.status_endpoint +
            '/cancel',
          'S5. a good submission is 202 with a Task Handle and Location',
          brief(r));
  r = await request(port, 'POST', SUBMIT, pepCred, submission(denied),
                    { 'idempotency-key': 'azarq-key-1' });
  t.check(r.status === 202 && r.json && r.json.task &&
          r.json.task.id === task.id,
          'S6. the same Idempotency-Key and body is the same task',
          brief(r));
  since = marks.length;
  r = await request(port, 'POST', SUBMIT, pepCred, submission(denied,
    { requested_access: { requested_until: '2099-01-01T00:00:00Z' } }),
    { 'idempotency-key': 'azarq-key-1' });
  t.check(r.status === 409 && /duplicate_request$/.test(problemOf(r)) &&
          markedSince(since, 'STS-AUTHZEN-0076'),
          'S7. the same key with another body is duplicate_request (409)',
          brief(r));

  // -------------------------------------------------------------------------
  // T. THE STATUS
  // -------------------------------------------------------------------------
  const STATUS = pathOf(task.status_endpoint);
  r = await request(port, 'GET', STATUS, pepCred);
  t.check(r.status === 200 && r.json && r.json.task.status === 'pending' &&
          Number(r.headers['retry-after']) > 0 && !r.json.result,
          'T1. the requester reads it pending, with Retry-After', brief(r));
  since = marks.length;
  r = await request(port, 'GET', STATUS, pep2Cred);
  t.check(r.status === 404 && /unknown_task$/.test(problemOf(r)) &&
          markedSince(since, 'STS-AUTHZEN-0080'),
          'T2. another caller is told unknown_task (STS-AUTHZEN-0080)',
          brief(r));

  // -------------------------------------------------------------------------
  // A. THE APPROVAL
  // -------------------------------------------------------------------------
  const listed = inRealm(function () {
    return { bob: requests.awaiting('azbob').map(function (one) {
               return one.id;
             }),
             alice: requests.awaiting('azalice').length,
             carol: requests.awaiting('azcarol').length,
             mailed: requests.approversOf(requests.task(task.id)) };
  });
  t.check(listed.bob.indexOf(task.id) >= 0 && listed.alice === 0 &&
          listed.carol === 0 && listed.mailed.indexOf('azbob') >= 0 &&
          listed.mailed.indexOf('azalice') < 0,
          'A1. the approver lists it; its own subject (in the group) and ' +
          'somebody not named do not, and the subject is not mailed',
          JSON.stringify(listed));
  let decided = inRealm(function () {
    return requests.decide(task.id, 'approve',
                           { username: 'azcarol', door: 'portal' });
  });
  t.check(!decided.ok && errorCodes.codeOf(decided) === 'STS-AUTHZEN-0088',
          'A2. the policy refuses somebody the advice did not name ' +
          '(STS-AUTHZEN-0088)', JSON.stringify(decided));
  decided = inRealm(function () {
    return requests.decide(task.id, 'approve',
                           { username: 'azalice', door: 'portal' });
  });
  t.check(!decided.ok && errorCodes.codeOf(decided) === 'STS-AUTHZEN-0088',
          'A3. the policy refuses the request\'s own subject, though in the ' +
          'approvers\' group', JSON.stringify(decided));
  const asked = inRealm(function () {
    return gate.check({ resource: 'authzen-access-request',
      action: 'approve-access-request',
      subject: { name: 'azcarol', kind: 'user', authenticated: true,
                 roles: ['ADMIN_WRITE'] },
      requiredRoles: ['ADMIN_WRITE'] });
  });
  t.check(!asked.allowed,
          'A4. the first rule never permits the resource, whatever role ' +
          'it requires', JSON.stringify(asked));
  decided = inRealm(function () {
    return requests.decide(task.id, 'approve',
                           { username: 'azbob', door: 'portal' });
  });
  t.check(decided.ok && decided.task.status === 'approved' &&
          decided.task.approval && decided.task.approval.approver === 'azbob',
          'A5. the approver approves through the portal\'s door',
          JSON.stringify(decided));
  r = await request(port, 'GET', STATUS, pepCred);
  const result = (r.json || {}).result || {};
  const approval = result.approval || {};
  t.check(r.status === 200 && r.json.task.status === 'approved' &&
          result.mode === 'reevaluate' && /^apr_/.test(approval.id) &&
          Date.parse(approval.approved_until) - Date.now() <= 3600 * 1000 +
            5000 && !r.headers['retry-after'],
          'A6. the task is approved with the reevaluate result, the ' +
          'advice\'s hour the longest', brief(r));
  r = await request(port, 'POST', EVAL, pepCred, evaluation({
    context: { application: 'todo-app', approval: approval } }));
  t.check(r.status === 200 && r.json && r.json.decision === true &&
          r.json.context && r.json.context.approval &&
          r.json.context.approval.id === approval.id,
          'A7. a re-evaluation carrying the approval is permitted by the ' +
          'root policy, which read the trusted approval-id', brief(r));
  r = await request(port, 'POST', EVAL, pepCred, evaluation({
    resource: { type: 'document', id: 'doc-9' },
    context: { application: 'todo-app', approval: approval } }));
  t.check(r.status === 200 && r.json && r.json.decision === false &&
          r.json.context.reason === 'out_of_scope' &&
          r.json.context.next_action === 'request' &&
          r.json.context.access_request,
          'A8. another resource is out_of_scope, next_action request with ' +
          'a fresh access_request', brief(r));
  r = await request(port, 'POST', EVAL, pep2Cred, evaluation({
    context: { application: 'todo-app', approval: approval } }));
  t.check(r.status === 200 && r.json && r.json.decision === false &&
          r.json.context.reason === 'approval_unverifiable' &&
          r.json.context.next_action === 'none',
          'A9. another caller presenting it is approval_unverifiable',
          brief(r));
  r = await request(port, 'POST', EVAL, pepCred, evaluation({
    context: { application: 'todo-app',
               approval: { id: 'apr_forged', approved_until:
                           '2099-01-01T00:00:00Z' } } }));
  t.check(r.status === 200 && r.json && r.json.decision === false &&
          r.json.context.reason === 'approval_unverifiable',
          'A10. a forged approval id is never believed', brief(r));
  decided = inRealm(function () {
    return authzenAdmin.act({ action: 'revoke-access-request',
                              request: task.id },
                            { actor: 'azbob', via: 'api', roles: [] });
  });
  r = await request(port, 'POST', EVAL, pepCred, evaluation({
    context: { application: 'todo-app', approval: approval } }));
  t.check(decided.ok && r.json && r.json.decision === false &&
          r.json.context.reason === 'approval_expired' &&
          r.json.context.next_action === 'request',
          'A11. once revoked (the console\'s door) the approval is ' +
          'approval_expired', JSON.stringify(decided) + ' / ' + brief(r));

  // A fresh denial for each of the next tasks.
  const fresh = async function () {
    log.debug("Entering fresh().");
    const got = await request(port, 'POST', EVAL, pepCred, evaluation());
    log.debug("Leaving fresh().");
    return got.json;
  };

  // -------------------------------------------------------------------------
  // C. CANCELLATION
  // -------------------------------------------------------------------------
  r = await request(port, 'POST', SUBMIT, pepCred,
                    submission(await fresh()));
  const second = ((r.json || {}).task || {});
  r = await request(port, 'DELETE', pathOf(second.links.cancel), pepCred);
  t.check(r.status === 200 && r.json && r.json.task.status === 'cancelled',
          'C1. the requester cancels a pending task (DELETE)', brief(r));
  since = marks.length;
  r = await request(port, 'POST', pathOf(second.links.cancel), pepCred, {});
  t.check(r.status === 409 && /invalid_task_state$/.test(problemOf(r)) &&
          markedSince(since, 'STS-AUTHZEN-0082'),
          'C2. a finished task is invalid_task_state (409)', brief(r));

  // -------------------------------------------------------------------------
  // X. AN ADMINISTRATOR'S DENIAL
  // -------------------------------------------------------------------------
  r = await request(port, 'POST', SUBMIT, pepCred,
                    submission(await fresh()));
  const third = ((r.json || {}).task || {});
  decided = inRealm(function () {
    return authzenAdmin.act({ action: 'deny-access-request',
                              request: third.id },
                            { actor: 'azcarol', via: 'api',
                              roles: ['ADMIN_WRITE'] });
  });
  r = await request(port, 'GET', pathOf(third.status_endpoint), pepCred);
  t.check(decided.ok && r.json && r.json.task.status === 'denied' &&
          !r.json.result,
          'X1. an Admin Write administrator the advice did not name denies ' +
          'it through the management API', JSON.stringify(decided));

  // -------------------------------------------------------------------------
  // E. EXPIRY
  // -------------------------------------------------------------------------
  r = await request(port, 'POST', SUBMIT, pepCred,
                    submission(await fresh()));
  const fourth = ((r.json || {}).task || {});
  const swept = inRealm(function () {
    requests.task(fourth.id).expiresAt = 1;
    return requests.sweep();
  });
  r = await request(port, 'GET', pathOf(fourth.status_endpoint), pepCred);
  const expiredRows = inRealm(function () {
    return audit.list().filter(function (row) {
      return row.action === 'authzen.access-request.expired';
    }).length;
  });
  t.check(r.json && r.json.task.status === 'expired' &&
          /expired/.test(String(swept.summary)) && expiredRows >= 1,
          'E1. the job\'s sweep expires a task past its deadline, with its ' +
          'audit row', JSON.stringify(swept) + ' / ' + brief(r));

  // -------------------------------------------------------------------------
  // M. EMERGENCY ACCESS
  // -------------------------------------------------------------------------
  since = marks.length;
  r = await request(port, 'POST', SUBMIT, pepCred, submission(await fresh(),
    { requested_access: { emergency: true } }));
  t.check(r.status === 400 && markedSince(since, 'STS-AUTHZEN-0083'),
          'M1. emergency access without a justification is refused',
          brief(r));
  r = await request(port, 'POST', SUBMIT, pepCred, submission(await fresh(),
    { requested_access: { emergency: true },
      context: { application: 'todo-app',
                 business_justification: 'the outage on call' } }));
  t.check(r.status === 201 && r.json && r.json.task.status === 'approved' &&
          r.json.result && r.json.result.approval &&
          Date.parse(r.json.result.approval.approved_until) - Date.now() <=
            3600 * 1000 + 5000,
          'M2. emergency access the advice allows is approved at once ' +
          '(201), for the shortest lifetime', brief(r));

  // -------------------------------------------------------------------------
  // B. A REGISTERED CALLBACK
  // -------------------------------------------------------------------------
  const CALLBACK = 'https://127.0.0.1:9/azarq-callback';
  const set = inRealm(function () {
    return authzenAdmin.act({ action: 'set-callbacks', caller: 'azpep',
                              callbacks: CALLBACK },
                            { actor: 'azcarol', via: 'api' });
  });
  r = await request(port, 'POST', SUBMIT, pepCred, submission(await fresh(),
    { callback: { endpoint: CALLBACK, state: 's-1',
                  events: ['cancelled'] } }));
  const fifth = ((r.json || {}).task || {});
  t.check(set.ok && r.status === 202 && fifth.id,
          'B1. a callback registered for the caller is accepted',
          JSON.stringify(set) + ' / ' + brief(r));
  const sent = await inRealm(function () {
    requests.cancelByAdministrator(fifth.id, 'azcarol');
    return requests.notify(requests.task(fifth.id));
  });
  const callbackRows = inRealm(function () {
    return audit.list().filter(function (row) {
      return row.action === 'authzen.access-request.callback';
    });
  });
  t.check(sent === false && callbackRows.length >= 1,
          'B2. the callback is attempted under the outbound policy and an ' +
          'undelivered one is recorded', JSON.stringify(callbackRows[0]));

  // -------------------------------------------------------------------------
  // O. OFF
  // -------------------------------------------------------------------------
  inRealm(function () {
    config.setOverride('authzen.accessRequests', false);
  });
  since = marks.length;
  r = await request(port, 'POST', SUBMIT, pepCred, {});
  const offDenial = await request(port, 'POST', EVAL, pepCred, evaluation());
  inRealm(function () {
    config.setOverride('authzen.accessRequests', true);
  });
  t.check(r.status === 501 && markedSince(since, 'STS-AUTHZEN-0070') &&
          offDenial.json && offDenial.json.decision === false &&
          !(offDenial.json.context && offDenial.json.context.access_request),
          'O1. off, the endpoint answers 501 and no denial is requestable',
          brief(r) + ' / ' + brief(offDenial));

  await new Promise(function (ok) {
    listener.close(ok);
  });
  log.debug("Leaving childBody().");
  return t.rows;
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = '1';
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 300000,
    maxBuffer: 64 * 1024 * 1024
  });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf(MARK) === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    '): ' + String(result.stderr || '').slice(-1500) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: JSON.parse(line.slice(MARK.length)) };
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== AuthZEN access requests and approvals (#1180) ===');
  const got = spawnChild();
  if (got.error) {
    t.bad('the child did not run', got.error);
    log.debug("Leaving run(). No child.");
    return;
  }
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG]) {
  childBody().then(function (rows) {
    process.stdout.write('\n' + MARK + JSON.stringify(rows) + '\n');
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'authzen_access_request',
  describe: 'The AuthZEN Access Request and Approval Profile (#1180): the ' +
            'requestable denial, the submission and its binding, the task ' +
            'status and cancellation, approval by the policy\'s approvers ' +
            'and never the subject, re-evaluation with the approval, ' +
            'revocation, expiry, emergency access and the callback',
  run: run
};
