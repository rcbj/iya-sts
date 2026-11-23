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
//      (expires_at, endpoint, request_schema_url, a binding_token that
//      verifies as the realm's, its inline tuple and binding_hash) and
//      evaluation_id, and no form_url; the schema is public JSON Schema
//      of the optional augmentations; a delete, denied without the
//      advice, is a plain false; the metadata names the endpoint,
//      jwks_uri and the capability.
//   S. THE SUBMISSION: a body not sent as application/json is 415
//      problem+json (STS-AUTHZEN-0122, #936) and makes no task, one sent
//      with a charset is read; no denial (not_requestable), a changed tuple and
//      another caller (invalid_denial_binding), a callback nobody
//      registered for an application (a person is refused), then 202
//      with a Task Handle and Location; the same
//      Idempotency-Key and body is the same task, another body 409.
//   T. THE STATUS: pending with Retry-After for its caller, unknown_task
//      for another.
//   A. THE APPROVAL: who is eligible and listed, the policy refusing
//      somebody not named and the request's own subject (who is in the
//      group), an approver approving through the portal's door; the task
//      approved with its result; a re-evaluation carrying the approval
//      true, another tuple out_of_scope with a fresh denial, another
//      caller approval_unverifiable; approval.state verifies, and a
//      tampered state or a forged id carrying that state does not; a
//      revocation and approval_expired.
//      The portal lists and revokes an approval the approver gave, mails
//      the requester, and draws Revoke only on that card (#1203); another
//      permitted approver is refused it there (0141), and the built-in
//      policy permits revoke-access-request.
//   H. THE DENIAL BY REFERENCE (#1204): an evaluation_id with expires_at
//      echoed, and no binding_token, is 202; an id this realm did not issue
//      is 0073; a real id with expires_at omitted or changed, or not the
//      token's, is 0074 and is not consumed; another caller is 0074; a
//      token whose binding_hash was changed does not submit, and one that
//      carries only the hash does.
//   C. CANCELLATION, and a finished task 409.
//   X. AN ADMINISTRATOR'S DENIAL through the console's door, as one the
//      advice did not name, holding ADMIN_WRITE.
//   E. EXPIRY by the scheduler job's sweep, and the audit row.
//   M. EMERGENCY ACCESS: refused without a justification, granted at once
//      (201) with one.
//   B. A REGISTERED CALLBACK, an application's or a person's (a person's
//      override refused), retried on the scheduler job, and recorded as
//      callbackDelivery (#1202).
//   G. THE BACKOFF DOUBLES, each attempt carries its code, and a finished
//      task is kept while its callback is still tried, then dropped with
//      the final STS-AUTHZEN-0135 row (#1202's review).
//   L. NO LOST REVOCATION: the delivery's write re-reads the row.
//   F. FAILED: an approval that cannot be stored (0142), and approvers who
//      resolve to nobody (0143); a computed role is never nobody.
//   K. THE DENIAL STORE'S CAP (0144): no record, the token still submits.
//   D. A DELETED SUBJECT (2026-11-16): the person's approval is revoked
//      and their pending request cancelled, so a person made again under
//      the name inherits neither; a task from before the subject index is
//      noted by the sweep job's backfill.
//   Y. DISPLAY (#1204): none by default; on, the denial's display is the
//      service's own words in the asked language, or the advice's
//      display-title and display-description verbatim, and a Task Handle's
//      follows its status; a handle built for a callback carries none.
//   W. THE HOSTED FORM (#1204): no form_url by default; on, a recorded
//      denial names the portal page, only its subject may use it, it is
//      refused emergency access without a justification, the PEP gets the
//      form's task back for the same denial (409 for other augmentations),
//      a Task Handle names links.ticket, the ticket shows only the subject,
//      the page lists their requests and draws a real submit button, and
//      off it is refused 0148.
//   O. OFF: authzen.accessRequests off answers 501, the schema too, and
//      no denial is requestable.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

// An address compared by parsing it, not searched for as text
// (`protocol/url_match.js`).
const urls = require('./protocol/url_match.js');
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
  '        rule displayedWrite {',
  '            deny',
  '            target clause act == "write"',
  '            on deny {',
  '                advice "' + ADVICE + '" {',
  '                    "' + ADVICE + ':approver-group" = "azapprovers"',
  '                    "' + ADVICE + ':display-title" = "Ask your manager"',
  '                    "' + ADVICE + ':display-description" = ' +
  '"Writing doc-1 needs your manager\'s approval."',
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
  const applications = require(ROOT + '/common/applications');
  const fedHttp = require(ROOT + '/federation/federation_http');
  const store = require(ROOT + '/xacml/xacml_store');
  const xml = require(ROOT + '/xacml/xacml_xml');
  const alfa = require(ROOT + '/xacml/xacml_alfa');
  const requests = require(ROOT + '/authzen/authzen_access_request');
  const oauth2 = require(ROOT + '/oauth-oidc/oauth2');
  const authzenAdmin = require(ROOT + '/authzen/authzen_admin');
  const mail = require(ROOT + '/common/mail');
  const ModelZod = require(ROOT + '/common/model_zod');
  const accessPages = require(ROOT + '/portal/web_access_requests');
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
  // azpep2 two PEPs, both in authzen-peps and scoped to todo-app. azapp
  // is an application in that group, the only kind that may register a
  // callback (#1202). An mTLS caller is kind 'entry' named by DN.
  const mint = function (subject) {
    log.debug("Entering mint().");
    log.debug("Leaving mint().");
    return outsideCa.mint({ subject: subject, crlBase: '' });
  };
  const pepCred = await mint('CN=azarqpep,O=Outside');
  const pep2Cred = await mint('CN=azarqpep2,O=Outside');
  const appCred = await mint('CN=azarqapp,O=Outside');
  const added = tls.addAnchors([pepCred, pep2Cred, appCred].map(
    function (one) {
      return one.anchorPem;
    }).join(''));
  t.check(added && added.added === 3,
          'setup: the outside Root CAs are in the client truststore',
          JSON.stringify(added));
  const derOf = function (minted) {
    log.debug("Entering derOf().");
    log.debug("Leaving derOf().");
    return new nodeCrypto.X509Certificate(minted.leaf.pem).raw;
  };
  const pepGroup = String(config.value('roles.authzenPepGroup'));
  inRealm(function () {
    ['azalice', 'azbob', 'azcarol', 'azerin', 'azpep', 'azpep2'].forEach(
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
    const made = applications.createApplication({
      identifier: 'azapp', protocols: ['oauth2'],
      fields: { oauthClientId: 'azapp' } });
    if (!made.ok) {
      throw new Error('azapp was not created: ' + JSON.stringify(made));
    }
    const stored = ldap.changeStoredCertificate('application', 'azapp',
                                                 { add: derOf(appCred) });
    if (!stored.ok) {
      throw new Error('azapp\'s certificate was not stored');
    }
    const appDn = applications.get('azapp').dn;
    const joined = adminActions.groupsAction({
      action: 'add-member', group: pepGroup, member: appDn });
    if (!joined.ok) {
      throw new Error('azapp was not added to ' + pepGroup + ': ' +
                      JSON.stringify(joined));
    }
    const scoped = authzenAdmin.act({ action: 'set-scope', caller: 'azapp',
                                      applications: ['todo-app'] },
                                    { actor: 'azcarol', via: 'api' });
    if (!scoped.ok) {
      throw new Error('azapp was not scoped: ' + JSON.stringify(scoped));
    }
    ldap.createGroup('azapprovers', { members: [] });
    ['azbob', 'azalice', 'azerin'].forEach(function (name) {
      adminActions.groupsAction({ action: 'add-member', group: 'azapprovers',
                                  member: name });
    });
    // A group nobody is in, for F2's approvers who resolve to nobody.
    ldap.createGroup('azempty', { members: [] });
    store.write('azarq-root', xml.writePolicy(alfa.parse(POLICY)),
                { enabled: true, isRoot: true });
  });

  const serverCa = await testCa.makeCa();
  const serverLeaf = await testCa.listenerCertificate(serverCa, '127.0.0.1');
  CA_PEM.value = serverCa.certPem;
  const listener = https.createServer(Object.assign({
    cert: serverLeaf.cert, key: serverLeaf.key,
    ca: tls.clientTruststoreOptions().ca
  }, tls.clientAuthOptions('optional'), tls.protocolOptions()), app);
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
  const hashed = claims ? requests.bindingHash(claims.subject,
    claims.resource, claims.action, claims.context || {}) : '';
  t.check(!!claims && claims.iss === own &&
          urls.holds(claims.aud, ar.endpoint) &&
          claims.resource && claims.resource.id === 'doc-1' &&
          claims.denial_expires_at === ar.expires_at &&
          claims.binding_hash === hashed,
          'R2. the binding_token is the realm\'s JWS over the denied tuple, ' +
          'audienced to the access request endpoint, with binding_hash',
          JSON.stringify(claims));
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
  const schemaUrl = own + '/access/v1/access-requests/schema';
  t.check(ar.request_schema_url === schemaUrl && !ar.form_url,
          'R5. a requestable denial names request_schema_url on the ' +
          'access request endpoint\'s origin, and hosts no form',
          JSON.stringify({ url: ar.request_schema_url, form: ar.form_url }));
  r = await request(port, 'GET',
                    PREFIX + '/access/v1/access-requests/schema', null);
  const schema = r.json || {};
  const props = schema.properties || {};
  const schemaAsked = (props.requested_access || {}).properties || {};
  const schemaCtx = (props.context || {}).properties || {};
  const rule = (schema.allOf || [])[0] || {};
  const emergency = ((((rule.if || {}).properties || {}).requested_access ||
                      {}).properties || {}).emergency || {};
  const thenCtx = (((rule.then || {}).properties || {}).context || {});
  t.check(r.status === 200 &&
          String(r.headers['cache-control'] || '') === 'no-store' &&
          /application\/json/.test(String(r.headers['content-type'] || '')) &&
          schema.$schema === 'https://json-schema.org/draft/2020-12/schema' &&
          schema.$id === schemaUrl &&
          schema.additionalProperties !== false &&
          !schema.required && !(props.context || {}).required &&
          !(props.requested_access || {}).required &&
          schemaCtx.business_justification &&
          schemaCtx.business_justification.maxLength === 1024 &&
          schemaAsked.requested_until && schemaAsked.requested_until.format ===
            'date-time' &&
          schemaAsked.emergency && schemaAsked.emergency.type === 'boolean' &&
          emergency.const === true &&
          Array.isArray(thenCtx.required) &&
          thenCtx.required.indexOf('business_justification') >= 0 &&
          Array.isArray((rule.then || {}).required) &&
          (rule.then || {}).required.indexOf('context') >= 0 &&
          !/form_url/.test(JSON.stringify(schema)),
          'R6. the schema is public JSON Schema of the optional ' +
          'augmentations, and emergency requires a justification',
          brief(r));

  // -------------------------------------------------------------------------
  // S. THE SUBMISSION
  // -------------------------------------------------------------------------
  let since = marks.length;
  // S0 (#936): section 10.1's media type, held here as at the evaluation.
  r = await request(port, 'POST', SUBMIT, pepCred, submission(denied),
                    { 'content-type': 'text/plain' });
  t.check(r.status === 415 &&
          /^application\/problem\+json/.test(
            String(r.headers['content-type'] || '')) &&
          r.json && r.json.status === 415 &&
          r.json.title === 'Unsupported media type' && !r.json.task &&
          markedSince(since, 'STS-AUTHZEN-0122'),
          'S0. a submission sent as text/plain is 415 problem+json ' +
          '(STS-AUTHZEN-0122) and makes no task', brief(r));
  since = marks.length;
  r = await request(port, 'POST', SUBMIT, pepCred,
                    { subject: { type: 'user', id: 'azalice' },
                      action: { name: 'read' },
                      resource: { type: 'document', id: 'doc-1' } },
                    { 'content-type': 'application/json; charset=utf-8' });
  t.check(r.status === 400 && /not_requestable$/.test(problemOf(r)),
          'S0. one sent as application/json with a charset is read',
          brief(r));
  since = marks.length;
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
  t.check(r.status === 400 && markedSince(since, 'STS-AUTHZEN-0079') &&
          !markedSince(since, 'STS-AUTHZEN-0136'),
          'S4. a callback nobody registered for the person is refused ' +
          '(STS-AUTHZEN-0079); a person may register one, as in 1.1.0',
          brief(r));
  const appEval = await request(port, 'POST', EVAL, appCred, evaluation());
  const appDenied = appEval.json || {};
  t.check(appEval.status === 200 && appDenied.decision === false &&
          appDenied.context && appDenied.context.access_request,
          'setup: the application certificate is an AuthZEN caller ' +
          'scoped to todo-app', brief(appEval));
  since = marks.length;
  r = await request(port, 'POST', SUBMIT, appCred, submission(appDenied,
    { callback: { endpoint: 'https://pep.example.com/cb' } }));
  t.check(r.status === 400 && markedSince(since, 'STS-AUTHZEN-0079'),
          'S4b. a callback nobody registered for the application is ' +
          'refused (STS-AUTHZEN-0079)', brief(r));
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
    context: { application: 'todo-app', approval: {
      id: approval.id, approved_until: approval.approved_until } } }));
  t.check(r.status === 200 && r.json && r.json.decision === false &&
          r.json.context.reason === 'out_of_scope' &&
          r.json.context.next_action === 'request' &&
          r.json.context.access_request,
          'A8. another resource, the approval named by id, is ' +
          'out_of_scope, next_action request with a fresh access_request',
          brief(r));
  r = await request(port, 'POST', EVAL, pepCred, evaluation({
    resource: { type: 'document', id: 'doc-9' },
    context: { application: 'todo-app', approval: approval } }));
  t.check(r.status === 200 && r.json && r.json.decision === false &&
          r.json.context.reason === 'out_of_scope' &&
          r.json.context.next_action === 'request' &&
          r.json.context.access_request,
          'A8b. echoing a verified approval.state against another resource ' +
          'is out_of_scope with next_action request, as the id alone is',
          brief(r));
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
  let stateClaims = null;
  try {
    stateClaims = inRealm(function () {
      return helpers.verifyOwnJws(String(approval.state || ''),
                                  { ignoreExpiration: true });
    });
  } catch (e) {
    log.debug("Caught in childBody(): " + ((e && e.message) || e));
    stateClaims = null;
  }
  t.check(!!stateClaims &&
          stateClaims.typ === 'authzen-access-request-approval' &&
          stateClaims.id === approval.id,
          'A6b. the approved task\'s result carries approval.state, this ' +
          'realm\'s JWS of that approval', JSON.stringify(stateClaims));
  r = await request(port, 'POST', EVAL, pepCred, evaluation({
    context: { application: 'todo-app', approval: {
      id: approval.id, state: String(approval.state || '') + 'x' } } }));
  t.check(r.status === 200 && r.json && r.json.decision === false &&
          r.json.context.reason === 'approval_unverifiable',
          'A6c. a tampered approval.state is approval_unverifiable even ' +
          'though the row is live', brief(r));
  r = await request(port, 'POST', EVAL, pepCred, evaluation({
    context: { application: 'todo-app', approval: {
      id: 'apr_forged', state: approval.state } } }));
  t.check(r.status === 200 && r.json && r.json.decision === false &&
          r.json.context.reason === 'approval_unverifiable',
          'A6d. a forged id carrying a real approval.state is ' +
          'approval_unverifiable', brief(r));
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
  const freshApp = async function () {
    log.debug("Entering freshApp().");
    const got = await request(port, 'POST', EVAL, appCred, evaluation());
    log.debug("Leaving freshApp().");
    return got.json;
  };

  // A submission that replaces the denial, so an evaluation_id-only body
  // does not also send the token.
  const byId = async function (one, denial, cred) {
    log.debug("Entering byId().");
    const got = await request(port, 'POST', SUBMIT, cred || pepCred,
                              submission(one, { denial: denial }));
    log.debug("Leaving byId().");
    return got;
  };
  // Re-signs a denial with its inline tuple removed, so binding_hash is
  // the binding. `mutate` changes the claims first.
  const resign = function (token, mutate) {
    log.debug("Entering resign().");
    const signed = inRealm(function () {
      const held = helpers.verifyOwnJws(String(token || ''));
      const exp = Number(held.exp) || 0;
      const copy = Object.assign({}, held);
      ['subject', 'resource', 'action', 'context', 'iss', 'iat', 'exp']
        .forEach(function (name) {
          delete copy[name];
        });
      if (mutate) {
        mutate(copy);
      }
      const now = Math.floor(Date.now() / 1000);
      return oauth2.signPublishedDocument(copy, own,
        Math.max(1, exp - now), 'oauth-signed-metadata');
    });
    log.debug("Leaving resign().");
    return signed;
  };

  // -------------------------------------------------------------------------
  // H. THE DENIAL BY REFERENCE, AND THE HASHED BINDING (#1204)
  // -------------------------------------------------------------------------
  const ref = await fresh();
  const refAr = ref.context.access_request;
  since = marks.length;
  r = await byId(ref, { evaluation_id: ref.context.evaluation_id,
                        expires_at: refAr.expires_at });
  t.check(r.status === 202 && r.json && r.json.task &&
          /^arq_/.test(r.json.task.id),
          'H1. an evaluation_id with expires_at echoed, and no ' +
          'binding_token, is 202', brief(r));
  since = marks.length;
  r = await byId(ref, { evaluation_id: 'eval_never',
                        expires_at: refAr.expires_at });
  t.check(r.status === 400 &&
          /invalid_denial_binding$/.test(problemOf(r)) &&
          markedSince(since, 'STS-AUTHZEN-0073'),
          'H2. an evaluation_id this realm did not issue is ' +
          'invalid_denial_binding (STS-AUTHZEN-0073)', brief(r));
  const echo = await fresh();
  const echoAr = echo.context.access_request;
  since = marks.length;
  r = await byId(echo, { evaluation_id: echo.context.evaluation_id });
  t.check(r.status === 400 && markedSince(since, 'STS-AUTHZEN-0074'),
          'H3. a real evaluation_id with expires_at omitted is ' +
          'invalid_denial_binding and is not consumed', brief(r));
  since = marks.length;
  r = await byId(echo, { evaluation_id: echo.context.evaluation_id,
                         expires_at: '2099-01-01T00:00:00Z' });
  t.check(r.status === 400 && markedSince(since, 'STS-AUTHZEN-0074'),
          'H4. a real evaluation_id with expires_at changed is ' +
          'invalid_denial_binding and is not consumed', brief(r));
  r = await request(port, 'POST', SUBMIT, pepCred, submission(echo));
  t.check(r.status === 202 && r.json && r.json.task,
          'H5. that denial\'s binding_token still submits', brief(r));
  const otherId = await fresh();
  const otherAr = otherId.context.access_request;
  since = marks.length;
  r = await byId(otherId, { binding_token: otherAr.binding_token,
                            expires_at: otherAr.expires_at,
                            evaluation_id: 'eval_other' });
  t.check(r.status === 400 && markedSince(since, 'STS-AUTHZEN-0074'),
          'H6. an evaluation_id that is not the binding_token\'s is ' +
          'invalid_denial_binding and is not consumed', brief(r));
  r = await request(port, 'POST', SUBMIT, pepCred, submission(otherId));
  t.check(r.status === 202,
          'H7. the matching submission of that denial is still 202',
          brief(r));
  const whose = await fresh();
  const whoseAr = whose.context.access_request;
  since = marks.length;
  r = await byId(whose, { evaluation_id: whose.context.evaluation_id,
                          expires_at: whoseAr.expires_at }, pep2Cred);
  t.check(r.status === 400 && markedSince(since, 'STS-AUTHZEN-0074'),
          'H8. another caller submitting the evaluation_id is ' +
          'invalid_denial_binding', brief(r));
  r = await request(port, 'POST', SUBMIT, pepCred, submission(whose));
  t.check(r.status === 202,
          'H9. the caller the denial was issued to still submits it',
          brief(r));
  const hashedDenial = await fresh();
  const hashedAr = hashedDenial.context.access_request;
  since = marks.length;
  const badHash = resign(hashedAr.binding_token, function (copy) {
    copy.binding_hash = 'not-the-hash';
  });
  r = await byId(hashedDenial, {
    binding_token: badHash,
    expires_at: hashedAr.expires_at,
    evaluation_id: hashedDenial.context.evaluation_id });
  t.check(r.status === 400 && markedSince(since, 'STS-AUTHZEN-0074'),
          'H10. a binding_hash that does not match is ' +
          'invalid_denial_binding and is not consumed', brief(r));
  const hashOnly = resign(hashedAr.binding_token);
  r = await byId(hashedDenial, {
    binding_token: hashOnly,
    expires_at: hashedAr.expires_at,
    evaluation_id: hashedDenial.context.evaluation_id });
  t.check(r.status === 202 && r.json && r.json.task,
          'H11. a token that carries binding_hash and no inline tuple ' +
          'submits', brief(r));

  // -------------------------------------------------------------------------
  // A12. THE PORTAL REVOKES AN APPROVAL THE PERSON GAVE (#1203)
  // -------------------------------------------------------------------------
  r = await request(port, 'POST', SUBMIT, pepCred,
                    submission(await fresh()));
  const portalTask = ((r.json || {}).task || {});
  const approved = inRealm(function () {
    return requests.decide(portalTask.id, 'approve',
                           { username: 'azbob', door: 'portal' });
  });
  const portalListed = inRealm(function () {
    const ids = function (rows) {
      log.debug("Entering ids().");
      log.debug("Leaving ids().");
      return rows.map(function (row) {
        return row.id;
      });
    };
    return {
      bob: ids(requests.grantedBy('azbob')),
      carol: ids(requests.grantedBy('azcarol')),
      alice: ids(requests.grantedBy('azalice')),
      waiting: ids(requests.awaiting('azbob'))
    };
  });
  t.check(approved.ok && portalListed.bob.indexOf(portalTask.id) >= 0 &&
          portalListed.carol.indexOf(portalTask.id) < 0 &&
          portalListed.alice.indexOf(portalTask.id) < 0 &&
          portalListed.waiting.indexOf(portalTask.id) < 0,
          'A12. the portal lists a live approval for the person who gave it',
          JSON.stringify(portalListed));
  since = marks.length;
  const carolRefused = inRealm(function () {
    return requests.decide(portalTask.id, 'revoke',
                           { username: 'azcarol', door: 'portal' });
  });
  t.check(!carolRefused.ok && markedSince(since, 'STS-AUTHZEN-0088'),
          'A13. somebody the policy does not let decide cannot revoke',
          JSON.stringify(carolRefused));
  // A13b (#1203's review): azerin is an approver the policy permits, and
  // the approval is azbob's. The portal refuses; the policy alone would
  // not have.
  since = marks.length;
  const erinRefused = inRealm(function () {
    return {
      decided: requests.decide(portalTask.id, 'revoke',
                               { username: 'azerin', door: 'portal' }),
      gate: gate.check({ resource: 'authzen-access-request',
        action: 'revoke-access-request',
        subject: { name: 'azerin', kind: 'user', authenticated: true,
                   roles: [] },
        context: { door: 'portal' },
        accessRequestObject: { id: portalTask.id, requester: 'azpep',
          subject: 'azalice', subjectType: 'user', action: 'read',
          resource: 'doc-1', resourceType: 'document',
          application: 'todo-app', eligible: true, door: 'portal',
          approverIdentity: ['azerin'] } }),
      still: requests.task(portalTask.id).approval.revokedAt
    };
  });
  t.check(!erinRefused.decided.ok &&
          errorCodes.codeOf(erinRefused.decided) === 'STS-AUTHZEN-0141' &&
          erinRefused.gate.allowed === true &&
          erinRefused.gate.decision === 'Permit' && !erinRefused.still,
          'A13b. on the portal another permitted approver cannot revoke ' +
          'an approval they did not give (STS-AUTHZEN-0141); the built-in ' +
          'policy permits revoke-access-request where it permits approval',
          JSON.stringify(erinRefused));
  inRealm(function () {
    ldap.locateEntry('azpep').stored.attributes.mail =
      ['azpep@example.com'];
  });
  const revoked = inRealm(function () {
    return requests.decide(portalTask.id, 'revoke',
                           { username: 'azbob', door: 'portal' });
  });
  const auditHit = inRealm(function () {
    return audit.list().filter(function (row) {
      return row.action === 'authzen.access-request.revoked' &&
        String(row.summary || '').indexOf('via the portal') >= 0 &&
        String(row.summary || '').indexOf(portalTask.id) >= 0;
    }).length;
  });
  r = await request(port, 'POST', EVAL, pepCred, evaluation({
    context: { application: 'todo-app',
               approval: { id: approved.task.approval.id } } }));
  const gone = inRealm(function () {
    return requests.grantedBy('azbob').map(function (row) {
      return row.id;
    });
  });
  const mailed = inRealm(function () {
    return mail.list({ username: 'azpep' }).filter(function (row) {
      return row.template === 'authzen-access-revoked';
    }).length;
  });
  t.check(revoked.ok && revoked.task.status === 'approved' &&
          revoked.task.approval && revoked.task.approval.revoked === true &&
          auditHit >= 1 && gone.indexOf(portalTask.id) < 0 && mailed >= 1 &&
          r.json && r.json.decision === false &&
          r.json.context.reason === 'approval_expired',
          'A14. the approver revokes through the portal, the requester is ' +
          'mailed, and a re-evaluation is approval_expired',
          JSON.stringify(revoked) + ' / ' + brief(r) + ' mail ' + mailed);
  const sample = {
    id: 'tsk_portalrevoke01', application: 'todo-app', requester: 'azpep',
    subject: { type: 'user', id: 'azalice' },
    action: { name: 'read' },
    resource: { type: 'document', id: 'doc-1' },
    expiresAt: 1, approval: { approvedUntil: 2 }
  };
  const fakeT = {
    html: function (key, params) {
      log.debug("Entering html().");
      log.debug("Leaving html().");
      return key + (params && params.when ? ':' + params.when : '');
    },
    date: function (ms) {
      log.debug("Entering date().");
      log.debug("Leaving date().");
      return String(ms);
    }
  };
  const pendingHtml = accessPages.card(sample, fakeT, 'pending');
  const grantedHtml = accessPages.card(sample, fakeT, 'granted');
  t.check(pendingHtml.indexOf('access-request-approve-') >= 0 &&
          pendingHtml.indexOf('access-request-deny-') >= 0 &&
          pendingHtml.indexOf('access-request-revoke-') < 0 &&
          grantedHtml.indexOf('access-request-revoke-') >= 0 &&
          grantedHtml.indexOf('access-request-approve-') < 0 &&
          grantedHtml.indexOf('portalAccessRequests.until') >= 0,
          'A15. the portal draws Revoke only for an approval the person ' +
          'gave', pendingHtml + ' / ' + grantedHtml);
  const parsed = ModelZod.body('account', 'decideAccessRequest').safeParse({
    request: 'tsk_portalrevoke01', action: 'revoke' });
  t.check(parsed.success === true,
          'A16. the account operation accepts revoke',
          JSON.stringify(parsed.error || null));
  const beforeApp = inRealm(function () {
    return mail.list().filter(function (row) {
      return row.template === 'authzen-access-revoked';
    }).length;
  });
  r = await request(port, 'POST', SUBMIT, appCred,
                    submission(await freshApp()));
  const appTask = ((r.json || {}).task || {});
  const appRevoked = inRealm(function () {
    const done = requests.decide(appTask.id, 'approve',
                                 { username: 'azbob', door: 'portal' });
    if (!done.ok) {
      return done;
    }
    return requests.decide(appTask.id, 'revoke',
                           { username: 'azbob', door: 'portal' });
  });
  const afterApp = inRealm(function () {
    return mail.list().filter(function (row) {
      return row.template === 'authzen-access-revoked';
    }).length;
  });
  t.check(appRevoked.ok && appRevoked.task.approval.revoked === true &&
          afterApp === beforeApp,
          'A17. an application requester is not mailed',
          JSON.stringify(appRevoked) + ' mail ' + beforeApp + '->' +
          afterApp);

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
  // B. A REGISTERED CALLBACK (#1202): an application only, retried by the
  // access-request job. A network failure or a 5xx schedules another
  // attempt. A delivery that will not succeed sets
  // callbackDelivery.state to failed. The task status stays what finish()
  // wrote. Development dials 127.0.0.1, so a closed port is a retry.
  // A string detail is stored as the audit row's summary.
  // -------------------------------------------------------------------------
  const CALLBACK = 'https://127.0.0.1:9/azarq-callback';
  const PUBLIC = 'https://pep.example.com/callbacks/access-requests';
  const callbackAudits = function (id) {
    log.debug("Entering callbackAudits().");
    const rows = audit.list().filter(function (row) {
      const text = String(row.summary || '') + ' ' +
                   (typeof row.detail === 'string' ? row.detail
                     : JSON.stringify(row.detail || {}));
      return row.action === 'authzen.access-request.callback' &&
             text.indexOf(id) >= 0;
    });
    log.debug("Leaving callbackAudits().");
    return rows;
  };
  const codesOf = function (rows) {
    log.debug("Entering codesOf().");
    log.debug("Leaving codesOf().");
    return rows.map(function (row) {
      return row.errorCode || '';
    });
  };
  // B0 (the review of #1202): a person's callback is registered and
  // honoured, as in 1.1.0; a retry override is an application's only.
  since = marks.length;
  const personSet = inRealm(function () {
    return authzenAdmin.act({ action: 'set-callbacks', caller: 'azpep',
      callbacks: 'https://pep.example.com/cb' },
      { actor: 'azcarol', via: 'api' });
  });
  const personOverride = inRealm(function () {
    return authzenAdmin.act({ action: 'set-callbacks', caller: 'azpep',
      callbacks: 'https://pep.example.com/cb attempts=2' },
      { actor: 'azcarol', via: 'api' });
  });
  const personStored = inRealm(function () {
    return authzenAdmin.callerOf('azpep');
  });
  r = await request(port, 'POST', SUBMIT, pepCred, submission(await fresh(),
    { callback: { endpoint: 'https://pep.example.com/cb',
                  events: ['cancelled'] } }));
  const personTask = ((r.json || {}).task || {});
  t.check(personSet.ok && !personOverride.ok &&
          errorCodes.codeOf(personOverride) === 'STS-AUTHZEN-0137' &&
          personStored.callbacks.indexOf('https://pep.example.com/cb') >= 0 &&
          r.status === 202 && personTask.id &&
          !markedSince(since, 'STS-AUTHZEN-0136'),
          'B0. set-callbacks registers a person\'s callback, refuses a ' +
          'person\'s override (STS-AUTHZEN-0137), and a submission naming ' +
          'it is accepted',
          JSON.stringify({ set: personSet, override: personOverride,
                           stored: personStored }) + ' / ' + brief(r));
  if (personTask.id) {
    inRealm(function () {
      const row = requests.task(personTask.id);
      if (row) {
        row.callback = null;
      }
      requests.cancelByAdministrator(personTask.id, 'azcarol');
    });
  }
  const set = inRealm(function () {
    return authzenAdmin.act({ action: 'set-callbacks', caller: 'azapp',
                              callbacks: CALLBACK },
                            { actor: 'azcarol', via: 'api' });
  });
  r = await request(port, 'POST', SUBMIT, appCred,
                    submission(await freshApp(),
    { callback: { endpoint: CALLBACK, state: 's-1',
                  events: ['cancelled'] } }));
  const fifth = ((r.json || {}).task || {});
  t.check(set.ok && r.status === 202 && fifth.id,
          'B1. a callback registered for the application is accepted',
          JSON.stringify(set) + ' / ' + brief(r));
  const sent = await inRealm(function () {
    requests.cancelByAdministrator(fifth.id, 'azcarol');
    return requests.notify(requests.task(fifth.id));
  });
  const callbackRows = inRealm(function () {
    return callbackAudits(fifth.id);
  });
  const fifthTask = inRealm(function () {
    return requests.task(fifth.id);
  });
  const refused = (fifthTask.callbackDelivery &&
                   fifthTask.callbackDelivery.attempts[0]) || {};
  t.check(sent === false && fifthTask.status === 'cancelled' &&
          fifthTask.callbackDelivery &&
          fifthTask.callbackDelivery.state === 'pending' &&
          fifthTask.callbackDelivery.attempts.length === 1 &&
          refused.status === 0 &&
          /ECONNREFUSED/.test(String(refused.why)) &&
          fifthTask.callbackDelivery.nextAt > Date.now() / 1000 &&
          fifthTask.callbackDelivery.inflightUntil === 0 &&
          fifthTask.callbackDelivery.bound === 5 &&
          codesOf(callbackRows).indexOf('STS-AUTHZEN-0091') >= 0 &&
          codesOf(callbackRows).indexOf('STS-AUTHZEN-0135') < 0,
          'B2. a refused connection is retried, the task stays ' +
          'cancelled, and the give-up is not audited yet',
          JSON.stringify({ status: fifthTask.status,
                           delivery: fifthTask.callbackDelivery,
                           codes: codesOf(callbackRows) }));
  const overridden = inRealm(function () {
    return authzenAdmin.act({ action: 'set-callbacks', caller: 'azapp',
      callbacks: PUBLIC + ' attempts=2' },
      { actor: 'azcarol', via: 'api' });
  });
  t.check(overridden.ok && overridden.caller &&
          overridden.caller.callbacks.indexOf(PUBLIC) >= 0 &&
          overridden.caller.callbackConfigs.length === 1,
          'B3. a per-callback attempts override is stored for that URL',
          JSON.stringify(overridden));
  const realDeliver = fedHttp.deliverJson;
  fedHttp.deliverJson = function () {
    return Promise.resolve({ ok: false, status: 503, kind: '',
                             why: 'unavailable' });
  };
  r = await request(port, 'POST', SUBMIT, appCred,
                    submission(await freshApp(),
    { callback: { endpoint: PUBLIC, events: ['cancelled'] } }));
  const retryTask = ((r.json || {}).task || {});
  const firstTry = await inRealm(function () {
    requests.cancelByAdministrator(retryTask.id, 'azcarol');
    return requests.notify(requests.task(retryTask.id));
  });
  const pendingDelivery = inRealm(function () {
    const row = requests.task(retryTask.id);
    return { status: row.status, delivery: row.callbackDelivery };
  });
  t.check(r.status === 202 && firstTry === false &&
          pendingDelivery.status === 'cancelled' &&
          pendingDelivery.delivery.state === 'pending' &&
          pendingDelivery.delivery.attempts.length === 1 &&
          pendingDelivery.delivery.bound === 2 &&
          pendingDelivery.delivery.nextAt > Date.now() / 1000,
          'B4. an HTTP 503 is retried: one attempt, the next not yet due, ' +
          'the task still cancelled',
          JSON.stringify(pendingDelivery));
  // sweep() starts notify() and does not await it. The second notify()
  // has to join that same flight before the stub's microtask settles it,
  // so both calls stay in this one turn.
  const retried = await inRealm(function () {
    const row = requests.task(retryTask.id);
    row.callbackDelivery.nextAt = 1;
    row.callbackDelivery.inflightUntil = 0;
    const swept = requests.sweep();
    return requests.notify(row).then(function () {
      const after = requests.task(retryTask.id);
      return { swept: swept, status: after.status,
               delivery: after.callbackDelivery,
               view: requests.viewOf(after) };
    });
  });
  const retryAudits = inRealm(function () {
    return codesOf(callbackAudits(retryTask.id));
  });
  t.check(retried.delivery.state === 'failed' &&
          retried.delivery.attempts.length === 2 &&
          retried.status === 'cancelled' &&
          /1 callback\(s\) retried\./.test(String(retried.swept.summary)) &&
          retryAudits.indexOf('STS-AUTHZEN-0091') >= 0 &&
          retryAudits.indexOf('STS-AUTHZEN-0135') >= 0 &&
          retried.view.callbackDelivery.state === 'failed' &&
          retried.view.callbackDelivery.attempts.length === 2 &&
          retried.view.status === 'cancelled' &&
          !Object.prototype.hasOwnProperty.call(retried.view.callbackDelivery,
                                                 'inflightUntil'),
          'B5. the job retries once the backoff is due, then gives up ' +
          'without failing the task',
          JSON.stringify(retried) + ' / ' + JSON.stringify(retryAudits));
  since = marks.length;
  const badOverride = inRealm(function () {
    return authzenAdmin.act({ action: 'set-callbacks', caller: 'azapp',
      callbacks: PUBLIC + ' attempts=0' },
      { actor: 'azcarol', via: 'api' });
  });
  const still = inRealm(function () {
    return authzenAdmin.callerOf('azapp');
  });
  t.check(!badOverride.ok &&
          errorCodes.codeOf(badOverride) === 'STS-AUTHZEN-0137' &&
          markedSince(since, 'STS-AUTHZEN-0137') &&
          still.callbacks.indexOf(PUBLIC) >= 0,
          'B6. a bad override is refused and the registration stays',
          JSON.stringify(badOverride) + ' / ' + JSON.stringify(still));
  inRealm(function () {
    authzenAdmin.act({ action: 'set-callbacks', caller: 'azapp',
      callbacks: PUBLIC + ' attempts=5' },
      { actor: 'azcarol', via: 'api' });
  });
  fedHttp.deliverJson = function () {
    return Promise.resolve({ ok: false, status: 400, kind: '',
                             why: 'bad request' });
  };
  r = await request(port, 'POST', SUBMIT, appCred,
                    submission(await freshApp(),
    { callback: { endpoint: PUBLIC, events: ['cancelled'] } }));
  const terminal = ((r.json || {}).task || {});
  const gaveUp = await inRealm(function () {
    requests.cancelByAdministrator(terminal.id, 'azcarol');
    return requests.notify(requests.task(terminal.id));
  });
  const terminalRow = inRealm(function () {
    const row = requests.task(terminal.id);
    return { sent: gaveUp, status: row.status,
             delivery: row.callbackDelivery,
             codes: codesOf(callbackAudits(terminal.id)) };
  });
  fedHttp.deliverJson = realDeliver;
  t.check(terminalRow.sent === false &&
          terminalRow.delivery.state === 'failed' &&
          terminalRow.delivery.attempts.length === 1 &&
          terminalRow.delivery.bound === 5 &&
          terminalRow.status === 'cancelled' &&
          terminalRow.codes.indexOf('STS-AUTHZEN-0091') >= 0 &&
          terminalRow.codes.indexOf('STS-AUTHZEN-0135') >= 0,
          'B7. an HTTP 400 is not retried, even with attempts left',
          JSON.stringify(terminalRow));

  // -------------------------------------------------------------------------
  // G. THE BACKOFF GROWS, AND A FINISHED TASK IS KEPT WHILE ITS CALLBACK IS
  // STILL BEING TRIED (#1202's review). Each attempt carries its code.
  // -------------------------------------------------------------------------
  fedHttp.deliverJson = function () {
    return Promise.resolve({ ok: false, status: 503, kind: '',
                             why: 'unavailable' });
  };
  r = await request(port, 'POST', SUBMIT, appCred,
                    submission(await freshApp(),
    { callback: { endpoint: PUBLIC, events: ['cancelled'] } }));
  const heldTask = ((r.json || {}).task || {});
  const firstWait = await inRealm(function () {
    requests.cancelByAdministrator(heldTask.id, 'azcarol');
    return requests.notify(requests.task(heldTask.id)).then(function () {
      const row = requests.task(heldTask.id);
      return Number(row.callbackDelivery.nextAt) -
             Number(row.callbackDelivery.attempts[0].at);
    });
  });
  const secondWait = await inRealm(function () {
    const row = requests.task(heldTask.id);
    row.callbackDelivery.nextAt = 1;
    return requests.notify(row).then(function () {
      const after = requests.task(heldTask.id);
      const last = after.callbackDelivery.attempts[1];
      return { wait: Number(after.callbackDelivery.nextAt) - Number(last.at),
               view: requests.viewOf(after).callbackDelivery };
    });
  });
  t.check(firstWait === 60 && secondWait.wait === 120 &&
          secondWait.view.attempts.length === 2 &&
          secondWait.view.attempts.every(function (one) {
            return one.code === 'STS-AUTHZEN-0091' && one.ok === false &&
                   one.status === 503;
          }),
          'G1. the wait doubles from authzen.callbackBackoffS, and each ' +
          'attempt is drawn with its time, status and code',
          JSON.stringify({ first: firstWait, second: secondWait }));
  const heldNow = inRealm(function () {
    const row = requests.task(heldTask.id);
    row.keepUntil = Math.floor(Date.now() / 1000) - 5;
    row.callbackDelivery.nextAt = Math.floor(Date.now() / 1000) + 3600;
    const swept = requests.sweep();
    return { swept: swept, still: !!requests.task(heldTask.id) };
  });
  t.check(heldNow.still &&
          /kept for a callback still being tried/.test(
            String(heldNow.swept.summary)),
          'G2. a finished task past its retention is kept while its ' +
          'callback has attempts left', JSON.stringify(heldNow));
  const droppedNow = inRealm(function () {
    const row = requests.task(heldTask.id);
    row.keepUntil = Math.floor(Date.now() / 1000) - 10 * 86400;
    requests.sweep();
    return { gone: !requests.task(heldTask.id),
             codes: codesOf(callbackAudits(heldTask.id)),
             last: callbackAudits(heldTask.id).filter(function (one) {
               return /before the task was removed/.test(
                 String(one.summary || ''));
             }).length };
  });
  fedHttp.deliverJson = realDeliver;
  t.check(droppedNow.gone && droppedNow.last === 1 &&
          droppedNow.codes.indexOf('STS-AUTHZEN-0135') >= 0,
          'G3. past the last attempt the bound allows, the row goes and ' +
          'the final STS-AUTHZEN-0135 row is written first',
          JSON.stringify(droppedNow));

  // -------------------------------------------------------------------------
  // L. NO LOST REVOCATION (#1202's review): a revocation written while the
  // callback POST is in flight survives the delivery's own write. A store
  // of this file's own stands in for another process's view of the row.
  // -------------------------------------------------------------------------
  const lostSetup = await request(port, 'POST', SUBMIT, appCred,
    submission(await freshApp(), { callback: { endpoint: PUBLIC,
                                               events: ['approved'] } }));
  const lostId = ((lostSetup.json || {}).task || {}).id;
  let release = null;
  fedHttp.deliverJson = function () {
    return new Promise(function (resolve) {
      release = resolve;
    });
  };
  const lost = await inRealm(async function () {
    // The real store's row sends nothing: only the stand-in's POST flies.
    const live = requests.task(lostId);
    const callback = JSON.parse(JSON.stringify(live.callback));
    live.callback = null;
    const decided = requests.decide(lostId, 'approve',
                                    { username: 'azbob', door: 'portal' });
    const own = {
      tasks: new Map(), index: new Map(), denials: new Map()
    };
    const deps = Object.assign(requests.AccessRequests.defaultDeps(), own);
    const other = new requests.AccessRequests(deps);
    const stored = JSON.parse(JSON.stringify(requests.task(lostId)));
    delete stored.callbackDelivery;
    stored.callback = callback;
    own.tasks.set(lostId, stored);
    const flying = other.notify(own.tasks.get(lostId));
    // Another process revokes, writing its own copy of the row.
    const theirs = JSON.parse(JSON.stringify(own.tasks.get(lostId)));
    theirs.approval.revokedAt = Math.floor(Date.now() / 1000);
    own.tasks.set(lostId, theirs);
    if (release) {
      release({ ok: true, status: 204, kind: '', why: '' });
    }
    const sent = await flying;
    const after = own.tasks.get(lostId);
    return { decided: decided.ok, sent: sent,
             revokedAt: after.approval.revokedAt,
             state: after.callbackDelivery && after.callbackDelivery.state };
  });
  fedHttp.deliverJson = realDeliver;
  t.check(lost.decided && lost.sent === true && lost.revokedAt > 0 &&
          lost.state === 'delivered',
          'L1. the delivery writes only its record onto the row as it is ' +
          'now: a revocation made during the POST is not lost',
          JSON.stringify(lost));

  // -------------------------------------------------------------------------
  // F. FAILED (#1202): an approval that cannot be stored, and approvers who
  // resolve to nobody, each move the task to failed with its audit row.
  // -------------------------------------------------------------------------
  r = await request(port, 'POST', SUBMIT, pepCred, submission(await fresh()));
  const unstorable = ((r.json || {}).task || {});
  const failedAudits = function (id, code) {
    log.debug("Entering failedAudits().");
    log.debug("Leaving failedAudits().");
    return audit.list().filter(function (row) {
      return row.action === 'authzen.access-request.failed' &&
        row.errorCode === code &&
        String(row.summary || '').indexOf(id) >= 0;
    }).length;
  };
  const f1 = inRealm(function () {
    const deps = requests.AccessRequests.defaultDeps();
    const real = deps.index;
    deps.index = {
      get: function (key) {
        return real.get(key);
      },
      set: function (key, value) {
        if (String(key).indexOf('approval:') === 0) {
          throw new Error('the store refused the write');
        }
        return real.set(key, value);
      },
      delete: function (key) {
        return real.delete(key);
      },
      forEach: function (fn) {
        return real.forEach(fn);
      }
    };
    const other = new requests.AccessRequests(deps);
    const out = other.decide(unstorable.id, 'approve',
                             { username: 'azbob', door: 'portal' });
    return { out: out, row: requests.task(unstorable.id),
             audited: failedAudits(unstorable.id, 'STS-AUTHZEN-0142') };
  });
  t.check(!f1.out.ok && errorCodes.codeOf(f1.out) === 'STS-AUTHZEN-0142' &&
          f1.row.status === 'failed' && !f1.row.approval &&
          f1.audited === 1,
          'F1. an approval that cannot be stored fails the task ' +
          '(STS-AUTHZEN-0142), with one audit row',
          JSON.stringify({ out: f1.out, status: f1.row.status,
                           audited: f1.audited }));
  r = await request(port, 'POST', SUBMIT, pepCred, submission(await fresh()));
  const nobody = ((r.json || {}).task || {});
  r = await request(port, 'POST', SUBMIT, pepCred, submission(await fresh()));
  const computed = ((r.json || {}).task || {});
  const f2 = inRealm(function () {
    const a = requests.task(nobody.id);
    a.terms = Object.assign({}, a.terms, { roles: [], groups: ['azempty'],
                                           owners: false });
    const b = requests.task(computed.id);
    b.terms = Object.assign({}, b.terms, { roles: ['EVERYBODY'],
                                           groups: [], owners: false });
    const swept = requests.sweep();
    return { swept: swept, a: requests.task(nobody.id).status,
             b: requests.task(computed.id).status,
             audited: failedAudits(nobody.id, 'STS-AUTHZEN-0143') };
  });
  t.check(f2.a === 'failed' && f2.b === 'pending' && f2.audited === 1 &&
          /access request\(s\) failed/.test(String(f2.swept.summary)),
          'F2. the job fails a request whose approvers resolve to nobody ' +
          '(STS-AUTHZEN-0143); a computed role is never taken for nobody',
          JSON.stringify(f2));
  inRealm(function () {
    requests.cancelByAdministrator(computed.id, 'azcarol');
  });

  // -------------------------------------------------------------------------
  // K. THE DENIAL STORE'S CAP (#1204's review), at the insert.
  // -------------------------------------------------------------------------
  inRealm(function () {
    config.setOverride('authzen.accessRequestMaxDenials', 1);
  });
  const capped = await fresh();
  since = marks.length;
  r = await byId(capped, { evaluation_id: capped.context.evaluation_id,
                           expires_at: capped.context.access_request
                             .expires_at });
  const fullRows = inRealm(function () {
    config.clearOverride('authzen.accessRequestMaxDenials');
    return audit.list().filter(function (row) {
      return row.action === 'authzen.access-request.denials-full' &&
             row.errorCode === 'STS-AUTHZEN-0144';
    }).length;
  });
  const tokenStill = await request(port, 'POST', SUBMIT, pepCred,
                                   submission(capped));
  t.check(r.status === 400 && markedSince(since, 'STS-AUTHZEN-0073') &&
          fullRows === 1 && tokenStill.status === 202,
          'K1. a full denial store records no new denial (audited once, ' +
          'STS-AUTHZEN-0144); its binding_token still submits',
          brief(r) + ' rows ' + fullRows + ' / ' + brief(tokenStill));

  // -------------------------------------------------------------------------
  // D. A DELETED SUBJECT (2026-11-16, #1612's rule: a person deleted and
  // made again under the same name inherits nothing)
  // -------------------------------------------------------------------------
  r = await request(port, 'POST', SUBMIT, pepCred,
                    submission(await fresh()));
  const sixth = ((r.json || {}).task || {});
  inRealm(function () {
    return requests.decide(sixth.id, 'approve',
                           { username: 'azbob', door: 'portal' });
  });
  r = await request(port, 'GET', pathOf(sixth.status_endpoint), pepCred);
  const kept = ((r.json || {}).result || {}).approval || {};
  r = await request(port, 'POST', SUBMIT, pepCred,
                    submission(await fresh()));
  const seventh = ((r.json || {}).task || {});
  // A task written before the subject index existed: its row removed, and
  // the sweep job's backfill notes it again.
  const deniedDave = await request(port, 'POST', EVAL, pepCred, evaluation({
    subject: { type: 'user', id: 'azdave' } }));
  r = await request(port, 'POST', SUBMIT, pepCred, submission(
    deniedDave.json, { subject: { type: 'user', id: 'azdave' } }));
  const eighth = ((r.json || {}).task || {});
  const subjectIndex = requests.AccessRequests.defaultDeps().index;
  const daveKey = 'subject:' +
    require(ROOT + '/common/crypto').credentialDigest('azdave');
  const backfilled = inRealm(function () {
    ldap.createUser('azdave', { invent: false });
    const had = !!subjectIndex.get(daveKey);
    subjectIndex.delete(daveKey);
    requests.sweep();
    return { had: had, now: !!subjectIndex.get(daveKey) };
  });
  r = await request(port, 'POST', EVAL, pepCred, evaluation({
    context: { application: 'todo-app', approval: kept } }));
  const before = r.json || {};
  const remade = inRealm(function () {
    const alice = ldap.deletePerson(ldap.locateEntry('azalice').stored.dn);
    const dave = ldap.deletePerson(ldap.locateEntry('azdave').stored.dn);
    ldap.createUser('azalice', { invent: false });
    ldap.createUser('azdave', { invent: false });
    return { alice: alice.ok, dave: dave.ok,
             seventh: requests.task(seventh.id).status,
             eighth: requests.task(eighth.id).status,
             revoked: !!requests.task(sixth.id).approval.revokedAt };
  });
  r = await request(port, 'POST', EVAL, pepCred, evaluation({
    context: { application: 'todo-app', approval: kept } }));
  t.check(before.decision === true && remade.alice && remade.revoked &&
          r.json && r.json.decision === false &&
          r.json.context.reason === 'approval_expired',
          'D1. a deleted person\'s approval is revoked with them: the ' +
          'person made again under the name, presented it by the PEP, is ' +
          'not approved', JSON.stringify(remade) + ' / ' + brief(r));
  t.check(remade.seventh === 'cancelled',
          'D2. and their pending request is cancelled',
          JSON.stringify(remade));
  t.check(backfilled.had && backfilled.now && remade.dave &&
          remade.eighth === 'cancelled',
          'D3. a task the subject index never noted (one from before it) ' +
          'is noted by the sweep job, and ended by the delete',
          JSON.stringify({ backfilled: backfilled, remade: remade }));

  // -------------------------------------------------------------------------
  // Y. DISPLAY (#1204): off by default; on, the denial's hints are the
  // advice's own words or the service's in the asked language, and the
  // task's follow its status. A callback's handle carries none.
  // -------------------------------------------------------------------------
  r = await request(port, 'POST', EVAL, pepCred, evaluation());
  const plainAr = ((r.json || {}).context || {}).access_request || {};
  t.check(r.status === 200 && plainAr.binding_token && !plainAr.display,
          'Y1. by default a requestable denial carries no display',
          brief(r));
  r = await request(port, 'POST', SUBMIT, pepCred,
                    submission(r.json || { context: { access_request: {} } }));
  const plainTask = (r.json || {}).task || {};
  t.check((r.status === 202 || r.status === 201) && plainTask.id &&
          !plainTask.display,
          'Y2. and its Task Handle none', brief(r));
  inRealm(function () {
    config.setOverride('authzen.accessRequestDisplay', true);
  });
  r = await request(port, 'POST', EVAL, pepCred, evaluation());
  const shownDenied = r.json || {};
  const shown = ((shownDenied.context || {}).access_request || {}).display ||
    {};
  t.check(r.status === 200 && shown.title === 'Request access' &&
          /can be requested/.test(String(shown.description || '')) &&
          Object.keys(shown).sort().join(',') === 'description,title',
          'Y3. on, the denial carries the service\'s own display in English',
          brief(r));
  r = await request(port, 'POST', EVAL, pepCred, evaluation(), {
    'accept-language': 'fr-CA, en;q=0.5' });
  const french = (((r.json || {}).context || {}).access_request || {})
    .display || {};
  t.check(r.status === 200 && french.title === 'Demander l\u2019accès',
          'Y4. in the language Accept-Language asks for', brief(r));
  r = await request(port, 'POST', EVAL, pepCred,
                    evaluation({ action: { name: 'write' } }),
                    { 'accept-language': 'fr' });
  const advised = (((r.json || {}).context || {}).access_request || {})
    .display || {};
  t.check(r.status === 200 && advised.title === 'Ask your manager' &&
          advised.description ===
            'Writing doc-1 needs your manager\'s approval.',
          'Y5. the advice\'s display-title and display-description are ' +
          'sent verbatim, never translated', brief(r));
  r = await request(port, 'POST', SUBMIT, pepCred, submission(shownDenied),
                    { 'accept-language': 'de' });
  const shownTask = (r.json || {}).task || {};
  t.check(r.status === 202 && shownTask.display &&
          shownTask.display.title === 'Zugriffsanfrage gesendet' &&
          !/azbob|azapprovers|azarq-root/.test(JSON.stringify(
            shownTask.display)),
          'Y6. a pending Task Handle\'s display is its status\'s, in the ' +
          'caller\'s language, naming no approver, group or policy',
          brief(r));
  r = await request(port, 'POST', PREFIX + '/access/v1/access-requests/' +
                    shownTask.id + '/cancel', pepCred, {});
  const cancelledTask = (r.json || {}).task || {};
  t.check(r.status === 200 && cancelledTask.status === 'cancelled' &&
          (cancelledTask.display || {}).title === 'Access request cancelled',
          'Y7. and follows the status once it finishes', brief(r));
  const callbackHandle = inRealm(function () {
    return requests.handleOf(requests.task(String(shownTask.id)));
  });
  t.check(callbackHandle && callbackHandle.id === shownTask.id &&
          !callbackHandle.display,
          'Y8. a handle built for nobody\'s language, as a callback\'s is, ' +
          'carries no display', JSON.stringify(callbackHandle));
  inRealm(function () {
    config.clearOverride('authzen.accessRequestDisplay');
  });

  // -------------------------------------------------------------------------
  // W. THE HOSTED FORM AND THE TICKET (#1204): off by default; on, a
  // recorded denial names form_url on the portal, its subject (and only
  // its subject) submits it there, the PEP gets that task back for the same
  // denial, and a Task Handle names links.ticket.
  // -------------------------------------------------------------------------
  const formPages = require(ROOT + '/portal/web_access_request');
  const portalForm = require(ROOT + '/portal/portal_access_request');
  r = await request(port, 'POST', EVAL, pepCred, evaluation());
  t.check(r.status === 200 &&
          !(((r.json || {}).context || {}).access_request || {}).form_url,
          'W1. by default a requestable denial carries no form_url',
          brief(r));
  inRealm(function () {
    config.setOverride('authzen.accessRequestForm', true);
  });
  r = await request(port, 'POST', EVAL, pepCred, evaluation());
  const formDenied = r.json || {};
  const formEval = String((formDenied.context || {}).evaluation_id || '');
  const formAr = (formDenied.context || {}).access_request || {};
  t.check(r.status === 200 && formEval &&
          formAr.form_url === own + '/portal/access-request?evaluation_id=' +
            encodeURIComponent(formEval),
          'W2. on, a recorded denial names form_url, the portal page on the ' +
          'access request endpoint\'s origin', brief(r));
  const formAs = function (who, asked) {
    log.debug("Entering formAs().");
    log.debug("Leaving formAs().");
    return inRealm(function () {
      return requests.formView(who, asked);
    });
  };
  const submitAs = function (who, given) {
    log.debug("Entering submitAs().");
    log.debug("Leaving submitAs().");
    return inRealm(function () {
      return requests.submitByForm(who, given);
    });
  };
  let fv = formAs('azcarol', { evaluationId: formEval });
  t.check(fv.refusal && fv.refusal.code === 'STS-AUTHZEN-0146' &&
          fv.refusal.status === 404 && !fv.view.request,
          'W3. somebody who is not the denial\'s subject is refused 0146 ' +
          'and shown nothing of it', JSON.stringify(fv));
  fv = formAs('azalice', { evaluationId: 'eval_nosuchdenial' });
  t.check(fv.refusal && fv.refusal.code === 'STS-AUTHZEN-0145',
          'W4. an evaluation_id this realm did not record is 0145',
          JSON.stringify(fv));
  fv = formAs('azalice', { evaluationId: formEval });
  const formReq = (fv.view || {}).request || {};
  t.check(!fv.refusal && fv.view.mode === 'denial' &&
          formReq.application === 'todo-app' && formReq.emergency === true &&
          (formReq.resource || {}).id === 'doc-1' && formReq.expiresAt > 0 &&
          !/azapprovers|azbob/.test(JSON.stringify(fv)),
          'W5. the subject is shown what the denial asks, never who ' +
          'approves', JSON.stringify(fv));
  let sub = submitAs('azalice', { evaluationId: formEval,
                                  justification: '', emergency: true });
  t.check(!sub.ok && sub.code === 'STS-AUTHZEN-0083',
          'W6. emergency access without a justification is refused, as on ' +
          'a PEP\'s submission', JSON.stringify(sub));
  sub = submitAs('azalice', { evaluationId: formEval,
                              justification: 'Quarterly report',
                              durationS: 3600, emergency: false });
  const formTask = (sub.task || {});
  t.check(sub.ok && formTask.status === 'pending' &&
          formTask.origin === 'form' &&
          formTask.formSubmittedBy === 'azalice' &&
          formTask.justification === 'Quarterly report' &&
          formTask.evaluationId === formEval,
          'W7. the subject submits the denial\'s access request on the form',
          JSON.stringify(sub && { ok: sub.ok, code: sub.code,
                                  error: sub.error,
                                  status: formTask.status }));
  r = await request(port, 'POST', SUBMIT, pepCred, submission(formDenied));
  const pepGot = (r.json || {}).task || {};
  t.check(r.status === 202 && pepGot.id === formTask.id &&
          formTask.requester && inRealm(function () {
            return requests.task(formTask.id).requester;
          }) === formTask.requester,
          'W8. the PEP that was denied gets the form\'s task back when it ' +
          'submits the same denial', brief(r));
  r = await request(port, 'POST', SUBMIT, pepCred, submission(formDenied, {
    context: { application: 'todo-app',
               business_justification: 'Something else' } }));
  t.check(r.status === 409 && problemOf(r) ===
            'urn:openid:authzen:access-request:error:duplicate_request',
          'W9. and duplicate_request when it asks for something else',
          brief(r));
  r = await request(port, 'GET', SUBMIT + '/' + formTask.id, pepCred);
  const ticketed = ((r.json || {}).task || {}).links || {};
  t.check(r.status === 200 && ticketed.ticket === own +
            '/portal/access-request?request=' + formTask.id &&
          ticketed.cancel,
          'W10. a Task Handle names links.ticket while the form is on',
          brief(r));
  fv = formAs('azalice', { request: formTask.id });
  const fvOther = formAs('azcarol', { request: formTask.id });
  t.check(!fv.refusal && fv.view.mode === 'task' &&
          fv.view.task.id === formTask.id && fv.view.task.origin === 'form' &&
          fvOther.refusal && fvOther.refusal.code === 'STS-AUTHZEN-0146',
          'W11. the ticket shows the subject the request, and nobody else',
          JSON.stringify(fv) + ' / ' + JSON.stringify(fvOther));
  fv = formAs('azalice', {});
  const again2 = formAs('azalice', { evaluationId: formEval });
  t.check(!fv.refusal && fv.view.mode === 'mine' &&
          (fv.view.mine || []).some(function (row) {
            return row.id === formTask.id;
          }) && again2.view && again2.view.mode === 'task' &&
          again2.view.task.id === formTask.id,
          'W12. the page lists the requests about the person, and a denial ' +
          'already requested shows its request', JSON.stringify(fv));
  sub = submitAs('azalice', { evaluationId: formEval, justification: 'x' });
  t.check(!sub.ok && sub.code === 'STS-AUTHZEN-0076',
          'W13. a denial already requested cannot be requested again',
          JSON.stringify(sub));
  const formHtml = formPages.render({ enabled: true, mode: 'denial',
    request: Object.assign({}, formReq,
                           { display: { title: 'Ask your <manager>' } }) },
    { t: fakeT });
  const ticketHtml = formPages.render(Object.assign({}, fv.view,
    { mode: 'task', task: fv.view.mine[0] }), { t: fakeT });
  t.check(formHtml.indexOf('access-request-submit') >= 0 &&
          formHtml.indexOf('name="evaluation_id"') >= 0 &&
          formHtml.indexOf('access-request-emergency') >= 0 &&
          formHtml.indexOf('Ask your &lt;manager&gt;') >= 0 &&
          ticketHtml.indexOf('access-request-status') >= 0 &&
          ticketHtml.indexOf('access-request-submit') < 0,
          'W14. the page draws the form with a real submit button, the ' +
          'policy\'s words escaped, and the ticket without one',
          formHtml.slice(0, 300));
  const formBody = ModelZod.body('account', 'submitAccessRequestForm')
    .safeParse({ evaluation_id: formEval, business_justification: 'why',
                 duration: '3600', emergency: 'true' });
  const formQuery = ModelZod.query('account', 'getAccessRequestForm')
    .safeParse({ evaluation_id: 'eval_<script>' });
  t.check(formBody.success && !formQuery.success &&
          typeof portalForm.accountOperations === 'function',
          'W15. the account API reads the form\'s fields and refuses a ' +
          'query that is not an id', JSON.stringify(formQuery.error || ''));
  inRealm(function () {
    config.setOverride('authzen.accessRequestForm', false);
  });
  sub = submitAs('azalice', { evaluationId: formEval, justification: 'x' });
  fv = formAs('azalice', {});
  r = await request(port, 'GET', SUBMIT + '/' + formTask.id, pepCred);
  t.check(!sub.ok && sub.code === 'STS-AUTHZEN-0148' &&
          fv.view.enabled === false &&
          !(((r.json || {}).task || {}).links || {}).ticket,
          'W16. off, the form is refused 0148 and no handle names a ticket',
          JSON.stringify(sub) + ' / ' + brief(r));
  inRealm(function () {
    config.clearOverride('authzen.accessRequestForm');
  });

  // -------------------------------------------------------------------------
  // O. OFF
  // -------------------------------------------------------------------------
  inRealm(function () {
    config.setOverride('authzen.accessRequests', false);
  });
  since = marks.length;
  r = await request(port, 'POST', SUBMIT, pepCred, {});
  const offSchema = await request(port, 'GET',
    PREFIX + '/access/v1/access-requests/schema', null);
  const offDenial = await request(port, 'POST', EVAL, pepCred, evaluation());
  inRealm(function () {
    config.setOverride('authzen.accessRequests', true);
  });
  t.check(r.status === 501 && markedSince(since, 'STS-AUTHZEN-0070') &&
          offDenial.json && offDenial.json.decision === false &&
          !(offDenial.json.context && offDenial.json.context.access_request),
          'O1. off, the endpoint answers 501 and no denial is requestable',
          brief(r) + ' / ' + brief(offDenial));
  t.check(offSchema.status === 501 &&
          markedSince(since, 'STS-AUTHZEN-0070') &&
          /problem\+json/.test(String(offSchema.headers['content-type'] || '')),
          'O2. off, the submission schema answers 501', brief(offSchema));

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
