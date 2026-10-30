// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: fga_issuance.js
//
// ===========================================================================
// FINE-GRAINED AUTHORIZATION AT ISSUANCE (#564, phase P3).
//
// An RFC 9396 detail whose type belongs to an application that ENFORCES
// fine-grained authorization is granted only when that application's own
// policy permits it (`common/fga_gate.ts`, `xacml/fga_pep.ts`). What this
// file holds, each a numbered section below:
//
//   1. THE GATE, in process: with no decider an enforcing application's
//      detail is a FAILURE (STS-FGA-0016), never a permit; a decider that
//      throws or answers nothing is a failure (0015); a refusal without a
//      code is given one.
//   2. THE PEP, in process, over stubbed dependencies: a resolve failure is
//      a failure under ITS code; a detail the mapping refuses is a denial; a
//      Permit permits; Deny and NotApplicable deny (0014); an Indeterminate
//      through a processing error is a failure (0015); a throw is a failure,
//      audited; the audit row carries digests and never a detail value; a
//      decision the PDP reached is counted on the monitor's `fga` row.
//   3. THE ENDPOINTS, in a child process, in a THROWAWAY REALM: FGA off
//      changes nothing; enabling is refused for an uncovered type; FGA on
//      with the default policy permits; a policy denying `delete` refuses at
//      the authorization endpoint BEFORE consent (access_denied, prompt=none
//      too), at the PAR endpoint and at the token endpoint
//      (invalid_authorization_details); a refresh after the policy changes
//      is decided against the new one; a disabled or missing policy is
//      server_error, never a permit; the token exchange's bound; a type
//      write left uncovered on an enforcing application is refused; and the
//      audit rows carry no detail value.
//
// **THE CHILD** is `tests/rfc9396_authorization_details.js`'s reason: the
// protocol stack registers every route on the shared app and builds a CA.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'fga_issuance',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// 1. THE GATE.
// ---------------------------------------------------------------------------
function theGate(t) {
  log.debug("Entering theGate().");
  t.log.info('=== 1. the gate refuses without a decider ===');
  const gate = require('../common/fga_gate');
  const before = gate.deciderInstalled();
  const asked = { application: 'docs', detail: { type: 't' },
                  definition: { type: 't' }, stage: 'token' };
  try {
    gate.setDecider(null);
    const none = gate.decide(asked);
    t.check(none.outcome === 'failure' && none.code === 'STS-FGA-0016',
            '1a. with no decider an enforcing application\'s detail is a ' +
            'FAILURE (STS-FGA-0016), never a permit', JSON.stringify(none));
    gate.setDecider(function () {
      throw new Error('boom');
    });
    const threw = gate.decide(asked);
    t.check(threw.outcome === 'failure' && threw.code === 'STS-FGA-0015',
            '1b. a decider that throws is a failure (STS-FGA-0015)',
            JSON.stringify(threw));
    gate.setDecider(function () {
      return { outcome: 'maybe' };
    });
    t.equal(gate.decide(asked).code, 'STS-FGA-0015',
            '1c. an answer with no known outcome is a failure');
    gate.setDecider(function () {
      return { outcome: 'deny' };
    });
    t.equal(gate.decide(asked).code, 'STS-FGA-0014',
            '1d. a denial that names no code is given the denial\'s');
    t.equal(gate.setDecider('not a function'), false,
            '1e. a decider that is not a function is refused');
  } finally {
    gate.setDecider(before);
  }
  log.debug("Leaving theGate().");
}

// ---------------------------------------------------------------------------
// 2. THE PEP, OVER STUBS.
// ---------------------------------------------------------------------------
function thePep(t) {
  log.debug("Entering thePep().");
  t.log.info('=== 2. the embedded FGA PEP ===');
  const errorCodes = require('../common/error_codes');
  const crypto = require('../common/crypto');
  const mapping = require('../xacml/fga_map');
  const applications = require('../common/applications');
  const FgaPep = require('../xacml/fga_pep').FgaPep;
  const definition = applications.authorizationDetailsTypeOf(JSON.stringify({
    type: 'document_access',
    schema: { type: 'object', additionalProperties: false,
              properties: { type: { const: 'document_access' },
                            actions: { type: 'array',
                                       items: { type: 'string' } },
                            identifier: { type: 'string' },
                            note: { type: 'string' } } },
    notForPolicy: ['note'] }));
  const detail = { type: 'document_access', actions: ['read'],
                   identifier: 'doc-sentinel-4711', note: 'sentinel-note' };
  const rows = [];
  const counted = [];
  let resolved = null;
  let decided = null;
  let throwOnDecide = false;
  const pep = new FgaPep({
    log: log,
    errorCodes: errorCodes,
    audit: { audit: function (row) { rows.push(row); return row; } },
    policies: { resolve: function () { return resolved; } },
    map: mapping,
    gate: { setDecider: function () { return true; } },
    sha256Hex: function (text) {
      return crypto.digest('sha256', text, 'hex');
    },
    loadXacml: function () {
      return {
        decidePolicy: function () {
          if (throwOnDecide) {
            throw new Error('the engine broke');
          }
          return decided;
        },
        enforce: function (answer) {
          const undischargeable = (answer.obligations || []).map(
            function (one) { return one.id; });
          return { allowed: answer.decision === 'Permit' &&
                            !undischargeable.length,
                   why: 'stub', undischargeable: undischargeable };
        }
      };
    },
    loadMonitor: function () {
      return { record: function (id, outcome) {
        counted.push([id, outcome]);
      } };
    }
  });
  const ask = function () {
    return pep.decide({ application: 'docs', detail: detail,
      definition: definition, stage: 'token', clientId: 'cli',
      subject: { id: 'alice', kind: 'user' }, grantType: 'client' });
  };
  const ok = { ok: true, policy: 'fga-docs', parsed: {},
               row: { name: 'fga-docs', id: 'urn:sts:xacml:fga:docs',
                      version: '1.0' } };

  resolved = errorCodes.mark({ ok: false, why: 'disabled' }, 'STS-FGA-0006');
  let a = ask();
  t.check(a.outcome === 'failure' && a.code === 'STS-FGA-0006' &&
          counted.length === 0,
          '2a. a policy that cannot be resolved is a FAILURE under its own ' +
          'code, and no PDP decision is counted', JSON.stringify(a));
  resolved = errorCodes.mark({ ok: false, why: 'unparseable' },
                             'STS-FGA-0007');
  t.equal(ask().code, 'STS-FGA-0007',
          '2b. one that does not parse, under 0007');

  resolved = ok;
  decided = { decision: 'Permit', obligations: [] };
  a = ask();
  t.check(a.outcome === 'permit' && a.policyId === 'urn:sts:xacml:fga:docs' &&
          a.version === '1.0' && counted.length === 1 &&
          counted[0][0] === 'fga' && counted[0][1].allowed === true,
          '2c. a Permit permits, and is counted on the fga row as allowed',
          JSON.stringify(a));
  decided = { decision: 'Deny', obligations: [] };
  t.check(ask().outcome === 'deny' && ask().code === 'STS-FGA-0014',
          '2d. a Deny is a DENIAL, STS-FGA-0014');
  decided = { decision: 'NotApplicable', obligations: [] };
  t.equal(ask().outcome, 'deny', '2e. NotApplicable is a denial');
  decided = { decision: 'Indeterminate', obligations: [],
              status: { code: 'urn:oasis:names:tc:xacml:1.0:status:' +
                              'missing-attribute' } };
  t.equal(ask().outcome, 'deny',
          '2f. an Indeterminate over a missing attribute is a denial');
  decided = { decision: 'Permit',
              obligations: [{ id: 'urn:example:obligation:notify' }] };
  t.equal(ask().outcome, 'deny',
          '2g. a Permit with an obligation this PEP cannot discharge is a ' +
          'denial');
  decided = { decision: 'Indeterminate', obligations: [],
              status: { code: 'urn:oasis:names:tc:xacml:1.0:status:' +
                              'processing-error' } };
  a = ask();
  t.check(a.outcome === 'failure' && a.code === 'STS-FGA-0015',
          '2h. an Indeterminate through a processing error is a FAULT, ' +
          'STS-FGA-0015', JSON.stringify(a));
  throwOnDecide = true;
  const auditedBefore = rows.length;
  a = ask();
  t.check(a.outcome === 'failure' && a.code === 'STS-FGA-0015' &&
          rows.length === auditedBefore + 1,
          '2i. an engine that throws is a failure, and is still audited',
          JSON.stringify(a));
  throwOnDecide = false;

  const unmapped = Object.assign({}, detail, { stranger: 'x' });
  decided = { decision: 'Permit', obligations: [] };
  a = pep.decide({ application: 'docs', detail: unmapped,
    definition: definition, stage: 'token', subject: {} });
  t.check(a.outcome === 'deny' && a.code === 'STS-FGA-0103',
          '2j. a member the type does not cover is a DENIAL under the ' +
          'mapping\'s code, never an attribute', JSON.stringify(a));

  const text = JSON.stringify(rows);
  const last = rows[2] || {};
  t.check(rows.every(function (row) {
    return row.action === 'fga.decision';
  }) && text.indexOf('sentinel') < 0 &&
          /^[0-9a-f]{64}$/.test(String((last.detail || {}).detailDigest)) &&
          /^[0-9a-f]{64}$/.test(String((last.detail || {})
            .definitionDigest)) &&
          last.detail.policyId === 'urn:sts:xacml:fga:docs' &&
          last.detail.policyVersion === '1.0' &&
          last.detail.subject === 'alice' && last.detail.client === 'cli' &&
          last.detail.stage === 'token' && last.detail.type ===
            'document_access',
          '2k. one fga.decision row per decision: application, policy, ' +
          'version, type, both digests, subject, client, stage — and no ' +
          'detail value anywhere in it', JSON.stringify(last));
  t.equal(pep.detailDigest({ b: 1, a: [2, { d: 3, c: 4 }] }),
          pep.detailDigest({ a: [2, { c: 4, d: 3 }], b: 1 }),
          '2l. the detail digest is of canonical JSON: member order does ' +
          'not change it');
  log.debug("Leaving thePep().");
}

// ---------------------------------------------------------------------------
// 3. THE ENDPOINTS, IN A CHILD.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.FGAI_ROOT;
  const OUT = process.env.FGAI_OUT;
  const http = require('http');
  const crypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const payloadOf = function (jwt) {
    try {
      return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url')
        .toString('utf8'));
    } catch (e) {
      return { parseError: e.message };
    }
  };

  let jar = {};
  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      const body = o.form ? new URLSearchParams(o.form).toString() : '';
      const headers = Object.assign({}, o.headers || {});
      if (o.cookies && Object.keys(jar).length) {
        headers.cookie = Object.keys(jar).map(function (k) {
          return k + '=' + jar[k];
        }).join('; ');
      }
      if (method !== 'GET') {
        headers['content-type'] = 'application/x-www-form-urlencoded';
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let text = '';
        (res.headers['set-cookie'] || []).forEach(function (line) {
          const pair = line.split(';')[0];
          const eq = pair.indexOf('=');
          jar[pair.slice(0, eq)] = pair.slice(eq + 1);
        });
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let parsed = null;
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            parsed = { parseError: e.message };
          }
          resolve({ status: res.statusCode, headers: res.headers, text: text,
                    json: parsed });
        });
      });
      req.end(body);
    });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const screen = require(ROOT + '/tests/tools/authn_screen');
    const applications = require(ROOT + '/common/applications');
    const realms = require(ROOT + '/common/realms');
    const audit = require(ROOT + '/common/audit');
    const store = require(ROOT + '/xacml/xacml_store');
    const alfa = require(ROOT + '/xacml/xacml_alfa');
    const xml = require(ROOT + '/xacml/xacml_xml');
    const fga = require(ROOT + '/xacml/fga_policies');
    const monitor = require(ROOT + '/xacml/xacml_monitor');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const SECRET = 'fgai-client-secret-0123456789abcdef0123456789';
    const REDIRECT = 'https://rp.fgai.example/cb';
    const BASIC = 'Basic ' + Buffer.from('fgai:' + SECRET).toString('base64');
    const REALM = 'fgai' + crypto.randomBytes(3).toString('hex');
    const PREFIX = '/realm/' + REALM;
    const made = realms.create({ id: REALM, name: REALM,
                                 description: 'fga_issuance.js' });
    note(made.ok, '3a. a throwaway trust realm',
         JSON.stringify(made.errors || ''));
    const inRealm = function (fn) {
      return realms.run(made.realm, fn);
    };

    // THE ISSUE'S EXAMPLE TYPE: a closed schema, one member mapped, one
    // deliberately not, the common fields built in.
    const DOCS = 'fgai-docs';
    const DOC = {
      type: 'document_access',
      description: 'Access to documents',
      locations: ['https://docs.fgai.example/'],
      actions: ['read', 'update', 'delete'],
      schema: { type: 'object', additionalProperties: false,
                properties: {
                  type: { const: 'document_access' },
                  locations: { type: 'array', items: { type: 'string' } },
                  actions: { type: 'array', items: { type: 'string' } },
                  identifier: { type: 'string' },
                  classification: { type: 'string' },
                  note: { type: 'string' } } },
      xacml: [{ path: 'classification',
                attributeId: 'urn:example:classification' }],
      notForPolicy: ['note']
    };
    inRealm(function () {
      const docs = applications.createApplication({ identifier: DOCS,
        protocols: ['oauth2'], fields: { oauthClientId: DOCS,
          oauthAudience: ['https://docs.fgai.example/'],
          oauthAuthorizationDetailsType: [JSON.stringify(DOC)] } });
      note(docs.ok, '3b. a resource declaring document_access, with its ' +
           'policy created beside it', JSON.stringify(docs.errors || ''));
      applications.createApplication({ identifier: 'fgai-open',
        protocols: ['oauth2'], fields: { oauthClientId: 'fgai-open',
          oauthAuthorizationDetailsType: ['open_access'] } });
      applications.createApplication({ identifier: 'fgai',
        protocols: ['oauth2'], fields: { oauthClientId: 'fgai',
          oauthClientSecret: SECRET, oauthRedirectUri: [REDIRECT],
          oauthTokenEndpointAuthMethod: 'client_secret_basic' } });
    });

    const doc = function (actions, extra) {
      return Object.assign({ type: 'document_access',
        locations: ['https://docs.fgai.example/'], actions: actions,
        identifier: 'doc-sentinel-4711', classification: 'internal',
        note: 'sentinel-note' }, extra || {});
    };
    const authorize = function (query, keepCookies) {
      if (!keepCookies) {
        jar = {};
      }
      return request(port, 'GET', PREFIX + '/oauth2/authorize?' +
        new URLSearchParams(Object.assign({ response_type: 'code',
          client_id: 'fgai', redirect_uri: REDIRECT, scope: 'openid',
          state: 'st-' + crypto.randomBytes(4).toString('hex') }, query))
          .toString(), { cookies: true });
    };
    const local = function (location) {
      return String(location || '').replace(/^https?:\/\/[^/]+/, '');
    };
    const drive = async function (first) {
      let r = first;
      const pages = { consentCount: 0 };
      for (let hop = 0; hop < 12; hop++) {
        const where = String(r.headers.location || '');
        if ((r.status !== 302 && r.status !== 303) ||
            where.indexOf(REDIRECT) === 0) {
          break;
        }
        if (/\/authn\/login/.test(where)) {
          r = await screen.submit({ port: port, jar: jar, at: local(where),
            fields: { action: 'login', username: 'fgai-alice',
                      password: 'anything' } });
          continue;
        }
        if (/\/oauth2\/consent/.test(where)) {
          const page = await screen.openConsent({ port: port, jar: jar,
                                                  at: local(where) });
          pages.consentCount += 1;
          r = await screen.answerConsent({ port: port, jar: jar,
            at: local(where), opened: page, decision: 'allow' });
          continue;
        }
        r = await request(port, 'GET', local(where), { cookies: true });
      }
      const location = String(r.headers.location || '');
      const query = location.indexOf('?') >= 0
        ? new URLSearchParams(location.split('?')[1]) : new URLSearchParams();
      return { final: r, location: location, query: query, pages: pages };
    };
    const token = function (form) {
      return request(port, 'POST', PREFIX + '/oauth2/token', { form: form,
        headers: { authorization: BASIC } });
    };
    const par = function (form) {
      return request(port, 'POST', PREFIX + '/oauth2/par', { form: Object.assign(
        { client_id: 'fgai', response_type: 'code', redirect_uri: REDIRECT,
          scope: 'openid' }, form), headers: { authorization: BASIC } });
    };
    const cc = function (detail) {
      return token({ grant_type: 'client_credentials',
        authorization_details: JSON.stringify([detail]) });
    };
    const policyName = function () {
      return inRealm(function () {
        return applications.fgaStateOf(DOCS).policy;
      });
    };
    const writePolicy = function (alfaText, options) {
      return inRealm(function () {
        return store.write(policyName(), xml.writePolicy(alfa.parse(alfaText)),
                           Object.assign({ enabled: true }, options || {}));
      });
    };
    const ALFA_HEAD = [
      'namespace fgai {',
      '    attribute act { category = actionCat',
      '        id = "urn:oasis:names:tc:xacml:1.0:action:action-id"',
      '        type = string }',
      '    attribute detailAction { category = actionCat',
      '        id = "urn:sts:xacml:fga:detail:action" type = string }',
      '    policy documents {',
      '        id = "urn:test:fgai"',
      '        apply firstApplicable',
      '        target clause act == "grant-authorization-detail"'];
    const NO_DELETE = ALFA_HEAD.concat([
      '        rule noDelete {',
      '            deny',
      '            target clause detailAction == "delete"',
      '        }',
      '        rule everythingElse {',
      '            permit',
      '        }',
      '    }',
      '}']).join('\n');
    const NO_READ = ALFA_HEAD.concat([
      '        rule noRead {',
      '            deny',
      '            target clause detailAction == "read"',
      '        }',
      '        rule everythingElse {',
      '            permit',
      '        }',
      '    }',
      '}']).join('\n');
    const fgaRows = function () {
      return inRealm(function () {
        return audit.list().filter(function (row) {
          return row.action === 'fga.decision';
        });
      });
    };

    // --- a. FGA off: unchanged ---------------------------------------------
    let r = await cc(doc(['delete']));
    note(r.status === 200 && Array.isArray(r.json.authorization_details),
         '3c. FGA off: a detail asking to delete is granted as before',
         r.status + ' ' + r.text.slice(0, 200));
    let flow = await drive(await authorize({
      authorization_details: JSON.stringify([doc(['delete'])]) }));
    note(flow.pages.consentCount === 1 && !!flow.query.get('code'),
         '3d. and the authorization endpoint draws it and issues a code',
         flow.location);
    note(fgaRows().length === 0,
         '3e. and no fine-grained decision is asked or audited');

    // --- b. enabling ---------------------------------------------------------
    const openRefused = inRealm(function () {
      return fga.enable('fgai-open', { actor: 'test' });
    });
    note(!openRefused.ok && /\*/.test(openRefused.why || '') &&
         require(ROOT + '/common/error_codes').codeOf(openRefused) ===
           'STS-FGA-0018',
         '3f. enabling is refused while a declared type is uncovered (an ' +
         'open schema), naming the paths', JSON.stringify(openRefused));
    const on = inRealm(function () {
      return fga.enable(DOCS, { actor: 'test' });
    });
    note(on.ok && on.enforced === true,
         '3g. enabling is accepted for a covered type', JSON.stringify(on));

    // --- c. FGA on, the default policy ---------------------------------------
    const monitorBefore = inRealm(function () {
      return (monitor.snapshot().rows.filter(function (row) {
        return row.id === 'fga';
      })[0] || {}).decisions || 0;
    });
    r = await cc(doc(['delete']));
    note(r.status === 200,
         '3h. FGA on with the default policy: permitted',
         r.status + ' ' + r.text.slice(0, 200));
    const monitorAfter = inRealm(function () {
      return (monitor.snapshot().rows.filter(function (row) {
        return row.id === 'fga';
      })[0] || {}).decisions || 0;
    });
    note(monitorAfter === monitorBefore + 1,
         '3i. counted on the monitor\'s fga row', monitorBefore + ' -> ' +
         monitorAfter);

    // --- d. a policy denying delete ------------------------------------------
    const denied = writePolicy(NO_DELETE);
    note(denied.ok, '3j. the application\'s policy now denies delete',
         JSON.stringify(denied));
    flow = await drive(await authorize({
      authorization_details: JSON.stringify([doc(['read', 'delete'])]) }));
    note(flow.query.get('error') === 'access_denied' &&
         flow.pages.consentCount === 0 && !flow.query.get('code'),
         '3k. the authorization endpoint refuses access_denied, redirected, ' +
         'BEFORE consent: the refused detail is never drawn', flow.location);
    r = await authorize({ prompt: 'none',
      authorization_details: JSON.stringify([doc(['delete'])]) }, true);
    const noneAt = String(r.headers.location || '');
    note(noneAt.indexOf(REDIRECT) === 0 && /error=access_denied/.test(noneAt),
         '3l. with prompt=none too — access_denied, not consent_required',
         noneAt);
    r = await par({ authorization_details: JSON.stringify([doc(['delete'])]) });
    note(r.status === 400 && r.json.error === 'invalid_authorization_details',
         '3m. the PAR endpoint refuses it invalid_authorization_details',
         r.status + ' ' + r.text.slice(0, 200));
    r = await par({ authorization_details: JSON.stringify([doc(['read'])]) });
    note(r.status === 201, '3n. and pushes a detail the policy permits',
         r.status + ' ' + r.text.slice(0, 200));
    r = await cc(doc(['delete']));
    note(r.status === 400 && r.json.error === 'invalid_authorization_details',
         '3o. the token endpoint refuses it invalid_authorization_details ' +
         '(client_credentials)', r.status + ' ' + r.text.slice(0, 200));
    r = await cc(doc(['read']));
    note(r.status === 200, '3p. and grants a detail the policy permits',
         r.status + ' ' + r.text.slice(0, 200));
    const readToken = r.json.access_token;

    flow = await drive(await authorize({
      authorization_details: JSON.stringify([doc(['read'])]) }));
    r = await token({ grant_type: 'authorization_code',
                      code: flow.query.get('code'), redirect_uri: REDIRECT });
    note(flow.pages.consentCount === 1 && r.status === 200 &&
         !!r.json.refresh_token,
         '3q. a permitted detail is drawn, consented, and redeemed with a ' +
         'refresh token', flow.location + ' ' + r.text.slice(0, 200));
    const refresh = r.json.refresh_token;
    const userToken = r.json.access_token;

    // --- e. the token exchange's bound ---------------------------------------
    const exchange = function (subjectToken, details) {
      return token({
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        subject_token: subjectToken,
        subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        authorization_details: JSON.stringify(details) });
    };
    r = await exchange(userToken, [doc(['read'])]);
    note(r.status === 200,
         '3r. an exchange asking for a detail the subject_token covers is ' +
         'granted', r.status + ' ' + r.text.slice(0, 200));
    r = await exchange(userToken, [doc(['read', 'update'])]);
    note(r.status === 400 && r.json.error === 'invalid_authorization_details' &&
         /subject_token/.test(r.json.error_description || ''),
         '3s. one asking for more than the subject_token carries is refused ' +
         '(STS-FGA-0017)', r.status + ' ' + r.text.slice(0, 200));
    r = await token({ grant_type: 'client_credentials' });
    r = await exchange(r.json.access_token, [doc(['read'])]);
    note(r.status === 400 && r.json.error === 'invalid_authorization_details',
         '3t. and a subject_token carrying no details covers none',
         r.status + ' ' + r.text.slice(0, 200));
    note(!!readToken, '3u. (the client credentials token carried details)');

    // --- f. a refresh after the policy changes -------------------------------
    writePolicy(NO_READ);
    r = await token({ grant_type: 'refresh_token', refresh_token: refresh });
    note(r.status === 400 && r.json.error === 'invalid_authorization_details',
         '3v. a refresh is decided against the CURRENT policy: read is now ' +
         'refused', r.status + ' ' + r.text.slice(0, 200));

    // --- g. a policy that cannot be used --------------------------------------
    writePolicy(NO_DELETE, { enabled: false });
    r = await cc(doc(['read']));
    note(r.status === 500 && r.json.error === 'server_error',
         '3w. a DISABLED policy is server_error, never a permit',
         r.status + ' ' + r.text.slice(0, 200));
    const keep = policyName();
    writePolicy(NO_DELETE, { enabled: true });
    inRealm(function () {
      applications.setFgaState(DOCS, { policy: 'fga-not-there' },
                               { actor: 'test' });
    });
    r = await cc(doc(['read']));
    note(r.status === 500 && r.json.error === 'server_error',
         '3x. a MISSING policy is server_error', r.status + ' ' +
         r.text.slice(0, 200));
    inRealm(function () {
      applications.setFgaState(DOCS, { policy: keep }, { actor: 'test' });
    });
    const codes = fgaRows().map(function (row) { return row.errorCode; });
    note(codes.indexOf('STS-FGA-0006') >= 0 &&
         codes.indexOf('STS-FGA-0004') >= 0 &&
         codes.indexOf('STS-FGA-0014') >= 0,
         '3y. each refusal is audited under its own code', codes.join(' '));

    // --- h. a type write left uncovered on an enforcing application ----------
    const write = inRealm(function () {
      return applications.updateApplication(DOCS, {
        attribute: 'oauthAuthorizationDetailsType', mode: 'add',
        value: 'bare_type' });
    });
    note(!write.ok && require(ROOT + '/common/error_codes').codeOf(write) ===
           'STS-FGA-0019',
         '3z. a type written to an enforcing application that it would ' +
         'leave uncovered is refused (STS-FGA-0019)', JSON.stringify(write));

    // --- i. what the audit rows carry ----------------------------------------
    const rows = fgaRows();
    const text = JSON.stringify(rows);
    note(rows.length > 0 && text.indexOf('sentinel') < 0 &&
         rows.every(function (row) {
           return /^[0-9a-f]{64}$/.test(String(
             ((row.detail || {}).detailDigest) || JSON.stringify(row)
               .match(/[0-9a-f]{64}/)));
         }),
         '3aa. the fga.decision rows carry digests and never a detail value',
         text.slice(0, 400));
    note(payloadOf(readToken).authorization_details !== undefined,
         '3ab. (the permitted token carries the detail it was granted)');

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

function inAChild(t) {
  log.debug("Entering inAChild().");
  t.log.info('=== 3. the endpoints, in a child process ===');
  const out = path.join(os.tmpdir(), 'fga-issuance-' + process.pid + '-' +
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
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', FGAI_ROOT: ROOT,
                                  FGAI_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  theGate(t);
  thePep(t);
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'fga issuance',
  describe: 'fine-grained authorization at issuance: the gate, the ' +
            'embedded FGA PEP, the authorization, PAR and token endpoints, ' +
            'and the exchange bound (#564 P3)',
  run: run
};
