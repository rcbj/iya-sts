// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: report_parameter_names.js
//
// ===========================================================================
// A SAVED PARAMETER'S NAME IS 1 TO 64 CHARACTERS, AND THE MODEL SAYS SO
// (#1579, rcbj's decision of 2026-11-11).
//
// Until then the Reports API OpenAPI document was OpenAPI 3.0.3, which has no
// `propertyNames`, and `report/jobs.ts` asked a name's length by hand. The
// document is 3.1.0 now and `ParameterBag` states the bound. The decision
// was that NOTHING A CALLER SEES CHANGES, so this file holds, over HTTP, in a
// child process with the whole stack on an ephemeral port, what the hand
// check answered — written and run against the code before the move:
//
//   A. A definition whose parameters name a 65-character name, or an empty
//      one, is refused 400 invalid_query "Parameters are names and values.";
//      a 64-character name is kept. Changing a definition the same way is
//      refused the same way.
//   B. WHERE IN THE ORDER IT IS ASKED. It was asked after the definition was
//      found and after its schedule and its query document, so a request
//      wrong in one of those as well is answered for that: a definition that
//      does not exist is 404, a schedule that is not cron and a document
//      naming no source are their own sentences.
//   C. A RUN'S PARAMETERS ARE NOT STORED, and their names were never
//      bounded: a run naming a 65-character or an empty name is accepted,
//      and a definition whose filter names a 65-character parameter runs
//      with it.
// ===========================================================================
const path = require('path');
const fs = require('fs');
const os = require('os');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'report_parameter_names',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.RPN_ROOT;
  const OUT = process.env.RPN_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function call(port, method, urlPath, token, body) {
    return new Promise(function (resolve, reject) {
      const text = body === undefined ? null : JSON.stringify(body);
      const headers = { accept: 'application/json' };
      if (token) {
        headers.authorization = 'Bearer ' + token;
      }
      if (text) {
        headers['content-type'] = 'application/json';
        headers['content-length'] = Buffer.byteLength(text);
      }
      const req = http.request({ host: '127.0.0.1', port: port,
                                 path: urlPath, method: method,
                                 headers: headers }, function (res) {
        let raw = '';
        res.on('data', function (d) { raw += d; });
        res.on('end', function () {
          let json = null;
          try {
            json = JSON.parse(raw);
          } catch (e) {
            // Not JSON; the finding reports the text.
            json = null;
          }
          resolve({ status: res.statusCode, text: raw, json: json });
        });
      });
      req.on('error', reject);
      if (text) {
        req.write(text);
      }
      req.end();
    });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const oauth2 = require(ROOT_DIR + '/oauth-oidc/oauth2');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const applications = require(ROOT_DIR + '/common/applications');
    const helpers = require(ROOT_DIR + '/common/helpers');

    const stamp = String(process.pid);
    const OWNER = 'rpn-owner-' + stamp;
    const CLIENT = 'rpn-client-' + stamp;
    ldap.createUser(OWNER, { invent: false });
    const joined = ldap.addGroupMember('report-users', OWNER,
                                       { actor: 'test' });
    const made = applications.createApplication({ identifier: CLIENT,
      protocols: ['oauth2'],
      fields: { oauthClientId: CLIENT,
                oauthTokenEndpointAuthMethod: ['client_secret_basic'],
                oauthAllowedScope: ['openid'],
                oauthDelegatedPermission: [
                  'urn:sts:report-api:report:use'] } });
    note(joined && joined.ok && made && made.ok,
         'precondition: a report user, and a client holding report:use',
         JSON.stringify([joined, made]));

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    const token = await oauth2.accessTokenAsync(base, {
      audience: base + '/report-api', client_id: CLIENT, username: OWNER,
      sub: String(helpers.subjectForName(OWNER) || ''), scope: 'report:use' });
    note(!!token, 'precondition: an access token for the report API');
    const brief = function (r) {
      return r.status + ' ' + (r.text || '').slice(0, 300);
    };
    const NAMES = JSON.stringify({ error: 'invalid_query',
      error_description: 'Parameters are names and values.' });
    const refusedForNames = function (r) {
      return r.status === 400 && r.text === NAMES;
    };
    const N64 = 'p'.repeat(64);
    const N65 = 'p'.repeat(65);
    const document = { source: 'users', select: ['username'], limit: 3 };
    const define = function (body) {
      return call(port, 'POST', '/report-api/definitions', token, body);
    };

    // --- A. the bound ----------------------------------------------------
    let r = await define({ name: 'sixty-five', document: document,
                           parameters: { [N65]: 1 } });
    note(refusedForNames(r), 'A1. a 65-character parameter name is ' +
         'refused 400 invalid_query, "Parameters are names and values."',
         brief(r));
    r = await define({ name: 'empty', document: document,
                       parameters: { '': 1 } });
    note(refusedForNames(r), 'A2. an empty parameter name is refused the ' +
         'same way', brief(r));
    r = await define({ name: 'sixty-four', document: document,
                       parameters: { [N64]: 1, b: 'x' } });
    const kept = r.json && r.json.definition;
    note(r.status === 200 && kept && kept.parameters &&
         kept.parameters[N64] === 1 && kept.parameters.b === 'x',
         'A3. a 64-character parameter name is kept', brief(r));
    const id = kept ? kept.id : 'none';
    r = await call(port, 'POST', '/report-api/definitions/' + id, token,
                   { name: 'sixty-four', document: document,
                     parameters: { [N65]: 1 } });
    note(refusedForNames(r), 'A4. changing a definition to a 65-character ' +
         'name is refused the same way', brief(r));
    r = await call(port, 'GET', '/report-api/definitions/' + id, token);
    note(r.status === 200 && r.json && r.json.definition &&
         r.json.definition.parameters &&
         r.json.definition.parameters[N64] === 1,
         'A5. and the stored definition keeps what it had', brief(r));

    // --- B. where in the order -------------------------------------------
    r = await call(port, 'POST', '/report-api/definitions/nope', token,
                   { name: 'x', document: document,
                     parameters: { [N65]: 1 } });
    note(r.status === 404 && r.text === JSON.stringify({
      error: 'not_found', error_description: 'No such definition.' }),
         'B1. a definition that does not exist is 404 first', brief(r));
    r = await define({ name: 'cron', document: document,
                       schedule: 'not cron', parameters: { [N65]: 1 } });
    note(r.status === 400 && r.text === JSON.stringify({
      error: 'invalid_query',
      error_description: 'The schedule is not a UTC cron expression.' }),
         'B2. a schedule that is not cron is answered for the schedule',
         brief(r));
    r = await define({ name: 'source', document: { source: 'nope' },
                       parameters: { [N65]: 1 } });
    note(r.status === 400 && r.text === JSON.stringify({
      error: 'unknown_source', error_description: 'No such source.' }),
         'B3. a document naming no source is answered for the document',
         brief(r));
    r = await define({ name: 'value', document: document,
                       parameters: { [N65]: { nested: true } } });
    note(refusedForNames(r), 'B4. a value the bag cannot hold beside the ' +
         'name is refused for the parameters', brief(r));

    // --- C. a run --------------------------------------------------------
    const run = function (defId, body) {
      return call(port, 'POST', '/report-api/definitions/' + defId + '/run',
                  token, body);
    };
    r = await run(id, { [N65]: 1 });
    note(r.status === 202 || r.status === 200,
         'C1. a run naming a 65-character parameter is accepted: a run\'s ' +
         'parameters are not stored', brief(r));
    r = await run(id, { '': 1 });
    note(r.status === 202 || r.status === 200,
         'C2. and so is one naming an empty one', brief(r));
    const filtered = Object.assign({}, document,
      { where: { op: 'eq', field: 'username', param: N65 } });
    r = await define({ name: 'filtered', document: filtered });
    const withParam = r.json && r.json.definition;
    note(r.status === 200 && !!withParam,
         'C3. a filter may name a 65-character parameter', brief(r));
    r = await run(withParam ? withParam.id : 'none', { [N65]: OWNER });
    note(r.status === 202 || r.status === 200,
         'C4. and the definition runs with it', brief(r));
    const many = {};
    for (let i = 0; i < 33; i++) {
      many['p' + i] = i;
    }
    r = await run(id, many);
    note(r.status === 400 && r.text === NAMES,
         'C5. a run naming 33 parameters is still refused', brief(r));

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'rpn-' + process.pid + '-' +
                        Date.now() + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  RPN_ROOT: ROOT, RPN_OUT: out }),
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
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'report_parameter_names',
  describe: 'a saved parameter\'s name is 1 to 64 characters, the model\'s ' +
            'bound, refused exactly as the hand check refused it (#1579)',
  run: run
};
