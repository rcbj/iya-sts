'use strict';

// ===========================================================================
// tests/software_statement.js — RFC 7591 SECTION 2.3 SOFTWARE STATEMENTS AT
// POST /oauth2/register AND RFC 7592's PUT (2026-09-13).
//
// What `oauth-oidc/software_statement.ts` promises, driven over HTTP against
// the protocol stack in a child process — the arrangement
// `tests/oauth_oid4vc_hardcoded.js` uses, because every case needs the mode
// and four settings flipped between requests, and a container cannot be told
// that per request.
//
// The claims, each a section below:
//
//   1. A TRUSTED statement's claims take precedence over the JSON (section
//      3.1.1), the statement is echoed unmodified (section 3.2.1), and the
//      entry records who vouched for it.
//   2. Every INVALID document is refused `invalid_software_statement` and an
//      undeclared issuer `unapproved_software_statement` — alg none, HMAC, a
//      bad signature, expiry, an `aud` addressed elsewhere, one of this
//      realm's OTHER JWTs presented as a statement.
//   3. With the issuer refusal OFF, an undeclared statement is accepted
//      UNVERIFIED: the JSON wins and the entry says untrusted.
//   4. A statement this realm ISSUED — through the same action the console
//      and /admin-api reach — registers, and the action refuses what a
//      statement may not fix.
//   5. PRODUCT MODE with oauth2.openRegistration off: only a TRUSTED
//      statement opens the endpoint, the discovery document follows the
//      setting, and a client let in that way cannot PUT its metadata away.
//   6. oauth2.softwareStatementRequired refuses a registration with none.
//   7. The application page's view model reports all three halves.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'software_statement',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.SS_ROOT;
  const OUT = process.env.SS_OUT;
  const http = require('http');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      const body = o.json !== undefined ? JSON.stringify(o.json) : '';
      const headers = Object.assign({}, o.headers || {});
      if (method !== 'GET' && method !== 'DELETE') {
        headers['content-type'] = 'application/json';
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let parsed = null;
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            // Not JSON; the raw text is kept. No logger in a `node -e` child,
            // so the reason travels on the result.
            parsed = { parseError: e.message };
          }
          resolve({ status: res.statusCode, text: text, json: parsed });
        });
      });
      req.end(body);
    });
  }

  function b64(value) {
    return Buffer.from(JSON.stringify(value)).toString('base64url');
  }

  function signRs256(header, claims, privateKey) {
    const input = b64(header) + '.' + b64(claims);
    return input + '.' +
      nodeCrypto.sign('sha256', Buffer.from(input), privateKey)
                .toString('base64url');
  }

  function payloadOf(jwt) {
    return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url')
                            .toString('utf8'));
  }

  function headerOf(jwt) {
    return JSON.parse(Buffer.from(String(jwt).split('.')[0], 'base64url')
                            .toString('utf8'));
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const applications = require(ROOT + '/common/applications');
    const helpers = require(ROOT + '/common/helpers');
    const adminActions = require(ROOT + '/admin-core/admin_actions');
    const adminViews = require(ROOT + '/admin-core/admin_views');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const BASE = 'http://127.0.0.1:' + port;
    const now = Math.floor(Date.now() / 1000);

    // --- the publisher, with a key of its own -------------------------------
    const PUBLISHER = 'ss-publisher';
    const ISS = 'https://publisher.ss.example';
    const pair = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const other = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = Object.assign(pair.publicKey.export({ format: 'jwk' }),
                              { kid: 'ss-kid', use: 'sig', alg: 'RS256' });
    const created = applications.createApplication({ identifier: PUBLISHER,
      protocols: ['oauth2'], fields: { oauthClientId: PUBLISHER } });
    note(created.ok, '0a. fixture: the publisher application is created',
         JSON.stringify(created.errors || ''));
    const jwks = applications.updateApplication(PUBLISHER, { mode: 'set',
      attribute: 'oauthJwks', value: JSON.stringify({ keys: [jwk] }) });
    const declared = applications.updateApplication(PUBLISHER, { mode: 'add',
      attribute: 'oauthSoftwareStatementIssuer', value: ISS });
    note(jwks.ok !== false && declared.ok !== false,
         '0b. fixture: its jwks and oauthSoftwareStatementIssuer are written ' +
         'through the editable-attribute door',
         JSON.stringify([jwks.errors, declared.errors]));

    const statementFrom = function (claims, opts) {
      const o = opts || {};
      return signRs256(Object.assign({ alg: 'RS256', kid: 'ss-kid',
                                       typ: 'JWT' }, o.header || {}),
                       Object.assign({ iss: ISS, iat: now,
                                       software_id: 'ss-app' }, claims),
                       o.key || pair.privateKey);
    };

    // ======================================================================
    // 1. A TRUSTED STATEMENT
    // ======================================================================
    let r = await request(port, 'POST', '/oauth2/register',
      { json: { redirect_uris: ['https://control.ss.example/cb'] } });
    note(r.status === 201, '1a. development: a registration with no ' +
         'statement is unchanged — the control', r.status + ' ' +
         r.text.slice(0, 120));

    const trusted = statementFrom({
      redirect_uris: ['https://app.ss.example/cb'],
      grant_types: ['authorization_code'] });
    r = await request(port, 'POST', '/oauth2/register',
      { json: { software_statement: trusted,
                redirect_uris: ['https://attacker.ss.example/cb'],
                grant_types: ['client_credentials'],
                client_name: 'From the JSON' } });
    const fromStatement = r.json || {};
    note(r.status === 201 &&
         JSON.stringify(fromStatement.redirect_uris) ===
           JSON.stringify(['https://app.ss.example/cb']) &&
         JSON.stringify(fromStatement.grant_types) ===
           JSON.stringify(['authorization_code']),
         '1b. a trusted statement\'s redirect_uris and grant_types take ' +
         'precedence over the JSON (section 3.1.1)', r.status + ' ' +
         r.text.slice(0, 300));
    note(fromStatement.client_name === 'From the JSON' &&
         fromStatement.software_id === 'ss-app',
         '1c. a member only the JSON carries is kept, and the statement\'s ' +
         'software_id is registered',
         JSON.stringify([fromStatement.client_name, fromStatement.software_id]));
    note(fromStatement.software_statement === trusted &&
         !('iss' in fromStatement) && !('iat' in fromStatement),
         '1d. the statement is returned unmodified (section 3.2.1) and its ' +
         'JWT claims are not registered as metadata',
         Object.keys(fromStatement).join(','));
    const facts = applications.softwareStatementFactsOf(
      fromStatement.client_id);
    note(facts && facts.issuer === ISS && facts.trusted === true &&
         facts.publisher === PUBLISHER,
         '1e. the entry records the issuer, TRUE and the publisher it was ' +
         'trusted through', JSON.stringify(facts));
    const read = await request(port, 'GET', '/oauth2/register/' +
      encodeURIComponent(fromStatement.client_id || 'x'), { headers: {
        authorization: 'Bearer ' + fromStatement.registration_access_token } });
    note(read.status === 200 && read.json &&
         read.json.software_statement === trusted,
         '1f. an RFC 7592 read hands the statement back too',
         read.status + ' ' + read.text.slice(0, 120));

    // ======================================================================
    // 2. REFUSALS
    // ======================================================================
    const refusedAs = async function (label, statement, error) {
      const answer = await request(port, 'POST', '/oauth2/register',
        { json: { software_statement: statement,
                  redirect_uris: ['https://refused.ss.example/cb'] } });
      note(answer.status === 400 && answer.json &&
           answer.json.error === error, label,
           answer.status + ' ' + answer.text.slice(0, 220));
      return answer;
    };
    await refusedAs('2a. an undeclared issuer is ' +
                    'unapproved_software_statement',
                    statementFrom({ iss: 'https://nobody.ss.example' }),
                    'unapproved_software_statement');
    await refusedAs('2b. alg "none" is invalid_software_statement',
                    b64({ alg: 'none' }) + '.' +
                      b64({ iss: ISS, software_id: 'x' }) + '.',
                    'invalid_software_statement');
    const hsInput = b64({ alg: 'HS256', typ: 'JWT' }) + '.' +
                    b64({ iss: ISS, software_id: 'x' });
    await refusedAs('2c. an HMAC statement is invalid — there is no shared ' +
                    'key',
                    hsInput + '.' + nodeCrypto.createHmac('sha256', 'k')
                      .update(hsInput).digest('base64url'),
                    'invalid_software_statement');
    await refusedAs('2d. a statement signed by a key the publisher does not ' +
                    'hold is invalid',
                    statementFrom({}, { key: other.privateKey }),
                    'invalid_software_statement');
    await refusedAs('2e. an expired statement is invalid',
                    statementFrom({ iat: now - 7200, exp: now - 3600 }),
                    'invalid_software_statement');
    await refusedAs('2f. a statement addressed to another server is invalid',
                    statementFrom({ aud: 'https://other-as.example' }),
                    'invalid_software_statement');
    r = await request(port, 'POST', '/oauth2/register',
      { json: { software_statement: statementFrom(
                  { aud: BASE + '/oauth2/register' }),
                redirect_uris: ['https://aud.ss.example/cb'] } });
    note(r.status === 201, '2g. while one addressed to this registration ' +
         'endpoint registers', r.status + ' ' + r.text.slice(0, 160));
    await refusedAs('2h. a statement that is not a JWS at all is invalid',
                    'not-a-jwt', 'invalid_software_statement');
    // ONE OF THIS REALM'S OTHER JWTs — signed with the realm's key, naming
    // the realm's issuer, and not typed as a statement. No `aud`, so that the
    // audience check cannot be what refuses it: the type is the only thing
    // standing between this and a registration.
    // certificate-header: none — a test fixture signing a token-shaped JWT.
    const tokenShaped = helpers.signJwtAs({ iss: BASE, sub: 'alice',
      iat: now, exp: now + 600,
      redirect_uris: ['https://confused.ss.example/cb'] }, 'RS256');
    const confused = await refusedAs('2i. a JWT this realm signed that is ' +
                                     'not typed software-statement+jwt is ' +
                                     'refused, not registered',
                                     tokenShaped,
                                     'invalid_software_statement');
    note(/software-statement\+jwt/.test(
           (confused.json && confused.json.error_description) || ''),
         '2j. and the refusal is the missing type, not some other check',
         confused.text.slice(0, 200));

    // ======================================================================
    // 3. THE ISSUER REFUSAL OFF
    // ======================================================================
    config.setOverride('oauth2.softwareStatementRequireTrustedIssuer', false);
    r = await request(port, 'POST', '/oauth2/register',
      { json: { software_statement: statementFrom(
                  { iss: 'https://nobody.ss.example',
                    redirect_uris: ['https://unverified.ss.example/cb'] }),
                redirect_uris: ['https://json.ss.example/cb'] } });
    const untrusted = r.json || {};
    const untrustedFacts = applications.softwareStatementFactsOf(
      untrusted.client_id);
    note(r.status === 201 &&
         JSON.stringify(untrusted.redirect_uris) ===
           JSON.stringify(['https://json.ss.example/cb']) &&
         untrustedFacts && untrustedFacts.trusted === false,
         '3a. with the refusal off an undeclared statement is accepted ' +
         'UNVERIFIED: the JSON wins and the entry says untrusted',
         r.status + ' ' + JSON.stringify(untrustedFacts) + ' ' +
         r.text.slice(0, 160));
    await refusedAs('3b. and a bad signature from a DECLARED issuer is ' +
                    'still invalid', statementFrom({}, { key: other.privateKey }),
                    'invalid_software_statement');
    config.clearOverride('oauth2.softwareStatementRequireTrustedIssuer');

    // ======================================================================
    // 4. A STATEMENT THIS REALM ISSUES
    // ======================================================================
    const issueAction = function (body) {
      return adminActions.applicationsAction(
        Object.assign({ action: 'issue-software-statement',
                        application: PUBLISHER }, body), [], { base: BASE });
    };
    const issued = issueAction({ metadata: JSON.stringify({
      redirect_uris: ['https://realm.ss.example/cb'],
      grant_types: ['authorization_code'] }) });
    const realmStatement = issued.softwareStatement || '';
    note(issued.ok && headerOf(realmStatement).typ ===
           'software-statement+jwt' &&
         payloadOf(realmStatement).iss === BASE &&
         payloadOf(realmStatement).sub === PUBLISHER &&
         payloadOf(realmStatement).software_id === PUBLISHER &&
         payloadOf(realmStatement).exp > now,
         '4a. the issue action signs a typed statement naming this realm\'s ' +
         'issuer, the publisher and an exp', JSON.stringify(issued.errors ||
           (realmStatement ? payloadOf(realmStatement) : '')));
    const onEntry = applications.get(PUBLISHER);
    note(onEntry && String([].concat(
           onEntry.fields.oauthIssuedSoftwareStatement || [])[0]) ===
           realmStatement,
         '4b. and writes it onto the entry as oauthIssuedSoftwareStatement');
    r = await request(port, 'POST', '/oauth2/register',
      { json: { software_statement: realmStatement,
                redirect_uris: ['https://elsewhere.ss.example/cb'] } });
    const realmClient = r.json || {};
    note(r.status === 201 &&
         JSON.stringify(realmClient.redirect_uris) ===
           JSON.stringify(['https://realm.ss.example/cb']) &&
         (applications.softwareStatementFactsOf(realmClient.client_id) || {})
           .publisher === PUBLISHER,
         '4c. a client presenting it registers with the members it fixes, ' +
         'trusted through the publisher it was issued for',
         r.status + ' ' + r.text.slice(0, 200));
    const noExpiry = issueAction({ metadata: {}, lifetimeSeconds: 0 });
    note(noExpiry.ok && !('exp' in payloadOf(noExpiry.softwareStatement)),
         '4d. a lifetime of 0 issues a statement with no exp',
         JSON.stringify(noExpiry.errors || ''));
    const reserved = issueAction({ metadata: { client_id: 'chosen' } });
    const notJson = issueAction({ metadata: '{nope' });
    const nobody = adminActions.applicationsAction(
      { action: 'issue-software-statement', application: 'ss-nobody' }, [],
      { base: BASE });
    const badUri = issueAction({ metadata: {
      redirect_uris: ['javascript:alert(1)'] } });
    note(reserved.ok === false && notJson.ok === false &&
         nobody.ok === false && badUri.ok === false,
         '4e. it refuses a server-assigned member, JSON that is not JSON, an ' +
         'application that does not exist and an address a registration ' +
         'would refuse', JSON.stringify([reserved.errors, notJson.errors,
                                         nobody.errors, badUri.errors]));
    const noBase = adminActions.applicationsAction(
      { action: 'issue-software-statement', application: PUBLISHER }, []);
    note(noBase.ok === false, '4f. and refuses when no request address ' +
         'reached it, rather than signing an empty iss',
         JSON.stringify(noBase.errors));

    // ======================================================================
    // 5. PRODUCT MODE, REGISTRATION CLOSED
    // ======================================================================
    config.setOverride('global.mode', 'product');
    r = await request(port, 'POST', '/oauth2/register',
      { json: { redirect_uris: ['https://closed.ss.example/cb'],
                token_endpoint_auth_method: 'client_secret_basic' } });
    note(r.status === 403 && r.json && r.json.error === 'access_denied',
         '5a. PRODUCT: a registration with no statement is refused',
         r.status + ' ' + r.text.slice(0, 160));
    let meta = await request(port, 'GET',
                             '/.well-known/oauth-authorization-server');
    note(meta.json && meta.json.registration_endpoint,
         '5b. PRODUCT: registration_endpoint is still advertised, because a ' +
         'trusted statement opens it', meta.json &&
         meta.json.registration_endpoint);
    r = await request(port, 'POST', '/oauth2/register',
      { json: { software_statement: trusted,
                token_endpoint_auth_method: 'client_secret_basic' } });
    const admitted = r.json || {};
    note(r.status === 201 && admitted.client_id,
         '5c. PRODUCT: a trusted statement opens the closed endpoint',
         r.status + ' ' + r.text.slice(0, 200));
    await refusedAs('5d. PRODUCT: an invalid statement is refused with its ' +
                    'own error rather than access_denied',
                    statementFrom({}, { key: other.privateKey }),
                    'invalid_software_statement');
    config.setOverride('oauth2.softwareStatementRequireTrustedIssuer', false);
    r = await request(port, 'POST', '/oauth2/register',
      { json: { software_statement: statementFrom(
                  { iss: 'https://nobody.ss.example' }),
                redirect_uris: ['https://unverified.ss.example/cb'] } });
    note(r.status === 403, '5e. PRODUCT: an UNVERIFIED statement does not ' +
         'open it', r.status + ' ' + r.text.slice(0, 160));
    config.clearOverride('oauth2.softwareStatementRequireTrustedIssuer');

    // RFC 7592 updates of the admitted client.
    const clientUri = '/oauth2/register/' +
      encodeURIComponent(admitted.client_id || 'x');
    const auth = { authorization: 'Bearer ' +
                   admitted.registration_access_token };
    r = await request(port, 'PUT', clientUri, { headers: auth,
      json: { redirect_uris: ['https://attacker.ss.example/cb'],
              client_id: admitted.client_id,
              token_endpoint_auth_method: 'client_secret_basic' } });
    note(r.status === 400 && r.json &&
         r.json.error === 'unapproved_software_statement',
         '5f. PRODUCT: a client let in by a statement cannot PUT its ' +
         'metadata away without one', r.status + ' ' + r.text.slice(0, 200));
    r = await request(port, 'PUT', clientUri, { headers: auth,
      json: { software_statement: realmStatement,
              client_id: admitted.client_id,
              token_endpoint_auth_method: 'client_secret_basic' } });
    note(r.status === 400 && r.json &&
         r.json.error === 'unapproved_software_statement',
         '5g. nor with a trusted statement from ANOTHER issuer',
         r.status + ' ' + r.text.slice(0, 200));
    r = await request(port, 'PUT', clientUri, { headers: auth,
      json: { software_statement: trusted, client_name: 'Renamed',
              client_id: admitted.client_id,
              token_endpoint_auth_method: 'client_secret_basic' } });
    note(r.status === 200 && r.json && r.json.client_name === 'Renamed' &&
         JSON.stringify(r.json.redirect_uris) ===
           JSON.stringify(['https://app.ss.example/cb']),
         '5h. and an update carrying the same issuer\'s statement is accepted',
         r.status + ' ' + r.text.slice(0, 200));

    config.setOverride('oauth2.softwareStatementOpensRegistration', false);
    r = await request(port, 'POST', '/oauth2/register',
      { json: { software_statement: trusted,
                token_endpoint_auth_method: 'client_secret_basic' } });
    meta = await request(port, 'GET',
                         '/.well-known/oauth-authorization-server');
    note(r.status === 403 && meta.json &&
         !('registration_endpoint' in meta.json),
         '5i. PRODUCT with oauth2.softwareStatementOpensRegistration off: ' +
         'even a trusted statement is refused, and the endpoint is not ' +
         'advertised', r.status + ' ' + (meta.json &&
           meta.json.registration_endpoint));
    config.clearOverride('oauth2.softwareStatementOpensRegistration');
    config.clearOverride('global.mode');

    // ======================================================================
    // 6. REQUIRED
    // ======================================================================
    config.setOverride('oauth2.softwareStatementRequired', true);
    r = await request(port, 'POST', '/oauth2/register',
      { json: { redirect_uris: ['https://none.ss.example/cb'] } });
    note(r.status === 400 && r.json &&
         r.json.error === 'invalid_software_statement',
         '6a. oauth2.softwareStatementRequired refuses a registration with ' +
         'none', r.status + ' ' + r.text.slice(0, 160));
    r = await request(port, 'POST', '/oauth2/register',
      { json: { software_statement: trusted } });
    note(r.status === 201, '6b. and accepts one that carries a statement',
         r.status + ' ' + r.text.slice(0, 120));
    config.clearOverride('oauth2.softwareStatementRequired');

    // DELETE takes the facts with the registration.
    const gone = await request(port, 'DELETE', '/oauth2/register/' +
      encodeURIComponent(fromStatement.client_id || 'x'), { headers: {
        authorization: 'Bearer ' + fromStatement.registration_access_token } });
    note(gone.status === 204 &&
         applications.softwareStatementFactsOf(fromStatement.client_id) ===
           null,
         '6c. an RFC 7592 delete takes the statement facts with the ' +
         'registration', gone.status);

    // ======================================================================
    // 7. THE PAGE'S VIEW MODEL
    // ======================================================================
    const fakeReq = { query: {}, headers: { host: '127.0.0.1:' + port },
                      protocol: 'http' };
    const view = adminViews.applicationDetailJson(fakeReq, PUBLISHER);
    const section = view.json && view.json.softwareStatements;
    note(section && section.declaredIssuers.indexOf(ISS) >= 0 &&
         section.usableKeys === 1 && section.issued &&
         section.issued.verifies === true &&
         section.issued.statement === noExpiry.softwareStatement,
         '7a. the application view reports the declared issuer, its usable ' +
         'key and the issued statement verifying now',
         JSON.stringify(section && Object.assign({}, section,
                                                 { issued: section.issued &&
                                                   section.issued.verifies })));
    const clientView = adminViews.applicationDetailJson(fakeReq,
                                                        realmClient.client_id);
    note(clientView.json && clientView.json.softwareStatements &&
         clientView.json.softwareStatements.registeredWith &&
         clientView.json.softwareStatements.registeredWith.issuer === BASE,
         '7b. and a client\'s view reports how a statement let it in',
         JSON.stringify(clientView.json &&
                        clientView.json.softwareStatements));

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
  const out = path.join(os.tmpdir(), 'software-statement-' + process.pid +
                        '-' + Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', SS_ROOT: ROOT, SS_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
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
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'software statements',
  describe: 'RFC 7591 section 2.3: trusted statements at registration and ' +
            'RFC 7592 update, the refusals, a realm-issued statement, ' +
            'product mode',
  run: run
};
