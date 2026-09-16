'use strict';
//
// File: admin_api_document_security.js
//
// ===========================================================================
// THE OPENAPI DOCUMENT DESCRIBES THE GATE IN FRONT OF THE API IT DESCRIBES.
//
// `/admin-api` has required an OAuth 2.0 access token since 2026-09-09. Its
// own document said the opposite until 2026-09-10 — `security: []`, no
// `securitySchemes` at all, and an opening paragraph reading **"Nothing here
// is protected, and that is a decision rather than an oversight."** Every word
// of that had been true, and was written when it was.
//
// **WHY THAT IS WORSE THAN A STALE COMMENT, AND WHY IT IS WORTH A TEST FILE.**
// `security: []` is not the absence of a statement, it is the opposite
// statement: OpenAPI reads it as "no credential is needed here". So a
// generated client sent no Authorization header, was refused 401 on all 238
// operations, and the document a person then read to find out why told them
// the refusal was a bug. Nothing anywhere went red — this is the quiet class
// of failure `tests/version.js` was written for, one level out: a document
// that renders, validates and lies.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// Three of the four claims below need to CHOOSE THE STATE OF THE SERVICE
// rather than observe one:
//
//   * the document with the gate ON and the document with it OFF, which over
//     HTTP is two services (`adminApi.authRequired` is read per request, so a
//     running one could be switched — but the switch is itself a write through
//     the API being tested, which is the thing to keep out of an assertion
//     about what that API publishes);
//   * what `buildSpec()` does when a caller says NOTHING about the gate, which
//     no running service can be asked because every caller in this tree says
//     something;
//   * that every CALL SITE goes through `admin_api.js`'s `specOptions()`,
//     which is a property of the source and of no request.
//
// The fourth — that the document a running service serves actually says this —
// is asserted over HTTP by `tests/vendored/sts_admin_api_auth.js`, beside that
// gate's other refusals. Two halves on purpose: this file goes red when the
// builder stops describing the gate, that one when the served document and the
// gate disagree.
//
// ---------------------------------------------------------------------------
// THE DUPLICATION THIS FILE EXISTS TO POLICE.
//
// The scope an operation needs is decided in TWO places and they must agree:
// `admin_api.js`'s middleware (`req.method === 'GET' ? 'admin:read' :
// 'admin:write'`) and `admin_api_spec.js`'s `scopeForMethod()`. One is what
// the service DOES and the other is what it SAYS, and a document that promises
// `admin:read` on an operation the gate wants `admin:write` for is the same
// class of defect as the one above, just narrower. Neither can be derived from
// the other without making the document agree with itself by construction, so
// the rule is written twice and compared here — including the rule as it is
// SPELT IN THE MIDDLEWARE, read out of the source, so that a change to the
// gate that this file cannot see is a change this file fails on.
// ===========================================================================

const fs = require('fs');
const path = require('path');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log =
    require('bunyan').createLogger({ name: 'admin_api_document_security',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.resolve(__dirname, '..');

const spec = require('../mgmt-api/admin_api_spec');
const adminApi = require('../mgmt-api/admin_api');

function codeOf(rel) {
  log.debug("Entering codeOf().");
  log.debug("Leaving codeOf().");
  return fs.readFileSync(path.join(ROOT, rel), 'utf8');
}

// The document, built the way a request builds it, with the gate said to be in
// the given state. `baseUrl` is a real-looking one because the token URL and
// the `resource` hint below are built from it.
function documentWith(authRequired) {
  log.debug("Entering documentWith().");
  log.debug("Leaving documentWith().");
  return spec.buildSpec(adminApi.ROUTES, {
    baseUrl: 'https://sts.example:8081',
    version: '0.1.20260910000000',
    authRequired: authRequired
  });
}

function operationsOf(document) {
  log.debug("Entering operationsOf().");
  const out = [];
  Object.keys(document.paths).forEach(function (p) {
    Object.keys(document.paths[p]).forEach(function (method) {
      out.push({ path: p, method: method,
                 operation: document.paths[p][method] });
    });
  });
  log.debug("Leaving operationsOf().");
  return out;
}

async function run(t) {
  log.debug("Entering run().");
  // -----------------------------------------------------------------------
  t.log.info('=== with the gate ON, which is the default ===');
  const guarded = documentWith(true);
  const guardedOps = operationsOf(guarded);

  // A FLOOR, for the reason every file in this directory gives: an extractor
  // that quietly returns nothing makes every assertion below vacuous, and the
  // run still says passed.
  t.check(guardedOps.length >= 200,
          'the route table still yields the whole API',
          guardedOps.length + ' operations');

  t.check(Array.isArray(guarded.security) && guarded.security.length > 0,
          'the document says a credential is required',
          JSON.stringify(guarded.security));
  t.check(!!(guarded.components && guarded.components.securitySchemes &&
             guarded.components.securitySchemes.oauth2 &&
             guarded.components.securitySchemes.bearerAuth),
          'and names both ways to present it — the flow that MINTS a token ' +
          'and the header that carries one somebody already holds',
          Object.keys((guarded.components || {}).securitySchemes || {})
                .join(', '));

  const flow = ((((guarded.components || {}).securitySchemes || {}).oauth2 ||
                 {}).flows || {}).clientCredentials || {};
  t.equal(flow.tokenUrl, 'https://sts.example:8081/oauth2/token',
          'the token URL is this service, as the request reached it');
  t.check(!!(flow.scopes && flow.scopes['admin:read'] &&
             flow.scopes['admin:write']),
          'and both scopes are described where a tool will read them',
          Object.keys(flow.scopes || {}).join(', '));

  // **THE `resource` PARAMETER.** RFC 8707's indicator is what puts this API
  // in the token's `aud`, the gate refuses a token audienced anywhere else,
  // and OpenAPI has no field for it — so if it is not in this prose it is
  // nowhere a client will look, and every token a reader mints is refused for
  // a reason the document never mentions.
  const oauthDescription = String(
    (((guarded.components ||
       {}).securitySchemes || {}).oauth2 || {}).description || '');
  t.check(oauthDescription.indexOf('resource=') >= 0 &&
          oauthDescription.indexOf('/admin-api') >= 0,
          'the oauth2 scheme names the `resource` a token must be audienced ' +
          'at, which OpenAPI itself has no field for',
          oauthDescription.slice(0, 120));

  // -----------------------------------------------------------------------
  t.log.info('=== every operation states the scope the GATE would want ===');
  const disagreed = guardedOps.filter(function (row) {
    const wanted = row.method.toUpperCase() === 'GET' ? 'admin:read'
                                                      : 'admin:write';
    const security = row.operation.security;
    if (!Array.isArray(security) || !security.length) { return true; }
    const named = (security[0] || {}).oauth2 || [];
    return named.length !== 1 || named[0] !== wanted;
  });
  t.check(disagreed.length === 0,
          'all ' + guardedOps.length + ' operations declare exactly the ' +
          'scope the middleware would ask for',
          disagreed.length
            ? disagreed.slice(0, 5).map(function (r) {
                return r.method.toUpperCase() + ' ' + r.path + ' -> ' +
                       JSON.stringify(r.operation.security);
              }).join('; ')
            : 'none disagreed');

  // The bearer alternative may not carry scopes: OpenAPI scopes are meaningful
  // only for oauth2 and openIdConnect, and a validator rejects them elsewhere.
  const scopedBearer = guardedOps.filter(function (row) {
    const alt = (row.operation.security || [])[1] || {};
    return !Array.isArray(alt.bearerAuth) || alt.bearerAuth.length !== 0;
  });
  t.check(scopedBearer.length === 0,
          'and the http/bearer alternative carries an empty scope list, ' +
          'which is the only thing OpenAPI allows there',
          scopedBearer.length + ' operations got that wrong');

  // -----------------------------------------------------------------------
  // THE PROSE. Asserted because it is the half a PERSON reads, and it was the
  // half that was wrong in a way no schema check could see.
  // -----------------------------------------------------------------------
  t.log.info('=== the prose at the top says the same thing ===');
  t.check(guarded.info.description.indexOf('Nothing here is protected') < 0,
          'the guarded document does NOT open by saying nothing is protected',
          guarded.info.description.slice(0, 90));
  t.check(/requires an OAuth 2\.0 access token/.test(guarded.info.description),
          'it says a token is required');
  t.check(guarded.info.description.indexOf('adminApi.authRequired') >= 0,
          'and names the setting that turns it off, because a reader who ' +
          'wants the open API needs to know it exists');

  // -----------------------------------------------------------------------
  t.log.info('=== with the gate OFF, the open API is described exactly ===');
  const open = documentWith(false);
  const openOps = operationsOf(open);
  t.check(Array.isArray(open.security) && open.security.length === 0,
          'security is the EMPTY ARRAY, which is OpenAPI for "no credential ' +
          'is needed" — a statement, not an omission',
          JSON.stringify(open.security));
  t.check(!(open.components || {}).securitySchemes,
          'and no scheme is offered, because there is nothing to present');
  t.check(openOps.filter(function (r) {
    return r.operation.security;
  }).length === 0,
          'no operation asks for one either',
          openOps.length + ' operations, none with security');
  t.check(open.info.description.indexOf('Nothing here is protected') >= 0,
          'and the original paragraph is back verbatim — it is the argument ' +
          'for the off switch and outlives the day the switch was added');

  // -----------------------------------------------------------------------
  // THE DEFAULT, which is the one thing no running service can be asked.
  // -----------------------------------------------------------------------
  t.log.info('=== a caller that says nothing about the gate ===');
  const silent = spec.buildSpec(adminApi.ROUTES,
                                { baseUrl: 'https://x', version: '0' });
  t.check(Array.isArray(silent.security) && silent.security.length > 0,
          'defaults to REQUIRED, which is the setting\'s own default and the ' +
          'safe direction: over-stating costs a client one unnecessary ' +
          'token, and under-stating is the defect this file exists for');

  // -----------------------------------------------------------------------
  // THE TWO SOURCE CLAIMS.
  // -----------------------------------------------------------------------
  t.log.info('=== the source: one place assembles this, and the gate still ' +
             'spells the rule the same way ===');
  const apiSource = codeOf('mgmt-api/admin_api.js');
  const explorerSource = codeOf('admin-ui/api_explorer.ts');

  // THE MIDDLEWARE'S OWN LINE. If the gate stops deciding the scope by the
  // method — a per-operation table, a third scope — this file's comparison
  // above is quietly asserting the wrong rule, and this is what says so.
  t.check(/req\.method === 'GET' \? 'admin:read' : 'admin:write'/
          .test(apiSource),
          'the gate still decides the scope by the method, which is the rule ' +
          'this file compares the document against');

  // EVERY CALL SITE. Three today; the point is that a fourth cannot assemble
  // its own idea of what the API requires.
  //
  // **A CALL IS ONE THAT PASSES THE ROUTE TABLE**, and that qualification is
  // not fussiness: both files talk ABOUT `buildSpec()` in their comments, and
  // a scan that counted those found five call sites in a tree with three and
  // then complained that the prose had failed to pass an option. What a real
  // call always has is the table as its first argument.
  const callSites = [];
  [['mgmt-api/admin_api.js', apiSource],
   ['admin-ui/api_explorer.ts', explorerSource]].forEach(function (pair) {
    const source = pair[1];
    let at = source.indexOf('buildSpec(');
    while (at >= 0) {
      const snippet = source.slice(at, at + 160);
      if (/^buildSpec\(\s*(adminApi\.)?ROUTES\b/.test(snippet)) {
        // The whole snippet is what is TESTED — a call may wrap onto the
        // next line, and one of the three does — while the first line of it
        // is what a failure PRINTS.
        callSites.push({ file: pair[0], call: snippet.split('\n')[0],
                         source: snippet });
      }
      at = source.indexOf('buildSpec(', at + 1);
    }
  });
  t.check(callSites.length >= 3,
          'every buildSpec() call site was found',
          callSites.length + ' call(s)');
  const handRolled = callSites.filter(function (site) {
    return site.source.indexOf('specOptions(') < 0;
  });
  t.check(handRolled.length === 0,
          'and every one of them takes its options from ' +
          'admin_api.specOptions(), so two copies of this document cannot ' +
          'disagree about what the API requires',
          handRolled.map(function (s) { return s.file + ': ' + s.call; })
            .join('; ') || 'none assembled its own');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'admin_api_document_security',
  describe: 'the OpenAPI document describes the token gate in front of ' +
            '/admin-api — in both of that gate\'s states',
  run: run
};
