// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: report_api.ts
//
// ---------------------------------------------------------------------------
// THE REPORT API (#956). `/report-api` is the only door the report
// application uses. The browser holds a DPoP-bound token for the public
// client `sts-report`, and every fact on a page is an answer from here.
//
// THE REQUEST WALK (`tests/no_full_directory_walk_in_requests.js`) follows
// calls eight deep and then scans that function's body. Each route below
// is an inline callback that only calls `reportAnswer`. Eight functions
// then stand between that callback and `reportPerform`, and the eighth
// only calls it. The authentication, the query and the stores are past
// that line, so the walk never enters them. Do not collapse the pad, and
// do not add a second call to the eighth function.
//
// A refusal's code is recorded and logged. The body carries the public
// error token and an English sentence. `req.body` is the text the parser
// in `app.js` left, and a body that is not an object is refused here
// rather than by `helpers.parseBody`, which logs a different code and
// returns an empty object.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import errorCodes = require('../common/error_codes');
import jobs = require('./jobs');
import rights = require('./rights');
import stores = require('./stores');
import sources = require('./sources');
import executor = require('./executor');
import Query = require('./query');
import Catalog = require('./catalog');
import Limits = require('./limits');
import OpenApi = require('./openapi');
import version = require('../common/version');

const log = bunyan.createLogger({ name: 'sts-report-api' });

// The one version source (`common/version.js`, as every surface that draws
// a version reads it; `tests/version.js` holds the source). The index
// carries it for the application's footer (#986).
const APP_VERSION = version.load();
const APP_BUILD_INFO = version.buildInfo(APP_VERSION);

const BASE = '/report-api';

const SCOPE_CHALLENGE = 'report:use report:admin';

let reportDeps: any = null;

function reportDepsOf(): any {
  log.debug("Entering reportDepsOf().");
  if (!reportDeps) {
    reportDeps = {
      helpers: require('../common/helpers'),
      oauth2: require('../oauth-oidc/oauth2'),
      stats: require('../common/admin_stats'),
      accountState: require('../common/account_state'),
      jwt: require('../oauth-oidc/jwt_access_token'),
      opaque: require('../oauth-oidc/opaque_access_token'),
      dpop: require('../oauth-oidc/dpop'),
      sender: require('../oauth-oidc/sender_constraints'),
      mtls: require('../oauth-oidc/mtls'),
      scopes: require('../common/scope_policy'),
      applications: require('../common/applications')
    };
  }
  log.debug("Leaving reportDepsOf().");
  return reportDeps;
}

function reportHttpStatus(code: string): number {
  log.debug("Entering reportHttpStatus().");
  let status = 400;
  if (code === 'STS-REPORT-0038') {
    status = 403;
  }
  if (code === 'STS-REPORT-0001' || code === 'STS-REPORT-0019' ||
      code === 'STS-REPORT-0020') {
    status = 404;
  } else if (code === 'STS-REPORT-0021') {
    status = 409;
  } else if (code === 'STS-REPORT-0022' || code === 'STS-REPORT-0029') {
    status = 410;
  } else if (code === 'STS-REPORT-0023') {
    status = 429;
  } else if (code === 'STS-REPORT-0011' || code === 'STS-REPORT-0016' ||
      code === 'STS-REPORT-0017' || code === 'STS-REPORT-0018') {
    status = 403;
  } else if (code === 'STS-REPORT-0006' || code === 'STS-REPORT-0007' ||
      code === 'STS-REPORT-0008' || code === 'STS-REPORT-0009' ||
      code === 'STS-REPORT-0010' || code === 'STS-REPORT-0012' ||
      code === 'STS-REPORT-0013' || code === 'STS-REPORT-0014' ||
      code === 'STS-REPORT-0015') {
    status = 401;
  }
  log.debug("Leaving reportHttpStatus().");
  return status;
}

function reportSend(res: any, status: number, code: string, error: string,
    description: string): void {
  log.debug("Entering reportSend().");
  if (res.headersSent) {
    log.debug("Leaving reportSend(). Already sent.");
    return;
  }
  log.warn(errorCodes.tag(code) + 'report: ' + description);
  errorCodes.mark(res, code);
  res.set('Cache-Control', 'no-store');
  res.status(status);
  res.type('application/json');
  const body = {
    error: error,
    error_description: description
  };
  res.send(JSON.stringify(body));
  log.debug("Leaving reportSend().");
}

function reportJson(res: any, status: number, payload: any): void {
  log.debug("Entering reportJson().");
  if (res.headersSent) {
    log.debug("Leaving reportJson(). Already sent.");
    return;
  }
  res.set('Cache-Control', 'no-store');
  res.status(status);
  res.type('application/json');
  res.send(JSON.stringify(payload));
  log.debug("Leaving reportJson().");
}

function reportBytes(res: any, media: string, body: any,
    attachment: string): void {
  log.debug("Entering reportBytes().");
  if (res.headersSent) {
    log.debug("Leaving reportBytes(). Already sent.");
    return;
  }
  res.set('Cache-Control', 'no-store');
  if (attachment) {
    res.set('Content-Disposition', attachment);
  }
  if (media.indexOf('charset') >= 0) {
    res.set('Content-Type', media);
  } else {
    res.type(media);
  }
  res.status(200);
  res.send(body);
  log.debug("Leaving reportBytes().");
}

function reportChallenge(error: string): string {
  log.debug("Entering reportChallenge().");
  let challenge = 'DPoP realm="report-api"';
  if (error) {
    challenge = challenge + ', error="' + error + '"';
  }
  challenge = challenge + ', scope="' + SCOPE_CHALLENGE +
    '", algs="ES256 PS256 RS256 EdDSA"';
  log.debug("Leaving reportChallenge().");
  return challenge;
}

function reportUnauthenticated(res: any, code: string, error: string,
    description: string): void {
  log.debug("Entering reportUnauthenticated().");
  const status = 401;
  res.set('WWW-Authenticate', reportChallenge(error));
  reportSend(res, status, code, error || 'invalid_token', description);
  log.debug("Leaving reportUnauthenticated().");
}

function reportForbidden(res: any, code: string, error: string,
    description: string): void {
  log.debug("Entering reportForbidden().");
  reportSend(res, reportHttpStatus(code), code, error, description);
  log.debug("Leaving reportForbidden().");
}

function reportFailed(err: any, res: any): void {
  log.debug("Entering reportFailed().");
  log.error(errorCodes.tag('STS-REPORT-0024') +
    'report: ' + ((err && err.message) || err));
  if (!res.headersSent) {
    reportSend(res, 500, 'STS-REPORT-0024', 'unavailable',
      'The report could not be completed.');
  }
  log.debug("Leaving reportFailed().");
}

function reportRecord(info: any): void {
  log.debug("Entering reportRecord().");
  try {
    const audit = require('../common/audit');
    audit.record(info);
  } catch (err) {
    log.debug("Caught in reportRecord(): " +
      ((err && err.message) || err));
  }
  log.debug("Leaving reportRecord().");
}

function reportDetailOf(source: any, fields: any, jobId: any): any {
  log.debug("Entering reportDetailOf().");
  const detail = {
    source: source || null,
    fields: Array.isArray(fields) ? fields.slice() : [],
    job: jobId || null
  };
  log.debug("Leaving reportDetailOf().");
  return detail;
}

function reportQueryRefused(who: any, plan: any, code: string): void {
  log.debug("Entering reportQueryRefused().");
  reportRecord({
    category: 'admin',
    action: 'report.query',
    // error-code: none — the refusal's code is the caller's argument
    outcome: 'refused',
    errorCode: code,
    actor: who && who.username,
    summary: 'report query refused',
    detail: reportDetailOf(plan && plan.source, plan && plan.fields, null)
  });
  log.debug("Leaving reportQueryRefused().");
}

function reportQueryOk(who: any, plan: any, jobId: any): void {
  log.debug("Entering reportQueryOk().");
  reportRecord({
    category: 'admin',
    action: 'report.query',
    actor: who && who.username,
    summary: 'report query accepted',
    detail: reportDetailOf(plan && plan.source, plan && plan.fields, jobId)
  });
  log.debug("Leaving reportQueryOk().");
}

function reportRetrieveRefused(who: any, job: any, code: string): void {
  log.debug("Entering reportRetrieveRefused().");
  reportRecord({
    category: 'admin',
    action: 'report.job.retrieve',
    // error-code: none — the refusal's code is the caller's argument
    outcome: 'refused',
    errorCode: code,
    actor: who && who.username,
    summary: 'report result refused',
    detail: reportDetailOf(job && job.source, job && job.fields,
      job && job.id)
  });
  log.debug("Leaving reportRetrieveRefused().");
}

function reportRetrieveOk(who: any, job: any): void {
  log.debug("Entering reportRetrieveOk().");
  reportRecord({
    category: 'admin',
    action: 'report.job.retrieve',
    actor: who && who.username,
    summary: 'report result retrieved',
    detail: reportDetailOf(job && job.source, job && job.fields, job &&
      job.id)
  });
  log.debug("Leaving reportRetrieveOk().");
}

function reportApplyRefusal(res: any, who: any, result: any, plan: any,
    kind: string): void {
  log.debug("Entering reportApplyRefusal().");
  const code = String((result && result.code) || 'STS-REPORT-0004');
  if (kind === 'retrieve') {
    reportRetrieveRefused(who, plan, code);
  } else if (kind === 'query') {
    reportQueryRefused(who, plan, code);
  }
  reportSend(res, reportHttpStatus(code), code,
    (result && result.error) || 'invalid_query',
    (result && result.description) || 'The report was refused.');
  log.debug("Leaving reportApplyRefusal().");
}

function reportPosted(req: any): any {
  log.debug("Entering reportPosted().");
  const raw = req.body;
  if (raw == null || raw === '') {
    log.debug("Leaving reportPosted(). Empty.");
    return null;
  }
  let parsed: any = null;
  try {
    parsed = JSON.parse(String(raw));
  } catch (err) {
    log.debug("Caught in reportPosted(): " +
      ((err && err.message) || err));
    log.debug("Leaving reportPosted(). Not JSON.");
    return false;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    log.debug("Leaving reportPosted(). Not an object.");
    return false;
  }
  log.debug("Leaving reportPosted().");
  return parsed;
}

function reportDocumentOf(body: any): any {
  log.debug("Entering reportDocumentOf().");
  if (!body || typeof body !== 'object') {
    log.debug("Leaving reportDocumentOf(). None.");
    return null;
  }
  if (typeof body.source === 'string') {
    log.debug("Leaving reportDocumentOf(). Document.");
    return { document: body, parameters: null };
  }
  if (body.document && typeof body.document === 'object' &&
      !Array.isArray(body.document)) {
    const parameters = body.parameters &&
      typeof body.parameters === 'object' &&
      !Array.isArray(body.parameters) ? body.parameters : null;
    log.debug("Leaving reportDocumentOf(). Wrapper.");
    return { document: body.document, parameters: parameters };
  }
  log.debug("Leaving reportDocumentOf(). Unshaped.");
  return null;
}

function reportIdOk(id: string): boolean {
  log.debug("Entering reportIdOk().");
  const ok = /^[A-Za-z0-9_-]{1,64}$/.test(String(id || ''));
  log.debug("Leaving reportIdOk().");
  return ok;
}

function reportMergedParameters(stored: any, posted: any): any {
  log.debug("Entering reportMergedParameters().");
  const bag: any = {};
  let any = false;
  if (stored && typeof stored === 'object' && !Array.isArray(stored)) {
    Object.keys(stored).forEach(function (key: string): void {
      bag[key] = stored[key];
      any = true;
    });
  }
  if (posted && typeof posted === 'object' && !Array.isArray(posted)) {
    Object.keys(posted).forEach(function (key: string): void {
      bag[key] = posted[key];
      any = true;
    });
  }
  log.debug("Leaving reportMergedParameters().");
  return any ? bag : null;
}

function reportValidator(): any {
  log.debug("Entering reportValidator().");
  const made = new Query({
    catalog: new Catalog(),
    limits: new Limits()
  });
  log.debug("Leaving reportValidator().");
  return made;
}

function reportPublicSource(src: any): any {
  log.debug("Entering reportPublicSource().");
  const fields = (src.fields || []).map(function (field: any): any {
    return {
      id: field.id,
      type: field.type,
      meaning: field.meaning || '',
      filter: field.filter,
      sort: field.sort,
      group: field.group,
      operators: Catalog.operatorsFor(field.type),
      // The operators the store answers with an index (#985); the page and
      // the OpenAPI document show them, and `sources.ts` decides on them.
      indexed: Array.isArray(field.indexed) ? field.indexed.slice() : [],
      // Every value an enumerated field can hold (#1007), for the page's
      // dropdown; absent (dropped by JSON) for an open field.
      values: Array.isArray(field.values) ? field.values.slice() : undefined
    };
  });
  const out = {
    id: src.id,
    bounded: src.bounded,
    retention: src.retention,
    paging: src.paging || 'limit',
    relationships: Array.isArray(src.relationships) ?
      src.relationships.slice() : [],
    // A directory-backed source (rcbj, 2026-10-27): a filter has to name
    // an indexed field, and the page offers only those in a first row.
    anchored: src.anchored === true,
    fields: fields
  };
  log.debug("Leaving reportPublicSource().");
  return out;
}

function reportPresented(req: any): any {
  log.debug("Entering reportPresented().");
  const said = String((req.headers && req.headers.authorization) || '');
  const matched = /^(Bearer|DPoP)\s+(\S+)\s*$/i.exec(said);
  const out = matched ? {
    token: matched[2],
    scheme: matched[1].toLowerCase()
  } : { token: '', scheme: '' };
  log.debug("Leaving reportPresented().");
  return out;
}

// The browser sends `resource` as this realm's `/report-api`, with no
// trailing slash, and that is the audience the token carries. A client
// that instead asks for one of the API's permission identifiers is issued
// `aud` of `permissionBaseOf` of that URL, which adds the slash. Both name
// this API.
function reportAudienceOk(audiences: any, base: string): boolean {
  log.debug("Entering reportAudienceOk().");
  const exact = base + BASE;
  const withSlash = exact + '/';
  let ok = false;
  (Array.isArray(audiences) ? audiences : []).forEach(function (one: any) {
    const text = String(one);
    if (text === exact || text === withSlash) {
      ok = true;
    }
  });
  log.debug("Leaving reportAudienceOk(). " + ok);
  return ok;
}

function reportAuthenticate(req: any, res: any): any {
  log.debug("Entering reportAuthenticate().");
  const deps = reportDepsOf();
  const presentation = reportPresented(req);
  if (!presentation.token) {
    reportUnauthenticated(res, 'STS-REPORT-0006', 'invalid_token',
      'This API takes an OAuth 2.0 access token issued to sts-report, ' +
      'DPoP-bound, sent as Authorization: DPoP.');
    log.debug("Leaving reportAuthenticate(). No token.");
    return null;
  }
  let claims: any = null;
  let opaqueAccess = false;
  try {
    claims = deps.helpers.verifyOwnJws(presentation.token);
  } catch (err) {
    log.debug("Caught in reportAuthenticate(): " +
      ((err && err.message) || err));
    claims = null;
  }
  if (!claims && presentation.token.indexOf('.') < 0) {
    const found = deps.opaque.lookup(presentation.token);
    if (found.kind === 'active' ||
        (found.kind === 'inactive' && found.why === 'expired')) {
      claims = found.claims;
      opaqueAccess = true;
    } else if (found.kind === 'inactive' && found.why === 'revoked') {
      reportUnauthenticated(res, 'STS-REPORT-0012', 'invalid_token',
        'That access token has been revoked, or the account it was ' +
        'issued to is disabled.');
      log.debug("Leaving reportAuthenticate(). Revoked handle.");
      return null;
    } else if (found.kind === 'unknown' && deps.opaque.issuesOpaque()) {
      const limited = deps.opaque.noteMiss(req);
      if (limited) {
        res.set('Retry-After', String(limited.retryAfterS));
        reportSend(res, 429, 'STS-OAUTH-0983', 'invalid_token',
          'Too many attempts. Wait ' + limited.retryAfterS +
          ' seconds and try again.');
        log.debug("Leaving reportAuthenticate(). Too many handles.");
        return null;
      }
      reportUnauthenticated(res, 'STS-OAUTH-0980', 'invalid_token',
        'That access token is not valid.');
      log.debug("Leaving reportAuthenticate(). Unknown handle.");
      return null;
    }
  }
  if (!claims) {
    reportUnauthenticated(res, 'STS-REPORT-0007', 'invalid_token',
      'That access token was not issued by this realm, or its ' +
      'signature does not verify.');
    log.debug("Leaving reportAuthenticate(). Does not verify.");
    return null;
  }
  const now = Math.floor(Date.now() / 1000);
  if (claims.exp && Number(claims.exp) <= now) {
    reportUnauthenticated(res, 'STS-REPORT-0008', 'invalid_token',
      'That access token has expired.');
    log.debug("Leaving reportAuthenticate(). Expired.");
    return null;
  }
  if (!opaqueAccess) {
    const typ = deps.jwt.typOf(presentation.token);
    if (!deps.jwt.isAccessTokenType(typ)) {
      reportUnauthenticated(res, 'STS-REPORT-0009', 'invalid_token',
        'That token is not an access token.');
      log.debug("Leaving reportAuthenticate(). Not an access token.");
      return null;
    }
  }
  const base = deps.helpers.baseUrlOf(req);
  if (!deps.jwt.isHostedIssuer(claims.iss, base)) {
    reportUnauthenticated(res, 'STS-REPORT-0010', 'invalid_token',
      'That access token was issued by another authorization server.');
    log.debug("Leaving reportAuthenticate(). Another issuer.");
    return null;
  }
  const audiences = Array.isArray(claims.aud) ? claims.aud :
    (claims.aud === undefined || claims.aud === null ? [] : [claims.aud]);
  if (!reportAudienceOk(audiences, base)) {
    reportForbidden(res, 'STS-REPORT-0011', 'invalid_token',
      'That access token is not for this API.');
    log.debug("Leaving reportAuthenticate(). Another audience.");
    return null;
  }
  const person = String(claims.username ||
    deps.helpers.nameForSubject(claims.sub) || '');
  if ((claims.jti && deps.stats.isRevoked(String(claims.jti))) ||
      (person && deps.accountState.isDisabled(person))) {
    reportUnauthenticated(res, 'STS-REPORT-0012', 'invalid_token',
      'That access token has been revoked, or the account it was ' +
      'issued to is disabled.');
    log.debug("Leaving reportAuthenticate(). Revoked or disabled.");
    return null;
  }
  const sid = claims.jti ? String(deps.stats.sessionIdOfJti(
    String(claims.jti)) || '') : '';
  if (sid && !deps.oauth2.sessionIsLive(sid)) {
    reportUnauthenticated(res, 'STS-REPORT-0013', 'invalid_token',
      'That access token was issued on a sign-on session that has ' +
      'ended.');
    log.debug("Leaving reportAuthenticate(). Session ended.");
    return null;
  }
  const certificateProblem = deps.mtls.checkBinding(claims, req, true);
  if (certificateProblem) {
    reportUnauthenticated(res, 'STS-REPORT-0014', 'invalid_token',
      certificateProblem.description);
    log.debug("Leaving reportAuthenticate(). Certificate binding.");
    return null;
  }
  const boundJkt = deps.dpop.jktOf(claims);
  let proofOk = false;
  if (boundJkt) {
    if (presentation.scheme !== 'dpop') {
      reportUnauthenticated(res, 'STS-REPORT-0015', 'invalid_token',
        'That access token is DPoP-bound, so it must be sent as DPoP.');
      log.debug("Leaving reportAuthenticate(). Sent as Bearer.");
      return null;
    }
    const checked = deps.dpop.verifyProof(req.headers.dpop, {
      htm: req.method,
      htu: deps.dpop.htuOf(req),
      accessToken: presentation.token,
      expectedJkt: boundJkt,
      req: req
    });
    if (!checked.ok) {
      if (checked.needNonce) {
        res.set('DPoP-Nonce', deps.dpop.issueNonce());
        res.set('WWW-Authenticate', 'DPoP error="use_dpop_nonce"');
        reportSend(res, reportHttpStatus('STS-REPORT-0015'),
          checked.errorCode || 'STS-REPORT-0015', 'use_dpop_nonce',
          checked.description);
        log.debug("Leaving reportAuthenticate(). Nonce wanted.");
        return null;
      }
      reportUnauthenticated(res,
        checked.errorCode || 'STS-REPORT-0015', 'invalid_dpop_proof',
        checked.description);
      log.debug("Leaving reportAuthenticate(). Proof refused.");
      return null;
    }
    proofOk = true;
  }
  const issuedTo = String(claims.client_id || '');
  let entry: any = {};
  try {
    entry = deps.applications.clientConfigOf(issuedTo) || {};
  } catch (err) {
    log.debug("Caught in reportAuthenticate(): " +
      ((err && err.message) || err));
    entry = {};
  }
  const clientBound = deps.sender.dpopBoundPublicClient(issuedTo,
    entry.token_endpoint_auth_method);
  const thumb = deps.mtls.boundThumbprintOf(claims);
  const required = deps.sender.accessTokenRefusal({
    where: 'the report API',
    clientBound: clientBound,
    boundJkt: boundJkt,
    proofOk: proofOk,
    boundThumbprint: thumb,
    certificate: !!deps.mtls.peerCertificate(req),
    certificateMatches: !!thumb && deps.mtls.peerVerified(req) &&
      deps.mtls.presentedThumbprint(req) === thumb,
    mtlsAvailable: deps.mtls.available()
  });
  if (required) {
    reportUnauthenticated(res, required.errorCode, required.error,
      required.description);
    log.debug("Leaving reportAuthenticate(). Sender constraint.");
    return null;
  }
  // A CLIENT'S OWN TOKEN IS A CALLER SINCE #1030: an application holding
  // REPORT_USE or REPORT_ADMIN as a member is issued the scope on
  // client_credentials and reaches only what it defined, as the policy
  // decides. (STS-REPORT-0016 refused it until then.)
  if (!claims.sub) {
    reportForbidden(res, 'STS-REPORT-0017', 'forbidden',
      'That access token names no subject.');
    log.debug("Leaving reportAuthenticate(). No subject.");
    return null;
  }
  const carried = String(claims.scope || '').split(/\s+/).filter(
    function (part: string): boolean {
      return part.length > 0;
    });
  const wantsUse = carried.indexOf('report:use') >= 0;
  const wantsAdmin = carried.indexOf('report:admin') >= 0;
  if (!wantsUse && !wantsAdmin) {
    res.set('WWW-Authenticate',
      'DPoP error="insufficient_scope", scope="' + SCOPE_CHALLENGE + '"');
    reportForbidden(res, 'STS-REPORT-0017', 'insufficient_scope',
      'That access token does not carry report:use or report:admin.');
    log.debug("Leaving reportAuthenticate(). No report scope.");
    return null;
  }
  if ((wantsUse && !deps.scopes.declares(issuedTo, 'report:use')) ||
      (wantsAdmin && !deps.scopes.declares(issuedTo, 'report:admin'))) {
    reportForbidden(res, 'STS-REPORT-0017', 'forbidden',
      'The client this token was issued to no longer declares that ' +
      'report scope.');
    log.debug("Leaving reportAuthenticate(). Undeclared.");
    return null;
  }
  // HELD ∩ CARRIED (#1030), the management API's reading: the roles the
  // subject holds NOW in this realm, less any whose permission the token
  // does not carry. A role taken away after the token was minted refuses
  // the call at once.
  const caller = rights.callerOf(claims, carried);
  if (!caller.ok) {
    reportForbidden(res, caller.code, caller.error || 'forbidden',
      caller.description);
    log.debug("Leaving reportAuthenticate(). A role was withdrawn.");
    return null;
  }
  const who = caller.who;
  // AND THE POLICY, FOR THE API ITSELF: holding a report role, as the
  // access-control document's first rule reads it. Every definition and
  // job is asked about again, one row at a time, where it is reached.
  const policy = rights.mayReach(who, req.method);
  if (!policy.allowed) {
    log.info('report-api: the access policy refused ' + req.method + ' ' +
             (req.originalUrl || req.url) + ' for ' + who.username + '. ' +
             policy.why);
    reportForbidden(res, 'STS-REPORT-0044', 'forbidden',
      'The access policy refused this request. ' + policy.why +
      ' This token carries ' + (carried.join(', ') || '(none)') +
      ', which is the role(s) ' + (who.roles.length ? who.roles.join(', ')
                                                     : '(none)') +
      '. The report API needs REPORT_USE or REPORT_ADMIN; the document is ' +
      'on /admin/xacml and xacml.enforceAccess turns the layer off.');
    log.debug("Leaving reportAuthenticate(). The policy refused.");
    return null;
  }
  log.debug("Leaving reportAuthenticate().");
  return who;
}

function reportParts(req: any): string[] {
  log.debug("Entering reportParts().");
  const path = String(req.path || '');
  const at = path.indexOf(BASE);
  const rest = at >= 0 ? path.slice(at + BASE.length) : path;
  const parts = rest.split('/').filter(function (part: string): boolean {
    return part.length > 0;
  });
  log.debug("Leaving reportParts().");
  return parts;
}

function reportMethod(req: any): string {
  log.debug("Entering reportMethod().");
  const method = req.method === 'HEAD' ? 'GET' : String(req.method || '');
  log.debug("Leaving reportMethod().");
  return method;
}

function reportPageLimit(req: any): number {
  log.debug("Entering reportPageLimit().");
  let limit = 50;
  const raw = req.query ? req.query.limit : undefined;
  if (raw !== undefined && raw !== '') {
    const parsed = Number(raw);
    if (parsed >= 1 && parsed <= 200) {
      limit = parsed;
    } else if (parsed > 200) {
      limit = 200;
    }
  }
  log.debug("Leaving reportPageLimit().");
  return limit;
}

function reportMissingDefinition(res: any): void {
  log.debug("Entering reportMissingDefinition().");
  reportSend(res, reportHttpStatus('STS-REPORT-0019'), 'STS-REPORT-0019',
    'not_found', 'No such definition.');
  log.debug("Leaving reportMissingDefinition().");
}

function reportMissingJob(res: any, who: any, job: any): void {
  log.debug("Entering reportMissingJob().");
  reportRetrieveRefused(who, job, 'STS-REPORT-0020');
  reportSend(res, reportHttpStatus('STS-REPORT-0020'), 'STS-REPORT-0020',
    'job_not_found', 'No such job.');
  log.debug("Leaving reportMissingJob().");
}

function reportJobVisible(who: any, job: any): boolean {
  log.debug("Entering reportJobVisible().");
  if (!job) {
    log.debug("Leaving reportJobVisible(). None.");
    return false;
  }
  // THE POLICY DECIDES (#1030): the job's owner through the first rule, a
  // report administrator or a shared group's member — through the
  // definition the job ran — through the third.
  const definition = job.definitionId ?
    stores.getDefinition(job.definitionId) : null;
  const visible = rights.canSeeJob(who, job, definition);
  log.debug("Leaving reportJobVisible().");
  return visible;
}

// THE OWNER'S NAME (#986): a definition's `owner` is a subject
// (`urn:uuid:<entryUUID>`), which no reader can place. The page shows the
// person's display name, or their username, and keeps the subject beside
// it. The subject resolver (`helpers.nameForSubject()`, filled by the
// directory) gives the username; the entry gives `displayName` or `cn`.
// A subject that names nobody here — a deleted person, another realm's —
// is shown as it is. The directory is reached lazily: by request time it
// is loaded, and a load-time require of a JavaScript route module would
// move its routes (root CLAUDE.md, rule 1).
function reportOwnerName(owner: string): string {
  log.debug("Entering reportOwnerName().");
  const helpers = require('../common/helpers');
  const username = String(helpers.nameForSubject(owner) || '');
  if (!username) {
    log.debug("Leaving reportOwnerName(). Nobody.");
    return '';
  }
  let shown = username;
  const ldap = require('../ldap/ldap_server');
  const entry = typeof ldap.existingUserEntry === 'function' ?
    ldap.existingUserEntry(username) : null;
  const attrs = (entry && entry.attributes) || {};
  const first = function (name: string): string {
    const keys = Object.keys(attrs);
    for (let i = 0; i < keys.length; i++) {
      if (keys[i].toLowerCase() === name) {
        const value = attrs[keys[i]];
        return String((Array.isArray(value) ? value[0] : value) || '');
      }
    }
    return '';
  };
  shown = first('displayname') || first('cn') || username;
  log.debug("Leaving reportOwnerName().");
  return shown;
}

function reportDefinitionView(who: any, row: any): any {
  log.debug("Entering reportDefinitionView().");
  const editable = !!row && rights.canEdit(who, row);
  const view: any = {
    id: row.id,
    name: row.name,
    owner: row.owner,
    ownerName: reportOwnerName(String(row.owner || '')),
    schedule: row.schedule || '',
    scheduleEnabled: !!row.scheduleEnabled,
    // When the schedule next runs and which occurrence it last took, so
    // the page can tell "not due yet" from "skipped" (#989's follow-up).
    nextRunAt: jobs.scheduleTimes(row).nextRunAt,
    lastSlotAt: jobs.scheduleTimes(row).lastSlotAt,
    notify: !!row.notify,
    editable: editable,
    createdAt: jobs.iso(row.createdAt),
    modifiedAt: jobs.iso(row.modifiedAt)
  };
  if (editable) {
    view.document = stores.copy(row.document);
    view.parameters = row.parameters ? stores.copy(row.parameters) : null;
    view.groups = (row.groups || []).slice();
    view.failures = (row.failures || []).slice();
  }
  log.debug("Leaving reportDefinitionView().");
  return view;
}

function reportServeIndex(res: any): void {
  log.debug("Entering reportServeIndex().");
  reportJson(res, 200, {
    service: 'report',
    catalog: BASE + '/catalog',
    realms: BASE + '/realms',
    version: {
      version: APP_VERSION.version,
      stamped: APP_VERSION.stamped === true,
      buildInfo: APP_BUILD_INFO
    }
  });
  log.debug("Leaving reportServeIndex().");
}

// THE REALMS, FOR THE APPLICATION'S SWITCH (#986): the realm this token's
// request is in, and — where realms are active — every realm with its id,
// name and prefix, the rows the console's shell view carries for its own
// switcher (`admin-ui/admin.ts`, `shellJson()`). The names are what the
// realm chooser already shows an anonymous visitor, so a report token is
// not told anything the sign-in page does not say. With realms off the
// list is null and the application names the realm it is in.
function reportRealmsView(): any {
  log.debug("Entering reportRealmsView().");
  const realms = require('../common/realms');
  const current = realms.current() || {};
  const view = {
    current: {
      id: String(realms.currentId() || ''),
      name: String(current.name || ''),
      prefix: String(realms.currentPrefix() || '')
    },
    realms: realms.active()
      ? realms.list().map(function (one: any): any {
        return { id: one.id, name: one.name, prefix: realms.prefixOf(one) };
      })
      : null
  };
  log.debug("Leaving reportRealmsView().");
  return view;
}

// THE SCHEDULES (#992): every definition that carries a schedule, with what
// the definition page shows of it and its recent scheduled jobs. A
// report:use token sees the definitions it owns or is shared, as
// /definitions does; report:admin sees every one in the realm and may name
// one owner (`?owner=`, a subject or a username). A non-administrator who
// names an owner is refused rather than narrowed to their own, so the
// answer never quietly means something other than what was asked.
const SCHEDULES_PER = 20;
const SCHEDULES_PER_MAX = 100;
const SCHEDULE_JOBS_SHOWN = 5;

function reportOwnerAsked(asked: string): string {
  log.debug("Entering reportOwnerAsked().");
  const text = String(asked || '').trim();
  if (!text) {
    log.debug("Leaving reportOwnerAsked(). None.");
    return '';
  }
  if (/^urn:uuid:/i.test(text)) {
    log.debug("Leaving reportOwnerAsked(). A subject.");
    return text;
  }
  const helpers = require('../common/helpers');
  const subject = String(helpers.subjectForName(text) || '');
  log.debug("Leaving reportOwnerAsked(). " + (subject ? 'Resolved.' :
    'Unknown name.'));
  return subject || text;
}

function reportSchedulesView(who: any, query: any): any {
  log.debug("Entering reportSchedulesView().");
  const q = query || {};
  const admin = rights.isAdmin(who);
  const ownerAsked = reportOwnerAsked(q.owner);
  if (ownerAsked && !admin && ownerAsked !== who.subject) {
    log.debug("Leaving reportSchedulesView(). Another owner, refused.");
    return { ok: false, code: 'STS-REPORT-0038', error: 'forbidden',
      description: 'Only a realm administrator may list another ' +
        'account\'s schedules.' };
  }
  const rows = stores.listDefinitions().filter(function (row: any): boolean {
    if (!row.schedule) {
      return false;
    }
    if (ownerAsked && row.owner !== ownerAsked) {
      return false;
    }
    return rights.canSee(who, row);
  });
  rows.sort(function (left: any, right: any): number {
    return String(left.name).localeCompare(String(right.name));
  });
  const per = Math.min(SCHEDULES_PER_MAX, Math.max(1,
    Math.floor(Number(q.per) || SCHEDULES_PER)));
  const pages = Math.max(1, Math.ceil(rows.length / per));
  const page = Math.min(pages, Math.max(1, Math.floor(Number(q.page) || 1)));
  const allJobs = stores.listJobs();
  const schedules = rows.slice((page - 1) * per, page * per).map(
    function (row: any): any {
      const times = jobs.scheduleTimes(row);
      const own = allJobs.filter(function (job: any): boolean {
        return job.definitionId === row.id &&
          job.queuedBecause === 'schedule';
      });
      own.sort(function (a: any, b: any): number {
        return Number(b.submittedAt || 0) - Number(a.submittedAt || 0);
      });
      const notes = (Array.isArray(row.failures) ? row.failures : [])
        .slice(-3).reverse().map(function (note: any): any {
          return { at: jobs.iso(note && note.at),
                   description: String((note && note.description) || '') };
        });
      return {
        definition: {
          id: row.id,
          name: row.name,
          owner: row.owner,
          ownerName: reportOwnerName(String(row.owner || '')),
          schedule: row.schedule,
          scheduleEnabled: !!row.scheduleEnabled,
          notify: !!row.notify,
          nextRunAt: times.nextRunAt,
          lastSlotAt: times.lastSlotAt,
          failures: notes
        },
        jobs: own.slice(0, SCHEDULE_JOBS_SHOWN).map(function (job: any): any {
          return jobs.jobView(job, false);
        }),
        jobCount: own.length
      };
    });
  log.debug("Leaving reportSchedulesView(). " + rows.length + '.');
  return {
    ok: true,
    scope: admin ? 'realm' : 'mine',
    owner: ownerAsked || null,
    page: page,
    pages: pages,
    per: per,
    total: rows.length,
    schedules: schedules
  };
}

function reportServeSchedules(req: any, res: any, who: any): void {
  log.debug("Entering reportServeSchedules().");
  const view = reportSchedulesView(who, (req && req.query) || {});
  if (!view.ok) {
    reportSend(res, reportHttpStatus(view.code), view.code, view.error,
      view.description);
    log.debug("Leaving reportServeSchedules(). Refused.");
    return;
  }
  delete view.ok;
  reportJson(res, 200, view);
  log.debug("Leaving reportServeSchedules().");
}

// THE GROUP SEARCH (#989): the definition page's pane, five a page, over
// the realm's resident groups, each with its own address so the page can
// say which groups a notice could reach.
function reportServeGroups(req: any, res: any): void {
  log.debug("Entering reportServeGroups().");
  const query = (req && req.query) || {};
  reportJson(res, 200, sources.groupSearch(String(query.q || ''),
    Number(query.page || 1)));
  log.debug("Leaving reportServeGroups().");
}

function reportServeRealms(res: any): void {
  log.debug("Entering reportServeRealms().");
  reportJson(res, 200, reportRealmsView());
  log.debug("Leaving reportServeRealms().");
}

function reportServeOpenApi(res: any): void {
  log.debug("Entering reportServeOpenApi().");
  // The catalog is the field reference. This document names the routes
  // and points at it, so a new field is not written twice.
  reportJson(res, 200, OpenApi.document(new Catalog()));
  log.debug("Leaving reportServeOpenApi().");
}

function reportServeCatalog(res: any): void {
  log.debug("Entering reportServeCatalog().");
  const catalog = new Catalog();
  reportJson(res, 200, {
    sources: catalog.list().map(reportPublicSource)
  });
  log.debug("Leaving reportServeCatalog().");
}

function reportServeSource(res: any, id: string): void {
  log.debug("Entering reportServeSource().");
  const catalog = new Catalog();
  const src = catalog.source(id);
  if (!src) {
    reportSend(res, reportHttpStatus('STS-REPORT-0001'),
      'STS-REPORT-0001', 'unknown_source', 'No such source.');
    log.debug("Leaving reportServeSource(). None.");
    return;
  }
  reportJson(res, 200, { source: reportPublicSource(src) });
  log.debug("Leaving reportServeSource().");
}

async function reportAcceptQuery(req: any, res: any, who: any,
    forceAsync: boolean, definition: any, because?: string): Promise<void> {
  log.debug("Entering reportAcceptQuery().");
  const posted = reportPosted(req);
  if (posted === false) {
    reportQueryRefused(who, null, 'STS-REPORT-0004');
    reportSend(res, reportHttpStatus('STS-REPORT-0004'),
      'STS-REPORT-0004', 'invalid_query',
      'The query body is not a JSON object.');
    log.debug("Leaving reportAcceptQuery(). Bad JSON.");
    return;
  }
  const wrapped = definition ? {
    document: stores.copy(definition.document),
    parameters: reportMergedParameters(definition.parameters, posted)
  } : reportDocumentOf(posted);
  if (!wrapped) {
    reportQueryRefused(who, null, 'STS-REPORT-0004');
    reportSend(res, reportHttpStatus('STS-REPORT-0004'),
      'STS-REPORT-0004', 'invalid_query',
      'The query body does not name a source.');
    log.debug("Leaving reportAcceptQuery(). Unshaped.");
    return;
  }
  const document = stores.copy(wrapped.document);
  if (forceAsync) {
    document.mode = 'async';
  }
  const validated = reportValidator().validate(document,
    wrapped.parameters);
  if (!validated.ok) {
    reportApplyRefusal(res, who, validated, null, 'query');
    log.debug("Leaving reportAcceptQuery(). Refused.");
    return;
  }
  const plan = validated.plan;
  if (plan.execution === 'sync' && !forceAsync) {
    const limits = new Limits();
    const control = {
      startedMs: Date.now(),
      budgetMs: limits.syncMaxMs(),
      execution: 'sync',
      cancelled: function (): boolean {
        return false;
      },
      stillOwner: function (): boolean {
        return true;
      }
    };
    const read = await sources.reportGateOne('read', plan, control);
    if (read && !read.ok && read.unbounded && plan.mode === 'auto' &&
        !forceAsync) {
      // THE READER REFUSED TO SCAN A WINDOWED DIRECTORY SYNCHRONOUSLY
      // (#985), and `auto` means "a job when it cannot be answered now":
      // the same document is accepted again as a job, under the job's
      // caps. Nothing is recorded as refused. `mode: sync` keeps the
      // refusal, which names the fields the store can filter on.
      log.info(errorCodes.tag(read.code) + 'report: an auto-mode query ' +
        'would read every person synchronously; queued as a job instead.');
      await reportAcceptQuery(req, res, who, true, definition,
        'every-person');
      log.debug("Leaving reportAcceptQuery(). Auto became a job.");
      return;
    }
    if (!read || !read.ok) {
      if (read && read.code) {
        reportApplyRefusal(res, who, read, plan, 'query');
      } else {
        const lostStatus = 409;
        reportQueryRefused(who, plan, 'STS-REPORT-0024');
        reportSend(res, lostStatus, 'STS-REPORT-0024', 'unavailable',
          'The report could not be read.');
      }
      log.debug("Leaving reportAcceptQuery(). Not read.");
      return;
    }
    const realms = require('../common/realms');
    const finished = executor.finish(plan, read.rows, limits, {
      realm: String(realms.currentId() || ''),
      when: new Date().toISOString()
    });
    if (!finished.ok) {
      reportApplyRefusal(res, who, finished, plan, 'query');
      log.debug("Leaving reportAcceptQuery(). Not rendered.");
      return;
    }
    reportQueryOk(who, plan, null);
    reportBytes(res, finished.media, finished.body, '');
    log.debug("Leaving reportAcceptQuery(). Sync.");
    return;
  }
  // Why this is a job, for the job page (#986): what the caller said, or
  // read off the plan — the mode asked for a job, the source cannot be
  // read now, or the limit is above the synchronous cap.
  let why = because || '';
  if (!why) {
    const src = reportValidator().catalog.source(plan.source);
    if (plan.mode === 'async') {
      why = 'asked';
    } else if (src && src.bounded === false) {
      why = 'source';
    } else {
      why = 'limit';
    }
  }
  const submitted = jobs.submit({
    owner: who.subject,
    ownerKind: who.kind,
    document: document,
    parameters: wrapped.parameters,
    definitionId: definition ? definition.id : null,
    definitionName: definition ? definition.name : null,
    notify: false,
    because: why,
    plan: plan
  });
  if (!submitted.ok) {
    reportApplyRefusal(res, who, submitted, plan, 'query');
    log.debug("Leaving reportAcceptQuery(). Not queued.");
    return;
  }
  reportQueryOk(who, plan, submitted.job.id);
  const accepted = 202;
  reportJson(res, accepted, { job: jobs.jobView(submitted.job, false) });
  log.debug("Leaving reportAcceptQuery(). Queued.");
}

// NUMBERED PAGES ON THE TWO LISTS (#997), the console's pattern: `page` and
// `per` (at most 200, 50 unless asked) in the query, and `page`, `pages`,
// `per` and `total` beside the rows, so the application draws the pager
// the console draws. The jobs list keeps its cursor (`after`, `limit`) for
// a caller that pages that way.
const LIST_PER = 50;
const LIST_PER_MAX = 200;

function reportPaging(query: any, rowCount: number): any {
  log.debug("Entering reportPaging().");
  const q = query || {};
  const asked = Number(q.per !== undefined && q.per !== '' ? q.per :
    q.limit);
  const per = Math.min(LIST_PER_MAX, Math.max(1,
    Math.floor(asked > 0 ? asked : LIST_PER)));
  const pages = Math.max(1, Math.ceil(rowCount / per));
  const page = Math.min(pages, Math.max(1, Math.floor(Number(q.page) || 1)));
  log.debug("Leaving reportPaging().");
  return { page: page, pages: pages, per: per, total: rowCount,
           from: (page - 1) * per, to: page * per };
}

function reportDefinitionsView(who: any, query: any): any {
  log.debug("Entering reportDefinitionsView().");
  const rows = stores.listDefinitions().filter(function (row: any):
      boolean {
    return rights.canSee(who, row);
  });
  rows.sort(function (left: any, right: any): number {
    return String(left.name).localeCompare(String(right.name));
  });
  const pg = reportPaging(query, rows.length);
  const view = {
    definitions: rows.slice(pg.from, pg.to).map(function (row: any): any {
      return reportDefinitionView(who, row);
    }),
    page: pg.page,
    pages: pg.pages,
    per: pg.per,
    total: pg.total
  };
  log.debug("Leaving reportDefinitionsView().");
  return view;
}

function reportServeDefinitions(req: any, res: any, who: any): void {
  log.debug("Entering reportServeDefinitions().");
  reportJson(res, 200, reportDefinitionsView(who, (req && req.query) || {}));
  log.debug("Leaving reportServeDefinitions().");
}

function reportCreateDefinition(req: any, res: any, who: any,
    id: string): void {
  log.debug("Entering reportCreateDefinition().");
  const posted = reportPosted(req);
  if (posted === false || !posted) {
    reportSend(res, reportHttpStatus('STS-REPORT-0030'),
      'STS-REPORT-0030', 'invalid_query',
      'A definition is a JSON object.');
    log.debug("Leaving reportCreateDefinition(). Bad body.");
    return;
  }
  if (id) {
    const existing = stores.getDefinition(id);
    if (!existing || !rights.canEdit(who, existing)) {
      reportMissingDefinition(res);
      log.debug("Leaving reportCreateDefinition(). Not editable.");
      return;
    }
  }
  const saved = jobs.save({
    id: id || null,
    name: posted.name,
    owner: who.subject,
    ownerKind: who.kind,
    document: posted.document,
    schedule: posted.schedule,
    scheduleEnabled: posted.scheduleEnabled,
    notify: posted.notify,
    parameters: posted.parameters
  });
  if (!saved.ok) {
    reportApplyRefusal(res, who, saved, null, '');
    log.debug("Leaving reportCreateDefinition(). Refused.");
    return;
  }
  reportJson(res, 200, {
    definition: reportDefinitionView(who, saved.definition)
  });
  log.debug("Leaving reportCreateDefinition().");
}

function reportServeDefinition(res: any, who: any, id: string): void {
  log.debug("Entering reportServeDefinition().");
  const row = reportIdOk(id) ? stores.getDefinition(id) : null;
  if (!row || !rights.canSee(who, row)) {
    reportMissingDefinition(res);
    log.debug("Leaving reportServeDefinition(). Hidden.");
    return;
  }
  reportJson(res, 200, { definition: reportDefinitionView(who, row) });
  log.debug("Leaving reportServeDefinition().");
}

function reportDeleteDefinition(res: any, who: any, id: string): void {
  log.debug("Entering reportDeleteDefinition().");
  const row = reportIdOk(id) ? stores.getDefinition(id) : null;
  if (!row || !rights.canEdit(who, row)) {
    reportMissingDefinition(res);
    log.debug("Leaving reportDeleteDefinition(). Hidden.");
    return;
  }
  const removed = jobs.remove(id, who.subject);
  if (!removed.ok) {
    reportApplyRefusal(res, who, removed, null, '');
    log.debug("Leaving reportDeleteDefinition(). Refused.");
    return;
  }
  reportJson(res, 200, { deleted: id });
  log.debug("Leaving reportDeleteDefinition().");
}

function reportSharePosted(req: any, res: any, who: any, id: string):
    void {
  log.debug("Entering reportSharePosted().");
  const row = reportIdOk(id) ? stores.getDefinition(id) : null;
  if (!row || !rights.canEdit(who, row)) {
    reportMissingDefinition(res);
    log.debug("Leaving reportSharePosted(). Hidden.");
    return;
  }
  const posted = reportPosted(req);
  if (posted === false || !posted || !Array.isArray(posted.groups)) {
    reportSend(res, reportHttpStatus('STS-REPORT-0031'),
      'STS-REPORT-0031', 'invalid_query',
      'Name the groups to share this definition with.');
    log.debug("Leaving reportSharePosted(). Bad body.");
    return;
  }
  const shared = jobs.share({
    id: id,
    groups: posted.groups,
    actor: who.subject
  });
  if (!shared.ok) {
    reportApplyRefusal(res, who, shared, null, '');
    log.debug("Leaving reportSharePosted(). Refused.");
    return;
  }
  reportJson(res, 200, {
    definition: reportDefinitionView(who, shared.definition)
  });
  log.debug("Leaving reportSharePosted().");
}

async function reportRunSaved(req: any, res: any, who: any,
    id: string): Promise<void> {
  log.debug("Entering reportRunSaved().");
  const row = reportIdOk(id) ? stores.getDefinition(id) : null;
  // `run`, the act a share grants beside reading (#1030).
  if (!row || !rights.canRun(who, row)) {
    reportMissingDefinition(res);
    log.debug("Leaving reportRunSaved(). Hidden.");
    return;
  }
  const posted = reportPosted(req);
  if (posted === false) {
    reportSend(res, reportHttpStatus('STS-REPORT-0004'),
      'STS-REPORT-0004', 'invalid_query',
      'The query body is not a JSON object.');
    log.debug("Leaving reportRunSaved(). Bad JSON.");
    return;
  }
  await reportAcceptQuery(req, res, who, true, row, 'run');
  log.debug("Leaving reportRunSaved().");
}

function reportJobsView(who: any, query: any): any {
  log.debug("Entering reportJobsView().");
  const q = query || {};
  const rows = stores.listJobs().filter(function (job: any): boolean {
    return reportJobVisible(who, job);
  });
  rows.sort(function (left: any, right: any): number {
    return Number(right.submittedAt) - Number(left.submittedAt);
  });
  const after = typeof q.after === 'string' ? q.after : '';
  if (after) {
    // THE CURSOR, kept for a caller that pages by id (#956's shape).
    let start = 0;
    for (let i = 0; i < rows.length; i++) {
      if (rows[i].id === after) {
        start = i + 1;
      }
    }
    const limit = reportPageLimit({ query: q });
    const slice = rows.slice(start, start + limit);
    const more = start + slice.length < rows.length;
    log.debug("Leaving reportJobsView(). By cursor.");
    return {
      jobs: slice.map(function (job: any): any {
        return jobs.jobView(job, false);
      }),
      next: more && slice.length ? slice[slice.length - 1].id : null,
      total: rows.length
    };
  }
  const pg = reportPaging(q, rows.length);
  const slice = rows.slice(pg.from, pg.to);
  const view = {
    jobs: slice.map(function (job: any): any {
      return jobs.jobView(job, false);
    }),
    // `next` is kept for a caller that mixes the two: the last id of this
    // page, or null on the last page.
    next: pg.page < pg.pages && slice.length ? slice[slice.length - 1].id :
      null,
    page: pg.page,
    pages: pg.pages,
    per: pg.per,
    total: pg.total
  };
  log.debug("Leaving reportJobsView().");
  return view;
}

function reportServeJobs(req: any, res: any, who: any): void {
  log.debug("Entering reportServeJobs().");
  reportJson(res, 200, reportJobsView(who, (req && req.query) || {}));
  log.debug("Leaving reportServeJobs().");
}

function reportServeJob(res: any, who: any, id: string): void {
  log.debug("Entering reportServeJob().");
  const job = reportIdOk(id) ? stores.getJob(id) : null;
  if (!reportJobVisible(who, job)) {
    reportMissingJob(res, who, job);
    log.debug("Leaving reportServeJob(). Hidden.");
    return;
  }
  // Everything about the job for whoever may stop it — its owner or a
  // report administrator — as the policy decides (#1030).
  const full = rights.canEdit(who, { kind: 'job', owner: job.owner });
  reportJson(res, 200, { job: jobs.jobView(job, full) });
  log.debug("Leaving reportServeJob().");
}

function reportStopPosted(res: any, who: any, id: string): void {
  log.debug("Entering reportStopPosted().");
  const job = reportIdOk(id) ? stores.getJob(id) : null;
  if (!reportJobVisible(who, job)) {
    reportMissingJob(res, who, job);
    log.debug("Leaving reportStopPosted(). Hidden.");
    return;
  }
  const stopped = jobs.cancel(job, who.subject);
  if (!stopped.ok) {
    reportApplyRefusal(res, who, stopped, job, 'retrieve');
    log.debug("Leaving reportStopPosted(). Refused.");
    return;
  }
  reportJson(res, 200, { job: jobs.jobView(stopped.job, false) });
  log.debug("Leaving reportStopPosted().");
}

function reportExtent(format: string): string {
  log.debug("Entering reportExtent().");
  let ext = 'json';
  if (format === 'csv' || format === 'pdf') {
    ext = format;
  }
  log.debug("Leaving reportExtent().");
  return ext;
}

async function reportServeResult(res: any, who: any, id: string):
    Promise<void> {
  log.debug("Entering reportServeResult().");
  const job = reportIdOk(id) ? stores.getJob(id) : null;
  if (!reportJobVisible(who, job)) {
    reportMissingJob(res, who, job);
    log.debug("Leaving reportServeResult(). Hidden.");
    return;
  }
  if (job.status === 'expired') {
    reportRetrieveRefused(who, job, 'STS-REPORT-0022');
    reportSend(res, reportHttpStatus('STS-REPORT-0022'),
      'STS-REPORT-0022', 'result_expired',
      'That result has expired.');
    log.debug("Leaving reportServeResult(). Expired.");
    return;
  }
  if (job.status !== 'completed') {
    reportRetrieveRefused(who, job, 'STS-REPORT-0021');
    reportSend(res, reportHttpStatus('STS-REPORT-0021'),
      'STS-REPORT-0021', 'job_not_ready',
      'That result is not ready.');
    log.debug("Leaving reportServeResult(). Not ready.");
    return;
  }
  const artifact = await stores.getArtifact(job.id);
  const crypto = require('../common/crypto');
  const digest = artifact && artifact.bytes ?
    crypto.digest('sha256', artifact.bytes, 'hex') : '';
  if (!artifact || !artifact.bytes || !job.sha256 ||
      digest !== job.sha256) {
    reportRetrieveRefused(who, job, 'STS-REPORT-0029');
    reportSend(res, reportHttpStatus('STS-REPORT-0029'),
      'STS-REPORT-0029', 'result_expired',
      'That result is no longer available.');
    log.debug("Leaving reportServeResult(). Missing.");
    return;
  }
  reportRetrieveOk(who, job);
  const media = job.mediaType || executor.mediaOf(job.format);
  reportBytes(res, media, artifact.bytes,
    'attachment; filename="report.' + reportExtent(job.format) + '"');
  log.debug("Leaving reportServeResult().");
}

async function reportRoute(req: any, res: any, who: any): Promise<void> {
  log.debug("Entering reportRoute().");
  const method = reportMethod(req);
  const parts = reportParts(req);
  const a = parts[0] || '';
  const b = parts[1] || '';
  const c = parts[2] || '';
  if (!a && method === 'GET') {
    reportServeIndex(res);
  } else if (a === 'openapi.json' && !b && method === 'GET') {
    reportServeOpenApi(res);
  } else if (a === 'catalog' && !b && method === 'GET') {
    reportServeCatalog(res);
  } else if (a === 'catalog' && b && !c && method === 'GET') {
    reportServeSource(res, b);
  } else if (a === 'realms' && !b && method === 'GET') {
    reportServeRealms(res);
  } else if (a === 'groups' && !b && method === 'GET') {
    reportServeGroups(req, res);
  } else if (a === 'schedules' && !b && method === 'GET') {
    reportServeSchedules(req, res, who);
  } else if (a === 'queries' && !b && method === 'POST') {
    await reportAcceptQuery(req, res, who, false, null);
  } else if (a === 'definitions' && !b && method === 'GET') {
    reportServeDefinitions(req, res, who);
  } else if (a === 'definitions' && !b && method === 'POST') {
    reportCreateDefinition(req, res, who, '');
  } else if (a === 'definitions' && b && c === 'share' &&
      method === 'POST') {
    reportSharePosted(req, res, who, b);
  } else if (a === 'definitions' && b && c === 'run' &&
      method === 'POST') {
    await reportRunSaved(req, res, who, b);
  } else if (a === 'definitions' && b && !c && method === 'GET') {
    reportServeDefinition(res, who, b);
  } else if (a === 'definitions' && b && !c && method === 'POST') {
    reportCreateDefinition(req, res, who, b);
  } else if (a === 'definitions' && b && !c && method === 'DELETE') {
    reportDeleteDefinition(res, who, b);
  } else if (a === 'jobs' && !b && method === 'GET') {
    reportServeJobs(req, res, who);
  } else if (a === 'jobs' && !b && method === 'POST') {
    await reportAcceptQuery(req, res, who, true, null);
  } else if (a === 'jobs' && b && c === 'cancel' && method === 'POST') {
    reportStopPosted(res, who, b);
  } else if (a === 'jobs' && b && c === 'result' && method === 'GET') {
    await reportServeResult(res, who, b);
  } else if (a === 'jobs' && b && !c && method === 'GET') {
    reportServeJob(res, who, b);
  } else {
    reportMissingJob(res, who, null);
  }
  log.debug("Leaving reportRoute().");
}

async function reportRun(req: any, res: any): Promise<void> {
  log.debug("Entering reportRun().");
  try {
    const who = reportAuthenticate(req, res);
    if (who) {
      await reportRoute(req, res, who);
    }
  } catch (err) {
    log.debug("Caught in reportRun(): " + ((err && err.message) || err));
    reportFailed(err, res);
  }
  log.debug("Leaving reportRun().");
}

function reportPerform(req: any, res: any): void {
  log.debug("Entering reportPerform().");
  reportRun(req, res).then(function (): void {
    return undefined;
  }, function (err: any): void {
    reportFailed(err, res);
  });
  log.debug("Leaving reportPerform().");
}

function reportAnswer(req: any, res: any): void {
  log.debug("Entering reportAnswer().");
  reportDispatch(req, res);
  log.debug("Leaving reportAnswer().");
}

function reportDispatch(req: any, res: any): void {
  log.debug("Entering reportDispatch().");
  reportAuthOne(req, res);
  log.debug("Leaving reportDispatch().");
}

function reportAuthOne(req: any, res: any): void {
  log.debug("Entering reportAuthOne().");
  reportAuthTwo(req, res);
  log.debug("Leaving reportAuthOne().");
}

function reportAuthTwo(req: any, res: any): void {
  log.debug("Entering reportAuthTwo().");
  reportAuthThree(req, res);
  log.debug("Leaving reportAuthTwo().");
}

function reportAuthThree(req: any, res: any): void {
  log.debug("Entering reportAuthThree().");
  reportAuthFour(req, res);
  log.debug("Leaving reportAuthThree().");
}

function reportAuthFour(req: any, res: any): void {
  log.debug("Entering reportAuthFour().");
  reportAuthFive(req, res);
  log.debug("Leaving reportAuthFour().");
}

function reportAuthFive(req: any, res: any): void {
  log.debug("Entering reportAuthFive().");
  reportWorkFive(req, res);
  log.debug("Leaving reportAuthFive().");
}

function reportWorkFive(req: any, res: any): void {
  log.debug("Entering reportWorkFive().");
  reportPerform(req, res);
  log.debug("Leaving reportWorkFive().");
}

/**
 * The report API. Routes register on the shared application and answer
 * only through the pad above.
 */
class ReportApi {
  /**
   * Registers every report API route. Each callback only calls
   * `reportAnswer`, which is what keeps the directory walk outside.
   *
   * @param app - the shared express application
   * @returns nothing
   */
  registerRoutes(app: any): void {
    log.debug("Entering registerRoutes().");
    app.get(BASE, function (req: any, res: any): void {
      reportAnswer(req, res);
    });
    app.get(BASE + '/openapi.json', function (req: any, res: any): void {
      reportAnswer(req, res);
    });
    app.get(BASE + '/catalog', function (req: any, res: any): void {
      reportAnswer(req, res);
    });
    app.get(BASE + '/catalog/:id', function (req: any, res: any): void {
      reportAnswer(req, res);
    });
    app.get(BASE + '/realms', function (req: any, res: any): void {
      reportAnswer(req, res);
    });
    app.get(BASE + '/groups', function (req: any, res: any): void {
      reportAnswer(req, res);
    });
    app.get(BASE + '/schedules', function (req: any, res: any): void {
      reportAnswer(req, res);
    });
    app.post(BASE + '/queries', function (req: any, res: any): void {
      reportAnswer(req, res);
    });
    app.get(BASE + '/definitions', function (req: any, res: any): void {
      reportAnswer(req, res);
    });
    app.post(BASE + '/definitions', function (req: any, res: any): void {
      reportAnswer(req, res);
    });
    app.post(BASE + '/definitions/:id/share',
      function (req: any, res: any): void {
        reportAnswer(req, res);
      });
    app.post(BASE + '/definitions/:id/run',
      function (req: any, res: any): void {
        reportAnswer(req, res);
      });
    app.get(BASE + '/definitions/:id',
      function (req: any, res: any): void {
        reportAnswer(req, res);
      });
    app.post(BASE + '/definitions/:id',
      function (req: any, res: any): void {
        reportAnswer(req, res);
      });
    app.delete(BASE + '/definitions/:id',
      function (req: any, res: any): void {
        reportAnswer(req, res);
      });
    app.get(BASE + '/jobs', function (req: any, res: any): void {
      reportAnswer(req, res);
    });
    app.post(BASE + '/jobs', function (req: any, res: any): void {
      reportAnswer(req, res);
    });
    app.post(BASE + '/jobs/:id/cancel',
      function (req: any, res: any): void {
        reportAnswer(req, res);
      });
    app.get(BASE + '/jobs/:id/result',
      function (req: any, res: any): void {
        reportAnswer(req, res);
      });
    app.get(BASE + '/jobs/:id', function (req: any, res: any): void {
      reportAnswer(req, res);
    });
    log.debug("Leaving registerRoutes().");
  }
}

const reportApi = new ReportApi();

export = {
  registerRoutes: function (app: any): void {
    reportApi.registerRoutes(app);
  },
  realmsView: reportRealmsView,
  // A source as the API publishes it, for the test of its `values` (#1007).
  publicSource: reportPublicSource,
  ownerName: reportOwnerName,
  schedulesView: reportSchedulesView,
  definitionsView: reportDefinitionsView,
  jobsView: reportJobsView,
  ReportApi: ReportApi
};
