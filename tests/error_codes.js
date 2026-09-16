'use strict';
//
// File: error_codes.js
//
// ===========================================================================
// THE ERROR CODES STAY COMPLETE, CURRENT AND OFF THE WIRE.
//
// `common/error_codes.js` is a table of every failure condition this service
// can produce. A table like that is worth exactly as much as its coverage, and
// every way it loses coverage is SILENT: a new refusal with no code still
// refuses correctly, a code whose row was deleted still records, a page of
// documentation that lags the table still renders. So this file makes each of
// those a failure of the build:
//
//   1. the table is well formed — every code shaped `STS-<SUB>-<NNNN>`, in a
//      subsystem that exists, with a summary, unique, and in order;
//   2. every code the source uses is registered, and every registered code is
//      used somewhere (a row nothing raises is documentation of a condition
//      that cannot happen);
//   3. docs/error-codes.md is exactly what the table generates;
//   4. **every failure-shaped call site has a code beside it** — the patterns
//      are FAILURE_PATTERNS below, and this is the check that makes "future
//      failures get a code" a property of the build rather than of memory;
//   5. no code reaches a client: a marked response carries no trace of the
//      code in its status line, headers or body, and no source line puts a
//      code literal into a response-writing call.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, which is the question tests/CLAUDE.md asks first: three of
// the five claims are properties of the SOURCE TREE, which no endpoint reports,
// and the fifth is asserted against the funnel directly so that the response
// being inspected is one this file wrote rather than one a protocol handler
// happened to produce.
//
// ---------------------------------------------------------------------------
// THE EXEMPTION, and why it needs a reason.
//
// A line matching a failure pattern that is not a failure — a helper's own
// definition, a 401 challenge that is step one of a successful handshake, a
// status in a table of examples — carries
//
//     // error-code: none — <why>
//
// on the same line or up to two lines above. The reason is required and is
// checked for: an exemption with no reason is a failure site somebody did not
// want to think about, which is the population this check exists to catch.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const http = require('http');

const errorCodes = require('../common/error_codes');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'error_codes',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// WHAT IS SCANNED.
//
// First-party service source. NOT scanned, each for a stated reason:
//   node_modules, node-ldapjs      somebody else's code
//   common/vendored, the Kerberos  byte-identical copies of the parent
//     codec modules                project's files, not editable here
//   tests                          assertions, not failures this service raises
//   docs                           prose
//   openbao                        a separate container's seed scripts, not
//                                  a service that fails at runtime
//
// `xacml-pep/` IS SCANNED although it is a separate container: its failures
// are operator-facing like the mock's, and its codes are in the one table (the
// XPEP subsystem). Its Dockerfile copies common/error_codes.js to the image
// root, which tests/xacml_pep.js pins.
//   xacml/conformance              the vendored OASIS suite's manifest
//   env                            the appconfig files and the generated
//                                  defaults.js
//   debugger/embedded              the debugger project's BUILD OUTPUT, its
//                                  node_modules included; gitignored, and its
//                                  codes are that project's business
//   protos                         SPIFFE's vendored protocol definitions
//   .git, coverage                 not source
//   .claude                        Claude Code's state, and its AGENT
//                                  WORKTREES — a second checkout of this
//                                  repository whose files are not this one's
//                                  (2026-09-16; .dockerignore says the same)
// ---------------------------------------------------------------------------
const SKIP_DIRS = ['node_modules', 'node-ldapjs', 'tests', 'docs',
                   'openbao', 'env', '.git', 'coverage', 'protos',
                   '.claude'];

const SKIP_PATHS = ['common/vendored', 'xacml/conformance',
                    'debugger/embedded'];

// kerberos/CLAUDE.md: the eight codec modules are vendored from the parent
// project and not editable here, despite not living under common/vendored.
const VENDORED_FILES = ['kerberos/krb5_asn1.js', 'kerberos/krb5_crypto.js',
                        'kerberos/krb5_gss.js', 'kerberos/krb5_messages.js',
                        'kerberos/krb5_ndr.js', 'kerberos/krb5_pac.js',
                        'kerberos/krb5_primitives.js',
                        'kerberos/krb5_spnego.js'];

function sourceFiles() {
  log.debug("Entering sourceFiles().");
  const out = [];
  function walk(dir) {
    log.debug("Entering walk().");
    fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
      const full = path.join(dir, entry.name);
      const rel = path.relative(ROOT, full).split(path.sep).join('/');
      if (entry.isDirectory()) {
        if (SKIP_DIRS.indexOf(entry.name) >= 0) return;
        if (SKIP_PATHS.indexOf(rel) >= 0) return;
        walk(full);
        return;
      }
      if (!/\.js$/.test(entry.name)) return;
      if (VENDORED_FILES.indexOf(rel) >= 0) return;
      out.push(rel);
    });
    log.debug("Leaving walk().");
  }
  walk(ROOT);
  log.debug("Leaving sourceFiles().");
  return out.sort();
}

// ---------------------------------------------------------------------------
// FAILURE_PATTERNS — the shapes a refusal or a failure takes in this source.
//
// Each carries the lines around a match in which a code must appear: `before`
// lines above and `after` below. Most are tight, because `mark()` is written
// immediately before the call it describes; the audit-object patterns are wider
// because `errorCode:` is one member of an object literal that can span a dozen
// lines.
//
// ADDING A FAILURE HELPER MEANS ADDING ITS SHAPE HERE. A new protocol family
// with a `fooError(res, …)` of its own would otherwise be invisible to check 4,
// which is the one gap this list cannot close by itself.
// ---------------------------------------------------------------------------
const FAILURE_PATTERNS = [
  // ----- HTTP, generic -----------------------------------------------------
  { re: /\.status\(\s*[45]\d\d\b/, before: 4, after: 2,
    what: 'an HTTP status of 400 or above' },
  { re: /\bsendStatus\(\s*[45]\d\d\b/, before: 4, after: 2,
    what: 'sendStatus with a failure status' },
  { re: /\bwriteHead\(\s*[45]\d\d\b/, before: 4, after: 2,
    what: 'writeHead with a failure status' },
  { re: /\b(?:oauthError|vciError|samlError|wsfedError)\(/, before: 4, after: 2,
    what: 'a protocol error helper' },
  { re: /\bsendJson\(\s*[A-Za-z_.]+\s*,\s*[45]\d\d\b/, before: 4, after: 2,
    what: 'sendJson with a failure status' },
  // ----- the audit log ------------------------------------------------------
  { re: /outcome:\s*['"](?:refused|error)['"]/, before: 12, after: 12,
    what: 'an audit row recording a refusal or an error' },
  // ----- the log ------------------------------------------------------------
  { re: /\blog\.error\(/, before: 3, after: 3,
    what: 'an error logged' },
  // ----- LDAP ---------------------------------------------------------------
  { re: /new\s+ldap\.[A-Za-z]+Error\(/, before: 6, after: 2,
    what: 'an LDAP result code other than success' },
  // SUBSYSTEM PATTERNS are appended below this line.
  // ----- ADMIN -----------------------------------------
  { re: /\brefuse\(\s*req\s*,\s*res\b/, before: 4, after: 2,
    what: 'admin console refuse() helper' },
  // ----- API -------------------------------------------
  { re: /\bsendJson\(\s*res\s*,\s*[A-Za-z_.]+\s*\?/, before: 4, after: 2,
    what: 'management API sendJson with a computed (possibly failing) status' },
  // ----- AUTHN -----------------------------------------
  { re: /\brefuseInvalid\(\s*res\b/, before: 4, after: 2,
    what: 'the sign-in service\'s validation refusal helper' },
  { re: /\breturnToCaller\(\s*res\s*,[^,]+,\s*'/, before: 4, after: 2,
    what: 'a sign-in returned to the calling protocol with an authn_error' },
  // ----- FED -------------------------------------------
  { re: /\brefuse\(\s*res\b/, before: 4, after: 2,
    what: 'a federation refuse() page' },
  { re: /^\s*(?:return\s+)?actionRefused\(/, before: 1, after: 1,
    what: 'a refused change to the federation register' },
  // ----- GNAP ------------------------------------------
  { re: /\bgnapError\(\s*res\b/, before: 4, after: 2,
    what: 'the GNAP gnapError(res, status, code, description) error response ' +
          '(RFC 9635 section 3.6)' },
  { re: /\binteractionError\(\s*res\b/, before: 4, after: 2,
    what: 'a GNAP interaction page refusing a link, a code or an answer' },
  // ----- ACME / EST / SCEP (2026-09-13) ------------------
  // ===== ACME patterns =====
  { re: /\bacmeProblem\(\s*ctx\b/, before: 4, after: 4,
    what: 'an ACME RFC 7807 problem document sent by acmeProblem(ctx, ' +
          'status, type, code, detail) (RFC 8555 section 6.7)' },
  { re: /\brefusal\(\s*'[A-Za-z]+'\s*,\s*[45]\d\d\b/, before: 1, after: 2,
    what: 'an ACME refusal object built by acme_jws.refusal(type, status, ' +
          'code, detail)' },
  // ===== EST patterns =====
  { re: /\bestError\(\s*req\s*,\s*res\b/, before: 3, after: 2,
    what: 'an EST refusal written by estError(req, res, ctx, status, …), ' +
          'whose code is marked on the line before it' },
  // ===== SCEP patterns =====
  { re: /\bscepError\(\s*res\b/, before: 4, after: 2,
    what: 'the SCEP scepError(res, status, code, text) HTTP refusal ' +
          '(scep/scep.js)' },
  { re: /\breturn failed\(\s*'STS-/, before: 1, after: 1,
    what: 'a SCEP CertRep FAILURE built by failed() (scep/scep.js)' },
  // ----- KRB -------------------------------------------
  { re: /\berrorReply\(\s*[\w.]+\s*,/, before: 1, after: 3,
    what: 'a Kerberos KRB-ERROR built by errorReply()' },
  { re: /\brefuseS4u\(\s*intent\b/, before: 1, after: 3,
    what: 'an S4U refusal built by refuseS4u()' },
  { re: /\b(?:rejection|bareVerdict|tokenVerdict)\(\s*door\b/, before: 2,
    after: 12,
    what: 'a SPNEGO verdict that is not an acceptance' },
  // ----- OAUTH -----------------------------------------
  { re: /\breturn fail\(/, before: 4, after: 2,
    what:
      'the authorization endpoint\'s fail() and the DPoP verifier\'s fail()' },
  { re: /\breturn challenge\(\s*[45]\d\d/, before: 4, after: 2,
    what: 'UserInfo\'s WWW-Authenticate challenge()' },
  { re: /^\s*\{\s*error:.*error_description:.*\},\s*$/, before: 4, after: 2,
    what: 'an OAuth error object handed to redirectBack()' },
  // ----- PKI -------------------------------------------
  { re: /\brefuse\(\s*res\s*,\s*[45]\d\d\b/, before: 4, after: 2,
    what: 'pki/pki_service.js refuse(res, status, …) helper' },
  // ----- PORTAL ----------------------------------------
  { re: /\bsend\(\s*res\s*,\s*[45]\d\d\b/, before: 4, after: 2,
    what: 'the portal\'s send(res, status, html) with a failure status' },
  { re: /\bsendKeysPage\(\s*res\s*,\s*[45]\d\d\b/, before: 4, after: 2,
    what:
      'the portal\'s sendKeysPage(res, status, html) with a failure status' },
  { re: /\brefuseShape\(\s*res\b/, before: 4, after: 2,
    what: 'the portal\'s validation refusal page' },
  // ----- SAML ------------------------------------------
  { re: /\bsendPage\(\s*res\s*,\s*[45]\d\d\b/, before: 4, after: 2,
    what: 'a SAML page with a failure status' },
  { re: /\banswer\(\s*STATUS_(?:REQUESTER|RESPONDER)\b/, before: 4, after: 2,
    what: 'a SAML SOAP answer carrying a non-Success status' },
  { re: /\bstatus:\s*STATUS_RESPONDER\b/, before: 6, after: 2,
    what: 'a SAML Response built with a Responder status' },
  { re: /\brefreshRefused\(/, before: 1, after: 1,
    what: 'a refused SP metadata refresh' },
  // ----- SCIM ------------------------------------------
  { re: /new\s+SCIMMY\.Types\.Error\(/, before: 2, after: 1,
    what: 'a SCIM error (RFC 7644 section 3.12)' },
  { re: /\bunauthenticated\(\s*req\b/, before: 1, after: 2,
    what: 'a SCIM authentication refusal (401 with challenges)' },
  { re: /\brefusal\(\s*(?:[45]\d\d\b|shim\.)/, before: 1, after: 2,
    what: 'a SCIM authentication refusal value' },
  { re: /\bok:\s*false,\s*status:\s*[45]\d\d\b/, before: 1, after: 2,
    what: 'a SCIM refusal value handed to scim.js' },
  // ----- SPIFFE ----------------------------------------
  { re: /\b(?:invalidArgument|notFound|permissionDenied|unavailable|statusError)\(/, before: 4, after: 2,
    what: 'a SPIFFE gRPC status refusal (spiffe_grpc.js status constructors)' },
  { re: /\bstatusFor\(\s*status\.(?!OK\b)/, before: 4, after: 2,
    what: 'a SPIRE Server API per-item batch refusal' },
  // ----- SSF -------------------------------------------
  { re: /\bfail\(\s*res\b/, before: 4, after: 2,
    what: 'the SSF/XACML fail(res, …) refusal helper' },
  { re: /ok: false, status: \w+, err: (?:''|String)/, before: 3, after: 4,
    what: 'an RFC 8935 push result that failed (ssf_http.js)' },
  { re: /ok: false, delivered: false/, before: 12, after: 2,
    what: 'an SSF transmission that did not happen (ssf.js transmit())' },
  { re: /status: [45]\d\d, entry:/, before: 4, after: 2,
    what:
      'an internal SSF receiver refusing a push (ssf_receivers.js accept())' },
  // ----- STORE -----------------------------------------
  { re: /^\s*failures\+\+;/, before: 3, after: 10,
    what: 'a persistence failure counter incremented' },
  // ----- TLS -------------------------------------------
  { re: /\.on\(\s*['"]tlsClientError['"]/, before: 2, after: 20,
    what: 'a TLS listener\'s refused handshake' },
  // ----- WSTRUST ---------------------------------------
  { re: /\bsoapFault\(\s*[\w'"]/, before: 4, after: 2,
    what: 'a WS-Trust SOAP fault' },
  // ----- XACML -----------------------------------------
  { re: /\bfail\(\s*res\b/, before: 4, after: 2,
    what: 'the xacml/ssf fail(res, status, code, description) helper' },
  { re: /\bpipFail\(\s*res\b/, before: 4, after: 2,
    what: 'xacml pipFail() helper' },
  // ----- XPEP ------------------------------------------
  { re: /\bsend\(\s*res\s*,\s*[45]\d\d\s*,\s*\{/, before: 4, after: 2,
    what: 'the remote PEP\'s send(res, 4xx/5xx, {...}) refusal' },
  { re: /\breturn\s+keep\(/, before: 1, after: 4,
    what: 'the remote PEP\'s failed pull (sync.js keep())' },
  { re: /\bcomplain\(/, before: 2, after: 1,
    what: 'the remote PEP\'s failed registration (sync.js complain())' }
];

// Lines a pattern must not be applied to: the definition of a helper is not a
// call to it, and a comment is not code.
function isExemptShape(line) {
  log.debug("Entering isExemptShape().");
  const trimmed = line.trim();
  if (/^(\/\/|\*|\/\*)/.test(trimmed)) {
    log.debug("Leaving isExemptShape().");
    return true;
  }
  if (/^(?:async\s+)?function\s+[A-Za-z_$][\w$]*\s*\(/.test(trimmed)) {
    log.debug("Leaving isExemptShape().");
    return true;
  }
  log.debug("Leaving isExemptShape().");
  return false;
}

const EXEMPTION = /error-code:\s*none\s*[—–-]+\s*\S.{4,}/;

const EXEMPTION_WITHOUT_REASON = /error-code:\s*none(?!\s*[—–-]+\s*\S.{4,})/;

// ---------------------------------------------------------------------------
// Lines that put a code into something a client receives. A code literal on a
// line that writes a response is the one shape rule 1 cannot survive, whatever
// else the line does.
// ---------------------------------------------------------------------------
const RESPONSE_WRITERS = /\.(?:send|json|write|end|redirect|set|setHeader|append|type)\(|error_description|errorDescription|WWW-Authenticate/;

function scan(options) {
  log.debug("Entering scan().");
  const opts = options || {};
  const known = {};
  errorCodes.CODES.forEach(function (row) { known[row.code] = row; });
  (opts.extraCodes || []).forEach(function (row) { known[row.code] = row; });
  const patterns = FAILURE_PATTERNS.concat(opts.extraPatterns || []);
  const filter = opts.files || null;

  const used = {};
  const unregistered = [];
  const uncoded = [];
  const reasonless = [];
  const leaking = [];

  sourceFiles().forEach(function (rel) {
    const inScope = !filter || filter.some(function (f) {
      return rel === f || rel.indexOf(f.replace(/\/?$/, '/')) === 0;
    });
    let text = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    if (rel === 'common/error_codes.js') {
      // The table itself is where codes are DEFINED, not used. Everything
      // after it — fallbackFor() — is a use.
      const start = text.indexOf('const CODES = [');
      const end = text.indexOf('// ===== END');
      if (start >= 0 && end > start) {
        text = text.slice(0, start) + text.slice(end);
      }
    }
    // The Entering/Leaving trace lines and the handled-exception lines the
    // code style puts in every function are not code for this check: a
    // function name inside one can match a failure pattern, and a trace line
    // between a `mark()` and the call it describes would push the code out of
    // the window. So the windows are counted over the other lines, and a
    // line's number is still its real one.
    const all = text.split('\n');
    const lineNumbers = [];
    const lines = [];
    all.forEach(function (line, n) {
      if (/^\s*log\.debug\("(?:Entering|Leaving|Caught in) /.test(line)) {
        return;
      }
      lineNumbers.push(n + 1);
      lines.push(line);
    });
    lines.forEach(function (line, i) {
      const found = line.match(errorCodes.CODE_IN_TEXT) || [];
      found.forEach(function (code) {
        used[code] = (used[code] || 0) + 1;
        if (!known[code]) {
          unregistered.push(rel + ':' + lineNumbers[i] + ' ' + code);
        }
      });
      if (!inScope) return;
      if (found.length && RESPONSE_WRITERS.test(line) &&
          !/errorCodes\.(?:mark|tag)\(|errorCode:/.test(line)) {
        leaking.push(rel + ':' + lineNumbers[i] + ' ' +
                     line.trim().slice(0, 120));
      }
      if (EXEMPTION_WITHOUT_REASON.test(line)) {
        reasonless.push(rel + ':' + lineNumbers[i]);
      }
      if (isExemptShape(line)) return;
      patterns.forEach(function (p) {
        if (!p.re.test(line)) return;
        const from = Math.max(0, i - p.before);
        const to = Math.min(lines.length - 1, i + p.after);
        let ok = false;
        for (let j = from; j <= to && !ok; j++) {
          errorCodes.CODE_IN_TEXT.lastIndex = 0;
          if (/STS-[A-Z][A-Z0-9]{1,9}-[0-9]{4}/.test(lines[j])) ok = true;
        }
        for (let j = Math.max(0, i - 2); j <= i && !ok; j++) {
          if (EXEMPTION.test(lines[j])) ok = true;
        }
        if (!ok) {
          uncoded.push(rel + ':' + lineNumbers[i] + ' [' + p.what + '] ' +
                       line.trim().slice(0, 110));
        }
      });
    });
  });

  const unused = Object.keys(known).filter(function (code) {
    return !used[code] && !known[code].retired;
  });

  log.debug("Leaving scan().");
  return { used: used, unregistered: unregistered, unused: unused,
           uncoded: uncoded, reasonless: reasonless, leaking: leaking };
}

function listed(items) {
  log.debug("Entering listed().");
  if (!items.length) {
    log.debug("Leaving listed().");
    return 'none';
  }
  log.debug("Leaving listed().");
  return items.length + ':\n      ' + items.slice(0, 60).join('\n      ') +
         (items.length > 60 ? '\n      … and ' + (items.length - 60) + ' more' :
          '');
}

// ---------------------------------------------------------------------------
// 1. THE TABLE IS WELL FORMED.
// ---------------------------------------------------------------------------
function checkTable(t) {
  log.debug("Entering checkTable().");
  t.log.info('=== the table is well formed ===');
  const subsystems = errorCodes.SUBSYSTEMS.map(function (s) { return s.id; });
  const malformed = [];
  const noSummary = [];
  const unknownSubsystem = [];
  const duplicates = [];
  const seen = {};
  errorCodes.CODES.forEach(function (row) {
    if (!errorCodes.isWellFormed(row.code)) malformed.push(row.code);
    if (!row.summary ||
        String(row.summary).trim().length < 12) noSummary.push(row.code);
    if (subsystems.indexOf(errorCodes.subsystemOf(row.code)) < 0) {
      unknownSubsystem.push(row.code);
    }
    if (seen[row.code]) duplicates.push(row.code);
    seen[row.code] = true;
  });
  t.check(!malformed.length, 'every code is shaped STS-<SUBSYSTEM>-<NNNN>',
          listed(malformed));
  t.check(!noSummary.length, 'every code has a summary a person can read',
          listed(noSummary));
  t.check(!unknownSubsystem.length,
          'every code belongs to a declared subsystem',
          listed(unknownSubsystem));
  t.check(!duplicates.length, 'no code is registered twice — a duplicate is ' +
          'two conditions sharing one name', listed(duplicates));

  // In SUBSYSTEMS order, ascending within each. A merge that interleaves two
  // branches' rows is what this catches, and a table out of order is one where
  // the next free number is found by reading all of it.
  const disorder = [];
  let lastSub = -1;
  let lastNum = -1;
  errorCodes.CODES.forEach(function (row) {
    const sub = subsystems.indexOf(errorCodes.subsystemOf(row.code));
    const num = parseInt(row.code.slice(-4), 10);
    if (sub < lastSub || (sub === lastSub && num <= lastNum)) {
      disorder.push(row.code);
    }
    if (sub !== lastSub) lastNum = -1;
    lastSub = sub;
    lastNum = num;
  });
  t.check(!disorder.length, 'the table is in subsystem order and ascending ' +
          'within each subsystem', listed(disorder));
  const ids = {};
  const dupSub = subsystems.filter(function (id) {
    const dup = !!ids[id];
    ids[id] = true;
    return dup;
  });
  t.check(!dupSub.length, 'no subsystem is declared twice', listed(dupSub));
  log.debug("Leaving checkTable().");
}

// ---------------------------------------------------------------------------
// 5a. A MARKED RESPONSE CARRIES NO TRACE OF ITS CODE.
//
// A small express app with the call-log funnel's own recorder on `finish`,
// one route that refuses the way a protocol handler does and marks the code
// first. The bytes a client receives are read back raw and searched; the audit
// row is read back and must carry the code. Both halves in one request, so a
// change that moved the code onto the wire in order to get it into the row is
// caught by the same assertion that would have caught it leaving the row.
// ---------------------------------------------------------------------------
function checkOffTheWire(t) {
  log.debug("Entering checkOffTheWire().");
  t.log.info('=== a code is recorded and never sent ===');
  const express = require('express');
  const audit = require('../common/audit');
  const helpers = require('../common/helpers');
  const app = express();
  app.use(function (req, res, next) {
    res.on('finish', function () {
      audit.recordHttp(req, res,
                       { route: '/probe', matched: true, durationMs: 0 });
    });
    next();
  });
  app.get('/probe', function (req, res) {
    errorCodes.mark(res, 'STS-HTTP-0002');
    helpers.oauthError(res, 400, 'invalid_request', 'a probe refusal');
  });
  app.get('/redirect', function (req, res) {
    // An OAuth error delivered in a redirect: a failure with a 302 status.
    errorCodes.mark(res, 'STS-HTTP-0002');
    res.redirect('https://client.example/cb?error=access_denied');
  });
  log.debug("Leaving checkOffTheWire().");
  return new Promise(function (resolve) {
    const server = app.listen(0, '127.0.0.1', function () {
      const port = server.address().port;
      function get(p) {
        log.debug("Entering get().");
        log.debug("Leaving get().");
        return new Promise(function (done, fail) {
          http.get({ host: '127.0.0.1', port: port, path: p }, function (res) {
            const chunks = [];
            res.on('data', function (c) { chunks.push(c); });
            res.on('end', function () {
              done({ status: res.statusCode, headers: res.rawHeaders.join('\n'),
                     body: Buffer.concat(chunks).toString('utf8') });
            });
          }).on('error', fail);
        });
      }
      get('/probe').then(function (probe) {
        t.equal(probe.status, 400, 'the refusal keeps its own status');
        t.check(probe.body === JSON.stringify({ error: 'invalid_request',
                                                error_description: 'a probe ' +
                                                    'refusal' }),
                'the body is exactly what the protocol helper sends',
                probe.body);
        t.check(!/STS-/.test(probe.body) && !/STS-/.test(probe.headers),
                'no code in the headers or the body the client received',
                probe.headers + '\n' + probe.body);
        return get('/redirect');
      }).then(function (redirect) {
        t.check(!/STS-/.test(redirect.headers) && !/STS-/.test(redirect.body),
                'no code in a redirect either', redirect.headers);
        // The funnel runs on `finish`; give it the tick it needs.
        return new Promise(function (r) { setTimeout(r, 20); });
      }).then(function () {
        const rows = audit.list().filter(function (row) {
          return row.target === '/probe' || row.target === '/redirect';
        });
        const probeRow =
            rows.filter(function (r) { return r.target === '/probe'; })[0];
        const redirectRow = rows.filter(function (r) {
          return r.target === '/redirect';
        })[0];
        t.check(!!probeRow && probeRow.errorCode === 'STS-HTTP-0002',
                'the audit row carries the code the handler marked',
                JSON.stringify(probeRow));
        t.check(!!probeRow && probeRow.summary.indexOf('[STS-HTTP-0002]') === 0,
                'the row\'s summary leads with the code',
                probeRow && probeRow.summary);
        t.check(!!redirectRow && redirectRow.outcome === 'refused' &&
                redirectRow.errorCode === 'STS-HTTP-0002',
                'a marked redirect is recorded as a refusal, not a success',
                JSON.stringify(redirectRow));
      }).catch(function (e) {
        t.bad('the off-the-wire probe could not run', e.stack);
      }).then(function () {
        server.close(resolve);
      });
    });
  });
}

function checkFallbacks(t) {
  log.debug("Entering checkFallbacks().");
  t.log.info('=== an unmarked failure still gets a code ===');
  t.equal(errorCodes.fallbackFor(404, false), 'STS-HTTP-0001',
          'an unrouted 404 is STS-HTTP-0001');
  t.equal(errorCodes.fallbackFor(404, true), 'STS-HTTP-0002',
          'a routed 404 nothing classified is the generic refusal');
  t.equal(errorCodes.fallbackFor(500, true), 'STS-HTTP-0003',
          'a 5xx nothing classified is the generic failure');
  t.equal(errorCodes.fallbackFor(302, true), '',
          'a success status nothing marked is not a failure');
  const res = {};
  errorCodes.mark(res, 'STS-HTTP-0002');
  t.equal(JSON.stringify(res), '{}',
          'a mark is not enumerable, so serialising the response object ' +
          'shows none');
  log.debug("Leaving checkFallbacks().");
}

function run(t) {
  log.debug("Entering run().");
  checkTable(t);
  checkFallbacks(t);

  t.log.info('=== every code used is registered, and every registered code ' +
             'used ===');
  const result = scan();
  t.check(!result.unregistered.length, 'every code in the source is in the ' +
                                       'table',
          listed(result.unregistered));
  t.check(!result.unused.length, 'every code in the table is raised ' +
          'somewhere (retire a row rather than leaving it ' +
          'unused)', listed(result.unused));

  t.log.info('=== every failure site has a code ===');
  t.check(!result.uncoded.length, 'every failure-shaped call site has a code ' +
          'within reach, or an `error-code: none — <why>` exemption',
          listed(result.uncoded));
  t.check(!result.reasonless.length, 'every exemption gives a reason',
          listed(result.reasonless));

  t.log.info('=== no code is written into a response ===');
  t.check(!result.leaking.length, 'no source line puts a code literal into a ' +
          'response-writing call', listed(result.leaking));

  t.log.info('=== the documentation page is current ===');
  let page = '';
  try {
    page = fs.readFileSync(errorCodes.docsPath(), 'utf8');
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // Missing is reported by the assertion below, with how to make it.
    page = '';
  }
  t.check(page === errorCodes.markdown(), 'docs/error-codes.md is exactly ' +
          'what the table ' +
          'generates', page ? 'stale — run: node common/error_codes.js ' +
                                    '--docs'
                                  : 'missing — run: node ' +
                                    'common/error_codes.js --docs');
  const config = fs.readFileSync(path.join(ROOT, 'docs', '_config.yml'),
                                 'utf8');
  t.check(config.indexOf('error-codes.md') >= 0,
          'the page is in the site navigation',
          'docs/_config.yml header_pages');

  log.debug("Leaving run().");
  return checkOffTheWire(t);
}

module.exports = {
  name: 'error_codes',
  describe: 'every failure has a registered, documented error code that ' +
            'never reaches a client',
  run: run,
  // For a maintainer checking one directory while adding codes to it:
  //   node -e "const s=require('./tests/error_codes').scan({files:['ldap/']});
  //            console.log(s.uncoded.join('\n'))"
  scan: scan,
  FAILURE_PATTERNS: FAILURE_PATTERNS
};
