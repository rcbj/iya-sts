'use strict';
//
// File: xacml-pep/pep.js
//
// ===========================================================================
// A REMOTE POLICY ENFORCEMENT POINT. PHASE FIVE.
//
// This is a whole separate process. It holds its own copy of the XACML engine
// (`engine.js`), PULLS the policy repository from the mock's PDP (`sync.js`)
// and ENFORCES it here — which is the point of the exercise, because a PEP
// that asked the PDP per request would be `POST /xacml/pdp` with a network hop
// in front of every access decision, and pushing POLICIES to something that
// could not evaluate them would make no sense at all.
//
// Four endpoints:
//
//   GET  /              what this PEP is, what it holds, what it has enforced
//   GET  /protected     THE RESOURCE. 200 or 403, decided here
//   POST /notify        the PDP's nudge: pull now
//   GET  /healthcheck   liveness, for the container
//
// ---------------------------------------------------------------------------
// WHAT MAKES THIS DIFFERENT FROM THE MOCK'S EMBEDDED PEP AT /xacml/protected.
//
// The embedded one shares a process with the PDP, so it can never disagree
// with it and can never be stale — which makes it a fine demonstration of
// section 7.2 and a useless demonstration of everything a distributed
// deployment is actually hard about. This one can be stale, can hold a policy
// the PDP no longer has, can refuse a document the PDP accepted, and can be
// unreachable while still enforcing. Every one of those is a real state that
// this container makes reachable and reports rather than hides:
//
//   * `GET /` says whether the copy is stale and how long since a successful
//     pull;
//   * the PDP's `/admin/xacml/peps` says the same thing from the other side,
//     which is the interesting half — those two answers can DISAGREE, and a
//     deployment where they do is one nobody could have debugged from either
//     end alone.
//
// ---------------------------------------------------------------------------
// THE ENFORCEMENT RULE IS THE MOCK'S, RESTATED RATHER THAN IMPORTED.
//
// `xacml.js`'s `enforce()` is fifty lines and it is not in `engine.js`'s copy
// list, deliberately. It is the PEP's own decision — the bias and the
// obligation rule — and a PEP that imported the PDP's enforcement would be
// demonstrating that two processes agree because they are one program, which
// is the thing `tests/sts_dpop.js` refuses to do when it writes its own DPoP
// client. Written out here, this PEP can be configured with a DIFFERENT bias
// from the mock's embedded one, and the two then disagree about exactly the
// answers the two biases disagree about — which is the demonstration worth
// having.
//
// The rule, both halves:
//
//   1. THE BIAS decides what a non-Permit means. Deny-biased: only Permit
//      allows. Permit-biased: only Deny refuses. They agree on Permit and Deny
//      and differ on Indeterminate and NotApplicable — the two nobody tests.
//   2. AN OBLIGATION THAT CANNOT BE DISCHARGED TURNS A PERMIT INTO A REFUSAL
//      (section 7.2). This PEP can discharge exactly one obligation and
//      refuses on any other, loudly. Allowing the access and dropping the
//      obligation would enforce half a policy and report success.
// ===========================================================================

const http = require('http');
const https = require('https');
const tls = require('tls');
const nodeCrypto = require('crypto');
const fs = require('fs');
const { URL } = require('url');
const engine = require('./engine');
const sync = require('./sync');
// THE REMOTE PIP. It requires `engine.js` for the model, the datatypes and the
// XML reader — the same three this file uses — so it can join no cycle, and it
// registers nothing because this container has no router to register with.
const pip = require('./pip');

const log = engine.log;
const model = engine.model;

// ---------------------------------------------------------------------------
// THE ERROR CODES — THE MOCK'S OWN REGISTRY, RESOLVED THE WAY THE VERSION IS.
//
// Every failure this container logs carries an `STS-XPEP-nnnn` code at the
// front of the line, from the ONE table in `common/error_codes.js`. There is no
// audit log in this process and no call-log funnel, so the LOG LINE is the only
// place a code is recorded here — never a response body, for the registry's
// own first rule: a client of this PEP sees HTTP and nothing this service
// invented.
//
// **TWO CANDIDATES, FOR `loadVersion()`'s REASON BELOW.** The Dockerfile copies
// the registry to the container ROOT beside this file (`./error_codes`) — not
// into `./common/`, which is the shim and must stay one file — and a checkout
// has it where it lives (`../common/error_codes`). Exactly one hits.
//
// **A MISSING REGISTRY MAY NOT STOP THIS CONTAINER STARTING**, which is the
// version's rule and for its reason: a PEP that cannot name its failures is
// still a PEP that enforces. So both misses fall back to a local `tag()` that
// writes the same `[STS-…] ` prefix, and say so once.
//
// It is resolved HERE and not in `engine.js`, deliberately:
// `tests/xacml_pep.js` loads `engine.js` alone in a child and asserts that not
// one of the mock's own modules is in its `require.cache`, and in a checkout
// the registry IS one. `sync.js` and `pip.js` are handed the resulting `tag` on
// `options`, which is how they are handed everything else this file decides at
// start.
function loadErrorCodes() {
  log.debug("Entering loadErrorCodes().");
  const candidates = ['./error_codes', '../common/error_codes'];
  for (let i = 0; i < candidates.length; i++) {
    try {
      const registry = require(candidates[i]);
      if (registry && typeof registry.tag === 'function') {
        log.debug("Leaving loadErrorCodes().");
        return registry;
      }
    } catch (error) {
      // Not this layout. Silent because exactly one of the two is expected to
      // miss on every start; the case worth reporting is BOTH, below.
      log.debug("Caught in loadErrorCodes(): " +
                ((error && error.message) || error));
    }
  }
  const fallback = { tag: function (code) {
    log.debug("Entering tag().");
    log.debug("Leaving tag().");
    return '[' + code + '] ';
  } };
  log.error(fallback.tag('STS-XPEP-0001') + 'xacml-pep: neither ' +
            './error_codes nor ../common/error_codes could be loaded, so the ' +
            'error-code registry is not here. Log lines still carry their ' +
            'codes; nothing else changes. In the image that means the ' +
            'Dockerfile stopped copying common/error_codes.js.');
  log.debug("Leaving loadErrorCodes().");
  return fallback;
}

const ERROR_CODES = loadErrorCodes();
const tag = ERROR_CODES.tag;

// ---------------------------------------------------------------------------
// THE VERSION, M.N.O — THE SAME ONE THE MOCK REPORTS, FROM THE SAME MODULE.
//
// **IT WAS THE STRING `'mock-sts xacml-pep, phase five'` UNTIL 2026-09-06**,
// and that is worth keeping written down because of where the value GOES: it
// is `options.version`, it rides on the registration this PEP sends the PDP,
// the PDP stores it as `xacmlPepVersion` on the entry, and `/admin/xacml/peps`
// draws it in a column headed Version. So an operator looking at the console
// to answer "which build is that enforcement point running" was told the name
// of a development phase — a label that had not changed in any commit since it
// was written and could not have, because nothing computed it.
//
// It is the mock's own `common/version.js`, copied into this image at BUILD
// TIME the way the seven engine modules are, and stamped there. One copy in
// the tree; this container cannot report a release the mock does not have.
//
// **TWO CANDIDATES, BECAUSE THIS FILE HAS TWO LAYOUTS AND ONLY ONE OF THEM IS
// THE IMAGE.** In the container the module is at the root beside this file
// (`./version`); in a checkout it is where it lives (`../common/version`).
// They are mutually exclusive — neither layout has both — so the loop finds
// exactly one and the other miss is normal. This is the shape the parent
// project's `api/server.js` uses for its own copy of this module, and the
// reason is the same: one implementation of the scheme rather than a second
// that could drift.
//
// A version may not stop this container starting, which is the rule the module
// itself is written to (an unreadable VERSION is 0.0, a corrupt stamp is a
// computed record). This adds the one failure that module cannot cover — being
// absent from BOTH paths, which would mean a Dockerfile that stopped copying
// it — and answers a version that SAYS SO rather than throwing. A PEP that
// cannot name its build is still a PEP that enforces.
function loadVersion() {
  log.debug("Entering loadVersion().");
  const candidates = ['./version', '../common/version'];
  for (let i = 0; i < candidates.length; i++) {
    try {
      log.debug("Leaving loadVersion().");
      return require(candidates[i]).load();
    } catch (error) {
      // Not this layout. Silent because exactly one of the two is expected to
      // miss on every start; the case worth reporting is BOTH, below.
      log.debug("Caught in loadVersion(): " +
                ((error && error.message) || error));
    }
  }
  log.error(tag('STS-XPEP-0002') +
            'xacml-pep: neither ./version nor ../common/version could be ' +
            'loaded, so this PEP cannot name the build it is running. It ' +
            'registers and enforces regardless. In the image that means the ' +
            'Dockerfile stopped copying common/version.js and VERSION.');
  log.debug("Leaving loadVersion().");
  return { version: 'unknown', build: 'unknown', commit: '',
           builtAt: null, stamped: false };
}

const APP_VERSION = loadVersion();
const VERSION = APP_VERSION.version;

// ---------------------------------------------------------------------------
// CONFIGURATION, ALL OF IT FROM THE ENVIRONMENT.
//
// No appconfig file and no settings table, and that is not a shortcut: this
// container is one component with a dozen knobs, and the mock's five-layer
// configuration exists to serve a console that can change a setting while the
// service runs. A PEP has no console.
// ---------------------------------------------------------------------------
function intFromEnv(name, dflt) {
  log.debug("Entering intFromEnv().");
  const raw = process.env[name];
  const n = raw === undefined ? NaN : parseInt(raw, 10);
  log.debug("Leaving intFromEnv().");
  return isNaN(n) ? dflt : n;
}

function fileFromEnv(name) {
  log.debug("Entering fileFromEnv().");
  const path = process.env[name];
  if (!path) {
    log.debug("Leaving fileFromEnv().");
    return null;
  }
  try {
    log.debug("Leaving fileFromEnv().");
    return fs.readFileSync(path);
  } catch (error) {
    // NAMED AND FATAL-ADJACENT rather than swallowed: a PEP configured with a
    // certificate path it cannot read would otherwise start, register
    // unauthenticated, and leave somebody looking at the PDP's console
    // wondering why the row says it proved nothing.
    log.error(tag('STS-XPEP-0003') +
              'xacml-pep: ' + name + ' names ' + path + ' and it could not ' +
              'be read (' + error.message + '). Carrying on WITHOUT it, ' +
              'which means this PEP registers unauthenticated if the PDP ' +
              'allows that and is refused if it does not.');
    log.debug("Leaving fileFromEnv().");
    return null;
  }
}

const options = {
  pdpUrl: process.env.PEP_PDP_URL || 'https://localhost:8081',
  name: process.env.PEP_NAME || 'pep-1',
  notifyUrl: process.env.PEP_NOTIFY_URL || '',
  resource: process.env.PEP_RESOURCE || '',
  version: VERSION,
  description: process.env.PEP_DESCRIPTION ||
    'A remote XACML Policy Enforcement Point holding its own copy of the ' +
    'engine and pulling this repository.',
  bias: process.env.PEP_BIAS === 'permit-biased' ? 'permit-biased'
                                                 : 'deny-biased',
  port: intFromEnv('PEP_PORT', 9090),
  pollIntervalMs: intFromEnv('PEP_POLL_INTERVAL_MS', 15000),
  heartbeatIntervalMs: intFromEnv('PEP_HEARTBEAT_INTERVAL_MS', 60000),
  timeoutMs: intFromEnv('PEP_TIMEOUT_MS', 5000),
  maxBodyBytes: intFromEnv('PEP_MAX_BODY_BYTES', 4 * 1024 * 1024),
  clientCertificate: fileFromEnv('PEP_TLS_CERT'),
  clientKey: fileFromEnv('PEP_TLS_KEY'),
  pdpCa: fileFromEnv('PEP_TLS_CA'),
  insecure: process.env.PEP_TLS_INSECURE === 'true',
  // ---------------------------------------------------------------------
  // THE REMOTE PIP. ON BY DEFAULT, AND TURNING IT OFF IS A SUPPORTED
  // DEPLOYMENT RATHER THAN A DEGRADED ONE.
  //
  // With it on, a designator the request did not carry is resolved against
  // the PDP's embedded directory before the policy is evaluated, so this
  // container decides on the same information the PDP's own PEP does. With
  // it off — or with no client certificate, which the PIP endpoint requires
  // — it decides on what the request asserts and nothing else, which is what
  // this container did before `pip.js` existed and is a real property of a
  // real deployment worth being able to demonstrate.
  //
  // ON by default because the surprising state is the other one: a PEP
  // enforcing the same policy as its PDP and reaching a different answer is
  // the failure this whole phase exists to make impossible, and a feature
  // that has to be switched on to get that is a feature most deployments
  // will not have.
  // ---------------------------------------------------------------------
  pipEnabled: process.env.PEP_PIP !== 'false',
  // ---------------------------------------------------------------------
  // THE HTTPS LISTENER (2026-09-13). PATHS AND NOT CONTENTS, unlike the
  // client certificate above, and that is the whole difference between the
  // two: the client certificate is read once at start because it exists
  // before the container does, and this pair usually does NOT — it is issued
  // by the realm the PEP REGISTERED to (`POST /admin-api/xacml/
  // issue-pep-certificate`), which needs the registration to exist first. So
  // the files are re-read on `httpsReloadIntervalMs`, a listener starts the
  // first time a usable pair appears, and a pair written later replaces the
  // one being served without a restart. See `reloadListenerPair()`.
  // ---------------------------------------------------------------------
  httpsCertPath: process.env.PEP_HTTPS_CERT || '',
  httpsKeyPath: process.env.PEP_HTTPS_KEY || '',
  httpsPort: intFromEnv('PEP_HTTPS_PORT', 9443),
  httpsReloadIntervalMs: intFromEnv('PEP_HTTPS_RELOAD_INTERVAL_MS', 5000),
  // The error-code tag for `sync.js` and `pip.js`'s log lines. See
  // `loadErrorCodes()` above.
  tag: tag
};

function send(res, status, body) {
  log.debug("Entering send().");
  const text = JSON.stringify(body, null, 2);
  res.writeHead(status, { 'Content-Type': 'application/json',
                          'Cache-Control': 'no-store',
                          'Content-Length': Buffer.byteLength(text) });
  res.end(text);
  log.debug("Leaving send().");
}

// ---------------------------------------------------------------------------
// WHAT THIS PEP DOES WITH A DECISION. See the header — the mock's rule,
// restated rather than imported.
// ---------------------------------------------------------------------------
const DISCHARGEABLE = ['urn:sts:xacml:obligation:log'];

function enforce(answer) {
  log.debug('Entering enforce(). decision=' + answer.decision);
  const discharged = [];
  const undischargeable = [];
  (answer.obligations || []).forEach(function (obligation) {
    if (DISCHARGEABLE.indexOf(obligation.id) >= 0) {
      log.info('xacml-pep: discharging obligation ' + obligation.id +
               ' with ' + (obligation.assignments || []).length +
               ' assignment(s).');
      discharged.push(obligation.id);
      return;
    }
    undischargeable.push(obligation.id);
  });
  const permitted = answer.decision === model.DECISION.PERMIT;
  const denied = answer.decision === model.DECISION.DENY;
  let allowed = options.bias === 'deny-biased' ? permitted : !denied;
  let why;
  if (options.bias === 'deny-biased') {
    why = permitted ? 'The PDP policy said Permit.'
      : 'The policy said ' + answer.decision + ', and this PEP is ' +
        'deny-biased, so anything that is not Permit is a refusal.';
  } else {
    why = denied ? 'The policy said Deny.'
      : 'The policy said ' + answer.decision + ', and this PEP is ' +
        'permit-biased, so anything that is not Deny is allowed.';
  }
  if (allowed && undischargeable.length) {
    allowed = false;
    log.warn(tag('STS-XPEP-0004') + 'xacml-pep: refusing a ' +
             answer.decision + ' that carries obligation(s) this PEP cannot ' +
             'discharge: ' + undischargeable.join(', ') + '.');
    why = 'The policy said ' + answer.decision + ', but the decision carries ' +
          (undischargeable.length === 1 ? 'an obligation' : 'obligations') +
          ' this PEP cannot discharge (' + undischargeable.join(', ') +
          '). Section 7.2: a PEP that cannot fulfil an obligation MUST NOT ' +
          'grant the access. Allowing it and dropping the obligation would ' +
          'enforce half a policy and report success.';
  }
  log.debug('Leaving enforce(). ' + (allowed ? 'Allowed.' : 'Refused.'));
  return { allowed: allowed, bias: options.bias, why: why,
           discharged: discharged, undischargeable: undischargeable };
}

// ---------------------------------------------------------------------------
// A DECISION, HERE, WITH WHAT WAS PULLED.
//
// THERE IS NO PIP. Every attribute a policy asks about has to be in the
// request, and one that is not produces an empty bag — which is a perfectly
// ordinary XACML result rather than an error. That is not a gap in this
// container: a real PEP knows who the caller is and generally nothing else
// about them, and the mock's PIP reads a person's entry in an embedded
// directory this process cannot see and should not have.
//
// So a policy that decides on `employeeType` decides here only if the caller
// asserts one. `GET /protected?employeeType=staff` is how this container lets
// somebody see that, and it is honest about what it means: an attribute the
// SUBJECT asserted about itself, which no real deployment would believe and
// which is exactly the sort of thing a mock exists to let you try.
// ---------------------------------------------------------------------------
async function decide(query) {
  log.debug('Entering decide().');
  const holding = sync.current();
  if (!holding.loaded) {
    log.warn(tag('STS-XPEP-0005') + 'xacml-pep: a decision was asked for ' +
             'and this PEP holds no root policy, so it is NotApplicable and ' +
             'the ' + options.bias + ' bias settles it.');
    log.debug('Leaving decide(). Nothing is held.');
    return { decision: model.DECISION.NOT_APPLICABLE,
             status: { code: model.STATUS.OK },
             obligations: [], advice: [], policyIdentifiers: [],
             note: 'This PEP holds no root policy — it has never pulled one ' +
                   'successfully, or what it pulled had no root. There is ' +
                   'nothing to evaluate, so the decision is NotApplicable ' +
                   'and the bias below is what actually decided.' };
  }
  const subject = String(query.subject || '');
  const resource = String(query.resource || options.resource ||
                          'urn:xacml-pep:protected');
  const action = String(query.action || 'GET');
  const subjectAttributes = subject
    ? [{ attributeId: model.ATTRIBUTE.SUBJECT_ID, issuer: null,
         includeInResult: true,
         values: [{ type: model.TYPE.STRING, lexical: subject }] }]
    : [];
  // EVERY OTHER QUERY PARAMETER BECOMES A SUBJECT ATTRIBUTE, ASSERTED UNDER
  // BOTH SPELLINGS — the bare name and the mock's own
  // `urn:sts:xacml:attribute:` form.
  //
  // **THAT IS NOT BELT AND BRACES; IT IS WHAT MAKES THE CONTRACT TRUE.** The
  // mock's `xacml_pip.js` answers BOTH spellings from ONE directory attribute
  // — a designator for `employeeType` and one for
  // `urn:sts:xacml:attribute:employeeType` both read the same entry — so
  // a policy author over there may legitimately write either and the PDP
  // decides identically. A remote PEP that asserted only one of them would
  // decide differently from the PDP for every policy that happened to use the
  // other, which is precisely the disagreement this whole phase exists to
  // make impossible. It cost a run to find: the seeded RBAC policy names
  // `employeeType` bare, this container asserted only the prefixed form, and
  // every request was denied by a policy that was working perfectly.
  //
  // The prefix is a literal here rather than imported from `xacml_pip.js`,
  // because that module is not in `engine.js`'s copy list and pulling it in
  // for one string would bring the mock's directory reader into a process
  // that has no directory.
  const PIP_PREFIX = 'urn:sts:xacml:attribute:';
  Object.keys(query).forEach(function (key) {
    if (key === 'subject' || key === 'resource' || key === 'action') {
      return;
    }
    const values = [{ type: model.TYPE.STRING, lexical: String(query[key]) }];
    subjectAttributes.push({ attributeId: key, issuer: null,
                             includeInResult: true, values: values });
    subjectAttributes.push({ attributeId: PIP_PREFIX + key, issuer: null,
                             includeInResult: true, values: values });
  });
  const request = {
    returnPolicyIdList: true,
    combinedDecision: false,
    categories: [
      { category: model.CATEGORY.ACCESS_SUBJECT, id: null, content: null,
        attributes: subjectAttributes },
      { category: model.CATEGORY.RESOURCE, id: null, content: null,
        attributes: [{ attributeId: model.ATTRIBUTE.RESOURCE_ID, issuer: null,
                       includeInResult: true,
                       values: [{ type: model.TYPE.ANYURI,
                                  lexical: resource }] }] },
      { category: model.CATEGORY.ACTION, id: null, content: null,
        attributes: [{ attributeId: model.ATTRIBUTE.ACTION_ID, issuer: null,
                       includeInResult: true,
                       values: [{ type: model.TYPE.STRING,
                                  lexical: action }] }] },
      { category: model.CATEGORY.ENVIRONMENT, id: null, content: null,
        attributes: [] }
    ]
  };
  // ---------------------------------------------------------------------
  // THE PIP, FETCHED BEFORE EVALUATION RATHER THAN DURING IT.
  //
  // `xacml_pdp.js`'s resolver is SYNCHRONOUS — it is handed a designator and
  // must return an array — and an HTTP request is not. Making the evaluator
  // asynchronous would be a change to the code every one of the 455 OASIS
  // conformance cases runs through, for the benefit of one deployment shape,
  // and it was refused. So `pip.js` walks the policy for the designators it
  // could be asked about, fetches them ALL IN ONE REQUEST, and hands back a
  // synchronous resolver over what came back.
  //
  // **THAT IS WHY THE PDP'S ENDPOINT TAKES A LIST.** The batch is not an
  // optimisation; it is what makes a synchronous engine able to use a remote
  // PIP at all.
  //
  // IT NEVER REJECTS. A PDP that will not answer, a refused query, a policy
  // designating more attributes than one query may carry — every one of them
  // comes back as a resolver answering empty bags, which is EXACTLY what this
  // container did before `pip.js` existed. The degraded state of this feature
  // is the old behaviour, reported on `GET /`, rather than a PEP that stops
  // deciding.
  // ---------------------------------------------------------------------
  const pipResolver = await pip.resolverFor(request, holding, options);
  lastPipReport = pipResolver.report;
  const answer = engine.pdp.evaluate(holding.root, request, {
    repository: holding.repository,
    resolver: pipResolver.resolve
  });
  // WHAT THE PIP DID, ON THE ANSWER. A decision that came out differently
  // because an attribute was resolved remotely is indistinguishable from one
  // that did not, and this is the only place the difference is visible to
  // whoever is reading a refusal.
  answer.pip = pipResolver.report;
  if (answer.decision === model.DECISION.INDETERMINATE) {
    log.warn(tag('STS-XPEP-0006') + 'xacml-pep: the engine answered ' +
             'Indeterminate (' +
             ((answer.status && answer.status.code) || 'no status') +
             ((answer.status && answer.status.message)
               ? ': ' + answer.status.message : '') +
             '), so the ' + options.bias + ' bias settles it.');
  }
  log.debug('Leaving decide(). ' + answer.decision);
  return answer;
}

// The last PIP query's outcome, for `GET /`. One value rather than a history:
// this page answers "is the PIP working", and a list would be a log in a
// container that already has one.
let lastPipReport = null;

// ---------------------------------------------------------------------------
// THE ROUTES. Node's own http and no framework: this container's whole surface
// is four endpoints and none of them takes a form, so express would be a
// dependency to describe four `if`s.
// ---------------------------------------------------------------------------
function overview() {
  log.debug("Entering overview().");
  const s = sync.state();
  const staleAfterMs = options.pollIntervalMs * 3;
  const lastPull = s.held.lastPullAt ? Date.parse(s.held.lastPullAt) : NaN;
  const stale = !(lastPull > 0) || (Date.now() - lastPull) > staleAfterMs;
  log.debug("Leaving overview().");
  return {
    what: 'A REMOTE XACML Policy Enforcement Point. It holds its own copy of ' +
          'the engine, PULLS the policy repository from the PDP below, and ' +
          'decides here. The PDP saw none of the decisions counted on this ' +
          'page, which is what a remote PEP is.',
    // ---------------------------------------------------------------------
    // WHETHER THIS PEP HAS A PIP, SAID OUT LOUD (2026-09-06).
    //
    // It used to say `pip: { here: false }` and explain at length that a
    // designator the request did not carry is an empty bag out here. That is
    // still true when `PEP_PIP` is off or no certificate is mounted, and it
    // is no longer the only state — so the page reports which one it is in
    // rather than asserting one of them.
    //
    // `lastQuery` is the last query's outcome and not a count, because the
    // question an operator has is "is it working", and the answer to that is
    // the most recent attempt with its reason.
    // ---------------------------------------------------------------------
    pip: {
      enabled: options.pipEnabled,
      endpoint: options.pipEnabled ? options.pdpUrl + '/xacml/pip' : null,
      credentialed: !!options.clientCertificate,
      lastQuery: lastPipReport,
      what: options.pipEnabled
        ? 'This PEP resolves attribute designators the request did not carry ' +
          'against the PDP\'s embedded directory, in ONE batched query ' +
          'before each evaluation, in XACML\'s own XML both ways. So a ' +
          'policy that reads employeeType off a person\'s entry decides HERE ' +
          'the way it decides at the PDP. The endpoint requires a client ' +
          'certificate whose subject holds the built-in REMOTE_PEPS role; ' +
          'without one every query is refused and this PEP falls back to ' +
          'deciding on what the request asserts.'
        : 'PEP_PIP is off, so this PEP has NO Policy Information Point: a ' +
          'designator the request did not carry produces an empty bag. Pass ' +
          'extra query parameters to /protected and each becomes a subject ' +
          'attribute — asserted by the caller about itself, which no real ' +
          'deployment would believe and which is exactly what a mock is for.'
    },
    version: VERSION,
    // THE PROVENANCE OF THAT NUMBER, broken out the way the mock's own
    // `GET /admin-api` breaks it out, and for the same reason: a client
    // comparing this PEP's build against the PDP's should read fields rather
    // than write a regular expression over a string.
    //
    // `stamped` is the one that changes how the rest is read. False means this
    // container computed its number when the process started — it was never
    // built, which happens when somebody runs pep.js by hand — so the build is
    // a start time and comparing it with the PDP's says nothing at all.
    build: {
      number: APP_VERSION.build,
      commit: APP_VERSION.commit || null,
      at: APP_VERSION.builtAt,
      stamped: APP_VERSION.stamped === true,
      // THE TWO IMAGES ARE BUILT SEPARATELY AND THEIR BUILD NUMBERS DIFFER
      // UNLESS ONE WAS PASSED TO BOTH. Said here rather than left for somebody
      // to infer from two timestamps that are four seconds apart, because the
      // question this page gets opened for is whether this PEP is the same
      // release as the PDP — and M.N is the part that answers it.
      what: 'M.N comes from the same VERSION file the PDP\'s does, so a ' +
            'difference THERE is a PEP left behind across a release. The ' +
            'build number is per IMAGE: these are two artifacts and they ' +
            'differ unless the same BUILD_NUMBER was passed to both builds.'
    },
    pdp: options.pdpUrl,
    bias: options.bias,
    protectedAt: '/protected',
    // THE HTTPS LISTENER, as this process sees it (2026-09-13). The PDP's
    // `/admin/xacml/peps` says which certificate the realm ISSUED; only this
    // page can say which one is being SERVED, and the two differ for exactly
    // as long as a pair has been issued and not yet written where
    // PEP_HTTPS_CERT points.
    https: {
      configured: listener.configured,
      listening: listener.listening,
      port: listener.listening ? listener.port : null,
      certificate: listener.certificate,
      loadedAt: listener.loadedAt,
      lastCheckedAt: listener.lastCheckedAt,
      problem: listener.lastProblem,
      what: listener.configured
        ? 'This PEP serves the same four endpoints over HTTPS with a ' +
          'certificate issued by the Remote PEP listeners Issuing CA of the ' +
          'realm it registered to. The pair is re-read from ' +
          options.httpsCertPath + ' and ' + options.httpsKeyPath + ' every ' +
          options.httpsReloadIntervalMs + 'ms, so a certificate issued after ' +
          'this container started — which is the ordinary order, since the ' +
          'realm certifies a PEP only once it has registered — is picked up ' +
          'without a restart.'
        : 'No HTTPS listener: PEP_HTTPS_CERT and PEP_HTTPS_KEY are not both ' +
          'set. Issue a pair with POST /admin-api/xacml/' +
          'issue-pep-certificate on the PDP, write it to two files this ' +
          'container can read, and name them.'
    },
    holding: s.held,
    // COMPUTED HERE AND SEPARATELY FROM THE PDP'S OWN VERDICT, on purpose.
    // The PDP calls this PEP stale after `xacml.pepStaleAfterS` without a
    // heartbeat; this PEP calls itself stale after three missed polls. The two
    // measure different things and CAN DISAGREE — a PEP that is pulling
    // happily while its heartbeats are being dropped looks fine here and
    // stale there, which is a real and confusing deployment state that is far
    // easier to recognise when both numbers are visible.
    stale: stale,
    staleAfterMs: staleAfterMs,
    registration: s.registration,
    enforced: s.counters,
    notify: options.notifyUrl || null,
    poll: { intervalMs: options.pollIntervalMs,
            heartbeatMs: options.heartbeatIntervalMs },
    contract: 'THE PULL IS THE CONTRACT. This PEP polls the PDP on its own ' +
              'interval and converges whether or not a nudge ever arrives. ' +
              'A PDP that is unreachable leaves this PEP enforcing what it ' +
              'last pulled rather than denying everything — which is a ' +
              'deliberate trade, and it means a policy change made during an ' +
              'outage is not enforced here until the next successful pull.',
    noPip: 'There is no Policy Information Point here. Every attribute a ' +
           'policy asks about must be IN the request, and one that is not ' +
           'produces an empty bag. Pass extra query parameters to ' +
           '/protected and each becomes a subject attribute under ' +
           'urn:sts:xacml:attribute: — asserted by the caller about ' +
           'itself, which no real deployment would believe and which is ' +
           'exactly what a mock is for.'
  };
}

async function protectedResource(query) {
  log.debug("Entering protectedResource().");
  const answer = await decide(query);
  const outcome = enforce(answer);
  sync.countDecision(outcome);
  const body = {
    decision: answer.decision,
    allowed: outcome.allowed,
    bias: outcome.bias,
    why: outcome.why,
    status: answer.status,
    obligations: (answer.obligations || []).map(function (one) {
      return { id: one.id,
               discharged: outcome.discharged.indexOf(one.id) >= 0 };
    }),
    advice: (answer.advice || []).map(function (one) {
      return one.id;
    }),
    applicablePolicies: answer.policyIdentifiers || [],
    decidedBy: { pep: options.name,
                 syncToken: sync.state().held.syncToken,
                 note: 'Decided IN THIS PROCESS, against the policy this PEP ' +
                       'last pulled. The PDP did not see this request.' },
    // WHAT WAS RESOLVED REMOTELY, ON EVERY ANSWER. Two decisions that differ
    // only because one had an attribute the other did not are otherwise
    // identical on the wire, and this is what makes the difference readable —
    // which is the whole point of a component that exists to stop a PEP and
    // its PDP disagreeing.
    pip: answer.pip || { used: false, why: 'nothing was asked.' }
  };
  if (answer.note) {
    body.note = answer.note;
  }
  log.debug("Leaving protectedResource().");
  return { status: outcome.allowed ? 200 : 403, body: body };
}

// ONE HANDLER FOR BOTH LISTENERS. The HTTPS listener serves exactly the four
// endpoints the HTTP one does, decided by exactly this code: a PEP whose two
// ports answered differently would be two enforcement points sharing a process,
// and a client moved from one to the other must see no difference but the
// transport. No per-request Entering/Leaving pair — this is the hot path of
// the container and would drown its log.
function handle(req, res) {
  let parsed;
  try {
    parsed = new URL(req.url, 'http://localhost');
  } catch (error) {
    // A URL node itself will not parse cannot name any of four fixed paths,
    // so there is nothing to route it to.
    log.warn(tag('STS-XPEP-0007') + 'xacml-pep: refused a request whose URL ' +
             'would not parse: ' + error.message);
    send(res, 400, { error: 'that is not a request URL' });
    return;
  }
  const path = parsed.pathname;
  const query = {};
  parsed.searchParams.forEach(function (value, key) {
    query[key] = value;
  });

  if (req.method === 'GET' && path === '/healthcheck') {
    // LIVENESS ONLY, AND IT DOES NOT ASK WHETHER THE POLICY IS CURRENT. A PEP
    // holding a stale copy is working — it is enforcing, and it is saying so
    // on `GET /`. A healthcheck that failed on staleness would make a
    // container restart loop out of a PDP outage, which would turn a
    // recoverable problem into an outage of its own.
    send(res, 200, { message: 'Success' });
    return;
  }
  if (req.method === 'GET' && (path === '/' || path === '')) {
    send(res, 200, overview());
    return;
  }
  if (req.method === 'GET' && path === '/protected') {
    // AWAITED WITH A CATCH, because this handler became asynchronous when the
    // PIP query went in front of the evaluation — and node's http server does
    // not look at what a handler returns, so an unhandled rejection here would
    // be a request that HANGS where it used to be a 500. `pip.js` is written
    // never to reject; this is the guard for everything else in the path.
    protectedResource(query).then(function (answer) {
      send(res, answer.status, answer.body);
    }).catch(function (error) {
      log.error(tag('STS-XPEP-0008') + 'xacml-pep: deciding threw: ' +
                error.message);
      send(res, 500, { error: 'decision_failed',
        error_description: 'This PEP could not reach a decision: ' +
                           error.message + '. That is a defect here rather ' +
                           'than a Deny, and it is reported as one.' });
    });
    return;
  }
  if (req.method === 'POST' && path === '/notify') {
    // THE NUDGE. Answered 204 IMMEDIATELY and the pull happens after, which
    // matters: the PDP times this request out in two seconds by default and
    // holding it open for the length of a pull would make a slow pull look
    // like an unreachable PEP on somebody's console.
    //
    // THE BODY IS NOT READ AND NOTHING IN IT IS TRUSTED. A nudge says only
    // that something changed; what actually changed is discovered by pulling
    // from the PDP over this PEP's own configured URL. A nudge that could tell
    // this PEP what the policy now is, or where to fetch it, would be an
    // unauthenticated caller supplying policy — and the whole reason a nudge
    // is affordable is that it carries nothing.
    req.resume();
    send(res, 204, {});
    log.info('xacml-pep: nudged by the PDP; pulling now rather than waiting ' +
             'up to ' + options.pollIntervalMs + 'ms for the next poll. ' +
             'Nothing in the nudge was read — what changed is discovered by ' +
             'pulling.');
    sync.pull(options).catch(function (error) {
      log.warn(tag('STS-XPEP-0010') + 'xacml-pep: the nudged pull failed: ' +
               error.message + '. The scheduled poll will try again.');
    });
    return;
  }
  log.info(tag('STS-XPEP-0009') + 'xacml-pep: no such endpoint: ' +
           req.method + ' ' + path);
  send(res, 404, {
    error: 'not_found',
    error_description: 'This PEP answers GET /, GET /protected, ' +
                       'POST /notify and GET /healthcheck.'
  });
}

const server = http.createServer(handle);

// ===========================================================================
// THE HTTPS LISTENER (2026-09-13).
//
// A remote PEP answers its CLIENTS — whoever calls `/protected` — and it
// answered them in plain http, because a certificate had to come from
// somewhere and nothing provided one. The PDP's realm now does: its Remote PEP
// listeners Issuing CA certifies a key pair for a REGISTERED PEP, hands the
// private key over once, and an operator (or a launcher) writes the two halves
// to the files `PEP_HTTPS_CERT` and `PEP_HTTPS_KEY` name.
//
// **THE FILES ARE WATCHED BECAUSE THE ORDER OF EVENTS REQUIRES IT, NOT FOR
// CONVENIENCE.** The certificate comes from the realm this PEP registered to,
// and registering is something this process does after it starts — so the
// pair does not exist when the container does, and a listener that read its
// files once at start would never get one. The launchers are the sharp case:
// they start this container minutes before the realm it polls is created.
// So the pair is re-read on an interval, the listener starts the first time a
// USABLE pair appears, and a pair that changes afterwards is swapped in with
// `setSecureContext()` — which is also what a renewal needs, and a restart to
// rotate a certificate is an outage of its own.
//
// **A BAD PAIR NEVER REPLACES A GOOD ONE.** Files are written one at a time,
// so between the two writes the certificate and the key disagree; a listener
// that took that moment's pair would fail every handshake until the second
// write landed. So a pair is checked whole — both parse, the key is the
// certificate's, TLS accepts them — before it is used, and the pair already
// being served stays until a better one arrives.
//
// **PLAIN HTTP STAYS**, on `PEP_PORT`. The container's own healthcheck uses it,
// a deployment with no certificate is still a PEP that enforces, and turning
// it off is the deployment's decision to make at its network edge rather than
// this process's to make for it.
// ===========================================================================
const listener = {
  configured: false,
  listening: false,
  port: null,
  digest: '',
  loadedAt: null,
  certificate: null,
  lastProblem: null,
  lastCheckedAt: null
};
let httpsServer = null;
// The last problem logged, so a file that stays missing for an hour is one log
// line and not seven hundred. Reset whenever a pair loads.
let lastLoggedProblem = '';

// A problem, logged once per distinct sentence and always recorded for GET /.
// `waiting` is the ordinary state before a certificate has been issued, which
// is information rather than an error.
function listenerProblem(code, sentence, waiting) {
  log.debug("Entering listenerProblem().");
  listener.lastProblem = sentence;
  if (sentence !== lastLoggedProblem) {
    lastLoggedProblem = sentence;
    if (waiting) {
      log.info('xacml-pep: ' + sentence);
    } else {
      // error-code: none — the code is the caller's, a literal at each call.
      log.error(tag(code) + 'xacml-pep: ' + sentence);
    }
  }
  log.debug("Leaving listenerProblem().");
}

// What GET / says about the certificate being served. Read with node's own
// parser, so what the page reports is what a client's handshake will see.
function describeServed(x509) {
  log.debug("Entering describeServed().");
  log.debug("Leaving describeServed().");
  return {
    subject: x509.subject.replace(/\n/g, ', '),
    issuer: x509.issuer.replace(/\n/g, ', '),
    serialHex: String(x509.serialNumber || '').toLowerCase(),
    subjectAltName: x509.subjectAltName || '',
    validFrom: new Date(x509.validFrom).toISOString(),
    validTo: new Date(x509.validTo).toISOString(),
    fingerprint256: x509.fingerprint256
  };
}

function reloadListenerPair() {
  log.debug("Entering reloadListenerPair().");
  listener.lastCheckedAt = new Date().toISOString();
  const certPath = options.httpsCertPath;
  const keyPath = options.httpsKeyPath;
  listener.configured = !!(certPath && keyPath);
  if (!certPath && !keyPath) {
    log.debug("Leaving reloadListenerPair(). Not configured.");
    return;
  }
  if (!certPath || !keyPath) {
    listenerProblem('STS-XPEP-0029', 'only ' +
      (certPath ? 'PEP_HTTPS_CERT' : 'PEP_HTTPS_KEY') + ' is set, so there ' +
      'is no HTTPS listener. Both halves of the pair are needed.', false);
    log.debug("Leaving reloadListenerPair(). Half configured.");
    return;
  }
  let cert;
  let key;
  try {
    cert = fs.readFileSync(certPath);
    key = fs.readFileSync(keyPath);
  } catch (error) {
    // A MISSING FILE IS THE ORDINARY STATE BEFORE A CERTIFICATE IS ISSUED, and
    // it is said as information: this PEP has to register before its realm
    // will certify it, so a fresh container meets this every time.
    const missing = error && error.code === 'ENOENT';
    listenerProblem('STS-XPEP-0030', missing
      ? 'no HTTPS listener yet: ' + error.path + ' does not exist. The ' +
        'certificate comes from the realm this PEP registered to (POST ' +
        '/admin-api/xacml/issue-pep-certificate); write the pair there and ' +
        'the listener starts within ' + options.httpsReloadIntervalMs + 'ms.'
      : 'the HTTPS certificate or key could not be read (' +
        error.message + ').', missing);
    log.debug("Leaving reloadListenerPair(). Unreadable.");
    return;
  }
  const digest = nodeCrypto.createHash('sha256').update(cert).update(key)
    .digest('hex');
  if (digest === listener.digest) {
    log.debug("Leaving reloadListenerPair(). Unchanged.");
    return;
  }
  let x509;
  try {
    // The FIRST certificate in the file is the leaf, which is what node's
    // parser reads; the rest is the chain, sent as it is.
    x509 = new nodeCrypto.X509Certificate(cert);
    const privateKey = nodeCrypto.createPrivateKey(key);
    if (!x509.checkPrivateKey(privateKey)) {
      throw new Error('the private key is not the key this certificate ' +
                      'certifies — most likely one file of the pair has been ' +
                      'written and the other not yet');
    }
    // And TLS will take them, which is a separate question from whether they
    // parse — this is the call that would otherwise throw inside the listener.
    tls.createSecureContext({ cert: cert, key: key });
  } catch (error) {
    listenerProblem('STS-XPEP-0030', 'the HTTPS certificate and key were ' +
      'not used: ' + error.message + '. ' + (listener.listening
        ? 'The listener keeps serving the pair it has.'
        : 'The listener starts when a usable pair is written.'), false);
    log.debug("Leaving reloadListenerPair(). Refused the pair.");
    return;
  }
  const served = describeServed(x509);
  const now = Date.now();
  if (now < Date.parse(served.validFrom) || now > Date.parse(served.validTo)) {
    log.warn(tag('STS-XPEP-0032') + 'xacml-pep: the HTTPS certificate ' +
             served.serialHex + ' is valid from ' + served.validFrom +
             ' to ' + served.validTo + ', which does not include now. It is ' +
             'served anyway — a listener with an expired certificate is ' +
             'easier to diagnose than one that is not there — and every ' +
             'client that checks will refuse the handshake.');
  }
  listener.digest = digest;
  listener.certificate = served;
  listener.loadedAt = new Date().toISOString();
  listener.lastProblem = null;
  lastLoggedProblem = '';
  if (httpsServer) {
    httpsServer.setSecureContext({ cert: cert, key: key });
    log.info('xacml-pep: the HTTPS listener on ' + options.httpsPort +
             ' now serves certificate ' + served.serialHex + ' (' +
             served.subjectAltName + '), issued by ' + served.issuer +
             '. Connections already open keep the certificate they ' +
             'negotiated.');
    log.debug("Leaving reloadListenerPair(). Swapped.");
    return;
  }
  httpsServer = https.createServer({ cert: cert, key: key }, handle);
  httpsServer.on('error', function (error) {
    listener.listening = false;
    listenerProblem('STS-XPEP-0031', 'the HTTPS listener could not listen ' +
      'on ' + options.httpsPort + ': ' + error.message + '. Plain HTTP on ' +
      options.port + ' and enforcement are unaffected.', false);
  });
  httpsServer.listen(options.httpsPort, function () {
    listener.listening = true;
    // The port BOUND, which is the configured one except where that is 0.
    listener.port = httpsServer.address().port;
    log.info('xacml-pep: HTTPS listening on ' + listener.port +
             ' with certificate ' + served.serialHex + ' (' +
             served.subjectAltName + '), issued by ' + served.issuer + '.');
  });
  log.debug("Leaving reloadListenerPair(). Started.");
}

async function start() {
  log.debug("Entering start().");
  // THE BUILD FIRST, before the configuration tour: it is the one line here
  // that is about the ARTIFACT rather than about how it was pointed at a PDP,
  // and it is the line somebody scrolls this container's log back to find when
  // it decides differently from the one next to it.
  log.info('xacml-pep: version ' + VERSION + ' (build ' + APP_VERSION.build +
           (APP_VERSION.commit ? ', commit ' + APP_VERSION.commit : '') +
           ', ' + (APP_VERSION.stamped
                     ? 'stamped at image build time'
                     : 'COMPUTED AT STARTUP — this is not a built image, so ' +
                       'the build number is when this process started') +
           '). M.N is the mock\'s own release; the build number is this ' +
           'image\'s.');
  log.info('xacml-pep: starting. PDP=' + options.pdpUrl + ' name=' +
           options.name + ' bias=' + options.bias);
  if (options.insecure) {
    // ON EVERY START rather than once somewhere, for `federation_http.js`'s
    // reason about insecure requests: a certificate check turned off months
    // ago and forgotten is the worst kind of leftover.
    log.warn('xacml-pep: PEP_TLS_INSECURE is on, so this PEP does NOT verify ' +
             'the PDP\'s certificate. That is the ordinary setting against ' +
             'the mock — it regenerates its key on every start and signs it ' +
             'itself, so there is no anchor to verify against — and it is ' +
             'the wrong setting against anything else.');
  }
  if (!options.clientCertificate) {
    // THE SECOND SENTENCE OF THIS WARNING WAS WRONG FROM 2026-09-06 and it
    // is the kind of wrong that costs an afternoon: it told an operator that
    // a missing certificate affected only the registration, while the PULL
    // had gone behind the same gate — so the visible symptom was a PEP
    // enforcing stale policy for ever, with a log line saying that was fine.
    log.warn('xacml-pep: no PEP_TLS_CERT, so this PEP has no client ' +
             'certificate. The PDP refuses the REGISTRATION unless ' +
             'xacml.pepRequireCertificate is off — and it refuses the PULL ' +
             'too, because GET /xacml/pep/policies requires a VERIFIED ' +
             'certificate whose subject holds the built-in REMOTE_PEPS role. ' +
             'This PEP will go on deciding against whatever policy it ' +
             'already holds, which on a fresh start is NOTHING, so every ' +
             'decision will be NotApplicable and the bias will settle it. ' +
             'Either mount a certificate whose CA the PDP trusts (POST ' +
             '/tls/trust) and put its DN in the group roles.remotePepGroup ' +
             'names, or turn xacml.enforceAccess off on the PDP.');
  }
  // REGISTER FIRST, PULL REGARDLESS. `await`ed rather than fired and
  // forgotten so that the first `GET /` after start reports a settled
  // registration rather than "not attempted yet" — but its result is not
  // checked, because a refused registration must not stop anything. **AND IT
  // IS NO LONGER THE ONLY ATTEMPT**: the poll timer below retries it until it
  // works, so a PEP started before its PDP — or before the realm it polls
  // exists — converges on a console row the same way it converges on policy.
  await sync.register(options);
  await sync.pull(options);

  setInterval(function () {
    // THE REGISTRATION IS RETRIED HERE AND NOWHERE ELSE, on the poll timer
    // rather than a timer of its own — see `sync.js`'s header for why it is
    // retried at all. `registerIfNeeded()` returns immediately once it has
    // worked, so the ordinary case is one comparison on a timer that was
    // already firing.
    //
    // IT DOES NOT GATE THE PULL. The two are chained so the register is
    // attempted first — a row that appears before the counters start moving
    // reads better on the console — but a registration that fails must never
    // stop a pull, which is the whole doctrine of this file, so the catch is
    // between them rather than around both.
    sync.registerIfNeeded(options).catch(function (error) {
      log.debug(tag('STS-XPEP-0011') +
                'xacml-pep: the retried registration threw: ' + error.message);
    }).then(function () {
      return sync.pull(options);
    }).catch(function (error) {
      log.warn(tag('STS-XPEP-0010') + 'xacml-pep: the scheduled pull threw: ' +
               error.message);
    });
  }, options.pollIntervalMs).unref();

  setInterval(function () {
    sync.heartbeat(options).then(function (result) {
      // A PDP THAT SAYS THIS COPY IS BEHIND GETS A PULL IMMEDIATELY. It is the
      // second path to convergence after the nudge and the poll, and it costs
      // one comparison on a beat that was happening anyway.
      if (result.ok && result.current === false) {
        return sync.pull(options);
      }
      return null;
    }).catch(function (error) {
      log.warn(tag('STS-XPEP-0012') + 'xacml-pep: the heartbeat threw: ' +
               error.message);
    });
  }, options.heartbeatIntervalMs).unref();

  server.listen(options.port, function () {
    log.info('xacml-pep: listening on ' + options.port +
             '. The protected resource is GET /protected.');
  });

  // THE HTTPS LISTENER, from whatever pair is on disk now, and again on its
  // own interval — see `reloadListenerPair()` for why it cannot be read once.
  // Not on the poll timer: that one is the policy contract and a slow read of
  // a mounted file has no business delaying a pull.
  if (options.httpsCertPath || options.httpsKeyPath) {
    log.info('xacml-pep: HTTPS is configured on ' + options.httpsPort +
             ' from ' + (options.httpsCertPath || '(no PEP_HTTPS_CERT)') +
             ' and ' + (options.httpsKeyPath || '(no PEP_HTTPS_KEY)') +
             ', re-read every ' + options.httpsReloadIntervalMs + 'ms.');
    reloadListenerPair();
    setInterval(reloadListenerPair, options.httpsReloadIntervalMs).unref();
  }
  log.debug("Leaving start().");
}

// Guarded so that `tests/xacml_pep.js` can require this file for `enforce()`
// and `decide()` without starting a listener or a timer — the same guard
// `common/worker.js` carries, for the same reason.
if (require.main === module) {
  start().catch(function (error) {
    log.error(tag('STS-XPEP-0013') + 'xacml-pep: could not start: ' +
              (error && error.stack ? error.stack : error));
    process.exit(1);
  });
}

module.exports = { enforce: enforce, decide: decide, overview: overview,
                   protectedResource: protectedResource, options: options,
                   server: server, start: start,
                   // For an in-process test of the listener's reload rules,
                   // which is the one part of this file a wrong pair on disk
                   // can reach without a PDP.
                   reloadListenerPair: reloadListenerPair,
                   listener: listener,
                   httpsServer: function () {
                     log.debug("Entering httpsServer().");
                     log.debug("Leaving httpsServer().");
                     return httpsServer;
                   } };
