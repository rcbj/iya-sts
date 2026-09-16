'use strict';
//
// File: xacml-pep/sync.js
//
// ===========================================================================
// THE PDP CLIENT: REGISTER, PULL, HEARTBEAT. THE PULL IS THE CONTRACT.
//
// This module holds the policies this PEP is enforcing, in memory, and keeps
// them current by POLLING the PDP. Everything else here is subordinate to that
// sentence:
//
//   * REGISTERING is optional. It buys a row on the PDP's console and an
//     address for the nudge; it is not what lets this PEP enforce. A PEP that
//     fails to register — no certificate, the PDP refusing, the register full
//     — goes on pulling and deciding, and says so rather than exiting. Getting
//     that backwards would make a monitoring feature into a hard dependency
//     for authorization, which is the worst trade in the file.
//
//     **AND SINCE 2026-09-06 IT IS RETRIED ON THE POLL TIMER UNTIL IT
//     SUCCEEDS, WHICH IS A CORRECTION AND NOT AN ELABORATION.** Registering
//     happened exactly once, at start, and a PEP that came up before its PDP
//     — or survived a PDP restart it started during — then enforced correctly
//     FOR EVER while appearing on nobody's console. That is the worst shape
//     the optional/required distinction can take: the feature degrades
//     invisibly and permanently, and `/admin/xacml/peps` reports an empty
//     register on a deployment that is working. `depends_on:
//     service_healthy` hides it in the shipped compose file and hides nothing
//     anywhere else.
//
//     The retry costs one request per polling interval while unregistered and
//     nothing at all afterwards, it is logged at `warn` ONCE and at `debug`
//     from then on so a PDP that refuses on policy grounds cannot fill a log,
//     and `registration.attempts` is on `GET /` so that "registered on the
//     fourth try" is visible rather than inferred.
//   * THE NUDGE is optional twice over. `pep.js` answers a nudge by calling
//     `pull()` early; if the nudge never arrives, the poll below arrives
//     instead, at most one interval later.
//   * THE HEARTBEAT is optional too. It reports what this PEP has enforced so
//     that a person can see it on the PDP's console. Nothing here reads the
//     answer except to log whether the PDP thinks this copy is current.
//
// So the only thing that must work is the pull, and this file is arranged so
// that a failure anywhere else cannot stop it.
//
// ---------------------------------------------------------------------------
// WHAT HAPPENS WHEN THE PULL ITSELF FAILS, WHICH IS THE INTERESTING CASE.
//
// **THE LAST GOOD POLICY SET IS KEPT AND ENFORCEMENT CONTINUES.** A PDP that
// is down, unreachable or answering nonsense does not make this PEP stop
// deciding — it makes it go on deciding with what it last pulled, and mark
// itself stale. The alternative is a distributed authorization system in which
// a PDP outage denies everything everywhere, which is the failure mode that
// makes people take authorization services out.
//
// That is a real trade and it is worth stating what it costs: a policy change
// made while this PEP cannot reach the PDP is NOT enforced here, and this PEP
// will go on allowing something the policy no longer allows. Both surfaces say
// so — `GET /` on this container reports `stale` and how long since the last
// successful pull, and the PDP's own `/admin/xacml/peps` shows the row as
// stale and not current. A PEP that hid it would be the dangerous one.
//
// **AND A PEP THAT HAS NEVER SUCCEEDED IS A DIFFERENT STATE FROM ONE THAT HAS
// GONE STALE.** With no policy set at all there is nothing to enforce, every
// decision is NotApplicable, and the bias decides — which for the default
// deny-biased PEP means refusing everything. That is the correct answer and it
// is reported as `loaded: false` rather than as an empty repository, because
// "no policy" and "a policy that permits nothing" are indistinguishable from
// the outside and want opposite fixes.
// ===========================================================================

const https = require('https');
const http = require('http');
const { URL } = require('url');
const engine = require('./engine');

const log = engine.log;

// THE ERROR-CODE TAG, handed in on `options` by `pep.js`, which resolves the
// registry across both layouts (see `loadErrorCodes()` there). The fallback is
// the registry's own format, so a caller that built its options elsewhere
// still gets a coded line rather than a TypeError out of a polling timer.
function tag(options, code) {
  log.debug("Entering tag().");
  if (options && typeof options.tag === 'function') {
    log.debug("Leaving tag().");
    return options.tag(code);
  }
  log.debug("Leaving tag().");
  return '[' + code + '] ';
}

// What this PEP holds. Everything about the current policy set in one object,
// replaced WHOLE on a successful pull rather than mutated field by field —
// so there is no moment at which the root and the repository disagree, which
// is a state a decision arriving mid-pull could otherwise be evaluated in.
let held = {
  loaded: false,
  syncToken: '',
  root: null,
  repository: {},
  policyCount: 0,
  lastPullAt: '',
  lastPullOk: false,
  lastPullWhy: 'No pull has been attempted yet.',
  refused: []
};

let registration = { registered: false, name: '', attempts: 0,
                     why: 'Not attempted yet.' };

// The PEP's own counters. Cumulative in THIS process — a restart resets them,
// which is honest and is what the PDP's console says about them.
const counters = { decisions: 0, allowed: 0, refused: 0, undischargeable: 0 };

function state() {
  log.debug("Entering state().");
  log.debug("Leaving state().");
  return {
    held: {
      loaded: held.loaded,
      syncToken: held.syncToken,
      // THE ROOT'S IDENTIFIER, NEVER THE PARSED TREE. `held.root` is the whole
      // policy object the evaluator walks, and returning it from a state
      // reporter put forty kilobytes of parsed XACML into `GET /` — which
      // buried the four fields somebody actually came to that page for. What a
      // reader wants here is which document this PEP starts from.
      root: held.root ? (held.root.id || '(unnamed)') : null,
      policyCount: held.policyCount,
      lastPullAt: held.lastPullAt,
      lastPullOk: held.lastPullOk,
      lastPullWhy: held.lastPullWhy,
      refused: held.refused.slice(0)
    },
    registration: Object.assign({}, registration),
    counters: Object.assign({}, counters)
  };
}

function countDecision(outcome) {
  log.debug("Entering countDecision().");
  counters.decisions += 1;
  if (outcome.allowed) {
    counters.allowed += 1;
  } else {
    counters.refused += 1;
  }
  if (outcome.undischargeable && outcome.undischargeable.length) {
    counters.undischargeable += 1;
  }
  log.debug("Leaving countDecision().");
}

// ---------------------------------------------------------------------------
// ONE HTTP CALL TO THE PDP.
//
// Resolves with `{ status, body, error }` and never rejects, for
// `xacml_pep_http.js`'s reason on the other side: every caller here wants to
// RECORD what happened and carry on, and an exception thrown out of a polling
// timer takes the process down.
//
// THE CLIENT CERTIFICATE, when there is one, goes on EVERY call rather than
// only on the registration. Two reasons: the PDP identifies a heartbeat by the
// certificate exactly as it identifies a registration, so a heartbeat sent
// without one would be filed against the name in the body — which the PDP
// rightly refuses to prefer — and a connection that is mutually authenticated
// for one request and not the next is a distinction nobody watching a TLS log
// would expect to have to make.
// ---------------------------------------------------------------------------
function call(options, method, path, body) {
  log.debug("Entering call().");
  log.debug("Leaving call().");
  return new Promise(function (resolve) {
    let base;
    try {
      base = new URL(options.pdpUrl);
    } catch (error) {
      log.debug("Caught in a callback in call(): " +
                ((error && error.message) || error));
      resolve({ status: 0, body: null,
                error: 'PEP_PDP_URL is not a URL: ' + options.pdpUrl });
      return;
    }
    const insecure = base.protocol === 'http:';
    const transport = insecure ? http : https;
    const payload = body === undefined ? null : JSON.stringify(body);
    const request = transport.request({
      method: method,
      hostname: base.hostname,
      port: base.port || (insecure ? 80 : 443),
      path: (base.pathname === '/' ? '' : base.pathname) + path,
      headers: Object.assign(
        { Accept: 'application/json' },
        payload ? { 'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(payload) } : {}),
      timeout: options.timeoutMs,
      cert: options.clientCertificate || undefined,
      key: options.clientKey || undefined,
      ca: options.pdpCa || undefined,
      // THE MOCK'S LISTENER CERTIFICATE IS ISSUED BY A SERVICE ROOT THAT
      // DEVELOPMENT MODE REGENERATES ON EVERY START, so there is no fixed
      // anchor to verify against until somebody fetches one (PEP_TLS_CA). That
      // is a property of the thing this PEP exists to talk to, not laziness
      // here — and it is why PEP_TLS_INSECURE exists and why `pep.js` logs it
      // on every start rather than once.
      rejectUnauthorized: !options.insecure
    }, function (response) {
      const chunks = [];
      let received = 0;
      response.on('data', function (chunk) {
        received += chunk.length;
        if (received <= options.maxBodyBytes) {
          chunks.push(chunk);
          return;
        }
        response.destroy();
      });
      response.on('end', function () {
        const text = Buffer.concat(chunks).toString('utf8');
        let parsed = null;
        if (text) {
          try {
            parsed = JSON.parse(text);
          } catch (error) {
            log.debug("Caught in a callback in call(): " +
                      ((error && error.message) || error));
            // Not JSON; the raw text is what gets reported, which is what a
            // PDP answering an HTML error page or a proxy's message looks
            // like and is exactly what somebody debugging needs to see.
            parsed = null;
          }
        }
        resolve({ status: response.statusCode || 0, body: parsed,
                  text: text, error: null });
      });
    });
    request.on('timeout', function () {
      request.destroy(new Error('the PDP did not answer within ' +
                                options.timeoutMs + 'ms'));
    });
    request.on('error', function (error) {
      resolve({ status: 0, body: null,
                error: error && error.message ? error.message
                                              : String(error) });
    });
    request.end(payload || undefined);
  });
}

// ---------------------------------------------------------------------------
// REGISTER. Best effort, always — see the header.
// ---------------------------------------------------------------------------
async function register(options) {
  log.debug('Entering register().');
  // COUNTED BEFORE THE REQUEST, so that a call which throws on the way out
  // still shows on `GET /` as an attempt. The count is also what decides the
  // log level below: the FIRST failure is a warn because it is news, and every
  // one after it is a debug because a PDP refusing on policy grounds — no
  // certificate, xacml.pepRequireCertificate on — would otherwise write a
  // warning every polling interval for as long as the container is up.
  const first = registration.attempts === 0;
  const attempts = registration.attempts + 1;
  const complain = first ? log.warn.bind(log) : log.debug.bind(log);
  const answer = await call(options, 'POST', '/xacml/pep/register', {
    name: options.name,
    notifyUrl: options.notifyUrl,
    bias: options.bias,
    resource: options.resource,
    version: options.version,
    description: options.description
  });
  if (answer.error) {
    registration = { registered: false, name: options.name, attempts: attempts,
                     why: 'Could not reach the PDP to register: ' +
                          answer.error + '. THIS PEP STILL ENFORCES — ' +
                          'registering buys a row on the PDP console and an ' +
                          'address for the nudge, not the ability to decide. ' +
                          'It is retried on every poll (attempt ' + attempts +
                          ').' };
    complain(tag(options, 'STS-XPEP-0015') + 'xacml-pep: ' + registration.why);
    log.debug('Leaving register(). Unreachable.');
    return registration;
  }
  if (answer.status !== 200 && answer.status !== 201) {
    const why = (answer.body && answer.body.error_description) ||
                answer.text || ('the PDP answered ' + answer.status);
    // ---------------------------------------------------------------------
    // WHAT THIS SENTENCE SAID UNTIL IT WAS FIXED, AND WHY IT MATTERED.
    //
    // It read "THIS PEP STILL ENFORCES — GET /xacml/pep/policies needs no
    // credential", which stopped being true on 2026-09-06 when the three
    // /xacml/pep/* endpoints went behind a verified client certificate
    // holding REMOTE_PEPS. `xacml-pep/CLAUDE.md` recorded that correction for
    // its prose and this string was missed — so an operator whose certificate
    // was missing or unrecognised was told, on the same `GET /` page whose
    // `holding.lastPullWhy` carried the PDP's 403 about REMOTE_PEPS, that the
    // pull needed no credential. The one place the two disagreed was the one
    // place somebody was reading to find out which it was.
    //
    // **REGISTERING IS STILL NOT WHAT LETS THIS PEP DECIDE**, and that half
    // is unchanged: it buys a row on the PDP's console and an address for the
    // nudge. What is no longer safe to say is anything about the PULL, and
    // the reason is that this branch covers refusals that need OPPOSITE
    // readings — 401 and 403 are the credential, and the pull is refused too;
    // 400 (the register is full, the name is taken) and 501 (remote PEPs are
    // turned off on that service) leave a credentialed PEP pulling and
    // enforcing perfectly. So it names both and points at the one field that
    // answers it for this deployment rather than guessing.
    // ---------------------------------------------------------------------
    registration = { registered: false, name: options.name, attempts: attempts,
                     why: 'The PDP refused the registration (' +
                          answer.status + '): ' + why + ' Registering buys a ' +
                          'row on the PDP console and an address for the ' +
                          'nudge, not the ability to decide — but the PULL ' +
                          'needs the same credential, since GET ' +
                          '/xacml/pep/policies requires the REMOTE_PEPS ' +
                          'role. So a refusal about a certificate or that ' +
                          'role will have refused the pull as well, and one ' +
                          'about anything else will not: holding.lastPullWhy ' +
                          'is what says which happened here. It is retried ' +
                          'on every poll (attempt ' + attempts + ').' };
    complain(tag(options, 'STS-XPEP-0016') + 'xacml-pep: ' + registration.why);
    log.debug('Leaving register(). Refused.');
    return registration;
  }
  const said = answer.body || {};
  registration = {
    registered: true,
    name: said.name || options.name,
    attempts: attempts,
    authenticated: !!said.authenticated,
    why: said.authenticated
      ? 'Registered over mutual TLS as "' + said.name + '".'
      : 'Registered as "' + said.name + '" WITHOUT a client certificate; ' +
        'the PDP has marked this row unauthenticated and is right to.',
    // REPORTED BACK RATHER THAN ASSUMED. If the PDP will not dial this PEP's
    // notify URL — wrong scheme, not on its allowlist — it says so in the
    // registration reply, and hiding that would leave somebody wondering for
    // an hour why a nudge never arrives when the answer was in the first
    // response.
    notify: said.notify || null
  };
  log.info('xacml-pep: ' + registration.why +
           (attempts > 1
             ? ' It took ' + attempts + ' attempts — this PEP was up before ' +
               'its PDP was, or before the realm it polls existed, and the ' +
               'retry on the poll timer is what closed the gap.'
             : '') +
           (registration.notify && !registration.notify.usable
             ? ' The PDP will NOT nudge this PEP: ' + registration.notify.why +
               ' That costs one polling interval of latency and nothing else.'
             : ''));
  log.debug('Leaving register(). Registered.');
  return registration;
}

// ---------------------------------------------------------------------------
// REGISTER AGAIN IF IT HAS NOT WORKED YET. Called from the poll timer, so the
// interval between attempts is the polling interval and there is no second
// timer to reason about.
//
// **A SUCCESSFUL REGISTRATION IS NEVER REPEATED**, which is what keeps this
// from being a request per interval for the life of the container: the guard
// is the state, not a counter or a backoff. Re-registering a PEP that is
// already on the register would also rewrite its row's `registeredAt`, and the
// PDP's own `register()` treats a second call as a re-registration and says
// `created: false` — harmless, and still noise nobody asked for.
// ---------------------------------------------------------------------------
async function registerIfNeeded(options) {
  log.debug("Entering registerIfNeeded().");
  if (registration.registered) {
    log.debug("Leaving registerIfNeeded().");
    return registration;
  }
  log.debug("Leaving registerIfNeeded().");
  return register(options);
}

// ---------------------------------------------------------------------------
// PULL. The one thing that has to work.
// ---------------------------------------------------------------------------
async function pull(options) {
  log.debug('Entering pull().');
  const since = held.syncToken
    ? '?since=' + encodeURIComponent(held.syncToken) +
      '&pep=' + encodeURIComponent(options.name)
    : '?pep=' + encodeURIComponent(options.name);
  const answer = await call(options, 'GET', '/xacml/pep/policies' + since);
  if (answer.error) {
    log.debug("Leaving pull().");
    return keep('Could not reach the PDP: ' + answer.error,
                tag(options, 'STS-XPEP-0017'));
  }
  if (answer.status === 304) {
    // UNCHANGED IS A SUCCESSFUL PULL. It moves `lastPullAt`, because the
    // question "when did this PEP last confirm it was current" is the one
    // `stale` is about — and a 304 answers it exactly as well as a 200.
    held.lastPullAt = new Date().toISOString();
    held.lastPullOk = true;
    held.lastPullWhy = 'Unchanged; this copy is current.';
    log.debug('Leaving pull(). Unchanged.');
    return state().held;
  }
  if (answer.status !== 200) {
    log.debug("Leaving pull().");
    return keep('The PDP answered ' + answer.status +
                ((answer.body && answer.body.error_description)
                  ? ': ' + answer.body.error_description : '') + '.',
                tag(options, 'STS-XPEP-0018'));
  }
  const said = answer.body;
  if (!said || !Array.isArray(said.policies)) {
    log.debug("Leaving pull().");
    return keep('The PDP answered 200 with something that is not a policy ' +
                'set. Keeping the previous one.',
                tag(options, 'STS-XPEP-0019'));
  }
  // PARSED AND STATICALLY VALIDATED HERE, by this PEP's own copy of the
  // validator, and NOT taken on trust because the PDP said it was fine. That
  // is the same reason `tests/vendored/sts_dpop.js` writes its own DPoP
  // client: if both ends of the exchange came from one running process, a
  // shared misunderstanding would pass and interoperate with nobody. Here the
  // two ends are the same SOURCE, which is deliberate — but they are different
  // PROCESSES with different memory, and a document that has been through a
  // JSON round trip is a document worth parsing again.
  const repository = {};
  const refused = [];
  let root = null;
  said.policies.forEach(function (row) {
    let parsed;
    try {
      parsed = engine.xml.parsePolicy(row.document);
    } catch (error) {
      // A POLICY THIS PEP CANNOT LOAD IS LEFT OUT AND NAMED, never silently
      // dropped and never fatal. Left out because enforcing half a document
      // is worse than not having it; named because a PEP whose policy count
      // disagrees with the PDP's is exactly what the console's policyCount
      // column exists to show.
      refused.push({ name: row.name,
                     why: error.message });
      return;
    }
    if (row.policyId) {
      repository[row.policyId] = parsed;
    }
    if (row.isRoot) {
      root = parsed;
    }
  });
  // The PDP's own convenience rule, restated here rather than relied on:
  // exactly one enabled policy is unambiguously the root. Written out because
  // this PEP must not decide differently from the PDP about which document it
  // starts from, and "the PDP will have set isRoot" is an assumption that
  // would fail silently as a NotApplicable.
  if (!root && said.policies.length === 1 && !refused.length) {
    try {
      root = engine.xml.parsePolicy(said.policies[0].document);
    } catch (error) {
      log.debug("Caught in pull(): " + ((error && error.message) || error));
      // Not reachable in practice: this branch runs only when the same
      // document parsed cleanly above (`!refused.length`). If it did throw,
      // there is no root and the state below says so.
      root = null;
    }
  }
  held = {
    loaded: !!root,
    syncToken: String(said.syncToken || ''),
    root: root,
    repository: repository,
    policyCount: said.policies.length,
    lastPullAt: new Date().toISOString(),
    lastPullOk: true,
    lastPullWhy: root
      ? 'Pulled ' + said.policies.length + ' policy(ies).'
      : 'Pulled ' + said.policies.length + ' policy(ies) and NONE IS THE ' +
        'ROOT, so there is nothing to start evaluation from and every ' +
        'decision is NotApplicable. The bias then decides, which for a ' +
        'deny-biased PEP means refusing everything.',
    refused: refused
  };
  if (refused.length) {
    log.warn(tag(options, 'STS-XPEP-0020') +
             'xacml-pep: ' + refused.length + ' of ' + said.policies.length +
             ' pulled policy(ies) would not load here and were left out: ' +
             refused.map(function (one) {
               return one.name + ' (' + one.why + ')';
             }).join('; '));
  }
  // Tagged only when nothing is the root: the pull worked and there is still
  // nothing to evaluate, which is the state an operator has to go and fix.
  log.info((root ? '' : tag(options, 'STS-XPEP-0021')) +
           'xacml-pep: pulled ' + said.policies.length + ' policy(ies), ' +
           'token ' + held.syncToken + '. ' + held.lastPullWhy);
  log.debug('Leaving pull(). Loaded.');
  return state().held;
}

// A FAILED PULL KEEPS WHAT IS HELD. See the header for the trade this is.
// `prefix` is the caller's error-code tag, which goes on the LOG LINE only —
// `lastPullWhy` is drawn on `GET /` and a code is never put in front of a
// caller.
function keep(why, prefix) {
  log.debug("Entering keep().");
  // `lastPullAt` IS DELIBERATELY NOT TOUCHED. It means "when did this PEP last
  // confirm it was current", so a FAILED pull must leave it where it was —
  // that gap is precisely what `stale` is computed from, and stamping it here
  // would make a PEP that has not reached the PDP for an hour report itself
  // freshly synchronised. It is the same rule `recordNotify()` follows on the
  // PDP's side for the same reason.
  held.lastPullOk = false;
  held.lastPullWhy = why + (held.loaded
    ? ' KEEPING the ' + held.policyCount + ' policy(ies) pulled at ' +
      held.lastPullAt + ' and going on enforcing them — a PDP outage that ' +
      'denied everything everywhere would be a worse failure than a stale ' +
      'copy. This PEP reports itself stale on GET / and the PDP shows it as ' +
      'stale too.'
    : ' NOTHING IS HELD, so there is no policy to enforce: every decision is ' +
      'NotApplicable and the bias decides. That is a different state from a ' +
      'stale copy and is reported as loaded: false.');
  log.warn((prefix || '') + 'xacml-pep: ' + held.lastPullWhy);
  log.debug("Leaving keep().");
  return state().held;
}

// ---------------------------------------------------------------------------
// HEARTBEAT. What this PEP has enforced, so a person can see it.
// ---------------------------------------------------------------------------
async function heartbeat(options) {
  log.debug('Entering heartbeat().');
  const answer = await call(options, 'POST', '/xacml/pep/heartbeat', {
    name: options.name,
    syncToken: held.syncToken,
    policyCount: held.policyCount,
    decisions: counters.decisions,
    allowed: counters.allowed,
    refused: counters.refused,
    undischargeable: counters.undischargeable,
    bias: options.bias,
    resource: options.resource,
    version: options.version,
    notifyUrl: options.notifyUrl
  });
  if (answer.error || answer.status !== 200) {
    // NOT A WARNING WORTH RAISING ABOVE debug ON EVERY BEAT. A heartbeat is
    // reporting, and a PEP that cannot report is still enforcing correctly —
    // logging it at warn on a sixty-second timer would fill a log with the
    // least important failure this container has.
    log.debug((answer.error ? tag(options, 'STS-XPEP-0022')
                            : tag(options, 'STS-XPEP-0023')) +
              'Leaving heartbeat(). Not delivered: ' +
              (answer.error || answer.status));
    log.debug("Leaving heartbeat().");
    return { ok: false };
  }
  const said = answer.body || {};
  if (said.current === false) {
    log.info('xacml-pep: the PDP says this copy is not the current one. ' +
             'Pulling.');
  }
  log.debug('Leaving heartbeat(). Acknowledged.');
  return { ok: true, current: !!said.current };
}

// What the PEP decides with. Handed to `xacml_pdp.js` as its repository, and
// a plain accessor rather than an exported variable so that a caller cannot be
// holding last minute's object while a pull replaces it.
function current() {
  log.debug("Entering current().");
  log.debug("Leaving current().");
  return { root: held.root, repository: held.repository,
           loaded: held.loaded };
}

module.exports = {
  register: register,
  registerIfNeeded: registerIfNeeded,
  pull: pull,
  heartbeat: heartbeat,
  current: current,
  state: state,
  countDecision: countDecision
};
