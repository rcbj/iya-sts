// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: session-vectors.js
//
// ---------------------------------------------------------------------------
// THE SESSION CORE (#444, phase 5, the `session` slice): what `authn/authn.ts`
// does with the sign-on session — start, record, re-authenticate, rotate,
// present, expire, end, merge, and the refusals at `startSession()` — door by
// door, for the Rust crate `sts-authn` to reproduce. Called by
// `tests/tools/crypto-vectors.js`'s `session-node.json` row, in a process of
// its own.
//
// THE METHOD IS `registers-vectors.js`'s: A RECORDING OF EVERY PORT. Each
// step drives the REAL `Authn` class, an instance built here over its own
// dependencies, with every dependency the Rust crate takes as a port wrapped
// in a recorder — the directory's subject resolver and `userFor()`, the
// account state, the issuance gate, the authentication policy, the post-login
// register, the identity register (`stats`), the audit log, the session
// observer, the device binding, the back-channel library, the clock and the
// random ids. The Rust test replays those answers to its own session service
// and checks that it made the same calls with the same arguments, gave the
// same answer, wrote the same cookies, and left the session store holding
// the same rows, member for member.
//
// WHAT IS PINNED RATHER THAN DRIVEN. `authn.multipleAccounts` is off (the
// account sets are not this slice's; the report says why), the session
// window is off (no minted persistence in process), and the risk engine is
// absent: each is a setting or a port the Rust crate answers the same way.
// The credentials slice's checks that `startSession()` asks of a passkey
// (`passkeySignInRefusal()`, `recoveryRefusalAtSession()` and the two notes
// beside them) are recorded as ports of the instance, because the ceremony
// they read is that slice's to port.
// ---------------------------------------------------------------------------

const path = require('path');

/**
 * A JSON copy of what crossed a port: functions and `undefined` dropped from
 * objects, `undefined` as null in arrays, a request object as `[request]`.
 *
 * @param {any} value - anything
 * @param {any[]} opaque - objects recorded by a name rather than copied
 * @returns {any} its JSON image
 */
function clone(value, opaque) {
  const ancestors = [];
  const copy = function (v) {
    if (v === undefined || typeof v === 'function' || typeof v === 'symbol') {
      return undefined;
    }
    if (v === null || typeof v !== 'object') {
      return typeof v === 'number' && !isFinite(v) ? null : v;
    }
    for (let i = 0; i < opaque.length; i++) {
      if (opaque[i].value === v) {
        return opaque[i].name;
      }
    }
    if (typeof v.toJSON === 'function') {
      return copy(v.toJSON());
    }
    if (ancestors.indexOf(v) >= 0) {
      return '[cycle]';
    }
    ancestors.push(v);
    let out;
    if (Array.isArray(v)) {
      out = v.map(function (one) {
        const c = copy(one);
        return c === undefined ? null : c;
      });
    } else {
      out = {};
      Object.keys(v).forEach(function (k) {
        const c = copy(v[k]);
        if (c !== undefined) {
          out[k] = c;
        }
      });
    }
    ancestors.pop();
    return out;
  };
  const out = copy(value);
  return out === undefined ? null : out;
}

/**
 * The recorder every wrapped port writes to.
 *
 * @returns {any} the recorder
 */
function recorder() {
  const rec = { calls: null, depth: 0, opaque: [] };
  rec.copy = function (v) {
    return clone(v, rec.opaque);
  };
  // A port method: each call written down with its arguments and answer,
  // unless it was made from inside another recorded call.
  rec.fn = function (port, method, f) {
    return function () {
      const args = Array.prototype.slice.call(arguments);
      if (!rec.calls || rec.depth > 0) {
        return f.apply(this, args);
      }
      rec.depth += 1;
      let answer;
      let threw = null;
      try {
        answer = f.apply(this, args);
      } catch (e) {
        threw = e;
      } finally {
        rec.depth -= 1;
      }
      const row = { port: port, method: method, args: rec.copy(args) };
      if (threw) {
        row.threw = String((threw && threw.message) || threw);
        rec.calls.push(row);
        throw threw;
      }
      row.answer = rec.copy(answer);
      rec.calls.push(row);
      return answer;
    };
  };
  return rec;
}

/**
 * The recorded ports and the real `Authn` over them, for this file's
 * steps and for `account-set-vectors.js`'s (#561).
 *
 * @param {string} ROOT - the repository root
 * @param {any} more - `{ overrides, people }` added to the defaults
 * @returns {any} what the steps are written with
 */
function harness(ROOT, more) {
  const req = function (rel) {
    return require(path.join(ROOT, rel));
  };
  const rec = recorder();

  // ---- the clock and the random ids -------------------------------------
  // Date.now() is the clock every lifetime is stamped and judged with; a
  // step sets it, and nothing moves it inside a step.
  const clock = { now: Date.UTC(2026, 10, 14, 12, 0, 0) };
  const realNow = Date.now;
  Date.now = function () {
    return clock.now;
  };
  const nodeCrypto = require('crypto');
  let counter = 0;
  const randomId = rec.fn('random', 'id', function (bytes) {
    counter += 1;
    return nodeCrypto.createHash('sha256').update('session-vectors:' +
      counter).digest('base64url').slice(0, Math.ceil((bytes || 24) * 4 / 3));
  });

  // ---- the settings ------------------------------------------------------
  const config = req('common/config');
  const realValue = config.value.bind(config);
  const overrides = {
    'authn.multipleAccounts': false,
    'authn.deviceBoundSessions': false,
    'authn.sessionWindow': 'off',
    'authn.sessionLifetimeS': 3600,
    'authn.sessionIdleTimeoutS': 0,
    'authn.sessionsEndedBefore': 0,
    'authn.maxSessions': 100000,
    'authn.maxSessionsPerSubject': 32,
    'authn.pendingTtlS': 600,
    'risk.fingerprinting': false,
    'global.https': true
  };
  Object.assign(overrides, (more && more.overrides) || {});
  config.value = rec.fn('settings', 'value', function (key) {
    if (Object.prototype.hasOwnProperty.call(overrides, key)) {
      return overrides[key];
    }
    return realValue.apply(null, arguments);
  });

  const mode = req('common/mode');
  const modeAnswers = { verifiesCredentials: false,
                        revokesAccessTokensAtSignOut: false };
  ['verifiesCredentials', 'revokesAccessTokensAtSignOut'].forEach(function (m) {
    mode[m] = rec.fn('mode', m, function () {
      return modeAnswers[m];
    });
  });

  const realms = req('common/realms');
  const state = { retiring: null };
  realms.retiringRefusal = rec.fn('realms', 'retiringRefusal', function () {
    return state.retiring;
  });

  // ---- the directory: who exists, and their subjects ----------------------
  const people = {
    dora: '0b6f6c1e-8c55-4b8a-9b2e-3d1f0d5c2a11',
    emil: '7d0f2a44-1b9c-4f3e-8a6d-5c2b1e9f4d22',
    fay: '3c9e7b55-2d8a-4e1f-9b3c-6a5d4e2f1b33',
    svc: '9a8b7c66-3e2d-4f1a-8c9b-7d6e5f4a3c44',
    anonymous: 'aa11bb22-cc33-4dd4-8ee5-ff66aa77bb88'
  };
  Object.assign(people, (more && more.people) || {});
  const gone = {};
  const subjectOf = function (name) {
    const key = String(name || '');
    return people[key] && !gone[key] ? 'urn:uuid:' + people[key] : '';
  };
  const nameOf = function (sub) {
    const id = String(sub || '').replace(/^urn:uuid:/i, '');
    const found = Object.keys(people).filter(function (n) {
      return people[n] === id && !gone[n];
    })[0];
    return found || '';
  };
  const helpers = req('common/helpers');
  const wrappedHelpers = Object.assign({}, helpers, {
    subjectForName: rec.fn('people', 'subjectForName', subjectOf),
    nameForSubject: rec.fn('people', 'nameForSubject', nameOf),
    hasSubjectResolver: rec.fn('people', 'hasSubjectResolver', function () {
      return true;
    }),
    cookieDomainAttribute: rec.fn('helpers', 'cookieDomainAttribute',
      function () {
        return '';
      })
  });
  const userFor = rec.fn('people', 'userFor', function (username) {
    const typed = String(username || 'mock-user');
    const sub = subjectOf(typed);
    return { sub: sub, username: typed, preferred_username: typed };
  });

  // ---- the registers and policies the doors ask --------------------------
  const disabled = {};
  const accountState = {
    isDisabled: rec.fn('accounts', 'isDisabled', function (who) {
      return !!disabled[nameOf(who) || String(who || '')];
    })
  };
  const serviceAccounts = { svc: true };
  const credentials = Object.assign(Object.create(req('common/credentials')),
    { serviceAccountRefusesDoor: rec.fn('accounts',
        'serviceAccountRefusesDoor', function (username) {
          return !!serviceAccounts[String(username || '')];
        }) });
  const policy = { allows: {} };
  const authnPolicy = Object.assign(Object.create(req('common/authn_policy')),
    { allows: rec.fn('authnPolicy', 'allows', function (mechanism, role) {
      const key = mechanism + '/' + role;
      return Object.prototype.hasOwnProperty.call(policy.allows, key)
        ? policy.allows[key] : true;
    }) });
  const passkeyPolicy = Object.assign(Object.create(req(
    'common/passkey_policy')), { select: rec.fn('passkeyPolicy', 'select',
    function () {
      return undefined;
    }) });
  const due = {};
  const postLogin = Object.assign(Object.create(req('common/post_login')),
    { dueFor: rec.fn('postLogin', 'dueFor', function (username) {
      return due[String(username)] || null;
    }) });
  const gateAnswers = [];
  const realGate = req('common/issuance_gate');
  const gate = Object.assign(Object.create(realGate), {
    ISSUANCE: realGate.ISSUANCE,
    check: rec.fn('gate', 'check', function () {
      return gateAnswers.length ? gateAnswers.shift()
        : { allowed: true, why: '' };
    }),
    deviceRequirementOf: rec.fn('gate', 'deviceRequirementOf', function () {
      return [];
    })
  });
  const deviceRecognition = { recognize: rec.fn('devices', 'recognize',
    function () {
      return null;
    }) };
  const clientHello = { of: rec.fn('request', 'clientHello', function (r) {
    return (r && r.hello) || null;
  }) };

  // ---- the effects -------------------------------------------------------
  const stats = req('common/admin_stats');
  const wrappedStats = Object.assign(Object.create(stats), {
    recordAuthentication: rec.fn('stats', 'recordAuthentication',
      function () {
        return undefined;
      }),
    revokeWhere: rec.fn('stats', 'revokeWhere', function () {
      return 0;
    }),
    recordAccountChoice: rec.fn('stats', 'recordAccountChoice',
      function () {
        return undefined;
      })
  });
  const audit = req('common/audit');
  const wrappedAudit = Object.assign(Object.create(audit), {
    audit: rec.fn('audit', 'audit', function () {
      return undefined;
    }),
    currentRequest: function () {
      return null;
    },
    currentAddress: function () {
      return '';
    }
  });
  const deviceBound = req('authn/device_bound_sessions');
  deviceBound.offer = rec.fn('deviceBound', 'offer', function () {
    return undefined;
  });
  deviceBound.honours = rec.fn('deviceBound', 'honours', function () {
    return true;
  });
  deviceBound.noteSkipped = rec.fn('deviceBound', 'noteSkipped', function () {
    return undefined;
  });
  deviceBound.bindingOf = rec.fn('deviceBound', 'bindingOf', function () {
    return null;
  });

  const authnModule = req('authn/authn');
  const Authn = authnModule.Authn;
  const deps = Object.assign(Authn.defaultDeps(), {
    randomId: randomId, userFor: userFor, helpers: wrappedHelpers,
    config: config, accountState: accountState, credentials: credentials,
    authnPolicy: authnPolicy, passkeyPolicy: passkeyPolicy,
    postLogin: postLogin, gate: gate, deviceRecognition: deviceRecognition,
    clientHello: clientHello, stats: wrappedStats, audit: wrappedAudit,
    mode: mode
  });
  const authn = new Authn(deps);

  // The credentials slice's checks, recorded as ports of the instance.
  const passkeyRefusals = {};
  authn.passkeySignInRefusal = rec.fn('credentials', 'passkeySignInRefusal',
    function (username) {
      return passkeyRefusals[String(username)] || null;
    });
  authn.recoveryRefusalAtSession = rec.fn('credentials',
    'recoveryRefusalAtSession', function () {
      return null;
    });
  authn.noteAlgorithmMismatch = rec.fn('credentials', 'noteAlgorithmMismatch',
    function () {
      return undefined;
    });
  authn.recoveryCompleted = rec.fn('credentials', 'recoveryCompleted',
    function () {
      return undefined;
    });
  authn.riskEngine = function () {
    return null;
  };
  authn.assessRisk = rec.fn('risk', 'assess', function () {
    return undefined;
  });
  const mechanisms = { declared: {}, mfa: {} };
  authn.declaredMechanismsFor = rec.fn('mechanisms', 'declared',
    function (app) {
      return { allowed: mechanisms.declared[String(app)] || [], usable: [],
               problem: '' };
    });
  authn.mfaAllowedFor = rec.fn('mechanisms', 'mfaAllowed', function (app) {
    return mechanisms.mfa[String(app)] || [];
  });
  // The back-channel library (oauth-oidc/backchannel_logout.ts), faked so
  // its three calls are recorded where a sign-out and an expiry make them.
  const backchannel = {
    onExpiry: rec.fn('backchannel', 'onExpiry', function () {
      return true;
    }),
    plan: rec.fn('backchannel', 'plan', function (session) {
      return session && session.oidcClients
        ? [{ sid: session.id, clients: Object.keys(session.oidcClients) }]
        : [];
    }),
    dispatch: rec.fn('backchannel', 'dispatch', function () {
      return undefined;
    })
  };
  authn.backchannelLibrary = function () {
    return backchannel;
  };
  const smState = { enabled: false };
  const sessionManagement = {
    enabled: rec.fn('sessionManagement', 'enabled', function () {
      return smState.enabled;
    }),
    // Its OP browser states for a browser's accounts (#561), recorded as
    // one call: `browserStateOf` of each, joined.
    browserStateOf: function (session) {
      return String((session && session.browserState) || '');
    },
    browserStatesValue: rec.fn('sessionManagement', 'browserStatesValue',
      function (states) {
        return (states || []).join('|');
      }),
    writeCookie: rec.fn('sessionManagement', 'writeCookie', function () {
      return undefined;
    })
  };
  authn.sessionManagementLibrary = function () {
    return sessionManagement;
  };

  const observed = [];
  authn.setSessionObserver(function (notice) {
    if (!rec.calls) {
      return;
    }
    const copy = Object.assign({}, notice);
    copy.req = notice.req ? '[request]' : null;
    rec.calls.push({ port: 'observer', method: 'notice',
                     args: [rec.copy(copy)], answer: null });
    observed.push(copy.kind);
  });

  const sessions = authnModule.sessions;
  const storeOf = function () {
    const out = {};
    sessions.forEach(function (value, key) {
      out[key] = rec.copy(value);
    });
    return out;
  };

  // A request and a response, as the doors are handed them.
  const request = function (cookie, more) {
    const r = Object.assign({ headers: { 'user-agent': 'Vectors/1.0' },
                              body: {} }, more || {});
    if (cookie) {
      r.headers = Object.assign({}, r.headers, { cookie: cookie });
    }
    return r;
  };
  const response = function () {
    return {
      cookies: [],
      locals: {},
      set: function (k, v) {
        if (String(k).toLowerCase() === 'set-cookie') {
          this.cookies = [v];
        }
      },
      append: function (k, v) {
        if (String(k).toLowerCase() === 'set-cookie') {
          this.cookies.push(v);
        }
      }
    };
  };
  const cookieOf = function (res) {
    const line = res.cookies.filter(function (l) {
      return /^sts_session=[^;]/.test(l);
    }).pop();
    return line ? line.split(';')[0] : '';
  };

  const steps = [];
  const step = function (name, door, input, run) {
    rec.calls = [];
    const res = response();
    rec.opaque.push({ value: res, name: '[response]' });
    let answer;
    let threw = null;
    try {
      answer = run(res);
    } catch (e) {
      threw = String((e && e.stack) || e);
    }
    const calls = rec.calls;
    rec.calls = null;
    const row = { name: name, door: door, now: clock.now,
                  input: rec.copy(input), answer: rec.copy(answer),
                  cookies: res.cookies.slice(), locals: rec.copy(res.locals),
                  calls: calls, store: storeOf() };
    if (threw) {
      row.threw = threw;
    }
    steps.push(row);
    return { answer: answer, res: res };
  };
  rec.opaque.push({ value: config, name: '[module]' });
  return { req, rec, clock, realNow, randomId, config, overrides, mode, realms, state, people, gone, subjectOf, nameOf, helpers, userFor, disabled, policy, due, gateAnswers, stats, audit, deviceBound, authnModule, Authn, authn, passkeyRefusals, mechanisms, backchannel, sessionManagement, smState, observed, sessions, storeOf, request, response, cookieOf, steps, step };
}

/**
 * Builds the vectors.
 *
 * @param {string} ROOT - the repository root
 * @returns {any} the vector document
 */
function build(ROOT) {
  const h = harness(ROOT, {});
  const req = h.req;
  const rec = h.rec;
  const clock = h.clock;
  const realNow = h.realNow;
  const randomId = h.randomId;
  const config = h.config;
  const overrides = h.overrides;
  const mode = h.mode;
  const realms = h.realms;
  const state = h.state;
  const people = h.people;
  const gone = h.gone;
  const subjectOf = h.subjectOf;
  const nameOf = h.nameOf;
  const helpers = h.helpers;
  const userFor = h.userFor;
  const disabled = h.disabled;
  const policy = h.policy;
  const due = h.due;
  const gateAnswers = h.gateAnswers;
  const stats = h.stats;
  const audit = h.audit;
  const deviceBound = h.deviceBound;
  const authnModule = h.authnModule;
  const Authn = h.Authn;
  const authn = h.authn;
  const passkeyRefusals = h.passkeyRefusals;
  const mechanisms = h.mechanisms;
  const backchannel = h.backchannel;
  const sessionManagement = h.sessionManagement;
  const smState = h.smState;
  const observed = h.observed;
  const sessions = h.sessions;
  const storeOf = h.storeOf;
  const request = h.request;
  const response = h.response;
  const cookieOf = h.cookieOf;
  const steps = h.steps;
  const step = h.step;

  // ---- start: a new session ----------------------------------------------
  const start = function (name, username, amr, acr, via, detail, cookie) {
    const req0 = request(cookie);
    rec.opaque.push({ value: req0, name: '[request]' });
    const d = Object.assign({ request: req0 }, detail || {});
    const input = { username: username, amr: amr, acr: acr, via: via,
                    detail: Object.assign({}, d, { request: undefined }),
                    cookie: cookie || '' };
    const out = step(name, 'startSession', input, function (res) {
      res.req = req0;
      const s = authn.startSession(res, username, amr, acr, via, d);
      return { session: s, detail: Object.assign({}, d,
                                                 { request: undefined }) };
    });
    return out;
  };
  const sessionOf = function (name, cookie) {
    const r = request(cookie);
    rec.opaque.push({ value: r, name: '[request]' });
    return step(name, 'sessionOf', { cookie: cookie }, function () {
      return { session: authn.sessionOf(r) };
    });
  };

  const first = start('a password sign-in', 'dora', ['pwd'], '1',
                      'OAuth 2.0 / OIDC',
                      { application: 'app-one',
                        credential: { kind: 'password' } });
  const doraCookie = cookieOf(first.res);
  sessionOf('the cookie names it', doraCookie);
  sessionOf('a bare id is refused', doraCookie.split('.')[0]);
  sessionOf('a wrong handle is refused', doraCookie + 'x');
  sessionOf('no cookie', '');

  // ---- presented: the first is the sign-in, the second is reported -------
  const doraId = first.answer.session.id;
  step('the first presentation is the sign-in', 'notePresented',
       { sid: doraId, via: 'SAML 2.0', application: 'sp-one' }, function () {
         return { reported: authn.notePresented(sessions.get(doraId),
                                                'SAML 2.0', null, 'sp-one') };
       });
  step('a second presentation is reported', 'notePresented',
       { sid: doraId, via: 'SAML 2.0', application: 'sp-one' }, function () {
         return { reported: authn.notePresented(sessions.get(doraId),
                                                'SAML 2.0', null, 'sp-one') };
       });
  step('a presentation held for the consent screen', 'holdPresentation',
       { sid: doraId }, function () {
         authn.holdPresentation(sessions.get(doraId));
         return { held: true };
       });

  // ---- step-up: the same person, more factors: one more event -----------
  clock.now += 60 * 1000;
  const up = start('a step-up re-authenticates', 'dora', ['pwd', 'otp'],
                   'mfa', 'OAuth 2.0 / OIDC',
                   { application: 'app-two',
                     credential: { kind: 'totp' } }, doraCookie);
  const doraCookie2 = cookieOf(up.res);
  sessionOf('the old handle is refused after rotation', doraCookie);
  sessionOf('the new handle reads the same sid', doraCookie2);
  clock.now += 60 * 1000;
  const down = start('a step-down is a re-authentication too', 'dora',
                     ['pwd'], '1',
        'SAML 2.0', { application: 'sp-one',
                      credential: { kind: 'password' },
                      sessionNotOnOrAfter: clock.now + 600 * 1000 },
        doraCookie2);
  const doraCookie3 = cookieOf(down.res) || doraCookie2;
  step('a federated sign-in backdates its authentication', 'backdate',
       { sid: doraId, seconds: Math.floor(clock.now / 1000) - 30 },
       function () {
         authn.backdateAuthentication(sessions.get(doraId),
                                      Math.floor(clock.now / 1000) - 30);
         return { authTime: sessions.get(doraId).authTime };
       });

  // ---- a different person in the same browser replaces the session ------
  clock.now += 60 * 1000;
  const emil = start('another person replaces the session', 'emil', ['pwd'],
                     '1', 'WS-Federation',
                     { application: 'rp-one',
                       credential: { kind: 'password' } }, doraCookie3);
  const emilCookie = cookieOf(emil.res);
  sessionOf('the replaced session is gone', doraCookie3);

  // ---- an arrival session, then the sign-in that upgrades it -------------
  const arrivalReq = request('');
  rec.opaque.push({ value: arrivalReq, name: '[request]' });
  const arrival = step('an arrival session', 'startArrivalSession',
    { cookie: '', via: 'OAuth 2.0 / OIDC' }, function (res) {
      return { session: authn.startArrivalSession(arrivalReq, res,
                                                  'OAuth 2.0 / OIDC') };
    });
  const arrivalCookie = cookieOf(arrival.res);
  sessionOf('an arrival is no sign-in', arrivalCookie);
  clock.now += 5 * 1000;
  const upgraded = start('a sign-in upgrades the arrival in place', 'fay',
                         ['hwk', 'user'],
        'mfa', 'OAuth 2.0 / OIDC',
        { application: 'app-one',
          credential: { kind: 'webauthn', id: 'cred-fay-1',
                        ceremony: 'assertion', backupEligible: false,
                        attestationTrusted: true, algorithm: 'ES256',
                        coseAlg: -7, lane: 'classical' } },
        arrivalCookie);
  const fayCookie = cookieOf(upgraded.res);

  // ---- the refusals --------------------------------------------------------
  disabled.fay = true;
  start('a disabled account is refused', 'fay', ['pwd'], '1',
        'OAuth 2.0 / OIDC', { application: 'app-one',
                              credential: { kind: 'password' } });
  sessionOf('a session whose account was disabled is ended', fayCookie);
  delete disabled.fay;
  start('a service account at a browser door', 'svc', ['pwd'], '1',
        'OAuth 2.0 / OIDC', { application: 'app-one',
                              credential: { kind: 'password' } });
  policy.allows['password/primary'] = false;
  start('the authentication policy refuses a password', 'dora', ['pwd'],
        '1', 'OAuth 2.0 / OIDC', { application: 'app-one',
                                   credential: { kind: 'password' } });
  delete policy.allows['password/primary'];
  policy.allows['passkey/primary'] = false;
  start('the authentication policy refuses a passkey', 'dora',
        ['hwk', 'user'], 'mfa', 'OAuth 2.0 / OIDC',
        { application: 'app-one', credential: { kind: 'webauthn',
                                                id: 'cred-dora' } });
  delete policy.allows['passkey/primary'];
  policy.allows['totp/second-factor'] = false;
  start('a second factor the policy refuses is asked as one', 'dora',
        ['pwd', 'otp'], 'mfa', 'OAuth 2.0 / OIDC',
        { application: 'app-one', credential: { kind: 'totp' } });
  delete policy.allows['totp/second-factor'];
  passkeyRefusals.dora = { code: 'STS-AUTHN-0263', reason: 'backup-eligible',
                           why: 'A synced passkey is not accepted here.' };
  start('the passkey policy refuses the passkey', 'dora', ['hwk', 'user'],
        'mfa', 'OAuth 2.0 / OIDC',
        { application: 'app-one', credential: { kind: 'webauthn',
                                                id: 'cred-dora' } });
  delete passkeyRefusals.dora;
  state.retiring = { why: 'The realm is being removed.' };
  start('a realm being removed refuses', 'dora', ['pwd'], '1',
        'OAuth 2.0 / OIDC', { application: 'app-one',
                              credential: { kind: 'password' } });
  state.retiring = null;
  start('nobody in the directory', 'zed', ['pwd'], '1', 'OAuth 2.0 / OIDC',
        { application: 'app-one', credential: { kind: 'password' } });
  start('nobody, through federation with provisioning off', 'zed', ['pwd'],
        '1', 'OpenID Connect federation',
        { application: 'app-one', credential: { kind: 'federation',
                                                relationship: 'p1' },
          federation: { id: 'p1', peer: 'https://idp.example', subject: 'z',
                        autocreate: false } });
  gateAnswers.push({ allowed: false, why: 'The policy says no.',
                     policy: 'deny-all' });
  start('the issuance policy refuses the session', 'dora', ['pwd'], '1',
        'OAuth 2.0 / OIDC', { application: 'app-one',
                              credential: { kind: 'password' } });
  gateAnswers.push({ allowed: false, why: 'Not that mechanism.',
                     policy: 'mech',
                     mechanism: { allowed: ['passkey'],
                                  satisfied: ['password'],
                                  secondFactor: false } });
  mechanisms.declared['app-mech'] = ['passkey'];
  start('the application allows only a passkey (gated)', 'dora', ['pwd'],
        '1', 'OAuth 2.0 / OIDC', { application: 'app-mech', gated: true,
                                   credential: { kind: 'password' } });
  gateAnswers.push({ allowed: false, why: 'Not that second factor.',
                     policy: 'mech2',
                     mechanism: { allowed: ['webauthn'],
                                  satisfied: ['totp'],
                                  secondFactor: true } });
  start('the application refuses that second factor', 'dora',
        ['pwd', 'otp'], 'mfa', 'OAuth 2.0 / OIDC',
        { application: 'app-mech', credential: { kind: 'totp' } });
  delete mechanisms.declared['app-mech'];
  gateAnswers.push({ allowed: false, why: 'The device is not compliant.',
                     policy: 'devices',
                     device: { refusal: 'non-compliant' } });
  start('the issuance policy refuses the device', 'dora', ['pwd'], '1',
        'OAuth 2.0 / OIDC', { application: 'app-one',
                              credential: { kind: 'password' } });
  due.dora = { activity: 'pqc-passkey', required: false,
               profile: 'default', askedBy: 'realm' };
  start('a post-login activity holds the sign-in', 'dora', ['pwd'], '1',
        'OAuth 2.0 / OIDC', { application: 'app-one', postLoginHold: true,
                              credential: { kind: 'password' } });
  due.dora = { activity: 'pqc-passkey', required: true,
               profile: 'default', askedBy: 'realm' };
  start('a required post-login activity this door cannot do', 'dora',
        ['pwd'], '1', 'SAML 2.0', { application: 'sp-one',
                                    credential: { kind: 'password' } });
  delete due.dora;

  // ---- a keyed API caller: one session per credential, touched -----------
  start('a keyed caller', 'emil', ['pwd'], '1', 'Shared Signals',
        { key: 'key-digest-1', cookie: false, note: 'a Basic credential' });
  clock.now += 1000;
  start('the same key again touches its session', 'emil', ['pwd'], '1',
        'Shared Signals', { key: 'key-digest-1', cookie: false });

  // ---- an unauthenticated session the person chose ------------------------
  start('continue without signing in', 'anonymous', [], '0',
        'OAuth 2.0 / OIDC', { authenticated: false,
                              application: 'app-one' });

  // ---- the events list is bounded ------------------------------------------
  let last = start('a session that will re-authenticate often', 'fay',
                   ['pwd'], '1', 'OAuth 2.0 / OIDC',
                   { application: 'app-one',
                     credential: { kind: 'password' } });
  let fay = cookieOf(last.res);
  for (let i = 0; i < 21; i++) {
    clock.now += 1000;
    last = start('re-authentication ' + (i + 1), 'fay', ['pwd'], '1',
                 'OAuth 2.0 / OIDC', { application: 'app-one',
                                       credential: { kind: 'password' } },
                 fay);
    fay = cookieOf(last.res) || fay;
  }

  // ---- the clocks: idle, absolute, ended by an administrator --------------
  overrides['authn.sessionIdleTimeoutS'] = 300;
  clock.now += 2000;
  sessionOf('a use is noted with an idle timeout', fay);
  clock.now += 301 * 1000;
  sessionOf('an idle session is ended', fay);
  overrides['authn.sessionIdleTimeoutS'] = 0;
  clock.now += 60 * 1000;
  const fresh = start('a fresh sign-in for the clocks', 'dora', ['pwd'], '1',
                      'OAuth 2.0 / OIDC',
                      { application: 'app-one',
                        credential: { kind: 'password' } });
  const freshCookie = cookieOf(fresh.res);
  overrides['authn.sessionsEndedBefore'] = clock.now + 1;
  sessionOf('an administrator ended every session', freshCookie);
  overrides['authn.sessionsEndedBefore'] = 0;
  const late = start('a sign-in that will run out', 'dora', ['pwd'], '1',
                     'OAuth 2.0 / OIDC',
                     { application: 'app-one',
                       credential: { kind: 'password' } });
  const lateCookie = cookieOf(late.res);
  clock.now += 3601 * 1000;
  sessionOf('a session past its lifetime is ended', lateCookie);

  // ---- the sweep --------------------------------------------------------------
  const a = start('a sign-in the sweep keeps', 'dora', ['pwd'], '1',
                  'OAuth 2.0 / OIDC',
                  { application: 'app-one',
                    credential: { kind: 'password' } });
  clock.now += 1800 * 1000;
  start('a sign-in the sweep also keeps', 'fay', ['pwd'], '1',
        'SAML 2.0', { application: 'sp-one',
                      credential: { kind: 'password' } });
  clock.now += 1801 * 1000;
  step('the sweep ends what ran out', 'sweep', {}, function () {
    return { ended: authn.sweepExpiredSessions() };
  });

  // ---- the caps ------------------------------------------------------------------
  overrides['authn.maxSessionsPerSubject'] = 2;
  start('a subject under the cap', 'emil', ['pwd'], '1', 'OAuth 2.0 / OIDC',
        { application: 'app-one', credential: { kind: 'password' } });
  clock.now += 1000;
  start('a subject at the cap loses their oldest', 'emil', ['pwd'], '1',
        'OAuth 2.0 / OIDC', { application: 'app-one',
                              credential: { kind: 'password' } });
  overrides['authn.maxSessionsPerSubject'] = 32;
  overrides['authn.maxSessions'] = 1;
  start('the realm at authn.maxSessions refuses', 'dora', ['pwd'], '1',
        'OAuth 2.0 / OIDC', { application: 'app-one',
                              credential: { kind: 'password' } });
  overrides['authn.maxSessions'] = 100000;

  // ---- the sign-outs ---------------------------------------------------------
  const out1 = start('a sign-in to sign out of', 'dora', ['pwd'], '1',
                     'OAuth 2.0 / OIDC',
                     { application: 'app-one',
                       credential: { kind: 'password' } });
  const outCookie = cookieOf(out1.res);
  const outId = out1.answer.session.id;
  step('an OIDC client is recorded on the session', 'noteSessionChanged',
       { sid: outId }, function () {
         const s = sessions.get(outId);
         s.oidcClients = { 'client-a': { first: clock.now, last: clock.now,
                                         count: 1, iss: 'https://as.example',
                                         sub: s.user.sub } };
         return { changed: authn.noteSessionChanged(s) };
       });
  const signOutReq = request(outCookie);
  rec.opaque.push({ value: signOutReq, name: '[request]' });
  step('the browser signs out', 'endSession', { cookie: outCookie },
       function (res) {
         return { session: authn.endSession(signOutReq, res) };
       });
  const noneReq = request('');
  rec.opaque.push({ value: noneReq, name: '[request]' });
  step('a sign-out with no session', 'endSession', { cookie: '' },
       function (res) {
         return { session: authn.endSession(noneReq, res) };
       });
  const byId = start('a sign-in ended by its id', 'emil', ['pwd'], '1',
                     'SAML 2.0', { application: 'sp-one',
                                   credential: { kind: 'password' } });
  step('an administrator ends a session by id', 'endSessionById',
       { sid: byId.answer.session.id, via: 'the admin console',
         initiatingEntity: 'admin' }, function () {
         return { session: authn.endSessionById(byId.answer.session.id,
                                                'the admin console',
                                                'admin') };
       });
  step('a sign-out naming nobody says who', 'endSessionById',
       { sid: 'no-such-session', via: 'somewhere', initiatingEntity: '' },
       function () {
         return { session: authn.endSessionById('no-such-session',
                                                'somewhere') };
       });
  const goneOne = start('a sign-in whose person is deleted', 'emil', ['pwd'],
                        '1', 'OAuth 2.0 / OIDC',
                        { application: 'app-one',
                          credential: { kind: 'password' } });
  gone.emil = true;
  sessionOf('a session whose person was deleted is ended',
            cookieOf(goneOne.res));
  delete gone.emil;

  // ---- the pure functions -----------------------------------------------------
  const pure = [];
  const merges = mergeCases(clock.now);
  merges.forEach(function (one) {
    pure.push({ fn: 'mergeSessionRows', name: one.name,
                args: [one.mine, one.theirs],
                answer: rec.copy(authn.mergeSessionRows(one.mine,
                                                        one.theirs)) });
  });
  ['', 'a=1', 'sts_session=abc.def; other=2', ' sts_session = x.y ;z=',
   'a=%41%20b; b==c', 'noequals; =v; k=v', 'x=%E0%A4%A']
    .forEach(function (header) {
      let answer;
      try {
        answer = authn.cookiesOf({ headers: { cookie: header } });
      } catch (e) {
        answer = { threw: String(e.message) };
      }
      pure.push({ fn: 'cookiesOf', args: [header], answer: answer });
    });
  [[['pwd']], [['pwd', 'otp']], [['hwk']], [['pwd', 'hwk']], [['otp']],
   [['pop']], [[]], [['hwk', 'user']]].forEach(function (args) {
    pure.push({ fn: 'methodPhraseFor', args: args,
                answer: authn.methodPhraseFor(args[0]) });
  });
  const ended = function (session, now) {
    return authn.sessionEnded(session, now);
  };
  [[{ expires: clock.now - 1 }, clock.now],
   [{ expires: clock.now + 1, startedAt: 5 }, clock.now],
   [null, clock.now],
   [{ expires: 0, lastSeenAt: 1 }, clock.now]].forEach(function (args) {
    pure.push({ fn: 'sessionEnded', args: args,
                answer: ended(args[0], args[1]) });
  });
  [{ sub: 'urn:uuid:abc', username: 'x' }, { sub: 'x', username: 'y' },
   { username: 'z' }, null].forEach(function (user) {
    pure.push({ fn: 'subjectIdOf', args: [user],
                answer: authn.subjectIdOf(user) });
  });
  [['password', ['pwd']], ['webauthn', ['hwk']], ['webauthn', ['pwd', 'hwk']],
   ['certificate', ['pwd', 'otp']], ['totp', ['pwd', 'otp']],
   ['email-code', ['otp']], ['email-link', ['otp']], ['wallet', ['pop']],
   ['', ['pwd']], ['kerberos', ['pwd']], ['federation', ['pwd']]]
    .forEach(function (pair) {
      policy.allows = {};
      rec.calls = [];
      const answer = authn.authnPolicyRefusal(pair[1], { kind: pair[0] });
      const calls = rec.calls;
      rec.calls = null;
      pure.push({ fn: 'authnPolicyRefusal', args: [pair[1], pair[0]],
                  answer: answer, calls: calls });
      policy.allows = { 'password/primary': false,
                        'passkey/primary': false,
                        'certificate/primary': false,
                        'totp/second-factor': false,
                        'emailCode/primary': false,
                        'emailLink/primary': false,
                        'wallet/primary': false,
                        'kerberos/primary': false,
                        'federation/primary': false };
      rec.calls = [];
      const refused = authn.authnPolicyRefusal(pair[1], { kind: pair[0] });
      const calls2 = rec.calls;
      rec.calls = null;
      pure.push({ fn: 'authnPolicyRefusal', args: [pair[1], pair[0]],
                  refusing: true, answer: refused, calls: calls2 });
      policy.allows = {};
    });
  overrides['global.https'] = false;
  const plainRes = response();
  authn.clearSessionCookie(plainRes);
  authn.clearSessionCookie(plainRes, 'sts_portal');
  pure.push({ fn: 'clearSessionCookie', https: false,
              answer: plainRes.cookies });
  overrides['global.https'] = true;
  const secureRes = response();
  authn.clearSessionCookie(secureRes);
  pure.push({ fn: 'clearSessionCookie', https: true,
              answer: secureRes.cookies });

  // ---- whether a second factor is required (#1490, #246, #221) ---------
  const Credentials = req('common/credentials').Credentials;
  const AuthnPolicyClass = req('common/authn_policy').AuthnPolicy;
  const bootstrapName = req('common/bootstrap_name');
  const realBootstrap = bootstrapName.current;
  const realEveryone = mode.requiresSecondFactorOfEveryone;
  const profiles = [
    { requireSecondFactor: 'if-held',
      requireSecondFactorForAdministrators: 'offer' },
    { requireSecondFactor: 'always',
      requireSecondFactorForAdministrators: 'always' },
    { requireSecondFactor: 'if-held',
      requireSecondFactorForAdministrators: 'if-held' }
  ];
  const facts = {
    people: ['', 'dora', 'mfa-person', 'svc-exempt', 'svc-held', 'admin',
             'bootstrap', 'reader'],
    mfaRequired: { 'mfa-person': true },
    serviceAccounts: { 'svc-exempt': true, 'svc-held': true },
    exempt: { 'svc-exempt': true },
    roles: { admin: { read: true, write: true },
             bootstrap: { read: true, write: true },
             reader: { read: true, write: false } },
    bootstrap: 'bootstrap'
  };
  [false, true].forEach(function (everyone) {
    profiles.forEach(function (profile) {
      mode.requiresSecondFactorOfEveryone = function () {
        return everyone;
      };
      bootstrapName.current = function () {
        return facts.bootstrap;
      };
      const policyThis = { deps: { log: helpers.log },
                           read: function () {
                             return profile;
                           } };
      const rules = {
        require: AuthnPolicyClass.prototype.requireSecondFactor
          .call(policyThis),
        configured: AuthnPolicyClass.prototype.configuredSecondFactor
          .call(policyThis),
        forAdministrators: AuthnPolicyClass.prototype
          .requireSecondFactorForAdministrators.call(policyThis)
      };
      pure.push({ fn: 'secondFactorRules', args: [profile, everyone],
                  answer: rules });
      facts.people.forEach(function (name) {
        const fake = {
          directory: { readMfaRequired: function (n) {
            return !!facts.mfaRequired[n];
          } },
          deps: {
            log: helpers.log, config: config, realms: realms,
            serviceAccounts: { isServiceAccountName: function (n) {
              return !!facts.serviceAccounts[n];
            } },
            serviceAccountPolicy: {
              profileFor: function (n) {
                return n;
              },
              exemptFromSecondFactor: function (n) {
                return !!facts.exempt[n];
              }
            },
            authnPolicy: {
              requireSecondFactor: function () {
                return rules.require;
              },
              configuredSecondFactor: function () {
                return rules.configured;
              },
              requireSecondFactorForAdministrators: function () {
                return rules.forAdministrators;
              }
            },
            consoleRolesOf: function (n) {
              return facts.roles[n] || { read: false, write: false };
            }
          }
        };
        pure.push({ fn: 'mfaRequirementFor', args: [name, everyone, profile],
                    answer: Credentials.prototype.mfaRequirementFor.call(
                      fake, name) });
      });
    });
  });
  mode.requiresSecondFactorOfEveryone = realEveryone;
  bootstrapName.current = realBootstrap;

  Date.now = realNow;
  return { steps: steps, pure: pure, observed: observed.length,
           secondFactorFacts: facts };
}

/**
 * Pairs of session rows for `mergeSessionRows()`, each a rule it holds.
 *
 * @param {number} now - the instant the rows are stamped around
 * @returns {any[]} the cases
 */
function mergeCases(now) {
  const base = function (more) {
    return Object.assign({ id: 's1', user: { username: 'dora', sub: 'u' },
                           chosen: true, authTime: 100, expires: now + 1000,
                           lastSeenAt: now - 10, startedAt: now - 100,
                           handleIssuedAt: now - 100, subjectId: 'u',
                           events: [{ at: 100, amr: ['pwd'] }] }, more);
  };
  return [
    { name: 'nothing of mine', mine: null, theirs: base({}) },
    { name: 'nothing stored', mine: base({}), theirs: null },
    { name: 'an arrival is behind a sign-in',
      mine: base({ chosen: false, authTime: 999 }), theirs: base({}) },
    { name: 'a later sign-in is ahead',
      mine: base({ authTime: 200, events: [{ at: 200, amr: ['otp'] }] }),
      theirs: base({ lastSeenAt: now }) },
    { name: 'a later handle rotation is ahead',
      mine: base({ handleIssuedAt: now, handleHash: 'h2' }),
      theirs: base({ handleHash: 'h1', expires: now + 5000 }) },
    { name: 'a later renewal is ahead',
      mine: base({ rpRenewedAt: 5 }), theirs: base({ rpRenewedAt: 9 }) },
    { name: 'the lists are unions',
      mine: base({ wsfedRealms: { a: 1 }, saml2ServiceProviders: { s: 1 },
                   relyingParties: [{ x: 1 }],
                   events: [{ at: 100, amr: ['pwd'] }] }),
      theirs: base({ wsfedRealms: { b: 2 }, saml11RelyingParties: { r: 1 },
                     relyingParties: [{ x: 1 }, { y: 2 }],
                     events: [{ at: 100, amr: ['pwd'] },
                              { at: 150, amr: ['otp'] }] }) },
    { name: 'a client both hold keeps iss and sub',
      mine: base({ oidcClients: { c: { first: 5, last: 9, count: 2,
                                       iss: 'https://a', sub: 'x' },
                                  d: { first: 1, last: 1, count: 1 } } }),
      theirs: base({ oidcClients: { c: { first: 3, last: 12, count: 4,
                                         iss: '', sub: 'y' },
                                    e: { first: 2, last: 2, count: 1 } } }) },
    { name: 'a client neither first-seen',
      mine: base({ oidcClients: { c: { last: 1 } } }),
      theirs: base({ oidcClients: { c: { last: 1, iss: 'i' } } }) },
    { name: 'a device binding is kept',
      mine: base({ dbsc: { offeredAt: 7 } }),
      theirs: base({ dbsc: { jkt: 'j', id: 'b1', refreshes: 2 } }) },
    { name: 'two copies of one binding keep more refreshes',
      mine: base({ dbsc: { jkt: 'j', id: 'b1', refreshes: 5 } }),
      theirs: base({ dbsc: { jkt: 'j', id: 'b1', refreshes: 2 } }) },
    { name: 'two offers keep the earliest and the reasons',
      mine: base({ dbsc: { offeredAt: 9 } }),
      theirs: base({ dbsc: { offeredAt: 4, skippedReasons: ['r'],
                             skippedIds: ['i'] } }) },
    { name: 'backsConsole is ORed, subjectId kept',
      mine: base({ backsConsole: true, subjectId: '' }),
      theirs: base({ subjectId: 'u2', accountSetId: 'set1' }) },
    { name: 'two subjects keep the base',
      mine: base({ subjectId: 'a', authTime: 300 }),
      theirs: base({ subjectId: 'b' }) }
  ];
}

/**
 * THE SESSIONS `sts-authn` MINTED, read back by Node's own `Authn`: each row
 * is put in the session store, and the cookie Rust wrote for it must name
 * it with its current handle, the row must be live at the instant it was
 * minted, and its `Session` view must be the one Node reads from it — so a
 * session the Rust runtime writes is one the Node service honours (D11).
 *
 * @param {string} ROOT - the repository root
 * @param {any} v - session-rust.json
 * @param {function(boolean, string, string=): void} check - the collector
 */
function checkRust(ROOT, v, check) {
  const authnModule = require(path.join(ROOT, 'authn', 'authn'));
  const realNow = Date.now;
  try {
    (v.sessions || []).forEach(function (one) {
      const row = one.session;
      Date.now = function () {
        return Number(one.now);
      };
      authnModule.sessions.set(row.id, JSON.parse(JSON.stringify(row)));
      const found = authnModule.cookieSession(
        { headers: { cookie: 'sts_session=' + one.cookie } }, 'sts_session');
      check(!!found && found.id === row.id &&
            JSON.stringify(found.session) === JSON.stringify(row),
            'session-rust: the cookie sts-authn wrote names its session in ' +
            'Node (' + one.name + ')');
      check(authnModule.sessionEnded(row, Number(one.now)) === '',
            'session-rust: Node reads the session sts-authn minted as live (' +
            one.name + ')');
      const view = authnModule.sessionView(row);
      check(view.id === row.id &&
            view.subjectId === String(row.subjectId || '') &&
            (view.events || []).length === (row.events || []).length,
            'session-rust: Node\'s Session view of the row is the row (' +
            one.name + ')');
      authnModule.sessions.delete(row.id);
    });
  } finally {
    Date.now = realNow;
  }
}

module.exports = { build: build, checkRust: checkRust, harness: harness };

if (require.main === module) {
  const out = build(path.join(__dirname, '..', '..'));
  process.stdout.write(JSON.stringify(out, null, 1) + '\n');
}
