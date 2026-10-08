// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: wstrust_fault_codes.js
//
// ===========================================================================
// EVERY WS-TRUST REFUSAL NAMES ITS WS-TRUST 1.4 SECTION 11 FAULT CODE, ON
// BOTH SOAP VERSIONS (#183) — and a refused delegation leaves no row.
//
// Section 11's codes are defined "in terms of SOAP 1.1"; on SOAP 1.2 the
// Code is env:Sender and the section 11 code is its Subcode. So every case
// below is asked twice, and each answer is held to its version's place:
//
//   SOAP 1.1   <faultcode xmlns:wst="…">wst:<Code></faultcode>
//   SOAP 1.2   <soap:Value>soap:Sender</soap:Value><soap:Subcode>
//                <soap:Value xmlns:wst="…">wst:<Code></soap:Value>
//
//   A. every refusal handleRst() answers, by its STS-WSTRUST code: the
//      malformed body, the requester's credential (incomplete, wrong, an
//      assertion that does not verify, is not yet valid, has expired, names
//      nobody), the token inside ActAs (the same four, and no assertion at
//      all), a delegation with no requester, no credential, the role gate,
//      the encryption that cannot happen, a JWT about nobody, the delegation
//      policy's refusals, Cancel in 2004/04 and both delegation elements;
//   B. the qualifying namespace is the REQUEST's own trust namespace;
//   C. the one fault that is not a refusal — this service failing — is
//      soap:Receiver / soap:Server with no section 11 code, in the request's
//      SOAP version;
//   D. the delegated subject is on /admin/users only once the delegation
//      policy has allowed the act: not after a refusal in product, and
//      still after an allowed one and after development's "would have been
//      refused".
//
// IN PROCESS, in a throwaway realm, for `delegation_policy.js`'s reason:
// most of these refusals are product mode's, the rest development's, and a
// job over HTTP runs in one mode. `STS-CELL-0124` / `0125` (a delegation
// across cells) and `STS-CORE-0121` (a realm being removed) are faulted
// through the same `soapFault()` with `wst:RequestFailed` and are held by
// the reading of the source only; `STS-WSTRUST-0014` is a wst:Status in a
// 200, not a fault, and `0016` is no refusal at all.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
require('../common/app');
const applications = require('../common/applications');
const dir = require('../ldap/ldap_server');
const credentials = require('../common/credentials');
const stats = require('../common/admin_stats');
const roles = require('../common/roles');
// Arms `issuance_gate.js`'s decider, the PEP the role gate and the
// delegation questions go to.
require('../xacml/xacml_role_pep');

const log = require('bunyan').createLogger({ name: 'wstrust_fault_codes',
  level: process.env.LOG_LEVEL || 'info' });

const WST = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';
const WST_2004_04 = 'http://schemas.xmlsoap.org/ws/2004/04/trust';
const BACK = 'https://wf-back.example';
const OTHER = 'https://wf-other.example';
const DELEGATED_METHOD = 'OnBehalfOf / ActAs (delegated)';

// THE IdP'S OWN NAME (#519): a token presented as the requester's
// credential is addressed to its holder or to this IdP, and the realm's
// WS-Trust issuer name is one of the names it answers to.
function idpAudience() {
  log.debug("Entering idpAudience().");
  log.debug("Leaving idpAudience().");
  return require('../common/issuer_names').wstrustIssuer();
}

function inMode(m, fn) {
  log.debug("Entering inMode(). " + m);
  config.setOverride('global.mode', m);
  try {
    log.debug("Leaving inMode().");
    return fn();
  } finally {
    config.clearOverride('global.mode');
  }
}

// Runs `fn` with the clock moved by `ms`, for an assertion built in the past
// or the future.
function shifted(ms, fn) {
  log.debug("Entering shifted().");
  const real = Date.now;
  Date.now = function () {
    return real() + ms;
  };
  try {
    log.debug("Leaving shifted().");
    return fn();
  } finally {
    Date.now = real;
  }
}

// An RST in `trustNs` (1.3's by default) whose security header carries
// `security` and whose body carries `body`, for `appliesTo` ('' for none).
function rst(opts) {
  log.debug("Entering rst().");
  const soapNs = opts.soap11 ? 'http://schemas.xmlsoap.org/soap/envelope/'
                             : 'http://www.w3.org/2003/05/soap-envelope';
  const ns = opts.trustNs || WST;
  log.debug("Leaving rst().");
  return '<s:Envelope xmlns:s="' + soapNs + '" ' +
    'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-' +
    'wssecurity-secext-1.0.xsd"><s:Header>' +
    (opts.security ? '<wsse:Security>' + opts.security + '</wsse:Security>'
                   : '') +
    '</s:Header><s:Body><wst:RequestSecurityToken xmlns:wst="' + ns + '">' +
    '<wst:RequestType>' + ns + '/' + (opts.op || 'Issue') +
    '</wst:RequestType>' + (opts.tokenType ? '<wst:TokenType>' +
      opts.tokenType + '</wst:TokenType>' : '') + (opts.appliesTo
      ? '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/' +
        'policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/' +
        '08/addressing"><wsa:Address>' + opts.appliesTo + '</wsa:Address>' +
        '</wsa:EndpointReference></wsp:AppliesTo>' : '') +
    (opts.body || '') +
    '</wst:RequestSecurityToken></s:Body></s:Envelope>';
}

function usernameToken(user, pass) {
  log.debug("Entering usernameToken().");
  log.debug("Leaving usernameToken().");
  return '<wsse:UsernameToken><wsse:Username>' + user + '</wsse:Username>' +
    (pass === null ? '' : '<wsse:Password>' + pass + '</wsse:Password>') +
    '</wsse:UsernameToken>';
}

function actAs(inner) {
  log.debug("Entering actAs().");
  log.debug("Leaving actAs().");
  return '<wst14:ActAs xmlns:wst14="http://docs.oasis-open.org/ws-sx/' +
    'ws-trust/200802">' + inner + '</wst14:ActAs>';
}

function onBehalfOf(inner) {
  log.debug("Entering onBehalfOf().");
  log.debug("Leaving onBehalfOf().");
  return '<wst:OnBehalfOf>' + inner + '</wst:OnBehalfOf>';
}

// Where section 11's code sits in a fault of each SOAP version, qualified
// with `ns`.
function carries(body, soap11, code, ns) {
  log.debug("Entering carries().");
  const esc = function (s) {
    return s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  };
  const re = soap11
    ? new RegExp('<soap:Fault><faultcode xmlns:wst="' + esc(ns) + '">wst:' +
                 code + '</faultcode>')
    : new RegExp('<soap:Code><soap:Value>soap:Sender</soap:Value>' +
                 '<soap:Subcode><soap:Value xmlns:wst="' + esc(ns) +
                 '">wst:' + code + '</soap:Value></soap:Subcode></soap:Code>');
  log.debug("Leaving carries().");
  return re.test(String(body));
}

function fixtures(t) {
  log.debug("Entering fixtures().");
  ['wf-alice', 'wf-carl', 'wf-dana', 'wf-erin', 'wf-person']
    .forEach(function (name) {
      dir.createUser(name, { invent: false });
    });
  const app = function (identifier, fields) {
    log.debug("Entering app().");
    log.debug("Leaving app().");
    return applications.createApplication({ identifier: identifier,
      protocols: ['wstrust'],
      fields: Object.assign({ oauthClientId: identifier }, fields || {}) });
  };
  const made = [
    app('wf-back', { wstrustAppliesTo: [BACK] }),
    app('wf-other', { wstrustAppliesTo: [OTHER] }),
    app('wf-front', { appAllowedToDelegateTo: ['wf-back'] }),
    app('wf-mid', {}),
    app('wf-gated', { appRequiredRole: ['wf-gated-role'] }),
    app('wf-payroll', { appAllowedToDelegateTo: ['wf-back'],
                        appRequiredRole: ['wf-payroll-role'] })
  ];
  t.check(made.every(function (one) { return one && one.ok; }),
          'precondition: the applications were created',
          JSON.stringify(made.filter(function (one) { return !one.ok; })));
  // The role the gated application requires, held by nobody — `sts_roles.js`'s
  // arrangement: the AppliesTo names the application itself.
  const role = roles.write('wf-gated-role', { users: [], groups: [] });
  t.check(role && role.ok !== false, 'precondition: the gated role exists',
          JSON.stringify(role));
  const carl = credentials.setNotDelegated('wf-carl', true);
  t.check(carl.ok, 'precondition: wf-carl carries stsNotDelegated',
          JSON.stringify(carl));
  log.debug("Leaving fixtures().");
}

// A. AND B. Every refusal, on both SOAP versions.
function everyRefusal(t) {
  log.debug("Entering everyRefusal().");
  t.log.info('=== A. every refusal, on SOAP 1.1 and SOAP 1.2 ===');
  const wstrust = require('../ws-trust/wstrust');
  const saml2 = require('../saml/saml2');
  const signed = function (name, audience, opts) {
    log.debug("Entering signed().");
    log.debug("Leaving signed().");
    return saml2.buildSamlAssertion(name, audience || idpAudience(), 5,
                                    opts);
  };
  const unsigned = function (name) {
    log.debug("Entering unsigned().");
    log.debug("Leaving unsigned().");
    return signed(name, '', { sign: false });
  };
  // Built two hours ahead, so its NotBefore has not come; built two hours
  // back with five minutes to live, so it has gone.
  const future = function (name) {
    log.debug("Entering future().");
    log.debug("Leaving future().");
    return shifted(2 * 3600 * 1000, function () {
      return signed(name);
    });
  };
  const expired = function (name) {
    log.debug("Entering expired().");
    log.debug("Leaving expired().");
    return shifted(-2 * 3600 * 1000, function () {
      return signed(name);
    });
  };
  const nameless = function () {
    log.debug("Entering nameless().");
    log.debug("Leaving nameless().");
    return signed('wf-alice', '', { nameIdValue: '' });
  };
  // A recipient certificate that is not one, ahead of every other
  // X509Certificate in the document.
  const badCertificate = '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/' +
    'xmldsig#"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>AAAA' +
    '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>';
  const stripCertificates = function (xml) {
    log.debug("Entering stripCertificates().");
    log.debug("Leaving stripCertificates().");
    return xml.replace(/<ds:X509Certificate>[^<]*<\/ds:X509Certificate>/g,
                       '');
  };
  const JWT = 'urn:ietf:params:oauth:token-type:jwt';

  // [label, mode, rst options (or a raw body), expected code, wst fault,
  //  handleRst options, overrides]
  const CASES = [
    ['a malformed body', 'development', { raw: '<a><b></a>' },
     'STS-WSTRUST-0001', 'InvalidRequest'],
    ['a UsernameToken with no password', 'development',
     { security: usernameToken('wf-alice', null) },
     'STS-WSTRUST-0002', 'FailedAuthentication'],
    ['a UsernameToken whose password is refused', 'development',
     { security: usernameToken('wf-alice', 'invalid') },
     'STS-WSTRUST-0003', 'FailedAuthentication'],
    ['an unsigned assertion as the credential', 'product',
     { security: unsigned('wf-front'), appliesTo: BACK },
     'STS-WSTRUST-0004', 'FailedAuthentication'],
    ['an unsigned assertion inside ActAs', 'product',
     { security: signed('wf-front'), body: actAs(unsigned('wf-alice')),
       appliesTo: BACK },
     'STS-WSTRUST-0004', 'InvalidRequest'],
    ['a credential not yet valid', 'product',
     { security: future('wf-front'), appliesTo: BACK },
     'STS-WSTRUST-0005', 'FailedAuthentication'],
    ['a token inside ActAs not yet valid', 'product',
     { security: signed('wf-front'), body: actAs(future('wf-alice')),
       appliesTo: BACK },
     'STS-WSTRUST-0005', 'InvalidRequest'],
    ['an expired credential', 'product',
     { security: expired('wf-front'), appliesTo: BACK },
     'STS-WSTRUST-0006', 'ExpiredData'],
    ['an expired token inside ActAs', 'product',
     { security: signed('wf-front'), body: actAs(expired('wf-alice')),
       appliesTo: BACK },
     'STS-WSTRUST-0006', 'ExpiredData'],
    ['a credential naming nobody', 'product',
     { security: nameless(), appliesTo: BACK },
     'STS-WSTRUST-0007', 'FailedAuthentication'],
    ['a token inside ActAs naming nobody', 'product',
     { security: signed('wf-front'), body: actAs(nameless()),
       appliesTo: BACK },
     'STS-WSTRUST-0007', 'InvalidRequest'],
    ['an ActAs carrying no assertion', 'product',
     { security: signed('wf-front'),
       body: actAs(usernameToken('wf-alice', 'x')), appliesTo: BACK },
     'STS-WSTRUST-0008', 'InvalidRequest'],
    ['a delegation with no requester credential', 'product',
     { body: actAs(signed('wf-alice', 'wf-front')), appliesTo: BACK },
     'STS-WSTRUST-0009', 'FailedAuthentication'],
    ['no credential at all', 'product', { appliesTo: BACK },
     'STS-WSTRUST-0010', 'FailedAuthentication'],
    ['the role gate', 'development',
     { security: usernameToken('wf-alice', 'x'), appliesTo: 'wf-gated' },
     'STS-WSTRUST-0011', 'RequestFailed'],
    ['?encrypt=1 with no recipient certificate', 'product',
     { security: stripCertificates(signed('wf-alice')), appliesTo: BACK },
     'STS-WSTRUST-0012', 'InvalidRequest', { encrypt: true }],
    ['?encrypt=1 to a certificate that is not one', 'product',
     { security: badCertificate + signed('wf-alice'), appliesTo: BACK },
     'STS-WSTRUST-0013', 'RequestFailed', { encrypt: true }],
    ['a JWT about somebody the directory does not hold', 'development',
     { security: usernameToken('wf-ghost-' + process.pid, 'x'),
       tokenType: JWT },
     'STS-WSTRUST-0017', 'RequestFailed', null,
     { 'ldap.autocreateUsers': false }],
    ['a protected subject', 'product',
     { security: signed('wf-front'), body: actAs(signed('wf-carl',
       'wf-front')), appliesTo: BACK },
     'STS-WSTRUST-0018', 'RequestFailed'],
    ['a person requester without delegation.actorRole', 'product',
     { security: signed('wf-person'), body: actAs(signed('wf-alice',
       'wf-front')), appliesTo: BACK },
     'STS-WSTRUST-0019', 'RequestFailed'],
    ['impersonation asked of an actor allowing delegation only', 'product',
     { security: signed('wf-front'), body: onBehalfOf(signed('wf-alice',
       'wf-front')), appliesTo: BACK },
     'STS-WSTRUST-0022', 'RequestFailed'],
    ['a subject without the authority S requires', 'product',
     { security: signed('wf-payroll'), body: actAs(signed('wf-alice',
       'wf-payroll')), appliesTo: BACK },
     'STS-WSTRUST-0023', 'RequestFailed'],
    // #496: STS-WSTRUST-0024 (the policy's no-target and
    // unregistered-target) is no longer reachable here in product: an RST
    // with no AppliesTo, or one nobody registered, is refused before the
    // policy is asked (STS-WSTRUST-0031 / 0030, below), and development
    // does not enforce the policy's target refusals. A target the
    // intermediary may not reach is the policy's default code.
    ['a target the intermediary may not reach', 'product',
     { security: signed('wf-front'), body: actAs(signed('wf-alice',
       'wf-front')), appliesTo: OTHER },
     'STS-WSTRUST-0018', 'RequestFailed'],
    ['an AppliesTo nobody registered (#496)', 'product',
     { security: signed('wf-front'),
       appliesTo: 'https://wf-nobody.example' },
     'STS-WSTRUST-0030', 'InvalidScope'],
    ['no AppliesTo (#496)', 'product',
     { security: signed('wf-front') },
     'STS-WSTRUST-0031', 'InvalidRequest'],
    ['Cancel in WS-Trust 2004/04', 'development',
     { security: usernameToken('wf-alice', 'x'), op: 'Cancel',
       trustNs: WST_2004_04 },
     'STS-WSTRUST-0021', 'InvalidRequest'],
    ['both OnBehalfOf and ActAs', 'development',
     { security: usernameToken('wf-front', 'x'),
       body: actAs(signed('wf-alice', 'wf-front')) +
             onBehalfOf(signed('wf-alice', 'wf-front')), appliesTo: BACK },
     'STS-WSTRUST-0025', 'InvalidRequest']
  ];
  CASES.forEach(function (c) {
    [true, false].forEach(function (soap11) {
      const label = c[3] + ' (' + c[0] + '), SOAP ' + (soap11 ? '1.1' : '1.2');
      const opts = Object.assign({ soap11: soap11 }, c[2]);
      const body = opts.raw || rst(opts);
      const ns = opts.raw ? WST : (opts.trustNs || WST);
      const overrides = c[6] || {};
      Object.keys(overrides).forEach(function (key) {
        config.setOverride(key, overrides[key]);
      });
      let r;
      try {
        r = inMode(c[1], function () {
          return wstrust.handleRst(body, soap11 ? 'text/xml'
                                                : 'application/soap+xml',
                                   c[5] || {});
        });
      } finally {
        Object.keys(overrides).forEach(function (key) {
          config.clearOverride(key);
        });
      }
      t.check(r.errorCode === c[3] && r.status >= 400 &&
              carries(r.body, soap11, c[4], ns),
              c[1] + ': ' + label + ' is wst:' + c[4],
              r.status + ' ' + r.errorCode + ' ' +
              String(r.body).slice(0, 500));
    });
  });
  // B. The namespace is the request's: a 2005/02 request is answered in
  // 2005/02's.
  const feb = 'http://schemas.xmlsoap.org/ws/2005/02/trust';
  [true, false].forEach(function (soap11) {
    const r = inMode('development', function () {
      return wstrust.handleRst(rst({ soap11: soap11, trustNs: feb,
        security: usernameToken('wf-alice', 'invalid') }),
      soap11 ? 'text/xml' : 'application/soap+xml');
    });
    t.check(carries(r.body, soap11, 'FailedAuthentication', feb),
            'B. a 2005/02 request\'s fault is qualified with 2005/02\'s ' +
            'namespace, SOAP ' + (soap11 ? '1.1' : '1.2'),
            String(r.body).slice(0, 400));
  });
  log.debug("Leaving everyRefusal().");
}

// A response object enough for the endpoint.
function fakeRes() {
  log.debug("Entering fakeRes().");
  const res = { statusCode: 200, headers: {}, body: null, locals: {} };
  res.status = function (code) {
    res.statusCode = code;
    return res;
  };
  res.type = function (type) {
    res.headers['content-type'] = type;
    return res;
  };
  res.set = function (k, v) {
    res.headers[String(k).toLowerCase()] = v;
    return res;
  };
  res.setHeader = res.set;
  res.getHeader = function (k) {
    return res.headers[String(k).toLowerCase()];
  };
  res.send = function (b) {
    res.body = b;
    return res;
  };
  log.debug("Leaving fakeRes().");
  return res;
}

// C. This service failing: the endpoint's own catch.
function receiverFault(t) {
  log.debug("Entering receiverFault().");
  t.log.info('=== C. the one fault that is not a refusal ===');
  const wstrust = require('../ws-trust/wstrust');
  let handler = null;
  wstrust.registerRoutes({
    get: function () {
      return null;
    },
    post: function (path, fn) {
      if (path === '/sts') {
        handler = fn;
      }
    }
  });
  const ask = function (soap11) {
    log.debug("Entering ask().");
    const res = fakeRes();
    const req = {
      body: rst({ soap11: soap11 }),
      headers: { 'content-type': soap11 ? 'text/xml'
                                        : 'application/soap+xml' },
      // The one thing the endpoint reads inside its try, made to throw.
      get query() {
        throw new Error('a failure planted by ' + __filename);
      }
    };
    log.debug("Leaving ask().");
    return Promise.resolve(inMode('development', function () {
      return handler(req, res);
    })).then(function () {
      return res;
    });
  };
  return ask(true).then(function (res) {
    t.check(res.statusCode === 500 &&
            /<faultcode>soap:Server<\/faultcode>/.test(res.body) &&
            !/wst:/.test(res.body) &&
            /^text\/xml/.test(res.headers['content-type']),
            'C1. SOAP 1.1: an exception is soap:Server, no section 11 code, ' +
            'in SOAP 1.1 (STS-WSTRUST-0015)',
            res.statusCode + ' ' + res.headers['content-type'] + ' ' +
            String(res.body).slice(0, 400));
    return ask(false);
  }).then(function (res) {
    t.check(res.statusCode === 500 &&
            /<soap:Value>soap:Receiver<\/soap:Value><\/soap:Code>/
              .test(res.body) && !/wst:/.test(res.body) &&
            /^application\/soap\+xml/.test(res.headers['content-type']),
            'C2. SOAP 1.2: soap:Receiver, no Subcode (STS-WSTRUST-0015)',
            res.statusCode + ' ' + String(res.body).slice(0, 400));
    log.debug("Leaving receiverFault().");
  });
}

// D. The delegated subject on /admin/users.
function usersRow(t) {
  log.debug("Entering usersRow().");
  t.log.info('=== D. a refused delegation leaves no /admin/users row ===');
  const wstrust = require('../ws-trust/wstrust');
  const saml2 = require('../saml/saml2');
  const signed = function (name, audience) {
    log.debug("Entering signed().");
    log.debug("Leaving signed().");
    return saml2.buildSamlAssertion(name, audience || idpAudience(), 5);
  };
  const seenDelegated = function (name) {
    log.debug("Entering seenDelegated().");
    const row = stats.userRows().filter(function (one) {
      return one && String(one.name || one.key || '').toLowerCase() === name;
    })[0];
    log.debug("Leaving seenDelegated().");
    return !!row && JSON.stringify(row).indexOf(DELEGATED_METHOD) >= 0;
  };
  const ask = function (m, requester, body) {
    log.debug("Entering ask().");
    log.debug("Leaving ask().");
    return inMode(m, function () {
      return wstrust.handleRst(rst({ security: signed(requester), body: body,
                                     appliesTo: BACK }),
                               'application/soap+xml');
    });
  };
  let r = ask('product', 'wf-front', actAs(signed('wf-carl', 'wf-front')));
  t.check(r.errorCode === 'STS-WSTRUST-0018' && !seenDelegated('wf-carl'),
          'D1. product: a delegation the policy refused leaves its subject ' +
          'OFF /admin/users', r.errorCode + ' ' + seenDelegated('wf-carl'));
  t.check(stats.userRows().some(function (one) {
    return String(one.name || one.key || '').toLowerCase() === 'wf-front';
  }), 'D2. and the requester, who did authenticate, is on it');
  r = ask('product', 'wf-front', actAs(signed('wf-dana', 'wf-front')));
  t.check(r.status === 200 && seenDelegated('wf-dana'),
          'D3. product: an allowed delegation records its subject, as a ' +
          'delegated subject', r.status + ' ' + r.errorCode + ' ' +
          seenDelegated('wf-dana'));
  r = ask('development', 'wf-front',
          onBehalfOf(signed('wf-erin', 'wf-front')));
  t.check(r.status === 200 && seenDelegated('wf-erin'),
          'D4. development: an act that WOULD have been refused is issued, ' +
          'and its subject recorded', r.status + ' ' + r.errorCode + ' ' +
          seenDelegated('wf-erin'));
  log.debug("Leaving usersRow().");
}

// EVERYTHING IN A THROWAWAY REALM, removed afterwards — the fixtures carry
// delegation attributes no other file should meet.
function run(t) {
  log.debug("Entering run().");
  const id = 'wf-' + process.pid;
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return undefined;
  }
  let done;
  try {
    done = realms.run(made.realm, function () {
      fixtures(t);
      everyRefusal(t);
      usersRow(t);
      return receiverFault(t);
    });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    realms.remove(id);
    throw e;
  }
  log.debug("Leaving run().");
  return Promise.resolve(done).then(function () {
    realms.remove(id);
  }, function (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    realms.remove(id);
    throw e;
  });
}

module.exports = {
  name: 'wstrust_fault_codes',
  describe: 'every WS-Trust refusal is its WS-Trust 1.4 section 11 fault on ' +
            'SOAP 1.1 and 1.2, an exception is soap:Receiver, and a refused ' +
            'delegation leaves no /admin/users row (#183)',
  run: run
};
