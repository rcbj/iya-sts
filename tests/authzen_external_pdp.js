// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/authzen_external_pdp.js
//
// DIRECTION B OF THE AUTHZEN TOKEN-EXCHANGE BINDING (#1200). This
// authorization server asks an external PDP before it issues an OAuth
// access token for an RFC 8693 exchange. Two halves, and neither one sets
// a process-wide override in THIS process:
//
//   * An injected dial. The switch off dials nothing. The batch is the
//     worked example. A false subject or party gate is 0125. A false
//     scope, granted_scope and token_lifetime only narrow. A timeout, a
//     non-2xx and outbound off are 0124. A bad body is 0126. A missing
//     certificate is 0127 and is not dialled. http, userinfo, a query and
//     a fragment are 0123 and are not dialled.
//   * A child, with a second realm as the PDP, over mutual TLS. The proof
//     the dial happened is the lifetime: the subject token is minted at
//     120 seconds, the setting is then raised to 3600, and the exchanged
//     token lives about the subject token's remaining life. A closed port
//     is 503 and STS-AUTHZEN-0124, in development, where the local
//     issuance policy would still have issued.

const childProcess = require('child_process');
const fs = require('fs');
const https = require('https');
const nodeCrypto = require('crypto');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_AUTHZEN_EXTERNAL_CHILD';
const REALM = 'azext';
const PREFIX = '/realm/' + REALM;
const AUDIENCE = 'https://api.example';
const GATE = 'issue:access_token:token_exchange';
const ACCESS = 'urn:ietf:params:oauth:token-type:access_token';
const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const CERT_PEM = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END ' +
  'CERTIFICATE-----\n';
const KEY_PEM = '-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE ' +
  'KEY-----\n';
const EC_KEY = '-----BEGIN EC PRIVATE KEY-----\nMIIB\n-----END EC PRIVATE ' +
  'KEY-----\n';
const REFUSED = 'The authorization server\'s policy refused this token ' +
  'exchange.';
const FAULT = 'The authorization server could not complete this token ' +
  'exchange. Try again shortly.';

const log = require('bunyan').createLogger({
  name: 'authzen_external_pdp',
  level: process.env.LOG_LEVEL || 'info' });

function note(rows, ok, what, detail) {
  log.debug("Entering note().");
  rows.push({ ok: !!ok, what: what,
              detail: detail === undefined ? '' : String(detail) });
  log.debug("Leaving note().");
}

function harness(Ctor, over) {
  log.debug("Entering harness().");
  const given = over || {};
  const calls = [];
  const tags = [];
  const infos = [];
  const reads = [];
  const values = Object.assign({
    'authzen.externalPdp': true,
    'authzen.externalPdpUrl':
      'https://pdp.example/access/v1/evaluations',
    'authzen.externalPdpTimeoutMs': 5000,
    'authzen.externalPdpClientCertFile': '/cert.pem',
    'authzen.externalPdpClientKeyFile': '/key.pem',
    'authzen.externalPdpCaFile': ''
  }, given.values || {});
  const files = Object.assign({
    '/cert.pem': CERT_PEM, '/key.pem': KEY_PEM
  }, given.files || {});
  const pdp = new Ctor({
    log: {
      debug: function () {},
      info: function (message) {
        infos.push(String(message));
      },
      error: function () {}
    },
    config: {
      value: function (key) {
        return values[key];
      }
    },
    errorCodes: {
      tag: function (code) {
        tags.push(code);
        return '[' + code + '] ';
      }
    },
    namedFileAllowed: given.allow || function () {
      return true;
    },
    readFile: function (file) {
      reads.push(file);
      if (given.read) {
        return given.read(file);
      }
      if (!Object.prototype.hasOwnProperty.call(files, file)) {
        const err = new Error('ENOENT');
        err.code = 'ENOENT';
        throw err;
      }
      return files[file];
    },
    request: function (url, options) {
      calls.push({ url: url, options: options });
      if (given.request) {
        return given.request(url, options);
      }
      const reply = given.reply;
      if (typeof reply === 'function') {
        return Promise.resolve(reply(url, options));
      }
      return Promise.resolve(reply || {
        ok: true, status: 200, kind: '', why: '', body: '{}' });
    }
  });
  log.debug("Leaving harness().");
  return { pdp: pdp, calls: calls, tags: tags, infos: infos,
           reads: reads };
}

function permit(body, tweak) {
  log.debug("Entering permit().");
  const sent = JSON.parse(String(body));
  const evaluations = sent.evaluations.map(function (item, index) {
    const one = { decision: true };
    if (tweak) {
      tweak(one, index, sent);
    }
    return one;
  });
  log.debug("Leaving permit().");
  return { ok: true, status: 200, kind: '', why: '',
           body: JSON.stringify({ evaluations: evaluations }) };
}

function workedInput() {
  log.debug("Entering workedInput().");
  log.debug("Leaving workedInput().");
  return {
    subject: { type: 'user', id: 'alice' },
    party: { type: 'client', id: 'gw' },
    audiences: [AUDIENCE],
    scopes: ['read:docs', 'write:docs'],
    clientId: 'gw',
    subjectTokenType: ACCESS,
    actorTokenType: '',
    subjectClaims: {
      aud: AUDIENCE, scope: 'read:docs write:docs', exp: 1893456000,
      iss: 'https://issuer.example', auth_time: 0, amr: [],
      acr: '', jti: 'jti-1', cnf: { jkt: 'thumb' }
    },
    mayAct: { sub: '' }
  };
}

function workedShape(body) {
  log.debug("Entering workedShape().");
  const sent = JSON.parse(body);
  const token = sent.context.subject_token || {};
  const items = sent.evaluations;
  const ok = sent.resource.type === 'audience' &&
    sent.resource.id === AUDIENCE &&
    sent.options.evaluations_semantic === 'execute_all' &&
    sent.context.client_id === 'gw' &&
    sent.context.subject_token_type === ACCESS &&
    !Object.prototype.hasOwnProperty.call(sent.context,
                                          'actor_token_type') &&
    !sent.context.iss && token.aud === AUDIENCE &&
    token.scope === 'read:docs write:docs' && token.exp === 1893456000 &&
    !token.iss && sent.context.auth_time === 0 &&
    sent.context.jti === 'jti-1' &&
    sent.context.cnf.jkt === 'thumb' &&
    sent.context.may_act.sub === '' &&
    !Object.prototype.hasOwnProperty.call(sent.context, 'acr') &&
    !Object.prototype.hasOwnProperty.call(sent.context, 'amr') &&
    items.length === 4 && !items[0].resource &&
    items[0].subject.type === 'user' && items[0].subject.id === 'alice' &&
    items[0].action.name === GATE && !items[1].resource &&
    items[1].subject.type === 'client' && items[1].subject.id === 'gw' &&
    items[1].action.name === GATE &&
    items[2].resource.type === 'protected_resource' &&
    items[2].resource.id === AUDIENCE &&
    items[2].action.name === 'read:docs' &&
    items[3].action.name === 'write:docs' &&
    items[3].resource.id === AUDIENCE;
  log.debug("Leaving workedShape().");
  return ok;
}

function chain(depth) {
  log.debug("Entering chain().");
  let act = { sub: 'leaf' };
  let left = depth - 1;
  while (left > 0) {
    act = { sub: 'link', act: act };
    left -= 1;
  }
  log.debug("Leaving chain().");
  return act;
}

async function unitFindings() {
  log.debug("Entering unitFindings().");
  const rows = [];
  const Mod = require(ROOT + '/authzen/authzen_external_pdp');
  const Ctor = Mod.AuthzenExternalPdp;
  note(rows, Mod.ACCESS_TOKEN_TYPE === ACCESS,
       'the access-token type is the RFC 8693 URI', Mod.ACCESS_TOKEN_TYPE);

  const off = harness(Ctor, { values: { 'authzen.externalPdp': false } });
  const offOut = await off.pdp.consult(workedInput());
  note(rows, offOut.ok === true && offOut.scope === null &&
       offOut.lifetimeCapS === null && off.calls.length === 0 &&
       off.reads.length === 0,
       'off dials nothing and leaves the local decision unchanged',
       JSON.stringify(offOut));

  const config = require(ROOT + '/common/config');
  if (config.value('authzen.externalPdp') !== true) {
    const exported = await Mod.consult(null);
    note(rows, exported.ok === true && exported.scope === null &&
         exported.lifetimeCapS === null,
         'the process consult(), with the switch off, changes nothing',
         JSON.stringify(exported));
  } else {
    note(rows, false, 'authzen.externalPdp is already on in this process');
  }

  const built = Ctor.batchOf(workedInput());
  note(rows, workedShape(JSON.stringify(built.body)),
       'the worked example is one subject gate, one party gate and one ' +
       'scope tuple per scope, execute_all, with no iss',
       JSON.stringify(built.body));

  const asked = harness(Ctor, {
    reply: function (url, options) {
      return permit(options.body);
    }
  });
  const askedOut = await asked.pdp.consult(workedInput());
  const sent = asked.calls[0];
  note(rows, askedOut.ok === true && askedOut.scope === null &&
       askedOut.lifetimeCapS === null && asked.calls.length === 1 &&
       sent.options.method === 'POST' &&
       sent.options.headers['Content-Type'] === 'application/json' &&
       sent.options.timeoutMs === 5000 &&
       sent.options.cert.indexOf('CERTIFICATE-----') >= 0 &&
       sent.options.key.indexOf('PRIVATE KEY-----') >= 0 &&
       sent.options.ca === undefined &&
       workedShape(sent.options.body),
       'a permit with no issuance dials the worked example and changes ' +
       'nothing; an empty CA file is not sent',
       JSON.stringify(askedOut));

  const urls = [
    ['http://pdp.example/access/v1/evaluations', 'not-https'],
    ['https://user:secret@pdp.example/a', 'userinfo'],
    ['https://pdp.example/a?x=1', 'query'],
    ['https://pdp.example/a#frag', 'fragment'],
    ['', 'unparseable'],
    ['not a url', 'unparseable']
  ];
  for (let i = 0; i < urls.length; i += 1) {
    const pair = urls[i];
    note(rows, Ctor.urlProblem(pair[0]) === pair[1],
         'urlProblem(' + (pair[0] || 'empty') + ') is ' + pair[1],
         Ctor.urlProblem(pair[0]));
    const bad = harness(Ctor, {
      values: {
        'authzen.externalPdpUrl': pair[0],
        'authzen.externalPdpClientCertFile': ''
      }
    });
    const badOut = await bad.pdp.consult(workedInput());
    note(rows, badOut.ok === false && badOut.code === 'STS-AUTHZEN-0123' &&
         badOut.status === 503 &&
         badOut.error === 'temporarily_unavailable' &&
         badOut.description === FAULT && bad.calls.length === 0 &&
         bad.reads.length === 0 &&
         badOut.description.indexOf('STS-') < 0,
         'a ' + pair[1] + ' URL is 0123 and is not dialled, ahead of a ' +
         'missing certificate',
         JSON.stringify(badOut) + ' reads ' + bad.reads.length);
  }

  const missing = harness(Ctor, {
    values: { 'authzen.externalPdpClientCertFile': '' }
  });
  const missingOut = await missing.pdp.consult(workedInput());
  note(rows, missingOut.code === 'STS-AUTHZEN-0127' &&
       missing.calls.length === 0,
       'an empty certificate is 0127 and is not dialled',
       JSON.stringify(missingOut));

  const unmarked = harness(Ctor, {
    files: { '/cert.pem': 'not a pem', '/key.pem': KEY_PEM }
  });
  const unmarkedOut = await unmarked.pdp.consult(workedInput());
  note(rows, unmarkedOut.code === 'STS-AUTHZEN-0127' &&
       unmarked.calls.length === 0,
       'a file that is not a PEM certificate is 0127',
       JSON.stringify(unmarkedOut));

  const ec = harness(Ctor, {
    files: { '/cert.pem': CERT_PEM, '/key.pem': EC_KEY },
    reply: function (url, options) {
      return permit(options.body);
    }
  });
  const ecOut = await ec.pdp.consult(workedInput());
  note(rows, ecOut.ok === true && ec.calls.length === 1 &&
       ec.calls[0].options.key.indexOf('EC PRIVATE KEY') >= 0,
       'an EC private key is a PEM key', JSON.stringify(ecOut));

  const rooted = harness(Ctor, {
    allow: function () {
      return false;
    }
  });
  const rootedOut = await rooted.pdp.consult(workedInput());
  note(rows, rootedOut.code === 'STS-AUTHZEN-0127' &&
       rooted.calls.length === 0 && rooted.reads.length === 0,
       'a file outside security.fileRoots is 0127 and is not read',
       JSON.stringify(rootedOut));

  const unread = harness(Ctor, {
    read: function () {
      const err = new Error('ENOENT');
      err.code = 'ENOENT';
      throw err;
    }
  });
  const unreadOut = await unread.pdp.consult(workedInput());
  note(rows, unreadOut.code === 'STS-AUTHZEN-0127' &&
       unread.calls.length === 0,
       'an unreadable certificate is 0127', JSON.stringify(unreadOut));

  const caBad = harness(Ctor, {
    values: { 'authzen.externalPdpCaFile': '/ca.pem' },
    read: function (file) {
      if (file === '/ca.pem') {
        const err = new Error('EACCES');
        err.code = 'EACCES';
        throw err;
      }
      return file.indexOf('key') >= 0 ? KEY_PEM : CERT_PEM;
    }
  });
  const caBadOut = await caBad.pdp.consult(workedInput());
  note(rows, caBadOut.code === 'STS-AUTHZEN-0127' &&
       caBad.calls.length === 0,
       'a named unreadable CA file is 0127 and is not dialled',
       JSON.stringify(caBadOut));

  const caOk = harness(Ctor, {
    values: { 'authzen.externalPdpCaFile': '/ca.pem' },
    files: { '/cert.pem': CERT_PEM, '/key.pem': KEY_PEM,
             '/ca.pem': CERT_PEM },
    reply: function (url, options) {
      return permit(options.body);
    }
  });
  await caOk.pdp.consult(workedInput());
  note(rows, caOk.calls.length === 1 && caOk.calls[0].options.ca === CERT_PEM,
       'a named CA file is the dial\'s ca',
       caOk.calls.length ? 'sent' : 'not dialled');

  const refused = harness(Ctor, {
    reply: function (url, options) {
      return permit(options.body, function (one, index) {
        if (index === 0) {
          one.decision = false;
          one.context = { issuance: { granted_scope: 'read:docs',
                                      token_lifetime: 15 } };
        }
      });
    }
  });
  const refusedOut = await refused.pdp.consult(workedInput());
  note(rows, refusedOut.ok === false &&
       refusedOut.code === 'STS-AUTHZEN-0125' && refusedOut.status === 400 &&
       refusedOut.error === 'invalid_request' &&
       refusedOut.description === REFUSED &&
       refusedOut.description.indexOf('STS-') < 0 &&
       refusedOut.description.indexOf(GATE) < 0 &&
       refusedOut.description.indexOf('https://') < 0 &&
       refused.infos.join(' ').indexOf(GATE) < 0,
       'a false subject gate is 0125 and wins over a narrowing; the ' +
       'client is told neither the gate nor the code',
       JSON.stringify(refusedOut) + ' ' + refused.infos.join(' | '));

  const party = harness(Ctor, {
    reply: function (url, options) {
      return permit(options.body, function (one, index) {
        if (index === 1) {
          one.decision = false;
        }
      });
    }
  });
  const partyOut = await party.pdp.consult(workedInput());
  note(rows, partyOut.code === 'STS-AUTHZEN-0125' && partyOut.status === 400,
       'a false requesting-party gate is 0125', JSON.stringify(partyOut));

  const narrowed = harness(Ctor, {
    reply: function (url, options) {
      return permit(options.body, function (one, index) {
        if (index === 0) {
          one.context = { issuance: {
            token_lifetime: 40, granted_scope: 'read:docs extra',
            sub: 'somebody', act: { sub: 'no' } } };
        }
        if (index === 3) {
          one.decision = false;
        }
      });
    }
  });
  const narrowedOut = await narrowed.pdp.consult(workedInput());
  note(rows, narrowedOut.ok === true &&
       narrowedOut.scope === 'read:docs' &&
       narrowedOut.lifetimeCapS === 40 &&
       narrowed.infos.join(' ').indexOf('write:docs') >= 0 &&
       narrowed.infos.join(' ').indexOf('40') >= 0 &&
       narrowed.infos.join(' ').indexOf('https://') < 0,
       'a false scope drops that scope, granted_scope cannot widen, and ' +
       'token_lifetime is a ceiling; other issuance members are ignored',
       JSON.stringify(narrowedOut) + ' ' + narrowed.infos.join(' | '));

  const same = harness(Ctor, {
    reply: function (url, options) {
      return permit(options.body, function (one, index) {
        if (index === 0) {
          one.context = { issuance: {
            granted_scope: 'read:docs write:docs',
            token_lifetime: '40' } };
        }
      });
    }
  });
  const sameOut = await same.pdp.consult(workedInput());
  note(rows, sameOut.ok === true && sameOut.scope === null &&
       sameOut.lifetimeCapS === null,
       'a granted_scope equal to the sent list leaves the scope, and a ' +
       'garbage token_lifetime is ignored',
       JSON.stringify(sameOut));

  const none = harness(Ctor, {
    reply: function (url, options) {
      return permit(options.body, function (one, index) {
        if (index === 0) {
          one.context = { issuance: { granted_scope: '' } };
        }
      });
    }
  });
  const noneOut = await none.pdp.consult(workedInput());
  note(rows, noneOut.ok === true && noneOut.scope === '',
       'an empty granted_scope grants nothing', JSON.stringify(noneOut));

  const listed = harness(Ctor, {
    reply: function (url, options) {
      return permit(options.body, function (one, index) {
        if (index === 0) {
          one.context = { issuance: {
            granted_scope: ['read:docs write:docs'] } };
        }
      });
    }
  });
  const listedOut = await listed.pdp.consult(workedInput());
  note(rows, listedOut.scope === null,
       'a granted_scope array of one string splits into scope names',
       JSON.stringify(listedOut));

  const mixed = harness(Ctor, {
    reply: function (url, options) {
      return permit(options.body, function (one, index) {
        if (index === 0) {
          one.context = { issuance: {
            granted_scope: ['read:docs', 1], token_lifetime: 0 } };
        }
      });
    }
  });
  const mixedOut = await mixed.pdp.consult(workedInput());
  note(rows, mixedOut.ok === true && mixedOut.scope === null &&
       mixedOut.lifetimeCapS === null,
       'a granted_scope that is not all strings, and a zero lifetime, ' +
       'are ignored',
       JSON.stringify(mixedOut));

  const faults = [
    [{ ok: false, status: 0, kind: 'timeout', why: 'timed out', body: '' },
     'STS-AUTHZEN-0124', 'a timeout'],
    [{ ok: false, status: 0, kind: 'outbound-off', why: 'off', body: '' },
     'STS-AUTHZEN-0124', 'outbound off'],
    [{ ok: false, status: 400, kind: '', why: '', body: '{"error":"no"}' },
     'STS-AUTHZEN-0124', 'a non-2xx, including 400'],
    [{ ok: true, status: 200, kind: '', why: '', body: 'not-json' },
     'STS-AUTHZEN-0126', 'a 2xx that is not JSON'],
    [{ ok: true, status: 200, kind: '', why: '',
       body: JSON.stringify({ evaluations: [{ decision: true }] }) },
     'STS-AUTHZEN-0126', 'a short evaluations array'],
    [{ ok: false, status: 0, kind: 'url', why: 'internal', body: '' },
     'STS-AUTHZEN-0123', 'a dialer URL refusal']
  ];
  for (let f = 0; f < faults.length; f += 1) {
    const row = faults[f];
    const one = harness(Ctor, { reply: row[0] });
    const out = await one.pdp.consult(workedInput());
    note(rows, out.code === row[1] && out.description === FAULT &&
         out.status === 503 && one.calls.length === 1,
         row[2] + ' is ' + row[1], JSON.stringify(out));
  }

  const buffered = harness(Ctor, {
    reply: function (url, options) {
      const answer = permit(options.body, function (one, index) {
        if (index === 0) {
          one.decision = 'true';
        }
      });
      answer.body = Buffer.from(answer.body);
      return answer;
    }
  });
  const bufferedOut = await buffered.pdp.consult(workedInput());
  note(rows, bufferedOut.code === 'STS-AUTHZEN-0126',
       'a Buffer body whose decision is not a boolean is 0126',
       JSON.stringify(bufferedOut));

  const erred = harness(Ctor, {
    reply: function (url, options) {
      return permit(options.body, function (one, index) {
        if (index === 2) {
          one.decision = false;
          one.context = { error: { status: 400 } };
        }
      });
    }
  });
  const erredOut = await erred.pdp.consult(workedInput());
  note(rows, erredOut.code === 'STS-AUTHZEN-0126',
       'an item carrying context.error is 0126, not a dropped scope',
       JSON.stringify(erredOut));

  const thrown = harness(Ctor, {
    request: function () {
      return Promise.reject(new Error('boom'));
    }
  });
  const thrownOut = await thrown.pdp.consult(workedInput());
  note(rows, thrownOut.code === 'STS-AUTHZEN-0124' &&
       thrown.tags.indexOf('STS-AUTHZEN-0124') >= 0,
       'a dial that throws is 0124 and consult does not throw',
       JSON.stringify(thrownOut));

  const sameParty = Ctor.batchOf({
    subject: { type: 'client', id: 'gw' },
    party: { type: 'client', id: 'gw' },
    audiences: [AUDIENCE],
    scopes: ['read:docs']
  });
  note(rows, sameParty.items.length === 2 &&
       sameParty.items[0].kind === 'subject' &&
       sameParty.items[1].kind === 'scope',
       'a party that is the subject is not sent',
       JSON.stringify(sameParty.items));

  const noParty = Ctor.batchOf({
    subject: { type: 'user', id: 'alice' },
    audiences: [],
    scopes: ['read:docs']
  });
  note(rows, noParty.body.resource.id === '' &&
       noParty.items.length === 2 && noParty.items[0].kind === 'subject',
       'no audience is one gate whose resource id is empty',
       JSON.stringify(noParty.body.resource));

  const two = {
    subject: { type: 'user', id: 'alice' },
    party: { type: 'client', id: 'gw' },
    audiences: ['https://a.example', 'https://b.example'],
    scopes: ['read:docs', 'write:docs'],
    clientId: 'gw',
    subjectTokenType: ACCESS,
    subjectClaims: { exp: 1893456000 }
  };
  const twoBuilt = Ctor.batchOf(two);
  note(rows, twoBuilt.items.length === 8 &&
       !twoBuilt.body.evaluations[0].resource &&
       twoBuilt.body.evaluations[4].resource.type === 'audience' &&
       twoBuilt.body.evaluations[4].resource.id === 'https://b.example' &&
       twoBuilt.body.evaluations[2].resource.type === 'protected_resource' &&
       twoBuilt.body.evaluations[5].resource.id === 'https://b.example' &&
       twoBuilt.body.resource.id === 'https://a.example',
       'a second audience repeats the gates and overrides the resource',
       JSON.stringify(twoBuilt.items));

  const secondGate = harness(Ctor, {
    reply: function (url, options) {
      return permit(options.body, function (one, index) {
        if (index === 4) {
          one.decision = false;
        }
      });
    }
  });
  const secondGateOut = await secondGate.pdp.consult(two);
  note(rows, secondGateOut.code === 'STS-AUTHZEN-0125',
       'a false gate on a later audience refuses the exchange',
       JSON.stringify(secondGateOut));

  const secondScope = harness(Ctor, {
    reply: function (url, options) {
      return permit(options.body, function (one, index) {
        if (index === 7) {
          one.decision = false;
        }
        if (index === 0) {
          one.context = { issuance: { token_lifetime: 90 } };
        }
        if (index === 4) {
          one.context = { issuance: { token_lifetime: 30,
                                      granted_scope: 'read:docs' } };
        }
        if (index === 1) {
          one.context = { issuance: { token_lifetime: 5 } };
        }
      });
    }
  });
  const secondScopeOut = await secondScope.pdp.consult(two);
  note(rows, secondScopeOut.ok === true &&
       secondScopeOut.scope === 'read:docs' &&
       secondScopeOut.lifetimeCapS === 30,
       'a false scope drops it for every audience, lifetimes take the ' +
       'minimum of the subject gates, and a party gate\'s lifetime is ' +
       'ignored',
       JSON.stringify(secondScopeOut));

  const omitGrant = harness(Ctor, {
    reply: function (url, options) {
      return permit(options.body, function (one, index) {
        if (index === 0) {
          one.context = { issuance: { granted_scope: 'read:docs' } };
        }
      });
    }
  });
  const omitOut = await omitGrant.pdp.consult(two);
  note(rows, omitOut.scope === 'read:docs',
       'a subject gate that omits granted_scope does not narrow by it; ' +
       'one that names a list does',
       JSON.stringify(omitOut));

  const deep = Ctor.contextOf({ act: chain(33), clientId: 'gw' });
  const shallow = Ctor.contextOf({ act: chain(2), clientId: 'x'.repeat(2049),
                                   subjectClaims: { exp: -1 } });
  note(rows, !deep.act && shallow.act && shallow.act.act &&
       !shallow.client_id && shallow.subject_token.exp === -1,
       'an act chain deeper than 32 is omitted whole, a too-long client ' +
       'id is omitted, and a negative exp is sent',
       JSON.stringify({ deep: deep, shallow: shallow }));

  note(rows, JSON.stringify(Ctor.grantOf('')) === '[]' &&
       JSON.stringify(Ctor.grantOf([])) === '[]' &&
       JSON.stringify(Ctor.grantOf(['read:docs write:docs'])) ===
         JSON.stringify(['read:docs', 'write:docs']) &&
       Ctor.grantOf(['read:docs', 1]) === null &&
       Ctor.grantOf(null) === null &&
       Ctor.issuanceOf({ context: { issuance: [] } }) === null &&
       Ctor.issuanceOf({ context: { issuance: { token_lifetime: 1 } } })
         .token_lifetime === 1 &&
       Ctor.partyOf(null, 'user').type === 'user' &&
       Ctor.partyOf({ type: 'client', id: 'gw' }, 'user').id === 'gw' &&
       Ctor.actSendable(null) === false &&
       Ctor.actSendable(chain(32)) === true &&
       Ctor.actSendable(chain(33)) === false,
       'grantOf, issuanceOf, partyOf and actSendable keep the edges the ' +
       'batch relies on');

  log.debug("Leaving unitFindings().");
  return rows;
}

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  const part = String(jwt || '').split('.')[1] || '';
  let out = null;
  try {
    out = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  } catch (e) {
    log.debug("Caught in claimsOf(): " + ((e && e.message) || e));
    // Not a JWT. The finding says so.
    out = null;
  }
  log.debug("Leaving claimsOf().");
  return out;
}

function postForm(port, urlPath, form, caPem) {
  log.debug("Entering postForm().");
  log.debug("Leaving postForm().");
  return new Promise(function (resolve) {
    const text = new URLSearchParams(form).toString();
    const req = https.request({
      host: '127.0.0.1', port: port, path: urlPath, method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        'content-length': Buffer.byteLength(text)
      },
      ca: caPem, agent: false
    }, function (res) {
      let raw = '';
      res.on('data', function (chunk) {
        raw += chunk;
      });
      res.on('end', function () {
        let json = null;
        try {
          json = JSON.parse(raw);
        } catch (e) {
          log.debug("Caught in postForm(): " + ((e && e.message) || e));
          json = null;
        }
        resolve({ status: res.statusCode, text: raw, json: json || {} });
      });
    });
    req.on('error', function (e) {
      log.debug("Caught in postForm(): " + ((e && e.message) || e));
      resolve({ status: 0, text: String(e && e.message || e), json: {} });
    });
    req.end(text);
  });
}

async function childBody() {
  log.debug("Entering childBody().");
  const rows = [];
  const marks = [];
  try {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const keystore = require(ROOT + '/common/keystore');
    const pki = require(ROOT + '/common/pki');
    const helpers = require(ROOT + '/common/helpers');
    const realms = require(ROOT + '/common/realms');
    const config = require(ROOT + '/common/config');
    const applications = require(ROOT + '/common/applications');
    const errorCodes = require(ROOT + '/common/error_codes');
    const tls = require(ROOT + '/tls/tls_server');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const adminActions = require(ROOT + '/admin-core/admin_actions');
    const testCa = require(ROOT + '/tests/protocol/outbound_test_ca');
    const outsideCa = require(ROOT + '/tests/tools/pep-credential.js');
    const mark = errorCodes.mark;
    errorCodes.mark = function (res, code) {
      marks.push(code);
      return mark.apply(this, arguments);
    };
    await keystore.start();
    if (!realms.get(REALM)) {
      realms.create({ id: REALM, name: REALM });
    }
    await pki.start({ realmIds: ['', REALM],
      keySetFor: function (id) {
        log.debug("Entering keySetFor().");
        log.debug("Leaving keySetFor().");
        return helpers.stsKeysFor.of(id);
      },
      keySetHeldFor: function () {
        log.debug("Entering keySetHeldFor().");
        log.debug("Leaving keySetHeldFor().");
        return false;
      } });
    const pep = await outsideCa.mint({
      subject: 'CN=azextpep,O=Outside', crlBase: '' });
    const added = tls.addAnchors(pep.anchorPem);
    note(rows, added && added.added === 1,
         'setup: the PDP caller\'s root is in the truststore',
         JSON.stringify(added));
    const der = new nodeCrypto.X509Certificate(pep.leaf.pem).raw;
    realms.run(realms.get(REALM), function () {
      log.debug("Entering the PDP realm setup().");
      ldap.createUser('azextpep', { invent: false });
      ldap.changeStoredCertificate('person', 'azextpep', { add: der });
      adminActions.groupsAction({
        action: 'add-member',
        group: String(config.value('roles.authzenPepGroup')),
        member: 'azextpep' });
      ldap.locateEntry('azextpep').stored.attributes
        .stsauthzenapplication = ['todo-app'];
      log.debug("Leaving the PDP realm setup().");
    });
    const serverCa = await testCa.makeCa();
    const serverLeaf = await testCa.listenerCertificate(serverCa,
                                                       '127.0.0.1');
    const listener = https.createServer(Object.assign({
      cert: serverLeaf.cert, key: serverLeaf.key,
      ca: tls.clientTruststoreOptions().ca
    }, tls.clientAuthOptions('optional'), tls.protocolOptions()), app);
    tls.trustClientCertificatesOn(listener,
      'the authzen_external_pdp listener', function () {
        log.debug("Entering the listener's certificateOf().");
        log.debug("Leaving the listener's certificateOf().");
        return { key: serverLeaf.key, cert: serverLeaf.cert };
      });
    await new Promise(function (ok) {
      listener.listen(0, '127.0.0.1', ok);
    });
    const port = listener.address().port;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'azext-'));
    const certFile = path.join(dir, 'cert.pem');
    const keyFile = path.join(dir, 'key.pem');
    const caFile = path.join(dir, 'ca.pem');
    fs.writeFileSync(certFile, pep.certPem);
    fs.writeFileSync(keyFile, pep.keyPem);
    fs.writeFileSync(caFile, serverCa.certPem);
    const url = 'https://127.0.0.1:' + port + PREFIX +
      '/access/v1/evaluations';
    const switches = [
      ['authzen.tokenExchange', true],
      ['authzen.externalPdp', true],
      ['authzen.externalPdpUrl', url],
      ['authzen.externalPdpClientCertFile', certFile],
      ['authzen.externalPdpClientKeyFile', keyFile],
      ['authzen.externalPdpCaFile', caFile],
      ['oauth2.accessTokenTtlS', 120]
    ];
    switches.forEach(function (pair) {
      const wrote = config.setOverride(pair[0], pair[1]);
      note(rows, wrote && wrote.ok === true,
           'setup: ' + pair[0] + ' is set',
           JSON.stringify(wrote));
    });
    const secret = 'azext-as-secret-0123456789abcdef';
    const client = applications.createApplication({
      identifier: 'azext-as', protocols: ['oauth2'],
      fields: {
        oauthClientId: 'azext-as', oauthClientSecret: secret,
        oauthTokenEndpointAuthMethod: 'client_secret_post',
        oauthGrantType: ['password', EXCHANGE]
      }
    });
    note(rows, client && client.ok !== false,
         'setup: the exchanging client exists', JSON.stringify(client));
    // A token is minted only for an audience an application holds (#1140),
    // in every mode. The PDP is asked about this same audience.
    const api = applications.createApplication({
      identifier: 'azext-api', kind: 'oauth2-resource-server',
      protocols: ['oauth2'],
      fields: { oauthAudience: [AUDIENCE] }
    });
    note(rows, api && api.ok !== false,
         'setup: the audience is a registered target', JSON.stringify(api));
    const auth = { client_id: 'azext-as', client_secret: secret };
    const issued = await postForm(port, '/oauth2/token', Object.assign({
      grant_type: 'password', username: 'azext-alice',
      password: 'anything', scope: 'read:docs'
    }, auth), serverCa.certPem);
    const subject = String(issued.json.access_token || '');
    const subjectClaims = claimsOf(subject);
    note(rows, issued.status === 200 && subjectClaims &&
         subjectClaims.exp - subjectClaims.iat === 120,
         'setup: the subject token lives 120 seconds',
         issued.status + ' ' + issued.text.slice(0, 300));
    const raised = config.setOverride('oauth2.accessTokenTtlS', 3600);
    note(rows, raised && raised.ok === true &&
         config.value('oauth2.accessTokenTtlS') === 3600,
         'setup: the access-token lifetime is now 3600',
         JSON.stringify(raised));
    const before = marks.length;
    const exchanged = await postForm(port, '/oauth2/token', Object.assign({
      grant_type: EXCHANGE, subject_token: subject,
      subject_token_type: ACCESS, audience: AUDIENCE
    }, auth), serverCa.certPem);
    const minted = claimsOf(exchanged.json.access_token);
    const now = Math.floor(Date.now() / 1000);
    const left = subjectClaims ? subjectClaims.exp - now : 0;
    const life = minted ? minted.exp - minted.iat : 0;
    note(rows, exchanged.status === 200 && !!minted && life < 600 &&
         life <= left + 20 && life >= left - 2 && life > 30 &&
         marks.slice(before).indexOf('STS-AUTHZEN-0124') < 0,
         'the exchanged token lives about the subject token\'s remaining ' +
         'life, not the 3600 setting, so the external PDP was asked and ' +
         'its token_lifetime was honoured',
         exchanged.status + ' life ' + life + ' left ' + left + ' ' +
         exchanged.text.slice(0, 400) + ' marks ' +
         marks.slice(before).join(','));
    const faultAt = marks.length;
    const closed = config.setOverride('authzen.externalPdpUrl',
      'https://127.0.0.1:1' + PREFIX + '/access/v1/evaluations');
    note(rows, closed && closed.ok === true, 'setup: the PDP URL is a ' +
         'closed port', JSON.stringify(closed));
    const fault = await postForm(port, '/oauth2/token', Object.assign({
      grant_type: EXCHANGE, subject_token: subject,
      subject_token_type: ACCESS, audience: AUDIENCE
    }, auth), serverCa.certPem);
    const told = String(fault.json.error_description || '');
    note(rows, fault.status === 503 &&
         fault.json.error === 'temporarily_unavailable' &&
         !fault.json.access_token &&
         marks.slice(faultAt).indexOf('STS-AUTHZEN-0124') >= 0 &&
         told.indexOf('STS-') < 0 && told.indexOf('127.0.0.1') < 0,
         'a closed PDP port is 503 and STS-AUTHZEN-0124, and the client ' +
         'is told neither the code nor the address',
         fault.status + ' ' + told + ' marks ' +
         marks.slice(faultAt).join(','));
    await new Promise(function (ok) {
      listener.close(ok);
    });
  } catch (e) {
    log.debug("Caught in childBody(): " + ((e && e.stack) || e));
    note(rows, false, 'the child ran to the end', e && e.stack);
  }
  log.debug("Leaving childBody().");
  return rows;
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const out = path.join(os.tmpdir(), 'sts-azext-' + process.pid + '-' +
                        Date.now() + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|OID4VC|OID4VP|OAUTH2_|CONFIG_FILE$)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean.STS_HTTPS = 'false';
  clean.STS_RISK_BREACH_CHECK = 'off';
  clean[CHILD_FLAG] = '1';
  clean.AZEXT_OUT = out;
  clean.LOG_LEVEL = 'error';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 180000,
    maxBuffer: 64 * 1024 * 1024
  });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in spawnChild(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    log.debug("Caught in spawnChild(): " + ((e && e.message) || e));
    // A temporary report left behind is not a failed assertion.
  }
  log.debug("Leaving spawnChild().");
  return { findings: findings, status: result.status,
           stderr: String(result.stderr || '').slice(-2500) };
}

async function run(t) {
  log.debug("Entering run().");
  const unit = await unitFindings();
  unit.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  const child = spawnChild();
  if (!child.findings) {
    t.check(false, 'the child wrote a report',
            'status ' + child.status + ' ' + child.stderr);
    log.debug("Leaving run(). No child report.");
    return;
  }
  let failed = false;
  child.findings.forEach(function (row) {
    if (!row.ok) {
      failed = true;
    }
    t.check(row.ok, row.what, row.detail);
  });
  if (failed) {
    t.check(false, 'child stderr', child.stderr);
  }
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG]) {
  childBody().then(function (rows) {
    fs.writeFileSync(process.env.AZEXT_OUT, JSON.stringify(rows));
    process.exit(0);
  }, function (e) {
    process.stderr.write(String((e && e.stack) || e));
    process.exit(1);
  });
}

module.exports = {
  name: 'authzen_external_pdp',
  describe: 'direction B: this authorization server asks an external ' +
            'AuthZEN PDP before an RFC 8693 access token (#1200)',
  run: run
};
