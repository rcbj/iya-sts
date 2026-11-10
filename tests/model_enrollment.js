// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_enrollment.js
//
// ---------------------------------------------------------------------------
// THE CERTIFICATE-ENROLLMENT MODEL, AND WHAT HOLDS ACME, EST AND SCEP TO IT
// (#1579).
//
// `models/enrollment/acme.tsp`, `est.tsp` and `scep.tsp` state every request
// document the three protocols read, the answers ACME and EST's nonce send,
// the error types, the registers and the operations. This holds three
// things:
//
//   A. the build's check (`models/lib/enrollment_lib.mjs`'s
//      checkEnrollment()) passes the generated table and refuses each kind
//      of wrong model, asserted on a copy with one thing broken;
//   B. every validator and register is the model's: the family's files
//      declare no zod schema and no copy of a register of their own, and the
//      generated validators refuse and accept what the model says;
//   C. what the three protocols answered — every ACME resource and problem
//      document, EST's nonce answers and SCEP's capabilities and CertRep
//      values that `tests/enrollment_model_wire.snapshot.json` recorded — is
//      the model's, and every error type `acme/` sends is declared.
//
// That the generated validators answer on the wire exactly as the
// hand-written ones did is `tests/enrollment_model_wire.js`'s.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const url = require('url');

const log = require('bunyan').createLogger({
  name: 'model_enrollment',
  level: process.env.LOG_LEVEL || 'info'
});

const ROOT = path.join(__dirname, '..');
const ModelTables = require('../common/model_tables');

// A copy of the generated table, for one thing to be broken in.
function copy() {
  log.debug("Entering copy().");
  log.debug("Leaving copy().");
  return JSON.parse(JSON.stringify(ModelTables.file('enrollment.json')));
}

// One member of a body of a copy, by family, id and name.
function field(model, family, id, name) {
  log.debug("Entering field().");
  const body = model.bodies.filter(function (one) {
    return one.family === family && one.id === id;
  })[0];
  log.debug("Leaving field().");
  return body.fields.filter(function (one) {
    return one.name === name;
  })[0];
}

// One register of a copy.
function register(model, family, id) {
  log.debug("Entering register().");
  log.debug("Leaving register().");
  return model.registers.filter(function (one) {
    return one.family === family && one.id === id;
  })[0];
}

// A. The build's refusals.
async function buildCheck(t) {
  log.debug("Entering buildCheck().");
  const lib = await import(url.pathToFileURL(path.join(ROOT, 'models', 'lib',
    'enrollment_lib.mjs')).href);
  const generated = ModelTables.file('enrollment.json');
  t.check(lib.checkEnrollment(generated).length === 0,
          'A. the generated enrollment model is clean',
          lib.checkEnrollment(generated).join('; '));
  const refused = function (what, pattern, change) {
    const broken = copy();
    change(broken);
    const said = lib.checkEnrollment(broken).join('; ');
    t.check(pattern.test(said), 'A. refused: ' + what, said || '(nothing)');
  };
  refused('a string with no bound', /new-order\.profile is a string with no/,
    function (m) {
      delete field(m, 'acme', 'new-order', 'profile').maxLength;
    });
  refused('an array with no bound', /identifiers is an array with no bound/,
    function (m) {
      delete field(m, 'acme', 'new-order', 'identifiers').maxItems;
    });
  refused('an item with no bound', /contact\[\] is a string with no bound/,
    function (m) {
      delete field(m, 'acme', 'new-account', 'contact').items.maxLength;
    });
  refused('an integer without both bounds', /no minimum and maximum/,
    function (m) {
      delete field(m, 'acme', 'revoke', 'reason').minimum;
    });
  refused('a length bound on an integer', /is not a string and takes/,
    function (m) {
      field(m, 'est', 'nonce-request', 'len').maxLength = 3;
    });
  refused('a pattern that does not compile', /pattern does not compile/,
    function (m) {
      field(m, 'est', 'nonce-request', 'reqTypeInfo').shape.fields[0]
        .pattern = '([';
    });
  refused('a valuesFrom naming nothing', /valuesFrom names no register/,
    function (m) {
      field(m, 'scep', 'query', 'operation').resolved = false;
    });
  refused('an enumeration in a JSON document', /enumeration in a JSON/,
    function (m) {
      field(m, 'acme', 'finalize', 'csr').json = 'enum';
      field(m, 'acme', 'finalize', 'csr').values = ['x'];
    });
  refused('a member citing nothing', /new-order\.replaces cites nothing/,
    function (m) {
      field(m, 'acme', 'new-order', 'replaces').cite = '';
    });
  refused('a register row citing nothing', /problems\.malformed cites/,
    function (m) {
      register(m, 'acme', 'problems').rows.filter(function (row) {
        return row.name === 'malformed';
      })[0].cite = '';
    });
  refused('two register rows with one value', /two rows the value 2/,
    function (m) {
      register(m, 'scep', 'fail-info').rows[0].value = '2';
    });
  refused('an answer member citing nothing', /order\.finalize cites/,
    function (m) {
      m.answers.filter(function (one) {
        return one.id === 'order';
      })[0].list.filter(function (one) {
        return one.name === 'finalize';
      })[0].cite = '';
    });
  refused('a body declared twice', /acme\/finalize is declared twice/,
    function (m) {
      m.bodies.push(JSON.parse(JSON.stringify(m.bodies.filter(
        function (one) {
          return one.family === 'acme' && one.id === 'finalize';
        })[0])));
    });
  refused('an operation answering a method none does', /answers PUT/,
    function (m) {
      m.operations[0].list[0].methods.push('PUT');
    });
  log.debug("Leaving buildCheck().");
}

// The family's files, with their comments taken out.
const FILES = ['acme/acme_jws.ts', 'acme/acme.ts', 'est/est.ts',
               'scep/scep.ts', 'scep/scep_cms.ts'];

function source(file) {
  log.debug("Entering source().");
  log.debug("Leaving source().");
  return fs.readFileSync(path.join(ROOT, file), 'utf8')
    .replace(/^\s*\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
}

// B. The validators and registers are the model's, and say what it says.
function validators(t) {
  log.debug("Entering validators().");
  FILES.forEach(function (file) {
    t.check(!/\bv[zt]\.|\bvzEst\b|validation\.(z|types)\b/.test(source(file)),
            'B. ' + file + ' writes no request schema of its own');
  });
  const copies = [
    ['acme/acme_jws.ts', /'RS256',\s*'RS384'/, 'the account algorithms'],
    ['acme/acme_jws.ts', /'HS256',\s*'HS384'/, 'the EAB algorithms'],
    ['acme/acme_jws.ts', /'keyCompromise'/, 'the revocation reasons'],
    ['acme/acme.ts', /\['dns',\s*'ip'/, 'the identifier types'],
    ['acme/acme.ts', /= 'sts-entry-binding-01'/, 'the challenge type'],
    ['acme/acme.ts', /re: \/\^\\\/directory/, 'the resources\' methods'],
    ['acme/acme.ts', /type !== 'badNonce'/, 'the uncounted error types'],
    ['est/est.ts', /name: 'cacerts', method/, 'the operations'],
    ['est/est.ts', /pkcs10: 'application\/pkcs10'/, 'the media types'],
    ['est/est.ts', /\[400, 401/, 'the counted statuses'],
    ['est/est.ts', /'tls-server': \['dNSName'/, 'the CSR attribute names'],
    ['scep/scep.ts', /\['GetCACaps',\s*'GetCACert'/, 'the operations'],
    ['scep/scep.ts', /'POSTPKIOperation',\s*'SHA-256'/, 'the capabilities'],
    ['scep/scep_cms.ts', /17: 'RenewalReq'/, 'the message types'],
    ['scep/scep_cms.ts', /SUCCESS: '0'/, 'the pkiStatus values'],
    ['scep/scep_cms.ts', /badAlg: '0'/, 'the failInfo values']
  ];
  copies.forEach(function (one) {
    t.check(!one[1].test(source(one[0])),
            'B. ' + one[0] + ' keeps no copy of ' + one[2]);
  });
  const EnrollmentModel = require('../common/enrollment_model');
  const generated = ModelTables.file('enrollment.json');
  generated.bodies.forEach(function (body) {
    t.check(!!EnrollmentModel.body(body.family, body.id),
            'B. a validator is generated for ' + body.family + ' ' + body.id);
  });
  const parse = function (family, id, value) {
    return EnrollmentModel.body(family, id).safeParse(value);
  };
  t.check(parse('acme', 'new-order', { identifiers: [{ type: 'dns',
    value: 'a.test' }], other: 1 }).success,
          'B. new-order is loose: an unknown member is kept');
  t.check(!parse('acme', 'new-order', { identifiers: [{ type: 'dns',
    value: 'a.test', other: 1 }] }).success,
          'B. an identifier is strict: an unknown member is refused');
  t.check(!parse('acme', 'flattened', { protected: 'a', payload: '',
    signature: 'b', header: {} }).success,
          'B. the flattened JWS allows no unprotected header');
  t.check(!parse('acme', 'revoke', { certificate: 'a', reason: 1.5 })
    .success && parse('acme', 'revoke', { certificate: 'a', reason: 4 })
    .success, 'B. revoke\'s reason is an integer');
  t.check(!parse('acme', 'authz-update', { status: 'valid' }).success,
          'B. an authorization update is deactivation only');
  t.check(!parse('est', 'nonce-request', { reqTypeInfo: { type: 'x' } })
    .success, 'B. a nonce request\'s type is a dotted-decimal OID');
  const query = parse('scep', 'query', { operation: 'GetCACaps', x: '1' });
  t.check(query.success && query.data.x === undefined,
          'B. SCEP\'s query drops a parameter the model does not name');
  t.check(!parse('scep', 'query', { operation: 'Nope' }).success,
          'B. SCEP\'s operation is one of the model\'s operations');
  t.check(parse('acme', 'orders-query', { page: '2' }).data.page === 2,
          'B. the orders list\'s page arrives as text and is an integer');
  log.debug("Leaving validators().");
}

// Which ACME answer a recorded body is.
function acmeAnswerOf(body) {
  log.debug("Entering acmeAnswerOf().");
  let id = null;
  if (body.type !== undefined && body.detail !== undefined) {
    id = 'problem';
  } else if (body.newNonce !== undefined) {
    id = 'directory';
  } else if (body.createdAt !== undefined) {
    id = 'account';
  } else if (body.finalize !== undefined) {
    id = 'order';
  } else if (body.challenges !== undefined) {
    id = 'authorization';
  } else if (body.url !== undefined && body.type !== undefined) {
    id = 'challenge';
  } else if (body.orders !== undefined) {
    id = 'orders';
  } else if (body.suggestedWindow !== undefined) {
    id = 'renewal-info';
  }
  log.debug("Leaving acmeAnswerOf(). " + id);
  return id;
}

// C. What the three protocols answered is the model's.
function answered(t) {
  log.debug("Entering answered().");
  const EnrollmentModel = require('../common/enrollment_model');
  const wire = require('./enrollment_model_wire').recorded().wire;
  const prefix = 'urn:ietf:params:acme:error:';
  const held = {};
  const strays = [];
  wire.forEach(function (one) {
    if (one.family !== 'acme' || !one.body || typeof one.body !== 'object') {
      return;
    }
    const id = acmeAnswerOf(one.body);
    if (!id) {
      strays.push(one.step);
      return;
    }
    held[id] = (held[id] || 0) + 1;
    const problems = EnrollmentModel.undeclared('acme', id, one.body);
    t.check(problems.length === 0, 'C. acme, ' + one.step + ': the ' + id +
            ' is the model\'s', problems.join('; '));
    if (id === 'problem') {
      t.check(!EnrollmentModel.unknownTerm('acme', 'problems',
        String(one.body.type).replace(prefix, '')),
              'C. acme, ' + one.step + ': ' + one.body.type + ' is declared');
    }
  });
  t.check(strays.length === 0, 'C. every recorded ACME body is an answer ' +
          'the model has', strays.join(', '));
  t.check(Object.keys(held).length === 8,
          'C. all eight ACME answers were recorded and held',
          JSON.stringify(held));
  const nonces = wire.filter(function (one) {
    return one.family === 'est' && one.status === 200 &&
           /^nonce/.test(one.step);
  });
  t.check(nonces.length >= 2 && nonces.every(function (one) {
    return EnrollmentModel.undeclared('est', 'nonce', one.body).length === 0;
  }), 'C. every recorded EST nonce answer is the model\'s');
  const caps = wire.filter(function (one) {
    return one.family === 'scep' && one.status === 200 &&
           /GetCACaps/.test(one.step);
  });
  t.check(caps.length >= 1 && caps.every(function (one) {
    return one.body === EnrollmentModel.names('scep', 'capabilities')
      .join('\n') + '\n';
  }), 'C. GetCACaps answered the model\'s capabilities, in order');
  const reps = wire.filter(function (one) {
    return one.family === 'scep' && one.body && one.body.pkiStatus;
  });
  const status = EnrollmentModel.map('scep', 'pki-status');
  const failInfo = EnrollmentModel.names('scep', 'fail-info');
  t.check(reps.length >= 3 && reps.every(function (one) {
    return Object.keys(status).some(function (name) {
      return status[name] === one.body.pkiStatus;
    }) && (one.body.failInfo === null ||
           failInfo.indexOf(one.body.failInfo) >= 0) &&
           EnrollmentModel.map('scep', 'message-types', true)[
             one.body.messageType] === 'CertRep';
  }), 'C. every recorded CertRep carries the model\'s messageType, ' +
      'pkiStatus and failInfo');
  // Every error type a funnel in acme/ names is declared.
  const named = new Set();
  ['acme/acme.ts', 'acme/acme_jws.ts', 'acme/acme_console.ts']
    .forEach(function (file) {
      const text = source(file).replace(/\s+/g, ' ');
      const patterns = [/acmeProblem\(ctx, \d+, '([a-zA-Z]+)'/g,
                        /refusal\('([a-zA-Z]+)'/g,
                        /\{ type: '([a-zA-Z]+)', detail/g,
                        /type = '([a-zA-Z]+)'/g,
                        /ERROR_PREFIX \+ '([a-zA-Z]+)'/g];
      patterns.forEach(function (pattern) {
        let found = pattern.exec(text);
        while (found) {
          named.add(found[1]);
          found = pattern.exec(text);
        }
      });
    });
  const undeclared = Array.from(named).filter(function (name) {
    return EnrollmentModel.unknownTerm('acme', 'problems', name);
  });
  t.check(named.size >= 15 && undeclared.length === 0,
          'C. every error type acme/ sends is declared (' + named.size +
          ' named)', undeclared.join(', '));
  log.debug("Leaving answered().");
}

async function run(t) {
  log.debug("Entering run().");
  await buildCheck(t);
  validators(t);
  answered(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'model_enrollment',
  describe: 'the certificate-enrollment model (#1579): the build\'s ' +
            'refusals, every ACME, EST and SCEP validator and register ' +
            'generated from it, and every recorded answer, error type, ' +
            'capability and CertRep value held to it',
  run: run
};
