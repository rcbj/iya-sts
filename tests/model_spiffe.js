// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_spiffe.js
//
// ---------------------------------------------------------------------------
// THE SPIFFE MODEL, AND WHAT HOLDS THE SERVICE TO IT (#1579).
//
// `models/spiffe/*.tsp` states every message, method and enum of the
// Workload API, the SPIRE Server API and the Broker API, each request
// field's refusal, each service's and method's statuses and why a method is
// unimplemented, the SPIFFE ID grammar, an X509-SVID leaf's rules, and the
// bundle's and a JWT-SVID's members. This holds four things:
//
//   A. the build's refusals: the model as written compiles and reads to
//      what `models/generated/spiffe.json` holds, and is the vendored
//      protos field for field; a copy with one thing broken — a field's
//      number, name, type or oneof, a field made required, a method's
//      streaming, a method missing, a well-known type's member spelt in
//      snake_case (the trap that serialises a Struct to nothing), a refusal
//      with a bad code or a stray `{reason}`, a grammar pattern that does
//      not compile — is refused by `checkSpiffe()`, as the image build runs
//      it;
//   B. no hand check is left in the family: the grammar, the leaf rules,
//      the bundle's key uses, the unimplemented reasons and every modelled
//      refusal's sentence appear nowhere in `spiffe/` but the model, every
//      `refuseField()` names a refusal the model declares, and the grammar
//      parses as it says;
//   C. what the endpoints answered — every message and status recorded in
//      `tests/spiffe_model_wire.snapshot.json`, in both modes — is its
//      model's: each member a field of its message, each status one its
//      service or method declares;
//   D. the holding: a stray member, a wrong type, a snake_case Struct value,
//      an undeclared status and a bundle key of an unknown use are gaps.
//
// That the generated checks answer on the wire exactly as the hand-written
// ones did, and that the live answers record no gap, is
// `tests/spiffe_model_wire.js`'s.
// ---------------------------------------------------------------------------

const fs = require('fs');
const os = require('os');
const path = require('path');
const url = require('url');

const log = require('bunyan').createLogger({
  name: 'model_spiffe',
  level: process.env.LOG_LEVEL || 'info'
});

const ROOT = path.join(__dirname, '..');
const ModelTables = require('../common/model_tables');

const PROTOS = ['workloadapi.proto', 'brokerapi.proto',
  'spire/api/server/entry/v1/entry.proto',
  'spire/api/server/agent/v1/agent.proto',
  'spire/api/server/bundle/v1/bundle.proto',
  'spire/api/server/svid/v1/svid.proto',
  'spire/api/server/trustdomain/v1/trustdomain.proto',
  'spire/api/server/debug/v1/debug.proto'];

async function toolchain() {
  log.debug("Entering toolchain().");
  const compiler = await import(url.pathToFileURL(path.join(__dirname,
    'node_modules', '@typespec', 'compiler', 'dist', 'src', 'index.js')).href);
  const lib = await import(url.pathToFileURL(path.join(ROOT, 'models', 'lib',
    'spiffe_lib.mjs')).href);
  const protobuf = require(path.join(ROOT, 'node_modules', 'protobufjs'));
  const protos = lib.describeProtos(protobuf, path,
                                    path.join(ROOT, 'spiffe', 'protos'),
                                    PROTOS);
  log.debug("Leaving toolchain().");
  return { compiler: compiler, lib: lib, protos: protos };
}

// The SPIFFE model compiled from a copy of `models/` with `edit` applied to
// one of its files, read and checked as the build does.
async function rendered(tools, file, edit) {
  log.debug("Entering rendered().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'model-spiffe-'));
  try {
    fs.cpSync(path.join(ROOT, 'models'), dir, { recursive: true });
    fs.symlinkSync(path.join(ROOT, 'node_modules'),
                   path.join(dir, 'node_modules'));
    fs.writeFileSync(path.join(dir, 'spiffe-only.tsp'),
                     'import "./spiffe/spiffe.tsp";\n');
    const where = path.join(dir, 'spiffe', file);
    const text = fs.readFileSync(where, 'utf8');
    const edited = edit ? edit(text) : text;
    fs.writeFileSync(where, edited);
    const program = await tools.compiler.compile(tools.compiler.NodeHost,
      path.join(dir, 'spiffe-only.tsp'), { noEmit: true });
    const errors = program.diagnostics.filter(function (one) {
      return one.severity === 'error';
    }).map(function (one) {
      return one.code + ': ' + one.message;
    });
    const spiffe = tools.lib.readSpiffe(program);
    log.debug("Leaving rendered().");
    return { errors: errors, spiffe: spiffe,
             problems: tools.lib.checkSpiffe(spiffe, tools.protos),
             changed: edited !== text };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// A. The build's refusals.
async function buildCheck(t) {
  log.debug("Entering buildCheck().");
  const tools = await toolchain();
  const clean = await rendered(tools, 'spiffe.tsp', null);
  t.check(clean.errors.length === 0 && clean.problems.length === 0,
          'A. the SPIFFE model compiles and is the vendored protos, field ' +
          'for field', clean.errors.concat(clean.problems).join('; '));
  t.check(JSON.stringify(clean.spiffe) ===
            JSON.stringify(ModelTables.file('spiffe.json')),
          'A. models/generated/spiffe.json is what the model reads to');
  t.check(clean.spiffe.services.length === 8 &&
          Object.keys(clean.spiffe.messages).length > 150,
          'A. eight services and every message they reach',
          clean.spiffe.services.length + ' service(s), ' +
          Object.keys(clean.spiffe.messages).length + ' message(s)');
  const refused = async function (what, file, pattern, edit) {
    const out = await rendered(tools, file, edit);
    const said = out.errors.concat(out.problems).join('; ');
    t.check(out.changed && pattern.test(said), 'A. refused: ' + what,
            said.slice(0, 600) || '(nothing)');
  };
  const inModel = function (model, from, to) {
    return function (text) {
      const at = text.indexOf('model ' + model + ' {');
      const end = text.indexOf('\n  }\n', at);
      return text.slice(0, at) +
        text.slice(at, end).replace(from, to) + text.slice(end);
    };
  };
  await refused('a field number that is not the proto\'s', 'workload.tsp',
    /JWTSVIDRequest\.audience is field 7 and the vendored one is 1/,
    inModel('JWTSVIDRequest', '@field(1)', '@field(7)'));
  await refused('a field the proto does not have', 'workload.tsp',
    /JWTSVIDRequest\.audiences is no field of the vendored message.*JWTSVIDRequest\.audience \(field 1\) is not in the model/,
    inModel('JWTSVIDRequest', 'audience?:', 'audiences?:'));
  await refused('a field of another type', 'workload.tsp',
    /JWTSVIDRequest\.spiffe_id is .*int32.* and the vendored field is .*string/,
    inModel('JWTSVIDRequest', 'spiffe_id?: string', 'spiffe_id?: int32'));
  await refused('a field made required', 'workload.tsp',
    /JWTSVIDRequest\.spiffe_id is required, and proto3 has no required field/,
    inModel('JWTSVIDRequest', 'spiffe_id?:', 'spiffe_id:'));
  await refused('a field out of its oneof', 'google.tsp',
    /google\.protobuf\.Value\.numberValue is in the oneof none/,
    inModel('Value', '@field(2)\n    @oneof("kind")', '@field(2)'));
  await refused('a Struct value spelt in snake_case', 'google.tsp',
    /google\.protobuf\.Value\.string_value is no field.*stringValue \(field 3\) is not in the model/,
    inModel('Value', 'stringValue?:', 'string_value?:'));
  await refused('a method that does not stream as the proto does',
    'workload.tsp', /SpiffeWorkloadAPI\/FetchJWTSVID's stream is server and the vendored one is unary/,
    function (text) {
      return text.replace(
        '@rpc(#{ stream: "unary" })\n    FetchJWTSVID(',
        '@rpc(#{ stream: "server" })\n    FetchJWTSVID(');
    });
  await refused('a method left out', 'workload.tsp',
    /SpiffeWorkloadAPI\/FetchJWTBundles is not in the model/,
    function (text) {
      return text.replace(/\n {4}@rpc\(#\{ stream: "server" \}\)\n {4}FetchJWTBundles\(request: JWTBundlesRequest\): JWTBundlesResponse;/,
                          '');
    });
  await refused('a refusal code that is not a SPIFFE code', 'workload.tsp',
    /JWTSVIDRequest\.spiffe_id's refusal code STS-OAUTH-0028/,
    function (text) {
      return text.replace('code: "STS-SPIFFE-0028"', 'code: "STS-OAUTH-0028"');
    });
  await refused('a {reason} where no SPIFFE ID gives one', 'broker.tsp',
    /audience's refusal has a \{reason\}/,
    function (text) {
      return text.replace('message: "audience must be specified"',
                          'message: "audience must be specified: {reason}"');
    });
  await refused('a grammar pattern that does not compile', 'spiffe.tsp',
    /trustDomainPattern does not compile/,
    function (text) {
      return text.replace('trustDomainPattern: "^[a-z0-9.\\\\-_]+$"',
                          'trustDomainPattern: "^[a-z0-9.\\\\-_+$"');
    });
  log.debug("Leaving buildCheck().");
}

// The family's sources, the node-local workload agent excepted: it is a leaf
// process with its own grammar and words (spiffe/CLAUDE.md).
function sources() {
  log.debug("Entering sources().");
  const dir = path.join(ROOT, 'spiffe');
  const out = {};
  fs.readdirSync(dir).filter(function (name) {
    return /\.ts$/.test(name) && name !== 'workload_agent.ts' &&
      name !== 'spiffe_model.ts';
  }).forEach(function (name) {
    out[name] = fs.readFileSync(path.join(dir, name), 'utf8');
  });
  log.debug("Leaving sources().");
  return out;
}

// B. No hand check is left.
function handCheck(t) {
  log.debug("Entering handCheck().");
  const SpiffeModel = require('../spiffe/spiffe_model');
  const spiffeId = require('../spiffe/spiffe_id');
  const files = sources();
  const all = Object.keys(files).map(function (name) {
    return files[name];
  }).join('\n');
  const model = ModelTables.file('spiffe.json');
  const sentences = [];
  Object.keys(model.messages).forEach(function (name) {
    model.messages[name].fields.forEach(function (field) {
      (field.refusals || []).forEach(function (one) {
        sentences.push(one.message.split('{reason}')[0]);
      });
    });
  });
  const written = sentences.filter(function (one) {
    // A sentence as the source would hold it: its first words, opening a
    // string literal. One too short to tell from anything else is skipped.
    const head = one.slice(0, 20).replace(/'/g, '\\\'');
    return head.length >= 15 && all.indexOf('\'' + head) >= 0;
  });
  t.check(sentences.length >= 14 && written.length === 0,
          'B. no modelled refusal\'s sentence is written in spiffe/',
          written.join(' | '));
  t.check(!/MAX_ID_BYTES = 2048|MAX_TRUST_DOMAIN_BYTES = 255/.test(
            files['spiffe_id.ts']) &&
          files['spiffe_id.ts'].indexOf('[a-z0-9.\\-_]') < 0 &&
          files['spiffe_id.ts'].indexOf('\'/spire') < 0,
          'B. spiffe_id.ts holds no byte bound, character class or ' +
          'reserved prefix of its own');
  const leaf = files['spiffe_auth.ts'].slice(
    files['spiffe_auth.ts'].indexOf('  leafSvidProblem(entry) {'));
  t.check(leaf.slice(0, leaf.indexOf('\n  }\n')).indexOf('keyCertSign') < 0,
          'B. leafSvidProblem() names no key usage of its own');
  t.check(!/NOT_IMPLEMENTED = \{/.test(files['spiffe_api.ts']) &&
          files['spiffe_ca.ts'].indexOf('key.use !== \'wit-svid\'') < 0,
          'B. no unimplemented-reasons table and no key-use list in code');
  const calls = all.match(/refuseField\(call,\s*'[^']+',\s*'[^']+',\s*'[a-z]+'(?:,\s*(?:undefined|'[A-Za-z]+'))?/g) || [];
  const unknown = calls.filter(function (one) {
    const parts = one.match(/'([^']+)'/g).map(function (q) {
      return q.slice(1, -1);
    });
    try {
      SpiffeModel.refusal(parts[0], parts[1], parts[2], parts[3]);
      return false;
    } catch (e) {
      log.debug("Caught in handCheck(): " + ((e && e.message) || e));
      return true;
    }
  });
  t.check(calls.length >= 12 && unknown.length === 0,
          'B. every refuseField() names a refusal the model declares (' +
          calls.length + ')', unknown.join(' | '));
  const g = SpiffeModel.grammar();
  t.check(spiffeId.MAX_ID_BYTES === g.maxBytes &&
          spiffeId.MAX_TRUST_DOMAIN_BYTES === g.maxTrustDomainBytes &&
          spiffeId.RESERVED_PREFIX === g.reservedPrefix &&
          spiffeId.PREFIX === g.scheme + '://',
          'B. spiffe_id.ts\'s exported bounds are the model\'s');
  const cases = [['spiffe://example.org/a/b-c_d.e', true],
                 ['spiffe://Example.org/a', false],
                 ['spiffe://example.org/a$b', false],
                 ['spiffe://' + 'a'.repeat(g.maxTrustDomainBytes) + '/x',
                  true],
                 ['spiffe://' + 'a'.repeat(g.maxTrustDomainBytes + 1) + '/x',
                  false]];
  cases.forEach(function (one) {
    t.equal(spiffeId.parse(one[0]).ok, one[1],
            'B. the grammar ' + (one[1] ? 'accepts ' : 'refuses ') +
            one[0].slice(0, 40));
  });
  t.check(spiffeId.isReservedPath('spiffe://example.org' +
                                  g.reservedPrefix + '/agent/x/y') &&
          spiffeId.serverId('example.org') ===
            'spiffe://example.org' + g.reservedPrefix + '/server',
          'B. the reserved prefix is the model\'s at every reader');
  log.debug("Leaving handCheck().");
}

// The members of one recorded message that are no field of its message.
function strays(model, name, value, where, out) {
  log.debug("Entering strays().");
  const declared = model.messages[name];
  if (!declared || !value || typeof value !== 'object' ||
      Array.isArray(value)) {
    log.debug("Leaving strays().");
    return;
  }
  Object.keys(value).forEach(function (key) {
    const field = declared.fields.find(function (f) {
      return f.name === key;
    });
    if (!field) {
      out.push(where + '.' + key);
      return;
    }
    if (field.type.kind !== 'message') {
      return;
    }
    const one = value[key];
    const items = field.repeated ? (Array.isArray(one) ? one : [])
      : (field.map ? Object.keys(one || {}).map(function (k) {
        return one[k];
      }) : [one]);
    items.forEach(function (item, i) {
      strays(model, field.type.name, item, where + '.' + key + '[' + i + ']',
             out);
    });
  });
  log.debug("Leaving strays().");
}

// C. Every recorded answer is its model's.
function recordedCheck(t) {
  log.debug("Entering recordedCheck().");
  const SpiffeModel = require('../spiffe/spiffe_model');
  const model = ModelTables.file('spiffe.json');
  const recorded = JSON.parse(fs.readFileSync(path.join(__dirname,
    'spiffe_model_wire.snapshot.json'), 'utf8'));
  const SURFACE = { workload: 'workload', broker: 'broker' };
  const LABEL = { entry: 'Entry', agent: 'Agent', bundle: 'Bundle',
                  svid: 'SVID', trustdomain: 'TrustDomain', debug: 'Debug' };
  const out = [];
  const statuses = [];
  let grpcSteps = 0;
  recorded.wire.forEach(function (step) {
    if (step.service === 'http') {
      return;
    }
    grpcSteps++;
    const surface = SURFACE[step.service] || 'server';
    const name = surface === 'server'
      ? LABEL[step.service] + '.' + step.method : step.method;
    const one = SpiffeModel.methodOf(surface, name);
    if (!one) {
      out.push(surface + ' ' + name + ' is not in the model');
      return;
    }
    (step.messages || []).forEach(function (message) {
      strays(model, one.method.response, message, step.mode + ' ' + name,
             out);
    });
    const named = Object.keys(model.statuses).find(function (key) {
      return model.statuses[key] === step.code;
    });
    const allowed = ['OK'].concat(one.service.statuses, one.method.statuses);
    if (allowed.indexOf(named) < 0) {
      statuses.push(step.mode + ' ' + name + ' ' + named);
    }
  });
  t.check(grpcSteps > 100 && out.length === 0,
          'C. every member of every recorded message is a field of its ' +
          'message (' + grpcSteps + ' calls)', out.join(' | '));
  t.check(statuses.length === 0,
          'C. every recorded status is one its service or method declares',
          statuses.join(' | '));
  const bundles = recorded.wire.filter(function (step) {
    return step.service === 'http';
  });
  t.check(bundles.length === 2 && bundles.every(function (step) {
    const doc = JSON.parse(JSON.stringify(step.body));
    // The recorded x5c is described rather than copied; the model's type is
    // a list of strings, which the description stands in for.
    (doc.keys || []).forEach(function (key) {
      if (key.x5c) {
        key.x5c = key.x5c.map(function () {
          return 'MII';
        });
      }
    });
    doc.spiffe_sequence = 1;
    return SpiffeModel.members('bundle', doc).length === 0;
  }), 'C. the recorded bundle documents are the model\'s bundle');
  log.debug("Leaving recordedCheck().");
}

// D. The holding.
function holdingCheck(t) {
  log.debug("Entering holdingCheck().");
  const SpiffeModel = require('../spiffe/spiffe_model');
  t.equal(SpiffeModel.holdReply('workload', 'FetchJWTSVID',
    { svids: [{ spiffe_id: 'spiffe://a.test/x', svid: 'a.b.c',
                hint: '' }] }).length, 0,
          'D. a JWTSVIDResponse of the model\'s is held clean');
  t.check(/svids\[0\]\.spifeId is no field/.test(SpiffeModel.holdReply(
    'workload', 'FetchJWTSVID',
    { svids: [{ spifeId: 'spiffe://a.test/x' }] }).join(' ')),
          'D. a misspelt member is a gap: it would serialise to nothing');
  t.check(SpiffeModel.holdReply('server', 'Entry.CountEntries',
    { count: 'many' }).length === 1,
          'D. a value of the wrong type is a gap');
  t.check(/claims\.fields\[sub\]\.string_value is no field/.test(
    SpiffeModel.holdReply('workload', 'ValidateJWTSVID',
      { spiffe_id: 'spiffe://a.test/x',
        claims: { fields: { sub: { string_value: 'x' } } } }).join(' ')),
          'D. a Struct value spelt in snake_case is a gap — protobufjs ' +
          'would send empty claims');
  t.equal(SpiffeModel.holdReply('workload', 'ValidateJWTSVID',
    { spiffe_id: 'spiffe://a.test/x',
      claims: { fields: { sub: { stringValue: 'x' } } } }).length, 0,
          'D. and the camelCase one is clean');
  t.check(SpiffeModel.holdStatus('server', 'Debug.GetInfo', 5) &&
          !SpiffeModel.holdStatus('server', 'Entry.GetEntry', 5) &&
          !SpiffeModel.holdStatus('server', 'Debug.GetInfo', 16),
          'D. a status neither the service nor the method declares is a ' +
          'gap; the method\'s and the surface\'s are not');
  t.check(/use is not one of x509-svid, jwt-svid, wit-svid/.test(
    SpiffeModel.members('bundle', { keys: [{ kty: 'EC', use: 'sig' }] })
      .join(' ')),
          'D. a bundle key of a use the registry does not name is a gap');
  t.check(SpiffeModel.gaps().length >= 4,
          'D. each gap is remembered for the wire test to read');
  log.debug("Leaving holdingCheck().");
}

async function run(t) {
  log.debug("Entering run().");
  await buildCheck(t);
  handCheck(t);
  recordedCheck(t);
  holdingCheck(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'model_spiffe',
  describe: 'the SPIFFE model (#1579): it is the vendored protos field for ' +
            'field and the build refuses a difference; the grammar, the ' +
            'leaf rules, the key uses, the unimplemented reasons and every ' +
            'request refusal come from it and nowhere else; every recorded ' +
            'answer and status is its model\'s; and the holding records a ' +
            'stray member, a wrong type, a snake_case Struct value and an ' +
            'undeclared status',
  run: run
};
