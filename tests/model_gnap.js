// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_gnap.js
//
// ---------------------------------------------------------------------------
// THE GNAP MODEL, AND WHAT HOLDS THE SERVICE TO IT (#1579).
//
// `models/gnap/gnap.tsp` states every document a GNAP client instance or
// resource server sends, the paths' parameters, the registries the request
// walk reads, the members of every answer, the access-type catalogue's
// definition and the error codes. This holds four things:
//
//   A. the build's refusals: the model as written renders cleanly and to
//      what `models/generated/gnap.json` holds, and a copy with one thing
//      broken — a string with no bound, an array with no item cap, a pattern
//      that does not compile, a shape stated on a member whose type is a
//      shared one, a registry that is not strings — is refused when it is
//      rendered (the TypeSpec compiler, as the image build runs it); a
//      duplicate, a missing citation or a misspelt code in the generated
//      table is refused by `checkGnap()`;
//   B. no hand schema is left in the family: `gnap/` writes no JSON Schema,
//      no zod object and no registry of its own, the schemas compile and
//      refuse and accept what the model says, the paths' validators are
//      generated, and the access-type catalogue refuses a member the model
//      does not name, listing the model's;
//   C. what the endpoints answered — every recorded answer of
//      `tests/gnap_model_wire.snapshot.json`, in both modes — is its
//      model's, and every error code it carries is declared;
//   D. the holding: an answer with a stray member, a wrong type, a missing
//      member or a stray member nested in an object the model names is a
//      gap, and an undeclared error code is one.
//
// That the generated schemas answer on the wire exactly as the hand-written
// ones did, and that the live answers record no gap, is
// `tests/gnap_model_wire.js`'s.
// ---------------------------------------------------------------------------

const fs = require('fs');
const os = require('os');
const path = require('path');
const url = require('url');

const log = require('bunyan').createLogger({
  name: 'model_gnap',
  level: process.env.LOG_LEVEL || 'info'
});

const ROOT = path.join(__dirname, '..');
const ModelTables = require('../common/model_tables');

async function toolchain() {
  log.debug("Entering toolchain().");
  const compiler = await import(url.pathToFileURL(path.join(__dirname,
    'node_modules', '@typespec', 'compiler', 'dist', 'src', 'index.js')).href);
  const lib = await import(url.pathToFileURL(path.join(ROOT, 'models', 'lib',
    'gnap_lib.mjs')).href);
  log.debug("Leaving toolchain().");
  return { compiler: compiler, lib: lib };
}

// The GNAP model compiled from a copy of `models/` with `edit` applied to
// gnap.tsp's text, read as the build reads it.
async function rendered(tools, edit) {
  log.debug("Entering rendered().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'model-gnap-'));
  try {
    fs.cpSync(path.join(ROOT, 'models'), dir, { recursive: true });
    fs.symlinkSync(path.join(ROOT, 'node_modules'),
                   path.join(dir, 'node_modules'));
    fs.writeFileSync(path.join(dir, 'gnap-only.tsp'),
                     'import "./gnap/gnap.tsp";\n');
    const file = path.join(dir, 'gnap', 'gnap.tsp');
    const text = fs.readFileSync(file, 'utf8');
    const edited = edit ? edit(text) : text;
    fs.writeFileSync(file, edited);
    const program = await tools.compiler.compile(tools.compiler.NodeHost,
      path.join(dir, 'gnap-only.tsp'), { noEmit: true });
    const errors = program.diagnostics.filter(function (one) {
      return one.severity === 'error';
    }).map(function (one) {
      return one.code + ': ' + one.message;
    });
    const gnap = tools.lib.readGnap(program);
    log.debug("Leaving rendered().");
    return { errors: errors, gnap: gnap,
             problems: tools.lib.checkGnap(gnap), changed: edited !== text };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// A. The build's refusals.
async function buildCheck(t) {
  log.debug("Entering buildCheck().");
  const tools = await toolchain();
  const clean = await rendered(tools, null);
  t.check(clean.errors.length === 0 && clean.problems.length === 0,
          'A. the GNAP model compiles and renders cleanly',
          clean.errors.concat(clean.problems).join('; '));
  const generated = ModelTables.file('gnap.json');
  const fresh = JSON.parse(JSON.stringify(clean.gnap));
  delete fresh.problems;
  t.check(JSON.stringify(fresh) === JSON.stringify(generated),
          'A. models/generated/gnap.json is what the model renders');
  const refused = async function (what, pattern, edit) {
    const out = await rendered(tools, edit);
    const said = out.errors.concat(out.problems).join('; ');
    t.check(out.changed && pattern.test(said), 'A. refused: ' + what,
            said || '(nothing)');
  };
  await refused('a string with no bound', /label is a string with no bound/,
    function (text) {
      return text.replace('@shape(#{ cap: "NAME" }) label?: string;',
                          'label?: string;');
    });
  await refused('a bound stated twice', /states its bound twice/,
    function (text) {
      return text.replace('@shape(#{ cap: "NAME" }) label?: string;',
        '@shape(#{ cap: "NAME", maxLength: 9 }) label?: string;');
    });
  await refused('an array with no item cap', /start is an array with no maxItems/,
    function (text) {
      return text.replace('@shape(#{ maxItems: 16 }) start?: StartMode[];',
                          'start?: StartMode[];');
    });
  await refused('a pattern that does not compile', /pattern does not compile/,
    function (text) {
      return text.replace('pattern: "^[A-Za-z0-9._~-]*$"',
                          'pattern: "^[A-Za-z0-9._~-*$"');
    });
  await refused('a shape on a member whose type is a shared one',
    /states maxLength on the shared type uri/, function (text) {
      return text.replace('  uri?: GnapUri;\n  @shape(#{ maxLength: 256 })',
        '  @shape(#{ maxLength: 9 }) uri?: GnapUri;\n' +
        '  @shape(#{ maxLength: 256 })');
    });
  await refused('a registry that is not strings', /registry finish-methods is not a union of strings/,
    function (text) {
      return text.replace('  push: "push",\n}', '  push: 7,\n}');
    });
  await refused('a decorator option the library does not declare',
    /invalid-argument|unassignable|not assignable/, function (text) {
      return text.replace('@shape(#{ maxItems: 16 }) start?',
                          '@shape(#{ maxItems: 16, minItems: 1 }) start?');
    });
  const copy = function () {
    return JSON.parse(JSON.stringify(generated));
  };
  const checked = function (what, pattern, change) {
    const broken = copy();
    broken.problems = [];
    change(broken);
    const said = tools.lib.checkGnap(broken).join('; ');
    t.check(pattern.test(said), 'A. refused: ' + what, said || '(nothing)');
  };
  checked('a member set declared twice', /grant-response is declared twice/,
    function (o) {
      o.members.push(JSON.parse(JSON.stringify(o.members.filter(
        function (one) {
          return one.id === 'grant-response';
        })[0])));
    });
  checked('a member citing nothing', /discovery\.grant_request_endpoint cites nothing/,
    function (o) {
      o.members.filter(function (one) {
        return one.id === 'discovery';
      })[0].list[0].cite = '';
    });
  checked('an error code declared twice', /too_fast is declared twice/,
    function (o) {
      o.errors.push({ code: 'too_fast', cite: 'x' });
    });
  checked('an error code not spelt as RFC 9635 spells them',
    /Bad-Code is not a lower-case word/, function (o) {
      o.errors.push({ code: 'Bad-Code', cite: 'x' });
    });
  checked('a parameter checked as neither a type nor values',
    /api-approve\.action must be checked as one shared type/, function (o) {
      o.params.filter(function (one) {
        return one.id === 'api-approve';
      })[0].params[0].kind = 'token';
    });
  checked('a path parameter required and empty',
    /continue\.grant is required and may be empty/, function (o) {
      o.params.filter(function (one) {
        return one.id === 'continue';
      })[0].params[0].empty = true;
    });
  log.debug("Leaving buildCheck().");
}

// B. No hand schema is left in the family, and the generated ones say what
// the model says.
function noHandSchema(t) {
  log.debug("Entering noHandSchema().");
  const files = fs.readdirSync(path.join(ROOT, 'gnap')).filter(
    function (name) {
      return /\.ts$/.test(name) && !/^web_/.test(name) &&
        name !== 'gnap_model.ts';
    });
  files.forEach(function (name) {
    const text = fs.readFileSync(path.join(ROOT, 'gnap', name), 'utf8')
      .replace(/^\s*\/\/.*$/gm, '');
    t.check(!/additionalProperties\s*:|\$defs\s*:|maxProperties\s*:/.test(text),
            'B. gnap/' + name + ' writes no JSON Schema of its own');
    t.check(!/\bvz\.object\(|validation\.z\.object\(/.test(text),
            'B. gnap/' + name + ' writes no zod object of its own');
  });
  const registries = { 'gnap_request.ts': [
    /\['redirect', 'app', 'user_code', 'user_code_uri'\]/,
    /\['redirect', 'push'\]/, /\['bearer'\]/, /\['durable'\]/,
    /iss_sub: \['iss', 'sub'\]/],
                       'gnap_keys.ts': [/\['httpsig', 'mtls', 'jwsd', 'jws'\]/,
                                        /\['jwk', 'cert', 'cert#S256'\]/] };
  Object.keys(registries).forEach(function (name) {
    const text = fs.readFileSync(path.join(ROOT, 'gnap', name), 'utf8');
    registries[name].forEach(function (pattern) {
      t.check(!pattern.test(text), 'B. gnap/' + name + ' lists no registry ' +
              'of its own: ' + pattern.source);
    });
  });
  const GnapModel = require('../gnap/gnap_model');
  const schemas = require('../gnap/gnap_schemas');
  t.check(JSON.stringify(Object.keys(schemas.SCHEMAS)) ===
          JSON.stringify(['grantRequest', 'continuation', 'modification',
                          'rotation', 'introspection', 'registration']),
          'B. the six documents are the model\'s');
  t.check(JSON.stringify(schemas.SCHEMAS) === JSON.stringify(
            GnapModel.schemas()) &&
          JSON.stringify(schemas.SCHEMAS).indexOf('$cap:') < 0,
          'B. gnap_schemas.ts compiles the model\'s schemas, every cap ' +
          'resolved');
  const grant = function (body) {
    return schemas.validate('grantRequest', body);
  };
  t.check(grant({ client: 'c1', access_token: { access: ['a'] } }).ok,
          'B. a well-formed grant request passes');
  t.check(/control character/.test(String(grant({ client: { display: {
    name: 'a\u0001' } } }).detail)),
          'B. a control character anywhere is refused by name');
  t.check(/additional properties/.test(String(grant({ interact: { finish: {
    method: 'redirect', extra: 1 } } }).detail)),
          'B. the finish object is closed');
  t.check(grant({ interact: { hints: { vendor_x: 1 } } }).ok,
          'B. the hints object is open (an extension registry)');
  t.check(/must NOT have more than 256 characters/.test(String(grant({
    access_token: { label: 'x'.repeat(257) } }).detail)),
          'B. a label is bounded by the NAME cap');
  t.check(/must be boolean/.test(String(schemas.validate('registration', {
    token_introspection_required: 'yes' }).detail)),
          'B. registration: token_introspection_required is a boolean');
  const validation = require('../common/validation');
  t.check(!validation.checkParsed({ grant: 'a b' }, 'params',
                                  GnapModel.params('continue')).ok &&
          validation.checkParsed({ grant: 'abc_-1' }, 'params',
                                 GnapModel.params('continue')).ok,
          'B. the continuation path\'s grant is a base64url value');
  t.check(validation.checkParsed({ as: '' }, 'params',
                                 GnapModel.params('as')).ok,
          'B. an empty authorization server name is no name');
  const act = function (body) {
    return validation.checkParsed(body, 'body',
                                  GnapModel.params('api-approve'));
  };
  t.check(act({ action: 'allow', right: 't0r0' }).ok &&
          Array.isArray(act({ action: 'allow', right: 't0r0' }).value.right),
          'B. /gnap-api/approve: one ticked right is a list of one');
  t.check(!act({ action: 'maybe' }).ok && !act({ action: 'deny', x: 1 }).ok,
          'B. /gnap-api/approve: action is allow or deny, and the body is ' +
          'closed');
  t.check(act({ action: 'deny', subject: '' }).ok,
          'B. /gnap-api/approve: an empty subject is no value');
  const applications = require('../common/applications');
  const stray = applications.authorizationDetailsTypeOf(JSON.stringify({
    type: 'm-type', owner: 'x' }));
  const names = GnapModel.members('access-type-definition').list
    .map(function (one) {
      return one.name;
    });
  t.check(stray.problem.indexOf('a definition holds only ' +
                                names.join(', ')) >= 0,
          'B. the catalogue refuses a member the model does not name, ' +
          'listing the model\'s', stray.problem);
  const interaction = applications.authorizationDetailsTypeOf(JSON.stringify({
    type: 'm-type', interaction: 'sometimes' }));
  t.check(/interaction must be one of always, default, never/
    .test(interaction.problem),
          'B. the catalogue\'s interaction values are the model\'s',
          interaction.problem);
  log.debug("Leaving noHandSchema().");
}

// The members a placeholder may stand in for, by the type it replaced.
const NUMERIC = ['expires_in', 'wait', 'exp', 'iat', 'nbf', 'ttl'];
const LISTS = ['revocation_ids', 'root_public_keys', 'verificationMethod',
  'assertionMethod', 'capabilityDelegation', 'capabilityInvocation', 'x5c'];

// A recorded value with each placeholder put back as a value of the type it
// replaced, so a type check reads it as the endpoint wrote it.
function restored(value, name) {
  log.debug("Entering restored().");
  let out = value;
  if (Array.isArray(value)) {
    out = value.map(function (one) {
      return restored(one, name);
    });
  } else if (value && typeof value === 'object') {
    out = {};
    Object.keys(value).forEach(function (key) {
      out[key] = restored(value[key], key);
    });
  } else if (typeof value === 'string' && /^<[a-z_]+>$/i.test(value)) {
    if (NUMERIC.indexOf(name) >= 0 || value === '<epoch>') {
      out = 1800000000;
    } else if (LISTS.indexOf(name) >= 0) {
      out = [];
    }
  }
  log.debug("Leaving restored().");
  return out;
}

// The member set a recorded step's answer is held to.
function setOf(step) {
  log.debug("Entering setOf().");
  const body = step.body;
  let id = null;
  if (body && typeof body === 'object' && body.error) {
    id = 'error-response';
  } else if (/^gnap-api/.test(step.step)) {
    id = body && body.api !== undefined ? 'gnap-api-index'
      : 'gnap-api-answer';
  } else if (step.status === 200) {
    id = { 'discovery': 'discovery',
           'discovery, a named server': 'discovery',
           'rs discovery': 'rs-discovery',
           'rs discovery, a named server': 'rs-discovery',
           'keys': 'keys', 'zcap controller': 'zcap-controller',
           'biscuit revocations': 'biscuit-revocations' }[step.step] ||
      (/^(grant|continue|manage)/.test(step.step) ? 'grant-response'
        : /^introspect/.test(step.step) ? 'introspection-response'
          : /^register/.test(step.step) ? 'registration-response' : null);
  }
  log.debug("Leaving setOf().");
  return id;
}

// C. What the endpoints answered is the model's.
function answered(t) {
  log.debug("Entering answered().");
  const GnapModel = require('../gnap/gnap_model');
  const wire = JSON.parse(fs.readFileSync(path.join(__dirname,
    'gnap_model_wire.snapshot.json'), 'utf8')).wire;
  const problems = [];
  const codes = new Set();
  let held = 0;
  wire.forEach(function (step) {
    if (!step.body || typeof step.body !== 'object') {
      return;
    }
    const id = setOf(step);
    if (!id) {
      problems.push(step.mode + ', ' + step.step + ': no member set');
      return;
    }
    held++;
    GnapModel.undeclared(id, restored(step.body, null)).forEach(
      function (one) {
        problems.push(step.mode + ', ' + step.step + ': ' + one);
      });
    if (step.body.error && step.body.error.code) {
      codes.add(step.body.error.code);
    }
  });
  t.check(held >= 80 && problems.length === 0,
          'C. every recorded JSON answer (' + held + ') is its model\'s',
          problems.slice(0, 20).join('\n'));
  const declared = new Set(GnapModel.errors().map(function (one) {
    return one.code;
  }));
  const strays = Array.from(codes).filter(function (one) {
    return !declared.has(one);
  });
  t.check(codes.size >= 6 && strays.length === 0,
          'C. every error code recorded (' + Array.from(codes).join(', ') +
          ') is declared', strays.join(', '));
  const sent = new Set();
  fs.readdirSync(path.join(ROOT, 'gnap')).filter(function (name) {
    return /\.ts$/.test(name) && !/^web_|^token_|gnap_spend/.test(name);
  }).forEach(function (name) {
    const text = fs.readFileSync(path.join(ROOT, 'gnap', name), 'utf8');
    const found = text.match(/gnapError: '[a-z_]+'|refusal\([^;]*?'([a-z]+_[a-z_]+)'\)/g) || [];
    found.forEach(function (one) {
      const code = (one.match(/'([a-z_]+)'\)?$/) || [])[1];
      if (code) {
        sent.add(code);
      }
    });
  });
  const undeclared = Array.from(sent).filter(function (one) {
    return !declared.has(one) && one !== 'invalid_token' &&
      one !== 'insufficient_scope';
  });
  t.check(sent.size >= 8 && undeclared.length === 0,
          'C. every error code an engine module names (' + sent.size +
          ') is declared — but invalid_token and insufficient_scope, a ' +
          'resource server\'s RFC 6750 answers, which no AS endpoint sends',
          undeclared.join(', '));
  log.debug("Leaving answered().");
}

// D. The holding finds what it is there to find.
function holding(t) {
  log.debug("Entering holding().");
  const GnapModel = require('../gnap/gnap_model');
  const ok = { continue: { uri: 'https://as/c', wait: 5,
                           access_token: { value: 'v' } },
               instance_id: 'i' };
  t.check(GnapModel.undeclared('grant-response', ok).length === 0,
          'D. a pending grant response is the model\'s');
  t.check(/grant-response\.extra is not a member/.test(GnapModel.undeclared(
    'grant-response', Object.assign({ extra: 1 }, ok)).join()),
          'D. a stray member is a gap');
  t.check(/continue\.wait is not integer/.test(GnapModel.undeclared(
    'grant-response', { continue: { uri: 'u', wait: '5',
                                    access_token: { value: 'v' } } }).join()),
          'D. a member of the wrong type is a gap, nested');
  t.check(/access_token\[1\]\.value is required/.test(GnapModel.undeclared(
    'grant-response', { access_token: [{ value: 'a', access: [] },
                                       { access: [] }] }).join()),
          'D. an item of a list of tokens is held to its set');
  t.check(/continue\.access_token\.other is not a member of bound-token/
    .test(GnapModel.undeclared('grant-response', { continue: { uri: 'u',
      access_token: { value: 'v', other: 1 } } }).join()),
          'D. two levels down is held too');
  t.check(GnapModel.undeclared('introspection-response', { active: true,
    email: 'x@example.com' }).length === 0,
          'D. introspection is open: a declared claim may be added');
  t.check(/next is not one of/.test(GnapModel.undeclared('gnap-api-answer',
    { ok: true, next: 'elsewhere' }).join()),
          'D. a value outside the model\'s list is a gap');
  // A view drawn for a signed-in person carries their own language as
  // `authn.preferredLanguageOf()` answers it, `{ value, populated }` — the
  // shape `/authn-api` models. Declared a string until 2026-11-12, so every
  // such view was recorded under STS-GNAP-0910.
  t.check(GnapModel.undeclared('gnap-api-answer',
    { ok: true, view: { kind: 'code' }, csrf: 'c',
      preferredLanguage: { value: 'fr-CA', populated: false } })
    .length === 0,
          'D. a view carrying the person\'s own language is the model\'s');
  t.check(/preferredLanguage\.other is not a member of gnap-api-language/
    .test(GnapModel.undeclared('gnap-api-answer', { ok: true,
      preferredLanguage: { value: 'fr', other: 1 } }).join()) &&
          /preferredLanguage is not object/.test(GnapModel.undeclared(
            'gnap-api-answer', { ok: true, preferredLanguage: 'fr' }).join()),
          'D. the language is held to its own closed set');
  const before = GnapModel.gaps().length;
  t.check(GnapModel.holdError('made_up_code', 'model_gnap') === true &&
          GnapModel.holdError('too_fast', 'model_gnap') === false &&
          GnapModel.gaps().length === before + 1,
          'D. an undeclared error code is recorded, a declared one is not');
  log.debug("Leaving holding().");
}

async function run(t) {
  log.debug("Entering run().");
  await buildCheck(t);
  noHandSchema(t);
  answered(t);
  holding(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'model_gnap',
  describe: 'the GNAP model (#1579): the build\'s refusals, the schemas, ' +
            'path validators and registries generated from it with no hand ' +
            'copy left in gnap/, every recorded answer and error code held ' +
            'to it, and the holding itself',
  run: run
};
