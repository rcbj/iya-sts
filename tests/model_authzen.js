// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_authzen.js
//
// ---------------------------------------------------------------------------
// THE AUTHZEN MODEL, AND WHAT HOLDS THE SERVICE TO IT (#1579).
//
// `models/authzen/authzen.tsp` states every request the AuthZEN
// Authorization API reads and `authzen_members.tsp` every answer's members,
// the Obligations Profile's registered types and the Access Request
// profile's problem types. This holds three things:
//
//   A. the build's check (`models/lib/authzen_lib.mjs`'s checkAuthzen())
//      passes the generated table and refuses each kind of wrong model,
//      asserted on a copy with one thing broken;
//   B. every reader is the model's: `authzen/` writes no shape check, no
//      member list and no refusal sentence of its own, the lists the code
//      branches on are the model's, and each reader refuses and accepts what
//      the model says;
//   C. every answer `tests/authzen_model_wire.snapshot.json` recorded — the
//      metadata, the evaluation and batch answers, the searches, the errors,
//      the problems, the tasks and the callback — is the model's.
//
// That the generated readers answer on the wire exactly as the hand-written
// ones did is `tests/authzen_model_wire.js`'s.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const url = require('url');

const log = require('bunyan').createLogger({
  name: 'model_authzen',
  level: process.env.LOG_LEVEL || 'info'
});

const ROOT = path.join(__dirname, '..');
const ModelTables = require('../common/model_tables');

// A copy of the generated table, for one thing to be broken in.
function copy() {
  log.debug("Entering copy().");
  log.debug("Leaving copy().");
  return JSON.parse(JSON.stringify(ModelTables.file('authzen.json')));
}

// One field of a request of a copy, by its dotted path.
function field(authzen, id, dotted) {
  log.debug("Entering field().");
  let fields = authzen.requests.filter(function (one) {
    return one.id === id;
  })[0].fields;
  let found = null;
  dotted.split('.').forEach(function (name) {
    found = fields.filter(function (one) {
      return one.name === name;
    })[0];
    fields = found ? found.fields : [];
  });
  log.debug("Leaving field().");
  return found;
}

// A. The build's refusals.
async function buildCheck(t) {
  log.debug("Entering buildCheck().");
  const lib = await import(url.pathToFileURL(path.join(ROOT, 'models', 'lib',
    'authzen_lib.mjs')).href);
  const generated = ModelTables.file('authzen.json');
  t.check(lib.checkAuthzen(generated).length === 0,
          'A. the generated AuthZEN model is clean',
          lib.checkAuthzen(generated).join('; '));
  const refused = function (what, pattern, change) {
    const broken = copy();
    change(broken);
    const said = lib.checkAuthzen(broken).join('; ');
    t.check(pattern.test(said), 'A. refused: ' + what, said || '(nothing)');
  };
  refused('an option on a kind it does not apply to',
    /evaluation\.subject\.type is string and takes maxItems/, function (a) {
      field(a, 'evaluation', 'subject.type').maxItems = 3;
    });
  refused('a sentence naming a placeholder nobody fills',
    /refusal names \{nobody\}/, function (a) {
      field(a, 'evaluation', 'context.application').refusal = '{nobody}';
    });
  refused('a request sentence naming a placeholder nobody fills',
    /stray sentence names \{nobody\}/, function (a) {
      a.requests[0].stray = 'it takes {nobody}';
    });
  refused('a default that is not one of the values',
    /default is not one of its values/, function (a) {
      field(a, 'evaluations', 'options.evaluations_semantic').default = 'x';
    });
  refused('a forbidden member with nothing to say',
    /search-action\.action may not be sent and says nothing/, function (a) {
      delete field(a, 'search-action', 'action').refusal;
    });
  refused('requireOne naming a member not declared',
    /requires one of nobody/, function (a) {
      field(a, 'access-request', 'denial').requireOne.push('nobody');
    });
  refused('a field citing nothing', /evaluation\.action\.name cites nothing/,
    function (a) {
      field(a, 'evaluation', 'action.name').cite = '';
    });
  refused('a request without a code of each kind',
    /the request evaluation has no stray code/, function (a) {
      a.requests[0].codes.stray = 'oops';
    });
  refused('a request declared twice', /request evaluation is declared twice/,
    function (a) {
      a.requests.push(JSON.parse(JSON.stringify(a.requests[0])));
    });
  refused('a member set declared twice', /metadata is declared twice/,
    function (a) {
      a.members.push(JSON.parse(JSON.stringify(a.members[0])));
    });
  refused('a problem type with no title', /unknown_task has no title/,
    function (a) {
      a.problems.types.filter(function (one) {
        return one.type === 'unknown_task';
      })[0].title = '';
    });
  log.debug("Leaving buildCheck().");
}

// B. The readers are the model's.
function readers(t) {
  log.debug("Entering readers().");
  // What the hand-written readers held, which may no longer be written in
  // `authzen/`: their member lists, the lists the code branches on, and the
  // sentences of a shape refusal.
  const HAND = [
    [/BATCH_MEMBERS|SUBMISSION_MEMBERS/, 'a list of the members a request ' +
     'takes'],
    [/\bconst MEMBERS\b/, 'the entities\' member lists'],
    [/\[\s*'execute_all',\s*'deny_on_first_deny'/, 'the batch semantics'],
    [/'step-up':\s*\{/, 'the obligation types'],
    [/not_requestable:\s*'/, 'the problem types\' titles'],
    [/'pending',\s*'approved'/, 'the task statuses'],
    [/freeze\(\[\s*'application',\s*'supported_obligations'/,
     'the reserved context'],
    [/must be a JSON object|is required, and a non-empty string|has no member "/,
     'a shape refusal\'s sentence'],
    [/page is an object with token/, 'the page refusal']
  ];
  fs.readdirSync(path.join(ROOT, 'authzen')).filter(function (name) {
    return /\.ts$/.test(name) && name !== 'authzen_model.ts';
  }).forEach(function (name) {
    const text = fs.readFileSync(path.join(ROOT, 'authzen', name), 'utf8')
      .replace(/^\s*\/\/.*$/gm, '');
    HAND.forEach(function (pair) {
      t.check(!pair[0].test(text), 'B. authzen/' + name + ' writes no ' +
              pair[1] + ' of its own');
    });
  });
  const AuthzenModel = require('../authzen/authzen_model');
  const catalogue = require('../authzen/authzen_catalogue');
  const map = require('../authzen/authzen_map');
  const authzen = require('../authzen/authzen');
  t.check(catalogue.RESERVED_CONTEXT.join() ===
            AuthzenModel.reservedContext().join() &&
          AuthzenModel.reservedContext().join() ===
            'supported_obligations,approval,application',
          'B. the reserved context members are the evaluation\'s context ' +
          'fields', catalogue.RESERVED_CONTEXT.join());
  t.check(map.supportedObligationTypes().join() ===
            'step-up,notification,session_termination,custom',
          'B. the obligation types are the model\'s obligation member sets',
          map.supportedObligationTypes().join());
  t.check(authzen.SEMANTICS.join() ===
            'execute_all,deny_on_first_deny,permit_on_first_permit',
          'B. the batch semantics are the model\'s values',
          authzen.SEMANTICS.join());
  t.check(AuthzenModel.problemType('unknown_task').uri ===
            'urn:openid:authzen:access-request:error:unknown_task',
          'B. a problem type\'s URI is the model\'s prefix and name');
  const read = function (id, body) {
    return AuthzenModel.read(id, body);
  };
  const good = { subject: { type: 'user', id: 'a' }, action: { name: 'r' },
                 resource: { type: 'd', id: 'x' } };
  t.check(read('evaluation', good) === null,
          'B. evaluation: a well-formed request is read');
  const said = function (id, body) {
    const r = read(id, body);
    return r ? r.code + ' ' + r.message : '';
  };
  t.check(said('evaluation', Object.assign({}, good, { x: 1 })) ===
            'STS-AUTHZEN-0009 An access evaluation request has no member ' +
            '"x"; it takes subject, action, resource and context.',
          'B. evaluation: a stray member, its sentence the model\'s');
  t.check(said('evaluation', { action: good.action,
                               resource: good.resource }) ===
            'STS-AUTHZEN-0002 The request has no subject, which AuthZEN ' +
            'requires (subject.type and subject.id).',
          'B. evaluation: an absent entity names its required members');
  t.check(said('evaluation', Object.assign({}, good, {
    subject: { type: 'u', id: 'i'.repeat(1025) } })) ===
            'STS-AUTHZEN-0003 subject.id must be a string of at most 1024 ' +
            'characters.',
          'B. evaluation: a string over its bound');
  t.check(said('evaluation', Object.assign({}, good, {
    context: { approval: { id: '' } } })) ===
            'STS-AUTHZEN-0003 context.approval must be the approval object ' +
            'a completed access request returned, with its id.',
          'B. evaluation: a field\'s refusal covers what it holds, at the ' +
          'type\'s code');
  t.check(said('evaluations', { options: { evaluations_semantic: 'x' } })
            .indexOf('STS-AUTHZEN-0036 options.evaluations_semantic must be ' +
                     'one of execute_all') === 0,
          'B. evaluations: an unknown semantic');
  t.check(read('evaluations', { options: { evaluations_semantic:
                                           ['execute_all'] } }) === null,
          'B. evaluations: the semantic is compared as String(value)');
  t.check(said('search-action', { page: 'x', action: {} })
            .indexOf('STS-AUTHZEN-0042') === 0,
          'B. search-action: page is read before the forbidden action');
  t.check(said('access-request', { items: [], colour: 1 })
            .indexOf('STS-AUTHZEN-0071 This service does not implement') === 0,
          'B. access-request: a forbidden member is refused before a stray ' +
          'one');
  t.check(said('access-request', { subject: {}, resource: {}, action: {} }) ===
            '',
          'B. access-request: denial is deferred to its own place');
  const denial = AuthzenModel.field('access-request', 'denial',
                                    { reason: 'x' });
  t.check(denial && denial.code === 'STS-AUTHZEN-0072',
          'B. access-request: a denial with neither binding is refused ' +
          '(requireOne)', JSON.stringify(denial));
  const events = AuthzenModel.field('access-request', 'callback.events', 'x');
  t.check(events && events.code === 'STS-AUTHZEN-0079' &&
          events.message === 'callback.events must be an array of event ' +
            'names.',
          'B. access-request: a nested deferred field takes its parent\'s ' +
          'code', JSON.stringify(events));
  const item = AuthzenModel.item('evaluations', 'evaluations', 'x');
  t.check(item && item.message === 'An evaluation is a JSON object.' &&
          AuthzenModel.item('evaluations', 'evaluations', {}) === null,
          'B. evaluations: an item is refused alone');
  log.debug("Leaving readers().");
}

// A recorded value with each decoded JWT put back as the string it was.
function restored(value) {
  log.debug("Entering restored().");
  let out = value;
  if (Array.isArray(value)) {
    out = value.map(restored);
  } else if (value && typeof value === 'object') {
    if (value.jwt && value.jwt.header) {
      out = 'a.jwt.restored';
    } else {
      out = {};
      Object.keys(value).forEach(function (key) {
        out[key] = restored(value[key]);
      });
    }
  }
  log.debug("Leaving restored().");
  return out;
}

// The member set a recorded answer is held to, or ''.
function setOf(one) {
  log.debug("Entering setOf().");
  const body = one.body || {};
  const type = String((one.headers || {})['content-type'] || '');
  let id = '';
  if (one.method === 'DELIVER') {
    id = 'callback-notification';
  } else if (/problem\+json/.test(type)) {
    id = 'problem';
  } else if (!/json/.test(type)) {
    id = '';
  } else if (one.status >= 400) {
    id = 'error';
  } else if (/authzen-configuration/.test(one.path)) {
    id = 'metadata';
  } else if (/\/access-requests/.test(one.path)) {
    id = 'task-response';
  } else if (/\/search\//.test(one.path)) {
    id = 'search-response';
  } else if (body.evaluations !== undefined) {
    id = 'evaluations-response';
  } else if (/\/access\/v1\/evaluations?$/.test(one.path)) {
    id = 'evaluation-response';
  }
  log.debug("Leaving setOf(). " + (id || 'none'));
  return id;
}

// C. What the endpoints answered is the model's.
function answered(t) {
  log.debug("Entering answered().");
  const AuthzenModel = require('../authzen/authzen_model');
  const wire = JSON.parse(fs.readFileSync(path.join(__dirname,
    'authzen_model_wire.snapshot.json'), 'utf8')).wire;
  const problems = [];
  const counted = {};
  wire.forEach(function (one) {
    const id = setOf(one);
    if (!id) {
      return;
    }
    counted[id] = (counted[id] || 0) + 1;
    const value = restored(id === 'callback-notification'
      ? one.body.payload : one.body);
    AuthzenModel.undeclared(id, value).forEach(function (problem) {
      problems.push(one.mode + ', ' + one.step + ': ' + problem);
    });
  });
  ['metadata', 'evaluation-response', 'evaluations-response',
   'search-response', 'error', 'problem', 'task-response',
   'callback-notification'].forEach(function (id) {
    t.check(counted[id] > 0, 'C. the record holds ' + id + ' answers (' +
            (counted[id] || 0) + ')');
  });
  t.check(problems.length === 0,
          'C. every recorded answer is its member set\'s, nested sets ' +
          'included', problems.slice(0, 20).join('\n'));
  log.debug("Leaving answered().");
}

async function run(t) {
  log.debug("Entering run().");
  await buildCheck(t);
  readers(t);
  answered(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'model_authzen',
  describe: 'the AuthZEN model (#1579): the build\'s refusals, every ' +
            'request reader built from it and no shape check left in ' +
            'authzen/, and every recorded answer held to its member set',
  run: run
};
