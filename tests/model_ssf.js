// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_ssf.js
//
// ---------------------------------------------------------------------------
// THE SHARED SIGNALS MODEL, AND WHAT HOLDS THE FAMILY TO IT (#1579).
//
// `models/ssf/ssf_events.tsp` states every event type and its payload
// members, and `models/ssf/ssf.tsp` the subject formats, the complex
// subject, the lists, the delivery methods, every document and the err
// values. This holds four things:
//
//   A. the build's check (`models/lib/ssf_lib.mjs`'s checkSsf()) passes the
//      generated table and refuses each kind of wrong model, asserted on a
//      copy with one thing broken;
//   B. no table restating the model is left in `ssf/`: the literals the
//      rows were converted from are gone, every row the family builds IS
//      the model's, and every event type with a member has a generator;
//   C. what the family answered and sent — every answer, refusal and SET
//      `tests/ssf_model_wire.snapshot.json` recorded, in four realms — is
//      the model's: each document to its members, each err to the declared
//      list, each SET's claims to RFC 8417's and its payload to its event
//      type's members;
//   D. the holding records and does not reshape: a document with a member
//      the model does not name answers the sentence, and the model's own
//      examples pass the grammar.
//
// That the switch changed nothing on the wire is `tests/ssf_model_wire.js`'s.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const url = require('url');

const log = require('bunyan').createLogger({
  name: 'model_ssf',
  level: process.env.LOG_LEVEL || 'info'
});

const ROOT = path.join(__dirname, '..');
const ModelTables = require('../common/model_tables');

// A copy of the generated table, for one thing to be broken in.
function copy() {
  log.debug("Entering copy().");
  log.debug("Leaving copy().");
  return JSON.parse(JSON.stringify(ModelTables.file('ssf.json')));
}

// One event row of a copy, by the tail of its URI.
function eventOf(ssf, tail) {
  log.debug("Entering eventOf().");
  log.debug("Leaving eventOf().");
  return ssf.events.filter(function (one) {
    return one.uri.slice(-tail.length - 1) === '/' + tail ||
      one.uri.slice(-tail.length - 1) === ':' + tail;
  })[0];
}

// A. The build's refusals.
async function buildCheck(t) {
  log.debug("Entering buildCheck().");
  const lib = await import(url.pathToFileURL(path.join(ROOT, 'models', 'lib',
    'ssf_lib.mjs')).href);
  const generated = ModelTables.file('ssf.json');
  t.check(lib.checkSsf(generated).length === 0,
          'A. the generated Shared Signals model is clean',
          lib.checkSsf(generated).join('; '));
  t.check(generated.events.length === 30 && generated.formats.length === 11,
          'A. it holds thirty event types and eleven formats',
          generated.events.length + ', ' + generated.formats.length);
  const refused = function (what, pattern, change) {
    const broken = copy();
    change(broken);
    const said = lib.checkSsf(broken).join('; ');
    t.check(pattern.test(said), 'A. refused: ' + what, said || '(nothing)');
  };
  refused('an event type declared twice', /session-revoked is declared twice/,
    function (o) {
      o.events.push(JSON.parse(JSON.stringify(eventOf(o, 'session-revoked'))));
    });
  refused('an event under another family\'s prefix', /not under the risc/,
    function (o) {
      eventOf(o, 'session-revoked').family = 'risc';
    });
  refused('an event citing nothing', /opt-in cites nothing/, function (o) {
    eventOf(o, 'opt-in').cite = '';
  });
  refused('a member of no JSON shape', /has no JSON shape/, function (o) {
    eventOf(o, 'credential-change').members[0].type = 'unknown';
  });
  refused('a member saying nothing', /says nothing/, function (o) {
    eventOf(o, 'credential-change').members[0].what = '';
  });
  refused('a narrowing to no format', /which is no format/, function (o) {
    eventOf(o, 'identifier-changed').subjectFormats = ['postal'];
  });
  refused('a narrowing on an event with no subject', /narrows its subject/,
    function (o) {
      eventOf(o, 'verification').subjectFormats = ['email'];
    });
  refused('a deprecation naming nothing', /which is no event type/,
    function (o) {
      eventOf(o, 'sessions-revoked').deprecated = 'urn:nope';
    });
  refused('a format declared twice', /format email is declared twice/,
    function (o) {
      o.formats.push(JSON.parse(JSON.stringify(o.formats[1])));
    });
  refused('an example with a member its format lacks', /carries extra/,
    function (o) {
      o.formats[1].example = JSON.stringify({ format: 'email',
        email: 'a@b.c', extra: 1 });
    });
  refused('an example of another format', /example is not one of it/,
    function (o) {
      o.formats[1].example = JSON.stringify({ format: 'opaque', id: '1' });
    });
  refused('a complex member name pattern that does not compile',
    /does not compile/, function (o) {
      o.complex.memberName = '([';
    });
  refused('a stream configuration member nobody supplies',
    /says nobody supplies it/, function (o) {
      const set = o.members.filter(function (one) {
        return one.id === 'stream-configuration';
      })[0];
      delete set.list[0].supplier;
    });
  refused('a document member citing nothing', /set-claims\.iss cites nothing/,
    function (o) {
      o.members.filter(function (one) {
        return one.id === 'set-claims';
      })[0].list[0].cite = '';
    });
  refused('an err value declared twice', /access_denied is declared twice/,
    function (o) {
      o.errors.push({ code: 'access_denied', cite: 'x' });
    });
  refused('an err value of the wrong shape', /SET Error Code's shape/,
    function (o) {
      o.errors.push({ code: 'Bad-Code', cite: 'x' });
    });
  log.debug("Leaving buildCheck().");
}

// B. No table restating the model is left, and the rows ARE the model's.
function noHandTables(t) {
  log.debug("Entering noHandTables().");
  const SsfModel = require('../ssf/ssf_model');
  const events = require('../ssf/ssf_events');
  const subjects = require('../ssf/ssf_subjects');
  const read = function (file) {
    log.debug("Entering read().");
    log.debug("Leaving read().");
    return fs.readFileSync(path.join(ROOT, file), 'utf8');
  };
  const FORBIDDEN = [
    ['ssf/ssf_events.js', /^const (SSF|CAEP|RISC|STS)_EVENTS = \[/m,
     'an event table literal'],
    ['ssf/ssf_events.js', /uri: (SSF|CAEP|RISC|STS)_PREFIX \+ '/,
     'an event row literal'],
    ['ssf/ssf_events.js', /^const CREDENTIAL_TYPES = \[/m,
     'the credential types'],
    ['ssf/ssf_events.js', /^const STATUSES = \[/m, 'the statuses'],
    ['ssf/ssf_events.js', /(CAEP|RISC)_COMMON_MEMBERS = \[/,
     'the common members'],
    ['ssf/ssf_subjects.js', /^const FORMATS = \[/m, 'the format table'],
    ['ssf/ssf_subjects.js', /^const COMPLEX_MEMBERS = \[/m,
     'the complex member table'],
    ['ssf/ssf_subjects.js', /^const PERSON_FORMATS = \[/m,
     'the person formats'],
    ['ssf/ssf_subjects.js', /'(account|email|did|uri|iss_sub)\.[a-z]+': f/,
     'a value check keyed by format'],
    ['ssf/ssf_streams.ts', /^const DELIVERY_METHODS = \[/m,
     'the delivery methods'],
    ['ssf/ssf_streams.ts', /\['iss', 'aud', 'events_supported'/,
     'the Transmitter-Supplied members'],
    ['ssf/ssf_transmitters.ts', /\['enabled', 'paused', 'disabled'\]/,
     'the statuses']
  ];
  FORBIDDEN.forEach(function (one) {
    t.check(!one[1].test(read(one[0])), 'B. ' + one[0] + ' writes no ' +
            one[2] + ' of its own');
  });
  const model = SsfModel.events();
  t.check(JSON.stringify(events.EVENTS.map(function (row) {
    return { uri: row.uri, members: row.members, what: row.what };
  })) === JSON.stringify(model.map(function (row) {
    return { uri: row.uri, members: row.members, what: row.what };
  })), 'B. every catalogue row is the model\'s, in its order');
  events.EVENTS.forEach(function (row) {
    const payload = row.generate({});
    const verdict = events.validateEvent(row.uri, payload);
    t.check(verdict.ok, 'B. ' + row.name + '\'s generated payload is its ' +
            'model\'s', verdict.errors.join(' '));
    if (row.members.length > 0) {
      t.check(row.required.every(function (name) {
        return payload[name] !== undefined;
      }), 'B. ' + row.name + '\'s generator fills every required member');
    }
  });
  t.check(JSON.stringify(subjects.FORMAT_NAMES) ===
          JSON.stringify(SsfModel.formats().map(function (row) {
            return row.format;
          })), 'B. the formats are the model\'s, in its order');
  t.check(subjects.FORMATS.every(function (row) {
    return row.members.every(function (name) {
      return typeof row.checks[name] === 'string';
    });
  }), 'B. every format member names its check');
  t.check(JSON.stringify(events.STATUSES) ===
          JSON.stringify(SsfModel.list('stream-statuses')) &&
          JSON.stringify(events.CREDENTIAL_TYPES) ===
          JSON.stringify(SsfModel.list('credential-types')),
          'B. the statuses and credential types are the model\'s');
  log.debug("Leaving noHandTables().");
}

// A recorded value with its placeholders put back as values of their kind:
// an instant as a number, anything else in angle brackets as a string.
function restored(value) {
  log.debug("Entering restored().");
  if (Array.isArray(value)) {
    log.debug("Leaving restored().");
    return value.map(restored);
  }
  if (value && typeof value === 'object') {
    const out = {};
    Object.keys(value).forEach(function (key) {
      out[key] = restored(value[key]);
    });
    log.debug("Leaving restored().");
    return out;
  }
  log.debug("Leaving restored().");
  return value === '<epoch>' || value === '<iat>' || value === '<toe>' ||
    value === '<event_timestamp>' ? 1800000000 : value;
}

// C. Every recorded answer, refusal and SET is the model's.
function recorded(t) {
  log.debug("Entering recorded().");
  const SsfModel = require('../ssf/ssf_model');
  const events = require('../ssf/ssf_events');
  const snapshot = JSON.parse(fs.readFileSync(path.join(__dirname,
    'ssf_model_wire.snapshot.json'), 'utf8'));
  const DOCUMENT_OF = {
    'metadata': 'transmitter-metadata',
    'metadata, the inserted-path form': 'transmitter-metadata',
    'create, push': 'stream-configuration',
    'create, poll': 'stream-configuration',
    'read, one': 'stream-configuration',
    'update, merge': 'stream-configuration',
    'update, replace': 'stream-configuration',
    'status': 'stream-status',
    'status, paused': 'stream-status',
    'status, enabled': 'stream-status',
    'poll': 'poll-response',
    'poll, acknowledging': 'poll-response'
  };
  let documents = 0;
  let refusals = 0;
  let sets = 0;
  const problems = [];
  snapshot.wire.forEach(function (one) {
    const where = one.mode + ', ' + one.step + ': ';
    const body = restored(one.body);
    if (one.status >= 400 && body && typeof body === 'object' &&
        body.err !== undefined) {
      refusals++;
      SsfModel.undeclared('error-response', body).forEach(function (p) {
        problems.push(where + p);
      });
      if (SsfModel.unknownError(body.err)) {
        problems.push(where + 'the err ' + body.err + ' is not declared');
      }
      return;
    }
    if (one.status >= 300) {
      return;
    }
    const id = DOCUMENT_OF[one.step];
    if (id) {
      documents++;
      SsfModel.undeclared(id, body).forEach(function (p) {
        problems.push(where + p);
      });
      if (id === 'stream-configuration') {
        SsfModel.undeclared('stream-delivery', body.delivery)
          .forEach(function (p) {
            problems.push(where + p);
          });
      }
    }
    if (one.step === 'read, every stream') {
      body.forEach(function (stream) {
        documents++;
        SsfModel.undeclared('stream-configuration', stream)
          .forEach(function (p) {
            problems.push(where + p);
          });
      });
    }
    if (id === 'poll-response' && Array.isArray(body.sets)) {
      body.sets.forEach(function (set) {
        sets++;
        const claims = set.jwt.claims;
        SsfModel.undeclared('set-claims', claims).forEach(function (p) {
          problems.push(where + p);
        });
        if (set.jwt.header.typ !== events.SET_MEDIA_TYPE) {
          problems.push(where + 'a SET\'s typ is ' + set.jwt.header.typ);
        }
        Object.keys(claims.events).forEach(function (uri) {
          const verdict = events.validateEvent(uri, claims.events[uri]);
          verdict.errors.forEach(function (p) {
            problems.push(where + p);
          });
        });
      });
    }
  });
  t.check(documents >= 40 && refusals >= 120 && sets >= 60 &&
          problems.length === 0,
          'C. every recorded document (' + documents + '), refusal (' +
          refusals + ') and SET (' + sets + ') is the model\'s',
          problems.slice(0, 20).join('\n'));
  log.debug("Leaving recorded().");
}

// D. The holding says what is wrong, and the examples pass the grammar.
function holding(t) {
  log.debug("Entering holding().");
  const SsfModel = require('../ssf/ssf_model');
  const subjects = require('../ssf/ssf_subjects');
  const said = SsfModel.undeclared('stream-status',
    { stream_id: 's', status: 7, extra: true }).join('; ');
  t.check(/extra is not a member of stream-status/.test(said) &&
          /stream-status\.status is not string/.test(said),
          'D. an extra member and a wrong type are both named', said);
  t.check(/status is required/.test(SsfModel.undeclared('stream-status',
          { stream_id: 's' }).join()), 'D. a missing required member is');
  t.check(SsfModel.undeclared('stream-status', { stream_id: 's' },
          { partial: true }).length === 0, 'D. but not in a partial request');
  t.check(SsfModel.undeclared('transmitter-metadata',
          { issuer: 'https://p/', vendor_member: 1 }, { open: true })
            .length === 0, 'D. a partner\'s extension is not a problem');
  t.check(/aud is not receiver-supplied/.test(SsfModel.undeclared(
          'stream-configuration', { stream_id: 's', aud: 'x' },
          { partial: true, supplier: 'receiver' }).join()),
          'D. a request carrying a transmitter\'s member says so');
  t.check(SsfModel.unknownError('invalid_request') === false &&
          SsfModel.unknownError('nope') === true,
          'D. the err list answers');
  subjects.FORMATS.forEach(function (row) {
    const verdict = subjects.validateSubjectId(row.example, {});
    t.check(verdict.ok, 'D. the model\'s ' + row.format + ' example passes ' +
            'the grammar', verdict.errors.join(' '));
  });
  log.debug("Leaving holding().");
}

async function run(t) {
  log.debug("Entering run().");
  await buildCheck(t);
  noHandTables(t);
  recorded(t);
  holding(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'model_ssf',
  describe: 'the Shared Signals model (#1579): the build\'s refusals, no ' +
            'hand-written table left in ssf/, every recorded answer, ' +
            'refusal and SET held to it, and the holding\'s sentences',
  run: run
};
