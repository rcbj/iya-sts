// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/lib/ssf_lib.mjs
//
// ---------------------------------------------------------------------------
// THE SHARED SIGNALS MODEL, READ FROM A COMPILED PROGRAM (#1579).
//
// `readSsf()` turns the `@event`, `@subjectFormat`, `@complexSubject`,
// `@list`, `@delivery`, `@members` and `@errorCodes` declarations into the
// tables `models/generated/ssf.json` holds: every event type with its
// payload members and the JSON shape of each, every RFC 9493 format with its
// closed member set and the check each value is held to, SSF's complex
// subject, the stream statuses and the credential types, the delivery
// methods, the members of every document the transmitter answers and the
// receiver sends, and the `err` values. `checkSsf()` refuses a model the
// service could not read faithfully — an event type under another family's
// prefix, a member of no JSON shape, a deprecation or a narrowing naming
// nothing declared, an example its own format refuses, a name declared
// twice — and the problem stops the image build.
//
// This is an ES module because the TypeSpec compiler loads a library with
// `import()`. It imports nothing from the compiler.
// ---------------------------------------------------------------------------

import bunyan from 'bunyan';

const log = bunyan.createLogger({
  name: 'sts-ssf-lib',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

const EVENT = Symbol.for('iya.ssf.event');
const EVENT_MEMBER = Symbol.for('iya.ssf.eventMember');
const COMMON = Symbol.for('iya.ssf.common');
const FORMAT = Symbol.for('iya.ssf.subjectFormat');
const SUBJECT_MEMBER = Symbol.for('iya.ssf.subjectMember');
const COMPLEX = Symbol.for('iya.ssf.complexSubject');
const COMPLEX_MEMBER = Symbol.for('iya.ssf.complexMember');
const LIST = Symbol.for('iya.ssf.list');
const DELIVERY = Symbol.for('iya.ssf.delivery');
const MEMBERS = Symbol.for('iya.ssf.members');
const MEMBER = Symbol.for('iya.ssf.member');
const ERRORS = Symbol.for('iya.ssf.errors');
const ERROR = Symbol.for('iya.ssf.error');

// The event type URI prefix of each family; an event under another family's
// prefix is refused.
const PREFIXES = {
  ssf: 'https://schemas.openid.net/secevent/ssf/event-type/',
  caep: 'https://schemas.openid.net/secevent/caep/event-type/',
  risc: 'https://schemas.openid.net/secevent/risc/event-type/',
  sts: 'urn:iya:sts:secevent:event-type:'
};

// The JSON type each TypeSpec scalar is, by the standard library's name.
const SCALARS = { string: 'string', url: 'string', boolean: 'boolean',
  int8: 'number', int16: 'number', int32: 'number', int64: 'number',
  integer: 'number', safeint: 'number', uint8: 'number', uint16: 'number',
  uint32: 'number', uint64: 'number', float32: 'number',
  float64: 'number', numeric: 'number', decimal: 'number',
  unknown: 'any' };

export const $decorators = {
  'IyaSts.SsfLib': {
    event: function (context, target, options) {
      context.program.stateMap(EVENT).set(target, options);
    },
    eventMember: function (context, target, options) {
      context.program.stateMap(EVENT_MEMBER).set(target, options);
    },
    common: function (context, target, options) {
      context.program.stateMap(COMMON).set(target, options);
    },
    subjectFormat: function (context, target, options) {
      context.program.stateMap(FORMAT).set(target, options);
    },
    subjectMember: function (context, target, options) {
      context.program.stateMap(SUBJECT_MEMBER).set(target, options);
    },
    complexSubject: function (context, target, options) {
      context.program.stateMap(COMPLEX).set(target, options);
    },
    complexMember: function (context, target, options) {
      context.program.stateMap(COMPLEX_MEMBER).set(target, options);
    },
    valueList: function (context, target, options) {
      context.program.stateMap(LIST).set(target, options);
    },
    delivery: function (context, target, options) {
      context.program.stateMap(DELIVERY).set(target, options);
    },
    members: function (context, target, options) {
      context.program.stateMap(MEMBERS).set(target, options);
    },
    member: function (context, target, options) {
      context.program.stateMap(MEMBER).set(target, options);
    },
    errorCodes: function (context, target) {
      context.program.stateMap(ERRORS).set(target, true);
    },
    errorCode: function (context, target, options) {
      context.program.stateMap(ERROR).set(target, options);
    }
  }
};

/**
 * The JSON name of a scalar, following its base scalars.
 *
 * @param type - a TypeSpec scalar
 * @returns `string`, `number`, `boolean`, `any`, or `unknown`
 */
function scalarName(type) {
  log.debug("Entering scalarName().");
  let scalar = type;
  while (scalar && !SCALARS[scalar.name]) {
    scalar = scalar.baseScalar;
  }
  log.debug("Leaving scalarName().");
  return scalar ? SCALARS[scalar.name] : 'unknown';
}

/**
 * The shape of an event payload member, as `ssf_events.js`'s `checkMember()`
 * names it, and the values of a list.
 *
 * @param type - the member's TypeSpec type
 * @returns `{ type, values? }`; `type` is `unknown` for no shape
 */
function memberShape(type) {
  log.debug("Entering memberShape().");
  if (type.kind === 'Scalar') {
    const name = scalarName(type);
    log.debug("Leaving memberShape(). A scalar.");
    return { type: name === 'any' ? 'unknown' : name };
  }
  if (type.kind === 'Model' && type.name === 'Array' && type.indexer) {
    const inner = type.indexer.value;
    log.debug("Leaving memberShape(). An array.");
    return { type: inner.kind === 'Scalar' && scalarName(inner) === 'string'
      ? 'strings' : 'unknown' };
  }
  if (type.kind === 'Model' && type.name === 'Record' && type.indexer) {
    const inner = type.indexer.value;
    if (inner.kind === 'Scalar' && scalarName(inner) === 'string') {
      log.debug("Leaving memberShape(). A language map.");
      return { type: 'langmap' };
    }
    log.debug("Leaving memberShape(). An object.");
    return { type: inner.kind === 'Intrinsic' && inner.name === 'unknown'
      ? 'object' : 'unknown' };
  }
  if (type.kind === 'Union') {
    const values = [];
    let open = false;
    let other = false;
    type.variants.forEach(function (variant) {
      const one = variant.type;
      if (one.kind === 'String') {
        values.push(one.value);
      } else if (one.kind === 'Scalar' && scalarName(one) === 'string') {
        open = true;
      } else {
        other = true;
      }
    });
    log.debug("Leaving memberShape(). A list.");
    return other || values.length === 0 ? { type: 'unknown' }
      : { type: open ? 'openenum' : 'enum', values: values };
  }
  log.debug("Leaving memberShape(). No shape.");
  return { type: 'unknown' };
}

/**
 * The JSON types a document member may be, as `typeof`-like names.
 *
 * @param type - the TypeSpec type
 * @returns the names
 */
function jsonTypesOf(type) {
  log.debug("Entering jsonTypesOf().");
  let out = ['unknown'];
  if (type.kind === 'Model' && type.name === 'Array' && type.indexer) {
    out = ['array'];
  } else if (type.kind === 'Model') {
    out = ['object'];
  } else if (type.kind === 'String') {
    out = ['string'];
  } else if (type.kind === 'Boolean') {
    out = ['boolean'];
  } else if (type.kind === 'Number') {
    out = ['number'];
  } else if (type.kind === 'Scalar') {
    const name = scalarName(type);
    out = [name === 'number' && /int/.test(type.name) ? 'integer' : name];
  } else if (type.kind === 'Intrinsic' && type.name === 'unknown') {
    out = ['any'];
  } else if (type.kind === 'Union') {
    out = [];
    type.variants.forEach(function (variant) {
      jsonTypesOf(variant.type).forEach(function (one) {
        if (out.indexOf(one) < 0) {
          out.push(one);
        }
      });
    });
  }
  log.debug("Leaving jsonTypesOf().");
  return out;
}

/**
 * The payload members of an event model, or of a common set, in order.
 *
 * @param program - the compiled program
 * @param model - the model
 * @returns the members as `ssf_events.js`'s rows carry them
 */
function eventMembersOf(program, model) {
  log.debug("Entering eventMembersOf().");
  const out = [];
  model.properties.forEach(function (property) {
    const options = program.stateMap(EVENT_MEMBER).get(property) || {};
    const shape = memberShape(property.type);
    const member = { name: property.name,
                     required: property.optional !== true,
                     type: shape.type };
    if (shape.values) {
      member.values = shape.values;
    }
    member.what = options.what || '';
    if (options.cite) {
      member.cite = options.cite;
    }
    out.push(member);
  });
  log.debug("Leaving eventMembersOf(). " + out.length);
  return out;
}

/**
 * Every declaration of the Shared Signals namespace in a compiled program.
 *
 * @param program - the compiled program
 * @returns `{ events, commons, formats, complex, lists, deliveries,
 *   members, errors }`
 */
export function readSsf(program) {
  log.debug("Entering readSsf().");
  const events = [];
  program.stateMap(EVENT).forEach(function (options, model) {
    const row = { uri: options.uri, family: options.family,
                  name: options.name, subject: options.subject };
    if (options.subjectFormats) {
      row.subjectFormats = options.subjectFormats.slice(0);
    }
    if (options.deprecated) {
      row.deprecated = options.deprecated;
    }
    row.members = eventMembersOf(program, model);
    row.what = options.what;
    row.cite = options.cite;
    row.model = model.name;
    events.push(row);
  });
  const commons = [];
  program.stateMap(COMMON).forEach(function (options, model) {
    commons.push({ id: options.id, cite: options.cite,
                   members: eventMembersOf(program, model) });
  });
  const formats = [];
  program.stateMap(FORMAT).forEach(function (options, model) {
    const members = [];
    model.properties.forEach(function (property) {
      const one = program.stateMap(SUBJECT_MEMBER).get(property) || {};
      members.push({ name: property.name,
                     required: property.optional !== true,
                     check: one.check || 'string',
                     types: jsonTypesOf(property.type) });
    });
    formats.push({ format: options.format, person: options.person === true,
                   what: options.what, example: options.example,
                   cite: options.cite, members: members });
  });
  let complex = null;
  program.stateMap(COMPLEX).forEach(function (options, model) {
    const members = [];
    model.properties.forEach(function (property) {
      const one = program.stateMap(COMPLEX_MEMBER).get(property) || {};
      members.push({ name: property.name, what: one.what || '' });
    });
    complex = { format: options.format, memberName: options.memberName,
                cite: options.cite, members: members };
  });
  const lists = [];
  program.stateMap(LIST).forEach(function (options, union) {
    const shape = memberShape(union);
    lists.push({ id: options.id, cite: options.cite,
                 open: shape.type === 'openenum',
                 values: shape.values || [] });
  });
  const deliveries = [];
  program.stateMap(DELIVERY).forEach(function (options) {
    deliveries.push({ method: options.method, name: options.name,
                      what: options.what, cite: options.cite });
  });
  const members = [];
  program.stateMap(MEMBERS).forEach(function (options, model) {
    const list = [];
    model.properties.forEach(function (property) {
      const one = program.stateMap(MEMBER).get(property) || {};
      const member = { name: property.name,
                       types: jsonTypesOf(property.type),
                       required: property.optional !== true,
                       cite: one.cite || '' };
      if (one.own === true) {
        member.own = true;
      }
      if (one.supplier) {
        member.supplier = one.supplier;
      }
      list.push(member);
    });
    members.push({ id: options.id, cite: options.cite,
                   members: options.members, model: model.name, list: list });
  });
  const errors = [];
  program.stateMap(ERRORS).forEach(function (flag, model) {
    model.properties.forEach(function (property) {
      const one = program.stateMap(ERROR).get(property) || {};
      errors.push({ code: property.name, cite: one.cite || '' });
    });
  });
  log.debug("Leaving readSsf(). " + events.length + " event type(s), " +
            formats.length + " format(s), " + members.length +
            " document(s).");
  return { events: events, commons: commons, formats: formats,
           complex: complex, lists: lists, deliveries: deliveries,
           members: members, errors: errors };
}

/**
 * The problems of the event types.
 *
 * @param ssf - from `readSsf()`
 * @param problems - where a problem is added
 */
function eventProblems(ssf, problems) {
  log.debug("Entering eventProblems().");
  const uris = new Set();
  const formats = new Set(ssf.formats.map(function (one) {
    return one.format;
  }));
  ssf.events.forEach(function (row) {
    if (uris.has(row.uri)) {
      problems.push('the event type ' + row.uri + ' is declared twice');
    }
    uris.add(row.uri);
  });
  ssf.events.forEach(function (row) {
    if (!row.cite) {
      problems.push('the event type ' + row.uri + ' cites nothing');
    }
    if (String(row.uri).indexOf(PREFIXES[row.family] || '\u0000') !== 0) {
      problems.push('the event type ' + row.uri + ' is not under the ' +
                    row.family + ' prefix ' + PREFIXES[row.family]);
    }
    if (row.subject === 'none' && row.subjectFormats) {
      problems.push('the event type ' + row.uri + ' has no subject and ' +
                    'narrows its subject\'s format');
    }
    (row.subjectFormats || []).forEach(function (name) {
      if (!formats.has(name)) {
        problems.push('the event type ' + row.uri + ' narrows its subject ' +
                      'to ' + name + ', which is no format');
      }
    });
    if (row.deprecated && !uris.has(row.deprecated)) {
      problems.push('the event type ' + row.uri + ' is deprecated for ' +
                    row.deprecated + ', which is no event type');
    }
    const names = new Set();
    row.members.forEach(function (member) {
      if (names.has(member.name)) {
        problems.push(row.uri + ' declares ' + member.name + ' twice');
      }
      names.add(member.name);
      if (member.type === 'unknown') {
        problems.push(row.uri + '.' + member.name + ' has no JSON shape a ' +
                      'payload member may have');
      }
      if (!member.what) {
        problems.push(row.uri + '.' + member.name + ' says nothing');
      }
    });
  });
  log.debug("Leaving eventProblems().");
}

/**
 * The problems of the subject formats: an example its own format refuses is
 * one, judged by the closed member set alone (the value checks are the
 * service's).
 *
 * @param ssf - from `readSsf()`
 * @param problems - where a problem is added
 */
function formatProblems(ssf, problems) {
  log.debug("Entering formatProblems().");
  const seen = new Set();
  ssf.formats.forEach(function (row) {
    if (seen.has(row.format)) {
      problems.push('the subject format ' + row.format + ' is declared twice');
    }
    seen.add(row.format);
    if (!row.cite) {
      problems.push('the subject format ' + row.format + ' cites nothing');
    }
    if (row.members.length === 0) {
      problems.push('the subject format ' + row.format + ' has no member');
    }
    let example = null;
    try {
      example = JSON.parse(row.example);
    } catch (e) {
      log.debug("Caught in formatProblems(): " + ((e && e.message) || e));
      example = null;
    }
    if (!example || example.format !== row.format) {
      problems.push('the subject format ' + row.format + '\'s example is ' +
                    'not one of it');
      return;
    }
    const names = row.members.map(function (one) {
      return one.name;
    });
    Object.keys(example).forEach(function (key) {
      if (key !== 'format' && names.indexOf(key) < 0) {
        problems.push('the subject format ' + row.format + '\'s example ' +
                      'carries ' + key + ', which it does not define');
      }
    });
    row.members.forEach(function (member) {
      if (member.required && example[member.name] === undefined) {
        problems.push('the subject format ' + row.format + '\'s example ' +
                      'has no ' + member.name);
      }
    });
  });
  if (!ssf.complex) {
    problems.push('no complex subject is declared');
  } else {
    try {
      new RegExp(ssf.complex.memberName);
    } catch (e) {
      log.debug("Caught in formatProblems(): " + ((e && e.message) || e));
      problems.push('the complex subject\'s member name pattern does not ' +
                    'compile: ' + e.message);
    }
    if (seen.has(ssf.complex.format)) {
      problems.push('the complex subject\'s format ' + ssf.complex.format +
                    ' is also a simple format');
    }
  }
  log.debug("Leaving formatProblems().");
}

/**
 * Holds the model to what the service can read faithfully.
 *
 * @param ssf - from `readSsf()`
 * @returns the problems, empty when there are none
 */
export function checkSsf(ssf) {
  log.debug("Entering checkSsf().");
  const problems = [];
  eventProblems(ssf, problems);
  formatProblems(ssf, problems);
  const ids = new Set();
  ssf.lists.forEach(function (list) {
    if (ids.has('list:' + list.id)) {
      problems.push('the list ' + list.id + ' is declared twice');
    }
    ids.add('list:' + list.id);
    if (list.values.length === 0) {
      problems.push('the list ' + list.id + ' has no value');
    }
  });
  ssf.commons.forEach(function (set) {
    if (ids.has('common:' + set.id)) {
      problems.push('the common members ' + set.id + ' are declared twice');
    }
    ids.add('common:' + set.id);
  });
  ssf.deliveries.forEach(function (one) {
    if (ids.has('delivery:' + one.method)) {
      problems.push('the delivery method ' + one.method + ' is declared ' +
                    'twice');
    }
    ids.add('delivery:' + one.method);
  });
  ssf.members.forEach(function (set) {
    if (ids.has('members:' + set.id)) {
      problems.push('the document ' + set.id + ' is declared twice');
    }
    ids.add('members:' + set.id);
    if (!set.cite) {
      problems.push('the document ' + set.id + ' cites nothing');
    }
    set.list.forEach(function (member) {
      if (!member.cite) {
        problems.push(set.id + '.' + member.name + ' cites nothing');
      }
      if (member.types.indexOf('unknown') >= 0) {
        problems.push(set.id + '.' + member.name + ' has a type no JSON ' +
                      'value is');
      }
      if (set.id === 'stream-configuration' && !member.supplier) {
        problems.push(set.id + '.' + member.name + ' says nobody supplies ' +
                      'it');
      }
    });
  });
  const codes = new Set();
  ssf.errors.forEach(function (error) {
    if (codes.has(error.code)) {
      problems.push('the error code ' + error.code + ' is declared twice');
    }
    codes.add(error.code);
    if (!error.cite) {
      problems.push('the error code ' + error.code + ' cites nothing');
    }
    if (!/^[a-z_]+$/.test(error.code)) {
      problems.push('the error code ' + error.code + ' is not a SET Error ' +
                    'Code\'s shape');
    }
  });
  if (ssf.errors.length === 0) {
    problems.push('no error code is declared');
  }
  log.debug("Leaving checkSsf(). " + problems.length + " problem(s).");
  return problems;
}
