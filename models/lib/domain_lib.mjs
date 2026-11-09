// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/lib/domain_lib.mjs
//
// ---------------------------------------------------------------------------
// THE CANONICAL DOMAIN MODELS, READ FROM A COMPILED PROGRAM (#1390).
//
// `readDomains()` turns the `@domain` models into plain values and
// `checkDomains()` holds them to the directory objects they read. A problem
// stops the image build: a domain model that names an attribute nothing
// holds, or that hides a credential's marking, is a wrong model and not a
// warning.
//
// This is an ES module because the TypeSpec compiler loads a library with
// `import()`. It imports nothing from the compiler.
// ---------------------------------------------------------------------------

import bunyan from 'bunyan';

const log = bunyan.createLogger({
  name: 'sts-domain-lib',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

const DOMAIN = Symbol.for('iya.domain.domain');
const FROM = Symbol.for('iya.domain.from');
const RECORD = Symbol.for('iya.domain.record');
const DERIVED = Symbol.for('iya.domain.derived');
const EMBEDDED = Symbol.for('iya.domain.embedded');
const INVARIANT = Symbol.for('iya.domain.invariant');

// The scalars a field may be, by the standard library's name.
const SCALARS = { string: 'string', boolean: 'boolean', integer: 'integer',
  int32: 'integer', int64: 'integer', safeint: 'integer',
  utcDateTime: 'dateTime', url: 'url' };

export const $decorators = {
  'IyaSts.DomainLib': {
    domain: function (context, target, options) {
      context.program.stateMap(DOMAIN).set(target, options);
    },
    fromAttr: function (context, target, options) {
      context.program.stateMap(FROM).set(target, options);
    },
    fromRecord: function (context, target, options) {
      context.program.stateMap(RECORD).set(target, options);
    },
    derived: function (context, target, options) {
      context.program.stateMap(DERIVED).set(target, options);
    },
    embedded: function (context, target) {
      context.program.stateMap(EMBEDDED).set(target, true);
    },
    invariant: function (context, target, options) {
      const held = context.program.stateMap(INVARIANT).get(target) || [];
      // A decorator nearest the model is applied first, so this keeps the
      // order the author wrote them in.
      context.program.stateMap(INVARIANT).set(target, [options].concat(held));
    }
  }
};

/**
 * What a field's TypeSpec type is, in the catalogue's words.
 *
 * @param program - the compiled program
 * @param type - the type
 * @returns `{ type, array?, values?, concept? }`
 */
function shapeOf(program, type) {
  log.debug("Entering shapeOf().");
  if (type.kind === 'Scalar') {
    let scalar = type;
    while (scalar && !SCALARS[scalar.name]) {
      scalar = scalar.baseScalar;
    }
    log.debug("Leaving shapeOf(). A scalar.");
    return { type: scalar ? SCALARS[scalar.name] : 'unknown' };
  }
  if (type.kind === 'Model' && type.name === 'Array' && type.indexer) {
    const element = shapeOf(program, type.indexer.value);
    log.debug("Leaving shapeOf(). An array.");
    return Object.assign({}, element, { array: true });
  }
  if (type.kind === 'Model' && program.stateMap(DOMAIN).has(type)) {
    log.debug("Leaving shapeOf(). A concept.");
    return { type: 'concept', concept: type.name };
  }
  if (type.kind === 'Union') {
    const variants = Array.from(type.variants.values()).map(function (one) {
      return one.type;
    });
    if (variants.length > 0 && variants.every(function (one) {
      return one.kind === 'String';
    })) {
      log.debug("Leaving shapeOf(). A closed list.");
      return { type: 'string', values: variants.map(function (one) {
        return one.value;
      }) };
    }
  }
  log.debug("Leaving shapeOf(). Not a shape a concept may have.");
  return { type: 'unknown' };
}

/**
 * Every domain model in a compiled program.
 *
 * @param program - the compiled program
 * @returns the concepts, by name order
 */
export function readDomains(program) {
  log.debug("Entering readDomains().");
  const concepts = [];
  program.stateMap(DOMAIN).forEach(function (options, model) {
    const fields = [];
    model.properties.forEach(function (property) {
      const from = program.stateMap(FROM).get(property);
      const held = program.stateMap(RECORD).get(property);
      const derived = program.stateMap(DERIVED).get(property);
      const row = Object.assign({ name: property.name,
        optional: property.optional === true },
      shapeOf(program, property.type));
      if (from) {
        row.from = from;
      }
      if (held) {
        row.held = held;
      }
      if (derived) {
        row.derived = derived.how;
      }
      if (program.stateMap(EMBEDDED).get(property)) {
        row.embedded = true;
      }
      fields.push(row);
    });
    concepts.push({ name: model.name, area: options.area, what: options.what,
      entry: options.entry, record: options.record, fields: fields,
      invariants: program.stateMap(INVARIANT).get(model) || [] });
  });
  concepts.sort(function (a, b) {
    return a.name.localeCompare(b.name);
  });
  log.debug("Leaving readDomains(). " + concepts.length);
  return concepts;
}

/**
 * The attributes of a directory object, by name.
 *
 * @param object - from `readDirectory()`
 * @returns the map
 */
function attributesOf(object) {
  log.debug("Entering attributesOf().");
  const held = new Map();
  object.attributes.concat(object.personAttributes).forEach(function (one) {
    held.set(one.name, one);
  });
  log.debug("Leaving attributesOf().");
  return held;
}

/**
 * One field's problems against what its directory object says.
 *
 * @param concept - the concept
 * @param field - the field
 * @param objects - by id
 * @param withheld - names withheld from every reader, in lower case
 * @returns the sentences
 */
function fieldProblems(concept, field, objects, withheld) {
  log.debug("Entering fieldProblems().");
  const where = concept.name + '.' + field.name;
  const states = [field.from, field.held, field.derived, field.embedded]
    .filter(Boolean).length;
  if (states !== 1) {
    log.debug("Leaving fieldProblems(). Not one source.");
    return [where + ' must say exactly one of @fromAttr, @fromRecord, ' +
      '@derived and @embedded'];
  }
  if ((field.from && concept.record) || (field.held && concept.entry)) {
    log.debug("Leaving fieldProblems(). The wrong kind of source.");
    return [where + (field.from ? ' reads an attribute and the concept is ' +
      'held on a record' : ' reads a record and the concept is held in the ' +
      'directory')];
  }
  if (field.type === 'unknown') {
    log.debug("Leaving fieldProblems(). An unknown type.");
    return [where + ' has a type a concept may not have'];
  }
  if (field.embedded && field.type !== 'concept') {
    log.debug("Leaving fieldProblems(). Embedded, not a concept.");
    return [where + ' is @embedded and is not a domain model'];
  }
  if (!field.from) {
    log.debug("Leaving fieldProblems(). Nothing stored to check.");
    return [];
  }
  const id = field.from.on || concept.entry;
  const object = objects.get(id);
  if (!object) {
    log.debug("Leaving fieldProblems(). No such object.");
    return [where + ' reads directory object ' + id + ', which is not one'];
  }
  const attribute = attributesOf(object).get(field.from.attr);
  if (!attribute) {
    log.debug("Leaving fieldProblems(). No such attribute.");
    return [where + ' reads ' + id + '.' + field.from.attr +
      ', which the directory object does not declare'];
  }
  const problems = [];
  const marked = attribute.sensitive === true || attribute.secret === true ||
    attribute.withheld === true ||
    withheld.has(field.from.attr.toLowerCase());
  if (marked !== (field.from.secret === true)) {
    problems.push(where + (marked ? ' reads a sensitive attribute and does ' +
      'not say secret: true' : ' says secret: true of an attribute that ' +
      'is not marked sensitive'));
  }
  const kind = attribute.kind === 'unspecified' ? attribute.storedAs :
    attribute.kind;
  if (kind === 'multi' && !field.array &&
      field.from.transform !== 'first') {
    problems.push(where + ' is one value of a multi-valued attribute and ' +
      'does not say transform: "first"');
  }
  if (kind === 'single' && field.array) {
    problems.push(where + ' is a list and its attribute holds one value');
  }
  log.debug("Leaving fieldProblems().");
  return problems;
}

/**
 * Holds the concepts to the directory objects they read.
 *
 * @param concepts - from `readDomains()`
 * @param directory - objects from `readDirectory()`
 * @param secretNames - the directory's list of attributes withheld from
 *   every reader
 * @returns the problems, empty when there are none
 */
export function checkDomains(concepts, directory, secretNames) {
  log.debug("Entering checkDomains().");
  const withheld = new Set((secretNames || []).map(function (one) {
    return one.toLowerCase();
  }));
  const objects = new Map(directory.map(function (object) {
    return [object.id, object];
  }));
  const problems = [];
  concepts.forEach(function (concept) {
    if (Boolean(concept.entry) === Boolean(concept.record)) {
      problems.push(concept.name + ' must say exactly one of entry and ' +
        'record');
      return;
    }
    if (concept.entry && !objects.has(concept.entry)) {
      problems.push(concept.name + ' reads directory object ' +
        concept.entry + ', which is not one');
      return;
    }
    if (!/^[A-Z]/.test(concept.area)) {
      problems.push(concept.name + ' names no area of the catalogue');
    }
    concept.fields.forEach(function (field) {
      problems.push.apply(problems,
        fieldProblems(concept, field, objects, withheld));
    });
  });
  log.debug("Leaving checkDomains(). " + problems.length);
  return problems;
}
