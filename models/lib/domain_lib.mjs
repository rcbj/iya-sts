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
  // `Record<unknown>`: members nobody can list ahead, such as an audit
  // row's `detail`. Only a record may hold one: an entry's attributes are
  // all named, so a map read from one would be an attribute nobody declared.
  if (type.kind === 'Model' && type.name === 'Record' && type.indexer) {
    log.debug("Leaving shapeOf(). A map.");
    return { type: 'map' };
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
  if (field.type === 'map' && !field.held) {
    log.debug("Leaving fieldProblems(). A map not held on a record.");
    return [where + ' is a map and only a record may hold one'];
  }
  if (field.embedded && field.type !== 'concept') {
    log.debug("Leaving fieldProblems(). Embedded, not a concept.");
    return [where + ' is @embedded and is not a domain model'];
  }
  // A record's `first` upgrades a list an older build stored where the field
  // is ONE value; on a list, a map or a concept it would mean nothing.
  if (field.held && field.held.transform === 'first' &&
      (field.array || ['string', 'integer', 'number', 'boolean']
        .indexOf(field.type) < 0)) {
    log.debug("Leaving fieldProblems(). first on a field not one value.");
    return [where + ' says transform: "first" and is not one string, ' +
      'number or boolean'];
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
  // EVERY ATTRIBUTE MEANS SOMETHING, OR THE MODEL IS NOT THE SOURCE.
  const read = new Set();
  concepts.forEach(function (concept) {
    concept.fields.forEach(function (field) {
      if (field.from) {
        read.add((field.from.on || concept.entry) + '.' + field.from.attr);
      }
    });
  });
  directory.filter(function (object) {
    return !object.projectionOf;
  }).forEach(function (object) {
    object.attributes.concat(object.personAttributes)
      .forEach(function (attribute) {
        if (!read.has(object.id + '.' + attribute.name) &&
            !read.has('person.' + attribute.name)) {
          problems.push(object.id + '.' + attribute.name +
            ' is read by no concept');
        }
      });
  });
  log.debug("Leaving checkDomains(). " + problems.length);
  return problems;
}

/**
 * A sentence as comment lines of at most 80 columns.
 *
 * @param text - the sentence
 * @param indent - what goes before each line
 * @returns the lines
 */
function commentLines(text, indent) {
  log.debug("Entering commentLines().");
  const lines = [];
  let line = '';
  String(text).split(/\s+/).forEach(function (word) {
    if (line && (indent + ' * ' + line + ' ' + word).length > 80) {
      lines.push(indent + ' * ' + line);
      line = word;
    } else {
      line = line ? line + ' ' + word : word;
    }
  });
  lines.push(indent + ' * ' + line);
  log.debug("Leaving commentLines().");
  return [indent + '/**'].concat(lines, indent + ' */');
}

/**
 * The TypeScript type of one field.
 *
 * @param field - a field from `readDomains()`
 * @returns the type's text
 */
function fieldType(field) {
  log.debug("Entering fieldType().");
  let type = { string: 'string', boolean: 'boolean', integer: 'number',
    dateTime: 'string', url: 'string', map: 'Record<string, unknown>'
  }[field.type] || field.concept;
  if (field.values) {
    type = field.values.map(function (one) {
      return JSON.stringify(one);
    }).join(' | ');
  }
  log.debug("Leaving fieldType().");
  return field.array ? (field.values ? '(' + type + ')[]' : type + '[]') : type;
}

/**
 * The declarations of every concept, for the type check.
 *
 * A secret field is optional whatever the model says, because `DomainMap`
 * leaves it out unless a caller names it. A derived field is optional too,
 * because a caller may not have supplied it.
 *
 * @param concepts - from `readDomains()`
 * @returns the text of `types/domain.generated.d.ts`
 */
export function renderTypes(concepts) {
  log.debug("Entering renderTypes().");
  const lines = ['// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, ' +
    'LLC', '// SPDX-License-Identifier: BUSL-1.1', '//',
  '// GENERATED from models/domain/ (#1390). Do not edit: change the model and',
  '// run tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails',
  '// when this differs.', '', 'declare namespace IyaDomain {'];
  concepts.forEach(function (concept, index) {
    if (index > 0) {
      lines.push('');
    }
    lines.push.apply(lines, commentLines(concept.what, '  '));
    lines.push('  interface ' + concept.name + ' {');
    concept.fields.forEach(function (field) {
      const secret = (field.from && field.from.secret) ||
        (field.held && field.held.secret);
      const optional = field.optional || secret || field.derived;
      lines.push('    ' + field.name + (optional ? '?' : '') + ': ' +
        fieldType(field) + ';');
    });
    lines.push('  }');
  });
  lines.push('', '  interface Concepts {');
  concepts.forEach(function (concept) {
    lines.push('    ' + concept.name + ': ' + concept.name + ';');
  });
  lines.push('  }', '}', '');
  log.debug("Leaving renderTypes().");
  return lines.join('\n');
}

/**
 * The classes of every concept, one for each, each made from an entry or a
 * record by `DomainMap`, so a caller holds a named thing rather than a bag.
 *
 * @param concepts - from `readDomains()`
 * @returns the text of `common/domain_classes.ts`
 */
export function renderClasses(concepts) {
  log.debug("Entering renderClasses().");
  const lines = ['// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, ' +
    'LLC', '// SPDX-License-Identifier: BUSL-1.1', '',
  '\'use strict\';', '//', '// File: domain_classes.ts', '//',
  '// GENERATED from models/domain/ (#1390). Do not edit: change the model and',
  '// run tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails',
  '// when this differs.', '',
  'import bunyan = require(\'bunyan\');',
  'import DomainMap = require(\'./domain_map\');', '',
  'const log = bunyan.createLogger({',
  '  name: \'sts-domain-classes\',',
  '  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || \'info\'',
  '});', ''];
  concepts.forEach(function (concept) {
    const source = concept.record ? 'fromRecord' : 'fromEntry';
    const fullName = concept.name + '.' + source;
    lines.push.apply(lines, commentLines(concept.what, ''));
    lines.push('class ' + concept.name + ' {');
    lines.push('  /**', '   * Makes one from what holds it.', '   *',
      '   * @param held - the attributes or the record',
      '   * @param options - what it alone cannot say',
      '   * @returns the concept', '   */');
    lines.push('  static ' + source + '(held: any, options?: any):');
    lines.push('      IyaDomain.' + concept.name + ' {');
    lines.push('    log.debug("Entering ' + fullName + '().");');
    lines.push('    const made = DomainMap.' + source + '(\'' + concept.name +
      '\', held, options);');
    lines.push('    log.debug("Leaving ' + fullName + '().");');
    lines.push('    return made;', '  }', '}', '');
  });
  lines.push('export = {');
  concepts.forEach(function (concept, index) {
    lines.push('  ' + concept.name + ': ' + concept.name +
      (index < concepts.length - 1 ? ',' : ''));
  });
  lines.push('};', '');
  log.debug("Leaving renderClasses().");
  return lines.join('\n');
}
