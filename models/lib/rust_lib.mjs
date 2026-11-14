// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/lib/rust_lib.mjs
//
// ---------------------------------------------------------------------------
// THE MODEL'S DATA OBJECTS AS RUST (#444, rust/DESIGN.md decision D15).
//
// The abstract model (#1390) is the one source of every domain concept and
// of every request and answer of the five published APIs. For the Node
// service the build writes them as TypeScript (`renderTypes()`,
// `renderClasses()`, `renderApiTypes()`); for the Rust runtime this writes
// the SAME objects as Rust data types, so the two implementations are held
// to one model rather than to two copies of it (rcbj, 2026-11-14: "we need
// rust data object classes generated rather than typescript classes").
//
// Two files, both committed as `rust/crates/sts-model/src/generated/*.rs` by
// tests/tools/regenerate-model-docs.sh and held there by
// tests/model_domain.js, as the TypeScript ones are:
//
//   domain.rs   a struct per concept (`renderRustDomain()`), with the
//               entry or record it is made from and where each field comes
//               from, as constants a Rust DomainMap reads
//   api.rs      a module per document and an operation module per
//               operationId (`renderRustApi()`): its method and path, and
//               its Body, Query and AnswerNNN types, every nested shape
//               named after the member that holds it
//
// THE RULES THE TYPES FOLLOW, each the TypeScript renderer's read again:
//
// * A member the schema does not require is an `Option`. A member that may
//   also be `null` is an `Option<Option<_>>`, so "absent" and "null" stay
//   two answers, as they are on the wire (`sts_model::double_option`).
// * A CLOSED object (`additionalProperties: false`, which nearly every one
//   is since #1353) refuses a member it does not name
//   (`deny_unknown_fields`); an OPEN one keeps the rest in `extra`.
// * A union of scalars (`number | string` and the like, most of the
//   documents' unions) is one of the shared enums in `unions`, named by its
//   kinds; a union with an object or a reference in it is an untagged enum
//   of its own. Alternatives that only constrain (`anyOf: [{ required: [...]
//   }]`) say which members must be present, not what the value is, and are
//   read through, as `typeOf()` does.
// * A string enum is a Rust enum whose variants serialize as the strings.
// * A type that reaches itself is boxed where it does.
//
// Validation is NOT here: the bounds, patterns and formats are checked
// against the served document at runtime, as Node checks them (#1353). These
// are the shapes a handler is written against.
//
// This is an ES module because generate.mjs is one. It imports nothing from
// the compiler: it reads what `readDomains()` and `documents()` produced.
// ---------------------------------------------------------------------------

import bunyan from 'bunyan';

const log = bunyan.createLogger({
  name: 'sts-rust-lib',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

// Rust's keywords, which a member name may not be. `r#` cannot take `self`,
// `Self`, `super`, `crate` or `_`, so a name that is a keyword gets a
// trailing underscore instead, the same for all of them.
const KEYWORDS = new Set(['as', 'async', 'await', 'break', 'const',
  'continue', 'crate', 'dyn', 'else', 'enum', 'extern', 'false', 'fn', 'for',
  'gen', 'if', 'impl', 'in', 'let', 'loop', 'match', 'mod', 'move', 'mut',
  'pub', 'ref', 'return', 'self', 'Self', 'static', 'struct', 'super',
  'trait', 'true', 'try', 'type', 'unsafe', 'use', 'where', 'while', 'abstract',
  'become', 'box', 'do', 'final', 'macro', 'override', 'priv', 'typeof',
  'unsized', 'virtual', 'yield']);

// The scalar kinds a shared union may hold, in the order serde must try
// them: an untagged enum takes the first variant that fits, so an integer
// is tried before a number and a list before anything that is not one.
const UNION_ORDER = ['boolean', 'integer', 'number', 'string', 'array',
  'object'];

const UNION_VARIANT = {
  boolean: ['Bool', 'bool'],
  integer: ['Integer', 'i64'],
  number: ['Number', 'f64'],
  string: ['String', 'String'],
  array: ['List', 'Vec<serde_json::Value>'],
  object: ['Object', 'serde_json::Map<String, serde_json::Value>']
};

const HEADER = ['// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, ' +
  'LLC', '// SPDX-License-Identifier: BUSL-1.1', '//'];

const DERIVES = '#[derive(Debug, Clone, PartialEq, serde::Serialize, ' +
  'serde::Deserialize)]';

/**
 * A name's words: camelCase, PascalCase, snake_case, kebab-case and dotted
 * names all split the same way.
 *
 * @param name - the name as the model writes it
 * @returns its words, lower-cased
 */
function wordsOf(name) {
  return String(name)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(function (one) {
      return one.length > 0;
    })
    .map(function (one) {
      return one.toLowerCase();
    });
}

/**
 * A type or variant name: PascalCase, never empty, never starting with a
 * digit.
 *
 * @param name - the name as the model writes it
 * @param fallback - what an empty name becomes
 * @returns the Rust name
 */
function pascal(name, fallback) {
  const words = wordsOf(name);
  let out = words.map(function (one) {
    return one.charAt(0).toUpperCase() + one.slice(1);
  }).join('');
  if (!out) {
    out = fallback || 'Empty';
  }
  if (/^[0-9]/.test(out)) {
    out = 'V' + out;
  }
  return out;
}

/**
 * A member or module name: snake_case, never a keyword, never starting with
 * a digit.
 *
 * @param name - the name as the model writes it
 * @returns the Rust name
 */
function snake(name) {
  let out = wordsOf(name).join('_');
  if (!out) {
    out = 'value';
  }
  if (/^[0-9]/.test(out)) {
    out = 'n_' + out;
  }
  if (KEYWORDS.has(out)) {
    out = out + '_';
  }
  return out;
}

/**
 * Distinct names for a list: a second one that would collide gets a number.
 *
 * @param names - the proposed names, in order
 * @returns the names, made distinct
 */
function distinct(names) {
  const seen = new Map();
  return names.map(function (one) {
    const count = seen.get(one) || 0;
    seen.set(one, count + 1);
    return count === 0 ? one : one + '_' + (count + 1);
  });
}

/**
 * A sentence as `///` lines of at most 80 columns.
 *
 * @param text - the sentence, or nothing
 * @param indent - what goes before each line
 * @returns the lines; none for no sentence
 */
function docLines(text, indent) {
  if (!text) {
    return [];
  }
  const lines = [];
  let line = '';
  String(text).split(/\s+/).filter(function (one) {
    return one.length > 0;
  }).forEach(function (word) {
    if (line && (indent + '/// ' + line + ' ' + word).length > 80) {
      lines.push(indent + '/// ' + line);
      line = word;
    } else {
      line = line ? line + ' ' + word : word;
    }
  });
  if (line) {
    lines.push(indent + '/// ' + line);
  }
  return lines;
}

/**
 * A string as a Rust string literal.
 *
 * @param text - the string
 * @returns the literal
 */
function literal(text) {
  return JSON.stringify(String(text));
}

// ---------------------------------------------------------------------------
// The domain concepts.
// ---------------------------------------------------------------------------

/**
 * The Rust type of one domain field, before it is made optional.
 *
 * @param field - a field from `readDomains()`
 * @param boxed - whether a concept it names must be boxed
 * @returns the type's text
 */
function domainFieldType(field, boxed) {
  log.debug("Entering domainFieldType(). " + field.name);
  let type = { string: 'String', boolean: 'bool', integer: 'i64',
    dateTime: 'String', url: 'String',
    map: 'serde_json::Map<String, serde_json::Value>'
  }[field.type];
  if (!type) {
    type = boxed && !field.array ? 'Box<' + field.concept + '>' :
      field.concept;
  }
  log.debug("Leaving domainFieldType().");
  return field.array ? 'Vec<' + type + '>' : type;
}

/**
 * The concepts that reach themselves through their concept fields, which
 * must be boxed where they do or the struct has no size.
 *
 * @param concepts - from `readDomains()`
 * @returns the names of the concepts on a cycle
 */
function cyclicConcepts(concepts) {
  log.debug("Entering cyclicConcepts().");
  const edges = new Map(concepts.map(function (concept) {
    return [concept.name, concept.fields.filter(function (field) {
      return field.type === 'concept' && !field.array;
    }).map(function (field) {
      return field.concept;
    })];
  }));
  const cyclic = new Set();
  edges.forEach(function (targets, start) {
    const seen = new Set();
    const stack = targets.slice();
    while (stack.length > 0) {
      const next = stack.pop();
      if (next === start) {
        cyclic.add(start);
        break;
      }
      if (!seen.has(next)) {
        seen.add(next);
        stack.push.apply(stack, edges.get(next) || []);
      }
    }
  });
  log.debug("Leaving cyclicConcepts(). " + cyclic.size);
  return cyclic;
}

/**
 * Every domain concept as a Rust struct, with what it is made from.
 *
 * A field is optional as it is in `renderTypes()`: when the model says so,
 * when it holds a secret (`DomainMap` leaves one out unless a caller names
 * it), and when it is derived (a caller may not have supplied it).
 *
 * @param concepts - from `readDomains()`
 * @returns the text of `rust/crates/sts-model/src/generated/domain.rs`
 */
export function renderRustDomain(concepts) {
  log.debug("Entering renderRustDomain().");
  const cyclic = cyclicConcepts(concepts);
  const lines = HEADER.concat([
    '// GENERATED from models/domain/ (#1390, #444). Do not edit: change the',
    '// model and run tests/tools/regenerate-model-docs.sh.',
    '// tests/model_domain.js fails when this differs.', '',
    '// The domain concepts, one struct each, as `common/domain_classes.ts`',
    '// holds them for the Node service. Included by sts-model\'s lib.rs.', '',
    'use crate::{FieldSource, MadeFrom};', '']);
  concepts.forEach(function (concept) {
    const names = distinct(concept.fields.map(function (field) {
      return snake(field.name);
    }));
    lines.push.apply(lines, docLines(concept.what, ''));
    lines.push(DERIVES, '#[serde(deny_unknown_fields)]',
      'pub struct ' + concept.name + ' {');
    concept.fields.forEach(function (field, index) {
      const secret = (field.from && field.from.secret) ||
        (field.held && field.held.secret);
      const optional = field.optional || secret || field.derived;
      const boxed = field.type === 'concept' && cyclic.has(field.concept);
      const type = domainFieldType(field, boxed);
      lines.push.apply(lines, docLines(field.derived, '    '));
      const attributes = [];
      if (names[index] !== field.name) {
        attributes.push('rename = ' + literal(field.name));
      }
      if (optional) {
        attributes.push('default', 'skip_serializing_if = "Option::is_none"');
      }
      if (attributes.length > 0) {
        lines.push('    #[serde(' + attributes.join(', ') + ')]');
      }
      lines.push('    pub ' + names[index] + ': ' +
        (optional ? 'Option<' + type + '>' : type) + ',');
    });
    lines.push('}', '');
    lines.push('impl ' + concept.name + ' {');
    lines.push('    /// What the concept is made from: a directory entry ' +
      'or a record.');
    lines.push('    pub const MADE_FROM: MadeFrom = ' + (concept.record ?
      'MadeFrom::Record(' + literal(concept.record) + ')' :
      'MadeFrom::Entry(' + literal(concept.entry || '') + ')') + ';');
    lines.push('    /// Where each field comes from, in the model\'s order.');
    lines.push('    pub const FIELDS: &\'static [FieldSource] = &[');
    concept.fields.forEach(function (field) {
      const from = field.from || {};
      const held = field.held || {};
      lines.push('        FieldSource {');
      lines.push('            name: ' + literal(field.name) + ',');
      lines.push('            attribute: ' + (from.attr ?
        'Some(' + literal(from.attr) + ')' : 'None') + ',');
      lines.push('            on: ' + (from.on ?
        'Some(' + literal(from.on) + ')' : 'None') + ',');
      lines.push('            key: ' + (held.key ?
        'Some(' + literal(held.key) + ')' : 'None') + ',');
      lines.push('            transform: ' + (from.transform || held.transform ?
        'Some(' + literal(from.transform || held.transform) + ')' : 'None') +
        ',');
      lines.push('            secret: ' + Boolean(from.secret || held.secret) +
        ',');
      lines.push('            derived: ' + Boolean(field.derived) + ',');
      lines.push('            embedded: ' + Boolean(field.embedded) + ',');
      lines.push('        },');
    });
    lines.push('    ];', '}', '');
  });
  lines.push('/// Every concept\'s name, in the model\'s order.');
  lines.push('pub const CONCEPTS: &[&str] = &[');
  concepts.forEach(function (concept) {
    lines.push('    ' + literal(concept.name) + ',');
  });
  lines.push('];', '');
  log.debug("Leaving renderRustDomain().");
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// The five APIs.
// ---------------------------------------------------------------------------

/**
 * The kinds a JSON Schema allows, read through what only constrains, with
 * `null` set apart. A kind is `boolean`, `integer`, `number`, `string`,
 * `array`, `object` (an object with no named members), or `shape` (one with
 * named members, an enum of strings, or a reference), which a shared union
 * cannot hold.
 *
 * @param schema - the schema
 * @returns `{ kinds, nullable, shapes }`, `shapes` the schemas of kind shape
 */
function kindsOf(schema) {
  const out = { kinds: new Set(), nullable: false, shapes: [] };
  function add(one) {
    if (!one || typeof one !== 'object') {
      out.kinds.add('any');
      return;
    }
    if (one.$ref || one.properties || (one.enum && one.enum.length > 0 &&
        one.enum.every(function (v) {
          return typeof v === 'string';
        }) && one.enum.length > 1)) {
      out.kinds.add('shape');
      out.shapes.push(one);
      return;
    }
    const options = one.anyOf || one.oneOf;
    if (options && shapingAlternatives(options)) {
      options.forEach(add);
      return;
    }
    if (options) {
      const rest = Object.assign({}, one);
      delete rest.anyOf;
      delete rest.oneOf;
      add(rest);
      return;
    }
    if (one.const !== undefined || one.enum) {
      const values = one.enum || [one.const];
      values.forEach(function (value) {
        if (value === null) {
          out.nullable = true;
        } else if (typeof value === 'string') {
          out.kinds.add('string');
        } else if (typeof value === 'boolean') {
          out.kinds.add('boolean');
        } else if (typeof value === 'number') {
          out.kinds.add(Number.isInteger(value) ? 'integer' : 'number');
        } else {
          out.kinds.add('any');
        }
      });
      return;
    }
    const types = Array.isArray(one.type) ? one.type :
      (one.type ? [one.type] : []);
    if (types.length === 0) {
      out.kinds.add('any');
      return;
    }
    types.forEach(function (type) {
      if (type === 'null') {
        out.nullable = true;
      } else if (type === 'array' && one.items && types.length === 1) {
        out.kinds.add('shape');
        out.shapes.push(Object.assign({}, one, { type: 'array' }));
      } else if (type === 'object') {
        out.kinds.add('object');
      } else {
        out.kinds.add(type);
      }
    });
  }
  add(schema);
  if (out.kinds.has('integer') && out.kinds.has('number')) {
    out.kinds.delete('integer');
  }
  return out;
}

/**
 * Whether alternatives say what the value IS, rather than only which members
 * it must carry (the same test as `typeOf()`'s).
 *
 * @param options - an anyOf or a oneOf
 * @returns whether they shape the value
 */
function shapingAlternatives(options) {
  return options.some(function (one) {
    return one && typeof one === 'object' && ['type', 'properties', '$ref',
      'enum', 'const', 'items', 'anyOf', 'oneOf'].some(function (key) {
      return one[key] !== undefined;
    });
  });
}

/**
 * The writer of one document's types: it names every anonymous shape after
 * where it is found, and remembers the shared unions it used.
 */
class ApiWriter {
  /**
   * @param document - the OpenAPI document
   * @param unions - the shared unions used so far, by name: their kinds
   */
  constructor(document, unions) {
    this.schemas = (document.components && document.components.schemas) ||
      {};
    this.unions = unions;
    this.cyclic = this.cyclicComponents();
    // EVERY NAME IN A SCOPE IS CLAIMED ONCE. A nested shape is named after
    // the members that hold it, and two paths can spell one name
    // (`factorsKeys` + `item`, `factors` + `keysItem`), as two component keys
    // can (`SsfDeadLetters`, `ssfDeadLetters`): the second gets a number.
    // The components are one scope, each operation module another.
    this.used = new Set();
    const self = this;
    this.componentNames = new Map();
    Object.keys(this.schemas).sort().forEach(function (key) {
      self.componentNames.set(key, self.claim(pascal(key)));
    });
    this.componentScope = new Set(this.used);
  }

  /**
   * A name made distinct in the current scope.
   *
   * @param name - the name wanted
   * @returns the name to use
   */
  claim(name) {
    let out = name;
    let count = 1;
    while (this.used.has(out)) {
      count = count + 1;
      out = name + '_' + count;
    }
    this.used.add(out);
    return out;
  }

  /**
   * The components that reach themselves through references, which are
   * boxed wherever another component holds them by reference.
   *
   * @returns their names
   */
  cyclicComponents() {
    log.debug("Entering ApiWriter.cyclicComponents().");
    const schemas = this.schemas;
    const refsIn = function (schema, into) {
      if (!schema || typeof schema !== 'object') {
        return into;
      }
      if (Array.isArray(schema)) {
        schema.forEach(function (one) {
          refsIn(one, into);
        });
        return into;
      }
      if (typeof schema.$ref === 'string') {
        into.add(schema.$ref.split('/').pop());
      }
      Object.keys(schema).forEach(function (key) {
        if (key !== '$ref' && key !== 'items') {
          refsIn(schema[key], into);
        }
      });
      return into;
    };
    const cyclic = new Set();
    Object.keys(schemas).forEach(function (start) {
      const seen = new Set();
      const stack = Array.from(refsIn(schemas[start], new Set()));
      while (stack.length > 0) {
        const next = stack.pop();
        if (next === start) {
          cyclic.add(start);
          break;
        }
        if (!seen.has(next) && schemas[next]) {
          seen.add(next);
          stack.push.apply(stack, Array.from(refsIn(schemas[next],
            new Set())));
        }
      }
    });
    log.debug("Leaving ApiWriter.cyclicComponents(). " + cyclic.size);
    return cyclic;
  }

  /**
   * The Rust type for a schema, writing whatever named types it needs.
   *
   * @param schema - the schema
   * @param name - the name a shape it needs is given
   * @param out - the lines named types are written to
   * @returns `{ type, nullable }`
   */
  typeFor(schema, name, out) {
    if (!schema || typeof schema !== 'object') {
      return { type: 'serde_json::Value', nullable: false };
    }
    const found = kindsOf(schema);
    const kinds = Array.from(found.kinds);
    if (kinds.length === 0) {
      return { type: '()', nullable: false };
    }
    if (kinds.indexOf('any') >= 0) {
      return { type: 'serde_json::Value', nullable: found.nullable };
    }
    if (kinds.length === 1 && kinds[0] === 'shape') {
      if (found.shapes.length === 1) {
        return { type: this.shapeType(found.shapes[0], name, out),
          nullable: found.nullable };
      }
      return { type: this.unionOfShapes(found.shapes, name, out),
        nullable: found.nullable };
    }
    if (kinds.indexOf('shape') >= 0) {
      return { type: this.mixedUnion(found, name, out),
        nullable: found.nullable };
    }
    if (kinds.length === 1) {
      return { type: UNION_VARIANT[kinds[0]][1], nullable: found.nullable };
    }
    const ordered = UNION_ORDER.filter(function (kind) {
      return found.kinds.has(kind);
    });
    const unionName = ordered.map(function (kind) {
      return UNION_VARIANT[kind][0];
    }).join('Or');
    this.unions.set(unionName, ordered);
    return { type: 'crate::unions::' + unionName, nullable: found.nullable };
  }

  /**
   * The type of one shape: a reference, an object with members, a string
   * enum, or an array of a shape.
   *
   * @param schema - the shape's schema
   * @param name - its name, if it needs one
   * @param out - where its declaration goes
   * @returns the type's text
   */
  shapeType(schema, name, out, fixed) {
    if (schema.$ref) {
      const target = schema.$ref.split('/').pop();
      const type = 'super::components::' +
        (this.componentNames.get(target) || pascal(target));
      return this.cyclic.has(target) ? 'Box<' + type + '>' : type;
    }
    if (schema.type === 'array') {
      const item = this.typeFor(schema.items, name + 'Item', out);
      return 'Vec<' + (item.nullable ? 'Option<' + item.type + '>' :
        item.type) + '>';
    }
    const claimed = fixed ? name : this.claim(name);
    if (schema.enum) {
      this.writeEnum(schema, claimed, out);
      return claimed;
    }
    this.writeStruct(schema, claimed, out);
    return claimed;
  }

  /**
   * An untagged enum of several shapes, each a variant named for where it
   * stands.
   *
   * @param shapes - the schemas
   * @param name - the enum's name
   * @param out - where it is written
   * @returns the type's text
   */
  unionOfShapes(shapes, name, out, fixed) {
    const self = this;
    name = fixed ? name : this.claim(name);
    const variants = shapes.map(function (one, index) {
      const label = one.$ref ? pascal(one.$ref.split('/').pop()) :
        'V' + (index + 1);
      return [label, self.shapeType(one, name + label, out)];
    });
    this.writeUntagged(name, variants, out);
    return name;
  }

  /**
   * An untagged enum of shapes and scalar kinds.
   *
   * @param found - from `kindsOf()`
   * @param name - the enum's name
   * @param out - where it is written
   * @returns the type's text
   */
  mixedUnion(found, name, out, fixed) {
    const self = this;
    name = fixed ? name : this.claim(name);
    const variants = found.shapes.map(function (one, index) {
      const label = one.$ref ? pascal(one.$ref.split('/').pop()) :
        'V' + (index + 1);
      return [label, self.shapeType(one, name + label, out)];
    });
    UNION_ORDER.forEach(function (kind) {
      if (found.kinds.has(kind)) {
        variants.push(UNION_VARIANT[kind]);
      }
    });
    this.writeUntagged(name, variants, out);
    return name;
  }

  /**
   * An untagged enum's declaration.
   *
   * @param name - its name
   * @param variants - `[label, type]` pairs, in the order serde tries them
   * @param out - where it is written
   */
  writeUntagged(name, variants, out) {
    const labels = distinct(variants.map(function (one) {
      return one[0];
    }));
    out.push(DERIVES, '#[serde(untagged)]', 'pub enum ' + name + ' {');
    variants.forEach(function (one, index) {
      out.push('    ' + labels[index] + '(' + one[1] + '),');
    });
    out.push('}', '');
  }

  /**
   * A string enum's declaration, each variant serialized as its string.
   *
   * @param schema - the schema, with `enum`
   * @param name - its name
   * @param out - where it is written
   */
  writeEnum(schema, name, out) {
    const values = schema.enum.filter(function (one) {
      return typeof one === 'string';
    });
    const labels = distinct(values.map(function (one) {
      return pascal(one, 'Empty');
    }));
    out.push.apply(out, docLines(schema.description, ''));
    out.push('#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ' +
      'serde::Serialize, serde::Deserialize)]', 'pub enum ' + name + ' {');
    values.forEach(function (value, index) {
      out.push('    #[serde(rename = ' + literal(value) + ')]');
      out.push('    ' + labels[index] + ',');
    });
    out.push('}', '');
  }

  /**
   * An object's declaration: a member per property, optional unless the
   * schema requires it, and the rest refused or kept as the schema says.
   *
   * @param schema - the object's schema
   * @param name - the struct's name
   * @param out - where it is written
   */
  writeStruct(schema, name, out) {
    const self = this;
    const properties = schema.properties || {};
    const required = schema.required || [];
    const keys = Object.keys(properties);
    const members = distinct(keys.map(snake));
    const open = schema.additionalProperties === true ||
      (schema.additionalProperties &&
       typeof schema.additionalProperties === 'object');
    const nested = [];
    const body = [];
    keys.forEach(function (key, index) {
      const member = self.typeFor(properties[key], name + pascal(key, 'Value'),
        nested);
      const optional = required.indexOf(key) < 0;
      const attributes = [];
      if (members[index] !== key) {
        attributes.push('rename = ' + literal(key));
      }
      let type = member.type;
      if (member.nullable && optional) {
        type = 'Option<Option<' + type + '>>';
        attributes.push('default', 'skip_serializing_if = "Option::is_none"',
          'with = "crate::double_option"');
      } else if (member.nullable || optional) {
        type = 'Option<' + type + '>';
        if (optional) {
          attributes.push('default',
            'skip_serializing_if = "Option::is_none"');
        }
      }
      body.push.apply(body, docLines(properties[key].description, '    '));
      if (attributes.length > 0) {
        body.push('    #[serde(' + attributes.join(', ') + ')]');
      }
      body.push('    pub ' + members[index] + ': ' + type + ',');
    });
    if (open) {
      body.push('    /// The members the schema does not name, which it ' +
        'allows.');
      body.push('    #[serde(flatten)]');
      body.push('    pub extra: serde_json::Map<String, serde_json::Value>,');
    }
    out.push.apply(out, nested);
    out.push.apply(out, docLines(schema.description, ''));
    out.push(DERIVES);
    if (!open) {
      out.push('#[serde(deny_unknown_fields)]');
    }
    out.push('pub struct ' + name + ' {');
    out.push.apply(out, body);
    out.push('}', '');
  }

  /**
   * A named type for a schema, written as a declaration when the schema is
   * not itself a struct or an enum.
   *
   * @param schema - the schema
   * @param name - the name
   * @param out - where it is written
   */
  writeNamed(schema, name, out) {
    // THE NAME IS RESERVED FOR THE DECLARATION ITSELF. A struct, a string
    // enum or a union that needs an enum of its own is written under it;
    // anything else (a list, a scalar, a reference) is an alias of that
    // name, and what it holds is named after it with a suffix, so no nested
    // shape can take the reserved name and no alias can name itself.
    const found = kindsOf(schema);
    const kinds = Array.from(found.kinds);
    const shapes = found.shapes;
    const lone = kinds.length === 1 && kinds[0] === 'shape' &&
      shapes.length === 1 && !shapes[0].$ref && shapes[0].type !== 'array';
    if (found.nullable && (lone || kinds.indexOf('shape') >= 0)) {
      out.push('/// The model allows `null` here too: a handler answers it ' +
        'as `None`', '/// of an `Option` of this type.');
    }
    if (kinds.indexOf('any') < 0 && lone) {
      this.shapeType(shapes[0], name, out, true);
      return;
    }
    if (kinds.indexOf('any') < 0 && kinds.length === 1 &&
        kinds[0] === 'shape' && shapes.length > 1) {
      this.unionOfShapes(shapes, name, out, true);
      return;
    }
    if (kinds.indexOf('any') < 0 && kinds.indexOf('shape') >= 0 &&
        kinds.length > 1) {
      this.mixedUnion(found, name, out, true);
      return;
    }
    const held = this.typeFor(schema, name + 'Item', out);
    out.push('pub type ' + name + ' = ' + (held.nullable ?
      'Option<' + held.type + '>' : held.type) + ';', '');
  }

  /**
   * The document's reusable schemas, as `components`.
   *
   * @returns the module's lines
   */
  components() {
    log.debug("Entering ApiWriter.components().");
    const self = this;
    const out = [];
    Object.keys(this.schemas).sort().forEach(function (key) {
      self.writeNamed(self.schemas[key], self.componentNames.get(key), out);
    });
    log.debug("Leaving ApiWriter.components().");
    return out;
  }

  /**
   * One operation as a module: its method, path and id, its body, its query
   * and an answer type per 2xx status the model gives a JSON answer.
   *
   * @param method - the method
   * @param path - the path, as the document writes it
   * @param operation - the OpenAPI operation
   * @returns the module's lines, indented for it
   */
  operation(method, path, operation) {
    const out = [];
    this.used = new Set(['Body', 'Query'].concat(
      Object.keys(operation.responses || {}).map(function (status) {
        return 'Answer' + status;
      })));
    out.push('    pub const METHOD: &str = ' + literal(method.toUpperCase()) +
      ';');
    out.push('    pub const PATH: &str = ' + literal(path) + ';');
    out.push('    pub const OPERATION_ID: &str = ' +
      literal(operation.operationId) + ';', '');
    const inner = [];
    const content = (operation.requestBody &&
      operation.requestBody.content) || null;
    if (content && content['application/json']) {
      this.writeNamed(content['application/json'].schema, 'Body', inner);
    } else if (content) {
      inner.push('/// The body is not JSON (an upload): its bytes.',
        'pub type Body = Vec<u8>;', '');
    }
    const query = {};
    const required = [];
    (operation.parameters || []).filter(function (one) {
      return one.in === 'query';
    }).forEach(function (one) {
      query[one.name] = one.schema;
      if (one.required) {
        required.push(one.name);
      }
    });
    if (Object.keys(query).length > 0) {
      this.writeStruct({ properties: query, required: required,
        additionalProperties: false }, 'Query', inner);
    }
    const self = this;
    Object.keys(operation.responses || {}).sort().forEach(function (status) {
      const media = /^2[0-9][0-9]$/.test(status) &&
        operation.responses[status].content &&
        operation.responses[status].content['application/json'];
      if (media) {
        self.writeNamed(media.schema, 'Answer' + status, inner);
      }
    });
    inner.forEach(function (line) {
      out.push(line ? '    ' + line : '');
    });
    return out;
  }
}

/**
 * Every request and answer of every document as Rust: a module per
 * document, `components` for its reusable schemas, and a module per
 * operation by its operationId, which every operation carries since #1579.
 *
 * @param served - the documents, by name
 * @returns the text of `rust/crates/sts-model/src/generated/api.rs`
 */
export function renderRustApi(served) {
  log.debug("Entering renderRustApi().");
  const unions = new Map();
  const body = [];
  Object.keys(served).sort().forEach(function (name) {
    const document = served[name];
    const writer = new ApiWriter(document, unions);
    body.push.apply(body, docLines((document.info && document.info.title) ||
      name, ''));
    body.push('pub mod ' + snake(name) + ' {');
    body.push('    pub mod components {');
    writer.components().forEach(function (line) {
      body.push(line ? '        ' + line : '');
    });
    body.push('    }', '');
    const operations = [];
    Object.keys(document.paths || {}).sort().forEach(function (path) {
      Object.keys(document.paths[path]).sort().forEach(function (method) {
        const operation = document.paths[path][method];
        if (!operation || typeof operation !== 'object' ||
            ['get', 'put', 'post', 'patch', 'delete', 'head',
             'options'].indexOf(method) < 0) {
          return;
        }
        if (!operation.operationId) {
          log.debug("Leaving renderRustApi(). No operationId.");
          throw new Error('The ' + name + ' document\'s ' +
            method.toUpperCase() + ' ' + path + ' has no operationId.');
        }
        operations.push([method, path, operation]);
      });
    });
    const modules = distinct(operations.map(function (one) {
      return snake(one[2].operationId);
    }));
    operations.forEach(function (one, index) {
      body.push.apply(body, docLines(one[2].summary, '    '));
      body.push('    pub mod ' + modules[index] + ' {');
      body.push('        #[allow(unused_imports)]');
      body.push('        use super::components;', '');
      writer.operation(one[0], one[1], one[2]).forEach(function (line) {
        body.push(line ? '    ' + line : '');
      });
      while (body[body.length - 1] === '') {
        body.pop();
      }
      body.push('    }', '');
    });
    // THE DISPATCH BY OPERATION: a JSON value read as an operation's body,
    // or as its answer for a status, by the operationId a route carries.
    // The runtime reads a request through it, and sts-model's tests hold
    // every example in the documents to it.
    body.push('    /// Reads `value` as the JSON body of `operation_id`; `None` ' +
      'when the', '    /// operation takes no JSON body.');
    body.push('    pub fn read_body(operation_id: &str, value: ' +
      '&serde_json::Value)', '        -> Option<Result<(), ' +
      'serde_json::Error>> {', '        match operation_id {');
    operations.forEach(function (one, index) {
      const content = one[2].requestBody && one[2].requestBody.content;
      if (content && content['application/json']) {
        body.push('            ' + literal(one[2].operationId) + ' => ' +
          'Some(serde_json::from_value::<' + modules[index] +
          '::Body>(value.clone()).map(|_| ())),');
      }
    });
    body.push('            _ => None,', '        }', '    }', '');
    body.push('    /// Reads `value` as the JSON answer of `operation_id` for ' +
      '`status`;', '    /// `None` when the model gives that status no JSON ' +
      'answer.');
    body.push('    pub fn read_answer(operation_id: &str, status: u16, ' +
      'value: &serde_json::Value)', '        -> Option<Result<(), ' +
      'serde_json::Error>> {', '        match (operation_id, status) {');
    operations.forEach(function (one, index) {
      Object.keys(one[2].responses || {}).sort().forEach(function (status) {
        const media = /^2[0-9][0-9]$/.test(status) &&
          one[2].responses[status].content &&
          one[2].responses[status].content['application/json'];
        if (media) {
          body.push('            (' + literal(one[2].operationId) + ', ' +
            status + ') => Some(serde_json::from_value::<' + modules[index] +
            '::Answer' + status + '>(value.clone()).map(|_| ())),');
        }
      });
    });
    body.push('            _ => None,', '        }', '    }');
    body.push('}', '');
  });
  const lines = HEADER.concat([
    '// GENERATED from models/api/ (#1390, #444). Do not edit: change the',
    '// model and run tests/tools/regenerate-model-docs.sh.',
    '// tests/model_domain.js fails when this differs.', '',
    '// Every request and answer of the five published APIs, as',
    '// `types/api.generated.d.ts` holds them for the Node service. Included',
    '// by sts-model\'s lib.rs.', '']);
  // Concatenated, not pushed: the body runs to more lines than a call may
  // take arguments.
  log.debug("Leaving renderRustApi(). " + unions.size + " union(s).");
  return { api: lines.concat(body).join('\n'),
    unions: renderUnions(unions) };
}

/**
 * The shared unions of scalars the documents use, one enum each, named by
 * its kinds.
 *
 * @param unions - by name: their kinds, in the order serde tries them
 * @returns the text of `rust/crates/sts-model/src/generated/unions.rs`
 */
function renderUnions(unions) {
  log.debug("Entering renderUnions().");
  const lines = HEADER.concat([
    '// GENERATED from models/api/ (#1390, #444). Do not edit: change the',
    '// model and run tests/tools/regenerate-model-docs.sh.',
    '// tests/model_domain.js fails when this differs.', '',
    '// The unions of scalars the five documents use (`number | string`',
    '// and the like), each an untagged enum named by its kinds. Included by',
    '// sts-model\'s lib.rs.', '']);
  Array.from(unions.keys()).sort().forEach(function (name) {
    lines.push(DERIVES, '#[serde(untagged)]', 'pub enum ' + name + ' {');
    unions.get(name).forEach(function (kind) {
      lines.push('    ' + UNION_VARIANT[kind][0] + '(' +
        UNION_VARIANT[kind][1] + '),');
    });
    lines.push('}', '');
  });
  log.debug("Leaving renderUnions().");
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// THE MANAGEMENT API'S OPERATIONS AS A RUST ENUM (#444, phase 4, the
// `mgmtapi` slice). `sts-mgmt-api` routes by it: its handler table is an
// exhaustive `match` over every variant, so an operation the model adds
// does not compile until it is routed or listed as not yet ported, and a
// route can only name an operation the model has.
// ---------------------------------------------------------------------------
/**
 * Every operation of the Management API OpenAPI document and the Admin
 * Console API OpenAPI document, as `sts-mgmt-api`'s `Operation` enum and
 * its table, in each document's path order.
 *
 * @param served - the documents, by name
 * @returns the text of `rust/crates/sts-mgmt-api/src/generated/operations.rs`
 */
export function renderRustManagementOperations(served) {
  log.debug("Entering renderRustManagementOperations().");
  const rows = [];
  ['management', 'console'].forEach(function (name) {
    const document = served[name];
    if (!document) {
      log.debug("Leaving renderRustManagementOperations(). No " + name +
                " document.");
      throw new Error('The model has no ' + name + ' document.');
    }
    Object.keys(document.paths || {}).forEach(function (path) {
      Object.keys(document.paths[path]).forEach(function (method) {
        const operation = document.paths[path][method];
        if (!operation || typeof operation !== 'object' ||
            !operation.operationId) {
          return;
        }
        rows.push({ kind: name, method: method.toUpperCase(), path: path,
                    id: operation.operationId,
                    variant: pascal(operation.operationId) });
      });
    });
  });
  const variants = distinct(rows.map(function (one) {
    return one.variant;
  }));
  const lines = HEADER.concat([
    '// GENERATED from models/api/ (#1390, #444). Do not edit: change the',
    '// model and run tests/tools/regenerate-model-docs.sh.',
    '// tests/model_domain.js fails when this differs.', '',
    '// Every operation of the two documents /admin-api serves, in each',
    '// document\'s path order. Included by sts-mgmt-api\'s operations.rs.', '',
    '/// One operation of the Management API or Admin Console API OpenAPI',
    '/// document, by its operationId.',
    '#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]',
    'pub enum Operation {']);
  rows.forEach(function (one, index) {
    lines.push('    /// `' + one.method + ' ' + one.path + '`');
    lines.push('    ' + variants[index] + ',');
  });
  lines.push('}', '', '/// The table: one row per operation.',
    'pub const OPERATIONS: &[OperationRow] = &[');
  rows.forEach(function (one, index) {
    lines.push('    OperationRow { operation: Operation::' + variants[index] +
      ', id: ' + literal(one.id) + ', method: ' + literal(one.method) +
      ', path: ' + literal(one.path) + ', kind: Kind::' +
      (one.kind === 'console' ? 'Console' : 'Management') + ' },');
  });
  lines.push('];', '');
  log.debug("Leaving renderRustManagementOperations(). " + rows.length +
            " operation(s).");
  return lines.join('\n');
}
