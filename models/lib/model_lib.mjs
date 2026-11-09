// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/lib/model_lib.mjs
//
// ---------------------------------------------------------------------------
// THE DECORATORS OF THE ABSTRACT MODEL, AND THE READER OF A COMPILED ONE
// (#1390).
//
// A decorator records its value on the compiled program. `readDirectory()`
// and `readPersistence()` turn a compiled program back into plain values, and
// those values are what the emitters take, so what an emitter writes comes
// from the TypeSpec a person can edit and from nothing else.
//
// This is an ES module because the TypeSpec compiler loads a library with
// `import()`. It imports nothing from the compiler.
// ---------------------------------------------------------------------------

import bunyan from 'bunyan';

const log = bunyan.createLogger({
  name: 'sts-model-lib',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

const ENTRY = Symbol.for('iya.model.entry');
const ATTR = Symbol.for('iya.model.attr');
const LINK = Symbol.for('iya.model.link');
const TABLE = Symbol.for('iya.model.table');
const COLUMN = Symbol.for('iya.model.column');
const SCHEMA = Symbol.for('iya.model.schema');
const SPELLINGS = Symbol.for('iya.model.spellings');

/**
 * Records one decorator's value on the program.
 *
 * @param context - the decorator context
 * @param key - the state key
 * @param target - the decorated node
 * @param options - the decorator's value
 */
function record(context, key, target, options) {
  log.debug("Entering record().");
  context.program.stateMap(key).set(target, options);
  log.debug("Leaving record().");
}

export const $decorators = {
  'IyaSts.ModelLib': {
    entry: function (context, target, options) {
      record(context, ENTRY, target, options);
    },
    attr: function (context, target, options) {
      record(context, ATTR, target, options);
    },
    link: function (context, target, options) {
      record(context, LINK, target, options);
    },
    table: function (context, target, options) {
      record(context, TABLE, target, options);
    },
    column: function (context, target, options) {
      record(context, COLUMN, target, options);
    },
    schema: function (context, target, options) {
      record(context, SCHEMA, target, options);
    },
    spellings: function (context, target, options) {
      record(context, SPELLINGS, target, options);
    }
  }
};

/**
 * One property as a catalogue attribute.
 *
 * @param program - the compiled program
 * @param property - the model property
 * @param index - its place in the model
 * @returns the attribute
 */
function attributeOf(program, property, index) {
  log.debug("Entering attributeOf().");
  const options = program.stateMap(ATTR).get(property) || {};
  const attribute = Object.assign({ name: property.name, sourceIndex: index },
    options);
  if (options.kind === undefined) {
    attribute.kind = 'unspecified';
  }
  log.debug("Leaving attributeOf().");
  return attribute;
}

/**
 * The links declared on a model's properties.
 *
 * @param program - the compiled program
 * @param model - the model
 * @returns one relationship per decorated property
 */
function linksOf(program, model) {
  log.debug("Entering linksOf().");
  const links = [];
  model.properties.forEach(function (property) {
    const link = program.stateMap(LINK).get(property);
    if (link) {
      links.push(Object.assign({ name: property.name }, link));
    }
  });
  log.debug("Leaving linksOf().");
  return links;
}

/**
 * The directory namespace of a compiled program. A model marked `onPerson`
 * is folded into the object of the same id as its person attributes.
 *
 * @param program - the compiled program
 * @returns the objects, sorted by id
 */
export function readDirectory(program) {
  log.debug("Entering readDirectory().");
  const byId = new Map();
  Array.from(program.stateMap(ENTRY).entries()).forEach(function (pair) {
    const model = pair[0];
    const options = pair[1];
    const attributes = Array.from(model.properties.values()).map(
      function (property, index) {
        return attributeOf(program, property, index);
      });
    const object = byId.get(options.id) || {
      id: options.id,
      objectClasses: [],
      attributes: [],
      personAttributes: [],
      relationships: []
    };
    if (options.onPerson) {
      object.personAttributes = attributes;
    } else {
      Object.assign(object, options, {
        objectClasses: options.objectClasses || [],
        attributes: attributes,
        relationships: linksOf(program, model)
      });
    }
    byId.set(options.id, object);
  });
  const objects = Array.from(byId.values()).sort(function (a, b) {
    return a.id.localeCompare(b.id);
  });
  log.debug("Leaving readDirectory().");
  return objects;
}

// The fields of a SCHEMA row that a row states as itself.
const ROW_KEYS = new Set(['from', 'what', 'editable', 'standard', 'identifier',
  'identifierName', 'sensitive', 'secret', 'families', 'familyWhy',
  'overrides', 'strictOverride', 'role', 'jsonBlob']);

/**
 * One row of a SCHEMA table, without what the model added to it, in the
 * order the decorator states its fields.
 *
 * In a file written by hand `kind` is what the author declared. In a
 * generated one `kind` may be the RFC's, and `declaredKind` is the module's.
 *
 * @param attribute - a catalogue attribute
 * @param authored - whether the object is written by hand
 * @returns the row
 */
function schemaRow(attribute, authored) {
  log.debug("Entering schemaRow().");
  const row = { name: attribute.name };
  Object.keys(attribute).forEach(function (key) {
    if (ROW_KEYS.has(key)) {
      row[key] = attribute[key];
    } else if (key === 'declaredKind') {
      row.kind = attribute[key];
    } else if (key === 'kind' && authored &&
        attribute[key] !== 'unspecified') {
      row.kind = attribute[key];
    } else if (key === 'allowed') {
      row.enum = attribute[key];
    }
  });
  log.debug("Leaving schemaRow().");
  return row;
}

/**
 * Rebuilds the SCHEMA table of one object from the compiled model.
 *
 * @param object - an object from `readDirectory()`
 * @returns the SCHEMA value
 */
export function schemaOf(object) {
  log.debug("Entering schemaOf().");
  const schema = {};
  if (object.ownContainer) {
    schema.container = object.container;
  }
  if (object.definitionContainer !== undefined) {
    schema.definitionContainer = object.definitionContainer;
  }
  const authored = object.authored === true;
  const toRow = function (attribute) {
    return schemaRow(attribute, authored);
  };
  if (object.section !== undefined) {
    schema.section = object.section;
  }
  if (object.note !== undefined) {
    schema.note = object.note;
  }
  schema.objectClasses = object.objectClasses.map(function (item) {
    const row = { name: item.name };
    Object.keys(item).forEach(function (key) {
      if (key === 'where' || key === 'standard' || key === 'what') {
        row[key] = item[key];
      }
    });
    return row;
  });
  if (!object.noAttributes) {
    schema.attributes = object.attributes.map(toRow);
  }
  if (object.personAttributes.length > 0) {
    schema.personAttributes = object.personAttributes.map(toRow);
  }
  log.debug("Leaving schemaOf().");
  return schema;
}

/**
 * The directory's name lists.
 *
 * @param program - the compiled program
 * @returns standard, own and secret, or null when none is declared
 */
export function readSpellings(program) {
  log.debug("Entering readSpellings().");
  const found = Array.from(program.stateMap(SPELLINGS).values())[0] || null;
  log.debug("Leaving readSpellings().");
  return found;
}

/**
 * Every reference between directory objects.
 *
 * @param objects - objects from `readDirectory()`
 * @returns one row per link, naming the object that holds it
 */
export function linksIn(objects) {
  log.debug("Entering linksIn().");
  const links = [];
  objects.forEach(function (object) {
    object.relationships.forEach(function (link) {
      links.push(Object.assign({ from: object.id }, link));
    });
  });
  log.debug("Leaving linksIn().");
  return links;
}

/**
 * The settings and selectors a policy object declares. A value the code
 * computes is not here; the module passes it to `ModelTables.fields()`.
 *
 * @param object - an object from `readDirectory()`
 * @returns the rows, in the model's order
 */
export function fieldsOf(object) {
  log.debug("Entering fieldsOf().");
  const fields = [];
  const selectors = [];
  object.attributes.forEach(function (attribute) {
    if (attribute.field) {
      fields.push(Object.assign({}, attribute.field,
        { attribute: attribute.name, what: attribute.what }));
    }
    if (attribute.selector) {
      selectors.push({ key: attribute.selector.key,
        attribute: attribute.name, what: attribute.what });
    }
  });
  log.debug("Leaving fieldsOf().");
  return { fields: fields, selectors: selectors };
}

/**
 * One CREATE TABLE statement from a compiled table.
 *
 * @param program - the compiled program
 * @param model - the table's model
 * @param options - its `@table` value
 * @returns the statement and the table's columns
 */
function tableOf(program, model, options) {
  log.debug("Entering tableOf().");
  const columns = [];
  const items = [];
  const constraints = (options.constraints || []).slice();
  Array.from(model.properties.values()).forEach(function (property, index) {
    constraints.filter(function (one) {
      return one.at === index;
    }).forEach(function (one) {
      items.push(one.text);
    });
    const column = program.stateMap(COLUMN).get(property) || {};
    items.push(property.name + ' ' + column.sql +
      (column.clauses ? ' ' + column.clauses : ''));
    columns.push({
      name: property.name,
      sqlType: column.sql,
      required: column.required === true,
      generated: column.generated === true,
      primaryKey: column.primaryKey === true,
      attributes: column.attributes || []
    });
  });
  constraints.filter(function (one) {
    return one.at >= model.properties.size;
  }).forEach(function (one) {
    items.push(one.text);
  });
  const statement = options.head + ' ' + options.name + ' ( ' +
    items.join(', ') + (options.tightClose ? ')' : ' )') +
    (options.suffix ? ' ' + options.suffix : '');
  log.debug("Leaving tableOf().");
  return { name: options.name, columns: columns, statement: statement };
}

/**
 * The persistence namespace of a compiled program: its tables, and every
 * statement of the script in the order the script runs them.
 *
 * @param program - the compiled program
 * @returns version, extensions, tables and statements
 */
export function readPersistence(program) {
  log.debug("Entering readPersistence().");
  const placed = [];
  const tables = [];
  Array.from(program.stateMap(TABLE).entries()).forEach(function (pair) {
    const options = pair[1];
    const table = tableOf(program, pair[0], options);
    tables.push({ name: table.name, columns: table.columns });
    placed.push({ at: options.at, text: table.statement });
    (options.indexes || []).forEach(function (one) {
      placed.push(one);
    });
  });
  const schemas = Array.from(program.stateMap(SCHEMA).values());
  const schema = schemas[0] || { version: 0 };
  (schema.statements || []).forEach(function (one) {
    placed.push(one);
  });
  placed.sort(function (a, b) {
    return a.at - b.at;
  });
  const result = {
    version: schema.version,
    extensions: schema.extensions || [],
    tables: tables,
    statements: placed.map(function (one) {
      return one.text;
    })
  };
  log.debug("Leaving readPersistence().");
  return result;
}
