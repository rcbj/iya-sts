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
  // The stated type says one or several where `kind` is silent. It is kept
  // apart from `kind` because a row in a SCHEMA table carries `kind`.
  if (property.type.kind === 'Scalar') {
    attribute.storedAs = 'single';
  } else if (property.type.kind === 'Model' && property.type.indexer) {
    attribute.storedAs = 'multi';
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
 * One table from a compiled model.
 *
 * @param program - the compiled program
 * @param model - the table's model
 * @param options - its `@table` value
 * @returns its name, columns, statement and script form
 */
function tableOf(program, model, options) {
  log.debug("Entering tableOf().");
  const columns = [];
  const items = [];
  const rows = [];
  const constraints = (options.constraints || []).slice();
  const place = function (index) {
    constraints.filter(function (one) {
      return one.at === index;
    }).forEach(function (one) {
      items.push(one.text);
      rows.push({ text: one.text });
    });
  };
  Array.from(model.properties.values()).forEach(function (property, index) {
    place(index);
    const column = program.stateMap(COLUMN).get(property) || {};
    const spelled = column.backticks ? '`' + property.name + '`' :
      property.name;
    items.push(spelled + ' ' + column.sql +
      (column.clauses ? ' ' + column.clauses : ''));
    rows.push({ name: spelled, sql: column.sql,
      clauses: column.clauses || '' });
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
    rows.push({ text: one.text });
  });
  const tail = options.suffix ? ' ' + options.suffix : '';
  const table = {
    name: options.name,
    columns: columns,
    statement: options.head + ' ' + options.name + ' ( ' +
      items.join(', ') + ' )' + tail,
    script: options.head + ' ' + options.name + ' (\n' +
      layout(rows).join(',\n') + '\n)' + tail
  };
  log.debug("Leaving tableOf().");
  return table;
}

/**
 * A table's lines, with its names and types in columns.
 *
 * @param rows - columns, and constraints as text
 * @returns the lines
 */
function layout(rows) {
  log.debug("Entering layout().");
  const widest = function (key) {
    return rows.reduce(function (most, row) {
      return row[key] && row[key].length > most ? row[key].length : most;
    }, 0);
  };
  const nameWidth = widest('name');
  const sqlWidth = widest('sql');
  const lines = rows.map(function (row) {
    if (row.text) {
      return '  ' + row.text;
    }
    const start = row.name.padEnd(nameWidth) + ' ';
    return '  ' + start + (row.clauses ?
      row.sql.padEnd(sqlWidth) + ' ' + row.clauses : row.sql);
  });
  log.debug("Leaving layout().");
  return lines;
}

/**
 * The persistence namespace of a compiled program.
 *
 * @param program - the compiled program
 * @param engine - `postgres`, or `mariadb`
 * @returns the version, the tables and the driver's objects in its order
 */
export function readPersistence(program, engine) {
  log.debug("Entering readPersistence().");
  const wanted = engine || 'postgres';
  const mine = function (options) {
    return (options.engine || 'postgres') === wanted;
  };
  const tables = [];
  const objects = [];
  const add = function (name, statement, driver) {
    const object = { name: name, statement: statement };
    Object.keys(driver).forEach(function (key) {
      if (key !== 'order') {
        object[key] = driver[key];
      }
    });
    objects.push({ order: driver.order, object: object });
  };
  Array.from(program.stateMap(TABLE).entries()).filter(function (pair) {
    return mine(pair[1]);
  }).forEach(function (pair) {
    const options = pair[1];
    const table = tableOf(program, pair[0], options);
    table.indexes = options.indexes || [];
    tables.push(table);
    add(table.name, table.statement, options.driver);
    table.indexes.forEach(function (one) {
      add(one.name, one.text, one.driver);
    });
  });
  objects.sort(function (a, b) {
    return a.order - b.order;
  });
  const schema = Array.from(program.stateMap(SCHEMA).values()).filter(mine)[0] ||
    { version: 0 };
  const result = {
    version: schema.version,
    tables: tables,
    objects: objects.map(function (one) {
      return one.object;
    })
  };
  log.debug("Leaving readPersistence().");
  return result;
}

/**
 * `postgres/schema.sql`: the template with each table and index filled in.
 *
 * @param template - the text of `schema.template.sql`
 * @param persistence - the value `readPersistence()` returned
 * @returns the script
 */
export function renderScript(template, persistence) {
  log.debug("Entering renderScript().");
  const tables = new Map();
  const indexes = new Map();
  persistence.tables.forEach(function (table) {
    tables.set(table.name, table.script);
    table.indexes.forEach(function (one) {
      indexes.set(one.name, one.text);
    });
  });
  const script = template.replace(/^--@(table|index) (\S+)$/mg,
    function (line, kind, name) {
      const held = (kind === 'table' ? tables : indexes).get(name);
      if (held === undefined) {
        throw new Error('The template names ' + kind + ' ' + name +
          ', which the model does not have.');
      }
      return held + ';';
    });
  log.debug("Leaving renderScript().");
  return script;
}
