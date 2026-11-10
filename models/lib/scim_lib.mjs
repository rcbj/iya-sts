// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/lib/scim_lib.mjs
//
// ---------------------------------------------------------------------------
// THE SCIM SCHEMAS AND THEIR MAPPING, READ FROM A COMPILED PROGRAM (#1579).
//
// `readScim()` turns the `@scimSchema` models into the tables
// `models/generated/scim.json` holds: every schema with its attributes in
// RFC 7643's terms, the common attributes, the two mapping tables and the
// prose of this service's own types. `checkScim()` holds them to the
// directory objects they map onto; a problem stops the image build, because
// a SCIM member stored in an attribute nothing declares is a wrong model and
// not a warning.
//
// This is an ES module because the TypeSpec compiler loads a library with
// `import()`. It imports nothing from the compiler.
// ---------------------------------------------------------------------------

import bunyan from 'bunyan';

const log = bunyan.createLogger({
  name: 'sts-scim-lib',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

const SCHEMA = Symbol.for('iya.scim.schema');
const COMMON = Symbol.for('iya.scim.common');
const ATTRIBUTE = Symbol.for('iya.scim.attribute');
const MAPS = Symbol.for('iya.scim.maps');
const OWN = Symbol.for('iya.scim.own');

// The scalars an attribute may be, by the standard library's name or this
// library's, as RFC 7643 section 2.3 names the type.
const SCALARS = { string: 'string', boolean: 'boolean', int32: 'integer',
  int64: 'integer', integer: 'integer', safeint: 'integer',
  float64: 'decimal', decimal: 'decimal', utcDateTime: 'dateTime',
  ScimReference: 'reference', ScimBinary: 'binary' };

// The schemas scimmy ships a class for, by name: a `resource` or `shipped`
// schema replaces one of these classes' attributes, so it must name one.
const SHIPPED = ['User', 'Group', 'EnterpriseUser'];

// The directory objects each mapping table's attributes are found on.
const STORED_ON = { user: ['person', 'operational'],
                    group: ['group', 'operational'] };

export const $decorators = {
  'IyaSts.ScimLib': {
    scimSchema: function (context, target, options) {
      context.program.stateMap(SCHEMA).set(target, options);
    },
    scimCommon: function (context, target) {
      context.program.stateMap(COMMON).set(target, true);
    },
    scimAttribute: function (context, target, options) {
      context.program.stateMap(ATTRIBUTE).set(target, options);
    },
    maps: function (context, target, options) {
      const held = context.program.stateMap(MAPS).get(target) || [];
      // A decorator nearest the property is applied first, so this keeps
      // the order the author wrote them in.
      context.program.stateMap(MAPS).set(target, [options].concat(held));
    },
    scimOwnTypes: function (context, target, options) {
      context.program.stateMap(OWN).set(target, options);
    }
  }
};

/**
 * What a property's TypeSpec type says of the attribute: its RFC 7643 type,
 * whether it is multi-valued, its canonical values and its sub-attribute
 * model.
 *
 * @param type - the property's type
 * @returns `{ type, multiValued, canonicalValues?, model? }`
 */
function shapeOf(type) {
  log.debug("Entering shapeOf().");
  if (type.kind === 'Model' && type.name === 'Array' && type.indexer) {
    const element = shapeOf(type.indexer.value);
    log.debug("Leaving shapeOf(). An array.");
    return Object.assign({}, element, { multiValued: true });
  }
  if (type.kind === 'String') {
    log.debug("Leaving shapeOf(). One canonical value.");
    return { type: 'string', multiValued: false,
             canonicalValues: [type.value] };
  }
  if (type.kind === 'Union') {
    const variants = Array.from(type.variants.values()).map(function (one) {
      return one.type;
    });
    if (variants.length > 0 && variants.every(function (one) {
      return one.kind === 'String';
    })) {
      log.debug("Leaving shapeOf(). Canonical values.");
      return { type: 'string', multiValued: false,
               canonicalValues: variants.map(function (one) {
                 return one.value;
               }) };
    }
  }
  if (type.kind === 'Scalar') {
    let scalar = type;
    while (scalar && !SCALARS[scalar.name]) {
      scalar = scalar.baseScalar;
    }
    log.debug("Leaving shapeOf(). A scalar.");
    return { type: scalar ? SCALARS[scalar.name] : 'unknown',
             multiValued: false };
  }
  if (type.kind === 'Model') {
    log.debug("Leaving shapeOf(). A complex attribute.");
    return { type: 'complex', multiValued: false, model: type };
  }
  log.debug("Leaving shapeOf(). Not a type an attribute may have.");
  return { type: 'unknown', multiValued: false };
}

/**
 * The attributes of one model, in the order they are written, each with
 * every characteristic RFC 7643 section 2.2 names stated, and the mapping
 * rows found on the way.
 *
 * @param program - the compiled program
 * @param model - the model
 * @param where - how the mapping names a member of this model
 * @param rows - where the mapping rows are collected
 * @returns the attributes
 */
function attributesOf(program, model, where, rows) {
  log.debug("Entering attributesOf().");
  const out = [];
  model.properties.forEach(function (property) {
    const options = program.stateMap(ATTRIBUTE).get(property) || {};
    const shape = shapeOf(property.type);
    const path = where.path.concat([property.name]);
    const attribute = {
      name: property.name,
      type: shape.type,
      multiValued: shape.multiValued,
      description: options.description || '',
      required: property.optional !== true,
      caseExact: options.caseExact === true,
      mutability: options.mutability || 'readWrite',
      returned: options.returned || 'default',
      uniqueness: options.uniqueness || 'none',
      direction: options.direction ||
        (options.mutability === 'writeOnly' ? 'in' : 'both')
    };
    if (shape.canonicalValues) {
      attribute.canonicalValues = shape.canonicalValues;
    }
    if (options.referenceTypes) {
      attribute.referenceTypes = options.referenceTypes.slice(0);
    }
    if (options.section) {
      attribute.section = options.section;
    }
    (program.stateMap(MAPS).get(property) || []).forEach(function (map) {
      rows.push({ map: map, attribute: attribute, path: path,
                  urn: where.urn, extension: where.extension });
    });
    if (shape.model) {
      attribute.subAttributes = attributesOf(program, shape.model,
        { path: path, urn: where.urn, extension: where.extension }, rows);
    }
    out.push(attribute);
  });
  log.debug("Leaving attributesOf(). " + out.length);
  return out;
}

/**
 * One mapping row as the service reads it: the SCIM member's path, the
 * directory attribute, and what the row says of both.
 *
 * @param found - a row from `attributesOf()`
 * @param own - what each of this service's own types is called
 * @returns the row
 */
function rowOf(found, own) {
  log.debug("Entering rowOf().");
  const map = found.map;
  const dotted = found.path.join('.');
  const row = {
    table: map.table,
    row: map.row,
    scim: found.extension ? found.urn + ':' + dotted : dotted,
    ldap: map.ldap,
    kind: map.kind,
    type: map.type || null,
    // Only a `complex` row is one member of a complex value the row does
    // not name; a single sub-attribute (`name.givenName`) is its own row.
    parent: map.kind === 'complex' ? found.path[0] : null,
    extension: found.extension === true,
    readOnly: found.attribute.mutability === 'readOnly',
    required: found.attribute.required === true &&
      found.path.length === 1,
    schema: map.own ? own[map.own] : (map.cite || ''),
    note: map.note || ''
  };
  if (map.own) {
    row.own = map.own;
  }
  if (map.transform) {
    row.transform = map.transform;
  }
  if (map.alsoClears) {
    row.alsoClears = map.alsoClears.slice(0);
  }
  if (found.attribute.section) {
    row.section = found.attribute.section;
  }
  log.debug("Leaving rowOf().");
  return row;
}

/**
 * Every SCIM schema in a compiled program, the common attributes, the two
 * mapping tables and the prose of this service's own types.
 *
 * @param program - the compiled program
 * @returns `{ ownTypes, common, schemas, mapping }`
 */
export function readScim(program) {
  log.debug("Entering readScim().");
  let ownTypes = null;
  program.stateMap(OWN).forEach(function (options) {
    ownTypes = Object.assign({}, options);
  });
  const found = [];
  let common = [];
  program.stateMap(COMMON).forEach(function (flag, model) {
    common = attributesOf(program, model,
      { path: [], urn: null, extension: false }, found);
  });
  const schemas = [];
  program.stateMap(SCHEMA).forEach(function (options, model) {
    const extension = /:extension:/.test(options.id);
    const schema = {
      id: options.id,
      name: options.name,
      description: options.description,
      resource: options.resource === true,
      shipped: options.shipped === true,
      realmDefined: options.realmDefined === true,
      extension: extension,
      attributes: attributesOf(program, model,
        { path: [], urn: options.id, extension: extension }, found)
    };
    if (options.extensions) {
      schema.extensions = options.extensions.map(function (one) {
        return { schema: one.schema, required: one.required };
      });
    }
    schemas.push(schema);
  });
  const own = ownTypes || {};
  const rows = found.map(function (one) {
    return rowOf(one, own);
  });
  const table = function (name) {
    return rows.filter(function (one) {
      return one.table === name;
    }).sort(function (a, b) {
      return a.row - b.row;
    });
  };
  log.debug("Leaving readScim(). " + schemas.length + " schema(s), " +
            rows.length + " row(s).");
  return { ownTypes: ownTypes, common: common, schemas: schemas,
           mapping: { user: table('user'), group: table('group') } };
}

/**
 * The attribute names a mapping table's directory objects declare,
 * lower-cased.
 *
 * @param objects - from `readDirectory()`
 * @param table - `user` or `group`
 * @returns the set
 */
function storedNames(objects, table) {
  log.debug("Entering storedNames().");
  const names = new Set();
  objects.filter(function (object) {
    return STORED_ON[table].indexOf(object.id) >= 0;
  }).forEach(function (object) {
    object.attributes.concat(object.personAttributes || [])
      .forEach(function (attribute) {
        names.add(String(attribute.name).toLowerCase());
      });
  });
  log.debug("Leaving storedNames(). " + names.size);
  return names;
}

/**
 * One attribute's problems, and its sub-attributes'.
 *
 * @param where - the attribute's path, for the sentence
 * @param attribute - the attribute
 * @param problems - where they are collected
 */
function attributeProblems(where, attribute, problems) {
  log.debug("Entering attributeProblems().");
  const at = where + attribute.name;
  if (attribute.type === 'unknown') {
    problems.push(at + ' has a type no SCIM attribute has');
  }
  if (attribute.type === 'reference' && !attribute.referenceTypes) {
    problems.push(at + ' is a reference and names no referenceTypes');
  }
  if (attribute.type !== 'reference' && attribute.referenceTypes) {
    problems.push(at + ' names referenceTypes and is not a reference');
  }
  if (attribute.direction === 'out' && attribute.mutability !== 'readOnly') {
    problems.push(at + ' is never taken in and is not readOnly');
  }
  (attribute.subAttributes || []).forEach(function (one) {
    attributeProblems(at + '.', one, problems);
  });
  log.debug("Leaving attributeProblems().");
}

/**
 * The attribute a mapping row's SCIM path names, or undefined.
 *
 * @param scim - from `readScim()`
 * @param row - the row
 * @returns the attribute
 */
function attributeAt(scim, row) {
  log.debug("Entering attributeAt().");
  let urn = 'urn:ietf:params:scim:schemas:core:2.0:' +
    (row.table === 'group' ? 'Group' : 'User');
  let path = row.scim;
  if (row.extension) {
    const colon = row.scim.lastIndexOf(':');
    urn = row.scim.slice(0, colon);
    path = row.scim.slice(colon + 1);
  }
  const schema = scim.schemas.filter(function (one) {
    return one.id === urn;
  })[0];
  let list = (schema ? schema.attributes : []).concat(scim.common);
  let attribute;
  path.split('.').forEach(function (name) {
    attribute = (list || []).filter(function (one) {
      return one.name === name;
    })[0];
    list = attribute && attribute.subAttributes;
  });
  log.debug("Leaving attributeAt().");
  return attribute;
}

/**
 * What is wrong with the SCIM model, held to the directory objects it maps
 * onto.
 *
 * @param scim - from `readScim()`
 * @param objects - from `readDirectory()`
 * @returns the sentences, empty when there are none
 */
export function checkScim(scim, objects) {
  log.debug("Entering checkScim().");
  const problems = [];
  if (!scim.ownTypes) {
    problems.push('the SCIM model names no prose for this service\'s own ' +
      'types (@scimOwnTypes)');
  }
  if (scim.common.length === 0) {
    problems.push('the SCIM model declares no common attributes (@scimCommon)');
  }
  const ids = new Set(scim.schemas.map(function (one) {
    return one.id;
  }));
  scim.schemas.forEach(function (schema) {
    if (!/^urn:ietf:params:scim:schemas:/.test(schema.id)) {
      problems.push(schema.id + ' is not a SCIM schema URN');
    }
    if ((schema.resource || schema.shipped) &&
        SHIPPED.indexOf(schema.name) < 0) {
      problems.push(schema.id + ' replaces a schema scimmy ships, and ' +
        schema.name + ' is not one (' + SHIPPED.join(', ') + ')');
    }
    if (schema.realmDefined && schema.attributes.length > 0) {
      problems.push(schema.id + ' is the realm\'s and declares attributes');
    }
    (schema.extensions || []).forEach(function (one) {
      if (!ids.has(one.schema)) {
        problems.push(schema.id + ' is extended by ' + one.schema +
          ', which the model does not declare');
      }
    });
    schema.attributes.forEach(function (attribute) {
      attributeProblems(schema.name + '.', attribute, problems);
    });
  });
  scim.common.forEach(function (attribute) {
    attributeProblems('common.', attribute, problems);
  });
  ['user', 'group'].forEach(function (name) {
    const stored = storedNames(objects, name);
    const rows = scim.mapping[name];
    rows.forEach(function (row, index) {
      const at = name + ' row ' + row.row + ' (' + row.scim + ')';
      if (row.row !== index + 1) {
        problems.push(at + ' is out of sequence: rows are numbered from 1 ' +
          'with no gap');
      }
      if (!attributeAt(scim, row)) {
        problems.push(at + ' names no attribute the model declares');
      }
      if (!row.schema) {
        problems.push(at + ' says neither cite nor own');
      }
      if ((row.kind === 'multi') !== (row.type !== null)) {
        problems.push(at + ': a multi row, and only one, states a type');
      }
      // A derived row may describe where its value comes from in words; a
      // stored one names an attribute the directory declares.
      const isName = /^[A-Za-z][A-Za-z0-9-]*$/.test(row.ldap);
      if ((row.kind !== 'derived' || isName) &&
          !stored.has(row.ldap.toLowerCase())) {
        problems.push(at + ' is kept in ' + row.ldap + ', which no ' +
          'directory object declares');
      }
      (row.alsoClears || []).forEach(function (one) {
        if (!stored.has(one.toLowerCase())) {
          problems.push(at + ' clears ' + one + ', which no directory ' +
            'object declares');
        }
      });
      if (row.required && !row.section) {
        problems.push(at + ' is required and names no section to cite');
      }
    });
    // The types of a multi-valued member are exactly its rows' types, in
    // the rows' order: a type with no row would be taken and stored
    // nowhere.
    const members = {};
    rows.filter(function (row) {
      return row.kind === 'multi';
    }).forEach(function (row) {
      members[row.scim] = (members[row.scim] || []).concat([row.type]);
    });
    rows.filter(function (row) {
      return row.kind === 'complex';
    }).forEach(function (row) {
      members[row.parent] = members[row.parent] || null;
    });
    Object.keys(members).forEach(function (member) {
      const type = attributeAt(scim, { table: name, scim: member + '.type',
                                       extension: false });
      const values = type && type.canonicalValues;
      if (!values) {
        problems.push(name + '.' + member + ' has rows and no canonical ' +
          'types');
      } else if (members[member] === null && values.length !== 1) {
        problems.push(name + '.' + member + ' is one complex value and ' +
          'offers ' + values.length + ' types');
      } else if (members[member] !== null &&
                 values.join(',') !== members[member].join(',')) {
        problems.push(name + '.' + member + ' offers ' + values.join(',') +
          ' and its rows store ' + members[member].join(','));
      }
    });
  });
  log.debug("Leaving checkScim(). " + problems.length);
  return problems;
}
