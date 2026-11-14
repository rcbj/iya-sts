// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/lib/spiffe_lib.mjs
//
// ---------------------------------------------------------------------------
// THE SPIFFE MODEL, READ FROM A COMPILED PROGRAM (#1579).
//
// `readSpiffe()` turns the `@grpcService`, `@message`, `@protoEnum`,
// `@idGrammar`, `@svidRules`, `@members` and `@registry` declarations into
// the tables `models/generated/spiffe.json` holds: every service with its
// methods, how each streams and the statuses it answers; every message with
// its fields, each field's number, type and the refusals of it; the SPIFFE
// ID grammar; an X509-SVID's leaf rules; the bundle's, a JWK's and a
// JWT-SVID's members; and the registries. `describeProtos()` reads the
// vendored `.proto` files the service decodes with, and `checkSpiffe()`
// holds the model to them — every service, method, message, field, number,
// type, oneof and enum value — and refuses a model a check could not be
// generated from faithfully. A problem stops the image build.
//
// This is an ES module because the TypeSpec compiler loads a library with
// `import()`. It imports nothing from the compiler; `describeProtos()` is
// handed protobufjs by its caller.
// ---------------------------------------------------------------------------

import bunyan from 'bunyan';

const log = bunyan.createLogger({
  name: 'sts-spiffe-lib',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

const SERVICE = Symbol.for('iya.spiffe.service');
const RPC = Symbol.for('iya.spiffe.rpc');
const MESSAGE = Symbol.for('iya.spiffe.message');
const FIELD = Symbol.for('iya.spiffe.field');
const ONEOF = Symbol.for('iya.spiffe.oneof');
const ENUM = Symbol.for('iya.spiffe.enum');
const REFUSE = Symbol.for('iya.spiffe.refuse');
const GRAMMAR = Symbol.for('iya.spiffe.grammar');
const SVID = Symbol.for('iya.spiffe.svid');
const MEMBERS = Symbol.for('iya.spiffe.members');
const MEMBER = Symbol.for('iya.spiffe.member');
const REGISTRY = Symbol.for('iya.spiffe.registry');

// The protobuf scalar each TypeSpec scalar is.
const SCALARS = { string: 'string', boolean: 'bool', int32: 'int32',
  int64: 'int64', uint32: 'uint32', uint64: 'uint64', bytes: 'bytes',
  float32: 'float', float64: 'double' };

// The JSON types each scalar's value may take on a member of a document.
const JSON_SCALARS = { string: 'string', boolean: 'boolean',
  int32: 'integer', int64: 'integer', uint32: 'integer', uint64: 'integer',
  integer: 'integer', float32: 'number', float64: 'number',
  numeric: 'number', unknown: 'any' };

// grpc-js's status names, and the numbers they are on the wire.
export const STATUSES = { OK: 0, CANCELLED: 1, UNKNOWN: 2,
  INVALID_ARGUMENT: 3, DEADLINE_EXCEEDED: 4, NOT_FOUND: 5,
  ALREADY_EXISTS: 6, PERMISSION_DENIED: 7, RESOURCE_EXHAUSTED: 8,
  FAILED_PRECONDITION: 9, ABORTED: 10, OUT_OF_RANGE: 11, UNIMPLEMENTED: 12,
  INTERNAL: 13, UNAVAILABLE: 14, DATA_LOSS: 15, UNAUTHENTICATED: 16 };

/**
 * Records a decorator's value on its target, keeping every one where a
 * target may carry several.
 *
 * @param context - the decorator context
 * @param key - the state map
 * @param target - the type
 * @param value - the value
 */
function keep(context, key, target, value) {
  log.debug("Entering keep().");
  const map = context.program.stateMap(key);
  const list = map.get(target) || [];
  list.push(value);
  map.set(target, list);
  log.debug("Leaving keep().");
}

export const $decorators = {
  'IyaSts.SpiffeLib': {
    grpcService: function (context, target, options) {
      context.program.stateMap(SERVICE).set(target, options);
    },
    rpc: function (context, target, options) {
      context.program.stateMap(RPC).set(target, options);
    },
    message: function (context, target, name) {
      context.program.stateMap(MESSAGE).set(target, name);
    },
    field: function (context, target, num) {
      context.program.stateMap(FIELD).set(target, num);
    },
    oneof: function (context, target, name) {
      context.program.stateMap(ONEOF).set(target, name);
    },
    protoEnum: function (context, target, name) {
      context.program.stateMap(ENUM).set(target, name);
    },
    refuse: function (context, target, options) {
      keep(context, REFUSE, target, options);
    },
    idGrammar: function (context, target, options) {
      context.program.stateMap(GRAMMAR).set(target, options);
    },
    svidRules: function (context, target, options) {
      context.program.stateMap(SVID).set(target, options);
    },
    members: function (context, target, options) {
      context.program.stateMap(MEMBERS).set(target, options);
    },
    member: function (context, target, options) {
      context.program.stateMap(MEMBER).set(target, options);
    },
    registry: function (context, target, options) {
      context.program.stateMap(REGISTRY).set(target, options);
    }
  }
};

/**
 * Whether a TypeSpec type is an array.
 *
 * @param type - the type
 * @returns true for `T[]`
 */
function isArray(type) {
  log.debug("Entering isArray().");
  log.debug("Leaving isArray().");
  return type.kind === 'Model' && type.name === 'Array' && !!type.indexer;
}

/**
 * Whether a TypeSpec type is a map.
 *
 * @param type - the type
 * @returns true for `Record<T>`
 */
function isMap(type) {
  log.debug("Entering isMap().");
  log.debug("Leaving isMap().");
  return type.kind === 'Model' && type.name === 'Record' && !!type.indexer;
}

/**
 * The proto type of one field's (or one value's) TypeSpec type.
 *
 * @param program - the compiled program
 * @param type - the type, an array's or a map's element already taken
 * @returns `{ kind: 'scalar', scalar }`, `{ kind: 'message', name }`,
 *   `{ kind: 'enum', name }`, or `{ kind: 'unknown', name }`
 */
function protoTypeOf(program, type) {
  log.debug("Entering protoTypeOf().");
  if (type.kind === 'Scalar') {
    let scalar = type;
    while (scalar && !SCALARS[scalar.name]) {
      scalar = scalar.baseScalar;
    }
    log.debug("Leaving protoTypeOf(). A scalar.");
    return scalar ? { kind: 'scalar', scalar: SCALARS[scalar.name] }
      : { kind: 'unknown', name: type.name };
  }
  if (type.kind === 'Model' && program.stateMap(MESSAGE).has(type)) {
    log.debug("Leaving protoTypeOf(). A message.");
    return { kind: 'message', name: program.stateMap(MESSAGE).get(type) };
  }
  if (type.kind === 'Enum' && program.stateMap(ENUM).has(type)) {
    log.debug("Leaving protoTypeOf(). An enum.");
    return { kind: 'enum', name: program.stateMap(ENUM).get(type) };
  }
  log.debug("Leaving protoTypeOf(). Not a proto type.");
  return { kind: 'unknown', name: type.name || type.kind };
}

/**
 * One field of a message.
 *
 * @param program - the compiled program
 * @param property - the property
 * @returns the field
 */
function fieldOf(program, property) {
  log.debug("Entering fieldOf().");
  let type = property.type;
  const repeated = isArray(type);
  const map = isMap(type);
  if (repeated || map) {
    type = type.indexer.value;
  }
  const out = {
    name: property.name,
    number: program.stateMap(FIELD).get(property),
    type: protoTypeOf(program, type),
    repeated: repeated,
    map: map,
    optional: property.optional === true
  };
  const oneof = program.stateMap(ONEOF).get(property);
  if (oneof) {
    out.oneof = oneof;
  }
  const refusals = program.stateMap(REFUSE).get(property);
  if (refusals && refusals.length) {
    out.refusals = refusals.map(function (one) {
      const out = { when: one.when, status: one.status, code: one.code,
                    message: one.message, cite: one.cite };
      if (one.method) {
        out.method = one.method;
      }
      if (one.errorInfo) {
        out.errorInfo = one.errorInfo;
      }
      return out;
    });
  }
  log.debug("Leaving fieldOf().");
  return out;
}

/**
 * The JSON types a member's TypeSpec type may be.
 *
 * @param type - the type
 * @returns the names
 */
function jsonTypesOf(type) {
  log.debug("Entering jsonTypesOf().");
  if (isArray(type)) {
    log.debug("Leaving jsonTypesOf(). An array.");
    return ['array'];
  }
  if (type.kind === 'Model') {
    log.debug("Leaving jsonTypesOf(). An object.");
    return ['object'];
  }
  if (type.kind === 'String') {
    log.debug("Leaving jsonTypesOf(). A string literal.");
    return ['string'];
  }
  if (type.kind === 'Union') {
    const out = [];
    type.variants.forEach(function (variant) {
      jsonTypesOf(variant.type).forEach(function (one) {
        if (out.indexOf(one) < 0) {
          out.push(one);
        }
      });
    });
    log.debug("Leaving jsonTypesOf(). A union.");
    return out;
  }
  if (type.kind === 'Scalar') {
    let scalar = type;
    while (scalar && !JSON_SCALARS[scalar.name]) {
      scalar = scalar.baseScalar;
    }
    log.debug("Leaving jsonTypesOf(). A scalar.");
    return [scalar ? JSON_SCALARS[scalar.name] : 'unknown'];
  }
  log.debug("Leaving jsonTypesOf(). Not a JSON type.");
  return ['unknown'];
}

/**
 * The string literals of a union, or null when it holds anything else.
 *
 * @param type - the type
 * @returns the values
 */
function literalsOf(type) {
  log.debug("Entering literalsOf().");
  if (type.kind === 'String') {
    log.debug("Leaving literalsOf(). One.");
    return [type.value];
  }
  if (type.kind !== 'Union') {
    log.debug("Leaving literalsOf(). Not a union.");
    return null;
  }
  const out = [];
  let all = true;
  type.variants.forEach(function (variant) {
    if (variant.type.kind === 'String') {
      out.push(variant.type.value);
    } else {
      all = false;
    }
  });
  log.debug("Leaving literalsOf().");
  return all ? out : null;
}

/**
 * One member of a document.
 *
 * @param program - the compiled program
 * @param property - the property
 * @returns the member
 */
function memberOf(program, property) {
  log.debug("Entering memberOf().");
  const options = program.stateMap(MEMBER).get(property) || {};
  const out = {
    name: property.name,
    types: jsonTypesOf(property.type),
    required: property.optional !== true,
    cite: options.cite || ''
  };
  const values = literalsOf(property.type);
  if (values) {
    out.values = values;
  }
  let inner = property.type;
  if (isArray(inner)) {
    inner = inner.indexer.value;
    out.items = jsonTypesOf(inner);
  }
  if (inner.kind === 'Model' && program.stateMap(MEMBERS).has(inner)) {
    out.set = program.stateMap(MEMBERS).get(inner).id;
  }
  if (inner.kind === 'Union') {
    const itemValues = literalsOf(inner);
    if (itemValues && isArray(property.type)) {
      out.itemValues = itemValues;
    }
  }
  if (options.own === true) {
    out.own = true;
  }
  log.debug("Leaving memberOf().");
  return out;
}

/**
 * Every SPIFFE declaration in a compiled program.
 *
 * @param program - the compiled program
 * @returns `{ grammar, svid, services, messages, enums, members,
 *   registries, statuses }`
 */
export function readSpiffe(program) {
  log.debug("Entering readSpiffe().");
  const services = [];
  program.stateMap(SERVICE).forEach(function (options, iface) {
    const methods = [];
    iface.operations.forEach(function (op) {
      const rpc = program.stateMap(RPC).get(op) || {};
      const param = op.parameters.properties.get('request');
      const method = {
        name: op.name,
        stream: rpc.stream || '',
        request: param ? protoTypeOf(program, param.type).name : '',
        response: protoTypeOf(program, op.returnType).name,
        statuses: (rpc.statuses || []).slice(0)
      };
      if (rpc.unimplemented) {
        method.unimplemented = rpc.unimplemented;
      }
      methods.push(method);
    });
    services.push({ name: options.name, surface: options.surface,
                    statuses: options.statuses.slice(0),
                    cite: options.cite, methods: methods });
  });
  const messages = {};
  program.stateMap(MESSAGE).forEach(function (name, model) {
    const fields = [];
    model.properties.forEach(function (property) {
      fields.push(fieldOf(program, property));
    });
    messages[name] = { model: model.name, fields: fields };
  });
  const enums = {};
  program.stateMap(ENUM).forEach(function (name, type) {
    const values = {};
    type.members.forEach(function (member) {
      values[member.name] = member.value === undefined ? null : member.value;
    });
    enums[name] = { values: values };
  });
  let grammar = null;
  program.stateMap(GRAMMAR).forEach(function (options) {
    grammar = Object.assign({}, options);
  });
  let svid = null;
  program.stateMap(SVID).forEach(function (options) {
    svid = { leaf: options.leaf.map(function (rule) {
      return Object.assign({}, rule, rule.excludes
        ? { excludes: rule.excludes.slice(0) } : {});
    }), cite: options.cite };
  });
  const members = [];
  program.stateMap(MEMBERS).forEach(function (options, model) {
    const list = [];
    model.properties.forEach(function (property) {
      list.push(memberOf(program, property));
    });
    members.push({ id: options.id, cite: options.cite,
                   members: options.members, model: model.name,
                   list: list });
  });
  const registries = {};
  program.stateMap(REGISTRY).forEach(function (options, union) {
    registries[options.id] = { cite: options.cite,
                               values: literalsOf(union) };
  });
  log.debug("Leaving readSpiffe(). " + services.length + " service(s), " +
            Object.keys(messages).length + " message(s).");
  return { statuses: STATUSES, grammar: grammar, svid: svid,
           services: services, messages: messages, enums: enums,
           members: members, registries: registries };
}

/**
 * The messages, enums and services of the vendored protos, as protobufjs
 * reads them with the options the service loads them with (`keepCase`, so a
 * field is spelt as in the file; protobufjs's own well-known types keep
 * their camelCase, which is the spelling a handler must write).
 *
 * @param protobuf - the protobufjs module
 * @param pathModule - node's `path`
 * @param dir - the directory of the `.proto` files
 * @param files - the files, relative to it
 * @returns `{ messages, enums, services }`
 */
export function describeProtos(protobuf, pathModule, dir, files) {
  log.debug("Entering describeProtos().");
  const root = new protobuf.Root();
  root.resolvePath = function (origin, target) {
    return pathModule.isAbsolute(target) ? target
      : pathModule.join(dir, target);
  };
  root.loadSync(files.map(function (one) {
    return pathModule.join(dir, one);
  }), { keepCase: true });
  root.resolveAll();
  const out = { messages: {}, enums: {}, services: {} };
  const nameOf = function (type) {
    return type.fullName.replace(/^\./, '');
  };
  const walk = function (ns) {
    (ns.nestedArray || []).forEach(function (one) {
      if (one instanceof protobuf.Type) {
        out.messages[nameOf(one)] = { fields: one.fieldsArray.map(function (f) {
          const field = { name: f.name, number: f.id, repeated: f.repeated,
                          map: !!f.map };
          if (f.resolvedType instanceof protobuf.Type) {
            field.type = { kind: 'message', name: nameOf(f.resolvedType) };
          } else if (f.resolvedType instanceof protobuf.Enum) {
            field.type = { kind: 'enum', name: nameOf(f.resolvedType) };
          } else {
            field.type = { kind: 'scalar', scalar: f.type };
          }
          if (f.partOf && !(f.partOf.name.charAt(0) === '_' &&
                            f.partOf.oneof.length === 1)) {
            field.oneof = f.partOf.name;
          }
          return field;
        }) };
      } else if (one instanceof protobuf.Enum) {
        out.enums[nameOf(one)] = { values: Object.assign({}, one.values) };
      } else if (one instanceof protobuf.Service) {
        const methods = {};
        one.methodsArray.forEach(function (m) {
          methods[m.name] = {
            request: nameOf(m.resolvedRequestType),
            response: nameOf(m.resolvedResponseType),
            stream: m.requestStream ? 'bidi'
              : (m.responseStream ? 'server' : 'unary')
          };
        });
        out.services[nameOf(one)] = { methods: methods };
      }
      if (one.nestedArray && !(one instanceof protobuf.Enum)) {
        walk(one);
      }
    });
  };
  walk(root);
  log.debug("Leaving describeProtos(). " + Object.keys(out.messages).length +
            " message(s).");
  return out;
}

/**
 * Every message a service's methods reach, through their fields.
 *
 * @param protos - from `describeProtos()`
 * @returns the names
 */
function reachable(protos) {
  log.debug("Entering reachable().");
  const seen = new Set();
  const visit = function (name) {
    if (seen.has(name) || !protos.messages[name]) {
      return;
    }
    seen.add(name);
    protos.messages[name].fields.forEach(function (field) {
      if (field.type.kind === 'message') {
        visit(field.type.name);
      }
    });
  };
  Object.keys(protos.services).forEach(function (name) {
    const methods = protos.services[name].methods;
    Object.keys(methods).forEach(function (m) {
      visit(methods[m].request);
      visit(methods[m].response);
    });
  });
  log.debug("Leaving reachable().");
  return seen;
}

/**
 * The problems of one field's refusals.
 *
 * @param at - the field, for the sentence
 * @param field - from `readSpiffe()`
 * @param problems - where a problem is added
 */
function refusalProblems(at, field, problems) {
  log.debug("Entering refusalProblems().");
  const whens = new Set();
  (field.refusals || []).forEach(function (one) {
    const key = one.when + ' ' + (one.method || '');
    if (whens.has(key)) {
      problems.push(at + ' is refused twice when ' + one.when +
                    (one.method ? ' in ' + one.method : ''));
    }
    whens.add(key);
    if (STATUSES[one.status] === undefined || one.status === 'OK') {
      problems.push(at + '\'s refusal answers ' + one.status +
                    ', which is not a refusal status');
    }
    if (!/^STS-SPIFFE-\d{4}$/.test(one.code)) {
      problems.push(at + '\'s refusal code ' + one.code + ' is not a ' +
                    'SPIFFE error code');
    }
    if (!one.message) {
      problems.push(at + '\'s refusal says nothing');
    }
    if (!one.cite) {
      problems.push(at + '\'s refusal cites nothing');
    }
    if (one.message.indexOf('{reason}') >= 0 && one.when !== 'malformed') {
      problems.push(at + '\'s refusal has a {reason} only a malformed ' +
                    'SPIFFE ID gives');
    }
    if (one.when === 'malformed' &&
        (field.type.kind !== 'scalar' || field.type.scalar !== 'string')) {
      problems.push(at + ' is refused as a malformed SPIFFE ID and is not ' +
                    'a string');
    }
  });
  log.debug("Leaving refusalProblems().");
}

/**
 * The problems of one message against the vendored one.
 *
 * @param name - the message's full name
 * @param model - from `readSpiffe()`
 * @param proto - from `describeProtos()`, or undefined
 * @param problems - where a problem is added
 */
function messageProblems(name, model, proto, problems) {
  log.debug("Entering messageProblems().");
  if (!proto) {
    problems.push('the message ' + name + ' is in no vendored proto');
    log.debug("Leaving messageProblems(). Not vendored.");
    return;
  }
  const byName = new Map();
  proto.fields.forEach(function (f) {
    byName.set(f.name, f);
  });
  const named = new Set();
  model.fields.forEach(function (field) {
    const at = name + '.' + field.name;
    named.add(field.name);
    refusalProblems(at, field, problems);
    const wanted = byName.get(field.name);
    if (!wanted) {
      problems.push(at + ' is no field of the vendored message');
      return;
    }
    if (field.number !== wanted.number) {
      problems.push(at + ' is field ' + field.number + ' and the vendored ' +
                    'one is ' + wanted.number);
    }
    if (field.repeated !== wanted.repeated || field.map !== wanted.map) {
      problems.push(at + ' repeats or maps where the vendored field does not');
    }
    if (JSON.stringify(field.type) !== JSON.stringify(wanted.type)) {
      problems.push(at + ' is ' + JSON.stringify(field.type) + ' and the ' +
                    'vendored field is ' + JSON.stringify(wanted.type));
    }
    if ((field.oneof || '') !== (wanted.oneof || '')) {
      problems.push(at + ' is in the oneof ' + (field.oneof || 'none') +
                    ' and the vendored field in ' + (wanted.oneof || 'none'));
    }
    if (!field.optional) {
      problems.push(at + ' is required, and proto3 has no required field');
    }
  });
  proto.fields.forEach(function (f) {
    if (!named.has(f.name)) {
      problems.push(name + '.' + f.name + ' (field ' + f.number + ') is not ' +
                    'in the model');
    }
  });
  log.debug("Leaving messageProblems().");
}

/**
 * Holds the model to the vendored protos and to what a check can be
 * generated from.
 *
 * @param spiffe - from `readSpiffe()`
 * @param protos - from `describeProtos()`
 * @returns the problems, empty when there are none
 */
export function checkSpiffe(spiffe, protos) {
  log.debug("Entering checkSpiffe().");
  const problems = [];
  const services = new Set();
  spiffe.services.forEach(function (service) {
    services.add(service.name);
    const vendored = protos.services[service.name];
    if (!service.cite) {
      problems.push('the service ' + service.name + ' cites nothing');
    }
    service.statuses.forEach(function (one) {
      if (STATUSES[one] === undefined) {
        problems.push('the service ' + service.name + ' answers ' + one +
                      ', which is no gRPC status');
      }
    });
    if (!vendored) {
      problems.push('the service ' + service.name + ' is in no vendored ' +
                    'proto');
      return;
    }
    const methods = new Set();
    service.methods.forEach(function (method) {
      const at = service.name + '/' + method.name;
      methods.add(method.name);
      const wanted = vendored.methods[method.name];
      if (!wanted) {
        problems.push(at + ' is no method of the vendored service');
        return;
      }
      ['request', 'response', 'stream'].forEach(function (key) {
        if (method[key] !== wanted[key]) {
          problems.push(at + '\'s ' + key + ' is ' + method[key] + ' and the ' +
                        'vendored one is ' + wanted[key]);
        }
      });
      method.statuses.forEach(function (one) {
        if (STATUSES[one] === undefined) {
          problems.push(at + ' answers ' + one + ', which is no gRPC status');
        }
      });
      if (method.unimplemented !== undefined && !method.unimplemented) {
        problems.push(at + ' is unimplemented and says not why');
      }
    });
    Object.keys(vendored.methods).forEach(function (name) {
      if (!methods.has(name)) {
        problems.push(service.name + '/' + name + ' is not in the model');
      }
    });
  });
  Object.keys(protos.services).forEach(function (name) {
    if (!services.has(name)) {
      problems.push('the vendored service ' + name + ' is not in the model');
    }
  });
  Object.keys(spiffe.messages).forEach(function (name) {
    messageProblems(name, spiffe.messages[name], protos.messages[name],
                    problems);
  });
  reachable(protos).forEach(function (name) {
    if (!spiffe.messages[name]) {
      problems.push('the message ' + name + ', which a method reaches, is ' +
                    'not in the model');
    }
  });
  Object.keys(spiffe.enums).forEach(function (name) {
    const vendored = protos.enums[name];
    if (!vendored) {
      problems.push('the enum ' + name + ' is in no vendored proto');
    } else if (JSON.stringify(spiffe.enums[name].values) !==
               JSON.stringify(vendored.values)) {
      problems.push('the enum ' + name + '\'s values are not the vendored ' +
                    'ones');
    }
  });
  const grammar = spiffe.grammar;
  if (!grammar) {
    problems.push('the SPIFFE ID grammar is not declared');
  } else {
    ['trustDomainPattern', 'pathSegmentPattern'].forEach(function (key) {
      try {
        new RegExp(grammar[key]);
      } catch (e) {
        log.debug("Caught in checkSpiffe(): " + ((e && e.message) || e));
        problems.push('the grammar\'s ' + key + ' does not compile: ' +
                      e.message);
      }
    });
    if (!(grammar.maxBytes > 0) || !(grammar.maxTrustDomainBytes > 0)) {
      problems.push('the grammar\'s byte bounds are not positive');
    }
    if (grammar.reservedPrefix.charAt(0) !== '/') {
      problems.push('the grammar\'s reserved prefix is not a path');
    }
    if (!grammar.cite) {
      problems.push('the grammar cites nothing');
    }
  }
  if (!spiffe.svid || !spiffe.svid.leaf.length) {
    problems.push('no X509-SVID leaf rule is declared');
  } else {
    spiffe.svid.leaf.forEach(function (rule, i) {
      const kinds = ['equals', 'includes', 'excludes'].filter(function (key) {
        return rule[key] !== undefined;
      });
      if (kinds.length !== 1) {
        problems.push('the X509-SVID leaf rule ' + i + ' states ' +
                      (kinds.join(', ') || 'nothing'));
      }
      if (rule.fact === 'ca' && rule.equals === undefined) {
        problems.push('the X509-SVID leaf rule ' + i + ' reads ca and ' +
                      'states no value');
      }
      if (rule.fact === 'keyUsage' && rule.equals !== undefined) {
        problems.push('the X509-SVID leaf rule ' + i + ' reads keyUsage ' +
                      'and states a value');
      }
    });
  }
  const sets = new Set();
  spiffe.members.forEach(function (set) {
    if (sets.has(set.id)) {
      problems.push('the member set ' + set.id + ' is declared twice');
    }
    sets.add(set.id);
    if (!set.cite) {
      problems.push('the member set ' + set.id + ' cites nothing');
    }
    set.list.forEach(function (member) {
      if (!member.cite) {
        problems.push(set.id + '.' + member.name + ' cites nothing');
      }
      if (member.types.indexOf('unknown') >= 0) {
        problems.push(set.id + '.' + member.name + ' has a type no JSON ' +
                      'value is');
      }
    });
  });
  Object.keys(spiffe.registries).forEach(function (id) {
    const one = spiffe.registries[id];
    if (!one.values || !one.values.length) {
      problems.push('the registry ' + id + ' is not a list of strings');
    }
    if (!one.cite) {
      problems.push('the registry ' + id + ' cites nothing');
    }
  });
  log.debug("Leaving checkSpiffe(). " + problems.length + " problem(s).");
  return problems;
}
