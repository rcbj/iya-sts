// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/lib/saml_lib.mjs
//
// ---------------------------------------------------------------------------
// THE SAML MODEL, READ FROM A COMPILED PROGRAM (#1579).
//
// `readSaml()` turns the `@vocabulary`, `@message` and `@params` models into
// the tables `models/generated/saml.json` holds: every vocabulary's terms
// with what this service does with each, every message's attributes and
// child elements in the order the schema's sequence has them, and every
// parameter set. `checkSaml()` refuses a model a reader or a writer could
// not be built from faithfully — a value or a name declared twice, a term
// flag on a vocabulary it does not apply to, a fixed value the attribute
// does not accept, an element naming a message nobody declares, an
// `equivalent` naming no term, a missing citation — and the problem stops
// the image build.
//
// This is an ES module because the TypeSpec compiler loads a library with
// `import()`. It imports nothing from the compiler.
// ---------------------------------------------------------------------------

import bunyan from 'bunyan';

const log = bunyan.createLogger({
  name: 'sts-saml-lib',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

const VOCABULARY = Symbol.for('iya.saml.vocabulary');
const TERM = Symbol.for('iya.saml.term');
const MESSAGE = Symbol.for('iya.saml.message');
const ATTRIBUTE = Symbol.for('iya.saml.attribute');
const ELEMENT = Symbol.for('iya.saml.element');
const PARAMS = Symbol.for('iya.saml.params');
const PARAM = Symbol.for('iya.saml.param');

// The term flags, and the vocabularies (by the end of their id) each applies
// to.
const TERM_FLAGS = {
  level: ['.status'],
  advertised: ['.nameIdFormat'],
  request: ['.binding'],
  response: ['.binding'],
  carries: ['.binding'],
  mfaDemand: ['.authnContext'],
  equivalent: ['.authnContext', '.authnMethod'],
  answered: ['.request'],
  readOnly: ['']
};

export const $decorators = {
  'IyaSts.SamlLib': {
    vocabulary: function (context, target, options) {
      context.program.stateMap(VOCABULARY).set(target, options);
    },
    term: function (context, target, options) {
      context.program.stateMap(TERM).set(target, options);
    },
    message: function (context, target, options) {
      context.program.stateMap(MESSAGE).set(target, options);
    },
    attribute: function (context, target, options) {
      context.program.stateMap(ATTRIBUTE).set(target, options);
    },
    element: function (context, target, options) {
      context.program.stateMap(ELEMENT).set(target, options);
    },
    params: function (context, target, options) {
      context.program.stateMap(PARAMS).set(target, options);
    },
    param: function (context, target, options) {
      context.program.stateMap(PARAM).set(target, options);
    }
  }
};

/**
 * How an attribute's TypeSpec type is read: `boolean` (xs:boolean, true only
 * for "true") or `text`.
 *
 * @param type - the TypeSpec type
 * @returns the reading
 */
function readingOf(type) {
  log.debug("Entering readingOf().");
  let scalar = type;
  while (scalar && scalar.kind === 'Scalar' && scalar.name !== 'boolean' &&
         scalar.baseScalar) {
    scalar = scalar.baseScalar;
  }
  const out = scalar && (scalar.kind === 'Boolean' ||
                         (scalar.kind === 'Scalar' &&
                          scalar.name === 'boolean')) ? 'boolean' : 'text';
  log.debug("Leaving readingOf(). " + out);
  return out;
}

/**
 * The SAML model a compiled program declares.
 *
 * @param program - the compiled program
 * @returns `{ vocabularies, messages, params }`
 */
export function readSaml(program) {
  log.debug("Entering readSaml().");
  const vocabularies = {};
  program.stateMap(VOCABULARY).forEach(function (options, model) {
    const terms = [];
    model.properties.forEach(function (property) {
      const one = program.stateMap(TERM).get(property) || {};
      const term = { name: property.name,
                     value: property.type.kind === 'String'
                       ? property.type.value : null,
                     cite: one.cite || '' };
      Object.keys(TERM_FLAGS).forEach(function (flag) {
        if (one[flag] !== undefined) {
          term[flag] = Array.isArray(one[flag]) ? one[flag].slice(0)
                                                : one[flag];
        }
      });
      terms.push(term);
    });
    const out = { cite: options.cite, model: model.name, terms: terms };
    if (options.prefix !== undefined) {
      out.prefix = options.prefix;
    }
    vocabularies[options.id] = out;
  });
  const messages = {};
  program.stateMap(MESSAGE).forEach(function (options, model) {
    const attributes = [];
    const elements = [];
    model.properties.forEach(function (property) {
      const attribute = program.stateMap(ATTRIBUTE).get(property);
      const element = program.stateMap(ELEMENT).get(property);
      if (attribute) {
        const one = { name: property.name, xml: attribute.xml,
                      reading: readingOf(property.type),
                      required: property.optional !== true,
                      cite: attribute.cite || '' };
        ['fixed', 'accepts', 'read', 'written'].forEach(function (key) {
          if (attribute[key] !== undefined) {
            one[key] = Array.isArray(attribute[key])
              ? attribute[key].slice(0) : attribute[key];
          }
        });
        attributes.push(one);
      } else if (element) {
        const held = property.type;
        const one = { name: property.name, xml: element.xml,
                      occurs: element.occurs, cite: element.cite || '' };
        if (held && held.kind === 'Model' &&
            program.stateMap(MESSAGE).has(held)) {
          one.message = program.stateMap(MESSAGE).get(held).id;
        }
        ['or', 'written', 'signer', 'read'].forEach(function (key) {
          if (element[key] !== undefined) {
            one[key] = Array.isArray(element[key]) ? element[key].slice(0)
                                                   : element[key];
          }
        });
        elements.push(one);
      } else {
        elements.push({ name: property.name, undecorated: true });
      }
    });
    messages[options.id] = { cite: options.cite, model: model.name,
                             element: options.element,
                             xmlns: options.xmlns,
                             direction: options.direction,
                             attributes: attributes, elements: elements };
  });
  const params = {};
  program.stateMap(PARAMS).forEach(function (options, model) {
    const list = [];
    model.properties.forEach(function (property) {
      const one = program.stateMap(PARAM).get(property) || {};
      const param = { name: property.name, wire: one.wire || '',
                      cite: one.cite || '' };
      if (one.nonSpec === true) {
        param.nonSpec = true;
      }
      if (one.accepts !== undefined) {
        param.accepts = one.accepts.slice(0);
      }
      list.push(param);
    });
    params[options.id] = { cite: options.cite, model: model.name,
                           params: list };
  });
  log.debug("Leaving readSaml(). " + Object.keys(vocabularies).length +
            " vocabularies, " + Object.keys(messages).length +
            " messages, " + Object.keys(params).length + " parameter sets.");
  return { vocabularies: vocabularies, messages: messages, params: params };
}

/**
 * The problems that keep the SAML model from building, each a sentence.
 *
 * @param saml - what `readSaml()` read
 * @returns the problems; empty when there are none
 */
export function checkSaml(saml) {
  log.debug("Entering checkSaml().");
  const problems = [];
  Object.keys(saml.vocabularies).forEach(function (id) {
    const vocabulary = saml.vocabularies[id];
    if (!vocabulary.cite) {
      problems.push('the vocabulary ' + id + ' cites nothing');
    }
    const values = new Set();
    vocabulary.terms.forEach(function (term) {
      const where = id + '.' + term.name;
      if (typeof term.value !== 'string' || !term.value) {
        problems.push(where + ' is not a string literal');
      } else if (values.has(term.value)) {
        problems.push(where + ' repeats the value ' + term.value);
      } else {
        values.add(term.value);
      }
      if (!term.cite) {
        problems.push(where + ' cites nothing');
      }
      if (vocabulary.prefix && term.value &&
          term.value.indexOf(vocabulary.prefix) !== 0 &&
          term.readOnly !== true && !/^(http|urn:ietf)/.test(term.value)) {
        problems.push(where + ' does not begin with the vocabulary\'s ' +
                      'prefix ' + vocabulary.prefix);
      }
      Object.keys(TERM_FLAGS).forEach(function (flag) {
        const applies = TERM_FLAGS[flag].some(function (end) {
          return id.slice(id.length - end.length) === end;
        });
        if (term[flag] !== undefined && !applies) {
          problems.push(where + ' carries ' + flag + ', which a term of ' +
                        id + ' cannot');
        }
      });
    });
  });
  // An equivalent names a term of the other vocabulary of the pair.
  Object.keys(saml.vocabularies).forEach(function (id) {
    saml.vocabularies[id].terms.forEach(function (term) {
      if (term.equivalent === undefined) {
        return;
      }
      const found = Object.keys(saml.vocabularies).some(function (other) {
        return other !== id && /\.(authnContext|authnMethod)$/.test(other) &&
          saml.vocabularies[other].terms.some(function (one) {
            return one.name === term.equivalent;
          });
      });
      if (!found) {
        problems.push(id + '.' + term.name + '\'s equivalent ' +
                      term.equivalent + ' is no term of the other ' +
                      'version\'s vocabulary');
      }
    });
  });
  Object.keys(saml.messages).forEach(function (id) {
    const message = saml.messages[id];
    if (!message.cite) {
      problems.push('the message ' + id + ' cites nothing');
    }
    const names = new Set();
    const xmls = new Set();
    message.attributes.forEach(function (one) {
      const where = id + '@' + one.xml;
      if (names.has(one.name) || xmls.has('@' + one.xml)) {
        problems.push(where + ' is declared twice');
      }
      names.add(one.name);
      xmls.add('@' + one.xml);
      if (!one.cite) {
        problems.push(where + ' cites nothing');
      }
      if (one.fixed !== undefined && one.accepts !== undefined &&
          one.accepts.indexOf(one.fixed) < 0) {
        problems.push(where + ' is fixed at ' + one.fixed +
                      ', which it does not accept');
      }
      if (one.read !== undefined && message.direction === 'write') {
        problems.push(where + ' says how it is read, and ' + id +
                      ' is never read');
      }
    });
    message.elements.forEach(function (one) {
      if (one.undecorated) {
        problems.push(id + '.' + one.name + ' is neither an @attribute ' +
                      'nor an @element');
        return;
      }
      const where = id + '/' + one.xml;
      if (names.has(one.name) || xmls.has(one.xml)) {
        problems.push(where + ' is declared twice');
      }
      names.add(one.name);
      xmls.add(one.xml);
      if (!one.cite) {
        problems.push(where + ' cites nothing');
      }
      if (one.signer === true && one.written !== false) {
        problems.push(where + ' is inserted by the signer, so the builder ' +
                      'does not write it (written: false)');
      }
    });
  });
  Object.keys(saml.params).forEach(function (id) {
    const set = saml.params[id];
    const wires = new Set();
    set.params.forEach(function (one) {
      if (!one.wire || wires.has(one.wire)) {
        problems.push(id + '.' + one.name + ' has no wire name or repeats ' +
                      'one');
      }
      wires.add(one.wire);
      if (!one.cite) {
        problems.push(id + '.' + one.name + ' cites nothing');
      }
    });
  });
  log.debug("Leaving checkSaml(). " + problems.length + " problem(s).");
  return problems;
}
