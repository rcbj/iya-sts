// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: common/xml_model.ts
//
// ---------------------------------------------------------------------------
// AN XML FAMILY'S MODEL, AS THE CODE READS IT (#1579).
//
// SAML 2.0 and 1.1 (`models/saml/`) and SOAP, WS-Trust and WS-Federation
// (`models/ws/`) are written with one set of decorators
// (`models/lib/saml_lib.tsp`), and the image build writes each family's
// facts into its own file — `saml.json`, `ws.json`. This is the one reader
// of those facts, built over one or more of the files: a family whose
// messages carry another family's (an RSTR's RequestedSecurityToken holds a
// SAML assertion) is built over both, so the assertion is held to SAML's
// own model and the facts are written once.
//
//   * `term(vocabulary, name)` is one value and `terms(vocabulary, flag)`
//     the values a flag marks, in the model's order.
//   * `read(id, element)` is a parsed request's attributes as the model
//     reads each, for those it marks `read`.
//   * `attributes(id, values)` and `children(id, parts)` are the WRITERS'
//     ORDER; a part the model does not name throws.
//   * `hold(id, xml, where, code)` checks a document this service built
//     against its message — the root, its attributes and fixed values, its
//     children and their order, recursively where a child is a declared
//     message — logs a gap under `code`, and answers the document unchanged:
//     the model describes the wire, it does not reshape it.
//
// `saml/saml_model.ts` and `ws-trust/ws_model.ts` are each one instance of
// this, with the family's own name for its error code.
//
// A LEAF: it requires `common/model_tables`, `common/error_codes`,
// `common/xml_parser` and bunyan.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
// This service's one XML parser, which refuses a DOCTYPE (#1299).
import xmldom = require('./xml_parser');
import ModelTables = require('./model_tables');
import errorCodes = require('./error_codes');

const log = bunyan.createLogger({
  name: 'sts-xml-model',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

type Json = Record<string, any>;

/**
 * One XML family's facts, and the readers and writers built from them.
 */
class XmlModel {
  private readonly tables: { vocabularies: Json; messages: Json;
                             params: Json };

  /**
   * Builds the reader over generated files, merged: their ids are disjoint
   * by family (`models/lib/saml_lib.mjs`'s FAMILIES).
   *
   * @param files - the generated files, such as `['ws.json', 'saml.json']`
   * @param family - the family's name, for the sentences
   */
  constructor(files: string[], private readonly family: string) {
    log.debug("Entering XmlModel.constructor(). " + files.join(','));
    const tables = { vocabularies: {}, messages: {}, params: {} };
    files.forEach(function (name) {
      const one: Json = ModelTables.file(name);
      ['vocabularies', 'messages', 'params'].forEach(function (key) {
        Object.assign(tables[key], one[key] || {});
      });
    });
    this.tables = tables;
    log.debug("Leaving XmlModel.constructor().");
  }

  /**
   * One vocabulary.
   *
   * @param id - its id, such as `saml2.status`
   * @returns the vocabulary
   */
  vocabulary(id: string): Json {
    log.debug("Entering XmlModel.vocabulary(). " + id);
    const found = this.tables.vocabularies[id];
    if (!found) {
      log.debug("Leaving XmlModel.vocabulary(). Undeclared.");
      throw new Error('the ' + this.family + ' model declares no ' +
                      'vocabulary ' + id);
    }
    log.debug("Leaving XmlModel.vocabulary().");
    return found;
  }

  /**
   * One term.
   *
   * @param id - the vocabulary
   * @param name - the term's name in the model
   * @returns the term, its value and flags
   */
  termOf(id: string, name: string): Json {
    log.debug("Entering XmlModel.termOf(). " + id + "." + name);
    const found = this.vocabulary(id).terms.find(function (one: Json) {
      return one.name === name;
    });
    if (!found) {
      log.debug("Leaving XmlModel.termOf(). Undeclared.");
      throw new Error('the ' + this.family + ' vocabulary ' + id +
                      ' has no term ' + name);
    }
    log.debug("Leaving XmlModel.termOf().");
    return found;
  }

  /**
   * One term's value.
   *
   * @param id - the vocabulary
   * @param name - the term's name in the model
   * @returns its value on the wire
   */
  term(id: string, name: string): string {
    log.debug("Entering XmlModel.term(). " + id + "." + name);
    const value = this.termOf(id, name).value;
    log.debug("Leaving XmlModel.term().");
    return value;
  }

  /**
   * The values of a vocabulary's terms, in the model's order, those a flag
   * marks when one is named (a flag with a value: those it has that value
   * for).
   *
   * @param id - the vocabulary
   * @param flag - the flag, or nothing for every term
   * @param value - the flag's value, or nothing for any true one
   * @returns the values
   */
  terms(id: string, flag?: string, value?: unknown): string[] {
    log.debug("Entering XmlModel.terms(). " + id + " " + (flag || ''));
    const out = this.vocabulary(id).terms
      .filter(function (one: Json): boolean {
        if (!flag) {
          return true;
        }
        return value === undefined ? !!one[flag] : one[flag] === value;
      }).map(function (one: Json): string {
        return one.value;
      });
    log.debug("Leaving XmlModel.terms(). " + out.length);
    return out;
  }

  /**
   * The vocabulary's prefix, where the model gives one.
   *
   * @param id - the vocabulary
   * @returns the prefix
   */
  prefix(id: string): string {
    log.debug("Entering XmlModel.prefix(). " + id);
    log.debug("Leaving XmlModel.prefix().");
    return String(this.vocabulary(id).prefix || '');
  }

  /**
   * The map from one vocabulary's terms to the other's by `equivalent`.
   *
   * @param from - the vocabulary whose terms name an equivalent
   * @param to - the vocabulary the equivalent is a term of
   * @returns the map
   */
  equivalents(from: string, to: string): Record<string, string> {
    log.debug("Entering XmlModel.equivalents(). " + from + " -> " + to);
    const out: Record<string, string> = {};
    this.vocabulary(from).terms.forEach((one: Json) => {
      if (one.equivalent !== undefined) {
        out[one.value] = this.term(to, one.equivalent);
      }
    });
    log.debug("Leaving XmlModel.equivalents().");
    return out;
  }

  /**
   * One message.
   *
   * @param id - its id, such as `saml2.AuthnRequest`
   * @returns the message
   */
  message(id: string): Json {
    log.debug("Entering XmlModel.message(). " + id);
    const found = this.tables.messages[id];
    if (!found) {
      log.debug("Leaving XmlModel.message(). Undeclared.");
      throw new Error('the ' + this.family + ' model declares no message ' +
                      id);
    }
    log.debug("Leaving XmlModel.message().");
    return found;
  }

  /**
   * One attribute of a message, by its name in the model.
   *
   * @param id - the message
   * @param name - the attribute's name in the model
   * @returns the attribute
   */
  attributeOf(id: string, name: string): Json {
    log.debug("Entering XmlModel.attributeOf(). " + id + "@" + name);
    const found = this.message(id).attributes.find(function (one: Json) {
      return one.name === name;
    });
    if (!found) {
      log.debug("Leaving XmlModel.attributeOf(). Undeclared.");
      throw new Error('the ' + this.family + ' message ' + id +
                      ' has no attribute ' + name);
    }
    log.debug("Leaving XmlModel.attributeOf().");
    return found;
  }

  /**
   * One child element of a message, by its name in the model.
   *
   * @param id - the message
   * @param name - the child's name in the model
   * @returns the child
   */
  elementOf(id: string, name: string): Json {
    log.debug("Entering XmlModel.elementOf(). " + id + "/" + name);
    const found = this.message(id).elements.find(function (one: Json) {
      return one.name === name;
    });
    if (!found) {
      log.debug("Leaving XmlModel.elementOf(). Undeclared.");
      throw new Error('the ' + this.family + ' message ' + id +
                      ' has no child ' + name);
    }
    log.debug("Leaving XmlModel.elementOf().");
    return found;
  }

  /**
   * The local names of a message's children a flag marks, in the model's
   * order.
   *
   * @param id - the message
   * @param flag - the flag, such as `read` or `anotherPartys`
   * @returns the local names
   */
  childNames(id: string, flag: string): string[] {
    log.debug("Entering XmlModel.childNames(). " + id + " " + flag);
    const out = this.message(id).elements
      .filter(function (one: Json): boolean {
        return one[flag] === true;
      }).map(function (one: Json): string {
        return one.xml;
      });
    log.debug("Leaving XmlModel.childNames(). " + out.length);
    return out;
  }

  /**
   * The values an attribute a request carries is held to.
   *
   * @param id - the message
   * @param name - the attribute's name in the model
   * @returns the values; empty when it is held to none
   */
  accepts(id: string, name: string): string[] {
    log.debug("Entering XmlModel.accepts(). " + id + "@" + name);
    const out = (this.attributeOf(id, name).accepts || []).slice(0);
    log.debug("Leaving XmlModel.accepts().");
    return out;
  }

  /**
   * A parsed element's attributes, as the model reads each: an xs:boolean
   * by XML Schema Part 2 section 3.2.2, true for "true" or "1" after its
   * whitespace is collapsed (rcbj on #1579, 2026-11-11; until then "1" read
   * as false), anything else is its text or '' when absent.
   * Only the attributes the model marks `read`.
   *
   * @param id - the message the element is
   * @param element - the parsed element
   * @returns the values, by each attribute's name in the model
   */
  read(id: string, element: any): Record<string, any> {
    log.debug("Entering XmlModel.read(). " + id);
    const out: Record<string, any> = {};
    this.message(id).attributes.forEach(function (one: Json) {
      if (one.read !== true) {
        return;
      }
      const raw = element ? element.getAttribute(one.xml) : '';
      out[one.name] = one.reading === 'boolean'
        ? XmlModel.booleanTrue(raw) : (raw || '');
    });
    log.debug("Leaving XmlModel.read().");
    return out;
  }

  /**
   * Whether an xs:boolean's text is true: XML Schema Part 2 section 3.2.2's
   * lexical space is {true, false, 1, 0}, its whitespace collapsed. Anything
   * else, absence included, is not true.
   *
   * @param raw - the attribute's or element's text
   * @returns true for "true" and "1"
   */
  static booleanTrue(raw: unknown): boolean {
    log.debug("Entering XmlModel.booleanTrue().");
    const text = String(raw == null ? '' : raw).trim();
    log.debug("Leaving XmlModel.booleanTrue().");
    return text === 'true' || text === '1';
  }

  /**
   * The same characters `common/helpers.js`'s `xmlEscape()` writes, for an
   * attribute's value.
   */
  static escape(value: unknown): string {
    // A hot path of every builder; no Entering/Leaving pair.
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
  }

  /**
   * A start tag's attributes, IN THE MODEL'S ORDER: ` Name="value"` for
   * each, its value escaped, a fixed value always, and nothing for a value
   * that is undefined, null or empty. A name the model does not declare, or
   * one it says this service does not write, throws.
   *
   * @param id - the message
   * @param values - the values, by each attribute's name in the model
   * @returns the text to follow the element's name (and its namespace
   *   declarations)
   */
  attributes(id: string, values: Record<string, unknown>): string {
    log.debug("Entering XmlModel.attributes(). " + id);
    const declared = this.message(id).attributes;
    Object.keys(values).forEach((name) => {
      const one = declared.find(function (a: Json) {
        return a.name === name;
      });
      if (!one || one.written === false) {
        log.debug("Leaving XmlModel.attributes(). Not written: " + name);
        throw new Error('the ' + this.family + ' message ' + id +
                        ' has no attribute ' + name + ' this service writes');
      }
    });
    const out = declared.filter(function (one: Json): boolean {
      return one.written !== false;
    }).map(function (one: Json): string {
      const value = one.fixed !== undefined ? one.fixed : values[one.name];
      if (value === undefined || value === null || value === '') {
        return '';
      }
      return ' ' + one.xml + '="' + XmlModel.escape(value) + '"';
    }).join('');
    log.debug("Leaving XmlModel.attributes().");
    return out;
  }

  /**
   * The child elements' text joined IN THE MODEL'S ORDER. A part the model
   * does not name, or one it says the builder never writes, throws.
   *
   * @param id - the message
   * @param parts - each child's text, by its name in the model
   * @returns the content
   */
  children(id: string, parts: Record<string, string>): string {
    log.debug("Entering XmlModel.children(). " + id);
    const declared = this.message(id).elements;
    Object.keys(parts).forEach((name) => {
      const one = declared.find(function (e: Json) {
        return e.name === name;
      });
      if (!one || one.written === false) {
        log.debug("Leaving XmlModel.children(). Not written: " + name);
        throw new Error('the ' + this.family + ' message ' + id +
                        ' has no child ' + name + ' its builder writes');
      }
    });
    const out = declared.map(function (one: Json): string {
      const text = parts[one.name];
      return text === undefined || text === null ? '' : String(text);
    }).join('');
    log.debug("Leaving XmlModel.children().");
    return out;
  }

  /**
   * One parameter of a parameter set.
   *
   * @param id - the set, such as `saml11.browser`
   * @param name - the parameter's name in the model
   * @returns the parameter
   */
  param(id: string, name: string): Json {
    log.debug("Entering XmlModel.param(). " + id + "." + name);
    const set = this.tables.params[id];
    const found = set && set.params.find(function (one: Json) {
      return one.name === name;
    });
    if (!found) {
      log.debug("Leaving XmlModel.param(). Undeclared.");
      throw new Error('the ' + this.family + ' parameter set ' + id +
                      ' has no ' + name);
    }
    log.debug("Leaving XmlModel.param().");
    return found;
  }

  /**
   * The wire names of a parameter set's parameters, those whose `use` is
   * the one named when one is.
   *
   * @param id - the set
   * @param use - the use, or nothing for every parameter
   * @returns the wire names, in the model's order
   */
  params(id: string, use?: string): string[] {
    log.debug("Entering XmlModel.params(). " + id + " " + (use || ''));
    const set = this.tables.params[id];
    if (!set) {
      log.debug("Leaving XmlModel.params(). Undeclared.");
      throw new Error('the ' + this.family + ' model declares no ' +
                      'parameter set ' + id);
    }
    const out = set.params.filter(function (one: Json): boolean {
      return !use || one.use === use;
    }).map(function (one: Json): string {
      return one.wire;
    });
    log.debug("Leaving XmlModel.params(). " + out.length);
    return out;
  }

  /**
   * The namespaces a message may be in: its own, or every term of the
   * vocabulary it names.
   *
   * @param message - the message
   * @returns the namespaces
   */
  private namespacesOf(message: Json): string[] {
    log.debug("Entering XmlModel.namespacesOf().");
    const out = message.namespaces !== undefined
      ? this.terms(message.namespaces) : [String(message.xmlns || '')];
    log.debug("Leaving XmlModel.namespacesOf().");
    return out;
  }

  /**
   * What is wrong with a built element, against its message: the element's
   * name and namespace, an attribute the model does not declare or says
   * this service does not write, a fixed value not written, a required
   * attribute missing, a child the model does not name or that is out of
   * the model's order, one repeated that may not be, a required child
   * missing — and the same of every child that is a declared message.
   *
   * @param id - the message
   * @param element - the parsed element
   * @param where - the element's path, for the sentences
   * @returns the problems; empty when there are none
   */
  problemsOf(id: string, element: any, where: string): string[] {
    log.debug("Entering XmlModel.problemsOf(). " + id);
    const message = this.message(id);
    const out: string[] = [];
    const namespaces = this.namespacesOf(message);
    if (element.localName !== message.element ||
        namespaces.indexOf(element.namespaceURI) < 0) {
      out.push(where + ' is {' + element.namespaceURI + '}' +
               element.localName + ', not {' + namespaces.join('|') + '}' +
               message.element);
      log.debug("Leaving XmlModel.problemsOf(). Another element.");
      return out;
    }
    const attrs = element.attributes;
    for (let i = 0; i < attrs.length; i++) {
      const name = attrs[i].name;
      if (name === 'xmlns' || name.indexOf('xmlns:') === 0) {
        continue;
      }
      const one = message.attributes.find(function (a: Json) {
        return a.xml === name;
      });
      if (!one || one.written === false) {
        out.push(where + '@' + name + ' is not an attribute this service ' +
                 'writes');
      } else if (one.fixed !== undefined && attrs[i].value !== one.fixed) {
        out.push(where + '@' + name + ' is "' + attrs[i].value + '", not ' +
                 'its fixed "' + one.fixed + '"');
      }
    }
    message.attributes.forEach(function (one: Json) {
      if (one.required && one.written !== false &&
          !element.hasAttribute(one.xml)) {
        out.push(where + ' has no ' + one.xml);
      }
    });
    let at = -1;
    const seen: Record<string, number> = {};
    for (let child = element.firstChild; child; child = child.nextSibling) {
      if (child.nodeType !== 1) {
        continue;
      }
      const index = message.elements.findIndex(function (e: Json) {
        const named = e.xml === child.localName ||
          (Array.isArray(e.or) && e.or.indexOf(child.localName) >= 0);
        return named && (!e.xmlns || e.xmlns === child.namespaceURI);
      });
      const one = message.elements[index];
      if (!one) {
        out.push(where + '/' + child.localName + ' is not a child the ' +
                 'model names');
        continue;
      }
      if (one.written === false && one.signer !== true) {
        out.push(where + '/' + child.localName + ' is a child this service ' +
                 'does not write');
      }
      if (index < at) {
        out.push(where + '/' + child.localName + ' is out of the ' +
                 'schema\'s order');
      }
      at = Math.max(at, index);
      seen[one.name] = (seen[one.name] || 0) + 1;
      if (seen[one.name] > 1 && one.occurs !== 'many') {
        out.push(where + '/' + child.localName + ' is repeated');
      }
      if (one.message && child.localName === one.xml) {
        this.problemsOf(one.message, child, where + '/' + child.localName)
          .forEach(function (problem) {
            out.push(problem);
          });
      }
    }
    message.elements.forEach(function (one: Json) {
      if (one.occurs === 'one' && one.written !== false && !seen[one.name]) {
        out.push(where + ' has no ' + one.xml);
      }
    });
    log.debug("Leaving XmlModel.problemsOf(). " + out.length);
    return out;
  }

  /**
   * What is wrong with a document this service built, against the message
   * its root is.
   *
   * @param id - the message
   * @param xml - the document
   * @param declarations - for a FRAGMENT whose prefixes are declared by the
   *   document it is put in (a metadata role inside an EntityDescriptor):
   *   those prefixes' namespaces, by prefix
   * @returns the problems; empty when there are none
   */
  problems(id: string, xml: string,
           declarations?: Record<string, string>): string[] {
    log.debug("Entering XmlModel.problems(). " + id);
    let root: any = null;
    const wrapped = declarations
      ? '<fragment' + Object.keys(declarations).map(function (prefix) {
        return ' xmlns:' + prefix + '="' +
          XmlModel.escape(declarations[prefix]) + '"';
      }).join('') + '>' + String(xml || '') + '</fragment>'
      : String(xml || '');
    try {
      const doc = new xmldom.DOMParser({ onError: function () {
        // A builder's document that does not parse is the problem below.
      } }).parseFromString(wrapped, 'text/xml');
      root = doc && doc.documentElement;
      if (root && declarations) {
        let first = root.firstChild;
        while (first && first.nodeType !== 1) {
          first = first.nextSibling;
        }
        root = first || null;
      }
    } catch (e) {
      log.debug("Caught in XmlModel.problems(): " +
                ((e && e.message) || e));
      root = null;
    }
    if (!root) {
      log.debug("Leaving XmlModel.problems(). Not XML.");
      return [id + ' is not well-formed XML'];
    }
    const out = this.problemsOf(id, root, this.message(id).element);
    log.debug("Leaving XmlModel.problems(). " + out.length);
    return out;
  }

  /**
   * HOLDS a document this service built to its message: what does not
   * match is recorded under `code` and the document is answered as it was
   * built — the model describes the wire and does not reshape it, so this
   * is a model gap to close.
   *
   * @param id - the message
   * @param xml - the document
   * @param where - what is being sent, for the log
   * @param code - the error code a gap is recorded under
   * @param directory - where the family's model is, for the log
   * @param declarations - a fragment's prefixes, as `problems()` takes them
   * @returns the document, unchanged
   */
  hold(id: string, xml: string, where: string, code: string,
       directory: string, declarations?: Record<string, string>): string {
    log.debug("Entering XmlModel.hold(). " + id);
    const problems = this.problems(id, xml, declarations);
    if (problems.length > 0) {
      // error-code: none — the family's own code arrives as `code`
      log.error(errorCodes.tag(code) + this.family + ': the ' + where +
                ' does not match its model ' + id + ' in ' + directory +
                ': ' + problems.slice(0, 5).join('; '));
    }
    log.debug("Leaving XmlModel.hold().");
    return xml;
  }
}

export = XmlModel;
