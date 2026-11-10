// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: saml/saml_model.ts
//
// ---------------------------------------------------------------------------
// THE SAML MODEL, AS BOTH IDENTITY PROVIDERS READ IT (#1579).
//
// `models/saml/saml2.tsp` and `saml11.tsp` are the source of SAML 2.0's and
// SAML 1.1's vocabularies, of what this service reads off an AuthnRequest
// and a LogoutRequest, of the attributes and child elements of every
// message and metadata document it writes in the order the schema's
// sequence has them, and of SAML 1.1's browser parameters. The image build
// writes `models/generated/saml.json` and this reads it:
//
//   * `term(vocabulary, name)` is one value — a binding, a status code, a
//     NameID format, a class — and `terms(vocabulary, flag)` the values a
//     flag marks, in the model's order: the NameID formats ADVERTISED, the
//     bindings a Response is DELIVERED on, the classes read as an MFA
//     DEMAND. `equivalents(from, to)` is the map between SAML 2.0's
//     classes and SAML 1.1's methods.
//   * `read(id, element)` is a parsed request's attributes, as the model
//     says each is read (an xs:boolean true only for "true", anything else
//     its text, '' when absent), for those it marks `read`; `accepts(id,
//     name)` the values one of them is held to.
//   * `attributes(id, values)` and `children(id, parts)` are the WRITERS'
//     ORDER: the attributes in the model's order (a fixed value always,
//     anything empty omitted), and the child elements' text joined in the
//     model's order. A part the model does not name throws: that is a
//     builder out of step with its model, which `tests/model_saml.js` and
//     the wire test reach.
//   * `hold(id, xml, where)` checks a document this service built against
//     its message — the root, its attributes and fixed values, its children
//     and their order, recursively where a child is a declared message —
//     records a gap under STS-SAML-0121 and answers the document unchanged:
//     the model describes the wire, it does not reshape it.
//
// WHAT STAYS IN THE CODE: XML parsing, canonicalisation, signing and
// encryption (`common/crypto.js`), and every check that needs state — a
// signature against a registered certificate, a registered address, a
// session's context, an artifact's spending, a request's freshness
// (`saml/CLAUDE.md`, *THE MESSAGES ARE THE MODEL'S*).
//
// A LEAF: it requires `common/model_tables`, `common/error_codes`,
// `common/xml_parser` and bunyan, so every module of this directory may
// require it.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
// This service's one XML parser, which refuses a DOCTYPE (#1299).
import xmldom = require('../common/xml_parser');
import ModelTables = require('../common/model_tables');
import errorCodes = require('../common/error_codes');

const log = bunyan.createLogger({
  name: 'sts-saml-model',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

type Json = Record<string, any>;

const MODEL: Json = ModelTables.file('saml.json');

/**
 * The SAML model's facts, and the readers and writers built from them.
 */
class SamlModel {
  /**
   * One vocabulary.
   *
   * @param id - its id, such as `saml2.status`
   * @returns the vocabulary
   */
  static vocabulary(id: string): Json {
    log.debug("Entering SamlModel.vocabulary(). " + id);
    const found = MODEL.vocabularies[id];
    if (!found) {
      log.debug("Leaving SamlModel.vocabulary(). Undeclared.");
      throw new Error('the SAML model declares no vocabulary ' + id);
    }
    log.debug("Leaving SamlModel.vocabulary().");
    return found;
  }

  /**
   * One term's value.
   *
   * @param id - the vocabulary
   * @param name - the term's name in the model
   * @returns its value on the wire
   */
  static term(id: string, name: string): string {
    log.debug("Entering SamlModel.term(). " + id + "." + name);
    const found = SamlModel.vocabulary(id).terms.find(function (one: Json) {
      return one.name === name;
    });
    if (!found) {
      log.debug("Leaving SamlModel.term(). Undeclared.");
      throw new Error('the SAML vocabulary ' + id + ' has no term ' + name);
    }
    log.debug("Leaving SamlModel.term().");
    return found.value;
  }

  /**
   * The values of a vocabulary's terms, in the model's order, those a flag
   * marks when one is named.
   *
   * @param id - the vocabulary
   * @param flag - the flag, or nothing for every term
   * @returns the values
   */
  static terms(id: string, flag?: string): string[] {
    log.debug("Entering SamlModel.terms(). " + id + " " + (flag || ''));
    const out = SamlModel.vocabulary(id).terms
      .filter(function (one: Json): boolean {
        return !flag || !!one[flag];
      }).map(function (one: Json): string {
        return one.value;
      });
    log.debug("Leaving SamlModel.terms(). " + out.length);
    return out;
  }

  /**
   * The vocabulary's prefix, where the model gives one.
   *
   * @param id - the vocabulary
   * @returns the prefix
   */
  static prefix(id: string): string {
    log.debug("Entering SamlModel.prefix(). " + id);
    log.debug("Leaving SamlModel.prefix().");
    return String(SamlModel.vocabulary(id).prefix || '');
  }

  /**
   * The map from one vocabulary's terms to the other's by `equivalent`:
   * each value of `from` that names one, to that term's value in `to`.
   *
   * @param from - the vocabulary whose terms name an equivalent
   * @param to - the vocabulary the equivalent is a term of
   * @returns the map
   */
  static equivalents(from: string, to: string): Record<string, string> {
    log.debug("Entering SamlModel.equivalents(). " + from + " -> " + to);
    const out: Record<string, string> = {};
    SamlModel.vocabulary(from).terms.forEach(function (one: Json) {
      if (one.equivalent !== undefined) {
        out[one.value] = SamlModel.term(to, one.equivalent);
      }
    });
    log.debug("Leaving SamlModel.equivalents().");
    return out;
  }

  /**
   * One message.
   *
   * @param id - its id, such as `saml2.AuthnRequest`
   * @returns the message
   */
  static message(id: string): Json {
    log.debug("Entering SamlModel.message(). " + id);
    const found = MODEL.messages[id];
    if (!found) {
      log.debug("Leaving SamlModel.message(). Undeclared.");
      throw new Error('the SAML model declares no message ' + id);
    }
    log.debug("Leaving SamlModel.message().");
    return found;
  }

  /**
   * One attribute of a message, by its name in the model.
   *
   * @param id - the message
   * @param name - the attribute's name in the model
   * @returns the attribute
   */
  static attributeOf(id: string, name: string): Json {
    log.debug("Entering SamlModel.attributeOf(). " + id + "@" + name);
    const found = SamlModel.message(id).attributes.find(function (one: Json) {
      return one.name === name;
    });
    if (!found) {
      log.debug("Leaving SamlModel.attributeOf(). Undeclared.");
      throw new Error('the SAML message ' + id + ' has no attribute ' + name);
    }
    log.debug("Leaving SamlModel.attributeOf().");
    return found;
  }

  /**
   * The values an attribute a request carries is held to.
   *
   * @param id - the message
   * @param name - the attribute's name in the model
   * @returns the values; empty when it is held to none
   */
  static accepts(id: string, name: string): string[] {
    log.debug("Entering SamlModel.accepts(). " + id + "@" + name);
    const out = (SamlModel.attributeOf(id, name).accepts || []).slice(0);
    log.debug("Leaving SamlModel.accepts().");
    return out;
  }

  /**
   * A parsed element's attributes, as the model reads each: an xs:boolean
   * is true only for "true", anything else is its text or '' when absent.
   * Only the attributes the model marks `read`.
   *
   * @param id - the message the element is
   * @param element - the parsed element
   * @returns the values, by each attribute's name in the model
   */
  static read(id: string, element: any): Record<string, any> {
    log.debug("Entering SamlModel.read(). " + id);
    const out: Record<string, any> = {};
    SamlModel.message(id).attributes.forEach(function (one: Json) {
      if (one.read !== true) {
        return;
      }
      const raw = element ? element.getAttribute(one.xml) : '';
      out[one.name] = one.reading === 'boolean'
        ? String(raw || '') === 'true' : (raw || '');
    });
    log.debug("Leaving SamlModel.read().");
    return out;
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
  static attributes(id: string, values: Record<string, unknown>): string {
    log.debug("Entering SamlModel.attributes(). " + id);
    const declared = SamlModel.message(id).attributes;
    Object.keys(values).forEach(function (name) {
      const one = declared.find(function (a: Json) {
        return a.name === name;
      });
      if (!one || one.written === false) {
        log.debug("Leaving SamlModel.attributes(). Not written: " + name);
        throw new Error('the SAML message ' + id + ' has no attribute ' +
                        name + ' this service writes');
      }
    });
    const out = declared.filter(function (one: Json): boolean {
      return one.written !== false;
    }).map(function (one: Json): string {
      const value = one.fixed !== undefined ? one.fixed : values[one.name];
      if (value === undefined || value === null || value === '') {
        return '';
      }
      return ' ' + one.xml + '="' + SamlModel.escape(value) + '"';
    }).join('');
    log.debug("Leaving SamlModel.attributes().");
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
  static children(id: string, parts: Record<string, string>): string {
    log.debug("Entering SamlModel.children(). " + id);
    const declared = SamlModel.message(id).elements;
    Object.keys(parts).forEach(function (name) {
      const one = declared.find(function (e: Json) {
        return e.name === name;
      });
      if (!one || one.written === false) {
        log.debug("Leaving SamlModel.children(). Not written: " + name);
        throw new Error('the SAML message ' + id + ' has no child ' + name +
                        ' its builder writes');
      }
    });
    const out = declared.map(function (one: Json): string {
      const text = parts[one.name];
      return text === undefined || text === null ? '' : String(text);
    }).join('');
    log.debug("Leaving SamlModel.children().");
    return out;
  }

  /**
   * One parameter of a parameter set.
   *
   * @param id - the set, such as `saml11.browser`
   * @param name - the parameter's name in the model
   * @returns the parameter
   */
  static param(id: string, name: string): Json {
    log.debug("Entering SamlModel.param(). " + id + "." + name);
    const set = MODEL.params[id];
    const found = set && set.params.find(function (one: Json) {
      return one.name === name;
    });
    if (!found) {
      log.debug("Leaving SamlModel.param(). Undeclared.");
      throw new Error('the SAML parameter set ' + id + ' has no ' + name);
    }
    log.debug("Leaving SamlModel.param().");
    return found;
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
  static problemsOf(id: string, element: any, where: string): string[] {
    log.debug("Entering SamlModel.problemsOf(). " + id);
    const message = SamlModel.message(id);
    const out: string[] = [];
    if (element.localName !== message.element ||
        element.namespaceURI !== message.xmlns) {
      out.push(where + ' is {' + element.namespaceURI + '}' +
               element.localName + ', not {' + message.xmlns + '}' +
               message.element);
      log.debug("Leaving SamlModel.problemsOf(). Another element.");
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
        return e.xml === child.localName ||
          (Array.isArray(e.or) && e.or.indexOf(child.localName) >= 0);
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
        SamlModel.problemsOf(one.message, child,
                             where + '/' + child.localName)
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
    log.debug("Leaving SamlModel.problemsOf(). " + out.length);
    return out;
  }

  /**
   * What is wrong with a document this service built, against the message
   * its root is.
   *
   * @param id - the message
   * @param xml - the document
   * @returns the problems; empty when there are none
   */
  static problems(id: string, xml: string): string[] {
    log.debug("Entering SamlModel.problems(). " + id);
    let root: any = null;
    try {
      const doc = new xmldom.DOMParser({ onError: function () {
        // A builder's document that does not parse is the problem below.
      } }).parseFromString(String(xml || ''), 'text/xml');
      root = doc && doc.documentElement;
    } catch (e) {
      log.debug("Caught in SamlModel.problems(): " +
                ((e && e.message) || e));
      root = null;
    }
    if (!root) {
      log.debug("Leaving SamlModel.problems(). Not XML.");
      return [id + ' is not well-formed XML'];
    }
    const out = SamlModel.problemsOf(id, root, SamlModel.message(id).element);
    log.debug("Leaving SamlModel.problems(). " + out.length);
    return out;
  }

  /**
   * HOLDS a document this service built to its message: what does not
   * match is recorded under STS-SAML-0121 and the document is answered as
   * it was built — the model describes the wire and does not reshape it,
   * so this is a model gap to close.
   *
   * @param id - the message
   * @param xml - the document
   * @param where - what is being sent, for the log
   * @returns the document, unchanged
   */
  static hold(id: string, xml: string, where: string): string {
    log.debug("Entering SamlModel.hold(). " + id);
    const problems = SamlModel.problems(id, xml);
    if (problems.length > 0) {
      log.error(errorCodes.tag('STS-SAML-0121') + 'saml: the ' + where +
                ' does not match its model ' + id + ' in models/saml/: ' +
                problems.slice(0, 5).join('; '));
    }
    log.debug("Leaving SamlModel.hold().");
    return xml;
  }
}

export = SamlModel;
