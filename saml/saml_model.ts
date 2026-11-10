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
// ONE INSTANCE OF `common/xml_model.ts`, the reader every XML family of the
// model shares (WS-Trust and WS-Federation read theirs through it too,
// `ws-trust/ws_model.ts`), over `saml.json` alone; these statics are its
// names in this directory, and the code that does the work is that file's.
//
// A LEAF: it requires `common/xml_model` (and through it
// `common/model_tables`, `common/error_codes`, `common/xml_parser`) and
// bunyan, so every module of this directory may require it.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import XmlModel = require('../common/xml_model');

const log = bunyan.createLogger({
  name: 'sts-saml-model',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

type Json = Record<string, any>;

const MODEL = new XmlModel(['saml.json'], 'saml');

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
    log.debug("Leaving SamlModel.vocabulary().");
    return MODEL.vocabulary(id);
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
    log.debug("Leaving SamlModel.term().");
    return MODEL.term(id, name);
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
    log.debug("Leaving SamlModel.terms().");
    return MODEL.terms(id, flag);
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
    return MODEL.prefix(id);
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
    log.debug("Leaving SamlModel.equivalents().");
    return MODEL.equivalents(from, to);
  }

  /**
   * One message.
   *
   * @param id - its id, such as `saml2.AuthnRequest`
   * @returns the message
   */
  static message(id: string): Json {
    log.debug("Entering SamlModel.message(). " + id);
    log.debug("Leaving SamlModel.message().");
    return MODEL.message(id);
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
    log.debug("Leaving SamlModel.attributeOf().");
    return MODEL.attributeOf(id, name);
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
    log.debug("Leaving SamlModel.accepts().");
    return MODEL.accepts(id, name);
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
    log.debug("Leaving SamlModel.read().");
    return MODEL.read(id, element);
  }

  /**
   * The same characters `common/helpers.js`'s `xmlEscape()` writes, for an
   * attribute's value.
   */
  static escape(value: unknown): string {
    // A hot path of every builder; no Entering/Leaving pair.
    return XmlModel.escape(value);
  }

  /**
   * A start tag's attributes, IN THE MODEL'S ORDER (`XmlModel.attributes()`).
   *
   * @param id - the message
   * @param values - the values, by each attribute's name in the model
   * @returns the text to follow the element's name
   */
  static attributes(id: string, values: Record<string, unknown>): string {
    log.debug("Entering SamlModel.attributes(). " + id);
    log.debug("Leaving SamlModel.attributes().");
    return MODEL.attributes(id, values);
  }

  /**
   * The child elements' text joined IN THE MODEL'S ORDER
   * (`XmlModel.children()`).
   *
   * @param id - the message
   * @param parts - each child's text, by its name in the model
   * @returns the content
   */
  static children(id: string, parts: Record<string, string>): string {
    log.debug("Entering SamlModel.children(). " + id);
    log.debug("Leaving SamlModel.children().");
    return MODEL.children(id, parts);
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
    log.debug("Leaving SamlModel.param().");
    return MODEL.param(id, name);
  }

  /**
   * What is wrong with a built element, against its message
   * (`XmlModel.problemsOf()`).
   *
   * @param id - the message
   * @param element - the parsed element
   * @param where - the element's path, for the sentences
   * @returns the problems; empty when there are none
   */
  static problemsOf(id: string, element: any, where: string): string[] {
    log.debug("Entering SamlModel.problemsOf(). " + id);
    log.debug("Leaving SamlModel.problemsOf().");
    return MODEL.problemsOf(id, element, where);
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
    log.debug("Leaving SamlModel.problems().");
    return MODEL.problems(id, xml);
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
    log.debug("Leaving SamlModel.hold().");
    return MODEL.hold(id, xml, where, 'STS-SAML-0121', 'models/saml/');
  }
}

export = SamlModel;
