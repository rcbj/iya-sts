// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ws-trust/ws_model.ts
//
// ---------------------------------------------------------------------------
// THE SOAP, WS-TRUST AND WS-FEDERATION MODEL, AS `/sts` AND `/wsfed` READ IT
// (#1579).
//
// `models/ws/soap.tsp`, `wstrust.tsp` and `wsfed.tsp` are the source of the
// SOAP versions' namespaces and fault codes, the trust namespaces, request
// types, actions, key types, status values, token types and section 11
// fault codes, the RST's children as they are read, every RSTR and Fault
// part as it is written in the order it is written, and WS-Federation's
// parameters, actions, token types, `wauth` values, claim types, sign-in
// response and metadata role. The image build writes
// `models/generated/ws.json`; this reads it beside `saml.json` through
// `common/xml_model.ts`, so an RSTR's SAML assertion is held to SAML's own
// model and SAML's terms (the assertion namespaces, the authentication
// methods `wauth` names) are SAML's, written once.
//
//   * `term(vocabulary, name)`, `terms(vocabulary, flag, value)`: a value,
//     the values a flag marks.
//   * `relative(vocabulary, name, trustNs)`: a request type, action, key
//     type or status, appended to the request's trust namespace.
//   * `attributes(id, values)`, `children(id, parts)`: the writers' order.
//   * `childNames(id, flag)`: the RST's children a flag marks — the ones
//     that hold another party's token, the ones a signed request must
//     carry inside its signed Body.
//   * `hold(id, xml, where)`: an envelope `/sts` built (STS-WSTRUST-0071)
//     or a sign-in response or metadata role `/wsfed` built
//     (STS-WSFED-0032), checked and answered unchanged.
//
// WHAT STAYS IN THE CODE: XML parsing (every child found by its local name,
// the namespace ignored, `helpers.firstByLocal()`), canonicalisation,
// signing, encryption, and every check that needs state (ws-trust/CLAUDE.md,
// *THE MESSAGES ARE THE MODEL'S*).
//
// A LEAF: it requires `common/xml_model` and bunyan, so both families'
// modules may require it.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import XmlModel = require('../common/xml_model');

const log = bunyan.createLogger({
  name: 'sts-ws-model',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

type Json = Record<string, any>;

const MODEL = new XmlModel(['ws.json', 'saml.json'], 'ws');

/**
 * The SOAP, WS-Trust and WS-Federation model's facts, and the readers and
 * writers built from them.
 */
class WsModel {
  /**
   * One term's value.
   *
   * @param id - the vocabulary, such as `wst.tokenType`
   * @param name - the term's name in the model
   * @returns its value on the wire
   */
  static term(id: string, name: string): string {
    log.debug("Entering WsModel.term(). " + id + "." + name);
    log.debug("Leaving WsModel.term().");
    return MODEL.term(id, name);
  }

  /**
   * One term, its value and flags.
   *
   * @param id - the vocabulary
   * @param name - the term's name in the model
   * @returns the term
   */
  static termOf(id: string, name: string): Json {
    log.debug("Entering WsModel.termOf(). " + id + "." + name);
    log.debug("Leaving WsModel.termOf().");
    return MODEL.termOf(id, name);
  }

  /**
   * A vocabulary's terms, whole, in the model's order.
   *
   * @param id - the vocabulary
   * @returns the terms
   */
  static termsOf(id: string): Json[] {
    log.debug("Entering WsModel.termsOf(). " + id);
    log.debug("Leaving WsModel.termsOf().");
    return MODEL.vocabulary(id).terms.slice(0);
  }

  /**
   * The values of a vocabulary's terms, in the model's order, those a flag
   * marks (with `value`, those it has that value for).
   *
   * @param id - the vocabulary
   * @param flag - the flag, or nothing for every term
   * @param value - the flag's value, or nothing for any true one
   * @returns the values
   */
  static terms(id: string, flag?: string, value?: unknown): string[] {
    log.debug("Entering WsModel.terms(). " + id + " " + (flag || ''));
    log.debug("Leaving WsModel.terms().");
    return MODEL.terms(id, flag, value);
  }

  /**
   * A term of a vocabulary the model says is APPENDED to the request's
   * trust namespace: a request type, an action, a key type, a status.
   *
   * @param id - the vocabulary
   * @param name - the term's name in the model
   * @param trustNs - the request's trust namespace
   * @returns the namespace and the term
   */
  static relative(id: string, name: string, trustNs: string): string {
    log.debug("Entering WsModel.relative(). " + id + "." + name);
    if (MODEL.vocabulary(id).relative !== true) {
      log.debug("Leaving WsModel.relative(). Not a relative vocabulary.");
      throw new Error('the ws vocabulary ' + id + ' is not appended to a ' +
                      'namespace');
    }
    log.debug("Leaving WsModel.relative().");
    return String(trustNs) + MODEL.term(id, name);
  }

  /**
   * One message.
   *
   * @param id - its id, such as `wst.RequestSecurityTokenResponse`
   * @returns the message
   */
  static message(id: string): Json {
    log.debug("Entering WsModel.message(). " + id);
    log.debug("Leaving WsModel.message().");
    return MODEL.message(id);
  }

  /**
   * A start tag's attributes, IN THE MODEL'S ORDER (`XmlModel.attributes()`).
   *
   * @param id - the message
   * @param values - the values, by each attribute's name in the model
   * @returns the text to follow the element's name
   */
  static attributes(id: string, values: Record<string, unknown>): string {
    log.debug("Entering WsModel.attributes(). " + id);
    log.debug("Leaving WsModel.attributes().");
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
    log.debug("Entering WsModel.children(). " + id);
    log.debug("Leaving WsModel.children().");
    return MODEL.children(id, parts);
  }

  /**
   * The local names of a message's children a flag marks, in the model's
   * order.
   *
   * @param id - the message
   * @param flag - the flag
   * @returns the local names
   */
  static childNames(id: string, flag: string): string[] {
    log.debug("Entering WsModel.childNames(). " + id + " " + flag);
    log.debug("Leaving WsModel.childNames().");
    return MODEL.childNames(id, flag);
  }

  /**
   * One parameter of a parameter set.
   *
   * @param id - the set, such as `wsfed.passive`
   * @param name - the parameter's name in the model
   * @returns the parameter
   */
  static param(id: string, name: string): Json {
    log.debug("Entering WsModel.param(). " + id + "." + name);
    log.debug("Leaving WsModel.param().");
    return MODEL.param(id, name);
  }

  /**
   * The wire names of a parameter set's parameters, those of one use when
   * one is named.
   *
   * @param id - the set
   * @param use - the use, or nothing for every parameter
   * @returns the wire names
   */
  static params(id: string, use?: string): string[] {
    log.debug("Entering WsModel.params(). " + id + " " + (use || ''));
    log.debug("Leaving WsModel.params().");
    return MODEL.params(id, use);
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
    log.debug("Entering WsModel.problems(). " + id);
    log.debug("Leaving WsModel.problems().");
    return MODEL.problems(id, xml);
  }

  /**
   * What is wrong with a built element, against its message.
   *
   * @param id - the message
   * @param element - the parsed element
   * @param where - the element's path, for the sentences
   * @returns the problems; empty when there are none
   */
  static problemsOf(id: string, element: any, where: string): string[] {
    log.debug("Entering WsModel.problemsOf(). " + id);
    log.debug("Leaving WsModel.problemsOf().");
    return MODEL.problemsOf(id, element, where);
  }

  /**
   * HOLDS a document this service built to its message: what does not
   * match is recorded — STS-WSFED-0032 for WS-Federation's, STS-WSTRUST-0071
   * for every other — and the document is answered as it was built.
   *
   * @param id - the message
   * @param xml - the document
   * @param where - what is being sent, for the log
   * @param declarations - for a fragment, the prefixes the document it is
   *   put in declares (`XmlModel.problems()`)
   * @returns the document, unchanged
   */
  static hold(id: string, xml: string, where: string,
              declarations?: Record<string, string>): string {
    log.debug("Entering WsModel.hold(). " + id);
    const out = id.indexOf('wsfed.') === 0
      ? MODEL.hold(id, xml, where, 'STS-WSFED-0032', 'models/ws/',
                   declarations)
      : MODEL.hold(id, xml, where, 'STS-WSTRUST-0071', 'models/ws/',
                   declarations);
    log.debug("Leaving WsModel.hold().");
    return out;
  }
}

export = WsModel;
