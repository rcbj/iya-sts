// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: common/xml_parser.js
//
// ---------------------------------------------------------------------------
// THE ONE XML PARSER, AND IT REFUSES A DOCUMENT TYPE DECLARATION (ASVS 5.0.0
// 1.5.2; docs/validation.md).
//
// @xmldom/xmldom resolves no external entity, which is what made XML parsing
// safe here so far. It still READS a `<!DOCTYPE>` and its internal subset, and
// nothing this service accepts is allowed one: SOAP 1.2 Part 1 section 5 says
// a SOAP message MUST NOT contain a Document Type Declaration, the SAML
// bindings and WS-Security deployments forbid DTD processing, and no
// metadata, XACML or WS-Federation document this service reads needs one. A
// DTD is how entity expansion ("billion laughs") and every external-entity
// trick start, so the declaration itself is refused, before the parser sees
// the document, rather than trusting what the parser then does with it.
//
// Every module that parses XML takes `DOMParser` from here instead of from
// @xmldom/xmldom, and `common/crypto.js` installs it as the global the XML
// Signature engine uses. Everything else xmldom exports is passed through.
//
// A refusal is xmldom's own shape of failure: a reported `fatalError`, to an
// `onError` the caller gave, and then a thrown Error. Every caller already
// handles a document that will not parse.
// ---------------------------------------------------------------------------

const xmldom = require('@xmldom/xmldom');
const bunyan = require('bunyan');
const config = require('./config');
const errorCodes = require('./error_codes');

const log = bunyan.createLogger({
  name: 'xml_parser',
  level: config.value('global.logLevel') || 'info'
});

// `<!DOCTYPE` anywhere, and `<!ENTITY` anywhere: a declaration the prolog
// would have held, or one smuggled inside a comment or CDATA, which no
// legitimate message here carries either.
const DECLARATION = /<!\s*(DOCTYPE|ENTITY)\b/i;

/**
 * Names the declaration a document carries that this service refuses.
 *
 * @param {unknown} source - the document text
 * @returns {string} `DOCTYPE` or `ENTITY`, or '' when it carries neither
 */
function declarationIn(source) {
  log.debug("Entering declarationIn().");
  const match = DECLARATION.exec(String(source == null ? '' : source));
  log.debug("Leaving declarationIn().");
  return match ? match[1].toUpperCase() : '';
}

/**
 * xmldom's DOMParser, refusing a document that declares a document type or an
 * entity.
 */
class DOMParser extends xmldom.DOMParser {
  /**
   * @param {any} [options] - xmldom's options, kept for the refusal's
   *   `onError`
   */
  constructor(options) {
    super(options);
    this.refusalHandler = options && typeof options.onError === 'function'
      ? options.onError : null;
  }

  /**
   * Parses a document, unless it declares a document type or an entity.
   *
   * @param {string} source - the document text
   * @param {string} mimeType - the MIME type
   * @returns {any} the document
   * @throws Error marked STS-CORE-0174 for a declaration
   */
  parseFromString(source, mimeType) {
    log.debug("Entering DOMParser.parseFromString().");
    const found = declarationIn(source);
    if (found) {
      const message = 'the document carries a <!' + found + '> declaration, ' +
        'which this service never accepts: SOAP 1.2 forbids a Document ' +
        'Type Declaration, and none of the XML this service reads needs one.';
      if (this.refusalHandler) {
        this.refusalHandler('fatalError', message);
      }
      log.debug("Leaving DOMParser.parseFromString(). A declaration.");
      throw errorCodes.mark(new Error(message), 'STS-CORE-0174');
    }
    log.debug("Leaving DOMParser.parseFromString().");
    return super.parseFromString(source, mimeType);
  }
}

module.exports = Object.assign({}, xmldom, {
  DOMParser: DOMParser,
  declarationIn: declarationIn
});
