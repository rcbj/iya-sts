// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/pep_model.js
//
// ---------------------------------------------------------------------------
// AN ANSWER HELD TO THE REMOTE PEP'S MODEL (#1830).
//
// `xacml-pep/openapi/*.json` are generated from `models/pep/`. A test that
// has a real answer of one of those operations in hand — the service's
// control plane in `tests/authzen_evaluation.js` — asks here whether the
// answer is what the document says, with the JSON Schema 2020-12 validator
// the service already depends on. Every object in the documents is closed
// unless the model says otherwise, so a member the code writes and the model
// does not declare is a failure, as one the model requires and the code
// leaves out is.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const Ajv2020 = require('ajv/dist/2020');
const addFormats = require('ajv-formats');

const log = require('bunyan').createLogger({
  name: 'pep_model',
  level: process.env.LOG_LEVEL || 'info'
});

const DIR = path.join(__dirname, '..', '..', 'xacml-pep', 'openapi');

const compiled = new Map();

/**
 * The validator of one document, compiled once.
 *
 * @param file - e.g. `pep-control-plane.json`
 * @returns `{ ajv, document }`
 */
function documentOf(file) {
  log.debug("Entering documentOf().");
  if (!compiled.has(file)) {
    const document = JSON.parse(fs.readFileSync(path.join(DIR, file),
      'utf8'));
    const ajv = new Ajv2020({ strict: false, allErrors: true });
    addFormats(ajv);
    ajv.addSchema(document, file);
    compiled.set(file, { ajv: ajv, document: document });
  }
  log.debug("Leaving documentOf().");
  return compiled.get(file);
}

/**
 * The problems with an answer, by the document's operationId and status.
 *
 * @param file - the document's file name
 * @param operationId - the operation
 * @param status - the HTTP status answered
 * @param body - the parsed JSON body
 * @returns the problems; empty when the answer is the model's
 */
function problems(file, operationId, status, body) {
  log.debug("Entering problems(). " + operationId + " " + status);
  const one = documentOf(file);
  let pointer = null;
  Object.keys(one.document.paths).forEach(function (route) {
    Object.keys(one.document.paths[route]).forEach(function (method) {
      const operation = one.document.paths[route][method];
      if (operation.operationId !== operationId) {
        return;
      }
      const answer = operation.responses[String(status)] ||
        operation.responses.default;
      if (answer && answer.content && answer.content['application/json']) {
        pointer = '#/paths/' + route.replace(/~/g, '~0')
          .replace(/\//g, '~1') + '/' + method + '/responses/' +
          (operation.responses[String(status)] ? status : 'default') +
          '/content/application~1json/schema';
      }
    });
  });
  if (!pointer) {
    log.debug("Leaving problems(). No JSON answer modelled.");
    return [operationId + ' has no JSON answer for ' + status +
      ' in ' + file];
  }
  const validate = one.ajv.getSchema(file + pointer);
  if (validate(body)) {
    log.debug("Leaving problems(). None.");
    return [];
  }
  log.debug("Leaving problems(). " + validate.errors.length);
  return validate.errors.map(function (error) {
    return (error.instancePath || '/') + ' ' + error.message +
      (error.params && error.params.additionalProperty ?
        ' (' + error.params.additionalProperty + ')' : '');
  });
}

module.exports = { problems: problems };
