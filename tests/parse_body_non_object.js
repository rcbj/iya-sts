// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/parse_body_non_object.js
//
// ---------------------------------------------------------------------------
// FUZZ REGRESSION (#1346): parseBody() returns a PLAIN OBJECT for a JSON body
// that is `null` or a primitive.
//
// A JSON request body of the literal `null` (or a number, string or boolean)
// is valid JSON a fuzzer emits. `common/helpers.js` parseBody() returned
// whatever JSON.parse() gave it, so a handler reading `body[name]` or `body.x`
// on `null` threw a TypeError, which the fault boundary turned into an
// uncaught 500 at /admin-api -- the Schemathesis gate (#1299) found ~129 of
// them (STS-HTTP-0003), across applications/*, claims/*, credential-claims/*
// and kerberos/claims/* through listField()/namesOf().
//
// parseBody() is documented to build a PLAIN OBJECT, so a null or primitive
// JSON body now becomes {}, which the handlers already refuse with their own
// 4xx and a recorded code exactly as they do for {}. An ARRAY is the one
// non-object a caller may legitimately send and is preserved.
//
// IN PROCESS because parseBody() is a pure cross-protocol parser; it reads
// only req.headers and req.body, which this file supplies.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const helpers = require('../common/helpers');

const log = require('bunyan').createLogger({
  name: 'parse_body_non_object',
  level: process.env.LOG_LEVEL || 'info' });

function jsonReq(body) {
  log.debug("Entering jsonReq().");
  log.debug("Leaving jsonReq().");
  return { headers: { 'content-type': 'application/json' }, body: body };
}

function run(t) {
  log.debug("Entering run().");

  // The four non-object JSON scalars a fuzzer sends. `null` is the one that
  // threw; the primitives did not throw but are no more a body than null is.
  t.check(JSON.stringify(helpers.parseBody(jsonReq('null'))) === '{}',
          '1. a JSON body of `null` is an empty object, not null');
  t.check(JSON.stringify(helpers.parseBody(jsonReq('123'))) === '{}',
          '2. a JSON number body is an empty object');
  t.check(JSON.stringify(helpers.parseBody(jsonReq('"x"'))) === '{}',
          '3. a JSON string body is an empty object');
  t.check(JSON.stringify(helpers.parseBody(jsonReq('true'))) === '{}',
          '4. a JSON boolean body is an empty object');

  // An array is the one non-object a caller may legitimately send; it is
  // preserved, and `[]['name']` is undefined, so it never threw.
  const arr = helpers.parseBody(jsonReq('[1,2]'));
  t.check(Array.isArray(arr) && arr.length === 2,
          '5. a JSON array body is preserved (the one non-object a caller ' +
          'may legitimately send)');

  // An ordinary object body is unchanged.
  const obj = helpers.parseBody(jsonReq('{"a":1}'));
  t.check(obj && typeof obj === 'object' && !Array.isArray(obj) && obj.a === 1,
          '6. a JSON object body is parsed as before');

  // An empty body was already an empty object (JSON.parse(raw || "{}")); it
  // still is, so the one legitimate "no body" case is unchanged.
  t.check(JSON.stringify(helpers.parseBody(jsonReq(''))) === '{}',
          '7. an empty JSON body is an empty object (unchanged)');

  log.debug("Leaving run().");
}

module.exports = {
  name: 'parse_body_non_object',
  describe: 'FUZZ REGRESSION (#1346): parseBody() returns a plain object for ' +
            'a JSON body of null or a primitive, so a handler reading ' +
            'body[name] cannot throw an uncaught 500; an array is preserved',
  run: run
};
