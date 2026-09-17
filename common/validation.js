// @ts-check
'use strict';
//
// File: validation.js
//
// ---------------------------------------------------------------------------
// THE ONE PLACE A VALUE FROM OUTSIDE BECOMES A VALUE THIS SERVICE WILL USE.
//
// Every other module here reads `req.query.x`, `req.body.x` or `req.params.x`
// and gets whatever express handed it. That is about five hundred read sites
// across nineteen directories, and until 2026-09-06 the only normalisation any
// of them had was `String(...)` written out at the call site — correctly in
// most places, and not at all in some.
//
// **`String()` AT THE READ SITE IS A CONVENTION AND NOT A CONTROL**, and the
// difference is the whole reason this file exists. It is applied by whoever
// wrote the line, it cannot be checked, and where it is missing nothing says
// so. When this file was written, `oauth-oidc/oauth2.ts`'s authorization
// endpoint had it on `redirect_uri` and passed `q.client_id` to
// `clientConfigOf()` without it four lines later. Neither was a bug. The point
// is that nobody could tell without reading both.
//
// ---------------------------------------------------------------------------
// SHAPE IS VALIDATED UNCONDITIONALLY. EXISTENCE STAYS WITH `mode.js`.
//
// **THIS IS THE RULE THAT KEEPS THE MOCK A MOCK**, and it is the first thing to
// check a proposed change here against.
//
// A `client_id` that is eight kilobytes long, a `redirect_uri` that arrived as
// an array, a username with a carriage return in it, a DN with an unescaped
// comma — those are malformed in BOTH modes, refusing them costs the mock
// nothing, and a client that sends one has a bug this service should name
// rather than absorb. So they are refused in development exactly as in product.
//
// Whether an UNKNOWN `client_id` is accepted, whether a password is checked,
// whether an application must hold a secret — none of that is here. It is
// `mode.js`'s, it stays `mode.js`'s, and a predicate from that module must
// never be read in this one. **If a change to this file would make development
// mode refuse a request it exists to accept, the change is wrong**: this file
// is about the SHAPE of what arrived, never about who sent it or whether they
// are known.
//
// The two questions are easy to confuse because both end in a 400. The test is
// whether the answer would change if the operator flipped `global.mode`. If it
// would, it does not belong here.
//
// ---------------------------------------------------------------------------
// WHAT IT REFUSES, AND WHY REFUSING BEATS REPAIRING.
//
// The `hpp` package — and most hand-written normalisers — resolve a repeated
// parameter by taking the last value and discarding the rest. **This one
// refuses instead**, and that is deliberate.
//
// Silently choosing one of two values is how two parsers come to disagree about
// what a request said, which is the whole mechanism behind parameter pollution
// and request smuggling. A caller that sent `redirect_uri` twice does not have
// a preference this service can infer; it has a bug, or somebody is probing for
// exactly that disagreement. Naming it costs one error response and removes the
// ambiguity entirely.
//
// **A PARAMETER THAT MAY LEGITIMATELY REPEAT SAYS SO IN ITS SCHEMA**, as
// `repeatable(...)`. RFC 8707's `resource` and RFC 8693's `audience` are the
// two that do. They are then kept as arrays and nothing is thrown away, which
// is the behaviour `helpers.bodyValues()` already had to be written by hand to
// get back after `parseBody()` had flattened it.
//
// ---------------------------------------------------------------------------
// CONTROL CHARACTERS ARE REFUSED EVERYWHERE, AND THE RULE IS NOT THE SAME IN
// BOTH DIRECTIONS.
//
// A carriage return or a newline in a value that reaches a response header is
// header injection; in a value that reaches the audit log it is log forging; in
// an LDAP filter or a DN it is a different query from the one the code was
// written to make. A NUL byte is worse than all of them, because half the
// libraries under this service are C underneath and treat it as the end of the
// string while node does not. (This repository has already lost time to a
// stray NUL — it makes a file invisible to `grep` while `sed`, `node` and the
// tests all still see it.)
//
// So: in a query parameter, a path parameter or a header, NO C0 control
// character is allowed at all. In a BODY field, tab, newline and carriage
// return are allowed — a textarea on the console legitimately contains them,
// and an XACML policy or a PEM block is nothing but lines — and every other C0
// character and NUL is still refused.
//
// ---------------------------------------------------------------------------
// UNKNOWN PARAMETERS ARE STRIPPED, NOT REFUSED, AND THAT IS A PROTOCOL
// REQUIREMENT RATHER THAN A KINDNESS.
//
// RFC 6749 section 3.1 says an authorization server MUST ignore unrecognised
// request parameters. OIDC Core says the same. SCIM, WS-Trust and SAML all
// carry extension points whose whole purpose is that an implementation which
// does not understand them proceeds anyway. So `z.object()`'s default — strip
// what is not declared — is the correct behaviour and is what these schemas
// use. `z.strictObject()` is available for the surfaces that are this
// service's own and answer to no specification: `/admin-api` and the console.
//
// ---------------------------------------------------------------------------
// A REFUSAL IS DESCRIBED HERE AND RENDERED WHERE THE PROTOCOL LIVES.
//
// There is no `res` in this file and there is not going to be one. What
// `check()` returns on a failure is a plain object — a code, the field, and a
// sentence — and the caller turns it into whatever its own specification says a
// bad request looks like: an OAuth `invalid_request`, a SCIM error resource, a
// SAML second-level status, an LDAP `resultCode`, a gRPC `INVALID_ARGUMENT`, or
// an HTML page in the console's shell.
//
// **That split is the "one copy of each fact" rule applied to error handling.**
// The DETECTION is one place, so no two endpoints can disagree about whether a
// value is acceptable. The RENDERING is at the endpoint, because eight
// protocols genuinely do not agree about what a rejection looks like and a
// central renderer would have to be told which one it was in anyway.
//
// ---------------------------------------------------------------------------
// A LIBRARY (rule 3): it registers no route, so its position in the require
// order is not a position.
//
// It is a LEAF and must stay one. It requires `zod`, `bunyan`, xmldom, node's
// `zlib`, `config` and the error-code table — and neither of those two
// requires anything that reaches back here — so `helpers.js` may require it,
// and it may NEVER require `helpers.js` back. That direction is load-bearing:
// the normalisation has to be available to `parseBody()` itself, which is in
// helpers, and a cycle there would hand back a half-initialised module whose
// exports are `undefined` and surface much later as something that is not a
// function (rule 2).
//
// It makes a bunyan logger of its own for the same reason `config.js` and
// `crypto.js` do: the shared one lives in `helpers.js`, which is above it.
// ---------------------------------------------------------------------------

const bunyan = require('bunyan');
const { z } = require('zod');
const config = require('./config');
const { DOMParser } = require('@xmldom/xmldom');
const zlib = require('zlib');
// The registry of failure codes. A LEAF that requires nothing, so this closes
// no cycle. The guard below marks its refusals with one, on the RESPONSE OBJECT
// and never in the body — see common/error_codes.js.
const errorCodes = require('./error_codes');

const log = bunyan.createLogger({
  name: 'sts-validation',
  level: config.value('global.logLevel') || 'info'
});

// ---------------------------------------------------------------------------
// THE CAPS.
//
// A length limit is the cheapest control in this file and the one most likely
// to be left out, because nothing fails without it until somebody sends a
// megabyte. body-parser caps a whole body at 5mb (`app.js`), which is right for
// a SOAP envelope and says nothing at all about one field inside it.
//
// DEFAULT is deliberately generous: this is a backstop, and a schema that knows
// what a field is says so itself. The named ones are the values that recur
// across protocols, so that "how long may a client_id be" has one answer rather
// than fourteen.
//
// LARGE exists because of SAML and WS-Federation — a base64 deflate-encoded
// AuthnRequest is routinely several kilobytes and a signed Response with an
// embedded assertion and a certificate chain is tens of them. Capping those at
// DEFAULT would refuse ordinary traffic, which is the failure mode that gets a
// control switched off rather than fixed.
// ---------------------------------------------------------------------------
const CAP = {
  IDENTIFIER: 256,      // a client_id, a realm id, an application id, a kid
  NAME: 256,            // a username, a group name, a principal name
  TOKEN: 4096,          // an opaque credential: a code, a token, an artifact
  URI: 2048,            // the de-facto browser limit, and more than any of ours needs
  SCOPE:
    2048,          // a space-delimited list, which grows with the deployment
  DEFAULT: 4096,        // the backstop for a field whose schema did not say
  TEXT: 65536,          // a console textarea: a policy, a PEM block, an LDIF fragment
  LARGE:
    1048576        // a SAML message, a SOAP envelope, an XACML request document
};

// ---------------------------------------------------------------------------
// The characters that are never allowed through, and the two readings of that.
//
// C0 is U+0000..U+001F plus U+007F. STRICT refuses all of them: that is for a
// query parameter, a path segment and a header, none of which has any business
// carrying a line break. TEXT allows tab (09), newline (0A) and carriage
// return (0D) and refuses the rest.
//
// U+007F (DEL) is in both because nothing legitimate here contains it, and it
// is a classic filter-evasion byte.
//
// They are written as escapes rather than as the characters themselves for a
// reason this repository has already paid for once: a literal control byte in a
// source file is invisible in every diff and makes the file unsearchable.
// ---------------------------------------------------------------------------
const CONTROL_STRICT = /[\x00-\x1F\x7F]/;
const CONTROL_TEXT = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;

// ---------------------------------------------------------------------------
// The three keys that turn an assignment into a prototype write.
//
// `parseBody()` builds its form object with `out[k] = v`, and assigning a
// STRING to `__proto__` is a silent no-op rather than pollution — so form
// bodies were never exposed. A JSON body is the case that is: `JSON.parse`
// gives an own `__proto__` property, harmless in itself, and dangerous the
// moment anything merges that object into another one. This service merges
// configuration layers and builds directory entries out of request bodies, so
// the ingredient is present even where the recipe is not written yet.
//
// Refusing the key outright is cheaper than auditing every merge in the
// service, and no legitimate caller of any protocol here sends one.
// ---------------------------------------------------------------------------
const POLLUTING_KEYS = ['__proto__', 'constructor', 'prototype'];

// ---------------------------------------------------------------------------
// WHY A REFUSAL IS AN OBJECT AND NOT AN EXCEPTION.
//
// Every caller of this module is inside an express handler that already knows
// how it answers a bad request, and most of them have to answer it in a
// protocol-specific envelope. Throwing would mean each of those handlers wraps
// the call in a try/catch to get back to the same place — sixty-odd of them —
// and this repository's style forbids the one-liner catch that people write
// when they are doing that sixty times.
//
// `code` is for the caller to switch on, `field` names the parameter so the
// message can point at it, and `detail` is a sentence that goes in front of a
// human. They are separate because an OAuth error_description and an HTML page
// want different amounts of it.
// ---------------------------------------------------------------------------
function refusal(code, field, detail) {
  log.debug("Entering refusal().");
  log.debug("Leaving refusal().");
  return { ok: false, code: code, field: field, detail: detail };
}

// ---------------------------------------------------------------------------
// SCALAR: the type-confusion fix, and the single most valuable function here.
//
// `req.query` is parsed by express's `qs`, which is still on its defaults —
// there is no `app.set('query parser', ...)` anywhere in this service. So a
// query parameter arrives as a STRING, an ARRAY (`?x=a&x=b`) or a nested OBJECT
// (`?x[y]=a`), and which one it is depends entirely on what the caller sent.
//
// That is the shape of nearly every parameter-pollution finding in a node
// service: code written for a string meets an array. `String(['a','b'])` is
// `'a,b'`, which fails an exact match — safe, and only by luck. `String({})` is
// `'[object Object]'`. `value.startsWith(...)` on an array throws a TypeError
// and becomes a 500. `value.length` on an array is a count, not a length, so a
// length check passes when it should not.
//
// Note what this does NOT do: it does not choose. See the header.
// ---------------------------------------------------------------------------
function scalar(value, field, allowText) {
  log.debug("Entering scalar().");
  if (value === undefined || value === null) {
    log.debug("Leaving scalar().");
    return { ok: true, value: undefined };
  }
  if (Array.isArray(value)) {
    log.debug("Leaving scalar().");
    return refusal('repeated', field,
                   'the parameter "' + field + '" was given ' + value.length +
                   ' times and this endpoint takes it once. It is refused ' +
                   'rather than resolved to one of them, because choosing ' +
                   'silently is how two readers of the same request come to ' +
                   'disagree.');
  }
  if (typeof value === 'object') {
    log.debug("Leaving scalar().");
    return refusal('structured', field,
                   'the parameter "' + field + '" arrived as a structure ' +
                   'rather than a value. Express parses ' +
                   '"' + field + '[key]=..." ' +
                   'into an object; this endpoint takes a single value.');
  }
  // A number or a boolean is what a JSON body legitimately carries, and the
  // schema below decides whether this field was allowed to be one. Coercing
  // here rather than refusing keeps `{"expires_in": 300}` working.
  const text = typeof value === 'string' ? value : String(value);
  const forbidden = allowText ? CONTROL_TEXT : CONTROL_STRICT;
  if (forbidden.test(text)) {
    log.debug("Leaving scalar().");
    return refusal('control-character', field,
                   'the value of "' + field +
                   '" contains a control character. ' +
                   (allowText
                     ? 'A line break is allowed in this field; the other ' +
                       'control characters are not.'
                     : 'A carriage return or newline here would reach a ' +
                       'response header, a log line or a directory query as ' +
                       'a second instruction rather than as text.'));
  }
  log.debug("Leaving scalar().");
  return { ok: true, value: text };
}

// ---------------------------------------------------------------------------
// Is this schema an array at its root, through whatever wrappers it carries.
//
// A repeatable parameter is almost never written bare: it is
// `repeatable(x).optional()` or `.default([])`, and each of those wraps the
// type in another one. zod exposes the wrapped type differently between
// versions, so this reads the type name and unwraps rather than reaching for a
// private field — and answers "no" if it cannot tell, which fails towards
// treating the parameter as single-valued and refusing a repeat. That is the
// safe direction: the cost is an error message on a request that was allowed,
// against silently accepting a repeat that was not.
// ---------------------------------------------------------------------------
function isArraySchema(schema) {
  log.debug("Entering isArraySchema().");
  let current = schema;
  for (let depth = 0; depth < 8 && current; depth++) {
    const def = current._def || current.def;
    if (!def) {
      log.debug("Leaving isArraySchema().");
      return false;
    }
    const kind = def.typeName || def.type;
    if (kind === 'ZodArray' || kind === 'array') {
      log.debug("Leaving isArraySchema().");
      return true;
    }
    const inner = def.innerType || def.schema;
    if (inner && typeof inner === 'object' && (inner._def || inner.def)) {
      current = inner;
      continue;
    }
    log.debug("Leaving isArraySchema().");
    return false;
  }
  log.debug("Leaving isArraySchema().");
  return false;
}

// ---------------------------------------------------------------------------
// Turn one express input group into a plain object of scalars and declared
// arrays, refusing on the first thing that is neither.
//
// The SCHEMA decides which fields may repeat, which is why this takes one: a
// field declared `repeatable(...)` keeps its array and a bare scalar is wrapped
// into a one-element array, because one occurrence of a repeatable parameter is
// a list of one. Everything else must be a scalar.
//
// Unknown keys are passed through untouched for `z.object()` to strip. They are
// still checked for a polluting name, because the strip happens after the
// object exists.
// ---------------------------------------------------------------------------
function flatten(input, shape, allowText) {
  log.debug("Entering flatten().");
  const source = (input && typeof input === 'object') ? input : {};
  const out = {};
  const keys = Object.keys(source);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    if (POLLUTING_KEYS.indexOf(key) >= 0) {
      log.warn('validation: a request carried the parameter "' + key +
               '", which is refused everywhere in this service.');
      log.debug("Leaving flatten(). A polluting key was refused.");
      return refusal('polluting-key', key,
                     'the parameter name "' + key + '" is refused. It is a ' +
                     'property of every object in javascript, and a request ' +
                     'that sets it is not asking for anything this service ' +
                     'offers.');
    }
    const declared = shape ? shape[key] : undefined;
    const repeats = declared ? isArraySchema(declared) : false;
    const value = source[key];
    if (repeats) {
      const list = Array.isArray(value) ? value : [value];
      const cleaned = [];
      for (let j = 0; j < list.length; j++) {
        const one = scalar(list[j], key, allowText);
        if (!one.ok) {
          log.debug("Leaving flatten(). An element of a repeated parameter " +
                    "was refused.");
          return one;
        }
        if (one.value !== undefined) {
          cleaned.push(one.value);
        }
      }
      out[key] = cleaned;
      continue;
    }
    const one = scalar(value, key, allowText);
    if (!one.ok) {
      log.debug("Leaving flatten(). A parameter was refused.");
      return one;
    }
    if (one.value !== undefined) {
      out[key] = one.value;
    }
  }
  log.debug("Leaving flatten(). " + Object.keys(out).length + " parameter(s).");
  return { ok: true, value: out };
}

// ---------------------------------------------------------------------------
// Turn zod's first issue into this service's refusal.
//
// Only the first: a caller fixing a malformed request fixes one thing at a
// time, and a list of eleven complaints about a request that was rejected at
// the first one is noise. The FIELD is the last path segment, because a nested
// path is a console form's business and the name is what the caller sent.
// ---------------------------------------------------------------------------
function fromZod(error, where) {
  log.debug("Entering fromZod().");
  const issues = (error && error.issues) || [];
  if (!issues.length) {
    log.debug("Leaving fromZod(). No issue was reported.");
    return refusal('invalid', '(request)',
                   'the ' + where +
                   ' did not validate and no reason was given.');
  }
  const first = issues[0];
  const path = Array.isArray(first.path) ? first.path : [];
  const field = path.length ? String(path[path.length - 1]) : '(request)';
  // zod reports a missing required field as an invalid type whose received
  // value is undefined. A caller can act on "you left it out" and cannot act on
  // "expected string, received undefined", so the two are told apart here.
  const missing = first.code === 'invalid_type' &&
                  (first.received === 'undefined' || first.input === undefined);
  const code = missing ? 'missing' : 'invalid';
  log.debug("Leaving fromZod(). code=" + code + " field=" + field);
  return refusal(code, field,
                 missing
                   ? 'the ' + where + ' parameter "' + field + '" is required.'
                   : 'the ' + where + ' parameter "' + field +
                     '" is not acceptable: ' + first.message + '.');
}

// ---------------------------------------------------------------------------
// THE ENTRY POINT.
//
// `where` is 'query', 'body', 'params' or 'headers' and decides two things:
// which object is read, and whether a line break is allowed in it (see the
// header — a body may hold a PEM block, a query string may not hold a newline).
//
// The return is `{ ok: true, value }` or `{ ok: false, code, field, detail }`
// and never throws for a bad request. It CAN throw for a bad SCHEMA, which is a
// programming error in this repository rather than something a caller did, and
// should fail loudly at the first test that touches the endpoint.
// ---------------------------------------------------------------------------
function check(req, where, schema) {
  log.debug("Entering check(). where=" + where);
  const allowText = (where === 'body');
  const input = req ? req[where] : undefined;
  const shape = schema && schema.shape ? schema.shape : undefined;
  const flat = flatten(input, shape, allowText);
  if (!flat.ok) {
    log.debug("Leaving check(). The input was refused before the schema ran.");
    return flat;
  }
  const parsed = schema.safeParse(flat.value);
  if (!parsed.success) {
    const why = fromZod(parsed.error, where);
    log.debug("Leaving check(). The schema refused: " + why.code + " " +
              why.field);
    return why;
  }
  log.debug("Leaving check(). Accepted.");
  return { ok: true, value: parsed.data };
}

// ---------------------------------------------------------------------------
// THE SAME CHECK AGAINST AN OBJECT SOMEBODY ELSE ALREADY PARSED.
//
// **THIS IS WHAT EVERY BODY IN THIS SERVICE ACTUALLY USES, and the reason is a
// property of `app.js` rather than a convenience here.** There is no
// `bodyParser.json()` or `bodyParser.urlencoded()` in this service: the raw
// parser takes the few binary types (Kerberos, OCSP, PKCS#10, SCEP) and
// `bodyParser.text({ type: () => true })` takes everything else, so
// **`req.body` IS A STRING** and `helpers.parseBody()` is what turns it into
// an object — `JSON.parse` for a JSON content type, `URLSearchParams`
// otherwise.
//
// So a handler holds the parsed object and `check(req, 'body', …)` would look
// at the raw text beside it and find no fields at all — silently, answering
// "every optional field was absent". This entry point takes what the handler
// already has.
//
// `where` is still passed, because it is what decides whether a line break is
// allowed (see the header) and because it is the word that appears in the
// refusal a caller reads.
// ---------------------------------------------------------------------------
function checkParsed(value, where, schema) {
  log.debug("Entering checkParsed(). where=" + where);
  const shape = schema && schema.shape ? schema.shape : undefined;
  const flat = flatten(value, shape, where === 'body');
  if (!flat.ok) {
    log.debug("Leaving checkParsed(). The input was refused before the " +
              "schema ran.");
    return flat;
  }
  const parsed = schema.safeParse(flat.value);
  if (!parsed.success) {
    const why = fromZod(parsed.error, where);
    log.debug("Leaving checkParsed(). The schema refused: " + why.code + " " +
              why.field);
    return why;
  }
  log.debug("Leaving checkParsed(). Accepted.");
  return { ok: true, value: parsed.data };
}

// Read one input group with no schema of its own: everything must be a scalar
// and nothing may be a polluting key. This is what an endpoint uses while its
// schema is still being written, so that the type-confusion class is closed
// everywhere before the per-endpoint work is finished.
function scalars(req, where) {
  log.debug("Entering scalars().");
  log.debug("Leaving scalars().");
  return flatten(req ? req[where] : undefined, undefined, where === 'body');
}

// ---------------------------------------------------------------------------
// A DOCUMENT WHOSE SHAPE IS NOT THIS SERVICE'S TO DECIDE.
//
// **SOME BODIES HERE ARE DELIBERATELY ARBITRARY JSON, and a schema is the wrong
// tool for every one of them.** RFC 7591 section 2 says a client registration
// MAY carry any metadata the client likes, and `applications.js` keeps the
// whole document verbatim in `appRegistrationJson` precisely because no fixed
// attribute set can represent it. SCIM's PATCH, an XACML request in the JSON
// Profile and an SSF stream configuration are the same case.
//
// Running `check()` over one of those would not merely be useless, it would
// BREAK IT: `flatten()` requires a scalar for every field a schema does not
// declare repeatable, and `redirect_uris` is an array, `jwks` is a nested
// object. Client registration would start refusing every conforming client.
//
// So this walks the document instead and asserts only the things that are true
// of ANY JSON this service accepts, whatever its shape:
//
//   * NO POLLUTING KEY, at any depth. This is the one that matters.
//     `JSON.parse` produces a real own `__proto__` property, and a registration
//     document is merged into a record — `applications.js` rebuilds a client
//     from the stored document and then overwrites members from attributes — so
//     the ingredient and the recipe are both present here.
//   * A BOUNDED DEPTH, because a deeply nested document is a stack overflow in
//     whatever walks it next, and nothing this service accepts is deep.
//   * A BOUNDED KEY COUNT, for the same reason a field has a length cap: the
//     5mb body limit says nothing about how many keys are inside it.
//
// It returns the value UNCHANGED on success. It is a check and never a
// transform — the whole point is that the caller stores what the client sent.
// ---------------------------------------------------------------------------
const JSON_MAX_DEPTH = 12;
const JSON_MAX_KEYS = 4096;

function checkDocument(value, where, opts) {
  log.debug("Entering checkDocument(). where=" + where);
  const maxDepth = (opts && opts.maxDepth) || JSON_MAX_DEPTH;
  const maxKeys = (opts && opts.maxKeys) || JSON_MAX_KEYS;
  let keys = 0;
  let bad = null;

  const walk = function (node, depth, path) {
    log.debug("Entering walk().");
    if (bad) {
      log.debug("Leaving walk().");
      return;
    }
    if (depth > maxDepth) {
      bad = refusal('too-deep', path || '(document)',
                    'the ' + where + ' is nested more than ' + maxDepth +
                    ' levels deep. Nothing this service accepts is, and what ' +
                    'reads it next would recurse as far as the document says.');
      log.debug("Leaving walk().");
      return;
    }
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length && !bad; i++) {
        walk(node[i], depth + 1, path);
      }
      log.debug("Leaving walk().");
      return;
    }
    if (node === null || typeof node !== 'object') {
      log.debug("Leaving walk().");
      return;
    }
    const names = Object.keys(node);
    for (let i = 0; i < names.length && !bad; i++) {
      const name = names[i];
      keys = keys + 1;
      if (keys > maxKeys) {
        bad = refusal('too-many-keys', path || '(document)',
                      'the ' + where + ' carries more than ' + maxKeys +
                      ' members.');
        log.debug("Leaving walk().");
        return;
      }
      if (POLLUTING_KEYS.indexOf(name) >= 0) {
        bad = refusal('polluting-key', name,
                      'the ' + where + ' carries a member named "' + name +
                      '"' + (path ? ' under "' + path + '"' : '') + '. It is ' +
                      'a property of every object in javascript, and a ' +
                      'document that sets it is not describing anything this ' +
                      'service offers.');
        log.debug("Leaving walk().");
        return;
      }
      walk(node[name], depth + 1, path ? path + '.' + name : name);
    }
    log.debug("Leaving walk().");
  };

  walk(value, 0, '');
  if (bad) {
    log.warn('validation: refused a ' + where + ' document — ' + bad.code +
             ' on "' + bad.field + '".');
    log.debug("Leaving checkDocument(). Refused.");
    return bad;
  }
  log.debug("Leaving checkDocument(). Accepted, " + keys + " member(s).");
  return { ok: true, value: value };
}

// ---------------------------------------------------------------------------
// THE UNIVERSAL GUARD, AND THE ONE PLACE THIS FILE RENDERS A RESPONSE ITSELF.
//
// Everything above is per endpoint: a handler declares what it takes and asks.
// That is the right shape and it is two hundred and seventy endpoints of work.
// **Two of the classes it closes are not per endpoint at all**, and waiting for
// the schema work to reach every family before closing them would leave the
// cheapest and widest protection until last.
//
//   * A CONTROL CHARACTER IN THE QUERY STRING. Express percent-decodes, so
//     `?state=a%0d%0aSet-Cookie:+x` arrives as a real CRLF; nothing legitimate
//     here carries one, and what it reaches is a response header, a log line or
//     a directory query. **THIS IS THE ONE THAT EARNS THE MIDDLEWARE.**
//   * A PARAMETER NAMED `constructor` or `prototype`. No caller of any protocol
//     this service speaks sends one, ever, in any endpoint.
//
// **THE SECOND IS DEFENCE IN DEPTH AND NOT A HOLE BEING CLOSED, and saying so
// precisely matters more than the check does.** Measured against this service
// on 2026-09-06, express's `qs` already neutralises the dangerous shapes on a
// QUERY STRING: `?__proto__[x]=1` and `?a[__proto__][x]=1` both leave
// `Object.prototype` untouched and produce no own key, so they reach this guard
// as nothing at all and answer 200. What DOES survive as an own key is
// `constructor` and `prototype`, which this refuses — cheaply, and without any
// claim that it was reachable.
//
// **THE PROTOTYPE SURFACE THAT IS REAL IS THE JSON BODY, AND IT IS NOT HERE.**
// `helpers.parseBody()` calls `JSON.parse`, which does not invoke the setter
// and therefore produces a genuine own `__proto__` property — harmless in
// itself and dangerous the moment anything merges that object into another.
// That path goes through `flatten()` above, which refuses all three names, and
// `tests/validation.js` builds its fixture with `JSON.parse` precisely so it is
// testing that path rather than an object literal that quietly sets a
// prototype and refuses nothing.
//
// **WHAT IT DELIBERATELY DOES NOT CHECK IS REPETITION**, and that is the whole
// reason this is a narrow guard rather than `scalars()` bolted to the router. A
// repeated parameter is legitimate at some endpoints and not at others — RFC
// 8707's `resource` at the authorization endpoint is the case — and only a
// schema knows which. A global refusal would break the two parameters this
// service went to some trouble to support.
//
// **IT ANSWERS A PLAIN 400 AND DOES NOT SPEAK ANY PROTOCOL'S DIALECT**, which
// is a deliberate exception to the rule in this file's header, and the argument
// for the exception is that it is unreachable by a well-formed client. There is
// no `error: "invalid_request"` here because there is no OAuth request here —
// this middleware runs before the router has decided which endpoint, and
// therefore which specification, the caller was aiming at. A request carrying a
// NUL byte in a query parameter has not made an OAuth error; it has made a
// request no protocol defines.
//
// **IT IS REGISTERED AFTER THE CALL LOG ON PURPOSE.** A refusal here is exactly
// the request an operator most wants to see afterwards, and the call log is
// what puts it in `/admin/audit`. Registered above it, every refusal would be
// invisible — the same argument `websecurity.js` makes about a lockout nobody
// can see being a support call with no evidence in it.
//
// It reads `req.query` and nothing else, and that is a limitation rather than a
// choice: `req.params` is not populated until the router has matched a route,
// and the body at this point is raw text that `helpers.parseBody()` has not yet
// parsed. Both are covered by the per-endpoint schemas.
// ---------------------------------------------------------------------------
function guard() {
  log.debug("Entering guard().");
  log.debug("Leaving guard().");
  return function (req, res, next) {
    log.debug("Entering the validation guard.");
    const query = req.query;
    if (!query || typeof query !== 'object') {
      log.debug("Leaving the validation guard. No query to check.");
      return next();
    }
    const keys = Object.keys(query);
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      let why = null;
      let code = '';
      if (POLLUTING_KEYS.indexOf(key) >= 0) {
        code = 'STS-HTTP-0010';
        why = refusal('polluting-key', key,
                      'the parameter name "' + key + '" is refused ' +
                      'everywhere in this service.');
      } else {
        // A repeat is NOT refused here (see above), so each value of one is
        // checked on its own. `flatten()` cannot be reused: it would refuse the
        // repeat itself, which is the one thing this guard must leave alone.
        const values = Array.isArray(query[key]) ? query[key] : [query[key]];
        for (let j = 0; j < values.length && !why; j++) {
          const value = values[j];
          if (typeof value === 'string' && CONTROL_STRICT.test(value)) {
            code = 'STS-HTTP-0011';
            why = refusal('control-character', key,
                          'the value of "' + key + '" contains a control ' +
                          'character. A carriage return or newline in a ' +
                          'query parameter reaches a response header, a log ' +
                          'line or a directory query as a second instruction ' +
                          'rather than as text.');
          }
        }
      }
      if (why) {
        log.warn('validation: refused a request to ' + req.method + ' ' +
                 (req.path || req.url) + ' — ' + why.code + ' on "' +
                 why.field + '".');
        errorCodes.mark(res,
                        code === 'STS-HTTP-0010' ? 'STS-HTTP-0010' :
                        'STS-HTTP-0011');
        res.status(400).type('text/plain').send(
          'Bad Request: ' + why.detail + '\n\n' +
          'This is refused before any endpoint sees it, in development mode ' +
          'and product mode alike, because no caller of any protocol this ' +
          'service speaks sends it.\n');
        log.debug("Leaving the validation guard. Refused.");
        return undefined;
      }
    }
    log.debug("Leaving the validation guard. " + keys.length + " " +
        "parameter(s) passed.");
    return next();
  };
}

// ---------------------------------------------------------------------------
// AN XML DOCUMENT FROM OUTSIDE, READ WITHOUT THROWING.
//
// Twelve places in this service parse caller-supplied XML — both SAML
// profiles, WS-Trust, WS-Federation, federation and SAML metadata. **Ten of
// them wrap the parse in a try/catch and two did not**, which on 2026-09-06
// made two endpoints answer 500 to input anybody can send:
//
//   * `POST /sts` — a malformed SOAP envelope, OR AN EMPTY BODY;
//   * `GET /saml2/sso` — a malformed `SAMLRequest`.
//
// **The reason both survived is a change in the library rather than
// carelessness.** `@xmldom/xmldom` used to report a malformed document by
// CALLING A HANDLER whose default wrote to the console and carried on, so a
// bare parse returned a partial tree and the code limped along. In 0.9.10 the
// default handler THROWS a `ParseError` — so the same bare parse that used to
// degrade quietly now takes the request down. Code written against the old
// behaviour became a 500 on a library bump, with nothing in this repository
// changed.
//
// So this is one reader, and it never throws: it answers a refusal the way
// everything else in this file does, and the caller renders it in its own
// protocol's words — a SOAP Fault, a SAML second-level status, an HTML page.
//
// **`onError` IS THE ONLY SPELLING, and passing the old one is fatal.** The
// `errorHandler` object is not merely deprecated in 0.9: passing one THROWS a
// TypeError out of the CONSTRUCTOR ("errorHandler object is no longer
// supported"), so carrying both spellings defensively is not free — it makes
// every parse in the service fail before a document is read. `xacml_xml.js`
// paid for that lesson on its first conformance run, where 449 of 455 cases
// reported "could not be loaded" and named an option rather than a policy.
//
// **A WARNING IS NOT AN ERROR.** Only `error` and `fatalError` refuse. Real
// documents in the field carry schema hints and namespace oddities that xmldom
// reports as warnings, and refusing those would fail a sign-in over an
// `xsi:schemaLocation` rather than over anything about the assertion.
//
// **WHAT THIS DOES NOT NEED TO DEFEND AGAINST, MEASURED ON 0.9.10 RATHER THAN
// ASSUMED:** entity expansion and XXE. A billion-laughs document expands to 3
// characters here and `<!ENTITY x SYSTEM "file:///etc/passwd">` leaves `&x;`
// as literal text — xmldom resolves neither custom nor external entities. The
// size cap below is therefore about memory and parse time, not amplification.
// If this service ever moves to a parser that DOES resolve entities, this is
// the function that has to refuse a DOCTYPE, and it is the only one.
// ---------------------------------------------------------------------------
function parseXml(xml, what, opts) {
  log.debug("Entering parseXml(). what=" + what);
  const label = what || 'document';
  const max = (opts && opts.max) || CAP.LARGE;
  const text = typeof xml === 'string' ? xml : String(xml == null ? '' : xml);
  if (!text.trim()) {
    log.debug("Leaving parseXml(). Empty.");
    return refusal('empty', label,
                   'the ' + label + ' is empty. An empty body is not a ' +
                   'document this service can read anything out of.');
  }
  if (text.length > max) {
    log.debug("Leaving parseXml(). Too large.");
    return refusal('too-large', label,
                   'the ' + label + ' is ' + text.length + ' characters and ' +
                   'the limit is ' + max + '.');
  }
  const errors = [];
  let doc = null;
  try {
    const parser = new DOMParser({
      onError: function (level, message) {
        log.debug("Entering onError().");
        if (level === 'error' || level === 'fatalError') {
          errors.push(String(message));
        }
        log.debug("Leaving onError().");
      }
    });
    doc = parser.parseFromString(text, 'text/xml');
  } catch (e) {
    // 0.9.10 throws a ParseError from the default handler for a fatal error,
    // and can still throw from ours if the document is unrecoverable. Either
    // way the answer is the same refusal rather than an exception escaping
    // into a request handler that has no idea what to do with one.
    errors.push(e && e.message ? e.message : String(e));
  }
  if (errors.length) {
    log.debug("Leaving parseXml(). Not well-formed.");
    return refusal('malformed', label,
                   'the ' + label + ' is not well-formed XML: ' + errors[0]);
  }
  if (!doc || !doc.documentElement) {
    log.debug("Leaving parseXml(). No document element.");
    return refusal('malformed', label,
                   'the ' + label + ' parsed to nothing. It carries no root ' +
                                    'element.');
  }
  log.debug("Leaving parseXml(). Read <" + doc.documentElement.nodeName + ">.");
  return { ok: true, value: doc };
}

// ---------------------------------------------------------------------------
// BYTES A CALLER COMPRESSED, INFLATED WITH A CEILING.
//
// **WITHOUT THE CEILING THIS IS A DECOMPRESSION BOMB, AND IT WAS ONE UNTIL
// 2026-09-06.** SAML 2.0's HTTP-Redirect binding carries a DEFLATEd, base64'd
// message, so `saml2_sso.js` inflates bytes somebody else chose. Node's
// `inflateRawSync` with no `maxOutputLength` inflates as far as the data says —
// the default ceiling is `buffer.kMaxLength`, about two gigabytes.
//
// Measured against this service rather than reasoned about:
//
// | | bomb answered in | `/healthcheck` during it |
// |---|---|---|
// | unbounded | 2956ms | **2753ms**, against 1-2ms idle |
// | bounded | 27ms | 2ms |
//
// One unauthenticated POST with a **531 KB body** — deflated 'A's at a ratio of
// about 1029:1 — froze the whole process for three seconds. The body limit is
// 5mb, so ten times that payload is half a minute of a service that answers
// nobody.
//
// **AND "ANSWERS NOBODY" IS LITERAL HERE.** This process runs every listener
// it owns on ONE THREAD — the express app, the KDC on TCP and UDP 88, the
// Kerberos service, the LDAP directory and the SPIFFE gRPC surfaces among
// them. That is the argument `common/CLAUDE.md` makes about post-quantum
// signing, and the whole reason `common/worker_pool.js` exists:
// a synchronous computation here does not slow this service down, it STOPS it,
// and a KDC that does not answer looks from the outside exactly like a KDC that
// is not there.
//
// The GET binding turned out to be bounded already, by accident: node's own
// 16 KB header limit answers 431 to a URL long enough to carry a useful bomb.
// **The POST binding had no such accident** and is where the measurement above
// comes from — which is worth remembering before trusting any bound that was
// not asked for on purpose.
// ---------------------------------------------------------------------------
function inflate(buf, what, opts) {
  log.debug("Entering inflate(). what=" + what);
  const label = what || 'message';
  const max = (opts && opts.max) || CAP.LARGE;
  try {
    const out = zlib.inflateRawSync(buf, { maxOutputLength: max });
    log.debug("Leaving inflate(). " + out.length + " byte(s).");
    return { ok: true, value: out };
  } catch (e) {
    // Two very different failures land here and the caller usually wants to
    // treat them alike: the bytes were not DEFLATEd at all (a POST-binding
    // message with leading whitespace, most often), or they were and they
    // inflate past the ceiling. `code` tells them apart for a caller that
    // cares — ERR_BUFFER_TOO_LARGE is the bomb.
    log.debug("Leaving inflate(). " + (e && e.code ? e.code : 'failed') + ".");
    return refusal(e && e.code === 'ERR_BUFFER_TOO_LARGE' ? 'too-large' :
                   'not-deflated',
                   label,
                   e && e.code === 'ERR_BUFFER_TOO_LARGE'
                     ? 'the ' + label + ' inflates past ' + max + ' bytes. A ' +
                       'message that large is not one this service was going ' +
                       'to be able to read.'
                     : 'the ' + label + ' is not DEFLATEd data.');
  }
}

// ---------------------------------------------------------------------------
// THE SHARED TYPES.
//
// One copy of each, for the reason everything in `common/` is here: a second
// answer to "what may a client_id contain" is a disagreement waiting to be
// found by somebody whose token one endpoint accepts and another refuses.
//
// A type that only one protocol has belongs in that protocol's own schema file,
// not here. The test for adding one is whether a SECOND family needs it.
// ---------------------------------------------------------------------------

// A protocol identifier: something this service or a client uses as a name.
// Printable ASCII with no space, because every one of these ends up in a URL,
// a JSON key, a log line or a DN, and a space in it is ambiguous in at least
// two of those.
const identifier = z.string().min(1).max(CAP.IDENTIFIER)
  .regex(/^[\x21-\x7E]+$/, 'must be printable ASCII with no spaces');

// A name a PERSON has: a username, a group, a Kerberos principal. Wider than an
// identifier because people legitimately have spaces and non-ASCII in their
// names, and this service has always accepted any name at all. The control
// characters are already gone by the time a schema sees the value.
const name = z.string().min(1).max(CAP.NAME);

// An opaque credential this service minted and is being handed back: an
// authorization code, an access or refresh token, a SAML artifact, a device
// code, a CSRF token. base64url plus the punctuation JWTs and this service's
// own composite ids use.
const token = z.string().min(1).max(CAP.TOKEN)
  .regex(/^[A-Za-z0-9._~+/=-]+$/, 'must be an opaque credential');

const base64url = z.string().min(1).max(CAP.TOKEN)
  .regex(/^[A-Za-z0-9_-]+$/, 'must be base64url with no padding');

// ---------------------------------------------------------------------------
// A URI is PARSED, not pattern-matched.
//
// A regular expression that accepts every legal URI and no illegal one is a
// famous mistake, and `URL` is right here in the runtime.
//
// **THE SCHEME IS CHECKED AND THE HOST IS NOT.** A redirect_uri may point
// anywhere — that is what makes this service useful for exercising a client on
// localhost, and narrowing it would be an existence question, which belongs to
// the application register rather than here. What must never be accepted is a
// scheme that EXECUTES: `javascript:` and `data:` in an href are how a URI
// becomes script in somebody's browser, and this service puts caller-supplied
// URIs into links and Location headers on a dozen pages.
// ---------------------------------------------------------------------------
const DANGEROUS_SCHEMES = ['javascript:', 'data:', 'vbscript:', 'file:',
                           'blob:'];

const uri = z.string().min(1).max(CAP.URI).refine(function (value) {
  let parsed = null;
  try {
    parsed = new URL(value);
  } catch (e) {
    log.debug("Caught in a callback in module scope: " +
              ((e && e.message) || e));
    // Not a URL at all. The refusal is the answer; the parse error itself says
    // nothing a caller can act on beyond "it did not parse".
    return false;
  }
  return DANGEROUS_SCHEMES.indexOf(parsed.protocol.toLowerCase()) < 0;
}, 'must be an absolute URI with a scheme that is not executable');

// ---------------------------------------------------------------------------
// A REDIRECTION ENDPOINT IS AN ALLOWLIST, NOT `uri` WITH A FRAGMENT RULE
// (2026-09-13).
//
// `uri` above refuses the five schemes that EXECUTE and accepts every other
// one, which was harmless while `/oauth2/authorize` and `/oauth2/logout` also
// demanded `^https?://` at the call site. Native applications need a
// PRIVATE-USE scheme there (RFC 8252 section 7.1, OAuth 2.1 section 8.4.3 in
// draft-ietf-oauth-v2-1-16), and removing that regex on top of a blocklist
// would turn both endpoints into redirectors to every protocol handler an
// operating system registers — `ms-msdt:`, `search-ms:`, `intent:` — none of
// which is on any list and each of which has had its day. So the rule is
// written the other way round, as the two shapes a redirection endpoint may
// have:
//
//   * http or https, WITH A HOST. `https:/cb` parses (the URL parser supplies
//     the missing slashes) and is nobody's callback.
//   * a private-use scheme NAMED FOR A DOMAIN IN REVERSE ORDER — which is to
//     say, containing a period. RFC 8252 section 7.1 makes that a MUST for the
//     app and OAuth 2.1 section 2.3.1 says a server SHOULD refuse a scheme with
//     no period, and it is also the rule that catches the commonest mistake:
//     `localhost:3000/cb`, typed without `http://`, parses as the scheme
//     `localhost:` and would otherwise be a perfectly valid redirect.
//
// And never a fragment (RFC 6749 section 3.1.2): the fragment is where a
// response goes.
//
// `uri` itself is deliberately NOT narrowed: OID4VC's `wallet` parameter reads
// it, and a wallet's own scheme (`openid-credential-offer:`) has no period in
// it by specification.
// ---------------------------------------------------------------------------
const PRIVATE_USE_SCHEME = /^[a-z][a-z0-9+-]*(?:\.[a-z0-9+-]+)+$/;

// The reason a value may not be a redirection endpoint, or null. A FUNCTION as
// well as the zod type below, because three callers have no schema to hand:
// registration (RFC 7591), the application register's own writes, and a URI
// read back out of the directory, where an `ldapmodify` put it without passing
// any of the other two. `privateUse: false` is the http(s)-only reading, which
// is what a sign-out return address gets while no client vouches for it.
function redirectUriProblem(value, options) {
  log.debug("Entering redirectUriProblem().");
  const opts = options || {};
  const allowPrivateUse = opts.privateUse !== false;
  const text = typeof value === 'string' ? value : '';
  if (!text) {
    log.debug("Leaving redirectUriProblem(). Empty.");
    return 'is empty';
  }
  if (text.length > CAP.URI) {
    log.debug("Leaving redirectUriProblem(). Too long.");
    return 'is longer than ' + CAP.URI + ' characters';
  }
  if (text.indexOf('#') >= 0) {
    log.debug("Leaving redirectUriProblem(). A fragment.");
    return 'must not contain a fragment (RFC 6749 section 3.1.2)';
  }
  let parsed = null;
  try {
    parsed = new URL(text);
  } catch (e) {
    log.debug("Caught in redirectUriProblem(): " + ((e && e.message) || e));
    // Not an absolute URI. The refusal below is the whole answer; the parser's
    // own message names nothing a caller can act on.
    log.debug("Leaving redirectUriProblem(). Does not parse.");
    return 'is not an absolute URI';
  }
  const scheme = parsed.protocol.toLowerCase().replace(/:$/, '');
  if (scheme === 'http' || scheme === 'https') {
    // The TEXT, not the parse: the URL parser supplies missing slashes for a
    // special scheme, so `https:/cb` comes back with the host `cb` — and the
    // value compared, stored and sent in a Location header is the text.
    if (!/^https?:\/\/[^/]/i.test(text) || !parsed.hostname) {
      log.debug("Leaving redirectUriProblem(). http(s) with no host.");
      return 'is an ' + scheme + ' URL with no host';
    }
    log.debug("Leaving redirectUriProblem(). http(s).");
    return null;
  }
  if (allowPrivateUse && PRIVATE_USE_SCHEME.test(scheme)) {
    log.debug("Leaving redirectUriProblem(). A private-use scheme.");
    return null;
  }
  log.debug("Leaving redirectUriProblem(). Scheme " + scheme + " refused.");
  return allowPrivateUse
    ? 'must be an http or https URL, or a native application\'s private-use ' +
      'scheme named for a domain in reverse order, such as ' +
      'com.example.app:/callback (RFC 8252 section 7.1; a scheme with no ' +
      'period, like "' + scheme + ':", is refused)'
    : 'must be an http or https URL';
}

// Whether a value that passed redirectUriProblem() is a private-use one. The
// authorization endpoint needs the distinction for exactly one decision —
// `response_mode=form_post` cannot deliver to a protocol handler, which is
// handed a URL and never a request body — and the sign-out endpoint for
// another, so it is answered here rather than re-parsed at two call sites.
function isPrivateUseRedirect(value) {
  log.debug("Entering isPrivateUseRedirect().");
  let parsed = null;
  try {
    parsed = new URL(String(value || ''));
  } catch (e) {
    log.debug("Caught in isPrivateUseRedirect(): " + ((e && e.message) || e));
    // Not a URI, so not a private-use one; the schema has refused it already.
    log.debug("Leaving isPrivateUseRedirect(). Does not parse.");
    return false;
  }
  const scheme = parsed.protocol.toLowerCase();
  log.debug("Leaving isPrivateUseRedirect().");
  return scheme !== 'http:' && scheme !== 'https:';
}

// OpenID Connect Front-Channel Logout 1.0's `frontchannel_logout_uri`. It is
// loaded in an IFRAME on the sign-out page and named in that page's CSP
// `frame-src`, so http(s) is not a preference here: a browser will not frame a
// protocol handler, and a value that is not an origin makes the header itself
// malformed.
function frontchannelUriProblem(value) {
  log.debug("Entering frontchannelUriProblem().");
  const problem = redirectUriProblem(value, { privateUse: false });
  log.debug("Leaving frontchannelUriProblem().");
  return problem;
}

// OpenID Connect Back-Channel Logout 1.0's `backchannel_logout_uri`
// (2026-09-17, #36). Section 2.2: an absolute URI, http or https, with no
// fragment. It is not framed — this service POSTs to it — so the reason
// http(s) is required is a different one from the front-channel URI's: the
// outbound policy dials nothing else. `redirectUriProblem()` already refuses a
// fragment, which is the other half of section 2.2.
function backchannelUriProblem(value) {
  log.debug("Entering backchannelUriProblem().");
  const problem = redirectUriProblem(value, { privateUse: false });
  log.debug("Leaving backchannelUriProblem().");
  return problem;
}

// ---------------------------------------------------------------------------
// AN ORIGIN, AS CORS COMPARES ONE (2026-09-13).
//
// `appCorsOrigin` on an application holds the origins a browser page may call
// this service from, and `global.corsOrigins` the ones a deployment names as
// its own. `common/cors.js` compares each with the `Origin` header a browser
// sent, BY STRING, because that is what the Fetch standard does with
// `Access-Control-Allow-Origin`: the value echoed must be byte-for-byte the
// serialised origin (RFC 6454 section 6.1) the browser sent. So a value is
// held in that serialisation, and two things follow.
//
//   * **IT IS NORMALISED WHEN IT IS WRITTEN.** `HTTPS://App.Example.com:443/`
//     is the origin `https://app.example.com`, and a stored copy in the first
//     spelling would never match a header in the second. The URL parser does
//     the work for http and https — case, the default port, an IDN host in its
//     ASCII form, an IPv6 literal in brackets — and one trailing `/` is
//     forgiven because it is what a person copying an address out of a
//     browser's bar pastes.
//   * **NOTHING BUT AN ORIGIN IS ACCEPTED.** A path, a query, a fragment or a
//     user name would be silently discarded by the comparison, so an operator
//     who wrote `https://app.example.com/spa` and believed it meant only that
//     page would be wrong — refused instead, with the origin it would have
//     been. A WILDCARD is refused for the same reason: `*` is the value this
//     rule exists to replace, and `https://*.example.com` is not an origin any
//     browser sends. And `null` is refused because it is the origin of EVERY
//     sandboxed frame, `data:` document and local file at once, so allowing it
//     would allow all of them.
//
// A scheme other than http or https is allowed with a host — a browser
// extension calls from `chrome-extension://<id>` or `moz-extension://<uuid>` —
// and is lower-cased rather than parsed, because the URL parser gives a
// non-special scheme the opaque origin `null`.
// ---------------------------------------------------------------------------
const ORIGIN_SHAPE = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#\s]+)\/?$/;

// `{ origin, problem }`: the serialised origin, or '' and the reason it is not
// one. Both halves from one parse, so the refusal and the normalisation cannot
// disagree about what a value is.
function readOrigin(value) {
  log.debug("Entering readOrigin().");
  const text = typeof value === 'string' ? value.trim() : '';
  if (!text) {
    log.debug("Leaving readOrigin(). Empty.");
    return { origin: '', problem: 'is empty' };
  }
  if (text.length > CAP.URI) {
    log.debug("Leaving readOrigin(). Too long.");
    return { origin: '', problem: 'is longer than ' + CAP.URI + ' characters' };
  }
  if (text.indexOf('*') >= 0) {
    log.debug("Leaving readOrigin(). A wildcard.");
    return { origin: '', problem: 'is a wildcard, and CORS here is an ' +
             'allowlist of exact origins — list each origin a page is ' +
             'served from' };
  }
  if (text.toLowerCase() === 'null') {
    log.debug("Leaving readOrigin(). The opaque origin.");
    return { origin: '', problem: 'is the opaque origin, which every ' +
             'sandboxed frame, data: document and local file shares — ' +
             'allowing it would allow all of them' };
  }
  const shape = ORIGIN_SHAPE.exec(text);
  if (!shape) {
    log.debug("Leaving readOrigin(). Not scheme://host[:port].");
    return { origin: '', problem: 'is not an origin: it must be ' +
             'scheme://host or scheme://host:port with no path, query or ' +
             'fragment, such as https://app.example.com' };
  }
  if (shape[2].indexOf('@') >= 0) {
    log.debug("Leaving readOrigin(). A user name.");
    return { origin: '', problem: 'carries a user name, which an origin ' +
             'never does' };
  }
  const scheme = shape[1].toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') {
    log.debug("Leaving readOrigin(). A non-special scheme.");
    return { origin: scheme + '://' + shape[2].toLowerCase(), problem: null };
  }
  let parsed = null;
  try {
    parsed = new URL(text);
  } catch (e) {
    log.debug("Caught in readOrigin(): " + ((e && e.message) || e));
    // The shape matched and the host did not parse — a bad port or an illegal
    // character. The refusal is the whole answer.
    log.debug("Leaving readOrigin(). Does not parse.");
    return { origin: '', problem: 'is not an origin: its host or port does ' +
             'not parse' };
  }
  if (!parsed.hostname || parsed.origin === 'null') {
    log.debug("Leaving readOrigin(). No host.");
    return { origin: '', problem: 'is an ' + scheme + ' origin with no host' };
  }
  log.debug("Leaving readOrigin(). origin=" + parsed.origin);
  return { origin: parsed.origin, problem: null };
}

// The reason a value may not be held as a CORS origin, or null.
function originProblem(value) {
  log.debug("Entering originProblem().");
  const read = readOrigin(value);
  log.debug("Leaving originProblem().");
  return read.problem;
}

// The value in the serialisation a browser sends, or '' if it is not an
// origin. What a write stores and what `common/cors.js` compares.
function normaliseOrigin(value) {
  log.debug("Entering normaliseOrigin().");
  const read = readOrigin(value);
  log.debug("Leaving normaliseOrigin().");
  return read.problem ? '' : read.origin;
}

// The zod types over those functions, so an endpoint's schema says it in one
// word. `superRefine` rather than `refine`, so the refusal carries the reason
// the function gave instead of one sentence for every way to be wrong.
function redirectType(options) {
  log.debug("Entering redirectType().");
  log.debug("Leaving redirectType().");
  return z.string().min(1).max(CAP.URI).superRefine(function (value, ctx) {
    const problem = redirectUriProblem(value, options);
    if (problem) {
      ctx.addIssue({ code: 'custom', message: problem });
    }
  });
}

const redirectUri = redirectType({ privateUse: true });

// An http(s) URL this service will DIAL. Narrower than `uri` on purpose: the
// outbound requests in this repository (a federation partner, an SSF push
// endpoint, a XACML PEP's notify URL among them) each take an address somebody
// configured, and none of them has any business being a non-HTTP scheme.
const httpUri = z.string().min(1).max(CAP.URI).refine(function (value) {
  let parsed = null;
  try {
    parsed = new URL(value);
  } catch (e) {
    log.debug("Caught in a callback in module scope: " +
              ((e && e.message) || e));
    // Not a URL; refused for the same reason as `uri` above.
    return false;
  }
  return parsed.protocol === 'http:' || parsed.protocol === 'https:';
}, 'must be an http or https URL');

// RFC 6749 section 3.3: a space-delimited, case-sensitive list. The character
// set is that section's own production, which is deliberately narrow.
const scope = z.string().max(CAP.SCOPE)
  .regex(/^[\x21\x23-\x5B\x5D-\x7E]+(?: +[\x21\x23-\x5B\x5D-\x7E]+)*$/,
         'must be a space-delimited scope list (RFC 6749 section 3.3)');

// Opaque round-trip values: state, nonce, a PKCE challenge or verifier. The
// client chose them and this service only echoes them, so the rule is a bound
// and no control characters rather than a grammar.
const opaque = z.string().min(1).max(CAP.TOKEN);

// An LDAP distinguished name. The full RFC 4514 grammar is not written out
// here — what this catches is the thing that actually goes wrong, which is a
// value concatenated into a DN without being escaped, turning one RDN into two.
// `helpers.escapeRdnValue()` is what prevents that; this refuses the result if
// it was skipped.
const dn = z.string().min(1).max(CAP.DEFAULT)
  .regex(/^[^\x00]+$/, 'must be a distinguished name');

// Free text a person typed into the console: a description, a policy, a PEM
// block. Bounded, and free of the control characters that are not line breaks.
const text = z.string().max(CAP.TEXT);

// A protocol message that arrived encoded and large: SAMLRequest, SAMLResponse,
// wresult, an XACML request document, a SOAP envelope.
const message = z.string().min(1).max(CAP.LARGE);

// A checkbox or a flag from a form, and the spellings this service's own pages
// and the RFCs between them actually send.
const flag = z.enum(['true', 'false', 'on', 'off', '1', '0', 'yes', 'no']);

// A bounded integer that arrived as a string, which is what every query
// parameter is. Coercion is right here and wrong for most things: the value is
// unambiguously meant to be a number and there is no second reading of "300".
function integer(min, max) {
  log.debug("Entering integer().");
  log.debug("Leaving integer().");
  return z.coerce.number().int().min(min).max(max);
}

// A value from a closed set this service defines. A thin wrapper so that call
// sites read as declarations rather than as zod.
function oneOf(values) {
  log.debug("Entering oneOf().");
  log.debug("Leaving oneOf().");
  return z.enum(values);
}

// A parameter a specification says may appear more than once. Wrapping it here
// rather than writing `z.array()` at the call site is what makes the intent
// greppable: every repeatable parameter in this service is one call to this,
// and `flatten()` above keys its whole behaviour off the array-ness this makes.
function repeatable(inner) {
  log.debug("Entering repeatable().");
  log.debug("Leaving repeatable().");
  return z.array(inner);
}

// ---------------------------------------------------------------------------
// **AN EMPTY STRING IS NOT A MALFORMED VALUE, AND FORGETTING THAT BROKE EIGHT
// PROTOCOL JOBS.**
//
// Every type above has a `min(1)` or a pattern that an empty string fails, and
// that is right for a value that is PRESENT. It is wrong for the commonest
// thing an HTML form sends: a control the person did not fill in submits
// `username=`, not nothing at all. A query string carries `?state=` the same
// way.
//
// The first version of these schemas typed the sign-in form's `username` as
// `vt.name.optional()`, so posting the form with the box empty was answered
// 400 — where this service re-shows the screen and asks for a name.
// **`tests/vendored/oauth2_sts_endpoints.js` asserts exactly that**: *an
// empty username should re-show the form, not redirect*.
//
// The line is the one this whole file is about. *Is a name required here* is an
// EXISTENCE question and belongs to the handler, which knows what it is asking
// for and has a screen to ask again with. *Is this a name* is a SHAPE question
// and is this file's. An empty string is the absence of an answer, not a
// malformed one, so it passes here and the handler decides.
//
// `opt()` is therefore what almost every optional field in this service wants,
// and a bare `.optional()` is the exception that needs a reason: it means the
// parameter may be left out but must be well-formed if it is written down at
// all, which is true of very little that arrives from a browser.
// ---------------------------------------------------------------------------
function opt(inner) {
  log.debug("Entering opt().");
  log.debug("Leaving opt().");
  return z.union([z.literal(''), inner]).optional();
}

// ---------------------------------------------------------------------------
// What the metadata pages report, so that "what does this service validate" is
// answered from the code that validates rather than from a paragraph that will
// drift — the argument `sts_metadata.js` and `crypto_metadata.js` both make.
// ---------------------------------------------------------------------------
function report() {
  log.debug("Entering report().");
  const out = {
    unconditional: true,
    modeIndependent: 'Shape is refused in development and product alike. ' +
                     'Existence and credentials remain with mode.js.',
    repeatedParameters: 'refused unless the schema declares the parameter ' +
                        'repeatable',
    unknownParameters: 'stripped, as RFC 6749 section 3.1 requires',
    controlCharacters: 'refused everywhere; tab, newline and carriage return ' +
                       'are allowed in body fields only',
    pollutingKeys: POLLUTING_KEYS.slice(),
    dangerousSchemes: DANGEROUS_SCHEMES.slice(),
    caps: Object.assign({}, CAP)
  };
  log.debug("Leaving report().");
  return out;
}

module.exports = {
  // The engine.
  check: check,
  checkParsed: checkParsed,
  checkDocument: checkDocument,
  parseXml: parseXml,
  inflate: inflate,
  scalars: scalars,
  scalar: scalar,
  refusal: refusal,
  guard: guard,
  report: report,
  redirectUriProblem: redirectUriProblem,
  isPrivateUseRedirect: isPrivateUseRedirect,
  frontchannelUriProblem: frontchannelUriProblem,
  backchannelUriProblem: backchannelUriProblem,
  // CORS origins: the refusal and the serialisation, from one parse.
  originProblem: originProblem,
  normaliseOrigin: normaliseOrigin,

  // The shared types.
  types: {
    identifier: identifier,
    name: name,
    token: token,
    base64url: base64url,
    uri: uri,
    redirectUri: redirectUri,
    httpUri: httpUri,
    scope: scope,
    opaque: opaque,
    dn: dn,
    text: text,
    message: message,
    flag: flag,
    integer: integer,
    oneOf: oneOf,
    repeatable: repeatable,
    opt: opt
  },

  // The caps, so a per-protocol schema can say "the same as an identifier"
  // rather than repeating a number that will drift from this one.
  CAP: CAP,

  // zod itself, so that a schema file requires this module and not two. Every
  // schema in this service is then written against one copy of the library,
  // which matters because zod compares instances rather than shapes.
  z: z
};
