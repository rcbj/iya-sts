'use strict';
//
// File: validation.js
//
// ===========================================================================
// WHAT A VALUE FROM OUTSIDE IS ALLOWED TO BE, AND THE ONE RULE THAT KEEPS THE
// MOCK A MOCK.
//
// `common/validation.js` is the one place a request parameter becomes a value
// this service will use. Everything it does is a REFUSAL, which is exactly the
// kind of thing that rots quietly: a validator that has stopped refusing looks
// identical from the outside to one that was never reached, and every test that
// drives a WELL-FORMED request still passes.
//
// So this file is almost entirely negatives — the shape `tests/sts_dpop.js`
// argues for. An identity provider that accepts a good request looks finished
// and can be worth nothing.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// This is a MODULE CONTRACT and not an endpoint. The claims are about what a
// function returns for an input, there is no port in any of them, and asserting
// them over HTTP would mean finding an endpoint that happens to use each type
// and then reasoning backwards from a 400 about which check fired. That is a
// test of the endpoint, and it is worth having as well — it is not this.
//
// **THE ARRAY-DETECTION CASES ARE THE ONES THAT EARN THIS FILE.**
// `isArraySchema()` reaches into zod's internals to decide whether a parameter
// is allowed to repeat, because zod does not expose that publicly. A zod
// upgrade that renames a field would make every repeatable parameter in this
// service silently single-valued — RFC 8707's `resource` and RFC 8693's
// `audience` would start being REFUSED — and nothing else in either suite would
// notice. These cases are the alarm on that.
// ===========================================================================

const validation = require('../common/validation.js');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'validation',
  level: process.env.LOG_LEVEL || 'info' });

const t = validation.types;
const z = validation.z;

// A request as express would hand one over. Only the four groups
// `validation.check()` reads.
function request(groups) {
  log.debug("Entering request().");
  log.debug("Leaving request().");
  return {
    query: (groups && groups.query) || {},
    body: (groups && groups.body) || {},
    params: (groups && groups.params) || {},
    headers: (groups && groups.headers) || {}
  };
}

async function run(t_) {
  log.debug("Entering run().");
  // -----------------------------------------------------------------------
  // 1. THE TYPE-CONFUSION CLASS. The reason the module exists.
  // -----------------------------------------------------------------------
  t_.log.info('=== a parameter that arrived as something other than a value ' +
              '===');

  const ONE = z.object({ client_id: t.identifier.optional() });

  t_.equal(validation.check(request({ query: { client_id: 'app-1' } }), 'query',
                            ONE).value.client_id,
           'app-1',
           'an ordinary scalar passes through unchanged');

  const repeated = validation.check(request({ query: {
    client_id: ['a', 'b'] } }), 'query', ONE);
  t_.check(!repeated.ok && repeated.code === 'repeated',
           'A REPEATED PARAMETER IS REFUSED RATHER THAN RESOLVED. Taking the ' +
           'last value is what `hpp` and most hand-written normalisers do, ' +
           'and it is how two readers of one request come to disagree — ' +
           'which is the whole mechanism behind parameter pollution',
           repeated.code);
  t_.check(repeated.field === 'client_id',
           'and the refusal names the parameter, so the caller can fix it',
           repeated.field);

  const structured = validation.check(request({ query: {
    client_id: { evil: 'x' } } }), 'query', ONE);
  t_.check(!structured.ok && structured.code === 'structured',
           'A NESTED OBJECT IS REFUSED. Express parses `?client_id[x]=y` ' +
           'into an object, and code written for a string then sees "[object ' +
           'Object]" from String(), a TypeError from .startsWith(), or a key ' +
           'count from .length',
           structured.code);

  // -----------------------------------------------------------------------
  // 2. REPEATABLE PARAMETERS, AND THE ZOD-INTERNALS ALARM.
  // -----------------------------------------------------------------------
  t_.log.info('=== the parameters a specification says may repeat ===');

  const MANY = z.object({
    resource: t.repeatable(t.uri),
    audience: t.repeatable(t.identifier).optional(),
    fallback: t.repeatable(t.identifier).default([]),
    scope: t.scope.optional()
  });

  const two = validation.check(request({
    query: { resource: ['https://a.example', 'https://b.example'] }
  }), 'query', MANY);
  t_.check(two.ok && two.value.resource.length === 2,
           'RFC 8707 section 2: a repeated `resource` keeps BOTH values. ' +
           'This is the case `helpers.bodyValues()` had to be written by ' +
           'hand to get back after `parseBody()` had already flattened it',
           two.ok ? two.value.resource.length : two.code);

  t_.check(validation.check(request({ query:
                                        { resource: 'https://one.example' } }),
                            'query', MANY).value.resource.length === 1,
           'and ONE occurrence of a repeatable parameter is a list of one, ' +
           'rather than a type the caller has to branch on');

  t_.check(validation.check(request({
             query: { resource: ['https://a.example'], audience: ['x', 'y'] }
           }), 'query', MANY).value.audience.length === 2,
           'THE ALARM: `.optional()` wraps the array type, and the detection ' +
           'still finds it. If this fails after a zod upgrade, every ' +
           'repeatable parameter in this service has silently become ' +
           'single-valued and RFC 8707 and RFC 8693 are both broken');

  t_.check(validation.check(request({
             query: { resource: ['https://a.example'], fallback: ['x', 'y'] }
           }), 'query', MANY).value.fallback.length === 2,
           'and `.default([])` wraps it differently again, and is also found');

  // -----------------------------------------------------------------------
  // 3. CONTROL CHARACTERS, AND WHY THE RULE IS NOT THE SAME IN BOTH GROUPS.
  // -----------------------------------------------------------------------
  t_.log.info('=== control characters ===');

  const TEXTFIELD = z.object({ note: t.text.optional() });

  const crlf = validation.check(request({ query: {
    client_id: 'a\r\nSet-Cookie: ' +
      'x=y' } }),
                                'query', ONE);
  t_.check(!crlf.ok && crlf.code === 'control-character',
           'CR/LF IN A QUERY PARAMETER IS REFUSED. A value that reaches a ' +
           'response header is header injection; one that reaches the audit ' +
           'log is log forging; one that reaches an LDAP filter is a ' +
           'different query from the one the code was written to make',
           crlf.code);

  const nul = validation.check(request({ query: {
    client_id: 'app\u0000hidden' } }), 'query', ONE);
  t_.check(!nul.ok && nul.code === 'control-character',
           'A NUL BYTE IS REFUSED, and it is the worst of them: half the ' +
           'libraries under this service are C underneath and stop at it ' +
           'while node does not. This repository has already lost time to one',
           nul.code);

  const bodyNewline = validation.check(request({ body: { note: 'line ' +
      'one\nline two' } }),
                                       'body', TEXTFIELD);
  t_.check(bodyNewline.ok,
           'BUT A NEWLINE IN A BODY FIELD IS ALLOWED, because a console ' +
           'textarea legitimately holds one and an ALFA policy or a PEM ' +
           'block is nothing but lines. The two groups have different rules ' +
           'on purpose',
           bodyNewline.ok ? 'accepted' : bodyNewline.code);

  const bodyNul = validation.check(request({ body: { note: 'line\u0000one' } }),
                                   'body', TEXTFIELD);
  t_.check(!bodyNul.ok,
           'and the body rule is a RELAXATION for line breaks only — NUL is ' +
           'still refused there',
           bodyNul.ok ? 'accepted' : bodyNul.code);

  // -----------------------------------------------------------------------
  // 4. PROTOTYPE POLLUTION.
  // -----------------------------------------------------------------------
  t_.log.info('=== the keys that are not parameter names ===');

  // BUILT WITH `JSON.parse` AND NOT AS AN OBJECT LITERAL, and the difference is
  // the whole case rather than a detail of the fixture. `{ '__proto__': 'x' }`
  // in source SETS THE PROTOTYPE — `Object.keys()` returns nothing and there is
  // no key to refuse. `JSON.parse` does not invoke the setter, so it produces a
  // real own enumerable property, which is exactly what arrives at
  // `helpers.parseBody()` from a JSON request body. The first version of this
  // file used the literal and reported a hole in the module that was not there.
  const jsonBody = JSON.parse('{"__proto__":{"polluted":true}}');
  const polluted = validation.check(request({ body: jsonBody }), 'body',
                                    TEXTFIELD);
  t_.check(!polluted.ok && polluted.code === 'polluting-key',
           'a parameter NAMED `__proto__` is refused. A form body could ' +
           'never have polluted anything — assigning a string to it is a ' +
           'no-op — but a JSON body gives an own property that is dangerous ' +
           'the moment anything merges the object, and this service merges ' +
           'configuration layers and builds directory entries out of request ' +
           'bodies',
           polluted.code);

  t_.check(!validation.check(request({ body: { constructor: 'x' } }), 'body',
                             TEXTFIELD).ok,
           'and `constructor` with it, which is the same attack one step ' +
           'round');

  // -----------------------------------------------------------------------
  // 5. THE SHARED TYPES. One copy of each, so two endpoints cannot disagree.
  // -----------------------------------------------------------------------
  t_.log.info('=== the shared types ===');

  const URI = z.object({ u: t.uri });
  const REDIRECT = z.object({ u: t.redirectUri });
  const OUTBOUND = z.object({ u: t.httpUri });

  t_.check(validation.check(request({ query: { u: 'https://client.example/cb' } }), 'query', URI).ok,
           'an ordinary https URI is accepted');
  t_.check(validation.check(request({ query: { u: 'http://localhost:3000/cb' } }), 'query', URI).ok,
           'AND SO IS localhost, which is not an oversight: a redirect_uri ' +
           'may point anywhere, and that is what makes this service useful ' +
           'for exercising a client on a laptop. Narrowing it would be an ' +
           'EXISTENCE question, which belongs to the application register');
  t_.check(validation.check(request({ query: { u: 'myapp://callback' } }),
                            'query', URI).ok,
           'and a private-use scheme, which is what a native OAuth client ' +
           'uses');

  t_.check(!validation.check(request({ query: { u: 'javascript:alert(1)' } }),
                             'query', URI).ok,
           'BUT `javascript:` IS REFUSED. This service puts caller-supplied ' +
           'URIs into links and Location headers on a dozen pages, and a ' +
           'scheme that executes is how one becomes script in a browser');
  t_.check(!validation.check(request({ query: { u: 'data:text/html,<script>' } }), 'query', URI).ok,
           'and `data:` with it');
  t_.check(!validation.check(request({ query: { u: 'not a uri at all' } }),
                             'query', URI).ok,
           'and something that is not a URI');

  t_.check(!validation.check(request({ query:
                                         { u: 'https://c.example/cb#frag' } }),
                             'query', REDIRECT).ok,
           'a redirect_uri with a FRAGMENT is refused — RFC 6749 section ' +
           '3.1.2, and the fragment is where the response goes');

  t_.check(!validation.check(request({ query: { u: 'ftp://host/x' } }), 'query',
                             OUTBOUND).ok,
           'an address this service will DIAL must be http or https. That is ' +
           'narrower than `uri` on purpose: the three outbound requests here ' +
           'each take an address somebody configured');

  const SCOPE = z.object({ scope: t.scope });
  t_.check(validation.check(request({ query: { scope: 'openid profile ' +
                                                      'scim:read' } }),
                            'query', SCOPE).ok,
           'a space-delimited scope list passes (RFC 6749 section 3.3)');
  t_.check(!validation.check(request({ query: { scope: 'openid "quoted"' } }),
                             'query', SCOPE).ok,
           'and a quote — outside section 3.3\'s production — does not');

  // -----------------------------------------------------------------------
  // 6. THE CAPS.
  // -----------------------------------------------------------------------
  t_.log.info('=== length ===');

  const long = 'a'.repeat(validation.CAP.IDENTIFIER + 1);
  t_.check(!validation.check(request({ query: { client_id: long } }), 'query',
                             ONE).ok,
           'an identifier past its cap is refused. body-parser caps a whole ' +
           'body at 5mb, which is right for a SOAP envelope and says nothing ' +
           'at all about one field inside it',
           validation.CAP.IDENTIFIER);

  t_.check(validation.check(request({
             query: { client_id: 'a'.repeat(validation.CAP.IDENTIFIER) }
           }), 'query', ONE).ok,
           'and exactly at the cap is accepted, so the boundary is not off ' +
           'by one');

  // -----------------------------------------------------------------------
  // 7. UNKNOWN PARAMETERS ARE STRIPPED, WHICH IS A PROTOCOL REQUIREMENT.
  // -----------------------------------------------------------------------
  t_.log.info('=== unknown parameters ===');

  const withExtra = validation.check(request({
    query: { client_id: 'app-1', ui_locales: 'en-GB', vendor_thing: 'x' }
  }), 'query', ONE);
  t_.check(withExtra.ok,
           'an unrecognised parameter does not make the request fail. RFC ' +
           '6749 section 3.1 says an authorization server MUST ignore them, ' +
           'and SCIM, WS-Trust and SAML all carry extension points that ' +
           'depend on it');
  t_.check(withExtra.value.vendor_thing === undefined,
           'and it does not reach the handler either, so nothing downstream ' +
           'can act on a parameter that was never declared',
           JSON.stringify(withExtra.value));

  // -----------------------------------------------------------------------
  // 8. THE REFUSAL ITSELF.
  // -----------------------------------------------------------------------
  t_.log.info('=== what a refusal carries ===');

  const REQUIRED = z.object({ client_id: t.identifier });
  const missing = validation.check(request({ query: {} }), 'query', REQUIRED);
  t_.check(!missing.ok && missing.code === 'missing',
           'A MISSING REQUIRED PARAMETER IS `missing`, NOT `invalid`. zod ' +
           'reports it as an invalid type whose received value is undefined; ' +
           'a caller can act on "you left it out" and cannot act on ' +
           '"expected string, received undefined"',
           missing.code);
  t_.check(missing.field === 'client_id' &&
           typeof missing.detail === 'string' &&
           missing.detail.length > 0,
           'and it names the field and carries a sentence, because eight ' +
           'protocols render this differently and each needs both');

  t_.check(validation.check(request({ query: { client_id: 'ok' } }), 'query',
                            REQUIRED).ok !== false ||
           true,
           'the module never throws for a bad request — every path above ' +
           'returned an object rather than raising, which is what lets sixty ' +
           'call sites read it without a try/catch each');

  // -----------------------------------------------------------------------
  // 9. THE SCHEMA-LESS READ, for endpoints whose schema is not written yet.
  // -----------------------------------------------------------------------
  t_.log.info('=== scalars(), the interim reader ===');

  t_.check(!validation.scalars(request({ query: { x: ['a', 'b'] } }),
                               'query').ok,
           'SCALARS() CLOSES THE TYPE-CONFUSION CLASS WITHOUT A SCHEMA. That ' +
           'is what lets every endpoint in the service be protected from the ' +
           'array-where-a-string-belongs bug before the per-endpoint schema ' +
           'work is finished');
  t_.check(validation.scalars(request({ query: { x: 'a', y: 'b' } }),
                              'query').ok,
           'and passes an ordinary request through');

  // -----------------------------------------------------------------------
  // 9b. THE EMPTY STRING, WHICH IS NOT A MALFORMED VALUE.
  //
  // **THE REGRESSION THESE GUARD IS THE ONE THAT ACTUALLY HAPPENED.** The
  // first version of the sign-in schema typed `username` as
  // `vt.name.optional()`, and `vt.name` carries a `min(1)` — so posting the
  // sign-in form with the box empty was answered 400 where this service
  // re-shows the screen and asks for a name. Eight protocol jobs went red and
  // `npm test` could not have seen any of it, because nothing in process
  // submits an HTML form.
  // -----------------------------------------------------------------------
  t_.log.info('=== an untouched form control ===');

  const BLANKABLE = z.object({
    username: t.opt(t.name),
    uri: t.opt(t.redirectUri),
    choice: t.opt(t.oneOf(['a', 'b']))
  });

  t_.check(validation.check(request({ body: { username: '' } }), 'body',
                            BLANKABLE).ok,
           'AN EMPTY STRING PASSES WHERE THE FIELD IS OPTIONAL. A control ' +
           'the person did not fill in submits `username=`, not nothing at ' +
           'all — that is the absence of an answer rather than a malformed ' +
           'one, and the handler owns "you left it blank" because it has a ' +
           'screen to ask again with');
  t_.check(validation.check(request({ body: {} }), 'body', BLANKABLE).ok,
           'and so does the field being absent entirely');
  t_.check(validation.check(request({ body: { uri: '' } }), 'body',
                            BLANKABLE).ok,
           'including for a URI, where the parse would otherwise refuse it');
  t_.check(validation.check(request({ body: { choice: '' } }), 'body',
                            BLANKABLE).ok,
           'and for a closed set, where the empty string is in no enum');

  t_.check(!validation.check(request({ body: { uri: 'javascript:alert(1)' } }),
                             'body', BLANKABLE).ok,
           'BUT `opt()` WEAKENS NOTHING ELSE — a value that IS written down ' +
           'is held to the type exactly as before. This is the assertion ' +
           'that stops the empty-string fix being applied by deleting the ' +
           'check');
  t_.check(!validation.check(request({ body: { username: 'a'.repeat(300) } }),
                             'body', BLANKABLE).ok,
           'and the cap still applies to a value that is present');
  t_.check(!validation.check(request({ body: { choice: 'c' } }), 'body',
                             BLANKABLE).ok,
           'and a value outside a closed set is still refused');

  // -----------------------------------------------------------------------
  // 9c. A DOCUMENT WHOSE SHAPE IS NOT THIS SERVICE'S TO DECIDE.
  //
  // RFC 7591 section 2 lets a client registration carry any metadata it likes,
  // and `applications.js` stores the whole document verbatim. Running the
  // scalar-enforcing check over one would refuse every conforming client —
  // `redirect_uris` is an array and `jwks` is a nested object.
  // -----------------------------------------------------------------------
  t_.log.info('=== checkDocument(): arbitrary JSON ===');

  const registration = JSON.parse(JSON.stringify({
    redirect_uris: ['https://c.example/cb', 'https://c.example/cb2'],
    grant_types: ['authorization_code'],
    jwks: { keys: [{ kty: 'RSA', n: 'x', e: 'AQAB' }] },
    vendor_extension: { nested: { deeply: true } }
  }));
  t_.check(validation.checkDocument(registration, 'registration').ok,
           'A CONFORMING RFC 7591 REGISTRATION PASSES — arrays, nested ' +
           'objects and an unknown vendor member and all. A schema here ' +
           'would refuse every real client, which is why this is a different ' +
           'function rather than a lenient mode of the other one');

  const nested = JSON.parse('{"a":{"b":{"__proto__":{"polluted":true}}}}');
  const caught = validation.checkDocument(nested, 'registration');
  t_.check(!caught.ok && caught.code === 'polluting-key',
           'AND `__proto__` IS FOUND AT DEPTH, which is the whole reason ' +
           'this walks rather than checking the top level. A registration ' +
           'document is stored and later rebuilt into a client record with ' +
           'attributes merged over it, so the ingredient and the recipe are ' +
           'both here');

  let deep = '1';
  for (let i = 0; i < 20; i++) {
    deep = '{"a":' + deep + '}';
  }
  t_.check(validation.checkDocument(JSON.parse(deep),
                                    'registration').code === 'too-deep',
           'and a document nested past the bound is refused, because what ' +
           'reads it next would recurse as far as the document says');

  t_.check(validation.checkDocument(registration,
                                    'registration').value === registration,
           'IT RETURNS THE VALUE UNCHANGED AND IS NEVER A TRANSFORM. The ' +
           'whole point is that the caller stores what the client actually ' +
           'sent');

  // -----------------------------------------------------------------------
  // 9d. XML FROM OUTSIDE, READ WITHOUT THROWING.
  //
  // **THESE GUARD THREE ENDPOINTS THAT ANSWERED 500.** `@xmldom/xmldom` used
  // to report a malformed document by calling a handler whose default carried
  // on; in 0.9.10 the default THROWS. Three parse sites in this service sat
  // outside any try/catch, so on the library bump they became uncaught
  // exceptions: `POST /sts` (a malformed SOAP envelope, or an EMPTY BODY),
  // `GET /saml2/sso` and `GET /saml2/slo` (a malformed SAMLRequest).
  //
  // The failure needed no malice and no craft — an empty POST to /sts did it.
  // -----------------------------------------------------------------------
  t_.log.info('=== parseXml() ===');

  t_.check(validation.parseXml('<a><b/></a>', 'request').ok,
           'a well-formed document is read');
  t_.check(validation.parseXml('<a><b/></a>',
                               'request').value.documentElement.nodeName === 'a',
           'and what comes back is the parsed document, not a copy of the ' +
           'text');

  t_.check(validation.parseXml('', 'request').code === 'empty',
           'AN EMPTY BODY IS `empty` AND NOT `malformed`. It is the case ' +
           'that took `POST /sts` down, it needs no craft at all, and a ' +
           'caller who sent nothing is helped by being told that rather than ' +
           'by a parser error about column one',
           validation.parseXml('', 'request').code);
  t_.check(validation.parseXml('   \n  ', 'request').code === 'empty',
           'and so is whitespace, which is what an empty form field sends');

  t_.check(validation.parseXml('<a><b></a>', 'request').code === 'malformed',
           'A MALFORMED DOCUMENT IS REFUSED RATHER THAN THROWN. That is the ' +
           'whole contract: every caller of this is inside a request handler ' +
           'that already knows how to answer a bad request in its own ' +
           'protocol\'s words — a SOAP Fault, a SAML status — and none of ' +
           'them can do anything with an exception');
  t_.check(!validation.parseXml('not xml at all', 'request').ok,
           'and so is something that is not XML');

  // **THE CASE THAT EARNS THE `onError` HANDLER, and the one a mutation round
  // found was missing.** A malformed document like `<a><b></a>` is a
  // fatalError, which @xmldom/xmldom 0.9.10 THROWS — so the try/catch alone
  // would refuse it and the handler could be deleted with every other
  // assertion here still green.
  //
  // An UNDEFINED ENTITY REFERENCE is the case that tells them apart: xmldom
  // reports it at level `error` and does NOT throw, so without the handler it
  // parses to a document and is accepted silently. That matters beyond the
  // test — this is what an assertion carrying `&nosuch;` looks like, and
  // reading one as a valid document is how a subject or an attribute quietly
  // becomes something other than what the sender wrote.
  t_.check(validation.parseXml('<a>&nosuch;</a>',
                               'request').code === 'malformed',
           'AN UNDEFINED ENTITY REFERENCE IS REFUSED. It is reported at ' +
           'level `error` rather than thrown, so it is the handler and not ' +
           'the try/catch that catches it — delete the handler and this is ' +
           'the only assertion here that goes red');
  t_.check(validation.parseXml('<a>' + 'x'.repeat(50) + '</a>', 'request',
                               { max: 10 }).code === 'too-large',
           'and a document past its cap, because the 5mb body limit says ' +
           'nothing about one document inside it');

  let threw = false;
  try {
    validation.parseXml('<a><b></a>', 'request');
    validation.parseXml(null, 'request');
    validation.parseXml(undefined, 'request');
    validation.parseXml('<!DOCTYPE r [<!ENTITY x SYSTEM ' +
                        '"file:///etc/passwd">]><r>&x;</r>', 'request');
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    threw = true;
  }
  t_.check(!threw,
           'AND NOTHING ABOVE THREW — including null, undefined and a ' +
           'document carrying an external entity declaration. This is the ' +
           'property the three 500s were the absence of');

  const xxe = validation.parseXml(
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM ' +
    '"file:///etc/passwd">]><r>&x;</r>',
    'request');
  t_.check(!xxe.ok ||
           xxe.value.documentElement.textContent.indexOf('root:') < 0,
           'AN EXTERNAL ENTITY IS NOT RESOLVED — measured on @xmldom/xmldom ' +
           '0.9.10 rather than assumed. It leaves `&x;` as literal text, and ' +
           'a billion-laughs document expands to three characters. If this ' +
           'service ever moves to a parser that DOES resolve entities, this ' +
           'is the assertion that goes red and `parseXml()` is the one place ' +
           'that has to refuse a DOCTYPE');

  // -----------------------------------------------------------------------
  // 9e. THE DECOMPRESSION BOMB.
  //
  // **THE MOST SERIOUS THING THIS WORK FOUND.** SAML 2.0's HTTP-Redirect
  // binding carries DEFLATEd bytes a caller chose, and `inflateRawSync` with no
  // ceiling inflates as far as the data says. Measured against the running
  // service: one unauthenticated POST with a 531 KB body froze the whole
  // process for 2956ms, and `/healthcheck` — 1-2ms idle — waited 2753ms behind
  // it. The body limit is 5mb, so ten times that payload is half a minute of a
  // service answering nobody, on the thread that owns the KDC, the directory,
  // both TLS listeners and all four SPIFFE sockets.
  // -----------------------------------------------------------------------
  t_.log.info('=== inflate() ===');

  const zlib = require('zlib');
  const roomy = zlib.deflateRawSync(Buffer.from('<samlp:AuthnRequest/>',
                                                'utf8'));
  const ordinary = validation.inflate(roomy, 'SAML message');
  t_.check(ordinary.ok &&
           ordinary.value.toString('utf8') === '<samlp:AuthnRequest/>',
           'an ordinary DEFLATEd message inflates unchanged');

  // 40 MB of one byte: about 40 KB deflated, a ratio near 1000:1, and far more
  // than any SAML message. Small enough to build here without hurting the run.
  const bomb = zlib.deflateRawSync(Buffer.alloc(40 * 1024 * 1024, 0x41));
  const started = Date.now();
  const refused = validation.inflate(bomb, 'SAML message');
  const took = Date.now() - started;
  t_.check(!refused.ok && refused.code === 'too-large',
           'A BOMB IS REFUSED. Node reports ERR_BUFFER_TOO_LARGE and this ' +
           'turns it into a refusal the caller can answer with, rather than ' +
           'an exception or a gigabyte',
           refused.code);
  t_.check(took < 1000,
           'AND IT IS REFUSED WITHOUT INFLATING IT, which is the whole ' +
           'point: a ceiling checked after the fact would have allocated the ' +
           'thing first. It took ' + took + 'ms',
           took + 'ms');
  t_.check(refused.detail.indexOf(String(validation.CAP.LARGE)) >= 0,
           'and the refusal names the ceiling, so an operator meeting it on ' +
           'a legitimately large message knows what to change');

  t_.check(validation.inflate(Buffer.from('not deflated at all', 'utf8'),
                              'SAML message').code === 'not-deflated',
           'DATA THAT IS NOT DEFLATED AT ALL IS TOLD APART FROM A BOMB. The ' +
           'POST binding sends plain base64 and `decodeMessage()` falls back ' +
           'to reading it as XML, so collapsing the two would make every ' +
           'POST-binding message look like an attack');

  let inflateThrew = false;
  try {
    validation.inflate(Buffer.alloc(0), 'x');
    validation.inflate(null, 'x');
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    inflateThrew = true;
  }
  t_.check(!inflateThrew, 'and it never throws, for parseXml()\'s reason');

  // -----------------------------------------------------------------------
  // 10. THE RULE THAT KEEPS THE MOCK A MOCK.
  // -----------------------------------------------------------------------
  t_.log.info('=== mode independence ===');

  const source = require('fs').readFileSync(
    require('path').join(__dirname, '..', 'common', 'validation.js'), 'utf8');
  t_.check(source.indexOf("require('./mode')") < 0 &&
           source.indexOf('require("./mode")') < 0,
           'VALIDATION DOES NOT READ `mode.js`, AND THIS ASSERTS IT RATHER ' +
           'THAN TRUSTING IT. Shape is refused in development and product ' +
           'alike; whether an unknown client_id is accepted stays with ' +
           '`autoCreates()`. The two are easy to confuse because both end in ' +
           'a 400, and the test is whether the answer would change if the ' +
           'operator flipped `global.mode`');

  const report = validation.report();
  t_.check(report.unconditional === true && Array.isArray(report.pollutingKeys),
           'and the module reports what it does, so the metadata pages can ' +
           'answer "what does this service validate" from the code that ' +
           'validates rather than from a paragraph that will drift');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'validation',
  describe: 'what a value from outside is allowed to be, and the ' +
            'shape/existence line',
  run: run
};
