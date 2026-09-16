// @ts-check
'use strict';
//
// File: gnap_schemas.js
//
// ---------------------------------------------------------------------------
// THE JSON SCHEMAS OF EVERY DOCUMENT A GNAP CLIENT OR RESOURCE SERVER SENDS,
// COMPILED WITH AJV AND ENFORCED BEFORE A HANDLER READS A MEMBER.
//
// The user asked (2026-09-12) that the GNAP endpoints do input sanitisation and
// JSON Schema validation. Each document now passes through THREE layers, and
// each layer adds checks the others do not make — the rule the 2026-09-06
// input-validation sweep settled on ("the validator adds the checks nothing
// else makes; it never duplicates a check the handler already makes better"):
//
//   1. `validation.checkDocument()` — the service-wide SANITISATION of any JSON
//      body: bounded depth, bounded key count, and no prototype-polluting
//      member names (`__proto__`, `constructor`, `prototype`) at any depth.
//   2. **these schemas** — the SHAPE: every known member's JSON type, a length
//      cap on every string, an item cap on every array and a member cap on
//      every object, URI formats where RFC 9635 says "absolute URI", and NO
//      control characters in any string. That last one is sanitisation too: a
//      label, a class_id or a display name is echoed onto the approval page,
//      the audit log and the console, and a C0 control character in it is never
//      meaningful.
//   3. `gnap_request.js`'s walk — the SEMANTICS, refused with the GNAP error
//      code the specification names: a flag twice is `invalid_flag`, a missing
//      label in a multi-token request is `invalid_request`, a key in two
//      formats is `invalid_client`.
//
// **WHICH IS WHY `required` AND `enum` ARE NOT IN THESE SCHEMAS.** A schema
// that enforced `required: ["client"]` would answer a request with no client as
// a generic shape error — `invalid_request`, "must have required property" —
// where section 2.3 makes it `invalid_client`, and an `enum` on `flags` would
// turn section 2.1.1's `invalid_flag` into the same. The walk refuses both, by
// name, with the right code; the schema would pre-empt it with a worse answer.
// It is the trade `mgmt-api/admin_api.js`'s `structureOnly()` made, for this
// reason.
//
// **`additionalProperties` IS OPEN WHERE RFC 9635 HAS AN EXTENSION REGISTRY** —
// the grant request (section 10.3), the client (10.7), its display (10.8), the
// subject request (10.5), a start mode object (10.9), the hints (10.11), a
// proof object (10.16) and an access right (section 8: "API-specific fields")
// — because refusing a registered extension this implementation does not know
// would refuse a conforming client. It is CLOSED where the document is fixed:
// the continuation body (section 5.1), the rotation body (6.1.1) and the finish
// object (2.5.2).
// ---------------------------------------------------------------------------

// `any` for the type checker (#50): CommonJS modules whose declared types are
// ES default exports.
const Ajv2020 = /** @type {any} */ (require('ajv/dist/2020'));
const addFormats = /** @type {any} */ (require('ajv-formats'));
const { log } = require('../common/helpers');
const validation = require('../common/validation');

const CAP = validation.CAP;

// A string with no C0 control character and no DEL.
const SAFE = '^[^\\u0000-\\u001f\\u007f]*$';

function str(max) {
  log.debug("Entering str().");
  log.debug("Leaving str().");
  return { type: 'string', maxLength: max || CAP.DEFAULT, pattern: SAFE };
}

function strings(maxItems, maxLength) {
  log.debug("Entering strings().");
  log.debug("Leaving strings().");
  return { type: 'array', maxItems: maxItems,
           items: str(maxLength || CAP.URI) };
}

const DEFS = {
  uri: { type: 'string', maxLength: CAP.URI, format: 'uri', pattern: SAFE },
  // A logo may be a data: image (section 2.3.2), which is legitimately long.
  logoUri: { type: 'string', maxLength: CAP.TEXT,
             pattern: '^(data:image/[A-Za-z0-9.+-]+;base64,' +
                      '[A-Za-z0-9+/=]*|[A-Za-z][A-Za-z0-9+.-]*:[^\\u0000-\\u001f\\u007f\\s]*)$' },
  accessRight: {
    anyOf: [
      str(CAP.URI),
      {
        type: 'object', maxProperties: 64,
        properties: {
          type: str(CAP.URI),
          actions: strings(100, CAP.NAME),
          locations: strings(100, CAP.URI),
          datatypes: strings(100, CAP.NAME),
          privileges: strings(100, CAP.NAME),
          identifier: str(CAP.URI)
        },
        additionalProperties: true
      }
    ]
  },
  access: { type: 'array', maxItems: 200,
            items: { $ref: '#/$defs/accessRight' } },
  proof: {
    anyOf: [
      str(64),
      { type: 'object', maxProperties: 16,
        properties: { method: str(64), alg: str(64),
                      'content-digest-alg': str(64) },
        additionalProperties: true }
    ]
  },
  jwk: {
    type: 'object', maxProperties: 32,
    properties: {
      kty: str(16), alg: str(64), kid: str(CAP.IDENTIFIER), crv: str(32),
      use: str(16),
      x: str(512), y: str(512), n: str(4096), e: str(64),
      x5c: { type: 'array', maxItems: 10, items: str(CAP.TEXT) }
    },
    additionalProperties: true
  },
  key: {
    anyOf: [
      str(CAP.IDENTIFIER),
      {
        type: 'object', maxProperties: 16,
        properties: {
          proof: { $ref: '#/$defs/proof' },
          jwk: { $ref: '#/$defs/jwk' },
          cert: { type: 'string', maxLength: CAP.TEXT,
                  pattern: '^[A-Za-z0-9+/=\\s-]*$' },
          'cert#S256': { type: 'string', maxLength: 128,
                         pattern: '^[A-Za-z0-9_-]*$' }
        },
        additionalProperties: true
      }
    ]
  },
  subId: {
    type: 'object', maxProperties: 16,
    properties: {
      format: str(64), uri: str(CAP.URI), email: str(CAP.NAME),
      iss: str(CAP.URI),
      sub: str(CAP.URI), id: str(CAP.URI), phone_number: str(32), url: str(
          CAP.URI),
      identifiers: { type: 'array', maxItems: 20,
                     items: { type: 'object', maxProperties: 16 } }
    },
    additionalProperties: true
  },
  subIds: { type: 'array', maxItems: 20, items: { $ref: '#/$defs/subId' } },
  tokenRequest: {
    type: 'object', maxProperties: 32,
    properties: {
      access: { $ref: '#/$defs/access' },
      label: str(CAP.NAME),
      flags: strings(16, 64)
    },
    additionalProperties: true
  },
  accessToken: {
    anyOf: [
      { $ref: '#/$defs/tokenRequest' },
      { type: 'array', maxItems: 32, items: { $ref: '#/$defs/tokenRequest' } }
    ]
  },
  subject: {
    type: 'object', maxProperties: 16,
    properties: {
      sub_id_formats: strings(20, 64),
      assertion_formats: strings(10, 64),
      sub_ids: { $ref: '#/$defs/subIds' }
    },
    additionalProperties: true
  },
  client: {
    anyOf: [
      str(CAP.IDENTIFIER),
      {
        type: 'object', maxProperties: 32,
        properties: {
          key: { $ref: '#/$defs/key' },
          class_id: str(CAP.IDENTIFIER),
          display: {
            type: 'object', maxProperties: 16,
            properties: { name: str(CAP.NAME), uri: { $ref: '#/$defs/uri' },
                          logo_uri: { $ref: '#/$defs/logoUri' } },
            additionalProperties: true
          }
        },
        additionalProperties: true
      }
    ]
  },
  user: {
    anyOf: [
      str(CAP.TOKEN),
      {
        type: 'object', maxProperties: 16,
        properties: {
          sub_ids: { $ref: '#/$defs/subIds' },
          assertions: {
            type: 'array', maxItems: 10,
            items: { type: 'object', maxProperties: 8,
                     properties: { format: str(64), value: str(CAP.LARGE) },
                     additionalProperties: true }
          }
        },
        additionalProperties: true
      }
    ]
  },
  interact: {
    type: 'object', maxProperties: 16,
    properties: {
      start: {
        type: 'array', maxItems: 16,
        items: { anyOf: [str(64), { type: 'object', maxProperties: 16,
                                    properties: { mode: str(64) },
                                    additionalProperties: true }] }
      },
      finish: {
        type: 'object',
        properties: { method: str(64), uri: { $ref: '#/$defs/uri' },
                      nonce: str(256),
                      hash_method: str(64) },
        additionalProperties: false
      },
      hints: {
        type: 'object', maxProperties: 16,
        properties: { ui_locales: strings(32, 64) },
        additionalProperties: true
      }
    },
    additionalProperties: true
  },
  resourceServer: {
    anyOf: [
      str(CAP.IDENTIFIER),
      { type: 'object', maxProperties: 16,
        properties: { key: { $ref: '#/$defs/key' } },
        additionalProperties: true }
    ]
  },
  // A GNAP access token value: token68 (RFC 9110 section 11.2), which every
  // format this AS issues satisfies. A ZCAP is the long one.
  tokenValue: { type: 'string', maxLength: CAP.TEXT,
                pattern: '^[A-Za-z0-9._~+/-]*=*$' }
};

const SCHEMAS = {
  // RFC 9635 section 2 (plus RFC 9767 section 4's existing_access_token).
  grantRequest: {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'urn:mock-sts:gnap:grant-request',
    type: 'object', maxProperties: 64,
    properties: {
      access_token: { $ref: '#/$defs/accessToken' },
      subject: { $ref: '#/$defs/subject' },
      client: { $ref: '#/$defs/client' },
      user: { $ref: '#/$defs/user' },
      interact: { $ref: '#/$defs/interact' },
      interact_ref: str(256),
      existing_access_token: { $ref: '#/$defs/tokenValue' }
    },
    additionalProperties: true,
    $defs: DEFS
  },
  // Section 5.1: nothing, or the interaction reference.
  continuation: {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'urn:mock-sts:gnap:continuation',
    type: 'object',
    properties: { interact_ref: { type: 'string', maxLength: 256,
                                  pattern: '^[A-Za-z0-9._~-]*$' } },
    additionalProperties: true,
    $defs: DEFS
  },
  // Section 5.3.
  modification: {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'urn:mock-sts:gnap:modification',
    type: 'object', maxProperties: 64,
    properties: {
      access_token: { $ref: '#/$defs/accessToken' },
      subject: { $ref: '#/$defs/subject' },
      user: { $ref: '#/$defs/user' },
      interact: { $ref: '#/$defs/interact' }
    },
    additionalProperties: true,
    $defs: DEFS
  },
  // Section 6.1.1.
  rotation: {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'urn:mock-sts:gnap:rotation',
    type: 'object', maxProperties: 4,
    properties: { key: { $ref: '#/$defs/key' } },
    additionalProperties: true,
    $defs: DEFS
  },
  // RFC 9767 section 3.3.
  introspection: {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'urn:mock-sts:gnap:introspection',
    type: 'object', maxProperties: 32,
    properties: {
      access_token: { $ref: '#/$defs/tokenValue' },
      proof: str(64),
      resource_server: { $ref: '#/$defs/resourceServer' },
      access: { $ref: '#/$defs/access' }
    },
    additionalProperties: true,
    $defs: DEFS
  },
  // RFC 9767 section 3.4.
  registration: {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'urn:mock-sts:gnap:registration',
    type: 'object', maxProperties: 32,
    properties: {
      access: { $ref: '#/$defs/access' },
      resource_server: { $ref: '#/$defs/resourceServer' },
      token_formats_supported: strings(16, 64),
      token_introspection_required: { type: 'boolean' }
    },
    additionalProperties: true,
    $defs: DEFS
  }
};

// Compiled ONCE, at require time, so a schema that does not compile fails the
// service loudly at start rather than the first request that needs it.
const ajv = new Ajv2020({ strict: true, allErrors: false, coerceTypes: false,
                          allowUnionTypes: true });
addFormats(ajv);
const COMPILED = {};
Object.keys(SCHEMAS).forEach(function (name) {
  COMPILED[name] = ajv.compile(SCHEMAS[name]);
});

// `{ ok: true }` or `{ ok: false, path, detail }`. The detail names the member
// by its JSON Pointer, because the client developer's first question is which
// one.
function validate(name, document) {
  log.debug("Entering validate(). schema=" + name);
  const check = COMPILED[name];
  if (!check) {
    log.debug("Leaving validate(). No such schema.");
    return { ok: false, path: '', detail: 'there is no schema called ' + name };
  }
  if (check(document)) {
    log.debug("Leaving validate(). Valid.");
    return { ok: true };
  }
  // THE MOST USEFUL ERROR, NOT THE FIRST. ajv reports every branch of an
  // `anyOf` it tried, so a control character inside an object member arrives
  // behind "must be string" from the string branch of the same union — true
  // and useless. A control character is named whenever one was found, and
  // otherwise the error at the deepest path is the one nearest the mistake.
  const errors = check.errors || [];
  const control = errors.filter(function (one) {
    return one.keyword === 'pattern' && one.params &&
           one.params.pattern === SAFE;
  })[0];
  const first = control || errors.slice().sort(function (a, b) {
    return String(b.instancePath || '').length -
           String(a.instancePath || '').length;
  })[0] || {};
  const path = first.instancePath || '(the document)';
  let detail;
  if (first.keyword === 'pattern' &&
      String(first.schemaPath || '').indexOf('pattern') >= 0 &&
      first.params && first.params.pattern === SAFE) {
    detail = path + ' contains a control character, which no member of a ' +
                    'GNAP document may carry';
  } else {
    detail = path + ' ' + (first.message || 'is not valid');
  }
  log.debug("Leaving validate(). " + detail);
  return { ok: false, path: path,
           detail: detail + ' (JSON Schema ' + SCHEMAS[name].$id + ')' };
}

module.exports = {
  SCHEMAS: SCHEMAS,
  validate: validate
};
