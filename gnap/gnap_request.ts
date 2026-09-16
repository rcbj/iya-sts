'use strict';
//
// File: gnap_request.ts
//
// ---------------------------------------------------------------------------
// THE SHAPE OF EVERY DOCUMENT A GNAP CLIENT OR RESOURCE SERVER SENDS, CHECKED
// ONCE, AND TURNED INTO ONE NORMALISED OBJECT THE ENDPOINTS READ.
//
// Five documents arrive at this authorization server: a grant request (RFC 9635
// section 2), a continuation (section 5.1/5.2), a modification (section 5.3), a
// token rotation body (section 6.1.1), and the two RS-facing requests of RFC
// 9767 (introspection, section 3.3; resource registration, section 3.4). They
// share members — `access`, a key, sub_ids — and a member checked in one place
// and not another is exactly the drift `common/validation.js` exists to stop.
//
// **WHY THIS IS A WALK AND NOT A ZOD SCHEMA.** Every other surface here
// declares its input with `validation.types`. That works for flat forms and
// queries, and `checkParsed()` refuses nested values on purpose. A GNAP request
// is nested four deep with members that are "an object OR an array of objects"
// and "a string OR an object" (section 10.3's registry registers
// `access_token`, `client` and `user` twice each, once per type), and the
// refusal a client needs is a GNAP error code naming WHICH member, not a
// flattened zod path. So the document is first passed through
// `validation.checkDocument()` — the shared bound on depth, key count and
// prototype-polluting names, which is the part that must be the same everywhere
// — then through its JSON SCHEMA (`gnap_schemas.ts`, ajv: types, lengths, caps,
// URI formats, no control characters), and only then walked here for the
// semantics.
//
// **SHAPE HERE, POLICY ELSEWHERE.** This file refuses what no authorization
// server could accept (an `access` that is not an array, two tokens with one
// label, a flag twice). It does NOT decide whether a known client may ask for
// bearer tokens, whether a finish URI is registered, or whether a reference
// string names anything — those change with configuration and mode, and they
// are `gnap_grants.ts`'s. That is the test `common/validation.js`'s header
// states: would the answer change if the operator flipped `global.mode`?
//
// Every refusal is `{ ok:false, errorCode, why, gnapError }`, carrying the RFC
// 9635 section 3.6 (or RFC 9767 section 3.5) code the client is told.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `GnapRequest` takes the logger, the error-code table, the shared
// document bound (`validation`) and the JSON Schemas (`gnap_schemas.ts`)
// through its constructor. The vocabularies are its static constants. The
// module still exports the constants, `checkAccess`, `checkSubId` and the six
// parsers from a TRANSITIONAL instance for the unconverted modules that
// require it (`gnap_rs.ts`, and the tests).
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import validation = require('../common/validation');
import schemas = require('./gnap_schemas');

// RFC 9635 section 10.4. `durable` is RESPONSE-only, so a client asking for it
// has a flag configuration that is not valid — which is precisely what
// `invalid_flag` says.
const REQUEST_FLAGS = ['bearer'];
const RESPONSE_ONLY_FLAGS = ['durable'];

// Section 10.9 and 10.10.
const START_MODES = ['redirect', 'app', 'user_code', 'user_code_uri'];
const FINISH_METHODS = ['redirect', 'push'];

// Section 10.6.
const ASSERTION_FORMATS = ['id_token', 'saml2'];

// ---------------------------------------------------------------------------
// RFC 9493 SUBJECT IDENTIFIER FORMATS, IN THE SPELLINGS RFC 9493 USES.
//
// `ssf/ssf_subjects.js` exists and is NOT used, deliberately: it carries SSF's
// own vocabulary (`issuer_subject_id`, `decentralized_identifier`) where RFC
// 9493 and GNAP section 2.2 say `iss_sub` and `did`. Aliasing between the two
// would put a translation on the path of every GNAP subject, and a client that
// sent `issuer_subject_id` to a GNAP AS would be accepted here and refused by
// every other GNAP implementation. So the grammar is written again, in GNAP's
// words, the way `ssf_subjects.js`'s own header argues a grammar should be.
// ---------------------------------------------------------------------------
const SUB_ID_FORMATS = {
  account: ['uri'],
  email: ['email'],
  iss_sub: ['iss', 'sub'],
  opaque: ['id'],
  phone_number: ['phone_number'],
  did: ['url'],
  uri: ['uri'],
  aliases: ['identifiers']
};

// The IANA "Named Information Hash Algorithm Registry" names node can compute,
// for section 2.5.2's `hash_method`. The truncated SHA-256 rows are the
// registry's too; a truncation is a prefix of the full digest (RFC 6920).
const HASH_METHODS = {
  'sha-256': { node: 'sha256', bits: 256 },
  'sha-256-128': { node: 'sha256', bits: 128 },
  'sha-256-120': { node: 'sha256', bits: 120 },
  'sha-256-96': { node: 'sha256', bits: 96 },
  'sha-256-64': { node: 'sha256', bits: 64 },
  'sha-256-32': { node: 'sha256', bits: 32 },
  'sha-384': { node: 'sha384', bits: 384 },
  'sha-512': { node: 'sha512', bits: 512 },
  'sha3-224': { node: 'sha3-224', bits: 224 },
  'sha3-256': { node: 'sha3-256', bits: 256 },
  'sha3-384': { node: 'sha3-384', bits: 384 },
  'sha3-512': { node: 'sha3-512', bits: 512 },
  'blake2s-256': { node: 'blake2s256', bits: 256 },
  'blake2b-512': { node: 'blake2b512', bits: 512 }
};

interface GnapRequestDeps {
  log: typeof helpers.log;
  errorCodes: typeof errorCodes;
  validation: typeof validation;
  schemas: typeof schemas;
}

class GnapRequest {
  static readonly REQUEST_FLAGS = REQUEST_FLAGS;
  static readonly START_MODES = START_MODES;
  static readonly FINISH_METHODS = FINISH_METHODS;
  static readonly ASSERTION_FORMATS = ASSERTION_FORMATS;
  static readonly SUB_ID_FORMATS = SUB_ID_FORMATS;
  static readonly HASH_METHODS = HASH_METHODS;

  constructor(private readonly deps: GnapRequestDeps) {
    deps.log.debug("Entering GnapRequest.constructor().");
    deps.log.debug("Leaving GnapRequest.constructor().");
  }

  private refusal(code, why, gnapError?) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering GnapRequest.refusal().");
    const out = { ok: false, errorCode: code, why: why,
                  gnapError: gnapError || 'invalid_request' };
    log.debug("Leaving GnapRequest.refusal().");
    return errorCodes.mark(out, code);
  }

  private isObject(value) {
    const { log } = this.deps;
    log.debug("Entering GnapRequest.isObject().");
    log.debug("Leaving GnapRequest.isObject().");
    return !!value && typeof value === 'object' && !Array.isArray(value);
  }

  private isStringArray(value) {
    const { log } = this.deps;
    log.debug("Entering GnapRequest.isStringArray().");
    log.debug("Leaving GnapRequest.isStringArray().");
    return Array.isArray(value) && value.every(function (one) {
      return typeof one === 'string';
    });
  }

  // An absolute URI with a scheme and no fragment — the three things sections
  // 2.3.2, 2.5.2 and 3.1 each say about a URI in this protocol.
  private absoluteUriProblem(value, name, allowData) {
    const { log } = this.deps;
    log.debug("Entering GnapRequest.absoluteUriProblem().");
    if (typeof value !== 'string' || !value) {
      log.debug("Leaving GnapRequest.absoluteUriProblem().");
      return '"' + name + '" must be a non-empty string';
    }
    if (allowData && /^data:image\/[a-z0-9.+-]+;base64,/i.test(value)) {
      log.debug("Leaving GnapRequest.absoluteUriProblem().");
      return '';
    }
    let parsed;
    try {
      parsed = new URL(value);
    } catch (e) {
      log.debug("Caught in GnapRequest.absoluteUriProblem(): " + ((e &&
          e.message) || e));
      log.debug("Leaving GnapRequest.absoluteUriProblem().");
      // Not a URI; the sentence below is the whole of what the caller needs.
      return '"' + name + '" must be an absolute URI';
    }
    if (parsed.hash || value.indexOf('#') >= 0) {
      log.debug("Leaving GnapRequest.absoluteUriProblem().");
      return '"' + name + '" must not carry a fragment';
    }
    log.debug("Leaving GnapRequest.absoluteUriProblem().");
    return '';
  }

  // ---------------------------------------------------------------------------
  // SECTION 8: ACCESS RIGHTS.
  //
  // An array whose members are reference strings (section 8.1) or objects with
  // a string `type`. The common dimensions — `actions`, `locations`,
  // `datatypes`, `privileges` as arrays of strings, `identifier` as a string —
  // are checked when present because section 8 defines their JSON type; any
  // other member is the API's own (the section's `geolocation` and `currency`
  // examples) and is carried untouched. Section 8 says the type MUST be
  // compared by exact bytes and never normalised, so nothing here trims or
  // lower-cases it.
  // ---------------------------------------------------------------------------
  checkAccess(access, where) {
    const { log } = this.deps;
    log.debug("Entering GnapRequest.checkAccess(). where=" + where);
    if (!Array.isArray(access)) {
      log.debug("Leaving GnapRequest.checkAccess(). Not an array.");
      return this.refusal('STS-GNAP-0020', '"' + where + '" must be an array ' +
                          'of access rights (RFC 9635 section 8).');
    }
    for (let i = 0; i < access.length; i++) {
      const right = access[i];
      if (typeof right === 'string') {
        if (!right) {
          log.debug("Leaving GnapRequest.checkAccess(). Empty reference.");
          return this.refusal('STS-GNAP-0021',
                              'an access reference in "' + where + '" ' +
              'is empty.');
        }
        continue;
      }
      if (!this.isObject(right) || typeof right.type !== 'string' ||
          !right.type) {
        log.debug("Leaving GnapRequest.checkAccess(). Element " + i +
                  " is not a typed object or string.");
        return this.refusal('STS-GNAP-0022', 'element ' + i + ' of "' + where +
            '" must be a reference string or an object with a string "type" ' +
                            '(RFC 9635 section 8).');
      }
      const arrays = ['actions', 'locations', 'datatypes', 'privileges'];
      for (let j = 0; j < arrays.length; j++) {
        if (right[arrays[j]] !== undefined &&
            !this.isStringArray(right[arrays[j]])) {
          log.debug("Leaving GnapRequest.checkAccess(). " + arrays[j] +
                    " is not an array of strings.");
          return this.refusal('STS-GNAP-0023',
                              '"' + arrays[j] + '" in element ' + i + ' ' +
              'of "' +
                              where + '" must be an array of strings.');
        }
      }
      if (right.identifier !== undefined &&
          typeof right.identifier !== 'string') {
        log.debug("Leaving GnapRequest.checkAccess(). identifier is not a " +
                  "string.");
        return this.refusal('STS-GNAP-0023',
                            '"identifier" in element ' + i + ' of "' + where +
                            '" must be a string.');
      }
    }
    log.debug("Leaving GnapRequest.checkAccess(). " + access.length +
              " right(s).");
    return { ok: true, access: access };
  }

  // One access token request (section 2.1.1).
  private checkTokenRequest(one, index, multiple) {
    const { log } = this.deps;
    log.debug("Entering GnapRequest.checkTokenRequest(). index=" + index);
    const where = multiple ? 'access_token[' + index + ']' : 'access_token';
    if (!this.isObject(one)) {
      log.debug("Leaving GnapRequest.checkTokenRequest(). Not an object.");
      return this.refusal('STS-GNAP-0024', '"' + where + '" must be an ' +
                          'object (RFC 9635 section 2.1.1).');
    }
    const access = this.checkAccess(one.access, where + '.access');
    if (!access.ok) {
      log.debug("Leaving GnapRequest.checkTokenRequest(). Bad access.");
      return access;
    }
    if (one.label !== undefined &&
        (typeof one.label !== 'string' || !one.label)) {
      log.debug("Leaving GnapRequest.checkTokenRequest(). Bad label.");
      return this.refusal('STS-GNAP-0025', '"' + where + '.label" must be a ' +
                                                         'non-empty string.');
    }
    if (multiple && typeof one.label !== 'string') {
      // Section 2.1.2 names THIS error for a missing label, not invalid_flag.
      log.debug("Leaving GnapRequest.checkTokenRequest(). Multiple tokens " +
                "and no label.");
      return this.refusal('STS-GNAP-0026', 'every access token in a request ' +
          'for multiple tokens must carry a label (RFC 9635 section 2.1.2).');
    }
    const flags = one.flags === undefined ? [] : one.flags;
    if (!this.isStringArray(flags)) {
      log.debug("Leaving GnapRequest.checkTokenRequest(). flags is not an " +
                "array of strings.");
      return this.refusal('STS-GNAP-0027', '"' + where + '.flags" must be an ' +
                          'array of strings.', 'invalid_flag');
    }
    const seen: Record<string, boolean> = {};
    for (let i = 0; i < flags.length; i++) {
      if (seen[flags[i]]) {
        log.debug("Leaving GnapRequest.checkTokenRequest(). A flag repeats.");
        return this.refusal('STS-GNAP-0028', 'the flag "' + flags[i] +
            '" appears more than once (RFC 9635 section 2.1.1 requires ' +
                            'invalid_flag).', 'invalid_flag');
      }
      seen[flags[i]] = true;
      if (RESPONSE_ONLY_FLAGS.indexOf(flags[i]) >= 0) {
        log.debug("Leaving GnapRequest.checkTokenRequest(). A response-only " +
                  "flag was requested.");
        return this.refusal('STS-GNAP-0029', 'the flag "' + flags[i] +
            '" is a response flag and cannot be requested (RFC 9635 section ' +
                            '10.4).', 'invalid_flag');
      }
      if (REQUEST_FLAGS.indexOf(flags[i]) < 0) {
        log.debug("Leaving GnapRequest.checkTokenRequest(). Unknown flag.");
        return this.refusal('STS-GNAP-0030', 'the flag "' + flags[i] +
            '" is not one this authorization server understands.',
                            'invalid_flag');
      }
    }
    log.debug("Leaving GnapRequest.checkTokenRequest().");
    return { ok: true, token: { label: one.label === undefined ? null :
                                one.label, access: access.access, bearer:
                                !!seen.bearer } };
  }

  // Section 2.1: an object for one token, an array for several.
  private checkAccessTokenMember(value) {
    const { log } = this.deps;
    log.debug("Entering GnapRequest.checkAccessTokenMember().");
    if (Array.isArray(value)) {
      if (!value.length) {
        log.debug("Leaving GnapRequest.checkAccessTokenMember(). Empty array.");
        return this.refusal('STS-GNAP-0031', '"access_token" must not be an ' +
                            'empty array.');
      }
      const tokens = [];
      const labels = {};
      for (let i = 0; i < value.length; i++) {
        const one = this.checkTokenRequest(value[i], i, true);
        if (!one.ok) {
          log.debug("Leaving GnapRequest.checkAccessTokenMember(). Element " +
                    i + " refused.");
          return one;
        }
        if (labels[one.token.label]) {
          log.debug("Leaving GnapRequest.checkAccessTokenMember(). Duplicate " +
                    "label.");
          return this.refusal('STS-GNAP-0032', 'the label "' + one.token.label +
              '" is used by more than one requested access token (RFC 9635 ' +
                              'section 2.1.2).');
        }
        labels[one.token.label] = true;
        tokens.push(one.token);
      }
      log.debug("Leaving GnapRequest.checkAccessTokenMember(). " +
                tokens.length + " tokens.");
      return { ok: true, multiple: true, tokens: tokens };
    }
    const single = this.checkTokenRequest(value, 0, false);
    if (!single.ok) {
      log.debug("Leaving GnapRequest.checkAccessTokenMember(). Single token " +
                "refused.");
      return single;
    }
    log.debug("Leaving GnapRequest.checkAccessTokenMember(). One token.");
    return { ok: true, multiple: false, tokens: [single.token] };
  }

  // RFC 9493 section 3, in GNAP's spelling.
  checkSubId(subject, where, nested?) {
    const { log } = this.deps;
    log.debug("Entering GnapRequest.checkSubId(). where=" + where);
    if (!this.isObject(subject) || typeof subject.format !== 'string') {
      log.debug("Leaving GnapRequest.checkSubId(). No format.");
      return this.refusal('STS-GNAP-0033', '"' + where + '" must be a ' +
          'Subject Identifier object with a "format" (RFC 9493).');
    }
    const members = SUB_ID_FORMATS[subject.format];
    if (!members) {
      log.debug("Leaving GnapRequest.checkSubId(). Unknown format.");
      return this.refusal('STS-GNAP-0034', '"' + where + '" uses the Subject ' +
                                                         'Identifier format "' +
                          subject.format + '", which is not in RFC 9493 (' +
                          Object.keys(SUB_ID_FORMATS).join(', ') + ').');
    }
    // RFC 9493 section 3: "A Subject Identifier MUST NOT contain any members
    // prohibited or not described by its Identifier Format." A closed set is
    // the half that is easy to leave out, and a member this service ignored is
    // one a stricter party downstream would refuse — so it is refused here,
    // naming it.
    const allowed = subject.format === 'aliases' ? ['format', 'identifiers'] :
                    ['format'].concat(members);
    const extra = Object.keys(subject).filter(function (name) {
      return allowed.indexOf(name) < 0;
    });
    if (extra.length) {
      log.debug("Leaving GnapRequest.checkSubId(). Undescribed member " +
                extra[0] + ".");
      return this.refusal('STS-GNAP-0036', 'a "' + subject.format +
                          '" Subject Identifier carries "' + extra[0] +
          '", which its format does not describe (RFC 9493 section 3).');
    }
    if (subject.format === 'aliases') {
      if (nested) {
        log.debug("Leaving GnapRequest.checkSubId(). Nested aliases.");
        return this.refusal('STS-GNAP-0035', 'an "aliases" identifier must ' +
            'not contain another "aliases" identifier (RFC 9493 section ' +
                            '3.2.8).');
      }
      if (!Array.isArray(subject.identifiers) || !subject.identifiers.length) {
        log.debug("Leaving GnapRequest.checkSubId(). aliases without " +
                  "identifiers.");
        return this.refusal('STS-GNAP-0036', '"' + where + '.identifiers" ' +
                            'must be a non-empty array.');
      }
      for (let i = 0; i < subject.identifiers.length; i++) {
        const inner = this.checkSubId(subject.identifiers[i],
                                      where + '.identifiers[' + i + ']', true);
        if (!inner.ok) {
          log.debug("Leaving GnapRequest.checkSubId(). An alias is malformed.");
          return inner;
        }
      }
      log.debug("Leaving GnapRequest.checkSubId(). aliases.");
      return { ok: true };
    }
    for (let i = 0; i < members.length; i++) {
      if (typeof subject[members[i]] !== 'string' || !subject[members[i]]) {
        log.debug("Leaving GnapRequest.checkSubId(). Missing " + members[i] +
                  ".");
        return this.refusal('STS-GNAP-0036', 'a "' + subject.format +
                            '" Subject Identifier must carry a string "' +
                            members[i] + '" (RFC 9493).');
      }
    }
    if (subject.format === 'account' && subject.uri.indexOf('acct:') !== 0) {
      log.debug("Leaving GnapRequest.checkSubId(). account without acct: URI.");
      return this.refusal('STS-GNAP-0036', 'an "account" Subject ' +
          'Identifier\'s uri must use the acct scheme (RFC 9493 section ' +
                          '3.2.1).');
    }
    if (subject.format === 'phone_number' &&
        !/^\+[1-9][0-9]{1,14}$/.test(subject.phone_number)) {
      log.debug("Leaving GnapRequest.checkSubId(). phone_number is not E.164.");
      return this.refusal('STS-GNAP-0036', 'a "phone_number" Subject ' +
                          'Identifier must be E.164 (RFC 9493 section 3.2.5).');
    }
    log.debug("Leaving GnapRequest.checkSubId().");
    return { ok: true };
  }

  private checkSubIds(value, where) {
    const { log } = this.deps;
    log.debug("Entering GnapRequest.checkSubIds().");
    if (!Array.isArray(value)) {
      log.debug("Leaving GnapRequest.checkSubIds().");
      return this.refusal('STS-GNAP-0037', '"' + where + '" must be an array ' +
                          'of Subject Identifiers.');
    }
    for (let i = 0; i < value.length; i++) {
      const one = this.checkSubId(value[i], where + '[' + i + ']', false);
      if (!one.ok) {
        log.debug("Leaving GnapRequest.checkSubIds().");
        return one;
      }
    }
    log.debug("Leaving GnapRequest.checkSubIds().");
    return { ok: true, subIds: value };
  }

  // Section 2.2.
  private checkSubjectMember(value) {
    const { log } = this.deps;
    log.debug("Entering GnapRequest.checkSubjectMember().");
    if (!this.isObject(value)) {
      log.debug("Leaving GnapRequest.checkSubjectMember(). Not an object.");
      return this.refusal('STS-GNAP-0038', '"subject" must be an object (RFC ' +
                          '9635 section 2.2).');
    }
    const out = { subIdFormats: [], assertionFormats: [], subIds: null };
    if (value.sub_id_formats !== undefined) {
      if (!this.isStringArray(value.sub_id_formats)) {
        log.debug("Leaving GnapRequest.checkSubjectMember(). sub_id_formats " +
                  "malformed.");
        return this.refusal('STS-GNAP-0038', '"subject.sub_id_formats" must ' +
                            'be an array of strings.');
      }
      out.subIdFormats = value.sub_id_formats;
    }
    if (value.assertion_formats !== undefined) {
      if (!this.isStringArray(value.assertion_formats)) {
        log.debug("Leaving GnapRequest.checkSubjectMember(). " +
                  "assertion_formats malformed.");
        return this.refusal('STS-GNAP-0038', '"subject.assertion_formats" ' +
                            'must be an array of strings.');
      }
      out.assertionFormats = value.assertion_formats;
    }
    if (value.sub_ids !== undefined) {
      const ids = this.checkSubIds(value.sub_ids, 'subject.sub_ids');
      if (!ids.ok) {
        log.debug("Leaving GnapRequest.checkSubjectMember(). sub_ids " +
                  "malformed.");
        return ids;
      }
      out.subIds = ids.subIds;
    }
    log.debug("Leaving GnapRequest.checkSubjectMember().");
    return { ok: true, subject: out };
  }

  // Section 2.3 (by value) and 2.3.1 (by reference). The KEY is described by
  // `gnap_keys.ts`; this checks only that there is one and that `display`'s
  // URIs are absolute.
  private checkClientMember(value) {
    const { log } = this.deps;
    log.debug("Entering GnapRequest.checkClientMember().");
    if (typeof value === 'string') {
      if (!value) {
        log.debug("Leaving GnapRequest.checkClientMember(). Empty reference.");
        return this.refusal('STS-GNAP-0039', '"client" must not be an empty ' +
                            'string.', 'invalid_client');
      }
      log.debug("Leaving GnapRequest.checkClientMember(). By reference.");
      return { ok: true,
               client: { reference: value, key: null, classId: null,
                         display: null } };
    }
    if (!this.isObject(value)) {
      log.debug("Leaving GnapRequest.checkClientMember(). Absent or not an " +
                "object.");
      return this.refusal('STS-GNAP-0039', '"client" is REQUIRED: an object ' +
                          'or an instance identifier (RFC 9635 section 2.3).',
                          'invalid_client');
    }
    if (value.key === undefined || value.key === null) {
      log.debug("Leaving GnapRequest.checkClientMember(). No key.");
      return this.refusal('STS-GNAP-0040', '"client.key" is REQUIRED (RFC ' +
                          '9635 section 2.3).', 'invalid_client');
    }
    if (value.class_id !== undefined && typeof value.class_id !== 'string') {
      log.debug("Leaving GnapRequest.checkClientMember(). class_id is not a " +
                "string.");
      return this.refusal('STS-GNAP-0041', '"client.class_id" must be a ' +
                          'string.');
    }
    let display = null;
    if (value.display !== undefined) {
      if (!this.isObject(value.display)) {
        log.debug("Leaving GnapRequest.checkClientMember(). display is not " +
                  "an object.");
        return this.refusal('STS-GNAP-0041', '"client.display" must be an ' +
                            'object.');
      }
      if (value.display.name !== undefined &&
          typeof value.display.name !== 'string') {
        log.debug("Leaving GnapRequest.checkClientMember(). display.name is " +
                  "not a string.");
        return this.refusal('STS-GNAP-0041',
                            '"client.display.name" must be a string.');
      }
      const uriProblem = value.display.uri === undefined ? '' :
          this.absoluteUriProblem(value.display.uri, 'client.display.uri',
                                  false);
      const logoProblem = value.display.logo_uri === undefined ? '' :
          this.absoluteUriProblem(value.display.logo_uri,
                                  'client.display.logo_uri', true);
      if (uriProblem || logoProblem) {
        log.debug("Leaving GnapRequest.checkClientMember(). A display URI is " +
                  "not absolute.");
        return this.refusal('STS-GNAP-0041', (uriProblem || logoProblem) +
                            ' (RFC 9635 section 2.3.2).');
      }
      display = { name: value.display.name || null,
                  uri: value.display.uri || null,
                  logoUri: value.display.logo_uri || null };
    }
    log.debug("Leaving GnapRequest.checkClientMember(). By value.");
    return { ok: true, client: { reference: null, key: value.key,
                                 classId: value.class_id === undefined ? null :
                                          value.class_id,
                                 display: display } };
  }

  // Section 2.4 and 2.4.1.
  private checkUserMember(value) {
    const { log } = this.deps;
    log.debug("Entering GnapRequest.checkUserMember().");
    if (typeof value === 'string') {
      if (!value) {
        log.debug("Leaving GnapRequest.checkUserMember(). Empty reference.");
        return this.refusal('STS-GNAP-0042', '"user" must not be an empty ' +
                            'string.', 'unknown_user');
      }
      log.debug("Leaving GnapRequest.checkUserMember(). By reference.");
      return { ok: true,
               user: { reference: value, subIds: null, assertions: null } };
    }
    if (!this.isObject(value)) {
      log.debug("Leaving GnapRequest.checkUserMember(). Not an object.");
      return this.refusal('STS-GNAP-0042', '"user" must be an object or a ' +
                          'reference string (RFC 9635 section 2.4).');
    }
    const out = { reference: null, subIds: null, assertions: null };
    if (value.sub_ids !== undefined) {
      const ids = this.checkSubIds(value.sub_ids, 'user.sub_ids');
      if (!ids.ok) {
        log.debug("Leaving GnapRequest.checkUserMember(). sub_ids malformed.");
        return ids;
      }
      out.subIds = ids.subIds;
    }
    if (value.assertions !== undefined) {
      if (!Array.isArray(value.assertions) ||
          !value.assertions.every((one) => {
        return this.isObject(one) && typeof one.format === 'string' &&
               typeof one.value === 'string';
      })) {
        log.debug("Leaving GnapRequest.checkUserMember(). assertions " +
                  "malformed.");
        return this.refusal('STS-GNAP-0043', '"user.assertions" must be an ' +
            'array of objects with string "format" and "value" (RFC 9635 ' +
                            'sections 2.4 and 3.4).');
      }
      out.assertions = value.assertions;
    }
    log.debug("Leaving GnapRequest.checkUserMember(). By value.");
    return { ok: true, user: out };
  }

  // Section 2.5.
  private checkInteractMember(value) {
    const { log } = this.deps;
    log.debug("Entering GnapRequest.checkInteractMember().");
    if (!this.isObject(value)) {
      log.debug("Leaving GnapRequest.checkInteractMember(). Not an object.");
      return this.refusal('STS-GNAP-0044', '"interact" must be an object ' +
                          '(RFC 9635 section 2.5).');
    }
    if (!Array.isArray(value.start)) {
      log.debug("Leaving GnapRequest.checkInteractMember(). start missing.");
      return this.refusal('STS-GNAP-0045', '"interact.start" is REQUIRED and ' +
                          'must be an array (RFC 9635 section 2.5).');
    }
    const start = [];
    for (let i = 0; i < value.start.length; i++) {
      const one = value.start[i];
      const mode = typeof one === 'string' ? one :
                   (this.isObject(one) ? one.mode : undefined);
      if (typeof mode !== 'string' || !mode) {
        log.debug("Leaving GnapRequest.checkInteractMember(). A start mode " +
                  "has no name.");
        return this.refusal('STS-GNAP-0046', 'element ' + i +
            ' of "interact.start" must be a mode name or an object with a ' +
                            '"mode" (RFC 9635 section 2.5.1).');
      }
      // An UNKNOWN start mode is not a malformed request: section 2.5 lets the
      // AS respond to "any, all, or none" of what the client offers, and a mode
      // registered after this implementation was written is exactly that. It
      // is kept, so the policy layer can see it was offered and decline it.
      if (start.indexOf(mode) < 0) {
        start.push(mode);
      }
    }
    let finish = null;
    if (value.finish !== undefined) {
      const f = value.finish;
      if (!this.isObject(f) || typeof f.method !== 'string' || !f.method) {
        log.debug("Leaving GnapRequest.checkInteractMember(). finish has no " +
                  "method.");
        return this.refusal('STS-GNAP-0047', '"interact.finish.method" is ' +
                            'REQUIRED (RFC 9635 section 2.5.2).');
      }
      if (typeof f.nonce !== 'string' || !f.nonce ||
          !/^[\x21-\x7e]+$/.test(f.nonce)) {
        log.debug("Leaving GnapRequest.checkInteractMember(). finish nonce " +
                  "missing or not ASCII.");
        return this.refusal('STS-GNAP-0048', '"interact.finish.nonce" is ' +
            'REQUIRED and must be an ASCII string (RFC 9635 section 2.5.2).');
      }
      if (f.method === 'redirect' || f.method === 'push') {
        const problem = this.absoluteUriProblem(f.uri, 'interact.finish.uri',
                                                false);
        if (problem) {
          log.debug("Leaving GnapRequest.checkInteractMember(). finish URI " +
                    "refused: " + problem);
          return this.refusal('STS-GNAP-0049', problem + ' (RFC 9635 section ' +
                              '2.5.2).');
        }
      }
      const hashMethod = f.hash_method === undefined ? 'sha-256' :
          f.hash_method;
      if (typeof hashMethod !== 'string' || !HASH_METHODS[hashMethod]) {
        log.debug("Leaving GnapRequest.checkInteractMember(). Unsupported " +
                  "hash_method.");
        return this.refusal('STS-GNAP-0050', 'the hash_method "' + hashMethod +
            '" is not one this authorization server computes (' +
                            Object.keys(HASH_METHODS).join(', ') + ').');
      }
      finish = { method: f.method, uri: typeof f.uri === 'string' ? f.uri :
                 null, nonce: f.nonce, hashMethod: hashMethod };
    }
    let hints = { uiLocales: [] };
    if (value.hints !== undefined) {
      if (!this.isObject(value.hints) ||
          (value.hints.ui_locales !== undefined &&
           !this.isStringArray(value.hints.ui_locales))) {
        log.debug("Leaving GnapRequest.checkInteractMember(). hints " +
                  "malformed.");
        return this.refusal('STS-GNAP-0051', '"interact.hints" must be an ' +
            'object whose "ui_locales" is an array of strings (RFC 9635 ' +
                            'section 2.5.3).');
      }
      hints = { uiLocales: value.hints.ui_locales || [] };
    }
    log.debug("Leaving GnapRequest.checkInteractMember(). start=" +
              start.join(',') + ", finish=" + (finish ? finish.method :
                                               'none'));
    return { ok: true, interact: { start: start, finish: finish, hints:
                                   hints } };
  }

  // ---------------------------------------------------------------------------
  // THE DOCUMENT MUST PASS SANITISATION AND ITS JSON SCHEMA FIRST.
  //
  // `checkDocument()` bounds depth and key count and refuses polluting member
  // names; `gnap_schemas.ts` then enforces the shape — types, lengths, item and
  // member caps, URI formats, no control characters. Only a document that
  // passes both is walked below. See gnap_schemas.ts's header for why the
  // schema leaves `required` and `enum` to the walk.
  // ---------------------------------------------------------------------------
  private checkEnvelope(body, where, schema, gnapError?) {
    const { log, validation, schemas } = this.deps;
    log.debug("Entering GnapRequest.checkEnvelope(). where=" + where);
    if (!this.isObject(body)) {
      log.debug("Leaving GnapRequest.checkEnvelope(). Not an object.");
      return this.refusal('STS-GNAP-0052', 'the ' + where + ' must be a JSON ' +
                          'object.', gnapError);
    }
    const bounded = validation.checkDocument(body, where,
                                             { maxDepth: 12, maxKeys: 2000 });
    if (!bounded.ok) {
      log.debug("Leaving GnapRequest.checkEnvelope(). " + bounded.code);
      return this.refusal('STS-GNAP-0053', bounded.detail, gnapError);
    }
    if (schema) {
      const shaped = schemas.validate(schema, body);
      if (!shaped.ok) {
        log.debug("Leaving GnapRequest.checkEnvelope(). Schema: " +
                  shaped.detail);
        return this.refusal('STS-GNAP-0061', 'the ' + where +
                            ' does not match its schema: ' + shaped.detail +
                            '.', gnapError);
      }
    }
    log.debug("Leaving GnapRequest.checkEnvelope().");
    return { ok: true };
  }

  // ---------------------------------------------------------------------------
  // SECTION 2: A NEW GRANT REQUEST.
  // ---------------------------------------------------------------------------
  parseGrantRequest(body) {
    const { log } = this.deps;
    log.debug("Entering GnapRequest.parseGrantRequest().");
    const envelope = this.checkEnvelope(body, 'grant request', 'grantRequest');
    if (!envelope.ok) {
      log.debug("Leaving GnapRequest.parseGrantRequest(). Envelope refused.");
      return envelope;
    }
    if (body.interact_ref !== undefined) {
      // Section 5.1: an interaction reference belongs to a CONTINUATION, and
      // the grant endpoint has no grant to continue.
      log.debug("Leaving GnapRequest.parseGrantRequest(). interact_ref on a " +
                "new request.");
      return this.refusal('STS-GNAP-0054', '"interact_ref" is only sent to a ' +
                          'continuation URI (RFC 9635 section 5.1).');
    }
    const out = { tokens: [], multiple: false, subject: null, client: null,
                  user: null,
                  interact: null, existingAccessToken: null };
    if (body.access_token === undefined && body.subject === undefined) {
      log.debug("Leaving GnapRequest.parseGrantRequest(). Neither " +
                "access_token nor subject.");
      return this.refusal('STS-GNAP-0055', 'a grant request must ask for ' +
          'something: "access_token" (section 2.1), "subject" (section 2.2), ' +
                          'or both.');
    }
    if (body.access_token !== undefined) {
      const tokens = this.checkAccessTokenMember(body.access_token);
      if (!tokens.ok) {
        log.debug("Leaving GnapRequest.parseGrantRequest(). access_token " +
                  "refused.");
        return tokens;
      }
      out.tokens = tokens.tokens;
      out.multiple = tokens.multiple;
    }
    if (body.subject !== undefined) {
      const subject = this.checkSubjectMember(body.subject);
      if (!subject.ok) {
        log.debug("Leaving GnapRequest.parseGrantRequest(). subject refused.");
        return subject;
      }
      out.subject = subject.subject;
    }
    const client = this.checkClientMember(body.client);
    if (!client.ok) {
      log.debug("Leaving GnapRequest.parseGrantRequest(). client refused.");
      return client;
    }
    out.client = client.client;
    if (body.user !== undefined) {
      const user = this.checkUserMember(body.user);
      if (!user.ok) {
        log.debug("Leaving GnapRequest.parseGrantRequest(). user refused.");
        return user;
      }
      out.user = user.user;
    }
    if (body.interact !== undefined) {
      const interact = this.checkInteractMember(body.interact);
      if (!interact.ok) {
        log.debug("Leaving GnapRequest.parseGrantRequest(). interact refused.");
        return interact;
      }
      out.interact = interact.interact;
    }
    if (body.existing_access_token !== undefined) {
      // RFC 9767 section 4.
      if (typeof body.existing_access_token !== 'string' ||
          !body.existing_access_token) {
        log.debug("Leaving GnapRequest.parseGrantRequest(). " +
                  "existing_access_token malformed.");
        return this.refusal('STS-GNAP-0056', '"existing_access_token" must ' +
                            'be a non-empty string (RFC 9767 section 4).');
      }
      out.existingAccessToken = body.existing_access_token;
    }
    log.debug("Leaving GnapRequest.parseGrantRequest(). " + out.tokens.length +
              " token request(s), subject=" + !!out.subject + ", interact=" +
              !!out.interact);
    return { ok: true, request: out };
  }

  // Section 5.1 / 5.2: an empty body (a poll) or `{ interact_ref }`.
  parseContinuation(body, hadContent?) {
    const { log } = this.deps;
    log.debug("Entering GnapRequest.parseContinuation().");
    if (!hadContent) {
      log.debug("Leaving GnapRequest.parseContinuation(). A poll.");
      return { ok: true, interactRef: null };
    }
    const envelope = this.checkEnvelope(body, 'continuation request',
                                        'continuation');
    if (!envelope.ok) {
      log.debug("Leaving GnapRequest.parseContinuation(). Envelope refused.");
      return envelope;
    }
    const unexpected = Object.keys(body).filter(function (name) {
      return name !== 'interact_ref';
    });
    if (unexpected.length) {
      // Section 5.3 puts modification on PATCH. A POST carrying access_token or
      // client is a client that has confused the two, and silently ignoring the
      // members would issue what it did NOT just ask for.
      log.debug("Leaving GnapRequest.parseContinuation(). Unexpected members.");
      return this.refusal('STS-GNAP-0057', 'a continuation POST carries only ' +
                          '"interact_ref"; "' + unexpected.join('", "') +
                          '" belong to a PATCH (RFC 9635 section 5.3).');
    }
    if (body.interact_ref !== undefined &&
        (typeof body.interact_ref !== 'string' ||
         !/^[A-Za-z0-9._~-]+$/.test(body.interact_ref))) {
      log.debug("Leaving GnapRequest.parseContinuation(). interact_ref " +
                "malformed.");
      return this.refusal('STS-GNAP-0058', '"interact_ref" must be a string ' +
                          'of unreserved characters (RFC 9635 section 4.2).',
                          'invalid_interaction');
    }
    log.debug("Leaving GnapRequest.parseContinuation().");
    return { ok: true,
             interactRef: body.interact_ref === undefined ? null :
                          body.interact_ref };
  }

  // Section 5.3.
  parseModification(body) {
    const { log } = this.deps;
    log.debug("Entering GnapRequest.parseModification().");
    const envelope = this.checkEnvelope(body, 'modification request',
                                        'modification');
    if (!envelope.ok) {
      log.debug("Leaving GnapRequest.parseModification(). Envelope refused.");
      return envelope;
    }
    if (body.client !== undefined) {
      log.debug("Leaving GnapRequest.parseModification(). client present.");
      return this.refusal('STS-GNAP-0059', 'a modification MUST NOT include ' +
                          '"client" (RFC 9635 section 5.3).');
    }
    if (body.interact_ref !== undefined) {
      log.debug("Leaving GnapRequest.parseModification(). interact_ref " +
                "present.");
      return this.refusal('STS-GNAP-0059', 'a modification MUST NOT include ' +
                          '"interact_ref" (RFC 9635 section 5.3).');
    }
    const out = { tokens: null, multiple: false, subject: null, user: null,
                  interact: null };
    if (body.access_token !== undefined) {
      const tokens = this.checkAccessTokenMember(body.access_token);
      if (!tokens.ok) {
        log.debug("Leaving GnapRequest.parseModification(). access_token " +
                  "refused.");
        return tokens;
      }
      out.tokens = tokens.tokens;
      out.multiple = tokens.multiple;
    }
    if (body.subject !== undefined) {
      const subject = this.checkSubjectMember(body.subject);
      if (!subject.ok) {
        log.debug("Leaving GnapRequest.parseModification(). subject refused.");
        return subject;
      }
      out.subject = subject.subject;
    }
    if (body.user !== undefined) {
      const user = this.checkUserMember(body.user);
      if (!user.ok) {
        log.debug("Leaving GnapRequest.parseModification(). user refused.");
        return user;
      }
      out.user = user.user;
    }
    if (body.interact !== undefined) {
      const interact = this.checkInteractMember(body.interact);
      if (!interact.ok) {
        log.debug("Leaving GnapRequest.parseModification(). interact refused.");
        return interact;
      }
      out.interact = interact.interact;
    }
    log.debug("Leaving GnapRequest.parseModification().");
    return { ok: true, request: out };
  }

  // Section 6.1 / 6.1.1: no content, or `{ key }`.
  parseRotation(body, hadContent?) {
    const { log } = this.deps;
    log.debug("Entering GnapRequest.parseRotation().");
    if (!hadContent) {
      log.debug("Leaving GnapRequest.parseRotation(). Plain rotation.");
      return { ok: true, key: null };
    }
    const envelope = this.checkEnvelope(body, 'rotation request', 'rotation',
                                        'invalid_rotation');
    if (!envelope.ok) {
      log.debug("Leaving GnapRequest.parseRotation(). Envelope refused.");
      return envelope;
    }
    const unexpected = Object.keys(body).filter(function (name) {
      return name !== 'key';
    });
    if (unexpected.length || body.key === undefined) {
      // Section 6.1: a rotation "cannot request to alter the access rights".
      log.debug("Leaving GnapRequest.parseRotation(). Members other than key.");
      return this.refusal('STS-GNAP-0060', 'a rotation request carries no ' +
          'content, or only "key" (RFC 9635 sections 6.1 and 6.1.1).',
                          'invalid_rotation');
    }
    log.debug("Leaving GnapRequest.parseRotation(). Key rotation.");
    return { ok: true, key: body.key };
  }

  // RFC 9767 section 3.2's `resource_server`: an object with a key, or a
  // string.
  private checkResourceServer(value) {
    const { log } = this.deps;
    log.debug("Entering GnapRequest.checkResourceServer().");
    if (typeof value === 'string' && value) {
      log.debug("Leaving GnapRequest.checkResourceServer().");
      return { ok: true, resourceServer: { reference: value, key: null } };
    }
    if (this.isObject(value) && value.key !== undefined) {
      log.debug("Leaving GnapRequest.checkResourceServer().");
      return { ok: true, resourceServer: { reference: null, key: value.key } };
    }
    log.debug("Leaving GnapRequest.checkResourceServer().");
    return this.refusal('STS-GNAP-0500', '"resource_server" is REQUIRED: an ' +
        'object with a "key" or an instance identifier (RFC 9767 section 3.2).',
                        'invalid_resource_server');
  }

  // RFC 9767 section 3.3.
  parseIntrospection(body) {
    const { log } = this.deps;
    log.debug("Entering GnapRequest.parseIntrospection().");
    const envelope = this.checkEnvelope(body, 'introspection request',
                                        'introspection');
    if (!envelope.ok) {
      log.debug("Leaving GnapRequest.parseIntrospection(). Envelope refused.");
      return envelope;
    }
    if (typeof body.access_token !== 'string' || !body.access_token) {
      log.debug("Leaving GnapRequest.parseIntrospection(). No access_token.");
      return this.refusal('STS-GNAP-0501', '"access_token" is REQUIRED (RFC ' +
                          '9767 section 3.3).');
    }
    if (body.proof !== undefined &&
        (typeof body.proof !== 'string' || !body.proof)) {
      log.debug("Leaving GnapRequest.parseIntrospection(). proof malformed.");
      return this.refusal('STS-GNAP-0501', '"proof" must be a key proofing ' +
                          'method name (RFC 9767 section 3.3).');
    }
    const rs = this.checkResourceServer(body.resource_server);
    if (!rs.ok) {
      log.debug("Leaving GnapRequest.parseIntrospection(). resource_server " +
                "refused.");
      return rs;
    }
    let access = null;
    if (body.access !== undefined) {
      const checked = this.checkAccess(body.access, 'access');
      if (!checked.ok) {
        log.debug("Leaving GnapRequest.parseIntrospection(). access refused.");
        return checked;
      }
      access = checked.access;
    }
    log.debug("Leaving GnapRequest.parseIntrospection().");
    return { ok: true, request: { accessToken: body.access_token, proof:
                                  body.proof || null, resourceServer:
                                  rs.resourceServer, access: access } };
  }

  // RFC 9767 section 3.4.
  parseRegistration(body) {
    const { log } = this.deps;
    log.debug("Entering GnapRequest.parseRegistration().");
    const envelope = this.checkEnvelope(body, 'resource registration request',
                                        'registration');
    if (!envelope.ok) {
      log.debug("Leaving GnapRequest.parseRegistration(). Envelope refused.");
      return envelope;
    }
    const access = this.checkAccess(body.access, 'access');
    if (!access.ok) {
      log.debug("Leaving GnapRequest.parseRegistration(). access refused.");
      return access;
    }
    if (!access.access.length) {
      log.debug("Leaving GnapRequest.parseRegistration(). Empty access.");
      return this.refusal('STS-GNAP-0502', '"access" must name at least one ' +
                          'right to register (RFC 9767 section 3.4).');
    }
    const rs = this.checkResourceServer(body.resource_server);
    if (!rs.ok) {
      log.debug("Leaving GnapRequest.parseRegistration(). resource_server " +
                "refused.");
      return rs;
    }
    if (body.token_formats_supported !== undefined &&
        !this.isStringArray(body.token_formats_supported)) {
      log.debug("Leaving GnapRequest.parseRegistration(). " +
                "token_formats_supported malformed.");
      return this.refusal('STS-GNAP-0502', '"token_formats_supported" must ' +
                          'be an array of strings.');
    }
    if (body.token_introspection_required !== undefined &&
        typeof body.token_introspection_required !== 'boolean') {
      log.debug("Leaving GnapRequest.parseRegistration(). " +
                "token_introspection_required malformed.");
      return this.refusal('STS-GNAP-0502', '"token_introspection_required" ' +
                          'must be a boolean.');
    }
    log.debug("Leaving GnapRequest.parseRegistration().");
    return { ok: true, request: {
      access: access.access, resourceServer: rs.resourceServer,
      tokenFormats: body.token_formats_supported || null,
      introspectionRequired: body.token_introspection_required === true
    } };
  }
}

// THE TRANSITIONAL INSTANCE — see the header above. Built from the real
// modules, as the composition root will build one.
const parser = new GnapRequest({
  log: helpers.log,
  errorCodes: errorCodes,
  validation: validation,
  schemas: schemas
});

export = {
  GnapRequest: GnapRequest,
  REQUEST_FLAGS: GnapRequest.REQUEST_FLAGS,
  START_MODES: GnapRequest.START_MODES,
  FINISH_METHODS: GnapRequest.FINISH_METHODS,
  ASSERTION_FORMATS: GnapRequest.ASSERTION_FORMATS,
  SUB_ID_FORMATS: GnapRequest.SUB_ID_FORMATS,
  HASH_METHODS: GnapRequest.HASH_METHODS,
  checkAccess: parser.checkAccess.bind(parser) as GnapRequest['checkAccess'],
  checkSubId: parser.checkSubId.bind(parser) as GnapRequest['checkSubId'],
  parseGrantRequest: parser.parseGrantRequest.bind(parser) as
    GnapRequest['parseGrantRequest'],
  parseContinuation: parser.parseContinuation.bind(parser) as
    GnapRequest['parseContinuation'],
  parseModification: parser.parseModification.bind(parser) as
    GnapRequest['parseModification'],
  parseRotation: parser.parseRotation.bind(parser) as
    GnapRequest['parseRotation'],
  parseIntrospection: parser.parseIntrospection.bind(parser) as
    GnapRequest['parseIntrospection'],
  parseRegistration: parser.parseRegistration.bind(parser) as
    GnapRequest['parseRegistration']
};
