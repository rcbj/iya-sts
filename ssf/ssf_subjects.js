// @ts-check
'use strict';
//
// File: ssf_subjects.js
//
// ---------------------------------------------------------------------------
// SUBJECT IDENTIFIERS FOR SECURITY EVENT TOKENS (RFC 9493), AND THE COMPLEX
// SUBJECT THE SHARED SIGNALS FRAMEWORK LAYERS ON TOP OF THEM.
//
// A Security Event Token says that something happened; a Subject Identifier is
// the part that says WHO it happened to. RFC 9493 gives eight formats, SSF 1.0
// section 3.5 adds three more, and the whole of the substance is that each one
// has a CLOSED set of members and every one of them is REQUIRED. That sounds
// like a formality and it is the thing implementations get wrong: a subject
// with an extra member is not a subject with an extra member, it is a subject
// a conforming receiver MUST reject, because the receiver cannot tell whether
// the member it does not recognise narrows the identifier.
//
// So this module refuses, by name, and says which member was the problem. A
// mock that accepted a loose subject would let somebody ship a transmitter
// that no real receiver will take.
//
// ---------------------------------------------------------------------------
// WHY THIS IS WRITTEN OUT HERE RATHER THAN VENDORED FROM THE DEBUGGER.
//
// It is the argument `common/pq_jose.js` makes, and it applies more sharply to
// a grammar than to a signature. This service exists to be the far end of the
// debugger's own SSF code: the debugger BUILDS a subject and this service
// READS it. If both ends read one implementation, a misunderstanding they
// share is one neither can see — and the round trip would pass while
// interoperating with nothing.
//
// So the debugger has `client/src/ssf_client.js`'s own grammar, this file is
// this service's, and `tests/ssf_protocol.js` in the parent project drives one
// against the other OVER THE WIRE. That is the only arrangement in which a
// disagreement surfaces as a failure rather than as agreement.
//
// It is the opposite decision from the Kerberos codec modules in `kerberos/`,
// which ARE vendored, and the difference is worth stating: a Kerberos codec is
// bytes with one legal encoding, so two implementations is two chances to be
// wrong about the same bytes with nothing to gain. A subject identifier is
// JSON, where the interesting defect is a READING — an accepted extra member,
// a missing required one, a format name spelt from memory — and two readings
// is exactly what makes that visible.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3). It registers no route, so its position in the
// route order is not a position. It requires `helpers.js` for the logger and
// `mode.js` (a leaf, below) and NOTHING ELSE in this repository, so it cannot
// join a cycle and a test can drive it with plain objects.
// ---------------------------------------------------------------------------

const net = require('net');
const { log, subjectForName } = require('../common/helpers');
// For `inventsClaimValues()`: whether an address may be made up for somebody
// whose entry carries none. A leaf requiring only config, so this file stays a
// library that can join no cycle.
const mode = require('../common/mode');
const realms = require('../common/realms');

// ---------------------------------------------------------------------------
// THE ELEVEN FORMATS: RFC 9493 SECTION 3.2'S EIGHT AND SSF 1.0 SECTION 3.5'S
// THREE, EACH WITH ITS CLOSED MEMBER SET.
//
// `members` is what the format defines; `required` is which of them a
// conforming subject MUST carry. For every row those two lists are the same,
// which is the specifications' own shape rather than a shortcut here: neither
// RFC 9493 nor SSF defines an optional member on any of them.
//
// **THE NAMES ARE THE REGISTRY'S, AND UNTIL 2026-09-22 TWO OF THEM WERE NOT.**
// This table said `issuer_subject_id` and `decentralized_identifier` — the
// names from the drafts before RFC 9493 — where the RFC and the IANA "Security
// Event Identifier Formats" registry say `iss_sub` and `did`. So every CAEP
// event this service sent named its user in a format no conforming receiver
// knows, a receiver that sent a correct `iss_sub` to subjects/add was refused,
// and `risc.subjectFormat`'s documented default of `iss_sub` silently fell back
// to the wrong name (#144). No old spelling is accepted on input: a receiver
// that learnt it here learnt something no other transmitter will take.
//
// `section` is where the row is defined, for the page. `what` is prose for the
// console and for `GET /ssf`; `example` is a real value of that format, used
// by the page and by the test as a fixture. None of the three is read by the
// validator.
// ---------------------------------------------------------------------------
const FORMATS = [
  { format: 'account',
    members: ['uri'], required: ['uri'],
    what: 'An "acct" URI (RFC 7565) — a user at a service, the identifier ' +
          'form WebFinger uses.',
    example: { format: 'account', uri: 'acct:alice@example.com' } },
  { format: 'email',
    members: ['email'], required: ['email'],
    what: 'An email address (RFC 5322 addr-spec). The commonest subject in ' +
          'practice and the one most likely to be RECYCLED, which is why ' +
          'RISC has an event type about exactly that.',
    example: { format: 'email', email: 'alice@example.com' } },
  { format: 'iss_sub',
    members: ['iss', 'sub'], required: ['iss', 'sub'],
    what: 'The pair an OpenID Connect ID Token is identified by — the ' +
          'issuer and the subject within it. The only format that is ' +
          'globally unique by construction rather than by convention.',
    example: { format: 'iss_sub',
               iss: 'https://issuer.example.com/', sub: '145234573' } },
  { format: 'opaque',
    members: ['id'], required: ['id'],
    what: 'A string meaningful only to the parties that agreed it. It says ' +
          'nothing about what kind of thing it names, which is the point: a ' +
          'transmitter that must not leak an email address uses this.',
    example: { format: 'opaque', id: '11112222333344445555' } },
  { format: 'phone_number',
    members: ['phone_number'], required: ['phone_number'],
    what: 'A phone number in E.164 form. RFC 9493 requires the leading "+" ' +
          'and digits only — no spaces, no punctuation, no extension.',
    example: { format: 'phone_number', phone_number: '+12065550100' } },
  { format: 'did',
    members: ['url'], required: ['url'],
    what: 'A DID or a DID URL (W3C DID Core). The identifier resolves to a ' +
          'document rather than to a record at the transmitter.',
    example: { format: 'did',
               url: 'did:example:123456789abcdefghi' } },
  { format: 'uri',
    members: ['uri'], required: ['uri'],
    what: 'Any URI. The escape hatch, and the one to reach for LAST — a ' +
          'receiver can do nothing with it but compare it, so a format that ' +
          'says what kind of thing this is is always better.',
    example: { format: 'uri', uri: 'https://example.com/users/1234' } },
  { format: 'aliases',
    members: ['identifiers'], required: ['identifiers'],
    what: 'SEVERAL identifiers for ONE subject, so a receiver that knows the ' +
          'person by any of them can act. It MUST NOT contain another ' +
          'aliases identifier — RFC 9493 section 3.2.8 forbids the nesting ' +
          'outright, and this service refuses it rather than flattening, ' +
          'because flattening would accept a document a conforming receiver ' +
          'rejects.',
    example: { format: 'aliases', identifiers: [
      { format: 'email', email: 'alice@example.com' },
      { format: 'phone_number', phone_number: '+12065550100' }
    ] } },
  // SSF 1.0 SECTION 3.5's THREE. Not in RFC 9493's registry; SSF defines them
  // for its own events, and CAEP's session and token events use the first two.
  { format: 'jwt_id', section: 'SSF 1.0 section 3.5.1',
    members: ['iss', 'jti'], required: ['iss', 'jti'],
    what: 'One JWT, by the issuer that minted it and its "jti" — which is ' +
          'how an event can be about a single token rather than about a ' +
          'person or a session.',
    example: { format: 'jwt_id', iss: 'https://idp.example.com/123456789/',
               jti: 'B70BA622-9515-4353-A866-823539EECBC8' } },
  { format: 'saml_assertion_id', section: 'SSF 1.0 section 3.5.2',
    members: ['issuer', 'assertion_id'], required: ['issuer', 'assertion_id'],
    what: 'One SAML 2.0 assertion, by its Issuer and its ID. The SAML ' +
          'counterpart of jwt_id; note the members are "issuer" and ' +
          '"assertion_id", not "iss" and "id".',
    example: { format: 'saml_assertion_id',
               issuer: 'https://idp.example.com/123456789/',
               assertion_id: '_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6' } },
  { format: 'ip-addresses', section: 'SSF 1.0 section 3.5.3',
    members: ['ip-addresses'], required: ['ip-addresses'],
    what: 'The IP addresses the transmitter observed the subject at, as a ' +
          'non-empty array of RFC 4001 strings. The only format whose value ' +
          'is an array, and the only one whose name and member are the same ' +
          'hyphenated word.',
    example: { format: 'ip-addresses',
               'ip-addresses': ['10.29.37.75',
                                '2001:0db8:0000:0000:0000:8a2e:0370:7334'] } }
];

const FORMAT_BY_NAME = {};
FORMATS.forEach(function (row) {
  FORMAT_BY_NAME[row.format] = row;
});

const FORMAT_NAMES = FORMATS.map(function (row) {
  return row.format;
});

// ---------------------------------------------------------------------------
// THE COMPLEX SUBJECT, which is the Shared Signals Framework's own addition
// and not RFC 9493's.
//
// SSF 1.0 section 3.3 lets a subject member of a SET be an object whose
// members are each themselves a Subject Identifier, so one event can name the
// person AND the device AND the session it is about. That is what makes "this
// session was revoked" expressible at all: the person is not revoked, one
// session of theirs is.
//
// **IT CARRIES `"format": "complex"` (SSF 1.0 final, section 3.3).** The drafts
// told a complex subject from a simple one by the ABSENCE of `format`, and this
// file did the same — sending complex subjects with no `format` and refusing
// one that carried it — until 2026-09-22 (#144). The final text gives it a
// format like every other subject, so the discriminator is now that value and
// a subject with no `format` at all is simply malformed.
//
// **SEVEN NAMES ARE DEFINED, AND OTHERS ARE ALLOWED.** `application` is the
// seventh the final text added. "Additional Subject Member names MAY be used",
// so a member this service does not know is no longer refused — it is read as
// a Subject Identifier like the rest, and refused only if it is not one. What
// a receiver MUST understand is a different list and is configuration rather
// than grammar: `critical_subject_members`, from `ssf.criticalSubjectMembers`.
// ---------------------------------------------------------------------------
const COMPLEX_FORMAT = 'complex';

const COMPLEX_MEMBERS = [
  { name: 'user', what: 'The person.' },
  { name: 'device', what: 'The device they are on.' },
  { name: 'session', what: 'The one session, of possibly many.' },
  { name: 'application', what: 'The application the event concerns.' },
  { name: 'tenant', what: 'The tenant, in a multi-tenant service.' },
  { name: 'org_unit', what: 'The organizational unit within the tenant.' },
  { name: 'group', what: 'The group membership the event is about.' }
];

const COMPLEX_MEMBER_NAMES = COMPLEX_MEMBERS.map(function (row) {
  return row.name;
});

// An additional member's NAME. The specification puts no grammar on it; this
// is the shape a JSON member name has to have to be one a receiver can refer
// to in `critical_subject_members` and a person can type, and it keeps out the
// empty string and `format`, which is the discriminator and not a member.
const MEMBER_NAME = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;

function isComplex(subject) {
  log.debug('Entering isComplex().');
  log.debug('Leaving isComplex().');
  return !!subject && typeof subject === 'object' && !Array.isArray(subject) &&
         subject.format === COMPLEX_FORMAT;
}

// E.164: a plus and between 1 and 15 digits. Deliberately no punctuation and
// no extension — RFC 9493 section 3.2.5 says the value is the number in that
// form, and a receiver comparing "+1 206 555 0100" to "+12065550100" finds two
// different subjects.
const E164 = /^\+[1-9][0-9]{1,14}$/;

// An addr-spec, checked loosely on purpose: this is a mock, and a grammar
// strict enough to be interesting about email addresses would refuse valid
// ones. What is checked is what a comparison depends on — one "@", something
// on each side of it, and no whitespace.
const ADDR_SPEC = /^[^\s@]+@[^\s@]+$/;

// An "acct" URI (RFC 7565): the scheme, then the same shape as an addr-spec.
const ACCT_URI = /^acct:[^\s@]+@[^\s@]+$/;

// A DID or DID URL: "did:", a lower-case method name, a colon, and at least
// one character of method-specific identifier. What follows (a path, a query,
// a fragment) is the URL half and is not constrained here.
const DID_URL = /^did:[a-z0-9]+:[^\s]+$/;

// Any absolute URI: a scheme, a colon and something. Deliberately not a URL
// parser — RFC 9493's `uri` format accepts a URI and `new URL()` would refuse
// several that are perfectly legal (a bare `urn:`, a `tag:`).
const ABSOLUTE_URI = /^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$/;

// ---------------------------------------------------------------------------
// The per-format value checks, one function each, keyed by MEMBER name rather
// than by format so that `uri` on the `uri` format and `uri` on the `account`
// format can differ — which they do, and the difference is the whole of what
// tells those two formats apart on the wire.
// ---------------------------------------------------------------------------
const VALUE_CHECKS = {
  'account.uri': function (value) {
    log.debug("Entering account.uri().");
    log.debug("Leaving account.uri().");
    return ACCT_URI.test(value)
      ? null
      : 'is not an "acct" URI (RFC 7565) — it has to begin "acct:" and ' +
        'carry a user and a host, as in acct:alice@example.com';
  },
  'email.email': function (value) {
    log.debug("Entering email.email().");
    log.debug("Leaving email.email().");
    return ADDR_SPEC.test(value)
      ? null
      : 'is not an email address — one "@", something either side of it, ' +
        'and no whitespace';
  },
  'phone_number.phone_number': function (value) {
    log.debug("Entering phone_number.phone_number().");
    log.debug("Leaving phone_number.phone_number().");
    return E164.test(value)
      ? null
      : 'is not an E.164 number — RFC 9493 section 3.2.5 wants a leading ' +
        '"+" and digits only, so "+1 206 555 0100" is a DIFFERENT subject ' +
        'from "+12065550100" to any receiver that compares them';
  },
  'did.url': function (value) {
    log.debug("Entering did.url().");
    log.debug("Leaving did.url().");
    return DID_URL.test(value)
      ? null
      : 'is not a DID or a DID URL — it has to begin "did:", name a method ' +
        'and carry a method-specific identifier';
  },
  'uri.uri': function (value) {
    log.debug("Entering uri.uri().");
    log.debug("Leaving uri.uri().");
    return ABSOLUTE_URI.test(value)
      ? null
      : 'is not an absolute URI — it needs a scheme and a colon';
  },
  'iss_sub.iss': function (value) {
    log.debug("Entering iss_sub.iss().");
    log.debug("Leaving iss_sub.iss().");
    return ABSOLUTE_URI.test(value)
      ? null
      : 'is not an absolute URI. An issuer identifier is one, always — it ' +
        'is the same string the ID Token carries';
  },
  // RFC 7519's `iss` is a StringOrURI, so a jwt_id's issuer is checked the way
  // an iss_sub's is: it is the same member of the same kind of token.
  'jwt_id.iss': function (value) {
    log.debug("Entering jwt_id.iss().");
    log.debug("Leaving jwt_id.iss().");
    return ABSOLUTE_URI.test(value)
      ? null
      : 'is not an absolute URI — it is the "iss" claim of the JWT being ' +
        'identified';
  }
};

// An `ip-addresses` value: a non-empty array of RFC 4001 strings. `net.isIP()`
// is node's own reading of both families, which is the check a comparison
// depends on; it refuses a CIDR, a port and a bracketed IPv6 literal, none of
// which is an address.
function checkIpAddresses(value) {
  log.debug('Entering checkIpAddresses().');
  if (!Array.isArray(value) || !value.length) {
    log.debug('Leaving checkIpAddresses(). Not a non-empty array.');
    return 'must be a non-empty array of IP address strings (SSF 1.0 ' +
           'section 3.5.3)';
  }
  const bad = value.filter(function (one) {
    return typeof one !== 'string' || net.isIP(one) === 0;
  });
  log.debug('Leaving checkIpAddresses(). ' + bad.length + ' bad.');
  return bad.length
    ? 'holds ' + bad.map(function (one) {
        return JSON.stringify(one);
      }).join(', ') + ', which ' + (bad.length === 1 ? 'is' : 'are') +
      ' not the RFC 4001 string form of an IPv4 or IPv6 address'
    : null;
}

// Every member that has no check of its own is a non-empty string and nothing
// more. `opaque.id` is the case that matters: it is opaque BY DEFINITION, so a
// check on its shape would be this service inventing a rule.
function checkMemberValue(format, member, value) {
  log.debug('Entering checkMemberValue(). ' + format + '.' + member);
  if (format === 'ip-addresses') {
    log.debug('Leaving checkMemberValue(). An array of addresses.');
    return checkIpAddresses(value);
  }
  if (typeof value !== 'string' || value === '') {
    log.debug('Leaving checkMemberValue(). Not a non-empty string.');
    return 'must be a non-empty string';
  }
  const check = VALUE_CHECKS[format + '.' + member];
  if (!check) {
    log.debug('Leaving checkMemberValue(). No shape rule for this member.');
    return null;
  }
  const problem = check(value);
  log.debug('Leaving checkMemberValue(). ' + (problem ? 'refused' : 'ok'));
  return problem;
}

// ---------------------------------------------------------------------------
// VALIDATE ONE SIMPLE SUBJECT IDENTIFIER.
//
// Returns `{ ok, format, errors }`. Every problem is collected rather than the
// first one thrown, because a subject built by hand on a debugger's form is
// usually wrong in more than one way at once and a validator that reports one
// error per attempt is a validator somebody stops reading.
//
// `path` is where this identifier sits in the document ("sub_id",
// "sub_id.user", "sub_id.identifiers[1]"), so the message names the member the
// caller can actually find.
// ---------------------------------------------------------------------------
function validateSubject(subject, path, options) {
  log.debug('Entering validateSubject(). ' + (path || 'sub_id'));
  const where = path || 'sub_id';
  const settings = options || {};
  const errors = [];
  if (!subject || typeof subject !== 'object' || Array.isArray(subject)) {
    errors.push(where + ' must be a JSON object.');
    log.debug('Leaving validateSubject(). Not an object.');
    return { ok: false, format: '', errors: errors };
  }
  const format = subject.format;
  if (typeof format !== 'string' || format === '') {
    errors.push(where + ' has no "format" member. RFC 9493 makes it ' +
        'REQUIRED on every Subject Identifier — without it a receiver ' +
        'cannot know which members to read. The formats are: ' +
        FORMAT_NAMES.join(', ') + '.');
    log.debug('Leaving validateSubject(). No format.');
    return { ok: false, format: '', errors: errors };
  }
  const row = FORMAT_BY_NAME[format];
  if (!row) {
    errors.push(where + ' names the format "' + format + '", which neither ' +
        'RFC 9493 nor SSF 1.0 section 3.5 defines. The formats are: ' +
        FORMAT_NAMES.join(', ') + (format === COMPLEX_FORMAT
          ? ' — "complex" is a sub_id of its own and cannot sit inside one'
          : '') + '.');
    log.debug('Leaving validateSubject(). Unknown format.');
    return { ok: false, format: format, errors: errors };
  }

  // THE CLOSED MEMBER SET, and this is the check that catches the defect
  // nothing else does. A subject with an extra member looks fine in a log and
  // is refused by a conforming receiver.
  Object.keys(subject).forEach(function (name) {
    if (name === 'format') {
      return;
    }
    if (row.members.indexOf(name) < 0) {
      errors.push(where + ' carries "' + name + '", which the "' + format +
          '" format does not define. RFC 9493 section 3 gives each format a ' +
          'CLOSED set of members — a receiver that met an unrecognised one ' +
          'could not tell whether it narrows the subject, so it must reject ' +
          'the identifier rather than ignore the member. This format has: ' +
          row.members.join(', ') + '.');
    }
  });

  row.required.forEach(function (name) {
    if (!Object.prototype.hasOwnProperty.call(subject, name)) {
      errors.push(where + ' has no "' + name + '", which the "' + format +
          '" format requires.');
    }
  });

  if (format === 'aliases') {
    validateAliases(subject, where, errors, settings);
  } else {
    row.members.forEach(function (name) {
      if (!Object.prototype.hasOwnProperty.call(subject, name)) {
        return;
      }
      const problem = checkMemberValue(format, name, subject[name]);
      if (problem) {
        errors.push(where + '.' + name + ' ' + problem + '.');
      }
    });
  }

  log.debug('Leaving validateSubject(). ' + errors.length + ' problem(s).');
  return { ok: errors.length === 0, format: format, errors: errors };
}

// The Aliases format's own rules, split out because they are the only ones
// that recurse and the only ones with a NESTING ban to enforce.
function validateAliases(subject, where, errors, options) {
  log.debug('Entering validateAliases().');
  const list = subject.identifiers;
  if (!Array.isArray(list)) {
    errors.push(where + '.identifiers must be an array of Subject ' +
        'Identifiers.');
    log.debug('Leaving validateAliases(). Not an array.');
    return;
  }
  if (!list.length) {
    errors.push(where + '.identifiers is empty. An Aliases identifier that ' +
        'names nobody identifies nobody.');
    log.debug('Leaving validateAliases(). Empty.');
    return;
  }
  list.forEach(function (one, index) {
    const inner = where + '.identifiers[' + index + ']';
    if (one && typeof one === 'object' && one.format === 'aliases') {
      errors.push(inner + ' is itself an "aliases" identifier. RFC 9493 ' +
          'section 3.2.8 forbids the nesting outright. This service refuses ' +
          'it rather than flattening it, because flattening would accept a ' +
          'document a conforming receiver rejects — and the sender would ' +
          'never find out.');
      return;
    }
    const verdict = validateSubject(one, inner, options);
    verdict.errors.forEach(function (message) {
      errors.push(message);
    });
  });
  log.debug('Leaving validateAliases().');
}

// ---------------------------------------------------------------------------
// VALIDATE A `sub_id`, WHICH MAY BE SIMPLE OR COMPLEX.
//
// The two are told apart by `format`: `"complex"` is a complex subject (SSF
// 1.0 section 3.3) and any other value is a simple Subject Identifier. A
// subject with no `format` is neither and is refused as a simple one missing
// its format — which it is, since the final text gives every subject one.
//
// `criticalMembers` is the transmitter's `critical_subject_members`: names a
// RECEIVER must understand. A complex subject that carries none of them is
// refused HERE, at the transmitter, rather than being sent and refused there,
// because a transmitter that publishes a critical member and then omits it is
// producing events nothing will act on.
// ---------------------------------------------------------------------------
function validateSubjectId(subject, options) {
  log.debug('Entering validateSubjectId().');
  const settings = options || {};
  const where = settings.path || 'sub_id';
  if (!subject || typeof subject !== 'object' || Array.isArray(subject)) {
    log.debug('Leaving validateSubjectId(). Not an object.');
    return { ok: false, complex: false, format: '',
      errors: [where + ' must be a JSON object.'] };
  }
  if (!isComplex(subject)) {
    const simple = validateSubject(subject, where, settings);
    if (!Object.prototype.hasOwnProperty.call(subject, 'format') &&
        Object.keys(subject).some(function (name) {
          return COMPLEX_MEMBER_NAMES.indexOf(name) >= 0;
        })) {
      simple.errors.push(where + ' looks like a complex subject without its ' +
          'format. SSF 1.0 final (section 3.3) gives a complex subject ' +
          '"format": "complex"; the drafts before it left the member out, ' +
          'and that shape is not accepted here.');
    }
    log.debug('Leaving validateSubjectId(). Simple.');
    return { ok: simple.ok && simple.errors.length === 0, complex: false,
      format: simple.format, errors: simple.errors };
  }

  const errors = [];
  const names = Object.keys(subject).filter(function (name) {
    return name !== 'format';
  });
  if (!names.length) {
    errors.push(where + ' is a complex subject with no members. SSF 1.0 ' +
        'section 3.3 requires one or more Simple Subject Members.');
  }
  names.forEach(function (name) {
    // ADDITIONAL NAMES ARE ALLOWED (section 3.3); a name that could not be one
    // is not. Each member is still a Subject Identifier and is read as one.
    if (COMPLEX_MEMBER_NAMES.indexOf(name) < 0 && !MEMBER_NAME.test(name)) {
      errors.push(where + ' carries a member named ' + JSON.stringify(name) +
          ', which is not a name a receiver could refer to. The seven SSF ' +
          'defines are ' + COMPLEX_MEMBER_NAMES.join(', ') + ', and an ' +
          'additional one is a letter followed by letters, digits, "_", "." ' +
          'or "-".');
      return;
    }
    const value = subject[name];
    if (isComplex(value)) {
      errors.push(where + '.' + name + ' is itself a complex subject. Each ' +
          'member of a complex subject is a SIMPLE Subject Identifier (SSF ' +
          '1.0 section 3.3).');
      return;
    }
    const verdict = validateSubject(value, where + '.' + name, settings);
    verdict.errors.forEach(function (message) {
      errors.push(message);
    });
  });

  const critical = settings.criticalMembers || [];
  critical.forEach(function (name) {
    if (!Object.prototype.hasOwnProperty.call(subject, name)) {
      errors.push(where + ' has no "' + name + '" member, and this ' +
          'transmitter publishes "' + name + '" in ' +
          'critical_subject_members — which is a promise that every complex ' +
          'subject it sends carries one. A receiver is entitled to refuse ' +
          'an event without it.');
    }
  });

  log.debug('Leaving validateSubjectId(). Complex, ' + errors.length +
            ' problem(s).');
  return { ok: errors.length === 0, complex: true, format: COMPLEX_FORMAT,
    errors: errors };
}

// A complex subject from its members, with the format member the final text
// requires. Every place this service BUILDS one goes through here, so none of
// them can forget it the way all four did until 2026-09-22.
function complexSubject(members) {
  log.debug('Entering complexSubject().');
  const out = { format: COMPLEX_FORMAT };
  Object.keys(members || {}).forEach(function (name) {
    if (members[name]) {
      out[name] = members[name];
    }
  });
  log.debug('Leaving complexSubject(). ' + (Object.keys(out).length - 1) +
            ' member(s).');
  return out;
}

// The members of a complex subject, without its format — what a matcher walks.
function complexMembers(subject) {
  log.debug('Entering complexMembers().');
  const names = isComplex(subject) ? Object.keys(subject).filter(
    function (name) {
      return name !== 'format';
    }) : [];
  log.debug('Leaving complexMembers(). ' + names.length + '.');
  return names;
}

// ---------------------------------------------------------------------------
// A STABLE STRING FOR ONE SUBJECT, so that "is this the same subject" can be
// answered by a Map lookup.
//
// It is NOT a canonical serialization of the JSON and must not be read as one:
// the members are sorted and joined with characters that cannot appear in a
// member name, which is enough to key a store and nothing more. An `aliases`
// identifier keys on its SORTED members, so the same two identifiers in the
// other order are one subject — which is what the format means.
// ---------------------------------------------------------------------------
function subjectKey(subject) {
  log.debug('Entering subjectKey().');
  if (!subject || typeof subject !== 'object') {
    log.debug('Leaving subjectKey(). Not an object.');
    return '';
  }
  if (!isComplex(subject)) {
    if (subject.format === 'aliases' && Array.isArray(subject.identifiers)) {
      const parts = subject.identifiers.map(subjectKey).sort();
      log.debug('Leaving subjectKey(). Aliases.');
      return 'aliases[' + parts.join('|') + ']';
    }
    const row = FORMAT_BY_NAME[subject.format];
    const members = (row ? row.members : Object.keys(subject).filter(
      function (name) {
        return name !== 'format';
      })).slice().sort();
    const body = members.map(function (name) {
      return name + '=' + String(subject[name] == null ? '' : subject[name]);
    }).join(';');
    log.debug('Leaving subjectKey(). Simple.');
    return subject.format + '{' + body + '}';
  }
  const complex = complexMembers(subject).sort().map(function (name) {
    return name + '=' + subjectKey(subject[name]);
  }).join(';');
  log.debug('Leaving subjectKey(). Complex.');
  return 'complex{' + complex + '}';
}

// A one-line rendering for a page, a log line or an audit entry. It is for
// PEOPLE and nothing reads it back.
function describeSubject(subject) {
  log.debug('Entering describeSubject().');
  if (!subject || typeof subject !== 'object') {
    log.debug('Leaving describeSubject(). Nothing.');
    return '(no subject)';
  }
  if (isComplex(subject)) {
    const parts = complexMembers(subject).map(function (name) {
      return name + ': ' + describeSubject(subject[name]);
    });
    log.debug('Leaving describeSubject(). Complex.');
    return parts.join(', ') || '(empty complex subject)';
  }
  if (subject.format === 'aliases') {
    const inner = Array.isArray(subject.identifiers)
      ? subject.identifiers.map(describeSubject).join(' = ')
      : '(no identifiers)';
    log.debug('Leaving describeSubject(). Aliases.');
    return inner;
  }
  const row = FORMAT_BY_NAME[subject.format];
  const values = (row ? row.members : []).map(function (name) {
    const value = subject[name];
    return Array.isArray(value) ? value.join(', ')
      : String(value == null ? '' : value);
  }).filter(Boolean);
  log.debug('Leaving describeSubject(). Simple.');
  return values.join(' / ') || subject.format;
}

// The subject this service uses for a person it knows by name, in whichever
// format a stream asked for. `format` comes off the stream configuration's own
// `format` member (SSF 1.0's "default subjects" arrangement), so a receiver
// that asked for `opaque` never sees an email address.
//
// ---------------------------------------------------------------------------
// **`facts` IS WHAT THE CALLER KNOWS ABOUT THE PERSON, AND IT WINS
// (2026-09-12).** `{ mail, phone, did }`, each optional. This function used to
// know only the username, so an `email` subject was `<name>@example.com` and a
// DID was `did:example:<name>` WHEREVER the person had a real address on their
// entry — `risc.js` holds `mail` on its row and was not passing it. A Security
// Event Token sent to a real receiver saying that `alice@example.com`'s account
// was disabled is about somebody at a domain nobody here owns.
//
// **AND WHERE THERE IS NO REAL VALUE, `mode.inventsClaimValues()` DECIDES.**
// Development invents, exactly as before, so a client has something to parse.
// Product does not: a format with no real value falls back to the
// issuer/subject pair — which is composed from this service's own issuer and
// the person's own name, and invents nothing — the way `phone_number` always
// has. An invented fact a receiver acts on is worse than a different format it
// can handle. A username that is itself an address is a real value in both.
// ---------------------------------------------------------------------------
// The formats a PERSON can be named in — every one but SSF 1.0 section 3.5's
// three, which are about a token, an assertion and an address.
const PERSON_FORMATS = ['account', 'email', 'iss_sub', 'opaque',
                        'phone_number', 'did', 'uri', 'aliases'];

function realOrInventedMail(name, facts) {
  log.debug("Entering realOrInventedMail().");
  const mail = String((facts || {}).mail || '').trim();
  if (mail) {
    log.debug("Leaving realOrInventedMail().");
    return mail;
  }
  if (name.indexOf('@') > 0) {
    log.debug("Leaving realOrInventedMail().");
    return name;
  }
  log.debug("Leaving realOrInventedMail().");
  return mode.inventsClaimValues() ? realms.inventedMailOf(name) : '';
}

function subjectForUser(userid, format, issuer, facts) {
  log.debug('Entering subjectForUser(). ' + format);
  const name = String(userid || '');
  const known = facts || {};
  // A PERSON's formats. jwt_id, saml_assertion_id and ip-addresses name a
  // token, an assertion and a network location, never somebody by name, so a
  // stream whose default format is one of them gets the issuer/subject pair.
  const chosen = FORMAT_BY_NAME[format] && PERSON_FORMATS.indexOf(format) >= 0
    ? format : 'iss_sub';
  // THE `sub` EVERY TOKEN THIS ISSUER HANDED OUT CARRIES (2026-09-14): the
  // person's `urn:uuid:<entryUUID>`. An iss_sub is RFC 9493's
  // "subject as the issuer knows it", and a receiver joins it to the tokens it
  // already holds — so a bare name here named a subject no token had. A caller
  // that knows the subject (an event about an entry already deleted) passes it
  // as `facts.subject`; somebody the directory does not hold keeps the name.
  const issuerSubject = String(known.subject || '') ||
                        subjectForName(name) || name;
  const fallback = { format: 'iss_sub', iss: String(issuer || ''),
    sub: issuerSubject };
  if (chosen === 'email') {
    const mail = realOrInventedMail(name, known);
    log.debug('Leaving subjectForUser(). email' + (mail ? '.' : ': none, ' +
              'and none is invented here; iss_sub.'));
    return mail ? { format: 'email', email: mail } : fallback;
  }
  if (chosen === 'account') {
    const mail = realOrInventedMail(name, known);
    log.debug('Leaving subjectForUser(). account' + (mail ? '.' : ': none; ' +
              'iss_sub.'));
    return mail ? { format: 'account', uri: 'acct:' + mail } : fallback;
  }
  if (chosen === 'opaque') {
    log.debug('Leaving subjectForUser(). opaque.');
    return { format: 'opaque', id: name };
  }
  if (chosen === 'uri') {
    log.debug('Leaving subjectForUser(). uri.');
    return { format: 'uri', uri: String(issuer || '') + '/users/' + name };
  }
  if (chosen === 'did') {
    const did = String(known.did || '').trim();
    if (did) {
      log.debug('Leaving subjectForUser(). did, a real one.');
      return { format: 'did', url: did };
    }
    if (mode.inventsClaimValues()) {
      log.debug('Leaving subjectForUser(). did, invented.');
      return { format: 'did', url: 'did:example:' + name };
    }
    log.debug('Leaving subjectForUser(). No DID; iss_sub.');
    return fallback;
  }
  if (chosen === 'phone_number') {
    // A number is used where the caller HOLDS one — `risc.js` keeps
    // `telephoneNumber` / `mobile` on its row — and never invented, in either
    // mode: a made-up phone number is a fact about somebody else's phone.
    const phone = String(known.phone || '').trim();
    if (phone) {
      log.debug('Leaving subjectForUser(). phone_number.');
      return { format: 'phone_number', phone_number: phone };
    }
    // A stream that asked for this format gets the issuer/subject pair
    // instead; the subject's own `format` member says which was sent.
    log.debug('Leaving subjectForUser(). No number; iss_sub.');
    return fallback;
  }
  if (chosen === 'aliases') {
    const mail = realOrInventedMail(name, known);
    /** @type {any[]} */
    const identifiers = [
      { format: 'iss_sub', iss: String(issuer || ''), sub: issuerSubject }
    ];
    if (mail) {
      identifiers.push({ format: 'email', email: mail });
    }
    log.debug('Leaving subjectForUser(). aliases, ' + identifiers.length + '.');
    return { format: 'aliases', identifiers: identifiers };
  }
  log.debug('Leaving subjectForUser(). iss_sub.');
  return fallback;
}

module.exports = {
  FORMATS: FORMATS,
  FORMAT_NAMES: FORMAT_NAMES,
  PERSON_FORMATS: PERSON_FORMATS,
  COMPLEX_FORMAT: COMPLEX_FORMAT,
  COMPLEX_MEMBERS: COMPLEX_MEMBERS,
  COMPLEX_MEMBER_NAMES: COMPLEX_MEMBER_NAMES,
  MEMBER_NAME: MEMBER_NAME,
  isComplex: isComplex,
  complexSubject: complexSubject,
  complexMembers: complexMembers,
  validateSubject: validateSubject,
  validateSubjectId: validateSubjectId,
  subjectKey: subjectKey,
  describeSubject: describeSubject,
  subjectForUser: subjectForUser
};
