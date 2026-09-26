'use strict';
//
// File: identity_assurance.ts
//
// ===========================================================================
// OPENID CONNECT FOR IDENTITY ASSURANCE 1.0 — `verified_claims` (#127,
// 2026-09-23).
//
// A person's IDENTITY VERIFICATIONS, kept on their directory entry, and the
// `verified_claims` element OIDC Core section 5.5's claims request asks for
// them by. Three things, in one file because they are one model:
//
//   * THE RECORD. One JSON value on the entry (`stsIdaVerification`, withheld
//     from every LDAP read like a credential — its evidence carries document
//     numbers) holding up to MAX_RECORDS verifications, newest first. Each is
//     the specification's `verification` element — `trust_framework`,
//     `assurance_level`, `time`, `verification_process`, `evidence` — and the
//     CLAIMS IT VERIFIED, as the values they had when it was recorded.
//
//   * WHERE A RECORD COMES FROM. An administrator records one (Directory →
//     Users, a person's page, and `/admin-api`), which is how an operator's
//     real-world check — a passport looked at, a bank account confirmed, a
//     colleague vouching — becomes something this service can say. And two
//     sign-ins record one of their own, where
//     `oauth2.idaAutomaticVerifications` is on: a wallet presentation of a
//     credential this realm issued (`electronic_record`, checked `vcrypt`)
//     and a client certificate this realm's authority issued
//     (`electronic_signature`). Each automatic kind REPLACES its previous
//     record rather than accumulating one per sign-in.
//
//   * THE ANSWER. `parseRequest()` checks a `verified_claims` request (section
//     6: `verification` and `claims` both present, `claims` not empty, every
//     `purpose` 3 to 300 characters, or invalid_request); `respond()` picks,
//     per requested element, the newest record whose verification satisfies
//     it — `value`/`values` on any verification member, `max_age` on `time`,
//     and every requested `evidence` element matched by one of the record's —
//     and answers ONLY the members asked for, with the claims that are both
//     requested and verified. An element no record satisfies is OMITTED, never
//     answered with a weaker one: section 6's "the OP MUST NOT return
//     verified_claims that do not fulfil the requirements".
//
// **A VERIFIED VALUE IS RELEASED ONLY WHILE THE ENTRY STILL HOLDS IT.** The
// record keeps what was verified; the entry holds what is current. Where the
// two differ — a name changed after the passport was checked — the claim is
// left out of `verified_claims` and the log says why, because releasing the
// old value would be asserting a verification of something the entry no
// longer says, and releasing the new one would be asserting a verification
// nobody made. The ordinary claim still carries the new value.
//
// **`value` AND `values` ARE ENFORCED ON EVERYTHING INSIDE
// `verified_claims`** (rcbj, #127: "as IDA requires"). On the verification
// they are how a relying party says "only under eIDAS" or "only a document
// check", and answering such a request with another framework is the
// failure section 6 names. On the CLAIMS inside `verified_claims` they were
// reported and not enforced, as on every ordinary claim, until #187: section
// 5.7.4 has the OP omit a claim whose data does not fulfil `value`, `values`
// or `max_age`, and the conformance suite's
// ekyc-server-one-claim-with-random-value-omitted found one released. An
// element left with no claim is omitted whole. ORDINARY claims keep the
// OIDC Core rule (`oauth2.ts`'s `requestedClaimsOf()` header argues it).
//
// **DEVELOPMENT INVENTS ONE, UNDER A FRAMEWORK THAT SAYS SO.** Where
// `mode.inventsClaimValues()` and the person has no record, the answer is a
// verification under the trust framework `urn:sts:demo` covering whatever was
// asked for — so a client can exercise its parser against any account — and
// `/admin/mode` lists it beside the invented persona. It is never published in
// product's discovery, never recordable, and a request that names any real
// framework never matches it.
//
// Aggregated and distributed verified claims (section 6's other two claim
// types) are #147's; this file answers the `normal` type only.
//
// A LIBRARY (rule 3): it registers nothing. Its store is the directory,
// reached through `credentials.ts`'s hook pair, and the values it verifies are
// read through `claim_attributes.ts`'s catalogue, as every claims request's
// are.
// ===========================================================================

import nodeCrypto = require('crypto');
import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import config = require('./config');
import mode = require('./mode');
import credentials = require('./credentials');
import claimAttributes = require('./claim_attributes');
import errorCodes = require('./error_codes');

// A loose JSON-shaped value: a request, a record, an answer.
type Json = any;

// Section 5.1's four evidence types, all four answered (rcbj, #127).
const EVIDENCE_TYPES = Object.freeze(['document', 'electronic_record', 'vouch',
  'electronic_signature']);

// The framework development's invented verification is recorded under. A URN
// in this service's own namespace so that nothing mistakes it for a real one.
const DEMO_FRAMEWORK = 'urn:sts:demo';

// The Identity Assurance schema's predefined document types (OpenID Identity
// Assurance Schema Definition 1.0, "Predefined Values"), the subset a person's
// identity is established by. What this service records it advertises in
// `documents_supported`, so a type outside the list is refused rather than
// recorded and left unadvertised.
const DOCUMENT_TYPES = Object.freeze(['idcard', 'passport', 'driving_permit',
  'residence_permit', 'visa', 'birth_certificate', 'bank_statement',
  'utility_statement']);

// The schema's check methods (`check_details[].check_method`).
const CHECK_METHODS = Object.freeze(['vpip', 'vpiruv', 'vri', 'vdig',
  'vcrypt', 'data', 'auth', 'token', 'kbv', 'pvp', 'pvr', 'bvp', 'bvr']);

// The schema's electronic record types, and this service's own for a wallet
// presentation of a credential it issued — the schema's list has no entry for
// a verifiable credential, and it says a trust framework may define more.
const WALLET_RECORD_TYPE = 'urn:sts:verifiable-credential';
const ELECTRONIC_RECORD_TYPES = Object.freeze(['bank_account',
  'utility_account', 'mortgage_account', 'loan_account', 'tax',
  'social_security', 'prison_record', WALLET_RECORD_TYPE]);

// A vouch's two attestation types.
const ATTESTATION_TYPES = Object.freeze(['written_attestation',
  'digital_attestation']);

// What a client certificate sign-in records as its `signature_type`.
const CERTIFICATE_SIGNATURE_TYPE = 'urn:sts:x509-client-certificate';

// The claims a verification may cover: the identity claims of OIDC Core
// section 5.1 and the Identity Assurance Claims Registration's section 4.1
// (#128). Not `picture` or `website`: nobody verifies a web page against a
// passport. Published as `claims_in_verified_claims_supported`.
const VERIFIABLE_CLAIMS = Object.freeze(['name', 'given_name', 'family_name',
  'middle_name', 'birthdate', 'gender', 'address', 'email', 'phone_number',
  'place_of_birth', 'nationalities', 'birth_family_name', 'birth_given_name',
  'birth_middle_name', 'salutation', 'title', 'msisdn', 'also_known_as']);

// An individual request's own members (OIDC Core 5.5.1, and section 6's
// `purpose` and `max_age`). Any other member of a request node names a member
// of the thing being asked for.
const LEAF_KEYS = Object.freeze(['essential', 'purpose', 'value', 'values',
  'max_age']);

// How many verifications one entry keeps, and how large one may be. The
// record lives in one attribute value, and the whole value is rewritten on
// every change.
const MAX_RECORDS = 16;
const MAX_RECORD_BYTES = 8192;

// How deep and how wide a `verified_claims` request may be. It rides inside
// the access token with the rest of the claims request.
const MAX_REQUEST_DEPTH = 8;
const MAX_REQUEST_NODES = 256;

// Section 6's bounds on `purpose`.
const PURPOSE_MIN = 3;
const PURPOSE_MAX = 300;


interface IdentityAssuranceDeps {
  log: typeof helpers.log;
  config: typeof config;
  mode: typeof mode;
  credentials: typeof credentials;
  claimAttributes: typeof claimAttributes;
  errorCodes: typeof errorCodes;
  now: () => number;
}

class IdentityAssurance {
  static readonly EVIDENCE_TYPES = EVIDENCE_TYPES;
  static readonly DEMO_FRAMEWORK = DEMO_FRAMEWORK;
  static readonly VERIFIABLE_CLAIMS = VERIFIABLE_CLAIMS;

  constructor(private readonly deps: IdentityAssuranceDeps) {
    deps.log.debug("Entering IdentityAssurance.constructor().");
    deps.log.debug("Leaving IdentityAssurance.constructor().");
  }

  // What the composition root passes, from the real modules.
  static defaultDeps(): IdentityAssuranceDeps {
    helpers.log.debug("Entering IdentityAssurance.defaultDeps().");
    helpers.log.debug("Leaving IdentityAssurance.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      mode: mode,
      credentials: credentials,
      claimAttributes: claimAttributes,
      errorCodes: errorCodes,
      now: Date.now
    };
  }

  // -------------------------------------------------------------------------
  // SMALL PREDICATES, static because they read nothing but their argument.
  // -------------------------------------------------------------------------

  static isObject(value: Json): boolean {
    helpers.log.debug("Entering IdentityAssurance.isObject().");
    helpers.log.debug("Leaving IdentityAssurance.isObject().");
    return !!value && typeof value === 'object' && !Array.isArray(value);
  }

  // A request node that constrains a value rather than naming members: null,
  // or an object holding only section 5.5.1's and section 6's own members.
  static isLeafSpec(node: Json): boolean {
    helpers.log.debug("Entering IdentityAssurance.isLeafSpec().");
    if (node === null || node === undefined) {
      helpers.log.debug("Leaving IdentityAssurance.isLeafSpec(). Null.");
      return true;
    }
    if (!IdentityAssurance.isObject(node)) {
      helpers.log.debug("Leaving IdentityAssurance.isLeafSpec(). Not an " +
                        "object.");
      return false;
    }
    const leaf = Object.keys(node).every(function (key) {
      return LEAF_KEYS.indexOf(key) >= 0;
    });
    helpers.log.debug("Leaving IdentityAssurance.isLeafSpec(). " + leaf);
    return leaf;
  }

  // The members of a request node that name members of the answer.
  static memberKeys(node: Json): string[] {
    helpers.log.debug("Entering IdentityAssurance.memberKeys().");
    helpers.log.debug("Leaving IdentityAssurance.memberKeys().");
    return Object.keys(node || {}).filter(function (key) {
      return LEAF_KEYS.indexOf(key) < 0;
    });
  }

  // ISO 8601 as the specification writes `time`: a date-time with a zone.
  static isDateTime(value: Json): boolean {
    helpers.log.debug("Entering IdentityAssurance.isDateTime().");
    const ok = typeof value === 'string' &&
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$/
        .test(value) &&
      !isNaN(Date.parse(value));
    helpers.log.debug("Leaving IdentityAssurance.isDateTime(). " + ok);
    return ok;
  }

  // A full-date, as `date_of_issuance` and `date_of_expiry` are written.
  static isDate(value: Json): boolean {
    helpers.log.debug("Entering IdentityAssurance.isDate().");
    const ok = typeof value === 'string' &&
      /^\d{4}-\d{2}-\d{2}$/.test(value) &&
      !isNaN(Date.parse(value + 'T00:00:00Z'));
    helpers.log.debug("Leaving IdentityAssurance.isDate(). " + ok);
    return ok;
  }

  // One JSON serialisation with its object keys sorted, so that two values
  // read from different places compare by what they say.
  static canonical(value: Json): string {
    helpers.log.debug("Entering IdentityAssurance.canonical().");
    const sort = function (v: Json): Json {
      if (Array.isArray(v)) {
        return v.map(sort);
      }
      if (IdentityAssurance.isObject(v)) {
        const out: Json = {};
        Object.keys(v).sort().forEach(function (key) {
          out[key] = sort(v[key]);
        });
        return out;
      }
      return v;
    };
    helpers.log.debug("Leaving IdentityAssurance.canonical().");
    return JSON.stringify(sort(value));
  }

  // -------------------------------------------------------------------------
  // SETTINGS
  // -------------------------------------------------------------------------

  // The frameworks an administrator may record under, and discovery lists.
  trustFrameworks(): string[] {
    const { log, config } = this.deps;
    log.debug("Entering IdentityAssurance.trustFrameworks().");
    const raw = config.value('oauth2.idaTrustFrameworks');
    const list = (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .map(function (one: Json) {
        return String(one).trim();
      })
      .filter(function (one: string, i: number, all: string[]) {
        return one && one !== DEMO_FRAMEWORK && all.indexOf(one) === i;
      });
    log.debug("Leaving IdentityAssurance.trustFrameworks(). " +
              list.length + ".");
    return list;
  }

  automaticEnabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering IdentityAssurance.automaticEnabled().");
    const on = config.value('oauth2.idaAutomaticVerifications') === true;
    log.debug("Leaving IdentityAssurance.automaticEnabled(). " + on);
    return on;
  }

  // -------------------------------------------------------------------------
  // WHAT DISCOVERY SAYS (section 7). Read per request, so the frameworks
  // setting and the mode are current.
  // -------------------------------------------------------------------------
  discoveryMetadata(): Json {
    const { log, mode } = this.deps;
    log.debug("Entering IdentityAssurance.discoveryMetadata().");
    const frameworks = this.trustFrameworks();
    if (mode.inventsClaimValues()) {
      frameworks.push(DEMO_FRAMEWORK);
    }
    const out = {
      verified_claims_supported: true,
      trust_frameworks_supported: frameworks,
      evidence_supported: EVIDENCE_TYPES.slice(0),
      documents_supported: DOCUMENT_TYPES.slice(0),
      documents_check_methods_supported: CHECK_METHODS.slice(0),
      electronic_records_supported: ELECTRONIC_RECORD_TYPES.slice(0),
      claims_in_verified_claims_supported: VERIFIABLE_CLAIMS.slice(0),
      // No attachments are ever stored or released.
      attachments_supported: []
    };
    log.debug("Leaving IdentityAssurance.discoveryMetadata().");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE RECORD
  // -------------------------------------------------------------------------

  // Every verification recorded for a person, newest first. A value that does
  // not parse is logged and read as none rather than thrown: a claims request
  // must not fail because an entry holds something damaged, and the console
  // shows the empty list, which is where somebody will notice.
  list(username: Json): Json[] {
    const { log, credentials, errorCodes } = this.deps;
    log.debug("Entering IdentityAssurance.list(). user=" + username);
    const raw = credentials.readIdaVerifications(String(username || ''));
    if (!raw) {
      log.debug("Leaving IdentityAssurance.list(). None.");
      return [];
    }
    let parsed: Json = null;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      log.error(errorCodes.tag('STS-OAUTH-0623') + 'identity-assurance: ' +
                'the verifications recorded for ' + username +
                ' are not JSON (' + ((e && e.message) || e) +
                '); read as none.');
      log.debug("Leaving IdentityAssurance.list(). Damaged.");
      return [];
    }
    if (!Array.isArray(parsed)) {
      log.error(errorCodes.tag('STS-OAUTH-0623') + 'identity-assurance: ' +
                'the verifications recorded for ' + username + ' are not a ' +
                'list; read as none.');
      log.debug("Leaving IdentityAssurance.list(). Damaged.");
      return [];
    }
    const records = parsed.filter(function (one: Json) {
      return IdentityAssurance.isObject(one) &&
             IdentityAssurance.isObject(one.verification) &&
             IdentityAssurance.isObject(one.claims);
    });
    log.debug("Leaving IdentityAssurance.list(). " + records.length + ".");
    return records;
  }

  private store(username: string, records: Json[]): boolean {
    const { log, credentials } = this.deps;
    log.debug("Entering IdentityAssurance.store().");
    const written = credentials.writeIdaVerifications(username,
      records.length ? JSON.stringify(records) : '');
    log.debug("Leaving IdentityAssurance.store(). " + written);
    return written;
  }

  // What the entry holds NOW for each of `names`, through the catalogue every
  // claims request reads. Only a claim the catalogue resolved is present, and
  // — unless `invented` — only one whose every value came from the DIRECTORY:
  // development fills an empty attribute with a persona value, and nobody
  // verified that. Only development's own demo verification takes those.
  currentValues(username: string, names: string[], invented?: boolean)
    : Json {
    const { log, claimAttributes } = this.deps;
    log.debug("Entering IdentityAssurance.currentValues().");
    const built = claimAttributes.requestedClaimsFor(username, names);
    const madeUp = new Set<string>();
    built.report.forEach(function (row: Json) {
      if (row.source !== 'directory') {
        madeUp.add(String(row.requested));
      }
    });
    const out: Json = {};
    names.forEach(function (name) {
      if (built.claims[name] !== undefined &&
          (invented || !madeUp.has(name))) {
        out[name] = built.claims[name];
      }
    });
    log.debug("Leaving IdentityAssurance.currentValues(). " +
              Object.keys(out).length + " of " + names.length + ".");
    return { values: out, entryFound: built.entryFound };
  }

  // -------------------------------------------------------------------------
  // CHECKING WHAT AN ADMINISTRATOR RECORDS
  //
  // The verification element is checked member by member, and what is kept is
  // what was checked: an unknown member of `verification` is dropped, so the
  // record can only ever say what discovery says this service supports.
  // Returns { verification } or { error }.
  // -------------------------------------------------------------------------
  checkVerification(raw: Json, opts: Json): Json {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering IdentityAssurance.checkVerification().");
    const refuse = function (why: string): Json {
      log.debug("Leaving IdentityAssurance.checkVerification(). " + why);
      return { error: why };
    };
    if (!IdentityAssurance.isObject(raw)) {
      return refuse('verification must be a JSON object.');
    }
    const framework = String(raw.trust_framework || '').trim();
    const allowed = (opts && opts.frameworks) || self.trustFrameworks();
    if (!framework) {
      return refuse('verification.trust_framework is required (Identity ' +
                    'Assurance section 5.1).');
    }
    if (allowed.indexOf(framework) < 0) {
      return refuse('trust framework "' + framework + '" is not one this ' +
                    'service is configured for (oauth2.idaTrustFrameworks: ' +
                    (allowed.join(', ') || 'none') + ').');
    }
    const out: Json = { trust_framework: framework };
    const shortString = function (name: string, max: number): Json {
      const value = raw[name];
      if (value === undefined || value === null || value === '') {
        return null;
      }
      if (typeof value !== 'string' || value.length > max) {
        return 'verification.' + name + ' must be a string of at most ' +
               max + ' characters.';
      }
      out[name] = value;
      return null;
    };
    const tooLong = shortString('assurance_level', 128) ||
                    shortString('verification_process', 256);
    if (tooLong) {
      return refuse(tooLong);
    }
    if (raw.assurance_process !== undefined && raw.assurance_process !== null) {
      if (!IdentityAssurance.isObject(raw.assurance_process)) {
        return refuse('verification.assurance_process must be a JSON ' +
                      'object.');
      }
      out.assurance_process = raw.assurance_process;
    }
    if (raw.time !== undefined && raw.time !== null && raw.time !== '') {
      if (!IdentityAssurance.isDateTime(raw.time)) {
        return refuse('verification.time must be an ISO 8601 date-time ' +
                      'with a time zone, such as 2026-09-23T10:00:00Z.');
      }
      out.time = raw.time;
    } else {
      out.time = new Date(self.deps.now()).toISOString()
        .replace(/\.\d+Z$/, 'Z');
    }
    if (raw.evidence !== undefined && raw.evidence !== null) {
      if (!Array.isArray(raw.evidence)) {
        return refuse('verification.evidence must be an array.');
      }
      const evidence: Json[] = [];
      for (let i = 0; i < raw.evidence.length; i++) {
        const one = self.checkEvidence(raw.evidence[i], i);
        if (one.error) {
          return refuse(one.error);
        }
        evidence.push(one.evidence);
      }
      if (evidence.length) {
        out.evidence = evidence;
      }
    }
    log.debug("Leaving IdentityAssurance.checkVerification().");
    return { verification: out };
  }

  // One evidence element, by its type (section 5.1.1). What each type
  // REQUIRES is the specification's; the vocabularies are the ones discovery
  // advertises.
  checkEvidence(raw: Json, index: number): Json {
    const { log } = this.deps;
    log.debug("Entering IdentityAssurance.checkEvidence().");
    const at = 'verification.evidence[' + index + ']';
    const refuse = function (why: string): Json {
      log.debug("Leaving IdentityAssurance.checkEvidence(). " + why);
      return { error: at + ' ' + why };
    };
    if (!IdentityAssurance.isObject(raw)) {
      return refuse('must be a JSON object.');
    }
    if (EVIDENCE_TYPES.indexOf(raw.type) < 0) {
      return refuse('has type "' + raw.type + '"; one of ' +
                    EVIDENCE_TYPES.join(', ') + ' is required.');
    }
    const out: Json = { type: raw.type };
    if (raw.time !== undefined && raw.time !== null && raw.time !== '') {
      if (!IdentityAssurance.isDateTime(raw.time)) {
        return refuse('time must be an ISO 8601 date-time with a zone.');
      }
      out.time = raw.time;
    }
    if (raw.check_details !== undefined && raw.check_details !== null) {
      if (!Array.isArray(raw.check_details)) {
        return refuse('check_details must be an array.');
      }
      const checks: Json[] = [];
      for (let i = 0; i < raw.check_details.length; i++) {
        const check = raw.check_details[i];
        if (!IdentityAssurance.isObject(check) ||
            CHECK_METHODS.indexOf(check.check_method) < 0) {
          return refuse('check_details[' + i + '].check_method must be one ' +
                        'of ' + CHECK_METHODS.join(', ') + '.');
        }
        const kept: Json = { check_method: check.check_method };
        ['organization', 'txn'].forEach(function (name) {
          if (typeof check[name] === 'string' && check[name]) {
            kept[name] = check[name].slice(0, 256);
          }
        });
        if (IdentityAssurance.isDateTime(check.time)) {
          kept.time = check.time;
        }
        checks.push(kept);
      }
      if (checks.length) {
        out.check_details = checks;
      }
    }
    const details = function (name: string, types: readonly string[],
                               required: boolean): Json {
      const value = raw[name];
      if (!IdentityAssurance.isObject(value)) {
        return required ? name + ' is required, as a JSON object.' : null;
      }
      if (types.indexOf(value.type) < 0) {
        return name + '.type must be one of ' + types.join(', ') + '.';
      }
      const dates = ['date_of_issuance', 'date_of_expiry'];
      for (let i = 0; i < dates.length; i++) {
        if (value[dates[i]] !== undefined &&
            !IdentityAssurance.isDate(value[dates[i]])) {
          return name + '.' + dates[i] + ' must be a date, YYYY-MM-DD.';
        }
      }
      if (value.created_at !== undefined &&
          !IdentityAssurance.isDateTime(value.created_at)) {
        return name + '.created_at must be an ISO 8601 date-time.';
      }
      out[name] = value;
      return null;
    };
    let problem: Json = null;
    if (raw.type === 'document') {
      problem = details('document_details', DOCUMENT_TYPES, true);
    } else if (raw.type === 'electronic_record') {
      problem = details('record', ELECTRONIC_RECORD_TYPES, true);
    } else if (raw.type === 'vouch') {
      problem = details('attestation', ATTESTATION_TYPES, true);
    } else {
      // electronic_signature: three REQUIRED strings and a date-time.
      const names = ['signature_type', 'issuer', 'serial_number'];
      for (let i = 0; i < names.length; i++) {
        const value = raw[names[i]];
        if (typeof value !== 'string' || !value || value.length > 512) {
          problem = names[i] + ' is required, as a string of at most 512 ' +
                    'characters.';
          break;
        }
        out[names[i]] = value;
      }
      if (!problem && raw.created_at !== undefined) {
        if (!IdentityAssurance.isDateTime(raw.created_at)) {
          problem = 'created_at must be an ISO 8601 date-time.';
        } else {
          out.created_at = raw.created_at;
        }
      }
    }
    if (problem) {
      return refuse(problem);
    }
    log.debug("Leaving IdentityAssurance.checkEvidence().");
    return { evidence: out };
  }

  // -------------------------------------------------------------------------
  // RECORDING
  //
  // `record()` is the administrator's door: the verification checked, the
  // claims named from VERIFIABLE_CLAIMS, and each one's value taken from the
  // entry as it is NOW — the value that was verified. A claim the entry holds
  // no value for is refused, because a verification of nothing cannot be
  // released and would only look like one on the console.
  // Returns { ok, record } or { ok: false, error }.
  // -------------------------------------------------------------------------
  record(username: Json, input: Json, by: Json): Json {
    const { log } = this.deps;
    log.debug("Entering IdentityAssurance.record(). user=" + username);
    const name = String(username || '').trim();
    if (!name) {
      log.debug("Leaving IdentityAssurance.record(). No person.");
      return { ok: false, error: 'a person is required.' };
    }
    if (typeof (input && input.verification) === 'string') {
      log.debug("Leaving IdentityAssurance.record(). Unreadable.");
      return { ok: false, error: input.verification };
    }
    const checked = this.checkVerification(input && input.verification, null);
    if (checked.error) {
      log.debug("Leaving IdentityAssurance.record(). " + checked.error);
      return { ok: false, error: checked.error };
    }
    const names = (Array.isArray(input && input.claims) ? input.claims : [])
      .map(function (one: Json) {
        return String(one).trim();
      })
      .filter(function (one: string, i: number, all: string[]) {
        return one && all.indexOf(one) === i;
      });
    if (!names.length) {
      log.debug("Leaving IdentityAssurance.record(). No claims.");
      return { ok: false, error: 'name at least one claim the verification ' +
                                 'covered.' };
    }
    const outside = names.filter(function (one: string) {
      return VERIFIABLE_CLAIMS.indexOf(one) < 0;
    });
    if (outside.length) {
      log.debug("Leaving IdentityAssurance.record(). Unverifiable claims.");
      return { ok: false, error: 'not a claim a verification covers here: ' +
               outside.join(', ') + '. The claims are ' +
               VERIFIABLE_CLAIMS.join(', ') + '.' };
    }
    const current = this.currentValues(name, names);
    if (!current.entryFound) {
      log.debug("Leaving IdentityAssurance.record(). No entry.");
      return { ok: false, error: 'there is no directory entry for "' + name +
                                 '" in this realm.' };
    }
    const missing = names.filter(function (one: string) {
      return current.values[one] === undefined;
    });
    if (missing.length) {
      log.debug("Leaving IdentityAssurance.record(). Values missing.");
      return { ok: false, error: 'the entry holds no value for ' +
               missing.join(', ') + ', so there is nothing to have ' +
               'verified.' };
    }
    const stored = this.add(name, {
      source: 'admin', by: String(by || ''),
      verification: checked.verification, claims: current.values });
    log.debug("Leaving IdentityAssurance.record(). " + stored.ok);
    return stored;
  }

  // -------------------------------------------------------------------------
  // THE CONSOLE'S FORM, AS THE API'S JSON. The management API takes the
  // `verification` element as JSON (or a string of it) and `claims` as an
  // array; the console's form posts one evidence element as flat fields, and
  // this is the one place those fields become the same element — so the two
  // doors record through one check.
  // -------------------------------------------------------------------------
  static fromForm(body: Json): Json {
    helpers.log.debug("Entering IdentityAssurance.fromForm().");
    const b = body || {};
    const text = function (name: string): string {
      const value = b[name];
      return typeof value === 'string' ? value.trim() : '';
    };
    const list = function (value: Json): string[] {
      if (Array.isArray(value)) {
        return value.map(function (one) {
          return String(one).trim();
        }).filter(Boolean);
      }
      return String(value || '').split(',').map(function (one) {
        return one.trim();
      }).filter(Boolean);
    };
    let verification: Json = b.verification;
    if (typeof verification === 'string' && verification.trim()) {
      try {
        verification = JSON.parse(verification);
      } catch (e) {
        helpers.log.debug("Caught in IdentityAssurance.fromForm(): " +
                          ((e && e.message) || e));
        helpers.log.debug("Leaving IdentityAssurance.fromForm(). Not JSON.");
        return { verification: 'verification is not JSON: ' +
                               ((e && e.message) || e),
                 claims: list(b.claims) };
      }
    }
    if (!IdentityAssurance.isObject(verification)) {
      verification = { trust_framework: text('trust_framework') };
      ['assurance_level', 'verification_process'].forEach(function (name) {
        if (text(name)) {
          verification[name] = text(name);
        }
      });
      if (text('time')) {
        verification.time = text('time');
      }
      const type = text('evidence_type');
      if (type) {
        const evidence: Json = { type: type };
        if (text('check_method')) {
          evidence.check_details = [{ check_method: text('check_method') }];
        }
        if (text('evidence_time')) {
          evidence.time = text('evidence_time');
        }
        const put = function (target: Json, name: string, field: string) {
          if (text(field)) {
            target[name] = text(field);
          }
        };
        if (type === 'document') {
          const details: Json = { type: text('document_type') };
          put(details, 'document_number', 'document_number');
          put(details, 'date_of_issuance', 'date_of_issuance');
          put(details, 'date_of_expiry', 'date_of_expiry');
          if (text('issuer_name') || text('issuer_country')) {
            details.issuer = {};
            put(details.issuer, 'name', 'issuer_name');
            put(details.issuer, 'country_code', 'issuer_country');
          }
          evidence.document_details = details;
        } else if (type === 'electronic_record') {
          evidence.record = { type: text('record_type') };
          if (text('source_name')) {
            evidence.record.source = { name: text('source_name') };
          }
        } else if (type === 'vouch') {
          evidence.attestation = { type: text('attestation_type') };
          put(evidence.attestation, 'reference_number', 'reference_number');
          if (text('voucher_name')) {
            evidence.attestation.voucher = { name: text('voucher_name') };
          }
        } else if (type === 'electronic_signature') {
          put(evidence, 'signature_type', 'signature_type');
          put(evidence, 'issuer', 'signature_issuer');
          put(evidence, 'serial_number', 'serial_number');
          put(evidence, 'created_at', 'created_at');
        }
        verification.evidence = [evidence];
      }
    }
    // The console posts one checkbox per claim (`claim_<name>`), because a
    // form body keeps only the last of a repeated name; the API sends
    // `claims` as an array.
    const claims = list(b.claims);
    VERIFIABLE_CLAIMS.forEach(function (name) {
      if (b['claim_' + name] === 'on' && claims.indexOf(name) < 0) {
        claims.push(name);
      }
    });
    helpers.log.debug("Leaving IdentityAssurance.fromForm().");
    return { verification: verification, claims: claims };
  }

  // Keeps a record, newest first, replacing a record from the same automatic
  // source when `replaces` names one, and capping the list.
  private add(username: string, fields: Json, replaces?: string): Json {
    const { log } = this.deps;
    log.debug("Entering IdentityAssurance.add().");
    const record = Object.assign({
      id: nodeCrypto.randomUUID(),
      recorded: new Date(this.deps.now()).toISOString()
    }, fields);
    if (Buffer.byteLength(JSON.stringify(record)) > MAX_RECORD_BYTES) {
      log.debug("Leaving IdentityAssurance.add(). Too large.");
      return { ok: false, error: 'a verification may be at most ' +
                                 MAX_RECORD_BYTES + ' bytes as JSON.' };
    }
    const kept = this.list(username).filter(function (one: Json) {
      return !replaces || one.source !== replaces;
    });
    const records = [record].concat(kept).slice(0, MAX_RECORDS);
    if (!this.store(username, records)) {
      log.debug("Leaving IdentityAssurance.add(). Not stored.");
      return { ok: false, error: 'the directory did not store it (no entry ' +
                                 'for "' + username + '" in this realm).' };
    }
    log.debug("Leaving IdentityAssurance.add().");
    return { ok: true, record: record };
  }

  // Returns { ok, removed }.
  remove(username: Json, id: Json): Json {
    const { log } = this.deps;
    log.debug("Entering IdentityAssurance.remove(). user=" + username);
    const name = String(username || '').trim();
    const records = this.list(name);
    const kept = records.filter(function (one: Json) {
      return one.id !== String(id || '');
    });
    if (kept.length === records.length) {
      log.debug("Leaving IdentityAssurance.remove(). No such record.");
      return { ok: false, error: 'no verification with that id is recorded ' +
                                 'for "' + name + '".' };
    }
    const written = this.store(name, kept);
    log.debug("Leaving IdentityAssurance.remove(). " + written);
    return written ? { ok: true, removed: String(id) } :
      { ok: false, error: 'the directory did not store the change.' };
  }

  // -------------------------------------------------------------------------
  // THE TWO AUTOMATIC SOURCES
  //
  // A sign-in hands over what it verified; what is recorded is the subset of
  // it the entry agrees with. The verification is this service's own, under
  // the first configured framework, and a sign-in that verified no claim the
  // entry holds records nothing. Never throws: a sign-in has already
  // succeeded when this runs, and bookkeeping must not undo it.
  //
  // `kind` is 'wallet' — `claims` the disclosed credential claims, `format`
  // the credential format — or 'certificate' — `claims` read off the
  // certificate's subject, `issuer`, `serial` and `notBefore`.
  // -------------------------------------------------------------------------
  recordAutomatic(username: Json, kind: string, facts: Json): Json {
    const { log } = this.deps;
    log.debug("Entering IdentityAssurance.recordAutomatic(). kind=" + kind);
    try {
      if (!this.automaticEnabled()) {
        log.debug("Leaving IdentityAssurance.recordAutomatic(). Off.");
        return { ok: false,
                 skipped: 'oauth2.idaAutomaticVerifications is off' };
      }
      const framework = this.trustFrameworks()[0];
      if (!framework) {
        log.debug("Leaving IdentityAssurance.recordAutomatic(). No " +
                  "framework.");
        return { ok: false, skipped: 'no trust framework is configured' };
      }
      const name = String(username || '').trim();
      const presented = (facts && facts.claims) || {};
      const names = Object.keys(presented).filter(function (one) {
        return VERIFIABLE_CLAIMS.indexOf(one) >= 0;
      });
      const current = names.length ? this.currentValues(name, names) :
        { values: {}, entryFound: false };
      const agreed: Json = {};
      names.forEach(function (one) {
        if (current.values[one] !== undefined &&
            IdentityAssurance.canonical(current.values[one]) ===
            IdentityAssurance.canonical(presented[one])) {
          agreed[one] = current.values[one];
        }
      });
      if (!Object.keys(agreed).length) {
        log.debug("Leaving IdentityAssurance.recordAutomatic(). Nothing " +
                  "the entry agrees with.");
        return { ok: false, skipped: 'the sign-in verified no claim the ' +
                                     'entry holds' };
      }
      const now = new Date(this.deps.now()).toISOString()
        .replace(/\.\d+Z$/, 'Z');
      let evidence: Json;
      if (kind === 'wallet') {
        evidence = { type: 'electronic_record',
          check_details: [{ check_method: 'vcrypt' }], time: now,
          record: { type: WALLET_RECORD_TYPE,
                    source: { name: 'this service\'s credential issuer' } } };
        if (facts.format) {
          evidence.record.format = String(facts.format);
        }
      } else if (kind === 'certificate') {
        evidence = { type: 'electronic_signature',
          signature_type: CERTIFICATE_SIGNATURE_TYPE,
          issuer: String(facts.issuer || '').slice(0, 512) || 'unknown',
          serial_number: String(facts.serial || '').slice(0, 512) ||
                         'unknown' };
        if (IdentityAssurance.isDateTime(facts.notBefore)) {
          evidence.created_at = facts.notBefore;
        }
      } else {
        log.debug("Leaving IdentityAssurance.recordAutomatic(). Unknown " +
                  "kind.");
        return { ok: false, skipped: 'unknown kind ' + kind };
      }
      const stored = this.add(name, {
        source: kind, by: 'the sign-in',
        verification: { trust_framework: framework, time: now,
                        evidence: [evidence] },
        claims: agreed }, kind);
      log.debug("Leaving IdentityAssurance.recordAutomatic(). " + stored.ok);
      return stored;
    } catch (e) {
      log.error(this.deps.errorCodes.tag('STS-OAUTH-0623') +
                'identity-assurance: recording a ' + kind +
                ' verification for ' + username + ' failed and was ' +
                'ignored; the sign-in stands: ' +
                ((e && e.message) || e));
      log.debug("Leaving IdentityAssurance.recordAutomatic(). It threw.");
      return { ok: false, skipped: 'it threw' };
    }
  }

  // -------------------------------------------------------------------------
  // PARSING A REQUEST (section 6)
  //
  // The value of `verified_claims` in one member of a claims request: an
  // object, or a non-empty array of them. Normalised to the array, which is
  // also a valid input — the parsed request rides in the access token and is
  // parsed again at the UserInfo endpoint.
  // Returns { elements, count } or { error }.
  // -------------------------------------------------------------------------
  parseRequest(raw: Json, where: string): Json {
    const { log } = this.deps;
    log.debug("Entering IdentityAssurance.parseRequest().");
    const at = 'claims.' + where + '.verified_claims';
    const refuse = function (why: string): Json {
      log.debug("Leaving IdentityAssurance.parseRequest(). " + why);
      return { error: why };
    };
    const list = Array.isArray(raw) ? raw : [raw];
    if (!list.length) {
      return refuse(at + ' is an empty array (Identity Assurance section ' +
                    '6).');
    }
    let count = 0;
    let problem: Json = null;
    // Every node: depth, count, and section 6's rules for `purpose` and
    // `max_age` wherever they appear.
    const walk = function (node: Json, path: string, depth: number): void {
      if (problem || node === null || typeof node !== 'object') {
        return;
      }
      count++;
      if (depth > MAX_REQUEST_DEPTH || count > MAX_REQUEST_NODES) {
        problem = at + ' is nested deeper than ' + MAX_REQUEST_DEPTH +
                  ' or has more than ' + MAX_REQUEST_NODES + ' members.';
        return;
      }
      if (Array.isArray(node)) {
        node.forEach(function (one, i) {
          walk(one, path + '[' + i + ']', depth + 1);
        });
        return;
      }
      if (node.purpose !== undefined &&
          (typeof node.purpose !== 'string' ||
           node.purpose.length < PURPOSE_MIN ||
           node.purpose.length > PURPOSE_MAX)) {
        problem = path + '.purpose must be a string of ' + PURPOSE_MIN +
                  ' to ' + PURPOSE_MAX + ' characters (Identity Assurance ' +
                  'section 6).';
        return;
      }
      if (node.max_age !== undefined &&
          (typeof node.max_age !== 'number' || !isFinite(node.max_age) ||
           node.max_age < 0 || Math.floor(node.max_age) !== node.max_age)) {
        problem = path + '.max_age must be a non-negative integer number ' +
                  'of seconds.';
        return;
      }
      if (node.values !== undefined &&
          (!Array.isArray(node.values) || !node.values.length)) {
        problem = path + '.values must be a non-empty array.';
        return;
      }
      if (node.essential !== undefined && typeof node.essential !== 'boolean') {
        problem = path + '.essential must be a boolean.';
        return;
      }
      IdentityAssurance.memberKeys(node).forEach(function (key) {
        walk(node[key], path + '.' + key, depth + 1);
      });
    };
    const elements: Json[] = [];
    for (let i = 0; i < list.length; i++) {
      const one = list[i];
      const path = at + (Array.isArray(raw) ? '[' + i + ']' : '');
      if (!IdentityAssurance.isObject(one)) {
        return refuse(path + ' must be a JSON object.');
      }
      if (!IdentityAssurance.isObject(one.verification)) {
        return refuse(path + '.verification is required, as a JSON object ' +
                      '(Identity Assurance section 6).');
      }
      if (!('trust_framework' in one.verification)) {
        return refuse(path + '.verification.trust_framework is required ' +
                      '(Identity Assurance section 6); null asks for any.');
      }
      if (!IdentityAssurance.isObject(one.claims) ||
          !Object.keys(one.claims).length) {
        return refuse(path + '.claims is required and may not be empty ' +
                      '(Identity Assurance section 6).');
      }
      walk(one.verification, path + '.verification', 1);
      walk(one.claims, path + '.claims', 1);
      if (problem) {
        return refuse(problem);
      }
      elements.push({ verification: one.verification, claims: one.claims });
    }
    log.debug("Leaving IdentityAssurance.parseRequest(). " +
              elements.length + " element(s).");
    return { elements: elements, count: count };
  }

  // -------------------------------------------------------------------------
  // MATCHING AND PROJECTING
  //
  // `matches()` asks whether an actual value satisfies a request node:
  // `value`/`values` compare the leaf, `max_age` bounds a date-time, an array
  // request needs each of its elements matched by some actual element, and a
  // member that is merely named (null, or only `essential`/`purpose`) is
  // satisfied whether or not it is present — it is released where it is.
  // `project()` then keeps only what the request named.
  // -------------------------------------------------------------------------
  matches(request: Json, actual: Json): boolean {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering IdentityAssurance.matches().");
    if (request === null || request === undefined) {
      log.debug("Leaving IdentityAssurance.matches(). Only named.");
      return true;
    }
    if (Array.isArray(request)) {
      const ok = Array.isArray(actual) && request.every(function (want) {
        return actual.some(function (have: Json) {
          return self.matches(want, have);
        });
      });
      log.debug("Leaving IdentityAssurance.matches(). Array: " + ok);
      return ok;
    }
    if (typeof request !== 'object') {
      log.debug("Leaving IdentityAssurance.matches(). Not a request node.");
      return true;
    }
    if (request.value !== undefined &&
        IdentityAssurance.canonical(request.value) !==
        IdentityAssurance.canonical(actual)) {
      log.debug("Leaving IdentityAssurance.matches(). value differs.");
      return false;
    }
    if (request.values !== undefined &&
        !request.values.some(function (v: Json) {
          return IdentityAssurance.canonical(v) ===
                 IdentityAssurance.canonical(actual);
        })) {
      log.debug("Leaving IdentityAssurance.matches(). Not among values.");
      return false;
    }
    if (request.max_age !== undefined) {
      const at = Date.parse(String(actual || ''));
      if (isNaN(at) || self.deps.now() - at > request.max_age * 1000) {
        log.debug("Leaving IdentityAssurance.matches(). Older than max_age.");
        return false;
      }
    }
    const keys = IdentityAssurance.memberKeys(request);
    for (let i = 0; i < keys.length; i++) {
      const sub = actual && typeof actual === 'object' ?
        actual[keys[i]] : undefined;
      if (!self.matches(request[keys[i]], sub)) {
        log.debug("Leaving IdentityAssurance.matches(). Member " + keys[i] +
                  ".");
        return false;
      }
    }
    log.debug("Leaving IdentityAssurance.matches(). Yes.");
    return true;
  }

  project(request: Json, actual: Json): Json {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering IdentityAssurance.project().");
    if (actual === undefined) {
      log.debug("Leaving IdentityAssurance.project(). Absent.");
      return undefined;
    }
    if (IdentityAssurance.isLeafSpec(request)) {
      log.debug("Leaving IdentityAssurance.project(). Whole.");
      return JSON.parse(JSON.stringify(actual));
    }
    if (Array.isArray(request)) {
      if (!Array.isArray(actual)) {
        log.debug("Leaving IdentityAssurance.project(). Not an array.");
        return undefined;
      }
      const out: Json[] = [];
      actual.forEach(function (have: Json) {
        const want = request.filter(function (one: Json) {
          return self.matches(one, have);
        })[0];
        if (want !== undefined) {
          out.push(self.project(want, have));
        }
      });
      log.debug("Leaving IdentityAssurance.project(). " + out.length +
                " element(s).");
      return out.length ? out : undefined;
    }
    if (!IdentityAssurance.isObject(actual)) {
      log.debug("Leaving IdentityAssurance.project(). A leaf asked for " +
                "members.");
      return undefined;
    }
    const out: Json = {};
    IdentityAssurance.memberKeys(request).forEach(function (key) {
      const value = self.project(request[key], actual[key]);
      if (value !== undefined) {
        out[key] = value;
      }
    });
    log.debug("Leaving IdentityAssurance.project().");
    return Object.keys(out).length ? out : undefined;
  }

  // The invented verification development answers with (see the header). It
  // covers what was asked for, at this moment, through a check that names
  // itself for what it is.
  demoRecord(username: string, names: string[]): Json {
    const { log } = this.deps;
    log.debug("Entering IdentityAssurance.demoRecord().");
    const now = new Date(this.deps.now()).toISOString()
      .replace(/\.\d+Z$/, 'Z');
    const current = this.currentValues(username, names.filter(function (one) {
      return VERIFIABLE_CLAIMS.indexOf(one) >= 0;
    }), true);
    log.debug("Leaving IdentityAssurance.demoRecord().");
    return { id: 'demo', source: 'demo', recorded: now,
      verification: { trust_framework: DEMO_FRAMEWORK, time: now,
        evidence: [{ type: 'electronic_record',
          check_details: [{ check_method: 'data' }], time: now,
          record: { type: DEMO_FRAMEWORK,
                    source: { name: 'invented by a development-mode ' +
                                    'service; nothing was checked' } } }] },
      claims: current.values };
  }

  // -------------------------------------------------------------------------
  // THE ANSWER
  //
  // `elements` is what parseRequest() returned. Returns { value, report }:
  // `value` is the `verified_claims` to release — an object for one element
  // asked for as an object, an array otherwise — or undefined when nothing
  // satisfies the request, and `report` a line per element for the log.
  // -------------------------------------------------------------------------
  respond(username: Json, elements: Json[], asArray: boolean): Json {
    const { log, mode } = this.deps;
    const self = this;
    log.debug("Entering IdentityAssurance.respond(). user=" + username);
    const name = String(username || '');
    const report: string[] = [];
    let records = self.list(name);
    const allNames: string[] = [];
    elements.forEach(function (element: Json) {
      Object.keys(element.claims || {}).forEach(function (one) {
        if (allNames.indexOf(one) < 0) {
          allNames.push(one);
        }
      });
    });
    if (!records.length && mode.inventsClaimValues()) {
      records = [self.demoRecord(name, allNames)];
      report.push('no verification is recorded; answered with an invented ' +
                  'one under ' + DEMO_FRAMEWORK + ' (development mode)');
    }
    const demo = records.length === 1 && records[0].source === 'demo';
    const current = records.length ?
      self.currentValues(name, allNames, demo).values : {};
    const answers: Json[] = [];
    elements.forEach(function (element: Json, index: number) {
      const asked = Object.keys(element.claims);
      let chosen: Json = null;
      let released: Json = null;
      for (let i = 0; i < records.length && !chosen; i++) {
        const record = records[i];
        if (!self.matches(element.verification, record.verification)) {
          continue;
        }
        const claims: Json = {};
        const stale: string[] = [];
        const unmet: string[] = [];
        asked.forEach(function (one) {
          if (record.claims[one] === undefined) {
            return;
          }
          if (IdentityAssurance.canonical(record.claims[one]) !==
              IdentityAssurance.canonical(current[one])) {
            stale.push(one);
            return;
          }
          // Section 5.7.4: a claim whose data does not fulfil the request's
          // `value`, `values` or `max_age` is omitted (#187).
          if (!self.matches(element.claims[one], record.claims[one])) {
            unmet.push(one);
            return;
          }
          const value = self.project(element.claims[one], record.claims[one]);
          if (value !== undefined) {
            claims[one] = value;
          }
        });
        if (stale.length) {
          report.push('element ' + index + ': ' + stale.join(', ') +
                      ' changed on the entry since verification ' +
                      record.id + ' and ' +
                      (stale.length > 1 ? 'are' : 'is') + ' not released ' +
                      'as verified');
        }
        if (unmet.length) {
          report.push('element ' + index + ': ' + unmet.join(', ') +
                      ' in verification ' + record.id + ' ' +
                      (unmet.length > 1 ? 'do' : 'does') + ' not fulfil ' +
                      'the value, values or max_age asked for; omitted ' +
                      '(Identity Assurance section 5.7.4)');
        }
        if (Object.keys(claims).length) {
          chosen = record;
          released = claims;
        }
      }
      if (!chosen) {
        report.push('element ' + index + ': no recorded verification ' +
                    'satisfies it; omitted (Identity Assurance section 6)');
        return;
      }
      const verification = self.project(element.verification,
                                        chosen.verification) || {};
      // `trust_framework` is REQUIRED in every answer, asked for or not.
      verification.trust_framework = chosen.verification.trust_framework;
      answers.push({ verification: verification, claims: released });
      report.push('element ' + index + ': verification ' + chosen.id +
                  ' under ' + chosen.verification.trust_framework + ', ' +
                  Object.keys(released).join(', '));
    });
    if (report.length) {
      log.info('identity-assurance: verified_claims for ' + name + ' — ' +
               report.join('; ') + '.');
    }
    log.debug("Leaving IdentityAssurance.respond(). " + answers.length +
              " answered.");
    if (!answers.length) {
      return { value: undefined, report: report };
    }
    return { value: asArray || answers.length > 1 ? answers : answers[0],
             report: report };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `common/instance_slot.ts`. The exports below are FACADES for the
// JavaScript that calls this module through `require()`.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<IdentityAssurance>(
  'common/identity_assurance',
  () => new IdentityAssurance(IdentityAssurance.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading a module always did.
slot.buildNowUnlessDeferred();

export = {
  IdentityAssurance: IdentityAssurance,
  installInstance: (instance: IdentityAssurance): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  EVIDENCE_TYPES: EVIDENCE_TYPES,
  DEMO_FRAMEWORK: DEMO_FRAMEWORK,
  DOCUMENT_TYPES: DOCUMENT_TYPES,
  CHECK_METHODS: CHECK_METHODS,
  ELECTRONIC_RECORD_TYPES: ELECTRONIC_RECORD_TYPES,
  ATTESTATION_TYPES: ATTESTATION_TYPES,
  VERIFIABLE_CLAIMS: VERIFIABLE_CLAIMS,
  WALLET_RECORD_TYPE: WALLET_RECORD_TYPE,
  CERTIFICATE_SIGNATURE_TYPE: CERTIFICATE_SIGNATURE_TYPE,
  MAX_RECORDS: MAX_RECORDS,
  fromForm: IdentityAssurance.fromForm,
  trustFrameworks: slot.forward('trustFrameworks'),
  discoveryMetadata: slot.forward('discoveryMetadata'),
  list: slot.forward('list'),
  record: slot.forward('record'),
  remove: slot.forward('remove'),
  recordAutomatic: slot.forward('recordAutomatic'),
  parseRequest: slot.forward('parseRequest'),
  respond: slot.forward('respond')
};
