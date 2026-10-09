// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_request.js
//
// ---------------------------------------------------------------------------
// ONE AUTHORIZATION REQUEST, BUILT ONE WAY, FOR EVERY PEP (#306, part E of
// #88, 2026-09-27).
//
// #88 section 7: every authorization question this service asks — may this
// be ISSUED, may this surface be REACHED, how should it REACT to a risk or a
// signal, and what a remote PEP asks on somebody else's behalf — is one
// shape, and the protocol adapter's job is to fill it in:
//
//   principal, principal_type       access-subject subject-id, subject-kind
//   target                          resource resource-id
//   requested actions               action action-id
//   roles, requested scopes, ...    the vocabulary below, in their category
//   protocol, grant type, consent   the environment
//
// Until this file each PEP built that request itself — the issuance PEP, the
// access PEP, the risk and signal PEPs and the remote PEP each carried its
// own `attribute()` and its own array of categories — and the five copies had
// already drifted in the small ways that matter to a policy: one dropped an
// empty value and another sent it, two asked for the attributes back in the
// result and two did not. The drift was harmless only because no policy had
// yet been written that could see it. This is the one place a request is
// made, and a PEP says WHAT it knows rather than how XACML spells it.
//
// ---------------------------------------------------------------------------
// **IT IS AN ENGINE MODULE, NOT A SERVICE ONE (rcbj's decision on #306).**
// It requires `xacml_model.js` and the helpers logger and nothing else, so
// the remote PEP container copies it beside the engine (`xacml-pep/
// engine.js`'s `MODULES`, and a COPY line in its Dockerfile that
// `tests/xacml_pep.js` holds to that list) and builds its requests with the
// same code this service does. That is also why the VOCABULARY is here and
// not in `xacml_templates.ts`: the templates are the service's, a remote PEP
// cannot load them, and one spelling of each identifier has to be somewhere
// both can read. `xacml_templates.ts` takes the shared ones from here.
//
// **IT DECIDES NOTHING.** Which facts a PEP puts in is that PEP's business;
// the builder only makes sure they are spelt, typed and grouped one way.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');
const model = require('./xacml_model');

// ---------------------------------------------------------------------------
// THE VOCABULARY OF #88 SECTION 7 THAT IS NOT XACML'S OWN. XACML supplies
// subject-id, resource-id and action-id (`model.ATTRIBUTE`); the rest are
// this service's, URI-shaped so `xacml_pip.ts` never mistakes one for a
// directory attribute name (see `xacml_templates.ts`'s ISSUANCE_ATTRIBUTE
// header for why that matters).
// ---------------------------------------------------------------------------
const VOCABULARY = Object.freeze({
  // access-subject: the roles the principal holds (#303 made the PIP answer
  // it for a subject a request did not describe).
  ROLE: 'urn:sts:xacml:role',
  // access-subject: `user` or `application` — principal_type. A name alone
  // cannot say: `payroll-worker` could be either (#303).
  SUBJECT_KIND: 'urn:sts:xacml:subject-kind',
  // access-subject: the OAuth client the request came through, where that is
  // not the principal itself.
  CLIENT_ID: 'urn:sts:xacml:client-id',
  // resource: the audience the issued artefact is for (RFC 8707 resource,
  // RFC 8693 audience, an AppliesTo, a service principal).
  AUDIENCE: 'urn:sts:xacml:audience',
  // action: each scope value the request asked for — requested_scopes.
  REQUESTED_SCOPE: 'urn:sts:xacml:requested-scope',
  // environment: the protocol family the request arrived over.
  PROTOCOL: 'urn:sts:xacml:protocol',
  // environment: the OAuth grant type, where there is one.
  GRANT_TYPE: 'urn:sts:xacml:grant-type',
  // environment: the realm's mode, `development` or `product` (#305 — rcbj's
  // decision that the mode and the settings a rule depends on are facts in
  // the request, so the policy decides what differs between the two).
  MODE: 'urn:sts:xacml:mode',
  // environment: a setting's value, the setting's key after this prefix
  // (`urn:sts:xacml:setting:oauth2.consentRequired`), typed as it is.
  SETTING_PREFIX: 'urn:sts:xacml:setting:',
  // environment: which moment a scope is judged at (#305): `request` (an
  // endpoint still talking to the client, which refuses), `mint` (the
  // backstop every grant mints through, which narrows) or `consent`.
  SCOPE_STAGE: 'urn:sts:xacml:scope-stage',
  // THE FACTS OF A TRANSFER QUESTION (#98 D4, the design's section 6 —
  // "geofencing is policy, not code"), asked by `common/cell_transfer.ts`
  // when the service is deployed as cells. access-subject: the jurisdiction
  // the subject is HOMED in, where their personal data lives.
  HOME_JURISDICTION: 'urn:sts:xacml:home-jurisdiction',
  // environment: the jurisdiction of the cell being asked to hold the
  // session or serve the request.
  SERVING_JURISDICTION: 'urn:sts:xacml:serving-jurisdiction',
  // environment: the country the CLIENT is in, where the GeoIP data `risk/`
  // imports could say (ISO 3166-1 alpha-2, lower-case); absent when unknown,
  // and an absent country is not a country — no rule may read it as one.
  CLIENT_COUNTRY: 'urn:sts:xacml:client-country',
  // environment, a boolean: the realm's `cells.permittedTransfers` names
  // this home>serving pair (staying in one jurisdiction always is). The
  // realm's STATED loosening, as a fact; what it means is the policy's.
  TRANSFER_LISTED: 'urn:sts:xacml:transfer-listed',
  // resource: what would leave home — `session` (a session and the
  // credential-free projection of the entry it stands on), `request` (one
  // request, relayed) or `attributes` (residents' entries released to a
  // reader at another cell, #98 D11). The design's "data category".
  DATA_CATEGORY: 'urn:sts:xacml:data-category',
  // environment: WHY attributes are released (#98 D11) —
  // `directory-list` (an administrator listing another cell's residents)
  // or `api` (a management-API call relayed with ?cell=).
  PURPOSE: 'urn:sts:xacml:purpose',
  // environment: the trust realm the question is asked in.
  REALM: 'urn:sts:xacml:realm',
  // THE FACTS OF AN EXCHANGE QUESTION (#186): who may act for whom, and as
  // what, at an RFC 8693 token exchange, a WS-Trust OnBehalfOf / ActAs or a
  // Kerberos S4U request — one vocabulary for the three, so one policy
  // decides all of them. Gathered by `common/delegation_policy.ts`; nothing
  // here decides. S is the application the subject token was issued for, R
  // the one the new token is asked for, the actor the party acting (in the
  // intermediary-subject category). Every party is named by its application
  // identifier, or a person's subject, so the policy compares them itself.
  //
  // access-subject: the subject is protected by its own entry (Kerberos's
  // NOT_DELEGATED, `stsNotDelegated` / `appNotDelegated`).
  EXCHANGE_SUBJECT_NOT_DELEGATED:
    'urn:sts:xacml:exchange:subject-not-delegated',
  // access-subject: the subject's groups, each as its cn AND its normalised
  // DN, so a protected group or an actor's subject group matches either way.
  EXCHANGE_SUBJECT_GROUP: 'urn:sts:xacml:exchange:subject-group',
  // access-subject / intermediary-subject: the semantics this party allows
  // (`delegation`, `impersonation`), and its default. Absent is the policy's
  // to read: the built-in rules read an actor's empty set as delegation
  // only, a subject's as both.
  EXCHANGE_ALLOWED_SEMANTICS: 'urn:sts:xacml:exchange:allowed-semantics',
  EXCHANGE_DEFAULT_SEMANTICS: 'urn:sts:xacml:exchange:default-semantics',
  // intermediary-subject: `user` or `application`; whether an entry backs it
  // in this realm; the targets it may reach as somebody else
  // (appAllowedToDelegateTo, resolved); the people it may act for
  // (appDelegationSubjectGroup, normalised DNs).
  EXCHANGE_ACTOR_KIND: 'urn:sts:xacml:exchange:actor-kind',
  EXCHANGE_ACTOR_REGISTERED: 'urn:sts:xacml:exchange:actor-registered',
  EXCHANGE_ACTOR_DELEGATES_TO: 'urn:sts:xacml:exchange:actor-delegates-to',
  EXCHANGE_ACTOR_SUBJECT_GROUP: 'urn:sts:xacml:exchange:actor-subject-group',
  // resource: S, and what it requires and delegates to.
  EXCHANGE_SOURCE: 'urn:sts:xacml:exchange:source',
  EXCHANGE_SOURCE_REQUIRED_ROLE:
    'urn:sts:xacml:exchange:source-required-role',
  EXCHANGE_SOURCE_DELEGATES_TO: 'urn:sts:xacml:exchange:source-delegates-to',
  // resource: R — how many targets were asked for (an integer), whether R is
  // a registered application, what it requires, and whom it accepts as an
  // actor (appAllowedToActOnBehalfOf, resolved). R itself is resource-id.
  EXCHANGE_TARGET_COUNT: 'urn:sts:xacml:exchange:target-count',
  EXCHANGE_TARGET_REGISTERED: 'urn:sts:xacml:exchange:target-registered',
  EXCHANGE_TARGET_REQUIRED_ROLE:
    'urn:sts:xacml:exchange:target-required-role',
  EXCHANGE_TARGET_ACCEPTS: 'urn:sts:xacml:exchange:target-accepts',
  // action: the semantics the REQUEST asked for (the extension parameter,
  // the WS-Trust element, the Kerberos mechanism), and the semantics the
  // choosing question settled on.
  EXCHANGE_REQUESTED_SEMANTICS:
    'urn:sts:xacml:exchange:requested-semantics',
  EXCHANGE_SEMANTICS: 'urn:sts:xacml:exchange:semantics',
  // environment: the subject token carried may_act (RFC 8693 section 4.4),
  // and whether it names this actor — an identity comparison the door makes.
  EXCHANGE_MAY_ACT_PRESENT: 'urn:sts:xacml:exchange:may-act-present',
  EXCHANGE_MAY_ACT_NAMES_ACTOR: 'urn:sts:xacml:exchange:may-act-names-actor',
  // environment: the groups whose members are never acted for — the
  // realm's `delegation.protectedGroups` and the console roster — as cn and
  // normalised DN.
  EXCHANGE_PROTECTED_GROUP: 'urn:sts:xacml:exchange:protected-group',
  // #186: the party the subject NAMED as their delegate (`stsMayAct` on a
  // person, `appMayAct` on an application), as the `may_act` claim would
  // name it — the fact the `assign-may-act` question decides on.
  EXCHANGE_SUBJECT_DELEGATE: 'urn:sts:xacml:exchange:subject-delegate',
  // THE FACTS OF A GNAP ACCESS RIGHT (#432 phase 3): one question per right,
  // action-id `issue-gnap-right`, the right's type (or its reference string)
  // as the resource-id. Gathered by `gnap/gnap_rights.ts`; nothing here
  // decides. RESOURCE: the right itself — `object` or `reference`, its five
  // common fields (RFC 9635 section 8) — whether the access-type catalogue
  // declares its type and what that entry declares, whether the client's
  // gnapAllowedAccess lists it, whether a reference names a registered
  // resource set, and whether it asks for one of this service's protected
  // scopes (#110) the client's entry does not declare.
  GNAP_RIGHT_KIND: 'urn:sts:xacml:gnap:right-kind',
  GNAP_RIGHT_ACTION: 'urn:sts:xacml:gnap:right-action',
  GNAP_RIGHT_LOCATION: 'urn:sts:xacml:gnap:right-location',
  GNAP_RIGHT_DATATYPE: 'urn:sts:xacml:gnap:right-datatype',
  GNAP_RIGHT_IDENTIFIER: 'urn:sts:xacml:gnap:right-identifier',
  GNAP_RIGHT_PRIVILEGE: 'urn:sts:xacml:gnap:right-privilege',
  GNAP_RIGHT_LISTED: 'urn:sts:xacml:gnap:right-listed',
  GNAP_REFERENCE_REGISTERED: 'urn:sts:xacml:gnap:reference-registered',
  GNAP_PROTECTED: 'urn:sts:xacml:gnap:protected',
  GNAP_PROTECTED_DECLARED: 'urn:sts:xacml:gnap:protected-declared',
  GNAP_CATALOGUED: 'urn:sts:xacml:gnap:catalogued',
  GNAP_TYPE_OWNER: 'urn:sts:xacml:gnap:type-owner',
  GNAP_TYPE_BEARER: 'urn:sts:xacml:gnap:type-bearer',
  GNAP_TYPE_MAX_LIFETIME: 'urn:sts:xacml:gnap:type-max-lifetime',
  GNAP_TYPE_ACR: 'urn:sts:xacml:gnap:type-acr',
  GNAP_TYPE_INTERACTION: 'urn:sts:xacml:gnap:type-interaction',
  GNAP_TYPE_CONSENT_ACTION: 'urn:sts:xacml:gnap:type-consent-action',
  GNAP_TYPE_DERIVABLE_FROM: 'urn:sts:xacml:gnap:type-derivable-from',
  GNAP_TYPE_INTROSPECTION_CLAIM:
    'urn:sts:xacml:gnap:type-introspection-claim',
  // THE RIGHT'S LIMITS AND WHO OWNS WHAT IT NAMES (#432 phase 5). The limits
  // as the right carries them (`limits`, the JSON) and each member with a
  // meaning decomposed (`common/access_limits.ts`): an amount (a double, in
  // its currency), a count, the receivers, the repeating interval and the
  // window's two ends. The owner of the right's identifier — from a
  // registered resource set or the resource server's lookup — whether one is
  // known, whether a declared lookup could not be answered, and, once an
  // approver is known, whether the approver is that owner (or a member of
  // that group). `owner-matches` is sent only with an approver.
  GNAP_LIMITS: 'urn:sts:xacml:gnap:limits',
  GNAP_LIMIT_AMOUNT: 'urn:sts:xacml:gnap:limit-amount',
  GNAP_LIMIT_CURRENCY: 'urn:sts:xacml:gnap:limit-currency',
  GNAP_LIMIT_COUNT: 'urn:sts:xacml:gnap:limit-count',
  GNAP_LIMIT_RECEIVER: 'urn:sts:xacml:gnap:limit-receiver',
  GNAP_LIMIT_INTERVAL: 'urn:sts:xacml:gnap:limit-interval',
  GNAP_LIMIT_NOT_BEFORE: 'urn:sts:xacml:gnap:limit-not-before',
  GNAP_LIMIT_NOT_AFTER: 'urn:sts:xacml:gnap:limit-not-after',
  GNAP_OWNER_KNOWN: 'urn:sts:xacml:gnap:owner-known',
  GNAP_OWNER: 'urn:sts:xacml:gnap:owner',
  GNAP_OWNER_SOURCE: 'urn:sts:xacml:gnap:owner-source',
  GNAP_OWNER_UNRESOLVED: 'urn:sts:xacml:gnap:owner-unresolved',
  GNAP_OWNER_MATCHES: 'urn:sts:xacml:gnap:owner-matches',
  // ACTION: the token the right is to be issued in — its label, the bearer
  // flag, the format it would be minted in and the resource servers it is
  // for.
  GNAP_TOKEN_LABEL: 'urn:sts:xacml:gnap:token-label',
  GNAP_TOKEN_BEARER: 'urn:sts:xacml:gnap:token-bearer',
  GNAP_TOKEN_FORMAT: 'urn:sts:xacml:gnap:token-format',
  GNAP_TOKEN_TARGET: 'urn:sts:xacml:gnap:token-target',
  // ACCESS-SUBJECT: the client — its REGISTERED class (a declared class_id
  // never raises trust, so it is never sent), whether its entry lists any
  // gnapAllowedAccess, and whether it refuses bearer tokens.
  GNAP_CLIENT_CLASS: 'urn:sts:xacml:gnap:client-class',
  GNAP_CLIENT_HAS_ALLOWED_ACCESS:
    'urn:sts:xacml:gnap:client-has-allowed-access',
  GNAP_CLIENT_BEARER_REFUSED: 'urn:sts:xacml:gnap:client-bearer-refused',
  // ENVIRONMENT: who approved and how (`pending` before anybody has,
  // `interaction`, `skipped`, `derived`, `remembered`, or — since #432
  // phase 6 — `owner`, the resource owner on their portal while somebody
  // else, or nobody, used the client), the session the
  // approval stands on (acr, amr), its risk (#62) and the registered device
  // (#164). UNDER NAMES OF THEIR OWN rather than the issuance's risk and
  // device attributes: the issuance's untargeted risk and device rules
  // decide the TOKEN through `gate.check()`, which is still asked, and a
  // right that carried their attributes would trip them on every
  // per-right question and answer it with an obligation no right reader
  // knows.
  GNAP_APPROVER: 'urn:sts:xacml:gnap:approver',
  GNAP_APPROVAL: 'urn:sts:xacml:gnap:approval',
  GNAP_SESSION_ACR: 'urn:sts:xacml:gnap:session-acr',
  GNAP_SESSION_AMR: 'urn:sts:xacml:gnap:session-amr',
  GNAP_RISK_LEVEL: 'urn:sts:xacml:gnap:risk-level',
  GNAP_RISK_SIGNAL: 'urn:sts:xacml:gnap:risk-signal',
  GNAP_DEVICE_RECOGNIZED: 'urn:sts:xacml:gnap:device-recognized',
  GNAP_DEVICE_STATUS: 'urn:sts:xacml:gnap:device-status',
  GNAP_DEVICE_COMPLIANCE: 'urn:sts:xacml:gnap:device-compliance',
  GNAP_DEVICE_ATTESTATION: 'urn:sts:xacml:gnap:device-attestation',
  GNAP_DEVICE_OWNER_MATCHES: 'urn:sts:xacml:gnap:device-owner-matches',
  // THE FACTS OF A PASSKEY QUESTION (#536): a passkey being registered
  // (`register-passkey`) or signing somebody in (`use-passkey`), gathered by
  // `common/passkey_policy.ts`. Nothing here decides; the built-in issuance
  // policy's passkey rules read these.
  //
  // environment: which groups of facts this question carries —
  // `backup-eligible`, `pin-length`, `serial`, `attestation`. Each built-in
  // rule fires only on a question that carries its group, so a question
  // asked at one door never trips a rule another door asks.
  PASSKEY_FACTS: 'urn:sts:xacml:passkey:facts',
  // resource, a boolean: the authenticator data's BE flag (#528).
  PASSKEY_BACKUP_ELIGIBLE: 'urn:sts:xacml:passkey:backup-eligible',
  // resource, an integer: the minimum PIN length the key reported (CTAP
  // 2.1's minPinLength extension, #529); absent when it reported none.
  PASSKEY_MIN_PIN_LENGTH: 'urn:sts:xacml:passkey:min-pin-length',
  // resource: the device serial a trusted attestation certificate named
  // (#532), and a boolean saying whether it is one of the person's (their
  // entry holds it in the attribute the passkey policy names).
  PASSKEY_SERIAL: 'urn:sts:xacml:passkey:serial',
  PASSKEY_SERIAL_HELD: 'urn:sts:xacml:passkey:serial-held',
  // resource: what the key's RECORDED attestation says (#530) — whether it
  // was verified and trusted, and its AAGUID (lower case, no hyphens).
  PASSKEY_ATTESTATION_VERIFIED: 'urn:sts:xacml:passkey:attestation-verified',
  PASSKEY_ATTESTATION_TRUSTED: 'urn:sts:xacml:passkey:attestation-trusted',
  PASSKEY_AAGUID: 'urn:sts:xacml:passkey:aaguid',
  // resource: what the FIDO Metadata Service says of the model NOW —
  // whether it lists it, whether it is compromised, its certification level
  // as a RANK (0 none, 1 L1, 2 L1plus, 3 L2, 4 L2plus, 5 L3, 6 L3plus) so a
  // rule can compare it, and whether it holds a FIPS 140 certification.
  // Absent unless the metadata was asked; `metadata-unchecked` true when it
  // was asked and could not be read.
  PASSKEY_MODEL_LISTED: 'urn:sts:xacml:passkey:model-listed',
  PASSKEY_MODEL_COMPROMISED: 'urn:sts:xacml:passkey:model-compromised',
  PASSKEY_CERTIFICATION_RANK: 'urn:sts:xacml:passkey:certification-rank',
  PASSKEY_FIPS: 'urn:sts:xacml:passkey:fips',
  PASSKEY_METADATA_UNCHECKED: 'urn:sts:xacml:passkey:metadata-unchecked',
  // environment: the SELECTED passkey policy profile's rows (#527, #535),
  // each after this prefix under its own name
  // (`urn:sts:xacml:passkey-policy:backupEligibility`).
  PASSKEY_POLICY_PREFIX: 'urn:sts:xacml:passkey-policy:',
  // environment, an integer: the rank of
  // `webauthn.attestationMinCertificationLevel`, absent when it is `none`.
  PASSKEY_REQUIRED_RANK: 'urn:sts:xacml:passkey:required-certification-rank'
});

// The principal types a request may name. Anything else is a person, which
// is what a request that never said meant.
const SUBJECT_KINDS = Object.freeze(['user', 'application']);

class AuthorizationRequest {
  // `options`:
  //   includeInResult  whether each attribute asks to be returned with the
  //                    result (the issuance and access PEPs say yes, the
  //                    reaction PEPs no). Default true.
  //   dropEmpty        whether an empty or absent VALUE is left out of its
  //                    bag rather than sent as ''. Default false: an empty
  //                    subject-id is how several PEPs say "nobody".
  //   returnPolicyIdList  default true.
  constructor(options) {
    log.debug("Entering AuthorizationRequest.constructor().");
    const given = options || {};
    this.includeInResult = given.includeInResult !== false;
    this.dropEmpty = !!given.dropEmpty;
    this.returnPolicyIdList = given.returnPolicyIdList !== false;
    // In the order a category was first named, so a request is built the
    // same every time and a reader of a logged one finds subject first.
    /** @type {Array<{category: string, attributes: any[]}>} */
    this.categories = [];
    log.debug("Leaving AuthorizationRequest.constructor().");
  }

  // The category's entry, made the first time it is named. Naming one with
  // no attributes is how a PEP sends an EMPTY category — the issuance and
  // access PEPs always send the environment, empty or not.
  category(id) {
    log.debug("Entering AuthorizationRequest.category().");
    let found = this.categories.filter(function (one) {
      return one.category === id;
    })[0];
    if (!found) {
      found = { category: id, attributes: [] };
      this.categories.push(found);
    }
    log.debug("Leaving AuthorizationRequest.category().");
    return found;
  }

  // ONE ATTRIBUTE, MULTI-VALUED: a bag rather than a value everywhere,
  // because every one of these genuinely is one. An empty list is sent as an
  // empty bag, which XACML reads as "nobody said" — the same as leaving the
  // attribute out.
  attribute(categoryId, attributeId, values, type) {
    log.debug("Entering AuthorizationRequest.attribute().");
    const self = this;
    const list = (values || []).filter(function (one) {
      return !self.dropEmpty ||
             (one !== undefined && one !== null && String(one) !== '');
    });
    this.category(categoryId).attributes.push({
      attributeId: attributeId,
      issuer: null,
      includeInResult: this.includeInResult,
      values: list.map(function (one) {
        return { type: type || model.TYPE.STRING, lexical: String(one) };
      })
    });
    log.debug("Leaving AuthorizationRequest.attribute().");
    return this;
  }

  // ---------------------------------------------------------------------------
  // THE FOUR CATEGORIES, by name.
  // ---------------------------------------------------------------------------
  subject(attributeId, values, type) {
    log.debug("Entering AuthorizationRequest.subject().");
    log.debug("Leaving AuthorizationRequest.subject().");
    return this.attribute(model.CATEGORY.ACCESS_SUBJECT, attributeId, values,
                          type);
  }

  resource(attributeId, values, type) {
    log.debug("Entering AuthorizationRequest.resource().");
    log.debug("Leaving AuthorizationRequest.resource().");
    return this.attribute(model.CATEGORY.RESOURCE, attributeId, values, type);
  }

  action(attributeId, values, type) {
    log.debug("Entering AuthorizationRequest.action().");
    log.debug("Leaving AuthorizationRequest.action().");
    return this.attribute(model.CATEGORY.ACTION, attributeId, values, type);
  }

  environment(attributeId, values, type) {
    log.debug("Entering AuthorizationRequest.environment().");
    log.debug("Leaving AuthorizationRequest.environment().");
    return this.attribute(model.CATEGORY.ENVIRONMENT, attributeId, values,
                          type);
  }

  // ---------------------------------------------------------------------------
  // THE FIELDS OF #88 SECTION 7.
  // ---------------------------------------------------------------------------

  // principal and principal_type. `kind` is sent only when given, so a PEP
  // whose question is always about a person need not say so.
  principal(name, kind) {
    log.debug("Entering AuthorizationRequest.principal().");
    this.subject(model.ATTRIBUTE.SUBJECT_ID, [name == null ? '' : name]);
    if (kind !== undefined && kind !== null) {
      this.subject(VOCABULARY.SUBJECT_KIND,
                   [SUBJECT_KINDS.indexOf(String(kind)) >= 0 ? String(kind)
                                                             : 'user']);
    }
    log.debug("Leaving AuthorizationRequest.principal().");
    return this;
  }

  // The roles the principal holds.
  roles(held) {
    log.debug("Entering AuthorizationRequest.roles().");
    log.debug("Leaving AuthorizationRequest.roles().");
    return this.subject(VOCABULARY.ROLE, held);
  }

  // target: what is being issued FOR or reached. A string by default — an
  // application handle is a client_id, a wtrealm or an entityID, and only
  // some of those are URIs (`xacml_role_pep.ts` argues it).
  target(id, type) {
    log.debug("Entering AuthorizationRequest.target().");
    log.debug("Leaving AuthorizationRequest.target().");
    return this.resource(model.ATTRIBUTE.RESOURCE_ID, [id], type);
  }

  // requested_actions: the action-id.
  requestedAction(id) {
    log.debug("Entering AuthorizationRequest.requestedAction().");
    log.debug("Leaving AuthorizationRequest.requestedAction().");
    return this.action(model.ATTRIBUTE.ACTION_ID, [id]);
  }

  // requested_scopes: each value, one bag.
  requestedScopes(values) {
    log.debug("Entering AuthorizationRequest.requestedScopes().");
    log.debug("Leaving AuthorizationRequest.requestedScopes().");
    return this.action(VOCABULARY.REQUESTED_SCOPE, values);
  }

  // The client the request came through.
  client(id) {
    log.debug("Entering AuthorizationRequest.client().");
    log.debug("Leaving AuthorizationRequest.client().");
    return this.subject(VOCABULARY.CLIENT_ID, id ? [id] : []);
  }

  // audience / resource indicator(s).
  audience(values) {
    log.debug("Entering AuthorizationRequest.audience().");
    log.debug("Leaving AuthorizationRequest.audience().");
    return this.resource(VOCABULARY.AUDIENCE, values);
  }

  protocol(name) {
    log.debug("Entering AuthorizationRequest.protocol().");
    log.debug("Leaving AuthorizationRequest.protocol().");
    return this.environment(VOCABULARY.PROTOCOL, name ? [name] : []);
  }

  grantType(name) {
    log.debug("Entering AuthorizationRequest.grantType().");
    log.debug("Leaving AuthorizationRequest.grantType().");
    return this.environment(VOCABULARY.GRANT_TYPE, name ? [name] : []);
  }

  // The realm's mode (#305).
  mode(name) {
    log.debug("Entering AuthorizationRequest.mode().");
    log.debug("Leaving AuthorizationRequest.mode().");
    return this.environment(VOCABULARY.MODE, name ? [name] : []);
  }

  // One setting's value (#305): a boolean as a boolean, anything else as a
  // string.
  setting(key, value) {
    log.debug("Entering AuthorizationRequest.setting().");
    const typed = typeof value === 'boolean';
    log.debug("Leaving AuthorizationRequest.setting().");
    return this.environment(VOCABULARY.SETTING_PREFIX + key,
                            value === undefined || value === null ? []
                                                                  : [value],
                            typed ? model.TYPE.BOOLEAN : undefined);
  }

  // The stage a scope is judged at (#305).
  stage(name) {
    log.debug("Entering AuthorizationRequest.stage().");
    log.debug("Leaving AuthorizationRequest.stage().");
    return this.environment(VOCABULARY.SCOPE_STAGE, name ? [name] : []);
  }

  // The party acting between the subject and the resource (XACML 3.0's
  // intermediary-subject category) — a delegation's actor.
  intermediary(name) {
    log.debug("Entering AuthorizationRequest.intermediary().");
    log.debug("Leaving AuthorizationRequest.intermediary().");
    return this.attribute(model.CATEGORY.INTERMEDIARY_SUBJECT,
                          model.ATTRIBUTE.SUBJECT_ID, [name]);
  }

  // THE FACTS OF A TRANSFER QUESTION (#98), each only when known: an empty
  // home or serving jurisdiction and an unknown client country are left out
  // rather than sent as '', because the built-in rule reads "the same
  // jurisdiction" as the two bags sharing a member and an absent fact must
  // never make two cells look alike. `listed` is always sent — it is the
  // realm's own list, and false is a fact.
  transfer(facts) {
    log.debug("Entering AuthorizationRequest.transfer().");
    const given = facts || {};
    const one = function (value) {
      log.debug("Entering one().");
      log.debug("Leaving one().");
      return value ? [String(value)] : [];
    };
    this.subject(VOCABULARY.HOME_JURISDICTION, one(given.home));
    this.environment(VOCABULARY.SERVING_JURISDICTION, one(given.serving));
    this.environment(VOCABULARY.CLIENT_COUNTRY, one(given.clientCountry));
    this.environment(VOCABULARY.TRANSFER_LISTED, [!!given.listed],
                     model.TYPE.BOOLEAN);
    this.resource(VOCABULARY.DATA_CATEGORY, one(given.category));
    this.environment(VOCABULARY.REALM, one(given.realm));
    this.environment(VOCABULARY.PURPOSE, one(given.purpose));
    log.debug("Leaving AuthorizationRequest.transfer().");
    return this;
  }

  // THE FACTS OF AN EXCHANGE QUESTION (#186). `facts` (each optional):
  //   subject { id, kind, roles, notDelegated, groups, semantics,
  //             defaultSemantics }
  //   actor   { id, kind, registered, roles, semantics, defaultSemantics,
  //             delegatesTo, subjectGroups }
  //   source  { id, requiredRoles, delegatesTo }   (S; id '' when unknown)
  //   target  { id, count, registered, requiredRoles, accepts }   (R)
  //   requestedSemantics, semantics, mayActPresent, mayActNamesActor,
  //   protectedGroups
  // An unknown identifier is left out rather than sent as '', so no absent
  // party can ever compare equal to another. Booleans are always sent.
  exchange(facts) {
    const given = facts || {};
    const V = VOCABULARY;
    const I = model.CATEGORY.INTERMEDIARY_SUBJECT;
    const one = function (value) {
      return value ? [String(value)] : [];
    };
    const list = function (values) {
      return (values || []).map(String).filter(function (v) { return !!v; });
    };
    const subject = given.subject || {};
    const actor = given.actor || {};
    const source = given.source || {};
    const target = given.target || {};
    this.subject(model.ATTRIBUTE.SUBJECT_ID, one(subject.id));
    this.subject(V.SUBJECT_KIND, [subject.kind === 'application'
      ? 'application' : 'user']);
    this.subject(V.ROLE, list(subject.roles));
    this.subject(V.EXCHANGE_SUBJECT_NOT_DELEGATED, [!!subject.notDelegated],
                 model.TYPE.BOOLEAN);
    this.subject(V.EXCHANGE_SUBJECT_GROUP, list(subject.groups));
    this.subject(V.EXCHANGE_ALLOWED_SEMANTICS, list(subject.semantics));
    this.subject(V.EXCHANGE_DEFAULT_SEMANTICS, one(subject.defaultSemantics));
    this.subject(V.EXCHANGE_SUBJECT_DELEGATE, list(subject.delegates));
    this.attribute(I, model.ATTRIBUTE.SUBJECT_ID, one(actor.id));
    this.attribute(I, V.EXCHANGE_ACTOR_KIND, [actor.kind === 'user'
      ? 'user' : 'application']);
    this.attribute(I, V.EXCHANGE_ACTOR_REGISTERED, [!!actor.registered],
                   model.TYPE.BOOLEAN);
    this.attribute(I, V.ROLE, list(actor.roles));
    this.attribute(I, V.EXCHANGE_ALLOWED_SEMANTICS, list(actor.semantics));
    this.attribute(I, V.EXCHANGE_DEFAULT_SEMANTICS,
                   one(actor.defaultSemantics));
    this.attribute(I, V.EXCHANGE_ACTOR_DELEGATES_TO, list(actor.delegatesTo));
    this.attribute(I, V.EXCHANGE_ACTOR_SUBJECT_GROUP,
                   list(actor.subjectGroups));
    this.resource(model.ATTRIBUTE.RESOURCE_ID, one(target.id));
    this.resource(V.EXCHANGE_TARGET_COUNT, [Number(target.count) || 0],
                  model.TYPE.INTEGER);
    this.resource(V.EXCHANGE_TARGET_REGISTERED, [!!target.registered],
                  model.TYPE.BOOLEAN);
    this.resource(V.EXCHANGE_TARGET_REQUIRED_ROLE, list(target.requiredRoles));
    this.resource(V.EXCHANGE_TARGET_ACCEPTS, list(target.accepts));
    this.resource(V.EXCHANGE_SOURCE, one(source.id));
    this.resource(V.EXCHANGE_SOURCE_REQUIRED_ROLE,
                  list(source.requiredRoles));
    this.resource(V.EXCHANGE_SOURCE_DELEGATES_TO, list(source.delegatesTo));
    this.action(V.EXCHANGE_REQUESTED_SEMANTICS,
                one(given.requestedSemantics));
    this.action(V.EXCHANGE_SEMANTICS, one(given.semantics));
    this.environment(V.EXCHANGE_MAY_ACT_PRESENT, [!!given.mayActPresent],
                     model.TYPE.BOOLEAN);
    this.environment(V.EXCHANGE_MAY_ACT_NAMES_ACTOR,
                     [!!given.mayActNamesActor], model.TYPE.BOOLEAN);
    this.environment(V.EXCHANGE_PROTECTED_GROUP, list(given.protectedGroups));
    return this;
  }

  // THE FACTS OF A PASSKEY QUESTION (#536). `facts` (each optional):
  //   groups          the fact groups carried (see PASSKEY_FACTS)
  //   backupEligible  a boolean; sent only with `backup-eligible`
  //   minPinLength    a whole number; sent only with `pin-length`, and left
  //                   out when the key reported none
  //   serial, serialHeld                       with `serial`
  //   attestation { verified, trusted, aaguid, listed, compromised, rank,
  //                 fips, unchecked }          with `attestation`
  //   policy { backupEligibility, enforcePinLength, minPinLength,
  //            pinLengthOnlyIfSupported, enforceAttestationAtSignIn,
  //            enterpriseSerialAttribute }     always
  //   settings { attestationPolicy, allowedAaguids, requiredRank,
  //              requireFips }                 with `attestation`
  // An empty string and an unknown value are left out, never sent as '', so
  // no rule reads an absent fact as a value.
  passkey(facts) {
    log.debug("Entering AuthorizationRequest.passkey().");
    const given = facts || {};
    const V = VOCABULARY;
    const T = model.TYPE;
    const groups = (given.groups || []).map(String);
    const has = function (group) {
      log.debug("Entering has().");
      log.debug("Leaving has().");
      return groups.indexOf(group) >= 0;
    };
    const whole = function (value) {
      log.debug("Entering whole().");
      log.debug("Leaving whole().");
      return typeof value === 'number' && Number.isInteger(value)
        ? [value] : [];
    };
    const one = function (value) {
      log.debug("Entering one().");
      log.debug("Leaving one().");
      return value === undefined || value === null || String(value) === ''
        ? [] : [String(value)];
    };
    this.environment(V.PASSKEY_FACTS, groups);
    if (has('backup-eligible') && typeof given.backupEligible === 'boolean') {
      this.resource(V.PASSKEY_BACKUP_ELIGIBLE, [given.backupEligible],
                    T.BOOLEAN);
    }
    if (has('pin-length')) {
      this.resource(V.PASSKEY_MIN_PIN_LENGTH, whole(given.minPinLength),
                    T.INTEGER);
    }
    if (has('serial')) {
      this.resource(V.PASSKEY_SERIAL, one(given.serial));
      this.resource(V.PASSKEY_SERIAL_HELD, [!!given.serialHeld], T.BOOLEAN);
    }
    const att = given.attestation || null;
    if (has('attestation') && att) {
      this.resource(V.PASSKEY_ATTESTATION_VERIFIED, [!!att.verified],
                    T.BOOLEAN);
      this.resource(V.PASSKEY_ATTESTATION_TRUSTED, [!!att.trusted],
                    T.BOOLEAN);
      this.resource(V.PASSKEY_AAGUID, one(att.aaguid));
      const flag = function (value) {
        log.debug("Entering flag().");
        log.debug("Leaving flag().");
        return typeof value === 'boolean' ? [value] : [];
      };
      this.resource(V.PASSKEY_MODEL_LISTED,
                    flag(att.listed), T.BOOLEAN);
      this.resource(V.PASSKEY_MODEL_COMPROMISED,
                    flag(att.compromised), T.BOOLEAN);
      this.resource(V.PASSKEY_CERTIFICATION_RANK, whole(att.rank), T.INTEGER);
      this.resource(V.PASSKEY_FIPS, flag(att.fips), T.BOOLEAN);
      this.resource(V.PASSKEY_METADATA_UNCHECKED, att.unchecked ? [true] : [],
                    T.BOOLEAN);
    }
    const policy = given.policy || {};
    const P = V.PASSKEY_POLICY_PREFIX;
    this.environment(P + 'backupEligibility', one(policy.backupEligibility));
    this.environment(P + 'enforcePinLength', [policy.enforcePinLength === true],
                     T.BOOLEAN);
    this.environment(P + 'minPinLength', whole(policy.minPinLength),
                     T.INTEGER);
    this.environment(P + 'pinLengthOnlyIfSupported',
                     [policy.pinLengthOnlyIfSupported === true], T.BOOLEAN);
    this.environment(P + 'enforceAttestationAtSignIn',
                     [policy.enforceAttestationAtSignIn === true], T.BOOLEAN);
    this.environment(P + 'enterpriseSerialAttribute',
                     one(policy.enterpriseSerialAttribute));
    const settings = given.settings || null;
    if (has('attestation') && settings) {
      this.setting('webauthn.attestationPolicy',
                   String(settings.attestationPolicy || ''));
      this.environment(V.SETTING_PREFIX + 'webauthn.attestationAllowedAaguids',
                       (settings.allowedAaguids || []).map(String));
      this.environment(V.PASSKEY_REQUIRED_RANK,
                       Number(settings.requiredRank) > 0
                         ? [Number(settings.requiredRank)] : [], T.INTEGER);
      this.setting('webauthn.attestationRequireFips',
                   settings.requireFips === true);
    }
    log.debug("Leaving AuthorizationRequest.passkey().");
    return this;
  }

  // THE FACTS OF A GNAP ACCESS RIGHT (#432 phase 3). `facts` (each optional):
  //   right     { kind, type, actions, locations, datatypes, identifier,
  //               privileges, listed, referenceRegistered, protected,
  //               protectedDeclared, limits: { json, amount, currency,
  //               count, receivers, interval, notBefore, notAfter } }
  //   owner     { known, owner, source, unresolved, matches } (#432
  //               phase 5)
  //   catalogue { catalogued, owner, bearer (null when undeclared),
  //               maxLifetimeS (null when undeclared), acr, interaction,
  //               consentActions, derivableFrom, introspectionClaims }
  //   token     { label, bearer, format, targets }
  //   client    { id, class, hasAllowedAccess, bearerRefused }
  //   approver, approval
  //   session   { acr, amr }, risk { level, signals },
  //   device    { recognized, status, compliance, attestation, ownerMatches }
  // A fact that is not known is left out rather than sent empty, so a rule
  // reading it is inapplicable — `boolean-is-in` over an empty bag is false.
  // The resource-id, principal, action-id, mode, stage and settings are the
  // caller's, through the methods above.
  gnapRight(facts) {
    log.debug("Entering AuthorizationRequest.gnapRight().");
    const given = facts || {};
    const V = VOCABULARY;
    const B = model.TYPE.BOOLEAN;
    const one = function (value) {
      log.debug("Entering one().");
      log.debug("Leaving one().");
      return value ? [String(value)] : [];
    };
    const list = function (values) {
      log.debug("Entering list().");
      log.debug("Leaving list().");
      return (Array.isArray(values) ? values : []).map(String)
        .filter(function (v) { return !!v; });
    };
    const bool = function (value) {
      log.debug("Entering bool().");
      log.debug("Leaving bool().");
      return typeof value === 'boolean' ? [value] : [];
    };
    const right = given.right || {};
    const catalogue = given.catalogue || {};
    const token = given.token || {};
    const client = given.client || {};
    const session = given.session || {};
    const risk = given.risk || {};
    const device = given.device || {};
    this.resource(V.GNAP_RIGHT_KIND, one(right.kind));
    this.resource(V.GNAP_RIGHT_ACTION, list(right.actions));
    this.resource(V.GNAP_RIGHT_LOCATION, list(right.locations));
    this.resource(V.GNAP_RIGHT_DATATYPE, list(right.datatypes));
    this.resource(V.GNAP_RIGHT_IDENTIFIER, one(right.identifier));
    this.resource(V.GNAP_RIGHT_PRIVILEGE, list(right.privileges));
    this.resource(V.GNAP_RIGHT_LISTED, bool(right.listed), B);
    this.resource(V.GNAP_REFERENCE_REGISTERED,
                  bool(right.referenceRegistered), B);
    this.resource(V.GNAP_PROTECTED, bool(right.protected), B);
    this.resource(V.GNAP_PROTECTED_DECLARED, bool(right.protectedDeclared), B);
    const limits = right.limits || null;
    if (limits) {
      this.resource(V.GNAP_LIMITS, one(limits.json));
      this.resource(V.GNAP_LIMIT_AMOUNT, typeof limits.amount === 'number'
        ? [limits.amount] : [], model.TYPE.DOUBLE);
      this.resource(V.GNAP_LIMIT_CURRENCY, one(limits.currency));
      this.resource(V.GNAP_LIMIT_COUNT, typeof limits.count === 'number'
        ? [limits.count] : [], model.TYPE.INTEGER);
      this.resource(V.GNAP_LIMIT_RECEIVER, list(limits.receivers));
      this.resource(V.GNAP_LIMIT_INTERVAL, one(limits.interval));
      this.resource(V.GNAP_LIMIT_NOT_BEFORE, one(limits.notBefore));
      this.resource(V.GNAP_LIMIT_NOT_AFTER, one(limits.notAfter));
    }
    const owner = given.owner || {};
    this.resource(V.GNAP_OWNER_KNOWN, bool(owner.known), B);
    this.resource(V.GNAP_OWNER, one(owner.owner));
    this.resource(V.GNAP_OWNER_SOURCE, one(owner.source));
    this.resource(V.GNAP_OWNER_UNRESOLVED, bool(owner.unresolved), B);
    this.resource(V.GNAP_OWNER_MATCHES, bool(owner.matches), B);
    this.resource(V.GNAP_CATALOGUED, bool(catalogue.catalogued), B);
    this.resource(V.GNAP_TYPE_OWNER, one(catalogue.owner));
    this.resource(V.GNAP_TYPE_BEARER, bool(catalogue.bearer), B);
    this.resource(V.GNAP_TYPE_MAX_LIFETIME,
                  typeof catalogue.maxLifetimeS === 'number'
                    ? [catalogue.maxLifetimeS] : [], model.TYPE.INTEGER);
    this.resource(V.GNAP_TYPE_ACR, one(catalogue.acr));
    this.resource(V.GNAP_TYPE_INTERACTION, one(catalogue.interaction));
    this.resource(V.GNAP_TYPE_CONSENT_ACTION, list(catalogue.consentActions));
    this.resource(V.GNAP_TYPE_DERIVABLE_FROM, list(catalogue.derivableFrom));
    this.resource(V.GNAP_TYPE_INTROSPECTION_CLAIM,
                  list(catalogue.introspectionClaims));
    this.action(V.GNAP_TOKEN_LABEL, one(token.label));
    this.action(V.GNAP_TOKEN_BEARER, bool(token.bearer), B);
    this.action(V.GNAP_TOKEN_FORMAT, one(token.format));
    this.action(V.GNAP_TOKEN_TARGET, list(token.targets));
    this.subject(V.CLIENT_ID, one(client.id));
    this.subject(V.GNAP_CLIENT_CLASS, one(client.class));
    this.subject(V.GNAP_CLIENT_HAS_ALLOWED_ACCESS,
                 bool(client.hasAllowedAccess), B);
    this.subject(V.GNAP_CLIENT_BEARER_REFUSED, bool(client.bearerRefused), B);
    this.environment(V.GNAP_APPROVER, one(given.approver));
    this.environment(V.GNAP_APPROVAL, one(given.approval));
    this.environment(V.GNAP_SESSION_ACR, one(session.acr));
    this.environment(V.GNAP_SESSION_AMR, list(session.amr));
    this.environment(V.GNAP_RISK_LEVEL, one(risk.level));
    this.environment(V.GNAP_RISK_SIGNAL, list(risk.signals));
    this.environment(V.GNAP_DEVICE_RECOGNIZED, bool(device.recognized), B);
    this.environment(V.GNAP_DEVICE_STATUS, one(device.status));
    this.environment(V.GNAP_DEVICE_COMPLIANCE, one(device.compliance));
    this.environment(V.GNAP_DEVICE_ATTESTATION, one(device.attestation));
    this.environment(V.GNAP_DEVICE_OWNER_MATCHES, bool(device.ownerMatches),
                     B);
    log.debug("Leaving AuthorizationRequest.gnapRight().");
    return this;
  }

  // The request, in the engine's shape (`xacml_model.js`).
  build() {
    log.debug("Entering AuthorizationRequest.build().");
    const out = {
      returnPolicyIdList: this.returnPolicyIdList,
      combinedDecision: false,
      categories: this.categories.map(function (one) {
        return { category: one.category, id: null, content: null,
                 attributes: one.attributes.slice(0) };
      })
    };
    log.debug("Leaving AuthorizationRequest.build(). " +
              out.categories.length + " categories.");
    return out;
  }
}

module.exports = {
  AuthorizationRequest: AuthorizationRequest,
  VOCABULARY: VOCABULARY,
  SUBJECT_KINDS: SUBJECT_KINDS
};
