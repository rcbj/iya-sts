// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

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
  REALM: 'urn:sts:xacml:realm'
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
