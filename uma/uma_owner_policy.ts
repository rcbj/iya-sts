// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: uma_owner_policy.ts
//
// ===========================================================================
// A RESOURCE OWNER'S OWN POLICY (#1168 phase 3, #1192): a real XACML
// document per owner, authored by a form.
//
// **THE DOCUMENT IS THE SOURCE OF TRUTH, AND NOTHING STRUCTURED IS STORED
// BESIDE IT.** Every share the portal's form saves is ONE Rule of a fixed
// shape, and the page reads the document back and draws every Rule of that
// shape as a card:
//
//   RuleId      `share:<id>`
//   Effect      Permit
//   Target      resource-id == the resource's `_id`, AND action-id == one
//               of the scopes (on the owner's layer the action-id IS the
//               scope — `uma/CLAUDE.md` argues it)
//   Condition   the recipient — a person (`subject-id` is their
//               `urn:uuid:` subject), a group (the group's DN is in
//               `urn:sts:xacml:uma:requesting-party-group`), anyone signed
//               in to this realm (`requesting-party-known`), or anyone whose
//               gathered claim X is Y (`urn:sts:xacml:uma:claim:X`) — AND
//               `current-dateTime` before an expiry, AND a required `acr`,
//               each only when asked for
//   Obligation  `urn:sts:xacml:obligation:uma-approval` for *Ask me each
//               time* (phase 5 discharges it)
//
// A RULE IS A SHARE ONLY IF IT IS EXACTLY WHAT THE FORM WOULD WRITE.
// `specOf()` reads the fields off a rule and rebuilds the rule from them; the
// two must be the same XML, or the rule is drawn as *A custom rule* with its
// ALFA, read-only — unless `uma.ownerAlfaEditing` is on (rcbj's decision 2),
// when the owner edits the whole document as ALFA. So a hand edit can never
// make a card say something the rule does not.
//
// THE DOCUMENT LIVES IN `uma.ownerPolicies` (decision 1), keyed by the owner
// — a person's subject, or an application's identifier (decision 5) —
// created from the `uma-owner-default` template at the first share; never in
// `ou=policies`, never the root, never in `repository()`'s map, never pulled
// by a remote PEP. Bounded by `uma.maxOwnerPolicyBytes` and
// `uma.maxOwnerRules` at the store's one writer.
//
// **AN OWNER'S POLICY IS ONLY EVER ASKED ABOUT THE OWNER'S OWN RESOURCES**
// (phase 4 pins the resource in the trusted facts), so the worst a
// hand-written rule can do is share what its author owns.
//
// Withdrawing reaches the tokens (decision 11): removing a share revokes the
// RPTs that carried a permission over its resource and scopes; an ALFA edit
// revokes every RPT over the owner's resources, because nothing here can say
// which rule a hand edit narrowed.
//
// A LIBRARY (rule 3): no route. The portal reaches it lazily.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import model = require('../xacml/xacml_model');
import xacmlRequest = require('../xacml/xacml_request');
import templates = require('../xacml/xacml_templates');
import umaStore = require('./uma_store');

const { log } = helpers;

type Json = any;

const V = xacmlRequest.VOCABULARY;
const U = templates.UMA_ATTRIBUTE;
const B = templates.PolicyBuilders;
const F1 = 'urn:oasis:names:tc:xacml:1.0:function:';
const TYPE = model.TYPE;
const S = model.CATEGORY.ACCESS_SUBJECT;

// The kinds of recipient the form offers.
const RECIPIENTS = Object.freeze(['person', 'group', 'realm', 'claim']);

// A claim name a share may test, and an acr value.
const CLAIM_NAME = /^[A-Za-z0-9_.:-]{1,64}$/;
const ACR_VALUE = /^[\x21-\x7e]{1,128}$/;
const PRINTABLE = /^[^\x00-\x1f\x7f]{1,256}$/;

/** One share, as the form writes it and the page draws it. */
interface ShareSpec {
  id: string;
  resourceId: string;
  scopes: string[];
  recipient: { kind: string; value: string; claim?: string;
               label?: string };
  expires: string;
  acr: string;
  askMe: boolean;
}

interface OwnerPolicyDeps {
  log: typeof log;
  config: typeof config;
  errorCodes: typeof errorCodes;
  store: Json;
  templates: typeof templates;
  randomId(bytes: number): string;
  now(): number;
  loadXml(): Json;
  loadAlfa(): Json;
  loadDirectory(): Json;
  subjectForName(name: string): string;
  nameForSubject(sub: string): string;
}

/**
 * A resource owner's own UMA document: read, written by the share form,
 * read back as cards, edited as ALFA where the realm allows.
 */
class UmaOwnerPolicy {
  /** The kinds of recipient a share may name. */
  static readonly RECIPIENTS = RECIPIENTS;

  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the logger, settings, error codes, the store, the
   *   templates, ids, the clock, and lazy loaders for the XML writer, ALFA
   *   and the directory
   */
  constructor(private readonly deps: OwnerPolicyDeps) {
    deps.log.debug("Entering UmaOwnerPolicy.constructor().");
    deps.log.debug("Leaving UmaOwnerPolicy.constructor().");
  }

  /**
   * The dependencies built from the real modules.
   *
   * @returns the dependencies
   */
  static defaultDeps(): OwnerPolicyDeps {
    log.debug("Entering UmaOwnerPolicy.defaultDeps().");
    log.debug("Leaving UmaOwnerPolicy.defaultDeps().");
    return {
      log: log,
      config: config,
      errorCodes: errorCodes,
      store: umaStore,
      templates: templates,
      randomId: helpers.randomId,
      now: function (): number {
        return Date.now();
      },
      loadXml: function (): Json {
        log.debug("Entering loadXml().");
        log.debug("Leaving loadXml().");
        return require('../xacml/xacml_xml');
      },
      loadAlfa: function (): Json {
        log.debug("Entering loadAlfa().");
        log.debug("Leaving loadAlfa().");
        return require('../xacml/xacml_alfa');
      },
      loadDirectory: function (): Json {
        log.debug("Entering loadDirectory().");
        log.debug("Leaving loadDirectory().");
        return require('../ldap/ldap_server');
      },
      subjectForName: helpers.subjectForName,
      nameForSubject: helpers.nameForSubject
    };
  }

  // -------------------------------------------------------------------------
  // THE RULE A SHARE IS, and the share a rule is.
  // -------------------------------------------------------------------------
  /**
   * The rule a share is written as: the one fixed shape.
   *
   * @param spec - the share
   * @returns the rule's model
   */
  static ruleFor(spec: ShareSpec): Json {
    log.debug("Entering UmaOwnerPolicy.ruleFor().");
    const target = B.targetOf([
      [B.match(F1 + 'string-equal', B.value(TYPE.STRING, spec.resourceId),
               B.designator(model.CATEGORY.RESOURCE,
                            model.ATTRIBUTE.RESOURCE_ID, TYPE.STRING))],
      spec.scopes.map(function (scope: string) {
        return B.match(F1 + 'string-equal', B.value(TYPE.STRING, scope),
                       B.designator(model.CATEGORY.ACTION,
                                    model.ATTRIBUTE.ACTION_ID, TYPE.STRING));
      })
    ]);
    const isIn = function (value: string, attributeId: string): Json {
      log.debug("Entering isIn().");
      log.debug("Leaving isIn().");
      return B.apply(F1 + 'string-is-in', [
        B.value(TYPE.STRING, value),
        B.designator(S, attributeId, TYPE.STRING)]);
    };
    const parts: Json[] = [];
    const r = spec.recipient;
    if (r.kind === 'person') {
      parts.push(isIn(r.value, model.ATTRIBUTE.SUBJECT_ID));
    } else if (r.kind === 'group') {
      parts.push(isIn(r.value, V.UMA_REQUESTING_PARTY_GROUP));
    } else if (r.kind === 'claim') {
      parts.push(isIn(r.value, V.UMA_CLAIM_PREFIX + String(r.claim || '')));
    } else {
      parts.push(B.holdsTrue(S, V.UMA_REQUESTING_PARTY_KNOWN));
    }
    if (spec.expires) {
      parts.push(B.apply(F1 + 'dateTime-less-than', [
        B.apply(F1 + 'dateTime-one-and-only', [
          B.designator(model.CATEGORY.ENVIRONMENT,
                       model.ATTRIBUTE.CURRENT_DATETIME, TYPE.DATETIME)]),
        B.value(TYPE.DATETIME, spec.expires)]));
    }
    if (spec.acr) {
      parts.push(isIn(spec.acr, V.ACR));
    }
    const rule = {
      id: U.SHARE_RULE_PREFIX + spec.id,
      effect: model.EFFECT.PERMIT,
      description: UmaOwnerPolicy.describe(spec),
      target: target,
      condition: parts.length === 1 ? parts[0] : B.apply(F1 + 'and', parts),
      obligations: spec.askMe
        ? [{ id: U.APPROVAL_OBLIGATION, on: model.EFFECT.PERMIT,
             assignments: [] }]
        : [],
      advice: []
    };
    log.debug("Leaving UmaOwnerPolicy.ruleFor().");
    return rule;
  }

  /**
   * The sentence a share's rule carries as its Description: what it allows,
   * in words, so the document reads on its own in the policy editor.
   *
   * @param spec - the share
   * @returns the sentence
   */
  static describe(spec: ShareSpec): string {
    log.debug("Entering UmaOwnerPolicy.describe().");
    const r = spec.recipient;
    const who = r.kind === 'person' ? 'the person ' + r.value
      : (r.kind === 'group' ? 'members of the group ' + r.value
        : (r.kind === 'claim' ? 'anyone whose claim ' + r.claim + ' is ' +
                                r.value
          : 'anyone signed in to this realm'));
    const out = 'A share of the resource ' + spec.resourceId + ' (' +
      spec.scopes.join(', ') + ') with ' + who +
      (spec.expires ? ', until ' + spec.expires : '') +
      (spec.acr ? ', at authentication level ' + spec.acr : '') +
      (spec.askMe ? ', asking the owner each time' : '') + '.';
    log.debug("Leaving UmaOwnerPolicy.describe().");
    return out;
  }

  // The lexical form of a parsed value node, whatever its datatype kept.
  private static lexicalOf(node: Json): string {
    if (!node) {
      return '';
    }
    if (node.lexical !== undefined) {
      return String(node.lexical);
    }
    if (node.value && node.value.lexical !== undefined) {
      return String(node.value.lexical);
    }
    return String(node.value === undefined ? '' : node.value);
  }

  // A rule wrapped in a policy and written: the one comparison of a rule
  // the form wrote with one it reads.
  private ruleXml(rule: Json): string {
    const { log } = this.deps;
    log.debug("Entering UmaOwnerPolicy.ruleXml().");
    const out = String(this.deps.loadXml().writePolicy({
      kind: 'Policy', id: 'urn:sts:uma:compare', version: '1.0',
      description: '', combiningAlgId: model.RULE_ALG.DENY_UNLESS_PERMIT,
      target: null, variables: {}, rules: [rule], obligations: [],
      advice: [] }));
    log.debug("Leaving UmaOwnerPolicy.ruleXml().");
    return out;
  }

  /**
   * The share a rule is, or null when it is not EXACTLY what the form
   * writes — a custom rule.
   *
   * @param rule - a rule of the document, as the parser answers it
   * @returns the share, or null
   */
  specOf(rule: Json): ShareSpec | null {
    const { log } = this.deps;
    log.debug("Entering UmaOwnerPolicy.specOf().");
    const lex = UmaOwnerPolicy.lexicalOf;
    try {
      const id = String((rule && rule.id) || '');
      if (id.indexOf(U.SHARE_RULE_PREFIX) !== 0 ||
          rule.effect !== model.EFFECT.PERMIT || !rule.target ||
          !rule.condition) {
        log.debug("Leaving UmaOwnerPolicy.specOf(). Not a share's shape.");
        return null;
      }
      const anyOf = rule.target.anyOf || [];
      const resourceId = lex(anyOf[0].allOf[0].matches[0].value);
      const scopes = (anyOf[1].allOf || []).map(function (a: Json) {
        return lex(a.matches[0].value);
      });
      const cond = rule.condition;
      const parts = /:and$/.test(String(cond.functionId)) ? cond.args
                                                          : [cond];
      const spec: ShareSpec = { id: id.slice(U.SHARE_RULE_PREFIX.length),
        resourceId: resourceId, scopes: scopes,
        recipient: { kind: '', value: '' }, expires: '', acr: '',
        askMe: (rule.obligations || []).some(function (o: Json) {
          return o.id === U.APPROVAL_OBLIGATION;
        }) };
      parts.forEach(function (part: Json, i: number) {
        const fn = String(part.functionId || '');
        if (/:string-is-in$/.test(fn)) {
          const attr = String(part.args[1].attributeId || '');
          const value = lex(part.args[0]);
          if (attr === V.ACR && i > 0) {
            spec.acr = value;
          } else if (attr === model.ATTRIBUTE.SUBJECT_ID) {
            spec.recipient = { kind: 'person', value: value };
          } else if (attr === V.UMA_REQUESTING_PARTY_GROUP) {
            spec.recipient = { kind: 'group', value: value };
          } else if (attr.indexOf(V.UMA_CLAIM_PREFIX) === 0) {
            spec.recipient = { kind: 'claim', value: value,
                               claim: attr.slice(V.UMA_CLAIM_PREFIX.length) };
          }
        } else if (/:any-of$/.test(fn)) {
          spec.recipient = { kind: 'realm', value: '' };
        } else if (/:dateTime-less-than$/.test(fn)) {
          spec.expires = lex(part.args[1]);
        }
      });
      if (!spec.recipient.kind) {
        log.debug("Leaving UmaOwnerPolicy.specOf(). No recipient.");
        return null;
      }
      const same = this.ruleXml(UmaOwnerPolicy.ruleFor(spec)) ===
                   this.ruleXml(rule);
      log.debug("Leaving UmaOwnerPolicy.specOf(). " +
                (same ? 'A share.' : 'A custom rule.'));
      return same ? spec : null;
    } catch (e) {
      log.debug("Caught in UmaOwnerPolicy.specOf(): " +
                ((e && e.message) || e));
      log.debug("Leaving UmaOwnerPolicy.specOf(). Not readable as a share.");
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // THE DOCUMENT.
  // -------------------------------------------------------------------------
  /**
   * An owner's document, parsed: the stored one, or the default the first
   * share will start from.
   *
   * @param owner - the owner's key
   * @returns `{ policy, stored, version, updatedAt }`
   * @throws when the stored document will not parse — a fault the caller
   *   reports under STS-UMA-0309, never a document that shares nothing
   */
  documentOf(owner: string): Json {
    const { log, store, templates } = this.deps;
    log.debug("Entering UmaOwnerPolicy.documentOf().");
    const row = store.ownerPolicy(owner);
    if (row) {
      const policy = this.deps.loadXml().parsePolicy(String(row.document));
      log.debug("Leaving UmaOwnerPolicy.documentOf(). Stored.");
      return { policy: policy, stored: true, version: row.version,
               updatedAt: row.updatedAt };
    }
    const built = templates.build(U.OWNER_TEMPLATE, { owner: owner },
                                  { name: 'uma-owner' });
    log.debug("Leaving UmaOwnerPolicy.documentOf(). The default.");
    return { policy: built.policy, stored: false, version: '1.0',
             updatedAt: 0 };
  }

  /**
   * An owner's document as XACML XML, or '' when there is none yet: what
   * phase 4 decides with and the console's editor opens.
   *
   * @param owner - the owner's key
   * @returns the document
   */
  documentXml(owner: string): string {
    const { log, store } = this.deps;
    log.debug("Entering UmaOwnerPolicy.documentXml().");
    const row = store.ownerPolicy(owner);
    log.debug("Leaving UmaOwnerPolicy.documentXml(). " + !!row);
    return row ? String(row.document) : '';
  }

  // The next version: the document's own `1.N`, counted on.
  private static nextVersion(version: string): string {
    const parts = String(version || '1.0').split('.');
    const minor = Number(parts[parts.length - 1]);
    return (parts.length > 1 ? parts.slice(0, -1).join('.') : '1') + '.' +
      (Number.isFinite(minor) ? minor + 1 : 1);
  }

  // Writes a policy model as the owner's document, version counted on.
  private write(owner: string, policy: Json): Json {
    const { log, store } = this.deps;
    log.debug("Entering UmaOwnerPolicy.write().");
    const next = Object.assign({}, policy, {
      id: templates.umaOwnerPolicyId(owner),
      version: UmaOwnerPolicy.nextVersion(policy.version) });
    const xml = this.deps.loadXml();
    const document = String(xml.writePolicy(next));
    // Parsed back before it is kept: a document that will not validate
    // never becomes the owner's.
    xml.parsePolicy(document);
    const rules = next.kind === 'Policy' ? (next.rules || []).length
      : UmaOwnerPolicy.countRules(next);
    const saved = store.saveOwnerPolicy(owner, document,
                                        { version: next.version,
                                          rules: rules });
    log.debug("Leaving UmaOwnerPolicy.write(). " + !!saved.ok);
    return saved;
  }

  // The rules of a PolicySet, counted through its children.
  private static countRules(node: Json): number {
    if (!node) {
      return 0;
    }
    if (node.kind === 'Policy') {
      return (node.rules || []).length;
    }
    return (node.children || []).reduce(function (n: number, c: Json) {
      return n + UmaOwnerPolicy.countRules(c);
    }, 0);
  }

  /**
   * What `/portal/shared` draws about an owner's document: the shares as
   * cards, the custom rules with their ALFA, and the whole document as
   * ALFA where the owner may edit it.
   *
   * @param owner - the owner's key
   * @returns `{ ok, shares, custom, version, rules, alfaEditing, alfa }`,
   *   or `{ ok: false, code, why }` for a document that will not parse
   */
  view(owner: string): Json {
    const self = this;
    const { log, config, errorCodes } = this.deps;
    log.debug("Entering UmaOwnerPolicy.view().");
    let doc: Json;
    try {
      doc = self.documentOf(owner);
    } catch (e) {
      log.error(errorCodes.tag('STS-UMA-0309') + 'uma: the document of ' +
                'the owner "' + owner + '" does not parse: ' +
                ((e && e.message) || e));
      log.debug("Leaving UmaOwnerPolicy.view(). Unreadable.");
      return { ok: false, code: 'STS-UMA-0309',
               why: 'Your sharing policy could not be read.' };
    }
    const alfa = self.deps.loadAlfa();
    const editing = config.value('uma.ownerAlfaEditing') === true;
    const rules: Json[] = doc.policy.kind === 'Policy'
      ? (doc.policy.rules || []) : [];
    const shares: Json[] = [];
    const custom: Json[] = [];
    rules.forEach(function (rule: Json) {
      if (rule.id === U.OWNER_SELF_RULE) {
        return;
      }
      const spec = self.specOf(rule);
      if (spec) {
        shares.push(self.withLabel(spec));
        return;
      }
      let text = '';
      try {
        text = String(alfa.write({ kind: 'Policy', id: 'custom',
          version: '1.0', description: '',
          combiningAlgId: model.RULE_ALG.DENY_UNLESS_PERMIT, target: null,
          variables: {}, rules: [rule], obligations: [], advice: [] }));
      } catch (e) {
        log.debug("Caught in UmaOwnerPolicy.view(): " +
                  ((e && e.message) || e));
        text = '';
      }
      custom.push({ id: String(rule.id || ''), description:
                    String(rule.description || ''), alfa: text });
    });
    if (doc.policy.kind !== 'Policy') {
      custom.push({ id: String(doc.policy.id || ''), description: 'A ' +
                    'policy set, written as ALFA.', alfa: '' });
    }
    let whole = '';
    if (editing) {
      try {
        whole = String(alfa.write(doc.policy));
      } catch (e) {
        log.debug("Caught in UmaOwnerPolicy.view(): " +
                  ((e && e.message) || e));
        whole = '';
      }
    }
    log.debug("Leaving UmaOwnerPolicy.view(). " + shares.length +
              " share(s).");
    return { ok: true, stored: doc.stored, version: doc.version,
             rules: UmaOwnerPolicy.countRules(doc.policy),
             shares: shares, custom: custom, alfaEditing: editing,
             alfa: whole };
  }

  // A share with the recipient's name for a reader: a person's username
  // for their subject, a group's name for its DN.
  private withLabel(spec: ShareSpec): Json {
    const { log } = this.deps;
    log.debug("Entering UmaOwnerPolicy.withLabel().");
    const out: Json = JSON.parse(JSON.stringify(spec));
    if (spec.recipient.kind === 'person') {
      out.recipient.label = this.deps.nameForSubject(spec.recipient.value) ||
        spec.recipient.value;
    } else if (spec.recipient.kind === 'group') {
      const cn = /^cn=([^,]+)/i.exec(spec.recipient.value);
      out.recipient.label = cn ? cn[1] : spec.recipient.value;
    }
    log.debug("Leaving UmaOwnerPolicy.withLabel().");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE FORM'S ACTS.
  // -------------------------------------------------------------------------
  /**
   * Reads the share form into a share, or why it cannot be one.
   *
   * @param owner - the owner's key
   * @param given - `resource`, `scopes`, `recipientKind`, `recipient`,
   *   `claim`, `expires`, `acr`, `askMe`
   * @returns `{ spec }`, or `{ code, why }`
   */
  readShare(owner: string, given: Json): Json {
    const self = this;
    const { log, store, config } = this.deps;
    log.debug("Entering UmaOwnerPolicy.readShare().");
    const g = given || {};
    const refuse = function (code: string, why: string): Json {
      log.debug("Entering refuse(). " + code);
      log.debug("Leaving refuse().");
      return { code: code, why: why };
    };
    const resource = store.resource(String(g.resource || ''));
    if (!resource || String(resource.owner) !== String(owner)) {
      log.debug("Leaving UmaOwnerPolicy.readShare(). Not theirs.");
      return refuse('STS-UMA-0300', 'That is not one of your registered ' +
                    'resources.');
    }
    const asked: string[] = [].concat(g.scopes || []).map(String)
      .filter(Boolean);
    const registered: string[] = resource.resource_scopes || [];
    const scopes = registered.filter(function (s: string) {
      return asked.indexOf(s) >= 0;
    });
    if (!asked.length || scopes.length !== asked.filter(function (s, i, a) {
      return a.indexOf(s) === i;
    }).length) {
      log.debug("Leaving UmaOwnerPolicy.readShare(). Bad scopes.");
      return refuse('STS-UMA-0301', 'Choose at least one of the scopes the ' +
                    'resource was registered with.');
    }
    const kind = String(g.recipientKind || '');
    const value = String(g.recipient || '').trim();
    const recipient: Json = { kind: kind, value: '' };
    if (RECIPIENTS.indexOf(kind) < 0) {
      log.debug("Leaving UmaOwnerPolicy.readShare(). No recipient kind.");
      return refuse('STS-UMA-0302', 'Choose who the share is with.');
    }
    if (kind === 'person') {
      const subject = value ? self.deps.subjectForName(value) : '';
      if (!subject || subject === owner) {
        log.debug("Leaving UmaOwnerPolicy.readShare(). Unknown person.");
        return refuse('STS-UMA-0302', subject === owner && subject
          ? 'You already reach your own resources.'
          : 'There is nobody of that username in this realm.');
      }
      recipient.value = subject;
    } else if (kind === 'group') {
      const directory = self.deps.loadDirectory();
      const dn = value ? String(directory.groupDnFor(value)) : '';
      const located = dn ? directory.locateEntry(dn) : null;
      if (!dn || !located || !located.stored) {
        log.debug("Leaving UmaOwnerPolicy.readShare(). Unknown group.");
        return refuse('STS-UMA-0303', 'There is no group of that name in ' +
                      'this realm.');
      }
      recipient.value = String(directory.normalizeDn(dn));
    } else if (kind === 'claim') {
      const claim = String(g.claim || '').trim();
      if (!CLAIM_NAME.test(claim) || !PRINTABLE.test(value)) {
        log.debug("Leaving UmaOwnerPolicy.readShare(). A bad claim.");
        return refuse('STS-UMA-0304', 'A share by claim names the claim ' +
                      '(letters, digits, _ . : -) and the value it must ' +
                      'have.');
      }
      recipient.claim = claim;
      recipient.value = value;
    }
    let expires = '';
    if (g.expires) {
      const at = Date.parse(String(g.expires).length === 10
        ? String(g.expires) + 'T23:59:59Z' : String(g.expires));
      if (!Number.isFinite(at) || at <= self.deps.now()) {
        log.debug("Leaving UmaOwnerPolicy.readShare(). A bad expiry.");
        return refuse('STS-UMA-0305', 'The expiry must be a date in the ' +
                      'future.');
      }
      expires = new Date(at).toISOString().replace(/\.\d+Z$/, 'Z');
    }
    const acr = String(g.acr || '').trim();
    if (acr && !ACR_VALUE.test(acr)) {
      log.debug("Leaving UmaOwnerPolicy.readShare(). A bad acr.");
      return refuse('STS-UMA-0305', 'The authentication level is one ' +
                    'printable word.');
    }
    const askMe = g.askMe === true || ['true', 'on', '1', 'yes']
      .indexOf(String(g.askMe)) >= 0;
    void config;
    log.debug("Leaving UmaOwnerPolicy.readShare().");
    return { spec: { id: self.deps.randomId(9), resourceId: resource._id,
                     scopes: scopes, recipient: recipient, expires: expires,
                     acr: acr, askMe: askMe } };
  }

  /**
   * Adds one share to an owner's document, creating the document from the
   * default template at the first.
   *
   * @param owner - the owner's key
   * @param given - the form's fields (`readShare()`)
   * @returns `{ ok: true, share }`, or `{ ok: false, code, why }`
   */
  share(owner: string, given: Json): Json {
    const self = this;
    const { log, errorCodes } = this.deps;
    log.debug("Entering UmaOwnerPolicy.share().");
    const read = self.readShare(owner, given);
    if (read.code) {
      log.debug("Leaving UmaOwnerPolicy.share(). " + read.code);
      return errorCodes.mark({ ok: false, code: read.code, why: read.why },
                             read.code);
    }
    let doc: Json;
    try {
      doc = self.documentOf(owner);
    } catch (e) {
      log.error(errorCodes.tag('STS-UMA-0309') + 'uma: the document of ' +
                'the owner "' + owner + '" does not parse, so no share was ' +
                'added: ' + ((e && e.message) || e));
      log.debug("Leaving UmaOwnerPolicy.share(). Unreadable.");
      return errorCodes.mark({ ok: false, code: 'STS-UMA-0309',
        why: 'Your sharing policy could not be read.' }, 'STS-UMA-0309');
    }
    if (doc.policy.kind !== 'Policy') {
      log.debug("Leaving UmaOwnerPolicy.share(). A policy set.");
      return errorCodes.mark({ ok: false, code: 'STS-UMA-0307',
        why: 'Your sharing policy is a policy set written as ALFA; add ' +
             'shares to it there.' }, 'STS-UMA-0307');
    }
    const policy = Object.assign({}, doc.policy, {
      rules: (doc.policy.rules || []).concat([
        UmaOwnerPolicy.ruleFor(read.spec)]) });
    const saved = self.write(owner, policy);
    if (!saved.ok) {
      log.debug("Leaving UmaOwnerPolicy.share(). " + saved.code);
      return saved;
    }
    log.debug("Leaving UmaOwnerPolicy.share(). " + read.spec.id);
    return { ok: true, share: self.withLabel(read.spec) };
  }

  /**
   * Removes one share and revokes the RPTs that carried a permission over
   * its resource and scopes.
   *
   * @param owner - the owner's key
   * @param shareId - the share's id
   * @returns `{ ok: true, share, revoked }`, or `{ ok: false, code, why }`
   */
  unshare(owner: string, shareId: string): Json {
    const self = this;
    const { log, errorCodes, store } = this.deps;
    log.debug("Entering UmaOwnerPolicy.unshare().");
    let doc: Json;
    try {
      doc = self.documentOf(owner);
    } catch (e) {
      log.error(errorCodes.tag('STS-UMA-0309') + 'uma: the document of ' +
                'the owner "' + owner + '" does not parse: ' +
                ((e && e.message) || e));
      log.debug("Leaving UmaOwnerPolicy.unshare(). Unreadable.");
      return errorCodes.mark({ ok: false, code: 'STS-UMA-0309',
        why: 'Your sharing policy could not be read.' }, 'STS-UMA-0309');
    }
    const wanted = U.SHARE_RULE_PREFIX + String(shareId || '');
    const rules: Json[] = doc.policy.kind === 'Policy'
      ? (doc.policy.rules || []) : [];
    const rule = rules.filter(function (one: Json) {
      return one.id === wanted;
    })[0];
    const spec = rule ? self.specOf(rule) : null;
    if (!doc.stored || !spec) {
      log.debug("Leaving UmaOwnerPolicy.unshare(). No such share.");
      return errorCodes.mark({ ok: false, code: 'STS-UMA-0308',
        why: 'There is no such share of yours. It may already be gone.' },
        'STS-UMA-0308');
    }
    const saved = self.write(owner, Object.assign({}, doc.policy, {
      rules: rules.filter(function (one: Json) {
        return one.id !== wanted;
      }) }));
    if (!saved.ok) {
      log.debug("Leaving UmaOwnerPolicy.unshare(). " + saved.code);
      return saved;
    }
    const affected = store.rptsBy('resource', spec.resourceId)
      .filter(function (row: Json) {
        return (row.permissions || []).some(function (p: Json) {
          return p.resource_id === spec.resourceId &&
            (p.resource_scopes || []).some(function (s: string) {
              return spec.scopes.indexOf(s) >= 0;
            });
        });
      });
    const revoked = store.revokeRpts(affected, 'a UMA share withdrawn');
    log.debug("Leaving UmaOwnerPolicy.unshare(). " + revoked +
              " revoked.");
    return { ok: true, share: self.withLabel(spec), revoked: revoked };
  }

  /**
   * Writes an owner's approval of a waiting request (#1194): for each
   * permission, a share with the requesting party until `until`, with no
   * approval obligation — the record of what was approved IS the policy.
   *
   * **PLACED RIGHT AFTER `owner-self`, before every share**: this engine's
   * deny-unless-permit answers with the FIRST permitting rule and its
   * obligations, so an approval placed after the owner's "ask me" share
   * would be shadowed by it and the request asked about again for ever.
   *
   * @param owner - the owner's key
   * @param pending - the request: `requestingParty`, `permissions`
   * @param until - the approval's end, an xs:dateTime
   * @returns `{ ok: true, shares }`, or `{ ok: false, code, why }`
   */
  approve(owner: string, pending: Json, until: string): Json {
    const self = this;
    const { log, errorCodes } = this.deps;
    log.debug("Entering UmaOwnerPolicy.approve().");
    let doc: Json;
    try {
      doc = self.documentOf(owner);
    } catch (e) {
      log.error(errorCodes.tag('STS-UMA-0309') + 'uma: the document of ' +
                'the owner "' + owner + '" does not parse, so no approval ' +
                'was written: ' + ((e && e.message) || e));
      log.debug("Leaving UmaOwnerPolicy.approve(). Unreadable.");
      return errorCodes.mark({ ok: false, code: 'STS-UMA-0309',
        why: 'Your sharing policy could not be read.' }, 'STS-UMA-0309');
    }
    if (doc.policy.kind !== 'Policy') {
      log.debug("Leaving UmaOwnerPolicy.approve(). A policy set.");
      return errorCodes.mark({ ok: false, code: 'STS-UMA-0307',
        why: 'Your sharing policy is a policy set written as ALFA; an ' +
             'approval cannot be added to it.' }, 'STS-UMA-0307');
    }
    const specs: ShareSpec[] = (pending.permissions || []).map(
      function (p: Json): ShareSpec {
        return { id: self.deps.randomId(9),
                 resourceId: String(p.resource_id),
                 scopes: (p.resource_scopes || []).map(String),
                 recipient: { kind: 'person',
                              value: String(pending.requestingParty) },
                 expires: until, acr: '', askMe: false };
      });
    const rules: Json[] = (doc.policy.rules || []).slice();
    const at = rules.length && rules[0].id === U.OWNER_SELF_RULE ? 1 : 0;
    Array.prototype.splice.apply(rules, [at, 0].concat(
      specs.map(UmaOwnerPolicy.ruleFor) as any));
    const saved = self.write(owner, Object.assign({}, doc.policy,
                                                  { rules: rules }));
    if (!saved.ok) {
      log.debug("Leaving UmaOwnerPolicy.approve(). " + saved.code);
      return saved;
    }
    log.debug("Leaving UmaOwnerPolicy.approve(). " + specs.length);
    return { ok: true, shares: specs };
  }

  /**
   * Replaces an owner's whole document with ALFA they wrote, where
   * `uma.ownerAlfaEditing` allows it; every RPT over their resources is
   * revoked, since nothing can say which rule a hand edit narrowed.
   *
   * @param owner - the owner's key
   * @param text - the ALFA
   * @returns `{ ok: true, revoked }`, or `{ ok: false, code, why }`
   */
  setAlfa(owner: string, text: string): Json {
    const self = this;
    const { log, config, errorCodes, store } = this.deps;
    log.debug("Entering UmaOwnerPolicy.setAlfa().");
    if (config.value('uma.ownerAlfaEditing') !== true) {
      log.debug("Leaving UmaOwnerPolicy.setAlfa(). Not allowed here.");
      return errorCodes.mark({ ok: false, code: 'STS-UMA-0306',
        why: 'Editing your sharing policy as ALFA is not allowed in this ' +
             'realm (uma.ownerAlfaEditing).' }, 'STS-UMA-0306');
    }
    let policy: Json;
    try {
      policy = self.deps.loadAlfa().parse(String(text || ''));
    } catch (e) {
      log.debug("Caught in UmaOwnerPolicy.setAlfa(): " +
                ((e && e.message) || e));
      log.debug("Leaving UmaOwnerPolicy.setAlfa(). Does not parse.");
      return errorCodes.mark({ ok: false, code: 'STS-UMA-0307',
        why: 'That ALFA does not parse: ' +
             String((e && e.message) || e).slice(0, 300) }, 'STS-UMA-0307');
    }
    let saved: Json;
    try {
      const was = store.ownerPolicy(owner);
      saved = self.write(owner, Object.assign({}, policy, {
        version: was ? was.version : '1.0' }));
    } catch (e) {
      log.debug("Caught in UmaOwnerPolicy.setAlfa(): " +
                ((e && e.message) || e));
      log.debug("Leaving UmaOwnerPolicy.setAlfa(). Does not validate.");
      return errorCodes.mark({ ok: false, code: 'STS-UMA-0307',
        why: 'That policy does not validate: ' +
             String((e && e.message) || e).slice(0, 300) }, 'STS-UMA-0307');
    }
    if (!saved.ok) {
      log.debug("Leaving UmaOwnerPolicy.setAlfa(). " + saved.code);
      return saved;
    }
    const revoked = store.revokeRpts(store.rptsBy('owner', owner),
                                     'a UMA owner\'s policy rewritten');
    log.debug("Leaving UmaOwnerPolicy.setAlfa(). " + revoked + " revoked.");
    return { ok: true, revoked: revoked };
  }
}

const slot = new InstanceSlot<UmaOwnerPolicy>(
  'uma/uma_owner_policy',
  () => new UmaOwnerPolicy(UmaOwnerPolicy.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * A resource owner's own UMA document (#1168 phase 3).
 * @namespace
 */
export = {
  UmaOwnerPolicy: UmaOwnerPolicy,
  installInstance: (instance: UmaOwnerPolicy): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  RECIPIENTS: RECIPIENTS,
  ruleFor: UmaOwnerPolicy.ruleFor,
  documentOf: slot.forward('documentOf'),
  documentXml: slot.forward('documentXml'),
  specOf: slot.forward('specOf'),
  view: slot.forward('view'),
  readShare: slot.forward('readShare'),
  share: slot.forward('share'),
  unshare: slot.forward('unshare'),
  approve: slot.forward('approve'),
  setAlfa: slot.forward('setAlfa')
};
