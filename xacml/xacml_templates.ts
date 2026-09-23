'use strict';
//
// File: xacml_templates.ts
//
// ---------------------------------------------------------------------------
// STARTING POINTS: A POLICY SOMEBODY CAN EDIT, RATHER THAN A BLANK ONE.
//
// The guided editor can build any policy from nothing, one element at a time,
// and mostly nobody wants to. A template is the first twenty clicks already
// made — a working, valid, evaluable policy in a shape people actually write
// — and the editor takes it from there.
//
// **THE `blank` ROW IS THE EXCEPTION AND IT IS DELIBERATE.** "Mostly" is
// doing work in that paragraph: somebody who means to write the policy
// themselves had no door at all, because deleting the rules out of an RBAC
// document is not the same thing as starting from an empty one. That row
// makes no argument and produces nothing to read — see its own comment for
// what it costs, which is that an empty deny-unless-permit document DENIES.
//
// ADDING A TEMPLATE IS A ROW IN `TEMPLATES` BELOW AND NOTHING ELSE. That is
// the whole design and it is the promise this file has to keep: the console
// lists what is here, the management API offers what is here, and the
// parameter form is DERIVED from the row's `parameters`. If adding one ever
// needs an edit to `xacml_admin.ts` or to `mgmt-api/admin_api.ts`, this
// separation has gone wrong and the fix belongs here.
//
// ---------------------------------------------------------------------------
// A TEMPLATE BUILDS THE MODEL, NOT A STRING OF XML.
//
// It would be far easier to keep each template as XML with `{{placeholders}}`
// in it, and it would be wrong in a way that shows up late. A template's
// parameters are user input — a role name, an attribute id, a resource URI —
// and substituting them into XML text means escaping them correctly at every
// one of a dozen sites. Miss one and a role called `a"b` produces a document
// that will not parse, or worse, one that parses into something else.
//
// Building the model and handing it to `xacml_xml.js`'s writer moves that
// problem to the one place that already solves it: every value goes through
// `xmlEscape` on the way out, once, in code that is exercised by every policy
// this service writes. The template never sees a `<`.
//
// It also means a template is checked the same way a hand-authored policy is —
// `store.write()` validates it — so a template that stopped typechecking would
// be refused rather than becoming the broken policy everybody starts from.
//
// ---------------------------------------------------------------------------
// RBAC AND ABAC ARE THE TWO HALVES OF THE ARGUMENT XACML EXISTS FOR.
//
// RBAC asks "what ROLE do you hold", ABAC asks "what is TRUE about you, this
// resource, and right now". The first is what most deployments have and the
// second is what they wanted; having both here side by side, producing
// documents in the same language, is the clearest way to show what the
// difference actually costs in policy.
//
// The other three rows are not part of that argument and are not a third and
// fourth position in it: `role-issuance` and `access-control` are the two
// documents this service asks about ITSELF, and `blank` is an empty page.
// This comment said "TWO TEMPLATES" until 2026-09-06, when there were five.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape:
//
//   * **THE SMALL MODEL BUILDERS ARE `PolicyBuilders`' STATIC METHODS**, so a
//     row of the table below calls `B.apply(...)` rather than a free
//     function. They take nothing but their arguments.
//   * **THE TABLE STAYS A MODULE-LEVEL CONSTANT**, because it IS the design
//     (adding a template is a row and nothing else), and `XacmlTemplates`
//     takes it, the logger and nothing more through its constructor.
//   * **THE MODULE STILL EXPORTS `ISSUANCE_ATTRIBUTE`, `TEMPLATES`, `lookup`,
//     `build`, `catalogue`, `listOf` AND `slug`**, for the callers that are
//     not converted: `lookup`, `build` and `catalogue` are FACADES forwarding
//     to the `XacmlTemplates` the composition root builds and installs
//     (#50's R2), and a process without the root builds a default when this
//     module loads. Both classes are exported.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import model = require('./xacml_model');

const { log } = helpers;

// One parameter of a template, as the form draws it.
interface TemplateParameter {
  name: string;
  label: string;
  dflt: string;
  type: string;
  help: string;
}

// What a row's `build` is handed besides the answers.
interface BuildOptions {
  idBase: string;
}

// One row of `TEMPLATES`. `build` answers a MODEL, whose shape is the
// engine's (`xacml_model.js`) and is not restated here.
interface TemplateRow {
  id: string;
  label: string;
  blurb: string;
  what: string;
  parameters: TemplateParameter[];
  build(answers: any, options: BuildOptions): any;
}

// What `build()` answers: `why` when it is not `ok`, the rest when it is.
interface BuildResult {
  ok: boolean;
  why?: string;
  policy?: any;
  answers?: Record<string, string>;
  template?: TemplateRow;
}

interface XacmlTemplatesDeps {
  log: { debug(message: string): void };
  templates: TemplateRow[];
}

const F1 = 'urn:oasis:names:tc:xacml:1.0:function:';
const F3 = 'urn:oasis:names:tc:xacml:3.0:function:';
const TYPE = model.TYPE;

// ---------------------------------------------------------------------------
// THE ATTRIBUTE VOCABULARY OF AN ISSUANCE DECISION.
//
// These four identifiers are the contract between the embedded PEP that
// ASSERTS them (`xacml/xacml_role_pep.ts`) and the policy that READS them —
// which is the one below, and any policy anybody writes afterwards. They are
// exported so there is ONE spelling of each: a template that built a policy
// reading `urn:sts:xacml:roles` while the PEP asserted
// `urn:sts:xacml:role` would produce an empty bag, an empty bag is no
// intersection, and no intersection is a Deny — a policy that refuses
// everybody for a reason invisible in both files.
//
// **THEY ARE URI-SHAPED ON PURPOSE.** `xacml_pip.ts` treats a BARE name as a
// directory attribute to look up on the subject's own entry, so an attribute
// called `roles` would send the PIP looking for a `roles` attribute in LDAP
// and quietly answer with whatever it found there instead of with what the PEP
// asserted. A colon in the name is what keeps these out of that path.
// ---------------------------------------------------------------------------
const ISSUANCE_ATTRIBUTE = {
  // On the SUBJECT: the roles the party being authenticated holds, from the
  // register and from the six built-in ones.
  ROLE: 'urn:sts:xacml:role',
  // On the SUBJECT: the roles found in a token the caller PRESENTED, read out
  // of the claim `roles.claimName` names. Separate from the above rather than
  // unioned into it, and that separation is the whole reason it is visible in
  // the policy: these two are not equally trustworthy. The register is this
  // service's own record; a claim is whatever was in a token, and this service
  // does not verify access tokens it did not issue.
  TOKEN_ROLE: 'urn:sts:xacml:role-from-token',
  // ON THE SUBJECT: whether anybody actually authenticated for the session the
  // decision is being made in. It is on the SESSION rather than worked out
  // again here — see authn.js — and it is what separates a person who signed
  // in from one who pressed "continue without signing in".
  AUTHENTICATED: 'urn:sts:xacml:authenticated',
  // ON THE RESOURCE: WHOSE it is, where that is a person. The User Portal sets
  // it; nothing else does yet. It is what lets a policy say "the subject is the
  // owner" — and, later, "or the subject holds a helpdesk role", which is the
  // whole reason the portal's own-data rule goes through a policy at all rather
  // than being an `if` in a handler.
  OWNER: 'urn:sts:xacml:resource-owner',
  // On the RESOURCE: the roles the application demands. `appRequiredRole` on
  // its entry, or EVERYBODY where it names none.
  REQUIRED_ROLE: 'urn:sts:xacml:required-role'
};

// ---------------------------------------------------------------------------
// THE ATTRIBUTE VOCABULARY OF A RISK DECISION (#62 P3, 2026-09-22).
//
// rcbj's directive that day: EVERY AUTHORIZATION DECISION IS POLICY, so the
// rules can be changed in `ou=policies` without a rebuild. `risk/` supplies
// FACTS about the authentication an issuance rests on; the issuance policy
// below DECIDES on them, in the same evaluation that decides the roles. The
// facts are on the ENVIRONMENT category because they are about the
// circumstances of this request — where it came from, over what, after how
// many refused passwords — and neither the subject's standing attributes nor
// the resource's. URI-shaped for `ISSUANCE_ATTRIBUTE`'s reason: a bare name
// would send the PIP to the directory.
//
// **AN ABSENT LEVEL IS NOT A LEVEL.** No assessment — a first sign-in's
// UNSCORED is still sent, but a door that could not score, a stale dataset or
// the engine switched off sends nothing — makes every risk rule below
// inapplicable, so unknown never denies. That is the datasets' rule
// (`risk/CLAUDE.md`) carried into the decision.
// ---------------------------------------------------------------------------
const RISK_ATTRIBUTE = {
  // LOW, MEDIUM, HIGH or UNSCORED — CAEP's own words, plus the one for a
  // first sign-in with nothing to compare it to.
  LEVEL: 'urn:sts:xacml:risk-level',
  // The score the level was read from: the model's times every evaluator's
  // factor. A double, for a policy that wants a threshold of its own.
  SCORE: 'urn:sts:xacml:risk-score',
  // A BAG: every evaluator that fired (`risk_engine.ts`'s SIGNALS keys —
  // tor-exit, reputation, operator-deny, operator-allow, automated-client,
  // new-tls-stack, account-failures, network-failures).
  SIGNAL: 'urn:sts:xacml:risk-signal',
  // A BAG: the step-ups the authentication ALREADY meets — `second-factor`
  // when it carried two (acr `mfa`), `security-key` when one of them was a
  // WebAuthn key (amr `hwk`). Computed from the session's events at each
  // decision, so a re-authentication with a key moves it at once.
  SATISFIED: 'urn:sts:xacml:risk-satisfied',
  // The obligation every risk rule carries, and its two assignments. It is
  // how the PEP tells a Deny about RISK from a Deny about ROLES — they are
  // enforced differently (a step-up, and observe-only in development) — and
  // what it reads to know which factor to ask for.
  OBLIGATION: 'urn:sts:xacml:obligation:risk',
  ACTION: 'urn:sts:xacml:risk-action',
  FACTOR: 'urn:sts:xacml:risk-step-up-factor',
  // The level the person's standing moved FROM (#62 P4) — the
  // `risk-response` policy's question is about a CHANGE, and a level with
  // nothing to compare it to is the person's first. Absent then.
  PREVIOUS_LEVEL: 'urn:sts:xacml:risk-previous-level'
};

// ---------------------------------------------------------------------------
// WHAT A CHANGE OF RISK CAN LEAD TO (#62 P4, 2026-09-22) — the action-ids the
// `risk-response` policy is asked about, one question per reaction. A Permit
// means DO IT. Asked one at a time rather than as one question whose Permit
// carries a list of obligations, because a combining algorithm that stops at
// its first Permit returns that rule's obligations and no other's, and a
// reaction silently dropped by the combining is the worst way for this to
// fail. One question per reaction also reads in the policy as what it is: a
// rule per thing that happens.
// ---------------------------------------------------------------------------
const RISK_RESPONSE = {
  // CAEP risk-level-change, to every stream that takes it — this service's
  // own console and portal among them (their signal inboxes).
  ANNOUNCE: 'risk-announce',
  // End everything the person holds: every session, every token, the
  // back-channel Logout Tokens.
  END_SESSIONS: 'risk-end-sessions',
  // RISC credential-compromise: the evidence is about a CREDENTIAL, so the
  // relying parties are told it is no longer to be trusted.
  CREDENTIAL_COMPROMISE: 'risk-credential-compromise',
  // Disable the account (pwdAccountLockedTime), RISC reason `hijacking`.
  DISABLE: 'risk-disable'
};

// ---------------------------------------------------------------------------
// SMALL MODEL BUILDERS.
//
// Named for what they produce rather than for the element they emit, because
// the point of building the model is that a template author does not have to
// know the element names — that is the writer's problem.
// ---------------------------------------------------------------------------
class PolicyBuilders {
  static value(type: string, lexical: unknown): any {
    log.debug("Entering PolicyBuilders.value().");
    log.debug("Leaving PolicyBuilders.value().");
    return { kind: 'value', type: type, lexical: String(lexical) };
  }

  static designator(category: string, attributeId: string,
                    type: string): any {
    log.debug("Entering PolicyBuilders.designator().");
    log.debug("Leaving PolicyBuilders.designator().");
    return { kind: 'designator', category: category,
             attributeId: attributeId, dataType: type, issuer: null,
             mustBePresent: false };
  }

  static match(matchId: string, literal: any, reference: any): any {
    log.debug("Entering PolicyBuilders.match().");
    log.debug("Leaving PolicyBuilders.match().");
    return { matchId: matchId, value: literal, reference: reference };
  }

  // A Target that is satisfied when ALL of the given match-groups are — one
  // `AnyOf` per group, since a Target ANDs its AnyOf children. Each group is a
  // list of alternatives, ORed, since an AnyOf ORs its AllOf children.
  static targetOf(groups: any[][]): any {
    log.debug("Entering PolicyBuilders.targetOf().");
    const anyOf = groups.filter(function (group) {
      return group && group.length;
    }).map(function (group) {
      return { allOf: group.map(function (one) {
        return { matches: [one] };
      }) };
    });
    log.debug("Leaving PolicyBuilders.targetOf().");
    return anyOf.length ? { anyOf: anyOf } : null;
  }

  static apply(functionId: string, args: any[]): any {
    log.debug("Entering PolicyBuilders.apply().");
    log.debug("Leaving PolicyBuilders.apply().");
    return { kind: 'apply', functionId: functionId, args: args };
  }

  // A list typed into a form: commas or newlines, blanks dropped. One reader
  // for every template parameter of list type, so that "a, b" and "a\nb"
  // cannot mean different things on two different templates.
  static listOf(raw: unknown): string[] {
    log.debug("Entering PolicyBuilders.listOf().");
    log.debug("Leaving PolicyBuilders.listOf().");
    return String(raw || '').split(/[,\n]/).map(function (one) {
      return one.trim();
    }).filter(function (one) {
      return one.length > 0;
    });
  }

  // A yes/no answer from a template parameter, which is a text field like
  // every other one. Anything that is not plainly a no is a yes, because these
  // two parameters both default to yes and the cost of misreading a typo as a
  // yes is a policy that permits slightly more than intended — while
  // misreading one as a no builds the issuance policy without an arm and
  // refuses people.
  static yes(answer: unknown, dflt?: boolean): boolean {
    log.debug("Entering PolicyBuilders.yes().");
    const text = String(answer === undefined || answer === null ? '' : answer)
      .trim().toLowerCase();
    if (!text) {
      log.debug("Leaving PolicyBuilders.yes().");
      return dflt !== false;
    }
    log.debug("Leaving PolicyBuilders.yes().");
    return !(text === 'no' || text === 'false' || text === 'off' ||
             text === '0' || text === 'n');
  }

  static slug(text: unknown): string {
    log.debug("Entering PolicyBuilders.slug().");
    log.debug("Leaving PolicyBuilders.slug().");
    return String(text || '').toLowerCase().replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'x';
  }
}

// The table's short name for the builders.
const B = PolicyBuilders;

// ---------------------------------------------------------------------------
// THE TABLE.
//
// `parameters` drives the form, so a parameter's `label` and `help` are what a
// person reads and its `dflt` is what they get if they say nothing. `build`
// receives the answers already coerced and returns a MODEL.
// ---------------------------------------------------------------------------
const TEMPLATES: TemplateRow[] = [
  {
    // -----------------------------------------------------------------------
    // THE ONE TEMPLATE THIS SERVICE EVALUATES ABOUT ITSELF.
    //
    // Every other template here builds a policy about somebody ELSE's
    // boundary, which is what a PDP is for. This one builds the policy the
    // EMBEDDED PEP asks before this service issues anything — a token, a
    // ticket, an assertion, a session — and `xacml.issuancePolicy` names the
    // repository entry it lives in.
    //
    // IT IS BUILT IN RATHER THAN SEEDED (`xacml_role_pep.ts` calls this row
    // at decision time and says why), AND IT IS NOT THE REPOSITORY ROOT. Two
    // questions, two documents: the root answers what a caller asks at
    // /xacml/pdp and what every remote PEP pulls, and this answers who may be
    // issued something here. Making them one document would mean editing the
    // demo policy changed who could sign in, and narrowing one application's
    // roles changed what /xacml/pdp told a remote PEP.
    //
    // WHY IT IS ONE POLICY FOR EVERY APPLICATION RATHER THAN ONE PER
    // APPLICATION. The alternative — a rule per application naming its roles —
    // was rejected because the requirement then lives in TWO places that can
    // disagree: `appRequiredRole` on the entry, which the console edits, and a
    // rule in a policy, which the editor edits. This way the policy states the
    // RULE ("you must hold one of the roles this application requires") and
    // the entry states the FACT, the PEP puts both in the request, and there
    // is nothing to keep in step.
    // -----------------------------------------------------------------------
    id: 'role-issuance',
    label: 'Role-based issuance (this service\'s own)',
    blurb: 'The policy the embedded PEP asks before this service issues ' +
           'anything: the party being authenticated must hold one of the ' +
           'roles the application requires, and the authentication must not ' +
           'be too risky (#62).',
    what: 'Produces ONE Permit rule whose condition is an intersection test ' +
          'between the roles the subject holds and the roles the resource ' +
          'requires — plus the same test against the roles found in a ' +
          'PRESENTED TOKEN\'s claim, and a permit for an application that ' +
          'requires nothing at all — and, with `decideRisk`, three Deny ' +
          'rules on the risk of the authentication (HIGH refused, MEDIUM ' +
          'refused until a step-up), each carrying an obligation that says ' +
          'what to ask for. The combining algorithm is ' +
          'ordered-deny-overrides with the risk rules and ' +
          'deny-unless-permit without, so either way anything the role rule ' +
          'does not permit is refused rather than left to the PEP\'s bias, ' +
          'and a risk Deny wins over a role Permit. Because the ' +
          'requirement travels in the REQUEST rather than being written into ' +
          'the policy, this one document decides for every application, and ' +
          'narrowing an application is editing its entry rather than editing ' +
          'a policy.',
    parameters: [
      { name: 'allowTokenRoles',
        label: 'Also accept roles found in a presented token',
        dflt: 'yes', type: 'string',
        help: 'yes or no. When yes, a role named in the roles claim of a ' +
              'token the caller presented counts as held. THAT IS WEAKER ' +
              'THAN THE REGISTER and the policy says so in its own ' +
              'description: this service does not verify access tokens it ' +
              'did not issue, so a claim is evidence about a token rather ' +
              'than about a person. It is on by default because reading the ' +
              'claim back is the thing most people come here to watch.' },
      { name: 'permitWhenNothingRequired',
        label: 'Permit when the application requires no role at all',
        dflt: 'yes', type: 'string',
        help: 'yes or no. An application that names no required role is ' +
              'given EVERYBODY by the registry, so this arm is a belt-and- ' +
              'braces answer for a request that carries no requirement at ' +
              'all — a PEP written by somebody else, or this one after a ' +
              'future change. Saying no makes such a request a Deny.' },
      { name: 'decideRisk',
        label: 'Decide on the risk of the authentication (#62)',
        dflt: 'yes', type: 'string',
        help: 'yes or no. When yes, the three risk rules are in the ' +
              'document: HIGH is refused, and MEDIUM is refused until the ' +
              'authentication carries the step-up the obligation names. ' +
              'Saying no builds the roles-only policy this was before risk ' +
              'scoring decided anything — assessments are still recorded.' },
      { name: 'keySignals',
        label: 'Signals that demand a SECURITY KEY at MEDIUM',
        dflt: 'automated-client, new-tls-stack', type: 'string',
        help: 'The risk signals, comma separated, that are about the DEVICE ' +
              'or the TLS client rather than the network. At MEDIUM with ' +
              'one of them, a second factor is not enough: an attacker ' +
              'relaying a person\'s one-time code from another machine ' +
              'passes a code, and cannot pass a WebAuthn ceremony bound to ' +
              'this origin. Empty makes every MEDIUM a second-factor step-up.' }
    ],
    build: function (answers, options) {
      log.debug('Entering buildRoleIssuance().');
      const given = answers || {};
      const useTokenRoles = B.yes(given.allowTokenRoles, true);
      const permitEmpty = B.yes(given.permitWhenNothingRequired, true);
      const decideRisk = B.yes(given.decideRisk, true);
      const keySignals = B.listOf(given.keySignals);

      // THE INTERSECTION TEST, and it is a HIGHER-ORDER function because that
      // is the only way XACML expresses "do these two bags share a member".
      // `any-of-any(string-equal, A, B)` is true when string-equal holds for
      // ANY pair — which is exactly the question, and which no ordinary
      // two-argument predicate can ask.
      function intersects(subjectAttribute) {
        log.debug("Entering intersects().");
        log.debug("Leaving intersects().");
        return B.apply(F3 + 'any-of-any', [
          { kind: 'function', functionId: F1 + 'string-equal' },
          B.designator(model.CATEGORY.ACCESS_SUBJECT, subjectAttribute,
                       TYPE.STRING),
          B.designator(model.CATEGORY.RESOURCE,
                       ISSUANCE_ATTRIBUTE.REQUIRED_ROLE, TYPE.STRING)
        ]);
      }

      const arms = [intersects(ISSUANCE_ATTRIBUTE.ROLE)];
      if (useTokenRoles) {
        arms.push(intersects(ISSUANCE_ATTRIBUTE.TOKEN_ROLE));
      }
      if (permitEmpty) {
        // "The resource requires nothing." Written as a bag-size test because
        // XACML has no way to ask whether a designator matched — an absent
        // attribute and an attribute with no values are the same empty bag,
        // which is the right answer here: both mean nobody said.
        arms.push(B.apply(F1 + 'integer-equal', [
          B.apply(F1 + 'string-bag-size', [
            B.designator(model.CATEGORY.RESOURCE,
                         ISSUANCE_ATTRIBUTE.REQUIRED_ROLE, TYPE.STRING)
          ]),
          B.value(TYPE.INTEGER, '0')
        ]));
      }

      const condition = arms.length === 1 ? arms[0]
        : B.apply(F1 + 'or', arms);

      // -------------------------------------------------------------------
      // THE RISK RULES (#62 P3, 2026-09-22). Deny rules, each carrying the
      // `RISK_ATTRIBUTE.OBLIGATION` that says refuse or step up and with
      // what, and MUTUALLY EXCLUSIVE by construction — HIGH, MEDIUM with a
      // key signal, MEDIUM without one — so a Deny carries exactly one
      // instruction. Under ordered-deny-overrides a risk Deny beats the role
      // Permit, and a request no rule speaks to is still refused, as it was
      // under deny-unless-permit: NotApplicable is not a Permit to the PEP.
      // -------------------------------------------------------------------
      const env = model.CATEGORY.ENVIRONMENT;
      const levelIs = function (level: string): any {
        log.debug("Entering levelIs().");
        log.debug("Leaving levelIs().");
        return B.apply(F1 + 'string-is-in', [
          B.value(TYPE.STRING, level),
          B.designator(env, RISK_ATTRIBUTE.LEVEL, TYPE.STRING)]);
      };
      const satisfied = function (factor: string): any {
        log.debug("Entering satisfied().");
        log.debug("Leaving satisfied().");
        return B.apply(F1 + 'string-is-in', [
          B.value(TYPE.STRING, factor),
          B.designator(env, RISK_ATTRIBUTE.SATISFIED, TYPE.STRING)]);
      };
      const obligation = function (action: string, factor: string): any {
        log.debug("Entering obligation().");
        const assignments = [{ attributeId: RISK_ATTRIBUTE.ACTION,
          category: null, issuer: null,
          expression: B.value(TYPE.STRING, action) }];
        if (factor) {
          assignments.push({ attributeId: RISK_ATTRIBUTE.FACTOR,
            category: null, issuer: null,
            expression: B.value(TYPE.STRING, factor) });
        }
        log.debug("Leaving obligation().");
        return [{ id: RISK_ATTRIBUTE.OBLIGATION, on: model.EFFECT.DENY,
                  assignments: assignments }];
      };
      const keySignal = keySignals.length
        ? B.apply(F3 + 'any-of-any', [
          { kind: 'function', functionId: F1 + 'string-equal' },
          B.designator(env, RISK_ATTRIBUTE.SIGNAL, TYPE.STRING),
          B.apply(F1 + 'string-bag', keySignals.map(function (one) {
            return B.value(TYPE.STRING, one);
          }))])
        : null;
      const riskRules: any[] = [];
      if (decideRisk) {
        riskRules.push({
          id: options.idBase + ':rule:risk-high',
          effect: model.EFFECT.DENY,
          description: 'Refuse an authentication whose risk is HIGH, ' +
                       'whatever roles the subject holds and however many ' +
                       'factors it presented.',
          target: null, condition: levelIs('HIGH'),
          obligations: obligation('refuse', ''), advice: []
        });
        if (keySignal) {
          riskRules.push({
            id: options.idBase + ':rule:risk-medium-key',
            effect: model.EFFECT.DENY,
            description: 'At MEDIUM, with a signal about the device or the ' +
                         'TLS client, refuse until the authentication used ' +
                         'a SECURITY KEY — the obligation asks for one.',
            target: null,
            condition: B.apply(F1 + 'and', [levelIs('MEDIUM'), keySignal,
              B.apply(F1 + 'not', [satisfied('security-key')])]),
            obligations: obligation('step-up', 'security-key'), advice: []
          });
        }
        const secondFactor = [levelIs('MEDIUM'),
          B.apply(F1 + 'not', [satisfied('second-factor')])];
        if (keySignal) {
          secondFactor.push(B.apply(F1 + 'not', [keySignal]));
        }
        riskRules.push({
          id: options.idBase + ':rule:risk-medium-second-factor',
          effect: model.EFFECT.DENY,
          description: 'At MEDIUM, refuse until the authentication carried ' +
                       'a SECOND FACTOR — the obligation asks for one.',
          target: null, condition: B.apply(F1 + 'and', secondFactor),
          obligations: obligation('step-up', 'second-factor'), advice: []
        });
      }

      log.debug('Leaving buildRoleIssuance(). ' + arms.length + ' arm(s), ' +
                riskRules.length + ' risk rule(s).');
      return {
        kind: 'Policy',
        id: options.idBase,
        version: '1.0',
        description: 'THE ISSUANCE POLICY. The embedded PEP asks this before ' +
                     'this service issues a token, a ticket, an assertion or ' +
                     'a session. It permits when the party being ' +
                     'authenticated holds one of the roles the application ' +
                     'requires' +
                     (useTokenRoles
                        ? ', or when a role in a PRESENTED TOKEN\'s claim is ' +
                          'one of them — which is weaker, because this ' +
                          'service does not verify tokens it did not issue'
                        : '') +
                     (permitEmpty
                        ? ', or when the application requires nothing at all'
                        : '') +
                     '. Everything else is denied: an issuance decision ' +
                     'must not depend on a PEP\'s bias.' +
                     (decideRisk
                        ? ' AND IT DECIDES ON RISK (#62): an authentication ' +
                          'whose risk is HIGH is refused, and one at MEDIUM ' +
                          'is refused until it carries the step-up the risk ' +
                          'obligation names' + (keySignals.length
                            ? ' — a security key where a signal is about the ' +
                              'device or TLS client (' + keySignals.join(', ') +
                              '), a second factor otherwise'
                            : ' — a second factor') + '. The risk rules deny ' +
                          'and override the role rule; an authentication ' +
                          'with no assessment is decided on roles alone.'
                        : '') ,
        combiningAlgId: decideRisk ? model.RULE_ALG.ORDERED_DENY_OVERRIDES
                                   : model.RULE_ALG.DENY_UNLESS_PERMIT,
        // NO TARGET, and that is deliberate rather than an omission: this
        // document is evaluated by ONE caller that only ever asks about an
        // issuance, so a target restating that could only ever refuse a
        // request the PEP would not have made — and would do it as
        // NotApplicable, which under deny-unless-permit is a Deny nobody can
        // explain.
        target: null,
        variables: {},
        rules: riskRules.concat([{
          id: options.idBase + ':rule:holds-a-required-role',
          effect: model.EFFECT.PERMIT,
          description: 'Permit when the roles the subject holds and the ' +
                       'roles the resource requires share a member.',
          target: null,
          condition: condition,
          obligations: [], advice: []
        }]),
        obligations: [], advice: []
      };
    }
  },
  {
    // -----------------------------------------------------------------------
    // THE RISK RESPONSE POLICY (#62 P4, 2026-09-22) — the third of this
    // service's own, and like the other two built in rather than seeded.
    //
    // `role-issuance` decides what is ISSUED on an authentication's risk.
    // This decides what HAPPENS when a person's risk CHANGES: whether the
    // change is announced (CAEP risk-level-change), whether everything they
    // hold is ended, whether RISC is told a credential is compromised, and
    // whether the account is disabled. rcbj's directive is that every
    // authorization decision is policy, and ending someone's access is one.
    //
    // `xacml/xacml_risk_pep.ts` asks it once per reaction (`RISK_RESPONSE`'s
    // action-ids) with the person as the subject and the change as the
    // environment; a Permit means do it. deny-unless-permit, so a reaction no
    // rule speaks to does not happen.
    //
    // **DISABLING IS OFF UNTIL SOMEBODY BUILDS IT IN.** The rule exists only
    // when `disableFromScore` is given: locking a person out on a score is the
    // one reaction an attacker can aim at somebody else (sign in as them from
    // a Tor exit, repeatedly), so it is the operator's decision, made in the
    // policy, with the threshold written where it is read.
    // -----------------------------------------------------------------------
    id: 'risk-response',
    label: 'Risk response (this service\'s own)',
    blurb: 'What happens when a person\'s risk level changes: announced ' +
           'over CAEP, everything they hold ended at HIGH, RISC told when ' +
           'the evidence is about a credential, and — only if you set a ' +
           'score — the account disabled.',
    what: 'Produces one Permit rule per reaction, each for its own ' +
          'action-id (risk-announce, risk-end-sessions, ' +
          'risk-credential-compromise, risk-disable), under ' +
          'deny-unless-permit. The embedded PEP asks one question per ' +
          'reaction with the person as the subject and the change — the ' +
          'level, the level before, the score and the signals — as the ' +
          'environment.',
    parameters: [
      { name: 'credentialSignals',
        label: 'Signals that are evidence about a CREDENTIAL',
        dflt: 'account-failures, authenticator-compromised, reported-not-me',
        type: 'string',
        help: 'Comma separated. Crossing into HIGH with one of them sends ' +
              'RISC credential-compromise: the password is being guessed or ' +
              'has been, or the security key\'s model is reported ' +
              'compromised in the FIDO metadata, and relying parties should ' +
              'stop trusting it.' },
      { name: 'disableFromScore',
        label: 'Disable the account from this score (empty: never)',
        dflt: '', type: 'string',
        help: 'A number. Empty builds no disable rule at all, which is the ' +
              'default: an attacker who can make somebody\'s sign-ins look ' +
              'risky could otherwise lock them out. With a value, crossing ' +
              'into HIGH at that score or above disables the account, with ' +
              'RISC reason hijacking.' }
    ],
    build: function (answers, options) {
      log.debug('Entering buildRiskResponse().');
      const given = answers || {};
      const credentialSignals = B.listOf(given.credentialSignals);
      const disableFrom = String(given.disableFromScore || '').trim();
      const env = model.CATEGORY.ENVIRONMENT;
      const actionIs = function (action: string): any {
        log.debug("Entering actionIs().");
        log.debug("Leaving actionIs().");
        return B.apply(F1 + 'string-is-in', [B.value(TYPE.STRING, action),
          B.designator(model.CATEGORY.ACTION, model.ATTRIBUTE.ACTION_ID,
                       TYPE.STRING)]);
      };
      const levelIs = function (id: string, level: string): any {
        log.debug("Entering levelIs().");
        log.debug("Leaving levelIs().");
        return B.apply(F1 + 'string-is-in', [B.value(TYPE.STRING, level),
          B.designator(env, id, TYPE.STRING)]);
      };
      const crossedIntoHigh = [levelIs(RISK_ATTRIBUTE.LEVEL, 'HIGH'),
        B.apply(F1 + 'not', [levelIs(RISK_ATTRIBUTE.PREVIOUS_LEVEL, 'HIGH')])];
      const rule = function (slug: string, description: string,
                             conjuncts: any[]): any {
        log.debug("Entering rule().");
        log.debug("Leaving rule().");
        return { id: options.idBase + ':rule:' + slug,
                 effect: model.EFFECT.PERMIT, description: description,
                 target: null,
                 condition: B.apply(F1 + 'and', conjuncts),
                 obligations: [], advice: [] };
      };
      const rules = [
        rule('announce', 'Announce every change of level over CAEP ' +
             '(risk-level-change): a level is known, it is not the level ' +
             'before, and it is not a person\'s FIRST level being LOW — ' +
             'every new person\'s second sign-in is that, and announcing ' +
             'it would be noise a receiver learns to ignore.', [
          actionIs(RISK_RESPONSE.ANNOUNCE),
          B.apply(F1 + 'or', [
            B.apply(F1 + 'integer-equal', [
              B.apply(F1 + 'string-bag-size', [
                B.designator(env, RISK_ATTRIBUTE.PREVIOUS_LEVEL,
                             TYPE.STRING)]),
              B.value(TYPE.INTEGER, '1')]),
            B.apply(F1 + 'not', [levelIs(RISK_ATTRIBUTE.LEVEL, 'LOW')])]),
          B.apply(F1 + 'integer-equal', [
            B.apply(F1 + 'string-bag-size', [
              B.designator(env, RISK_ATTRIBUTE.LEVEL, TYPE.STRING)]),
            B.value(TYPE.INTEGER, '1')]),
          B.apply(F1 + 'not', [B.apply(F3 + 'any-of-any', [
            { kind: 'function', functionId: F1 + 'string-equal' },
            B.designator(env, RISK_ATTRIBUTE.LEVEL, TYPE.STRING),
            B.designator(env, RISK_ATTRIBUTE.PREVIOUS_LEVEL, TYPE.STRING)])])
        ]),
        rule('end-sessions', 'On crossing into HIGH, end everything the ' +
             'person holds.',
             [actionIs(RISK_RESPONSE.END_SESSIONS)].concat(crossedIntoHigh))
      ];
      if (credentialSignals.length) {
        rules.push(rule('credential-compromise', 'On crossing into HIGH on ' +
          'evidence about a credential (' + credentialSignals.join(', ') +
          '), tell RISC the credential is compromised.',
          [actionIs(RISK_RESPONSE.CREDENTIAL_COMPROMISE)]
            .concat(crossedIntoHigh).concat([
              B.apply(F3 + 'any-of-any', [
                { kind: 'function', functionId: F1 + 'string-equal' },
                B.designator(env, RISK_ATTRIBUTE.SIGNAL, TYPE.STRING),
                B.apply(F1 + 'string-bag',
                        credentialSignals.map(function (one) {
                          return B.value(TYPE.STRING, one);
                        }))])])));
      }
      if (disableFrom && isFinite(Number(disableFrom))) {
        rules.push(rule('disable', 'On crossing into HIGH at a score of ' +
          disableFrom + ' or more, disable the account.',
          [actionIs(RISK_RESPONSE.DISABLE)].concat(crossedIntoHigh).concat([
            B.apply(F1 + 'double-greater-than-or-equal', [
              B.apply(F1 + 'double-one-and-only', [
                B.designator(env, RISK_ATTRIBUTE.SCORE, TYPE.DOUBLE)]),
              B.value(TYPE.DOUBLE, String(Number(disableFrom)))])])));
      }
      log.debug('Leaving buildRiskResponse(). ' + rules.length + ' rule(s).');
      return {
        kind: 'Policy',
        id: options.idBase,
        version: '1.0',
        description: 'THE RISK RESPONSE POLICY. The embedded PEP asks it, ' +
                     'once per reaction, when a person\'s risk level ' +
                     'changes. It announces every change over CAEP, ends ' +
                     'everything the person holds on crossing into HIGH' +
                     (credentialSignals.length
                        ? ', tells RISC a credential is compromised when the ' +
                          'evidence is about one (' +
                          credentialSignals.join(', ') + ')'
                        : '') +
                     (disableFrom
                        ? ', and disables the account from a score of ' +
                          disableFrom
                        : ', and never disables the account') +
                     '. Anything no rule permits does not happen.',
        combiningAlgId: model.RULE_ALG.DENY_UNLESS_PERMIT,
        target: null,
        variables: {},
        rules: rules,
        obligations: [], advice: []
      };
    }
  },
  {
    // -----------------------------------------------------------------------
    // THE ACCESS-CONTROL POLICY (2026-09-06). The second of this service's own
    // two, and the sibling of `role-issuance` above.
    //
    // That one answers "may this be ISSUED"; this one answers "may this
    // SUBJECT do this to this RESOURCE" — the admin console, the management
    // API, the User Portal, SCIM, the SPIRE Server API and the other surfaces
    // `common/access_gate.ts` lists.
    //
    // **THE SUBJECT IS ALWAYS THE SECURITY CONTEXT'S PERSON**, taken from the
    // session by `common/access_gate.ts` and never from the request. That is
    // not this policy's business — a PDP decides about the subject it is
    // handed — but it is the reason the decision means anything: a policy
    // engine deciding faithfully about a subject the caller nominated is
    // broken access control with extra steps.
    //
    // TWO QUESTIONS, BOTH OF WHICH MUST BE ANSWERED YES, and the second is the
    // one that could not have been written as an `if` in a handler:
    //
    //   1. does the subject satisfy the resource's ROLE requirement — holding
    //      one the resource names, or the resource naming none? The console's
    //      two roles are the first half; the second is what lets a surface
    //      nobody has narrowed behave as it did before there was a policy.
    //   2. does the subject satisfy the resource's OWNERSHIP requirement — the
    //      resource naming no owner, or **the subject BEING the owner**? That
    //      is the User Portal's whole rule, expressed as a comparison between
    //      two attributes rather than as an equality buried in a route.
    //
    // **THEY ARE CONJOINED AND NOT ALTERNATIVES, AND THE FIRST DRAFT GOT THAT
    // WRONG.** Written as three OR'd arms, "the resource requires nothing" was
    // true for the portal — which narrows nobody — so it swallowed the owner
    // comparison and any signed-in person could reach ANY OTHER PERSON'S
    // account. The build function carries the full account of it.
    //
    // Question 2 is why this exists. "You may manage your own account" and "a
    // helpdesk role may manage anybody's" are the same policy with one more
    // rule, and only one of those two sentences can be added to a document.
    // -----------------------------------------------------------------------
    id: 'access-control',
    label: 'Access control (this service\'s own)',
    blurb: 'The policy the embedded PEP asks before a subject reaches the ' +
           'admin console, the management API, the User Portal, SCIM or the ' +
           'SPIRE Server API.',
    what: 'Produces ONE Permit rule whose condition conjoins two questions: ' +
          'does the subject satisfy the resource\'s ROLE requirement ' +
          '(holding one it names, or it naming none), AND does it satisfy ' +
          'the resource\'s OWNERSHIP requirement (the resource naming no ' +
          'owner, or the subject being that owner). Both must hold, so ' +
          'ownership is a constraint rather than a way round the roles. The ' +
          'combining algorithm is deny-unless-permit, so anything not ' +
          'permitted is refused rather than left to the PEP\'s bias. Because ' +
          'the requirement and the owner both travel in the REQUEST, one ' +
          'document decides for every surface — and adding a helpdesk role ' +
          'that may manage somebody else\'s account is a SECOND RULE in this ' +
          'policy rather than a change to this one or to any handler.',
    parameters: [
      { name: 'permitOwner',
        label: 'Permit a subject to act on a resource they own',
        dflt: 'yes', type: 'string',
        help: 'yes or no. This is the User Portal\'s rule: a person may ' +
              'manage their own account and nobody else\'s. It is a ' +
              'CONSTRAINT rather than an alternative — a resource that names ' +
              'an owner is reachable only by that owner, whatever roles are ' +
              'held. Saying no leaves only the ownerless surfaces reachable, ' +
              'so the portal refuses everybody including its owner, which is ' +
              'a useful thing to be able to demonstrate and a terrible thing ' +
              'to leave on.' },
      { name: 'permitWhenNothingRequired',
        label: 'Permit when the resource requires no role at all',
        dflt: 'yes', type: 'string',
        help: 'yes or no. A surface nobody has narrowed then behaves as it ' +
              'did before there was a policy. Saying no denies every request ' +
              'that carries no requirement, which is how to see what a fully ' +
              'closed deployment looks like.' },
      { name: 'requireAuthenticated',
        label: 'Refuse a subject that did not authenticate',
        dflt: 'yes', type: 'string',
        help: 'yes or no. An unauthenticated session — the sign-in screen\'s ' +
              '"continue without signing in" — is a real subject here, and ' +
              'this conjunct keeps it out of every gated surface without ' +
              'anybody having to name it in a role.' }
    ],
    build: function (answers, options) {
      log.debug('Entering buildAccessControl().');
      const given = answers || {};
      const permitOwner = B.yes(given.permitOwner, true);
      const permitEmpty = B.yes(given.permitWhenNothingRequired, true);
      const requireAuth = B.yes(given.requireAuthenticated, true);

      // The same intersection test `role-issuance` uses, and for the same
      // reason: `any-of-any` is the only way XACML asks whether two bags share
      // a member.
      const holdsRequiredRole = B.apply(F3 + 'any-of-any', [
        { kind: 'function', functionId: F1 + 'string-equal' },
        B.designator(model.CATEGORY.ACCESS_SUBJECT, ISSUANCE_ATTRIBUTE.ROLE,
                     TYPE.STRING),
        B.designator(model.CATEGORY.RESOURCE, ISSUANCE_ATTRIBUTE.REQUIRED_ROLE,
                     TYPE.STRING)
      ]);

      // ---------------------------------------------------------------------
      // **OWNERSHIP IS A CONSTRAINT AND NOT AN ALTERNATIVE**, and this was the
      // defect the first draft shipped with. It was written as a third ARM —
      // permit when the subject holds a required role, OR when nothing is
      // required, OR when the subject owns the resource — and the middle arm
      // then swallowed the third: the User Portal requires no role, so
      // `requiredRole` is an empty bag, so the second arm is TRUE for
      // everybody, and the policy permitted any signed-in person to reach
      // ANOTHER PERSON'S account. The owner comparison was evaluated, was
      // false, and made no difference, because an `or` does not care.
      //
      // So the shape is a CONJUNCTION of two independent questions:
      //
      //   1. does the subject satisfy the resource's ROLE requirement —
      //      holding one it names, or it naming none;
      //   2. does the subject satisfy the resource's OWNERSHIP requirement —
      //      the resource naming no owner, or the subject BEING the owner.
      //
      // Both must hold. A surface with no owner (the console, the management
      // API, SCIM, the SPIRE Server API) answers question 2 vacuously and
      // behaves exactly as an RBAC policy; a surface with one (the portal)
      // adds ownership on top of whatever role it also requires, rather than
      // offering it as a way round.
      //
      // **A HELPDESK ROLE IS STILL A RULE AND NOT AN EDIT TO THIS ONE.** Under
      // deny-unless-permit, adding a second Permit rule targeted at
      // `manage-own` whose condition is "holds the helpdesk role" reaches
      // somebody else's account without touching this rule at all — which is
      // the property the whole document exists for, and which the OR spelling
      // was pretending to have while giving it to everybody.
      // ---------------------------------------------------------------------
      const roleArms = [holdsRequiredRole];

      if (permitEmpty) {
        // A bag-size test, because XACML cannot ask whether a designator
        // matched: an absent attribute and one with no values are the same
        // empty bag, and here both mean "nobody narrowed this".
        roleArms.push(B.apply(F1 + 'integer-equal', [
          B.apply(F1 + 'string-bag-size', [
            B.designator(model.CATEGORY.RESOURCE,
                         ISSUANCE_ATTRIBUTE.REQUIRED_ROLE, TYPE.STRING)
          ]),
          B.value(TYPE.INTEGER, '0')
        ]));
      }

      const satisfiesRole = roleArms.length === 1
        ? roleArms[0]
        : B.apply(F1 + 'or', roleArms);

      // The resource names nobody. The same bag-size reading as above, and it
      // is what makes this one policy serve every gated surface: only the
      // portal sets an owner, so for the rest this is true and the whole
      // ownership question is vacuous.
      const ownerless = B.apply(F1 + 'integer-equal', [
        B.apply(F1 + 'string-bag-size', [
          B.designator(model.CATEGORY.RESOURCE, ISSUANCE_ATTRIBUTE.OWNER,
                       TYPE.STRING)
        ]),
        B.value(TYPE.INTEGER, '0')
      ]);

      // **THE COMPARISON THAT COULD NOT HAVE BEEN AN `if`.** Two designators
      // compared to each other — the subject's id and the resource's owner —
      // which is a statement about the RELATIONSHIP between them rather than
      // about either one. `any-of-any` because both are bags.
      const isTheOwner = B.apply(F3 + 'any-of-any', [
        { kind: 'function', functionId: F1 + 'string-equal' },
        B.designator(model.CATEGORY.ACCESS_SUBJECT, model.ATTRIBUTE.SUBJECT_ID,
                     TYPE.STRING),
        B.designator(model.CATEGORY.RESOURCE, ISSUANCE_ATTRIBUTE.OWNER,
                     TYPE.STRING)
      ]);

      // `permitOwner: no` leaves `ownerless` alone, so a resource that names
      // an owner is refused to EVERYBODY — including the owner. That is what
      // the parameter's help says it does, and it is the only reading that
      // makes the setting demonstrable: the ownerless surfaces are
      // untouched by it, which is how somebody can see that the portal is the
      // surface the setting is about.
      const satisfiesOwnership = permitOwner
        ? B.apply(F1 + 'or', [ownerless, isTheOwner])
        : ownerless;

      const conjuncts = [];
      if (requireAuth) {
        // AUTHENTICATION IS A CONJUNCT rather than an arm, because it is a
        // precondition and not an alternative: holding a role must not admit
        // somebody who never signed in.
        //
        // `any-of` IS A 3.0 FUNCTION (F3) and not a 1.0 one. Written with F1
        // it is a function id nothing implements, and the engine answers
        // Indeterminate — which under deny-unless-permit is a Deny, so every
        // surface refused everybody and the reason said only "the policy
        // denied it". `any-of-all` is the 1.0 one, which is a different
        // function; the neighbouring namespace is the trap.
        conjuncts.push(B.apply(F3 + 'any-of', [
          { kind: 'function', functionId: F1 + 'boolean-equal' },
          B.value(TYPE.BOOLEAN, 'true'),
          B.designator(model.CATEGORY.ACCESS_SUBJECT,
                       ISSUANCE_ATTRIBUTE.AUTHENTICATED, TYPE.BOOLEAN)
        ]));
      }
      conjuncts.push(satisfiesRole);
      conjuncts.push(satisfiesOwnership);

      const condition = conjuncts.length === 1
        ? conjuncts[0]
        : B.apply(F1 + 'and', conjuncts);

      log.debug('Leaving buildAccessControl(). ' + conjuncts.length +
                ' conjunct(s), ' + roleArms.length + ' role arm(s).');
      return {
        kind: 'Policy',
        id: options.idBase,
        version: '1.0',
        description: 'THE ACCESS-CONTROL POLICY. The embedded PEP asks this ' +
                     'before a subject reaches the admin console, the ' +
                     'management API, the User Portal, SCIM or the SPIRE ' +
                     'Server API. It permits when the subject satisfies the ' +
                     'resource\'s ROLE requirement — holding a role it ' +
                     'requires' +
                     (permitEmpty ? ', or the resource requiring none' : '') +
                     ' — AND satisfies its OWNERSHIP requirement: the ' +
                     'resource names no owner' +
                     (permitOwner ? ', or the subject IS that owner, which ' +
                                    'is how a person reaches their own ' +
                                    'account and nobody else\'s' : '') +
                     (requireAuth ? '. A subject that did not authenticate ' +
                                    'is refused whatever else is true' : '') +
                     '. Everything else is denied: the combining algorithm ' +
                     'is deny-unless-permit, so an access decision does not ' +
                     'depend on a PEP\'s bias.',
        combiningAlgId: model.RULE_ALG.DENY_UNLESS_PERMIT,
        // NO TARGET, for `role-issuance`'s reason: one caller asks this
        // document and only ever about an access decision, so a target
        // restating that could only refuse a request the PEP would not have
        // made — as NotApplicable, which under deny-unless-permit reads as a
        // Deny nobody can explain.
        target: null,
        variables: {},
        rules: [{
          id: options.idBase + ':rule:may-reach-it',
          effect: model.EFFECT.PERMIT,
          description: 'Permit when the subject satisfies the resource\'s ' +
                       'role requirement AND its ownership requirement. ' +
                       'Ownership is a constraint rather than a way round ' +
                       'the roles: a resource that names an owner is ' +
                       'reachable only by that owner.',
          target: null,
          condition: condition,
          obligations: [], advice: []
        }],
        obligations: [], advice: []
      };
    }
  },
  {
    id: 'rbac',
    label: 'Role-based (RBAC)',
    blurb: 'A permission is granted to a ROLE, and the role is an attribute ' +
           'of the subject. The shape most deployments already have.',
    what: 'Produces one Permit rule per role, each matching a role value ' +
          'against a subject attribute and — where the role is limited to ' +
          'certain actions — those actions too. The combining algorithm is ' +
          'deny-unless-permit, so anything not granted is denied and the ' +
          'answer never depends on the PEP\'s bias.',
    parameters: [
      { name: 'roleAttribute', label: 'The subject attribute holding the role',
        dflt: 'employeeType', type: 'string',
        help: 'A bare directory attribute name is read off the person\'s own ' +
              'entry by the PIP. `employeeType` is what the seeded people ' +
              'here carry.' },
      { name: 'adminRoles', label: 'Roles that may do anything',
        dflt: 'admin', type: 'list',
        help: 'Comma- or newline-separated. Each gets a rule with no action ' +
              'restriction.' },
      { name: 'readerRoles', label: 'Roles limited to certain actions',
        dflt: 'staff', type: 'list',
        help: 'Each gets a rule that also matches the actions below.' },
      { name: 'readerActions', label: 'The actions those roles may perform',
        dflt: 'GET, HEAD', type: 'list',
        help: 'Matched against the standard action-id attribute.' }
    ],
    build: function (answers, options) {
      log.debug('Entering buildRbac().');
      const roleAttribute = answers.roleAttribute || 'employeeType';
      const actions = B.listOf(answers.readerActions);
      const rules = [];
      B.listOf(answers.adminRoles).forEach(function (role) {
        rules.push({
          id: options.idBase + ':rule:' + B.slug(role) + '-anything',
          effect: model.EFFECT.PERMIT,
          description: 'Anyone whose ' + roleAttribute + ' is "' + role +
                       '" may perform any action.',
          target: B.targetOf([[
            B.match(F1 + 'string-equal', B.value(TYPE.STRING, role),
                    B.designator(model.CATEGORY.ACCESS_SUBJECT,
                                 roleAttribute, TYPE.STRING))
          ]]),
          condition: null, obligations: [], advice: []
        });
      });
      B.listOf(answers.readerRoles).forEach(function (role) {
        rules.push({
          id: options.idBase + ':rule:' + B.slug(role) + '-limited',
          effect: model.EFFECT.PERMIT,
          description: 'Anyone whose ' + roleAttribute + ' is "' + role +
                       '" may perform ' +
                       (actions.length ? actions.join(', ') : 'any action') +
                       '.',
          // TWO AnyOf GROUPS, WHICH IS AN AND. The role must match AND the
          // action must be one of the listed ones. Putting both matches in one
          // AllOf would also be an AND but would require BOTH to be about the
          // same category, and putting them in one AnyOf would be an OR —
          // which is the mistake that grants every action to anybody holding
          // the role.
          target: B.targetOf([
            [B.match(F1 + 'string-equal', B.value(TYPE.STRING, role),
                     B.designator(model.CATEGORY.ACCESS_SUBJECT,
                                  roleAttribute, TYPE.STRING))],
            actions.map(function (action) {
              return B.match(F1 + 'string-equal',
                             B.value(TYPE.STRING, action),
                             B.designator(model.CATEGORY.ACTION,
                                          model.ATTRIBUTE.ACTION_ID,
                                          TYPE.STRING));
            })
          ]),
          condition: null, obligations: [], advice: []
        });
      });
      log.debug('Leaving buildRbac(). ' + rules.length + ' rule(s).');
      return {
        kind: 'Policy',
        id: options.idBase,
        version: '1.0',
        description: 'Role-based access control on the subject attribute "' +
                     roleAttribute + '". Anything not granted below is ' +
                     'denied, because the combining algorithm is ' +
                     'deny-unless-permit.',
        combiningAlgId: model.RULE_ALG.DENY_UNLESS_PERMIT,
        target: null,
        variables: {},
        rules: rules,
        obligations: [], advice: []
      };
    }
  },
  {
    id: 'abac',
    label: 'Attribute-based (ABAC)',
    blurb: 'A permission is granted on what is TRUE about the subject, the ' +
           'resource and the action — no roles anywhere.',
    what: 'Produces one Permit rule whose Target selects the resource and ' +
          'whose Condition is the conjunction of every attribute test you ' +
          'ask for. This is the shape that shows what XACML is actually ' +
          'for: the condition is an expression rather than a lookup, so a ' +
          'rule can compare two attributes with each other rather than each ' +
          'against a constant.',
    parameters: [
      { name: 'resource', label: 'The resource this applies to',
        dflt: 'https://example.test/records', type: 'string',
        help: 'Matched against the standard resource-id attribute. Leave it ' +
              'empty to apply to every resource.' },
      { name: 'actions', label: 'The actions it permits',
        dflt: 'GET', type: 'list',
        help: 'Comma- or newline-separated. Empty means any action.' },
      { name: 'subjectAttribute', label: 'A subject attribute to test',
        dflt: 'departmentNumber', type: 'string',
        help: 'A bare directory attribute name, read off the person\'s own ' +
              'entry by the PIP.' },
      { name: 'subjectValue', label: 'The value it must equal',
        dflt: '42', type: 'string',
        help: 'Compared as a string.' },
      { name: 'clearanceAttribute',
        label: 'A numeric subject attribute (optional)',
        dflt: '', type: 'string',
        help: 'If set, the rule additionally requires this attribute to be ' +
              'at least the level below. This is the part RBAC cannot ' +
              'express without a role per level.' },
      { name: 'clearanceMinimum', label: 'The minimum it must reach',
        dflt: '3', type: 'string', help: 'An integer.' }
    ],
    build: function (answers, options) {
      log.debug('Entering buildAbac().');
      const actions = B.listOf(answers.actions);
      const groups = [];
      if (answers.resource) {
        groups.push([B.match(F1 + 'anyURI-equal',
                             B.value(TYPE.ANYURI, answers.resource),
                             B.designator(model.CATEGORY.RESOURCE,
                                          model.ATTRIBUTE.RESOURCE_ID,
                                          TYPE.ANYURI))]);
      }
      if (actions.length) {
        groups.push(actions.map(function (action) {
          return B.match(F1 + 'string-equal', B.value(TYPE.STRING, action),
                         B.designator(model.CATEGORY.ACTION,
                                      model.ATTRIBUTE.ACTION_ID,
                                      TYPE.STRING));
        }));
      }
      const tests = [];
      if (answers.subjectAttribute) {
        // `string-is-in(value, bag)` rather than
        // `string-equal(value, one-and-only(bag))`, and the difference is the
        // whole reason to prefer it: a person with TWO values for the
        // attribute makes `one-and-only` Indeterminate, and makes `is-in`
        // true if either matches. A multi-valued directory attribute is the
        // normal case, not the exception.
        tests.push(B.apply(F1 + 'string-is-in', [
          B.value(TYPE.STRING, answers.subjectValue || ''),
          B.designator(model.CATEGORY.ACCESS_SUBJECT,
                       answers.subjectAttribute, TYPE.STRING)
        ]));
      }
      if (answers.clearanceAttribute) {
        tests.push(B.apply(F1 + 'integer-greater-than-or-equal', [
          B.apply(F1 + 'integer-one-and-only', [
            B.designator(model.CATEGORY.ACCESS_SUBJECT,
                         answers.clearanceAttribute, TYPE.INTEGER)
          ]),
          B.value(TYPE.INTEGER, answers.clearanceMinimum || '0')
        ]));
      }
      // A Condition must be exactly one boolean. One test is that test; two or
      // more are an `and`; none at all means the Target alone decides, and the
      // rule carries no Condition rather than one that is trivially true —
      // `and()` with no arguments IS true, and writing it would be a puzzle
      // for the next reader.
      let condition = null;
      if (tests.length === 1) {
        condition = tests[0];
      } else if (tests.length > 1) {
        condition = B.apply(F1 + 'and', tests);
      }
      log.debug('Leaving buildAbac(). ' + tests.length + ' test(s).');
      return {
        kind: 'Policy',
        id: options.idBase,
        version: '1.0',
        description: 'Attribute-based access control. The Target selects the ' +
                     'resource and action; the Condition is what must be ' +
                     'true about the subject. Anything not permitted is ' +
                     'denied.',
        combiningAlgId: model.RULE_ALG.DENY_UNLESS_PERMIT,
        target: null,
        variables: {},
        rules: [{
          id: options.idBase + ':rule:permit',
          effect: model.EFFECT.PERMIT,
          description: 'Permit when every attribute test holds.',
          target: B.targetOf(groups),
          condition: condition,
          obligations: [], advice: []
        }],
        obligations: [], advice: []
      };
    }
  },
  {
    // -----------------------------------------------------------------------
    // THE BLANK ONE, AND IT IS THE ODD ROW IN THIS TABLE.
    //
    // Every other template here is an argument — RBAC against ABAC, and the
    // two documents this service asks about itself. This one makes no
    // argument at all: it produces an EMPTY Policy or an EMPTY PolicySet with
    // a name, a version and a combining algorithm and nothing inside it, and
    // hands it to the editor.
    //
    // The header of this file says a template is "the first twenty clicks
    // already made", and that sentence is why this row did not exist for the
    // first four. It is still true of the other four; what it missed is that
    // SOMEBODY WHO WANTS TO WRITE THE POLICY THEMSELVES had no door at all.
    // Deleting the rules out of an RBAC policy is not the same starting point
    // — it leaves the RBAC PolicyId, the RBAC description and whatever the
    // template's own name was — and until this row the only way to reach an
    // empty document was to write ALFA, which is a second language to learn
    // before you may use the editor at all.
    //
    // **THIS IS ALSO THE ONLY WAY TO CREATE A PolicySet FROM THE CONSOLE.**
    // The other four all build a `Policy`, so the whole PolicySet half of the
    // editor — nested policies, `PolicyIdReference`, the policy-combining
    // menu, which is a different set of URIs from the rule-combining one —
    // was reachable only by importing ALFA's `policyset`. That was a gap
    // rather than a decision, and it is closed by a parameter rather than by
    // a fifth and sixth row, because the two documents differ in their
    // children and in nothing else a person choosing between them cares
    // about.
    //
    // WHAT IT DECIDES BEFORE YOU EDIT IT, which is the thing to know before
    // making it the root: an empty deny-unless-permit document DENIES. It
    // does not answer NotApplicable and it is not inert. That is the same
    // choice `xacml_editor.ts` makes for a child policy added in the editor,
    // and for the same reason — this editor is LIVE, so a blank document that
    // started life permitting whatever reached it would be a hole opened by
    // pressing Create. The `blurb` says so on the page, because the person
    // pressing Create is exactly the person who has not read this file.
    // -----------------------------------------------------------------------
    id: 'blank',
    label: 'Blank (for the brave)',
    blurb: 'An empty document with nothing in it: a name, a version and a ' +
           'combining algorithm. IT DENIES EVERYTHING until you add a rule, ' +
           'because deny-unless-permit over nothing at all is a Deny — so ' +
           'build it before you make it the root.',
    what: 'Produces a Policy with no rules, or a PolicySet with no policies. ' +
          'No Target, so it applies to every request; deny-unless-permit, so ' +
          'it refuses every one of them until you say otherwise. This is the ' +
          'starting point for writing a policy in the editor rather than ' +
          'editing one somebody else shaped, and it is the only way to ' +
          'create a PolicySet here without importing ALFA. The combining ' +
          'algorithm is a dropdown on the document\'s own row in the editor, ' +
          'so it is not a parameter here.',
    parameters: [
      { name: 'kind', label: 'Policy or PolicySet', dflt: 'policy',
        type: 'string',
        help: 'policy or policyset. A Policy holds RULES and a PolicySet ' +
              'holds POLICIES — a nested one, or a PolicyIdReference naming ' +
              'another entry in this repository, which is how a PDP reaches ' +
              'more than one document. ANYTHING BUT "policyset" MEANS A ' +
              'POLICY, which is the reading `yes` and `no` get everywhere ' +
              'else on these forms; the Kind column on this page says which ' +
              'you got before you have clicked anything else.' }
    ],
    build: function (answers, options) {
      log.debug('Entering buildBlank().');
      const given = answers || {};
      const set = String(given.kind || '').trim().toLowerCase() === 'policyset';
      const policy: any = {
        kind: set ? 'PolicySet' : 'Policy',
        id: options.idBase,
        version: '1.0',
        description: 'An empty ' + (set ? 'PolicySet' : 'Policy') +
                     ' to build on. It ' +
                     (set ? 'holds no policies' : 'holds no rules') +
                     ' yet, and deny-unless-permit over nothing at all is a ' +
                     'DENY — so this document refuses every request until ' +
                     'you put something in it. Edit this description: it is ' +
                     'what the next person reads first.',
        // DENY-UNLESS-PERMIT, and the two spellings are genuinely different
        // URIs rather than one with a word swapped — a PolicySet carrying the
        // rule-combining spelling names an algorithm that does not exist for
        // it. `xacml_editor.ts` chooses the menu by the node for the same
        // reason.
        combiningAlgId: set ? model.POLICY_ALG.DENY_UNLESS_PERMIT
                            : model.RULE_ALG.DENY_UNLESS_PERMIT,
        // NO TARGET, so it applies to every request. An empty document that
        // applied to nothing would be TWO things to undo before it decided
        // anything, and the second one is invisible: a target nobody added is
        // easy to add, where a target that is there and matches nothing looks
        // exactly like a policy that is working.
        target: null,
        obligations: [], advice: []
      };
      if (set) {
        policy.children = [];
      } else {
        policy.variables = {};
        policy.rules = [];
      }
      log.debug('Leaving buildBlank(). An empty ' + policy.kind + '.');
      return policy;
    }
  }
];

class XacmlTemplates {
  static readonly ISSUANCE_ATTRIBUTE = ISSUANCE_ATTRIBUTE;
  static readonly RISK_ATTRIBUTE = RISK_ATTRIBUTE;
  static readonly RISK_RESPONSE = RISK_RESPONSE;
  static readonly TEMPLATES = TEMPLATES;

  constructor(private readonly deps: XacmlTemplatesDeps) {
    deps.log.debug("Entering XacmlTemplates.constructor().");
    deps.log.debug("Leaving XacmlTemplates.constructor().");
  }

  // What the composition root passes: the real table and logger.
  static defaultDeps(): XacmlTemplatesDeps {
    helpers.log.debug("Entering XacmlTemplates.defaultDeps().");
    helpers.log.debug("Leaving XacmlTemplates.defaultDeps().");
    return {
      log: log,
      templates: TEMPLATES
    };
  }

  lookup(id: string): TemplateRow | null {
    const { log, templates } = this.deps;
    log.debug("Entering XacmlTemplates.lookup().");
    log.debug("Leaving XacmlTemplates.lookup().");
    return templates.filter(function (one) {
      return one.id === id;
    })[0] || null;
  }

  // -------------------------------------------------------------------------
  // BUILD ONE.
  //
  // `answers` is whatever the form or the management API sent; missing
  // parameters fall back to the row's `dflt`, so a caller may send none at all
  // and get the documented example. That is deliberate: the management API's
  // "create from template" with an empty body should produce something,
  // because the first thing anybody does with an API is call it with nothing.
  // -------------------------------------------------------------------------
  build(id: string, answers?: Record<string, unknown> | null,
        options?: { name?: string; idBase?: string } | null): BuildResult {
    const { log, templates } = this.deps;
    log.debug('Entering XacmlTemplates.build(). template=' + id);
    const template = this.lookup(id);
    if (!template) {
      log.debug('Leaving XacmlTemplates.build(). No such template.');
      return { ok: false,
               why: 'There is no template "' + id + '". The ones here are: ' +
                    templates.map(function (one) {
                      return one.id;
                    }).join(', ') + '.' };
    }
    const settings = options || {};
    const filled: Record<string, string> = {};
    template.parameters.forEach(function (parameter) {
      const given = answers ? answers[parameter.name] : undefined;
      filled[parameter.name] = (given === undefined || given === null ||
                                String(given).trim() === '')
        ? parameter.dflt : String(given).trim();
    });
    const name = settings.name || template.id;
    const policy = template.build(filled, {
      idBase: settings.idBase || 'urn:sts:xacml:policy:' + B.slug(name)
    });
    // A PolicySet HAS NO `rules`, and this line said `undefined rule(s)` for
    // one from the moment the blank template could build one. What a document
    // holds is named by what it IS.
    log.debug('Leaving XacmlTemplates.build(). ' +
      (policy.kind === 'PolicySet'
        ? (policy.children || []).length + ' child policy(ies).'
        : (policy.rules || []).length + ' rule(s).'));
    return { ok: true, policy: policy, answers: filled, template: template };
  }

  // What the console and the management API list. Derived, so a template
  // added to the table above appears in both with no second edit.
  catalogue(): object[] {
    const { log, templates } = this.deps;
    log.debug("Entering XacmlTemplates.catalogue().");
    log.debug("Leaving XacmlTemplates.catalogue().");
    return templates.map(function (one) {
      return { id: one.id, label: one.label, blurb: one.blurb, what: one.what,
               parameters: one.parameters.map(function (parameter) {
                 return { name: parameter.name, label: parameter.label,
                          help: parameter.help, type: parameter.type,
                          dflt: parameter.dflt };
               }) };
    });
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<XacmlTemplates>(
  'xacml/xacml_templates',
  () => new XacmlTemplates(XacmlTemplates.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  XacmlTemplates: XacmlTemplates,
  installInstance: (instance: XacmlTemplates): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  PolicyBuilders: PolicyBuilders,
  ISSUANCE_ATTRIBUTE: XacmlTemplates.ISSUANCE_ATTRIBUTE,
  RISK_ATTRIBUTE: XacmlTemplates.RISK_ATTRIBUTE,
  RISK_RESPONSE: XacmlTemplates.RISK_RESPONSE,
  TEMPLATES: XacmlTemplates.TEMPLATES,
  lookup: slot.forward('lookup'),
  build: slot.forward('build'),
  catalogue: slot.forward('catalogue'),
  listOf: PolicyBuilders.listOf,
  slug: PolicyBuilders.slug
};
