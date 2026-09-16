'use strict';
//
// File: group_claims.ts
//
// ---------------------------------------------------------------------------
// THE DIRECTORY'S GROUPS, IN A TOKEN.
//
// For anybody who is a member of a group in the embedded LDAP directory, every
// OAuth 2.0 access token, OIDC ID Token, UserInfo response, SAML 2.0 assertion
// and SAML 1.1 assertion this service issues carries a claim naming those
// groups — all five claim sets in `admin_stats.js`. It is
// automatic — there is nothing to tick per user and nothing to tick per set —
// and `groups.claim` turns the whole of it off.
//
// ---------------------------------------------------------------------------
// WHAT THIS DOES NOT CHANGE, AND THE SENTENCE IT DOES CHANGE.
//
// THE CLAIM GRANTS NOTHING. No endpoint in this service reads this claim and
// nothing decides anything on it. /admin/groups says so and goes on saying so.
//
// A GROUP ITSELF CAN GRANT SOMETHING NOW, AND NONE OF IT GOES THROUGH HERE.
// This paragraph used to say a group granted nothing at all, bar two. By now:
// `admin.readGroup` and `admin.writeGroup` (`cn=admin-read`, `cn=admin-write`)
// decide who may use the ADMIN CONSOLE (`admin-ui/admin_rbac.js`);
// `roles.remotePepGroup` and `roles.xacmlUserGroup` grant the built-in
// REMOTE_PEPS and XACML_USER roles; and a group may be a member of a
// configured role in `ou=roles` (`common/roles.js`). Every one of those reads
// the DIRECTORY at decision time, never this claim: the groups are put in the
// claim exactly like any other group a person is in. A client that saw
// `admin-write` in an access token and concluded the token could do something
// would be making precisely the mistake the paragraph above is about.
//
// What stopped being true is the OTHER half of that sentence, which used to run
// "...and no token carries a group from this directory". One now can. The two
// are different claims and merging them is the mistake to avoid — it is the
// same distinction this service already draws between an identity being
// RECORDED and an identity being AUTHENTICATED (a verified TLS client
// certificate, a presentation that verifies at the OID4VP Verifier). Carrying
// a fact is not acting on it.
//
// Why it is worth carrying at all: a groups claim is one of the two or three
// things a relying party actually branches on, and until now there was no way
// to produce one here. A client whose authorization code has never seen a
// `groups` member, or has only ever seen names where the next identity provider
// will send DNs, has never run that code. That is the whole value of this
// service, and `groups.claimValue` exists so both shapes are reachable.
//
// ---------------------------------------------------------------------------
// SIX THINGS ARE LOAD-BEARING.
//
// **It is a LIBRARY (rule 3) and it registers no route**, so its position in
// the require order is not a position at all. It requires `helpers.js`,
// `config.js`, `applications.js`, `admin_stats.js` and `error_codes.js`, and
// none of those requires it back — which
// is what keeps it out of the cycles rule 2 exists for. In particular
// `admin_stats.js` CANNOT require it: this file requires that one (for the
// set ids, the reserved names and `identityKeyOf()`), so a require in the other
// direction would close a loop and node would hand back a half-initialised
// module whose exports are undefined. The symptom would arrive later and
// somewhere else as something that is not a function.
//
// **So the merge into a token is INVERTED, exactly as `claim_attributes.ts`'s
// is.** `admin_stats.js` offers `setGroupResolver()` and this file fills it at
// ITS require time. That is what buys the thing that matters: NO ISSUANCE SITE
// CHANGED. `oauth2.js`'s calls to `stats.jwtClaims()` and the two assertion
// builders' calls to `stats.samlAttributes()` are the lines they always were,
// and the groups claim arrives through them. Four edited call sites would have
// been four that drift and a fifth added later that nobody remembers — the same
// reasoning that keeps `signJwt()` the single token counter.
//
// **AND THE DIRECTORY ARRIVES THROUGH A SECOND SLOT, pointing the other way.**
// The membership can only be answered by `ldap_server.js`, which
// `common/protocol_stack.js` requires at 21 (rule 6): requiring it from here
// would drag every `/ldap` route to the front of the express router that
// `/admin/sts-metadata` is built by walking. So this file offers
// `setDirectory()` and that one fills it, the same shape `vc_claims.js` and
// `applications.js` already have.
//
// **THE CLAIM IS OMITTED ENTIRELY FOR SOMEBODY IN NO GROUP.** Not an empty
// array — absent. That is what makes `groups.claim` defensible as ON by
// default: on a fresh start the only people in a group are the ones the
// directory seeds, so a caller who has never touched `ou=groups` gets the
// tokens it got before this file existed. An empty array would be a new member
// in every token every existing client parses, which is the upgrade this
// repository's claim-attribute selection defaults to nothing to avoid.
//
// **THE MEMBERSHIP IS READ PER TOKEN, never cached.** That is the same rule
// `applications.js` follows for the registry and for the same reason: it is
// what makes an `ldapadd` of a member change the very next token, which is the
// thing somebody came here to watch. There is nothing to gain by a cache on a
// mock whose store is a Map in this process.
//
// **A RESERVED NAME IS REFUSED AT ISSUANCE, NOT AT CONFIGURATION TIME.**
// `config.js` requires nothing from this repository — that is deliberate and
// `helpers.js` requires IT — so the reserved list cannot be reached from a
// `check` over there without copying it, and a copied list is one that goes
// wrong. So the refusal is here, it logs, and the token goes out without the
// claim rather than with an `exp` a web form could set. Same rule
// `setClaimSet()` applies to a typed claim, made in the only place that can
// make it.
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `GroupClaims` takes the logger, the settings, the application
// registry, the claim-set registry (`admin_stats.js`) and the error codes
// through its constructor, and holds the directory slot. The module still
// exports every old name from a TRANSITIONAL instance — `setDirectory` among
// them, the slot `ldap/ldap_server.js` fills — and that instance FILLS
// `stats.setGroupResolver()` at require time, at the same point the original
// did: before the load line and before the exports (`export =` is emitted
// last), and nothing calls this module's exports during the fill.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import config = require('./config');
// The claim sets, the reserved names, the SAML 1.1 default namespace and
// the identity normalisation. This is the module whose slot is filled at the
// bottom of this file, and the dependency runs in this direction only.
// A LIBRARY REQUIRING A LIBRARY (rule 3e's test): applications.js registers no
// route and requires nothing that requires this, so it closes no cycle and
// moves nothing in the router. It is here for the four per-application
// overrides the functions below resolve.
import applications = require('./applications');
import stats = require('./admin_stats');
// The registry of failure codes, a LEAF — see common/error_codes.js.
import errorCodes = require('./error_codes');

const { log } = helpers;

// One group as `ldap_server.js`'s groupsOfUser() reports it.
interface GroupRow {
  dn?: string;
  cn?: string;
  via: unknown[];
  viaMemberOf?: unknown;
  [member: string]: unknown;
}

// What `ldap_server.js` installs through `setDirectory()`.
interface DirectoryHooks {
  groupsOfUser?(key: string): { dn: string; entryFound?: boolean;
                                groups: GroupRow[] } | null;
}

// The two kinds of context the resolver halves are handed.
interface IssuanceContext {
  username?: unknown;
  subject?: unknown;
  client_id?: unknown;
  audience?: unknown;
  [member: string]: unknown;
}

// What this module needs from the rest of the service. Named for what is
// asked of each, so a test can supply exactly that and nothing more.
interface GroupClaimsDeps {
  log: typeof helpers.log;
  config: unknown;
  applications: {
    settingFor(identifier: string, settingKey: string, config: any): any;
  };
  stats: {
    identityKeyOf(value: unknown): string;
    RESERVED_JWT_CLAIMS: string[];
    DEFAULT_SAML11_NAMESPACE: string;
    CLAIM_SET_IDS: string[];
    setGroupResolver(hooks: unknown): void;
  };
  errorCodes: {
    mark<T>(target: T, code: string): T;
    tag(code: string): string;
  };
}

class GroupClaims {
  // -------------------------------------------------------------------------
  // THE DIRECTORY SLOT. See the header for why the direction is this way
  // round.
  //
  // One function: groupsOfUser(key), which answers "which groups is this
  // person in" for one identity key. What counts as a group, how a member
  // value is resolved, and where the containers are stay over there — this
  // module decides what to DO with the answer and nothing about what the
  // answer is.
  // -------------------------------------------------------------------------
  private directory: DirectoryHooks | null = null;

  constructor(private readonly deps: GroupClaimsDeps) {
    deps.log.debug("Entering GroupClaims.constructor().");
    deps.log.debug("Leaving GroupClaims.constructor().");
  }

  // -------------------------------------------------------------------------
  // The settings, read PER TOKEN rather than captured here.
  //
  // All four are `runtime: true` in config.js's table, and a module-level
  // `const` is the one thing /admin/config cannot reach — it would fail in the
  // direction that looks like the console is broken. So they are functions,
  // the same way `maxEntries()` and `clockSkewSeconds()` are.
  // -------------------------------------------------------------------------
  // -------------------------------------------------------------------------
  // ALL FOUR ARE PER APPLICATION SINCE 2026-08-27, AND THESE FOUR FUNCTIONS
  // ARE THE ONLY PLACE THAT IS DECIDED.
  //
  // Each takes the application a token or an assertion is being issued TO and
  // answers what that application should get: `appGroupsClaim` and its three
  // siblings on the entry where they are set, and the service-wide setting
  // where they are not.
  //
  // THIS IS THE ONE OVERRIDE GROUP THAT IS NOT A PROTOCOL'S, and that is the
  // point of it: all four claim sets come through here, so one application
  // entry answers for that application's access token, its ID Token, its SAML
  // 2.0 assertion and its SAML 1.1 one at once. An application declared for
  // two protocols gets the same claim name in both, which is what a claim
  // mapping should do and is why these are four attributes rather than eight.
  //
  // AN EMPTY `app` GETS THE SERVICE-WIDE VALUE, which is what every caller got
  // before this existed — and is deliberately what the console's preview gets,
  // because a preview with no application in mind is asking what the DEFAULT
  // does. groupsOf() says so in its answer.
  enabled(app?: unknown): boolean {
    const { log, applications, config } = this.deps;
    log.debug("Entering GroupClaims.enabled().");
    log.debug("Leaving GroupClaims.enabled().");
    return !!applications.settingFor((app || '') as string, 'groups.claim',
                                     config);
  }

  claimName(app?: unknown): string {
    const { log, applications, config } = this.deps;
    log.debug("Entering GroupClaims.claimName().");
    log.debug("Leaving GroupClaims.claimName().");
    return String(applications.settingFor((app || '') as string,
                                          'groups.claimName',
                                          config) || '').trim();
  }

  valueForm(app?: unknown): string {
    const { log, applications, config } = this.deps;
    log.debug("Entering GroupClaims.valueForm().");
    log.debug("Leaving GroupClaims.valueForm().");
    return String(applications.settingFor((app || '') as string,
                                          'groups.claimValue',
                                          config) || 'cn').trim();
  }

  memberOfCounts(app?: unknown): boolean {
    const { log, applications, config } = this.deps;
    log.debug("Entering GroupClaims.memberOfCounts().");
    log.debug("Leaving GroupClaims.memberOfCounts().");
    return !!applications.settingFor((app || '') as string,
                                     'groups.claimFromMemberOf', config);
  }

  // WHICH APPLICATION A CLAIM IS BEING BUILT FOR, out of the context both
  // resolver halves are handed. `client_id` is what an OAuth 2.0 or OIDC
  // context carries and `audience` is what a SAML one does — the service
  // provider's entityID, or the SAML 1.1 relying party — and the registry
  // files an application under either, so one lookup answers for all four
  // claim sets.
  private appOf(context: IssuanceContext | null | undefined): string {
    const { log } = this.deps;
    log.debug("Entering GroupClaims.appOf().");
    const ctx = context || {};
    log.debug("Leaving GroupClaims.appOf().");
    return String(ctx.client_id || ctx.audience || '');
  }

  setDirectory(hooks: DirectoryHooks | null | undefined): void {
    const { log } = this.deps;
    log.debug("Entering GroupClaims.setDirectory().");
    this.directory = hooks || null;
    log.debug("A directory was installed; the groups claim can now be read " +
              "from the embedded LDAP directory.");
    log.debug("Leaving GroupClaims.setDirectory().");
  }

  private directoryLoaded(): boolean {
    const { log } = this.deps;
    log.debug("Entering GroupClaims.directoryLoaded().");
    log.debug("Leaving GroupClaims.directoryLoaded().");
    return !!(this.directory &&
              typeof this.directory.groupsOfUser === 'function');
  }

  // Wrapped, for the reason every other directory read in this service is
  // wrapped: a store this service consults must never be able to fail the
  // issuance it was consulted during. A token missing its groups claim is a
  // bug somebody can see and diagnose; a token endpoint returning 500 because
  // an entry was mid-write is a bug that looks like the token endpoint.
  //
  // This comment used to say readGroups(), nameProblem() and valuesFrom()
  // carry no Entering/Leaving pair because groupsOf() already brackets them.
  // The 2026-09-12 style sweep gave all three a pair, so the log now shows
  // them.
  private readGroups(username: string) {
    const { log, stats, errorCodes } = this.deps;
    log.debug("Entering GroupClaims.readGroups().");
    if (!this.directoryLoaded()) {
      log.debug("Leaving GroupClaims.readGroups().");
      return null;
    }
    try {
      // Normalised for the reason vc_claims.js's directoryAttributes() gives:
      // the directory files a person under their local name, so an access
      // token's `urn:uuid:<entryUUID>` and a Kerberos `alice@REALM` would
      // otherwise look up an entry nothing ever created. identityKeyOf() is
      // the one place that mapping is made, which is what keeps `alice` one
      // person here and one person on /admin/users.
      log.debug("Leaving GroupClaims.readGroups().");
      return this.directory.groupsOfUser(stats.identityKeyOf(username)) ||
        null;
    } catch (e) {
      log.error(errorCodes.tag('STS-REG-0045') +
                'the directory threw while being read for the groups claim ' +
                'and was ignored; the token is issued without it: ' +
                e.message);
      log.debug("Leaving GroupClaims.readGroups().");
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // Is the configured name usable?
  //
  // Returned as a reason string rather than a boolean, because both the
  // console and the management API have to be able to SAY why a claim that is
  // switched on is not arriving. "It is configured and nothing appears in my
  // token" is the single most expensive way for this to fail, and an empty
  // reason is what turns it into a support question.
  // -------------------------------------------------------------------------
  private nameProblem(app?: unknown): string {
    const { log, stats } = this.deps;
    log.debug("Entering GroupClaims.nameProblem().");
    const name = this.claimName(app);
    if (!name) {
      log.debug("Leaving GroupClaims.nameProblem().");
      return 'groups.claimName is empty, so there is no claim to add.';
    }
    if (stats.RESERVED_JWT_CLAIMS.indexOf(name) >= 0) {
      log.debug("Leaving GroupClaims.nameProblem().");
      return '"' + name + '" is one of the names this service sets itself (' +
             stats.RESERVED_JWT_CLAIMS.join(', ') + '), so it is refused for ' +
             'the same reason a typed custom claim of that name is: a ' +
             'settable `exp` or `scope` would produce tokens that fail to ' +
             'verify, or change what UserInfo answers, with nothing pointing ' +
             'back at the setting. Choose another groups.claimName.';
    }
    log.debug("Leaving GroupClaims.nameProblem().");
    return '';
  }

  // -------------------------------------------------------------------------
  // THE VALUES.
  //
  // `via` and `viaMemberOf` come back per group from ldap_server.js and the
  // choice between them is made HERE, because it is a policy
  // (`groups.claimFromMemberOf`) and that module reports facts. See its
  // groupsOfUser() header for why both answers exist at all: nothing in this
  // directory maintains `memberOf` from the group's member list or the other
  // way round, so a client can create a disagreement in one operation and
  // /admin/groups exists partly to show it.
  //
  // Deduplicated on the VALUE and not on the DN, because two entries can share
  // a `cn` — a `groupOfNames` somebody added under `ou=users` and a real one
  // under `ou=groups` — and a claim listing `developers` twice is a claim every
  // client has to defend against for no reason. First occurrence wins, and the
  // order is the directory's own (DN order), so the same directory produces
  // the same claim every time rather than one that reshuffles between tokens.
  // -------------------------------------------------------------------------
  private valuesFrom(rows: GroupRow[] | null | undefined, form: string,
                     useMemberOf: boolean): string[] {
    const { log } = this.deps;
    log.debug("Entering GroupClaims.valuesFrom().");
    const seen = new Set<string>();
    const out: string[] = [];
    (rows || []).forEach(function (row) {
      if (!row.via.length && !useMemberOf) {
        return;
      }
      const value = form === 'dn' ? String(row.dn || '') :
        String(row.cn || '');
      if (!value || seen.has(value)) {
        return;
      }
      seen.add(value);
      out.push(value);
    });
    log.debug("Leaving GroupClaims.valuesFrom().");
    return out;
  }

  // Everything about one person's groups claim, in one object, so that the
  // issuance path, the console's preview and the management API's reply are
  // three readers of one answer rather than three walks that can disagree.
  // That is the same reason claim_attributes.ts's previewFor() is built on the
  // function the issuance path calls.
  groupsOf(username: unknown, app?: unknown) {
    const { log, stats, errorCodes } = this.deps;
    log.debug("Entering GroupClaims.groupsOf(). user=" + username +
              ", app=" + (app || '(the service-wide defaults)'));
    const out = {
      user: String(username == null ? '' : username),
      key: stats.identityKeyOf(username),
      // WHICH APPLICATION THIS ANSWER IS FOR, reported rather than left
      // implicit: the same person can get two different claim names in two
      // applications, and an answer that did not say which one it was about
      // would be unusable for explaining either.
      application: String(app || ''),
      enabled: this.enabled(app),
      loaded: this.directoryLoaded(),
      claim: this.claimName(app),
      valueForm: this.valueForm(app),
      memberOfCounts: this.memberOfCounts(app),
      reason: '',
      dn: '',
      entryFound: false,
      groups: [] as GroupRow[],
      values: [] as string[]
    };
    if (!out.enabled) {
      out.reason = 'groups.claim is off, so no token or assertion carries a ' +
                   'groups claim.';
      log.debug("Leaving GroupClaims.groupsOf(). The feature is off.");
      return out;
    }
    out.reason = this.nameProblem(app);
    if (out.reason) {
      log.debug("Leaving GroupClaims.groupsOf(). The configured name is " +
                "unusable.");
      // A token is issued WITHOUT the claim somebody switched on. Carried
      // non-enumerably, so the report `/admin/groups` serialises is unchanged.
      return errorCodes.mark(out, 'STS-REG-0046');
    }
    if (!out.loaded) {
      out.reason = 'The embedded LDAP directory is not loaded in this ' +
                   'process, so there are no groups to read. Nothing else is ' +
                   'affected.';
      log.debug("Leaving GroupClaims.groupsOf(). There is no directory.");
      return out;
    }

    const read = this.readGroups(out.user);
    if (!read) {
      out.reason = 'The directory could not be read; the token is issued ' +
                   'without a groups claim.';
      log.debug("Leaving GroupClaims.groupsOf(). The directory read failed.");
      return errorCodes.mark(out, 'STS-REG-0045');
    }
    out.dn = read.dn;
    out.entryFound = !!read.entryFound;
    out.groups = read.groups;
    out.values = this.valuesFrom(read.groups, out.valueForm,
                                 out.memberOfCounts);
    if (!out.values.length) {
      // Not an error and phrased as one of the two ordinary answers, because
      // it is BY FAR the common one and a reader who sees "reason" filled in
      // assumes something is broken otherwise.
      out.reason = read.groups.length
        ? 'This person is named by ' + read.groups.length + ' group(s), but ' +
          'only through their own memberOf, and groups.claimFromMemberOf is ' +
          'off.'
        : 'This person is in no group here, so the claim is omitted ' +
          'entirely rather than sent as an empty list.';
    }
    log.debug("Leaving GroupClaims.groupsOf(). " + out.values.length +
              " group(s) for " + out.dn + ".");
    return out;
  }

  // Who the token is about. The two kinds of caller spell it differently and
  // neither spelling is wrong — oauth2.js's context calls it `username`
  // because that is the claim it carries, and the assertion builders call it
  // `subject` because that is what a SAML Subject is. Reading both here is one
  // line, and it is the same line claim_attributes.ts has for the same reason.
  private subjectOf(context: IssuanceContext | null | undefined): string {
    const { log } = this.deps;
    log.debug("Entering GroupClaims.subjectOf().");
    const ctx = context || {};
    log.debug("Leaving GroupClaims.subjectOf().");
    return String(ctx.username || ctx.subject || '');
  }

  // -------------------------------------------------------------------------
  // What the two resolver halves hand back.
  //
  // Both are shaped so an EMPTY answer is the ordinary one — `{}` and `[]` —
  // and both go through groupsOf() rather than reading the directory
  // themselves, so the console's preview cannot come to disagree with the
  // token.
  //
  // `setId` is accepted and deliberately unread: all five sets carry the
  // claim, because "automatically" is what this feature is for and a per-set
  // selection is what the claim-set pages already offer for everything that
  // wants one. It stays in the signature because the resolver contract has it
  // and because a future per-set rule would go here rather than at five call
  // sites.
  // -------------------------------------------------------------------------
  jwtClaimsFor(setId: unknown,
               context: IssuanceContext | null | undefined) {
    const { log } = this.deps;
    log.debug("Entering GroupClaims.jwtClaimsFor().");
    const answer = this.groupsOf(this.subjectOf(context),
                                 this.appOf(context));
    if (!answer.values.length) {
      log.debug("Leaving GroupClaims.jwtClaimsFor().");
      return {};
    }
    const out: Record<string, string[]> = {};
    out[answer.claim] = answer.values;
    log.debug("Leaving GroupClaims.jwtClaimsFor().");
    return out;
  }

  // A SAML Attribute is multi-valued in both profiles — several
  // <AttributeValue> children under one <Attribute> — and that is how this is
  // emitted, through the `values` member both builders now understand. The
  // alternative was one <Attribute> element per group with the same Name,
  // which is the exact defect samlAttributes()'s dedup filter exists to
  // prevent: a relying party reads the first and silently sees one group where
  // the person is in four.
  samlAttributesFor(setId: unknown,
                    context: IssuanceContext | null | undefined) {
    const { log, stats } = this.deps;
    log.debug("Entering GroupClaims.samlAttributesFor().");
    const answer = this.groupsOf(this.subjectOf(context),
                                 this.appOf(context));
    if (!answer.values.length) {
      log.debug("Leaving GroupClaims.samlAttributesFor().");
      return [];
    }
    const attribute: { name: string; value: string; values: string[];
                       namespace?: string } =
      { name: answer.claim, value: answer.values[0],
        values: answer.values.slice(0) };
    // The same default namespace a typed SAML 1.1 claim gets, for the reason
    // admin_stats.js states beside it: it is the claim namespace every
    // WS-Federation relying party already reads, so an attribute configured
    // with just a name arrives somewhere useful instead of somewhere nothing
    // looks.
    if (setId === 'saml11') {
      attribute.namespace = stats.DEFAULT_SAML11_NAMESPACE;
    }
    log.debug("Leaving GroupClaims.samlAttributesFor().");
    return [attribute];
  }

  // The feature's own state, for the console's section and for all three
  // claim-set pages' JSON replies (`admin-core/admin_views.js`). Built here
  // rather than in admin.js because two surfaces answer it and neither of them
  // should be reading the four settings itself.
  state() {
    const { log, stats } = this.deps;
    log.debug("Entering GroupClaims.state().");
    const out = {
      enabled: this.enabled(),
      loaded: this.directoryLoaded(),
      claim: this.claimName(),
      valueForm: this.valueForm(),
      memberOfCounts: this.memberOfCounts(),
      sets: stats.CLAIM_SET_IDS.slice(0),
      problem: this.enabled() ? this.nameProblem() : '',
      // Said in the reply and not only on the page, because it is the
      // sentence a caller is most likely to get wrong about this feature, and
      // the API is read by people who never open the console.
      grants: 'A group here grants nothing. No endpoint in this service ' +
              'reads this claim and nothing decides anything on it; the ' +
              'token merely carries it. The two admin-console roles are the ' +
              'one exception and are not an exception to THIS sentence: they ' +
              'are read from the directory by /admin and never from this ' +
              'claim, so a token carrying admin-write can still do nothing a ' +
              'token without it cannot.',
      precedence: 'A typed claim and a directory attribute of the same name ' +
                  'both win over the groups claim.',
      settings: ['groups.claim', 'groups.claimName', 'groups.claimValue',
                 'groups.claimFromMemberOf']
    };
    log.debug("Leaving GroupClaims.state(). enabled=" + out.enabled);
    return out;
  }

  // -------------------------------------------------------------------------
  // FILLING THE SLOT.
  //
  // This is the whole of the installation, and it is why no issuance site
  // changed. admin_stats.js calls these two from inside jwtClaims() and
  // samlAttributes(), wraps them, and merges what comes back UNDERNEATH both
  // the typed claims and the directory attributes — see the note on
  // precedence there.
  //
  // Done at require time, at module scope, like every other inverted
  // dependency here (the transitional code below calls this at the point the
  // original filled the slot). A process that never loads this module simply
  // has no groups claim, which is a smaller service and not a broken one.
  // -------------------------------------------------------------------------
  installResolver(): void {
    const { log, stats } = this.deps;
    log.debug("Entering GroupClaims.installResolver().");
    stats.setGroupResolver({
      jwtClaims: this.jwtClaimsFor.bind(this),
      samlAttributes: this.samlAttributesFor.bind(this)
    });
    log.debug("Leaving GroupClaims.installResolver().");
  }
}

// ---------------------------------------------------------------------------
// THE TRANSITIONAL INSTANCE — see the header. Built from the real modules, as
// the composition root will build one, and set going in the original file's
// order: the slot, then the load line, then the exports.
// ---------------------------------------------------------------------------
const groupClaims = new GroupClaims({
  log: log,
  config: config,
  applications: applications,
  stats: stats,
  errorCodes: errorCodes
});

groupClaims.installResolver();

log.info('The group claim is loaded: an access token, an ID Token and both ' +
         'SAML assertions will carry "' + groupClaims.claimName() + '" for ' +
         'anybody who is a member of a group in the embedded directory. It ' +
         'is ' + (groupClaims.enabled() ? 'ON' : 'OFF') + ' (groups.claim), ' +
         'and the claim is omitted entirely for somebody who is in no ' +
         'group. A group here still grants nothing — no endpoint reads this ' +
         'claim.');

export = {
  GroupClaims: GroupClaims,
  setDirectory: groupClaims.setDirectory.bind(groupClaims) as
    GroupClaims['setDirectory'],
  enabled: groupClaims.enabled.bind(groupClaims) as GroupClaims['enabled'],
  claimName: groupClaims.claimName.bind(groupClaims) as
    GroupClaims['claimName'],
  valueForm: groupClaims.valueForm.bind(groupClaims) as
    GroupClaims['valueForm'],
  memberOfCounts: groupClaims.memberOfCounts.bind(groupClaims) as
    GroupClaims['memberOfCounts'],
  groupsOf: groupClaims.groupsOf.bind(groupClaims) as GroupClaims['groupsOf'],
  jwtClaimsFor: groupClaims.jwtClaimsFor.bind(groupClaims) as
    GroupClaims['jwtClaimsFor'],
  samlAttributesFor: groupClaims.samlAttributesFor.bind(groupClaims) as
    GroupClaims['samlAttributesFor'],
  state: groupClaims.state.bind(groupClaims) as GroupClaims['state']
};
