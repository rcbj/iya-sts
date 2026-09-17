'use strict';
//
// File: xacml_store.ts
//
// ---------------------------------------------------------------------------
// THE POLICY STORE, AND `ou=policies` IS IT.
//
// There is no store here. A policy is an entry in the embedded directory under
// `ou=policies`, exactly the way `ou=federations` IS the federation register
// and the SPIFFE registry is its two containers — and for the same three
// reasons, none of which is tidiness:
//
//   1. PERSISTENCE COMES FOR FREE, IN ALL THREE MODES. `persistence/` writes
//      the directory, so a policy survives a restart under `postgres` and
//      under `ldif` with nothing added to any driver. A store of this module's
//      own would have needed a fourth thing to persist, three driver changes,
//      and a migration.
//   2. PER-REALM ISOLATION COMES FOR FREE. The directory is `realms.map()`, so
//      `/realm/acme/...` gets its own `ou=policies` and cannot see the default
//      realm's. A `new Map()` here would have been process-wide, and
//      `tests/realm_isolation.js` exists because that mistake has been made in
//      this repository twice already.
//   3. IT IS INSPECTABLE WITH `ldapsearch`, and it appears on
//      `/admin/ldap/directory` beside everything else, rather than being a
//      private table only this module can show anybody.
//
// This module owns the SCHEMA — what a policy entry carries — and the
// directory functions arrive through `setDirectory()`, filled by
// `ldap/ldap_server.js` at require time. That is the same inverted install
// `federation.js` and `spiffe_registry.js` take, and for the same reason: this
// module must not require `ldap_server.js`, because doing so would drag every
// `/ldap` route into the router at whatever point this file is first loaded.
//
// ---------------------------------------------------------------------------
// A POLICY IS STORED AS ITS XML, AND THE PARSE IS CACHED BESIDE IT.
//
// The entry holds the DOCUMENT — `xacmlPolicyDocument`, the XACML 3.0 XML as
// written — and not a decomposition of it into attributes. Two reasons, and
// the second is the one that matters:
//
//   * a policy is a document somebody authored, and round-tripping it through
//     a set of LDAP attributes would lose comments, ordering and whitespace
//     that a policy author put there on purpose;
//   * an `ldapmodify` of the document is then a policy change, with no way for
//     the stored XML and a parsed copy to disagree — because there is no
//     stored parsed copy. The cache below is keyed by the document's own
//     digest, so editing the entry through ANY door invalidates it.
//
// The indexed attributes beside it (`xacmlPolicyId`, `xacmlVersion`,
// `xacmlEnabled`, `xacmlCombiningAlgId`) are DERIVED from the document at
// write time. They exist so that the console can list policies without parsing
// every one, and they are never read back as the truth about a policy — if one
// disagrees with the document, the document wins and the attribute is stale.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `XacmlStore` takes the logger, the error-code registry, the engine's
// XML reader and the hash it keys the parse cache by through its constructor.
// Both slots — `setDirectory()`, filled by `ldap/ldap_server.js`, and
// `setChangeObserver()`, filled by `xacml.ts` — are methods of it and are
// still exported under their old names, as is every other old name.
//
// R2 (#50): `common/protocol_stack.ts` builds the instance and installs it;
// the old exports are facades for the JavaScript callers, and a process
// without the root builds the default when this module loads. The two
// installed references and the parse cache stay module-level, declared as
// they were.
//
// **`setDirectory()` IS STATIC AND `seed()` IS HELD, BECAUSE
// `ldap/ldap_server.js` CALLS BOTH WHILE IT LOADS** — inside the root's
// require of `admin-ui/crypto_metadata`, before the root reaches this
// module's build line. A facade there would build the default instance
// early, and the root's install would then be refused. Filling a
// module-level reference needs no instance, so `setDirectory()` does not
// ask for one; `seed()` does, so a call made before any instance exists is
// recorded and run by `wire()` when the root installs this module — still
// before anything listens, and against the directory already installed.
// ---------------------------------------------------------------------------

import crypto = require('crypto');
import helpers = require('../common/helpers');
// The error-code registry (a leaf). A refused write's code is marked on the
// RESULT as a non-enumerable property, so the console and `/admin-api` can mark
// their response with it and no serialisation of the result carries it out.
// This module is not one the remote PEP container copies, so the require costs
// that image nothing.
import errorCodes = require('../common/error_codes');
import cacheRegistry = require('../common/cache_registry');
import InstanceSlot = require('../common/instance_slot');
// The engine's vocabulary. Nothing here reads it, but the original required it
// at this point, and an `import` whose name is unused is dropped by the
// compiler — so it stays a bare require, which is kept, to leave the load
// order exactly as it was.
require('./xacml_model');
import xml = require('./xacml_xml');

// The directory functions this module calls, installed by
// `ldap/ldap_server.js`.
interface PolicyDirectory {
  allPolicies(): Array<{ name: string; dn: string;
                         attributes: Record<string, any> }>;
  writePolicy(name: string, attributes: Record<string, any>): any;
  deletePolicy(name: string): any;
  [name: string]: any;
}

// One policy entry, as `all()` answers it.
interface PolicyRow {
  name: string;
  dn: string;
  id: string | null;
  kind: string;
  version: string;
  combiningAlgId: string;
  description: string;
  enabled: boolean;
  isRoot: boolean;
  document: string;
}

// What `write()` is told besides the document.
interface WriteOptions {
  isRoot?: boolean;
  enabled?: boolean;
  description?: unknown;
}

// What `write()` answers.
interface WriteResult {
  ok: boolean;
  why?: string;
  problems?: any;
  id?: string;
  kind?: string;
}

interface XacmlStoreDeps {
  log: { debug(message: string): void; warn(message: string): void };
  errorCodes: {
    tag(code: string): string;
    mark<T>(target: T, code: string): T;
  };
  xml: { parsePolicy(document: string): any };
  sha256Hex(text: string): string;
}

// ---------------------------------------------------------------------------
// THE SCHEMA. Published on `/admin/ldap/*` the way every other container's is,
// because this directory is schemaless and a container of entries carrying
// invented attributes needs to say what they mean somewhere.
// ---------------------------------------------------------------------------
const SCHEMA = {
  objectClasses: [
    { name: 'xacmlPolicy',
      what: 'One XACML 3.0 Policy or PolicySet, stored as the document it ' +
            'was authored as. THIS CONTAINER IS THE POLICY REPOSITORY — an ' +
            'ldapmodify of xacmlPolicyDocument here changes what the PDP ' +
            'decides on the next request.' }
  ],
  attributes: [
    { name: 'xacmlPolicyId',
      what: 'The PolicyId or PolicySetId inside the document. DERIVED at ' +
            'write time and used for listing and for resolving a ' +
            'PolicyIdReference; the document is the truth.' },
    { name: 'xacmlPolicyDocument',
      what: 'The XACML 3.0 XML. THIS IS THE POLICY. Everything else on the ' +
            'entry is derived from it.' },
    { name: 'xacmlVersion',
      what: 'The Version attribute of the document. Derived.' },
    { name: 'xacmlKind',
      what: '"Policy" or "PolicySet". Derived.' },
    { name: 'xacmlCombiningAlgId',
      what: 'The rule- or policy-combining algorithm the document names. ' +
            'Derived, and shown on the console because it is the single ' +
            'most consequential line in a policy.' },
    { name: 'xacmlEnabled',
      what: '"TRUE" or "FALSE". A disabled policy stays in the repository ' +
            'and is not evaluated. NOT derived — it is the one thing here ' +
            'that is a fact about the deployment rather than about the ' +
            'document, which is why it is an attribute rather than a ' +
            'comment in the XML.' },
    { name: 'xacmlIsRoot',
      what: '"TRUE" on the policy the PDP starts from. A repository with no ' +
            'root decides nothing and says so; a repository with two is ' +
            'refused at write time rather than picking one.' },
    { name: 'description',
      what: "The document's own <Description>, where it has one." }
  ]
};

// The directory functions, installed by `ldap/ldap_server.js`.
let directory: PolicyDirectory | null = null;
let warnedAboutNoDirectory = false;

// ---------------------------------------------------------------------------
// THE CHANGE OBSERVER, FILLED BY `xacml.ts`, AND IT IS AN INVERTED HOOK FOR A
// REASON THAT IS PURELY MECHANICAL.
//
// A repository change is what nudges a registered remote PEP (phase five), and
// the nudge lives in `xacml_pep_http.ts` behind the register in
// `xacml_pep_registry.ts` — which requires THIS module, for the sync token it
// computes over the repository's content. So a require in the obvious
// direction closes a cycle, and node answers a cycle with a half-initialised
// module rather than with an error.
//
// **IT IS ALSO NOT THE MECHANISM, AND THAT IS WHY THERE IS EXACTLY ONE OF
// THEM.** Every door that writes a policy through this module moves it — the
// console, the editor, a template, an ALFA import, `/admin-api` — and one door
// does NOT: an `ldapmodify` on 389 changes `xacmlPolicyDocument` without ever
// entering this file. That is a gap in the NUDGE and not in the design, for
// the reason `xacml_pep_http.ts` argues at length: a PEP pulls on its own
// interval and converges regardless, so the worst an unhooked door can cost is
// one polling interval. A second hook down in the directory to close it would
// be buying nothing with a dependency.
// ---------------------------------------------------------------------------
let changeObserver: ((what: string) => void) | null = null;

// Parsed policies, keyed by the SHA-256 of the document text. Keyed by content
// rather than by policy id or DN precisely so that a change made through any
// door — the console, `/admin-api`, an `ldapmodify` on 389, an LDIF restore —
// invalidates it without anything having to remember to.
const parsed = new Map();

// Described to `/admin/caches` (#74, rule 3ap). Unbounded, and said so: the
// entries are the policy documents that have ever been read in this process,
// and a document that is edited leaves its old parse behind.
const parsedCount = cacheRegistry.register({
  name: 'xacml.parsed-policies',
  title: 'Parsed XACML policies',
  description: 'Policies and policy sets from ou=policies, parsed and ' +
    'statically validated once per document text, keyed by the SHA-256 of ' +
    'that text so a change through any door is a new entry.',
  owner: 'xacml/xacml_store.ts',
  scope: 'process',
  maxEntries: function (): null {
    return null;
  },
  lifetime: function (): string {
    return 'No expiry and no bound: keyed by content, so an edited policy ' +
      'is a new entry and the old parse stays until the process restarts.';
  },
  entries: function (): unknown[] {
    const out: unknown[] = [];
    parsed.forEach(function (policy: any, digest: string): void {
      out.push({
        key: String((policy && policy.id) || '(no id)') + ' — sha256 ' +
          digest.slice(0, 16) + '…',
        validUntil: null,
        basis: 'content-keyed'
      });
    });
    return out;
  }
});

// ---------------------------------------------------------------------------
// THE SEEDED POLICY.
//
// This service seeds a directory — people, groups, containers — so that it
// answers something the moment it starts, and the policy repository follows
// the same rule for the same reason: a PDP with an empty repository answers
// NotApplicable to everything, which is indistinguishable from a PDP that is
// broken. One policy, seeded, makes `GET /xacml/protected?subject=alice`
// mean something before anybody has authored anything.
//
// IT IS A REAL POLICY AND NOT A PLACEHOLDER. Role-based, in the shape the
// OASIS RBAC profile takes: a permission is granted to a role, and the role
// is an attribute of the subject — read here by the PIP off the person's own
// `employeeType` in the embedded directory, which is an attribute this
// service's seeded entries already carry. So the seeded policy and the seeded
// directory agree, and the first decision anybody asks for exercises the
// PDP, the repository AND the PIP rather than just the first of the three.
//
// `deny-unless-permit` deliberately: the combining algorithm that cannot
// return NotApplicable or Indeterminate, so the seeded repository never hands
// the embedded PEP an answer whose meaning depends on the PEP's bias. A
// reader who wants to see the bias matter should disable this policy or write
// one that can be Indeterminate — which is the point of the setting.
// ---------------------------------------------------------------------------
const SEED_NAME = 'seeded-rbac';

const SEED_DOCUMENT = [
  '<?xml version="1.0" encoding="UTF-8"?>',
  '<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"',
  '        PolicyId="urn:sts:xacml:policy:seeded-rbac"',
  '        Version="1.0"',
  '        RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:' +
    'rule-combining-algorithm:deny-unless-permit">',
  '  <Description>',
  '    Seeded by the mock STS so that the PDP answers something before',
  '    anybody has authored a policy. Anyone whose directory entry carries',
  '    employeeType=staff may GET; anyone with employeeType=admin may do',
  '    anything. Everybody else is denied, because deny-unless-permit cannot',
  '    return NotApplicable. Replace it rather than editing it.',
  '  </Description>',
  '  <Target/>',
  '  <Rule RuleId="urn:sts:xacml:rule:admin-anything" Effect="Permit">',
  '    <Description>An admin may do anything.</Description>',
  '    <Target>',
  '      <AnyOf><AllOf>',
  '        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:' +
    'string-equal">',
  '          <AttributeValue',
  '            DataType="http://www.w3.org/2001/XMLSchema#string"' +
    '>admin</AttributeValue>',
  '          <AttributeDesignator',
  '            Category="urn:oasis:names:tc:xacml:1.0:subject-category:' +
    'access-subject"',
  '            AttributeId="employeeType"',
  '            DataType="http://www.w3.org/2001/XMLSchema#string"',
  '            MustBePresent="false"/>',
  '        </Match>',
  '      </AllOf></AnyOf>',
  '    </Target>',
  '  </Rule>',
  '  <Rule RuleId="urn:sts:xacml:rule:staff-read" Effect="Permit">',
  '    <Description>Staff may GET.</Description>',
  '    <Target>',
  '      <AnyOf><AllOf>',
  '        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:' +
    'string-equal">',
  '          <AttributeValue',
  '            DataType="http://www.w3.org/2001/XMLSchema#string"' +
    '>staff</AttributeValue>',
  '          <AttributeDesignator',
  '            Category="urn:oasis:names:tc:xacml:1.0:subject-category:' +
    'access-subject"',
  '            AttributeId="employeeType"',
  '            DataType="http://www.w3.org/2001/XMLSchema#string"',
  '            MustBePresent="false"/>',
  '        </Match>',
  '      </AllOf></AnyOf>',
  '      <AnyOf><AllOf>',
  '        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:' +
    'string-equal">',
  '          <AttributeValue',
  '            DataType="http://www.w3.org/2001/XMLSchema#string"' +
    '>GET</AttributeValue>',
  '          <AttributeDesignator',
  '            Category="urn:oasis:names:tc:xacml:3.0:attribute-category:' +
    'action"',
  '            AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id"',
  '            DataType="http://www.w3.org/2001/XMLSchema#string"',
  '            MustBePresent="false"/>',
  '        </Match>',
  '      </AllOf></AnyOf>',
  '    </Target>',
  '  </Rule>',
  '</Policy>'
].join('\n');

class XacmlStore {
  static readonly SCHEMA = SCHEMA;
  static readonly SEED_NAME = SEED_NAME;
  static readonly SEED_DOCUMENT = SEED_DOCUMENT;

  constructor(private readonly deps: XacmlStoreDeps) {
    deps.log.debug("Entering XacmlStore.constructor().");
    deps.log.debug("Leaving XacmlStore.constructor().");
  }

  // The deps the composition root builds this class from: the real modules,
  // and the SHA-256 this module has always keyed its parse cache by.
  static defaultDeps(): XacmlStoreDeps {
    helpers.log.debug("Entering XacmlStore.defaultDeps().");
    const deps: XacmlStoreDeps = {
      log: helpers.log,
      errorCodes: errorCodes,
      xml: xml,
      sha256Hex: function (text: string): string {
        return crypto.createHash('sha256').update(text).digest('hex');
      }
    };
    helpers.log.debug("Leaving XacmlStore.defaultDeps().");
    return deps;
  }

  setChangeObserver(fn: unknown): void {
    const { log } = this.deps;
    log.debug('Entering XacmlStore.setChangeObserver().');
    changeObserver = typeof fn === 'function'
      ? fn as (what: string) => void : null;
    log.debug('Leaving XacmlStore.setChangeObserver(). ' +
              (changeObserver ? 'Installed.' : 'Cleared.'));
  }

  // Called AFTER a successful write or removal, never before and never on a
  // refusal — a nudge sent for a policy the store then rejected would have
  // every PEP re-pull an unchanged repository, which is the one way an
  // optimisation can cost more than it saves. It must not throw into its
  // caller: a PEP that cannot be nudged is not a reason for a policy save to
  // fail.
  private changed(what: string): void {
    const { log, errorCodes } = this.deps;
    log.debug('Entering XacmlStore.changed(). what=' + what);
    if (!changeObserver) {
      log.debug('Leaving XacmlStore.changed(). Nobody is watching.');
      return;
    }
    try {
      changeObserver(what);
    } catch (error) {
      log.debug('Caught in XacmlStore.changed(): ' +
                ((error && error.message) || error));
      // Swallowed on purpose and logged: the observer's whole job is to dial
      // somebody else, and a failure there must not turn a successful policy
      // write into a 500 for the person who made it.
      log.warn(errorCodes.tag('STS-XACML-0060') +
               'xacml: the repository change observer threw and the change ' +
               'itself was fine: ' + error.message);
    }
    log.debug('Leaving XacmlStore.changed().');
  }

  // Static: see the header — it is called before any instance exists.
  static setDirectory(fns: PolicyDirectory | null | undefined): void {
    const log = helpers.log;
    log.debug('Entering XacmlStore.setDirectory().');
    directory = fns || null;
    log.debug('Leaving XacmlStore.setDirectory(). The repository ' +
              (directory ? 'has its container.' : 'has none.'));
  }

  // WHAT IS CURRENTLY INSTALLED, so that a test which stubs the slot can put
  // back WHAT WAS THERE rather than `null`. `tests/CLAUDE.md` records why that
  // distinction is not pedantry: `run.js` runs every file in one process, so
  // this is one reference shared by the whole run, and restoring `null` is
  // only correct in a process where `ldap/ldap_server.js` was never loaded —
  // which is a fact about the file list rather than about the test. Nothing in
  // the service calls this, exactly as nothing calls
  // `applications.directoryInstalled()`.
  directoryInstalled(): PolicyDirectory | null {
    const { log } = this.deps;
    log.debug("Entering XacmlStore.directoryInstalled().");
    log.debug("Leaving XacmlStore.directoryInstalled().");
    return directory;
  }

  private haveDirectory(): boolean {
    const { log } = this.deps;
    log.debug("Entering XacmlStore.haveDirectory().");
    if (directory) {
      log.debug("Leaving XacmlStore.haveDirectory().");
      return true;
    }
    if (!warnedAboutNoDirectory) {
      warnedAboutNoDirectory = true;
      log.warn('xacml: the embedded directory was never loaded, so there is ' +
               'no ou=policies to hold a policy. The PDP answers ' +
               'NotApplicable to everything and the repository is empty. ' +
               'This is the ordinary state of an in-process test that ' +
               'requires only app.js and one module; it is not a failure, ' +
               'and there is no fallback store, deliberately — a policy ' +
               'repository that quietly lived in memory would decide things ' +
               'nobody could find.');
    }
    log.debug("Leaving XacmlStore.haveDirectory().");
    return false;
  }

  // -------------------------------------------------------------------------
  // PARSE, CACHED.
  //
  // The parse INCLUDES static validation (`xacml_xml.js` calls
  // `xacml_validate.js`), so a document that does not typecheck never becomes
  // a usable policy — it is reported at write time and, if it got in some
  // other way, at read time.
  // -------------------------------------------------------------------------
  parseDocument(document: string): any {
    const { log, xml, sha256Hex } = this.deps;
    log.debug('Entering XacmlStore.parseDocument().');
    const digest = sha256Hex(document);
    const cached = parsed.get(digest);
    if (cached) {
      parsedCount.hit();
      log.debug('Leaving XacmlStore.parseDocument(). Cached.');
      return cached;
    }
    parsedCount.miss();
    const policy = xml.parsePolicy(document);
    parsed.set(digest, policy);
    log.debug('Leaving XacmlStore.parseDocument(). Parsed and cached as ' +
              digest.slice(0, 12) + '.');
    return policy;
  }

  // What the derived attributes should be for a document. One function,
  // called at write time, so the entry and the document cannot drift at the
  // moment they are written — they can still drift afterwards through an
  // `ldapmodify`, which is why the document is the truth and these are only an
  // index.
  describe(document: string): { id: string; kind: string; version: string;
                                combiningAlgId: string } {
    const { log } = this.deps;
    log.debug('Entering XacmlStore.describe().');
    const policy = this.parseDocument(document);
    log.debug('Leaving XacmlStore.describe(). id=' + policy.id);
    return { id: policy.id,
             kind: policy.kind,
             version: policy.version,
             combiningAlgId: policy.combiningAlgId };
  }

  // -------------------------------------------------------------------------
  // READING.
  // -------------------------------------------------------------------------
  all(): PolicyRow[] {
    const self = this;
    const { log } = this.deps;
    log.debug('Entering XacmlStore.all().');
    if (!this.haveDirectory()) {
      log.debug('Leaving XacmlStore.all(). No directory.');
      return [];
    }
    const rows = directory.allPolicies().map(function (entry) {
      const at = self.attributeReader(entry.attributes);
      return {
        name: entry.name,
        dn: entry.dn,
        id: at('xacmlPolicyId'),
        kind: at('xacmlKind') || 'Policy',
        version: at('xacmlVersion') || '1.0',
        combiningAlgId: at('xacmlCombiningAlgId') || '',
        description: at('description') || '',
        enabled: at('xacmlEnabled') !== 'FALSE',
        isRoot: at('xacmlIsRoot') === 'TRUE',
        document: at('xacmlPolicyDocument') || ''
      };
    });
    log.debug('Leaving XacmlStore.all(). ' + rows.length + ' policy(ies).');
    return rows;
  }

  // -------------------------------------------------------------------------
  // READING AN ATTRIBUTE BACK, CASE-INSENSITIVELY, BECAUSE LDAP IS.
  //
  // RFC 4512: attribute type names are case-insensitive, and this directory
  // normalises them to lower case on the way in. So an entry written with
  // `xacmlPolicyDocument` reads back as `xacmlpolicydocument`, and a reader
  // that asks for the camel-case name it wrote gets `undefined`.
  //
  // That cost a boot here and it failed in the worst available way: `all()`
  // returned rows whose every field was empty, `root()` found no root because
  // `xacmlIsRoot` read as undefined, and the PDP answered NotApplicable to
  // everything — with a repository that plainly had a policy in it and no
  // error anywhere. `federation.js` reads `stored.attributes.fedid` in lower
  // case for exactly this reason; this does it through one function so that
  // the fifteen call sites cannot each get it right separately.
  // -------------------------------------------------------------------------
  private attributeReader(attributes: Record<string, any> | null |
                            undefined): (name: string) => string | null {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering XacmlStore.attributeReader().");
    const lowered = {};
    Object.keys(attributes || {}).forEach(function (key) {
      lowered[key.toLowerCase()] = attributes[key];
    });
    log.debug("Leaving XacmlStore.attributeReader().");
    return function (name) {
      return self.one(lowered[String(name).toLowerCase()]);
    };
  }

  private one(value: unknown): string | null {
    const { log } = this.deps;
    log.debug("Entering XacmlStore.one().");
    if (Array.isArray(value)) {
      log.debug("Leaving XacmlStore.one().");
      return value.length ? String(value[0]) : null;
    }
    log.debug("Leaving XacmlStore.one().");
    return value === undefined || value === null ? null : String(value);
  }

  read(name: string): PolicyRow | null {
    const { log } = this.deps;
    log.debug('Entering XacmlStore.read(). name=' + name);
    const found = this.all().filter(function (row) {
      return row.name === name;
    })[0] || null;
    log.debug('Leaving XacmlStore.read(). ' +
              (found ? 'Found.' : 'Not found.'));
    return found;
  }

  // -------------------------------------------------------------------------
  // THE ROOT, AND THE REPOSITORY BEHIND IT.
  //
  // A PDP evaluates ONE document and reaches the rest through
  // `PolicyIdReference`. So the repository has a root, and this is where
  // "which one" is answered — as an explicit `xacmlIsRoot` rather than by a
  // rule like "the only PolicySet" or "the first one", both of which change
  // their answer when somebody adds a second policy and neither of which
  // anybody can see.
  // -------------------------------------------------------------------------
  root(): PolicyRow | null {
    const { log } = this.deps;
    log.debug('Entering XacmlStore.root().');
    const enabled = this.all().filter(function (row) {
      return row.enabled;
    });
    const roots = enabled.filter(function (row) {
      return row.isRoot;
    });
    if (roots.length === 1) {
      log.debug('Leaving XacmlStore.root(). ' + roots[0].id);
      return roots[0];
    }
    if (roots.length > 1) {
      // Refused rather than resolved. Two roots is a repository whose answer
      // depends on iteration order, and a PDP that picked one would decide
      // consistently and arbitrarily.
      log.debug('Leaving XacmlStore.root(). More than one.');
      return null;
    }
    if (enabled.length === 1) {
      // The one unambiguous convenience: a repository holding exactly one
      // enabled policy has an obvious root, and demanding the flag there would
      // make the simplest possible setup fail for a reason that reads as a
      // bug.
      log.debug('Leaving XacmlStore.root(). The only enabled policy.');
      return enabled[0];
    }
    log.debug('Leaving XacmlStore.root(). None.');
    return null;
  }

  // Every enabled policy keyed by its PolicyId, which is what `xacml_pdp.js`
  // resolves a `PolicyIdReference` against. Built per decision rather than
  // held, because the directory is the store and a cached map is a second copy
  // of it.
  repository(): Record<string, any> {
    const self = this;
    const { log, errorCodes } = this.deps;
    log.debug('Entering XacmlStore.repository().');
    const map = {};
    this.all().forEach(function (row) {
      if (!row.enabled || !row.id) {
        return;
      }
      try {
        map[row.id] = self.parseDocument(row.document);
      } catch (error) {
        log.debug('Caught in XacmlStore.repository(): ' +
                  ((error && error.message) || error));
        // A policy that does not parse is left OUT of the repository rather
        // than taking the whole decision down. It is not silent: a reference
        // to it is then unresolvable, which `xacml_pdp.js` reports as
        // Indeterminate naming the reference — and the console shows the
        // parse error on the policy itself.
        log.warn(errorCodes.tag('STS-XACML-0058') +
                 'xacml: policy "' + row.name + '" is in the repository and ' +
                 'does not parse, so nothing can reference it: ' +
                 error.message);
      }
    });
    log.debug('Leaving XacmlStore.repository(). ' + Object.keys(map).length +
              ' entry(ies).');
    return map;
  }

  // -------------------------------------------------------------------------
  // WRITING.
  //
  // The document is VALIDATED before it is written. A repository that accepts
  // a policy which does not typecheck is a repository whose next decision is
  // Indeterminate for a reason nobody will connect to the save that caused it
  // — so the refusal happens at the moment somebody can still fix it.
  // -------------------------------------------------------------------------
  write(name: string, document: string,
        options?: WriteOptions | null): WriteResult {
    const { log, errorCodes } = this.deps;
    log.debug('Entering XacmlStore.write(). name=' + name);
    const settings = options || {};
    if (!this.haveDirectory()) {
      log.debug('Leaving XacmlStore.write(). No directory.');
      return errorCodes.mark({ ok: false,
                               why: 'There is no embedded directory, so ' +
                                    'there is nowhere to put a policy.' },
                             'STS-XACML-0026');
    }
    if (!name || !/^[A-Za-z0-9._-]{1,128}$/.test(name)) {
      log.debug('Leaving XacmlStore.write(). Bad name.');
      return errorCodes.mark({ ok: false,
                               why: 'A policy name is 1 to 128 characters of ' +
                               'letters, digits, dot, dash or underscore. It ' +
                               'names the DIRECTORY ENTRY; the PolicyId ' +
                               'inside the document is a separate thing and ' +
                               'may be any URI.' }, 'STS-XACML-0029');
    }
    let described;
    try {
      described = this.describe(document);
    } catch (error) {
      log.debug('Caught in XacmlStore.write(): ' +
                ((error && error.message) || error));
      log.debug('Leaving XacmlStore.write(). The document was refused.');
      return errorCodes.mark({ ok: false, why: error.message,
               problems: (error.xacmlDetail && error.xacmlDetail.problems) ||
                         null }, 'STS-XACML-0028');
    }
    // TWO ROOTS IS REFUSED AT WRITE TIME rather than reported at decision
    // time, for the reason `root()` gives: a repository with two roots answers
    // arbitrarily, and the moment to say so is while somebody is looking.
    if (settings.isRoot) {
      const clash = this.all().filter(function (row) {
        return row.isRoot && row.name !== name;
      })[0];
      if (clash) {
        log.debug('Leaving XacmlStore.write(). A root already exists.');
        return errorCodes.mark({ ok: false,
                 why: 'Policy "' + clash.name + '" is already the root of ' +
                      'this repository. A PDP evaluates one document and ' +
                      'reaches the rest through PolicyIdReference, so there ' +
                      'is exactly one root. Clear the flag there first.' },
                 'STS-XACML-0030');
      }
    }
    const attributes: Record<string, any> = {
      objectClass: ['top', 'xacmlPolicy'],
      xacmlPolicyId: described.id,
      xacmlPolicyDocument: document,
      xacmlVersion: described.version,
      xacmlKind: described.kind,
      xacmlCombiningAlgId: described.combiningAlgId,
      xacmlEnabled: settings.enabled === false ? 'FALSE' : 'TRUE',
      xacmlIsRoot: settings.isRoot ? 'TRUE' : 'FALSE'
    };
    if (settings.description) {
      attributes.description = String(settings.description);
    }
    const written = directory.writePolicy(name, attributes);
    if (written) {
      this.changed('policy "' + name + '" was written');
    }
    log.debug('Leaving XacmlStore.write(). ' +
              (written ? 'Written.' : 'Refused.'));
    return written ? { ok: true, id: described.id, kind: described.kind }
                   : errorCodes.mark({ ok: false,
                                       why: 'The directory refused the ' +
                                            'entry. The container may be at ' +
                                            'its maximum.' },
                                     'STS-XACML-0027');
  }

  remove(name: string): boolean {
    const { log } = this.deps;
    log.debug('Entering XacmlStore.remove(). name=' + name);
    if (!this.haveDirectory()) {
      log.debug('Leaving XacmlStore.remove(). No directory.');
      return false;
    }
    const removed = directory.deletePolicy(name);
    if (removed) {
      this.changed('policy "' + name + '" was removed');
    }
    log.debug('Leaving XacmlStore.remove(). ' +
              (removed ? 'Removed.' : 'Not there.'));
    return removed;
  }

  // Called by `ldap/ldap_server.js` immediately after it creates ou=policies,
  // which is the only moment "the repository is new" is knowable. It writes
  // through the ordinary `write()` path — so the seeded document is parsed and
  // STATICALLY VALIDATED like any other, and a seed that stopped typechecking
  // would be refused at startup and say so rather than becoming the one policy
  // in the repository nobody had checked.
  seed(): boolean {
    const { log, errorCodes } = this.deps;
    log.debug('Entering XacmlStore.seed().');
    const written = this.write(SEED_NAME, SEED_DOCUMENT,
                               { isRoot: true, enabled: true,
                                 description: 'Seeded role-based policy. ' +
                                              'Replace it rather than ' +
                                              'editing it.' });
    if (!written.ok) {
      log.warn(errorCodes.tag('STS-XACML-0059') +
               'xacml: the seeded policy was refused: ' + written.why);
    }
    log.debug('Leaving XacmlStore.seed(). ' +
              (written.ok ? 'Seeded.' : 'Refused.'));
    return written.ok;
  }
}

// A `seed()` asked for before any instance existed — see the header.
let seedRequested = false;

function seedFacade(): boolean {
  helpers.log.debug('Entering seedFacade().');
  if (slot.origin() === 'none') {
    seedRequested = true;
    helpers.log.debug('Leaving seedFacade(). Held until an instance is ' +
                      'installed.');
    return true;
  }
  const seeded = slot.get().seed();
  helpers.log.debug('Leaving seedFacade().');
  return seeded;
}

function wireStore(instance: XacmlStore): void {
  helpers.log.debug('Entering wireStore().');
  if (seedRequested) {
    seedRequested = false;
    instance.seed();
  }
  helpers.log.debug('Leaving wireStore().');
}

const slot = new InstanceSlot<XacmlStore>(
  'xacml/xacml_store',
  () => new XacmlStore(XacmlStore.defaultDeps()),
  wireStore, helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  XacmlStore: XacmlStore,
  installInstance: (instance: XacmlStore): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  SCHEMA: XacmlStore.SCHEMA,
  SEED_NAME: XacmlStore.SEED_NAME,
  SEED_DOCUMENT: XacmlStore.SEED_DOCUMENT,
  seed: seedFacade,
  setDirectory: XacmlStore.setDirectory,
  directoryInstalled: slot.forward('directoryInstalled'),
  setChangeObserver: slot.forward('setChangeObserver'),
  all: slot.forward('all'),
  read: slot.forward('read'),
  root: slot.forward('root'),
  repository: slot.forward('repository'),
  write: slot.forward('write'),
  remove: slot.forward('remove'),
  describe: slot.forward('describe'),
  parseDocument: slot.forward('parseDocument')
};
