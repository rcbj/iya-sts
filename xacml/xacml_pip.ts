'use strict';
//
// File: xacml_pip.ts
//
// ---------------------------------------------------------------------------
// THE POLICY INFORMATION POINT: WHERE AN ATTRIBUTE THE REQUEST DID NOT CARRY
// COMES FROM.
//
// XACML's architecture has the PDP ask for attributes it needs and a PIP
// answer. Here the PIP is the EMBEDDED DIRECTORY: a designator in the
// access-subject category is looked up on the entry of the person the request
// names, and any attribute that entry holds can be returned. That is the whole
// of phase one of this component, deliberately — no LDAP filter language, no
// second source, no caching policy.
//
// ---------------------------------------------------------------------------
// THE ONE RULE THAT MATTERS, AND IT IS ABOUT WHAT "NOT THERE" MEANS.
//
// An attribute the directory does not hold returns an EMPTY BAG. Not false,
// not null, not an error. Whether that empty bag ends the decision is settled
// by `MustBePresent` on the designator and by the function it is handed to —
// and NOT here:
//
//   `string-one-and-only` on an empty bag   → Indeterminate
//   `string-is-in` on an empty bag          → False
//   a designator with MustBePresent="true"  → Indeterminate
//
// Getting this backwards is the classic PIP defect and it fails in the
// permissive direction: a PIP that returned `false` for a missing attribute
// makes the first case decide something instead of refusing to, and a policy
// that should have been Indeterminate returns Permit. So this file never
// invents a value, never substitutes a default, and never converts an absence
// into a presence. `xacml_pdp.js`'s `resolveDesignator()` is the only place an
// empty bag becomes an error, and it does so because the policy asked.
//
// ---------------------------------------------------------------------------
// THE REQUEST WINS OVER THE DIRECTORY, AND THAT ORDERING IS DELIBERATE.
//
// `xacml_pdp.js` consults this resolver only when the request carried nothing
// for that designator. A PEP that asserted an attribute is describing THIS
// REQUEST; the directory is describing the world. Where they disagree the
// request is the more specific claim, and a PIP that overrode it would make a
// PEP unable to say anything about the transaction in front of it.
//
// ---------------------------------------------------------------------------
// WHO THE REQUEST IS ABOUT.
//
// The subject is `urn:oasis:names:tc:xacml:1.0:subject:subject-id` in the
// access-subject category, and it may be a bare name (`bob`), a DN, or a
// certificate subject — all three of which `ldap_server.js`'s `locateEntry()`
// already knows how to resolve, which is exactly why this file calls that
// rather than building a fourth lookup. A request with no subject-id gets an
// empty bag for every subject attribute; it does not get an error, because a
// resource-only or environment-only decision is perfectly ordinary.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `XacmlPip` takes the logger, the error-code registry, the engine's
// vocabulary and its datatypes through its constructor. The directory slot
// (`setDirectory()`) is a method of it and is still exported under its old
// name, as are `resolverFor`, `locateSubject`, `rawAttribute`,
// `directoryAttributeFor`, `subjectOf`, `available` and `ATTRIBUTE_PREFIX` —
// as FACADES forwarding to the instance the composition root builds and
// installs (#50's R2), for `ldap/ldap_server.js` and the other callers that
// are not converted. A process without the root builds a default when this
// module loads. `XacmlPip` is exported for the root.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
// The error-code registry (a leaf), for the one data failure below whose only
// record is a log line. Not a module the remote PEP container copies.
import errorCodes = require('../common/error_codes');
import model = require('./xacml_model');
import datatypes = require('./xacml_datatypes');

// The directory functions this module calls. Installed by
// `ldap/ldap_server.js`.
interface PipDirectory {
  locateEntry(subject: string): { stored?: any } | null | undefined;
  [name: string]: any;
}

interface XacmlPipDeps {
  log: { debug(message: string): void; warn(message: string): void };
  errorCodes: { tag(code: string): string };
  model: typeof model;
  datatypes: { parseValue(type: string, lexical: string): any };
}

// Installed by `ldap/ldap_server.js` at require time, the way every other
// consumer of the directory receives it. See `xacml_store.ts`'s header for why
// this is an inverted install rather than a require.
let directory: PipDirectory | null = null;
let warnedAboutNoDirectory = false;

// ---------------------------------------------------------------------------
// AN ATTRIBUTE NAME THIS PIP WILL LOOK FOR ON AN ENTRY.
//
// A designator's AttributeId is a URI and a directory attribute is a short
// name, so something has to bridge them. Two forms are accepted and NOTHING
// else is guessed:
//
//   * a bare name — `mail`, `departmentNumber`, `employeeType` — used as it
//     stands. This is what a policy author writes and what the PAP's editor
//     will offer from the directory's own schema.
//   * the URN prefix this service uses for its own attributes,
//     `urn:sts:xacml:attribute:<name>`, so that a policy which wants to
//     be explicit about where an attribute comes from can be.
//
// A standard XACML URI like `urn:oasis:names:tc:xacml:1.0:subject:subject-id`
// is NOT mapped to a directory attribute. It names the subject, the request
// carries it, and inventing a directory lookup for it would let a policy
// silently read a different subject-id from the one being decided about.
// ---------------------------------------------------------------------------
const ATTRIBUTE_PREFIX = 'urn:sts:xacml:attribute:';

class XacmlPip {
  static readonly ATTRIBUTE_PREFIX = ATTRIBUTE_PREFIX;

  constructor(private readonly deps: XacmlPipDeps) {
    deps.log.debug("Entering XacmlPip.constructor().");
    deps.log.debug("Leaving XacmlPip.constructor().");
  }

  // What the composition root passes, from the real modules.
  static defaultDeps(): XacmlPipDeps {
    helpers.log.debug("Entering XacmlPip.defaultDeps().");
    helpers.log.debug("Leaving XacmlPip.defaultDeps().");
    return {
      log: helpers.log,
      errorCodes: errorCodes,
      model: model,
      datatypes: datatypes
    };
  }

  setDirectory(fns: PipDirectory | null | undefined): void {
    const { log } = this.deps;
    log.debug('Entering XacmlPip.setDirectory().');
    directory = fns || null;
    log.debug('Leaving XacmlPip.setDirectory(). The PIP ' +
              (directory ? 'has the directory.' : 'has none.'));
  }

  available(): boolean {
    const { log } = this.deps;
    log.debug("Entering XacmlPip.available().");
    if (directory) {
      log.debug("Leaving XacmlPip.available().");
      return true;
    }
    if (!warnedAboutNoDirectory) {
      warnedAboutNoDirectory = true;
      log.warn('xacml: the embedded directory was never loaded, so the PIP ' +
               'answers nothing. Every decision then sees only the ' +
               'attributes the REQUEST carried, which is the pure-XACML ' +
               'behaviour the conformance suite runs under and is not a ' +
               'failure.');
    }
    log.debug("Leaving XacmlPip.available().");
    return false;
  }

  directoryAttributeFor(attributeId: unknown): string | null {
    const { log } = this.deps;
    log.debug('Entering XacmlPip.directoryAttributeFor(). id=' + attributeId);
    const id = String(attributeId || '');
    if (id.indexOf(ATTRIBUTE_PREFIX) === 0) {
      const name = id.slice(ATTRIBUTE_PREFIX.length);
      log.debug('Leaving XacmlPip.directoryAttributeFor(). Prefixed: ' + name);
      return name || null;
    }
    if (/^[A-Za-z][A-Za-z0-9;-]*$/.test(id)) {
      log.debug('Leaving XacmlPip.directoryAttributeFor(). A bare name.');
      return id;
    }
    log.debug('Leaving XacmlPip.directoryAttributeFor(). Not a directory ' +
              'attribute.');
    return null;
  }

  // The subject the request is about, or null. Read out of the request rather
  // than out of any session: a PDP decides about the subject the PEP named,
  // and this service's own sign-on session is a different thing that has no
  // business influencing somebody else's authorization question.
  subjectOf(request: any): string | null {
    const { log, model } = this.deps;
    log.debug('Entering XacmlPip.subjectOf().');
    let found = null;
    request.categories.forEach(function (category) {
      if (found || category.category !== model.CATEGORY.ACCESS_SUBJECT) {
        return;
      }
      category.attributes.forEach(function (attribute) {
        if (found || attribute.attributeId !== model.ATTRIBUTE.SUBJECT_ID) {
          return;
        }
        if (attribute.values.length) {
          found = attribute.values[0].lexical;
        }
      });
    });
    log.debug('Leaving XacmlPip.subjectOf(). ' + (found ? found : 'none'));
    return found;
  }

  // An attribute off a directory entry, matched without regard to case. See
  // the call site for why this is not `attributes[name]`.
  //
  // **EXPORTED as `rawAttribute()` for `POST /xacml/pip`**, which has to tell
  // a caller apart the two ways a bag can be empty on an entry that exists:
  // the entry does not hold the attribute at all, or it holds values that will
  // not parse at the datatype the policy declared. `resolverFor()` below
  // cannot distinguish them and deliberately must not — a PDP has to see one
  // empty bag — but the warning it logs about the second is the only trace of
  // it, and a caller in another container cannot read this service's log.
  attributeOf(attributes: Record<string, any> | null | undefined,
              name: string): any {
    const { log } = this.deps;
    log.debug("Entering XacmlPip.attributeOf().");
    if (!attributes) {
      log.debug("Leaving XacmlPip.attributeOf().");
      return null;
    }
    const wanted = String(name).toLowerCase();
    const keys = Object.keys(attributes);
    for (let i = 0; i < keys.length; i += 1) {
      if (keys[i].toLowerCase() === wanted) {
        log.debug("Leaving XacmlPip.attributeOf().");
        return attributes[keys[i]];
      }
    }
    log.debug("Leaving XacmlPip.attributeOf().");
    return null;
  }

  // -------------------------------------------------------------------------
  // DOES THIS SUBJECT RESOLVE TO AN ENTRY AT ALL?
  //
  // Exported for `POST /xacml/pip`, which has to tell a caller WHY a bag came
  // back empty — and *there is no such person* and *that person holds no such
  // attribute* are opposite answers needing opposite fixes. The resolver below
  // cannot answer it: an empty array is all it has to say, deliberately,
  // because a PDP must not be able to tell the two apart and decide
  // differently.
  //
  // It goes through the SAME `locateEntry()` the resolver uses rather than a
  // second lookup, so "resolves" means one thing here — the fourth-lookup
  // mistake this file's header refuses to make, met from the other direction.
  // -------------------------------------------------------------------------
  locateSubject(subject: unknown): any {
    const { log } = this.deps;
    log.debug('Entering XacmlPip.locateSubject().');
    if (!subject || !this.available()) {
      log.debug('Leaving XacmlPip.locateSubject(). Nothing to look up.');
      return null;
    }
    const located = directory.locateEntry(String(subject));
    const stored = located && located.stored ? located.stored : null;
    log.debug('Leaving XacmlPip.locateSubject(). ' +
              (stored ? 'Found.' : 'No entry.'));
    return stored;
  }

  // -------------------------------------------------------------------------
  // THE RESOLVER `xacml_pdp.js` IS HANDED.
  //
  // Returns an array of PARSED values at the designator's declared datatype,
  // or an empty array. Never null, never a bag — the PDP wraps it, because the
  // PDP owns the bag's type and a resolver that built one could disagree with
  // the designator about what type it just returned.
  // -------------------------------------------------------------------------
  resolverFor(request: any): (designator: any) => any[] {
    const self = this;
    const { log, errorCodes, model, datatypes } = this.deps;
    log.debug('Entering XacmlPip.resolverFor().');
    // Resolved once per decision, not once per designator: a policy that reads
    // six attributes about one person must not be able to see six different
    // people because somebody wrote to the directory in between.
    let entry;
    let looked = false;

    const subjectEntry = function subjectEntry(): any {
      log.debug("Entering XacmlPip.resolverFor().subjectEntry().");
      if (looked) {
        log.debug("Leaving XacmlPip.resolverFor().subjectEntry().");
        return entry;
      }
      looked = true;
      entry = null;
      if (!self.available()) {
        log.debug("Leaving XacmlPip.resolverFor().subjectEntry().");
        return null;
      }
      const subject = self.subjectOf(request);
      if (!subject) {
        log.debug('resolverFor(): the request names no subject-id, so no ' +
                  'entry is looked up.');
        log.debug("Leaving XacmlPip.resolverFor().subjectEntry().");
        return null;
      }
      const located = directory.locateEntry(subject);
      entry = located && located.stored ? located.stored : null;
      log.debug("Leaving XacmlPip.resolverFor().subjectEntry().");
      return entry;
    };

    log.debug("Leaving XacmlPip.resolverFor().");
    return function resolve(designator) {
      log.debug('Entering XacmlPip.resolverFor().resolve(). id=' +
                designator.attributeId);
      if (designator.category !== model.CATEGORY.ACCESS_SUBJECT) {
        // ONLY the subject category, in this phase. A resource or environment
        // attribute has no entry to be looked up on, and answering them out of
        // the person's entry would be an attribute appearing in a category it
        // does not belong to — which a policy author cannot see and cannot
        // debug.
        log.debug('Leaving XacmlPip.resolverFor().resolve(). Not a subject ' +
                  'attribute.');
        return [];
      }
      const name = self.directoryAttributeFor(designator.attributeId);
      if (!name) {
        log.debug('Leaving XacmlPip.resolverFor().resolve(). Not a ' +
                  'directory attribute name.');
        return [];
      }
      const stored = subjectEntry();
      if (!stored) {
        log.debug('Leaving XacmlPip.resolverFor().resolve(). No entry for ' +
                  'the subject.');
        return [];
      }
      // CASE-INSENSITIVELY, because LDAP attribute type names are (RFC 4512)
      // and this directory normalises them to lower case on the way in. A
      // lookup for the camel-case name a policy author wrote — `employeeType`,
      // which is the standard inetOrgPerson spelling — finds nothing on an
      // entry that plainly has it. The same mistake in `xacml_store.ts` made
      // the whole repository read back empty; here it is quieter and worse,
      // because a missing attribute is a legitimate answer, so the PDP simply
      // decides as though the person had no roles and says nothing at all.
      const raw = self.attributeOf(stored.attributes, name);
      if (raw === undefined || raw === null) {
        log.debug('Leaving XacmlPip.resolverFor().resolve(). The entry does ' +
                  'not hold it.');
        return [];
      }
      const list = Array.isArray(raw) ? raw : [raw];
      const values = [];
      list.forEach(function (item) {
        try {
          values.push(datatypes.parseValue(designator.dataType,
                                           String(item)));
        } catch (error) {
          log.debug('Caught in XacmlPip.resolverFor().resolve(): ' +
                    ((error && error.message) || error));
          // A directory value that will not parse at the type the POLICY asked
          // for is DROPPED, with a warning, rather than making the decision
          // Indeterminate. The directory is schemaless — anything can be
          // written into any attribute — so a policy asking for
          // `employeeNumber` as an integer will meet a non-numeric one
          // eventually, and one bad value among five must not take the other
          // four with it. What it costs is that a wholly unparseable attribute
          // looks exactly like a missing one; the warning is the only place
          // that difference is visible, and it names both the attribute and
          // the type.
          log.warn(errorCodes.tag('STS-XACML-0061') +
                   'xacml: the directory value "' + item + '" on attribute "' +
                   name + '" is not a valid ' + designator.dataType +
                   ', so it is not returned to the PDP: ' + error.message);
        }
      });
      log.debug('Leaving XacmlPip.resolverFor().resolve(). ' + values.length +
                ' value(s).');
      return values;
    };
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
const slot = new InstanceSlot<XacmlPip>(
  'xacml/xacml_pip',
  () => new XacmlPip(XacmlPip.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  XacmlPip: XacmlPip,
  installInstance: (instance: XacmlPip): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  setDirectory: slot.forward('setDirectory'),
  resolverFor: slot.forward('resolverFor'),
  locateSubject: slot.forward('locateSubject'),
  rawAttribute: slot.forward('attributeOf'),
  directoryAttributeFor: slot.forward('directoryAttributeFor'),
  subjectOf: slot.forward('subjectOf'),
  available: slot.forward('available'),
  ATTRIBUTE_PREFIX: XacmlPip.ATTRIBUTE_PREFIX
};
