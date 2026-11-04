// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: scim_realm_schema.ts
//
// ---------------------------------------------------------------------------
// WHAT /Schemas SAYS OF ONE REALM (#699, a follow-up of #396).
//
// Two facts about a person are the realm's and not the process's: what the
// realm's attribute policy requires (`common/CLAUDE.md` 3co), and the realm's
// custom attributes (`cn=<name>,ou=attributeDefinitions`). Until this, SCIM
// refused a create that lacked a required value (400 invalidValue,
// STS-LDAP-0162) while the schema a client reads said nothing was required
// but `userName`, and a custom attribute could not be read or written over
// SCIM at all.
//
// THE DESIGN QUESTION WAS THAT scimmy's SCHEMA DEFINITIONS ARE THE
// PROCESS'S. A realm is told apart only by the ambient realm, held in an
// `AsyncLocalStorage` (`common/realms.js`), and every SCIM request runs
// inside it. Two things make that enough:
//
//   * scimmy reads an extension's `attributes` EVERY time it uses the
//     extension — to coerce a resource in either direction, to apply a
//     filter, to resolve a PATCH path, to describe it at /Schemas — and
//     keeps no copy (`SchemaDefinition.extend()` wraps the extension in an
//     object whose `attributes` is a getter onto the extension's own). So
//     ONE process-wide extension, `CUSTOM_SCHEMA` below, whose `attributes`
//     is a getter over the ambient realm's register, is a per-realm schema
//     everywhere scimmy looks, with nothing of scimmy changed.
//   * `required` is NOT put on any scimmy definition. scimmy enforces a
//     required attribute on the way OUT as well (the `userName` episode in
//     `scim/CLAUDE.md`), so a person created before the policy said so would
//     make `GET /Users` fail for the whole realm; and the core definitions
//     are the process's, so one realm's policy would leak into every other.
//     It is set on the DOCUMENT /Schemas answers, after scimmy has drawn it
//     and after it has been copied out of scimmy's objects
//     (`publishSchemas()`), which is the only place a client reads it.
//
// WHICH PROFILE. A realm may hold several named attribute profiles (#1241);
// /Schemas is one document for every person, so it publishes the `default`
// profile — the one a SCIM create is held to, since SCIM maps nothing to
// `stsAttributePolicy` and its `groups` is read-only. A person a group puts
// under a stricter profile is still refused by the ingress for what that
// profile asks; the document is the floor, not the ceiling.
//
// ONLY WHERE IT IS ENFORCED. The policy holds in product mode
// (`attributePolicy.enforced()`); in development nothing but `userName` is
// required, and the document says exactly that.
//
// THE REGISTER IS READ ONCE PER SCIM REQUEST. scimmy asks for the
// extension's attributes once per attribute access on every resource of a
// list, and the register is a directory read; `inRequest()` (entered by
// `scim.ts`'s `handle()`) keeps what the first read found for the rest of
// the request. The Attribute objects built from it are kept per realm and
// rebuilt only when the definitions differ, so scimmy sees the same objects
// from one request to the next. Outside a request — a test, the start-up
// declaration — the register is read each time.
// ---------------------------------------------------------------------------

import { AsyncLocalStorage } from 'async_hooks';
import helpers = require('../common/helpers');
import realms = require('../common/realms');
import attributePolicy = require('../common/attribute_policy');
import personEditor = require('../ldap/person_editor');
import scimMap = require('./scim_map');

type Fn = (...args: any[]) => any;

// A custom attribute, as `attribute_policy.ts`'s `definitions()` lists it.
interface Definition {
  name: string;
  label: string;
  syntax: string;
  multi: boolean;
  description: string;
}

// What a request's values for the extension come to: the names the write
// replaces (`window`) and the values it writes for each. `null` from
// `fromScim()` is "the resource does not say", which leaves the entry's
// values as they are.
interface Converted {
  window: string[];
  values: Record<string, string[]>;
}

interface RealmSchemaDeps {
  SCIMMY: any;
  log: {
    debug(message: string): void;
    warn(message: string): void;
  };
  realms: { currentId(): string };
  attributePolicy: { definitions: Fn; required: Fn; enforced: Fn };
  personEditor: { checkCreateValues: Fn };
  scimMap: { USER_ATTRIBUTES: any[]; USER_SCHEMA: string };
}

// The URN. This service's own namespace, as the iya-sts User extension's is;
// one URN for every realm, because a realm is a service provider of its own
// at its own base URL and RFC 7643 section 7 makes /Schemas the schemas THAT
// service provider supports.
const CUSTOM_SCHEMA =
  'urn:ietf:params:scim:schemas:extension:iya-sts:2.0:CustomAttributes';

// A custom attribute's syntax as a SCIM type (RFC 7643 section 2.3). Only
// `integer` and `boolean` have a type of their own; a date is stored
// YYYYMMDD and has no time, so it is not RFC 7643's dateTime, and `uri` may
// carry a label after a space (RFC 2079), so it is not a reference.
const SCIM_TYPES: Record<string, string> = {
  integer: 'integer', boolean: 'boolean'
};

// What each syntax accepts, in the words the extension's description uses.
const SYNTAX_NOTES: Record<string, string> = {
  string: 'Text.',
  integer: 'A whole number.',
  boolean: 'true or false.',
  date: 'A date, YYYY-MM-DD (YYYYMMDD is accepted too).',
  email: 'An email address.',
  uri: 'An http or https URL, optionally followed by a space and a label.',
  dn: 'A distinguished name.'
};

// The attribute policy's names a SCIM create never has to send: `uid` is
// `userName`, already required by RFC 7643, and `cn` is made of the names
// where the resource gives none (`deriveCommonName()`), at every door.
const NOT_ASKED_OF_SCIM = ['uid', 'cn'];

/**
 * The per-realm half of SCIM's schemas: the realm's custom attributes as an
 * extension, and the attribute policy's required attributes on the
 * documents `/Schemas` and `/ResourceTypes` answer.
 */
class ScimRealmSchema {
  /**
   * The URN of the custom-attribute extension.
   */
  static readonly CUSTOM_SCHEMA = CUSTOM_SCHEMA;

  private readonly scope = new AsyncLocalStorage<{ defs?: Definition[] }>();
  private readonly built = new Map<string, { signature: string;
                                             attributes: any[] }>();
  private extensionDefinition: any = null;

  /**
   * @param deps - scimmy, the logger, the ambient realm, the attribute
   *   policy, the person editor's value check and the mapping
   */
  constructor(private readonly deps: RealmSchemaDeps) {
    deps.log.debug("Entering ScimRealmSchema.constructor().");
    deps.log.debug("Leaving ScimRealmSchema.constructor().");
  }

  /**
   * The dependencies this module uses outside a test.
   *
   * @param SCIMMY - the scimmy instance `scim.ts` declares its resources on
   * @returns the dependencies
   */
  static defaultDeps(SCIMMY: any): RealmSchemaDeps {
    helpers.log.debug("Entering ScimRealmSchema.defaultDeps().");
    helpers.log.debug("Leaving ScimRealmSchema.defaultDeps().");
    return {
      SCIMMY: SCIMMY,
      log: helpers.log,
      realms: realms,
      attributePolicy: attributePolicy,
      personEditor: personEditor,
      scimMap: scimMap as any
    };
  }

  /**
   * Runs one SCIM request with the realm's register read at most once.
   *
   * @param fn - the request's work
   * @returns what `fn` returns
   */
  inRequest<T>(fn: () => T): T {
    const { log } = this.deps;
    log.debug("Entering ScimRealmSchema.inRequest().");
    log.debug("Leaving ScimRealmSchema.inRequest().");
    return this.scope.run({}, fn);
  }

  /**
   * The ambient realm's custom attributes, read once per request.
   *
   * @returns the definitions, by name
   */
  definitions(): Definition[] {
    const { log, attributePolicy } = this.deps;
    log.debug("Entering ScimRealmSchema.definitions().");
    const store = this.scope.getStore();
    if (store && store.defs) {
      log.debug("Leaving ScimRealmSchema.definitions(). This request's.");
      return store.defs;
    }
    let defs: Definition[] = [];
    try {
      defs = (attributePolicy.definitions() || []).map(function (one: any) {
        return { name: String(one.name), label: String(one.label || one.name),
                 syntax: String(one.syntax || 'string'), multi: !!one.multi,
                 description: String(one.description || '') };
      });
    } catch (e) {
      // A register that cannot be read offers nothing: the extension is
      // then empty, which is what a realm defining nothing publishes too.
      log.debug("Caught in ScimRealmSchema.definitions(): " +
                ((e && e.message) || e));
      defs = [];
    }
    if (store) {
      store.defs = defs;
    }
    log.debug("Leaving ScimRealmSchema.definitions(). " + defs.length);
    return defs;
  }

  // The scimmy attributes of the ambient realm's register, built once per
  // distinct register. A HOT PATH, read by scimmy for every attribute
  // access on every resource it coerces: no Entering/Leaving pair, which
  // would drown the log in lines per resource.
  private realmAttributes(): any[] {
    const defs = this.definitions();
    const realm = this.deps.realms.currentId();
    const signature = JSON.stringify(defs);
    const held = this.built.get(realm);
    if (held && held.signature === signature) {
      return held.attributes;
    }
    const Attribute = this.deps.SCIMMY.Types.Attribute;
    const attributes: any[] = [];
    defs.forEach((one) => {
      try {
        attributes.push(new Attribute(SCIM_TYPES[one.syntax] || 'string',
          one.name, {
            multiValued: one.multi,
            description: one.label +
              (one.description ? ' — ' + one.description : '') + ' ' +
              (SYNTAX_NOTES[one.syntax] || SYNTAX_NOTES.string) +
              ' (stored as the directory attribute ' + one.name + ').'
          }));
      } catch (e) {
        // A name scimmy refuses is left out rather than taking the realm's
        // whole extension with it. RFC 4512's descr is a subset of RFC
        // 7643's ATTRNAME, so none is expected.
        this.deps.log.debug("Caught in ScimRealmSchema.realmAttributes(): " +
                            ((e && e.message) || e));
      }
    });
    this.built.set(realm, { signature: signature, attributes: attributes });
    return attributes;
  }

  /**
   * The custom-attribute extension, built once: a scimmy schema definition
   * whose `attributes` are the ambient realm's.
   *
   * @returns the schema definition, for `User.extend()`
   */
  extension(): any {
    const { log, SCIMMY } = this.deps;
    log.debug("Entering ScimRealmSchema.extension().");
    if (this.extensionDefinition) {
      log.debug("Leaving ScimRealmSchema.extension(). Built already.");
      return this.extensionDefinition;
    }
    const definition = new SCIMMY.Types.SchemaDefinition('CustomAttributes',
      CUSTOM_SCHEMA,
      'This realm\'s custom attributes, as its administrators define them ' +
      'on Directory → Policies → Attribute policy. Each realm has its own; ' +
      'not sent on a PUT, they are left as they are.');
    // The common members every scimmy definition carries (`schemas`, `id`,
    // `externalId`, `meta`, all shadowed), kept, and the realm's after them.
    const common = definition.attributes.slice(0);
    Object.defineProperty(definition, 'attributes', {
      configurable: true,
      enumerable: true,
      get: () => common.concat(this.realmAttributes()),
      // scimmy's own `truncate()` and `extend()` would write here; neither
      // is ever called on this definition, and a write is ignored rather
      // than allowed to make the realm's attributes the process's.
      set: (value: unknown) => {
        log.warn('scim: a write to the custom-attribute extension\'s ' +
                 'attributes was ignored (' + typeof value + ').');
      }
    });
    this.extensionDefinition = definition;
    log.debug("Leaving ScimRealmSchema.extension().");
    return definition;
  }

  // A stored value as SCIM carries it, or undefined where it cannot be.
  private scimValue(syntax: string, value: unknown): unknown {
    const { log } = this.deps;
    log.debug("Entering ScimRealmSchema.scimValue(). " + syntax);
    const text = String(value == null ? '' : value).trim();
    if (text === '') {
      log.debug("Leaving ScimRealmSchema.scimValue(). Empty.");
      return undefined;
    }
    if (syntax === 'boolean') {
      log.debug("Leaving ScimRealmSchema.scimValue(). A boolean.");
      return text.toUpperCase() === 'TRUE';
    }
    if (syntax === 'integer') {
      const number = Number(text);
      // A JSON number carries an integer exactly only to 2^53 - 1, and the
      // directory holds up to eighteen digits. A value past it is left out
      // of the resource rather than sent as a different number.
      log.debug("Leaving ScimRealmSchema.scimValue(). An integer.");
      return Number.isSafeInteger(number) ? number : undefined;
    }
    if (syntax === 'date') {
      const m = /^(\d{4})(\d{2})(\d{2})$/.exec(text);
      log.debug("Leaving ScimRealmSchema.scimValue(). A date.");
      return m ? m[1] + '-' + m[2] + '-' + m[3] : text;
    }
    log.debug("Leaving ScimRealmSchema.scimValue().");
    return text;
  }

  /**
   * The extension's member of a User resource, drawn from the entry's
   * attributes.
   *
   * @param attributes - the entry's attributes, any case of name
   * @returns the extension's object form, or null when the person holds
   *   no custom attribute
   */
  toScim(attributes: Record<string, unknown>): Record<string, unknown> | null {
    const { log } = this.deps;
    log.debug("Entering ScimRealmSchema.toScim().");
    const held = attributes || {};
    const keys = Object.keys(held);
    const out: Record<string, unknown> = {};
    this.definitions().forEach((one) => {
      const key = keys.filter(function (name) {
        return name.toLowerCase() === one.name.toLowerCase();
      })[0];
      if (!key) {
        return;
      }
      const values = [].concat(held[key] as any)
        .map((value) => {
          return this.scimValue(one.syntax, value);
        })
        .filter(function (value) {
          return value !== undefined;
        });
      if (!values.length) {
        return;
      }
      out[one.name] = one.multi ? values : values[0];
    });
    const any = Object.keys(out).length > 0;
    log.debug("Leaving ScimRealmSchema.toScim(). " + Object.keys(out).length);
    return any ? out : null;
  }

  // Whether a raw request body names the extension at all, in its object
  // form or by a namespaced member.
  private named(raw: any): boolean {
    const { log } = this.deps;
    log.debug("Entering ScimRealmSchema.named().");
    const lower = CUSTOM_SCHEMA.toLowerCase();
    const out = !!raw && typeof raw === 'object' &&
      Object.keys(raw).some(function (key) {
        const k = key.toLowerCase();
        return k === lower || k.indexOf(lower + ':') === 0;
      });
    log.debug("Leaving ScimRealmSchema.named(). " + out);
    return out;
  }

  /**
   * The custom values a User write asks for, checked.
   *
   * WHAT "NOT SAID" MEANS DEPENDS ON THE METHOD, as it does for
   * `federationLinks` (`scim.ts`): a create writes what it carries; a PATCH
   * reaches the ingress as the whole resource egress drew, patched, so what
   * it leaves is what is written; a PUT that does not name the extension
   * leaves the values as they are — `active`'s rule, so a provisioning
   * client that never heard of this realm's attributes cannot erase them —
   * and a PUT that names it replaces every one.
   *
   * @param data - the resource scimmy coerced
   * @param method - the HTTP method
   * @param raw - the request body as sent, for a PUT
   * @returns `{ window, values }`, null when the values are left as they
   *   are, or `{ error }` naming the value refused
   */
  fromScim(data: any, method: string, raw: unknown):
      Converted | { error: string } | null {
    const { log, personEditor } = this.deps;
    log.debug("Entering ScimRealmSchema.fromScim(). " + method);
    const verb = String(method || '').toUpperCase();
    const defs = this.definitions();
    if (!defs.length) {
      log.debug("Leaving ScimRealmSchema.fromScim(). Nothing defined.");
      return null;
    }
    const extension = data ? data[CUSTOM_SCHEMA] : undefined;
    if (verb === 'PUT' && extension === undefined && !this.named(raw)) {
      log.debug("Leaving ScimRealmSchema.fromScim(). Not said.");
      return null;
    }
    const out: Converted = { window: [], values: {} };
    for (const one of defs) {
      out.window.push(one.name);
      const given = extension ? extension[one.name] : undefined;
      const list = (given === undefined || given === null ? []
        : [].concat(given)) as unknown[];
      const texts: string[] = [];
      for (const value of list) {
        if (one.syntax === 'integer' && !Number.isSafeInteger(value)) {
          log.debug("Leaving ScimRealmSchema.fromScim(). An integer " +
                    "past what JSON carries exactly.");
          return { error: 'The value for ' + CUSTOM_SCHEMA + ':' +
                          one.name + ' is not a whole number a JSON number ' +
                          'carries exactly (at most 2^53 - 1 either way).' };
        }
        if (one.syntax === 'boolean') {
          texts.push(value ? 'TRUE' : 'FALSE');
        } else if (value !== undefined && value !== null &&
                   String(value).trim() !== '') {
          texts.push(String(value));
        }
      }
      // THE PERSON EDITOR'S OWN CHECK, which the console's create and a
      // person's Attributes tab use: the syntax, the length, no control
      // character, one value for a single-valued attribute — and the
      // value's normal form (a date as YYYYMMDD).
      const checked = texts.length
        ? personEditor.checkCreateValues(one.name, texts) : null;
      if (checked && checked.error !== undefined) {
        log.debug("Leaving ScimRealmSchema.fromScim(). Refused.");
        return { error: String(checked.error) + ' (' + CUSTOM_SCHEMA + ':' +
                        one.name + ')' };
      }
      const values = checked && checked.values ? checked.values : texts;
      if (values.length) {
        out.values[one.name] = values;
      }
    }
    log.debug("Leaving ScimRealmSchema.fromScim(). " +
              Object.keys(out.values).length + " of " + out.window.length);
    return out;
  }

  /**
   * Writes what `fromScim()` found onto an attribute set: every name in
   * the window is replaced, or removed where the resource gave no value.
   *
   * @param attributes - the attribute set about to be written; changed
   * @param converted - what `fromScim()` answered
   */
  applyTo(attributes: Record<string, unknown>, converted: Converted): void {
    const { log } = this.deps;
    log.debug("Entering ScimRealmSchema.applyTo().");
    const lower = converted.window.map(function (name) {
      return name.toLowerCase();
    });
    Object.keys(attributes).forEach(function (name) {
      if (lower.indexOf(name.toLowerCase()) >= 0) {
        delete attributes[name];
      }
    });
    Object.keys(converted.values).forEach(function (name) {
      attributes[name] = converted.values[name].slice(0);
    });
    log.debug("Leaving ScimRealmSchema.applyTo().");
  }

  // -------------------------------------------------------------------------
  // `required`, ON THE DOCUMENTS ONLY.
  // -------------------------------------------------------------------------

  // Where each attribute the realm requires is published: by schema URN, the
  // attribute paths to mark (a sub-attribute's parent too, since a parent
  // without a value cannot carry the sub-attribute), a note for a member
  // whose type matters, and the names no member carries.
  private requiredPlaces(): { paths: Record<string, string[]>;
                              notes: Record<string, string[]>;
                              unmapped: string[]; custom: boolean } {
    const { log, attributePolicy, scimMap } = this.deps;
    log.debug("Entering ScimRealmSchema.requiredPlaces().");
    const out = { paths: {} as Record<string, string[]>,
                  notes: {} as Record<string, string[]>,
                  unmapped: [] as string[], custom: false };
    if (!attributePolicy.enforced()) {
      log.debug("Leaving ScimRealmSchema.requiredPlaces(). Not enforced.");
      return out;
    }
    const add = function (urn: string, path: string): void {
      out.paths[urn] = out.paths[urn] || [];
      if (out.paths[urn].indexOf(path) < 0) {
        out.paths[urn].push(path);
      }
    };
    const defs = this.definitions();
    const names: string[] = [].concat(attributePolicy.required() || []);
    names.forEach(function (name) {
      const lower = String(name).toLowerCase();
      if (NOT_ASKED_OF_SCIM.indexOf(lower) >= 0) {
        return;
      }
      const custom = defs.filter(function (one) {
        return one.name.toLowerCase() === lower;
      })[0];
      if (custom) {
        add(CUSTOM_SCHEMA, custom.name);
        out.custom = true;
        return;
      }
      const rows = scimMap.USER_ATTRIBUTES.filter(function (row: any) {
        return String(row.ldap).toLowerCase() === lower &&
          ['single', 'multi', 'complex'].indexOf(row.kind) >= 0;
      });
      if (!rows.length) {
        out.unmapped.push(String(name));
        return;
      }
      rows.forEach(function (row: any) {
        const scim = String(row.scim);
        const at = row.extension ? scim.lastIndexOf(':') : -1;
        const urn = at >= 0 ? scim.slice(0, at) : scimMap.USER_SCHEMA;
        const path = at >= 0 ? scim.slice(at + 1) : scim;
        const parts = path.split('.');
        add(urn, parts[0]);
        if (parts.length > 1) {
          add(urn, path);
        }
        if (row.type) {
          out.notes[urn + ':' + parts[0]] =
            out.notes[urn + ':' + parts[0]] || [];
          out.notes[urn + ':' + parts[0]].push('one of type "' + row.type +
            '" (' + row.ldap + ')');
        }
      });
    });
    log.debug("Leaving ScimRealmSchema.requiredPlaces(). " +
              out.unmapped.length + " unmapped.");
    return out;
  }

  // One schema document, marked. `doc` is a plain copy, never scimmy's.
  private markSchema(doc: any, places: ReturnType<
      ScimRealmSchema['requiredPlaces']>): void {
    const { log, scimMap } = this.deps;
    log.debug("Entering ScimRealmSchema.markSchema(). " +
              (doc && doc.id));
    const urn = String((doc && doc.id) || '');
    const paths = places.paths[urn] || [];
    const find = function (list: any[], name: string): any {
      return (list || []).filter(function (one: any) {
        return String(one && one.name).toLowerCase() === name.toLowerCase();
      })[0];
    };
    paths.forEach(function (path) {
      const parts = path.split('.');
      const top = find(doc.attributes, parts[0]);
      const target = parts.length > 1 && top
        ? find(top.subAttributes, parts[1]) : top;
      if (target) {
        target.required = true;
      }
      const notes = places.notes[urn + ':' + parts[0]];
      if (top && notes && parts.length === 1) {
        top.description = String(top.description || '') +
          ' This realm requires ' + notes.join(', and ') + '.';
      }
    });
    if (urn === scimMap.USER_SCHEMA && places.unmapped.length) {
      doc.description = String(doc.description || '') +
        ' This realm\'s attribute policy also requires ' +
        places.unmapped.join(', ') + ', which no SCIM member carries, so ' +
        'a User created over SCIM here is refused (400 invalidValue) ' +
        'until the policy stops requiring ' +
        (places.unmapped.length > 1 ? 'them' : 'it') + '.';
    }
    log.debug("Leaving ScimRealmSchema.markSchema(). " + paths.length);
  }

  /**
   * The answer of `GET /Schemas` or `GET /Schemas/{id}`, copied out of
   * scimmy's objects and marked with what this realm requires.
   *
   * @param answer - a ListResponse or one schema document, as scimmy drew it
   * @returns a plain copy, marked
   */
  publishSchemas(answer: unknown): any {
    const { log } = this.deps;
    log.debug("Entering ScimRealmSchema.publishSchemas().");
    const copy = JSON.parse(JSON.stringify(answer));
    const places = this.requiredPlaces();
    // A REALM THAT DEFINES NO CUSTOM ATTRIBUTE LISTS NO EXTENSION FOR THEM
    // (2026-11-05). scimmy registers the extension once for the process, so
    // it is in every realm's list; an empty one was read by scim2-tester as
    // an extension to PATCH, and what it added came back as nothing
    // (sts_scim_conformance). `/Schemas/{urn}` still answers it, as an
    // extension nothing uses.
    if (Array.isArray(copy && copy.Resources) &&
        this.definitions().length === 0) {
      copy.Resources = copy.Resources.filter(function (doc: any) {
        return !(doc && doc.id === CUSTOM_SCHEMA);
      });
      copy.totalResults = copy.Resources.length;
      if (copy.itemsPerPage !== undefined) {
        copy.itemsPerPage = copy.Resources.length;
      }
    }
    const docs = Array.isArray(copy && copy.Resources) ? copy.Resources
      : [copy];
    docs.forEach((doc: any) => {
      this.markSchema(doc, places);
    });
    log.debug("Leaving ScimRealmSchema.publishSchemas().");
    return copy;
  }

  /**
   * The answer of `GET /ResourceTypes` or `GET /ResourceTypes/{id}`, with
   * the custom-attribute extension REQUIRED on the User type where this
   * realm requires one of its attributes (RFC 7643 section 6).
   *
   * @param answer - a ListResponse or one resource type, as scimmy drew it
   * @returns a plain copy, marked
   */
  publishResourceTypes(answer: unknown): any {
    const { log } = this.deps;
    log.debug("Entering ScimRealmSchema.publishResourceTypes().");
    const copy = JSON.parse(JSON.stringify(answer));
    // No custom attribute defined: the User type names no extension for
    // them (see publishSchemas()).
    if (this.definitions().length === 0) {
      const types = Array.isArray(copy && copy.Resources) ? copy.Resources
        : [copy];
      types.forEach(function (doc: any) {
        if (doc && Array.isArray(doc.schemaExtensions)) {
          doc.schemaExtensions = doc.schemaExtensions.filter(
            function (one: any) {
              return !(one && one.schema === CUSTOM_SCHEMA);
            });
        }
      });
      log.debug("Leaving ScimRealmSchema.publishResourceTypes(). " +
                "No custom attribute defined.");
      return copy;
    }
    if (!this.requiredPlaces().custom) {
      log.debug("Leaving ScimRealmSchema.publishResourceTypes(). " +
                "Nothing custom required.");
      return copy;
    }
    const docs = Array.isArray(copy && copy.Resources) ? copy.Resources
      : [copy];
    docs.forEach(function (doc: any) {
      (doc && Array.isArray(doc.schemaExtensions)
        ? doc.schemaExtensions : []).forEach(function (one: any) {
        if (one && one.schema === CUSTOM_SCHEMA) {
          one.required = true;
        }
      });
    });
    log.debug("Leaving ScimRealmSchema.publishResourceTypes().");
    return copy;
  }
}

export = ScimRealmSchema;
