// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: directory_model.ts
//
// ---------------------------------------------------------------------------
// THE DIRECTORY NAMESPACE OF THE COMMON MODEL (#1390).
//
// Each owning module already publishes a SCHEMA table. This collector
// reads those tables and the hand catalogue and writes one model per
// object. It does not load the directory server: that module registers
// routes when it is loaded. Spellings are read as text.
//
// The requires of the SCHEMA owners are inside `collect()`, not at the
// top of this file. A top-level import would run policy registration and
// the application register's load-time work for anyone who required this
// library. The collector is not on `protocol_stack.ts`. `import x =
// require` remains the rule for the libraries this file always loads.
//
// A missing `kind` stays `unspecified` unless the attribute's own RFC says
// SINGLE-VALUE or not. Nothing here reads the word "multi-valued" out of a
// `what` sentence. OIDs, syntaxes and matching rules come only from
// `models/directory/rfc_schema.json`, which `models/tools/import_rfc_schema.mjs`
// reads out of the RFCs; a name no RFC defines stays a gap. The directory
// stays schemaless: this model is not consulted when an entry is written.
//
// A LIBRARY. No route.
// ---------------------------------------------------------------------------

import fs = require('fs');
import path = require('path');
import { createRequire } from 'module';
import bunyan = require('bunyan');
import zodModule = require('zod');
import ModelIr = require('./model_ir');
import DirectorySpellings = require('./directory_spellings');
import DirectoryModelCatalog = require('./directory_model_catalog');
import ModelTables = require('./model_tables');

const log = bunyan.createLogger({
  name: 'sts-directory-model',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

const requireFromHere = createRequire(__filename);
const z: any = (zodModule as any).z;

/**
 * Policy kinds the collector names. A kind registered in
 * `policy_kinds.ts` and missing here is a gap, so a new kind cannot
 * arrive in the model unnoticed and cannot be skipped unnoticed.
 */
const POLICY_KIND_IDS = [
  'password', 'authn', 'serviceAccount', 'passkey', 'locale',
  'attributes', 'postLogin'
];

/**
 * SCHEMA exports that are not policy kinds. The module path is resolved
 * from this file.
 */
const SCHEMA_OWNERS = [
  { id: 'application', modulePath: './applications',
    container: 'ou=applications' },
  { id: 'federationRelationship', modulePath: '../federation/federation',
    container: 'ou=federations' },
  { id: 'role', modulePath: './roles', container: 'ou=roles' },
  { id: 'device', modulePath: './devices', container: 'ou=devices' },
  { id: 'serviceAccount', modulePath: './service_accounts',
    container: 'ou=users' },
  { id: 'spiffe', modulePath: '../spiffe/spiffe_registry',
    container: 'ou=spiffe' },
  { id: 'xacmlPolicy', modulePath: '../xacml/xacml_store',
    container: 'ou=policies' },
  { id: 'xacmlPep', modulePath: '../xacml/xacml_pep_registry',
    container: 'ou=peps' }
];

const DIRECTORY_STRING = '1.3.6.1.4.1.1466.115.121.1.15';

type Provenance = 'rfc' | 'oasis-or-other' | 'iya-sts' | 'derived' |
  'unspecified';

interface ModelAttribute {
  name: string;
  kind: 'single' | 'multi' | 'unspecified';
  provenance: Provenance;
  sourceIndex: number;
  declaredKind?: string;
  standard?: boolean;
  sensitive?: boolean;
  secret?: boolean;
  withheld?: boolean;
  from?: string;
  what?: string;
  families?: string[];
  familyWhy?: string;
  section?: string;
  editable?: boolean | string;
  identifier?: boolean;
  identifierName?: string;
  overrides?: string;
  strictOverride?: boolean;
  role?: string;
  allowed?: string[];
  jsonBlob?: boolean;
  oid?: string;
  syntax?: string;
  equality?: string;
  ordering?: string;
  substr?: string;
  sup?: string;
  ldapSingleValue?: boolean;
  noUserModification?: boolean;
  usage?: string;
  citation?: string;
}

interface ModelClass {
  name: string;
  provenance: Provenance;
  sourceIndex: number;
  standard?: boolean;
  what?: string;
  where?: string;
  oid?: string;
  classType?: string;
  sup?: string[];
  must?: string[];
  may?: string[];
  citation?: string;
}

interface ModelObject {
  id: string;
  container: string;
  source: string;
  section?: string;
  note?: string;
  ownContainer?: boolean;
  noAttributes?: boolean;
  definitionContainer?: string;
  projectionOf?: string;
  objectClasses: ModelClass[];
  attributes: ModelAttribute[];
  personAttributes: ModelAttribute[];
  relationships: unknown[];
}

interface ModelGap {
  code: string;
  object: string;
  name: string;
  detail: string;
}

interface DirectoryCatalog {
  objects: ModelObject[];
  gaps: ModelGap[];
  policyKindIds: string[];
  // The register's root and whether it is still RFC 5612's documentation
  // number (#1573), so a page drawn from the catalogue says so only while
  // it is.
  oidRoot: { root: string; placeholder: boolean };
}

/**
 * The numbers this service has given its own names, under one root.
 */
interface OidRegister {
  root: string;
  placeholder: boolean;
  attributes: Record<string, number>;
  classes: Record<string, number>;
  publishedElsewhere: { attributes: string[]; classes: string[] };
}

interface SpellMaps {
  standard: Map<string, string>;
  own: Set<string>;
  both: string[];
  citations: Map<string, string>;
  secret: Set<string>;
  rfc: { attributes: Record<string, any>; classes: Record<string, any> };
  register: OidRegister;
}

/**
 * What `collect()` needs. Tests can point `root` at a fixture tree.
 */
interface DirectoryModelDeps {
  root: string;
  load: (modulePath: string) => any;
}

/**
 * Collects the directory namespace and parses one object's values.
 */
class DirectoryModel {
  /**
   * @param deps - the package root and the loader for SCHEMA modules
   */
  constructor(private readonly deps: DirectoryModelDeps) {
    log.debug("Entering DirectoryModel.constructor().");
    log.debug("Leaving DirectoryModel.constructor().");
  }

  /**
   * The dependencies a process in this tree uses.
   *
   * @returns the root next to `common/`, and node's require
   */
  static defaultDeps(): DirectoryModelDeps {
    log.debug("Entering DirectoryModel.defaultDeps().");
    const deps = {
      root: path.join(__dirname, '..'),
      load: DirectoryModel.loadModule
    };
    log.debug("Leaving DirectoryModel.defaultDeps().");
    return deps;
  }

  /**
   * Loads one SCHEMA module. Not a top-level import: see the file header.
   *
   * @param modulePath - a path `createRequire` resolves from this file
   * @returns the module exports
   */
  static loadModule(modulePath: string): any {
    log.debug("Entering DirectoryModel.loadModule().");
    const loaded = requireFromHere(modulePath);
    log.debug("Leaving DirectoryModel.loadModule().");
    return loaded;
  }

  /**
   * Reads every named SCHEMA and the hand catalogue.
   *
   * @returns objects sorted by id, and the gap list
   */
  collect(): DirectoryCatalog {
    log.debug("Entering DirectoryModel.collect().");
    const spellings = DirectorySpellings.read(this.deps.root);
    const maps = this.maps(spellings);
    maps.rfc = this.rfcTable();
    maps.register = this.oidRegister();
    const gaps: ModelGap[] = [];
    maps.both.forEach(function (name) {
      gaps.push(ModelIr.gap('spelling-in-both-lists',
        'The name is in STANDARD_NAMES and OWN_NAMES.', '', name));
    });
    const objects: ModelObject[] = [];
    this.collectOwners(maps, objects, gaps);
    this.collectPolicies(maps, objects, gaps);
    this.collectCatalogue(maps, objects, gaps);
    this.ownNameGaps(spellings.own, objects, gaps);
    this.secretGaps(maps, objects, gaps);
    this.kindConflicts(objects, gaps);
    this.finishOwnClasses(maps, objects);
    this.oidGaps(maps, objects, gaps);
    this.collectProjections(objects);
    this.collectLinks(objects, gaps);
    objects.sort(function (a, b) {
      return a.id.localeCompare(b.id);
    });
    const catalog = {
      objects: objects,
      gaps: ModelIr.sortGaps(gaps),
      policyKindIds: POLICY_KIND_IDS.slice(),
      oidRoot: {
        root: maps.register.root,
        placeholder: maps.register.placeholder === true
      }
    };
    log.debug("Leaving DirectoryModel.collect().");
    return catalog;
  }

  /**
   * Indexes the spelling lists. A name in both is reported, not resolved.
   *
   * @param spellings - the lists read as text
   * @returns the maps
   */
  maps(spellings: { standard: { name: string; citation: string }[];
      own: { name: string; citation: string }[];
      secret: string[] }): SpellMaps {
    log.debug("Entering DirectoryModel.maps().");
    const standard = new Map<string, string>();
    spellings.standard.forEach(function (one) {
      if (!standard.has(one.name)) {
        standard.set(one.name, one.citation);
      }
    });
    const own = new Set<string>();
    spellings.own.forEach(function (one) {
      own.add(one.name);
    });
    const both: string[] = [];
    own.forEach(function (name) {
      if (standard.has(name)) {
        both.push(name);
      }
    });
    both.sort();
    const citations = new Map<string, string>();
    spellings.own.forEach(function (one) {
      citations.set(one.name, one.citation);
    });
    const secret = new Set<string>();
    (spellings.secret || []).forEach(function (name) {
      secret.add(name.toLowerCase());
    });
    log.debug("Leaving DirectoryModel.maps().");
    return { standard: standard, own: own, both: both, citations: citations,
      secret: secret, rfc: { attributes: {}, classes: {} },
      register: { root: '', placeholder: true, attributes: {}, classes: {},
        publishedElsewhere: { attributes: [], classes: [] } } };
  }

  /**
   * The definitions the RFCs publish.
   *
   * @returns the table, keyed by lower-case name
   */
  rfcTable(): { attributes: Record<string, any>;
      classes: Record<string, any> } {
    log.debug("Entering DirectoryModel.rfcTable().");
    const table = JSON.parse(fs.readFileSync(path.join(this.deps.root,
      'models', 'directory', 'rfc_schema.json'), 'utf8'));
    log.debug("Leaving DirectoryModel.rfcTable().");
    return table;
  }

  /**
   * The numbers this service has given its own names.
   *
   * @returns the register
   */
  oidRegister(): OidRegister {
    log.debug("Entering DirectoryModel.oidRegister().");
    const register = JSON.parse(fs.readFileSync(path.join(this.deps.root,
      'models', 'directory', 'oid_register.json'), 'utf8'));
    log.debug("Leaving DirectoryModel.oidRegister().");
    return register;
  }

  /**
   * A name the service's secret list holds and no model row carries.
   *
   * @param maps - spellings
   * @param objects - objects already collected
   * @param gaps - the gap list
   */
  secretGaps(maps: SpellMaps, objects: ModelObject[],
      gaps: ModelGap[]): void {
    log.debug("Entering DirectoryModel.secretGaps().");
    const known = new Set<string>();
    objects.forEach(function (object) {
      object.attributes.concat(object.personAttributes).forEach(
        function (attribute) {
          known.add(attribute.name.toLowerCase());
        });
    });
    maps.secret.forEach(function (name) {
      if (!known.has(name)) {
        gaps.push(ModelIr.gap('secret-without-row',
          'The directory withholds this name and no model carries it.', '',
          name));
      }
    });
    log.debug("Leaving DirectoryModel.secretGaps().");
  }

  /**
   * This service's classes, which no RFC describes. A class beside a
   * published structural class is auxiliary to it; otherwise it is the
   * entry's structural class. It may hold the object's own attributes.
   *
   * @param maps - spellings
   * @param objects - objects already collected
   */
  finishOwnClasses(maps: SpellMaps, objects: ModelObject[]): void {
    log.debug("Entering DirectoryModel.finishOwnClasses().");
    objects.forEach(function (object) {
      const hasStructural = object.objectClasses.some(function (item) {
        return item.classType === 'structural';
      });
      const own = object.attributes.concat(object.personAttributes).filter(
        function (attribute) {
          return maps.register.attributes[attribute.name] !== undefined;
        }).map(function (attribute) {
          return attribute.name;
        });
      object.objectClasses.forEach(function (item) {
        if (maps.register.classes[item.name] !== undefined) {
          item.classType = hasStructural ? 'auxiliary' : 'structural';
          item.sup = ['top'];
          item.must = [];
          item.may = own;
        }
      });
    });
    log.debug("Leaving DirectoryModel.finishOwnClasses().");
  }

  /**
   * A name with no OID from a standard, no number in the register and no
   * entry saying somebody else publishes it.
   *
   * @param maps - spellings
   * @param objects - objects already collected
   * @param gaps - the gap list
   */
  oidGaps(maps: SpellMaps, objects: ModelObject[], gaps: ModelGap[]): void {
    log.debug("Entering DirectoryModel.oidGaps().");
    const elsewhere = maps.register.publishedElsewhere;
    objects.forEach(function (object) {
      object.attributes.concat(object.personAttributes).forEach(
        function (attribute) {
          if (!attribute.oid &&
              elsewhere.attributes.indexOf(attribute.name) < 0) {
            gaps.push(ModelIr.gap('oid-unassigned',
              'Add this name to models/directory/oid_register.json.',
              object.id, attribute.name));
          }
        });
      object.objectClasses.forEach(function (item) {
        if (!item.oid && elsewhere.classes.indexOf(item.name) < 0) {
          gaps.push(ModelIr.gap('oid-unassigned',
            'Add this name to models/directory/oid_register.json.',
            object.id, item.name));
        }
      });
    });
    log.debug("Leaving DirectoryModel.oidGaps().");
  }

  /**
   * One attribute name stated as single on one object and multi on
   * another. Both stand. This reports them.
   *
   * @param objects - objects already collected
   * @param gaps - the gap list
   */
  kindConflicts(objects: ModelObject[], gaps: ModelGap[]): void {
    log.debug("Entering DirectoryModel.kindConflicts().");
    const seen = new Map<string, Set<string>>();
    objects.forEach(function (object) {
      object.attributes.forEach(function (attribute) {
        if (attribute.kind === 'unspecified') {
          return;
        }
        const kinds = seen.get(attribute.name) || new Set<string>();
        kinds.add(attribute.kind);
        seen.set(attribute.name, kinds);
      });
    });
    seen.forEach(function (kinds, name) {
      if (kinds.size > 1) {
        gaps.push(ModelIr.gap('kind-conflict',
          'Objects state different kinds for this attribute.', '', name));
      }
    });
    log.debug("Leaving DirectoryModel.kindConflicts().");
  }

  /**
   * An object that is a part of another object's entry. A secrets
   * destination is an application entry with these attributes set.
   *
   * @param objects - objects already collected
   */
  collectProjections(objects: ModelObject[]): void {
    log.debug("Entering DirectoryModel.collectProjections().");
    const self = this;
    const application = objects.filter(function (one) {
      return one.id === 'application';
    })[0];
    if (!application) {
      log.debug("Leaving DirectoryModel.collectProjections(). None.");
      return;
    }
    const object = self.emptyObject('secretsDestination',
      'projection:application', application.container);
    object.projectionOf = 'application';
    object.note = 'An application entry that has these attributes set.';
    object.objectClasses = application.objectClasses.slice();
    object.attributes = application.attributes.filter(function (attribute) {
      return attribute.name === ModelTables.facts('application').key ||
        attribute.name.indexOf('secretDest') === 0;
    });
    objects.push(object);
    log.debug("Leaving DirectoryModel.collectProjections().");
  }

  /**
   * The references between objects. A link to an object or from an
   * attribute the catalogue does not have is a gap.
   *
   * @param objects - objects already collected
   * @param gaps - the gap list
   */
  collectLinks(objects: ModelObject[], gaps: ModelGap[]): void {
    log.debug("Entering DirectoryModel.collectLinks().");
    const byId = new Map<string, ModelObject>();
    objects.forEach(function (object) {
      byId.set(object.id, object);
    });
    const rows: any[] = ModelTables.links();
    rows.forEach(function (row) {
      const from = byId.get(row.from);
      const has = from && from.attributes.some(function (attribute) {
        return attribute.name === row.name;
      });
      if (!from || !has || !byId.has(row.to)) {
        gaps.push(ModelIr.gap('link-unresolved',
          'The link names an object or an attribute the model does not ' +
          'have.', row.from, row.name));
        return;
      }
      from.relationships.push({ name: row.name, to: row.to,
        cardinality: row.cardinality, owns: row.owns, what: row.what });
    });
    log.debug("Leaving DirectoryModel.collectLinks().");
  }

  /**
   * The fixed SCHEMA owners.
   *
   * @param maps - spellings
   * @param objects - the catalogue being built
   * @param gaps - the gap list
   */
  collectOwners(maps: SpellMaps, objects: ModelObject[],
      gaps: ModelGap[]): void {
    log.debug("Entering DirectoryModel.collectOwners().");
    const self = this;
    SCHEMA_OWNERS.forEach(function (owner) {
      const loaded = self.deps.load(owner.modulePath);
      const schema = loaded && loaded.SCHEMA;
      if (!schema) {
        gaps.push(ModelIr.gap('schema-missing',
          'The module has no SCHEMA export.', owner.id, owner.modulePath));
        return;
      }
      objects.push(self.objectFromSchema(owner.id, owner.modulePath,
        owner.container, schema, maps, gaps));
    });
    log.debug("Leaving DirectoryModel.collectOwners().");
  }

  /**
   * One object per registered policy kind. The expected ids are pinned
   * so a new kind fails the test until this list names it.
   *
   * @param maps - spellings
   * @param objects - the catalogue being built
   * @param gaps - the gap list
   */
  collectPolicies(maps: SpellMaps, objects: ModelObject[],
      gaps: ModelGap[]): void {
    log.debug("Entering DirectoryModel.collectPolicies().");
    const PolicyKinds = this.deps.load('../admin-core/policy_kinds');
    const listed = PolicyKinds.list();
    const byId = new Map<string, any>();
    listed.forEach(function (kind: any) {
      byId.set(kind.id, kind);
    });
    const self = this;
    POLICY_KIND_IDS.forEach(function (id) {
      const kind = byId.get(id);
      if (!kind) {
        gaps.push(ModelIr.gap('policy-kind-missing',
          'policy_kinds.ts has no kind with this id.', 'policy.' + id, id));
        return;
      }
      const schema = kind.module && kind.module.SCHEMA;
      if (!schema) {
        gaps.push(ModelIr.gap('schema-missing',
          'The policy kind\'s module has no SCHEMA export.',
          'policy.' + id, id));
        return;
      }
      objects.push(self.objectFromSchema('policy.' + id,
        'policy_kinds:' + id, kind.container || '', schema, maps, gaps));
    });
    listed.forEach(function (kind: any) {
      if (POLICY_KIND_IDS.indexOf(kind.id) < 0) {
        gaps.push(ModelIr.gap('policy-kind-unlisted',
          'A registered policy kind is not in the collector\'s list.',
          'policy.' + kind.id, kind.id));
      }
    });
    log.debug("Leaving DirectoryModel.collectPolicies().");
  }

  /**
   * People, groups, attribute sources and operational attributes.
   *
   * @param maps - spellings
   * @param objects - the catalogue being built
   * @param gaps - the gap list
   */
  collectCatalogue(maps: SpellMaps, objects: ModelObject[],
      gaps: ModelGap[]): void {
    log.debug("Entering DirectoryModel.collectCatalogue().");
    const self = this;
    DirectoryModelCatalog.objects().forEach(function (source: any) {
      const object = self.emptyObject(source.id, 'catalogue',
        source.container || '');
      object.section = source.section;
      object.note = source.note;
      if (source.id === 'person' || source.id === 'group') {
        gaps.push(ModelIr.gap('no-schema',
          'The page describes this object. No module exports a SCHEMA.',
          source.id, ''));
      }
      (source.objectClasses || []).forEach(function (row: any, index: number) {
        const item = self.classFrom(row, index, maps);
        object.objectClasses.push(item);
        self.absenceGaps(gaps, source.id, item);
      });
      (source.attributes || []).forEach(function (row: any, index: number) {
        const item = self.attributeFrom(row, index, maps);
        object.attributes.push(item);
        self.absenceGaps(gaps, source.id, item);
        if (item.kind === 'unspecified') {
          gaps.push(ModelIr.gap('kind-unspecified',
            'The catalogue does not state single or multi.', source.id,
            item.name));
        }
        if (row.jsonBlob) {
          gaps.push(ModelIr.gap('json-blob',
            'The attribute is one JSON value, not a set of fields.',
            source.id, item.name));
        }
        if (!maps.standard.has(item.name) && !maps.own.has(item.name)) {
          gaps.push(ModelIr.gap('spelling-missing',
            'The catalogue names an attribute the spelling lists do not.',
            source.id, item.name));
        }
      });
      self.sortMembers(object);
      objects.push(object);
    });
    log.debug("Leaving DirectoryModel.collectCatalogue().");
  }

  /**
   * Each own name no object carries, one gap per name. A group with one
   * modelled name must not hide the rest.
   *
   * @param own - the own names, in source order
   * @param objects - objects already collected
   * @param gaps - the gap list
   */
  ownNameGaps(own: { name: string; citation: string }[],
      objects: ModelObject[], gaps: ModelGap[]): void {
    log.debug("Entering DirectoryModel.ownNameGaps().");
    const known = new Set<string>();
    objects.forEach(function (object) {
      object.attributes.forEach(function (attribute) {
        known.add(attribute.name);
      });
      object.personAttributes.forEach(function (attribute) {
        known.add(attribute.name);
      });
      object.objectClasses.forEach(function (item) {
        known.add(item.name);
      });
    });
    own.forEach(function (one) {
      if (!known.has(one.name)) {
        gaps.push(ModelIr.gap('own-name-without-row',
          one.citation || 'No citation.', '', one.name));
      }
    });
    log.debug("Leaving DirectoryModel.ownNameGaps().");
  }

  /**
   * One SCHEMA table as a model object.
   *
   * @param id - the object id
   * @param source - the module the table was read from
   * @param fallbackContainer - used when the table states none
   * @param schema - the SCHEMA value
   * @param maps - spellings
   * @param gaps - the gap list
   * @returns the object, members sorted by name
   */
  objectFromSchema(id: string, source: string, fallbackContainer: string,
      schema: any, maps: SpellMaps, gaps: ModelGap[]): ModelObject {
    log.debug("Entering DirectoryModel.objectFromSchema().");
    const container = typeof schema.container === 'string' ?
      schema.container : fallbackContainer;
    const object = this.emptyObject(id, source, container);
    object.ownContainer = typeof schema.container === 'string';
    if (!Array.isArray(schema.attributes)) {
      object.noAttributes = true;
    }
    if (typeof schema.definitionContainer === 'string') {
      object.definitionContainer = schema.definitionContainer;
    }
    const self = this;
    (schema.objectClasses || []).forEach(function (row: any, index: number) {
      const item = self.classFrom(row, index, maps);
      object.objectClasses.push(item);
      self.absenceGaps(gaps, id, item);
    });
    (schema.attributes || []).forEach(function (row: any, index: number) {
      object.attributes.push(self.attributeFrom(row, index, maps));
    });
    (schema.personAttributes || []).forEach(function (row: any,
        index: number) {
      object.personAttributes.push(self.attributeFrom(row, index, maps));
    });
    object.attributes.forEach(function (attribute) {
      self.absenceGaps(gaps, id, attribute);
      if (attribute.kind === 'unspecified') {
        gaps.push(ModelIr.gap('kind-unspecified',
          'The SCHEMA row does not say single or multi.', id,
          attribute.name));
      }
    });
    object.personAttributes.forEach(function (attribute) {
      self.absenceGaps(gaps, id, attribute);
      gaps.push(ModelIr.gap('person-attribute',
        'The policy SCHEMA lists this on a person, not on the policy entry.',
        id, attribute.name));
    });
    this.sortMembers(object);
    log.debug("Leaving DirectoryModel.objectFromSchema().");
    return object;
  }

  /**
   * An empty object, relationships included so a later overlay can fill
   * them without the collector inventing any.
   *
   * @param id - the object id
   * @param source - where it was read
   * @param container - the directory container, or empty
   * @returns the object
   */
  emptyObject(id: string, source: string, container: string): ModelObject {
    log.debug("Entering DirectoryModel.emptyObject().");
    const object = {
      id: id,
      container: container,
      source: source,
      objectClasses: [] as ModelClass[],
      attributes: [] as ModelAttribute[],
      personAttributes: [] as ModelAttribute[],
      relationships: [] as unknown[]
    };
    log.debug("Leaving DirectoryModel.emptyObject().");
    return object;
  }

  /**
   * Sorts classes and attributes by name, keeping `sourceIndex`.
   *
   * @param object - the object
   */
  sortMembers(object: ModelObject): void {
    log.debug("Entering DirectoryModel.sortMembers().");
    const byName = function (a: { name: string; sourceIndex: number },
        b: { name: string; sourceIndex: number }) {
      const name = a.name.localeCompare(b.name);
      if (name !== 0) {
        return name;
      }
      return a.sourceIndex - b.sourceIndex;
    };
    object.objectClasses.sort(byName);
    object.attributes.sort(byName);
    object.personAttributes.sort(byName);
    log.debug("Leaving DirectoryModel.sortMembers().");
  }

  /**
   * One object-class row.
   *
   * @param row - the SCHEMA or catalogue row
   * @param index - its place in the source array
   * @param maps - spellings
   * @returns the model class
   */
  classFrom(row: any, index: number, maps: SpellMaps): ModelClass {
    log.debug("Entering DirectoryModel.classFrom().");
    const item: ModelClass = {
      name: String(row.name),
      provenance: this.provenance(String(row.name), row.standard, maps),
      sourceIndex: index
    };
    if (typeof row.standard === 'boolean') {
      item.standard = row.standard;
    }
    if (typeof row.what === 'string') {
      item.what = row.what;
    }
    if (typeof row.where === 'string') {
      item.where = row.where;
    }
    const fact = row.standard === false ? undefined :
      maps.rfc.classes[item.name.toLowerCase()];
    if (fact) {
      item.oid = fact.oid;
      item.classType = fact.classType;
      item.sup = fact.sup;
      item.must = fact.must;
      item.may = fact.may;
      item.citation = fact.source;
    } else if (maps.register.classes[item.name] !== undefined) {
      item.oid = maps.register.root + '.1.2.' +
        String(maps.register.classes[item.name]);
    }
    log.debug("Leaving DirectoryModel.classFrom().");
    return item;
  }

  /**
   * One attribute row. `kind` other than single or multi, including a
   * missing kind, is unspecified.
   *
   * @param row - the SCHEMA or catalogue row
   * @param index - its place in the source array
   * @param maps - spellings
   * @returns the model attribute
   */
  attributeFrom(row: any, index: number, maps: SpellMaps): ModelAttribute {
    log.debug("Entering DirectoryModel.attributeFrom().");
    const name = String(row.name);
    const fact = row.standard === false ? undefined :
      maps.rfc.attributes[name.toLowerCase()];
    let kind = row.kind === 'single' || row.kind === 'multi' ?
      row.kind : 'unspecified';
    if (kind === 'unspecified' && fact) {
      kind = fact.singleValue ? 'single' : 'multi';
    }
    const item: ModelAttribute = {
      name: String(row.name),
      kind: kind,
      provenance: this.provenance(String(row.name), row.standard, maps),
      sourceIndex: index
    };
    if (row.kind !== undefined) {
      item.declaredKind = String(row.kind);
    }
    if (typeof row.standard === 'boolean') {
      item.standard = row.standard;
    }
    if (row.sensitive === true) {
      item.sensitive = true;
    }
    if (row.secret === true) {
      item.secret = true;
    }
    if (row.sensitive === true || row.secret === true ||
        maps.secret.has(name.toLowerCase())) {
      item.withheld = true;
    }
    if (typeof row.from === 'string') {
      item.from = row.from;
    }
    if (typeof row.what === 'string') {
      item.what = row.what;
    } else if (maps.citations.get(name)) {
      item.what = maps.citations.get(name);
    }
    ['editable', 'identifier', 'identifierName', 'familyWhy', 'overrides',
      'strictOverride', 'role', 'jsonBlob'].forEach(function (key) {
      if (row[key] !== undefined) {
        (item as any)[key] = row[key];
      }
    });
    if (Array.isArray(row.enum)) {
      item.allowed = row.enum.slice();
    }
    if (fact) {
      item.oid = fact.oid;
      item.syntax = fact.syntax;
      item.equality = fact.equality;
      item.ordering = fact.ordering;
      item.substr = fact.substr;
      item.sup = fact.sup;
      item.ldapSingleValue = fact.singleValue;
      item.noUserModification = fact.noUserModification;
      item.usage = fact.usage;
      item.citation = fact.source;
    } else if (maps.register.attributes[name] !== undefined) {
      // RFC 4512 requires a syntax or a superior. Nothing in the source
      // states one, and the directory checks none, so this is the widest
      // the RFC offers: Directory String.
      item.oid = maps.register.root + '.1.1.' +
        String(maps.register.attributes[name]);
      item.syntax = DIRECTORY_STRING;
      item.ldapSingleValue = kind === 'single';
    }
    if (typeof row.section === 'string') {
      item.section = row.section;
    }
    if (Array.isArray(row.families)) {
      item.families = row.families.map(function (family: unknown) {
        return String(family);
      });
    }
    log.debug("Leaving DirectoryModel.attributeFrom().");
    return item;
  }

  /**
   * Provenance from the row's own flag first, then the spelling lists.
   * `standard: false` is this service's name even when a spelling list
   * also carries it. A STANDARD_NAMES citation of an RFC is `rfc`. A
   * citation of SCHAC, draft-behera, PKCS or OASIS is `oasis-or-other`.
   *
   * @param name - the attribute or class name
   * @param standard - the row's flag, when it has one
   * @param maps - spellings
   * @returns the provenance
   */
  provenance(name: string, standard: unknown, maps: SpellMaps): Provenance {
    log.debug("Entering DirectoryModel.provenance().");
    if (standard === false) {
      log.debug("Leaving DirectoryModel.provenance(). iya-sts.");
      return 'iya-sts';
    }
    const fact = maps.rfc.attributes[name.toLowerCase()] ||
      maps.rfc.classes[name.toLowerCase()];
    if (fact) {
      const rfc = /^RFC /.test(fact.source);
      log.debug("Leaving DirectoryModel.provenance(). A published definition.");
      return rfc ? 'rfc' : 'oasis-or-other';
    }
    if (maps.register.attributes[name] !== undefined ||
        maps.register.classes[name] !== undefined) {
      log.debug("Leaving DirectoryModel.provenance(). In the register.");
      return 'iya-sts';
    }
    if (standard === true) {
      log.debug("Leaving DirectoryModel.provenance(). rfc.");
      return 'rfc';
    }
    if (maps.own.has(name)) {
      log.debug("Leaving DirectoryModel.provenance(). own list.");
      return 'iya-sts';
    }
    const citation = maps.standard.get(name) || '';
    if (/RFC\s+\d+/.test(citation)) {
      log.debug("Leaving DirectoryModel.provenance(). RFC citation.");
      return 'rfc';
    }
    if (/SCHAC|draft-behera|PKCS|OASIS/i.test(citation)) {
      log.debug("Leaving DirectoryModel.provenance(). other citation.");
      return 'oasis-or-other';
    }
    log.debug("Leaving DirectoryModel.provenance(). unspecified.");
    return 'unspecified';
  }

  /**
   * What no published definition states for this name. A class has no
   * syntax and no matching rule, so only its OID can be absent.
   *
   * @param gaps - the gap list
   * @param objectId - the model
   * @param item - the attribute or class
   */
  absenceGaps(gaps: ModelGap[], objectId: string,
      item: { name: string; provenance: Provenance; oid?: string }): void {
    log.debug("Entering DirectoryModel.absenceGaps().");
    if (item.oid) {
      log.debug("Leaving DirectoryModel.absenceGaps(). Published.");
      return;
    }
    gaps.push(ModelIr.gap('no-oid',
      'The source states no OID. None is invented. Provenance ' +
      item.provenance + '.', objectId, item.name));
    gaps.push(ModelIr.gap('no-syntax',
      'The source states no LDAP syntax.', objectId, item.name));
    gaps.push(ModelIr.gap('no-matching-rule',
      'The source states no matching rule.', objectId, item.name));
    log.debug("Leaving DirectoryModel.absenceGaps().");
  }

  /**
   * Checks one value against the object's attribute names and kinds.
   * Every attribute is optional: the directory does not enforce MUST.
   * An unknown key fails. Unspecified kind accepts any JSON value,
   * because picking string would be a guess.
   *
   * @param catalog - a catalogue from `collect()`
   * @param id - the object id
   * @param value - the candidate
   * @returns whether it matches, and the Zod errors when it does not
   */
  parse(catalog: DirectoryCatalog, id: string, value: unknown): {
      ok: boolean; errors: string[] } {
    log.debug("Entering DirectoryModel.parse().");
    const object = catalog.objects.filter(function (one) {
      return one.id === id;
    })[0];
    if (!object) {
      log.debug("Leaving DirectoryModel.parse(). Unknown object.");
      return { ok: false, errors: ['unknown object ' + id] };
    }
    const shape: Record<string, any> = {};
    object.attributes.forEach(function (attribute) {
      shape[attribute.name] = DirectoryModel.zodOf(attribute).optional();
    });
    const parsed = z.strictObject(shape).safeParse(value);
    if (!parsed.success) {
      const errors = parsed.error.issues.map(function (issue: any) {
        return issue.path.join('.') + ': ' + issue.message;
      });
      log.debug("Leaving DirectoryModel.parse(). Rejected.");
      return { ok: false, errors: errors };
    }
    log.debug("Leaving DirectoryModel.parse().");
    return { ok: true, errors: [] };
  }

  /**
   * The Zod type of one attribute.
   *
   * @param attribute - the model attribute
   * @returns the Zod schema, not yet optional
   */
  static zodOf(attribute: ModelAttribute): any {
    log.debug("Entering DirectoryModel.zodOf().");
    if (attribute.kind === 'single') {
      log.debug("Leaving DirectoryModel.zodOf(). string.");
      return z.string();
    }
    if (attribute.kind === 'multi') {
      log.debug("Leaving DirectoryModel.zodOf(). string array.");
      return z.array(z.string());
    }
    log.debug("Leaving DirectoryModel.zodOf(). unknown.");
    return z.unknown();
  }
}

const directoryModel = new DirectoryModel(DirectoryModel.defaultDeps());

export = {
  DirectoryModel: DirectoryModel,
  POLICY_KIND_IDS: POLICY_KIND_IDS,
  SCHEMA_OWNERS: SCHEMA_OWNERS,
  model: directoryModel
};
