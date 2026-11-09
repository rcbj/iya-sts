// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The decorators of the abstract model (#1390). A value a decorator takes is
// closed: a key that is not declared here is a compile error, so a new fact
// about an attribute is added on purpose.

import "./model_lib.mjs";

using TypeSpec.Reflection;

namespace IyaSts.ModelLib;

/**
 * What an attribute's text means. LDAP stores all of these as strings, so
 * each extends string: the directory says how it is held, and a domain model
 * says what it becomes. `unknown` is kept only where the code does not settle
 * whether an attribute holds one value or several.
 */
scalar DirectoryBoolean extends string;
scalar DirectoryInteger extends string;
scalar DirectoryTime extends string;
scalar DirectoryJson extends string;
scalar DirectoryDn extends string;
scalar DirectoryBase64 extends string;

/** One object class on a directory entry, with what its RFC states. */
model ClassRow {
  name: string;
  where?: string;
  standard?: boolean;
  what?: string;
  provenance?: string;
  oid?: string;
  classType?: string;
  sup?: string[];
  must?: string[];
  may?: string[];
  citation?: string;
}

/** A directory object: its container, its classes, where it was read. */
model EntryOptions {
  id: string;
  source: string;
  container?: string;
  ownContainer?: boolean;
  noAttributes?: boolean;
  authored?: boolean;
  definitionContainer?: string;
  section?: string;
  note?: string;
  onPerson?: boolean;
  projectionOf?: string;
  objectClasses?: ClassRow[];

  /** The attribute the entry is keyed by. Case-sensitive. */
  key?: string;

  /** The RDN attribute, and why it may differ from the key. */
  naming?: NamingOptions;

  /** Names that are worked out and are not LDAP attributes. */
  derived?: DerivedName[];

  /** The attributes saying an entry was registered. */
  registration?: string[];

  /** The attribute holding what the entry is declared for. */
  declaration?: string;

  /** The attribute holding what has been seen. */
  observation?: string;

  /** Closed lists a row's `allowedFrom` and the owning module both read. */
  lists?: Record<string[]>;
}

/** The attribute an entry is filed under. */
model NamingOptions {
  attribute: string;
  what: string;
}

/** A name that is worked out and is not an LDAP attribute. */
model DerivedName {
  name: string;
  what: string;
}

/**
 * One attribute. `declaredKind` is what the owning module says; `kind` is
 * that, or what the attribute's RFC says when the module says nothing.
 */
model AttributeOptions {
  kind?: string;
  declaredKind?: string;
  provenance?: string;
  from?: string;
  what?: string;
  editable?: boolean | string;
  standard?: boolean;
  identifier?: boolean;
  identifierName?: string;
  sensitive?: boolean;
  secret?: boolean;
  withheld?: boolean;
  families?: string[];
  familyWhy?: string;
  overrides?: string;
  strictOverride?: boolean;
  role?: string;
  allowed?: string[];
  allowedFrom?: string[];
  section?: string;
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
  field?: FieldOptions;
  selector?: SelectorOptions;
}

/** A setting a policy stores in this attribute. */
model FieldOptions {
  key: string;
  type: string;
  dflt?: unknown;
  min?: float64;
  max?: float64;
  label?: string;
  unit?: string;
  values?: string[];
  optional?: boolean;
  empty?: unknown;
  maxItems?: float64;
  mechanism?: string;
  role?: string;
  email?: boolean;
  door?: string;
}

/** How a person or a group names the policy that applies to them. */
model SelectorOptions {
  key: string;
}

/** A reference to another directory object. */
model LinkOptions {
  to: string;
  cardinality: string;
  owns: boolean;
  what: string;
}

/** A constraint, and the column it comes before. */
model PlacedText {
  at: int32;
  text: string;
}

/** The directory's name lists. */
model SpellingOptions {
  standard: string[];
  own: string[];
  secret: string[];
}

/** One index on a table. */
model IndexOptions {
  name: string;
  text: string;
  driver: unknown;
}

/** One PostgreSQL table. */
model TableOptions {
  name: string;
  engine?: string;
  head: string;
  suffix?: string;
  constraints?: PlacedText[];
  driver: unknown;
  indexes?: IndexOptions[];
}

/** One column: its SQL type and the clauses after that type. */
model ColumnOptions {
  sql: string;
  clauses?: string;
  required?: boolean;
  generated?: boolean;
  primaryKey?: boolean;
  backticks?: boolean;
  attributes?: string[];
}

/** What a schema holds beyond its tables. */
model SchemaOptions {
  engine?: string;
  version: int32;
}

extern dec entry(target: Model, options: valueof EntryOptions);
extern dec attr(target: ModelProperty, options: valueof AttributeOptions);
extern dec link(target: ModelProperty, options: valueof LinkOptions);
extern dec table(target: Model, options: valueof TableOptions);
extern dec column(target: ModelProperty, options: valueof ColumnOptions);
extern dec schema(target: Model, options: valueof SchemaOptions);
extern dec spellings(target: Model, options: valueof SpellingOptions);
