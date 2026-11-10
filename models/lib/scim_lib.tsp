// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The decorators of the SCIM namespace of the abstract model (#1579). A SCIM
// schema is a model; each of its properties is one attribute of RFC 7643,
// and the property's TypeSpec type states the attribute's type, whether it
// is multi-valued (an array), whether it is required (not optional), its
// sub-attributes (a model) and its canonical values (string literals). What
// a TypeSpec type cannot state is `@scimAttribute`'s, and where the
// attribute is kept in the directory is `@maps`'s. A value a decorator takes
// is closed, so a new fact about an attribute is added here on purpose.

import "./scim_lib.mjs";

using TypeSpec.Reflection;

namespace IyaSts.ScimLib;

/** A reference attribute's value: RFC 7643 section 2.3.7. */
scalar ScimReference extends string;

/** A binary attribute's value, base64: RFC 7643 section 2.3.6. */
scalar ScimBinary extends string;

/** One schema extension of a resource type: RFC 7643 section 6. */
model ExtensionRow {
  /** The extension schema's URN. */
  schema: string;

  /** Whether a resource of the type must carry it. */
  required: boolean;
}

/** A SCIM schema: RFC 7643 section 7. */
model SchemaOptions {
  /** The schema's URN. */
  id: string;

  /** Its name, which is also its resource type's id and name. */
  name: string;

  /** Its description, as /Schemas and /ResourceTypes publish it. */
  description: string;

  /**
   * A resource's core schema (RFC 7643 section 4), which scimmy also ships:
   * the model replaces every attribute scimmy's copy holds, the common ones
   * included.
   */
  resource?: boolean;

  /**
   * An extension scimmy ships (RFC 7643 section 4.3): the model replaces its
   * own attributes and leaves its common ones, which nothing reads, alone.
   */
  shipped?: boolean;

  /**
   * The members are the realm's own (#699), built when a realm asks: the
   * model states the schema and no attribute.
   */
  realmDefined?: boolean;

  /** A core schema's resource type's extensions, in order. */
  extensions?: ExtensionRow[];
}

/** What RFC 7643 section 2.2 says of an attribute and its type cannot. */
model AttributeOptions {
  description?: string;

  /** `readWrite` when not said. */
  mutability?: "readOnly" | "readWrite" | "immutable" | "writeOnly";

  /** `default` when not said. */
  returned?: "always" | "never" | "default" | "request";

  /**
   * `none` when not said. `unpublished` leaves the characteristic out of
   * /Schemas, as scimmy's definitions of a multi-valued complex attribute do.
   */
  uniqueness?: "none" | "server" | "global" | "unpublished";

  /** false when not said. */
  caseExact?: boolean;

  /** A reference's types: RFC 7643 section 7. */
  referenceTypes?: string[];

  /**
   * A read-only member that is never taken in at all, rather than taken in
   * and ignored: scimmy's `direction: "out"`.
   */
  direction?: "out";

  /** Where RFC 7643 requires the attribute, for the refusal that cites it. */
  section?: string;
}

/** Where an attribute is kept in the directory: one row of a mapping table. */
model MapOptions {
  /** The table: the User resource's or the Group resource's. */
  table: "user" | "group";

  /** The row's place in its table, from 1. An untyped value of a
   * multi-valued member goes to its first row. */
  row: int32;

  /** The directory attribute, spelled as the directory object spells it. */
  ldap: string;

  /**
   * How the two shapes differ: `single` one value each side; `bool` an LDAP
   * boolean; `lock` the PRESENCE of the password-policy lock, inverted;
   * `multi` one LDAP attribute per `type` of a multi-valued member;
   * `complex` one sub-attribute of a complex value per LDAP attribute;
   * `derived` read-only and computed; `links` the federation links, which
   * `scim.ts` converts; `members` a group's resolved membership.
   */
  kind: "single" | "bool" | "lock" | "multi" | "complex" | "derived" |
    "links" | "members";

  /** A `multi` row's type. */
  type?: string;

  /** The document and section defining the LDAP attribute. */
  cite?: string;

  /** Said instead of `cite` for one of this service's own types. */
  own?: "plain" | "claims" | "federation";

  /** What the console and /admin-api say beside the row. */
  note?: string;

  /** A conversion between the two spellings of one value. */
  transform?: "postalAddress";

  /** The mapping introduced this attribute type; the directory learns it. */
  introduced?: boolean;

  /** Attributes a write of a `members` row also clears. */
  alsoClears?: string[];
}

/** What a `cite` says for each of this service's own types. */
model OwnTypes {
  plain: string;
  claims: string;
  federation: string;
}

extern dec scimSchema(target: Model, options: valueof SchemaOptions);
extern dec scimCommon(target: Model);
extern dec scimAttribute(target: ModelProperty,
  options: valueof AttributeOptions);
extern dec maps(target: ModelProperty, options: valueof MapOptions);
extern dec scimOwnTypes(target: Namespace, options: valueof OwnTypes);
