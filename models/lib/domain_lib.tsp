// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The decorators of the canonical domain models (#1390). A directory object
// says how something is STORED; a domain model says what it MEANS, and states
// where each field comes from. A value a decorator takes is closed, so a new
// fact about a field is added on purpose.

import "./domain_lib.mjs";

using TypeSpec.Reflection;

namespace IyaSts.DomainLib;

/** A domain concept: its area of the catalogue and the entry it reads. */
model DomainOptions {
  area: string;
  what: string;
  entry: string;
}

/** Where a field is stored. */
model FieldSource {
  /** The attribute, spelled as the directory object spells it. */
  attr: string;

  /** The directory object holding it, when not the concept's own entry. */
  on?: string;

  /** `first` takes one value of an attribute that may hold several. */
  transform?: "first";

  /** Stated, and checked against the attribute's own marking. */
  secret?: boolean;
}

/** A field no attribute holds, and how it is worked out. */
model DerivedOptions {
  how: string;
}

/** A rule the concept keeps that a directory schema cannot state. */
model InvariantOptions {
  id: string;
  statement: string;
}

extern dec domain(target: Model, options: valueof DomainOptions);
extern dec fromAttr(target: ModelProperty, options: valueof FieldSource);
extern dec derived(target: ModelProperty, options: valueof DerivedOptions);
extern dec embedded(target: ModelProperty);
extern dec invariant(target: Model, options: valueof InvariantOptions);
