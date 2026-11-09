// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/policy_attributes.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table:
// `models/tools/generate.mjs` compiles it during the image build and `common/attribute_policy.ts`
// reads the result. The comments are the ones that sat on these rows there.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

// THE REFERENCE (#1241): on a person's entry and on a group's, the
// profile it names. The directory is schemaless; listed for the reader.
@entry(#{
  id: "policy.attributes",
  source: "policy_kinds:attributes",
  container: "ou=attributePolicies",
  ownContainer: true,
  definitionContainer: "ou=attributeDefinitions",
  authored: true,
  objectClasses: #[
    #{
      name: "stsAttributePolicy",
      what: "This service's class for an attribute policy: the attributes every person in a realm must hold. Named by the PROFILE (`cn=default`, or a named profile of the realm's own)."
    },
    #{
      name: "stsAttributeDefinition",
      what: "This service's class for a custom attribute of a realm, in ou=attributeDefinitions, named by the attribute (`cn=<name>`)."
    }
  ]
})
model PolicyAttributes {
  @attr(#{
    what: "The attributes every person in this realm must hold a value of, besides uid, cn and sn, which are always required. A list, or comma-separated. Any attribute a person may be given a value for: the inetOrgPerson schema, the credential catalogue, mail, and this realm's custom attributes. Enforced in product mode: a create without one is refused at every door, and an edit may not take one away. Default givenName, sn and mail.",
    field: #{key: "requiredAttributes", type: "attributeList", dflt: "givenName, sn, mail", label: "Required attributes"}
  })
  stsAttributeRequired?: (string)[];
  @attr(#{
    what: "What the profile or the custom attribute is for, for the next person."
  })
  description?: (string)[];
  @attr(#{
    what: "A custom attribute's label, drawn beside its name."
  })
  stsAttributeLabel?: string;
  @attr(#{
    what: "A custom attribute's syntax: string, integer, boolean, date, email, uri or dn. Its values are checked against it."
  })
  stsAttributeSyntax?: string;
  @attr(#{
    what: "TRUE where a custom attribute holds one value, FALSE where it holds several."
  })
  stsAttributeSingleValued?: DirectoryBoolean;
  @attr(#{
    what: "TRUE where a person sees their own values of a custom attribute on the user portal's Overview. FALSE, or absent, by default."
  })
  stsAttributePortalVisible?: DirectoryBoolean;
  @attr(#{
    what: "TRUE where a person may change their own values of a custom attribute on the user portal. Implies stsAttributePortalVisible. FALSE, or absent, by default."
  })
  stsAttributePortalEditable?: DirectoryBoolean;
  @attr(#{
    what: "Which named attribute policy applies where the person and their groups name several: the lowest, from 1 to 1000.",
    selector: #{key: "precedence"}
  })
  stsAttributePolicyPrecedence?: DirectoryInteger;
}

@entry(#{
  id: "policy.attributes",
  source: "policy_kinds:attributes",
  onPerson: true
})
model PolicyAttributesOnPerson {
  @attr(#{what: "On a person or a group: the attribute policy it names, `default` or a named profile of the realm. One value."})
  stsAttributePolicy?: string;
}
