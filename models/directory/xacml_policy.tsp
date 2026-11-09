// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/xacml_policy.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table:
// `models/tools/generate.mjs` compiles it during the image build and `xacml/xacml_store.ts`
// reads the result. The comments are the ones that sat on these rows there.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

@entry(#{
  id: "xacmlPolicy",
  source: "../xacml/xacml_store",
  container: "ou=policies",
  ownContainer: false,
  authored: true,
  objectClasses: #[
    #{
      name: "xacmlPolicy",
      what: "One XACML 3.0 Policy or PolicySet, stored as the document it was authored as. THIS CONTAINER IS THE POLICY REPOSITORY — an ldapmodify of xacmlPolicyDocument here changes what the PDP decides on the next request."
    }
  ]
})
model XacmlPolicy {
  @attr(#{
    what: "The PolicyId or PolicySetId inside the document. DERIVED at write time and used for listing and for resolving a PolicyIdReference; the document is the truth."
  })
  xacmlPolicyId?: string;
  @attr(#{
    what: "The XACML 3.0 XML. THIS IS THE POLICY. Everything else on the entry is derived from it."
  })
  xacmlPolicyDocument?: string;
  @attr(#{
    what: "The Version attribute of the document. Derived."
  })
  xacmlVersion?: string;
  @attr(#{
    what: "\"Policy\" or \"PolicySet\". Derived."
  })
  xacmlKind?: string;
  @attr(#{
    what: "The rule- or policy-combining algorithm the document names. Derived, and shown on the console because it is the single most consequential line in a policy."
  })
  xacmlCombiningAlgId?: string;
  @attr(#{
    what: "\"TRUE\" or \"FALSE\". A disabled policy stays in the repository and is not evaluated. NOT derived — it is the one thing here that is a fact about the deployment rather than about the document, which is why it is an attribute rather than a comment in the XML."
  })
  xacmlEnabled?: DirectoryBoolean;
  @attr(#{
    what: "\"TRUE\" on the policy the PDP starts from. A repository with no root decides nothing and says so; a repository with two is refused at write time rather than picking one."
  })
  xacmlIsRoot?: DirectoryBoolean;
  @attr(#{
    what: "The document's own <Description>, where it has one."
  })
  description?: (string)[];
  // #564: APPLICATION-SCOPED FINE-GRAINED AUTHORIZATION. Two facts about
  // the DEPLOYMENT, like xacmlEnabled, and neither derived from the
  // document — so an edit of the document through any door keeps them.
  @attr(#{
    what: "The identifier of the application that OWNS this policy, which decides the details of that application's authorization_details types. Such a policy is never the root, is never reached by a PolicyIdReference from the root, and is never sent to a remote PEP."
  })
  xacmlApplication?: string;
  @attr(#{
    what: "When the owning application was deleted. The policy is kept, disabled, for audit, until an administrator removes it."
  })
  xacmlOrphanedAt?: unknown;
}
