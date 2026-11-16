// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/xacml_pep_cluster.tsp
//
// Written by hand (#1760, Remote PEP clusters phase 1). THIS IS THE SOURCE
// of this object's table: `models/tools/generate.mjs` compiles it during the
// image build and `xacml/xacml_pep_clusters.ts` reads the result.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

@entry(#{
  id: "xacmlPepCluster",
  source: "../xacml/xacml_pep_clusters",
  container: "ou=pepClusters",
  ownContainer: false,
  authored: true,
  objectClasses: #[
    #{
      name: "xacmlPepCluster",
      what: "A logical cluster of remote Policy Enforcement Points that share one configuration (#1760): the reverse proxy, the managed settings and the listener definitions are held here once, and every member pulls them as its own. A member differs only in its name and its addresses. Membership is held here, so a PEP may be listed before it registers, and a PEP belongs to at most one cluster."
    }
  ]
})
model XacmlPepCluster {
  // THE THREE SHARED DOCUMENTS, in the PEP's own grammars: one validator
  // each, so a cluster's document is a document a PEP could hold.
  @attr(#{
    kind: "single",
    jsonBlob: true,
    what: "The reverse-proxy configuration every member of the cluster pulls from GET /xacml/pep/proxy (#1760): the PEP's own document (xacmlPepProxy), validated by the same grammar, its routes' generated policies named pepc-<cluster>-<route> and marked @<cluster>/<route>. Its publicBaseUrl is the cluster's logical base URL, which a simple or public route's default resource is built from and which a member without a publicBaseUrl of its own is sent. Written by the set-pep-cluster-proxy and set-pep-cluster-route actions."
  })
  xacmlPepClusterProxy?: string;
  @attr(#{
    kind: "single",
    jsonBlob: true,
    what: "The managed settings every member of the cluster pulls from GET /xacml/pep/settings (#1760): the PEP's own document (xacmlPepSettings), validated by the same table, except the notify URL, which is a member's address and is set on the member. Written by the set-pep-cluster-settings action."
  })
  xacmlPepClusterSettings?: string;
  @attr(#{
    kind: "single",
    jsonBlob: true,
    what: "The listeners defined for every member of the cluster (#1760): the PEP's own array (xacmlPepListeners), validated by the same grammar. A member may override a listener's address and port and add DNS names to its certificate; each member's certificate is its own, issued for its own key. Written by the set-pep-cluster-listener and remove-pep-cluster-listener actions."
  })
  xacmlPepClusterListeners?: string;
  @attr(#{
    kind: "single",
    jsonBlob: true,
    what: "The cluster's members (#1760): one JSON array of { pep, publicBaseUrl, notifyUrl, listeners: { <listener id>: { address, port, names } } }, each pep a registered PEP's name or one not yet registered, the rest the member's own addresses. A PEP is a member of at most one cluster. Written by the create-pep-cluster, add-pep-cluster-member, set-pep-cluster-member and remove-pep-cluster-member actions."
  })
  xacmlPepClusterMembers?: string;
  @attr(#{
    what: "What an administrator said about the cluster when creating it."
  })
  description?: (string)[];
}
