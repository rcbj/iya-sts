// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The Federation area of the catalogue (#1390).

import "../lib/domain_lib.tsp";

using IyaSts.DomainLib;

namespace IyaSts.Domain;

@domain(#{
  area: "Federation",
  entry: "federationRelationship",
  what: "An agreement with one partner, in either direction and one protocol."
})
@invariant(#{
  id: "federation.configured-only",
  statement: "This service federates only with a partner somebody configured; it is the one refusal by default."
})
model FederationRelationship {
  @fromAttr(#{attr: "fedId"})
  identifier: string;

  @fromAttr(#{attr: "fedName"})
  name?: string;

  @fromAttr(#{attr: "fedRole"})
  role?: string;

  @fromAttr(#{attr: "fedProtocol"})
  protocol?: string;

  @fromAttr(#{attr: "fedProvider"})
  provider?: string;

  @fromAttr(#{attr: "fedPeer"})
  peer?: string;

  @fromAttr(#{attr: "fedLocalEntityId"})
  localEntityId?: string;

  @fromAttr(#{attr: "fedEnabled"})
  enabled?: boolean;

  @fromAttr(#{attr: "fedClientId"})
  clientId?: string;

  @fromAttr(#{attr: "fedClientSecret", secret: true})
  clientSecret?: string;

  @fromAttr(#{attr: "fedSsoUrl"})
  authorizationUrl?: string;

  @fromAttr(#{attr: "fedTokenUrl"})
  tokenUrl?: string;

  @fromAttr(#{attr: "fedJwksUri"})
  jwksUri?: string;

  @derived(#{how: "The trust realm whose directory holds the entry."})
  realm: string;
}
