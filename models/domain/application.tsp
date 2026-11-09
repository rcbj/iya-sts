// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The Application area of the catalogue (#1390). The protocols stay separate
// concepts on purpose: an OAuth client, a SAML service provider and a
// WS-Federation relying party share an identity and little else, and one
// universal model would be the union of three things nobody means.

import "../lib/domain_lib.tsp";

using IyaSts.DomainLib;

namespace IyaSts.Domain;

@domain(#{
  area: "Application",
  entry: "application",
  what: "What an OAuth 2.0 client or OpenID Connect relying party is registered with."
})
model OAuthClient {
  @fromAttr(#{attr: "oauthClientId"})
  clientIds?: string[];

  @fromAttr(#{attr: "oauthClientSecret", secret: true})
  clientSecrets?: string[];

  @fromAttr(#{attr: "oauthRedirectUri"})
  redirectUris?: string[];

  @fromAttr(#{attr: "oauthPostLogoutRedirectUri"})
  postLogoutRedirectUris?: string[];

  @fromAttr(#{attr: "oauthGrantType"})
  grantTypes?: string[];

  @fromAttr(#{attr: "oauthResponseType"})
  responseTypes?: string[];

  @fromAttr(#{attr: "oauthTokenEndpointAuthMethod"})
  tokenEndpointAuthMethods?: string[];

  @fromAttr(#{attr: "oauthIdTokenSignedResponseAlg"})
  idTokenSigningAlgorithm?: string;
}

@domain(#{
  area: "Application",
  entry: "application",
  what: "What a SAML service provider is registered with."
})
model SamlServiceProvider {
  @fromAttr(#{attr: "samlEntityId"})
  entityIds?: string[];

  @fromAttr(#{attr: "samlAcsEndpoint"})
  assertionConsumerServices?: string[];
}

@domain(#{
  area: "Application",
  entry: "application",
  what: "What a WS-Federation relying party is registered with."
})
model WsFederationRelyingParty {
  @fromAttr(#{attr: "wsfedRealm"})
  realms?: string[];

  @fromAttr(#{attr: "wsfedReplyUrl"})
  replyUrls?: string[];
}

@domain(#{
  area: "Application",
  entry: "application",
  what: "Something this service issues to or accepts from, in any protocol."
})
@invariant(#{
  id: "application.identifier-is-the-key",
  statement: "The identifier is exactly what the protocol presented; the entry's cn may be a digest of it."
})
@invariant(#{
  id: "application.protocol-identifiers-reach-one-entry",
  statement: "A client id, an entity id and a WS-Federation realm of one application all resolve to this one entry."
})
model Application {
  @fromAttr(#{attr: "appIdentifier"})
  identifier: string;

  @fromAttr(#{attr: "appName"})
  displayName?: string;

  @fromAttr(#{attr: "description"})
  description?: string;

  @fromAttr(#{attr: "appHomePageUrl"})
  homePage?: string;

  @fromAttr(#{attr: "appAllowedProtocol"})
  allowedProtocols?: string[];

  @fromAttr(#{attr: "appRegistered"})
  registered?: boolean;

  @fromAttr(#{attr: "appFirstSeen"})
  firstSeen?: utcDateTime;

  @fromAttr(#{attr: "appLastSeen"})
  lastSeen?: utcDateTime;

  @derived(#{how: "The trust realm whose directory holds the entry."})
  realm: string;

  @embedded
  oauth?: OAuthClient;

  @embedded
  saml?: SamlServiceProvider;

  @embedded
  wsFederation?: WsFederationRelyingParty;
}
