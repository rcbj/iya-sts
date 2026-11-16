// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/pep/pep_proxy.tsp
//
// Written by hand (#1830). THE SOURCE OF THE REMOTE PEP REVERSE PROXY OPENAPI
// DOCUMENT (`xacml-pep/openapi/pep-proxy.json`): the paths the reverse proxy
// (#1760, `rust/bins/xacml-pep/src/proxy.rs`) owns on its own listeners
// whatever it is configured with — the OpenID Connect callback, sign-out,
// the account chooser and its three acts, the logo and the start page.
//
// THE CONFIGURED ROUTES ARE NOT HERE. Which paths are forwarded, to which
// upstream, under which mechanisms, is the configuration the PEP pulls
// (`GET /xacml/pep/proxy`, `pep_control_plane.tsp`), so no document can list
// them. What every route answers whatever its configuration — the order of
// the checks, the refusal envelope, the challenges, the sign-in redirect and
// the headers it changes upstream — is in the document's description and in
// `Refusal`, so a client of a protected application knows what to expect.
//
// AS THE CODE DOES IT:
//
// * The callback and sign-out take GET and HEAD (#1830); any other method
//   is 405 with `Allow: GET, HEAD` (STS-XPEP-0132, 0133), the callback's
//   state not looked up and so not spent.
// * Every refusal is the error page when Accept names text/html and the JSON
//   `Refusal` otherwise, except the callback's 403 STS-XPEP-0108, always the
//   page. Each operation's `default` says so.
// * The accounts acts read a form of at most 4096 bytes (a larger one is
//   read as empty) merged over the query, the form winning, and never read
//   its Content-Type; a cross-site POST is 403 STS-XPEP-0109 first.
// * `/.iya-pep/` is the proxy's whole (#1830): a path under it that is none
//   of these is 404 STS-XPEP-0134 and never reaches the route table, and a
//   configured route there is refused with the configuration.

import "../lib/api_lib.tsp";

using IyaSts.ApiLib;

@apiDocument(#{
  `openapi`:"3.1.0",
  `info`:#{
    `title`:"IYA STS remote PEP reverse proxy",
    `version`:"1",
    `description`:"The paths a remote PEP's reverse proxy owns on its listeners (PEP_PROXY_PORT, 9180, plain; PEP_PROXY_HTTPS_PORT, 9543, which asks for and never requires a client certificate; and listeners of purpose proxy the service defines). Every other path is a configured route, decided by the configuration the PEP pulls, and is not described here. EVERY PATH, ROUTES INCLUDED, IS ANSWERED IN THIS ORDER: a path that does not normalise (a backslash, a control or non-ASCII byte, a bad or encoded-separator escape, //, a . or .. segment) is 400 STS-XPEP-0064; before the first configuration arrives every path is 503 STS-XPEP-0118 with Retry-After; /.iya-pep/logo.png; with no active configuration, the start page for a browser's GET of / and 404 STS-XPEP-0065 otherwise; then the callback, sign-out and accounts paths; then any other path under /.iya-pep/, which is the proxy's own and 404 STS-XPEP-0134 (a route may not be configured there); then the route table. A ROUTE then answers: 405 STS-XPEP-0066 with Allow for a method it does not list; 403 STS-XPEP-0093 when its application is not usable; 413 STS-XPEP-0067 over its maxBodyBytes; its mechanism (an Authorization header of scheme Bearer for oauth2, SAML for saml2, Basic for basic, else the session cookie): 401 with one challenge header per mechanism it allows (Bearer realm, with error=\"invalid_token\" when a token was refused; Basic realm, charset=\"UTF-8\"; SAML realm; none for session) and codes 0070 to 0084 and 0089, 429 0080 with Retry-After when the service has locked a password out, 502 0075 when the service cannot be asked; for a browser (GET or HEAD accepting text/html) with no live session, 302 to the provider's authorization endpoint (code flow, PKCE S256, or a PAR request_uri), or on a multipleAccounts route with accounts held, 302 to /.iya-pep/accounts?return=; 403 0117 when its policy is not held and 0086 when the XACML decision refuses; 403 0116 for a deny-all route; 502 0095 to 0098 when the identity cannot be delivered (403 0095 when the service refuses it); 502 0091, 0092 or 0069 and 504 0068 for the upstream; else the upstream's own answer, streamed, redirects not followed, hop-by-hop headers removed and nothing added. Upstream, the proxy removes Host, Forwarded, X-Forwarded-*, every route's identity headers, Authorization (unless forwardCredentials), its own cookies and the service's, and adds X-Forwarded-For, X-Forwarded-Proto and X-Forwarded-Host and the route's identity (headers, a service-issued Bearer token, or a SAML session held for it at the application). Error codes are recorded in the PEP's log, with the error page's incident ID, and never sent.",
    `x-iya-cookies`:#{
      `iya_pep_session`:"A single-account session: 43 base64url characters. Path=/; HttpOnly; SameSite=Lax; Secure on HTTPS; no expiry. The server ends it after PEP_PROXY_SESSION_TTL_MS (8 hours).",
      `iya_pep_accounts`:"A browser's set of accounts on multipleAccounts routes: 32 base64url characters, the same attributes."
    }
  },
  `servers`:#[
    #{`url`:"https://localhost:9543",`description`:"The proxy's HTTPS listener, PEP_PROXY_HTTPS_PORT."},
    #{`url`:"http://localhost:9180",`description`:"The proxy's plain listener, PEP_PROXY_PORT."}
  ],
  `x-iya-doc`:"pepProxy"
})
namespace IyaSts.Pep.Proxy {

@js(#{`description`:"A refusal to a request whose Accept does not name text/html (one that does gets the error page). error follows the status: 400 invalid_request, 401 unauthorized or invalid_token, 403 access_denied, 404 not_found, 405 method_not_allowed, 413 payload_too_large, 429 too_many_requests, 503 temporarily_unavailable, 504 gateway_timeout, any other bad_gateway. Cache-Control: no-store."})
@component model `Refusal` {
  `error`: "invalid_request" | "unauthorized" | "invalid_token" | "access_denied" | "not_found" | "method_not_allowed" | "payload_too_large" | "too_many_requests" | "temporarily_unavailable" | "gateway_timeout" | "bad_gateway";
  `error_description`: string;
}

@js(#{`description`:"The error page: text/html; charset=utf-8, no script, with the title and sentence for the refusal, its error name, the time, an incident ID that names the log line, and a link to the start page. Cache-Control: no-store; Content-Security-Policy: default-src 'none'; style-src 'sha256-…'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; X-Content-Type-Options: nosniff; Referrer-Policy: no-referrer.",`$raw`:#{`type`:"string",`contentMediaType`:"text/html"}})
@component model `Page` {}

@component model `SignedOut` {
  @js(#{`description`:"Whether a session was held and ended."})
  `signedOut`: boolean;
}

@component model `Account` {
  @js(#{`description`:"This account's id in the browser's set: 12 base64url characters."})
  `account`: string;
  `username`: string;
  `name`: string;
  `application`: string;
  `active`: boolean;
}

@component model `Accounts` {
  `accounts`: `Account`[];
  @js(#{`description`:"PEP_PROXY_MAX_ACCOUNTS: how many a browser may hold (1 to 32, 5 by default)."})
  `max`: int64;
}

@js(#{`description`:"The form of /.iya-pep/accounts/switch and /.iya-pep/accounts/logout, application/x-www-form-urlencoded; the same names in the query are read too, the form winning."})
@component model `AccountForm` {
  `account`: string;
  @js(#{`description`:"Where to go next: a path on a configured route, not under /.iya-pep/; anything else is /."})
  `return`?: string;
}

@js(#{`description`:"The form of /.iya-pep/accounts/logout-all."})
@component model `ReturnForm` {
  `return`?: string;
}

@endpoint("/.iya-pep/callback", "get", #{
  `operationId`:"getCallback",
  `summary`:"The OpenID Connect redirect URI",
  `description`:"Completes the sign-in the proxy started for a session route: finds it by state (spent on lookup, so any later refusal spends it too), redeems the code at the token endpoint with the application client's credentials and the PKCE verifier, and verifies the ID Token. GET and HEAD; any other method is 405 STS-XPEP-0132 with Allow: GET, HEAD, and the state is not looked up. There is no SAML browser endpoint: SAML is a per-request mechanism.",
  `parameters`:#[
    #{`name`:"state",`in`:"query",`required`:true,`description`:"The pending sign-in; unknown, used or older than 600 s is 401 STS-XPEP-0082.",`schema`:#{`type`:"string"}},
    #{`name`:"code",`in`:"query",`required`:false,`description`:"Required unless error is sent; a code already redeemed is refused.",`schema`:#{`type`:"string"}},
    #{`name`:"iss",`in`:"query",`required`:false,`description`:"RFC 9207; required when the provider publishes authorization_response_iss_parameter_supported, and must be its issuer.",`schema`:#{`type`:"string",`format`:"uri"}},
    #{`name`:"error",`in`:"query",`required`:false,`description`:"The provider refused: 401 STS-XPEP-0083.",`schema`:#{`type`:"string"}},
    #{`name`:"error_description",`in`:"query",`required`:false,`description`:"Logged only.",`schema`:#{`type`:"string"}}
  ],
  `responses`:#{
    `302`:#{`description`:"Signed in: Location is the path that started the sign-in. Set-Cookie: iya_pep_session (a single-account route) or iya_pep_accounts (a multipleAccounts route, whose new account becomes the active one).",`headers`:#{`Location`:#{`schema`:#{`type`:"string"}},`Set-Cookie`:#{`schema`:#{`type`:"string"}}}},
    `401`:#{`description`:"No such pending sign-in, or its relying party is gone (STS-XPEP-0082); the provider's error, a wrong iss, no code, a replayed code, a token endpoint or ID Token failure, a token in the query, or another person on an account's re-sign-in (0083).",`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}},
    `403`:#{`description`:"The browser already holds PEP_PROXY_MAX_ACCOUNTS accounts (STS-XPEP-0108): always the error page, with a link to the chooser.",`content`:#{`text/html`:#{`schema`:null}}},
    `405`:#{`description`:"A method other than GET or HEAD (STS-XPEP-0132).",`headers`:#{`Allow`:#{`schema`:#{`type`:"string",`const`:"GET, HEAD"}}},`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}},
    `503`:#{`description`:"The session store is full or no random value was had (STS-XPEP-0085); no Retry-After.",`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}},
    `default`:#{`description`:"Before dispatch: 400 STS-XPEP-0064, 503 0118, 404 0065.",`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}}
  }
})
op `getCallback`(`responses/401/content/application~1json/schema`: `Refusal`,
  `responses/401/content/text~1html/schema`: `Page`,
  `responses/403/content/text~1html/schema`: `Page`,
  `responses/405/content/application~1json/schema`: `Refusal`,
  `responses/405/content/text~1html/schema`: `Page`,
  `responses/503/content/application~1json/schema`: `Refusal`,
  `responses/503/content/text~1html/schema`: `Page`,
  `responses/default/content/application~1json/schema`: `Refusal`,
  `responses/default/content/text~1html/schema`: `Page`): void;

@endpoint("/.iya-pep/logout", "get", #{
  `operationId`:"getLogout",
  `summary`:"Sign out of a single-account session",
  `description`:"Ends the session iya_pep_session names, here and in the relying party, and always clears that cookie. GET and HEAD, with no same-origin check; any other method is 405 STS-XPEP-0133 with Allow: GET, HEAD, and nothing is ended. A multipleAccounts set is not touched: its acts are under /.iya-pep/accounts. The service's sign-on session ends only if the provider's end-session endpoint ends it.",
  `responses`:#{
    `200`:#{`description`:"Nothing more to do: no session, or the provider publishes no end_session_endpoint. JSON even to a browser.",`headers`:#{`Set-Cookie`:#{`schema`:#{`type`:"string"}}},`content`:#{`application/json`:#{`schema`:null}}},
    `302`:#{`description`:"To the provider's end_session_endpoint with id_token_hint and client_id (no post_logout_redirect_uri).",`headers`:#{`Location`:#{`schema`:#{`type`:"string"}},`Set-Cookie`:#{`schema`:#{`type`:"string"}}}},
    `405`:#{`description`:"A method other than GET or HEAD (STS-XPEP-0133).",`headers`:#{`Allow`:#{`schema`:#{`type`:"string",`const`:"GET, HEAD"}}},`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}},
    `default`:#{`description`:"Before dispatch: 400 STS-XPEP-0064, 503 0118, 404 0065.",`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}}
  }
})
op `getLogout`(`responses/200/content/application~1json/schema`: `SignedOut`,
  `responses/405/content/application~1json/schema`: `Refusal`,
  `responses/405/content/text~1html/schema`: `Page`,
  `responses/default/content/application~1json/schema`: `Refusal`,
  `responses/default/content/text~1html/schema`: `Page`): void;

@endpoint("/.iya-pep/accounts", "get", #{
  `operationId`:"getAccounts",
  `summary`:"The account chooser",
  `description`:"The accounts iya_pep_accounts holds. The page lists each with a form to continue (the active one, a GET to the return path), switch to it or sign it out, a link to add another and a form to sign out of all. HEAD is answered as GET. Any other method, or a path under /.iya-pep/accounts/ not listed here, is 404 STS-XPEP-0110.",
  `parameters`:#[
    #{`name`:"return",`in`:"query",`required`:false,`description`:"Where to go after: a path on a configured route, not under /.iya-pep/; anything else is /.",`schema`:#{`type`:"string"}},
    #{`name`:"format",`in`:"query",`required`:false,`description`:"json answers Accounts instead of the page.",`schema`:#{`type`:"string",`enum`:#["json"]}}
  ],
  `responses`:#{
    `200`:#{`description`:"The chooser, or with format=json the list.",`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}},
    `default`:#{`description`:"Before dispatch: 400 STS-XPEP-0064, 503 0118, 404 0065.",`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}}
  }
})
op `getAccounts`(`responses/200/content/application~1json/schema`: `Accounts`,
  `responses/200/content/text~1html/schema`: `Page`,
  `responses/default/content/application~1json/schema`: `Refusal`,
  `responses/default/content/text~1html/schema`: `Page`): void;

@endpoint("/.iya-pep/accounts/add", "get", #{
  `operationId`:"getAccountsAdd",
  `summary`:"Sign in another account",
  `description`:"Starts a sign-in with prompt=login that joins the browser's set. With account naming one already held, it signs that person in again: login_hint is their username and the ID Token must name the same subject. GET only.",
  `parameters`:#[
    #{`name`:"return",`in`:"query",`required`:true,`description`:"A path on a route with multipleAccounts and the session mechanism that is not public; otherwise 404 STS-XPEP-0110.",`schema`:#{`type`:"string"}},
    #{`name`:"account",`in`:"query",`required`:false,`description`:"An account of the set to sign in again; an unknown one is ignored.",`schema`:#{`type`:"string"}}
  ],
  `responses`:#{
    `302`:#{`description`:"To the provider's authorization endpoint (code flow, PKCE S256, prompt=login), or its PAR request_uri.",`headers`:#{`Location`:#{`schema`:#{`type`:"string"}}}},
    `404`:#{`description`:"The return path is not on such a route (STS-XPEP-0110).",`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}},
    `502`:#{`description`:"The provider could not be asked: discovery or PAR failed (STS-XPEP-0075).",`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}},
    `503`:#{`description`:"The relying party could not be built (STS-XPEP-0090).",`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}},
    `default`:#{`description`:"Before dispatch: 400 STS-XPEP-0064, 503 0118, 404 0065.",`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}}
  }
})
op `getAccountsAdd`(`responses/404/content/application~1json/schema`: `Refusal`,
  `responses/404/content/text~1html/schema`: `Page`,
  `responses/502/content/application~1json/schema`: `Refusal`,
  `responses/502/content/text~1html/schema`: `Page`,
  `responses/503/content/application~1json/schema`: `Refusal`,
  `responses/503/content/text~1html/schema`: `Page`,
  `responses/default/content/application~1json/schema`: `Refusal`,
  `responses/default/content/text~1html/schema`: `Page`): void;

@endpoint("/.iya-pep/accounts/switch", "post", #{
  `operationId`:"postAccountsSwitch",
  `summary`:"Make an account the active one",
  `description`:"For its application. Refused as cross-site (403 STS-XPEP-0109) when Sec-Fetch-Site is neither same-origin nor none, or Origin's host is not Host's.",
  `requestBody`:#{`required`:true,`content`:#{`application/x-www-form-urlencoded`:#{`schema`:null}}},
  `responses`:#{
    `303`:#{`description`:"To the return path.",`headers`:#{`Location`:#{`schema`:#{`type`:"string"}}}},
    `403`:#{`description`:"Cross-site (STS-XPEP-0109).",`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}},
    `404`:#{`description`:"The set holds no such account (STS-XPEP-0111).",`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}},
    `default`:#{`description`:"Before dispatch: 400 STS-XPEP-0064, 503 0118, 404 0065.",`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}}
  }
})
op `postAccountsSwitch`(`requestBody/content/application~1x-www-form-urlencoded/schema`: `AccountForm`,
  `responses/403/content/application~1json/schema`: `Refusal`,
  `responses/403/content/text~1html/schema`: `Page`,
  `responses/404/content/application~1json/schema`: `Refusal`,
  `responses/404/content/text~1html/schema`: `Page`,
  `responses/default/content/application~1json/schema`: `Refusal`,
  `responses/default/content/text~1html/schema`: `Page`): void;

@endpoint("/.iya-pep/accounts/logout", "post", #{
  `operationId`:"postAccountsLogout",
  `summary`:"Sign one account out",
  `description`:"Ends that account's proxy session here and in the relying party; the service's sign-on session is not ended. The same cross-site check as switch.",
  `requestBody`:#{`required`:true,`content`:#{`application/x-www-form-urlencoded`:#{`schema`:null}}},
  `responses`:#{
    `303`:#{`description`:"Back to the chooser: /.iya-pep/accounts?return=<return>.",`headers`:#{`Location`:#{`schema`:#{`type`:"string"}}}},
    `403`:#{`description`:"Cross-site (STS-XPEP-0109).",`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}},
    `404`:#{`description`:"The set holds no such account (STS-XPEP-0111).",`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}},
    `default`:#{`description`:"Before dispatch: 400 STS-XPEP-0064, 503 0118, 404 0065.",`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}}
  }
})
op `postAccountsLogout`(`requestBody/content/application~1x-www-form-urlencoded/schema`: `AccountForm`,
  `responses/403/content/application~1json/schema`: `Refusal`,
  `responses/403/content/text~1html/schema`: `Page`,
  `responses/404/content/application~1json/schema`: `Refusal`,
  `responses/404/content/text~1html/schema`: `Page`,
  `responses/default/content/application~1json/schema`: `Refusal`,
  `responses/default/content/text~1html/schema`: `Page`): void;

@endpoint("/.iya-pep/accounts/logout-all", "post", #{
  `operationId`:"postAccountsLogoutAll",
  `summary`:"Sign every account out",
  `description`:"Ends every session of the browser's set and clears iya_pep_accounts; never fails on an empty or unknown set. The same cross-site check as switch.",
  `requestBody`:#{`required`:false,`content`:#{`application/x-www-form-urlencoded`:#{`schema`:null}}},
  `responses`:#{
    `303`:#{`description`:"To the return path, clearing iya_pep_accounts.",`headers`:#{`Location`:#{`schema`:#{`type`:"string"}},`Set-Cookie`:#{`schema`:#{`type`:"string"}}}},
    `403`:#{`description`:"Cross-site (STS-XPEP-0109).",`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}},
    `default`:#{`description`:"Before dispatch: 400 STS-XPEP-0064, 503 0118, 404 0065.",`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}}
  }
})
op `postAccountsLogoutAll`(`requestBody/content/application~1x-www-form-urlencoded/schema`: `ReturnForm`,
  `responses/403/content/application~1json/schema`: `Refusal`,
  `responses/403/content/text~1html/schema`: `Page`,
  `responses/default/content/application~1json/schema`: `Refusal`,
  `responses/default/content/text~1html/schema`: `Page`): void;

@endpoint("/.iya-pep/logo.png", "get", #{
  `operationId`:"getLogo",
  `summary`:"The logo the proxy's pages show",
  `description`:"GET and HEAD. Served once a configuration has arrived, active or not; another method is the reserved prefix's 404 (STS-XPEP-0134), or 0065 with no active configuration.",
  `responses`:#{
    `200`:#{`description`:"Cache-Control: public, max-age=3600.",`content`:#{`image/png`:#{`schema`:#{`type`:"string",`contentMediaType`:"image/png"}}}},
    `default`:#{`description`:"Before dispatch: 400 STS-XPEP-0064, 503 0118.",`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}}
  }
})
op `getLogo`(`responses/default/content/application~1json/schema`: `Refusal`,
  `responses/default/content/text~1html/schema`: `Page`): void;

@endpoint("/", "get", #{
  `operationId`:"getStartPage",
  `summary`:"The start page",
  `description`:"For a GET or HEAD of / that accepts text/html, when no configuration is active or no route is mounted at /: the logo and a title, no links and no forms. A route mounted at / answers instead; anything else is 404 STS-XPEP-0065.",
  `responses`:#{
    `200`:#{`description`:"The page.",`content`:#{`text/html`:#{`schema`:null}}},
    `default`:#{`description`:"400 STS-XPEP-0064, 503 0118, 404 0065, or the route at /.",`content`:#{`application/json`:#{`schema`:null},`text/html`:#{`schema`:null}}}
  }
})
op `getStartPage`(`responses/200/content/text~1html/schema`: `Page`,
  `responses/default/content/application~1json/schema`: `Refusal`,
  `responses/default/content/text~1html/schema`: `Page`): void;

}
