---
title: Authentication libraries
---

# Authentication libraries

These are client libraries that have been tested against iya-sts. Each one is
the relying party's side of a flow this service implements, packaged so an
application can use it without writing the protocol code itself.

**This list will grow.** More libraries will be added as they are tested
against iya-sts or written for it. A library listed here has been run against
iya-sts; that does not mean it works only with iya-sts. Both libraries below
are written to the specifications and also work with other OpenID providers
and SSF transmitters.

The two libraries listed so far have the same use case on two platforms:

* **OpenID Connect Authorization Code flow with PKCE, as a public client.** The
  application holds no client secret (`token_endpoint_auth_method: none`). It
  signs a person in, keeps their tokens and refreshes them before they expire.
* **CAEP signals over the Shared Signals Framework.** With the signed-in
  person's own access token, the application creates or reuses a Shared
  Signals stream at iya-sts, polls it (RFC 8936), validates each Security Event
  Token, and calls one handler per CAEP event type. For example, a
  `session-revoked` event signs the person out of the application at once.

| Library | Platform | Language | Repository |
|---|---|---|---|
| **oidc-caep-client** | Single-page applications in the browser | JavaScript, with TypeScript declarations | [rcbj/oidc-caep-client](https://github.com/rcbj/oidc-caep-client) ([documentation](https://rcbj.github.io/oidc-caep-client/), npm [`oidc-caep-client`](https://www.npmjs.com/package/oidc-caep-client)) |
| **swift-oidc-caep-native-app** (`OIDCCAEPClient`) | Native macOS apps; Linux desktops too | Swift | [rcbj/swift-oidc-caep-native-app](https://github.com/rcbj/swift-oidc-caep-native-app) ([documentation](https://rcbj.github.io/swift-oidc-caep-native-app/)) |

The Swift library is a port of the JavaScript one. It keeps the JavaScript
library's names where Swift allows, and its protections are the same. The
feature lists below are therefore nearly identical. The differences are in the
[comparison](#comparison) at the end.

This page covers what each library does and what to set up in iya-sts for it.
How the libraries are built and called in detail is in each library's own
documentation. How iya-sts behaves as an OpenID provider and as a Shared
Signals transmitter is on [OAuth 2.0 and OpenID Connect](oauth-oidc.md) and
[Shared Signals](shared-signals.md).

* TOC
{:toc}

## oidc-caep-client: single-page applications

An OpenID Connect client for **browser single-page applications**, written in
JavaScript and shipped with TypeScript declarations. It runs in the page as a
public client and receives CAEP events through the Shared Signals Framework.
It uses only Web APIs (`fetch`, WebCrypto, `URL`, Web Storage, IndexedDB), so it
runs in every current browser, and also in Node.js 24.22.1 or later for tests
and tools. Its one dependency is [`jose`](https://github.com/panva/jose).

**Use it for** a single-page application that signs people in at iya-sts
directly from the browser, calls APIs with the person's access token, and
reacts to CAEP signals about that person while the page is open.

### Install

```sh
npm install oidc-caep-client           # latest: built from main
npm install oidc-caep-client@next      # next: pre-releases built from develop
```

The package is ES modules only. With a bundler (Vite, webpack, esbuild, Rollup)
import it as usual. Without one, serve `node_modules/oidc-caep-client/src/` and
`jose`'s browser build, and map both in an import map. TypeScript finds the
declarations with nothing to install.

### A minimal sketch

Taken from the library's README:

```js
import { OIDCClient, TokenManager, IndexedDBKeyStore, SSFReceiver, Subject }
  from 'oidc-caep-client';

const client = await OIDCClient.discover({
  issuer: 'https://sts.example.com',             // iya-sts's issuer
  clientId: 'my-spa',                            // a PUBLIC client
  redirectUri: `${location.origin}/callback`,
  postLogoutRedirectUri: `${location.origin}/`,
  dpop: { keyStore: new IndexedDBKeyStore() },   // optional, recommended
});
const tokens = new TokenManager(client);         // in memory, auto-refreshing

// Sign in: PKCE, state and nonce are made for you; PAR is used if offered.
location.assign((await client.createAuthorizationRequest()).url);

// On /callback: validate the response and the ID Token, keep the tokens.
await tokens.set('user', await client.callback(location.href));

// Call an API with a fresh token (and a DPoP proof when bound).
await client.fetchResource(await tokens.getTokenSet('user'),
                           'https://api.example.com/me');

// CAEP: one handler per event, over a poll stream.
const caep = new SSFReceiver({
  transmitterIssuer: 'https://sts.example.com',
  authorizationHeaders: async (req) =>
    client.resourceHeaders(await tokens.getTokenSet('user'), req),
});
caep.onSessionRevoked(async (evt) => { /* sign the person out */ });
await caep.start({ catchUp: true });   // create or reuse the stream, poll
```

[Building a browser single-page app](https://github.com/rcbj/oidc-caep-client/blob/develop/packages/oidc-caep-client/docs/spa-guide.md)
walks through a whole application. The repository's `demo/` is a working one,
run in one container against iya-sts.

### Features

**Sign-in and tokens**

* OpenID Connect discovery (`OIDCClient.discover()`), or a metadata document
  you supply (`fromMetadata()`).
* Authorization Code flow only (`response_type=code`), with PKCE `S256`. It
  refuses a provider whose metadata does not offer `S256`.
* `state`: 256 random bits per request, kept with the transaction in
  `sessionStorage`. On return it is required, compared in constant time, used
  once, expires after `transactionTtlSec` (ten minutes by default), and is
  bound to the issuer and client that started it.
* `nonce`: 256 random bits per request, compared in constant time with the ID
  Token's.
* Mix-up defence (RFC 9207): the `iss` response parameter must match, and is
  required when the provider advertises it.
* Authorization response hygiene: tokens in the front channel (query or
  fragment) and repeated parameters are refused.
* Pushed Authorization Requests (RFC 9126): used automatically when the
  provider advertises them (`par: 'auto'`), and always when it requires them.
* DPoP (RFC 9449): access and refresh tokens, and the authorization code
  (`dpop_jkt`), are bound to a **non-extractable** WebCrypto key. Proofs go to
  the token endpoint, UserInfo, the SSF endpoints and your own APIs. Server
  nonces (`use_dpop_nonce`) are handled. With DPoP on, a `Bearer` token
  response is refused (`requireDpop`), and a bound grant is never refreshed
  into a Bearer one.
* ID Token validation: all of OpenID Connect Core section 3.1.3.7 (signature
  with the expected `alg` only, `iss`, `aud`, `azp`, `exp`, `iat` age, `nonce`,
  `at_hash`, `max_age`/`auth_time`), and the refresh rules of section 12.2.
  Other JWT types presented as ID Tokens, unknown `crit` headers, and an `acr`
  outside the requested `acr_values` are refused.
* Resource indicators (RFC 8707): `resource` on the authorization, token and
  refresh requests.
* Token refresh: refresh-token rotation, concurrent refreshes merged into one
  request, scheduled refresh before expiry (`TokenManager`), and a Web Lock so
  two tabs never present the same rotating refresh token.
* UserInfo, with the `sub` checked against the ID Token's; a signed UserInfo
  response is verified.
* Token revocation (RFC 7009).
* RP-Initiated Logout, with its own single-use, expiring `state` checked on
  return (`validateEndSessionCallback()`).
* Dynamic Client Registration (RFC 7591) as a public client, and RFC 7592
  read and delete of the registration.
* HTTPS required for every provider and transmitter URL and every redirect
  URI. Loopback `http` is allowed for development.

**Several accounts in one browser** (`AccountManager`)

* Several people signed in at once, one cached token set each, in IndexedDB
  shared by every tab of the origin. One active account per tab; the others
  stay dormant and are not refreshed.
* `signIn()`, `chooseAccount()` (`prompt=select_account`), `addAccount()`
  (`prompt=login`), `resume()` (`prompt=none`) and `reauthenticate()`. A
  request that names an account accepts only that account
  (`account_mismatch`).
* Signing one account out ends only its session at the provider;
  `signOutAll()` lets the provider ask which to end.
* Changes to the account list are announced to the other tabs
  (`BroadcastChannel`) under a lock.
* Hooks (`onActivate`, `onDeactivate`, `onLeave`) where an application starts,
  stops or deletes the account's signal stream.
* This matches iya-sts's [several accounts in one browser](multiple-accounts.md),
  which is on by default.

**Storage**

* Tokens: in memory by default (`MemoryTokenStore`), or Web Storage or
  IndexedDB. `AccountManager` uses IndexedDB by default only when DPoP is on,
  and warns when tokens go to persistent storage without DPoP.
* DPoP key: `IndexedDBKeyStore` (non-extractable, kept across page loads),
  `WebStorageKeyStore` or `MemoryKeyStore`.
* Sign-ins in progress: `sessionStorage`.

**CAEP and the Shared Signals Framework** (`SSFReceiver`)

* Transmitter discovery from `/.well-known/ssf-configuration`.
* Poll delivery (RFC 8936). A browser cannot receive a push, so push is not
  offered.
* Stream management (SSF 1.0): create, list, read, update, replace and delete
  a stream; read and change its status; add and remove subjects; request a
  verification event.
* **Stream reuse.** If iya-sts refuses a new stream because the person already
  has one (409) or holds as many as `ssf.maxStreams` allows (403), `start()`
  reuses one of their streams: the one whose `description` matches, or else
  the first. It points that stream at this receiver's delivery settings.
* `start({ catchUp: true })` handles the events queued while nobody was
  polling before it returns.
* `stop()` stops polling and sends the acknowledgements still owed;
  `stop({ deleteStream: true })` also deletes the stream (on sign-out, with
  `ssf.manage`). The opt-in `deleteOnPageHide` deletes the stream, best effort,
  when the page is unloaded for good. It is off by default, because a kept
  stream holds the events that arrive while no tab is open.
* One handler per CAEP 1.0 event: `session-revoked`, `token-claims-change`,
  `credential-change`, `assurance-level-change`,
  `device-compliance-change`, `session-established`, `session-presented` and
  `risk-level-change`. Also the SSF `verification` and `stream-updated`
  events, any event by URI (the RISC 1.0 event types are exported as `RISC`),
  every event (`onAnyEvent`) and events with no handler
  (`onUnhandledEvent`).
* An `onEventReceived` hook runs before the typed handlers for every accepted
  event. By default it logs one line with the event's name and `jti` only.
* SET validation: a compact JWS with `typ` `secevent+jwt`, signed with an
  asymmetric algorithm, verified against the transmitter's JWKS; `iss`,
  `aud`, `jti`, `iat` and exactly one event checked; a replayed `jti` dropped.
* Careful acknowledgement: a SET is acknowledged only after its handlers
  succeed, and is retried up to `maxDeliveryAttempts` times otherwise. Only a
  definitely invalid SET is reported back as an error. Polls never overlap.
* Subject matching (`subjectMatches()`, `accountsForSubject()`): by
  `iss`/`sub`, a verified email or phone number, and `sid`. A session-scoped
  subject matches only the account that holds that session.
* The poll endpoint must be `https` and on the transmitter's origin, because
  every poll carries the person's access token.

**Not included:** confidential-client authentication (client secrets,
`private_key_jwt`, mutual TLS), JAR and JARM, front- and back-channel logout,
and CAEP push delivery.

## swift-oidc-caep-native-app: native macOS apps

An OpenID Connect client library for **native macOS apps**, written in Swift:
the `OIDCCAEPClient` product of a Swift package. It is the native counterpart
of oidc-caep-client. It signs the person in through the system browser
(RFC 8252), keeps their tokens in the Keychain, binds them to a key in the
Secure Enclave, and receives CAEP events through the Shared Signals Framework.
It needs macOS 13 or later and Swift 5.9 or later. Its only dependency is
Apple's [swift-crypto](https://github.com/apple/swift-crypto), which is
CryptoKit on Apple platforms.

The core also builds and runs on **Linux desktops** (GNOME, KDE). There, sign-in
uses a loopback redirect, and tokens and the DPoP key are held in memory only.
The repository's
[Linux and macOS](https://rcbj.github.io/swift-oidc-caep-native-app/linux.html)
page lists every difference.

**Use it for** a desktop app that signs people in at iya-sts, calls APIs with a
sender-constrained token, keeps people signed in across launches, and reacts
to CAEP signals about them.

### Install

With Swift Package Manager, in `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/rcbj/swift-oidc-caep-native-app.git",
             from: "0.1.0"),
],
targets: [
    .target(name: "MyApp", dependencies: [
        .product(name: "OIDCCAEPClient",
                 package: "swift-oidc-caep-native-app"),
    ]),
]
```

In Xcode: **File → Add Package Dependencies…**, the same URL, and the
**OIDCCAEPClient** library for the app target.

### A minimal sketch

Taken from the library's README and reference. The app's settings (the
provider's metadata URL, the `client_id`, the scopes and the redirect URI) are
in `OIDCConfiguration.plist`:

```swift
import OIDCCAEPClient

let config = try OIDCAppConfiguration.load()          // OIDCConfiguration.plist
let client = try await config.makeClient(
    dpopKeyStore: await preferredDPoPKeyStore())      // the Secure Enclave
let accounts = try await AccountManager(client: client).restore()  // Keychain
try await accounts.signIn(using: SystemWebAuthenticator())  // system browser
let tokens = try await accounts.getTokenSet()         // refreshed when due

// CAEP: one handler per event, over a poll stream.
let receiver = SSFReceiver(SSFReceiverConfiguration(
    transmitterIssuer: client.issuer,
    authorization: .oidc(client) { try await accounts.getTokenSet() }))
receiver.onSessionRevoked { event in /* sign the person out */ }
try await receiver.start(catchUp: true)   // create or reuse the stream, poll
```

[Building a native macOS app](https://github.com/rcbj/swift-oidc-caep-native-app/blob/develop/Documentation/native-app-guide.md)
walks through a whole app, including sandboxing and signing. The repository's
`Demo/` is a working one (SwiftUI on macOS, GTK 4 on Linux) configured for
iya-sts at `https://localhost:8081`.

### Features

**Sign-in and tokens**

* The system browser, never an embedded web view. `SystemWebAuthenticator`
  uses `ASWebAuthenticationSession`, so the app never sees the password and
  the browser's session is shared: single sign-on, `prompt=none` and several
  accounts work. `prefersEphemeralWebBrowserSession` turns the sharing off.
* Redirect URIs: a private-use scheme in reverse-domain form
  (`com.example.app:/callback`, RFC 8252 section 7.1). The scheme must contain a
  period. `https` with an associated domain works on macOS 14.4 and later.
  `LoopbackWebAuthenticator` receives a loopback redirect
  (`http://127.0.0.1:<port>/callback`, RFC 8252 section 7.3) by listening on
  the port and opening the default browser; it is how the Linux build signs
  in, and it works on macOS too.
* Configuration from `OIDCConfiguration.plist` (or an `OIDCConfiguration`
  dictionary in `Info.plist`): metadata URL, client ID, scopes, redirect and
  post-logout redirect URIs, resources, DPoP, PAR, the ID Token algorithm,
  ACR values, the SSF transmitter, and extra TLS trust anchors for a provider
  with a private CA.
* OpenID Connect discovery, or a metadata document you supply.
* Authorization Code flow only, with PKCE `S256`. It refuses a provider that
  does not offer `S256` or does not accept public clients (`none`).
* `state` and `nonce` as in the browser library. `state` is required, compared
  in constant time, used once, expires, and is bound to the issuer and client.
  Sign-ins in progress are held in memory, so the redirect must come back to
  the process that started the sign-in.
* Mix-up defence (RFC 9207) and authorization response hygiene.
* Pushed Authorization Requests (RFC 9126): `auto`, `always` or `never`.
* DPoP (RFC 9449), on by default in the configuration file. The key is made in
  the **Secure Enclave** when the Mac has one (`SecureEnclaveKeyStore`: the app
  can ask it to sign, but nothing can read it out), else in the Keychain
  (`KeychainKeyStore`). The authorization code is bound too (`dpop_jkt`).
  Proofs go to the token endpoint, UserInfo, the SSF endpoints and your own
  APIs. Server nonces are handled, and a `Bearer` response is refused while
  DPoP is on.
* ID Token validation: all of OpenID Connect Core section 3.1.3.7 and the
  refresh rules of section 12.2, as in the browser library.
* Resource indicators (RFC 8707).
* Token refresh with rotation, concurrent refreshes merged, and a refresh
  scheduled before expiry (`TokenManager`).
* UserInfo with the `sub` checked; a signed response verified.
* Token revocation (RFC 7009).
* RP-Initiated Logout in the browser, with its `state` checked
  (`endSession(using:request:)`).
* Dynamic Client Registration (RFC 7591) as a public client, and RFC 7592
  read and delete.
* HTTP through an ephemeral `URLSession` with no cookies and no cache, which
  never follows a redirect. HTTPS is required for every provider and
  transmitter URL; loopback `http` is allowed for development.

**Several accounts in one app** (`AccountManager`)

* The same model as the browser library: several people signed in, one active
  account, the others dormant. The cache is the Keychain, so every account,
  and which one was active, survives a relaunch.
* `signIn`, `chooseAccount`, `addAccount`, `resume` (`prompt=none`) and
  `reauthenticate`, each with a `using:` form that runs the browser step for
  you. A request that names an account accepts only that account.
* Signing one account out ends only its session; `signOutAll` lets the
  provider ask which to end.
* Hooks (`onActivate`, `onDeactivate`, `onLeave`) for starting, stopping and
  deleting the account's stream.

**Storage**

* Tokens: `KeychainTokenStore` by default on Apple platforms (the login
  keychain, or the data protection keychain with
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`); `MemoryTokenStore`
  elsewhere.
* DPoP key: `SecureEnclaveKeyStore`, `KeychainKeyStore` or `MemoryKeyStore`;
  `preferredDPoPKeyStore()` picks the strongest available.
* Your own stores implement `TokenStore`, `DPoPKeyStore` or
  `TransactionStore`, and your own networking implements `HTTPTransport`.

**CAEP and the Shared Signals Framework** (`SSFReceiver`)

* Everything the browser library's receiver does: discovery, poll delivery
  (RFC 8936), the full SSF 1.0 stream management, one handler per CAEP 1.0
  event and per SSF event, any event by URI (RISC included), `onAnyEvent`,
  `onUnhandledEvent`, the `onEventReceived` hook, the same SET validation and
  acknowledgement rules, and subject matching.
* **Stream reuse** on a 409, or a 403 at `ssf.maxStreams`: the stream whose
  `description` matches, or else the first, is reused and re-pointed at this
  receiver.
* `start(catchUp: true)`, `stop()`, and `stop(deleteStream: true)` on sign-out.
  The guidance is not to delete the stream when the app quits or goes to the
  background, but to keep its id and pass it as `streamID` on the next launch.
* The receiver authorizes with the signed-in person's token and a DPoP proof
  (`.oidc(client)`), a static bearer token (`.bearer`), or headers you build
  (`.headers`).
* SETs obtained some other way can be passed to `receiveSet(_:)`.

**Not included:** confidential-client authentication, JAR and JARM, front- and
back-channel logout, CAEP push delivery, an embedded web view (on purpose),
and a sign-in that survives a relaunch part way through.

## Setting up iya-sts for either library

Both libraries need the same things from iya-sts. Only the redirect URI and
CORS differ between them. Each library's repository has a script,
`scripts/register-iya-sts-client.mjs`, that does all of the steps below
for its demo through the [Management API](management-api.md). It is also a
worked example of the calls.

1. **Register a public client.** Create an application declared for
   **OAuth 2.0** and **OpenID Connect**, with:

   | Field | SPA (oidc-caep-client) | Native app (swift-oidc-caep-native-app) |
   |---|---|---|
   | `oauthTokenEndpointAuthMethod` | `none` | `none` |
   | `oauthResponseType` | `code` | `code` |
   | `oauthGrantType` | `authorization_code`, `refresh_token` | `authorization_code`, `refresh_token` |
   | `oauthRedirectUri` | the page's callback, e.g. `https://app.example.com/callback` | a private-use scheme, e.g. `com.example.myapp:/callback`; or loopback `http://127.0.0.1:<port>/callback` on Linux |
   | `oauthPostLogoutRedirectUri` | e.g. `https://app.example.com/` | e.g. `com.example.myapp:/logged-out` |
   | `oauthAllowedScope` | `openid`, `profile`, `email`, `offline_access`, `ssf.read`, `ssf.manage` | the same |
   | `appCorsOrigin` | **required**: the page's origin, e.g. `https://app.example.com` | not needed: a native app is not subject to CORS |

   [Configuring OAuth 2.0 grants → A public client](configure-oauth2-grants.md#a-public-client-a-browser-or-native-app)
   gives the console steps and the API call. [Applications](applications.md)
   describes every field, `appCorsOrigin` included. The browser calls
   discovery, PAR, the token endpoint, UserInfo, revocation and every SSF
   endpoint directly, so without `appCorsOrigin` those calls fail as network
   errors.

2. **Let the client be issued the Shared Signals scopes.** In iya-sts
   `ssf.read` and `ssf.manage` are gated by role. The application must be an
   **application member** of the native role `SSF_READ` for `ssf.read`, and of
   `SSF_MANAGE` for `ssf.manage`. Ask for both, because `SSF_MANAGE` does not
   authorize `ssf.read`. Nothing adds an application to the roles for you
   (`api` is the shell helper from
   [Configuring OAuth 2.0 grants → Before you start](configure-oauth2-grants.md#before-you-start);
   the console page is `/admin/roles`):
   ```bash
   api roles/add-member '{"role":"SSF_READ","kind":"application","member":"my-spa"}'
   api roles/add-member '{"role":"SSF_MANAGE","kind":"application","member":"my-spa"}'
   ```
   A library that only creates and deletes its own stream needs `ssf.manage`.
   One that only reads a stream somebody else created needs only `ssf.read`.
   [Shared Signals → Authentication](shared-signals.md#authentication-four-schemes-two-scopes)
   explains the two scopes, and
   [Configuring Shared Signals → Register a receiver](configure-shared-signals.md#register-a-receiver)
   the receiver side.

3. **Put the people in the matching groups.** A person is issued `ssf.read`
   only while they are in the group `ssf-read`, and `ssf.manage` only while they
   are in `ssf-manage`. Every realm has these roles and groups by default:
   ```bash
   api groups/add-member '{"group":"ssf-read","member":"alice"}'
   api groups/add-member '{"group":"ssf-manage","member":"alice"}'
   ```
   When the person or the application lacks a role, the scope is left off the
   token (or the request fails with `invalid_scope`), and iya-sts logs
   `STS-ADMIN-0821`, saying which condition failed. The stream calls then fail
   for want of the scope.

4. **Consent.** Consent is on by default, so the first sign-in stops at
   `/oauth2/consent` until the person approves the client. For a first-party
   application, grant consent for everybody in advance, as
   [Configuring OpenID Connect flows](configure-oidc-flows.md#two-things-to-know-first)
   describes.

5. **The issuer.** Point the library at the issuer the realm's discovery
   document names: the address the service is reached at, with
   `/realm/<id>` in front of the path for any realm but the default one
   ([Trust realms](trust-realms.md)). The SSF transmitter has the same
   issuer, and its metadata is at `/.well-known/ssf-configuration`.

**Settings that affect the libraries' streams.** Each library creates a
**person-owned poll stream** with the signed-in person's own token. iya-sts
sends such a stream only events about that person while
`ssf.personStreamsSelfOnly` is on (the default). The stream is deleted after
`ssf.personStreamInactivityTimeoutS` (a day by default) with no poll, which
cleans up after a tab or app that never comes back. `ssf.maxStreams` (25) caps
how many streams one receiver may hold, and the libraries reuse a stream
rather than fail at that cap. Every setting is on
[Shared Signals → Configuration](shared-signals.md#configuration). What fires
each CAEP event a library will receive is on [CAEP events](caep-events.md).

**TLS.** In development, iya-sts's certificate is issued under its own Root,
which is rebuilt on every start. The browser, or the Mac, has to trust it:
open the URL once and accept it, or trust the Root as
[TLS → The server certificate](tls.md#the-server-certificate) describes. The
Swift library's `TrustedCertificates` setting adds a trust anchor without
touching the system.

**Optional extras the libraries use when iya-sts offers them.** PAR is used
whenever the discovery document advertises it. DPoP-bound tokens need nothing
configured in iya-sts, and can be required of a client
([Security profiles](oauth-security.md)). Several accounts in one browser is
on by default ([Several accounts](multiple-accounts.md)).

## Comparison

| | oidc-caep-client | swift-oidc-caep-native-app |
|---|---|---|
| Kind of application | Browser single-page application | Native macOS app (Linux desktops too) |
| Language | JavaScript, with TypeScript declarations | Swift 5.9+ |
| Distribution | npm (`latest`, and `next` from `develop`) | Swift Package Manager |
| Runtime requirement | A current browser; Node.js 24.22.1+ outside one | macOS 13+ (glibc 2.35 and GTK 4.6 for the Linux demo) |
| Dependency | `jose` | `swift-crypto` |
| Client type | Public (`none`) | Public (`none`) |
| Flow | Authorization Code + PKCE `S256` | Authorization Code + PKCE `S256` |
| Where sign-in happens | The page redirects itself | The system browser (`ASWebAuthenticationSession`), or the default browser with a loopback listener |
| Redirect URI | `https` on the page's origin | Private-use scheme; `https` with an associated domain; loopback |
| CORS origin in iya-sts | Required | Not needed |
| PAR, RFC 9207, RFC 8707 | Yes | Yes |
| DPoP key | Non-extractable WebCrypto key in IndexedDB | Secure Enclave, else Keychain |
| DPoP default | Off; turn it on | On in `OIDCConfiguration.plist` |
| Token cache | Memory by default; IndexedDB for several accounts | Keychain |
| Survives a reload or relaunch | With IndexedDB | Yes, on macOS |
| Several accounts | Yes, one active account per tab, shared across tabs | Yes, one active account per app |
| RP-Initiated Logout, revocation | Yes | Yes |
| Dynamic Client Registration | Yes (RFC 7591, RFC 7592) | Yes (RFC 7591, RFC 7592) |
| SSF delivery | Poll (RFC 8936) | Poll (RFC 8936) |
| CAEP events with their own handler | All eight CAEP 1.0 events, plus SSF verification and stream-updated | The same |
| RISC events | Through `onEvent(RISC.…)` | Through `onEvent(RISC.…)` |
| Stream reuse at 409/403 | Yes | Yes |
| Stream deletion | On sign-out; opt-in on page unload | On sign-out |
| Not included | Confidential clients, JAR/JARM, front- and back-channel logout, push delivery | The same, and an embedded web view |
| Licence | MIT | MIT |

## Related

* [OAuth 2.0 and OpenID Connect](oauth-oidc.md)
* [Configuring OpenID Connect flows](configure-oidc-flows.md)
* [Configuring OAuth 2.0 grants](configure-oauth2-grants.md)
* [Security profiles: RFC 9700, OAuth 2.1, DPoP, mTLS](oauth-security.md)
* [Shared Signals: SSF, CAEP, RISC](shared-signals.md)
* [CAEP events](caep-events.md)
* [Configuring Shared Signals](configure-shared-signals.md)
* [Several accounts in one browser](multiple-accounts.md)
* [Sessions](sessions.md)
