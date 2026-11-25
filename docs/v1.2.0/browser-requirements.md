---
title: Browser requirements
---

# Browser requirements

## For people using this service

The sign-in pages, your account portal, the reports pages and the admin
console run in your web browser. They work in a **current version** of any
mainstream browser on a computer, phone or tablet. Your browser needs to:

* **allow JavaScript** for this site;
* open the page over **HTTPS** (an address starting `https://`);
* **allow site data** for this site: cookies and session storage. Private
  browsing and some privacy settings block it, and then you cannot sign in;
* for **passkeys**, support WebAuthn, which every current browser does.

If something is missing, the page says so in your language instead of
staying blank. The page then shows "This browser cannot open this page",
"This browser cannot sign you in here", or "This browser cannot use
passkeys". Update your browser, or try another one. Some features use
pop-up windows. If your browser blocks them, the page tells you and you can
continue on the same page.

## For operators

The rest of this page is for an operator deciding which browsers their people
can use, and for whoever answers "this page doesn't work in my browser". It
lists the
browser features that the admin console (`/admin`), the user portal
(`/portal`), the reports application (`/report`) and the sign-in screens
(`/authn/*`) depend on, and what a person sees when one is missing. It
answers ASVS 5.0.0 requirement 3.1.1.

All four are **static applications**. The service sends one HTML document
and a script, and the script draws every page from an API
([User-facing pages](user-facing-pages.md)). Each feature below is one that
script uses. No browser is named, and no user-agent string is checked: what
matters is whether the browser has the feature.

## Summary

| Feature | Console, portal, reports | Sign-in screens | When it is missing |
|---|---|---|---|
| JavaScript (ECMAScript 2022) | Required | Required | The `<noscript>` notice with scripts blocked; "This browser cannot open this page" in a browser too old to run them |
| WebCrypto (`crypto.subtle`, `crypto.getRandomValues`) | Required | Not used | "This browser cannot open this page", and no sign-in starts |
| A secure context (HTTPS) | Required, for WebCrypto | Recommended | As WebCrypto |
| Content Security Policy | Required for protection | Required for protection | The pages still work, without that protection |
| `SameSite` cookies | Used | Used | The session cookie is sent more widely; nothing breaks |
| Fetch, Promises, `TextEncoder`, `URL` | Required | Required | "This browser cannot open this page", naming what is missing |
| `sessionStorage` | Required for sign-in | Not used | "This browser cannot sign you in here", and no sign-in starts |
| `window.open` and `BroadcastChannel` | Used for a write that needs more permission | Not used | The browser leaves the page to get permission. The page's choices are kept; the pending change is not sent |
| `Intl` | Used for plurals, numbers, dates and text direction | Used | English plural forms, plain numbers and ISO dates |
| WebAuthn | Needed for passkeys | Needed for passkeys | "This browser cannot use passkeys", and no ceremony starts |
| Device Bound Session Credentials | Optional, off by default | Optional | The session stays an ordinary cookie session |
| Reporting API | Optional | Optional | CSP violations are not reported by that browser |
| `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy` | Sent | Sent, except COOP | The pages still work, without that isolation |

## JavaScript

**Required everywhere.** Every one of these pages is drawn by its script, and
none has a server-drawn fallback or a submit button that works without it
(`common/shell_document.ts`). The scripts are built for ECMAScript 2022
(`--target=es2022` in `build-typescript.sh`), so a browser must implement
that edition's syntax.

With scripts blocked, the page shows its `<noscript>` notice and nothing else:

| Surface | What the person sees |
|---|---|
| Console | **Scripts are blocked.** "This console is a script that runs in your browser and draws every page from `/admin-api`; with scripts blocked there is nothing it can show." |
| Portal | "This portal is a script that runs in your browser and draws every page from `/account-api`; with scripts blocked there is nothing it can show." |
| Reports | "This page needs its script." |
| Sign-in | **Sign in.** "This sign-in page is a script that runs in your browser, and with scripts blocked there is nothing it can show. Allow scripts for this page to sign in." |

The front page, consent, the sign-out, GNAP's interaction pages, the
federation pages and the protocol description pages have notices of the
same kind. The server draws each notice in the request's language, chosen as
it chooses every page's ([Languages and regions](languages.md)): the language
chooser's cookie, `Accept-Language`, and the locale policy. Each notice ends
with a link to [For people using this service](#for-people-using-this-service).

### A browser too old for the scripts

A browser can run JavaScript and still be too old for these pages. Every
page's document therefore loads a small check, `/web/browser-check.js`,
before its main script. The check is written in ECMAScript 5, so an old
browser can run it (`common/web_browser_check.ts`). It asks for `fetch`,
`Promise`, `TextEncoder`, `TextDecoder`, `URL`, `URLSearchParams`,
`history.pushState`, and ECMAScript 2022. A script cannot test ECMAScript
2022 syntax without `eval`, which the Content Security Policy refuses. So the
check asks for `Object.hasOwn` and `Array.prototype.at`, which arrived in
that edition. It also watches for a `SyntaxError` from the main script while
the page loads.

If something is missing, the check shows a notice that the server drew
hidden, in the person's language:

> **This browser cannot open this page**
> This browser lacks features this page needs, so the page cannot be drawn.
> Use a current version of your browser, or another browser. (fetch, URL)

The names in brackets are what is missing. The notice links to
[For people using this service](#for-people-using-this-service), and the
page's main script does not start. Both scripts are this service's own files,
under `script-src 'self'`; neither is inline.

## WebCrypto

**Required by the console, the portal and the reports application.** Each
signs in as an OAuth public client, with PKCE and a DPoP-bound access token
held in memory ([OAuth security](oauth-security.md)). The script uses:

* `crypto.getRandomValues` for the PKCE verifier, the `state` and each DPoP
  proof's `jti`;
* `crypto.subtle.digest` (SHA-256) for the PKCE challenge;
* `crypto.subtle.generateKey` for a non-extractable ECDSA P-256 key, and
  `exportKey`, `sign`, `importKey` and `verify`, for DPoP and for checking a
  JARM answer.

Before anything else, each application checks that all of these exist
(`common/web_spa_client.ts`, `webCryptoMissing()`). If one is missing, no
sign-in starts and the page shows, in the person's language:

> **This browser cannot open this page**
> This browser cannot run this page securely: WebCrypto is unavailable,
> usually because the page was not opened over HTTPS or the browser is too
> old.

The message links to [For people using this service](#for-people-using-this-service).
The sign-in screens use no WebCrypto.

## A secure context

Browsers provide `crypto.subtle` only in a secure context: a page served over
HTTPS, or from `localhost`. A product deployment always serves HTTPS
([Security in product mode](product-security.md#connections-and-browsers)).
Nothing checks `window.isSecureContext` directly. A page opened over plain
HTTP elsewhere fails the WebCrypto check above and shows the same message.

The console's and the portal's **Copy** buttons use `navigator.clipboard`,
which needs a secure context. Without it, or when the browser refuses it,
they select the text and use `document.execCommand('copy')`
(`common/web_clipboard.ts`). If that fails too, the button says **Copy
failed** in the person's language, and its tooltip says to select the text
and copy it by hand.

## Content Security Policy

Every page is sent a Content Security Policy. The four applications'
documents carry `script-src 'self'`, `style-src 'self'` and `connect-src
'self'` (plus the origins of other listeners the page calls), and always
`frame-ancestors` and `base-uri` (`common/shell_document.ts`). There is no
inline script and no `eval`, so a browser that enforces CSP blocks injected
script. The service also removes scripts, event handlers and unsafe
addresses from markup before it reaches the page
([Security in product mode](product-security.md#browser-pages)).

A browser that does not support CSP still runs the pages, but without that
second layer of protection. The service does not detect this.

## Cookies and `SameSite`

The console, portal and reports application call their APIs with a bearer
token, not a cookie. The **sign-on session** is a cookie:
`sts_session`, sent as `__Host-sts_session` over TLS, with `HttpOnly`,
`SameSite=Lax` and `Secure` (`authn/authn.ts`). The sign-in screens, the
language chooser and the account chooser rely on cookies, and their API
requests are same-origin and carry a CSRF header.

`Lax` is chosen on purpose: a cross-site form POST, such as a WS-Federation
response, arrives without the session. A browser that does not support
`SameSite` sends the cookie on cross-site requests too. Sign-in still works,
with less protection against cross-site request forgery. Cookies must be
enabled for anyone to sign in.

## Fetch and the rest of the platform

Every page loads its content with `fetch`, and uses Promises, `async` and
`await`, `TextEncoder` and `TextDecoder`, `URL` and `URLSearchParams`, and
`history.pushState` and `replaceState`. The browser check detects each of
these before the page's script runs
([A browser too old for the scripts](#a-browser-too-old-for-the-scripts)).
`AbortController` is used where present and skipped where not.

Downloads (CSV and file exports) use `Blob` and `URL.createObjectURL`. The
portal's profile photo upload uses `FileReader`. QR codes are drawn in the
page; no camera is used, and the `Permissions-Policy` header turns the
camera, microphone and location off.

The console's layout uses the CSS `:has()` selector. Where a browser lacks
it, `@supports selector(:has(*))` makes the console show every field instead
of hiding the ones that do not apply.

## `sessionStorage`

At sign-in the console, the portal and the reports application keep the PKCE
verifier, the `state` and the return address in `sessionStorage` until the
browser comes back from `/oauth2/authorize`. Sign-in needs it. A browser can
block it, for example in some private-browsing modes or with site data
refused. So before anything else, beside the WebCrypto check, each
application writes a test value to `sessionStorage` and reads it back
(`common/web_spa_client.ts`, `sessionStorageMissing()`). If that fails, no
sign-in starts, and the page shows, in the person's language:

> **This browser cannot sign you in here**
> This browser does not let this page use session storage, which signing in
> needs. Private browsing and some privacy settings block it: allow site data
> for this site, then reload the page.

The message links to [For people using this service](#for-people-using-this-service).

Other uses (the tab's account hint, the console's unsaved form, sign-out
clean-up) are wrapped so that a missing `sessionStorage` is ignored.
`localStorage` and IndexedDB are not used.

## Pop-up windows and `BroadcastChannel`

The console, the portal and the reports application sign in with read
permission only. A change that needs more asks for it when it is made, in a
small window (`/oauth2/authorize` cannot be framed). That window hands the
answer back over a `BroadcastChannel` and closes itself
(`common/web_spa_client.ts`, #2168).

What a person sees:

| Situation | What happens |
|---|---|
| Both are available | A window opens. The page shows "Getting permission to make this change…" until it is done |
| The browser blocked the window | A bar says "This change needs your permission. Open the window to give it.", with **Continue** (opens it again) and **Cancel** |
| The window was refused | "Permission to make this change was not given: " and the reason |
| A different account signed in | "That sign-in was another account, so nothing was sent." |
| `window.open` or `BroadcastChannel` does not exist | The page leaves for the authorization page and comes back. The change that asked for permission is not sent and has to be made again. First, each application saves the choices on the page: checkboxes, radio buttons and lists, never typed text or secrets (`common/web_page_state.ts`). When the page comes back for the same person, they are put back, with "You are signed in again. The choices on this page were put back, and nothing was sent: make the change again to send it." |

The console also uses a window when a session needs signing in again:

* With no `BroadcastChannel`: "This browser cannot hand a sign-in back from
  another window, so sign in on this page."
* With the window blocked: "The sign-in window was blocked. Allow pop-ups for
  this site, or sign in on this page."
* With no `window.open`, the page signs in by leaving and coming back.

Two other channels, one keeping several tabs' account lists in step and one
handing a sign-in callback to the tab that started it, are skipped silently
when `BroadcastChannel` is missing.

## `Intl`, for translation

The pages are translated in the browser ([Languages and regions](languages.md)).
The language comes from, in order: `ui_locales`, the person's
`preferredLanguage`, the language chooser, `navigator.languages`, and the
realm's default. The pages use `Intl.PluralRules`, `Intl.NumberFormat`,
`Intl.DateTimeFormat`, `Intl.getCanonicalLocales` and `Intl.Locale` (for text
direction). Each use has a fallback: the "other" plural form, the plain
number, the ISO date and time, English weekday names, or skipping a catalog
whose language tag the browser cannot read.

## WebAuthn, for passkeys

Passkeys need `navigator.credentials` and `PublicKeyCredential`
([Passkeys](passkeys.md)). The `Permissions-Policy` header allows
`publickey-credentials-create` and `publickey-credentials-get` for this
origin only.

* **Sign-in screens.** Without WebAuthn the ceremony reports
  `NotSupportedError`, and the page says "Your browser did not use a passkey
  (NotSupportedError)." The person can sign in another way the realm allows.
* **Passkey autofill** needs `PublicKeyCredential.isConditionalMediationAvailable`
  and `AbortController`, and is skipped without them.
* **Post-quantum passkeys.** Where a device cannot make an ML-DSA passkey and
  the realm requires one, the page says "This service requires a post-quantum
  (ML-DSA) passkey, and this device could not make one. Use another device, or
  a security key that can." Where the browser reports (through
  `PublicKeyCredential.getClientCapabilities`) that it can use a phone nearby,
  it adds "Your browser can also make the passkey on a phone or another device
  nearby: choose that when it asks."
* The WebAuthn Signal API, used to tell a credential manager about removed or
  renamed passkeys, is used where present and skipped where not.
* **Console.** Enrolling a passkey for a person with no WebAuthn shows "This
  browser cannot create a WebAuthn credential." Upgrading a person's passkey
  checks for WebAuthn before it starts, and shows "This browser cannot use
  passkeys: WebAuthn is unavailable. Use a current browser, or another
  device."
* **Portal.** Before a passkey ceremony the portal checks for
  `PublicKeyCredential` and `navigator.credentials`
  (`common/web_webauthn.ts`, `missing()`). Without them it shows the same
  sentence beside the ceremony, hides its button, and sends nothing.

## Device Bound Session Credentials (optional)

**Off by default** (`authn.deviceBoundSessions`, per realm). When it is on,
the sign-in response carries a `Secure-Session-Registration` header, and a
browser that supports DBSC binds the session to a key it holds
(`authn/device_bound_sessions.ts`). A browser that does not ignores the
header and keeps an ordinary cookie session. Nothing is shown either way.
See [Sessions](sessions.md).

## Reporting API (optional)

Every page's policy names `report-uri` and `report-to csp-endpoint`, and a
`Reporting-Endpoints` header names `/web/csp-report` (#2164). This is always
on. A browser that supports either sends a report when it blocks something;
one that does not just blocks it. **Monitoring → CSP reports** counts what
arrives, and `cspReports.forwardUrl` (empty by default) forwards it
([OAuth security](oauth-security.md#content-security-policy-violation-reports)).

## Cross-origin isolation headers

* The console's, portal's and reports application's documents are sent
  `Cross-Origin-Opener-Policy: same-origin-allow-popups`, which still lets the
  permission window above talk back, and `Cross-Origin-Resource-Policy:
  same-origin` (`common/shell_document.ts`).
* Every other response that names none is sent `Cross-Origin-Resource-Policy:
  same-site`, and every other HTML document `Cross-Origin-Opener-Policy:
  same-origin`. The sign-in screens and every page on a sign-in path
  (`/oauth2/authorize`, `/authn`, SAML, WS-Federation, GNAP, federation,
  `/launch`, `/logout` and others) get no COOP, because a relying party that
  signs a person in through a popup would otherwise never get its answer
  (`common/app.js`, #2181).
* `Cross-Origin-Embedder-Policy` is not sent.

A browser that does not support these headers runs the pages without that
isolation.

## Minimum browser versions

No version is enforced or checked. The hard requirements set the floor: a
browser must implement ECMAScript 2022, WebCrypto with ECDSA P-256 and
SHA-256, Fetch, `TextEncoder`, `URL`, `sessionStorage`, and cookies with the
`__Host-` prefix. Any browser that has those can sign in to and use all four
applications. Passkeys add WebAuthn, and a permission step without losing the
pending change adds `window.open` and `BroadcastChannel`.

## Known gaps

None are open. The gaps this page listed until #2220 are closed: the
session-storage, WebAuthn, browser-too-old and pop-up messages, the
translated `<noscript>` notices, the portal's and the reports application's
page state, the portal's **Copy**, and the
[statement for people](#for-people-using-this-service).

## Related

* [User-facing pages](user-facing-pages.md)
* [Languages and regions](languages.md)
* [Passkeys](passkeys.md)
* [Sessions](sessions.md)
* [OAuth security](oauth-security.md)
* [Security in product mode](product-security.md)
