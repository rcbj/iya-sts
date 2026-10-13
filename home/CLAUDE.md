# home/

The front door. One server module, one page drawn in the browser, one image —
**a static surface since #579 (2026-10-12)**, the first of #569's public pages
and the first to follow #570's recipe (`common/CLAUDE.md` 3cl):

| File | What it is |
|---|---|
| `home.ts` | The server half: `GET /` (the shell), `GET /home.js` (the bundle), `GET /home.css` (the card's own rules), `GET /home-api` (the API's index) and `GET /home-api/front` (the page's view), `GET /realms`, and `GET /logo.png`, the only image this service serves. |
| `web_home_front.ts` | The renderer: the card's body from the view, its band (the logo) for the surface's frame, in the page's language from the `home` catalogs. |
| `web_home_pages.ts` | The page table (`PAGES`, `render`, `frame`), and the renderers' bundle `home.bundle.js` (`StsHome`) the tests load. |
| `web_home.ts` | The entry: `new WebSurface(...).start()`. Built to `home-spa.js` — never `home.js`, which is `home.ts` compiled — and served at `/home.js`. |
| `assets/logo.png` | That image: this project's own logo, a byte-for-byte copy of `docs/logo.png`, the one README.md shows — see below. |

It is a directory of its own rather than a route in `common/`, and the entry
test that file states is the reason: *a file lands there because more than one
family needs it*. Nothing needs this one. It is also not a candidate for the
package root, where there are exactly two modules and both earn it.

## Its place in the require order (6a)

No constraint. Exact paths (`/`, `/home.js`, `/home.css`, `/realms`,
`/logo.png`) and the `/home-api` prefix, and nothing but the app and libraries
behind them; first among the route modules — the first `register()` call in
`common/protocol_stack.ts`, since #50's R1 moved registration out of the
require — so that the page a person meets first heads the list on
`/admin/sts-metadata`.

## What this page is for, and the one rule it must keep

Until 2026-08-24 the root of this service was an unrouted path, so the answer to
the one URL a person types first was Express's `Cannot GET /`. That is a true
statement about the router and a useless one about the service: this port
answers well over a hundred endpoints across sixteen protocol families and none
of them was discoverable from `/`.

So the page is a **signpost**: the logo, the name, the version, one sentence
about what this service is, the warning that it verifies nothing, and five
links — the repository, its issues, the documentation site, and the two
surfaces on this instance that a person rather than a client goes to, `/admin`
and `/portal`.

**IT LISTS NO ENDPOINTS AND MUST NOT START.** `GET /admin/sts-metadata` builds
that list by walking the running Express router, so it cannot go stale by
omission, and this repository's own `tests/vendored/sts_metadata.js` fails on drift in
either direction. A hand-written set of highlights here would be a second,
unchecked copy of it — wrong within a month, on the page most likely to be read
first and least likely to be re-read. `docs/endpoints.md` makes the same
argument for the documentation site. Link to the thing that generates the list.

The same goes for anything else this service already publishes about itself:
`GET /oauth2/rfc9700`, `GET /spiffe`, `GET /admin/ldap/service`, `GET /tls`. A summary of one
of those on the front page is a summary that will disagree with it.

## The five links

Three are written out as constants rather than derived. `package.json` carries no
`repository` member, and adding one so that this page could compute three URLs
from it would make a reader open two files to answer *where does this link go*.
The documentation URL is GitHub Pages' arrangement of the same repository —
`.github/workflows/pages.yml` builds `docs/` and `docs/_config.yml` sets
`baseurl: /iya-sts` — so **changing the repository changes all three and that
baseurl together**.

The fourth and fifth, `/admin` and `/portal`, are **relative on purpose**. This
service is reached as localhost, as `sts` on a compose network and through a
published port; `baseUrlOf()` exists because documents carrying absolute URLs
have to follow the request, and a same-origin link does not have to know any of
that. **The one exception is #472's**: where the console or the portal is on a
listener this request did not arrive on, the view carries that listener's
advertised base instead (`Home.linkTo()`), since a relative link would land on
a listener that answers it with a 404.

**`/portal` arrived 2026-09-10 and closed a door that had never been opened.**
The user portal has existed since 2026-09-06, and the only ways to reach it
were to know the path already or to be handed an activation link — so the one
surface in this service built for a PERSON rather than for an operator or a
client was the one surface with nothing on the front door pointing at it. Its
row lists none of the portal's pages, for the endpoint rule one section up:
`portal/portal.ts`'s `NAV` is the page list and `sts_metadata.ts` reports it,
so a set of highlights here would be a second copy that goes stale the first
time a page is added there.

**What a sign-in here MEANS is one sentence shared by both rows**, chosen once
by `web_home_front.ts`'s `signInMeans()` from the view's
`mode.verifiesCredentials`, which the server reads per request. What a sign-in
screen actually CHECKS is a property of `global.mode` —
`mode.verifiesCredentials()` — rather than of either surface, so a copy on
each row would disagree the first time somebody corrected one of them.

**It replaced a clause that was wrong in two ways at once**, and adding the
portal link is what put the first of them in front of a reader. The console's
row read *"it asks you to sign in, and nothing else here does"* — true when it
was written and false from the day the portal arrived, now stated on the same
page as a link to the portal — and *"no password checked"*, which is a
DEVELOPMENT-mode fact that was stated unconditionally.

**Neither row offers an off switch, because there is no longer one to offer.**
`admin.authRequired` was removed on 2026-09-06 when `common/mode.js` took over
the four gates that were already on: `mode.gatesConsole()` returns `true` in
both modes, so the console row's `else` arm is unreachable and its old text —
*"It is open: admin.authRequired is off on this instance"* — named a setting
that does not exist.

**FINDING THAT IS WHAT TURNED A LINK INTO A SWEEP, AND THE SWEEP IS THE MORE
USEFUL HALF.** That name survived in prose across thirty-nine files, along with
`scim.authRequired`, `spiffe.authRequired` and `ssf.authRequired`, which went
the same day — including as THREE ROWS IN README's settings table, with
defaults and environment variables, four days after the settings stopped
existing. `tests/readme_settings.js` is the check that would have caught it and
now does; `tests/CLAUDE.md` carries the argument.

**What the two rows are told apart by is the ROLE, and that is a real
difference rather than a missing setting.** The console asks for one of two;
the portal asks for none, because every page of it is about the person looking
at it, so saying who you are is the entire question.

## The image

`GET /logo.png` serves the file from disk. Four things about it:

* **It is a route, not `express.static()`.** One file does not need a static
  middleware, and a middleware mounted at the root would sit in front of every
  route registered after this module's for the rest of the process's life — rule
  1 in the root `CLAUDE.md`. (This module's routes are registered first among
  the route modules, by `common/protocol_stack.ts`, since #50's R1.)
* **It is read once, at require time**, and a failure to read it is RECORDED
  rather than thrown, for the reason the socket-owning modules start their
  listeners from `listen()`: a `require` that throws takes the whole service
  down, and a missing decoration is the least important thing that could go
  wrong here. With no image the page is drawn without one and the route answers
  **404 in its own words**. That last part is load-bearing for the link check in
  `tests/vendored/sts_metadata.js`, which fails on Express's `Cannot GET` and passes on an
  endpoint answering for itself.
* **It is this project's own logo (2026-10-01, rcbj)**: `docs/logo.png`, the
  one README.md shows, copied byte for byte (906 × 269, opaque, 22 kB, drawn
  at half that width so it stays sharp on a 2× display). It replaced a
  derivative of the parent project's debugger artwork, which was white
  lettering drawn for a black band. This one is dark lettering on an off-white
  ground, so the band behind it is the image's own colour (`#fbfaf8`). Copy
  `docs/logo.png` over it again if the README's logo changes.

## A static surface since #579

Until #579 `homePage()` drew the card on the server with no script at all.
#569 converts every human-facing page into a static application, and the front
door went first, being the smallest, to prove #570's foundation. What it is
now, by the recipe:

* **`GET /` answers the shell** (`ShellDocument.document()` and `serve()`):
  `/web/card.css` and `/home.css`, the deferred `/home.js`, the language
  attributes (`PageLocale.shellAttributes()`), `data-sts-prefix` in a realm,
  and `data-sts-authn` where the sign-in service — the chooser posts to
  `/authn/language` — is on another listener. **Script is required** (rcbj on
  #569): the `<noscript>` notice says so and links the documentation, the one
  link that works with nothing drawn.
* **The policy is the shell's**: `script-src 'self'`, `style-src 'self'` — the
  page's old inline `<style>` is `/home.css` now, over the sign-in card's
  stylesheet, whose centring and width it overrides — `connect-src 'self'`
  plus the sign-in service's origin where it is elsewhere, `img-src 'self'`
  for the logo, and `frame-ancestors` re-added by
  `app.contentSecurityPolicy()` whatever is asked.
* **`GET /home-api/front` is the page's view, and it has no words**: the
  name, the version and its build (the tooltip), the mode's two facts, the
  logo (or `null`, see *The image*), and the five links as `{ id, href,
  external }`. `GET /home-api` is the index, `/account-api`'s convention: the
  view's operation `mirrors` `GET /`, and nothing posts. Both `no-store`,
  because the mode and the listeners can change while the process runs.
* **The browser draws it in its language** from the `home` catalog namespace,
  the same messages the server-drawn page used (translated for #539), and the
  chooser is the surface runtime's. The band with the logo is drawn by the
  surface's `frame`, above the chooser as before — which is why #579 gave
  `WebSurface`'s frame the page's `view` in its context.
* **Held by** `tests/web_surfaces.js` (the round trip, from the row in
  `tests/tools/web_surfaces.js`: both modes, with and without the image, a
  console elsewhere, English and French) and `tests/home_static_surface.js`
  (the shell, its policy and attributes in and out of a realm, the bundle,
  the API, and the bundle drawing the live view).
