# home/

The front door. One module, two routes, one image:

| File | What it is |
|---|---|
| `home.js` | `GET /` — the page — and `GET /logo.png`, the only image this service serves. |
| `assets/debugger-logo.png` | That image. A DERIVATIVE of the parent project's artwork, not a copy of it — see below. |

It is a directory of its own rather than a route in `common/`, and the entry
test that file states is the reason: *a file lands there because more than one
family needs it*. Nothing needs this one. It is also not a candidate for the
package root, where there are exactly two modules and both earn it.

## Its place in the require order (6a)

No constraint. Two EXACT paths (`/` and `/logo.png`) and nothing but the app
behind them; first among the route modules so that the page a person meets
first heads the list on `/admin/sts-metadata`.

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
`baseurl: /mock-sts` — so **changing the repository changes all three and that
baseurl together**.

The fourth and fifth, `/admin` and `/portal`, are **relative on purpose**. This
service is reached as localhost, as `sts` on a compose network and through a
published port; `baseUrlOf()` exists because documents carrying absolute URLs
have to follow the request, and a same-origin link does not have to know any of
that.

**`/portal` arrived 2026-09-10 and closed a door that had never been opened.**
The user portal has existed since 2026-09-06, and the only ways to reach it
were to know the path already or to be handed an activation link — so the one
surface in this service built for a PERSON rather than for an operator or a
client was the one surface with nothing on the front door pointing at it. Its
row lists none of the portal's pages, for the endpoint rule one section up:
`portal/portal.js`'s `NAV` is the page list and `sts_metadata.js` reports it,
so a set of highlights here would be a second copy that goes stale the first
time a page is added there.

**What a sign-in here MEANS is one sentence shared by both rows**, read per
request, in `signInMeans()`. What a sign-in screen actually CHECKS is a
property of `global.mode` — `mode.verifiesCredentials()` — rather than of
either surface, so a copy on each row would disagree the first time somebody
corrected one of them.

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
  route registered after this module for the rest of the process's life — rule 1
  in the root `CLAUDE.md`.
* **It is read once, at require time**, and a failure to read it is RECORDED
  rather than thrown, for the reason the four socket-owning modules start their
  listeners from `listen()`: a `require` that throws takes the whole service
  down, and a missing decoration is the least important thing that could go
  wrong here. With no image the page is drawn without one and the route answers
  **404 in its own words**. That last part is load-bearing for the link check in
  `tests/vendored/sts_metadata.js`, which fails on Express's `Cannot GET` and passes on an
  endpoint answering for itself.
* **It sits on a BLACK band, and that is not a style choice.** The artwork is
  white lettering with a dark outline, a green wordmark and a pale-blue mark,
  drawn for a dark ground; on the card's own background the "IYA CYBER SECURITY"
  half all but disappears. The parent project ships a black-backed copy of the
  same artwork on its error pages for the same reason.
* **It is a derivative and therefore NOT in `common/vendored/`.** That
  directory's rule is that its files are byte-identical to the parent's, and two
  of the parent's tests hold them to it. This one was produced from
  `client/public/images/oauth2oidcdebugger+iyasec-logo-transparent.png` (2172 ×
  724, 745 kB) with:

  ```bash
  convert <source> -resize 720x -strip PNG32:debugger-logo.png
  convert debugger-logo.png -colors 256 PNG8:debugger-logo.png
  optipng -o5 debugger-logo.png
  ```

  720px is twice the width it is drawn at, so it stays sharp on a 2× display,
  and 256 colours takes it to 31 kB. Re-run those three lines if the parent's
  artwork changes.

## No script and no external resource

`app.js` sets `script-src 'none'` service-wide and this page needs no exception:
it has no behaviour. Its one `<style>` block is covered by the
`style-src 'unsafe-inline'` several pages here already rely on, and the image is
same-origin, which `img-src 'self' data:` already allows. A page that fetched a
font from a CDN would need the policy widened for a decoration — so it does not.
Four pages here have a script on them and each had to argue for it separately;
this is not a fifth.
