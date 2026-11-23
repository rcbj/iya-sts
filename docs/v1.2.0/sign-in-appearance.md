---
title: Sign-in appearance
nav_order: 10
---

# Sign-in appearance: a realm's colours, layout and logo

Each [trust realm](trust-realms.md) can give the pages a person sees its own
look: four colours, one of three layouts, a display name and an uploaded
logo. A realm that sets none of it looks exactly as the service always has.

What it changes is how the pages LOOK. The form on the sign-in screen, its
fields, their order and their ids are the same in every layout, so a test or
a password manager that fills them keeps working. The words stay in the
reader's language ([Languages and regions](languages.md)); the display name
is the one exception, an operator's brand, shown as typed.

## Which pages take it

- **The sign-in screen** and every step after it: the second factors, the
  emailed codes and links, the wallet sign-in, the identity-provider chooser,
  the password change and the SPNEGO pages.
- **The consent screen** at `/oauth2/consent`.
- **GNAP's interaction pages**, **the federation pages** and the protocol
  families' **description pages** (`/saml2`, `/saml11`, `/xacml`, `/ssf`,
  `/scim`, `/spiffe`).
- **The sign-out page** at `/logout`. The page drawn after a sign-out that
  still had something for the browser to do (front-channel logout frames,
  SAML LogoutRequests) is the protocols' own and keeps the service's look.
- **The front door** at `/`. When the realm has a logo, it takes the place
  of the service's own image; with none, the front door is unchanged.
- **The user portal** at `/portal`: its colours, and the logo and name in
  its header.

**The admin console does not change.** It is the service's own tool rather
than the realm's face to the people who sign in.

## The settings

Every setting is per realm and takes effect at the next page load. The
[Every setting](configuration.md#sign-in-appearance) table lists them with
their environment variables.

| Setting | Default | What it does |
|---|---|---|
| `branding.layout` | `centered` | One of the three layouts below. |
| `branding.accentColor` | `#12107c` | Buttons, links, focus rings, the split panel and the banner. |
| `branding.pageColor` | `#f4f4f7` | The background behind the card. |
| `branding.cardColor` | `#ffffff` | The card the form is drawn on. |
| `branding.textColor` | `#222222` | The text on the card. |
| `branding.displayName` | *(empty)* | A name beside the logo and at the end of the browser tab's title (`Sign in — Acme`). Plain text, at most 80 characters. |
| `branding.logoAlt` | *(empty)* | The logo's alternative text. Required while there is a logo. At most 160 characters. |
| `branding.logoLinkUrl` | *(empty)* | Where the logo leads when followed: an absolute `https` URL, or empty for a logo that is not a link. |
| `branding.logoMaxBytes` | `262144` | The largest logo an upload may carry, for every realm (1 KiB to 2 MiB). |

Colours are written `#rgb` or `#rrggbb` and kept as lower-case `#rrggbb`.
Anything else, a colour name included, is refused (`STS-CORE-0006`).

**The quieter tones are derived, not set.** The text on a button is black or
white, whichever reads better on the accent. The muted text of notes and
hints, the borders and the rules are mixed from the text colour and the card
colour, and the muted text never falls below the contrast rule. A realm that
keeps the default text and card colours keeps the default tones exactly.

### The contrast rule

A change that leaves the **text** or the **accent** (the links) below WCAG
2.2 AA contrast, **4.5:1, against the card** is refused with
`STS-AUTHN-0544`, and nothing is written. The rule applies at every door:
the console, the management API, `POST /admin-api/config/set` and a restored
configuration.

Colours set together are judged together. A dark card with light text is
two changes that are each illegal alone and legal as a pair, so send them in
one request (the console's page and `POST /admin-api/branding/save` both do).

## The three layouts

- **`centered`** (the default): the card in the middle of the page, with the
  logo and the display name above it.
- **`split`**: a panel in the accent colour beside the card, carrying the
  logo and the name. On a screen narrower than 720 pixels the panel sits
  above the card.
- **`banner`**: a band in the accent colour across the top, carrying the logo
  and the name, with the card below it.

Pages that are not a single card draw the layouts in the way their shape
allows. **The front door, the sign-out page and the user portal draw both
`split` and `banner` as the band across the top**: the front door and the
sign-out page are wide pages rather than a small card, and the portal
already has a navigation column beside its pages. `centered` puts the logo
and name above the page on all three.

## The logo

- **PNG, JPEG or WebP.** The image's own bytes decide the type, whatever the
  upload's `Content-Type` says; anything else is refused (`STS-AUTHN-0545`).
  SVG is not accepted.
- **Each side 16 to 2048 pixels** (`STS-AUTHN-0547`), and **no larger than
  `branding.logoMaxBytes`**, 256 KiB by default (`STS-AUTHN-0546`). It is
  drawn at most 240 pixels wide and 64 high, so a logo around twice that
  size stays sharp on a high-density screen.
- **Alternative text is required.** An upload without it is refused, and
  `branding.logoAlt` cannot be emptied while the realm has a logo
  (`STS-AUTHN-0548`).
- **It is served from this service**, at the realm's `/web/branding/logo`
  (`/realm/acme/web/branding/logo` for the realm `acme`). No other origin is
  added to a sign-in page, so no third party learns who is signing in, and it
  works in a deployment with no outside network. It is served with
  `X-Content-Type-Options: nosniff`, a sandboxing content security policy
  and an `ETag`. A realm with no logo answers 404 there (`STS-AUTHN-0549`).
- **It is kept in the realm**: every node and process serves the same logo,
  and removing the realm removes it. Uploads and removals are audited
  (`branding.logo`), with the image's digest and never its bytes.

An application's own logo, the one its registration names, is a different
thing: it stays inside the card, under the realm's.

## Setting it

### In the console

**Sign-in appearance**, under the server configuration pages of the
realm's own console, edits all of it: the colours with their derived tones
and contrast results, the layout, the display name, the logo with its
alternative text and link, and the upload and removal. Its **Preview** opens
the realm's sign-in screen in a new tab with the values not yet saved, so
they can be seen before they are kept; the preview is never a real sign-in.

### Over the management API

The same acts, with an access token audienced to `/admin-api`
([Management API](management-api.md)), in the realm the path names:

| Request | What it does |
|---|---|
| `GET /admin-api/branding` | Everything the console's page shows: the layout and the layouts there are, the colours, the derived tones, the contrast of the text, links and button text, the display name, the logo's alternative text and link, and the stored logo's type, sides, size and digest (never its bytes). |
| `POST /admin-api/branding/save` | Writes the `branding.*` settings the JSON body names, judged together; nothing is written when any is refused. |
| `POST /admin-api/branding/logo` | The request body is the image. `?alt=` sets the alternative text with it. It replaces the realm's logo. |
| `POST /admin-api/branding/remove-logo` | Removes the logo. The alternative text stays, so the next upload needs none. |

`GET /admin-api/openapi.json` describes each of them. The colour and layout
settings can also be written one at a time with
`POST /admin-api/config/set`, under the same contrast rule.

```bash
# A dark card with light text, as one change in the realm "acme".
curl -X POST https://sts.example.com/realm/acme/admin-api/branding/save \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"branding.cardColor":"#111111","branding.textColor":"#eeeeee",
       "branding.accentColor":"#8ab4f8","branding.layout":"banner",
       "branding.displayName":"Acme"}'

# The logo, with its alternative text.
curl -X POST 'https://sts.example.com/realm/acme/admin-api/branding/logo?alt=Acme' \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: image/png' \
  --data-binary @acme.png
```

## How it reaches a page

A realm whose appearance differs from the default gets a stylesheet of its
own, `/web/theme.css`, linked after the page's stylesheet. It carries only
colour values, each already checked to be six hex digits, so nothing an
administrator types becomes style text. The pages keep their content
security policy (`style-src 'self'`, no inline style). The logo, the
alternative text, the link and the display name travel as attributes of the
page and are drawn as text by the page's script.

A realm that sets nothing gets no extra stylesheet and no extra attribute:
its pages are byte for byte what they were.

## Related

- [Trust realms](trust-realms.md)
- [User-facing pages](user-facing-pages.md)
- [Configuration: Every setting](configuration.md#every-setting)
- [Error codes](error-codes.md)
