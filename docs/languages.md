---
title: Languages and regions
---

# Languages and regions

The pages people read can be drawn in any language, for any region, that has a
catalog. That covers the sign-in screens, consent, sign-out, the user portal
and the admin console. English is the source language. These are shipped:

| Language | Locales the chooser offers | Catalogs |
|---|---|---|
| English | `en` | `en` |
| French | `fr-FR`, `fr-CA` | `fr`, and `fr-CA` for Canadian wording |
| Spanish | `es-MX`, `es-PA`, `es-ES` | `es` (Latin American), and `es-ES` for Spain |
| Chinese (Simplified) | `zh-CN` | `zh-Hans` |
| Chinese (Traditional) | `zh-HK`, `zh-TW` | `zh-Hant`, and `zh-Hant-HK` for Hong Kong wording |
| Filipino (Tagalog) | `fil-PH` | `fil` |
| Swedish | `sv-SE` | `sv` |

[User-facing pages](user-facing-pages.md) lists every page a person sees, and
whether each is translated yet.

> **What is translated so far (#539, in phases).** The sign-in screens and
> every second-factor step, the emailed and wallet sign-ins, consent, the
> hand-off pages, sign-out, the front door, the realm chooser and the GNAP
> pages, the user portal (with a language field on the person's own
> account), the built-in mail and the admin console — including the text the
> server writes into a console page's data (#543): setting descriptions,
> policy rules, each page's notes and the protocol metadata. See [Text the
> server writes](#text-the-server-writes).

> **Every catalog except English was machine-written and has not been
> reviewed by a native speaker.** Each catalog's status is in
> `common/locales/catalogs.json` (`machine-unreviewed`). Have the text reviewed
> before you rely on it, and mark a catalog `reviewed` once it has been.

**Errors are always in English.** Refusals, validation messages, error pages,
protocol error descriptions and log lines are never translated. A page in
Swedish shows a refused password in English.

## Which language a page is drawn in

The first of these that a catalog answers wins:

1. **`ui_locales`** on the OpenID Connect authorization request in progress
   (Core 1.0, section 3.1.2.1). It is honoured on the sign-in screens. The
   discovery document's `ui_locales_supported` lists the offered locales.
2. **The person's own `preferredLanguage`** (RFC 2798), once the page knows
   who they are. A value the [locale policy](#the-locale-policy) filled in
   when the account was created is treated as the policy's, not the
   person's, and ranks after the browser (4). Once the person or an
   administrator sets a language, it is theirs and ranks here.
3. **The language chooser** on the page, which is remembered in a cookie.
4. **The browser's `Accept-Language`**.
5. **The realm's [locale policy](#the-locale-policy)**: the default for the
   application the page is drawn for.

A language with no catalog is skipped in favour of the next one. A reader whose
browser asks for German, then French, reads French.

Dates and numbers are formatted for the locale that won, even where the words
come from a broader catalog. `es-PA` reads the Spanish catalog and gets
Panamanian date formats. Times are given in UTC and say so.

Matching follows BCP 47 lookup, with the script worked out from the region.
`zh-HK` and `zh-TW` read Traditional Chinese and never Simplified. `zh` and
`zh-CN` read Simplified. `tl` is read as Filipino.

## What a region changes

A locale has a language and, often, a region: `fr-CA` is French as used in
Canada. The region decides three things:

- **Wording.** Where a region says something differently, its overlay catalog
  says it that way, and only there. Some examples:
  - `fr-CA` says *courriel* and *témoin* where France says *e-mail* and
    *cookie*.
  - `es-ES` says *ordenador* and *cartera* where Latin America says
    *computadora* and *billetera*.
  - `zh-HK` says 電郵 where Taiwan says 電子郵件.

  A region with no overlay reads its language's base catalog. `es-MX`,
  `es-PA` and `fr-BE` all do.
- **Dates, times and numbers.** These are always formatted for the exact
  locale chosen, even with no overlay: `es-PA` and `es-ES` write the same
  date differently. Times are given in UTC and name the zone, so nobody has to
  guess which zone a page means.
- **Plurals.** Plural forms follow the language's own rules (Unicode CLDR).
  Chinese has one form, French counts 0 and 1 as singular, and English does
  not.

A locale with no catalog at all, `de-CH` for instance, is passed over in
favour of the reader's next preference. If nothing answers, the realm's
default is used. The realm's default can itself be a locale with no catalog,
such as `de-CH`. Pages are then English but format dates and numbers for that
locale.

## Right-to-left languages

The page's direction is set from the locale (`dir="rtl"` for Arabic, Hebrew,
Persian, Urdu and the other right-to-left scripts). No code changes when a
right-to-left catalog is added. None is shipped yet.

## The language chooser

Every user-facing page carries a small **Language** form. It works without
JavaScript. Choosing a language:

- remembers it in the `sts_lang` cookie, which lasts a year, is `HttpOnly` and
  is `SameSite=Lax`;
- if you are signed in, also sets your own `preferredLanguage`, because your
  entry outranks the cookie;
- returns you to the page you were on. The return address is always a path on
  this service. Anything else returns you to `/`.

A language no catalog answers is refused (`STS-I18N-0008`).

## The locale policy

The locale policy is the fifth kind of policy on **Directory → Policies**,
with a tab of its own. Set it there, or with
`POST /admin-api/policies/save-locale-policy`.

| Field | Default | What it does |
|---|---|---|
| `defaultLocale` | `en` | Any BCP 47 tag. Pages fall back to it. Mail to a person whose entry names no language is written in it. A tag no catalog answers is kept: dates and numbers are formatted for it, and the words are English. |
| `populatePreferredLanguage` | on | A person **created** without a `preferredLanguage` is given `defaultLocale` as one, so mail, the `locale` claim and SCIM have a value. Existing entries are never rewritten. A page ranks a filled-in value after the browser's language, until somebody changes it (`stsPreferredLanguagePopulated` records what was written). |

The `default` profile applies everywhere in the realm. A realm with no
`default` of its own follows the default realm's.

### Named profiles, for applications and groups

A realm may keep **named profiles**. Each has the two fields above and a
**precedence**, a whole number from 1 to 1000 (100 if you leave it out). A
named profile lists nothing. Whatever it covers names it instead:

- **an application**, in its `appLocalePolicy` field (the application's
  page, or `POST /admin-api/applications/set`);
- **a group**, in its `stsLocalePolicy` (the group's page, or
  `POST /admin-api/groups/set-policy`).

Each reference is `default` or the name of a named profile of the realm.
Anything else is refused when it is written. The page draws the three
sub-tabs every ranked policy has: **Default**, **Named policies** (each
profile with the applications and groups naming it) and **New policy**.

When a page or a mail needs the fallback language, the candidates are the
profile the application names and the profile each of the person's groups
names. **The lowest precedence wins**, ties go by name, and `default` applies
when nothing names a profile. The person counts wherever the page knows who
it is drawn for: a sign-in step after the first factor, consent, sign-out, the
portal and the console, and mail to a person. A page drawn before anybody is
known, such as the first sign-in screen, is chosen by its application alone.

For example, name `support-fr` (precedence 10, `fr-CA`) on the group
`support`, and `mobile` (precedence 50, `sv`) on the application
`mobile-app`. A member of `support` signing in to `mobile-app` falls back to
`fr-CA` once known; anybody else falls back to `sv`.

The same choice decides the language a **new person** is given: the profile
the application that caused the creation names (a person provisioned by its
SCIM client, or created by signing in to it), or one a group that already
lists the new entry names. A person created from the console or `/admin-api`
names no application.

A reference to a profile the realm does not hold, written past the console,
selects nothing and is logged (`STS-I18N-0013`). The policy only chooses a
fallback language, so it does not refuse anything over this: `default`
applies wherever nothing else names a profile. A named profile that an
application or a group still names cannot be deleted (`STS-I18N-0014`).
Named profiles belong to their realm and are not inherited.

Before #1238 a named profile listed its applications (`selectApplications`)
and an application could be on one at most (`STS-I18N-0007`, now retired).
Those lists are not read any more and are not migrated: name each profile
from its applications again.

### Replaces `mail.defaultLanguage`

`mail.defaultLanguage` (`STS_MAIL_DEFAULT_LANGUAGE`) was removed. Pages and
mail now share one default, the locale policy's. A service started with the
old setting still named refuses to start and says what replaced it.

## Adding a language

A catalog is data:

1. Add a row to `common/locales/catalogs.json`, with its tag, its name in its
   own language and its status. If the chooser should offer it, add it to
   `offered` as well.
2. Add `common/locales/<namespace>/<tag>.json` for each namespace. A
   **regional** catalog (`fr-CA`) holds only the messages whose wording
   differs from its base (`fr`).

`tests/i18n_catalogs.js` checks every catalog against the English one: the
same keys, the same `{placeholders}` and the same inline markup. A
right-to-left language is drawn with `dir="rtl"` without further change.

## Text the server writes

Some of what a console page shows is written by the server into the page's
data rather than by the console. Examples are setting labels and
descriptions, policy rules, the notes on the Mode, Encryption, PKI, SCIM and
LDAP pages, scheduler jobs, caches and the protocol metadata. The management API translates that text, but
only when the request names a language in `Accept-Language`:

- **The console** always sends the language it chose for you, so its pages
  are drawn in that language.
- **A script or integration** that sends no `Accept-Language` gets English,
  whatever the realm's locale policy defaults to. Its answers are the same as
  before this was added. Send the header to get translated text, for example
  `Accept-Language: fr`.
- **The OpenAPI documents** (`/admin-api/openapi.json` and the console's own)
  are always English.

Values are never translated, only the server's own sentences. Error messages
stay English. A coverage note keeps its first word (`full`, `partial` or
`minimal`) in English, because software reads it. A few sentences remain
English: scheduler jobs a node registers only after it starts, a cache whose
lifetime text is computed in a module that has no template for it, and
text written by another node running an older build.

A sentence that has changed since it was translated is shown in English until
its translation is updated. An out-of-date translation is never shown. These
translations are machine-written and unreviewed, like the catalogs above.
Regional overlays (`fr-CA`, `es-ES`, `zh-Hant-HK`) use their base language's
text for now.
