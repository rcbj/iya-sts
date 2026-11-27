---
title: Policies
nav_order: 12
---

# Policies

**Directory → Policies** (`/admin/policies`) is where a realm sets the rules
it holds people to: passwords, sign-in, passkeys, language, the attributes a
person must carry, what a service account may do, and what somebody is asked
to do after they sign in. How a policy relates to the person and the
application that name it is the [Directory](directory.md#a-policy) chapter.

Each kind is a directory entry in its own container, with a tab of its own.
`GET /admin-api/policies` answers every kind. The
[OpenAPI document](management-api.md) (`GET /admin-api/openapi.json`) lists
each save. The fields of a kind are on the page linked from the table below;
this page is how a realm chooses which profile applies.

XACML policies are a different store. They live under **Protocols → XACML**,
in `ou=policies`, and a PDP evaluates them. See
[Authorization](authorization.md) and [XACML](xacml.md).

## The seven kinds

The console draws the tabs in this order. **All profiles**, last, lists every
profile of every kind.

| Tab | Id | What `default` governs | Where the fields are |
|---|---|---|---|
| Password policy | `password` | the next password set in this realm | [Passwords](authentication.md#passwords) |
| Authentication policy | `authn` | which ways of signing in are accepted, and when a second factor is required | [The authentication policy](authentication.md#the-authentication-policy) |
| Service-account policy | `serviceAccount` | what a service account may do, and how its password rotates | [Service accounts](service-accounts.md#the-policy) |
| Passkey policy | `passkey` | how passkeys behave at the next sign-in and the next enrolment | [The passkey policy](authentication.md#the-passkey-policy), [Passkeys](passkeys.md) |
| Locale policy | `locale` | the language a page falls back to, and the language a new person is given | [Languages](languages.md#the-locale-policy) |
| Attribute policy | `attributes` | the attributes every person must hold, and the realm's custom attributes | [The attribute policy](#the-attribute-policy) |
| Post-login activity policy | `postLogin` | what a person is asked to do after signing in | [Post-login activities](post-login-activities.md) |

A profile applies to the **next** password, sign-in, page or create. A
password already stored, a session already started and a person already
created keep what they have. The password policy and the attribute policy
are enforced in **product mode** only. The others are asked in both modes.
[What is not checked](what-is-not-checked.md) is the full line between the
modes.

## Named policies

Beside `default`, a realm may keep **named policies** of any kind. A named
policy holds the same fields as `default` and a **precedence**, a whole
number from 1 to 1000. Leave it out and it is 100.

**The policy lists nobody.** What it covers names it, with one single-valued
attribute on the holder. `default` and an empty value both mean "no
preference". A named policy belongs to the realm it was created in and is
never inherited by another realm.

### Who names which kind

| Kind | Application | Group | Person |
|---|---|---|---|
| Password | `appPasswordPolicy` | `stsPasswordPolicy` | |
| Authentication | `appAuthnPolicy` | `stsAuthnPolicy` | |
| Service account | | | `stsServiceAccountPolicy` |
| Passkey | `appPasskeyPolicy` | `stsPasskeyPolicy` | |
| Locale | `appLocalePolicy` | `stsLocalePolicy` | |
| Attribute | | `stsAttributePolicy` | `stsAttributePolicy` |
| Post-login | `appPostLoginPolicy` | `stsPostLoginPolicy` | |

An application's reference is a field of its Configuration tab, *Every
protocol*, or `POST /admin-api/applications/set` with `attribute` and
`value`. A group's is on the group's page under **Policies this group
names**, or `POST /admin-api/groups/set-policy` with `group`, `attribute`
and `policy`. A person's is on the **Policies** sub-tab of **Attributes**
(and on **Users → New user**), or `POST /admin-api/users/set-attribute`.
Only a service account may hold `stsServiceAccountPolicy`.

Each write accepts `default` or the name of a named policy this realm holds.
Anything else is refused. A value written with an LDAP client can still name
a policy the realm does not hold; what that does is
[below](#a-name-the-realm-does-not-hold).

### How one is chosen

When a decision needs a profile, the candidates are:

* the policy the **application** names, when this kind has an application
  attribute and an application is in hand;
* the policy the **person** names, when this kind has a person attribute;
* the policy **each of the person's groups** names.

An empty reference and `default` are not candidates. Of the policies that
are, the **lowest precedence number** applies. A precedence of 10 beats 50.
A tie goes to the name that sorts first. Where nothing names a policy,
`default` applies.

Two moments have fewer candidates, because less is known:

* **Before the person is known** — the first draw of a sign-in screen — only
  the application's policy can apply. Once the person is known, the choice
  is made again.
* **With no application** — the portal, a reset link, activation, the
  console, `/admin-api`, an LDAP write, a reminder mail — the person's
  reference and their groups' references are the candidates. Registration
  of a passkey on `/portal/keys` is one of these.

A group that should be held to a stricter profile names that profile and
gives it the lower number. A group or an application that should be left
out names a profile that switches the behaviour off, again at a lower number
than the profile that would otherwise reach them. The post-login page walks
through that for one kind; the ranking is the same for every kind.

### A name the realm does not hold

A reference to a name this realm has no policy of is not a candidate. The
console and the API refuse to write one. An `ldapmodify`, or a policy
deleted by hand, can leave one behind. What it means depends on the kind,
because some kinds can fall through to `default` and one cannot:

| Kind | What a dangling name does | Logged as |
|---|---|---|
| Authentication | That sign-in allows **no** mechanism, until the policy exists or the reference changes. The authentication policy fails closed: a missing name must not widen what a sign-in allows. | `STS-AUTHN-0536` |
| Password | That reference is dropped. The references that remain still rank. `default` applies only when none remain. | `STS-AUTHN-0539` |
| Passkey | That reference is dropped. `default` applies when nothing else names a profile. | `STS-AUTHN-0537` |
| Locale | That reference is dropped. `default` applies when nothing else names a profile. The policy only chooses a fallback language. | `STS-I18N-0013` |
| Attribute | That reference is dropped. The references that remain decide, and `default` when none remain. | `STS-LDAP-0196` |
| Post-login | That reference is dropped. The references that remain decide. | `STS-AUTHN-0542` |
| Service account | The account follows `default`. | `STS-SVCACCT-0047` |

Each of those is logged, and none of them is sent to a client.
[Error codes](error-codes.md) has the record.

### Writing and deleting

A name is lower-case letters, digits and hyphens, starting with a letter or
a digit. It is at most 64 characters. A **named authentication policy** is
at most 63 (`STS-AUTHN-0532`). The name `default` is the realm's own profile
and is refused as a named policy.

Save a named profile with `POST /admin-api/policies/save-<id>-policy` and a
`profile` other than `default`, and remove it with `reset-<id>-policy` and
the same `profile`. The authentication policy is the exception: its named
policies use `save-named-authn-policy` and `delete-named-authn-policy`,
because a named authentication policy stores two lists (`mechanisms` and
`secondFactors`) beside the realm's own profile.

**A named policy that any holder still names is not deleted.** Point each
holder at `default` or at another policy first. The **Named policies**
sub-tab lists who names it (`namedBy`: applications, groups and people).

| Kind | Refused while a holder names it |
|---|---|
| Password | `STS-AUTHN-0540` |
| Authentication | `STS-AUTHN-0534` |
| Service account | `STS-SVCACCT-0049` |
| Passkey | `STS-AUTHN-0538` |
| Locale | `STS-I18N-0014` |
| Attribute | `STS-LDAP-0197` |
| Post-login | `STS-AUTHN-0543` |

On the console each tab has three sub-tabs: **Default**, **Named policies**
and **New policy**. The attribute policy adds **Custom attributes**. The
passkey policy adds **Learned clients**.

### The `default` profile, and what is inherited

`default` is `cn=default` in the kind's container. For every kind except the
password policy, a realm with no `default` of its own follows the **default
realm's** profile, and the built-in defaults where that realm has none
either. Saving the form writes this realm's own profile, which then applies
here only. Removing it puts the realm back to following.

The **password policy does not follow another realm.** Until this realm
saves one, the built-in defaults are in force (minimum length 12, one
symbol, an uppercase letter, a digit, and none of the last five).

Named policies are never part of that fallback. A realm that has not created
`admins` does not see another realm's `admins`.

## Password policy

`ou=passwordPolicies`. A group names one in `stsPasswordPolicy`; an
application names one in `appPasswordPolicy`. The application's policy
applies to a password chosen **while signing in to that application** (the
forced change after a reset). A password set on the portal, through a reset
or activation link, on the console, through `/admin-api` or by an LDAP write
of `userPassword` has no application, so the person's groups decide, and
`default` where they name none.

The same profile decides the length of a password the service generates and
how the password is hashed. Product mode enforces it at every door that sets
a password. Development mode records the history and enforces nothing.

The rules, the generator and the API body are under
[Different password rules](authentication.md#different-password-rules-for-different-applications-or-groups).
The directory entry is under
[LDAP](ldap.md#the-password-policy-is-a-directory-entry).

## Authentication policy

`ou=authnPolicies`. A named policy narrows the realm's: it lists the
first-factor mechanisms and the second factors a sign-in may use. Nothing
ticked in a list allows every mechanism the realm allows. A mechanism the
realm has switched off stays off.

An application names one in `appAuthnPolicy`. A group names one in
`stsAuthnPolicy`. For a sign-in to an application, the two compete by
precedence. An application naming a policy this realm does not hold allows
no mechanism, and so does a group naming one, for every member
(`STS-AUTHN-0536`).

[Named authentication policies](authentication.md#named-authentication-policies)
has the lists, the re-prompt and the API. An application's page is
[Sign-in mechanisms](applications.md#sign-in-mechanisms-how-its-people-may-sign-in).

## Service-account policy

`ou=serviceAccountPolicies`. Only a **service account** names one, in
`stsServiceAccountPolicy` on its own entry. A group has no attribute for
this kind, and neither does an application. An account that names nothing
follows `default`. Writing the attribute on anybody else is refused
(`STS-SVCACCT-0048`).

[Named policies](service-accounts.md#named-policies) has the fields and the
rotation.

## Passkey policy

`ou=passkeyPolicies`. An application names one in `appPasskeyPolicy`; a
group names one in `stsPasskeyPolicy`. At a sign-in the two compete. A
registration on `/portal/keys` has no application, so the groups decide.

[Different rules for different applications or
groups](passkeys.md#different-rules-for-different-applications-or-groups)
has the save body. An application's own page shows which profile a sign-in
gets before the person is known:
[The passkey policy that applies to it](applications.md#the-passkey-policy-that-applies-to-it).

## Locale policy

`ou=localePolicies`. An application names one in `appLocalePolicy`; a group
names one in `stsLocalePolicy`. The lowest precedence chooses the fallback
language, and the language a new person is given when the application caused
the create. A page drawn before anybody is known follows the application
alone.

[Named profiles](languages.md#named-profiles-for-applications-and-groups)
has the two fields and an example. A named profile used to list its
applications itself. Those lists are not read any more: name the profile
from the application and the group.

## The attribute policy

`ou=attributePolicies`. `uid`, `cn` and `sn` are always required. By default
`givenName` and `mail` are too. The **Default** sub-tab lists every
attribute a person may be given, with a **Required** box.

A **named** attribute policy is a required list and a precedence. A person
names one in `stsAttributePolicy` on their own entry. A group names one with
the same attribute on the group. There is no application attribute for this
kind. Of the person's reference and their groups' references, the lowest
precedence applies, and `default` when they name none.

**At a create** the policy is the reference the create writes, together with
any group that already lists the new DN. **At an edit** it is the reference
the entry will hold after the edit, together with the groups the person is
in. SCIM maps no attribute to `stsAttributePolicy`, so a SCIM create is held
to a group that already lists the person. A replace or a PATCH is held to
the policy the person's own reference and their groups then select. See
[Configuring SCIM](configure-scim.md#the-attribute-policy-in-product-mode).

Product mode refuses a create that lacks a required attribute, at every
door, and refuses an edit that would take one away. Development mode stores
the policy and does not enforce it. A person created before an attribute
became required is not refused for lacking it.
`GET /admin-api/policies?missing=count` counts those people, each against
their own policy. A service account and the bootstrap administrator are
exempt.

**Custom attributes** are defined on the same tab: a name, a label, a syntax
and whether the attribute holds one value or several. They belong to the
realm (`ou=attributeDefinitions`) and are not inherited. A custom attribute
cannot be removed while anybody holds a value of it, or while any profile of
this realm requires it. `POST /admin-api/policies/define-person-attribute`
and `remove-person-attribute` are the same acts.

Each custom attribute has two user portal settings, both off by default:
**Show it to the person on the portal** and **Let the person change it on
the portal**. The person then sees, or edits, their own values on the
portal's Overview ([User-facing pages](user-facing-pages.md#the-user-portal);
`POST /account-api/attributes`). Letting the person change an attribute also
shows it, and hiding it also stops the editing. **Change** on the attribute's
row edits its label, description and the two settings, as does
`POST /admin-api/policies/update-person-attribute`. The syntax and whether it
holds several values cannot be changed (STS-LDAP-0208).

The directory shape is under
[LDAP schema](ldap-schema.md#attribute-policies-and-custom-attributes-ouattributepolicies-ouattributedefinitions).

## Post-login activity policy

`ou=postLoginPolicies`. A group names one in `stsPostLoginPolicy`; an
application names one in `appPostLoginPolicy`. At a sign-in the two compete.
A reminder mail and the progress report have no application, so they follow
the person's groups.

A named profile with the activity switched off, given a lower precedence
than the profile that would otherwise apply, keeps those people out. One a
group names keeps them out of the mails as well. One an application names
keeps them out of a sign-in to that application only.

[Which profile applies](post-login-activities.md#which-profile-applies-groups-and-applications-name-it)
has the fields and a worked example.

## All profiles

The last tab lists every profile of every kind: the kind, the name, where it
is stored, and how many problems the profile has. A row that is stored shows
its DN. A `default` this realm has not saved shows either that it is
inherited from the default realm, with that realm's DN, or that nothing is
stored and the built-in defaults are in force. The list is paged.
`GET /admin-api/policies` is the same list.

## Export and import

The **Export and import** tab moves a realm's policies as one signed JSON
document: to another realm of this service, to another installation, or back
into the same realm as a restore.

**What an export holds.** Every kind on this page, and of each only what the
realm *stores*: its own `default` profile and its named policies. A profile
the realm inherits from the default realm, or the built-in defaults, is not
the realm's and is left out. Each profile is carried as the body its kind's
Save takes, so an import goes through the same checks a Save from this page
does.

**How it is signed.** The document is a JWS in the flattened JSON
serialization (RFC 7515 section 7.2.2): three members, `protected`, `payload`
and `signature`. Any JOSE library can verify it. Every export is signed with
a fresh key that this realm's **Policy Export Signing CA** certifies. That
Issuing CA is a use case of its own on [the PKI page](pki.md). The protected
header carries `typ` `policy-export+json` and the whole chain in `x5c`: the
signing certificate, the Policy Export Signing CA, the realm's Intermediate
and the service Root. The service keeps no copy of the private key.
`pki.policyExportAlgorithm` chooses the algorithm: RS256 by default (the
algorithm of the realm's own JOSE signing key), or PS256, ES256, ES384,
ES512, EdDSA, ML-DSA-44, ML-DSA-65 or ML-DSA-87.

**What an import trusts.** **Check the signer** verifies the signature with
the key in `x5c` and holds the chain to full PKI validation, whatever the
mode: validity, key usage, the path and revocation of every certificate. This
is the `policy-signer` row of [paranoid PKI mode](pki-use-cases.md), on by
default, and while it is on the checks run in development mode too. Then:

| The signer | What happens |
|---|---|
| this realm's own Policy Export Signing CA, under this service's Root | trusted; **Import it** writes the document |
| another realm whose chain this realm's signer truststore holds for policy imports | trusted the same way |
| any other realm, of this service or another | the page shows the chain and asks whether to trust it |

**The question.** **Yes: trust this chain and import** adds the chain's three
certificate authorities to this realm's signer truststore, for policy imports
and no other use, and imports the document. The next export from that realm
is trusted without asking. The answer names the Issuing CA it was shown. Every
realm of one service shares the Root, so trusting the Root alone would trust
every realm's exports. The yes is therefore pinned to that one Issuing CA,
and another realm of the same service is still asked about. To withdraw the
trust, remove those entries on PKI → Trust.

**What is written.** Each profile goes through its kind's own Save. A profile
of the same name is replaced, and a profile the document does not carry is
left alone. A profile its kind refuses is named with the reason, and the
others are still written.

### One policy, or a few

A policy is named by its **kind** and its **name**: `password` and `default`,
`passkey` and a named policy, `authn` and one of the named authentication
policies. The same pair names it on this page and to each kind's Save.

**Exporting a selection.** Each policy this realm stores has an **Export**
button on the **All profiles** tab, and each named authentication policy has
one beside its Delete. It downloads a signed document that holds that one
policy. On the **Export and import** tab, tick the policies to carry and press
**Export this realm's policies**. With none ticked, the export carries every
policy, as before. A selection is the same document with fewer profiles in
it, signed the same way, so any importer reads it. Its payload says which
policies it was asked to hold, in `selection`. Only what the realm stores can
be selected, so a profile it inherits cannot. A name the realm does not store
is refused with `STS-ADMIN-0937`, and nothing is exported.

**Importing a selection.** **Check the signer** lists every policy in the
document, each ticked, with **replaces an existing policy** beside a name this
realm already stores. Untick the ones to leave out, then import. With none
ticked, the whole document is imported. The trust question is asked about the
document's signer before anything is written, whatever is ticked. A selected
name the document does not carry is refused with `STS-ADMIN-0938` before the
question, and nothing is trusted or written.

Through the API: `POST /admin-api/policies/transfer/export`, `inspect` and
`import`. Another realm's import answers 400 with `needsTrust` until it is
posted again with `trustSigner: true` and `issuerFingerprint`, the Issuing
CA's SHA-256 fingerprint from the inspection. Export and import each take an
optional `policies`, a list of `{ "kind": …, "name": … }`; left out, they act
on everything. The inspection's `profiles` lists what the document carries,
each with `replaces`. `GET /admin-api/policies/transfer` lists what this realm
can export in `policies`. Export, the yes and the import each write an audit
row: `admin.policies.export`, `admin.policies.trust-signer` and
`admin.policies.import`. A selection's export and import rows record the
policies it named.

**What this realm signs with, and whom it trusts.** The tab, and
`GET /admin-api/policies/transfer`, show the algorithm the next export is
signed with, whether `pki.paranoidPolicySigner` is on, this realm's Policy
Export Signing CA, and the signer truststore's entries for policy imports.
The CA is shown with its subject, its validity and its SHA-256 fingerprint,
the value another realm's administrator names to trust this realm's exports.
The answer also carries the CA's `x5t#S256` and its chain up to the service
Root, without the Root itself. The entries are the other realms this realm
has said yes to. The CA is missing until the realm's first export creates it,
and reading the tab or the API does not create it. The answer holds
certificates only, never a private key.

## In the running service

* **Console:** Directory → Policies, `/admin/policies`. A tab per kind, then
  **Export and import** and **All profiles**.
* **API:** `GET /admin-api/policies`. `POST /admin-api/policies/save-<id>-policy`
  and `reset-<id>-policy`, with `<id>` from the table above.
  `save-named-authn-policy` and `delete-named-authn-policy` for a named
  authentication policy. `POST /admin-api/groups/set-policy` to point a
  group at one. `POST /admin-api/applications/set` to point an application
  at one. `POST /admin-api/users/set-attribute` to point a person at one.
* **Who names a profile** is `namedBy` on each named row of
  `GET /admin-api/policies`.
