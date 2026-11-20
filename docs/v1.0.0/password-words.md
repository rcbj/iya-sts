---
title: Words a password may not contain
---

A new password may not contain a word that identifies your organization or this
service, because those are the first words an attacker tries.

## The list

These are always refused:

* the service's own names: `iya-sts`, `iyasec` and `iya cybersecurity`
* the realm's id and display name, except in the default realm
* each part of the realm's DNS domain, apart from the top-level part. For
  `acme.example.com` that is `acme` and `example`.

Add your own in `security.passwordContextWords`, separated by commas. Good
candidates are organization, product, project and department names, and role or
system names people use every day. The setting is on **Server Settings**, and
each realm can have its own value.

## How words are matched

A password is refused if a word appears anywhere inside it. Case, spaces and
punctuation are ignored, and so are common letter swaps such as `0` for `o`, `3`
for `e` and `@` for `a`. So `Acm3-2026-winter` is refused when `acme` is on the
list. Words shorter than four letters are ignored, because they would refuse good
passwords by chance.

The check runs wherever a password is set in product mode: on the portal, in the
console, through the APIs and over LDAP.
