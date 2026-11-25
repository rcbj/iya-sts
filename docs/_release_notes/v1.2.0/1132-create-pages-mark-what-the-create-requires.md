---
title: "Create pages mark what the create requires"
heading: "Create pages mark what the create requires"
kind: changed
issue: 1132
---

Each Directory object has a create page that marks a field required exactly
when the create refuses it empty. New user marks the owners required while
**Service account** is ticked, and the push destination and the secret's
name each once the other is filled in. New policy no longer marks a field
the save accepts empty, such as the passkey policy's sign-in hints or the
attribute policy's required attributes.

A policy save through the management API that leaves `profile` out still
edits the default profile, as in 1.0.0. A save whose `profile` is empty or
null, and the console's new-policy form without a name, are refused with
"A name is required." (`STS-ADMIN-0549`). A named authentication policy
saved without a `name` is refused with `STS-AUTHN-0532`, as before.
