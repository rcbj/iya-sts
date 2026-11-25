---
title: "A very large groups claim is referenced instead of carried"
kind: behaviour-change
issue: 2247
---

An access token or ID Token whose groups claim would be over
`groups.claimMaxBytes` (new, 4096 bytes by default) no longer carries the
list. It carries OpenID Connect Core section 5.6.2's distributed claim instead:
`_claim_names` maps the claim's name (`groups` by default) to `sts-groups`, and
`_claim_sources.sts-groups.endpoint` is the realm's new `/oauth2/groups`. A
relying party or resource server presents the access token there (`Bearer` or
`DPoP`, as at UserInfo) and gets the list back as a signed JWT with `iss`,
`sub`, `aud`, `iat`, `exp` and the claim. The list is never cut short. Only
an access token that itself carries the reference may ask, and it gets
exactly what it would have carried below the cap, after its client's own
group settings and release filter, and nothing more.

Below the cap nothing changes, and 4096 bytes is about 150 group names or 60
DNs. Until now a person in a few hundred groups got a token over 8 KiB, which
most servers refuse with `431` (Node.js refuses one over 16 KiB). UserInfo
responses and SAML assertions still carry the whole list, because neither
travels in a header. Set `groups.claimMaxBytes` to `0` for the old behaviour
(ASVS 5.0.0 4.2.5).
