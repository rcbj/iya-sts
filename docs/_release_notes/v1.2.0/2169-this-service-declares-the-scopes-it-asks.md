---
title: "this service declares the scopes it asks a partner for"
kind: behaviour-change
issue: 2169
---

Where this service is the relying party and registers itself, it now
declares the scopes it will ask for, so a partner that issues a client only
what it declared (this service's own OP, in product mode, since the change
above) issues them. A relationship with `fedRegister` sends its `fedScope`
as the RFC 7591 registration's `scope`, and a realm's Entity Configuration
publishes, as its `openid_relying_party` metadata's `scope`, every scope its
OpenID Federation relationships (`fedTrustAnchor`) ask for. Until 1.2.0
neither carried a `scope`, and such a partner refused everything past
`openid` (`invalid_scope`). A partner that limits the scopes a client may
register may now refuse or trim the registration; set the relationship's
`fedScope` to what the partner offers.

**Upgrading.** Nothing to run. A relationship already registered with
`fedRegister` keeps its registration, which declared nothing; clear its
`fedClientId` (or press **Register at the partner**) to register again with
its scopes. An automatic OpenID Federation registration picks the scope up
when the OP registers the realm again, once the earlier registration ends.
