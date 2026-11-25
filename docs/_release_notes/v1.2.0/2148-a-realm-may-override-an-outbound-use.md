---
title: "a realm may override an outbound use case's truststores"
kind: added
issue: 2148
---

A trust realm may now give an outbound service-wide use case (a federation
partner, a mail relay, a SCIM target, an audit destination and the like) a
truststore list of its own, used for the connections made from that realm
(#2148). A realm with no override keeps trusting the default realm's list,
so nothing changes until an administrator sets one. `GET
/admin-api/truststores` reports `overridable` and `realmOverride` for every
use case.
