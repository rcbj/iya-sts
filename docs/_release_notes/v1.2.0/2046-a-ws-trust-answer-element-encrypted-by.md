---
title: "a WS-Trust answer element encrypted by a custom expression"
kind: fixed
issue: 2046
---

A response encryption expression naming an element below the top of the
answer, such as `//wst:RequestedSecurityToken` or `//wst:Lifetime`, was
encrypted as text declaring that element's namespace prefix twice. That is
not well-formed XML, and a receiver that parses what it decrypts strictly,
such as Apache WSS4J, could not read the answer. The Body and Header
presets were not affected. Each prefix is now declared once.
