---
title: "PKCE is compared in constant time, and outbound requests are bounded"
kind: security
issue: 2247
---

The token endpoint now compares a `code_verifier` with its challenge in
constant time (ASVS 5.0.0 11.2.4); `plain` is still refused wherever RFC 9700
mode is in force. An outbound request whose path and query are over 8 KiB
(`STS-HTTP-0035`), or whose header fields come to more than 16 KiB
(`STS-HTTP-0036`), is no longer sent, and the call fails as a network failure
naming the bound (ASVS 5.0.0 4.2.5). No call this service makes comes near
either bound.
