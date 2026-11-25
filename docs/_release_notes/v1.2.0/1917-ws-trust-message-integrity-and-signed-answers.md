---
title: "WS-Trust message integrity, and signed answers"
kind: added
issue: 1917
---

A WS-Trust application can require its requests signed and name what the
signature must cover (`wstrustSignRequest`, `wstrustSignRequestElements`),
and can have its answers signed with the realm's XML signing key over a
`wsu:Timestamp` and the Body or the elements it names
(`wstrustSignResponse`, `wstrustSignResponseElements`). With encryption
also on, `wstrustResponseProtectionOrder` chooses sign-then-encrypt or
encrypt-then-sign, and `wstrustEncryptSignature` encrypts the signature
too. Each has a realm setting beside it (`wstrust.signRequest`,
`wstrust.signResponse`, `wstrust.responseProtectionOrder`,
`wstrust.encryptSignature`), all off by default. The WSDL's binding carries
`sp:IncludeTimestamp` while the realm signs its answers. On the
application's WS-Trust tab, **Body** and **Header** checkboxes write the
common expressions into the four encryption and signing maps, replacing
what a map held and putting it back when the last box is unticked, and an
**XPath builder** writes one for an element clicked in a sample message.
Putting a map to use turns its switch on, and giving it back turns the
switch back.
The tab has a simplified and an advanced view, the advanced one in General,
Message encryption and Message signing sections, each split into request
and response processing. Each field that holds XPath expressions has a
button that opens the XPath builder for that field in a window over the
page, where a list of expressions is built and added to it.
The XPath subset gains `not(…)`. New refusals: `STS-WSTRUST-0084`,
`0085`, `0086` and `0087`. See [Message integrity](ws-trust.md#message-integrity).
