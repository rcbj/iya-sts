---
title: "cross-origin isolation headers on every response"
kind: added
issue: 2181
---

Every response now carries `Cross-Origin-Resource-Policy` (`same-site`;
profile photos and the sign-in logo stay `cross-origin`), and every HTML page
carries `Cross-Origin-Opener-Policy: same-origin` (ASVS 5.0.0 3.4.8 and
3.5.8). The pages a relying party may open in a popup (the authorization
endpoint and the sign-in, consent, SAML, WS-Federation, GNAP, federation and
sign-out pages) carry no COOP, as before, so popup sign-ins keep working. See
[The other response headers](oauth-security.md#the-other-response-headers).
