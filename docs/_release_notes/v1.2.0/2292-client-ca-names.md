---
title: "A smart card's certificate is offered to every listener"
kind: fixed
issue: 2292
---
A browser offered a smart card's certificate to this service only if it could
build a path from the card's certificate to the service Root itself, because
each TLS listener named only the Root when it asked for a client certificate.
A card holds only its own certificate, so Firefox sent none, and the sign-in
page appeared instead. The listeners now also name every realm's Intermediate
and each realm's Issuing CAs for client certificates, and can verify a
certificate presented without its chain. Nothing more is trusted: every one of
those authorities is signed by the Root. A realm created later is included as
soon as its authorities are built. See
[A PIV smart card's certificate](configure-tls.md#a-piv-smart-cards-certificate).
