---
title: "A certificate request with an empty extension request is accepted"
kind: fixed
issue: 2290
---
A certificate request (CSR) whose extension request attribute holds no
extensions, as `ykman piv certificates request` writes one, was refused as
unreadable (`STS-ENROLL-0034`). It now requests nothing and is accepted.
This applies to PIV enrolment on the portal and the console, and to ACME,
EST and SCEP. An extension request that is not a list is still refused.
