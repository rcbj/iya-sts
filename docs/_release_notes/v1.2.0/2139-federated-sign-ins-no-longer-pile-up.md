---
title: "federated sign-ins no longer pile up cookies"
kind: fixed
issue: 2139
---

In product mode each federated sign-in sets a cookie that binds it to the
browser that started it (`sts_fed_flow_…`). Until 1.2.0 none was ever
cleared, so a person who started many sign-ins within ten minutes could fill
their Cookie header until the service answered 431 (ASVS 5.0.0
4.2.5, #2139). The cookie is now cleared by the partner's answer, whether it signs
the person in or is refused, and one browser holds at most eight: a ninth
start clears the oldest. Nothing to configure; a cookie set by an earlier
build still binds its sign-in.
