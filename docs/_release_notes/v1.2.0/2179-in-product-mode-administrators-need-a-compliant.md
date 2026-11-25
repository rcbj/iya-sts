---
title: "in product mode, administrators need a compliant registered device"
kind: behaviour-change
issue: 2179
---

In product mode, a person's token for the admin console, or any token
carrying an `admin:*` scope for `/admin-api`, is now issued only from a
compliant registered device of their own (ASVS 5.0.0 8.4.2). The check is
made at the token endpoint, on every grant and every refresh. A refusal is
`access_denied`, recorded as `STS-DEVICE-0054`. The new setting
`devices.requireCompliantDeviceForAdmin` controls it: `auto` (the default)
is on in product and off in development, and `on` and `off` force it.
Programs that use their own client credentials are not affected.

**Upgrading.** Nothing to run, and nobody is locked out. The requirement
starts unarmed in every realm, so every administrator signs in exactly as
before. It arms itself the first time a console administrator signs in from
a compliant registered device. Directory → Devices says which state a realm
is in. Before that first sign-in, register your administrators' devices,
have them marked compliant, and sign them in with the passkey or
certificate on the device. [Devices](devices.md) has the steps, and the way
back in if every administrator loses their device. A realm that keeps its
own `role-issuance` document must rebuild it from the template to get the
rule. To keep the 1.1 behaviour, set the setting to `off`.

This repository's own test stacks run with the setting `off`
(`docker-compose-run-tests.yml`), because their browser-driven console jobs
sign in from browsers that hold no registered device. One job,
`tests/protocol/sts_admin_device_requirement.js`, turns it on in a realm of
its own and checks the rule end to end.
