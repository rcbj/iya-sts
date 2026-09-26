---
title: Devices
---

# Devices

This service keeps a **device register**: every phone, computer and host a
trust realm knows, each an entry under `ou=devices` in the realm's directory
([LDAP schema](ldap-schema.md)), owned by **one** person or **one**
application. A device is recognised again by the keys it holds, and each device
records whether it is attested, whether it is compliant, and which
applications used it.

The register is being built in phases (issue #164). This page says what is
built today; the console's **Protocols → Device registration** page says the
same, from the running build, and is the one to trust.

## Features

* **Two kinds of owner.** A person (a username), or an application entry — a
  workload or a server host registering the machines it runs on.
* **Keys a device is known by**, each with a SHA-256 thumbprint:
  * `x509` — a certificate; the thumbprint is over its SubjectPublicKeyInfo, so
    a renewed certificate over the same key is the same key;
  * `jwk` — a public JWK or DPoP key; the thumbprint is RFC 7638, which is
    DPoP's `jkt`;
  * `webauthn` — a security key the owner enrolled, linked to the device;
  * and the OpenID Connect Native SSO `device_secret`, which is not a key and is
    held only as a hash.

  One key belongs to one device in the realm. Keys are public material: a JWK
  with a private member, or any symmetric key, is refused.
* **Attestation**: a device is `attested` when a verifier checked an
  attestation statement for one of its keys, and `self-asserted` otherwise.
* **Compliance**: `compliant`, `not-compliant` or `unknown`, with the previous
  value and who set it.

## How a device is registered

| Method | Built | What happens |
|---|---|---|
| Native SSO | yes | The first app's authorization-code grant with `device_sso` makes the device ([OAuth 2.0 and OpenID Connect](oauth-oidc.md)). |
| An administrator | yes | **Directory → Devices** (`/admin/devices`) or `POST /admin-api/devices/create`, owned by a person or an application, with keys typed by value. A key added this way is recorded as proven by nobody and self-asserted. |
| The owner, on the portal | not yet | Proving a WebAuthn platform credential or a JWK. |
| EST and SCEP | not yet | A device certificate issued to the device entry. |

A person sees their devices on `/portal/devices` and can remove one.

## Development and product mode

Registration by an administrator and by Native SSO behave the same in both
modes today.

## Configuration

Drawn on **Protocols → Device registration**; the live source is that page and
`GET /admin-api/config`.

| Setting | Environment | Default | Runtime | What it does |
|---|---|---|---|---|
| `devices.maxPerPerson` | `STS_DEVICES_MAX_PER_PERSON` | `20` | yes | Devices one person owns. A Native SSO sign-in at the bound replaces the least recently used device whose session has ended; an administrator's registration is refused. It was `oauth2.maxDevicesPerPerson`. |
| `devices.maxPerApplication` | `STS_DEVICES_MAX_PER_APPLICATION` | `1000` | yes | Devices one application owns; a registration at the bound is refused. |
| `devices.maxKeysPerDevice` | `STS_DEVICES_MAX_KEYS_PER_DEVICE` | `10` | yes | Keys one device holds. |
| `devices.eventsKept` | `STS_DEVICES_EVENTS_KEPT` | `5000` | yes | Registrations, removals and evictions kept for **Monitoring → Devices**. |

## In the running service

* **Directory → Devices** (`/admin/devices`, `GET /admin-api/devices`): the
  register, paged and filtered, with a page per device.
* **Directory → As the directory holds it → Device entries**
  (`/admin/ldap/devices`, `GET /admin-api/ldap/devices`): the entries attribute
  by attribute, and the schema.
* **Protocols → Device registration** (`/admin/device-registration`,
  `GET /admin-api/device-registration`).
* **Monitoring → Devices** (`/admin/devices/monitor`,
  `GET /admin-api/devices/monitor`): counts by owner kind, compliance,
  attestation and key kind, and registrations, removals and evictions day by
  day.

Every operation is in the OpenAPI document at `GET /admin-api/openapi.json`.

## Related

[LDAP schema](ldap-schema.md) · [OAuth 2.0 and OpenID Connect](oauth-oidc.md) ·
[Management API](management-api.md) · [Configuration](configuration.md)
