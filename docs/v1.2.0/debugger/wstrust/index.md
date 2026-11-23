---
title: "Using the WS-Trust workflow"
nav_order: 27
---

# Using the WS-Trust workflow

> Copied from the [id-proto-debugger](https://github.com/rcbj/id-proto-debugger) release 0.9.5 user guide, which is the debugger this service embeds. Its addresses are the embedded ones: the debugger is `https://localhost:8444/` and its api `https://localhost:8444/api`. [Accessing the debugger](https://github.com/rcbj/id-proto-debugger/blob/0.9.5/docs/v0.9.5/access.md) says how to reach, enable and disable it.

The debugger is a WS-Trust client. `wstrust_tools.html` builds a SOAP
`RequestSecurityToken` and sends it to a security token service you
choose. `wstrust_response.html` shows the answer.

The version selector defaults to **WS-Trust 1.4**. SOAP defaults to
1.2. The four operations are Issue, Renew, Validate, and Cancel.

These pages are for somebody **using** the debugger.

* TOC
{:toc}

## Before you start

Open `https://localhost:8444/` and sign in as a console administrator
([Accessing the debugger](../access.md)), then choose **WS-Trust
Protocol**.

**The security token service is yours to choose.** The screenshots use
iya-sts at `https://localhost:8081/sts`. Another service has its own
accounts and its own policy for `AppliesTo`.

**Backend or browser.** **Initiate STS Call From** defaults to
**Backend (proxy)**, which is `POST /wstrust` on the api. The STS URL
then has to be reachable from the api. **Frontend (browser)** calls
that URL from the page, which needs the service to send CORS headers
for the debugger's origin. iya-sts does.

On a deployed static site the backend choice is disabled. The call is
made from the browser, so the service must allow that origin.

## What the static sites can and cannot do

The static sites have the page. They have no api, so **Backend
(proxy)** is off and **Validate STS TLS certificate** has nothing to
apply to. A service that answers a browser, iya-sts included, can still
be called with **Frontend (browser)**.

## Optional: iya-sts setup

[setup-iya-sts.md](setup-iya-sts.md) is only for iya-sts. Product mode
checks the password, requires a registered `AppliesTo` on Issue and
Renew, and authenticates a signed request by a certificate it issued
or that you registered. The tutorials do not depend on that page when
the service you call is not iya-sts.

## Configuration reference

| Page | Reference |
|---|---|
| `wstrust_tools.html` and `wstrust_response.html` | [reference.md](reference.md) |

## Protocol

| | |
|---|---|
| Issue, Renew, Validate, Cancel, delegation, and a signed request | [protocol.md](protocol.md) |

## Tutorials

| You want to | Tutorial |
|---|---|
| Ask for a bearer SAML assertion | [Issue a bearer token](tutorials.md#issue-a-bearer-token) |
| Renew it, validate it, and cancel it | [Renew, validate, cancel](tutorials.md#renew-validate-and-cancel) |
| Authenticate with a signature | [Sign the request](tutorials.md#sign-the-request) |
| Receive an encrypted token and open it | [An encrypted token](tutorials.md#an-encrypted-issued-token) |
| Act for the subject of a token you already hold | [OnBehalfOf and ActAs](tutorials.md#onbehalfof-and-actas) |

## Related pages

* [SAML workflow](../saml/index.md) — **Import from SAML workflow**
  copies the last assertion into the SAML-token credential.
* [WS-Federation](https://github.com/rcbj/id-proto-debugger/blob/0.9.5/docs/v0.9.5/wsfed.md) — the passive profile, which carries a
  WS-Trust response in `wresult`.
* [Post-quantum XML Signature](https://github.com/rcbj/id-proto-debugger/blob/0.9.5/docs/v0.9.5/xmldsig-pqc.md) — the draft methods
  added to the signature menu on load.

## Regenerating the screenshots

The screenshots are taken by the debugger project's own Selenium jobs, against
the standalone debugger and this service, so the address bar in them shows
`https://localhost:3000` where the embedded debugger is
`https://localhost:8444`. How to retake them is in that project's
[guide](https://github.com/rcbj/id-proto-debugger/blob/0.9.5/docs/v0.9.5/wstrust/index.md#regenerating-the-screenshots).
