---
title: Client certificates in TLS
nav_order: 22
---

# Client certificates in TLS

Part of [Smart cards](smart-cards.md). How a card's certificate reaches the
service, and what the service checks before it believes it.

* TOC
{:toc}

## The standards

* **TLS 1.3 (RFC 8446) client authentication**: the server sends a
  CertificateRequest, the client sends its certificate and a
  CertificateVerify signed with the card's key over the handshake. Because
  that signature covers the handshake, which carries this server's own
  certificate, a relaying party can neither replay nor forward it. That is
  why a certificate sign-in earns OpenID Connect EAP's `phr`. TLS 1.2
  (RFC 5246) works the same way where a listener allows it.
* **RFC 5280** path validation from the leaf to an anchor of the client
  truststore, and its section 6.1 policy processing, which a certificate
  sign-in profile's `policies` run with an explicit policy required and
  policy mappings honoured.
* **Revocation**: OCSP (RFC 6960) and the CRLs a certificate names.
* **RFC 9440**, `Client-Cert` and `Client-Cert-Chain`: a TLS-terminating
  proxy passing on the certificate it received.
* **RFC 4513**'s SASL EXTERNAL: an LDAP bind as the certificate's holder.

## What iya-sts implements

* **The main port asks every connection for a certificate and requires
  none**, so a card works there with nothing turned on. Each listener can be
  told not to ask, or to require one; LDAPS 636 asks for none by default.
  [Require a client certificate, or stop asking for one](configure-tls.md#require-a-client-certificate-or-stop-asking-for-one).
* **A certificate that does not verify still completes the handshake**, and
  every door that reads a certificate as a person refuses it. Refusing at the
  handshake would refuse every caller without a certificate on a port that
  carries every protocol ([TLS → Not implemented](tls.md#not-implemented)).
* **The client truststore starts empty** of outside roots: add the CAs your
  cards chain to ([Trust a CA for client certificates](configure-tls.md#trust-a-ca-for-client-certificates)),
  or assign the `tls-client` use case a named truststore
  ([Truststores](truststores.md#smart-cards-and-certificate-sign-in)).
* **Which account a certificate is**: a certificate this realm issued names
  its person; an outside one is decided by a certificate sign-in profile,
  else by the certificate stored on exactly one entry, else by its card UUID.
  A certificate's name is read only by a profile's opted-in low-affinity
  method. [What decides a certificate](configure-tls.md#what-decides-a-certificate).
* **Revocation is consulted after the handshake**, under
  `pki.revocationCheck`, and a sign-in can require a verified status
  (`certSignIn.requireRevocation`, required in product mode by default).
  [Revocation is consulted](tls.md#revocation-is-consulted),
  [Require a verified revocation status](configure-tls.md#require-a-verified-revocation-status),
  [PKI → Consulting revocation](pki.md#consulting-revocation).
* **The handoff**: the PIN prompt on a listener of its own, bound to the
  pending sign-in and the browser's session cookie.
  [A listener of its own for the card](configure-tls.md#a-listener-of-its-own-for-the-card-the-handoff).
* **RFC 9440 from a named proxy only**: both its client certificate and its
  address must be configured, the forwarded certificate is verified here,
  and from anybody else the headers are removed.
  [A TLS-terminating proxy in front of certificate sign-in](configure-tls.md#a-tls-terminating-proxy-in-front-of-certificate-sign-in).
* **SASL EXTERNAL on LDAPS**, once 636 asks for a certificate.
  [LDAP → Binding with a client certificate](ldap.md#binding-with-a-client-certificate).
* **RFC 8705** client authentication for applications, on the same
  handshake: [Configuring TLS](configure-tls.md), *RFC 8705 `tls_client_auth`: the TLS side*, and
  [Client authentication methods](configure-oauth2-grants.md#client-authentication-methods).
  An application's certificate never signs a person in.

## What it does not implement

* A certificate in any header but RFC 9440's, or from a proxy not named by
  both settings.
* A session started from a certificate's name alone, unless a profile opts
  in with `lowAffinity`, and never an entry created for a certificate
  ([Low affinity](configure-tls.md#low-affinity-what-you-accept-by-opting-in)).
* Refusing an unverified certificate at the handshake on the main port.

## Where it is configured

| What | Console | Setting |
|---|---|---|
| The CAs a card chains to | **Protocols → Client-certificate truststore** (`/admin/tls/trust`), or **Protocols → PKI trust → Use cases** | `tls.trustAnchorsFile` at startup; the `tls-client` use case |
| Profiles, revocation, handoff, proxy | **Protocols → PIV**, or **Server configuration → Listeners → Certificate sign-in** | `certSignIn.*`, `tls.trustedProxy*` ([Configuration → Certificate sign-in](configuration.md#certificate-sign-in)) |
| Whether a listener asks | **Server configuration → Listeners**, the listener's tab | `tls.mainPortDisableOptionalClientCertificate`, `tls.mainPortRequireClientCertificate`, `ldap.ldapsDisableOptionalClientCertificate`, `ldap.ldapsRequireClientCertificate` |
| How revocation is fetched | **Protocols → PKI** | `pki.revocation*` ([PKI → Consulting revocation](pki.md#consulting-revocation)) |

Recipes: [Smart-card guide](smart-cards-guide.md).

## Related

[TLS and mutual TLS](tls.md) ·
[Configuring TLS and mutual TLS](configure-tls.md) ·
[Listeners and hosted applications](listeners.md) ·
[Authentication pathways](authentication-pathways.md)
