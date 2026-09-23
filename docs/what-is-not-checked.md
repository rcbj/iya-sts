---
title: What is not checked
nav_order: 16
---

# What is not checked

This service runs in one of two modes, set by `global.mode`, and what it checks
depends almost entirely on which.

* **Development mode — the default — is permissive on purpose.** It checks no
  end user's password, creates a person, a client or a service provider the
  first time something names one, invents claim values the directory does not
  hold, and accepts tokens and assertions from anybody. A client that has only
  ever met a permissive server has never run its own refusal paths; a client
  that has only met a strict one cannot reproduce the behaviour it is trying to
  detect. So the default is permissive, several negatives are made deliberately
  *reachable*, and where the service can be told to be strict, it can.
* **Product mode is meant to be deployed.** It verifies every password
  presented at every door, creates nothing because something named it, invents
  no claim value, delivers a response only to an address somebody registered,
  closes the test controls, and **implies RFC 9700 mode** — PKCE with S256,
  exactly matched redirect URIs, rotating refresh tokens, no token-issuing
  response types at the authorization endpoint, unknown `client_id`s refused,
  and no password grant at all.

Every row below says what **product** mode does first and what **development**
mode does after it. [What product mode still does not check](#what-product-mode-still-does-not-check)
lists what neither mode checks and a deployment should know about.

The service publishes the same split about itself, live: `GET /admin/mode`
(Server configuration → Mode) and `GET /admin-api/mode` list every requirement
with the answer in force, and every development-only setting with the value
stored and the value in force (#181), and
`GET /oauth2/rfc9700` and `GET /oauth2/oauth21` list each OAuth requirement with
whether it is enforced. Read those for the running instance; read this page for
the reasons.

Read it before using this service for anything, and again before concluding that
something here is a bug.

## Checked in both modes

These are verified whatever `global.mode` says, because a permissive version of
any of them would be a broken implementation rather than a lenient one:

* a **Kerberos** key and ticket (see [Kerberos](#kerberos-is-the-exception-and-cannot-not-be));
* an **RFC 6238 one-time code** and a **recovery code**;
* a **WebAuthn** ceremony — challenge, origin, RP ID, flags, the credential's
  algorithm against the offer, the credential id's length, signature and
  counter — and, where `webauthn.attestationPolicy` says (product by default),
  its **attestation statement**;
* a **TLS client certificate** at `GET /tls/sign-in`, revocation included;
* a **federation partner's** signature, issuer and audience;
* an **RFC 7523 or RFC 7522 assertion's** signer, which must be declared;
* a **wallet presentation** at `/authn/wallet`: the issuer's signature and the
  holder's proof — a Key Binding JWT (`dc+sd-jwt`), a Verifiable Presentation
  JWT (`jwt_vc_json`) or a Data Integrity proof (`ldp_vc`);
* a **signed SAML request**, against the service provider's registered
  certificate;
* the reserved password **`invalid`**, refused at every door that takes a
  password, so a client's wrong-password path is always reachable;
* a **disabled account** (`pwdAccountLockedTime`), refused at every door — see
  the SCIM `active: false` row;
* a **SPIFFE node attestation**, by all nine of SPIRE's node attestors, and a
  Workload API caller on the Unix socket, by the workload attestors (#40).

## The list

| It does not | In product mode | In development mode |
|---|---|---|
| Check an end user's password | **Verified**, against the hashed `userPassword` on the person's entry, at every door that takes one: the sign-in screen, an LDAP bind, a WS-Trust UsernameToken, SCIM, Shared Signals and EST Basic. The sign-in screen rate-limits by name and by address, across the cluster. A person with no stored password cannot sign in (`STS-AUTHN-0052`), and one flagged `pwdReset` must choose a new password first. **A person who holds or must hold a second factor is refused their own password at the five password-only doors** — answered as a wrong password (`STS-AUTHN-0213`, recorded only) — and uses an app password there; `authn.passwordAloneDoors` lists doors that accept the password anyway, at one factor | Any password but `invalid` is accepted, and the name typed at `/authn/login` becomes the identity in every token and assertion |
| Issue without asking — **this row runs the other way** | Consent is asked: the first time a person signs in to a `client_id` for a scope, `/oauth2/consent` is drawn and nothing is issued until they answer. `oauth2.consentRequired` is ON by default in both modes. See [Consent](#consent-is-asked-in-both-modes) | The same |
| Hold a new password to a policy | **Enforced**, from the realm's policy (Directory → Policies, `/admin/policies`): a minimum length, a symbol count, an uppercase letter, a number, and none of the current password or the last five. At every door that sets one: the console and `/admin/users/new`, `/admin-api` (including `users/create`), `/portal/password`, `/portal/activate`, the forced change at sign-in, and an LDAP add or modify of `userPassword`. SCIM carries no password. A password already stored is not re-checked | Any password is set. The history is recorded in both modes, and a generated password meets the policy in both |
| Offer the OAuth 2.0 password grant | **It does not exist**: `unsupported_grant_type` (RFC 9700 section 2.4), because product mode implies RFC 9700 mode | Any password but `invalid` is accepted, as at the sign-in screen — unless `oauth2.rfc9700` or `oauth2.oauth21` is on, which removes the grant here too |
| Refuse an LDAP bind | Five kinds are refused before a password is read: an anonymous bind (48, `inappropriateAuthentication`), a bind on the plain listener on 389 (13, `confidentialityRequired`), a DN with an empty password (53), a DN that is not a person's — an application, a federation, a container — (49, the same answer as a wrong password), and a DN or address with too many failed binds inside `security.rateLimitWindowS` (53 — a correct password during a lockout is refused like a wrong one). Then the password is verified, and a wrong one is 49. The anonymous refusal needs the bundled `node-ldapjs` to support `routeAnonymousBinds`; an older checkout logs `STS-LDAP-0098` and lets the bind through, though every read on that connection is still refused. `ldap.plainListener` turns 389 off | Any DN and any password bind, anonymous included, on 389 and 636 alike — except `invalid` and a disabled account, which get 49 |
| Require a bind to read the directory, or withhold a credential from a search | A search or compare needs a bind (50, `insufficientAccessRights`). The exceptions are the root DSE and a base search of a certificate revocation list entry under `ou=crl`, which a relying party must be able to fetch anonymously. **No credential attribute is ever returned, matched by a filter or compared** — passwords and their history, client secrets, registration access tokens, private keys, TOTP secrets, recovery codes, activation and reset tokens, Kerberos keys, ACME and SCEP enrolment secrets, GNAP symmetric and macaroon keys — to anybody, administrators included. `createTimestamp`, `modifyTimestamp` and `entryDN` cannot be written by anybody (19, `constraintViolation`). What a bound connection may read beyond that is the next row | Any connection may read every entry and every attribute, except Kerberos keys and the three certificate-enrolment secrets, which are withheld in every mode. `entryUUID` cannot be written in either mode |
| Authorize an LDAP read per identity | **Every search and compare is authorized against the identity that bound.** Somebody holding Admin Read or Admin Write reads every entry in their scope — the default realm's roster reaches every realm, a realm's own roster reaches that realm. Anybody else reads their **own entry** whole; of **other people**, only the attributes `ldap.directoryReadableAttributes` names, which is **empty by default**, so another person is not there at all; a **group** only if they are a member of it, and then its `cn`, `description` and `objectClass` (its members too with `ldap.groupMembersReadable`); and the containers by name. **Applications, federations, policies, roles, trust anchors and SPIFFE registrations are invisible** to them. An entry the reader may not see answers noSuchObject (32) exactly as a missing one does; an attribute they may not read is absent from the result **and from a search filter**, so a filter cannot be used to read it; a compare of one is 50. Credentials stay withheld from everybody | Any connection reads every entry and every attribute but the credentials the row above withholds in every mode |
| Authorize an LDAP write | Every write is authorized against the identity that bound. Anonymous writes nothing. Somebody holding Admin Write in the default realm writes anything; a realm's own administrator writes that realm's directory. Anybody else may modify only the attributes `ldap.selfWritableAttributes` names, on their own entry — contact details, `displayName`, `preferredLanguage` and `userPassword` by default. A role held only because the roster is empty does not count. Refusals are 50 | Any connection, anonymous included, may add, modify, rename or delete any entry in any realm |
| Verify an access token at the OpenID4VCI endpoints | The credential, deferred credential and notification endpoints refuse a token this realm cannot verify, and one it revoked, with `invalid_token` | A token this realm cannot verify — or has revoked — is read unverified, since OpenID4VCI lets the authorization server be somebody else. A credential issued that way cannot sign anybody in |
| Verify the tokens in an RFC 8693 token exchange | **Since 2026-09-21**: the `subject_token` and the `actor_token` must verify against this realm's signing key, be unexpired and not revoked, or the exchange is `invalid_request` (`STS-OAUTH-0555`, `0556`, `0557`). Until that date product exchanged a forged token exactly as development does | A `subject_token` this realm cannot verify is read for its name and exchanged, and the `/admin/users` row says the subject was *told about* rather than authenticated. An `actor_token` is read and never verified. A **revoked** token this realm signed is refused in both modes |
| Require DPoP or mutual TLS | Refresh tokens rotate (product implies RFC 9700 mode). Nothing else here changes with the mode, and `POST /dpop/nonce-mode` is refused | Four settings make a sender constraint mandatory, all off unless set: `oauth2.accessTokenRequireDpop` and `oauth2.accessTokenRequireMtls` refuse a presented access token with no `cnf.jkt` or `cnf["x5t#S256"]` at every surface that takes one, and `oauth2.refreshTokenRequireDpop` and `oauth2.refreshTokenRequireMtls` refuse to issue or redeem an unbound refresh token. Neither OAuth 2.1 nor RFC 9700 asks for these, so no mode turns one on. The access-token pair refuses at the resource only, and the mutual TLS pair needs `global.https`. `oauth2.dpopNonceRequired` makes proofs fresher, not mandatory |
| Require a client to revoke a token | `POST /oauth2/revoke` requires client authentication — a confidential client's credential, or a public client's registered `client_id` — and refuses without it (401 `invalid_client`). A client may revoke only its own tokens (`invalid_grant`) | Anybody holding the token string may revoke it. **A credential that is presented is verified in both modes**, and then only the client's own tokens may be revoked |
| Require a credential to introspect a token as JSON | `POST /oauth2/introspect` requires client authentication and refuses without it (401 `invalid_client`). A caller learns only about tokens meant for it | Anybody holding the token string gets RFC 7662 JSON. **An RFC 9701 JWT response requires client authentication in both modes** |
| Require a request object to be signed | An RFC 9101 request object with `alg: none` is refused, and a `request_uri` must be https and answer with the `oauth-authz-req+jwt` or `jwt` media type | `alg: none` is accepted unless `oauth2.requireSignedRequestObject`, the client or a named authorization server asks for a signed one. In both modes a signed object is always verified, a `request_uri` is fetched only from an address the client registered, and a `jti` is accepted once |
| Refuse a pushed authorization request whose client credential did not verify | A client that declared a confidential method is refused 401; a public client may push without one. The pushed request is always validated and bound to its client | The credential is observed and the push accepted. Section 2.4's unregistered `redirect_uri` (`oauth2.parAllowUnregisteredRedirectUris`, off) needs a credential that verified in every mode |
| Register a client only for an administrator | `POST /oauth2/register` is closed — 403 — unless `oauth2.openRegistration` is on, or the registration carries a software statement this realm trusts. `oauth2.softwareStatementOpensRegistration` is **on by default**, so a trusted statement opens it out of the box | Anybody may register. A software statement is verified in both modes: an invalid one is `invalid_software_statement`, one from an undeclared issuer `unapproved_software_statement` |
| Create what something named | **Nothing is created because something named it**: no person, client, SAML service provider, SPIFFE entry, GNAP key or Kerberos principal. A certificate sign-in, federated sign-in, assertion grant or security-key enrolment for somebody with no entry is refused | The first time a name turns up — at the sign-in screen, in a certificate, a presentation, an SVID, a federated assertion, an RFC 7523 `sub`, a `client_id`, an `AuthnRequest` issuer — an entry is created for it |
| ~~Turn a verified client certificate into a login~~ — reversed 2026-09-05 | `GET /tls/sign-in` starts a session for the holder of a certificate that verified, after consulting revocation: the person the certificate was issued to, when this service issued it, or the entry named by its common name or subject. No entry means no session (`STS-AUTHN-0180`). A certificate from an authority of this service that does not issue client identities is refused, and an application's certificate signs nobody in — it is an RFC 8705 client credential | The same, except that a name with no entry gets one |
| ~~Turn a verified presentation into a sign-on~~ — reversed 2026-09-17 | "Sign in with a wallet" (`/authn/wallet`, `oid4vp.signIn`, on by default) starts a session for the entry a **holder-bound credential this service issued** was issued for — on an access token it verified, not disowned, with a good status — after a fresh holder proof. It is offered through the W3C Digital Credentials API; the plain QR code, which can be relayed to a victim, is off (`oid4vp.signInCrossDevice`). Any other presentation verifies and signs nobody in. In product the offer page `/issuer/offer` needs a sign-in and a wallet URL must be registered | The same. A credential issued on an unverified token is never in the sign-in register, so it cannot sign in either |
| ~~Publish a status for a credential it issued~~ — reversed 2026-09-17 | Every credential carries a Token Status List claim, a Bitstring Status List entry, or both, served at `/oid4vci/status-lists*`. A sign-out, a disabled account, a revocation on `/admin/tokens` and `/admin/vc-status` each set the bit; a restore on `/admin/tokens` clears it. The Verifier requires a status reference that resolves VALID on every presented credential (`oid4vp.requireStatusReference`, `all` by default, since #165): a foreign credential naming none is refused (`STS-VC-0088`) unless its issuer's certificate thumbprint is in `oid4vp.statusOptionalIssuers` or the rule is relaxed to `own-only` (which warns that such a credential can never be shown revoked); this realm's own with none is refused; a trusted foreign issuer's whose list cannot be fetched is refused; and an `ldp_vc` whose presentation withheld its `credentialStatus` is refused at the Verifier (`STS-VC-0089`) — its query asks for it — while a sign-in reads that credential's status from the register. `off` cannot be set (`STS-CORE-0103`) and is read as `all` | The same, by default. `oid4vp.requireStatusReference` `off` also accepts this realm's own credential with no reference and an `ldp_vc` that withheld its status |
| Count a wallet as more than one factor | A presentation proves possession of one key: `amr ["pop"]`, `acr "1"`. A verified key attestation for hardware storage adds `hwk`; `acr "mfa"` needs the attestation to say the key is guarded by the person's own authentication as well. A second factor after the presentation — an authenticator app, a security key or the person's password — is asked when the request, the realm or the account demands two | The same, except that the password offered as that second factor is not checked, so a wallet and any password make `acr "mfa"` |
| Verify anything in an issued credential's values | Nothing is invented: the values come from the access token and then the directory entry, and an attribute neither holds is absent — from the credential, a claims request, and the ID Token and UserInfo profile claims. `email_verified` is never asserted | What the entry lacks is invented from the username |
| ~~Deactivate anybody on SCIM `active: false`~~ — reversed 2026-09-17 | `active: false` writes `pwdAccountLockedTime`, the same state **Disable** on `/admin/users` writes. Every door then refuses the person — a password anywhere (an LDAP bind included), any sign-in, a session they already hold, a Kerberos AS-REQ or S4U2Self, every token grant and refresh, the issuance of any SAML, WS-Federation, WS-Trust or GNAP artifact, and the management API — and everything they hold is ended and their wallet credentials disowned. `active: true` enables them again | The same |
| ~~Restrict which people a federation partner may assert~~ — reversed 2026-09-22 ([#109](https://github.com/rcbj/iya-sts/issues/109)) | A partner signs in only the person its subject is **linked** to — a `federationLink` of the relationship, the partner's issuer and its `sub` or persistent NameID. An unlinked subject naming an existing person must first sign in here as that person, password and second factor, before the link is made (`fedSubjectPolicy` `link-at-first-sign-in`, the default); `pre-linked` refuses it (`STS-FED-0091`); `jit-namespaced` never reaches an existing person; **`any-existing`, the old name match, is refused** (`STS-FED-0094`, `STS-FED-0095`). Nothing is written onto an entry before that. Group, domain and DN-pattern rules narrow it further (`STS-FED-0092`), and a console administrator is refused even with a link unless `fedMayAssertAdministrators` is on (`STS-FED-0093`). Nothing is created for a subject naming nobody (`STS-FED-0090`) | The same, except that `any-existing` may be set and matches the name, and a subject naming nobody gets an entry named `<relationship>~<name>`, linked at creation, unless `fedAutocreateUsers` is off. No password is checked at the linking sign-in (the reserved `invalid` is refused) |
| ~~Verify a SAML `AuthnRequest`'s signature, or consume a service provider's metadata~~ — reversed 2026-09-17 | A signed `AuthnRequest`, `LogoutRequest`, `LogoutResponse` or `ArtifactResolve` is verified against the service provider's **registered** certificates — never the one the request carries — and refused if it does not verify. An **unsigned** request is refused (`saml2.requireSignedAuthnRequests`, `auto`). Every assertion is signed, so `WantAssertionsSigned` is always met. SHA-1 is refused, whatever `saml.allowSha1Signatures` says (#181); MD5, a MAC and a stateful hash-based signature are refused as not checkable. Consumed metadata registers the provider's endpoints, certificates and `NameIDFormat`s; its `validUntil` is enforced, it is refreshed after `cacheDuration`, and it must verify against `saml2.metadataTrustAnchors` when any is set. A metadata or MDQ fetch to an internal address is refused. An artifact is resolved only for the provider it was issued to | A present signature is verified in both modes. An unsigned request is accepted unless the provider's metadata says `AuthnRequestsSigned="true"`. `WantAssertionsSigned` is warned about rather than honoured when `saml2.signAssertion` is off. SHA-1 verifies with `saml.allowSha1Signatures` on. Internal addresses may be fetched |
| Check which entityID a SAML service provider claims | An unknown entityID is not registered by its request: the request is refused, having no registered return address and no signature. **An MDQ lookup the request starts registers it only when a trust anchor vouches for it** ([#112](https://github.com/rcbj/iya-sts/issues/112)): with no `saml2.metadataTrustAnchors` no lookup is made (`STS-SAML-0080`), and with them the answer creates the entry only if it verifies against one (`STS-SAML-0081`); the refused entityIDs are listed on `/admin/saml2` and `GET /admin-api/saml2`. An administrator's Import from MDQ with no anchor is refused (`STS-SAML-0084`) unless `saml2.mdqImportWithoutAnchors` is on — and then the document is consumed **unverified**, which its description warns about. `/saml2/metadata|sso|slo|ars/{sp}` and `/saml11/metadata|sso|responder/{rp}` answer **404** for a name that is not a registered provider of that profile (`STS-SAML-0082`, `STS-SAML-0083`) | Any entityID is accepted, and the first `AuthnRequest` from one creates its application entry; an MDQ answer registers an unknown service provider whether or not it is signed, unless trust anchors are set; the per-provider metadata is minted for any name |
| Check where a SAML response or WS-Federation token is delivered | The `AssertionConsumerServiceURL`, SAML 1.1 `shire` or `wreply` must be **registered** on the application (`samlAssertionConsumerService`, `wsfedReplyUrl`) and match exactly, with no mock fallback. An address development recorded is marked *observed* (`appReturnAddressObserved`) and refused until an administrator confirms it — **Confirm** and **Discard** under Applications, or `POST /admin-api/applications/confirm-address` and `/discard-address`. A provider whose metadata was consumed is answered only at an endpoint that metadata registered | The address a request names is used as it stands; with none, the registered one or a built-in mock. A consumed-metadata provider is held to its endpoints here too |
| Authenticate a caller at the SAML 1.1 attribute authority | Both query types are refused | Anybody may send an `AttributeQuery` about anybody. In both modes an `AuthenticationQuery` is answered only from a live session, and an attribute answer carries no invented `AuthenticationStatement` |
| Require a credential at the WS-Trust STS | A request with no credential is refused; a UsernameToken's password is verified; an assertion is accepted only when this STS signed it and it is inside its `Conditions`; `OnBehalfOf` and `ActAs` need the requester's own credential and an assertion this STS signed (`STS-WSTRUST-0009`); a token asked for encrypted is not sent in the clear (`STS-WSTRUST-0012`, `0013`). Nothing decides **who** may act for whom | A request with no credential gets a token for `anonymous`, an unsigned assertion is believed, and `OnBehalfOf` needs no requester. A requested lifetime is clamped to `wstrust.maxTokenLifetimeMin` in both modes |
| Encrypt an assertion it was asked to encrypt but holds no certificate for | Refused: a SAML Responder status with no assertion (`STS-SAML-0011`). It never encrypts to a certificate a request merely carried | The assertion is sent in the clear, with a warning. A provider whose metadata publishes an encryption key is encrypted to in both modes |
| ~~Decrypt an assertion a federation partner encrypted~~ — reversed 2026-09-23 ([#168](https://github.com/rcbj/iya-sts/issues/168)) | A SAML 2.0 `EncryptedAssertion`, `EncryptedID` and `EncryptedAttribute`, a WS-Federation token and an OpenID Connect JWE ID Token are **decrypted** with the relationship's own key, under exactly the algorithms it publishes. A **plaintext** assertion, or a signed-only `id_token` by form_post, is **refused** (`STS-FED-0140`) unless the relationship sets `fedAllowUnencrypted` | Plaintext is accepted; an encrypted one is decrypted as in product. In both modes AES-CBC, `rsa-1_5` and `RSA1_5` are refused (`STS-FED-0139`) and every decryption failure is one code (`STS-FED-0138`) |
| ~~Consume a federated sign-out~~ — reversed 2026-09-23 ([#167](https://github.com/rcbj/iya-sts/issues/167)) | A partner's sign-out ends the session it started, and only that one: a SAML 2.0 `LogoutRequest` (signed, verified against `fedSigningCertificate`, issued by `fedPeer`, addressed here, fresh and accepted once — `STS-FED-0115` to `0120`), an OpenID Connect Back-Channel Logout Token (section 2.6 whole, the `jti` once — `0127` to `0129`) or Front-Channel logout (`iss` and `sid` required — `0130`), and a WS-Federation cleanup the person confirms in their own browser (`0126`), at `/federation/slo/{id}` and the two OpenID Connect logout paths. The partner's SAML `SessionNotOnOrAfter` is the session's latest end (`0131`). A sign-out here offers the partner its own. SAML 1.1 and OAuth 2.0 define no sign-out. `fedAcceptSignout` off refuses them all (`0123`) | The same, except that a relationship may set `fedRequireSignedLogout` off and accept an unsigned SAML logout message; product refuses the setting (`STS-FED-0132`) |
| ~~Attest a workload or a node~~ — **reversed 2026-09-21 (#40)** | All nine of SPIRE's node attestors verify or refuse. The Workload API's Unix socket attests its caller with the `unix`, `docker` and `k8s` workload attestors; without the native module the socket is not served (`STS-SPIFFE-0113`), and asserted selectors are never believed. **A caller over TCP cannot be attested, so the Workload API is not served over TCP** (`STS-SPIFFE-0120`, #166) unless `spiffe.workloadTcpSourceAuthenticated` declares that the network authenticates source addresses, and then only on a named address (`STS-SPIFFE-0121`); an entry must select something that identifies its workload — `peer:<address>` for TCP — never only `transport:` and `endpoint:` (`STS-SPIFFE-0122`) — see [SPIFFE](#the-workload-api-is-the-opposite-case) | The same attestors. Without the native module the socket is served unattested, `spiffe.acceptAssertedSelectors` lets a caller assert its own selectors, and the TCP port is served to anybody who reaches it, where an entry on `transport:tcp` alone is issued to every caller |
| Let a group grant anything by being a group | A group grants what a role or roster names it for: the console's Admin Read and Admin Write, each realm's own administrator roster, `REMOTE_PEPS` and `XACML_USER` for the XACML surfaces, a configured role's `roleMemberGroup`, and the embedded debugger through the console roles. The groups claim in a token grants nothing | The same |
| ~~Decide who may delegate to whom, in two of the three families that can~~ — **reversed 2026-09-23 (#108)** | Kerberos polices S4U against `msDS-AllowedToDelegateTo` and `msDS-AllowedToActOnBehalfOfOtherIdentity`. WS-Trust `OnBehalfOf` / `ActAs` and RFC 8693 token exchange are decided by the same model on application entries — `appAllowedToDelegateTo`, `appAllowedToActOnBehalfOf`, `appDelegationSubjectGroup`, `appTrustedToImpersonate` — with `stsNotDelegated` and the console roster protecting people, then a deny-only XACML layer (action-id `delegate`). A refusal is `wst:RequestFailed` (`STS-WSTRUST-0018`, `0019`, `0020`) or `invalid_request` / `invalid_target` (`STS-OAUTH-0618`, `0619`, `0622`); only an application may be a WS-Trust requester that delegates, and an exchange may not widen its subject_token's scope (`STS-OAUTH-0621`). An ungranted delegated permission is `invalid_scope` (`STS-OAUTH-0155`). See [Delegation](#delegation-is-decided-in-all-three-families) | The KDC holds fixture delegation rules. WS-Trust and token exchange issue every delegation and record on the act what product would have refused. WS-Trust needs no requester at all. An ungranted delegated permission is honoured unless `oauth2.delegatedPermissionsEnforced` is on. In both modes a subject_token's `may_act` naming somebody else is refused (`STS-OAUTH-0620`) |
| Verify the certificate of whoever answers an outbound request — a GNAP push finish, an SSF push, a federation back channel (and the SAML metadata, RFC 9728, Logout Token and status-list fetches that share its policy), an XACML PEP nudge, a kubelet | **Always verified, since 2026-09-23 (#171)**: every `…SkipTlsVerification` setting and `spiffe.k8sSkipKubeletVerification` is ignored (logged once with its family's code) and cannot be turned on (`STS-CORE-0103`). A private CA is trusted through the family's `…CaFile`. Plain http is refused for SSF, federation and XACML whatever `…AllowHttp` says, and allowed for a GNAP push finish to a loopback address only | `…SkipTlsVerification` turns verification off, warned on every request, and `…AllowHttp` admits plain http to any host. Both are off by default |
| ~~Tie a scope to a client~~ — **reversed 2026-09-22 (#110)** | A client is issued only the scopes its `oauthAllowedScope` declares — or, declaring none, the default set: `openid`, `profile`, `email`, `address`, `phone`, `offline_access` and the realm's OpenID4VCI scopes. Anything else is `invalid_scope` (`STS-OAUTH-0578`); a scope naming an application or a delegated permission keeps its own rules. See [Scopes](#a-scope-is-tied-to-the-client) | Any scope is issued — except this service's own protected scopes (`admin:read`, `admin:write`, the SCIM and Shared Signals scopes, the debugger permission), which are held to the declaration in both modes (`STS-OAUTH-0577`) |

**Recorded is not the same claim as authenticated, and the two are kept apart
everywhere.** A verified TLS client certificate, a presentation at the
Verifier's own pages and an accepted SPIFFE credential are recorded on
`/admin/users` because an identity turned up here and something about it was
accepted. The recording signs nobody in: a certificate starts a session only at
`GET /tls/sign-in`, a presentation only at `/authn/wallet` for a credential this
service issued and has not disowned, and an SVID never. In development the same
three also create a directory entry for a name nobody provisioned; **in product
they create nothing**, and the row on `/admin/users` is all there is. A mock
that quietly promoted a record into a session would teach a client something
false about every real server it will ever meet.

## Consent is asked, in both modes

Everything above is a check. Consent is not one: it is a screen this service
insists on drawing, and `oauth2.consentRequired` is ON by default in both
modes. It is not the only setting that defaults to on —
`oauth2.jwtBearerRequireRegisteredIssuer`,
`oauth2.saml2BearerRequireRegisteredIssuer`, `oauth2.requestObjectJtiOnce`,
`adminApi.authRequired`, `admin.openWhenEmpty` and `gnap.consentRequired` are
among the others — but it is the one that changes what every client meets on a
first sign-in. (`admin.openWhenEmpty` is a development setting: product mode
never opens the console to whoever signs in, whatever it says.)

The reason it is on even in development is that consent is not a refusal. A
consent screen ADDS a test case: the extra redirect, the second visit to the
authorization endpoint, and the `access_denied` a client gets when somebody says
no are all code paths a client that has never met a first-time sign-in has never
run.

**What it establishes is that a person pressed a button.** In product that
person has already proved who they are; in development they typed any name they
liked at a screen that checks no password.

Three things about it are worth knowing:

* **The answer is a record, not a permission.** It is written to `oauthConsent`
  on the person's own entry — one value per (person, application, scope) — and
  read by two things: the authorization endpoint, deciding whether to draw the
  screen again, and the refresh grant, deciding whether the grant still
  stands.
* **Withdrawn means withdrawn** (#172). Revoking a consent — at
  `/admin/consent`, through `/admin-api`, or by the person themselves on
  `/portal/consents` — revokes every access and refresh token that application
  holds for them carrying the scope, on every node, and records the instant as
  `oauthConsentWithdrawn` on their entry. The refresh grant asks again at every
  refresh, in both modes: a refresh token granted before a withdrawal is
  refused even after the person consents again, and withdrawing one scope
  revokes the whole refresh token. With `oauth2.refreshRequiresConsent` (on by
  default) a refresh token from the authorization endpoint that no recorded
  consent covers — one obtained while consent was off — is refused as well.
* **`oauthGlobalConsent` on an application's entry turns the asking off for
  everybody who signs in to it**, without writing anything about anybody — so
  taking it away asks everybody again, and revokes the tokens it covered for
  everybody who did not agree to the scope themselves. It is keyed on
  (application, scope) and never on the scope alone, and
  `revoke-global-consent` is the only way to take it away.

Turning the setting off means nothing is asked and nothing recorded. It does
**not** mean everybody consented, so turning it back on asks again.

## Delegation is decided in all three families

`/admin/delegation` records every exchange in which somebody acted on somebody
else's behalf — Kerberos S4U2Self, S4U2Proxy (classic and resource-based) and a
forwarded ticket-granting ticket; WS-Trust `OnBehalfOf` and `ActAs`; RFC 8693
token exchange as impersonation and as delegation — against one model, with the
initial identity, the intermediary acting for them and the target on every row.

**Kerberos decides who may act for whom from two attributes.** The
KDC checks `msDS-AllowedToDelegateTo` on the front-end account and
`msDS-AllowedToActOnBehalfOfOtherIdentity` on the back-end one, enforces the
asymmetries between them (classic needs forwardable evidence; resource-based
needs `PA-PAC-OPTIONS` and gets `KDC_ERR_BADOPTION` without it), and refuses with
a message naming both attributes and their current values. In development the
KDC holds fixture rules so the refusals and the successes can both be reached;
in product there are none until an operator writes one.

**WS-Trust and RFC 8693 are decided by the same model since 2026-09-23 (#108)**,
on application entries:

* `appAllowedToDelegateTo` on the **intermediary** — the OAuth client, or the
  application a WS-Trust requester authenticates as — names the targets it may
  reach as somebody else. An `audience`, `resource` or `AppliesTo` is resolved
  to the application that registered it first.
* `appAllowedToActOnBehalfOf` on the **target** names the intermediaries it
  accepts — the resource-based form.
* `appDelegationSubjectGroup` narrows the people an intermediary may act for,
  by group DN; empty means anybody who is not protected.
* `appTrustedToImpersonate` (default FALSE) lets it **impersonate** —
  `OnBehalfOf`, or an exchange with no `actor_token` — as well as delegate.
* A person carrying `stsNotDelegated`, or a member of the console's Admin Read
  or Admin Write roster, is never delegated.

When the attributes allow, the issuance policy is asked about action-id
`delegate` with the intermediary, subject and target, and only an explicit Deny
refuses. **Product enforces it**: WS-Trust answers a SOAP Fault carrying WS-Trust
1.4 section 11's `wst:RequestFailed`, and only an application entry may be a
requester that delegates; the token endpoint answers `invalid_request`, or
`invalid_target` for a target it will not issue for (RFC 8693 section 2.2.2),
and refuses an exchange that widens the verified subject_token's `scope`
(`invalid_scope`). **Development asks the same question and issues anyway**,
and the act says what would have been refused.

**`may_act` (RFC 8693 section 4.4) is read in every mode.** A verified
subject_token naming a party other than the actor is refused; one naming it
stands in for `appTrustedToImpersonate` and the subject groups, never for the
target. It is issued only from the person's own choice, `stsMayAct`, set on
`/portal/delegate` or by an administrator. `act` nests: a prior actor chain is
kept beneath the new actor (section 4.1).

**Refusals are recorded, and they are the rows worth having.** A refused
delegation appears in no other list, which is why that page keeps a store of its
own.

Under an **impersonation** (S4U2Self, a forwarded TGT, `OnBehalfOf`, an RFC 8693
exchange with no `actor_token`) nothing in the credential records that a middle
tier was involved, so the issuer is the only place that fact can ever be seen.
That is what impersonation *is*, and it is why a page like that one belongs on
an identity provider.

## Kerberos is the exception, and cannot not be

The password there *is* the key: pre-authentication and the AS-REP's enc-part are
both encrypted under it, so even a permissive KDC has to pick a key the client
cannot guess.

**In product mode** none of the fixture accounts exist, nobody is created on
first sight, no password is published, and no rc4-hmac key exists (#182). Each trust realm with
`krb5.enabled` has a KDC, a Kerberos realm and keys of its own, on the shared
port 88, told apart by the realm name in the request. **Its `krbtgt` key is
random** (#169) — made once per realm, sealed on the directory entry
`krbtgt/<REALM>@<REALM>`, never shown and never derived from
`krb5.krbtgtPassword`, which product ignores — and the account
`krb5.servicePrincipal` names is created only when its password setting is not
the default this repository publishes.
**People in the directory authenticate with their own passwords**: a person's
keys are derived when their password is set or a sign-in verifies it, stored
sealed on their entry, and checked — a wrong password is
`KDC_ERR_PREAUTH_FAILED`, somebody whose keys have not been derived yet is told
to sign in once, and a disabled account is `KDC_ERR_CLIENT_REVOKED`.
`krb5.personKeys` turns person keys off. Service principals an operator creates
at `/admin/kerberos/principals` get a random key and a keytab. A person's keytab
is derived from a password in hand — their own on `/portal/kerberos`, or one an
administrator sets with **Reset password and download keytab** — and holds the
current kvno only. A password change
or rotation keeps the previous key version for a bounded window
(`krb5.retainedKeyVersions`, `krb5.retainedKeyTtlS`) so a ticket issued under it
is still accepted; the old *password* is not. **The `krbtgt` key rotates**
(#169): the `krb5.krbtgt-rotate` job replaces it every
`krb5.krbtgtRotationIntervalDays` (180 by default) and keeps the version it
replaced for the longest a TGT under it can live, renewals included, so every
TGT goes on working until it expires; it never rotates while that window is
open. An administrator rotates it by hand, or with **rotate and invalidate**
keeps nothing — every TGT in the realm is refused `KRB_AP_ERR_BADKEYVER` and a
Shared Signals event says so. The inter-realm trust key (`krbtgt/<partner>`)
is a secret shared with the partner and is not rotated.

**A person who holds or must hold a second factor gets no ticket on a password
alone** (#173). An authenticator app, a security key in the `mfa` role,
`stsMfaRequired` on their entry or `authn.mfaRequired` for the realm — the
same rule as the [password-only doors](#app-passwords-at-the-password-only-doors) —
and an AS-REQ proving only the password (`PA-ENC-TIMESTAMP`, or FAST's
encrypted challenge) is refused `KDC_ERR_POLICY` (12). The refusal comes
**after** the password verified: a wrong password is still
`KDC_ERR_PREAUTH_FAILED`, so nobody without the password learns anything, not
even that the account has a second factor. Kerberos can ask for the second
factor, so a person with an authenticator app gets a ticket through **RFC 6113
FAST** — armored by a ticket-granting ticket the client host got with its own
keytab (a service principal from `/admin/kerberos/principals`) — carrying **RFC
6560 OTP pre-authentication**: the password as the PIN and the code, both
checked in one exchange (`kinit -T <armor ccache>`). The code is verified by the
sign-in screen's own verifier and spent from the same once-only step, so one
code cannot be used at both. The ticket carries the RFC 8129 authentication
indicator `otp`, copied into the service tickets it buys, and `/authn/spnego`
counts it as the second factor. An app password is never a Kerberos key, so the
KDC refuses it like any wrong password. A person whose only second factor is a
security key cannot use Kerberos at all yet: PKINIT is
[#179](https://github.com/rcbj/iya-sts/issues/179).

**In development mode** any username authenticates and every user shares one
password (`password!`, `KRB5_USER_PASSWORD`), with a name nobody configured
created on first sight. Three refusals are kept reachable: a service-shaped name
for a host this service is not willing to *be* (`KDC_ERR_S_PRINCIPAL_UNKNOWN`),
the names in `KRB5_UNKNOWN_USERS` (`KDC_ERR_C_PRINCIPAL_UNKNOWN`), and a wrong
password (`KDC_ERR_PREAUTH_FAILED`). A password alone gets a ticket whatever
second factor the person holds (`mode.issuesTicketsOnPasswordAlone()`); FAST
and OTP work the same as in product, and the one-time code is verified.

The acceptor verifies tickets a real KDC issued to its service principal, in
both modes.

## A one-time code is verified in both modes

RFC 6238. A person enrols an authenticator app from `/portal/mfa`, and from then
on **the code they type is verified** — against the shared secret this service
generated, the clock, and a skew window of `totp.window` steps either side (one
by default; `0` demands a perfectly synchronised clock) — in development mode
as well as in product mode.

A one-time password verifier that accepted any six digits would not be a
permissive RFC 6238; it would be a broken one, with nothing for somebody testing
an authenticator integration to test against.

* **A code is accepted once** (RFC 6238 section 5.2). The code that confirmed an
  enrolment cannot also sign anybody in, and it is refused *as a repeat*, not as
  a wrong code.
* **A person who has enrolled one cannot sign in at `/authn/login` without it.**
  That is the only door that can ASK for it. The five doors that take a
  password and nothing else — an LDAP bind, a WS-Trust UsernameToken, SCIM,
  Shared Signals and EST Basic — cannot, so in product they **refuse that
  person's own password**, answered exactly as a wrong password and counted
  against the rate limit as one, and accept an **app password** scoped to the
  door instead (see [App passwords](#app-passwords-at-the-password-only-doors)).
  Development accepts the password there as it accepts every password.
* **A second factor can be required** of a person (`stsMfaRequired`, set from
  `/admin/users`) or of a realm (`authn.mfaRequired`); somebody who holds none is
  then asked to enrol one at `/authn/mfa-setup` before the sign-in completes.
* **It can never be a first factor.** This service holds the same shared secret
  the app does, which is fine for proving somebody still has the app and is not
  a thing to hang an account on.
* **A person can remove their own authenticator app** at `/portal/mfa`, signed
  in. One who has lost the phone signs in with a **recovery code** and does the
  same. An operator can clear it from that person's row under `/admin/users`, or
  with `POST /admin-api/mfa/clear-totp`.

In development the password in front of the code is not checked, and any name
may enrol. In product the password is verified first.

## App passwords at the password-only doors

An LDAP simple bind, a WS-Security UsernameToken, SCIM and Shared Signals HTTP
Basic and EST Basic take a password and have nowhere to ask for anything more
(RFC 4513 section 5.1.3, the UsernameToken Profile, RFC 7617, RFC 7030 section
3.2.3). NIST SP 800-63B section 4.2 puts an account bound to two factors at
AAL2, and a door that accepts one of them alone brings it down to AAL1. So, **in
product mode**, a person who holds an authenticator app or a security key in
the `mfa` role, or of whom a second factor is required (`stsMfaRequired`,
`authn.mfaRequired`), is refused their own password at those five doors:

* **The answer is a wrong password's**, byte for byte — LDAP
  `invalidCredentials` (49), the WS-Trust fault, SCIM's, Shared Signals' and
  EST's 401 — and it counts against the rate limit as a wrong password does.
  Anything else would tell a guesser the password was right.
* **An app password is accepted instead.** A person makes one on
  `/portal/app-passwords` after signing in, or an administrator makes one for
  them on their `/admin/users` page or with `POST
  /admin-api/users/create-app-password`. It is generated here (twenty-four
  characters), shown once, stored as a scrypt hash, named, and scoped to one or
  more of `ldap`, `wstrust`, `scim`, `ssf` and `est`. It is accepted only at
  those doors and **never at `/authn/login`** or any other browser sign-in. It
  is one factor, and the door records that an app password was used.
* **Each one can be revoked**, on the same pages or with `POST
  /admin-api/users/revoke-app-password`; making or revoking one sends a CAEP
  `credential-change`. Its last use is recorded. A disabled account refuses it;
  a password reset leaves it working.
* **`authn.passwordAloneDoors`** names doors that accept the password alone
  anyway. Every door listed is ONE factor for every such person, so it is the
  weaker option and documented as one.

Development mode checks no password at those doors, so it refuses nothing
there. The Kerberos AS exchange is a sixth door that CAN ask for the second
factor, so there a password alone is refused with `KDC_ERR_POLICY` instead and
the way in is FAST with OTP pre-authentication (see
[Kerberos](#kerberos-is-the-exception-and-cannot-not-be), #173); an app
password is not accepted by the KDC.

## A WebAuthn ceremony is verified, and so is the authenticator's attestation

The registration and every assertion are checked, in both modes — the
challenge, the origin, the RP ID hash, the flags (BS only where BE), the
credential's algorithm against the `pubKeyCredParams` offered, a credential id
of at most 1023 bytes, the signature over
`authenticatorData || SHA-256(clientDataJSON)` against the COSE public key the
credential registered (ES256/384/512, RS256/384/512, PS256/384/512, EdDSA and
ML-DSA-44/65/87), and the signature counter, which only ever goes up.

**The attestation statement is verified since #105** (2026-09-23), under
`webauthn.attestationPolicy`:

| | In product mode | In development mode |
|---|---|---|
| `by-mode` (the default) | `verify-if-present`: every statement is verified by its WebAuthn Level 3 section 8 procedure — packed, tpm, android-key, android-safetynet, fido-u2f, none, apple and compound — and refused if it does not verify. A chain is checked against `webauthn.attestationTrustAnchors` and the roots the FIDO Metadata Service lists for the model; a model MDS lists must chain to its roots, a model MDS reports REVOKED, USER_VERIFICATION_BYPASS or KEY_COMPROMISE is refused, and the chain's revocation is consulted. `none`, self attestation and a chain no anchor knows are accepted and recorded as **untrusted** — synced passkeys send `none` | `off`: the format is recorded and nothing in the statement is checked |
| `off` | Refused on write (`STS-CORE-0103`) and read as `by-mode` | Nothing is checked |
| `require-trusted` | Only a statement that chains to an anchor is accepted — no `none`, no self attestation, and so no synced passkey | The same |

An AAGUID allow-list (`webauthn.attestationAllowedAaguids`), a least FIDO
certification level and FIPS each require a trusted statement whatever the
policy says. The FIDO MDS3 BLOB is #62's dataset: uploaded on Monitoring →
Risk, imported by the loader or the dataset directory, or downloaded daily from
`risk.mdsUrl` by the `risk.mds-refresh` job. What each key's statement proved
is on its row on `/portal/keys`, `/admin/users` and `GET /admin-api/users`; a
key whose statement was not verified is shown as *claimed*.

**`webauthn.userVerification: required` is enforced** — the UV flag in the
signed authenticator data is checked — and it is the only ceremony OPTION that
could be, because nothing signed says what the browser was asked about the
attestation conveyance, the resident key or the attachment.

**Where a key can be enrolled depends on the mode.** In product a security key
that signs in on its own is added only where the person has already proved who
they are: `/portal/keys` behind a session, an activation link, or an operator.
**The passwordless box on the sign-in screen never enrols one in product**
(`STS-AUTHN-0206`, since 2026-09-21) — until that date it did, for anybody who
named an existing person holding no key, which gave that account to whoever
asked. In development it still enrols on first use, and the screen says the
first person to claim a name gets it. A key enrolled as a *second* factor at the
sign-in screen comes after the password, and only for somebody who holds no
second factor yet.

**A passwordless sign-in is one factor** — `amr ["hwk"]`, `acr "1"` — even under
`required`. RFC 8176 has no registered value for *the authenticator verified the
user* that this service could honestly assert.

## The reachable negatives

Several refusals are kept reachable on purpose, so a client's error paths have
something to run against:

- **The literal password `invalid`** is refused in both modes at every door that
  takes a password — the sign-in screen every browser protocol uses, an LDAP
  bind (49, `invalidCredentials`), WS-Trust, SCIM, Shared Signals and EST Basic,
  and, in development, the password grant. In development it is the one way to
  get LDAP 49 besides a disabled account; in product any wrong password does.
- **`invalid` as a SCIM `userName`** is refused, as is a duplicate one.
- **`oauth2.breakIdTokenNonce`** puts a deliberately wrong `nonce` in every ID
  Token. It is off by default, is not part of RFC 9700 mode, and **is honoured
  in development mode only** (#104): a product realm ignores it where the ID
  Token is built — even with it still stored from before the realm was
  switched, which is logged once (`STS-CORE-0106`) — and refuses turning it on
  (`STS-CORE-0103`). The same is true of SSF's two deliberate defects,
  `ssf.breakSetSignature` and `ssf.legacySubClaim`, and since #181 of RISC's,
  `risc.googleSubjectType`, and the KDC's `krb5.clockOffset`.
- **Broken algorithms and unsigned SAML are development's** (#181). A product
  realm signs XML with RSA-SHA256 whatever `saml.signatureAlgorithm` says
  (`rsa-sha1` is ignored), wraps an encrypted assertion's key with
  RSA-OAEP whatever `saml2.keyTransportAlgorithm` or an application's
  `saml2KeyTransportAlgorithm` says (`rsa-1_5` is ignored), refuses to unwrap
  an `rsa-1_5` key sent to it (`STS-KEYS-0070`), refuses a SHA-1 signature
  whatever `saml.allowSha1Signatures` says, never signs a certificate with
  SHA-1 (`STS-PKI-0191` when a build names it), and signs every SAML 2.0
  assertion and every SAML 1.1 Response and assertion whatever
  `saml2.signAssertion`, `saml11.signAssertion`, `saml11.signResponse` or an
  application's override of them says. `spiffe.requireSecurityHeader` off is
  ignored too. Each is refused on write (`STS-CORE-0103`, `STS-REG-0193` on an
  application) and logged once when a stored one is ignored (`STS-CORE-0106`);
  the stronger values of every setting stay available.
- **rc4-hmac in Kerberos and MD5 in SCIM Digest are development's** (#182).
  `krb5.enctypes` keeps 23 in its default so a development KDC exercises an
  RC4 client; a product realm reads the list without it, so no RC4 key is
  derived, stored or put in a keytab for the `krbtgt`, a service or a person,
  an AS-REQ or TGS-REQ offering only RC4 is `KDC_ERR_ETYPE_NOSUPP`, and an RC4
  session key or subkey in a TGS-REQ, an AP-REQ or FAST armor is refused —
  also in a realm switched to product with RC4 keys already derived.
  `scim.digestMd5` is off by default in both modes and cannot be turned on in
  product, which offers no Digest at all. RFC 8429 and RFC 7616 section 3.3.
  [MS-SFU]'s PA-FOR-USER checksum is HMAC-MD5 whatever the session key, fixed
  by that specification, and is unaffected.
- **WS-Federation's `wauth`** is never faked. A relying party demanding
  multi-factor or a hardware token against a session that does not have it
  sends the person back through the sign-in with that factor required — a
  hardware demand only a security key answers — and the assertion reports what
  was actually done. If that attempt still does not produce it, the request is
  refused. An unknown `wauth` is refused (`STS-WSFED-0006`).
- **A SAML 2.0 `ProtocolBinding` this service does not implement is refused by
  name.** A service provider that asked for PAOS and received a form post would
  conclude that PAOS worked.
- **`IsPassive="true"` with no usable session** gets a `<samlp:Response>`
  carrying `NoPassive` rather than a sign-in screen. A cancelled sign-in gets
  `AuthnFailed`.
- **A SAML artifact resolves exactly once**, across the cluster. A refused caller
  does not spend it.
- **A URL a caller hands over to fetch a credential from is never followed**:
  WS-Federation's `wreqptr` and a foreign SPIFFE bundle URL. The addresses this
  service does dial are ones an administrator wrote down, ones a client
  registered in advance (an RFC 9101 `request_uri`, a `jwks_uri`), or ones inside something that has already verified — a status
  list named in a credential signed by a trusted issuer, and the CRL and OCSP
  addresses in a certificate whose chain verified.

## Federation inverts all of this

Everything above describes this service being **asked** for something.
Federation is the other direction — it CONSUMES what a foreign identity service
issued — and there the posture is reversed in both modes.

`/federation/acs/{id}` receives an unauthenticated HTTP request that claims to
be a person. The only thing between "alice signed in at the partner" and
"somebody POSTed some XML" is the signature check, and the session that comes
out is **the same session** `/oauth2/authorize`, `/wsfed`, `/saml2/sso`,
`/saml11/sso` and `/admin` all read. So "accept any SAML Response" would be an
authentication bypass for every protocol in this process, which is why this is
the one feature here that **has to be configured before it will do anything**:

* nothing federated happens until a relationship is created;
* a relationship is created **disabled**, and enabling it is a second act;
* an enabled relationship missing a field its protocol needs **refuses and
  names the field** rather than half-working;
* an assertion is refused unless it verifies against the certificate configured
  on that relationship — **not** one the document brought with it — and that
  certificate is checked for revocation;
* the assertion's issuer must be the partner the relationship names (`fedPeer`
  is required), and the response must answer a request this service sent unless
  `fedAllowUnsolicited` allows identity-provider-initiated sign-on;
* the assertion must be addressed to this service: an `<Audience>` naming
  another service provider is refused, and a SAML 2.0 assertion with no audience
  restriction is refused. `fedLocalEntityId` says what this service is called to
  a partner that knows it by another name.

**The gate is on the signer AND on the subject (#109).** A verified
assertion signs in only the person its partner's subject is linked to: a
`federationLink` value of the relationship, the partner's issuer and its
stable identifier for the person — OpenID Connect's `iss` and `sub` (Core
section 5.7 makes that pair the only identifier a relying party may rely on),
a SAML persistent NameID qualified by the partner's entity ID (SAML 2.0 Core
section 8.3.7). A name alone never signs anybody in. What happens to a subject
nobody linked is the relationship's `fedSubjectPolicy`: the person it names
signs in here first and is then linked (`link-at-first-sign-in`, the
default), it is refused (`pre-linked`), or it gets a new entry of its own
(`jit-namespaced`); the old name match (`any-existing`) is development only.
Group, domain and DN-pattern rules apply on top of every policy, and a console
administrator is refused unless the relationship allows it. Nothing is written
onto an entry until all of that has passed. In product a subject naming nobody
is refused; in development it gets an entry `<relationship>~<name>`.

**A partner's sign-out is authenticated exactly as its sign-in is (#167).**
The partner is the authority on the person's sign-on, so when it ends a
session its message ends the one session here that it started — matched by the
SAML NameID and SessionIndex or the OpenID Connect `sid` (or `sub`) through
that relationship, never a local sign-in of the same person. A SAML
`LogoutRequest` must be signed and verify against the relationship's
certificate, come from `fedPeer`, name this endpoint as its Destination, be
fresh, and not have been seen before; a Logout Token is verified by the code
that verifies the partner's ID Token and then held to Back-Channel Logout
section 2.6, its `jti` accepted once ever. WS-Federation's cleanup is unsigned
by its specification, so it ends nothing until the person presses a button on
a page this service draws, in the browser holding the session. The partner's
`SessionNotOnOrAfter` bounds the session. OpenID Connect Session Management
is not used as a relying party: its iframe needs a script, and Back-Channel
Logout already carries what it would learn.

**A partner encrypts to the relationship, and product requires it to (#168).**
Every SAML 2.0, WS-Federation and OpenID Connect relationship holds an
encryption key of its own, issued under the realm's Intermediate and published
— `KeyDescriptor use="encryption"` in `/federation/metadata/{id}`, `use: enc`
at `/federation/jwks/{id}` — with the one key management and content cipher it
accepts: RSA-OAEP with SHA-256 and MGF1-SHA-256 and AES-256-GCM for XML, ECDH-ES
and A256GCM for an ID Token, by default. An encrypted assertion's own
signature is checked on what was inside it; an encrypted ID Token must be a
signed token, encrypted. Rotating the key keeps the old one decrypting for
`federation.encryptionKeyGraceS`. SAML 1.1 has no encryption construct, and a
plain OAuth 2.0 relationship reads no ID Token. There is no post-quantum key
encapsulation yet: XML Encryption has no ML-KEM method and JOSE's is a draft.

**Federation dials out, and it is not the only thing that does.** The OpenID
Connect and OAuth 2.0 relationships call the partner's token endpoint, UserInfo
and JWKS — OpenID Connect's default code flow included, so three of the five
protocols need no back channel, not four. The module that dials will not accept
a URL at all, only the *name* of the relationship attribute holding one, and
`federation.outbound` turns off everything that goes through it: federation,
back-channel logout, status-list fetches and the SAML metadata fetcher.
Shared Signals delivery, the GNAP push finish, CRL and OCSP fetches, the remote
XACML PEP nudge, the embedded debugger and the admin console's and portal's
calls to this service's own token endpoint dial out too, each under its own
setting.

## An assertion grant inverts it the same way

RFC 7521 with RFC 7523 or RFC 7522: **`grant_type=…:jwt-bearer` has no
permissive answer available in either mode.** A trusted party signs a document
saying *this is alice, issue a token for her*, and there is no browser, password
or consent step anywhere in the grant — the signature is the whole of it. So
the ISSUER has to be configured before anything is believed:

* an assertion is refused unless some application in the realm declares its
  `iss` on `oauthAssertionIssuer` — `oauth2.jwtBearerRequireRegisteredIssuer`
  and, for SAML, `oauth2.saml2BearerRequireRegisteredIssuer` are **on by
  default**;
* the signature must verify against a key registered for that issuer: a `jwks`
  by value, a JWKS this service issued it from its own certificate authority, or
  an `x5c` chain **that builds a path to this realm's Root CA** — a certificate
  that arrives WITH the signature is not evidence on its own;
* the certificate behind that key has its **whole chain validated** every time
  it verifies an assertion, and is checked for revocation;
* a registered `jwks_uri` is **fetched under the outbound policy** (https, no
  redirect, internal addresses refused in product mode) and cached;
* a **person** as issuer may assert only about themselves.

**The gate is on the SIGNER.** In product the `sub` must be somebody this realm
knows — an unknown one is refused (`STS-OAUTH-0510`). In development a name
nobody has used is created, exactly as typing it at the sign-in screen does. The
scope granted is narrowed to the assertion's own `scope` claim, and delegated
permissions and the RFC 9068 audience plan apply as for any other grant.

Turning the issuer requirement off does not make the grant credulous: the
signature must still verify against a key this service holds for the issuer.
`oauth2.jwtBearerGrant` removes the grant altogether, and the metadata stops
advertising it.

## The certificate authority publishes revocation, and consults it

Every certificate authority in `/admin/pki` signs an RFC 5280 CRL and answers
RFC 6960 OCSP, at `/pki/crl/{scope}/{ca}` and `/pki/ocsp/{scope}/{ca}` and in the
embedded directory under `ou=crl`. Every certificate this service issues names
its own; a pane on that page revokes one by hand; and anything replaced or
rotated goes on its issuer's list as `superseded`.

A certificate presented on the main port (XACML, SCIM, RFC 8705 client
authentication and `GET /tls/sign-in`), at the SPIRE Server API, in an
assertion's `x5c`, as a federation partner's pinned certificate, or behind a
trusted wallet issuer is checked under `pki.revocationCheck` — the register for
one this service issued, the OCSP responder and CRL it names for anybody else's,
with delta CRLs merged and indirect CRLs read per issuer. `auto` is **hard-fail
in product mode and soft-fail in development**. See [the PKI page](pki.md).

What is still not checked, in either mode unless a setting says so:

* **A delegated OCSP responder carrying `id-pkix-ocsp-nocheck`** is not asked
  about, because its issuer said not to.
* **An OCSP response that echoes no nonce** is believed unless
  `pki.revocationOcspRequireNonce` is on.
* **A certificate naming no CRL and no responder, in development.**
  `pki.revocationRequireDistributionPoint` is `auto`: product refuses one
  issued by a CA it does not hold (`STS-PKI-0190`) — nobody could ever revoke
  it — and development accepts it. `off` accepts it in product too, and its
  description says what that costs. A self-signed certificate is an anchor and
  is never refused for this, and one carrying RFC 9608 `noRevAvail` is not
  checked in either mode, because its issuer declared that no revocation
  information exists.
* **A list this service is configured not to dial** — a plain `ldap:`
  distribution point under the default `pki.revocationLdap=ldaps`, any LDAP
  address with it `off`, a name relative to its CRL issuer without
  `pki.revocationLdapDirectory`, an OCSP responder with `pki.revocationOcsp=off`
  — is **not read**. When it is all a certificate names, its status could not
  be established: hard-fail refuses it (`STS-PKI-0188`, the reason naming the
  setting) and soft-fail accepts it and reports it.
* **A bare registered key** — a JWK with no `x5c` — names no issuer and no list;
  only taking it off the entry stops it verifying.
* **LDAPS 636** asks for no client certificate, so there is nothing to check.
* **Under soft-fail — development's default — a foreign CRL that cannot be
  fetched is accepted.**

**Taking a key pair off an application is not revocation either.** The console's
*Take the key pair off* clears that profile's attributes from the entry — seven
for the JWT key pair, six for the SAML one — so this service stops accepting
assertions signed with it. The certificate is still valid and still chains to
the realm's Root; the reply says so and points at **Revoke**, which is what puts
it on the CRL.

**Where the CA private keys live** follows `keys.source`. With `auto`, the
default, they are held in memory and die with the process in development, and
are kept sealed under the key-encryption key in product. `persisted` and
`generated` choose one or the other in either mode. Both surfaces that report it
say which is in force.

## The surfaces that require a credential in every mode

These ask for a credential whatever the mode. Development still lets a caller
get one easily; product checks it.

| Surface | What it requires |
|---|---|
| `/scim/v2` | one of RFC 7644 section 2's schemes; the OAuth ones need `scim:read` or `scim:write` |
| the SPIRE Server API | an X509-SVID over mutual TLS, authorized against SPIRE's per-method table |
| `/admin` | a session and one of two roles held through directory groups |
| `/admin-api` | an OAuth 2.0 access token audienced to it, with `admin:read` or `admin:write` |
| the Shared Signals endpoints | an access token with `ssf:read` or `ssf:write` |
| `/xacml/*` and `POST /xacml/pip` | a verified client certificate whose entry holds `XACML_USER` or `REMOTE_PEPS` |
| `/federation/acs/{id}` | a signature verifying against the relationship's certificate |
| `/authn/spnego` | a Kerberos ticket verified against a real key |
| `/oauth2/introspect` | client authentication — for a JWT response in every mode, for JSON in product |
| the embedded debugger's listener | an access token only a console administrator is issued |

### SCIM, at `/scim/v2`

These endpoints create, replace, patch and **delete** accounts. A credential is
required in both modes, and after authentication the XACML access gate decides
(it permits by default).

**In product** Basic verifies the password against the entry, Digest is not
offered and is refused (`STS-SCIM-0056`) — and MD5 in it cannot be turned on
(`scim.digestMd5`, #182) — and a HOBA key can be registered only
by the account's own signed-in owner (`STS-SCIM-0069`) — registration never
creates an account.

**In development it is a turnstile rather than a lock**: any password but
`invalid` passes Basic, any username passes
Digest with the one shared password, and anybody can register a HOBA key for any
name. Digest and HOBA still genuinely verify the exchange, because a server that
accepted anything would not be performing it — a replayed nonce count is refused
**without** `stale=true`, because `stale` means "your credential was fine, try
again".

In both modes the SCIM scopes are issued only to a client whose
`oauthAllowedScope` declares them, and a token is honoured only while its client
still does — withdrawing the declaration cuts off tokens already issued
(`STS-SCIM-0079`). See [Scopes](#a-scope-is-tied-to-the-client). The discovery
endpoints are open unless
`scim.authDiscovery` is on. A credential that was presented and failed is always
a refusal.

### The SPIRE Server API

Its TCP port is **mutual TLS** in both modes. Callers present an X509-SVID
verified against the trust bundle and checked for revocation, and every method
is authorized against SPIRE's own per-method table, copied row for row from
`pkg/server/authpolicy/policy_data.json`. `Agent.AttestAgent` is open to
everybody by design. **The private Unix socket is trusted as `local` with no
credential** while `spiffe.trustLocalSocket` is on, which it is by default —
in development on the socket's existence alone, as a real `spire-server` does.
**In product the boundary is verified per connection** (#104): the socket must
have been made 0600 in a directory with no group or other bits
(`STS-SPIFFE-0117`), and the caller's kernel uid, read with `SO_PEERCRED`
through the native module, must be the service's own (`STS-SPIFFE-0118`;
`STS-SPIFFE-0119` where it cannot be read). Any other caller on the socket is
not `local` and needs an administrator's X509-SVID on the TCP port.

**Node attestation is verified or refused, in every mode (2026-09-21).**
`Agent.AttestAgent` accepts only an attestation type the realm names in
`spiffe.nodeAttestors` **and** an attestor here can verify; anything else is
refused with `FAILED_PRECONDITION`, as SPIRE refuses an attestor it has no plugin
for. Until then any type was accepted with its payload unread and the agent
marked `unverified:true`. The verifiable types are `join_token` (minted here,
single use), `x509pop` (an X.509 certificate chaining to the realm's anchors and
a signature over a fresh challenge — RSA, ECDSA or, beyond SPIRE, a
post-quantum key), `sshpop` (an SSH host certificate from a configured
authority, and a signature by its host key) and `tpm_devid` (a DevID key
resident in a TPM whose endorsement key a configured manufacturer certified,
proved by credential activation), `k8s_psat` (a projected service account
token the cluster's own TokenReview authenticates), `http_challenge` (a nonce
served from a host name the realm allows — as strong as the network's DNS,
and the one place this service dials an address a caller named), and
`aws_iid`, `gcp_iit` and `azure_imds` (each cloud's signed identity document,
once per instance).

### The admin console, at `/admin`

**There is no setting that opens this console.** Every page and form needs a
sign-on session and one of two roles: **Admin Read** and **Admin Write**. The
roles are two ordinary directory groups — `cn=admin-read` and `cn=admin-write`
by default — so `/admin/rbac`, `POST /admin-api/rbac/grant`, an `ldapmodify` and
a SCIM `PATCH` are four doors onto one membership. Each trust realm has a roster
of its own, confined to that realm; the default realm's is the service roster.

**In product** the sign-in verifies the password, and the bootstrap
administrator `admin` gets a generated password written to the log once, or
`admin.bootstrapPassword` from a secret store. An `ldapmodify` of the role
groups must be bound as somebody holding Admin Write, and nobody may write
`memberOf` onto their own entry.

**In development** no password is checked, so the gate proves only that somebody
*typed* a name that holds a role.

**In development, until the bootstrap administrator first signs in, anybody
who signs in by any method holds both roles**, and every page says so.
`admin.openWhenEmpty` (on by default) is that window; its first console sign-in
ends it.

**In product that window never opens**, whatever `admin.openWhenEmpty` says:
only the roster decides, and at first the roster is the bootstrap
administrator alone. Until it has claimed the console, its roles are honoured
only from a **password** sign-in verified here through its own realm, and only
that sign-in claims it — a federation partner asserting `admin`, a certificate
whose CN is `admin`, a wallet or a Kerberos ticket holds nothing and is refused
`bootstrap_password_required` (`STS-ADMIN-0796`). Anybody else is refused
until somebody grants them a role (`STS-ADMIN-0797`, logged once per session),
the embedded debugger waits for the claim (`STS-DBG-0033`), and a realm with no
bootstrap administrator and an empty roster is closed and logged at startup
(`STS-ADMIN-0798`) — `POST /admin-api/rbac/grant` with an `admin:write` token
is the way in.

### The management API, at `/admin-api`

An OAuth 2.0 access token audienced to the API, carrying `admin:read` to read and
`admin:write` to change anything, obtained with the client-credentials grant as
the seeded `sts-management-api` client and the secret in
`adminApi.clientSecret` (one is generated at each start when that is empty).
Those scopes are issued only to a client whose `oauthAllowedScope` declares
them, in both modes, and the API asks again on every call: a token whose client
no longer declares the scope an operation needs is refused 403
(`STS-API-0123`). The seeded `sts-management-api` and `sts-admin-console` declare
both, in every realm.

`adminApi.authRequired=false` behaves differently by mode. **In development** it
opens the API to anybody who can reach the port. **In product** it falls back to
the console's own gate — a session and a role — plus the XACML policy.

## GNAP proves the key, and that is not a turnstile

Every GNAP request is proofed by the key the client instance presented — an HTTP
message signature, mutual TLS, or a detached or attached JWS — in both modes,
because in GNAP the key IS the client.

* **An unknown key** gets an application entry on first sight in development,
  and is refused `invalid_client` in product until it is registered.
* **The resource owner is whoever the authentication service let in** — in
  product somebody who proved it, in development anybody.
* **A key proved by mutual TLS is held to a PKI in product and pinned in
  development** (`gnap.mtlsTrust=auto`). In product the certificate must chain
  to the client truststore and be bound to the client's application entry:
  issued to it by this realm, or carrying the RFC 8705 subject the entry
  registers. In development the certificate the key names proves itself,
  self-signed included. **A revoked certificate is refused in both.**
  `gnap.mtlsTrust=pinned` weakens a product realm, and is documented with a
  warning — see [mutual TLS trust](gnap.md#mutual-tls-trust).
* **A push finish** must go to a registered URI in product. It dials `http`
  only with `gnap.pushAllowHttp` — any host in development, a loopback address
  only in product (RFC 9635 section 2.5.2.1) — and only hosts in
  `gnap.pushAllowedHosts` when that list is set. **The client's certificate is
  verified in product whatever `gnap.pushSkipTlsVerification` says** (#171);
  a client certified by a private CA is reached through `gnap.pushCaFile`.
  In development that setting still turns verification off.
* **Macaroon third-party caveats, Biscuit third-party blocks and ZCAP invocation
  proofs are not implemented**; a token that needs one is refused.
* **A zcap token's proof is checked only in the suite the realm is set to.**
  By default that is `eddsa-jcs-2022`, which signs the JSON a resource server
  reads. **`gnap.zcapCryptosuite=Ed25519Signature2020` weakens this**: it
  signs the RDF canonicalization instead, so its safety rests on this service
  refusing any `@context` but its own, and a resource server cannot check the
  signature without a JSON-LD processor. Set it only for a verifier that knows
  nothing newer — see [zcap proof suites](gnap.md#zcap-proof-suites).

## A scope is tied to the client

Since 2026-09-22 (#110) a client is issued only the scopes it declared.
`oauthAllowedScope` on its application entry is the list — RFC 7591 section 2's
`scope`, written there by a registration and returned by it, and editable on the
console and through `/admin-api/applications/add` and `remove`.

* **This service's own protected scopes**, in both modes: `admin:read` and
  `admin:write`, the SCIM scopes (`scim.scopeRead`, `scim.scopeWrite`), the
  Shared Signals scopes (`ssf.authScopeRead`, `ssf.authScopeWrite`) and the
  embedded debugger's permission. A client that does not list one is refused
  `invalid_scope` (`STS-OAUTH-0577`). `/admin-api`, SCIM and Shared Signals ask
  again on every call, so withdrawing a declaration cuts off tokens already
  issued. A dynamic registration may not declare one
  (`invalid_client_metadata`); an administrator does. GNAP's `ssf` access
  rights are held to the same attribute (`STS-GNAP-0719`).
* **Every other scope, in product**: a client with a list gets what the list
  names; a client with no list gets the default set — `openid`, `profile`,
  `email`, `address`, `phone`, `offline_access` and this realm's OpenID4VCI
  scopes. Anything else is `invalid_scope` (`STS-OAUTH-0578`). In development
  any scope is issued.
* **A scope naming an application or a delegated permission** keeps its own
  rules: the first becomes the token's audience, the second needs a grant.
  Product mode refuses an ungranted delegated permission whatever
  `oauth2.delegatedPermissionsEnforced` says.

The authorization, pushed authorization and token endpoints refuse. A grant that
carries its scope from earlier — a refresh, a token exchange's inherited scope,
an assertion grant — is issued without the scope instead, the token response's
`scope` says what was issued, and an audit row records it (`STS-OAUTH-0579`).

## A logout cannot recall what has already been issued

`/logout` ends every session and revokes every credential this service can
still reach — see [signing out](signing-out.md). What it has already handed out
it **disowns**: it marks them revoked in its own records, sets the status bit of
every wallet credential, sends Shared Signals, SAML Single Logout and
back-channel logout to the relying parties it knows about. Three things it
still **cannot** end:

* a **SAML assertion** already in a service provider's hands;
* a **Kerberos service ticket** already in a cache;
* an **X509-SVID** already minted.

**Nothing consults the issuer when they are presented.** A relying party
verifies a signature and some `Conditions`; a Kerberos service decrypts with its
own key; an SVID verifies against a bundle. A real identity provider cannot
recall any of them either.

What the KDC does do is refuse every `TGS-REQ` presenting a ticket-granting
ticket authenticated before the sign-out, with `KDC_ERR_TGT_REVOKED` (20), while
`logout.kerberosSignOut` is on (the default), in both modes. **The person's
next AS-REQ succeeds and does not lift that**: its new ticket is accepted, and
every ticket from before the sign-out — a renewal of one included, since a
renewal keeps `authtime` — stays refused until the latest one could still be
valid (the sign-out plus the longer of `krb5.ticketLifetimeSeconds` and
`krb5.renewLifetimeSeconds`, plus `krb5.clockSkew`), on every node. The
console's undo, `restore-kerberos`, is refused in product mode. A service
ticket already issued is untouched.

## The Workload API is the opposite case

It authenticates nobody **because its specification says it MUST NOT**. A
workload has no secret and no root of trust until that call gives it one, so the
SPIFFE Workload Endpoint specification requires that the endpoint not demand
authentication. No mode changes that.

What it needs there is **attestation, not authentication**, and the two must
not be merged. **Since 2026-09-21 (#40) the Unix socket attests its caller** the
way a SPIRE agent does: the kernel names the connecting process (`SO_PEERCRED`,
through a small native module built into the image, and a pidfd that holds the
process), and the workload attestors that `spiffe.workloadAttestors` names turn it
into SPIRE's selectors:

* `unix`: `uid:`, `user:`, `gid:`, `group:`, the supplementary groups, and with
  `spiffe.unixDiscoverWorkloadPath` the executable's `path:` and `sha256:`;
* `docker`: the container's `label:`, `env:`, `image_id:` and
  `image_config_digest:`, asked of the Docker Engine;
* `k8s`: the pod's `sa:`, `ns:`, `pod-name:`, `pod-label:`, `pod-owner:`,
  `container-name:`, `container-image:` and the rest of SPIRE's list, read from
  the kubelet.

A connection is attested once, when it is accepted, and **every call on it
checks that the process is still the one attested**: a process that has exited,
a reused pid or an `exec` of another program is refused (`PERMISSION_DENIED`). An
attestor that fails refuses every call on the connection (`UNAVAILABLE`). A peer
in a pid namespace this service cannot see is attested on the uid and gid the
kernel recorded, and nothing else.

What is still not attested:

* **A caller over TCP.** It has no peer process to ask, so it is identified by
  the transport, the endpoint and its address, spelt `transport:`, `endpoint:`
  and `peer:`. The specification allows TCP only "if the underlying network
  allows the Workload Endpoint server to strongly authenticate the workload
  based on source IP address" (section 3), and this service cannot see whether
  it does — so **product mode does not bind the TCP port** (`STS-SPIFFE-0120`,
  #166) unless the operator declares it with
  `spiffe.workloadTcpSourceAuthenticated`, and even then **not on a wildcard
  `spiffe.grpcHost`** (`STS-SPIFFE-0121`): name the address whose network you
  vouch for. A realm switched to product with the port already bound refuses
  every call on it. **An entry must select something that identifies a
  workload** in product — never only `transport:` and `endpoint:`, which every
  caller of the port carries, and never nothing (`STS-SPIFFE-0122`, at the
  console, `/admin-api` and the SPIRE Server API); one written in development
  answers nobody once the realm is in product (`STS-SPIFFE-0123`). For TCP that
  is `peer:<address>`, matched **exactly** — no prefix, as in SPIRE. With the
  declaration, every host that reaches the port from that address is issued
  the entry's SVIDs, which is the declaration's warning. `GET /spiffe` says
  which of the two a realm has, under `workloadAttestation.tcp`. Development
  serves TCP as it always did.
* **A Unix-socket caller where the native module is missing.** Development serves
  the socket unattested and `GET /spiffe` says so under `workloadAttestation`.
  **Product does not serve the socket at all** (`STS-SPIFFE-0113`).
* SPIRE's `systemd` workload attestor, the docker attestor's sigstore signature
  checks and Podman sockets, and the Kubernetes broker. Each is a follow-up on #40.

**Asserted selectors are never believed in product mode**, and
`spiffe.acceptAssertedSelectors` cannot be turned on there (#104). In
development it still lets a caller assert them, so that selector matching can
be exercised with no attestor at all.

Selector matching still **decides** which entries answer a caller
(`spiffe.attestWorkloads`, on by default). **Off is development only** (#104):
it hands every caller every entry, so a product realm reads it as on whatever
is stored and refuses turning it off. A caller that matches no entry gets
an empty SVID list — what a real agent does for an unregistered workload — **in
product always**, and in development when `spiffe.autoCreateEntries` is off;
with it on, development creates an entry for the caller. Product seeds no
registration entries at all. **`spiffe.acceptAssertedSelectors`** (off) makes
the server believe selectors a caller sends in a header — in development only;
product mode never believes them (#40).

## RFC 9700 mode

`oauth2.rfc9700` turns the OAuth 2.0 and OpenID Connect flows into conforming
ones. **Product mode implies it**, so everything here applies to a product
deployment whatever the setting says. In development it is off by default; it is
restart-only for the process, and a trust realm can turn it on for itself at
runtime.

In that mode a client that declared a confidential method must present a
credential that verifies, whichever method it declared — a client secret,
`private_key_jwt`, `client_secret_jwt`, `tls_client_auth` or
`self_signed_tls_client_auth`, or a SAML assertion. In development a
`client_id` nobody registered has no credential on file and is let through; in
product it is refused. No end user's password is checked by the mode itself —
that is product mode's doing, not RFC 9700's.

Everything the mode does and does not enforce is at `GET /oauth2/rfc9700`, row by
row. Two rows say `enforced: no` because the requirement is the *client's* — it
must validate the ID Token's nonce, and must not use a token before that
succeeds — and nothing this server observes separates a client that checks from
one that does not.

## OAuth 2.1 mode

`oauth2.oauth21` (draft-ietf-oauth-v2-1-16) turns RFC 9700 mode on and checks
more: **a credential a client presents must verify** against one on file, even
from a client that did not need one, and the client credentials grant requires a
client that authenticated. A client must also have registered its own redirect
URI, and a token request naming a client whose entry declares nothing is
refused. `GET /oauth2/oauth21` says which requirements are enforced and which are
inherited.

What it still does not check: a client at `/oauth2/introspect` beyond what that endpoint checks in every mode; and the
client of an assertion grant that names none. In product a pre-authorized code
grant that names no client is refused.

## What product mode still does not check

These are true in a product deployment today, and are tracked as issues:

* **A person whose only second factor is a security key cannot use Kerberos.**
  Since #173 the KDC refuses a password alone to anybody who holds or must hold
  a second factor, and takes an authenticator app's code through FAST and OTP
  pre-authentication; the security-key equivalent, PKINIT, is
  [#179](https://github.com/rcbj/iya-sts/issues/179). FAST in the TGS exchange
  (implicit armor) is not implemented either: a TGS-REQ that carries it is
  answered unarmored, which MIT's client accepts.
