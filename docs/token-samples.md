---
title: Token samples
nav_order: 16
---

# Token samples

One real example of every kind of token, assertion and certificate this
service issues, decoded. They were captured from a running
development-mode container reached at `https://127.0.0.1:38081`, so
`127.0.0.1:38081` in a value below is the address the request arrived on.
That address becomes the issuer, and yours will differ. Every value was
produced by the service. Nothing here was written by hand, apart from the
cuts listed below.

**Cuts.** Long base64 values are shortened with `…` wherever a token is shown
decoded. That covers JWT signatures, XML `SignatureValue`, `DigestValue` and
`X509Certificate`, and the hex dumps in certificates. XML is re-indented for
reading, so **a pretty-printed signed document no longer verifies**; the
signature covers the bytes as sent. The OAuth access token and the ID Token
are the exceptions: they are given encoded in full as well.

**Two starts.** Most samples come from one start of the service. The
ones marked *second start* were added later from a fresh start of the same
image, so their signing keys (`kid`), certificates and serial numbers
differ from the rest.

**None of these verify today.** In development mode every key, certificate
authority and session is made again at each start, so the keys that signed
these samples no longer exist. To make your own, run the requests shown with
each sample against your instance and paste the result into any JWT or ASN.1
decoder. Which door accepts which token is covered in
[Accepted tokens](accepted-tokens.md); every endpoint is listed live at
[`/admin/sts-metadata`](endpoints.md).

The person in every sample is `alice`, a seeded development user whose stable
subject is `urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2` (the
`entryUUID` of the directory entry). Development mode checks no password,
so `password=x` is enough wherever one is asked for. It also accepts any
`client_id`, so `demo`, `ssf-rx` and `wallet` below are names made up
for the request, not registered clients.

* [OAuth 2.0 access token](#oauth-20-access-token)
* [OpenID Connect ID Token](#openid-connect-id-token)
* [Other JWTs](#other-jwts): refresh token, token exchange, RFC 9701
  introspection response, UserInfo JWT, back-channel Logout Token, WS-Trust JWT,
  software statement, signed metadata
* [SAML 2.0 assertion](#saml-20-assertion), artifact, ArtifactResponse and
  signed metadata
* [SAML 1.1 assertion](#saml-11-assertion) and artifact
* [WS-Federation and WS-Trust responses](#ws-federation-and-ws-trust-responses)
* [Shared Signals: SSF, CAEP and RISC](#shared-signals-ssf-caep-and-risc)
* [Verifiable credentials and status lists](#verifiable-credentials-and-status-lists),
  the OpenID4VP request object, the Domain Linkage Credential and a
  Credential Offer
* [GNAP access tokens](#gnap-access-tokens)
* [SPIFFE SVIDs](#spiffe-svids)
* [X.509 certificates, CRLs and OCSP](#x509-certificates-crls-and-ocsp),
  including ACME and SCEP
* [Kerberos tickets, keytabs and SPNEGO](#kerberos-tickets-keytabs-and-spnego)
* [Second factors: TOTP and recovery codes](#second-factors-totp-and-recovery-codes)
* [Opaque values](#opaque-values)

## OAuth 2.0 access token

An [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) JWT access token, in
every mode: `typ` is `at+jwt`, it is signed with the realm key published at
`/oauth2/jwks`, and `x5u` names that key's certificate chain under
`/pki/chain/`. This one came from the authorization code flow (a browser at
`/oauth2/authorize`, the sign-in screen, the consent screen, then):

```bash
curl -X POST https://127.0.0.1:38081/oauth2/token \
  -d grant_type=authorization_code -d client_id=demo \
  -d code=qVqFgarG41wqzJk_HdOcC9ZJoLT5iY4A \
  -d redirect_uri=https://client.example.org/cb
```

*Encoded:*

```text
eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K2p3dCIsImtpZCI6InN0cy1mNzA0NTI0MWU2YjAiLCJ4NXUiOiJodHRwczovLzEyNy4wLjAuMTozODA4MS9wa2kvY2hhaW4vZGVmYXVsdC84ZjFlMTljZmVlYzNkNTZjNDk5ODI1YjFlZjcwOTQ5NjExNjYxOTg0NjNiMTRlMzAxOTE0YmVmNTk1YzE5OWRjLnBlbSJ9.eyJncm91cHMiOlsiZGV2ZWxvcGVycyJdLCJpc3MiOiJodHRwczovLzEyNy4wLjAuMTozODA4MSIsInN1YiI6InVybjp1dWlkOjAxNmRjOGYxLTFiYzQtNTVkOS05NjU3LTliMmViYjNjZDRkMiIsImF1ZCI6Imh0dHBzOi8vMTI3LjAuMC4xOjM4MDgxL3Jlc291cmNlIiwiY2xpZW50X2lkIjoiZGVtbyIsInR5cCI6IkJlYXJlciIsImp0aSI6IklINVBZNTNUWkUtb25EM01qZ2gzbEEiLCJpYXQiOjE3OTAxMTA0OTMsIm5iZiI6MTc5MDExMDQ5MywiZXhwIjoxNzkwMTE0MDkzLCJ1c2VybmFtZSI6ImFsaWNlIiwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlIiwiYXV0aF90aW1lIjoxNzkwMTEwNDc2LCJhbXIiOlsicHdkIl0sImFjciI6IjEifQ.p13KXOIHRnuBr9kLHJF3iYLnQy8iVA0HPQX1xvuwm2j02_WfS8TFhla4sNpWRCIsUQlT3NFlpwwxEZSDJNT6jSUr2uUhI-qQ0pshHynmnfI6J3b2WXpLVzOw-F2eOx1KD9ZHrKpgD5nNIKAoJ3IrT3IcR-z0A3FDyuy6UfUhVlcR8WQREhw6oJMYf4nT4zP_I-outC5wjPtZeR7Vd882dtePp8opkVaocOo4Uu5gS9BL-T-CDkLgP8aj3T64Vx0fb9JQZKTCXmb1wUsteNb684Td_2Z5hL-l_HpJbGLnXRNeVIrNyEPEu1e6c5ZcubSAtN7I0Z6y0fyMJH614WtWhw
```

*Header:*

```json
{
  "alg": "RS256",
  "typ": "at+jwt",
  "kid": "sts-f7045241e6b0",
  "x5u": "https://127.0.0.1:38081/pki/chain/default/8f1e19cfeec3d56c499825b1ef7094961166198463b14e301914bef595c199dc.pem"
}
```

*Payload:*

```json
{
  "groups": [
    "developers"
  ],
  "iss": "https://127.0.0.1:38081",
  "sub": "urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2",
  "aud": "https://127.0.0.1:38081/resource",
  "client_id": "demo",
  "typ": "Bearer",
  "jti": "IH5PY53TZE-onD3Mjgh3lA",
  "iat": 1790110493,
  "nbf": 1790110493,
  "exp": 1790114093,
  "username": "alice",
  "scope": "openid profile",
  "preferred_username": "alice",
  "auth_time": 1790110476,
  "amr": [
    "pwd"
  ],
  "acr": "1"
}
```

Claims worth knowing:

* `sub` is the person's stable subject, `urn:uuid:<entryUUID>`, never the
  user name. The user name is in `username` and `preferred_username`.
* `aud` is the default resource, `{issuer}/resource`, unless the request named
  one with `resource` ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)).
  The token exchange sample below names another.
* `typ` inside the payload (`Bearer`) is this service's own marker. Its doors
  read it to tell an access token from an ID Token or a refresh token, all
  three being signed by one key.
* `auth_time`, `amr` and `acr` are copied from the session. A
  `client_credentials` token has none of them, and its `sub` is the client.
* `groups` comes from the person's directory groups.

## OpenID Connect ID Token

Issued beside the access token above, from the same token response. Its
`typ` header is `JWT`.

**This sample was captured before
[#118](https://github.com/rcbj/iya-sts/issues/118) and shows
the earlier shape.** An ID Token from the authorization code flow no longer
carries:

* the payload member `typ: "ID"`, which no specification defines. An ID
  Token has no `typ` member now, while an access token carries
  `typ: "Bearer"` and a refresh token `typ: "Refresh"`, and that is how the
  two are still told apart.
* the profile and email claims. OpenID Connect Core section 5.4 returns them
  from UserInfo when an access token is issued, and in the ID Token only for
  `response_type=id_token`.
* an `auth_time` when the time of authentication is not known.

`at_hash` is now computed with the hash of the ID Token's own `alg`.

*Encoded:*

```text
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InN0cy1mNzA0NTI0MWU2YjAiLCJ4NXUiOiJodHRwczovLzEyNy4wLjAuMTozODA4MS9wa2kvY2hhaW4vZGVmYXVsdC84ZjFlMTljZmVlYzNkNTZjNDk5ODI1YjFlZjcwOTQ5NjExNjYxOTg0NjNiMTRlMzAxOTE0YmVmNTk1YzE5OWRjLnBlbSJ9.eyJncm91cHMiOlsiZGV2ZWxvcGVycyJdLCJpc3MiOiJodHRwczovLzEyNy4wLjAuMTozODA4MSIsInN1YiI6InVybjp1dWlkOjAxNmRjOGYxLTFiYzQtNTVkOS05NjU3LTliMmViYjNjZDRkMiIsImF1ZCI6ImRlbW8iLCJ0eXAiOiJJRCIsImlhdCI6MTc5MDExMDQ5MywibmJmIjoxNzkwMTEwNDkzLCJleHAiOjE3OTAxMTQwOTMsImF1dGhfdGltZSI6MTc5MDExMDQ3NiwiYXpwIjoiZGVtbyIsImp0aSI6IkVsOWhzNUhaNHhfSUg2YzNXOGxrOUEiLCJuYW1lIjoiYWxpY2UgKG1vY2spIiwiZ2l2ZW5fbmFtZSI6ImFsaWNlIiwiZmFtaWx5X25hbWUiOiJNb2NrIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2UiLCJlbWFpbCI6ImFsaWNlQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImFtciI6WyJwd2QiXSwiYWNyIjoiMSIsIm5vbmNlIjoibjEiLCJzaWQiOiJzSGlLbUhCa09KNmJqS1hNLVRuRm9IelpQRVBJekhTNyIsImF0X2hhc2giOiJVVk9QdTAxY1NxQWlUT1d4YjFUdExBIn0.fCwfKe7lc77252_ukLrVgC4xvmOXcXTxdWo4aY8_VKyY7RVJyOUJ8no1qytXk-JzMCFFjiMkHPpWnDW3izWimFZ3RbNEygi5WNglfLpucqbCvHDU69u6jEtTVkuzAErGv3XPiHrHzor7loyzOtSBDJqDjb4PrHdZR6fY1gBZniwap-LcrHgTsDRIfRizc6Y3Pw0E4SSgIcTYmAgFF4b8bkoLNiwpmTOLzuANtG8gVSFvTJJJmwAoA9inP2HsBz49YPefbtDSLw5Yl4J-0Zk_i4vpN_b9ygk_CIK6sK8ihIctZL8WzmOqg0dkSsJrboVAOutQ-1IR1s9Da0ys9kkgNA
```

*Header:*

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "sts-f7045241e6b0",
  "x5u": "https://127.0.0.1:38081/pki/chain/default/8f1e19cfeec3d56c499825b1ef7094961166198463b14e301914bef595c199dc.pem"
}
```

*Payload:*

```json
{
  "groups": [
    "developers"
  ],
  "iss": "https://127.0.0.1:38081",
  "sub": "urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2",
  "aud": "demo",
  "typ": "ID",
  "iat": 1790110493,
  "nbf": 1790110493,
  "exp": 1790114093,
  "auth_time": 1790110476,
  "azp": "demo",
  "jti": "El9hs5HZ4x_IH6c3W8lk9A",
  "name": "alice (mock)",
  "given_name": "alice",
  "family_name": "Mock",
  "preferred_username": "alice",
  "email": "alice@example.com",
  "email_verified": true,
  "amr": [
    "pwd"
  ],
  "acr": "1",
  "nonce": "n1",
  "sid": "sHiKmHBkOJ6bjKXM-TnFoHzZPEPIzHS7",
  "at_hash": "UVOPu01cSqAiTOWxb1TtLA"
}
```

* `aud` and `azp` are the client, `demo`.
* `nonce` echoes the authorization request's `nonce=n1`.
* `sid` is the sign-on session, the same value that appears as the SAML
  `SessionIndex`, in the CAEP events' `session` subject and in the Logout
  Token below. The ID Token, SAML 2.0, SAML 1.1 and WS-Federation samples
  all came from this one session.
* `at_hash` is the left half of the SHA-256 of the access token, SHA-256
  being RS256's hash
  ([OIDC Core 3.1.3.6](https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken)).
* `name`, `given_name`, `family_name`, `email` and `email_verified` are
  invented in development mode (`mode.inventsClaimValues()`), which is why the
  family name is `Mock`. Product mode fills them only from the directory
  entry, and `email_verified` is `true` only when the person verified that
  address by following a link sent to it ([mail](mail.md)), `false`
  otherwise.
* `email` is here although the request asked only for `openid profile`.
  That was a bug, [#155](https://github.com/rcbj/iya-sts/issues/155), fixed by
  #118: none of these claims are in a code-flow ID Token now.

## Other JWTs

### Refresh token

A refresh token is a **nested JWT**: the signed JWT is encrypted to a key only
this service holds, so a client cannot read it. Only the JWE header is
readable. It is five dot-separated parts, not three. From the password grant
with `offline_access`:

```bash
curl -X POST https://127.0.0.1:38081/oauth2/token \
  -d grant_type=password -d client_id=demo -d username=alice -d password=x \
  -d 'scope=openid profile email offline_access'
```

*Encoded (shortened):*

```text
eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIiwidHlwIjoi…TkQSKXuj_h5vWvDX-Cfg
```

*JWE header:*

```json
{
  "alg": "RSA-OAEP-256",
  "enc": "A256GCM",
  "typ": "JWT",
  "cty": "JWT",
  "kid": "sts-rt-rsa-qs7d_OUa3sImlIYA"
}
```

### Token exchange (RFC 8693)

The access token above, exchanged for one audienced to another API.
Development mode does not verify the `subject_token`; product mode does.

```bash
curl -X POST https://127.0.0.1:38081/oauth2/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d client_id=demo -d subject_token=$ACCESS_TOKEN \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d audience=https://api.example.org
```

*Response (tokens shortened):*

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Im…WgQY_nzkzS2Jvz3aUyWg",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ik…pbF4jTS4SWDAXv04ZEig",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"
}
```

*Issued access token payload:*

```json
{
  "groups": [
    "developers"
  ],
  "iss": "https://127.0.0.1:38081",
  "sub": "urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2",
  "aud": "https://api.example.org",
  "client_id": "demo",
  "typ": "Bearer",
  "jti": "-fpFs1wXvCNyFLlgASNYBw",
  "iat": 1790110709,
  "nbf": 1790110709,
  "exp": 1790114309,
  "username": "alice",
  "preferred_username": "alice"
}
```

The empty `scope` and the unrequested `id_token` are a bug,
[#156](https://github.com/rcbj/iya-sts/issues/156).

### Introspection response as a JWT (RFC 9701)

Asked for with `Accept: application/token-introspection+jwt`. The caller must
authenticate for this in every mode, so the sample used a confidential client
registered at `/oauth2/register`. The response is signed. It carries no `sub`
or `exp` of its own, so it cannot be replayed as a token (RFC 9701 section 5).

```bash
curl -X POST https://127.0.0.1:38081/oauth2/introspect \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -H 'Accept: application/token-introspection+jwt' -d token=$ACCESS_TOKEN
```

*Encoded (shortened):*

```text
eyJhbGciOiJSUzI1NiIsInR5cCI6InRva2VuLWludHJvc3BlY3Rpb24rand0…8dnnk0d02hTEGwLGQItA
```

*Header:*

```json
{
  "alg": "RS256",
  "typ": "token-introspection+jwt",
  "kid": "sts-f7045241e6b0",
  "x5u": "https://127.0.0.1:38081/pki/chain/default/8f1e19cfeec3d56c499825b1ef7094961166198463b14e301914bef595c199dc.pem"
}
```

*Payload:*

```json
{
  "iss": "https://127.0.0.1:38081",
  "aud": "sts-client-L2a5XvtDkIM",
  "iat": 1790110888,
  "token_introspection": {
    "active": true,
    "scope": "openid profile",
    "client_id": "demo",
    "username": "alice",
    "token_type": "Bearer",
    "exp": 1790114488,
    "iat": 1790110888,
    "nbf": 1790110888,
    "sub": "urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2",
    "aud": "https://127.0.0.1:38081/resource",
    "iss": "https://127.0.0.1:38081",
    "jti": "QAleLVpphyI22Ah96I60nw"
  }
}
```

### UserInfo response as a JWT

Plain JSON unless the client registered `userinfo_signed_response_alg` (or
an encryption algorithm), in which case `GET /oauth2/userinfo` answers
`application/jwt`. The payload's `typ` is `UserInfo`, and `aud` is the
client. Registered with `{"redirect_uris":[…],"userinfo_signed_response_alg":"RS256"}`
at `/oauth2/register`, token from the password grant with
`scope=openid profile email`:

*Encoded (shortened):*

```text
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InN0cy1mNzA0NTI0…qPuyg_prtkE3Ja_WiK9g
```

*Header:*

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "sts-f7045241e6b0",
  "x5u": "https://127.0.0.1:38081/pki/chain/default/8f1e19cfeec3d56c499825b1ef7094961166198463b14e301914bef595c199dc.pem"
}
```

*Payload:*

```json
{
  "iss": "https://127.0.0.1:38081",
  "aud": "sts-client-eoo6k70Q_BM",
  "typ": "UserInfo",
  "groups": [
    "developers"
  ],
  "name": "alice (mock)",
  "given_name": "alice",
  "family_name": "Mock",
  "preferred_username": "alice",
  "email": "alice@example.com",
  "email_verified": true,
  "sub": "urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2",
  "iat": 1790111229
}
```

### Back-channel Logout Token

[OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html).
It is POSTed as `logout_token=…` to every relying party with a
`backchannel_logout_uri` on a session that a sign-out, an expiry or a disable
ends. `typ` is `logout+jwt`. It has an `events` member, and no `nonce`, so it
cannot pass as an ID Token. This one went to a client registered with
`backchannel_logout_uri` and `backchannel_logout_session_required`, after a
`POST /logout`.

*Encoded (shortened):*

```text
eyJhbGciOiJSUzI1NiIsInR5cCI6ImxvZ291dCtqd3QiLCJraWQiOiJzdHMt…ccHV_s7joyrUJCx-78QA
```

*Header:*

```json
{
  "alg": "RS256",
  "typ": "logout+jwt",
  "kid": "sts-f7045241e6b0",
  "x5u": "https://127.0.0.1:38081/pki/chain/default/8f1e19cfeec3d56c499825b1ef7094961166198463b14e301914bef595c199dc.pem"
}
```

*Payload:*

```json
{
  "iss": "https://127.0.0.1:38081",
  "aud": "sts-client-uKVxpMdQRw8",
  "iat": 1790110868,
  "exp": 1790110988,
  "jti": "5PQLkv9b02A7d-Za-L_Usw",
  "events": {
    "http://schemas.openid.net/event/backchannel-logout": {}
  },
  "sub": "urn:uuid:3cea6a34-920a-5d76-a92f-8c48e3c242e2",
  "sid": "O6TQEO65_DvzQwagWzON9_fDYxLrqFhq"
}
```

### WS-Trust JWT

WS-Trust issues a JWT when the `RequestSecurityToken` asks for
`TokenType` `urn:ietf:params:oauth:token-type:jwt`. It comes back as a
`wsse:BinarySecurityToken`; the whole response is under
[WS-Trust](#ws-trust-rstr-carrying-a-jwt), below. Its issuer is
`wstrust.issuer`, not the OAuth issuer.

*Encoded (shortened):*

```text
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InN0cy1mNzA0NTI0…pOEKlLtol60lc225EQkQ
```

*Header:*

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "sts-f7045241e6b0",
  "x5u": "https://127.0.0.1:38081/pki/chain/default/8f1e19cfeec3d56c499825b1ef7094961166198463b14e301914bef595c199dc.pem"
}
```

*Payload:*

```json
{
  "iss": "urn:wstrust:mock:sts",
  "sub": "urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2",
  "name": "alice",
  "iat": 1790110586,
  "exp": 1790114186,
  "jti": "NMoXwR8cHHDGDpd62DzFQFxy",
  "aud": "https://rp.example.org/"
}
```

The status list tokens, the OpenID4VP request object, the Domain Linkage
Credential and the JWT-SVID are JWTs as well. They are under
[Verifiable credentials](#verifiable-credentials-and-status-lists) and
[SPIFFE SVIDs](#spiffe-svids).

### Software statement (RFC 7591 section 2.3)

*From the second start of the service (see the note at the top), so its keys differ from the samples above.*

An administrator issues a signed statement of a publisher's
client metadata. A client then presents it as `software_statement` at
`/oauth2/register`, and the values it fixes win over the ones sent beside it.
`typ` is `software-statement+jwt`.

```bash
curl -X POST https://127.0.0.1:38081/admin-api/applications/issue-software-statement \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' \
  -d '{"application":"<publisher client_id>","metadata":{"software_id":"acme-mobile-app",
       "software_version":"4.2","client_name":"Acme Mobile",
       "redirect_uris":["com.acme.mobile:/oauth2/cb"],
       "grant_types":["authorization_code","refresh_token"],
       "token_endpoint_auth_method":"none"}}'
```

*Encoded (shortened):*

```text
eyJhbGciOiJSUzI1NiIsInR5cCI6InNvZnR3YXJlLXN0YXRlbWVudCtqd3Qi…VIbAU6zkCrSBFyvFz-5w
```

*Header:*

```json
{
  "alg": "RS256",
  "typ": "software-statement+jwt",
  "kid": "sts-8525a218fafe"
}
```

*Payload:*

```json
{
  "software_id": "acme-mobile-app",
  "software_version": "4.2",
  "client_name": "Acme Mobile",
  "redirect_uris": [
    "com.acme.mobile:/oauth2/cb"
  ],
  "grant_types": [
    "authorization_code",
    "refresh_token"
  ],
  "token_endpoint_auth_method": "none",
  "iss": "https://127.0.0.1:38081",
  "sub": "sts-client-Xiok04NIR48",
  "iat": 1790111793,
  "jti": "7znJ6CQwgLwkVx5K_gGZ1g",
  "exp": 1821647793
}
```

### Signed discovery metadata (`signed_metadata`)

*From the second start of the service (see the note at the top), so its keys differ from the samples above.*

`GET /.well-known/openid-configuration` (and
`/.well-known/oauth-authorization-server`) carries every member as plain
JSON and again as `signed_metadata`, a JWT signed with the realm key
([RFC 8414 section 2.1](https://www.rfc-editor.org/rfc/rfc8414#section-2.1)).
When the two differ, a client that verified the JWT uses the signed values.
The payload is the whole document, so only a few members are shown here.
The OpenID4VCI issuer metadata carries a `signed_metadata` of the same kind.

*Encoded (shortened):*

```text
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InN0cy04NTI1YTIx…RsX5Rtv8zrBdv2D3c5Zg
```

*Header:*

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "sts-8525a218fafe",
  "x5u": "https://127.0.0.1:38081/pki/chain/default/06e0368d006718352a8b5d103d29a41095e3e0a4fa2f53f912f8fccfdfa91402.pem"
}
```

*Payload (66 members; 8 shown):*

```json
{
  "issuer": "https://127.0.0.1:38081",
  "authorization_endpoint": "https://127.0.0.1:38081/oauth2/authorize",
  "token_endpoint": "https://127.0.0.1:38081/oauth2/token",
  "jwks_uri": "https://127.0.0.1:38081/oauth2/jwks",
  "registration_endpoint": "https://127.0.0.1:38081/oauth2/register",
  "iat": 1790111766,
  "exp": 1790115366,
  "iss": "https://127.0.0.1:38081"
}
```

### Crypto metadata (`/crypto/metadata.jwt`)

*From the second start of the service (see the note at the top), so its keys differ from the samples above.*

This service's own document of every signing key it
holds, per realm. Each *unit* is a use (JOSE signing per algorithm, XML
signing, SPIFFE, …) with each key generation and its certificate chain. It
is published as JSON, XML, a JWT signed with the realm key, and XML with an
enveloped signature. The JWT is about 200 KB; one unit is shown here, with
its long values shortened.

*Header:*

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "sts-8525a218fafe",
  "x5u": "https://127.0.0.1:38081/pki/chain/default/06e0368d006718352a8b5d103d29a41095e3e0a4fa2f53f912f8fccfdfa91402.pem"
}
```

*Payload (shortened):*

```json
{
  "specVersion": 1,
  "issuer": "https://127.0.0.1:38081",
  "realm": "default",
  "generatedAt": "2026-09-22T21:16:06.937Z",
  "rotation": {
    "scheduled": false,
    "intervalDays": 90,
    "retiredKeyGraceDays": 0,
    "why": "this is a development-mode service, whose keys are made anew at every start and are not rotated"
  },
  "units": [
    {
      "unit": "jose:RS256",
      "useCase": "jose",
      "alg": "RS256",
      "crv": null,
      "kind": "rsa",
      "purposes": [
        "access_token",
        "id_token",
        "refresh_token",
        "logout_token",
        "userinfo_response",
        "introspection_response",
        "signed_metadata",
        "software_statement",
        "security_event",
        "credential",
        "status_list",
        "request_object"
      ],
      "lastRotated": null,
      "keys": [
        {
          "kid": "sts-8525a218fafe",
          "state": "current",
          "jwk": {
            "kty": "RSA",
            "n": "uvKrGJmKlGJI8N7UzIVKD1UVbuw3NbcEn1WcJLmq…",
            "e": "AQAB",
            "kid": "sts-8525a218fafe",
            "use": "sig"
          },
          "certificate": {
            "x5c": [
              "MIIEdDCCA16gAwIBAgIQUQ9nOdaSZAtOWjYVehkR…",
              "… 2 more"
            ],
            "subject": "CN=JOSE signing (RS256), O=sts",
            "issuer": "CN=sts JOSE Signing CA (default), O=sts",
            "serialNumber": "510F6739D692640B4E5A36157A191114",
            "notBefore": "2026-09-22T21:12:06.000Z",
            "notAfter": "2027-09-22T21:12:06.000Z",
            "sha256Fingerprint": "06e0368d006718352a8b5d103d29a41095e3e0a4fa2f53f912f8fccfdfa91402",
            "selfSigned": false,
            "crl": [
              "http://localhost:8082/pki/crl/default/jose.crl",
              "ldap://localhost:389/cn=jose,ou=crl,dc=e…"
            ],
            "ocsp": "http://localhost:8082/pki/ocsp/default/jose",
            "caIssuers": "http://localhost:8082/pki/ca/default/jose.cer"
          }
        }
      ]
    },
    "… 18 more signing units"
  ],
  "algorithms": {
    "jose": {
      "signing": [
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "… 18 more"
      ],
      "default": "RS256",
      "signedMetadata": "RS256",
      "encryption": {
        "alg": [
          "RSA-OAEP-256",
          "RSA-OAEP",
          "ECDH-ES",
          "ECDH-ES+A128KW",
          "ECDH-ES+A192KW",
          "ECDH-ES+A256KW",
          "A128KW",
          "A192KW",
          "A256KW",
          "A128GCMKW",
          "A192GCMKW",
          "A256GCMKW",
          "PBES2-HS256+A128KW",
          "PBES2-HS384+A192KW",
          "PBES2-HS512+A256KW",
          "dir"
        ],
        "enc": [
          "A128GCM",
          "A192GCM",
          "A256GCM",
          "A128CBC-HS256",
          "A192CBC-HS384",
          "A256CBC-HS512"
        ]
      }
    },
    "xml": {
      "signing": [
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224",
        "http://www.w3.org/2007/05/xmldsig-more#rsa-sha224",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
        "… 36 more"
      ],
      "default": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    }
  },
  "links": {
    "jwks_uri": "https://127.0.0.1:38081/oauth2/jwks",
    "openid_configuration": "https://127.0.0.1:38081/.well-known/openid-configuration",
    "saml2_metadata": "https://127.0.0.1:38081/saml2/metadata",
    "wsfed_metadata": "https://127.0.0.1:38081/FederationMetadata/2007-06/FederationMetadata.xml",
    "json": "https://127.0.0.1:38081/crypto/metadata.json",
    "xml": "https://127.0.0.1:38081/crypto/metadata.xml",
    "signed_json": "https://127.0.0.1:38081/crypto/metadata.jwt",
    "signed_xml": "https://127.0.0.1:38081/crypto/metadata.signed.xml",
    "schema": "https://127.0.0.1:38081/crypto/metadata.xsd"
  },
  "sub": "https://127.0.0.1:38081",
  "iat": 1790111766,
  "exp": 1790115366,
  "iss": "https://127.0.0.1:38081"
}
```

## SAML 2.0 assertion

A Web Browser SSO `Response` over the HTTP-POST binding, answering an
unsigned `AuthnRequest` from `https://sp.example.org`, which development mode
serves without registration. The request was sent over the HTTP-Redirect
binding:

```xml
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_docs1" Version="2.0"
    IssueInstant="…" Destination="https://127.0.0.1:38081/saml2/sso"
    AssertionConsumerServiceURL="https://sp.example.org/saml/acs"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>https://sp.example.org</saml:Issuer>
</samlp:AuthnRequest>
```

The response is the base64 `SAMLResponse` field of the auto-posting form.
Both the `Response` and the `Assertion` are signed (RSA-SHA256, exclusive
C14N). The `KeyInfo` certificate is issued by the realm's *XML signing* CA.

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_2114a1cac6ec1cd39be48fe07f4e79e8" Version="2.0" IssueInstant="2026-09-22T20:55:15.421Z" Destination="https://sp.example.org/saml/acs" InResponseTo="_docs1">
  <saml:Issuer>urn:sts:idp:app-aaf6073df227</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#_2114a1cac6ec1cd39be48fe07f4e79e8">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>Jx7BjK6Qhm1icmXBod2sPRj4…</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>T5XUiqmpn//Z3ob0j+ycklUK…</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>MIIEbjCCA1igAwIBAgIQN+qz…</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_1005fb4d063d2743146fe26e759c3f7f" Version="2.0" IssueInstant="2026-09-22T20:55:15.389Z">
    <saml:Issuer>urn:sts:idp:app-aaf6073df227</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#_1005fb4d063d2743146fe26e759c3f7f">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>MD48zmHiaCpDZYVpoYQA+rsO…</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>Qo+L6c3i1ArA24fKyMBYIqhe…</ds:SignatureValue>
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIIEbjCCA1igAwIBAgIQN+qz…</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">alice</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2026-09-22T21:55:15.388Z" Recipient="https://sp.example.org/saml/acs" InResponseTo="_docs1"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-09-22T20:55:15.389Z" NotOnOrAfter="2026-09-22T21:55:15.389Z">
      <saml:AudienceRestriction>
        <saml:Audience>https://sp.example.org</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2026-09-22T20:54:36.000Z" SessionIndex="sHiKmHBkOJ6bjKXM-TnFoHzZPEPIzHS7">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>alice</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>alice</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>Mock</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>alice@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue>alice</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue>alice@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="givenName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue>alice</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="sn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue>Mock</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="displayName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue>alice (mock)</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="groups">
        <saml:AttributeValue>developers</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

* The `Issuer` is `urn:sts:idp:app-…`, a per-application entityID
  (`saml2.perApplicationEntityId`).
* `SessionIndex` is the session's `sid`, the value in the ID Token.
* `NameID` is the user name in the `unspecified` format by default. A
  `NameIDPolicy` or `saml2.nameIdFormat` picks another format; see
  [SAML 2.0 Web Browser SSO](saml2-sso.md).

### SAML 2.0 artifact

The same request with `ProtocolBinding` set to the HTTP-Artifact binding
sends the browser back with a `SAMLart` instead of the response:

```text
https://sp.example.org/saml/acs?SAMLart=AAQAAEsd2WlW%2BnW3m3q9nHN8CjaKwK8UyoXV8nBHbKGykNSjAAb3M7iWzg0%3D
```

Decoded, it is the 44 bytes of SAML 2.0 Bindings section 3.6.4:

| Bytes | Value | Meaning |
|---|---|---|
| 0–1 | `0004` | TypeCode 4 |
| 2–3 | `0000` | EndpointIndex of the artifact resolution service |
| 4–23 | `4b1dd96956fa75b79b7abd9c737c0a368ac0af14` | SourceID: SHA-1 of the entityID `urn:sts:idp:app-aaf6073df227` |
| 24–43 | `ca85d5f270476ca1b290d4a30006f733b896ce0d` | MessageHandle: random, one use |

The service provider exchanges it with a SOAP `ArtifactResolve` at
`POST /saml2/ars` and receives a signed `ArtifactResponse` wrapping the
`Response` shown above. Resolving an artifact destroys it, so a second
resolve gets nothing.

### SAML 2.0 ArtifactResponse

*From the second start of the service (see the note at the top), so its keys differ from the samples above.*

The service provider resolves the artifact over the SOAP
binding at the resolver its metadata names, `POST /saml2/ars/{sp}`:

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>
  <samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_docsres2" Version="2.0"
      IssueInstant="…" Destination="https://127.0.0.1:38081/saml2/ars/app-aaf6073df227">
    <saml:Issuer>https://sp.example.org</saml:Issuer>
    <samlp:Artifact>AAQAAEsd2WlW+nW3m3q9nHN8CjaKwK8UHnFtwio5G+yW3v04/DVHF7U/zgI=</samlp:Artifact>
  </samlp:ArtifactResolve>
</soap:Body></soap:Envelope>
```

The `ArtifactResponse` itself is unsigned on purpose: what the service
provider verifies is the signed `Response` inside it, and the back channel
is protected by TLS. The inner signatures are shortened to one line.
Resolving the same artifact at the unscoped `/saml2/ars` also works, and
answers with a different `Issuer`. That is a bug,
[#160](https://github.com/rcbj/iya-sts/issues/160).

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <samlp:ArtifactResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_5747603c71e8bb2bec676132012de9e2" Version="2.0" IssueInstant="2026-09-22T21:14:19.493Z" InResponseTo="_docsres2">
      <saml:Issuer>urn:sts:idp:app-aaf6073df227</saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
      </samlp:Status>
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_c730984c573bb5dc9bcb17c5b7779bf1" Version="2.0" IssueInstant="2026-09-22T21:14:19.303Z" Destination="https://sp.example.org/saml/acs" InResponseTo="_docs4">
        <saml:Issuer>urn:sts:idp:app-aaf6073df227</saml:Issuer>
        <ds:Signature>…enveloped signature, as in the SAML 2.0 sample…</ds:Signature>
        <samlp:Status>
          <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
        </samlp:Status>
        <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_4fac291f0a1b510f377062fa43971ac3" Version="2.0" IssueInstant="2026-09-22T21:14:19.230Z">
          <saml:Issuer>urn:sts:idp:app-aaf6073df227</saml:Issuer>
          <ds:Signature>…enveloped signature, as in the SAML 2.0 sample…</ds:Signature>
          <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">alice</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
              <saml:SubjectConfirmationData NotOnOrAfter="2026-09-22T22:14:19.229Z" Recipient="https://sp.example.org/saml/acs" InResponseTo="_docs4"/>
            </saml:SubjectConfirmation>
          </saml:Subject>
          <saml:Conditions NotBefore="2026-09-22T21:14:19.230Z" NotOnOrAfter="2026-09-22T22:14:19.230Z">
            <saml:AudienceRestriction>
              <saml:Audience>https://sp.example.org</saml:Audience>
            </saml:AudienceRestriction>
          </saml:Conditions>
          <saml:AuthnStatement AuthnInstant="2026-09-22T21:13:14.000Z" SessionIndex="16g7q765xwycim_M3yhkyzpjDFSrlzFx">
            <saml:AuthnContext>
              <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
          </saml:AuthnStatement>
          <saml:AttributeStatement>
            <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
              <saml:AttributeValue>alice</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
              <saml:AttributeValue>alice</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
              <saml:AttributeValue>Mock</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
              <saml:AttributeValue>alice@example.com</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
              <saml:AttributeValue>urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
              <saml:AttributeValue>alice</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
              <saml:AttributeValue>alice@example.com</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="givenName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
              <saml:AttributeValue>alice</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="sn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
              <saml:AttributeValue>Mock</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="displayName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
              <saml:AttributeValue>alice (mock)</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="groups">
              <saml:AttributeValue>developers</saml:AttributeValue>
            </saml:Attribute>
          </saml:AttributeStatement>
        </saml:Assertion>
      </samlp:Response>
    </samlp:ArtifactResponse>
  </soap:Body>
</soap:Envelope>
```

### SAML 2.0 identity provider metadata

*From the second start of the service (see the note at the top), so its keys differ from the samples above.*

`GET /saml2/metadata/{sp}`: the per-application
`EntityDescriptor`, signed (the signature comes first, as the metadata
schema requires). `GET /saml2/metadata` is the service-wide one
(`urn:sts:idp`). The WS-Federation equivalent is at
`/FederationMetadata/2007-06/FederationMetadata.xml`, and SAML 1.1's is at
`/saml11/metadata`.

```xml
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="_912703adb9b5af5facf10294115ac77e" entityID="urn:sts:idp:app-aaf6073df227">
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#_912703adb9b5af5facf10294115ac77e">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>CCvPLvOLH0Rpr9GVhJuirUdl…</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>ezB/v041j6Jpm8qbyOVCIjZb…</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>MIIEbjCCA1igAwIBAgIQMztF…</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>
  <md:Extensions>
    <cm:CryptoMetadataLocation xmlns:cm="urn:iya:sts:crypto-metadata:1">https://127.0.0.1:38081/crypto/metadata.xml</cm:CryptoMetadataLocation>
  </md:Extensions>
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIEbjCCA1igAwIBAgIQMztF…</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIEbjCCA1igAwIBAgIQMztF…</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://127.0.0.1:38081/saml2/ars/app-aaf6073df227" index="0" isDefault="true"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://127.0.0.1:38081/saml2/slo/app-aaf6073df227"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://127.0.0.1:38081/saml2/slo/app-aaf6073df227"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="https://127.0.0.1:38081/saml2/slo/app-aaf6073df227"/>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:entity</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://127.0.0.1:38081/saml2/sso/app-aaf6073df227"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://127.0.0.1:38081/saml2/sso/app-aaf6073df227"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="https://127.0.0.1:38081/saml2/sso/app-aaf6073df227"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://127.0.0.1:38081/saml2/sso/app-aaf6073df227"/>
  </md:IDPSSODescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="en">sts</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="en">Mock security token service</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="en">https://127.0.0.1:38081/</md:OrganizationURL>
  </md:Organization>
</md:EntityDescriptor>
```

## SAML 1.1 assertion

The SAML 1.1 Browser/POST profile, started at the inter-site transfer service
with Shibboleth's request parameters:

```text
GET https://127.0.0.1:38081/saml11/sso?TARGET=https://sp11.example.org/app&shire=https://sp11.example.org/saml11/acs&providerId=https://sp11.example.org
```

SAML 1.1 puts the `Issuer` on the assertion as an attribute. The subject
appears once per statement. Attributes are named by `AttributeName` and
`AttributeNamespace` rather than a URI. The two signatures are the same shape
as SAML 2.0's, so they are shortened to one line here.

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" ResponseID="_2e010a46f60a0dd5a4111e29c784d800" MajorVersion="1" MinorVersion="1" IssueInstant="2026-09-22T20:55:22.196Z" Recipient="https://sp11.example.org/saml11/acs">
  <ds:Signature>…enveloped signature, as in the SAML 2.0 sample…</ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="samlp:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" MajorVersion="1" MinorVersion="1" AssertionID="_b481af8c611fa47bc18bfce50b154976" Issuer="urn:sts:idp:saml11:app-2b946c3616bd" IssueInstant="2026-09-22T20:55:22.167Z">
    <saml:Conditions NotBefore="2026-09-22T20:55:22.167Z" NotOnOrAfter="2026-09-22T21:55:22.167Z">
      <saml:AudienceRestrictionCondition>
        <saml:Audience>https://sp11.example.org</saml:Audience>
      </saml:AudienceRestrictionCondition>
      <saml:DoNotCacheCondition/>
    </saml:Conditions>
    <saml:AuthenticationStatement AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password" AuthenticationInstant="2026-09-22T20:54:36.000Z">
      <saml:Subject>
        <saml:NameIdentifier NameQualifier="urn:sts:idp:saml11:app-2b946c3616bd" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">alice</saml:NameIdentifier>
        <saml:SubjectConfirmation>
          <saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod>
        </saml:SubjectConfirmation>
      </saml:Subject>
      <saml:SubjectLocality IPAddress="172.17.0.1"/>
    </saml:AuthenticationStatement>
    <saml:AttributeStatement>
      <saml:Subject>
        <saml:NameIdentifier NameQualifier="urn:sts:idp:saml11:app-2b946c3616bd" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">alice</saml:NameIdentifier>
        <saml:SubjectConfirmation>
          <saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod>
        </saml:SubjectConfirmation>
      </saml:Subject>
      <saml:Attribute AttributeName="name" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
        <saml:AttributeValue>alice</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute AttributeName="givenname" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
        <saml:AttributeValue>alice</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute AttributeName="surname" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
        <saml:AttributeValue>Mock</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute AttributeName="emailaddress" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
        <saml:AttributeValue>alice@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute AttributeName="nameidentifier" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
        <saml:AttributeValue>urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute AttributeName="upn" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
        <saml:AttributeValue>alice@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute AttributeName="authenticationmethod" AttributeNamespace="http://schemas.microsoft.com/ws/2008/06/identity/claims">
        <saml:AttributeValue>urn:oasis:names:tc:SAML:1.0:am:password</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute AttributeName="authenticationinstant" AttributeNamespace="http://schemas.microsoft.com/ws/2008/06/identity/claims">
        <saml:AttributeValue>2026-09-22T20:54:36.000Z</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute AttributeName="uid" AttributeNamespace="urn:mace:dir:attribute-def">
        <saml:AttributeValue>alice</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute AttributeName="mail" AttributeNamespace="urn:mace:dir:attribute-def">
        <saml:AttributeValue>alice@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute AttributeName="givenName" AttributeNamespace="urn:mace:dir:attribute-def">
        <saml:AttributeValue>alice</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute AttributeName="sn" AttributeNamespace="urn:mace:dir:attribute-def">
        <saml:AttributeValue>Mock</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute AttributeName="displayName" AttributeNamespace="urn:mace:dir:attribute-def">
        <saml:AttributeValue>alice (mock)</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute AttributeName="groups" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
        <saml:AttributeValue>developers</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
    <ds:Signature>…enveloped signature, as in the SAML 2.0 sample…</ds:Signature>
  </saml:Assertion>
</samlp:Response>
```

### SAML 1.1 artifact

*From the second start of the service (see the note at the top), so its keys differ from the samples above.*

The non-standard `profile=artifact` parameter on
`/saml11/sso` selects Browser/Artifact. The browser comes back to the
`shire` with `SAMLart` and `TARGET`:

```text
https://sp11.example.org/saml11/acs?SAMLart=AAHNn0I4HwELxDxT1HpT8xKvnqiFCvT+rOVvV7fnvs29s7DYFfaG2eht&TARGET=https://sp11.example.org/app
```

A SAML 1.1 type 0x0001 artifact is 42 bytes:

| Bytes | Value | Meaning |
|---|---|---|
| 0–1 | `0001` | TypeCode 1 |
| 2–21 | `cd9f42381f010bc43c53d47a53f312af9ea8850a` | SourceID: SHA-1 of the providerID `urn:sts:idp:saml11:app-2b946c3616bd` |
| 22–41 | `f4feace56f57b7e7becdbdb3b0d815f686d9e86d` | AssertionHandle: random, one use |

The relying party resolves it with a SOAP `samlp:Request` at
`POST /saml11/responder`:

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>
  <samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1"
      MinorVersion="1" RequestID="_docsreq1" IssueInstant="…">
    <samlp:AssertionArtifact>AAHNn0I4HwELxDxT1HpT8xKvnqiFCvT+rOVvV7fnvs29s7DYFfaG2eht</samlp:AssertionArtifact>
  </samlp:Request>
</soap:Body></soap:Envelope>
```

The answer is a signed `samlp:Response` whose assertion is built when it is
resolved. Its subject confirmation is `cm:artifact`, not `cm:bearer`:

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" ResponseID="_b13e05e3715e09ec927a61d1be712bd3" MajorVersion="1" MinorVersion="1" IssueInstant="2026-09-22T21:13:23.222Z" Recipient="https://sp11.example.org" InResponseTo="_docsreq1">
      <ds:Signature>…enveloped signature, as in the SAML 2.0 sample…</ds:Signature>
      <samlp:Status>
        <samlp:StatusCode Value="samlp:Success"/>
      </samlp:Status>
      <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" MajorVersion="1" MinorVersion="1" AssertionID="_70bb85d350e7c93f40e7174d5553b687" Issuer="urn:sts:idp:saml11:app-2b946c3616bd" IssueInstant="2026-09-22T21:13:14.852Z">
        <saml:Conditions NotBefore="2026-09-22T21:13:14.852Z" NotOnOrAfter="2026-09-22T22:13:14.852Z">
          <saml:AudienceRestrictionCondition>
            <saml:Audience>https://sp11.example.org</saml:Audience>
          </saml:AudienceRestrictionCondition>
        </saml:Conditions>
        <saml:AuthenticationStatement AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password" AuthenticationInstant="2026-09-22T21:13:14.000Z">
          <saml:Subject>
            <saml:NameIdentifier NameQualifier="urn:sts:idp:saml11:app-2b946c3616bd" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">alice</saml:NameIdentifier>
            <saml:SubjectConfirmation>
              <saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:artifact</saml:ConfirmationMethod>
            </saml:SubjectConfirmation>
          </saml:Subject>
          <saml:SubjectLocality IPAddress="172.17.0.1"/>
        </saml:AuthenticationStatement>
        <saml:AttributeStatement>
          <saml:Subject>
            <saml:NameIdentifier NameQualifier="urn:sts:idp:saml11:app-2b946c3616bd" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">alice</saml:NameIdentifier>
            <saml:SubjectConfirmation>
              <saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:artifact</saml:ConfirmationMethod>
            </saml:SubjectConfirmation>
          </saml:Subject>
          <saml:Attribute AttributeName="name" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
            <saml:AttributeValue>alice</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute AttributeName="givenname" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
            <saml:AttributeValue>alice</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute AttributeName="surname" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
            <saml:AttributeValue>Mock</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute AttributeName="emailaddress" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
            <saml:AttributeValue>alice@example.com</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute AttributeName="nameidentifier" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
            <saml:AttributeValue>urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute AttributeName="upn" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
            <saml:AttributeValue>alice@example.com</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute AttributeName="authenticationmethod" AttributeNamespace="http://schemas.microsoft.com/ws/2008/06/identity/claims">
            <saml:AttributeValue>urn:oasis:names:tc:SAML:1.0:am:password</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute AttributeName="authenticationinstant" AttributeNamespace="http://schemas.microsoft.com/ws/2008/06/identity/claims">
            <saml:AttributeValue>2026-09-22T21:13:14.000Z</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute AttributeName="uid" AttributeNamespace="urn:mace:dir:attribute-def">
            <saml:AttributeValue>alice</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute AttributeName="mail" AttributeNamespace="urn:mace:dir:attribute-def">
            <saml:AttributeValue>alice@example.com</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute AttributeName="givenName" AttributeNamespace="urn:mace:dir:attribute-def">
            <saml:AttributeValue>alice</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute AttributeName="sn" AttributeNamespace="urn:mace:dir:attribute-def">
            <saml:AttributeValue>Mock</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute AttributeName="displayName" AttributeNamespace="urn:mace:dir:attribute-def">
            <saml:AttributeValue>alice (mock)</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute AttributeName="groups" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
            <saml:AttributeValue>developers</saml:AttributeValue>
          </saml:Attribute>
        </saml:AttributeStatement>
        <ds:Signature>…enveloped signature, as in the SAML 2.0 sample…</ds:Signature>
      </saml:Assertion>
    </samlp:Response>
  </soap:Body>
</soap:Envelope>
```

## WS-Federation and WS-Trust responses

### WS-Federation sign-in response

The passive requestor profile answers `wa=wsignin1.0` with a form that posts
`wresult`, a `RequestSecurityTokenResponse` carrying a signed SAML 1.1
assertion (the same builder as [SAML 1.1](#saml-11-assertion)):

```text
GET https://127.0.0.1:38081/wsfed?wa=wsignin1.0&wtrealm=urn:rp:docs&wreply=https://rp.example.org/wsfed&wctx=docs
```

```xml
<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">
  <t:Lifetime>
    <wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2026-09-22T20:55:28.975Z</wsu:Created>
    <wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2026-09-22T21:55:28.975Z</wsu:Expires>
  </t:Lifetime>
  <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
    <wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
      <wsa:Address>urn:rp:docs</wsa:Address>
    </wsa:EndpointReference>
  </wsp:AppliesTo>
  <t:RequestedSecurityToken>
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" MajorVersion="1" MinorVersion="1" AssertionID="_97cbca81dcb4d15fc59d635bb9ae5cb9" Issuer="urn:wstrust:mock:sts" IssueInstant="2026-09-22T20:55:28.946Z">
      <saml:Conditions NotBefore="2026-09-22T20:55:28.946Z" NotOnOrAfter="2026-09-22T21:55:28.946Z">
        <saml:AudienceRestrictionCondition>
          <saml:Audience>urn:rp:docs</saml:Audience>
        </saml:AudienceRestrictionCondition>
      </saml:Conditions>
      <saml:AuthenticationStatement AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password" AuthenticationInstant="2026-09-22T20:54:36.000Z">
        <saml:Subject>
          <saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">alice</saml:NameIdentifier>
          <saml:SubjectConfirmation>
            <saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod>
          </saml:SubjectConfirmation>
        </saml:Subject>
      </saml:AuthenticationStatement>
      <saml:AttributeStatement>
        <saml:Subject>
          <saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">alice</saml:NameIdentifier>
          <saml:SubjectConfirmation>
            <saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod>
          </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Attribute AttributeName="nameidentifier" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
          <saml:AttributeValue>urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute AttributeName="name" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
          <saml:AttributeValue>alice</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute AttributeName="givenname" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
          <saml:AttributeValue>alice</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute AttributeName="surname" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
          <saml:AttributeValue>Mock</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute AttributeName="emailaddress" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
          <saml:AttributeValue>alice@example.com</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute AttributeName="upn" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
          <saml:AttributeValue>alice@example.com</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute AttributeName="authenticationmethod" AttributeNamespace="http://schemas.microsoft.com/ws/2008/06/identity/claims">
          <saml:AttributeValue>urn:oasis:names:tc:SAML:1.0:am:password</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute AttributeName="authenticationinstant" AttributeNamespace="http://schemas.microsoft.com/ws/2008/06/identity/claims">
          <saml:AttributeValue>2026-09-22T20:54:36.000Z</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute AttributeName="groups" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
          <saml:AttributeValue>developers</saml:AttributeValue>
        </saml:Attribute>
      </saml:AttributeStatement>
      <ds:Signature>…enveloped signature, as in the SAML 2.0 sample…</ds:Signature>
    </saml:Assertion>
  </t:RequestedSecurityToken>
  <t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType>
  <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
  <t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>
</t:RequestSecurityTokenResponse>
```

### WS-Trust RSTR carrying a SAML 2.0 assertion

A WS-Trust 1.3 `Issue` over SOAP 1.2 with a `UsernameToken`. With no
`TokenType`, the token is a signed SAML 2.0 assertion from the SAML 2.0
identity provider's builder:

```xml
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"
    xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"
    xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <s:Header><wsse:Security><wsse:UsernameToken>
    <wsse:Username>alice</wsse:Username><wsse:Password>x</wsse:Password>
  </wsse:UsernameToken></wsse:Security></s:Header>
  <s:Body><wst:RequestSecurityToken>
    <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
    <wsp:AppliesTo><wsa:EndpointReference>
      <wsa:Address>https://rp.example.org/</wsa:Address>
    </wsa:EndpointReference></wsp:AppliesTo>
  </wst:RequestSecurityToken></s:Body>
</s:Envelope>
```

*POSTed to `/sts`, answered:*

```xml
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Header>
    <wsa:Action xmlns:wsa="http://www.w3.org/2005/08/addressing">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTRC/IssueFinal</wsa:Action>
  </soap:Header>
  <soap:Body>
    <wst:RequestSecurityTokenResponseCollection xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
      <wst:RequestSecurityTokenResponse>
        <wst:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</wst:TokenType>
        <wst:RequestedSecurityToken>
          <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_516945cce8286656b15e95873ea73743" Version="2.0" IssueInstant="2026-09-22T20:56:26.019Z">
            <saml:Issuer>urn:wstrust:mock:sts</saml:Issuer>
            <ds:Signature>…enveloped signature, as in the SAML 2.0 sample…</ds:Signature>
            <saml:Subject>
              <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">alice</saml:NameID>
              <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"/>
            </saml:Subject>
            <saml:Conditions NotBefore="2026-09-22T20:56:26.019Z" NotOnOrAfter="2026-09-22T21:56:26.019Z">
              <saml:AudienceRestriction>
                <saml:Audience>https://rp.example.org/</saml:Audience>
              </saml:AudienceRestriction>
            </saml:Conditions>
            <saml:AuthnStatement AuthnInstant="2026-09-22T20:56:26.019Z" SessionIndex="_516945cce8286656b15e95873ea73743">
              <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
              </saml:AuthnContext>
            </saml:AuthnStatement>
            <saml:AttributeStatement>
              <saml:Attribute Name="name">
                <saml:AttributeValue>alice</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="issuedBy">
                <saml:AttributeValue>urn:wstrust:mock:sts</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="groups">
                <saml:AttributeValue>developers</saml:AttributeValue>
              </saml:Attribute>
            </saml:AttributeStatement>
          </saml:Assertion>
        </wst:RequestedSecurityToken>
        <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wsa="http://www.w3.org/2005/08/addressing">
          <wsa:EndpointReference>
            <wsa:Address>https://rp.example.org/</wsa:Address>
          </wsa:EndpointReference>
        </wsp:AppliesTo>
        <wst:Lifetime xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
          <wsu:Created>2026-09-22T20:56:26.058Z</wsu:Created>
          <wsu:Expires>2026-09-22T21:56:26.058Z</wsu:Expires>
        </wst:Lifetime>
        <wst:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</wst:KeyType>
        <wst:RequestedAttachedReference>
          <wsse:SecurityTokenReference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <wsse:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID">_516945cce8286656b15e95873ea73743</wsse:KeyIdentifier>
          </wsse:SecurityTokenReference>
        </wst:RequestedAttachedReference>
      </wst:RequestSecurityTokenResponse>
    </wst:RequestSecurityTokenResponseCollection>
  </soap:Body>
</soap:Envelope>
```

### WS-Trust RSTR carrying a JWT

The same request with
`<wst:TokenType>urn:ietf:params:oauth:token-type:jwt</wst:TokenType>`. The
JWT is decoded under [Other JWTs](#ws-trust-jwt).

```xml
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Header>
    <wsa:Action xmlns:wsa="http://www.w3.org/2005/08/addressing">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTRC/IssueFinal</wsa:Action>
  </soap:Header>
  <soap:Body>
    <wst:RequestSecurityTokenResponseCollection xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
      <wst:RequestSecurityTokenResponse>
        <wst:TokenType>urn:ietf:params:oauth:token-type:jwt</wst:TokenType>
        <wst:RequestedSecurityToken>
          <wsse:BinarySecurityToken xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" ValueType="urn:ietf:params:oauth:token-type:jwt">eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InN0cy1mNzA0NTI0MWU2YjAiLCJ4NXUiOiJodHRwczovLzEyNy4wLjAuMTozODA4MS9wa2kvY2hhaW4vZGVmYXVsdC84ZjFlMTljZmVlYzNkNTZjNDk5ODI1YjFlZjcwOTQ5NjExNjYxOTg0NjNiMTRlMzAxOTE0YmVmNTk1YzE5OWRjLnBlbSJ9.eyJpc3MiOiJ1cm46d3N0cnVzdDptb2NrOnN0cyIsInN1YiI6InVybjp1dWlkOjAxNmRjOGYxLTFiYzQtNTVkOS05NjU3LTliMmViYjNjZDRkMiIsIm5hbWUiOiJhbGljZSIsImlhdCI6MTc5MDExMDU4NiwiZXhwIjoxNzkwMTE0MTg2LCJqdGkiOiJOTW9Yd1I4Y0hIREdEcGQ2MkR6RlFGeHkiLCJhdWQiOiJodHRwczovL3JwLmV4YW1wbGUub3JnLyJ9.aYT6_coGff_o0wyWwCVBDEnGX3Jwdeh5GgrkigIOTsEZ-WOMvbkOk--emI4g6DTHhE4RLOq5l3ikvOLv4xoCIQQrubEQkPYNVFQlT_BAOUSaH2o79UhcU2T5-rminWuuUcl8H7eZqCoxfXs55hwV3kzkvpJuQ6Vm0SJCWPgZ3Ujvgu5ZvYGzknZMHLImOApwAraZ1N2l0IJF1eIIv0muykMbJPU_tg9szynaiVd1fWFTseYrX518C8svsQ_3p8iTSIgmGYEdwCf7G_pkG-UQwL2M0HYrJXwBZ2uUyGgL_nzTgxOjzxq_ph4kN0FuP2Da6JpOEKlLtol60lc225EQkQ</wsse:BinarySecurityToken>
        </wst:RequestedSecurityToken>
        <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wsa="http://www.w3.org/2005/08/addressing">
          <wsa:EndpointReference>
            <wsa:Address>https://rp.example.org/</wsa:Address>
          </wsa:EndpointReference>
        </wsp:AppliesTo>
        <wst:Lifetime xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
          <wsu:Created>2026-09-22T20:56:26.089Z</wsu:Created>
          <wsu:Expires>2026-09-22T21:56:26.090Z</wsu:Expires>
        </wst:Lifetime>
        <wst:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</wst:KeyType>
      </wst:RequestSecurityTokenResponse>
    </wst:RequestSecurityTokenResponseCollection>
  </soap:Body>
</soap:Envelope>
```
## Shared Signals: SSF, CAEP and RISC

Every Security Event Token (SET, [RFC 8417](https://www.rfc-editor.org/rfc/rfc8417))
is a JWT with `typ` `secevent+jwt`, signed with the realm key. The samples
below were collected over one poll stream
([RFC 8936](https://www.rfc-editor.org/rfc/rfc8936)). The receiver was a
client, `ssf-rx`, holding a `client_credentials` token with
`ssf:read ssf:write`:

```bash
curl -X POST https://127.0.0.1:38081/ssf/stream -H "Authorization: Bearer $SSF_TOKEN" \
  -H 'content-type: application/json' -d '{"delivery":{"method":"urn:ietf:rfc:8936"}}'
# PATCH /ssf/stream with events_requested = every entry of events_supported, then:
curl -X POST https://127.0.0.1:38081/ssf/poll -H "Authorization: Bearer $SSF_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"stream_id":"ssf-cMy49a2ttnFFG6ot","maxEvents":50,"returnImmediately":true}'
```

`aud` is the receiver's client id, which the transmitter assigns.
The header is the same on every SET:

```json
{
  "alg": "RS256",
  "typ": "secevent+jwt",
  "kid": "sts-f7045241e6b0",
  "x5u": "https://127.0.0.1:38081/pki/chain/default/8f1e19cfeec3d56c499825b1ef7094961166198463b14e301914bef595c199dc.pem"
}
```

Some of the events below were caused by real activity: a sign-in, a single
sign-on, a sign-out, an administrator setting a password, and disabling and
re-enabling an account. The rest were sent by hand with
`POST /admin-api/ssf/transmit`, because this service never emits them itself.
[CAEP events](caep-events.md) says which activity fires which event.

**Two issuers appear in these samples.** The events raised through
`/admin-api` (`credential-change`, `account-disabled`, `account-enabled`)
name the person as `iss` `https://127.0.0.1:8081`, which is the container's
internal listener, and not as the published issuer. That is a bug,
[#154](https://github.com/rcbj/iya-sts/issues/154). The samples are shown
as the service sent them.

### SSF

#### Verification

Sent on `POST /ssf/verify` (or the console's *Verify*). It carries `state` when the receiver sent one. Its subject is the stream itself.

```json
{
  "iss": "https://127.0.0.1:38081",
  "jti": "mnQjCurB2txPRWVRIDaJEA",
  "iat": 1790110571,
  "aud": "ssf-rx",
  "events": {
    "https://schemas.openid.net/secevent/ssf/event-type/verification": {}
  },
  "sub_id": {
    "format": "opaque",
    "id": "ssf-cMy49a2ttnFFG6ot"
  },
  "txn": "iZB_-Umc5JkSVGFNvJNTzw"
}
```

### CAEP

The three session events name a **complex subject**: the person as
`iss_sub` and the session as `opaque`. The session `id` and `ext_id` are
the `sid` of the ID Token above.

#### session-established

Fired by the sign-in at `/authn/login` during the authorization code flow above.

```json
{
  "iss": "https://127.0.0.1:38081",
  "jti": "VPXnmadXSJRyYbCV_ri_sA",
  "iat": 1790110476,
  "aud": "ssf-rx",
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/session-established": {
      "acr": "1",
      "amr": [
        "pwd"
      ],
      "ext_id": "sHiKmHBkOJ6bjKXM-TnFoHzZPEPIzHS7",
      "event_timestamp": 1790110476,
      "initiating_entity": "user",
      "reason_admin": {
        "en": "A session was created at OAuth 2.0 / OIDC."
      },
      "reason_user": {
        "en": "You signed in."
      }
    }
  },
  "sub_id": {
    "format": "complex",
    "user": {
      "format": "iss_sub",
      "iss": "https://127.0.0.1:38081",
      "sub": "urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2"
    },
    "session": {
      "format": "opaque",
      "id": "sHiKmHBkOJ6bjKXM-TnFoHzZPEPIzHS7"
    }
  },
  "txn": "9NRAdwIDAzNU4-8kbzCGFg",
  "toe": 1790110476
}
```

#### session-presented

Fired when an existing session answered a request without a new sign-in. This one is the WS-Federation sign-in above.

```json
{
  "iss": "https://127.0.0.1:38081",
  "jti": "BBa96owRaHR4UKAYycTLkQ",
  "iat": 1790110528,
  "aud": "ssf-rx",
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/session-presented": {
      "ext_id": "sHiKmHBkOJ6bjKXM-TnFoHzZPEPIzHS7",
      "event_timestamp": 1790110528,
      "initiating_entity": "user",
      "reason_admin": {
        "en": "An existing session was presented at WS-Federation and honoured without a new authentication."
      },
      "reason_user": {
        "en": "You are still signed in."
      }
    }
  },
  "sub_id": {
    "format": "complex",
    "user": {
      "format": "iss_sub",
      "iss": "https://127.0.0.1:38081",
      "sub": "urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2"
    },
    "session": {
      "format": "opaque",
      "id": "sHiKmHBkOJ6bjKXM-TnFoHzZPEPIzHS7"
    }
  },
  "txn": "7iQf_1gihJMXVEC1qn6-9A",
  "toe": 1790110528
}
```

#### session-revoked

Fired by `POST /logout`.

```json
{
  "iss": "https://127.0.0.1:38081",
  "jti": "s4pCl7gHfZGd1XlkR9nOrA",
  "iat": 1790110536,
  "aud": "ssf-rx",
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
      "event_timestamp": 1790110536,
      "initiating_entity": "user",
      "reason_admin": {
        "en": "The session was ended at /logout, on its own session."
      },
      "reason_user": {
        "en": "You have been signed out."
      }
    }
  },
  "sub_id": {
    "format": "complex",
    "user": {
      "format": "iss_sub",
      "iss": "https://127.0.0.1:38081",
      "sub": "urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2"
    },
    "session": {
      "format": "opaque",
      "id": "sHiKmHBkOJ6bjKXM-TnFoHzZPEPIzHS7"
    }
  },
  "txn": "3oL4KMucm0QVAfk09q8Uhw",
  "toe": 1790110536
}
```

#### credential-change

Fired by `POST /admin-api/users/set-password`.

```json
{
  "iss": "https://127.0.0.1:38081",
  "jti": "nBdeGRGur0rpfSbxw3tV2g",
  "iat": 1790110559,
  "aud": "ssf-rx",
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/credential-change": {
      "credential_type": "password",
      "change_type": "update",
      "event_timestamp": 1790110559,
      "initiating_entity": "admin",
      "reason_admin": {
        "en": "An administrator set the password of alice."
      },
      "reason_user": {
        "en": "Your password was changed by an administrator."
      }
    }
  },
  "sub_id": {
    "format": "complex",
    "user": {
      "format": "iss_sub",
      "iss": "https://127.0.0.1:8081",
      "sub": "urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2"
    }
  },
  "txn": "a4Jfe1Nf6ld5wf5ZPM0OwQ",
  "toe": 1790110559
}
```

#### assurance-level-change

Sent by hand here. The service sends it itself when a re-authentication on a held session moves its `acr`.

```json
{
  "iss": "https://127.0.0.1:38081",
  "jti": "NSe-3rAIDD7P8kUM4zYDbQ",
  "iat": 1790110571,
  "aud": "ssf-rx",
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change": {
      "namespace": "NIST-AAL",
      "current_level": "nist-aal2",
      "previous_level": "nist-aal1",
      "change_direction": "increase"
    }
  },
  "sub_id": {
    "format": "email",
    "email": "alice@example.com"
  },
  "txn": "pBA_-Oe8CPZhzB4HXKQO1A"
}
```

#### token-claims-change

Sent by hand here. The service sends it itself only when a GNAP grant is modified.

```json
{
  "iss": "https://127.0.0.1:38081",
  "jti": "pQOOOm99qLRUKLMRNrdn3w",
  "iat": 1790110571,
  "aud": "ssf-rx",
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/token-claims-change": {
      "claims": {
        "role": "auditor"
      }
    }
  },
  "sub_id": {
    "format": "email",
    "email": "alice@example.com"
  },
  "txn": "JuweC6L-kRdQGgOm-mzRew"
}
```

#### device-compliance-change

By hand only. This service knows nothing about devices.

```json
{
  "iss": "https://127.0.0.1:38081",
  "jti": "Lh8h4QKp7UjdfHydmyr7Ag",
  "iat": 1790110571,
  "aud": "ssf-rx",
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change": {
      "previous_status": "compliant",
      "current_status": "not-compliant"
    }
  },
  "sub_id": {
    "format": "email",
    "email": "alice@example.com"
  },
  "txn": "CsKS0c0rsxlvOlswIJ4w0A"
}
```

#### risk-level-change

By hand only.

```json
{
  "iss": "https://127.0.0.1:38081",
  "jti": "Qd5oy6GTEMoB-z4tqiAjDg",
  "iat": 1790110571,
  "aud": "ssf-rx",
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/risk-level-change": {
      "risk_reason": "PASSWORD_FOUND_IN_DATA_BREACH",
      "principal": "USER",
      "current_level": "HIGH",
      "previous_level": "LOW"
    }
  },
  "sub_id": {
    "format": "email",
    "email": "alice@example.com"
  },
  "txn": "pdpXvtZKBbs3zghHf3edDA"
}
```

### RISC

#### account-disabled

Fired by `POST /admin-api/users/disable`. `reason` is RISC's own vocabulary (`hijacking` or `bulk-account`), not the reason the administrator typed.

```json
{
  "iss": "https://127.0.0.1:38081",
  "jti": "KpKt8ECvyQk3im11paKRag",
  "iat": 1790110559,
  "aud": "ssf-rx",
  "events": {
    "https://schemas.openid.net/secevent/risc/event-type/account-disabled": {
      "reason": "hijacking"
    }
  },
  "sub_id": {
    "format": "iss_sub",
    "iss": "https://127.0.0.1:8081",
    "sub": "urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2"
  },
  "txn": "_EnfF5XOyfQ4MzP6-NDFUg"
}
```

#### account-enabled

Fired by `POST /admin-api/users/enable`.

```json
{
  "iss": "https://127.0.0.1:38081",
  "jti": "x03WcUA4TYZBVm84NypZDA",
  "iat": 1790110559,
  "aud": "ssf-rx",
  "events": {
    "https://schemas.openid.net/secevent/risc/event-type/account-enabled": {}
  },
  "sub_id": {
    "format": "iss_sub",
    "iss": "https://127.0.0.1:8081",
    "sub": "urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2"
  },
  "txn": "W6rAiUdeXzKbZSx95lsg7w"
}
```

#### credential-compromise

Sent by hand, with an `email` subject.

```json
{
  "iss": "https://127.0.0.1:38081",
  "jti": "YpW-W746iSJ_q258fXPMPw",
  "iat": 1790110571,
  "aud": "ssf-rx",
  "events": {
    "https://schemas.openid.net/secevent/risc/event-type/credential-compromise": {
      "credential_type": "password",
      "reason_admin": {
        "en": "Found in a public breach corpus"
      }
    }
  },
  "sub_id": {
    "format": "email",
    "email": "alice@example.com"
  },
  "txn": "4cSRX3kV7qfrJq7-F59yaA"
}
```

#### account-credential-change-required

Sent by hand.

```json
{
  "iss": "https://127.0.0.1:38081",
  "jti": "Rf1xRliQ4DQI0DhDO1T9eQ",
  "iat": 1790110571,
  "aud": "ssf-rx",
  "events": {
    "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required": {}
  },
  "sub_id": {
    "format": "email",
    "email": "alice@example.com"
  },
  "txn": "4tLrbUmuf5-X4E8Q1k9l1g"
}
```

#### identifier-changed

Sent by hand.

```json
{
  "iss": "https://127.0.0.1:38081",
  "jti": "QSAMuGxUykMMhasLwaunog",
  "iat": 1790110571,
  "aud": "ssf-rx",
  "events": {
    "https://schemas.openid.net/secevent/risc/event-type/identifier-changed": {
      "new-value": "alice.new@example.com"
    }
  },
  "sub_id": {
    "format": "email",
    "email": "alice@example.com"
  },
  "txn": "9cGK_HN1GDiXOp9duG_Biw"
}
```

The stream also offers the rest of RISC: `account-purged`,
`identifier-recycled`, `opt-in`, the three `opt-out-*` events,
`recovery-activated`, `recovery-information-changed` and `sessions-revoked`.
It offers `urn:iya:sts:secevent:event-type:signing-key-rotated`, this
service's own event, too. `GET /admin/risc` and `GET /admin-api/risc` list
what each carries.

## Verifiable credentials and status lists

Issued at `POST /oid4vci/credential` ([OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html))
with an access token and a holder key proof (`openid4vci-proof+jwt`, ES256,
the holder's public key in the header):

```bash
curl -X POST https://127.0.0.1:38081/oid4vci/nonce            # c_nonce for the proof
curl -X POST https://127.0.0.1:38081/oid4vci/credential \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'content-type: application/json' \
  -d '{"credential_configuration_id":"IdentityCredential","proofs":{"jwt":["<proof JWT>"]}}'
```

The claim values (Alice Anderson of Westerveld) are invented in development
mode.

### SD-JWT VC (`dc+sd-jwt`)

The issuer-signed JWT, then one `~`-separated **disclosure** per selectively
disclosable claim, then a trailing `~`. Each disclosure is
`[salt, name, value]`, and its SHA-256 is one of the `_sd` digests. There is
one more digest than disclosures because a decoy is added. `cnf.jwk` is the
holder's key, which a presentation must prove.

*Encoded (shortened):*

```text
eyJhbGciOiJSUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsImtpZCI6InN0cy1m…3m3pJKQqQq-XHjPUIsPg~WyJGaEhsck1oWmJI…~WyJfejE3NjJtZjVk…~WyJCY0wtcGREX3dK…~WyJoWFh3U1hidkZi…~WyJlRUc2VS11NTR0…~WyJ3ZGFSOUhvc2xR…~
```

*Header:*

```json
{
  "alg": "RS256",
  "typ": "dc+sd-jwt",
  "kid": "sts-f7045241e6b0",
  "x5u": "https://127.0.0.1:38081/pki/chain/default/8f1e19cfeec3d56c499825b1ef7094961166198463b14e301914bef595c199dc.pem"
}
```

*Payload:*

```json
{
  "iss": "https://127.0.0.1:38081",
  "nbf": 1790110682,
  "exp": 1792702682,
  "vct": "urn:idptools:sd-jwt-vc:identity",
  "sub": "urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2",
  "cnf": {
    "jwk": {
      "kty": "EC",
      "x": "T56NwGCCM6FWeBpoJIXpVxASLzbxE9TkGJ29oO622CY",
      "y": "XFcU4uYxBhdq4G-tz_Z6HBNfRVcmuXjMlICdOSQaUhk",
      "crv": "P-256"
    }
  },
  "_sd_alg": "sha-256",
  "_sd": [
    "7-DGNIlsgYtNCIGq01d8U8qeE40t1hhuw0B2Qeay6gw",
    "SZR3t2JV4EIg5cGRnm-oE3h3l14Rv04pkbJDUVe4-R4",
    "_s37ZRac8qdhgXJcYZkKiJLp49qfpAtXdJBoe1l9JSs",
    "b-a5FduugSreiCYHR1sNCMUNbt_8MfriGBGvwLXbrBk",
    "dwKjCC17sqAbYZSD0uSKUbNctU46oR8XZIsjjmFtWFo",
    "lA810L3YgLw2-0PZTFGxeiOY5eOsKjT6lSMOhGoSQxc",
    "usOTLd-t5k8amUP5khn06KJKQ2mvr42FiifEEUojsmQ"
  ],
  "status": {
    "status_list": {
      "idx": 13809,
      "uri": "https://127.0.0.1:38081/oid4vci/status-lists/1"
    }
  },
  "iat": 1790110682
}
```

*Disclosures, decoded:*

```json
["FhHlrMhZbHKmcSYz45Ojjw", "given_name", "Alice"]
["_z1762mf5d_MaoA3X758ug", "family_name", "Anderson"]
["BcL-pdD_wJzfmjOVha7RYg", "email", "alice@example.com"]
["hXXwSXbvFbsQMC6seLYPtQ", "birthdate", "1967-11-16"]
["eEG6U-u54tmIlDtWSYBk8Q", "nationality", "NL"]
["wdaR9HoslQAJ6O-Dcsh2iA", "address", {"street_address": "891 Mock Lane", "locality": "Westerveld", "region": "Utrecht", "postal_code": "4395 LG", "country": "NL"}]
```

### W3C VC as a JWT (`jwt_vc_json`)

The VC Data Model 1.1 credential inside a `vc` claim. `credentialStatus`
points at the two Bitstring Status Lists, and `status` at the Token Status
List.

*Encoded (shortened):*

```text
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InN0cy1mNzA0NTI0…WrQRR1-UqEIz-GmtgeHA
```

*Header:*

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "sts-f7045241e6b0",
  "x5u": "https://127.0.0.1:38081/pki/chain/default/8f1e19cfeec3d56c499825b1ef7094961166198463b14e301914bef595c199dc.pem"
}
```

*Payload:*

```json
{
  "iss": "https://127.0.0.1:38081",
  "sub": "urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2",
  "nbf": 1790110682,
  "exp": 1792702682,
  "jti": "urn:uuid:7d806f49-86f8-4170-a75c-bce9a9e8622f",
  "cnf": {
    "jwk": {
      "kty": "EC",
      "x": "T56NwGCCM6FWeBpoJIXpVxASLzbxE9TkGJ29oO622CY",
      "y": "XFcU4uYxBhdq4G-tz_Z6HBNfRVcmuXjMlICdOSQaUhk",
      "crv": "P-256"
    }
  },
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1"
    ],
    "type": [
      "VerifiableCredential",
      "IdentityCredential"
    ],
    "issuer": "https://127.0.0.1:38081",
    "issuanceDate": "2026-09-22T20:58:02.000Z",
    "expirationDate": "2026-10-22T20:58:02.000Z",
    "credentialSubject": {
      "id": "urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2",
      "given_name": "Alice",
      "family_name": "Anderson",
      "email": "alice@example.com",
      "birthdate": "1967-11-16",
      "nationality": "NL",
      "address": {
        "street_address": "891 Mock Lane",
        "locality": "Westerveld",
        "region": "Utrecht",
        "postal_code": "4395 LG",
        "country": "NL"
      }
    },
    "credentialStatus": [
      {
        "id": "https://127.0.0.1:38081/oid4vci/status-lists/bitstring/revocation#14156",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": "14156",
        "statusListCredential": "https://127.0.0.1:38081/oid4vci/status-lists/bitstring/revocation"
      },
      {
        "id": "https://127.0.0.1:38081/oid4vci/status-lists/bitstring/suspension#14156",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "suspension",
        "statusListIndex": "14156",
        "statusListCredential": "https://127.0.0.1:38081/oid4vci/status-lists/bitstring/suspension"
      }
    ]
  },
  "status": {
    "status_list": {
      "idx": 14156,
      "uri": "https://127.0.0.1:38081/oid4vci/status-lists/1"
    }
  },
  "iat": 1790110682
}
```

### W3C VC with a Data Integrity proof (`ldp_vc`)

VC Data Model 2.0, JSON-LD, signed with a `bbs-2023` Data Integrity proof so
a holder can derive a selective-disclosure proof from it. The subject `id` is
the holder's key as a `did:jwk`.

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://idptools.com/contexts/identity/v1"
  ],
  "type": [
    "VerifiableCredential",
    "IdentityCredential"
  ],
  "issuer": "https://127.0.0.1:38081",
  "validFrom": "2026-09-22T20:58:09.000Z",
  "validUntil": "2026-10-22T20:58:09.000Z",
  "credentialSubject": {
    "id": "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImowZ09DTkVsTGMzbVpZdjBlVHVIVDlFVno3N2NzdW1rQ0tDd2cxODJMM0EiLCJ5IjoiU05tUUtLMlNRbFlCSXZmcE5ST2xnaXJ3NEtFQ2F6R1FJaVdTbDU4WThMbyJ9",
    "given_name": "Alice",
    "family_name": "Anderson",
    "email": "alice@example.com",
    "birthDate": "1967-11-16",
    "nationality": "NL",
    "streetAddress": "891 Mock Lane",
    "locality": "Westerveld",
    "region": "Utrecht",
    "country": "NL"
  },
  "credentialStatus": [
    {
      "id": "https://127.0.0.1:38081/oid4vci/status-lists/bitstring/revocation#96646",
      "type": "BitstringStatusListEntry",
      "statusPurpose": "revocation",
      "statusListIndex": "96646",
      "statusListCredential": "https://127.0.0.1:38081/oid4vci/status-lists/bitstring/revocation"
    },
    {
      "id": "https://127.0.0.1:38081/oid4vci/status-lists/bitstring/suspension#96646",
      "type": "BitstringStatusListEntry",
      "statusPurpose": "suspension",
      "statusListIndex": "96646",
      "statusListCredential": "https://127.0.0.1:38081/oid4vci/status-lists/bitstring/suspension"
    }
  ],
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "bbs-2023",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "https://127.0.0.1:38081/bbs/keys/bbs-urHoxY0-JItkTvDkQZ7ODM",
    "created": "2026-09-22T20:58:09.000Z",
    "proofValue": "ulY6hpQE-w5iRcHt3KOvIMbcbTpPB-cX7gXT7bedR_amgyOL79FwXBe2PUEL6v4MKRhm_ugm1V-yq9kPZ6n03-c4Z-V_1rLYUzQzEshX8qNk"
  }
}
```

### Token Status List (`statuslist+jwt`)

`GET /oid4vci/status-lists/1`. `lst` is the zlib-compressed, base64url list,
`bits` per credential. The credential's `status.status_list.idx` is its
position in the list.

*Encoded (shortened):*

```text
eyJhbGciOiJSUzI1NiIsInR5cCI6InN0YXR1c2xpc3Qrand0Iiwia2lkIjoi…8K4IZIeEwJ2vrHB0woGw
```

*Header:*

```json
{
  "alg": "RS256",
  "typ": "statuslist+jwt",
  "kid": "sts-f7045241e6b0",
  "x5u": "https://127.0.0.1:38081/pki/chain/default/8f1e19cfeec3d56c499825b1ef7094961166198463b14e301914bef595c199dc.pem"
}
```

*Payload:*

```json
{
  "sub": "https://127.0.0.1:38081/oid4vci/status-lists/1",
  "iat": 1790110695,
  "exp": 1790197095,
  "ttl": 300,
  "status_list": {
    "bits": 2,
    "lst": "eNrtwQEBAAAAgJD-r-4ICgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYgAAAAQ",
    "aggregation_uri": "https://127.0.0.1:38081/oid4vci/status-lists"
  }
}
```

### Bitstring Status List credential (`vc+jwt`)

`GET /oid4vci/status-lists/bitstring/revocation` (and `…/suspension`).
`encodedList` is the multibase, GZIP-compressed bitstring.

*Encoded (shortened):*

```text
eyJhbGciOiJSUzI1NiIsInR5cCI6InZjK2p3dCIsImtpZCI6InN0cy1mNzA0…MndHy4ilnGEWuBI8aBqg
```

*Header:*

```json
{
  "alg": "RS256",
  "typ": "vc+jwt",
  "kid": "sts-f7045241e6b0",
  "x5u": "https://127.0.0.1:38081/pki/chain/default/8f1e19cfeec3d56c499825b1ef7094961166198463b14e301914bef595c199dc.pem",
  "cty": "vc"
}
```

*Payload:*

```json
{
  "iat": 1790110695,
  "@context": [
    "https://www.w3.org/ns/credentials/v2"
  ],
  "id": "https://127.0.0.1:38081/oid4vci/status-lists/bitstring/revocation",
  "type": [
    "VerifiableCredential",
    "BitstringStatusListCredential"
  ],
  "issuer": "https://127.0.0.1:38081",
  "validFrom": "2026-09-22T20:58:15.730Z",
  "validUntil": "2026-09-23T20:58:15.730Z",
  "credentialSubject": {
    "id": "https://127.0.0.1:38081/oid4vci/status-lists/bitstring/revocation#list",
    "type": "BitstringStatusList",
    "statusPurpose": "revocation",
    "encodedList": "uH4sIAAAAAAACA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA",
    "ttl": 300000
  }
}
```

### OpenID4VP request object (`oauth-authz-req+jwt`)

This service's verifier asks a wallet for a presentation with a signed
request object, passed by reference
([OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html),
RFC 9101). `GET /oid4vp/start?by=reference` sends the browser to the wallet
with `request_uri`, and the wallet fetches the object from
`/oid4vp/request/{id}`. The query is DCQL. The long algorithm lists in
`client_metadata` are shortened here.

*Encoded (shortened):*

```text
eyJhbGciOiJSUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QiLCJr…5TwyyUHNDoTzk47sXpyw
```

*Header:*

```json
{
  "alg": "RS256",
  "typ": "oauth-authz-req+jwt",
  "kid": "sts-f7045241e6b0",
  "x5u": "https://127.0.0.1:38081/pki/chain/default/8f1e19cfeec3d56c499825b1ef7094961166198463b14e301914bef595c199dc.pem"
}
```

*Payload:*

```json
{
  "typ": "oauth-authz-req+jwt",
  "iss": "sts-verifier",
  "aud": "https://self-issued.me/v2",
  "iat": 1790111229,
  "exp": 1790111829,
  "client_id": "sts-verifier",
  "response_type": "vp_token",
  "response_mode": "direct_post",
  "response_uri": "https://127.0.0.1:38081/oid4vp/response",
  "nonce": "nHqlPbFdh3r168UNnvQzRldQ",
  "state": "O4JHL3lpztGoKFXcpSlrGiRI",
  "dcql_query": {
    "credentials": [
      {
        "id": "identity_credential",
        "format": "dc+sd-jwt",
        "meta": {
          "vct_values": [
            "urn:idptools:sd-jwt-vc:identity"
          ]
        },
        "claims": [
          {
            "path": [
              "given_name"
            ]
          },
          {
            "path": [
              "family_name"
            ]
          }
        ]
      }
    ]
  },
  "client_metadata": {
    "client_name": "Mock Verifier (bar door)",
    "vp_formats_supported": {
      "dc+sd-jwt": {
        "sd-jwt_alg_values": [
          "RS256",
          "RS384",
          "RS512",
          "PS256",
          "… 18 more, post-quantum included"
        ],
        "kb-jwt_alg_values": [
          "RS256",
          "RS384",
          "RS512",
          "PS256",
          "… 18 more, post-quantum included"
        ]
      },
      "jwt_vc_json": {
        "alg_values": [
          "RS256",
          "RS384",
          "RS512",
          "PS256",
          "… 18 more, post-quantum included"
        ]
      },
      "ldp_vc": {
        "proof_type_values": [
          "DataIntegrityProof"
        ],
        "cryptosuite_values": [
          "bbs-2023",
          "ecdsa-jcs-2019",
          "eddsa-jcs-2022",
          "mldsa44-jcs-2024",
          "… 1 more, post-quantum included"
        ]
      }
    }
  }
}
```

### Domain Linkage Credential

[DIF Well Known DID Configuration](https://identity.foundation/.well-known/resources/did-configuration/).
`GET /.well-known/did-configuration.json` returns `linked_dids`, a list of JWT
credentials. Each one binds the realm's `did:web` to its origin, signed by
the key the DID document names in `kid`. The header has no `typ`, as the
specification's examples show.

*Encoded (shortened):*

```text
eyJhbGciOiJSUzI1NiIsImtpZCI6ImRpZDp3ZWI6MTI3LjAuMC4xJTNBMzgw…M2-thfMMaiN-NA01buFQ
```

*Header:*

```json
{
  "alg": "RS256",
  "kid": "did:web:127.0.0.1%3A38081#sts-f7045241e6b0"
}
```

*Payload:*

```json
{
  "iss": "did:web:127.0.0.1%3A38081",
  "sub": "did:web:127.0.0.1%3A38081",
  "nbf": 1790111229,
  "exp": 1821647229,
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://identity.foundation/.well-known/did-configuration/v1"
    ],
    "issuer": "did:web:127.0.0.1%3A38081",
    "issuanceDate": "2026-09-22T21:07:09.000Z",
    "expirationDate": "2027-09-22T21:07:09.000Z",
    "type": [
      "VerifiableCredential",
      "DomainLinkageCredential"
    ],
    "credentialSubject": {
      "id": "did:web:127.0.0.1%3A38081",
      "origin": "https://127.0.0.1:38081"
    }
  }
}
```

### Credential Offer and the pre-authorized code grant

*From the second start of the service (see the note at the top), so its keys differ from the samples above.*

`GET /issuer/offer?mode=cross-device` draws a QR code for
a Credential Offer that carries a **pre-authorized code**, plus a
Transaction Code (`tx_code`) shown on the page to type into the wallet.
In development mode the offer is for `oid4vci.offerUsername`
(`diploma.student`), for anybody who asks. The QR code holds:

```text
openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2F…rval%22%3A5%7D%7D%7D
```

*`credential_offer`, decoded:*

```json
{
  "credential_issuer": "https://127.0.0.1:38081",
  "credential_configuration_ids": [
    "IdentityCredential"
  ],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "pnX0EbzFOr_b9Mx4SI8LQFP0uewrC4uh",
      "tx_code": {
        "input_mode": "numeric",
        "length": 5,
        "description": "Type the 5-digit code shown by the issuer."
      },
      "interval": 5
    }
  }
}
```

The wallet redeems it at the token endpoint, and needs no client
authentication and no browser:

```bash
curl -X POST https://127.0.0.1:38081/oauth2/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code \
  -d pre-authorized_code=pnX0EbzFOr_b9Mx4SI8LQFP0uewrC4uh \
  -d tx_code=90757
```

*Issued access token payload:*

```json
{
  "iss": "https://127.0.0.1:38081",
  "sub": "",
  "aud": "https://127.0.0.1:38081/resource",
  "client_id": "",
  "typ": "Bearer",
  "jti": "ge_28dKJ77xm4FJRc0QjpA",
  "iat": 1790111821,
  "nbf": 1790111821,
  "exp": 1790115421,
  "username": "diploma.student",
  "scope": "identity_credential",
  "preferred_username": "diploma.student"
}
```

The empty `sub` and `client_id` are a bug,
[#158](https://github.com/rcbj/iya-sts/issues/158).

### Token Status List as a CWT (`statuslist+cwt`)

*From the second start of the service (see the note at the top), so its keys differ from the samples above.*

The same list as the `statuslist+jwt` above, asked for with
`Accept: application/statuslist+cwt`. It is a COSE_Sign1 (CBOR tag 18) and
516 bytes on the wire. In CBOR diagnostic notation, with the byte strings
shortened:

```text
== COSE_Sign1:
18([
  h'a20139010010781a6170706c69636174696f6e2f73746174…',
  {
    4: h'7374732d383532356132313866616665'
  },
  h'a502782e68747470733a2f2f3132372e302e302e313a3338…',
  h'80c518f1d0700d317dbd8fb0f031d01d2b823313dc549242…'
])
== protected header:
{
  1: -257,
  16: "application/statuslist+cwt"
}
== payload (CWT claims):
{
  2: "https://127.0.0.1:38081/oid4vci/status-lists/1",
  6: 1790111855,
  4: 1790198255,
  65534: 300,
  65533: {
    "bits": 2,
    "lst": h'78daedc101010000008090feafee080a0000000000000000…',
    "aggregation_uri": "https://127.0.0.1:38081/oid4vci/status-lists"
  }
}
```

The protected header's `1: -257` is RS256, and `16` is the COSE `typ`. The
unprotected `4` is the `kid` (`sts-8525a218fafe` as bytes). In the payload,
`2` is `sub`, `6` is `iat`, `4` is `exp`, `65534` is `ttl` and `65533` is
`status_list`, as the Token Status List draft registers them.

## GNAP access tokens

GNAP ([RFC 9635](https://www.rfc-editor.org/rfc/rfc9635)) mints all five
token formats that [RFC 9767](https://www.rfc-editor.org/rfc/rfc9767)
registers. Each sample came from a
*trusted* client (`gnapSkipInteraction`) whose application entry sets
`gnapAccessTokenFormat`, with a request signed by the client's ES256 key
(RFC 9421 HTTP message signatures):

```json
POST /gnap
{"client":{"key":{"proof":"httpsig","jwk":{…}}},
 "access_token":{"access":[{"type":"photo-api","actions":["read"],
                            "locations":["https://server.example.net/"]}]}}
```

*The grant response (the same shape for every format; `value` shortened):*

```json
{
  "instance_id": "J54DF-ILw6-vqJSzCvT4T9qj",
  "access_token": {
    "value": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ik…4Ssgn6IN5TfYAj-LyOpw",
    "access": [
      {
        "type": "photo-api",
        "actions": [
          "read"
        ],
        "locations": [
          "https://server.example.net/"
        ]
      }
    ],
    "expires_in": 3600,
    "manage": {
      "uri": "https://127.0.0.1:38081/gnap/token/iBBKdW3f7zLydoaN",
      "access_token": {
        "value": "AkHGlBseiXqlFhuJACFCtlbncsWs3NJT"
      }
    }
  },
  "continue": {
    "access_token": {
      "value": "Z0-4glFqjhKzQJrAlk5OdpPjakKwDGQG"
    },
    "uri": "https://127.0.0.1:38081/gnap/continue/CUvnTrawKo8DvEI5D3-_PtUR",
    "wait": 5
  }
}
```

Every format carries the same facts. These are the issuer, the audience (the
resource server), the client, the `access` array, the lifetime and the key
binding: the thumbprint of the client's key, so the token is useless without
that key's signature.

### `jwt-signed`

The header's `typ` is `JWT`, and `GNAP` is the payload's `typ` claim.
[GNAP](gnap.md) says otherwise, which is
[#157](https://github.com/rcbj/iya-sts/issues/157).

*Encoded (shortened):*

```text
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InN0cy1mNzA0NTI0…4Ssgn6IN5TfYAj-LyOpw
```

*Header:*

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "sts-f7045241e6b0",
  "x5u": "https://127.0.0.1:38081/pki/chain/default/8f1e19cfeec3d56c499825b1ef7094961166198463b14e301914bef595c199dc.pem"
}
```

*Payload:*

```json
{
  "typ": "GNAP",
  "iss": "https://127.0.0.1:38081/gnap",
  "jti": "C8l0zf7_-QfFjHw6zyaP1Q",
  "iat": 1790110754,
  "nbf": 1790110754,
  "exp": 1790114354,
  "client_id": "gnap-docs-jwt-signed",
  "access": [
    {
      "type": "photo-api",
      "actions": [
        "read"
      ],
      "locations": [
        "https://server.example.net/"
      ]
    }
  ],
  "aud": "https://127.0.0.1:38081/gnap/rs/resource",
  "cnf": {
    "jkt": "tW5j9hcg4YLCsPLrPSNOfQcPXW6g0hixgR072bGtsxA"
  }
}
```

### `jwt-encrypted`

The same JWT inside a JWE. This resource server registered no `gnapJweKey`,
so the JWE is `dir` / `A256GCM` under a key only this service holds, and the
resource server has to introspect it (`POST /gnap/introspect`).

*Encoded (shortened):*

```text
eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwidHlwIjoiSldUIiwiY3R5…Ky2h5NzIJtr9svmztCbQ
```

*JWE header:*

```json
{
  "alg": "dir",
  "enc": "A256GCM",
  "typ": "JWT",
  "cty": "JWT"
}
```

### `macaroon`

The V2 binary format (base64url here). It has a location, an identifier and
first-party **caveats**, chained with HMAC-SHA256 under a root key written to
the resource server's entry. The readable strings in it:

```text
https://127.0.0.1:38081/gnap
gnap:v1:2qB1s07g0s3nrrm25eA7PA
gnap:iss=https://127.0.0.1:38081/gnap
gnap:iat=1790110754
gnap:client=gnap-docs-macaroon
gnap:cnf=jkt:bEtFh2pdKik85DdLdhq2jq0xbyI9furqsd55VzLyOi0
gnap:exp<1790114354
gnap:nbf>=1790110754
gnap:aud=https://127.0.0.1:38081/gnap/rs/resource
gnap:access=W3sidHlwZSI6InBob3RvLWFwaSIsImFjdGlvbnMiOlsicmVhZCJdLCJsb2NhdGlvbnMiOlsiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5uZXQvIl19XQ
```

The last caveat's value is the `access` array as base64url JSON.

### `biscuit`

A Biscuit v2 token: Protobuf, signed with Ed25519, and carrying Datalog facts
and checks. The root public key is at `/gnap/keys`. The readable strings are
the facts' names and values:

```text
gnap_token
RYX5EJ9FytWzKkymD1SpMg
issuer
https://127.0.0.1:38081/gnap
issued_at
expires
not_before
audience
https://127.0.0.1:38081/gnap/rs/resource
client_instance
gnap-docs-biscuit
access
{"type":"photo-api","actions":["read"],"locations":["https://server.example.net/"]}
access_type
photo-api
access_action
access_location
https://server.example.net/
cnf_jkt
Yek_TrhX6tKam2k4iBqdTF4hAp-tQGp2uJbZkQp9I4c
presented_key
```

### `zcap`

A ZCAP-LD capability, base64url JSON on the wire. It has an `eddsa-jcs-2022`
Data Integrity proof (`gnap.zcapCryptosuite`) whose verification method is
in the controller document at `/gnap/zcap/controller`. The proof repeats the
capability's `@context`; it is shortened here.

```json
{
  "@context": [
    "https://w3id.org/zcap/v1",
    "https://w3id.org/security/data-integrity/v2",
    {
      "@version": 1.1,
      "gnap": "urn:ietf:params:gnap#",
      "gnapIssuer": "gnap:iss",
      "gnapSubject": "gnap:sub",
      "gnapAudience": {
        "@id": "gnap:aud",
        "@type": "@json"
      },
      "gnapClient": "gnap:client",
      "gnapAccess": {
        "@id": "gnap:access",
        "@type": "@json"
      },
      "gnapFlags": {
        "@id": "gnap:flags",
        "@type": "@json"
      },
      "gnapCnf": "gnap:cnf",
      "gnapLabel": "gnap:label",
      "gnapIssuedAt": {
        "@id": "gnap:iat",
        "@type": "@json"
      },
      "gnapNotBefore": {
        "@id": "gnap:nbf",
        "@type": "@json"
      }
    }
  ],
  "id": "urn:gnap:token:7FSZ8N98os2ljiljtHc1MQ",
  "parentCapability": "urn:zcap:root:https%3A%2F%2F127.0.0.1%3A38081%2Fgnap%2Frs%2Fresource",
  "invocationTarget": "https://127.0.0.1:38081/gnap/rs/resource",
  "controller": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:wwdCppya3lKAlSneLpSsl3cs7_x166BTjrGwJcxpPLs",
  "expires": "2026-09-22T21:59:14Z",
  "allowedAction": [
    "read"
  ],
  "gnapIssuer": "https://127.0.0.1:38081/gnap",
  "gnapAudience": [
    "https://127.0.0.1:38081/gnap/rs/resource"
  ],
  "gnapClient": "gnap-docs-zcap",
  "gnapAccess": [
    {
      "type": "photo-api",
      "actions": [
        "read"
      ],
      "locations": [
        "https://server.example.net/"
      ]
    }
  ],
  "gnapFlags": [],
  "gnapCnf": "jkt:wwdCppya3lKAlSneLpSsl3cs7_x166BTjrGwJcxpPLs",
  "gnapIssuedAt": 1790110754,
  "gnapNotBefore": 1790110754,
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2026-09-22T20:59:14Z",
    "verificationMethod": "https://127.0.0.1:38081/gnap/zcap/controller#sts-eddsa-6ed79092",
    "proofPurpose": "capabilityDelegation",
    "capabilityChain": [
      "urn:zcap:root:https%3A%2F%2F127.0.0.1%3A38081%2Fgnap%2Frs%2Fresource"
    ],
    "@context": "…the capability's @context, repeated…",
    "proofValue": "z4tcyp8xbdJgUAJb3GTmNB3xSUh4T2PeV25Xh8BqbAHo9Z3oR9AHfp335T5Lv8R84xBsHbiSM4vmjRwBQkCP6iysb"
  }
}
```
## SPIFFE SVIDs

From the SPIFFE Workload API over TCP (`spiffe.workloadPort`, 8092) with the
`workload.spiffe.io: true` metadata header. Development mode created a
registration entry for the unattested caller (`spiffe.autoCreateEntries`), so
the SPIFFE ID is `spiffe://example.org/workload`.

### JWT-SVID (`FetchJWTSVID`, audience `https://api.example.org`)

Signed with the trust domain's own JWT authority, which the trust bundle at
`GET /spiffe/bundle` publishes. It is not the OAuth key.

*Encoded (shortened):*

```text
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InNwaWZmZS1rbjZa…YaRAirn8opeoYFRuWX9A
```

*Header:*

```json
{
  "alg": "ES256",
  "typ": "JWT",
  "kid": "spiffe-kn6ZOo6KkJo4ix8i"
}
```

*Payload:*

```json
{
  "sub": "spiffe://example.org/workload",
  "aud": "https://api.example.org",
  "exp": 1790111092,
  "iat": 1790110792,
  "jti": "JlESUHZa0iSrOy07"
}
```

### X509-SVID (`FetchX509SVID`)

The SPIFFE ID is the only URI SAN. The subject is SPIRE's `C=US, O=SPIRE`,
the lifetime is one hour, and the issuer is the realm's *SPIFFE* Issuing CA.

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            78:ff:fc:21:b3:fb:0b:35:8d:ad:2d:8b:a2:39:35:1f
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN = sts SPIFFE Issuing CA (default), O = sts
        Validity
            Not Before: Sep 22 20:59:52 2026 GMT
            Not After : Sep 22 21:59:52 2026 GMT
        Subject: C = US, O = SPIRE
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage:
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Alternative Name:
                URI:spiffe://example.org/workload
            X509v3 Subject Key Identifier:
                4B:1A:F6:5F:85:85:D2:FC:BC:10:8B:0B:A3:CE:CB:14:4D:93:27:BE
            X509v3 Authority Key Identifier:
                ED:DA:84:A3:4A:E2:BD:B5:A9:A5:5E:D7:92:D6:31:D3:37:1E:18:EA
```
## X.509 certificates, CRLs and OCSP

Everything hangs from one Root CA, with an Intermediate per realm and an
Issuing CA per use ([PKI](pki.md)). Each leaf carries its CRL distribution
points (HTTP and LDAP) and an OCSP responder in its AIA. Those point at the
plain-HTTP revocation listener (`pki.httpPort`, 8082). A container is told its
published name and ports with `pki.distributionBaseUrl` and
`pki.distributionPort`; this one was not, so its certificates say
`localhost:8082`.

### Root CA

`GET /pki/ca/service/root.cer` (DER). Self-signed, valid for twenty years.

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            68:ee:8f:0f:cb:40:8b:34:17:43:a9:13:06:57:4f:90
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = sts Root CA, O = sts
        Validity
            Not Before: Sep 22 20:54:03 2026 GMT
            Not After : Sep 22 20:54:03 2046 GMT
        Subject: CN = sts Root CA, O = sts
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier:
                C0:37:CA:95:27:CC:AD:3E:B0:24:60:A5:C4:C0:94:32:B9:35:3B:29
            X509v3 Authority Key Identifier:
                C0:37:CA:95:27:CC:AD:3E:B0:24:60:A5:C4:C0:94:32:B9:35:3B:29
```

### JOSE signing certificate (the key behind every JWT above)

The first certificate in the `x5u` chain of every JWT on this page.
`GET /pki/chain/default/{sha256}.pem` returns the leaf, the *JOSE Signing* CA,
the realm's Intermediate and the Root:

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            02:60:d0:8e:90:c2:88:75:2c:17:13:fd:94:a0:5c:0b
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = sts JOSE Signing CA (default), O = sts
        Validity
            Not Before: Sep 22 20:54:03 2026 GMT
            Not After : Sep 22 20:54:03 2027 GMT
        Subject: CN = JOSE signing (RS256), O = sts
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature, Non Repudiation, Key Encipherment
            X509v3 Subject Key Identifier:
                45:AA:BC:A0:E7:DA:28:62:D0:A3:4B:BF:C5:52:0E:EB:48:B9:CC:0C
            X509v3 Authority Key Identifier:
                BB:75:B0:19:EE:21:22:E5:55:1C:26:E5:56:68:8D:CB:B2:5A:F9:1B
            X509v3 CRL Distribution Points:
                Full Name:
                  URI:http://localhost:8082/pki/crl/default/jose.crl
                Full Name:
                  URI:ldap://localhost:389/cn=jose,ou=crl,dc=example,dc=com?certificateRevocationList;binary
            Authority Information Access:
                OCSP - URI:http://localhost:8082/pki/ocsp/default/jose
                CA Issuers - URI:http://localhost:8082/pki/ca/default/jose.cer
```

### TLS server certificate

What the main port presents, issued by the *TLS* Issuing CA under the
process Intermediate. The same certificate is served on LDAPS 636 and the
debugger's listener.

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            10:55:f5:57:f5:4c:a6:39:7e:b6:81:b7:11:3c:22:19
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = sts TLS Issuing CA (Process), O = sts
        Validity
            Not Before: Sep 22 20:54:03 2026 GMT
            Not After : Sep 22 20:54:03 2027 GMT
        Subject: CN = localhost, O = sts
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            X509v3 Subject Alternative Name:
                DNS:localhost, DNS:sts, DNS:sts-mock, DNS:sts.example.com, IP Address:127.0.0.1
            X509v3 Subject Key Identifier:
                03:2C:D5:97:BE:63:EB:5D:AC:12:91:6E:E4:F8:5C:7A:2B:B7:72:06
            X509v3 Authority Key Identifier:
                F5:A0:A6:C7:CA:81:F0:2E:F3:07:2F:B3:EF:46:57:C5:9D:66:D5:00
            X509v3 CRL Distribution Points:
                Full Name:
                  URI:http://localhost:8082/pki/crl/process/tls.crl
                Full Name:
                  URI:ldap://localhost:389/cn=tls,ou=process,ou=crl,dc=example,dc=com?certificateRevocationList;binary
            Authority Information Access:
                OCSP - URI:http://localhost:8082/pki/ocsp/process/tls
                CA Issuers - URI:http://localhost:8082/pki/ca/process/tls.cer
```

### A certificate issued over EST

`POST /.well-known/est/simpleenroll` with a PKCS#10 request for `CN=alice` and
Basic authentication as `alice`. The response is a base64 PKCS#7
`certs-only`. The subject is built from the directory entry, not from the
request. The SAN is the person's URN, and the EKU is client authentication.
ACME and SCEP issue from the same core, under their own Issuing CAs.

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout alice.key -subj /CN=alice -outform DER | base64 -w0 > alice.csr.b64
curl -u alice:x -X POST https://127.0.0.1:38081/.well-known/est/simpleenroll \
  -H 'content-type: application/pkcs10' -H 'content-transfer-encoding: base64' \
  --data-binary @alice.csr.b64
```

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            74:62:05:25:d1:b7:85:5b:bd:fa:ab:e3:57:64:d1:bc
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = sts EST Issuing CA (default), O = sts
        Validity
            Not Before: Sep 22 21:00:11 2026 GMT
            Not After : Sep 22 21:00:11 2027 GMT
        Subject: CN = alice, O = sts
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Client Authentication
            X509v3 Subject Alternative Name:
                URI:urn:sts:person:alice
            X509v3 Subject Key Identifier:
                DA:89:A9:EC:27:96:6B:C0:01:97:BC:EF:90:86:67:B2:89:01:79:DD
            X509v3 Authority Key Identifier:
                1F:F0:86:2A:DA:18:CA:69:6B:E0:69:7B:DF:E0:44:26:F8:67:CC:F0
            X509v3 CRL Distribution Points:
                Full Name:
                  URI:http://localhost:8082/pki/crl/default/est.crl
                Full Name:
                  URI:ldap://localhost:389/cn=est,ou=crl,dc=example,dc=com?certificateRevocationList;binary
            Authority Information Access:
                OCSP - URI:http://localhost:8082/pki/ocsp/default/est
                CA Issuers - URI:http://localhost:8082/pki/ca/default/est.cer
```

### A certificate issued over ACME

*From the second start of the service (see the note at the top), so its keys differ from the samples above.*

ACME (RFC 8555) at `/enroll/acme/directory`. The account
is bound for life to a person or application by an External Account Binding
key (`POST /admin-api/acme/create-eab`, or the person's own at
`/portal/certificates`). The identifier here is a `permanent-identifier` naming
the person, so the order is `ready` at once and there is
no challenge to answer. A DNS name has to be registered on the entry first.
The certificate profile is chosen with the order's `profile` member,
from the nine the directory lists in `meta.profiles`.

*The order, and the order after `finalize`:*

```json
{
  "order": {
    "status": "ready",
    "expires": "2026-09-23T21:12:32.630Z",
    "identifiers": [
      {
        "type": "permanent-identifier",
        "value": "alice"
      }
    ],
    "profile": "tls-client",
    "authorizations": [
      "https://127.0.0.1:38081/enroll/acme/authz/emm2U1PGnhNnGGaORM2_"
    ],
    "finalize": "https://127.0.0.1:38081/enroll/acme/order/T4w5dyfpcCBvRMFliJM6/finalize"
  },
  "finalized": {
    "status": "valid",
    "expires": "2026-09-23T21:12:32.630Z",
    "identifiers": [
      {
        "type": "permanent-identifier",
        "value": "alice"
      }
    ],
    "profile": "tls-client",
    "authorizations": [
      "https://127.0.0.1:38081/enroll/acme/authz/emm2U1PGnhNnGGaORM2_"
    ],
    "finalize": "https://127.0.0.1:38081/enroll/acme/order/T4w5dyfpcCBvRMFliJM6/finalize",
    "certificate": "https://127.0.0.1:38081/enroll/acme/cert/RWEdplGYTCybNVzCCn3Q"
  }
}
```

The download is `application/pem-certificate-chain`: the leaf, the ACME
Issuing CA and the realm Intermediate, without the Root. The leaf:

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            2c:d3:a1:51:d8:43:46:ca:2d:e8:b9:1d:a0:be:b5:f8
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = sts ACME Issuing CA (default), O = sts
        Validity
            Not Before: Sep 22 21:12:33 2026 GMT
            Not After : Dec 21 21:12:33 2026 GMT
        Subject: CN = alice, O = sts
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Client Authentication
            X509v3 Subject Alternative Name:
                URI:urn:sts:person:alice
            X509v3 Subject Key Identifier:
                BC:CB:60:16:A3:73:9A:DE:86:01:25:52:98:0C:53:C9:94:9B:51:E8
            X509v3 Authority Key Identifier:
                A6:07:AB:33:2A:83:86:FC:AA:9B:9A:4C:7B:0D:55:33:69:76:88:17
            X509v3 CRL Distribution Points:
                Full Name:
                  URI:http://localhost:8082/pki/crl/default/acme.crl
                Full Name:
                  URI:ldap://localhost:389/cn=acme,ou=crl,dc=example,dc=com?certificateRevocationList;binary
            Authority Information Access:
                OCSP - URI:http://localhost:8082/pki/ocsp/default/acme
                CA Issuers - URI:http://localhost:8082/pki/ca/default/acme.cer
```

### A certificate issued over SCEP

*From the second start of the service (see the note at the top), so its keys differ from the samples above.*

SCEP (RFC 8894) at `/enroll/scep`. The device gets the
RA certificate with `GetCACert`, then sends a `PKIOperation`. That is a CMS
SignedData, signed with a throwaway self-signed key, around an EnvelopedData
encrypted to the RA, which holds a PKCS#10 request with a **challenge
password**. The challenge is single-use, from
`POST /admin-api/scep/create-challenge` or the person's own at
`/portal/certificates`.

```json
{
  "id": "scep-p-YWxpY2U-2c0fbc7e1ca942e7",
  "challenge": "scep-p-YWxpY2U-2c0fbc7e1ca942e7.QmxDpVpDwaWEq32oBk_as8aOgDmjcPvr",
  "profile": "tls-client",
  "expiresAt": "2026-09-22T22:13:05.871Z",
  "target": {
    "kind": "person",
    "id": "alice"
  },
  "entryUri": "urn:sts:person:alice",
  "url": "https://127.0.0.1:38081/enroll/scep/tls-client"
}
```

The reply is a `CertRep`: a SignedData from the RA whose signed attributes
say `messageType` 3, `pkiStatus` 0 (SUCCESS), the request's
`transactionID`, and a `recipientNonce` echoing its `senderNonce`. Inside
is an EnvelopedData, encrypted back to the requester's self-signed key,
that holds a degenerate certs-only PKCS#7 with the certificate:

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            7a:65:f3:29:38:9d:9a:3b:77:82:3d:2e:78:fb:99:cb
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = sts SCEP Issuing CA (default), O = sts
        Validity
            Not Before: Sep 22 21:13:06 2026 GMT
            Not After : Sep 22 21:13:06 2027 GMT
        Subject: CN = alice, O = sts
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Client Authentication
            X509v3 Subject Alternative Name:
                URI:urn:sts:person:alice
            X509v3 Subject Key Identifier:
                7E:1B:D2:C2:3D:93:81:49:EF:FE:D4:4E:BA:35:98:19:2D:A1:1A:90
            X509v3 Authority Key Identifier:
                D4:0E:94:1F:62:A4:88:C3:44:7F:41:4A:C9:D3:D9:CC:99:0B:1C:E4
            X509v3 CRL Distribution Points:
                Full Name:
                  URI:http://localhost:8082/pki/crl/default/scep.crl
                Full Name:
                  URI:ldap://localhost:389/cn=scep,ou=crl,dc=example,dc=com?certificateRevocationList;binary
            Authority Information Access:
                OCSP - URI:http://localhost:8082/pki/ocsp/default/scep
                CA Issuers - URI:http://localhost:8082/pki/ca/default/scep.cer
```


### CRL

`GET http://localhost:8082/pki/crl/default/jose.crl` (DER), signed by the CA
it lists for. It lasts `pki.crlLifetimeMinutes` (60), and its CRL number is a
timestamp in milliseconds.

```text
Certificate Revocation List (CRL):
        Version 2 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = sts JOSE Signing CA (default), O = sts
        Last Update: Sep 22 20:57:34 2026 GMT
        Next Update: Sep 22 21:57:34 2026 GMT
        CRL extensions:
            X509v3 CRL Number:
                1790110654262
            X509v3 Authority Key Identifier:
                BB:75:B0:19:EE:21:22:E5:55:1C:26:E5:56:68:8D:CB:B2:5A:F9:1B
No Revoked Certificates.
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        …
```

### OCSP response

For the JOSE signing certificate, from that CA's responder
(`http://localhost:8082/pki/ocsp/default/jose`). The responder is the CA
itself, named by key hash, and it echoes the request's nonce.

```bash
openssl ocsp -issuer jose-ca.pem -cert jose-leaf.pem \
  -url http://localhost:8082/pki/ocsp/default/jose -resp_text
```

```text
OCSP Response Data:
    OCSP Response Status: successful (0x0)
    Response Type: Basic OCSP Response
    Version: 1 (0x0)
    Responder Id: BB75B019EE2122E5551C26E556688DCBB25AF91B
    Produced At: Sep 22 20:57:34 2026 GMT
    Responses:
    Certificate ID:
      Hash Algorithm: sha1
      Issuer Name Hash: 1964625C2BC22DA7BE4DE3CBCD13CBAFABDE23B9
      Issuer Key Hash: BB75B019EE2122E5551C26E556688DCBB25AF91B
      Serial Number: 0260D08E90C288752C1713FD94A05C0B
    Cert Status: good
    This Update: Sep 22 20:57:34 2026 GMT
    Next Update: Sep 22 21:57:34 2026 GMT

    Response Extensions:
        OCSP Nonce:
            0410766C8B3AF3B61BA5347C0AA115F1A96C
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        …
```
## Kerberos tickets, keytabs and SPNEGO

### Tickets

From the KDC on port 88 with MIT Kerberos. In development mode every user
shares one password, `password!` (`krb5.userPassword`). A ticket is ASN.1 DER.
Its `enc-part`, which holds the session key, the client name, the times and
the authorization data, is encrypted under the *service's* long-term key, so
only the service can read it.

```bash
# krb5.conf: [realms] EXAMPLE.COM = { kdc = <host>:88 }
kinit alice@EXAMPLE.COM          # AS-REQ  -> a TGT for krbtgt/EXAMPLE.COM
kvno HTTP/localhost@EXAMPLE.COM  # TGS-REQ -> a service ticket
klist -e -f
```

```text
Default principal: alice@EXAMPLE.COM

Valid starting       Expires              Service principal
09/22/2026 13:57:02  09/22/2026 23:57:02  krbtgt/EXAMPLE.COM@EXAMPLE.COM
	Flags: IA, Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96
09/22/2026 13:57:02  09/22/2026 23:57:02  HTTP/localhost@EXAMPLE.COM
	Flags: A, Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96
```

The service ticket for `HTTP/localhost`, as `openssl asn1parse` reads it.
It is `Ticket ::= [APPLICATION 1] SEQUENCE { tkt-vno [0] 5, realm [1],
sname [2] { name-type 1 (NT-PRINCIPAL), name-string }, enc-part [3] {
etype [0] 18 (aes256-cts-hmac-sha1-96), kvno [1] 3, cipher [2] } }`
([RFC 4120 section 5.3](https://www.rfc-editor.org/rfc/rfc4120#section-5.3)):

```text
    0:d=0  hl=4 l=1170 cons: appl [ 1 ]
    4:d=1  hl=4 l=1166 cons:  SEQUENCE
    8:d=2  hl=2 l=   3 cons:   cont [ 0 ]
   10:d=3  hl=2 l=   1 prim:    INTEGER           :05
   13:d=2  hl=2 l=  13 cons:   cont [ 1 ]
   15:d=3  hl=2 l=  11 prim:    GENERALSTRING  EXAMPLE.COM
   28:d=2  hl=2 l=  28 cons:   cont [ 2 ]
   30:d=3  hl=2 l=  26 cons:    SEQUENCE
   32:d=4  hl=2 l=   3 cons:     cont [ 0 ]
   34:d=5  hl=2 l=   1 prim:      INTEGER           :01
   37:d=4  hl=2 l=  19 cons:     cont [ 1 ]
   39:d=5  hl=2 l=  17 cons:      SEQUENCE
   41:d=6  hl=2 l=   4 prim:       GENERALSTRING  HTTP
   47:d=6  hl=2 l=   9 prim:       GENERALSTRING  localhost
   58:d=2  hl=4 l=1112 cons:   cont [ 3 ]
   62:d=3  hl=4 l=1108 cons:    SEQUENCE
   66:d=4  hl=2 l=   3 cons:     cont [ 0 ]
   68:d=5  hl=2 l=   1 prim:      INTEGER           :12
   71:d=4  hl=2 l=   3 cons:     cont [ 1 ]
   73:d=5  hl=2 l=   1 prim:      INTEGER           :03
   76:d=4  hl=4 l=1094 cons:     cont [ 2 ]
   80:d=5  hl=4 l=1090 prim:      OCTET STRING      [HEX DUMP]:93D80E21FD7CA924FF5486C8…
```

The same ticket, wrapped in an AP-REQ inside a SPNEGO token, is what a
browser sends to `/authn/spnego` in `Authorization: Negotiate …`; the
[SPNEGO tokens](#spnego-tokens) below show one.

### Keytab

*From the second start of the service (see the note at the top), so its keys differ from the samples above.*

An MIT keytab for a service principal, returned once
(base64) when an administrator creates or rotates it:

```bash
curl -X POST https://127.0.0.1:38081/admin-api/kerberos/principals/create-service \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' \
  -d '{"spn":"HTTP/app.example.com"}'
# .keytab is base64 in the reply; decode it, then:
klist -k -t -e -K HTTP_app.example.com.kvno3.keytab
```

```text
Keytab name: FILE:HTTP_app.example.com.kvno3.keytab
KVNO Timestamp           Principal
---- ------------------- ------------------------------------------------------
   3 09/22/2026 14:14:31 HTTP/app.example.com@EXAMPLE.COM (aes256-cts-hmac-sha1-96)  (0x3abb449a2e9a…)
   3 09/22/2026 14:14:31 HTTP/app.example.com@EXAMPLE.COM (aes128-cts-hmac-sha1-96)  (0x0b956665c16e…)
   3 09/22/2026 14:14:31 HTTP/app.example.com@EXAMPLE.COM (aes256-cts-hmac-sha384-192)  (0x160e0c189bb0…)
   3 09/22/2026 14:14:31 HTTP/app.example.com@EXAMPLE.COM (aes128-cts-hmac-sha256-128)  (0xf656e6175626…)
   3 09/22/2026 14:14:31 HTTP/app.example.com@EXAMPLE.COM (DEPRECATED:arcfour-hmac)  (0xd37871190f92…)
```

The key version is `krb5.kvno` (3) for every principal built from
configuration. One key per `krb5.enctypes` entry. The list includes RC4 by
default in development mode, as above; in product mode it never does, and no
keytab carries an RC4 key there
([#182](https://github.com/rcbj/iya-sts/issues/182)).

### SPNEGO tokens

*From the second start of the service (see the note at the top), so its keys differ from the samples above.*

`curl --negotiate` against `/spnego/protected`, with a
TGT from `kinit` as above. The request's `Authorization: Negotiate` carries
a **NegTokenInit** (RFC 4178) wrapping the Kerberos AP-REQ:

```text
    0:d=0  hl=4 l=1470 cons: appl [ 0 ]
    4:d=1  hl=2 l=   6 prim:  OBJECT            :1.3.6.1.5.5.2
   12:d=1  hl=4 l=1458 cons:  cont [ 0 ]
   16:d=2  hl=4 l=1454 cons:   SEQUENCE
   20:d=3  hl=2 l=  13 cons:    cont [ 0 ]
   22:d=4  hl=2 l=  11 cons:     SEQUENCE
   24:d=5  hl=2 l=   9 prim:      OBJECT            :1.2.840.113554.1.2.2
   35:d=3  hl=4 l=1435 cons:    cont [ 2 ]
   39:d=4  hl=4 l=1431 prim:     OCTET STRING      [HEX DUMP]:6082059306092A864886F71201020201006E8205…
```

`1.3.6.1.5.5.2` is SPNEGO and `1.2.840.113554.1.2.2` is the Kerberos
mechanism. The octet string is the GSS-wrapped AP-REQ, which holds the
service ticket for `HTTP/localhost`. The 200 response's
`WWW-Authenticate: Negotiate` carries a **NegTokenResp**: `negState` 0
(accept-completed), the mechanism, the AP-REP for mutual authentication, and
a `mechListMIC`:

```text
    0:d=0  hl=3 l= 215 cons: cont [ 1 ]
    3:d=1  hl=3 l= 212 cons:  SEQUENCE
    6:d=2  hl=2 l=   3 cons:   cont [ 0 ]
    8:d=3  hl=2 l=   1 prim:    ENUMERATED        :00
   11:d=2  hl=2 l=  11 cons:   cont [ 1 ]
   13:d=3  hl=2 l=   9 prim:    OBJECT            :1.2.840.113554.1.2.2
   24:d=2  hl=3 l= 159 cons:   cont [ 2 ]
   27:d=3  hl=3 l= 156 prim:    OCTET STRING      [HEX DUMP]:60819906092A864886F71201020202006F818930…
  186:d=2  hl=2 l=  30 cons:   cont [ 3 ]
  188:d=3  hl=2 l=  28 prim:    OCTET STRING      [HEX DUMP]:040405FFFFFFFFFF0000000000000000CFC78F39…
```

## Second factors: TOTP and recovery codes

*From the second start of the service (see the note at the top), so its keys differ from the samples above.*

Neither is a token a client sees. They are secrets a
**person** is shown once, on `/portal/mfa`, after signing in to the portal.

### TOTP secret (RFC 6238)

*Set one up* shows a QR code and the same values for typing in by hand.
Nothing is stored until a code computed from the secret is typed back.
This one was confirmed with a code computed from the secret below:

```text
Secret     OFCZ JCEU QJ4E DKF3 V3HD 3CDI NI6P Q6BZ   (base32, 160 bits)
Account    alice
Issuer     127.0.0.1:38081 (default)
Type       Time based
Algorithm  HMAC-SHA-1
Digits     6
Period     30 seconds
```

The QR code is drawn on the server as SVG, and encodes the same values as
an `otpauth://totp/…` key URI.

### Recovery codes

*Generate recovery codes* shows a set of ten, once. It is stored only when
the person confirms, and then only as one scrypt hash per code. Each code
works once, in place of the second factor. Dashes and case are ignored.

```text
27RIH-VXXXL  2B2DC-QAURI  2EOBM-YYFIF  SWVG7-HA4KP  G2CPX-EO426
ANIX7-K46ZZ  TZ3QJ-PFAKS  76PY3-OZFXB  QIF7B-OSI3G  JS54N-7PT4F
```

## Opaque values

Some things this service issues are deliberately **not** self-describing.
They are random handles to a record on the server, and decoding one tells a
client nothing:

| Value | Sample | Where |
|---|---|---|
| OAuth authorization code | `qVqFgarG41wqzJk_HdOcC9ZJoLT5iY4A` | the `code` on the redirect back to the client |
| Stream id (SSF) | `ssf-cMy49a2ttnFFG6ot` | `POST /ssf/stream` |
| GNAP token management access token | `AkHGlBseiXqlFhuJACFCtlbncsWs3NJT` | `access_token.manage` in a grant response |
| PAR `request_uri` (RFC 9126), *second start* | `urn:ietf:params:oauth:request_uri:pvwZ_Imv1VRnaDzuj1o-5eGh4TLepK1VaMHCjmSIWf4` | `POST /oauth2/par`; lives 60 seconds and is spent at `/oauth2/authorize` |
| Client secret, *second start* | `n7_Cj7ojyhHHACI1J2IR7Kj9B9XIt_3K` | `POST /oauth2/register` with `client_secret_basic` |
| Registration access token (RFC 7592), *second start* | `lSSLd0otQHaXcF8OPP4Byjys_yc6J60o` | the same response, for `GET`/`PUT`/`DELETE` on `registration_client_uri` |
| OpenID4VCI `c_nonce`, *second start* | `SL6XJugFSq0gDJHubS2J3Foc2lxdIDZ9` | `POST /oid4vci/nonce`; goes in the key proof's `nonce` |
| OpenID4VCI pre-authorized code and Transaction Code, *second start* | `pnX0EbzFOr_b9Mx4SI8LQFP0uewrC4uh`, `90757` | a cross-device Credential Offer (above) |
| Password reset token, *second start* | `LoxEJXPnfjFc3c-70gD-KOBT4HWQ0g7KjJKuttojU18` | `POST /admin-api/users/issue-password-reset` returns `https://…/portal/reset-password?user=alice&token=…`; shown once, stored hashed |
| Session `sid` | `sHiKmHBkOJ6bjKXM-TnFoHzZPEPIzHS7` | the ID Token's `sid`, the SAML `SessionIndex`, CAEP's session subject |

## Related

* [Accepted tokens](accepted-tokens.md): which door accepts which of these.
* [OAuth 2.0 and OpenID Connect](oauth-oidc.md),
  [Security profiles](oauth-security.md): what changes the access token and
  ID Token (DPoP's `cnf.jkt`, mTLS's `cnf.x5t#S256`, encrypted ID Tokens).
* [SAML 2.0 Web Browser SSO](saml2-sso.md), [SAML 1.1](saml11.md),
  [WS-Trust](ws-trust.md), [WS-Federation](ws-federation.md).
* [Shared Signals](shared-signals.md), [CAEP events](caep-events.md).
* [OpenID4VCI and status lists](oid4vci.md), [GNAP](gnap.md),
  [SPIFFE](spiffe.md), [PKI](pki.md), [EST](est.md),
  [Kerberos and SPNEGO](kerberos.md).
