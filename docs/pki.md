---
title: PKI
nav_order: 7
---

# A certificate authority, at `/admin/pki`

Protocols → PKI builds a **Root CA, an Intermediate CA and an Issuing CA** for
the trust realm it is reached in, and issues **signing key pairs** from the
bottom of it to applications.

It exists because of [JWT assertions](jwt-assertions.md): an application can
authenticate, or present an authorization grant, with a signed JWT instead of a
shared secret — and **a signing key nobody vouched for is a key an operator has
to move by hand**.

It is the only surface here that issues an X.509 certificate to something that
is not this service. TLS issues its own listener certificate and SPIFFE issues
SVIDs for workloads it also authenticates — **both from Issuing CAs on this
page** — and this hands both halves of a key pair to an
application.

## One Root for the service, and what hangs from it

**Every key pair this service generates is a leaf of one certificate
authority**, built at startup, and the tree is on this page.

```
Root CA                             one, for the whole service
├── Intermediate — process          for what belongs to no realm
│    └── Issuing: TLS               → the main port, LDAPS 636, the debugger
├── Intermediate — realm (default)
│    ├── Issuing: JOSE signing      → RS256, ES256/384/512/256K, EdDSA ×2
│    ├── Issuing: XML signing       → SAML 2.0/1.1, WS-Fed, WS-Trust
│    ├── Issuing: App assertions    → RFC 7523 client key pairs
│    └── Issuing: SPIFFE            → every X509-SVID minted in this realm
└── Intermediate — realm `acme`
     └── …the same four
```

So an operator installs **one anchor** and it covers the main port, LDAPS, the
embedded debugger's listener, every token, assertion and signed document this
service issues — and every X509-SVID it mints — in every realm.

### The page shows the realm you are in

That is the whole service. What `/admin/pki` puts in front of you is the
**Root**, the **process** branch and **your realm's** Intermediate with its
Issuing CAs. Another realm's branch is not on it and cannot be edited from it —
**switch realms** to reach that one, which is how every other setting on the
console already works. `GET /admin-api/pki` answers exactly the same in
whichever realm it is reached in, because the page and that reply are one
function.

The Root is on every realm's page because every realm hangs from it, and the
process branch is because the TLS certificate is served on sockets every realm
answers on — it belongs to no realm, so it is edited from any of them.

### The Root is shared and the Intermediate is not

A CA shared across realms might look like *one authority vouching for several
identity services*. That argument is about the ANCHOR, and the anchor is not
where the realm boundary is. **The Intermediate is**: each realm has one of its own, and a path
must pass through it.

That matters more than it looks. With one Root, "does this certificate chain to
our Root" is true of *every certificate this service has ever issued, in any
realm* — so with a shared Root, that test is not a boundary. A certificate issued in one realm still does not verify in another,
and the refusal says which Intermediate it failed to pass through rather than
blaming an anchor check that can no longer fail.

### An Issuing CA per use case

Six of them, and the split is what makes an operator able to narrow one
surface without touching the rest:

| Use case | Scope | What it certifies |
|---|---|---|
| **JOSE signing** | realm | The RSA key behind RS256, the four ECDSA curves and both Edwards curves — what a client verifies against `/oauth2/jwks`. |
| **XML signing** | realm | SAML 2.0 and 1.1 assertions and responses, WS-Federation, WS-Trust, per-service-provider metadata. |
| **Application assertions** | realm | The signing key pairs issued for RFC 7521 / 7523 — to applications, and to PEOPLE as well (`target=person`, written onto the person's own entry as `stsAssertion*`; see [JWT assertions](jwt-assertions.md)). This is the Issuing CA this page had before the others existed. |
| **TLS listeners** | **process** | The certificate served on the main port, LDAPS 636 and the embedded debugger's listener. |
| **SPIFFE authority** | realm | **Every X509-SVID minted in this realm**. The one Issuing CA here with `pathLen: 1` rather than `0`, because `NewDownstreamX509CA` asks it for a CA and not a leaf; the realm Intermediate above it is widened to `2` to match. See [SPIFFE below](#spiffe-takes-its-authority-from-here-now). |
| **Remote PEP listeners** | realm | The HTTPS listener certificate of a remote XACML PEP **registered in this realm** — `serverAuth`, naming the PEP and the hosts its clients dial, issued from `/admin/xacml/peps` or `POST /admin-api/xacml/issue-pep-certificate`. The private key is handed over once and not kept. Realm-scoped because a PEP enforces one realm's policy. See [Remote PEP](remote-pep.md#an-https-listener-certified-by-the-realm-it-registered-to). |

**A realm branch built before a use case existed gets that Issuing CA added**,
under the Intermediate it already has, the next time the branch is asked for —
on a restart in product mode, or the first time something issues from it.
Nothing already issued is replaced or revoked to do it — rebuilding an
incomplete branch whole would, on a restart, supersede every certificate in the
realm to add one authority.

**The RSA signing key is certified twice**, by the JOSE CA and by the XML CA. It
signs JWTs and it signs XML documents, and those are two use cases: a relying
party that trusts this service for SAML has not thereby said anything about its
OAuth tokens, and two certificates over one key is how that stays sayable.

**TLS hangs off a `process` Intermediate** rather than a realm's, because the
sockets it certifies are shared by every realm. One realm's Intermediate
signing the certificate every realm's front door presents would be that realm
vouching for all the others.

### Nothing about key generation changed

The same RSA key, the same six curve keys, the same eleven post-quantum keys
made lazily on first use, the same algorithms, in the same order, at the same
moment. `pki.autoBuild` is on by default and builds the tree before the
listener binds; what it adds happens afterwards and only ever adds a
certificate.

**The `kid` does not move.** It names the KEY and is derived from the
self-signed certificate the key was born with, which never changes for that
key's life — so a client sees byte for byte the `kid` it saw before any of this
existed, and reissuing an authority underneath a key does not disturb it.

Turn `pki.autoBuild` off and this service behaves exactly as it did before:
nothing is built until Build is pressed, and every key carries the self-signed
certificate it was born with.

### The post-quantum keys are leaves of it too

A realm's eleven post-quantum signing keys — ML-DSA
at three sizes, SLH-DSA at two and the six composite ML-DSA + traditional
algorithms — are issued from that realm's own **JOSE signing** Issuing CA as
they are made, one certificate per algorithm, and each is refused in any other
realm by the same Intermediate boundary every leaf here is held to.

What the old sentence was protecting is still true. The keys are generated,
held and signed with by `common/pq_jose.js` — this service's own reading of
those constructions, deliberately independent of the vendored implementation
the certificate encoder uses. **Only the public key crosses**: it is read out of
the AKP JWK `/oauth2/jwks` already publishes and written into a
SubjectPublicKeyInfo, with the one layout difference between the two readings —
an ECDSA half's `0x04` prefix, which JOSE drops and X.509 keeps — written out
rather than guessed. And the crossing is a check rather than a leap: the test
suite verifies a signature from `pq_jose.js` under the vendored X.509 reading
against the key in each certificate.

Nothing a client sees changed. The JWKS still publishes AKP JWKs with the same
`kid`s; what is new is on this page, in the `certifiedBy` member of each key's
row in `/admin/keys`' JSON, and in the certificate chain the management API's
key export returns beside the JWK.

**An ML-DSA listener certificate** (`tls.certificateAlgorithms`) is a leaf of the
**TLS listeners** Issuing CA beside the RSA one, so one anchor covers whichever
certificate the handshake picks.

What stays outside is outside by its nature: the SPIFFE JWT authority, which
has no certificate to issue, and the OpenID4VCI request-encryption key, which
only decrypts and is trusted because a wallet read it from the issuer's own
metadata.

### Hybrid authorities: a second, post-quantum key and signature (off by default)

**Off by default.** `pki.alternativeKeyAlgorithm` is `none`, so every
authority is classical and every use case and every signature has its own
key pair, as before #68. A hybrid certificate is larger and less familiar than
many products accept: Cisco libest, for one, refuses any enroll response over
4 KB, and every hybrid leaf is larger. Turn it on for a realm whose relying
parties can take it.

Set to a post-quantum algorithm (ML-DSA-87 is the recommended value), a
certificate authority holds an **alternative key** beside its classical one.
That covers the Root, every Intermediate and every Issuing CA built after the
setting changes. It is carried in
the three non-critical extensions of ITU-T X.509 (2019) clause 9.8:
`subjectAltPublicKeyInfo`, `altSignatureAlgorithm` and `altSignatureValue`.
Every certificate an authority issues is then **signed twice**. The classical
signature goes in the ordinary fields. The alternative signature is made with
the authority's ML-DSA key over the certificate *minus* its classical signature
algorithm and the alternative signature itself, a structure clause 9.8 calls
the preTBSCertificate.

The two signatures serve two kinds of validator:

* **A validator that has never heard of the extensions** (OpenSSL, a browser,
  every OAuth library) sees an ordinary RSA or EC chain and accepts it. The
  extensions are non-critical, so nothing breaks.
* **A hybrid-aware validator** checks both signatures. This service is one.
  On a path in its own hierarchy, a certificate issued by an authority that
  holds an alternative key **must** carry an alternative signature that
  verifies. A missing one is refused as `STS-PKI-0202`, and a wrong or
  uncheckable one as `STS-PKI-0201`. The rule exists to stop a downgrade:
  "RSA + ML-DSA" that a relying party accepts as "RSA **or** ML-DSA" is
  post-quantum protection nobody is required to use.
* **A foreign chain** (a trust anchor you configured) may legitimately issue a
  classical leaf under a hybrid CA, so there only a *wrong* alternative
  signature is refused.

The choice is made per build. The three build forms on this page, and
`altKeyAlg` on `POST /admin-api/pki/build`, `build-root` and `build-scope`,
take an alternative key algorithm. It can be any pure ML-DSA or SLH-DSA
signature algorithm, or `none`. A hierarchy keeps what it was built with. The
page shows each tier's alternative key under its classical algorithm, with the
algorithm its own alternative signature was made with.

> **Warning.** `none`, the default, builds a **classical-only** authority. A
> quantum-capable attacker who recovers its RSA or EC key can mint
> certificates this service accepts.

**What it costs is size.** An ML-DSA-87 public key is 2,592 bytes and a
signature 4,627, so each CA certificate grows by about 7 KB and each leaf by
about 4.6 KB. A TLS handshake on the main port carries the leaf, the Issuing
CA and the Intermediate, about 19 KB more than before. A JWS whose header
carries the whole chain in `x5c` grows by the same amount, base64-encoded,
which can exceed an HTTP server's header limit when the token is sent as a
bearer. `x5u`, the default, does not carry the chain.

**CRLs and OCSP responses are signed classically only, on purpose.** No
published profile defines an alternative signature on either, so no client
could check one, and a second signature nothing verifies would add size and
no protection.

### Signer groups: a key pair per use, in a chosen set of algorithms

A realm normally signs with **one key per algorithm**: an RSA key, six curve
keys and eleven post-quantum keys, shared by every kind of JWT. Setting
`keys.signerModel` to `hybrid-groups` changes that for the realm. Each of five
**signer groups** gets keys of its own:

| Group | What it signs |
|---|---|
| `tokens` | access tokens, ID Tokens, refresh tokens, signed UserInfo, JWT introspection responses, signed discovery metadata |
| `credentials` | OpenID4VCI credentials and status lists, signed issuer metadata, OpenID4VP request objects |
| `events` | Security Event Tokens (CAEP, RISC) |
| `wstrust-gnap` | WS-Trust JWTs, GNAP access tokens |
| `xml` | SAML, WS-Federation and WS-Trust XML signatures |

Each group has seven key pairs and four certificates:

* an **RSA-3072** key, certified together with an **ML-DSA-65** key
* a **P-256** key, certified together with an **ML-DSA-44** key
* a **P-384** key, certified together with an **ML-DSA-87** key
* an **SLH-DSA-SHA2-128s** key, certified alone

"Certified together" means one hybrid certificate: the classical key in the
ordinary field and the ML-DSA key in `subjectAltPublicKeyInfo` (see above).
Every key is still a key pair of its own; what the two share is the
certificate.

A JWT signed for a group's use takes the group's key for its algorithm. RS256
and PS256 use the RSA key, ES256 the P-256 key, and ML-DSA-65 the ML-DSA-65
key. **An algorithm outside the set** (ES512, ES256K, EdDSA, a composite)
still signs with the per-algorithm key. The keys are made in the background
when the service starts, or on the first signature after a realm is switched.
Until they exist, signatures use the per-algorithm keys.

**XML** signs with the `xml` group. `saml.signatureAlgorithm` picks the key:

* the RSA values use the RSA-3072 key
* `ecdsa-sha256` and `ecdsa-sha384` use the P-256 and P-384 keys
* `ml-dsa-44/65/87` and `slh-dsa-sha2-128s` use the post-quantum keys, under
  the W3C xmldsig-more draft identifiers

KeyInfo must carry a certificate whose key IS the signing key, so each of the
XML group's ML-DSA keys also gets a plain certificate of its own, besides
being the alternative key in its partner's hybrid certificate. The SAML
metadata lists every XML signing certificate under `use="signing"`, with the
configured one first. The encryption KeyDescriptor stays RSA, because an
ECDSA or ML-DSA key cannot receive an encrypted assertion.

**In the JWKS**, a group's classical key carries its hybrid certificate in
`x5c`. Its ML-DSA partner is published **without** `x5c`, because RFC 7517
requires the first certificate to hold the JWK's own key, and this
certificate's primary key is the classical one. A token signed with that
ML-DSA key likewise carries no `x5c` header. The SLH-DSA key has a
certificate of its own and carries it.

### SPIFFE takes its authority from here now

Two objections to a SPIFFE authority under this service's Root — that a trust
domain whose root is also this service's conflates two unrelated trust
decisions, and that an Issuing CA here carries `pathLen: 0` while a SPIFFE
authority signs SVIDs — are both answered rather than waived:

* **The trust decision is not conflated.** The SPIFFE authority is a *sibling*
  of the TLS one, not the same certificate — its own Issuing CA, its own key.
  The only thing they share is the anchor you install. Narrowing trust to
  SPIFFE alone is still sayable: pin that Issuing CA instead of the Root.
* **The `pathLen` was moved rather than argued around.** The SPIFFE Issuing CA
  carries `pathLen: 1` and the realm Intermediate above it `2`, both derived
  from one table so they cannot come apart.

**The shortest description is that this service's PKI is SPIRE's
[UpstreamAuthority](https://spiffe.io/docs/latest/deploying/spire_server/).**
The SPIFFE bundle publishes the **Root** — which is what SPIRE publishes with
an upstream plugin configured — and an X509-SVID carries its Issuing CA and the
realm's Intermediate in its own chain:

```
bundle                  Root CA
X509-SVID chain         [ leaf, SPIFFE Issuing CA, Intermediate — realm ]
```

Three things follow:

* **A rotation no longer changes the bundle.** Re-issuing the SPIFFE Issuing CA
  leaves the anchor alone, so an SVID minted a minute ago keeps verifying and
  nobody re-fetches anything. That was not true of the self-signed arrangement,
  where every rotation changed the bundle.
* **Every realm's bundle is the same document.** The authority is per realm and
  the anchor is not, which is what keeps a per-realm authority coherent with
  SPIFFE's four shared sockets — those answer in the default realm, and what a
  realm's own Issuing CA adds is a line in the chain saying who issued the SVID.
* **A realm with no certificate authority still works.** It falls back to the
  self-signed authority this service always had, and `/admin/spiffe` and `GET
  /spiffe` both say which one is in use. `pki.autoBuild: false` reaches that
  state deliberately.

`spiffe.x509KeyType` still decides the key in each **SVID**; the **authority's**
key is the branch's, chosen when you build the hierarchy — and out of the box it
is EC P-256, which is what SPIRE issues.

### Editing it

Four acts, and they are deliberately named apart because their consequences are
not alike:

| | What it does |
|---|---|
| **Rebuild this branch** | A new Intermediate and a new Issuing CA for every use case under it, then everything re-certified. The Root is untouched. |
| **Reissue this CA** | A NEW KEY for one Issuing CA, and everything under it re-certified. The other use cases are untouched. |
| **Renew certificates** | The same authorities and the same keys, fresh certificates with fresh serials. **Nothing stops verifying.** |
| **Replace the Root** | Every branch is re-issued under the new Root in the same act. **Anything trusting the old Root stops trusting this service.** |

### Your own CAs and your own keys

**Import a CA** — paste a certificate and its private key, as the Root or as one
use case's Issuing CA, and the tree chains to your own corporate authority
instead. Three checks happen before anything is stored: both halves present, the
key actually belongs to the certificate, and the certificate is a CA at all. A
rebuild leaves an imported authority alone.

**Use your own key pair** — per slot, which is a use case and an algorithm
(`jose` / `ES256:P-256`). With no certificate this service issues one from its
own authority, so your key chains here exactly as a generated one would; with a
certificate, the pair is used as you supplied it.

## A branch is built whole, or not at all

A trust chain is only worth anything **whole**. An Issuing CA with no
Intermediate above it is a two-tier chain wearing a three-tier name, and a
half-built hierarchy is exactly the state in which somebody issues a certificate
that verifies here and nowhere else. A failure at any tier stores nothing.

That rule is about a **branch** — an Intermediate and every
Issuing CA under it — rather than about three tiers: a branch with two of its
three Issuing CAs is the state in which one use case silently has no authority
and its keys come out uncertified.

| Tier | `pathLen` | Default life | What it is for |
|---|---|---|---|
| **Root CA** | unconstrained | 20 years | The trust anchor. Self-signed, and the only certificate a relying party has to be given out of band — everything below it travels in the chain. |
| **Intermediate CA** | 1 | 10 years | So the Root's key can be used once and left alone: a compromise here is repaired by reissuing this tier, and a compromise of the Root is not repaired at all. |
| **Issuing CA** | **0** | 5 years | The only tier that signs anything handed out. `pathLen: 0` means it signs LEAVES and no further CA — so "an application certificate cannot mint another" is a property of the encoding rather than of this service's manners. |

**Building again REPLACES.** Everything issued from the old hierarchy chains to
nothing the moment it does, and the page says so before the button is pressed —
this service keeps no copy of what it issued, so none of it can be listed.

**AND THAT INCLUDES THE CERTIFICATE THIS SERVICE IS SERVING ON ITS OWN HTTPS
PORT.** The main listener's certificate is a leaf of this hierarchy like every
other key here, so rebuilding the Root re-issues it under the new one: anything
holding the anchor from before — a truststore you built with `curl -k
https://host:8081/tls/server-certificate`, a browser you told to trust it, a
client with `NODE_EXTRA_CA_CERTS` — **stops trusting this service on the next
connection**, with `unable to get local issuer certificate` and nothing in the
message about what changed. Fetch it again.

The listener does not have to be restarted for this and never is: the new
certificate is applied to the live socket, and connections already open keep the
one they were made under.

## A realm's own branch

A realm is a logical identity service with its own signing key, its own sessions
and its own applications — and its own **Intermediate CA**, which is what a
realm has of its own now that the Root is the service's. Reaching
`/realm/acme/admin/pki` shows that realm's branch.

A certificate issued in `acme` does not verify at the default realm's token
endpoint. **The check is the Intermediate and not the anchor** — see *The Root
is shared and the Intermediate is not* above for why that distinction is the
whole of the change.

## What issuing writes, and what it forgets

The key pair goes onto that application's **own directory entry**. Seven
attributes:

| Attribute | What it holds |
|---|---|
| `oauthAssertionPrivateKey` | The private key, PEM — **sealed at rest** under the key-encryption key wherever it persists |
| `oauthAssertionCertificate` | The leaf, PEM |
| `oauthAssertionCertificateChain` | The Issuing CA and the Intermediate, in that order |
| `oauthAssertionJwks` | The public half as a JWKS, each key carrying `x5c` and `x5t#S256` |
| `oauthAssertionKid` | The `kid`, derived from the key material (RFC 7638) |
| `oauthAssertionExpiresAt` | When the certificate expires |
| `oauthAssertionKeySource` | `issued` — or, for a certificate uploaded in its place, where that came from (see [below](#an-applications-credentials-on-its-own-page)) |

**This service keeps no second copy of the private key.** It is handed over
once, at issuance, and forgotten — so the entry is where it lives.

**AND IT IS SEALED THERE.** AES-256-GCM under the key-encryption key, through
`common/keystore.js` — the same mechanism and the same key that seal this
service's own signing keys and the three CA key pairs this leaf was issued from
— wherever that key outlives the process, which is product mode. So an
`ldapsearch` on TCP 389 where every bind succeeds, an LDIF file, a database row
and a backup of either hold `$aesgcm$…` and not a usable signing key. The
surfaces that come through `common/applications.js` — `/admin/applications` and
`GET /admin-api/applications`, both behind a credential — are handed the PEM,
because **the seal protects the store rather than the console an operator
collects an issued credential from**. `/admin/ldap/applications` is the
deliberate exception and shows the ciphertext: that page is headed *the registry
as the directory sees it*.

In **development mode** it is written in the clear. The key-encryption key there
is ephemeral — it exists so the request-worker pool can share minted rows — and
sealing an entry that survives a restart under a key that does not would leave
the certificate readable and the private half permanent garbage. That is the
same rule an authenticator's shared secret follows, and in that mode the
decision `oauthClientSecret` and `GET /krb5/principals` make still applies:
a debugger whose credentials are unusable without reading the source is worse
than one that says what they are.

**`oauthJwks` is never overwritten.** A client that registered its own keys and
is later issued a pair by an operator has two ways to sign, both of which
somebody deliberately arranged, and writing over the first would silently end it
the moment somebody pressed a button about the second.

**The leaf is a signing certificate and deliberately not a TLS one** —
`digitalSignature` and `nonRepudiation`, and **no extended key usage**. What it
signs is a JWT, not a TLS handshake. Giving it `clientAuth` would make it usable
for RFC 8705 section 2 as well, which is a DIFFERENT credential with a different
registration attribute, and one certificate quietly doing both is how a
deployment ends up unable to revoke either. The application's identifier is a
URI subjectAltName besides the CN, because a CN is a display name and a SAN is
the machine-readable one.

**The lifetime is clamped, not refused.** A certificate that would outlive the
Issuing CA is shortened to the CA's own expiry: the ordinary cause is a five-year
Issuing CA in its fifth year, and an operator who asked for a year should get
eleven months rather than an error about arithmetic.

## An application's credentials, on its own page

`/admin/applications?application=<id>` has a **Credentials**
section: the application's client secret, and for each assertion profile — RFC
7523 (JWT) and RFC 7522 (SAML) — the key pair this service manages for it, beside
the keys the application registered itself (`oauthJwks`,
`oauthSamlAssertionSigningCertificate`). For each managed key pair it shows the
certificate, who issued it, the chain above it, the key handle, whether this
service holds the private key, and **where the key pair came from**:

| `oauthAssertionKeySource` / `oauthSamlAssertionKeySource` | Meaning |
|---|---|
| `issued` | Generated here and signed by this realm's Issuing CA. The private key is on the entry. |
| `uploaded-realm-ca` | A certificate this realm's own CA issued, uploaded in place of a generated pair. The application holds the private key. |
| `uploaded-external-ca` | A certificate from another CA, uploaded with its full chain. The application holds the private key. |

### Replacing a key pair

Both ways **replace** the key pair for that one profile; the other profile's is
untouched.

* **Issue from this realm's CA.** The same act as the Issue control above,
  drawn on the application's page so the application does not have to be typed
  into a box. It needs this realm to have a CA.
* **Upload a certificate** the application already holds. **No private key is
  taken**: an upload carrying one is refused, nothing is stored, and the refusal
  tells you to treat that key as exposed. The private key attribute on the
  entry is cleared, so a previously issued key stops signing for the application.

What an upload must include depends on who issued the certificate:

* **This realm's own CA** — the leaf alone is enough; this service holds every
  tier above it. It is checked exactly as a presented `x5c` is: it must pass
  through this realm's own Intermediate, and nothing on it may be revoked.
* **Any other CA** — the leaf **and its full trust chain**: every intermediate
  and the **self-signed root**, pasted in either box and in any order. Every
  link is verified: signatures, issuer names, validity windows; every issuer
  must be a CA whose key usage permits certificate signing and whose path
  length constraint the chain respects; the leaf must not be a CA and must
  permit `digitalSignature`. Its revocation is checked the way a registered
  certificate is checked when it is used. The root does **not** have to be
  trusted by anything here — you are registering a key, and the chain is the
  evidence for it — but it has to be there. For an external CA the stored chain
  keeps the root, because revocation checking needs every issuer.

Refused by name: an incomplete chain, a certificate that is not on the path, a
self-signed leaf (register that on `oauthJwks` or
`oauthSamlAssertionSigningCertificate` instead), and a certificate from
**another realm** of this service, even with its whole chain — every realm
shares one Root, so such a chain is consistent and is still not this realm's.

The key must be one the profile's verifier can use: RSA of at least 2048 bits,
or ECDSA on P-256, P-384 or P-521, for both profiles; for RFC 7523 also
secp256k1 (ES256K) or Ed25519 (EdDSA); and for RFC 7522 — whose XML Signature
verifier takes every family — also Ed25519, Ed448, DSA, ML-DSA
or SLH-DSA.

As with an issued key pair, **a key pair is not a trust decision**: to present
an authorization grant the application's issuer must still be declared on
`oauthAssertionIssuer` or `oauthSamlAssertionIssuer`.

### The client secret

The section shows `oauthClientSecret` behind a fold, and **Regenerate the client
secret** mints a new one — `oauth2.registeredSecretBytes` random bytes,
base64url, as a registration mints one — and replaces the old one at once.
Wherever the token endpoint checks a secret (RFC 9700 mode, product mode) the old
one stops working on the next request. The new value is shown on the page and in
the API reply; the audit log names the attribute and never the value.
`sts-management-api`'s secret is refused while `adminApi.clientSecret` pins it,
because every token for `/admin-api` is minted with that setting.

```bash
H="Authorization: Bearer $ADMIN_TOKEN"

# Replace webapp1's JWT key pair with its own certificate from another CA.
curl -sk -X POST https://localhost:8081/admin-api/pki/upload-certificate \
  -H "$H" -H 'Content-Type: application/json' \
  -d "$(jq -n --rawfile c leaf.pem --rawfile ch chain.pem \
        '{identifier:"webapp1", purpose:"jwt", certificate:$c, chain:$ch}')"

# What the entry now holds, per profile — no secret and no private key in it.
curl -sk "https://localhost:8081/admin-api/applications?application=webapp1" \
  -H "$H" | jq .credentials

# A new client secret, returned once.
curl -sk -X POST https://localhost:8081/admin-api/applications/regenerate-secret \
  -H "$H" -H 'Content-Type: application/json' \
  -d '{"application":"webapp1"}' | jq -r .clientSecret
```

## A person's credentials, on their own page

`/admin/users?user=<name>` has a **Credentials** section too:
the person's own assertion key pairs, one per profile — RFC 7523 (JWT, on
`stsAssertion*`) and RFC 7522 (SAML 2.0, on `stsSamlAssertion*`). **A person may
hold an RFC 7522 key pair**, and the SAML 2.0 bearer grant reads it.

It shows what the application's section shows — the certificate, its issuer, the
chain, the key handle (`kid` for JWT, the certificate thumbprint for SAML),
where the key pair came from (`stsAssertionKeySource` /
`stsSamlAssertionKeySource`, with the same three values) and the issuer the
person asserts as — with one difference: **it says whether this service holds
the private key and never shows it.** A person's private key is shown once, on
the page the Issue button opens, and nothing opens it again.

The controls are the same three, needing Admin Write:

* **Issue from this realm's CA** — generates a key pair for that profile,
  signs it with the realm's Issuing CA, seals the private key on the entry and
  shows it once, with a link back to the person.
* **Upload a certificate** the person already holds, under exactly the chain
  rules above — this realm's alone, or another CA's with its full chain to a
  self-signed root. No private key is taken, and the one an earlier issue left
  is cleared. **A certificate this realm issued must have been issued to this
  person**: an application's leaf, or another person's, is refused, because a
  person's key pair is that one person's credential and registering somebody
  else's would let its holder assert as them. (For the same reason a person's
  leaf is refused for an application.) A self-signed certificate is refused —
  a person has no by-value registration.
* **Take this key pair off** — that profile's key pair and its declared issuer;
  the other profile's is untouched. Not revocation.

**Whichever way the key pair got there, a person's assertion may only be about
themselves**: the JWT grant refuses a `sub`, and the SAML grant a `<Subject>`,
naming anybody else.

```bash
H="Authorization: Bearer $ADMIN_TOKEN"

# An RFC 7522 key pair for alice. The reply carries the private key, once.
curl -sk -X POST https://localhost:8081/admin-api/pki/issue \
  -H "$H" -H 'Content-Type: application/json' \
  -d '{"identifier":"alice","target":"person","purpose":"saml"}' > saml.json

# Or replace it with a certificate alice already holds from another CA.
curl -sk -X POST https://localhost:8081/admin-api/pki/upload-certificate \
  -H "$H" -H 'Content-Type: application/json' \
  -d "$(jq -n --rawfile c leaf.pem --rawfile ch chain.pem \
        '{identifier:"alice", target:"person", purpose:"saml",
          certificate:$c, chain:$ch}')"

# What her entry holds, per profile — no private key in it.
curl -sk "https://localhost:8081/admin-api/users?user=alice" \
  -H "$H" | jq .credentials

# Take the SAML key pair off, leaving the JWT one.
curl -sk -X POST https://localhost:8081/admin-api/pki/revoke \
  -H "$H" -H 'Content-Type: application/json' \
  -d '{"identifier":"alice","target":"person","purpose":"saml"}'
```

`/portal/signing-key`, where a person issues themselves a key pair, offers both
profiles: a card each, with its own Generate and its own Take
off, and the one-time page describing the grant the new key is for.

## A TLS client certificate for your browser

A third card on `/portal/signing-key` issues a **TLS client certificate** to the
signed-in person, from the realm's own **TLS Client Issuing CA**:

* it carries `clientAuth`, `CN=<username>`, a `urn:sts:person:<username>`
  subjectAltName and, where the directory holds one, your email address;
* you choose the key (RSA 2048 by default, RSA 3072, ECDSA P-256 or P-384) and a
  **file password**, typed twice;
* the page that comes back offers three downloads, **once**: a `.p12` (the key,
  the certificate and the two CAs above it, AES-256 protected by that password), an
  encrypted `-key.pem` and a `-chain.pem`, with install steps for Windows, macOS,
  Firefox, Chrome on Linux and curl. Nothing keeps the private key.

**This service trusts its own Root for client certificates**
(`tls.trustIssuedClientCertificates`, on by default), and **the main port asks
every connection for a client certificate and requires none** — so after
importing the `.p12`, opening `https://<host>:8081/tls/sign-in` and choosing the
certificate when the browser asks signs you in, **in the realm whose portal
issued it**. Your other applications on this service then sign you in without
asking.

Presenting a certificate is the client's own decision rather than the port's demand: the browser sends it because you
chose it, and `GET /tls/sign-in` answers what arrived, whether it verified, its
thumbprint, the revocation verdict and whether a session was started.

Trusting the Root does not make every certificate this service issues a way in.
A verified chain through the Root is an identity only for a leaf from a TLS client
(or ACME, EST or SCEP enrollment) Issuing CA, with `clientAuth` and one
`urn:sts:person:` or `urn:sts:application:` name; an application's assertion key
pair or an SVID completes the handshake and is refused as an identity — the
sign-in says so and starts nothing.

You may hold up to `pki.personTlsClientCertificateMax` (5) valid certificates, one
per device. Each has a **Revoke** button; revocation is real — the CRL, the OCSP
responder, and every door that reads a certificate refuse it.

```bash
curl --cert alice-laptop-tls-client-chain.pem \
     --key alice-laptop-tls-client-key.pem --pass '<file password>' \
     https://localhost:8081/tls/sign-in
```

## Revocation is published, and consulted

| | |
|---|---|
| **A CRL per authority** | RFC 5280 section 5, DER, at `GET /pki/crl/{scope}/{ca}` — and as `certificateRevocationList;binary` under `ou=crl` in the embedded directory, which is what the `ldap://` address inside every certificate resolves to, readable anonymously by a base search in every mode. Built and signed ON DEMAND, so `thisUpdate` is always now and every signing gets a new CRL number; the directory copy is republished whenever the branch changes and at half of `pki.crlLifetimeMinutes`, so it is never past its `nextUpdate`. |
| **An OCSP responder per authority** | RFC 6960, both transports of appendix A.1, at `GET|POST /pki/ocsp/{scope}/{ca}`. Signed with the CA ITSELF rather than a delegated responder certificate, so a client verifies with the anchor it already has; the responder ID is by key hash and every time is whole seconds (RFC 5019). The nonce is echoed, and one of 0 or more than 32 octets is `malformedRequest` (RFC 8954). A request about no certificate this authority issued is `unauthorized`. An authoritative answer carries RFC 5019 section 6.2's cache headers. A GET of the address with nothing appended is a 400 naming both transports. |
| **The issuing certificate** | `GET /pki/ca/{scope}/{ca}.cer`, which is the `caIssuers` address in every certificate that authority signed. |
| **An index** | `GET /pki/revocation` — every authority with its addresses, so a person pointing a client at this does not have to read them out of a certificate first. |
| **The addresses inside a certificate** | `http://` for the CRL, the OCSP responder and the issuer's certificate, and `ldap://` for the CRL — **never `https://` or `ldaps://`**, which RFC 5280 section 8 says a CA SHOULD NOT write into an extension: a client that checks revocation before it trusts a connection cannot fetch the answer over that connection. The `http://` addresses name **`pki.httpPort` (8082)**, a plain listener that answers `/pki/` and nothing else; RFC 5019 section 5 requires an OCSP responder to answer plain HTTP. The main port answers the same paths. |
| **Behind a port mapping** | The addresses are built from inside the process, so a container must be TOLD where it is reachable: `pki.distributionPort` / `PKI_DISTRIBUTION_PORT` and `pki.distributionLdapPort` / `PKI_DISTRIBUTION_LDAP_PORT` for the published ports, or `pki.distributionBaseUrl` and `pki.distributionLdapHost` for a different name. `docker-compose.yml` publishes 8082 on `STS_PKI_HOST_PORT` and passes it through. A change reaches certificates issued afterwards, never one that exists. |
| **Per authority and NOT per realm** | A CRL is signed by an ISSUER and lists serials that issuer minted, so a list per realm would be a document with no valid issuer and nothing could sign it. |
| **A pane on `/admin/pki`** | Pick an authority, see what it has issued, revoke with any of the nine RFC 5280 reasons, release a `certificateHold`. |
| **Rotation revokes automatically** | Reissuing a use case's Issuing CA puts every leaf it had signed on its own list and the replaced CA on the Intermediate's, as `superseded`. |

**AND IT CONSULTS THEM.** A certificate PRESENTED to this service is checked
under `pki.revocationCheck`:

| Where a certificate is presented | What is checked |
|---|---|
| **`GET /tls/sign-in`** (a verified client certificate) | the whole chain. A refused one starts no session and is not recorded as an authentication, and the answer says *refused on revocation*. |
| **The main port** — the remote XACML PEP and XACML user chains, SCIM's client-certificate scheme, RFC 8705 `tls_client_auth` / `self_signed_tls_client_auth` | the whole chain, computed once per request before any route; each of those doors refuses a certificate the policy refuses |
| **An RFC 7523 assertion's `x5c`** | the register only — the path is this realm's own by construction |
| **The SPIRE Server API** (an X509-SVID) | the register only, whatever the policy — a federated SVID has no revocation mechanism but its bundle |
| **LDAPS 636** | nothing — it asks for no client certificate |

**A certificate REGISTERED rather than presented is checked too, when it is
USED** — the same sources and the same policy, refused as `STS-PKI-0129`:

| Where a registered certificate verifies something | What is checked |
|---|---|
| **An RFC 7523 grant or `private_key_jwt` client authentication** | the `x5c` of the key in `jwks` / `oauthAssertionJwks` / a person's `stsAssertionJwks` that verified the assertion. A key with **no** `x5c` is a bare key: nothing to look up, and the result says `bare` rather than good |
| **An RFC 7522 grant or client authentication** | the registered or issued certificate that verified the assertion |
| **A federated sign-in** (SAML 2.0, SAML 1.1, WS-Federation, OpenID Connect, OAuth 2.0 with a JWT access token) | `fedSigningCertificate`, or the `x5c` of the partner key that verified the token — before the session starts |
| **The OID4VP response endpoint** | the certificate in `oid4vp.trustedIssuerCertificates` that verified the credential, as a check row |

A registered certificate usually arrives with nothing above it, so its issuer is
**fetched from its own caIssuers address**, hop by hop, each certificate
believed only because its key verifies the one below. One naming no such address
is refused where `pki.revocationRequireDistributionPoint` says — `auto`, in
product mode; one naming an address that did not answer is refused under
hard-fail.

**Where the answer comes from depends on who signed the certificate.** One of
this service's own authorities is answered from the REGISTER — the list this
page revokes into — with no network in it, for every certificate on the chain,
**including the tiers the client did not send**: revoke an Issuing CA and every
leaf under it is refused. Anybody else's is answered by the **OCSP responder**
its Authority Information Access names and by the **CRL** its
`cRLDistributionPoints` names — in the order `pki.revocationOcsp` chooses, each
the other's fallback — fetched over **http, https or `ldaps:`** (plain `ldap:`
only with `pki.revocationLdap=ldaps-and-ldap`; never `file:`; OCSP over http(s)
only), with a timeout, a size cap, no redirects or referrals, and a cache that
honours the document's own validity. An `ldaps:` directory's certificate must
chain to node's CA store or `pki.revocationLdapCaFile`; the URL is read per RFC
4516 with a host, base scope and no critical extension, and only a list's or a CA
certificate's attribute is read. A distribution point named **relative to its CRL
issuer** is looked up in the directory `pki.revocationLdapDirectory` names, when
every RDN of the whole name is single-valued. **A URL is dialled only for a chain that VERIFIED
against this service's truststore** — an unverified certificate can name
anything.

**An address this service will not dial is not the same as no address
(#174).** A plain `ldap:` list under the default `pki.revocationLdap=ldaps`,
any LDAP address with it `off`, a relative name without
`pki.revocationLdapDirectory` (or with a multi-valued RDN), a scheme that is
never dialled, an OCSP responder that is not http(s), and any responder with
`pki.revocationOcsp=off` are **not dialled** — and when that is all a
certificate names, the issuer published a list that this service's own policy
kept it from reading. Its status could not be established: hard-fail refuses it
as `STS-PKI-0188`, with the reason naming the setting that would dial it, and
soft-fail accepts it and reports it. The verdict lists every such address
(`notDialled`), and the policy report on this page lists them apart from what
names none.

**A certificate that names NOTHING — no CRL, no OCSP responder — can never be
revoked (#174).** `pki.revocationRequireDistributionPoint` decides it: `auto`
(the default) is `mode.refusesUnrevocableCertificates()`, which refuses one
issued by a CA this service does not hold in **product** mode
(`STS-PKI-0190`) and accepts it in development; `on` refuses it in both. **`off`
accepts certificates nobody can ever revoke** — a stolen key under such an
authority is good until it expires — and is there for a private CA you know
publishes nothing; giving that CA a distribution point is better. A self-signed
certificate is untouched (the walk stops at it as an anchor). A certificate
carrying **RFC 9608 `noRevAvail`** is not checked in either mode — section 4
skips the check, its issuer having declared that no revocation information
exists — and one carrying it beside `cA` TRUE, `cRLDistributionPoints`,
`freshestCRL` or an OCSP responder is **invalid** (section 3) and refused under
every policy but `off` (`STS-PKI-0189`).

**Whose signature is believed:**

| Document | Signed by |
|---|---|
| An OCSP response | the certificate's issuer, or a **delegated responder** whose certificate is in the response, was issued by that issuer, carries `id-kp-OCSPSigning`, is inside its validity period — and **is not itself revoked**: its own status comes from the CRL its certificate names (never from OCSP), unless it carries `id-pkix-ocsp-nocheck`. A revoked responder's answers are unusable; one whose status could not be established is not believed under hard-fail |
| A CRL | the certificate's issuer — or, for an **indirect** CRL, the `cRLIssuer` the certificate's distribution point names, whose certificate must carry `cRLSign` and chain to an authority the presented chain passes through. It is found in that chain, among this service's own authorities, in `pki.revocationCrlIssuersFile`, or at the **caIssuers address the CRL's own Authority Information Access names** — which also verifies a list the issuer signed with a rollover key |
| A delta CRL | the same signer as its base |

**What else is checked:**

| | |
|---|---|
| OCSP freshness | `thisUpdate` not in the future and `nextUpdate` not past, within `pki.revocationClockSkewS`; a response with no `nextUpdate` is fresh for `pki.revocationOcspMaxAgeS` |
| OCSP nonce | always sent; a response echoing a **different** one is a replay and refused; one echoing **none** is believed (RFC 5019 responders cannot echo one) unless `pki.revocationOcspRequireNonce` is on |
| A responder's `unknown` | is **unknown** — refused under hard-fail, and not turned into good by a CRL that does not list the certificate. A CRL that lists it still wins |
| A delta CRL | fetched from the `freshestCRL` on the certificate or its base; merged only when it is from the same issuer and scope, its `BaseCRLNumber` is no newer than the base's `cRLNumber` and its own number is greater. `removeFromCRL` takes an entry off. A delta that cannot be applied leaves a base's **permanent** revocation standing and makes everything else unknown |
| An indirect CRL | must declare `indirectCRL`; each entry belongs to the `certificateIssuer` before it, so a serial is matched only under the right issuer |
| The issuing distribution point | its name must match the point the certificate named; `onlyContainsUserCerts` / `onlyContainsCACerts` / `onlyContainsAttributeCerts` decide whether the list is about this certificate at all; `onlySomeReasons` and the point's own `reasons` narrow what it covers, and a certificate is good only once its lists cover **every** reason between them |

| `pki.revocationCheck` | Refuses |
|---|---|
| `off` | nothing |
| `soft-fail` | a certificate that is revoked |
| `hard-fail` | that, and one whose status could not be fetched, did not verify, was stale, or that its issuer's responder does not know — and one whose only list or responder is at an address this service is configured not to dial (`STS-PKI-0188`). A certificate naming **no** CRL and **no** responder is refused where `pki.revocationRequireDistributionPoint` says: `auto` refuses it in product mode (`STS-PKI-0190`) |
| `auto` (default) | `hard-fail` in product mode, `soft-fail` in development |

**What remains are limits, and `common/mode.js` carries them**: a bare registered
key names no list, so only taking it off stops it verifying; plain `ldap:` is
dialled only when allowed, and a relative distribution point needs
`pki.revocationLdapDirectory` and single-valued RDNs — refused under hard-fail
when nothing else answers; a certificate naming nothing is accepted in
development; LDAPS 636 asks for no client certificate. The verdict for a
certificate you present is in `GET /tls/sign-in`'s answer; the policy is on `GET /tls` and
`/admin/crypto-metadata`.

**AND THERE IS A THIRD ACT WITH THE SAME WORD IN IT.** The console has a
control labelled *Take the key pair off*, and it is **not** revocation:

* it clears the seven attributes, so **this service** will no longer accept an
  assertion signed with that key, because the key is no longer registered
  against that application;
* the certificate is still valid, still chains to this realm's Root, and would
  still verify anywhere that trusts that Root.

The reply says exactly that, in those words. It is the same distinction the
sign-out page draws about an assertion already issued: nothing consults this
service when one is presented, and nothing can be made to.

## How a certificate path is checked

Every certificate path this service checks — a WebAuthn attestation, a SPIFFE
node attestor's certificate, the certificate behind a key that signed an RFC
7523 or 7522 assertion, a presented `x5c`, an uploaded chain, an X509-SVID at
the SPIRE Server API, an OpenID4VCI key attestation, a client certificate on the
main port and the server certificate of an outbound request — is held to ONE set
of RFC 5280 rules (since #201):

* the path is BUILT by trying every issuer whose name matches and whose key
  verifies, backtracking past one that breaks a rule or has expired, within 12
  certificates and 256 signature checks;
* every certificate above the leaf is a CA, may sign certificates, and has a
  pathLenConstraint the non-self-issued certificates below it respect;
* NAME CONSTRAINTS are evaluated — DNS names, e-mail addresses, URIs, IP
  addresses and directory names — including a leaf's host-like common name when
  it has no subjectAltName, and a wildcard is refused where it reaches into an
  excluded subtree;
* CERTIFICATE POLICIES are processed as RFC 5280 section 6.1 defines them —
  policy mappings, requireExplicitPolicy, inhibitPolicyMapping and
  inhibitAnyPolicy — and a path whose certificates require an explicit policy
  none of them leaves is refused;
* a critical extension nothing here implements, an extension twice, a
  certificate signed with MD5 or SHA-1 (SHA-1 is allowed on this service's own
  hierarchy in a development realm only), an EC key not on a named curve, and a
  malformed name or constraint are refused;
* a client certificate OpenSSL verified on the main port that breaks these rules
  is treated as unverified, and every outbound TLS connection this service
  makes — federation, GNAP, SSF, XACML, SMTP, CRL and OCSP over https, LDAPS,
  the database, a cloud provider's or secret store's SDK — fails when the
  server's chain breaks them, and matches the host against the certificate's
  subjectAltName only (RFC 9525), never its common name.

What is deliberately NOT checked — the CA/Browser Forum's Web PKI rules, the
rules RFC 5280 places on what a CA issues that a relying party is not asked to
check (key identifiers, serial number length), extended key usage as a path
rule, and certificate policies — is listed with the reason in the test that
holds all of this to [C2SP x509-limbo](https://github.com/C2SP/x509-limbo),
`tests/x509_limbo.js`, and to [NIST PKITS](https://csrc.nist.gov/projects/pki-testing),
`tests/nist_pkits.js`. An https CRL distribution point or OCSP responder is
verified too, against node's store and `pki.revocationHttpsCaFile`.

## A signed token names its certificate chain

Every JWT this service signs with a certified key can carry the chain of that
key in its header, so a relying party holding only the token can reach the CRL
distribution points, OCSP responders and caIssuers addresses without first
finding the JWKS. RFC 7515 gives two header parameters for it, and each kind of
token has a setting of its own choosing between them:

| Value | The header carries |
|---|---|
| `x5u` *(default)* | `https://<host>/pki/chain/<realm or default>/<sha256>.pem` — the chain in PEM, leaf first, the service Root last. About a hundred bytes. |
| `x5c` | The same chain inline, base64 DER. Four certificates, several kilobytes on every token. |
| `both` | Both. |
| `none` | Neither — the header is exactly what it was before this existed. |

| Setting | Page | Governs |
|---|---|---|
| `oauth2.accessTokenCertificateHeader` | OAuth 2.0 / OIDC | access tokens, every grant |
| `oauth2.idTokenCertificateHeader` | OAuth 2.0 / OIDC | ID Tokens, in any algorithm |
| `oauth2.refreshTokenCertificateHeader` | OAuth 2.0 / OIDC | the signed JWT inside a refresh token |
| `oauth2.userinfoCertificateHeader` | OAuth 2.0 / OIDC | signed UserInfo responses |
| `oauth2.introspectionCertificateHeader` | OAuth 2.0 / OIDC | RFC 9701 JWT introspection responses |
| `oauth2.signedMetadataCertificateHeader` | OAuth 2.0 / OIDC | `signed_metadata` of both discovery documents |
| `oid4vci.credentialCertificateHeader` | OID4VCI | dc+sd-jwt and jwt_vc_json credentials |
| `oid4vci.signedMetadataCertificateHeader` | OID4VCI | the credential issuer's `signed_metadata` |
| `oid4vp.requestObjectCertificateHeader` | OID4VP | the Verifier's Request Object |
| `ssf.setCertificateHeader` | SSF | Security Event Tokens, CAEP and RISC included |
| `wstrust.jwtCertificateHeader` | WS-Trust | a JWT issued in an RSTR |
| `gnap.accessTokenCertificateHeader` | GNAP | jwt-signed and jwt-encrypted access tokens |

Every one may be set per trust realm. Four things get neither header whatever
is configured:

* **an HMAC signature** — the key is a client's secret and has no certificate;
* **a key not yet certified** — keys are certified shortly after they are made,
  and not at all with `pki.autoBuild` off;
* **a JWE** — every JWE here is encrypted either to somebody else's key or to
  the refresh-token keys, which have no certificate; a nested refresh token
  carries the header on the JWS inside it;
* **the DIF Domain Linkage Credential**, whose specification allows only `alg`
  and `kid` in its header, and the SPIFFE JWT-SVID, whose authority has no
  certificate.

The chain address is named by the leaf's SHA-256, so it names one certificate
for ever: after a key is rotated, an old token's `x5u` answers 404 rather than a
chain over a different key. RFC 7515 requires the `x5u` fetch to use TLS; with
`global.https` off the address is `http://` and a strict verifier will not follow
it.

### The `kid` can be the key's thumbprint instead

The `x5c` and `x5u` headers name the **certificate**. The `kid` beside them
names the **key**, and by default it is this service's own name for it
(`sts-1a2b3c4d5e6f`), which a verifier can only look up in the JWKS.
`keys.kidFormat` on */admin/config* (*Key material*) can make it the key's
RFC 9278 JWK Thumbprint URI instead, which anybody holding the public key can
compute:

```
urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs
```

| Value | A signed token's `kid` |
|---|---|
| `internal` *(default)* | `sts-…` — every token exactly as before |
| `jwk-thumbprint-uri` | the SHA-256 JWK Thumbprint URI of the signing key |

It applies to every JWT the realm signs with one of its keys: all twelve kinds in
the table above, plus software statements and the other tokens signed the same
way. The post-quantum keys are covered too (RFC 9964 defines their thumbprint).
It does not apply to:

* **an HMAC signature**, which carries no `kid` at all;
* **the SPIFFE JWT-SVID**, whose authority is a separate key published in
  the SPIFFE bundle;
* **the DIF Domain Linkage Credential and the credential `/did/generate`
  returns**, whose `kid` names a DID verification method (`did:…#sts-…`), and
  the DID document's verification methods themselves.

**While it is on, `/oauth2/jwks` lists every signing key twice**: once under its
`sts-…` name, in the same place as before (the RSA key is still first), and once
more under its thumbprint URI, after the other signing keys and before the
request-object encryption keys. A token signed before the setting was turned on
still finds its key. Turning it off again removes the second entries, so a token
signed while it was on names a key the JWKS no longer lists until that token
expires. This service's own checks of its own tokens accept either name whatever
the setting says. It can be set per realm.

## Signing key generations, and the crypto metadata document

Every signer of a realm is a UNIT — a use case and an algorithm: `jose:RS256`
(tokens), `xml:RS256` (SAML, WS-Federation and WS-Trust, a key of its own), one per elliptic curve and one per post-quantum algorithm.
A unit holds a **current** key, and may hold a **next** key and **retired**
keys:

* a **next** key is published — in `/oauth2/jwks`, in the SAML 2.0, SAML 1.1
  and WS-Federation metadata, in the DID document and in `/crypto/metadata` —
  before it signs anything, so a relying party that refreshes its copy of
  your keys already holds it on the day it starts being used;
* when a unit is rotated, its next key becomes current and the old one is
  **retired**: still published and still accepted for what it signed, until
  `signing.retiredKeyGraceDays` or the longest lifetime of anything it could
  have signed, whichever is later;
* after that the retired key is dropped, its certificate superseded.

Each generation has a certificate of its own from the unit's Issuing CA.

`GET /crypto/metadata` (per realm: `/realm/<id>/crypto/metadata`) lists every
generation of every unit with its kid, JWK, certificate chain, validity,
SHA-256 fingerprint and revocation addresses; the algorithms per use case; and
the rotation policy. It needs no credential, is never cached, and comes as:

| Path | Form |
|---|---|
| `/crypto/metadata` | by `Accept`: JSON, XML (`application/xml`) or signed JSON (`application/jwt`) |
| `/crypto/metadata.json` | JSON |
| `/crypto/metadata.xml` | XML, namespace `urn:iya:sts:crypto-metadata:1` |
| `/crypto/metadata.jwt` | the JSON signed as a JWS by the realm's current JOSE key |
| `/crypto/metadata.signed.xml` | the XML with an enveloped XML Signature by the realm's current XML key |
| `/crypto/metadata.xsd` | the XML Schema |

OpenID Connect discovery links to it as `crypto_metadata_uri`, and the SAML
2.0 metadata in an `md:Extensions` element (`cm:CryptoMetadataLocation`). No
specification defines this document.

In development mode keys are made anew at every start and are not rotated.
In product mode two scheduler jobs, per realm, do it (`/admin/scheduler`):

* **`signing.rotate`**, hourly: a unit with no next key is given one, and a
  unit whose next key has been published for a whole
  `signing.rotationIntervalDays` is promoted. The refresh-token encryption
  keys rotate on the same interval; the set they replace goes on opening the
  refresh tokens sealed under it until the longest of them expires.
* **`signing.retire`**, hourly: drops each retired key past its grace and
  puts its certificate on its Issuing CA's CRL as `superseded`.

The key verifiable credentials are signed with
(`oid4vci.credentialSigningAlgorithm`) keeps its retired keys verifying until
the longest credential lifetime has passed, and rotates on
`signing.credentialRotationIntervalDays` — when no token is signed with the
same key. RS256, the default, is the token signer's key, so it rotates on the
token interval; choose an algorithm of its own (for example ES256K) to give
credentials a longer-lived key.

**Rotating by hand**, in either mode: the Rotation section of `/admin/keys`
(Rotate selected, Rotate all), or

```bash
curl -X POST https://sts.example/admin-api/keys/rotate \
     -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"units": ["jose:RS256"]}'        # [] or omitted: every unit
```

which answers `202` with a `runId` to follow at
`/admin-api/scheduler?run=<runId>`. **An emergency**, for keys presumed
compromised, is `POST /admin-api/keys/emergency` with
`{"confirm": "compromised"}` (or the Emergency form): every key is replaced
with a new one — not the published next key — with no grace, the old
certificates are revoked for `keyCompromise`, the refresh-token keys are
replaced, and every session of the realm is ended. Everything signed before
it stops verifying at once.

After each rotation a Shared Signals event of this service's own,
`urn:iya:sts:secevent:event-type:signing-key-rotated`, goes to every stream
that asked for it. The settings are the Signing keys group on `/admin/keys`.

## Where the CA private keys live

They inherit the mode, and both surfaces that report it say which is in force
rather than describing the mode they wish they were in.

| Mode | What happens |
|---|---|
| **development** (the default) | Held in memory only. The hierarchy lives exactly as long as the process — which is the rule the signing key already follows, and for its reason: a mock is disposable and its credentials are meant to die with it. |
| **product** | Written to `sts_keys`, sealed AES-256-GCM under the same key-encryption key as the signing keys, in the same row family. |

A store of the PKI module's own would have been a **second answer to "where does
this service keep a private key"**, and the second answer is the one nobody
remembers to rotate. It is shared across the request-worker pool over the same
channel the signing keys use, so a hierarchy built on one worker is the one every
other worker issues from.

## The encoder is the debugger's own, vendored byte-identical

`common/vendored/x509.js` — the same module behind the
[OAuth2/OIDC Debugger](https://idptools.com)'s *PKI / X.509* workflow page, and
what `spiffe/spiffe_ca.ts` already issues X509-SVIDs with. So a certificate
issued here and one issued there are built by **one** encoder, and a difference
between them is a difference in the arguments rather than in two implementations
that drifted. The three tiers are that module's own `root-ca`, `intermediate-ca`
and `issuing-ca` **profiles** rather than a second table, so a change to what an
Intermediate CA *is* reaches both.

The key and signature algorithm lists offered on the page are read from the
modules that generate and perform them, which is the rule
`/admin/crypto-metadata` is built on: a dropdown that offered an algorithm the
encoder cannot produce would be a third entry that is a 500.

| | |
|---|---|
| Key algorithms, for the **hierarchy** | `rsa-2048`, `rsa-3072`, `rsa-4096`, `ec-p256`, `ec-p384`, `ec-p521`, `ed25519` |
| Key algorithms, on the **pane below** | those seven plus thirty-four post-quantum ones — ML-DSA, SLH-DSA, composite ML-DSA and ML-KEM — narrowed by the cryptographic approach |
| Signature algorithms | RSASSA-PKCS1-v1_5 and RSASSA-PSS with SHA-256/384/512, ECDSA with SHA-256/384/512, Ed25519 — **and the two SHA-1 ones, marked weak**, because *does my stack refuse a SHA-1 certificate?* is a question a debugger should be able to ask. Nothing defaults to them. Plus the post-quantum ones, where the key is one. |

**The hierarchy is deliberately the shorter list.** What the Issuing CA signs is
a client assertion somebody else's OAuth library has to verify, and an ML-DSA
signature is one almost nothing can read yet. The pane below is where a
certificate nothing can read is the point.

**Leave the signature algorithm empty unless you mean it.** Empty means "the
right one for the key algorithm", which is what almost every deployment wants:
an EC key's digest is decided by its CURVE, so a fixed value can hand a P-521
key SHA-256 — legal, verifying, and nobody's intention. A pair whose families
disagree is refused with the list of what that key *can* sign with beside it.

## The page has no script on it

Every page of this console but the API explorer is `script-src 'none'`, and this
one keeps that. The argument is made from scratch rather than inherited from the
page next door, because the rule here is that it has to be: the test is whether
the page **cannot** work without a script.

It plainly can. Generating a key pair and issuing a certificate are things this
process does far better than a browser — it holds the CA private keys, and a
browser must never — so the button is a POST and the result is a re-rendered
page. The debugger's PKI page needs a script because its whole point is that the
key never leaves the browser; this page's whole point is the opposite.


## Which key pairs are post-quantum

A key pair that uses a post-quantum algorithm carries a small lattice icon, here
and on **Server configuration → Key pairs**:

| Icon | Meaning |
|---|---|
| **PQC** | A post-quantum key: ML-DSA (FIPS 204) or SLH-DSA (FIPS 205). |
| **PQC+** | A composite key: one key with a post-quantum ML-DSA half and a classical half, both of which must verify. |
| **PQC KEM** | A post-quantum key-establishment key, ML-KEM (FIPS 203). It signs nothing. |
| **PQC alt** (dashed) | A classical key whose certificate also carries an alternative post-quantum key (X.509 clause 9.8). The key itself is not post-quantum. |

Hover an icon for the exact algorithm. A key with no icon is classical (RSA,
ECDSA or EdDSA). What decides it is the key's own algorithm, not the signature
on its certificate: every post-quantum key this service holds is certified by an
RSA authority and is marked, and an RSA key certified by an ML-DSA authority
would not be. The same answer is the `pqc` member of each row of
`GET /admin-api/keys`, and of the application and person key-pair rows of
`GET /admin-api/pki`.

## Looking inside a certificate

Every certificate on this page — the Root, each Intermediate and Issuing CA,
everything they certified, the workbench store — and every certificate on
**Server configuration → Cryptography** has a **View details** link. It opens a
dialog over the page, in the same tab, with an **×** at the top and a **Close**
button at the bottom, both of which return you to where you were.

The dialog shows:

* **A summary** — subject, issuer, validity and days left, key, signature
  algorithm, whether it is a CA, its SHA-256 fingerprint, and every place this
  service holds it (the Root is the Root and a SPIFFE trust anchor).
* **The trust chain**, built from the certificates this service holds by
  matching each issuer's name *and* verifying its signature — so a certificate
  whose issuer was replaced shows the broken link instead of a stored chain that
  no longer verifies. Each link says whether its signature verifies, whether its
  issuer may sign certificates (`keyCertSign`), and whether it is in date; the
  path is marked **Trusted** only when it ends at this service's Root CA (or a
  SPIFFE trust anchor this service publishes). Every certificate in the chain
  can be expanded to its own full fields.
* **Every X.509 field**, in RFC 5280's order: version, serial number (hex and
  decimal), the signature algorithm inside the signed part, issuer and subject
  attribute by attribute with their OIDs, both validity bounds with their ASN.1
  time type, the public key's algorithm, parameters, size and bytes, both unique
  identifiers, **every X.509 v3 extension decoded** with its OID and criticality,
  the outer signature algorithm and value, both fingerprints, and the PEM.

The page still runs no script: opening a dialog adds `?certificate=<SHA-256>` to
the address, so a dialog can be bookmarked or sent to someone, and **Back**
closes it. Only certificates this service holds in the trust realm you are in
can be opened — a certificate from another realm opens under that realm's
prefix. The same answer is `GET /admin-api/certificates?certificate=<SHA-256>`,
and `GET /admin-api/certificates` lists every certificate with its fingerprint.

## The Certificate & Key Configuration pane

**Everything above is the hierarchy this service maintains for itself. This is
the other half of the page: the debugger's *PKI / X.509* workflow, on the
server.** Build a certificate authority of any shape and issue the leaf
certificates any of them can sign — TLS server, TLS client for mutual
authentication, code signing, S/MIME, OCSP responder, time stamping, smartcard
logon and Kerberos PKINIT — with every field and every extension exposed.

It is modelled on [that page](https://idptools.com) field for field, over the
same encoder, with the same field names. What differs is where the computation
happens, and that difference decides the shape of everything in it.

| On the debugger's page | Here |
|---|---|
| the profile rewrites the extension boxes as you pick it | **Apply the profile** is a submit, and the form comes back rewritten |
| the cryptographic approach filters the algorithm menus live | the same submit |
| the Copy buttons | gone — this console has no script, and a textarea selects |
| **Download** builds a Blob in the browser | `POST /admin/pki/export` answers with the **file** |
| the key is generated in your browser and never leaves it | the key is generated **here**, because this process holds the CA private keys and a browser must never |

**The form is the state and there is no draft anywhere.** Every field is
re-posted by every button, which is what lets *Apply the profile* rewrite
twenty-two extension boxes with nothing kept between requests — and what lets
*Use this key pair* in the store below load a key without discarding the subject
you have been typing.

### The three columns

**Issue a Certificate** — the profile (fourteen of them), the authority that
signs it, the cryptographic approach, the signature algorithm, a random 128-bit
serial you can edit, and the validity as either a number of years or two
instants. A serial is **refilled after every issue**: one that stayed put would
be re-used by the next certificate the same authority signs, and two
certificates from one issuer sharing a serial are indistinguishable to anything
that revokes, caches or pins by (issuer, serial).

**Key Pair** — the algorithm, a PEM/JWK toggle, *Generate a key pair* on its
own, the pair itself, the PKCS#10 request, the alternative key a hybrid
certificate carries, and the export.

**Subject Distinguished Name** — CN, O, OU, L, ST, C, emailAddress, DC, UID and
the DN attribute called serialNumber, then any further `NAME=value` or
`OID=value` lines. It is written **in the order shown**: a Name is an ordered
RDNSequence, and a reordered DN is a different name that chains to nothing.

### The five cryptographic approaches

Not variations on one idea — three different answers to *what do I do about a
validator that has never heard of ML-DSA*, plus the two that do not ask.

| Approach | What the certificate carries |
|---|---|
| **Classical** | RSA, ECDSA, Ed25519 — what a certificate has carried since RFC 5280. |
| **Pure post-quantum** | One key and one signature, both post-quantum: ML-DSA (RFC 9881), SLH-DSA (RFC 9909) and, as a subject key only, ML-KEM (RFC 9935). Anything older than OpenSSL 3.5 refuses the certificate outright, which is the trade. |
| **Composite** | One OID naming an ML-DSA key **and** a traditional key, two signatures inside one `signatureValue` (draft-ietf-lamps-pq-composite-sigs). A verifier checks both halves or understands neither. Still a draft. |
| **Hybrid** | A second key and signature in three **non-critical** extensions — `subjectAltPublicKeyInfo` (2.5.29.72), `altSignatureAlgorithm` (2.5.29.73), `altSignatureValue` (2.5.29.74), ITU-T X.509 (2019) clause 9.8 — so a validator that has never heard of them sees an ordinary certificate and accepts it. That is the entire point. |
| **Any** | Every algorithm this build has, listed together. |

**SLH-DSA key generation takes seconds and it runs on this thread.** This
process owns six listener families on one thread, so while one is being made
this service answers nobody. It is deliberately not moved to the worker pool:
that pool runs this service's own reading of the post-quantum constructions,
which is independent of the vendored one **on purpose**, and crossing the two to
save a button a few seconds is exactly the defect that independence exists to
expose. Generate one pair and issue several certificates from it with *reuse the
key pair below*.

### The twenty-two extensions

Every extension RFC 5280 defines, plus the ones in common use that it does not,
plus **anything at all by OID**:

`basicConstraints` · `keyUsage` (all nine bits) · `extendedKeyUsage` (sixteen
purposes and any further OIDs) · `subjectKeyIdentifier` ·
`authorityKeyIdentifier` · `subjectAltName` · `issuerAltName` ·
`cRLDistributionPoints` · `freshestCRL` · `authorityInfoAccess` ·
`subjectInfoAccess` · `certificatePolicies` · `policyMappings` ·
`policyConstraints` · `nameConstraints` · `inhibitAnyPolicy` ·
`privateKeyUsagePeriod` · TLS Feature (RFC 7633) · `id-pkix-ocsp-nocheck` ·
Netscape certificate type · Netscape comment · any other extension

**The `critical` flag is separately settable on most of them**, which is the
point: a validator must reject a certificate carrying a critical extension it
does not understand, so making the wrong one critical is a good way to find out
what your stack actually implements. Four are fixed critical because RFC 5280
says MUST or SHOULD and a box that could clear it would produce a certificate
nothing profiles.

Six of the boxes take one item per line, and each has a grammar:

| Box | A line is |
|---|---|
| subjectAltName, issuerAltName | `dns:` `ip:` `email:` `uri:` `upn:` `krb5:` `rid:` `dirname:` or `othername:<oid>:<base64 DER>` |
| authorityInfoAccess, subjectInfoAccess | `ocsp:<url>`, `caissuers:<url>`, `timestamping:<url>`, `carepository:<url>`, or `<oid>:<url>` |
| certificatePolicies | `<oid>` optionally followed by `\|cps=<uri>` and `\|notice=<text>` |
| policyMappings | `<issuer oid>=<subject oid>` |
| nameConstraints | `permit <name>` or `exclude <name>`. **An IP constraint takes a PREFIX** (`10.0.0.0/8`): a name constraint's `iPAddress` is the address followed by its mask, which is the one place a general name is not simply an address |
| any other extension | `<oid>\|<critical or ->\|<base64 DER of the extension value>` |

**A line one of them cannot read is refused and the message names it.** Nothing
is dropped: a certificate quietly missing a name somebody typed is the worst
outcome available here, because it verifies.

### The certification request nothing here consumes

Tick *generate a CSR* and the PKCS#10 this key pair and subject would have sent
to an external authority is built beside the certificate — from the **same**
inputs, because a request assembled from a second reading of the form would
differ in ways nobody could see.

**Three extensions travel and the rest do not.** A CSR carries what the
requester *asks for*, and `subjectKeyIdentifier` and `authorityKeyIdentifier`
are the issuer's to compute — a requester asserting them is asking a CA to
certify its own arithmetic. So key usage, extended key usage, basic constraints
and `subjectAltName` go in, and nothing else.

### Keys & Certificates

Everything the pane issues is kept **in the same place as the hierarchy** — this
realm's keystore row, sealed under the same key-encryption key — so there is one
answer to *where does this service keep a private key*. It inherits the mode:
product keeps it, development loses it with the process.

Select a row to export it or to load its key pair back into the form.
*Use this key pair* ticks **reuse the key pair below** itself, because a pair
loaded into the boxes and then silently replaced by a fresh one at the next
issue is the most confusing thing this pane could do.

**Building the hierarchy does not empty this store, and clearing this store does
not remove the hierarchy.** They are two things in one row, and one button
meaning both would be the worst kind of surprise on a page that holds key
material.

**Clearing *keep the private key in this service*** is the one control that
means something different from the debugger's. There it keeps the key out of the
browser's `localStorage`; here it keeps it out of the keystore row. The
certificate and the public key are stored either way, so the object can be
inspected and used as a trust anchor — and it can never sign again or be
exported.

### Export

PEM, DER, a JWK set or a password-protected PKCS#12, of the selected object or
of whatever is in the key boxes. It is the same export `/admin/keys` uses, so a
`.p12` from here imports identically into keytool, OpenSSL, Windows and macOS.

It needs **Admin Write**, like every other door here that hands over a private
key: reading this console needs Admin Read, and taking a key out of it needs the
other role. A DER export is two files and the private one is sent — this service
will not take a zip dependency to send two, and the public half comes out of the
private one with one `openssl` command.

## Driving it without a browser

Every control has an operation, through the same functions the console calls.

```bash
H="Authorization: Bearer $ADMIN_TOKEN"

# What this realm holds. No private key is ever in the reply.
curl -sk https://localhost:8081/admin-api/pki -H "$H"

curl -sk -X POST https://localhost:8081/admin-api/pki/build -H "$H" \
  -H 'Content-Type: application/json' \
  -d '{"keyAlg":"ec-p384","organisation":"Acme","country":"US",
       "cn_root":"Acme Root","years_root":30}'

curl -sk -X POST https://localhost:8081/admin-api/pki/issue -H "$H" \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"webapp1","days":90}'

curl -sk -X POST https://localhost:8081/admin-api/pki/revoke -H "$H" \
  -H 'Content-Type: application/json' -d '{"identifier":"webapp1"}'

curl -sk -X POST https://localhost:8081/admin-api/pki/clear -H "$H" \
  -H 'Content-Type: application/json' -d '{}'
```

**The pane has eight of its own, and every one of them takes and returns the
whole form.** That is not an API shaped by a page: `apply-profile` rewrites
twenty-two of its hundred and fifteen fields, and a caller reconstructing that
itself would be a second implementation of what a profile *means*. So the reply
carries `draft` — the form as it should now be — and you post back what came
back. `GET /admin-api/pki` publishes the whole field list as
`workbench.fields`, so the vocabulary is read from the service rather than from
a copy of it here.

```bash
# Fill the form in from a profile. Nothing is issued.
curl -sk -X POST https://localhost:8081/admin-api/pki/apply-profile -H "$H" \
  -H 'Content-Type: application/json' \
  -d '{"pki_profile":"tls-server","pki_pq_mode":"classical"}' > draft.json

# Issue from it: any profile, any issuer in this realm, every extension.
curl -sk -X POST https://localhost:8081/admin-api/pki/issue-certificate \
  -H "$H" -H 'Content-Type: application/json' \
  -d '{"pki_profile":"tls-server","pki_issuer":"tier:issuing",
       "pki_key_alg":"ec-p256","pki_dn_cn":"www.example.test",
       "pki_ext_san":"1","pki_san":"dns:www.example.test\nip:10.0.0.1",
       "pki_ext_ku":"1","pki_ku_digitalSignature":"1",
       "pki_ext_eku":"1","pki_eku_serverAuth":"1","pki_save_keys":"1"}'

# Write one out. `files[].base64` is the bytes; the console's own Download
# button answers with the file itself, because a browser asked for a file.
curl -sk -X POST https://localhost:8081/admin-api/pki/export -H "$H" \
  -H 'Content-Type: application/json' \
  -d '{"objectId":"leaf-…","pki_ks_format":"pkcs12",
       "pki_ks_password":"changeit","pki_ks_include_chain":"1"}'
```

The other four are `generate-keys` and `generate-alt-keys` (a pair into the form
without issuing), `use-key` (a stored pair back into it) and `remove-object` /
`clear-store`. **`clear-store` does not touch the hierarchy and `clear` does not
touch the store**, which is the same rule the two buttons follow.

## Configuration

Thirty-eight `pki.*` settings, in four groups. Two are restart-only
(`pki.autoBuild` and `pki.httpPort`); the rest take effect at runtime.

### The hierarchy

They are **defaults for a form** rather than policy: what a hierarchy was built
with is stored on the hierarchy, so a change here reaches the next build and
never a certificate that exists.

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `pki.autoBuild` | `PKI_AUTO_BUILD` | `true` | no (restart) | Build the hierarchy at startup and certify every key this service generates under it. **Restart-only**: a key can only be issued by an authority that exists when the key is made, and the keys are made at startup. Off leaves every generated key uncertified. |
| `pki.keyAlgorithm` | `STS_PKI_KEY_ALGORITHM` | `rsa-2048` | yes | The key algorithm a build uses when the form names none. RSA 2048 because the leaf signs a client assertion somebody else's OAuth library has to verify. |
| `pki.signatureAlgorithm` | `STS_PKI_SIGNATURE_ALGORITHM` | *(empty)* | yes | Empty means "the right one for the key algorithm" — see [above](#the-encoder-is-the-debuggers-own-vendored-byte-identical). `sha1-rsa` and `sha1-ecdsa` are development mode only: product uses the key's default instead and refuses setting either, or a build naming one (#181). |
| `pki.alternativeKeyAlgorithm` | `STS_PKI_ALTERNATIVE_KEY_ALGORITHM` | `ml-dsa-87` | yes | The post-quantum key every authority built holds beside its classical one, and signs everything it issues with a second time (ITU-T X.509 clause 9.8) — see [Every authority is hybrid](#every-authority-is-hybrid-a-second-post-quantum-key-and-signature). One of `ml-dsa-87`, `ml-dsa-65`, `ml-dsa-44`, `slh-dsa-sha2-256s`, `slh-dsa-sha2-192s`, `slh-dsa-sha2-128s` or `none`. **Warning:** `none` builds classical-only authorities; SLH-DSA costs seconds per certificate issued. |
| `pki.organisation` | `STS_PKI_ORGANISATION` | `sts` | yes | The `O=` every tier and leaf carries, and what the tiers are named after when no common name is given. |
| `pki.leafLifetimeDays` | `STS_PKI_LEAF_LIFETIME_DAYS` | `365` | yes | How long an issued signing certificate is good for, clamped to the Issuing CA's expiry. |
| `pki.rootLifetimeYears` | `STS_PKI_ROOT_LIFETIME_YEARS` | `0` | yes | A new Root CA's lifetime when the build names none; `0` is the profile's twenty years. |
| `pki.intermediateLifetimeYears` | `STS_PKI_INTERMEDIATE_LIFETIME_YEARS` | `0` | yes | A new Intermediate CA's lifetime; `0` is the profile's ten years, clamped to the Root's expiry. |
| `pki.issuingLifetimeYears` | `STS_PKI_ISSUING_LIFETIME_YEARS` | `0` | yes | Each new Issuing CA's lifetime; `0` is the profile's five years, clamped to its Intermediate's expiry. |
| `pki.maxStoredObjects` | `STS_PKI_MAX_STORED_OBJECTS` | `200` | yes | How many objects the Certificate & Key Configuration pane may keep in one realm; a full store refuses the next one rather than discarding the oldest. |

### Publishing revocation

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `pki.crlLifetimeMinutes` | `PKI_CRL_LIFETIME_MINUTES` | `60` | yes | The gap between `thisUpdate` and `nextUpdate` on every CRL, and the `nextUpdate` of every OCSP answer — short on purpose, so a revocation is seen while testing. |
| `pki.httpPort` | `PKI_HTTP_PORT` | `8082` | no (restart) | The plain-HTTP listener every certificate names for its CRL, OCSP responder and issuer's certificate. `/pki/` only; `0` binds nothing and the addresses then name the main port. |
| `pki.distributionBaseUrl` | `PKI_DISTRIBUTION_BASE_URL` | *(empty)* | yes | The whole base of the http addresses written into certificates, when the service is reached by a name or port it cannot derive. |
| `pki.distributionPort` | `PKI_DISTRIBUTION_PORT` | `0` | yes | The published port of those addresses; `0` means the listener's own. |
| `pki.distributionLdapHost` | `PKI_DISTRIBUTION_LDAP_HOST` | *(empty)* | yes | The host of the `ldap://` CRL address; empty means the first of `tls.hostnames`. |
| `pki.distributionLdapPort` | `PKI_DISTRIBUTION_LDAP_PORT` | `0` | yes | The published port of the `ldap://` address; `0` means `ldap.port`. |
| `pki.publishCrlToDirectory` | `PKI_PUBLISH_CRL_TO_DIRECTORY` | `true` | yes | Write each authority's CRL into the embedded directory under `ou=crl`, so the `ldap://` address resolves; off, the address is still written and fetches nothing. |

A change to an address reaches certificates issued afterwards and never one
that exists.

### Consulting revocation

How a certificate **presented** to this service, or registered and then used,
is checked — see
[Revocation is published, and consulted](#revocation-is-published-and-consulted).

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `pki.revocationCheck` | `STS_PKI_REVOCATION_CHECK` | `auto` | yes | `off`, `soft-fail` (refuse only a revoked certificate) or `hard-fail` (also refuse one whose status could not be established); `auto` is hard-fail in product mode and soft-fail in development. |
| `pki.revocationRequireDistributionPoint` | `STS_PKI_REVOCATION_REQUIRE_DISTRIBUTION_POINT` | `auto` | yes | Under hard-fail, whether a CA-issued foreign certificate that names no CRL and no OCSP responder (and no RFC 9608 `noRevAvail`) is refused. `auto` refuses it in product mode; `on` in both; **`off` accepts certificates nobody can ever revoke**. |
| `pki.revocationFetchTimeoutMs` | `STS_PKI_REVOCATION_FETCH_TIMEOUT_MS` | `3000` | yes | How long a fetch of a foreign CRL may take. |
| `pki.revocationMaxCrlBytes` | `STS_PKI_REVOCATION_MAX_CRL_BYTES` | `1048576` | yes | A distribution point answering more than this is treated as unreachable rather than read into memory. |
| `pki.revocationCrlCacheEntries` | `STS_PKI_REVOCATION_CRL_CACHE_ENTRIES` | `256` | yes | How many verified foreign CRLs, and remembered failures, are cached; the oldest goes first. |
| `pki.revocationCrlMaxAgeS` | `STS_PKI_REVOCATION_CRL_MAX_AGE_S` | `3600` | yes | A cached CRL is used until its own `nextUpdate` or this long after it was fetched, whichever is first. |
| `pki.revocationFailureRetryS` | `STS_PKI_REVOCATION_FAILURE_RETRY_S` | `60` | yes | How long an unreachable or unusable CRL is remembered, so a dead server costs one timeout per window; `0` retries every request. |
| `pki.revocationOcsp` | `STS_PKI_REVOCATION_OCSP` | `first` | yes | Whether a foreign certificate's OCSP responder is asked before the CRL (`first`), only when the CRL gave no answer (`after-crl`), or never (`off`). |
| `pki.revocationOcspMaxAgeS` | `STS_PKI_REVOCATION_OCSP_MAX_AGE_S` | `3600` | yes | How long an OCSP response with no `nextUpdate` is fresh, and the most any response is cached. |
| `pki.revocationOcspRequireNonce` | `STS_PKI_REVOCATION_OCSP_REQUIRE_NONCE` | `false` | yes | Refuse an OCSP response that echoes no nonce; off by default because pre-produced responses cannot carry one. |
| `pki.revocationClockSkewS` | `STS_PKI_REVOCATION_CLOCK_SKEW_S` | `300` | yes | How far a CRL's or OCSP response's `nextUpdate` may be past, or an OCSP `thisUpdate` in the future, before it is refused. |
| `pki.revocationCrlIssuersFile` | `STS_PKI_REVOCATION_CRL_ISSUERS_FILE` | *(empty)* | yes | A PEM file of indirect CRL issuers a distribution point may name in `cRLIssuer`; read again when it changes. |
| `pki.revocationLdap` | `STS_PKI_REVOCATION_LDAP` | `ldaps` | yes | Whether `ldaps:` (verified), also plain `ldap:` (`ldaps-and-ldap`), or no directory address (`off`) is dialled for a CRL or issuer. An address not dialled is not "no address": under hard-fail a certificate whose only list is there is refused (`STS-PKI-0188`). |
| `pki.revocationLdapCaFile` | `STS_PKI_REVOCATION_LDAP_CA_FILE` | *(empty)* | yes | A PEM file of CA certificates an `ldaps` directory's certificate may chain to, beside node's own CA store. |
| `pki.revocationHttpsCaFile` | `STS_PKI_REVOCATION_HTTPS_CA_FILE` | *(empty)* | yes | A PEM file of CA certificates an https CRL distribution point's or OCSP responder's certificate may chain to, beside node's own CA store (#201). |
| `pki.revocationLdapDirectory` | `STS_PKI_REVOCATION_LDAP_DIRECTORY` | *(empty)* | yes | The directory (scheme, host, port) a distribution point named relative to its CRL issuer is looked up in; without it such a name is not dialled. |

### Self-service and limits

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `pki.personSelfService` | `STS_PKI_PERSON_SELF_SERVICE` | `true` | yes | Whether `/portal/signing-key` offers a person an RFC 7523 or RFC 7522 key pair of their own; off takes away no key already held. |
| `pki.personSelfServicePerIdentity` | `STS_PKI_PERSON_SELF_SERVICE_PER_IDENTITY` | `5` | yes | How often one person may press Generate on `/portal/signing-key` in a `security.rateLimitWindowS` window. |
| `pki.personSelfServicePerAddress` | `STS_PKI_PERSON_SELF_SERVICE_PER_ADDRESS` | `5` | yes | The same limit counted per client address, for everybody behind one NAT or proxy. |
| `pki.personTlsClientCertificateMax` | `STS_PKI_PERSON_TLS_CLIENT_CERTIFICATE_MAX` | `5` | yes | Valid TLS client certificates one person may issue themselves on the portal; past it the portal refuses (`STS-PKI-0170`) rather than revoking an older one. |
| `pki.applicationTlsClientCertificateMax` | `STS_PKI_APPLICATION_TLS_CLIENT_CERTIFICATE_MAX` | `5` | yes | Valid TLS client certificates an administrator may issue one application; past it the issue is refused (`STS-PKI-0180`). |
| `pki.enrollmentMaxCertificatesPerEntry` | `STS_PKI_ENROLLMENT_MAX_CERTIFICATES_PER_ENTRY` | `20` | yes | Certificates issued over [ACME](acme.md), [EST](est.md) or [SCEP](scep.md) one entry may carry at once; past it a request is refused (`STS-ENROLL-0040`) rather than an older certificate being forgotten. |

Settings this page discusses that are not `pki.*`: the twelve
`*CertificateHeader` settings ([above](#a-signed-token-names-its-certificate-chain)),
`keys.kidFormat` ([above](#the-kid-can-be-the-keys-thumbprint-instead)) and the
`signing.*` rotation settings
([above](#signing-key-generations-and-the-crypto-metadata-document)). See
[Configuration](configuration.md) for how a value resolves and where it is
changed — `/admin/pki`, or `POST /admin-api/config/set`.

## Design decisions

* **One Root for the service; the realm boundary is the Intermediate.** An
  operator installs one anchor, and a path must still pass through the realm's
  own Intermediate — see [above](#the-root-is-shared-and-the-intermediate-is-not).
* **An Issuing CA per use case.** So one surface can be narrowed or rotated
  without touching the rest, and a relying party that trusts SAML has said
  nothing about OAuth — see [above](#an-issuing-ca-per-use-case).
* **Nothing about key generation changed, and the `kid` does not move.** The
  hierarchy only ever adds a certificate over keys made exactly as before — see
  [above](#nothing-about-key-generation-changed).
* **A branch is built whole, or not at all, and building again replaces.** A
  half-built hierarchy is the state in which a certificate verifies here and
  nowhere else — see [above](#a-branch-is-built-whole-or-not-at-all).
* **The issued leaf is a signing certificate, not a TLS one.** One certificate
  quietly doing both is how a deployment ends up unable to revoke either — see
  [above](#what-issuing-writes-and-what-it-forgets).
* **The private key is handed over once and the entry is where it lives,
  sealed.** This service keeps no second copy — see
  [above](#what-issuing-writes-and-what-it-forgets).
* **The RFC 7523 and RFC 7522 key pairs are two.** Neither signs for the other
  profile, and taking one off leaves the other working — see
  [SAML assertions](saml-assertions.md#two-key-pairs-one-application).
* **A lifetime is clamped, not refused.** A certificate that would outlive its
  Issuing CA is shortened to the CA's expiry.
* **Revocation addresses are `http://` and `ldap://`, never `https://` or
  `ldaps://`.** A client that checks revocation before trusting a connection
  cannot fetch the answer over that connection, so the plain listener on
  `pki.httpPort` exists — see
  [above](#revocation-is-published-and-consulted).
* **A CRL is per authority, not per realm.** A list is signed by an issuer and
  lists what that issuer minted, so a per-realm list would have no valid
  issuer.
* **Presented and registered certificates are checked for revocation, hard-fail
  in product mode.** `pki.revocationCheck`'s `auto` is soft-fail in
  development and hard-fail in product, because hard-fail is what stops an
  attacker who can block the fetch turning revoked into accepted.
* **The CA private keys follow the mode.** In memory in development, sealed in
  the persistence store in product, in the same place as the signing keys — see
  [above](#where-the-ca-private-keys-live).
* **One encoder, the debugger's own, vendored byte-identical.** A certificate
  issued here and one issued there are built by one implementation — see
  [above](#the-encoder-is-the-debuggers-own-vendored-byte-identical).
* **The page has no script.** Generating keys and issuing certificates are
  things the process holding the CA keys should do, not a browser — see
  [above](#the-page-has-no-script-on-it).
* **A limit refuses rather than forgets.** A full object store, a person's or
  an application's certificate cap, and the per-entry enrollment cap each
  refuse the next request instead of discarding something somebody may still
  be using.

## Related

* [JWT assertions](jwt-assertions.md) and [SAML assertions](saml-assertions.md)
  — what the issued key pairs are for
* [ACME](acme.md), [EST](est.md) and [SCEP](scep.md) — certificate enrollment
  from the realm's Issuing CAs
* [TLS and mutual TLS](tls.md) — the listener certificate and client
  certificates
* [SPIFFE](spiffe.md) — X509-SVIDs from the realm's SPIFFE authority
* [Remote PEP](remote-pep.md)
* [Trust realms](trust-realms.md)
* [Encryption at rest](encryption-at-rest.md)
* [What is not checked](what-is-not-checked.md)
* [Configuration](configuration.md) and [error codes](error-codes.md)
