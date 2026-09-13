# tls/

TLS and mutual TLS: two HTTPS listeners of its own, 8443 and 9443, whose whole
content is what the SERVER saw of the connection. One file — and it is the source
of the certificate and key that THREE other sockets in this process use.

`tls_server.js` is the newest of the four and the one whose sockets are easiest to
forget are sockets — and there are now TWO MORE TLS sockets in this process that are
not its own, both on `serverCertificate()`'s certificate and key rather than a second
pair: the directory's LDAPS listener on 636, and — when `global.https` is set, which
`oauth2.rfc9700` does by default — THE MAIN PORT ITSELF, bound as HTTPS from
`listen()` in `server.js`. So one anchor covers 8443, 9443, 636 and 8081, and a
caller trusts this service once per start rather than four times. The LDAPS half is
what makes `ldap_server.js` require this module, and therefore what fixes their order
in `server.js` (rule 6); the main-port half needs no require order at all, because
`server.js` already has this module in hand by the time it listens. The private key
crosses a module boundary and no network one: it is generated per start, held in
memory, and `GET /tls/server-certificate` publishes the certificate alone.

## The truststore reaches the MAIN listener too, since 2026-09-06

`POST /tls/trust` filled the client truststore for 8443 and 9443. It now fills
it for the main HTTPS port as well, and that is one function
(`trustClientCertificatesOn()`) plus one registration in `server.js`.

**WHY IT DID NOT BEFORE, AND WHY THAT STOPPED BEING RIGHT.** The main port has
always been `requestCert: true, rejectUnauthorized: false` — asked for, never
required — because RFC 8705 certificate-bound tokens need a certificate to be
ASKED for there, and section 3 binds to the certificate rather than to anybody's
opinion of it. With no `ca` passed, `socket.authorized` was false for every
client certificate ever presented on that port, and reading it would have been
reading a constant. That cost nothing while token binding was the only reader.

It stopped being right when the remote XACML PEP arrived. That caller has to be
RECOGNISED — its DN resolved to a directory entry, a group and a role — and
recognition is precisely what an unverified certificate cannot support: a DN
read off a certificate that chains to nothing is a name the caller chose for
itself.

**THE POSTURE ON THAT PORT IS UNCHANGED.** A certificate that chains to nothing
still completes the handshake and still binds a token. What the truststore adds
is that a certificate which DOES chain is now known to, and
`oauth-oidc/mtls.js`'s `peerVerified()` is where the two are told apart —
carrying node's own `authorizationError` out whole, because that string is what
tells somebody which of a dozen things went wrong.

Three listeners share one anchor list, so a single `POST /tls/trust` covers all
of them and `clearAnchors()` empties all of them. A listener created outside
this module registers rather than being required, for the ordinary reason:
`server.js` requires this module, so this module cannot require it back.


## The serial number is random, and a constant one was a browser-only bug

The self-signed certificate this module mints is regenerated at every start,
its subject never varies (`CN=localhost, O=sts`), and it is the one a
PERSON is asked to trust in a browser. Its serial was the constant `'03'` until
2026-09-01 — chosen so that two of this service's certificates could be told
apart in a packet capture — and NSS files a certificate under **(issuer,
serial)**. So the second start of this service produced a different key under a
pair Firefox had already seen, and Firefox refused the port outright:

```
SEC_ERROR_REUSED_ISSUER_AND_SERIAL
```

**That is a database conflict and not a trust warning**, which is what made it
worth writing down: there is no "accept the risk" past it, the message says
nothing about this service, and it appears only in a browser (curl and Chrome
keep no such index), only after a restart, and only once an earlier copy has
been trusted. Two of these processes running at once — a mock beside a test
stack — collide the same way with no restart at all.

The serial is now 128 bits of randomness with the caller's byte in FRONT of it,
so `03…` still says which of this service's certificates a capture is looking
at. `certificateSerial()` in `common/crypto.js` is where that is argued, and it
is the same 128-bit serial `common/vendored/x509.js` has always minted for a
SPIFFE SVID. The signing key's certificate (`'02'`, `common/helpers.js`) and
the ML-DSA one (`'04'`, below) were changed with it — neither is met in a
browser, so neither showed the failure, and leaving them constant would have
left the same trap for whichever socket a browser reached next.

## The certificate can be one somebody else issued

`tls.certificateFile` and `tls.keyFile` (`STS_TLS_CERT_FILE` / `STS_TLS_KEY_FILE`)
make this service serve a certificate it was given instead of the self-signed one it
issues at startup. Both or neither: one alone is refused at startup by name, because
a certificate and a key that do not go together fail inside the handshake with a
message about neither of them. A mismatched key and an unparseable file are refused
there too, for the same reason.

**Why it exists is arithmetic about a person, not about TLS.** Self-signed and
regenerated per start means the anchor changes on every restart, and this service is
a THIRD origin beside the debugger's UI and api. Handed a leaf from the same issuing
CA as those two, one trusted root covers all three and survives restarts — which is
what `../generate-tls-cert.sh` in the parent repository now issues, with this
service's own `tls.hostnames` defaults (`localhost`, `sts`, `sts-mock`,
`sts.example.com`) in the leaf's subjectAltNames so it answers to the names its
callers already use. One supplied pair reaches all four sockets, since they share
one.

The file may be a CHAIN — leaf first, issuers after — and all of it is sent, which is
what lets a client build a path to a root it holds. Everything that reads a
certificate back OUT of it takes the first: the fingerprint, the subject, the names,
and `GET /tls/server-certificate`.

`tls.certificateAlgorithms` is ignored while this is set, and says so: that setting
chooses among certificates this service ISSUES, and there is nothing to choose from
when it was handed one.

**`certificateProvenance()` is exported for the six modules that describe this
certificate to a reader**, and it is not decoration — it changes what the reader has
to DO. A self-signed certificate has to be fetched and trusted again after every
restart; a supplied one does not, and telling somebody to re-trust a certificate that
never changed sends them looking for a problem that is not there. `server.js`,
`ldap_server.js` (twice) and the LDAP metadata page ask it rather than asserting the
answer; `spiffe_server.js` says only that the certificate is not in the Web PKI,
which is true either way and spares it a require this module's ordering rules would
have to account for.

**One thing that arrangement costs, and it is stated on the page rather than left to
be met as a handshake failure**: with the main port TLS there is no plain listener in
this process, so `POST /tls/trust` and `GET /tls/server-certificate` — which exist to
be reachable BEFORE anything is trusted — have to be called the first time with
verification off.

Its own sockets: they speak **HTTP**, so they look as though they belong on the
plain listener — but they are HTTPS on 8443 and 9443, and `GET /admin/sts-metadata` walks
the plain listener's router, which cannot see them. Its four rows there are the
plain-HTTP views only, and the listeners are described in their text. Its truststore
for CLIENT certificates is empty at startup and is filled at runtime through
`POST /tls/trust`, because the CA it verifies is generated in somebody's browser
minutes before the connection; that endpoint is on the MAIN port on purpose, since
that is normally the one reachable before anything is trusted. `global.https` —
which `oauth2.rfc9700` turns on — takes that property away by making the main port
TLS as well, so the first fetch of the certificate and the first POST of an anchor
then have to be made with verification off. Every sentence in that module which
names the port goes through `mainPortPhrase()` for exactly that reason; seven of
them used to say "the plain HTTP port" outright, which would be quietly wrong in
the one place a reader goes when a handshake is failing.

---

## A verified client certificate IS a login now, and its revocation is checked first

**THIS SECTION SAID THE OPPOSITE UNTIL 2026-09-05 AND ITS HEADING WAS "A
verified client certificate is not a login".** The old text is below, kept
rather than deleted, because it was a good argument and knowing exactly what it
protected is how to avoid losing that.

* **A request on a connection carrying a verified client certificate starts a
  sign-on session** for the certificate's common name — or its RFC 4514 subject
  where it has none — and the response carries the session cookie. Cookies are
  not port-scoped, so a browser that presents a certificate to 9443 comes away
  signed in on the main port too, which is single sign-on and is the same thing
  every other family here already gives it.
* **What did NOT change is the strength of the CHAIN claim.** Verification still
  means one thing exactly: OpenSSL built a chain from what the client sent to an
  anchor in the truststore. ~~**No revocation is checked**~~ — **since
  2026-09-12 it is**, before the session starts and before the authentication is
  recorded; see the section below. `authentication.revocationChecked` used to be
  the constant `false` beside `authenticated: true`, and is now what the check
  did.
* **Why it changed.** PKI client-certificate authentication is a real, deployed
  way for a person to sign in to a web application, and this service exists to
  exercise clients of exactly that kind. Every other family here resolves the
  same tension the same way and always has — the KDC issues tickets to anybody
  with the one shared password, the sign-in screen checks nothing, LDAP refuses
  no bind — and all three start real sessions. **The permissiveness lives in what
  is ACCEPTED, not in refusing to record what was accepted.** This listener was
  the one place that made the opposite choice, and what it cost was that a global
  sign-out could not end a way in that nothing on `/admin/sessions` could see.
* **The identity is the COMMON NAME and the record is the SUBJECT**, and they are
  deliberately different strings. A certificate naming `CN=alice` signs in the
  same alice the password screen, the KDC and the SAML profile do — one entry per
  person whatever they authenticated with, a rule this repository keeps in eight
  places. What goes in the DIRECTORY is the certificate's own full subject,
  because that is the identity the certificate asserts.
* **`amr` is `["swk"]`** — RFC 8176's software key — and `acr` is `"1"`. One
  factor, and a factor whose private key sits in a file: claiming `hwk` would
  say a hardware key was used and this service cannot know that.
* **One session per connection at most.** The cookie comes back on the next
  request and is honoured, so six requests on one connection are one sign-in —
  the same property `recordClientCertificate()` gets by living on
  `secureConnection`, reached differently because a cookie needs a response to be
  written on and that event has none.

### The argument that used to be here

* **A verified client certificate on the TLS listeners is not a login**, and no
  revocation is checked there. Verification means one thing exactly: OpenSSL built a
  chain from what the client sent to an anchor somebody POSTed to `/tls/trust`. No
  session starts, no token is issued, no endpoint will let its holder do anything an
  anonymous caller cannot, and a revoked certificate verifies here and would not
  verify anywhere that matters. All of that is stated in the report itself rather
  than left to be discovered — a mock that quietly turned a certificate into an
  identity would teach a client something false about every server it will ever meet.

  *Every sentence there about VERIFICATION still holds. The one that stopped
  holding is "no session starts", and the reason it was written — that a mock
  must not overstate what a chain check proved — is now carried by
  `revocationChecked: false` sitting beside the session in the same report.*
  **It IS recorded, which is a different claim and the two must not be merged.** When
  a handshake completes with a certificate that verified, `tls_server.js` calls
  `stats.recordAuthentication()` — the same funnel every other family uses — so the
  subject DN appears on `/admin/users` under protocol `TLS` and the directory's
  observer seeds an entry for it. Three things there are load-bearing: it happens on
  `secureConnection` and **not in the request handler**, because the credential was
  accepted at the handshake and per-request counting would report one connection's six
  requests as six authentications; it happens only when `authorized` is true, so a
  certificate that failed records nothing on the permissive listener; and the identity
  is the subject in **RFC 4514 form** (leaf first, values escaped), which is a
  different string from the display DN shown beside it and is the one the directory
  builds from.

* **`dnRfc4514()` NOW LIVES IN `common/helpers.js` and is re-exported from here.**
  It was written in this module and the export stays, because `scim_auth.js` and
  `spiffe_auth.js` require this module for it. What forced the move is a FOURTH
  producer of that string: the SPIFFE authority records the certificate behind
  every X509-SVID it mints onto the holder's directory entry, using **the same six
  `x509*` attributes this path writes**, and `spiffe_ca.js` cannot require this
  module — `admin.js` requires that one and is required first, so the require
  would move every `/tls*` route ahead of the console's and `GET /admin/sts-metadata`
  walks that router. Two spellings of one DN is two people on `/admin/users`,
  which is the sentence the export comment here has always carried; there are now
  four callers of it rather than two. `common/CLAUDE.md` has the argument,
  including the second shape of DN the function learnt for that caller.

* **The SPIFFE path ASSIGNS those six where this one APPENDS, and the difference
  is not a disagreement.** A renewed client certificate is a new serial for the
  same person and is rare, so appending is what makes both visible. An X509-SVID
  is minted afresh at half its lifetime for as long as the workload runs, so
  appending there would add six values an hour for ever. See
  `applySpiffeCertificate()` in `ldap/ldap_server.js`, which says so beside
  `certificatePlan()` for exactly this reason: the two functions look alike
  enough to be "fixed" into agreement by somebody reading only one.

## A PRESENTED CERTIFICATE'S REVOCATION IS CONSULTED (2026-09-12)

`common/revocation_status.js` is the check and `common/CLAUDE.md` 3ad argues it.
What is this directory's:

* **8443 AND 9443 CHECK BEFORE THEY ACT.** The handler awaits the verdict
  (`checkedSocket()`) and then answers (`answer()`); `secureConnection` awaits it
  before `recordClientCertificate()`. A certificate the policy refuses starts
  **no session**, is **not recorded** as an authentication (it gets a refusal
  audit row with `STS-PKI-0118` or `-0119` instead), and on the **required
  listener answers 403** with the report as its body. The optional listener still
  answers 200 — reporting is what it is for — and its `authentication` block says
  `refusedOnRevocation: true`. `/tls/whoami` carries the whole verdict at
  `clientCertificate.revocation`; `GET /tls` carries the policy at `revocation`.
* **NOT AT THE HANDSHAKE, AND THAT WAS MEASURED RATHER THAN ASSUMED.** Node's
  `crl` secure-context option turns on OpenSSL's CRL check for the leaf, which
  then REQUIRES a CRL for every issuer: a client from an authority with no list
  loaded fails with `UNABLE_TO_GET_CRL` (two CAs, a CRL for one — the other's
  client was refused). It is also static, leaf-only and fetches nothing. So the
  handshake completes and the request, the session and the recorded identity are
  what get refused.
* **THE MAIN PORT IS `common/app.js`'s ANNOTATION**, read by
  `oauth-oidc/mtls.js`'s `peerVerified()` — which answers `verified: false` with
  `error: 'CERT_REVOKED'` for a refused chain, so every caller that resolves a
  certificate to an identity refuses it — and by SCIM's and RFC 8705's
  client-certificate doors. With request workers the check runs in the worker,
  which sees the chain because `common/request_pool.js`'s `peerOf()` forwards
  `issuerChain` beside the leaf now.
* **LDAPS 636 IS NOT A DOOR**: it asks for no client certificate.
* **A FOREIGN CLIENT CERTIFICATE IS ASKED ABOUT BY OCSP TOO, THE SAME DAY**, and
  its delta and indirect CRLs are read — which matters here more than anywhere,
  because these two listeners are where a certificate from somebody else's CA
  most often arrives. Two consequences for this directory. **A first request can
  wait on two fetches**, the responder and then the CRL when the responder fails,
  each bounded by `pki.revocationFetchTimeoutMs`; the answers are cached, so the
  second request with the same certificate waits on neither. **And the 403 on
  9443 now also means "the issuer's own responder does not know this
  certificate"** under hard-fail — `unknownKind: 'responder-unknown'` on the
  link in `clientCertificate.revocation`, which is where to look before reading
  a 403 as a revocation.
* **AND SINCE THE THIRD PASS THE FIRST REQUEST CAN WAIT ON MORE THAN TWO.** A
  delegated responder's own CRL is fetched before its answer is used; a list whose
  signer nothing here holds has that signer fetched from the list's caIssuers
  address; a distribution point may be `ldaps:` (or `ldap:`, where
  `pki.revocationLdap` allows it). Each is bounded by the same timeout and cached.
  **Under hard-fail a 403 can therefore also mean** a delegated responder whose own
  status could not be established (`STS-PKI-0127` in the log), a caIssuers address
  that did not answer (`STS-PKI-0126`), or a directory that answered unusably
  (`STS-PKI-0128`) — each named in `clientCertificate.revocation`'s `why`.
  **A presented chain whose issuer the client did not send is not path-built**
  from caIssuers: the handshake could not have verified without it, so the case
  does not reach these listeners.

`tests/revocation_status.js` binds both listeners on port 0 in a child process
and asserts the 403, the 200 and the absent session over a real handshake. Its
OpenSSL child (sections 8 to 11) holds OCSP, delta and indirect CRLs against a
real `openssl ocsp` responder and `openssl ca` lists; it calls `verdictFor()`
directly, because what those sections vary is the documents, and the listener
half already shows that a refused verdict reaches both ports.

## Post-quantum certificates

`tls.certificateAlgorithms` (`STS_TLS_CERT_ALGS`) decides what the two
listeners present. It is `rsa` alone by default and takes any of `ml-dsa-44`,
`ml-dsa-65` and `ml-dsa-87` beside it, comma separated.

**More than one is the setting worth having.** node takes parallel `key`/`cert`
arrays and OpenSSL serves whichever certificate matches the signature
algorithms the CLIENT offered — so `rsa,ml-dsa-65` answers an ordinary client
with RSA and a post-quantum one with ML-DSA over the same port and the same
listener. That is what a migration looks like, and it is a property of OpenSSL
rather than of this code, which is why `tests/pq_certificates.js` asserts it
rather than describing it.

The ML-DSA certificate comes from `common/crypto.js`'s
`selfSignedMlDsaCertificate()`. **node-forge cannot build it** — it has no
ML-DSA and cannot represent the key — so the key and the signature come from
node's own OpenSSL 3.5 and the DER is written out there against RFC 9881 and
RFC 5280. It is deliberately not vendored from the debugger: this service is
the far end of that code, and two copies of one reading of a specification
agree with each other and interoperate with nothing. `common/pq_jose.js` makes
the same argument at greater length.

**IT NEEDS NODE 24, AND ASKING FOR IT ON AN OLDER ONE NO LONGER STOPS THE
SERVICE.** ML-DSA reaches node with OpenSSL 3.5, which is node 24 — the version
the Dockerfile pins (24.16.0). On node 22 `generateKeyPairSync('ml-dsa-65')`
throws `ERR_INVALID_ARG_VALUE`, and until 2026-09-01 that throw came out of the
certificate block at this module's TOP LEVEL: a `require` that throws takes the
whole process down where a route could not, so a developer on node 22 who set
`tls.certificateAlgorithms` met a mock that would not start — sixteen other
protocol families stopped by a certificate nobody was going to connect with.
`common/crypto.js` answers the question instead (`mlDsaAvailable()`, a probe
that GENERATES a cheap key rather than comparing `process.versions`, because the
version is a proxy for what the linked OpenSSL has), this module warns and skips
the algorithm, and the existing fall-back to RSA does the rest. The
post-quantum JOSE algorithms are untouched by any of it: they come from
`@noble/post-quantum` and need nothing of OpenSSL. `tests/pq_certificates.js`
asserts the refusal names the runtime and the requirement, which is the only
branch of this a node 22 can reach.

Three consequences are worth knowing before turning it on:

* **`GET /tls/server-certificate` returns every certificate**, concatenated. A
  truststore built from the first one alone fails to verify the connection it
  actually gets, and which one it gets is the caller's own doing.
* **Whether the `openssl` binary can read any of it depends on which one you
  have.** 3.5 prints an ML-DSA certificate in full; 3.0 — Ubuntu 22.04's, and
  `ubuntu:latest`'s until recently — says `Unable to load certificate`. Node
  reads it whatever the binary does, because node's OpenSSL moves with the node
  version rather than with the image.
* **`/tls/whoami` reports the post-quantum posture in two independent halves**,
  the key exchange and the certificates, because they answer different
  questions on different timescales and a single boolean would be wrong for
  almost every connection made today. Node cannot NAME a hybrid ML-KEM group —
  `getEphemeralKeyInfo()` knows ECDH and DH only — so an unnamed group is
  reported as unnamed, with both readings (a hybrid group, or a resumed
  session) rather than a guess.

LDAPS on 636 keeps serving the FIRST certificate, which is the RSA one unless
the setting says otherwise: no LDAP client in reach speaks ML-DSA, and the
point of that listener is that one anchor covers 8443, 9443 and 636.

**AND THE ML-DSA CERTIFICATE IS A LEAF OF THE TLS ISSUING CA TOO, SINCE
2026-09-13.** It was the one key pair on these sockets still self-signed after
the RSA certificate came under the Root, so a post-quantum client that OpenSSL
handed it had to pin it while a classical client on the same port trusted the
anchor. Each ML-DSA certificate is registered with `common/pki.js` beside the
RSA one — slot `server:<algorithm>`, `digitalSignature` alone, the same
subjectAltName through `serverCertificateExtensions()` — and adopted through the
same `takeIssuedCertificate()`, so the two cannot disagree about what adopting a
certificate involves. **The KEY is still made by node's OpenSSL** in
`makeMlDsaServerCertificate()`, and what `pki.js` is handed is the SPKI that
same OpenSSL exports: the Issuing CA signs, and nothing asks the vendored
encoder to sign with an ML-DSA key. `reconcileWithHierarchy()` checks every
certificate this process had certified rather than the first, because a
rebuilt Root strands an ML-DSA leaf exactly as it strands the RSA one.
`serverCertificateChains()` is the public view of all of them, and
`tests/pq_key_certification.js` section F pins it on node 24.

## THE LISTENER CERTIFICATE IS ISSUED BY THIS SERVICE'S OWN ROOT (2026-09-11)

It was SELF-SIGNED for this module's whole life, and that shaped everything
around it: anybody who wanted to verify this service had to fetch that exact
certificate and trust it, a restart invalidated what they had trusted, and
`POST /tls/trust` exists partly because of it.

Now `common/pki.js` builds a Root for the service at startup and this
listener's key is a leaf of it — under a **process** Intermediate rather than
a realm's, because these sockets are shared by every realm and one realm's
Intermediate signing the certificate every realm's front door presents would be
that realm vouching for all the others.

**So ONE anchor covers 8443, 9443, LDAPS 636, the main port AND every token
this service signs**, and it survives a restart wherever the keystore does.

Four things about how it is wired are worth knowing before changing any of it:

* **IT IS A REGISTRATION AND NOT A CALL.** This module hands `pki.js` a
  `registerCertifiable()` record at require time and that module acts on it in
  `start()`. A require in the other direction would drag every `/tls` route
  into the router wherever `pki.js` is first required from — which is
  `common/service_state.js`, above everything.
* **THE ORDERING IS WHAT MAKES IT WORK.** This module is required at 20 and its
  certificate is built at require time; `pki.start()` runs afterwards and
  BEFORE `listen()` binds anything. So no client ever sees the self-signed one
  and nothing is re-keyed under a live listener.
* **THE LISTENERS HAVE TO BE TOLD.** `permissiveServer` and `strictServer` are
  created at module top level with their secure context evaluated THERE, so
  mutating the certificate record is invisible to them. `onCertified` calls
  `applyAnchors()` — the rebuild path `POST /tls/trust` already uses — and
  without that line the certificate is issued, recorded, reported on every page
  and **not served**, which is the most convincing way for this to look
  finished and be wrong.
* **THE CHAIN GOES ON THE WIRE.** `secureContextOptions()` sends the leaf
  followed by the Issuing CA and the Intermediate, because a client holding
  only the Root needs them: without that, "trust this one anchor" is true and
  unusable, and the failure is `unable to get local issuer certificate`, which
  names nothing.

**A SUPPLIED CERTIFICATE IS LEFT ALONE.** `tls.certificateFile` means an
operator handed this service a certificate somebody else issued, and re-issuing
it under this mock's Root would be the opposite of what they asked for.

### AND THE ANCHOR STOPPED BEING THE CERTIFICATE, WHICH BROKE THREE CALLERS THE SAME HOUR

The section above got the SERVING side right and left the PINNING side alone,
and those are two different questions the moment a leaf acquires an issuer.
Three callers in this repository answered the second one by reading
`serverCertificate().certPem`, and all three were correct for as long as that
certificate was self-signed:

| Caller | What it is | What it did instead |
|---|---|---|
| `common/oidc_rp.js`'s back channel | how `/admin` and `/portal` redeem an authorization code at `/oauth2/token` | **the admin console could not be signed into** — *Signing in did not complete*, with `the loopback request to /oauth2/token failed: unable to get local issuer certificate` under it |
| `ssf/ssf_http.js`'s push | delivery to this service's own two Shared Signals receivers | every push to a loopback receiver failed |
| `tests/tools/trust.js` | the anchor every node-driven job in the protocol suite is handed as `NODE_EXTRA_CA_CERTS` | the suite could not open a connection to the service at all |

**WHY IT LOOKS LIKE A PIN AND REFUSES EVERYTHING.** OpenSSL takes a
SELF-SIGNED leaf found in a truststore as an anchor — which is the surprise
`tests/tools/trust.js` has a paragraph about, since this certificate carries
`basicConstraints CA:FALSE`. It will not do the same for a CERTIFIED one: the
path walks leaf → Issuing CA → Intermediate, finds no Root, and fails at depth
2 about a certificate the caller was never given. So the pin does not weaken,
it **refuses every connection**, which is worse than no pin because it reads as
a broken server.

**`serverCertificate()` ANSWERS BOTH QUESTIONS NOW.** `chainPem` is what the
certificate TRAVELS WITH (the Issuing CA and the Intermediate, leaf-first and
without the Root, as RFC 5246 section 7.4.2 asks); `trustAnchorPem` is what a
caller VERIFIES it against. `trustAnchorPems()` answers the Root when this
service has one and the self-signed certificate when it does not — which is
what `tls.certificateFile` and any process that never runs `pki.start()`
(`npm test`, every in-process job) leave behind. **The invariant is that the
anchor is SELF-SIGNED**, not that it is any particular certificate, and a call
site should never have to know which of the two states it is looking at.

**`GET /tls/server-certificate` PUBLISHES THE CHAIN AND THE ROOT WITH IT.**
That is a change of content and not of contract: every document in this
repository that names that path tells a reader to fetch it and TRUST it, and
that stopped being possible the hour these certificates were certified. The
leaves stay FIRST — `tests/tools/trust.js` reads the first certificate to
compute the SPKI pin the browser job uses, and a reader looking for "the server
certificate" should find it at the top. It still publishes no private key.

**AND ONE SOCKET WAS SERVING THE CERTIFICATE THIS PROCESS THREW AWAY.** The
bullet above says no client ever sees the self-signed one, and that was true of
this module's own two listeners and of the main port and false of LDAPS 636:
`ldap/ldap_server.js` reads `serverCertificate()` at REQUIRE time, at 21, which
is before `pki.start()`. So 636 presented the self-signed certificate while
8443, 9443 and the main port presented the certified one — *one anchor covers
all four* said on that module's own page, and false on the one socket it is
about. It re-reads the record and calls `setSecureContext()` on the way into
`listen()` now, which is also how the chain gets onto that wire.

`tests/tls_trust_anchor.js` pins all of it, and pins it as a HANDSHAKE: every
version of that test which compared subjects and issuers passed on a truststore
OpenSSL would refuse, which is precisely the state this service was in.

## THE PUBLISHED ANCHOR MUST SIGN THE PUBLISHED CHAIN (2026-09-11)

`GET /tls/server-certificate` hands a client a truststore: the listener's leaf,
the chain it travels with, and the Root to verify them against. **The first two
are a SNAPSHOT and the third is read LIVE**, and on the day the listener became
a certified leaf rather than a self-signed certificate, those two halves came
apart.

`SERVER_CERTIFICATE.chainPem` is filled by `onCertified` when the listener is
certified. `trustAnchorPems()` asks `common/pki.js` for the service Root every
time it is called. Replace the Root without rebuilding the branch beneath it
and the bundle is four certificates from two hierarchies.

### It survives being looked at, which is the whole reason it cost a day

Every Root this service builds is called `<organisation> Root CA`. The broken
bundle therefore has the right subjects, the right issuers, in the right order,
and a Root whose KEY signed none of it. Nothing that compares names can see it
— not the console, not `openssl x509 -subject`, not a log line. The only check
that tells the two apart is the SIGNATURE.

**And `curl` accepts it while node does not.** `curl --cacert bundle.pem`
answered 200 throughout; every node client answered `unable to get local issuer
certificate`. So the obvious by-hand check said the service was fine while this
repository's entire protocol suite — every job is a node process — failed at
its first request, two post-quantum jobs spun until the 300s watchdog, and this
service's own OpenID Connect back channel could not redeem a code, which took
out every `/admin` and `/portal` sign-in. `openssl verify` names it properly:
`error 30 at 2 depth lookup: authority and subject key identifier mismatch`.

### The fix is in `common/pki.js` and the guard here is the net

**`certify()` rebuilds a branch that no longer chains to the Root before it
issues anything from it.** That is the repair, and it is there rather than here
because that function is the one funnel every leaf in this service goes through
and the only place that holds the branch and the Root at once. Re-issuing the
leaf alone — which is what happened — changes the leaf and leaves the chain,
so the bundle still goes out unverifiable.

`trustAnchorPems()` additionally REFUSES to publish an anchor that does not
sign the chain in hand (`anchorSigns()`), and that is a net rather than the
fix: it catches the one case the repair cannot reach, which is **a request
worker holding a `pki` state of its own while the front process owns the socket
and supplied the certificate**. That process never issued what it is serving,
so it has nothing to repair.

### It publishes NOTHING rather than the Intermediate, and that was tried

The obvious substitute for a Root that will not do is the chain's own
Intermediate: it is a CA, so it looks like a usable anchor. **OpenSSL will not
terminate a path at a trusted certificate that is not self-signed** without
`-partial_chain`, so `openssl verify` still fails and so does every client that
does not set it. An anchor only some clients can use is the same class of
mistake one layer along, so the bundle goes out as leaf + chain with no anchor
and the error says to rebuild the hierarchy.

`serverCertificate().trustAnchorPem` answers `''` in that state rather than the
leaf. The leaf is the right answer for a SELF-SIGNED listener, where it really
is its own anchor; where there is a chain, a leaf in a truststore terminates no
path — which is the bug the comment beside `trustAnchorPems()` already warned
about, reintroduced as a fallback.

`tests/pki_anchor_drift.js` pins all of it, and it is in process because no
endpoint can produce the state: `/admin-api/pki/build-root` rebuilds every
branch in the same act, which is correct.

## A WORKER IS HANDED THE CERTIFICATE, THE CHAIN **AND THE ANCHOR** (2026-09-11)

The hand-off already existed and was half done. `handedInCertificate()` took
`STS_TLS_SERVER_CERT_PEM` and `STS_TLS_SERVER_KEY_PEM` — the leaf and the key —
so every process presented the same certificate. **Nothing carried the chain or
the anchor**, so a worker had neither: it presented a leaf with no chain, and
`trustAnchorPems()` fell through to asking `common/pki.js` for the Root, which
in a worker is a Root that worker built itself.

The certificate came from the front process and the anchor came from the
worker. Two hierarchies, the same subject name, and `/admin` and `/portal`
failing their own OpenID Connect back channel with **`unable to get local
issuer certificate`** — the console's *Signing in did not complete*.

`server.js` now hands all four across, `request_pool.js` carries them,
`request_worker.js` installs them, and `trustAnchorPems()` **prefers a handed-in
anchor over anything this process's own PKI would answer** — because a worker
does not own the socket and did not make the certificate, so its own Root is
not an answer it can honestly give. The handed anchor still goes through
`anchorSigns()`: one that does not sign the certificate it arrived with is a
hand-off gone wrong rather than a hierarchy drifting, and is reported.

### The chain is CONCATENATED, and two wrong separators got there first

The key stays out of `process.env` for the reason the older block above gives.
The chain and the anchor are PUBLIC — a chain travels in every handshake, the
anchor is published at `GET /tls/server-certificate` — so the environment costs
nothing for them.

**NUL was the first separator and it is the one byte an environment variable
cannot carry.** It is a C string: the value truncates at the first NUL, so the
worker received the Issuing CA and silently lost the Intermediate. It was
caught only because the log line counts what arrived and said `1 chain
certificate(s)` where there were two.

**Then the split regex lost a newline.** `/(?<=-----END CERTIFICATE-----\n?)/`
splits BEFORE the newline when the `\n` does not match, so the first
certificate loses its final line ending and the next gains a leading blank
line. OpenSSL rejects both — `error:04800066:PEM routines::bad end line` — and
**not one of the three workers started**, which the pool correctly reported and
then handled every request in the front process.

There was never a separator to choose: concatenated PEMs are self-delimiting,
which is how that endpoint already publishes a bundle and how every other
reader here already splits one. Each piece is re-normalised on the way out so a
bundle with no trailing newline still yields usable PEMs.

## AND THE HAND-OFF IS A SNAPSHOT, WHICH THE ROOT BEING REBUILT BROKE (2026-09-12)

Everything in the section above is about a worker being handed the right
material **at fork time**. It is right and it is not enough: `process.env` is
read once, before this module loads, and this service has a control that
replaces every certificate in it while it is running.

`POST /admin-api/pki/build-root` replaces the Root, every Intermediate and
Issuing CA under it, and the leaf this listener is serving. In ONE process that
is the end of it — `certify()` fires `onCertified()`, which mutates the record
and calls `applyAnchors()`, and the socket has the new certificate in the same
act. **With request workers it lands on a worker**, because that request is
dispatched like any other, and then two processes disagree about a certificate
neither can see the other holding.

### The worker certified a certificate it does not serve

A worker registered a certifiable at require time like every other process, so
`pki.start()` issued it a leaf from the hierarchy IT holds and `onCertified()`
overwrote the handed-in record with it. That was invisible at startup — the
service Root is shared, so the worker's own `*process` Intermediate is signed by
it and `anchorSigns()` is satisfied — and it became visible the moment a worker
rebuilt the Root: its record's chain was now from the NEW hierarchy while the
handed anchor was the OLD Root, so `trustAnchorPems()` reported the hand-off as
broken (which it was not) and fell back to this process's own Root. **That Root
signs nothing the front process is serving**, so every OpenID Connect back
channel that worker ran failed with `unable to get local issuer certificate` —
reaching a reader as `/admin/callback` and `/portal/callback` answering 400.

**A worker certifies nothing now.** `handedInCertificate()` marks the record
`handedIn`, and `certifyServerCertificateUnderPki()` returns on it — the same
shape as the older refusal above it for `tls.certificateFile`, and for a
stronger reason: an operator's supplied certificate must not be re-issued
because they asked for it, and a worker's must not be because **a worker owns no
socket**. It serves what it was handed and pins what came with it.

### And the front process had to learn that its own certificate had gone stale

The other half, and it is the one that leaves a service publishing nothing
usable. The front process ADOPTS the rebuilt hierarchy — that part already
worked, a CA is a row and `request_pool.js`'s `receivePublishedPki()` has
carried it since the pool existed — and went on serving a leaf whose Root
nothing in the service holds any more. `trustAnchorPems()` then refuses to
publish an anchor, correctly, and `GET /tls/server-certificate` answers a bundle
of leaf + chain that **terminates nowhere**: `UNABLE_TO_GET_ISSUER_CERT_LOCALLY`
for every client that fetches it from then on.

`reconcileWithHierarchy()` is the repair and it is deliberately thin. It asks
`anchorSigns()` whether what this listener presents still chains to
`pki.serviceRoot()`, and where it does not it calls `pki.certifyRegistered()` —
the same call `pki.start()` makes, and `certify()` rebuilds a branch that no
longer chains before it issues from it, so one call repairs the branch and the
leaf together. **The check is the SIGNATURE and not a name or a serial**: the
two Roots this has to tell apart have identical subjects, which is why every
version of this written as a name comparison passes on exactly the broken case.

It is called on every hierarchy any process publishes and does nothing at all in
the ordinary case, which is what makes calling it there affordable.

### Then the workers are told, over IPC, with no private key in it

`serverCertificateBundle()` is what goes out — leaf, chain, anchor — and
`adoptServerCertificate()` is what a worker does with it. **No key travels**,
and that is not caution: a worker PINS and REPORTS this certificate and never
presents it, because the socket is the front process's, so the key it was handed
at fork is still the only one it needs and still the only copy in that process.

`common/request_pool.js`'s `reconcileTheListener()` is the caller and its header
argues the shape against the LDAP connection list, which is the other thing in
this service that is a socket rather than a row. The two are deliberately
different: the directory needed a mirror pushed OUT and an instruction sent
BACK, because the decision to end a connection is a worker's; here the decision
is the front process's alone — it owns the certificate — so nothing comes back
and what goes out is the result.

**`tests/worker_server_certificate.js` pins both halves**, seven mutants, all
caught. Section A runs in a CHILD PROCESS, because the environment has to be set
before this module loads and a module loaded once cannot be asked twice — the
same reason `tests/tls_trust_anchor.js`'s first section forks.

### What it cost the suite, which is the other half of the same day

The protocol half pinned the service's certificate ONCE, at run start, which was
right for as long as this certificate could only change when the process did.
`tests/vendored/sts_admin_api_operations.js` drives every declared operation of
the management API, `build-root` among them, so **every job after it lost its
anchor**: twenty-nine failures per mode in `memory` and `postgres`, each naming
a certificate and none naming a cause, on a service that was answering
perfectly throughout. `tests/tools/run-report.js` re-reads it before every
protocol job now; `tests/CLAUDE.md` carries that half.

## THE TRUSTSTORE IS A TEST CONTROL ONLY IN DEVELOPMENT MODE (2026-09-12)

`POST /tls/trust` and `POST /tls/trust/clear` answered anybody who could reach the port,
and since 2026-09-06 an anchor decides whose client certificate becomes an IDENTITY — a
directory entry, a group, a role, and for a remote XACML PEP the documents this service
enforces its own access with. **In product mode both answer 403**, naming
`tls.trustAnchorsFile`: a PEM file read at require time, before 8443 and 9443 are created
from `secureContextOptions()` (which is why it pushes into `anchors` directly — `addAnchors()`
re-applies the context to listeners that do not exist yet). A file that cannot be read, or
holds no certificate, is FATAL.

**The mode is asked in the DEFAULT realm** (`truststoreOpenToAnybody()`): the anchors are
one array for every listener in the process, so a realm left in development inside a
product process must not be a way to add one.

**REFUSED RATHER THAN GATED, AND THAT IS A STRUCTURAL CHOICE.** The natural gate is
`/admin-api`'s access token with `admin:write`, and that verification is middleware inside
`mgmt-api/admin_api.js`, exported as nothing — a copy here would be a second answer to who
may administer this service. **That argument still holds for these two routes and they are
unchanged**; what it no longer implies is that product mode has no runtime door. It read
*"there is no management-API truststore operation either … the runtime door still to
build"*, and the next section is that door.

## THE GATED DOORS: `/admin/tls/trust` AND `/admin-api/tls/trust` (2026-09-12)

The runtime door the section above was missing, built the way that section said it had to
be: behind the gates that already exist rather than a copy of one here. The console page
lists every anchor — subject, issuer, serial, validity, SHA-256 fingerprint and **source**
(`file` for one read from `tls.trustAnchorsFile`, `runtime` otherwise), paged — with an add
form and a Remove button per row; `GET /admin-api/tls/trust` and `POST
/admin-api/tls/trust/{add,remove}` are its twins (rule 7). Both answer in both modes.

**THIS MODULE OWNS WHAT A CERTIFICATE IS AND NOTHING ELSE.** `truststore` — `list`, `add`,
`remove` — is the whole interface: `describePem()` now also reads the issuer, serial,
validity and `ca` off OpenSSL (it reads the ML-DSA anchors forge cannot), each anchor
carries `source` and `addedAt`, and `removeAnchor()` takes ONE fingerprint in either the
colon or the plain-hex spelling. The vocabulary, the audit row (`admin.truststore.change`)
and the sentences are `admin-core/admin_actions.js`'s `truststoreAction()`; the reply is
`admin-core/admin_views.js`'s `truststoreJson()`.

Four things about it are decisions:

* **`add` IS STRICT AND `POST /tls/trust` IS NOT.** Through the gated doors a bundle with
  one block OpenSSL cannot read is refused WHOLE, checked before anything is pushed — an
  unparseable `ca` entry makes the next `setSecureContext()` throw on every listener, which
  `applyAnchors()` logs while the listeners keep their old context and the page says
  otherwise. The test control keeps accepting what it is given, because development-mode
  behaviour is not this change's to alter.
* **THERE IS NO BULK CLEAR ON EITHER GATED DOOR.** `clearAnchors()` stays behind
  `POST /tls/trust/clear` only. A clear's reach is every client certificate every other
  caller relies on, and `tests/CLAUDE.md` records one unguarded clear costing a remote PEP
  its identity for the rest of a run. Removing a `file` anchor IS allowed, and both the
  page and the reply say it comes back at the next start.
* **NOTHING IS PERSISTED**, which is the rule this array already follows (the note above
  `anchors`). The durable door is still `tls.trustAnchorsFile`.
* **THE SLOT IS FILLED BY `common/protocol_stack.js`, NOT BY THIS MODULE, AND THAT IS
  FORCED.** This module is really first loaded from INSIDE `admin-ui/admin.js`'s require —
  `admin.js` → `admin-core/admin_views.js` → `spiffe/spiffe_auth.js` → here — so a
  `require('../admin-ui/admin')` at its top level would be a cycle and would find no
  `setTruststore` on that module's half-built exports. The stack fills it on the line after
  it requires this module, where both are whole. **That load order is itself worth
  knowing**: the documented position of this module is 20, and its routes are in fact
  registered during 18.

**BOTH DOORS ARE PINNED TO THE FRONT PROCESS** with request workers
(`common/request_pool.js`'s `NEVER_DISPATCHED`, beside `/tls`). The array is the
configuration of listeners only that process holds, so a worker changing its own copy
changes nothing a handshake reads — the socket argument the listener certificate made on
the same day, read a third time. `tests/truststore_admin.js` pins the primitives, the slot,
the layer, the pin and the product refusal, the last three in a child process, and asserts
the add and the remove as a REAL HANDSHAKE on a registered listener; `sts_admin_api_operations`
and `sts_admin_console` drive both doors over HTTP with a CA they mint and remove.

## THE PROTOCOL POLICY, AND THE BIND ADDRESS

**`protocolOptions()` is where `tls.minVersion` and `tls.ciphers` are stated for every TLS
socket this process owns** — it rides in `secureContextOptions()`, so 8443 and 9443 are
created with it AND every truststore change re-applies it to every registered listener
(the main port among them), `server.js` passes it when creating the main port, and
`ldap_server.js` asks for it for LDAPS. The defaults are node's own written down, so an
unedited service negotiates exactly what it did. **A cipher list that builds no context is
FATAL at require time**: found later it would be a TypeError from `createServer()`, or a
listener silently keeping its old context after a `setSecureContext()` throws.

Both listeners bind `global.host` (`helpers.listenHost()`), which they ignored for the
literal `'0.0.0.0'`. The self-signed fallback certificate's three literals are
`tls.selfSignedKeyBits`, `tls.selfSignedValidityYears` and `tls.selfSignedOrganization`,
defaults unchanged; the CN is still the first of `tls.hostnames`.

`tests/ldap_tls_product_mode.js` asserts the 403, the anchors file (and its fatal
refusal), the fatal cipher list, and — as a real handshake — that `tls.minVersion=TLSv1.3`
refuses a TLS 1.2 client on 8443. Mutation-tested against the product refusal removed.

## A RUNTIME ANCHOR SURVIVES A RESTART (2026-09-12)

The gated doors above said *nothing is persisted*, and the durable door was
`tls.trustAnchorsFile` alone. A product deployment that added its remote PEP's
CA through `/admin/tls/trust` lost it at the next restart, and every PEP then
failed to authenticate with nothing on any page saying why.

**THE STORE IS THE DIRECTORY**: `ou=trustAnchors` in the DEFAULT realm, one
`stsTrustAnchor` entry per anchor (RDN `cn=<SHA-256 fingerprint, upper hex>`,
the PEM, the fingerprint, who added it), seeded as a structural container and
owned by `ldap/ldap_server.js`. It was chosen over the keystore's row family
(product-only, never adopted across processes) and over an appconfig override
(a PEM bundle is not a setting and would be drawn as a text box): the directory
is the one thing persisted in every store mode and replicated between processes,
so an anchor added in one front process survives a restart and reaches another
with no mechanism of its own.

Four rules:

* **WRITTEN AS IT IS ADDED, REMOVED AS IT IS REMOVED** — `addAnchors()`,
  `removeAnchor()` and `clearAnchors()` go through the store; an anchor from
  `tls.trustAnchorsFile` is never written, because the file brings it back.
* **RESTORED BEFORE ANYTHING BINDS** — `listen()` calls `reloadStoredAnchors()`,
  which is after `persistence.start()` restored the directory.
* **ANOTHER PROCESS'S CHANGE IS RE-APPLIED** — the directory's replication
  appliers call `reloadStoredAnchors()` for any key under the container. It adds
  what the store has and the array lacks, removes a STORED anchor the store no
  longer has, leaves an anchor the store refused (a full directory) and every
  `file` anchor alone, and writes nothing — so it cannot echo a change back.
  A store that cannot be read changes nothing: that is not evidence of a removal.
* **A SLOT, FILLED BY THE DIRECTORY** — `setTrustAnchorStore({list, write,
  remove})`, validated whole. `ldap_server.js` already requires this module for
  its LDAPS certificate, so the fill is a call in the ordinary direction; a
  require from here would register every `/ldap` route ahead of the console's.
  With nothing installed (`npm test`, the parent project's in-process Kerberos
  jobs) the truststore behaves exactly as before.

Every anchor row carries `persisted`, and the list carries `stored`. In
`memory` persistence mode an anchor is still written to the directory and the
directory itself is not kept — `stored: true` means *written down*, and
`/admin/persistence` says whether anything written down survives.

**WHAT IT DOES NOT CLOSE**: anybody the directory lets write
`ou=trustAnchors` over LDAP can add an anchor. That is the directory's
authorization gap, which covers `ou=federations`, `ou=policies` and every other
container equally, and is recorded in `common/mode.js`.

`tests/truststore_persistence.js` pins the reload rules against a store it
controls and a real restart against an `ldif` store, in child processes. It
found a pre-existing defect in `persistence/persistence.js` on its first run —
see that directory's `CLAUDE.md`.
