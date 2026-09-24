---
title: Caches
nav_order: 15
---

# The caches this service keeps

This service remembers some things it could work out or fetch again, and some
things it has to remember to refuse a second use. This page lists both. For each
one it gives what is held, how long it is held, the setting that bounds it, and
what makes it forget.

It matters for two reasons:

- **A cache is a window in which an answer can be out of date.** If a change you
  made does not show up at once, the entry below says how long to wait.
- **Replay stores decide whether something is refused.** They are security
  state, not a speed-up, so they are listed separately at the end.

Every setting named here can be changed while the service runs, on the page for
its protocol in the admin console or through `POST /admin-api/config/set`.
[Configuration](configuration.md) describes the settings themselves.

## Three terms

| Term | Meaning |
|---|---|
| **Per process** | One copy in each node process. With request workers turned on (`workers.requestCount` above 0) every worker has its own, so two requests answered by two workers may see two different cached answers until both expire. |
| **Per realm** | One copy for each [trust realm](trust-realms.md), in each process. Removing a realm empties its copy. |
| **Persisted** | Written to the persistence store and restored at the next start, and shared between processes that use the same store. See [Persistence](persistence.md). |

Nothing on this page is cleared by an admin console button. A restart empties
everything that is not persisted.

**Every cache and replay store has a maximum size.** Some bounds are enforced:
at its maximum the store either drops its oldest entry or, if it is a replay
store, refuses the new one. Other bounds are structural: the store cannot grow
past something that is already limited, such as one key set per realm, or a
directory index that can never hold more entries than `ldap.maxEntries` allows.
For a store kept per realm the maximum applies to each realm.

## Watching them

**Monitoring → Caches** (`/admin/caches`) lists every cache and replay store
below as the running process holds it:
- its current size against its maximum;
- how many entries are still valid, and how many have expired but not yet been
  evicted;
- its hit ratio since the process started.

Open one to see its entries, soonest deadline first, each with how long it is
still valid. The same figures are at `GET /admin-api/caches`, and
`GET /admin-api/caches?cache=<name>&page=<n>` returns one store's entries. Both
show keys only, never cached values.

Each row also shows:
- **the maximum**, marked *per realm* for a store kept per realm, with the size
  of its fullest realm, which is the figure to compare against it;
- **what kind of bound it is**, enforced or structural;
- **how many entries were dropped or refused** at the maximum since the process
  started.

A store at its maximum is marked. A replay store that refuses because it is full
also logs `STS-CORE-0097`, at most once a minute.

Four things to know when reading it:
- **The figures belong to the process that answered.** With request workers or
  a cluster, each process has its own caches, and the page shows its `pid`.
- **Other cluster nodes are shown too.** Each node publishes the sizes and
  counters of its caches on its cluster membership row every 30 seconds. The
  page shows each other node's last report, and how old it is, in a section of
  its own. If a request worker draws the page, this node's front process is
  shown there as well. Only sizes and counters are published, so opening a
  store's entries always shows this process's own.
- **A hit means different things for the two kinds of store.** For a cache, it
  is a lookup answered from the cache. For a replay store, it is a value found
  already held, and each store says which that is: a second use refused, or a
  nonce honoured.
- **The Kerberos authenticator store is listed but not counted.** Its lookup is
  in a file shared with the parent project.

The page is for service administrators; a realm's own administrators cannot
open it.

---

## Expired entries are cleared every minute

Each store refuses an expired entry whenever it is asked for one, whatever
else happens. On top of that, the scheduler job `caches.eject-expired`
(`/admin/scheduler`) runs every minute in every process and deletes the
expired entries of every store that has them, so an idle store does not hold
dead rows until its next lookup. What it removed is counted in each store's
**Evictions** on `/admin/caches`. Two stores are cleared by other means: the
back-channel Logout Token deliveries (their own sweep, which dead-letters a
delivery before removing it) and the decrypted signing keys (dropped
`keys.plaintextTtlS` after their last use, to the second).

## Certificates and revocation

When a client certificate or a signed assertion names a CRL, an OCSP responder
or an issuer certificate address, the service fetches it and remembers the
answer.

| Cache | Holds | Scope | How long | Setting |
|---|---|---|---|---|
| CRLs | each fetched certificate revocation list | per process | until the CRL's own `nextUpdate`, but never longer than the setting | `pki.revocationCrlMaxAgeS` (3600) |
| OCSP answers | each fetched OCSP response | per process | until the response's `nextUpdate`, but never longer than the setting | `pki.revocationOcspMaxAgeS` (3600) |
| Issuer certificates | certificates fetched from an Authority Information Access address | per process | as for CRLs | `pki.revocationCrlMaxAgeS` |
| Failed fetches | an address that did not answer, so it is not asked again at once | per process | the setting; 0 means a failure is not remembered | `pki.revocationFailureRetryS` (60) |
| Certificate files | trust anchors read from a file named in a setting | per process | until the file's path or modification time changes; one entry per setting that names a file (two) | — |
| Client certificate chains | the chain a verified client certificate built on a full TLS handshake, handed back when that session is resumed (a resumed session carries the leaf alone) | per process | no expiry; 1024 leaves, the oldest dropped first | — |

The first three share one size limit, `pki.revocationCrlCacheEntries` (256);
the oldest entry is dropped first.

**If you revoke a certificate at an external authority**, this service may go on
accepting it for up to an hour, or until the list it holds reaches its
`nextUpdate`. A certificate this service issued itself is checked against its own
register on every use, with no cache.

Three smaller caches remember work already done on content that cannot change:
- parsed certificates, 256 entries;
- whether a certificate holds a given key, and whether its chain ends under the
  current service Root, 512 entries each;
- the result of mapping a TLS client certificate to an identity, 256 entries.

They need no setting because a changed certificate is a different entry.

## Signing keys

| Cache | Holds | Scope | How long | Setting |
|---|---|---|---|---|
| Decrypted signing keys | a realm's private keys, decrypted from the store | per process | depends on the policy: `timed` drops them after the idle time, `per-use` after each signature, `resident` never; at most one realm's material per realm | `keys.plaintextRetention` (`timed`), `keys.plaintextTtlS` (300) |
| A realm's key set | the keys a realm signs with, built when first needed | per realm | for the life of the process, unless another process's copy is adopted; one per realm | — |
| Post-quantum keys | the realm's ML-DSA and SLH-DSA keys, generated when first needed | per realm | as for the key set; one per realm | — |
| Certificate authorities | each realm's CA hierarchy, held decrypted | per process | replaced when the hierarchy changes; one per realm, plus the service Root and the process branch | — |
| Thumbprint key IDs | the RFC 9278 URI for each key ID | per process | never needed again (512 entries) | — |

The decrypted-key policy only applies where keys persist. In development mode
there is no stored copy to fall back to, so keys stay in memory.
[Encryption at rest](encryption-at-rest.md) has the full story.

## OAuth 2.0 and OpenID Connect

| Cache | Holds | Scope | How long | Setting |
|---|---|---|---|---|
| Signed metadata | the signed `signed_metadata` JWT published in the discovery document | per realm | the setting; at most the second setting's number of entries | `oauth2.signedMetadataCacheS` (60), `oauth2.maxSignedMetadataEntries` (64) |
| Fetched client key sets | the JSON Web Key Set a client's registered `jwks_uri` answered (#120) | per realm | 256 entries per realm, the oldest dropped | `oauth2.clientJwksCacheS` (300), `oauth2.clientJwksRefetchS` (30) |
| Request objects | JWT request objects fetched from a client's registered `request_uri` | per realm | the setting; 0 (the default) turns it off; at most 256 entries | `oauth2.requestUriCacheS` (0) |
| Authorization details types | parsed RFC 9396 type definitions and their compiled JSON Schemas | per process | until the definition text changes (512 entries) | — |
| SSF event permissions | which Shared Signals events each application may receive | per realm | until any application entry changes; 4,096 answers, oldest first | — |

**After a signing key rotation**, a discovery document can carry `signed_metadata`
signed with the old key for up to `oauth2.signedMetadataCacheS` seconds. A change
to the algorithm, the certificate header or the key ID format takes effect at
once.

There is no JWKS cache for federation partners or for this service's own admin
console and portal: both fetch the key set every time they need it.

## The directory

The embedded directory keeps indexes so that a lookup does not walk every entry.

| Index | Holds | Scope | How long |
|---|---|---|---|
| Usernames | name → entry | per realm | kept current on every write |
| Groups | member → groups | per realm | rebuilt after a change that affects groups |
| entryUUIDs | UUID → entry | per realm | rebuilt when a lookup finds it stale |
| Container listings | the entries under each container | per realm | rebuilt after a write under that container; 64 containers, oldest first |

These are exact. A write is visible to the next read whichever door made it: the
console, `/admin-api`, SCIM or LDAP on port 389. Each index is one per realm and
can hold no more than the directory does, and the directory is capped by
`ldap.maxEntries`.

## Other protocols

| Cache | Holds | Scope | How long | Setting |
|---|---|---|---|---|
| XACML policies | each policy document, parsed and validated | per process, shared by all realms | 1,024 parses, least recently used first (see below) | — |
| Federation release policy | which attributes each application releases to its partner | per realm | the setting | `federation.releaseIndexTtlMs` (5000) |
| SPIFFE authorities | a realm's X.509 SVID authorities, unpacked | per process | until the stored authorities change | — |
| Kerberos keys | long-term keys derived for each principal | per trust realm, in the realm's own principal database | until the principal changes; at most 4,096 principals hold keys at once, least recently used first, and the keys are derived or read again at the next ticket; never persisted | — |
| SAML 1.1 assertions | issued assertions, kept so a Browser/Artifact request can be answered | per realm, persisted | the oldest is dropped past the limit | `saml11.assertionCacheMax` (500) |
| SAML SP metadata | a service provider's metadata, stored as received, and what consuming it registered | the application entry | until refreshed (the application's page, an upload on `/admin/saml2`, an MDQ import, or the background refresher once its `cacheDuration` has elapsed); past its effective `validUntil` it is EXPIRED and every request from that service provider is refused | — |
| Dead-letter counts | an estimate of each Shared Signals stream's dead letters | per realm | recounted at each sweep | — |
| Remote PEP policy | the policy set a remote PEP last pulled | the PEP container | until the next successful pull | — |
| Debugger files | the embedded debugger's files with this service's address filled in | per process | until the file changes (400 entries) | — |
| Fetched status lists | a Status List Token or Bitstring Status List credential a trusted foreign issuer published, fetched when one of its credentials was presented | per process | the list's own `ttl`, never past its `exp`, at most `oid4vp.statusListMaxCacheS` (3600); a failed fetch 30 seconds | `oid4vp.statusListMaxCacheS` |
| Signed status lists | the last Status List Token and Bitstring Status List credential this process signed for each realm | per process | until the list changes, or half of `oid4vci.statusListTtlS`; 1,024 documents, oldest first | `oid4vci.statusListTtlS` |

**XACML policy parses are kept by content.** Each distinct policy text is a new
entry, so an edited policy leaves its old parse behind until it becomes the
least recently used and is dropped. A dropped policy is parsed again the next
time it is asked for.

## Worker pools

| Cache | Holds | Scope | Bound |
|---|---|---|---|
| Crypto worker affinity | which crypto worker last handled a session | per process | 1,000; forgotten when a worker exits |
| Request worker affinity | which request worker a browser, credential or LDAP connection is pinned to, one map for each pool | front process | 5,000 per pool; forgotten when a worker exits |
| Unchanged-write shadow | the last copy of each directory entry written to the store, so an unchanged entry is not written again | per process | refreshed at each flush; one row per directory entry, so at most `ldap.maxEntries` + 1 in a realm |

## Small memos

Three caches hold a single value, and each is listed on the Caches page as a
store of one entry:

| Cache | Holds | How long |
|---|---|---|
| Trusted proxy ranges | `global.trustedProxies`, parsed | until the setting's text changes |
| Version stamp | the build record read from `version.json` | for the life of the process |
| Observation-store declarations | whether each persisted store is a tally the read barrier does not wait for | for the life of the process; one flag per declared store |

Affinity only decides where a request goes; losing it costs nothing but a
re-route. See [Sessions](sessions.md) for what a session pins.

---

## Replay caches and nonces

These are the stores that make a one-time value work once. Clearing one would let
something be used twice, which is why none of them has a control.

| Store | Remembers | Scope | Limit | Forgets |
|---|---|---|---|---|
| Used assertions | every RFC 7523 JWT and RFC 7522 SAML assertion accepted, for a grant or client authentication, and the `jti` of every RFC 9101 request object an authorization response was issued on | per realm, persisted in every store mode | `oauth2.assertionReplayCacheSize` (1000); **refuses new assertions when full** | once the assertion itself expires; a request that fails releases its claim |
| Kerberos authenticators | each authenticator the protected service accepted | per trust realm (the realm whose Kerberos realm issued the ticket), persisted | `krb5.replayCacheMaxEntries` (10000); **refuses when full** | after twice the clock skew |
| DPoP proof IDs | each DPoP proof's `jti` | per realm, persisted | `oauth2.dpopReplayCacheSize` (100000); **refuses new proofs when full** | after twice `oauth2.dpopIatSkewS` (300) |
| DPoP nonces | server-issued DPoP nonces | per realm, persisted | `oauth2.dpopNonceCacheSize` (10000), oldest first | after `oauth2.dpopNonceTtlS` (300) |
| GNAP signatures | each signed GNAP request | per realm, persisted | `gnap.replayCacheSize` (100000); **refuses new signatures when full** | after twice `gnap.signatureMaxAgeS` (300) |
| ACME nonces | spent ACME `Replay-Nonce` values | per realm, persisted | 100,000; **refuses when full of live nonces** (answered `badNonce`) | expired ones are cleared when the limit is reached |
| SCIM Digest nonces | Digest challenges handed out | per realm | `scim.maxDigestNonces` (2000) | after `scim.digestNonceSeconds` (300), then oldest first |
| SCIM HOBA challenges | HOBA challenges handed out | per realm | `scim.maxHobaChallenges` (2000) | after `scim.hobaMaxAgeSeconds` (600), then oldest first |
| SCIM HOBA signatures | HOBA signatures already seen | per realm | `scim.maxHobaSeen` (5000) | oldest first |
| SCIM Digest nonce counts | the nonce-count values already accepted under each Digest nonce | per realm | `scim.maxDigestNonces` (2000) nonces, oldest first, and 1,024 counts per nonce, after which the nonce is retired | with its nonce |
| OID4VCI nonces | `c_nonce` values issued to wallets | per realm, persisted | `oid4vci.cNonceCacheSize` (10000), oldest first | after `oid4vci.cNonceTtlS` (300), or when used |
| Redeemed codes | each authorization code already exchanged, and the tokens it produced | per realm, persisted | `oauth2.redeemedCodeCacheSize` (10000), oldest first | one code lifetime (five minutes by default) after the code would have expired |
| OpenID4VP transactions | every presentation request the Verifier is waiting on — the bar door's, and a wallet sign-in's with its Digital Credentials API request and the key its answer is encrypted to | per realm, persisted | `oid4vp.maxTransactions` (5000), oldest first | `oid4vp.presentationRequestTtlS`, or `oid4vp.signInTtlS` for a sign-in |
| Wallet sign-in register | the credentials this realm issued for a person on an access token it verified, which are the only ones a wallet may sign in with | per realm, persisted | `oid4vp.signInRegisterMaxEntries` (100000), the row issued first dropped | until the last credential on the row expires |
| Credential status entries | each issued credential's index in this realm's status lists, and the status set for it | per realm, persisted | 131,072 | as long as the credential it describes |
| Back-channel Logout deliveries | one row per relying party told that a session ended: its state, its attempts, when it is next due and the signed Logout Token | per realm, persisted | `oauth2.backchannelLogoutMaxRows` (2000), oldest FINISHED first | `oauth2.backchannelLogoutRetentionS` (86400) after it was queued; a row still pending then becomes a dead letter |

Three behaviours are worth knowing:

- **Stores that detect a second use refuse when full rather than forgetting.**
  That is the used-assertion history, the Kerberos authenticators, the DPoP
  proof IDs, the GNAP signatures and the spent ACME nonces. Dropping a live
  entry would reopen a replay, so a burst that fills one is answered with
  refusals until entries expire. Each refusal is counted on the Caches page and
  `STS-CORE-0097` is logged at most once a minute. Raise the limit if a
  legitimate load reaches it.
- **Stores of values this service handed out drop their oldest entry.** A DPoP
  nonce, a `c_nonce` or a Digest nonce that is dropped is simply refused as
  unknown, and the client asks for a fresh one, which each protocol already
  requires it to handle.
- **The wallet sign-in register fails closed.** A credential whose row has been
  dropped signs nobody in, which is the same as a credential that was disowned.

## Not caches

These look similar in the code but only prevent duplicate work or duplicate log
lines while something is in progress:
- a CRL fetch or certificate authority build already under way;
- a token renewal already running for a session;
- warnings that have already been logged once.

None of them grows with traffic. An operation in progress ends. A warning
logged once is remembered by a configured value, such as an origin, a realm name
or a trust domain, so the number of entries is limited by the configuration.

Registers that are the record of something, such as sessions, tokens, the audit
log, consent and the directory itself, are covered in their own pages.
