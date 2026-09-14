# CLAUDE.md — `openbao/`

**THE SECOND DIRECTORY HERE THAT IS NOT PART OF THE SERVICE**, after
`xacml-pep/`, and the first that is not a program at all: three files the
SECRET STORE container runs, plus a policy that is a claim about what this
service may do. `server.js` requires none of it and nothing here is loaded by
the service.

Added 2026-09-12, when the key-encryption key and the database password stopped
being things this stack wrote into files of its own.

| File | What it is |
|---|---|
| `bao.hcl` | The store's configuration: raft storage, a TLS listener, and `seal "static"` — a real auto-unseal, not dev mode. |
| `generate-tls.js` | Mints the listener's certificate BEFORE the store starts, with this repository's own encoder. Runs in the image this repository builds. |
| `seed.js` | One shot, idempotent: initialise, write the two secrets (**the key is written once and never replaced** — everything sealed under it would be unreadable), build a CA inside the store, issue this service its client certificate, bind it to the policy — and then PROVE the policy by using it. |
| `read-only.hcl` | What that identity may do: read two paths. Everything else is denied, because Vault denies by default. |

---

## Why a secret store at all, and why this one

The service reads two things at startup that must not be in its configuration:
the **key-encryption key** every signing key, certificate authority and minted
row is sealed under, and the **database password**. Both had file-shaped
answers, and both were argued as acceptable *because this is a mock* — an
argument that stopped being the whole story on 2026-09-12, when this project
started moving toward being a real identity provider with the mock as a mode
rather than as the point.

**OpenBao rather than HashiCorp Vault** because it is the same API, the same
CLI and the same auth methods under an open licence: `common/secrets.js`'s
`vault` provider and the `node-vault` SDK behind it reach either unchanged, so
a deployment pointing this service at a real Vault changes one URL and nothing
else.

## The three things the stack does that are worth understanding

### It unseals itself, and it is not dev mode

`seal "static"` is a builtin auto seal: the unseal key is handed to the process
in `BAO_STATIC_SEAL_CURRENT_KEY` and the store unseals ITSELF at every start,
with no operator and no quorum. **`bao server -dev` was refused** and the reason
is the whole design — dev mode holds everything in memory, so the
key-encryption key would change on every restart, and a service whose KEK
changes cannot read back a single thing it sealed. This is an ordinary server
with ordinary storage that happens to need no ceremony to start.

**The key must be base64 of exactly 32 bytes.** Thirty-one fails initialisation
with `invalid key size`, and a failed initialisation leaves the storage dirty
enough that the next attempt answers *already initialized* with no root token
anywhere — which reads as a corrupted store and is a mistyped key.

What it costs is stated rather than hidden: the key that unseals the store
travels beside it, so the store protects its contents from a reader of the
DATABASE and not from somebody who can read this stack's environment. A
deployment sets `STS_BAO_SEAL_KEY` from its own orchestrator, or replaces the
stanza with `transit`, `awskms`, `gcpckms` or `azurekeyvault` — one stanza, the
same auto-unseal behaviour, the key somewhere this stack cannot read.

### The identity is a certificate the store itself issued

Not a token. A token in a file is a bearer credential: whoever reads the file is
the identity, it does not expire, and rotating it is an outage. `seed.js`
enables the store's own PKI engine, generates a certificate authority inside the
store, issues a client certificate for `CN=sts`, and binds **that CA plus that
common name** to a read-only policy. The private key never leaves the volume it
is written into, the store can revoke the identity, and the trust is the store's
own rather than a file somebody copied in.

Trusting the CA alone would admit every certificate it ever issues;
`allowed_common_names` is what makes it one identity rather than a class.

### The first write after enabling the engine is refused, and that is not a failure

`ensureMount()` enables `secret/` as kv version 2 and OpenBao answers the very
next write with **400 `Upgrading from non-versioned to versioned data. This
backend will be unavailable for a brief period and will resume service
shortly.`** — the store asking to be come back to, in the shape of an error.

It is a RACE, so it is intermittent: never seen for a fortnight, then twice in a
row on a machine that was building an image at the same time. **What it costs is
the whole run** — this container is `service_completed_successfully` for the
service, so a refusal here is a stack that never starts and a suite that reports
*the service under the protocol jobs never came up*, which names nothing.

So that one answer is retried for ten seconds and said out loud the first time.
**Only that one**: every other 400 is a real refusal — a bad path, a bad
payload, a policy that does not parse — and retrying those would turn a mistake
into a pause followed by the same mistake.

### The policy is verified, not asserted

`read-only.hcl` says this service may read two paths and write nothing.
**Whether OpenBao agrees is a different question**, and one typo in a capability
list is the difference between a service that cannot rotate its own
key-encryption key and one that can. So `seed.js` finishes by logging in *as the
service*, reading what the service reads, and attempting the write the service
must never be able to make — and **refuses to finish if the write is accepted**,
which fails the whole stack before anything starts.

It is there rather than only in a test because of what it protects: a stack that
came up with a writable identity is a stack somebody deployed. A test that runs
afterwards reports it; this stops it.

---

## Why the two one-shot containers run OUR image

`openbao/openbao` is Alpine with `bao` and busybox in it — **no `openssl`, no
`curl`, no `jq`**. The listener needs a certificate before it starts and every
interesting step of the seeding answers JSON, so both jobs had to happen
somewhere else. Using the image this repository already builds buys the property
worth having: the store's listener certificate comes out of
`common/vendored/x509.js`, the same encoder behind every other certificate this
service issues.

**A subject alternative name is not optional** on that certificate. Every
current client reads the SAN and ignores the Common Name (RFC 6125, since 2011),
so a certificate with `CN=openbao` and nothing else is one the service could not
verify — which would leave an operator turning verification off and losing the
point of the exercise.

## Two ownership traps, both of which cost a container start

* **A named volume is created root-owned**, and docker only copies an image's
  ownership into one when the image HAS that path. `/openbao/data` does not
  exist in the image, so a volume mounted there is unusable by the server's own
  user; `/openbao/file` does exist and is owned by it. That is why the storage,
  the TLS material and the seed state all live under `/openbao/file`.
* **Whichever container mounts the volume first decides the ownership**, and
  here that is the TLS generator running as root. It hands the tree over
  explicitly (`chown 100:1000`) — without which the store's own entrypoint finds
  a root-owned directory, tries to chown it, fails because it has already
  dropped privileges, and the container exits 1 with `Operation not permitted`
  as the only sentence.

## Where this appears in the rest of the repository

* `docker-compose.yml` and `docker-compose-run-tests.yml` bring the three
  services up; the service waits on the SEEDER rather than on the store,
  because a store that answers is not a store with anything in it.
* `tests/tools/modes.sh` sets `STS_KEYS_SOURCE=persisted` for the **dispatch**
  mode, which is what makes that mode read its key-encryption key from here.
  The database password comes from here in every mode, because the compose
  files' connection strings no longer carry one.
* `tests/vendored/sts_secret_store.js` asserts the half this directory cannot:
  that the RUNNING SERVICE took this path rather than a file.
* `common/secrets.js` is the client — rule 3ab's neighbour in
  `common/CLAUDE.md` — and `common/config.js`'s `keys.vault*` rows are how it is
  told where the certificate is.
* **`/admin/secrets`, under Monitoring, is where an operator SEES all of this
  from the running service** (2026-09-12): the seal state and seal type, the
  version and build, the cluster and its leader, the store's clock against this
  process's, the client certificate this service presents and when it expires,
  the policies the token it got carries, and every version of the secret the
  store has kept. **The most useful row on it is the one that checks this
  directory's central claim from the other side**: `sys/capabilities-self` on
  the paths this service reads, which is `seed.js`'s final proof asked of the
  RUNNING store by the RUNNING service rather than once at seeding. A widened
  policy fails the stack here AND is drawn in words there.
  `admin-ui/CLAUDE.md` argues the page.
