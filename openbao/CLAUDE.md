# CLAUDE.md — `openbao/`

**THE SECOND DIRECTORY HERE THAT IS NOT PART OF THE SERVICE**, after
`xacml-pep/`, and the first that is not a program at all: three files the
SECRET STORE container runs, three policies that are claims about who may do
what, and — since #254 — the start-up helper the SERVICE container runs as root
before node starts. `server.js` requires none of it and nothing here is loaded
by the service.

Added 2026-09-12, when the key-encryption key and the database password stopped
being things this stack wrote into files of its own.

| File | What it is |
|---|---|
| `bao.hcl` | The store's configuration: raft storage, a TLS listener, and `seal "static"` — a real auto-unseal, not dev mode. |
| `generate-tls.js` | Mints the listener's certificate BEFORE the store starts, with this repository's own encoder. Runs in the image this repository builds. |
| `seed.js` | One shot, idempotent: initialise, write the two secrets (**the key is written once, with KV v2 check-and-set, and never replaced** — everything sealed under it would be unreadable), make the Transit key `sts-kek` once (#391), build a CA inside the store, issue this service its client certificate, bind it to the policy — and then PROVE the policy by using it. A second stack against an initialised store proves its credential instead. |
| `read-only.hcl` | What that identity may do: read two paths, and USE one Transit key (encrypt, decrypt, read its versions). Everything else is denied, because Vault denies by default. **Not `secret/sts-admin`** (#254), and the seeder proves the refusal. |
| `admin-secret.hcl` | #254: read on `secret/sts-admin` — the start-up secrets — and nothing else. Carried by the single-use START-UP tokens and the printed OPERATOR token, both from the `sts-admin-secret` token role. |
| `seeder.hcl` | #254: what the seeder may do once root is revoked — issue the service's client certificate and mint `sts-admin-secret` tokens. Nothing else. |
| `startup-secrets.js` | #254: run as ROOT by the `sts` command, before it drops to uid 10001. Takes and deletes the node's wrapping token, unwraps it (a refusal stops the node: somebody else may have it), reads `secret/sts-admin`, revokes the token, writes each value to a 0400 file of 10001's on the `/run/sts-startup` tmpfs and prints `export <ENV>_FILE=…`. The service reads each once and deletes it (`common/delivered_secrets.ts`). |

**THE KEY-ENCRYPTION KEY IS THE TRANSIT KEY `sts-kek` IN `docker-compose.yml`
SINCE #391** (`keys.kekProvider=vault-transit`): it wraps each data encryption
key inside the store and never leaves it, so the service holds no
key-encryption key at all. `aes256-gcm96` (only an AEAD key takes the
associated data each wrap is bound by), made only when absent, and checked to
be neither exportable nor deletable. The identity can use it and **cannot
rotate or reconfigure it** — the seeder proves both refusals as the service,
for the reason the KV key is read-only: a compromised service must not be able
to change the key its data is sealed under. The console's *Rotate the
key-encryption key* therefore answers STS-KEYS-0105 here; an operator rotates
it with a root token made for the purpose (`bao operator generate-root` from
the recovery key, since the seeder revokes its own — #254, below; then
`bao write -f transit/keys/sts-kek/rotate`), and the next start re-wraps every
data key under the new version. The KV `kek` is still
written: it is `keys.kekProvider=vault`, which the test stack
(`docker-compose-run-tests.yml`) still uses, and the PREVIOUS key a stack
moving to Transit names in `keys.previousKek*`. The database password has its
own `STS_DATABASE_PASSWORD_REF` now: it used to borrow the key's location, and
a Transit key's name is no place to read from (`secrets.js` borrows nothing
from a KMS key).

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

### Several stacks against one store: check-and-set, and a second stack that only proves (2026-09-14, #46)

The seeder was written for one stack. A cluster is several containers against
ONE store, and a stack per container brings a seeder per container:

* **Two seeders on an empty store raced the key-encryption key** — each read
  nothing, generated a key and wrote it, the later write won, and a node that had
  started against the earlier key sealed rows the store could no longer open: a
  node that never starts again, silently. The write is KV version 2's
  **check-and-set** now: `cas: 0` for a new key (written only if the path has no
  version), `cas: <version read>` when refreshing the database password beside an
  existing key. A refusal (`check-and-set parameter did not match`) means somebody
  else wrote first; the seeder re-reads and keeps theirs. A path whose latest
  version is DELETED is refused outright rather than given a new key — `bao kv
  undelete` recovers it.
* **Initialisation is the store's own check-and-set**: of two seeders calling
  `sys/init` exactly one gets a root token; the other re-reads `initialized` and
  carries on as a second stack.
* **A second stack's seeder no longer refuses to finish.** Its volume holds no
  token. With `STS_BAO_TOKEN` (an operator token) it re-declares
  everything as usual; with none, but a client credential already in
  `/openbao/client`, it **proves** that credential (`proveReadOnly()`) and
  succeeds without changing the store — and writes no start-up token, so its
  node starts without the start-up secrets (#254); with neither it refuses and
  says which to supply.
* **The shape to deploy is one seeding, out of band**: a one-shot init job run
  once against the store (or an operator doing the same by hand), with each
  node's container handed the client credential it produced — not a seeder in
  every stack. Per-container seeders are now safe, and still the wrong place for
  a root token.
* **The client certificate is issued for ninety days (`STS_BAO_CLIENT_TTL`;
  a year until #254) and nothing in the running service renews it.** A seeder
  holding a token — the seeder token counts — re-issues it when it has
  `STS_BAO_RENEW_WITHIN_DAYS` (30) or fewer left; a proving-only seeder warns.
  A stack that is never re-seeded stops reading its secrets the day it expires —
  `/admin/secrets` shows the expiry. Schedule the init job, or renew by hand
  (`bao write pki/issue/sts-client common_name=sts ttl=2160h`). The service
  reads the files once per start (#254), so a renewal is in force at the next
  start, which a seeder run precedes.
* **Verified against a STUB of the API, not a real store** (2026-09-14; the
  OpenBao image was not available on the machine that day): a scratch HTTPS
  server answering the endpoints this file calls, with KV v2's `cas` rule. Two
  seeders holding a token started together on an initialised, empty store:
  the seeder as committed wrote TWO different keys in two of three runs; this
  one wrote one key in three of three, the loser logging that another seeder
  wrote first. Two seeders on an UNinitialised store: one initialised, the
  other carried on as a second stack; with no token and no credential it
  refused with the sentence above, and with a copied credential it proved it
  and exited 0. A re-run holding the root token refreshed the password and
  left the key. **What a stub cannot show** is that OpenBao's own wording of a
  `cas` refusal matches `casRefused()`'s `/check-and-set/` — it is the message
  KV v2 has documented, and it is worth one run against a real store.

### Nothing a shell in the service can read opens `/admin-api`, and nothing on disk holds root (#254, 2026-10-06)

Issue #254 began with `docker exec sts cat /run/secrets/sts-admin-api-secret`,
which the compose file called readable *by design*. The inventory on the issue
found worse beside it: the OpenBao client key at **0644**, read by a service
running as **root** — the use of the key-encryption key and the database
password for anybody with a shell — and the store's **root token** kept in its
volume. rcbj's four decisions, and what each became:

* **The service runs as uid 10001** (Dockerfile). The low ports need no
  capability (Docker's `ip_unprivileged_port_start=0`, set explicitly in the
  compose files and in ECS `systemControls`). The compose `sts` command starts
  as root, adds the SPIFFE addresses, chowns `data/`, runs
  `startup-secrets.js`, and `exec setpriv`s to 10001 with no capabilities and
  no_new_privs. The client key is 0600 and 10001's, written by the seeder
  (which runs as root for that) and re-owned on every run, so an old volume's
  0644 key is fixed without a new credential. `secrets.js` reads it once per
  start.
* **The management API secret is at `secret/sts-admin`, a separate path read
  at start through a narrower policy.** "Narrower" needs a second credential,
  since one identity with both policies is one identity: each node gets a
  RESPONSE-WRAPPED, single-use token minted from the `sts-admin-secret` role
  (orphan, `admin-secret.hcl` only, ten minutes and two uses once unwrapped,
  thirty minutes to unwrap), in `<node>.wrap` on the `sts-bao-startup` volume
  — 0600, root's, never readable by 10001. A wrapping token that will not
  unwrap stops the node, because it may mean somebody else took the secret.
  The value reaches node as a file on a tmpfs, read once and deleted
  (`common/delivered_secrets.ts`), never as an environment variable: an
  environment is `docker inspect`, `/proc/1/environ` and every child. The
  test launchers' per-run secret and the product modes' Kerberos passwords
  take the same road, by way of the seeder's environment.
* **The operator path**: the secret is for the FIRST token. Each seeder run
  prints an operator token (read on `secret/sts-admin`, `STS_BAO_OPERATOR_TTL`,
  24 hours); after that the operator makes an application of their own with
  ADMIN_READ and ADMIN_WRITE and a client secret, on client credentials — in
  the default realm for every realm, in a realm for that realm.
  `docs/management-api.md` is the procedure.
* **The root token is revoked after seeding.** The initialising run uses it in
  memory and revokes it last; a volume from before #254 that kept
  `seed/root.token` has it used once and revoked, and the file deleted. The
  recovery key is printed once and kept nowhere. Later runs hold
  `seed/seeder.token` (`seeder.hcl`, periodic, renewed by each run): renew the
  certificate, prove, hand out start-up tokens — and **declare nothing**. A
  changed policy, role or mount on a running store is an operator's act with a
  root token made for it, or `down -v`.

**What it still is, and is not.** A shell as uid 10001 in `sts` reads the
OpenBao client credential — which grants what the service itself does — and
nothing else from disk or the environment. `docker compose exec -u 0` is root
in the container and the docker group on the host; so is a shell in
`openbao`, whose static seal key is in its environment. Those are not lines
this stack can draw, and `bao.hcl`'s seal stanza is where a deployment draws
the second.

**What a restart costs.** `docker compose restart sts` runs no seeder, so the
node finds no wrapping token and starts without the start-up secrets (it says
so); the management API client then has a secret minted per start, and an
application of your own still works. `docker compose up` re-runs the seeder.

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
  here that is the TLS generator running as root (`user: "0"` since #254,
  because the image's own user is 10001). It hands the tree over
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
* `common/secrets.js` is the client — argued in `common/CLAUDE.md` under
  *`keystore.js` AND `secrets.js`* — and `common/config.js`'s `keys.vault*`
  rows are how it is told where the certificate is.
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
