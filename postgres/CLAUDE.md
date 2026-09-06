# CLAUDE.md — `postgres/`

**Two shell scripts the database container runs, and nothing else. Neither is
run by this service**, and nothing in this repository requires them —
`docker-compose.yml` mounts them into the PostgreSQL image.

| Script | What it does |
|---|---|
| `generate-tls.sh` | makes the server key pair on first start |
| `require-tls.sh` | rewrites every `host` rule in `pg_hba.conf` to `hostssl` |

**The key pair is generated rather than committed, which is the same decision
every other key in this repository follows**: a certificate committed to a
repository is a private key committed to a repository. It is the reason this
service's own signing key is regenerated on every start too.

**`require-tls.sh` is what makes TLS REQUIRED rather than merely available.** A
server that supports TLS and still accepts a plaintext connection is one
misconfigured client away from sending credentials in the clear; rewriting the
rules means the database refuses, so both ends say it and neither can be quietly
relaxed.

**The argument for both is in `persistence/CLAUDE.md`** — *TLS TO THE DATABASE,
REQUIRED AT BOTH ENDS* — along with the thing this arrangement deliberately does
NOT do: the certificate is signed by nobody, so the connection is encrypted and
the server is not authenticated, and `/admin/persistence` reports those as two
facts rather than one tick. Do not argue it again here.
