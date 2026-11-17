# Utilities

Load and soak scripts used against a running iya-sts (8081 by default), and
two operator tools. Apart from `config-dump.js` and
`register-remote-pep.js` (with `pep-assertion-request.js`, which it needs),
they are not part of the service: `.dockerignore` keeps them out of the
image, and no test runs them. `tests/register_remote_pep.js` runs the
remote PEP tool.

| Script | What it does |
|---|---|
| `config-dump.js` | Saves the masked configuration dump (`docs/v1.1.0/configuration-dump.md`). Ships in the image. |
| `register-remote-pep.js` | Registers a new remote XACML PEP through the management API: its entry, its membership of the remote PEPs group, its service account, its assertion key (generated locally; only a certificate request is sent), optionally its cluster membership and HTTPS listener pair, and the container's `pep.env` and compose service. Safe to run again; `--dry-run` writes nothing. Ships in the image. `docs/v1.1.0/remote-pep.md`, *Registering a new remote PEP, step by step*. |
| `pep-assertion-request.js` | The key pair and PKCS #10 request the tool above and `tests/tools/pep-credential.js --assertion` both make. A library. |
| `load-users.js` (`run.sh`) | Adds people to a realm's directory over LDAPS, resumably, through a bind identity it creates and then takes Admin Write back from. |
| `bulk-import.sh` | Loads people with the offline bulk import (`persistence/bulk_import.js`), one generated LDIF file at a time, with the `sts` container stopped. |
| `sessions-1m/setup.js` | Prepares the realm for the session test: raises the session, refresh-family and revocation limits, and creates the relying party `sessions-1m-rp`. |
| `sessions-1m/set-passwords.js` | Gives people 1..COUNT one shared password over LDAPS, bound as `load-users.js`'s binder with Admin Write for the run. |
| `sessions-1m/sessions.js` | Signs each person in once through the OIDC code flow with PKCE, then keeps every session alive by refreshing. |
| `sessions-1m/teardown.js` | Puts back every setting `setup.js` changed. |
| `sessions-1m/soak-check.sh` | One stability reading of a running soak; `--brief` for one line. |
| `create-rcbj-apps-8081.sh` | Rebuilds a demonstration set around one person: a resource application (`oauth2-resource-server`) defining two permissions, a confidential client granted them, a group, a role and two service accounts, all owned by that person. Its header says what it makes and the scope rules it follows (#1139). |
| `create-qualys-scanner-client.sh` | Makes `qualys-scanner`, a read-only `/admin-api` client for an authenticated Qualys WAS scan: `client_credentials` only, granted `admin:read` and a member of ADMIN_READ, never write. It proves the result (a read works, `admin:write` is refused, a write is 403) and prints the secret and the Qualys authentication-record values once. |

Each `run-*.sh` runs its script with the service's Root trusted and appends
to a log beside it. `sessions-1m/README.md` describes the session test.

**Nothing secret is in this folder.** Before a run, put these beside the
scripts (`.gitignore` keeps them out of commits):

* `ca.pem`: the service's Root certificate (in `utilities/`);
* `app.secret`: the `/admin-api` client's secret (`CLIENT_ID`, default
  `claude-293-runner`, a `client_credentials` client with `admin:read
  admin:write`);
* `sessions-1m/client.secret` and `sessions-1m/people.secret`: the relying
  party's secret and the shared password, which the scripts generate and
  write themselves (mode 0600) on their first run.

Every path and name can be overridden by an environment variable; each
script's header lists them.
