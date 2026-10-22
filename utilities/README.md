# Utilities

Load and soak scripts used against a running iya-sts (8081 by default). They
are not part of the service: `.dockerignore` keeps them out of the image, and
no test runs them.

| Script | What it does |
|---|---|
| `load-users.js` (`run.sh`) | Adds people to a realm's directory over LDAPS, resumably, through a bind identity it creates and then takes Admin Write back from. |
| `bulk-import.sh` | Loads people with the offline bulk import (`persistence/bulk_import.js`), one generated LDIF file at a time, with the `sts` container stopped. |
| `sessions-1m/setup.js` | Prepares the realm for the session test: raises the session, refresh-family and revocation limits, and creates the relying party `sessions-1m-rp`. |
| `sessions-1m/set-passwords.js` | Gives people 1..COUNT one shared password over LDAPS, bound as `load-users.js`'s binder with Admin Write for the run. |
| `sessions-1m/sessions.js` | Signs each person in once through the OIDC code flow with PKCE, then keeps every session alive by refreshing. |
| `sessions-1m/teardown.js` | Puts back every setting `setup.js` changed. |
| `sessions-1m/soak-check.sh` | One stability reading of a running soak; `--brief` for one line. |

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
