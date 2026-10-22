# One million live sessions against 8081

This test signs in one million different people to the default realm of the
product-mode service on 8081. It uses OIDC's authorization code flow with PKCE
for the confidential client `sessions-1m-rp`. After that it keeps every
person's session and token set alive indefinitely by refreshing before
expiry. The first time all of them are signed in and current, it logs
`STEADY STATE REACHED`.

## Run order

```bash
./run-setup.sh            # settings + the application; records priors
./run-set-passwords.sh    # one password for load-26cb84b3-1..1000000 (LDAPS) — ~10 h
./run-sessions.sh         # sign everyone in, then keep them alive; Ctrl-C to stop
./run-teardown.sh         # put every setting back (DELETE_APP=1 also deletes the app)
```

Every script can be resumed. `sessions.js` can start while the passwords are
still being written: it never signs in a person beyond the mark in
`set-passwords.state.json`. Each wrapper tees its output to `<name>.log`, and
`status.json` is rewritten every minute.

## What the service is asked to hold

| | Setting | Why |
|---|---|---|
| Sessions | `authn.maxSessions` 1,100,000 | 1M, plus room for everyone else |
| | `authn.sessionLifetimeS` 2,592,000 (30 d, the maximum) | each person is signed in again a day before it ends |
| Refresh families | `oauth2.maxRefreshTokenFamilies` 1,000,000 | **that is the maximum**: one per person and no headroom, so anyone else's offline_access grant on this realm evicts one of ours (which then signs in again) |
| Revocations | `oauth2.maxRevokedJtis` 10,000,000 (the maximum) | rotation keeps each spent refresh token's id until that token's `exp` |
| Risk | `risk.listsMatchSpecialPurpose` false | the docker bridge address is RFC 1918 and otherwise scores as special-purpose |
| | `risk.rescoreEveryS` 86,400 | the rescore walks every live session |
| | `risk.networkFailureThreshold` 1,000,000 (the maximum) | every caller is the docker gateway, one network: on 2026-10-21 twenty refused passwords from it put `network-failures` (MEDIUM, step-up) on every sign-in after a restart |

The client sends a Chrome User-Agent, because node's default scores as an
automated client and product mode refuses that at a first sign-in.

## The application

The client is `sessions-1m-rp`, using `client_secret_basic` (kept in
`client.secret`, mode 0600):
- grants `authorization_code` and `refresh_token`, with PKCE S256;
- scopes `openid profile offline_access`, all consented globally, so no
  consent screen appears;
- access and ID tokens live 12 h (`ACCESS_TTL_S`);
- refresh tokens live 2 days, and the idle limit is also 2 days
  (`REFRESH_TTL_S`).

The redirect URI `https://127.0.0.1:9/sessions-1m/cb` is never dialled; the
script reads the code out of the `Location` header.

## The arithmetic

- **Refresh traffic:** 1,000,000 people ÷ (0.8 × 43,200 s) ≈ **29 refreshes/s**,
  spread by ±5% jitter.
- **Login ramp:** at most 40/s (`LOGIN_RATE`) with 8 in flight
  (`LOGIN_CONCURRENCY`). In practice the rate is bounded by the password-hash
  verify. 1M takes at least about 7 h, and this overlaps the password phase.
- **Signing in again:** 1M every 29 days ≈ 0.4/s.
- **Revocations:** 29/s × the refresh lifetime. With the agreed 30-day refresh
  lifetime that would be about 75M, which passes the 10M cap in about 4 days.
  **So the refresh lifetime is 2 days**, which keeps about 5M. Nothing is lost
  by this, because every refresh issues a new 2-day token.
  `REFRESH_TTL_S=2592000 ./run-setup.sh` (on a fresh app) restores 30 days.
- **Password phase:** each write is one synchronous scrypt (about 70 ms) on a
  request worker. Two workers manage about 25–30 writes/s, so 1M takes about
  10 h, and the service's latency rises while it runs.

## What protects the machine

- Sign-ins pause while the `sts` container's memory is over `MEM_CEILING_GB`
  (24).
- Sign-ins also pause while any refresh is more than 60 s overdue. Refreshes
  always come first.
- State lives in `sessions.db` (SQLite, WAL), written in one transaction per
  second. The script's own memory is typed arrays (a min-heap of due times),
  not a million objects.
- How a failure is handled:
  - a 400 or 401 on refresh signs that person in again;
  - anything else is retried in 30 s;
  - a failed first sign-in is retried once the cursor reaches the end.

## Knobs

`COUNT`, `FIRST`, `LOGIN_RATE`, `LOGIN_CONCURRENCY`, `REFRESH_CONCURRENCY`,
`REFRESH_AT` (0.8), `JITTER` (0.05), `MEM_CEILING_GB`, `STATUS_EVERY_S`,
`DB_FILE`, `PASSWORD_GATE`; for `set-passwords.js`, `CONCURRENCY`, `FIRST` and
`LAST`.

## Not measured yet

- **The memory a session costs** on the service, across the session, the
  refresh family and the revocations. The 20-person smoke test is too small
  to show it. Watch `mem` in the status line during the ramp; the ceiling is
  what stops it.
- **Risk scoring's population count** grows with N on every sign-in, so login
  latency should be expected to climb as the ramp proceeds.
