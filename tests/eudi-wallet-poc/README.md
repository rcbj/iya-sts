<!--
SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
SPDX-License-Identifier: BUSL-1.1
-->

# eudi-dev wallet against the portal: the hand-run basis of #668

**These are not tests.** They are the scripts used on 2026-10-17 to drive the
8081 stack's user portal with the eudi-dev wallet as its web wallet, kept as
the starting point for the job #668 asks for. `run.js` does not read
subdirectories, so nothing here runs in a suite. The flow, the results and
the traps are in #668; the bugs it found are #666 and #667 (and #659).

## What it needs

* the 8081 stack up (`docker compose up` in iya-sts), whose web wallet is
  `http://localhost:8085`;
* the eudi-dev wallet from `rcbj/eudi-dev` `main` (Go 1.26):
  `go build -o eudi . && ./eudi wallet serve --port 8085`;
* `google-chrome`, `jq`, node, and `tests/node_modules` installed (for `ws`);
* a regular user: `./create-wallet-user.sh` (`WALLET_USER=name`; it reads the
  admin API secret from OpenBao the way `create-rcbj-apps-8081.sh` does).
  Put that user's password in `<user>.pw` beside these scripts. **Never commit
  a `.pw` file.**

Start Chrome with a normal User-Agent. Headless Chrome's own UA is scored
`automated-client`, which refuses the sign-in and leaves the person's
standing HIGH (#666):

```bash
google-chrome --headless=new --disable-gpu --no-sandbox --ignore-certificate-errors \
  --user-data-dir=/tmp/eudi-poc-chrome --remote-debugging-port=9222 \
  --user-agent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36' \
  about:blank &
```

## The run

```bash
WUSER=walletuser2 ./login.sh            # realm chooser, then password
./issue.sh                              # /portal/wallet offer -> web wallet -> tx code -> approve
./endsession.sh                         # ends the session only (a global logout leaves the VCs valid too)
./walletsignin.sh wallet-signin         # prints the wallet's consent dialog
node cdp.js eval "document.querySelector('#consent-approve').click()"
#   Remove each copy on /portal/wallet, then:
python3 -I statuscheck.py https://localhost:8081/oid4vci/status-lists/1 <idx>...
#   Self-issued IDs: /portal/self-issued -> #siop-enrol -> #wallet-web -> approve,
#   then ./endsession.sh && ./walletsignin.sh siop-signin
```

| File | What it does |
|---|---|
| `cdp.js` | `goto`, `eval`, `wait`, `shot` against the first page of the Chrome on `$CDP_PORT` (9222) |
| `login.sh` | password sign-in through the realm chooser |
| `issue.sh` | makes an offer on `/portal/wallet` and accepts it in the web wallet, typing the transaction code |
| `walletsignin.sh` | starts a wallet (`wallet-signin`) or SIOPv2 (`siop-signin`) sign-in and opens it in the web wallet |
| `endsession.sh` | ends only the sign-on session and its RP sessions at `/logout` |
| `logout.sh` | global logout: ends every session, token, code and connection, and leaves the person's verifiable credentials valid (ticking their rows on `/logout` ends them) |
| `statuscheck.py` | decodes a Token Status List and prints each index's status |
| `create-wallet-user.sh` | creates a regular user through `/admin-api` |

The status indices of the copies the wallet holds are in the `raw` SD-JWTs of
`~/.eudi-dev/wallet/wallet.json` (`status.status_list.idx` of each).
