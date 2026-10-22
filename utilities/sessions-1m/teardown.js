// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
// teardown.js — put back every setting setup.js changed, exactly as it was.
//
// A setting that was an override before is set back to that value; one that
// was not is RESET, because writing the old default back would leave it
// reading "source: override". The application sessions-1m-rp and the
// passwords set-passwords.js wrote are left alone; DELETE_APP=1 deletes the
// application too, which ends nothing already issued.
"use strict";

const path = require("path");
const c = require("./common");

const STATE = path.join(c.HERE, "setup.state.json");

async function main() {
  const state = c.readJson(STATE, null);
  if (!state || !state.prior) {
    c.log("nothing recorded in " + STATE + "; nothing to restore");
    return;
  }
  for (const [key, was] of Object.entries(state.prior)) {
    if (was.source === "override") {
      await c.setSetting(key, was.value);
      c.log("  " + key + " set back to " + was.value);
    } else {
      await c.resetSetting(key);
      c.log("  " + key + " reset (was " + was.value + " from " + was.source + ")");
    }
  }
  if (process.env.DELETE_APP === "1") {
    const r = await c.api("POST", "/applications/delete",
                          { identifier: c.cfg.APP_ID });
    c.log("  deleting " + c.cfg.APP_ID + ": " + r.status);
  }
  state.restoredAt = new Date().toISOString();
  c.writeJson(STATE, state);
  c.log("teardown done");
}

main().catch((e) => {
  c.log("teardown FAILED: " + (e && e.stack || e));
  process.exit(1);
});
