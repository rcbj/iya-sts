---
title: "the image's optional SDKs come from a lockfile"
kind: changed
issue: 2141
---

The Vault client every image carries, and the SDKs the `STS_CLOUD_SDKS` build
argument adds, were installed with a bare `npm install`: the newest version the
registry had that day, with install scripts on. They are now pinned in the
repository's `sdk/` directory, one npm workspace per SDK, and installed from
`sdk/package-lock.json` with `npm ci --ignore-scripts` (ASVS 5.0.0 15.2.4).
`STS_CLOUD_SDKS` takes the same package names as before. A name the lockfile
does not pin, or a `name@version` whose version it does not hold, now fails the
build instead of installing something unpinned; to move a pin, change it in
`sdk/packages/` and run `npm install --package-lock-only --ignore-scripts` in
`sdk/`.

The advisory check every CI run makes (`tests/tools/dependency-windows.js`) now
audits `sdk/package-lock.json` as well, under the same windows, and names the
lockfile of each finding. Its first run found ten vulnerable packages under
`dbus-next`, reached through its optional `usocket` and node-gyp 7 (`request`,
`form-data`, `qs`, `tough-cookie`, `uuid`, `tar`) and its `xml2js`; none is in
an image built without `STS_CLOUD_SDKS=dbus-next`. `sdk/package.json` now
overrides `usocket` to 1.1.0 and `xml2js` to 0.6.2, and `npm audit` there
reports nothing.
