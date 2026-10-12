#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: build-typescript.sh
#
# ---------------------------------------------------------------------------
# COMPILE THE TYPESCRIPT, INSIDE AN IMAGE BUILD AND NOWHERE ELSE (#50).
#
# rcbj's rules for the conversion (issue #50, 2026-09-16):
#
#   * transpiling happens in a container build step;
#   * no compiled artifact is ever written to the host's filesystem;
#   * the original .ts files are not in the service's final image.
#
# So this script is run by `Dockerfile` (in its `typescript` stage) and by
# `tests/Dockerfile`, never by hand on a checkout — and it refuses to run
# outside a container, because a `.js` it wrote beside a `.ts` on the host
# would be exactly the artifact the rules forbid, and would then shadow nothing
# and confuse everything.
#
# WHAT IT DOES:
#
#   1. `tsc -p tsconfig.json` — the type check, the same one
#      `tests/typecheck.js` runs on the host. It writes nothing.
#   2. `tsc -p tsconfig.build.json` — emits `x.js` BESIDE each `x.ts`. Beside
#      and not into a dist/ tree, because this service reads files relative to
#      its own modules (`__dirname`, 158 uses), forks workers by path, and is
#      required by path from the tests and from the parent project; an emitted
#      tree in the same place keeps every one of those working unchanged.
#      Skipped when there is no .ts to compile (tsc refuses an empty input).
#   3. With `--strip`: deletes every `.ts`, `types/` and the two tsconfig
#      files, for the service image's final stage to copy the tree without
#      them. The tests image does NOT strip: `tests/typecheck.js` checks a
#      pristine copy of the sources there (STS_TYPECHECK_ROOT).
#   4. With `--strip`, too (#365, 2026-09-30): takes the COMMENTS out of every
#      `.js` the service image ships — the compiled ones and the ones written
#      in JavaScript — with `tests/tools/strip-comments.js`. V8 keeps every
#      script's source for the life of the process, as UTF-16 when a comment
#      holds an em-dash, and that was 79 MB of every process's heap (#339).
#      Names, whitespace between tokens and every line break are kept, so a
#      line number in a stack trace from the image is the repository's; the
#      tool proves each file's token stream unchanged and fails the build
#      otherwise. Since #369 it also writes every character above U+00FF in
#      a string or regular-expression literal as a \uXXXX escape (proved the
#      same value), so V8 stores the script one-byte: another ~20 MB per
#      isolate. Its header says what it skips and why. The tests image does
#      not strip here either: its tests read the sources as text.
#
# The compiler is `tests/node_modules/.bin/tsc`, a dependency of
# `tests/package.json` for `.npmrc`'s reason; the caller installs it first.
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")"

STRIP=false
for arg in "$@"; do
  case "$arg" in
    --strip) STRIP=true ;;
    *) echo "build-typescript.sh: unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if [ ! -f /.dockerenv ] && [ -z "${STS_IN_IMAGE_BUILD:-}" ]; then
  echo "build-typescript.sh: this runs inside an image build only (issue #50:" \
       "no compiled files on the host). Use ./docker-npm-test.sh or" \
       "./run-tests.sh." >&2
  exit 1
fi

TSC=tests/node_modules/.bin/tsc
if [ ! -x "$TSC" ]; then
  echo "build-typescript.sh: $TSC is missing; install tests/package.json" \
       "first (npm install --prefix tests)." >&2
  exit 1
fi

# The sources to compile: every .ts that is not a declaration, outside the
# trees that are not ours. The same exclusions as tsconfig.build.json.
sources() {
  find . \( -path ./node_modules -o -path ./tests -o -path ./node-ldapjs \
            -o -path ./xacml-pep -o -path ./common/vendored \
            -o -path ./debugger/embedded -o -path ./.git \) -prune \
         -o -type f -name '*.ts' ! -name '*.d.ts' -print
}

echo "build-typescript.sh: type-checking (tsc -p tsconfig.json)"
"$TSC" -p tsconfig.json --pretty false

COUNT="$(sources | wc -l | tr -d ' ')"
if [ "$COUNT" -gt 0 ]; then
  echo "build-typescript.sh: compiling $COUNT file(s)" \
       "(tsc -p tsconfig.build.json)"
  "$TSC" -p tsconfig.build.json --pretty false
  # Every source must now have its .js beside it; a missing one is a module
  # the service would fail to require at start, so it fails the build here.
  missing=0
  while IFS= read -r ts; do
    if [ ! -f "${ts%.ts}.js" ]; then
      echo "build-typescript.sh: no output for $ts" >&2
      missing=1
    fi
  done < <(sources)
  [ "$missing" -eq 0 ]
else
  echo "build-typescript.sh: no .ts sources; nothing to compile"
fi

# ---------------------------------------------------------------------------
# THE STATIC SURFACES' BROWSER BUNDLES: ONE FUNCTION, ONE CALL PER SURFACE
# (#446, #568; a function since #570).
#
# A static surface — the admin console (#446), the user portal (#568), and
# every public page #569 converts, one bundle per surface (rcbj's decision 2
# on #570) — draws its pages in the browser with renderers that are `web_*.ts`
# modules, and `bundle_surface` is where they become files a browser loads:
#
#   1. THE RENDERERS ALONE, an IIFE whose value is a global (`StsConsole`,
#      `StsPortal`), from the surface's page table. No browser loads it; the
#      tests do (`tests/console_web_bundle.js`, `tests/web_surfaces.js` and
#      the jobs that draw a page from its answer) — it is what they compare
#      this process's pages with. NOT minified: a failure is easier to read
#      out of it in its own shape.
#   2. THE SURFACE ITSELF: its runtime with every renderer, MINIFIED (rcbj,
#      2026-10-05), because it is the one generated file a browser downloads
#      — 1.89 MB to 1.47 MB for the console (461 KB to 420 KB gzipped) on
#      2026-10-05, most of it prose minifying cannot shorten. The renderers
#      are string-building functions and nothing reads a function's or a
#      class's name, so shortening them changes nothing a page does. No
#      source map: one would carry the sources' comments, which the shipped
#      image strips (#365).
#   3. QUEUED FOR PRECOMPRESSION (the last step of this script), so the
#      surface's server sends it as brotli or gzip without compressing it per
#      request (`common/shell_document.ts`'s `readFile()` and `sendFile()`).
#
# EACH OUTPUT NAME IS EXPLICIT, never derived from the entry: the portal's
# runtime is `portal/portal-spa.js` and not `portal/portal.js`, which is the
# server module `portal.ts` compiles to — the bundle once overwrote it.
#
# esbuild, as a BUNDLER and nothing else (rcbj's choice on #446): no
# framework, no transform of what the pages are. It is run FOR A BROWSER,
# and that is the check: a `web_` module that reaches a server module, or one
# of node's, does not resolve and the image does not build. Bundled from the
# .ts sources, which tsc has just type-checked, and BEFORE the strip below
# removes them. Like every compiled file it is written inside an image build
# only, and the strip takes its comments with the rest. esbuild is
# `tests/package.json`'s, as the compiler is: a build tool the typescript
# stage installs and the service image never carries.
#
# A stylesheet needs no step: each surface's is a string a `web_` module
# holds (`admin-ui/admin.ts`'s `stylesheet()`, `web_portal_kit.ts`'s STYLE,
# `common/web_card_css.ts` for the public surfaces), served as one line with
# nothing to remove.
#
# Usage: bundle_surface <label> <pages entry> <global> <pages out>
#                       <runtime entry> <runtime out>
# ---------------------------------------------------------------------------
ESBUILD=tests/node_modules/.bin/esbuild
# The bundles are this repository's own source in another shape, so each
# opens with the two SPDX lines every source file here carries
# (tests/copyright_notices.js reads them in the tests image).
BUNDLE_OWNER="2026 Iya CyberSecurity Solutions, LLC"
BUNDLE_BANNER="// SPDX-FileCopyrightText: ${BUNDLE_OWNER}
// SPDX-License-Identifier: BUSL-1.1"
PACKED_FILES=()

bundle_surface() {
  local label="$1" pages="$2" global="$3" pages_out="$4" entry="$5" out="$6"
  if [ ! -f "$pages" ] || [ ! -f "$entry" ]; then
    echo "build-typescript.sh: no $pages or $entry; $label is not bundled"
    return 0
  fi
  if [ ! -x "$ESBUILD" ]; then
    echo "build-typescript.sh: $ESBUILD is missing; install" \
         "tests/package.json first (npm install --prefix tests)." >&2
    exit 1
  fi
  echo "build-typescript.sh: bundling $label for a browser (esbuild $entry)"
  "$ESBUILD" "$pages" --bundle --platform=browser --format=iife \
    --global-name="$global" --target=es2022 --charset=ascii \
    --legal-comments=none --log-level=warning \
    --banner:js="$BUNDLE_BANNER" --outfile="$pages_out"
  "$ESBUILD" "$entry" --bundle --platform=browser --format=iife \
    --target=es2022 --charset=ascii --legal-comments=none --minify \
    --log-level=warning --banner:js="$BUNDLE_BANNER" --outfile="$out"
  local one
  for one in "$pages_out" "$out"; do
    if [ ! -s "$one" ]; then
      echo "build-typescript.sh: esbuild wrote no $one" >&2
      exit 1
    fi
  done
  PACKED_FILES+=("$out")
}

# THE ADMIN CONSOLE (#446): `admin-ui/console.bundle.js` (`StsConsole`, the
# entry `web_pages.ts`) and `admin-ui/console.js` (`web_runtime.ts`, started
# by `web_console.ts`), served at `/admin/console.js`.
bundle_surface "the admin console" admin-ui/web_pages.ts StsConsole \
  admin-ui/console.bundle.js admin-ui/web_console.ts admin-ui/console.js

# THE USER PORTAL (#568): `portal/portal.bundle.js` (`StsPortal`,
# `web_portal_pages.ts`) and `portal/portal-spa.js` (`web_portal.ts`), served
# at `/portal/portal.js`.
bundle_surface "the user portal" portal/web_portal_pages.ts StsPortal \
  portal/portal.bundle.js portal/web_portal.ts portal/portal-spa.js

# THE FRONT DOOR (#579), the first public surface: `home/home.bundle.js`
# (`StsHome`, `web_home_pages.ts`) and `home/home-spa.js` (`web_home.ts`),
# served at `/home.js` — `home-spa.js` because `home/home.js` is `home.ts`.
bundle_surface "the front door" home/web_home_pages.ts StsHome \
  home/home.bundle.js home/web_home.ts home/home-spa.js

# THE SIGN-IN SCREEN (#571): `authn/authn.bundle.js` (`StsAuthn`,
# `web_authn_pages.ts`) and `authn/authn-spa.js` (`web_authn.ts`), served at
# `/authn/signin.js` — `authn-spa.js` because `authn/authn.js` is `authn.ts`.
bundle_surface "the sign-in screen" authn/web_authn_pages.ts StsAuthn \
  authn/authn.bundle.js authn/web_authn.ts authn/authn-spa.js

# GNAP'S INTERACTION PAGES (#578): `gnap/gnap-interaction.bundle.js`
# (`StsGnapInteract`, `web_gnap_interact_pages.ts`) and
# `gnap/gnap-interaction-spa.js` (`web_gnap_interact.ts`), served at
# `/gnap/interaction.js` — never `gnap_interact.js`, which is
# `gnap_interact.ts`.
bundle_surface "GNAP's interaction pages" gnap/web_gnap_interact_pages.ts \
  StsGnapInteract gnap/gnap-interaction.bundle.js gnap/web_gnap_interact.ts \
  gnap/gnap-interaction-spa.js
# THE SIGN-OUT (#577): `logout/signout.bundle.js` (`StsSignout`,
# `web_signout_pages.ts`) and `logout/signout-spa.js` (`web_signout.ts`),
# served at `/logout/signout.js` — `-spa` for the rule above, though no
# server module beside it is called `signout`.
bundle_surface "the sign-out" logout/web_signout_pages.ts StsSignout \
  logout/signout.bundle.js logout/web_signout.ts logout/signout-spa.js

# THE OPENID4VC DEMONSTRATION (#582): `oid4vc/vc-demo.bundle.js`
# (`StsVcDemo`, `web_vc_demo_pages.ts`) and `oid4vc/vc-demo-spa.js`
# (`web_vc_demo.ts`), served at `/issuer/demo.js` — never `vc_demo_api.js`
# or `vc_demo_shell.js`, the server modules beside it.
bundle_surface "the OpenID4VC demonstration" oid4vc/web_vc_demo_pages.ts \
  StsVcDemo oid4vc/vc-demo.bundle.js oid4vc/web_vc_demo.ts \
  oid4vc/vc-demo-spa.js

# THE FEDERATION PAGES (#580): `federation/federation-pages.bundle.js`
# (`StsFederation`, `web_federation_pages.ts`) and
# `federation/federation-pages-spa.js` (`web_federation_surface.ts`), served
# at `/federation/pages.js` — never `federation_pages.js`, which is
# `federation_pages.ts`.
bundle_surface "the federation pages" federation/web_federation_pages.ts \
  StsFederation federation/federation-pages.bundle.js \
  federation/web_federation_surface.ts federation/federation-pages-spa.js

# THE DESCRIPTION PAGES (#584): `common/description-pages.bundle.js`
# (`StsDescriptions`, `web_description_pages.ts`) and
# `common/description-pages-spa.js` (`web_description_surface.ts`), ONE file
# served at `<family>/description.js` on the six families' paths —
# `common/description_pages.ts` argues the one bundle — and never
# `description_pages.js`, which is `description_pages.ts`.
bundle_surface "the description pages" common/web_description_pages.ts \
  StsDescriptions common/description-pages.bundle.js \
  common/web_description_surface.ts common/description-pages-spa.js

# THE TLS DIAGNOSTIC PAGES' BUNDLE (#583) WENT WITH THEM (#597): `/tls` and
# `/tls/forwarded` are Monitoring → TLS connection, a page of the console's
# own bundle (`tls/web_tls_connection.ts`).

# THE SPNEGO DEMONSTRATION PAGES (#583): `kerberos/spnego-pages.bundle.js`
# (`StsSpnegoPages`, `web_spnego_pages.ts`) and `kerberos/spnego-pages-spa.js`
# (`web_spnego_surface.ts`), served at `/spnego/pages.js` — never
# `spnego_pages.js`, which is `spnego_pages.ts`.
bundle_surface "the SPNEGO demonstration pages" kerberos/web_spnego_pages.ts \
  StsSpnegoPages kerberos/spnego-pages.bundle.js \
  kerberos/web_spnego_surface.ts kerberos/spnego-pages-spa.js

# A PUBLIC SURFACE OF #569 IS ONE MORE LINE HERE, in the same shape, and one
# row in `tests/tools/web_surfaces.js` (`common/CLAUDE.md`, *Static public
# surfaces*).

if [ "$STRIP" = true ]; then
  # The list is taken BEFORE anything is deleted, so the count is honest.
  STRIPPED="$(sources | wc -l | tr -d ' ')"
  sources | xargs -r rm -f
  rm -rf ./types ./tsconfig.json ./tsconfig.build.json
  echo "build-typescript.sh: stripped $STRIPPED .ts source(s), types/ and" \
       "the tsconfig files"
  # The comments, from what is left (#365). Its parser is a dependency of
  # tests/package.json, installed by the caller with the compiler.
  node tests/tools/strip-comments.js .
fi

# ---------------------------------------------------------------------------
# EVERY SURFACE'S SCRIPT, PRECOMPRESSED (rcbj, 2026-10-05). `admin-ui/
# console.js.br` (brotli, quality 11) and `console.js.gz` (gzip, level 9) are
# written beside it, LAST — after the comment strip above, which rewrites the
# script, so each is the script exactly as it is served. `AdminConsole`
# serves whichever the request's Accept-Encoding takes, with `Vary:
# Accept-Encoding`; nothing is compressed per request for this file, which is
# the one large thing a browser downloads (1.47 MB; 322 KB as brotli and
# 419 KB as gzip on 2026-10-05).
# Every surface's runtime `bundle_surface` queued is compressed (#568, #570),
# and nothing else: an /admin-api, /account-api or protocol
# answer often carries a secret beside text the caller chose, which is what
# BREACH reads through compression.
# ---------------------------------------------------------------------------
for PACKED in ${PACKED_FILES[@]+"${PACKED_FILES[@]}"}; do
if [ -f "$PACKED" ]; then
  PACKED="$PACKED" node -e '
    const fs = require("fs");
    const zlib = require("zlib");
    const file = process.env.PACKED;
    const raw = fs.readFileSync(file);
    fs.writeFileSync(file + ".br", zlib.brotliCompressSync(raw, { params: {
      [zlib.constants.BROTLI_PARAM_QUALITY]: 11,
      [zlib.constants.BROTLI_PARAM_SIZE_HINT]: raw.length } }));
    fs.writeFileSync(file + ".gz", zlib.gzipSync(raw, { level: 9 }));
    console.log("build-typescript.sh: precompressed " + file + ": " +
                raw.length + " bytes, " +
                fs.statSync(file + ".br").size + " as brotli, " +
                fs.statSync(file + ".gz").size + " as gzip");
  '
fi
done
