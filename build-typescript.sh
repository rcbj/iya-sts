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
# THE ADMIN CONSOLE'S BROWSER BUNDLE (#446, 2026-10-05).
#
# The console is being converted into a static application that draws its
# pages in the browser from /admin-api's JSON. Its page renderers are the
# `admin-ui/web_*.ts` modules — the same functions this service draws those
# pages with until the cutover — and this is where they are bundled into the
# ONE file a browser loads: `admin-ui/console.bundle.js`, an IIFE whose value
# is the global `StsConsole` (`admin-ui/web_pages.ts`, the entry).
#
# esbuild, as a BUNDLER and nothing else (rcbj's choice on #446): no
# framework, no transform of what the pages are. It is run FOR A BROWSER, and
# that is the check: a `web_` module that reaches a server module, or one of
# node's, does not resolve and the image does not build.
#
# Bundled from the .ts sources, which tsc has just type-checked, and BEFORE
# the strip below removes them. Like every compiled file it is written inside
# an image build only, and the strip takes its comments with the rest.
#
# esbuild is `tests/package.json`'s, as the compiler is: a build tool the
# typescript stage installs and the service image never carries.
# ---------------------------------------------------------------------------
BUNDLE_ENTRY=admin-ui/web_pages.ts
BUNDLE_OUT=admin-ui/console.bundle.js
if [ -f "$BUNDLE_ENTRY" ]; then
  ESBUILD=tests/node_modules/.bin/esbuild
  if [ ! -x "$ESBUILD" ]; then
    echo "build-typescript.sh: $ESBUILD is missing; install" \
         "tests/package.json first (npm install --prefix tests)." >&2
    exit 1
  fi
  echo "build-typescript.sh: bundling the admin console for a browser" \
       "(esbuild $BUNDLE_ENTRY)"
  # The bundle is this repository's own source in another shape, so it opens
  # with the two SPDX lines every source file here carries
  # (tests/copyright_notices.js reads them in the tests image).
  BUNDLE_OWNER="2026 Iya CyberSecurity Solutions, LLC"
  BUNDLE_BANNER="// SPDX-FileCopyrightText: ${BUNDLE_OWNER}
// SPDX-License-Identifier: BUSL-1.1"
  "$ESBUILD" "$BUNDLE_ENTRY" --bundle --platform=browser --format=iife \
    --global-name=StsConsole --target=es2022 --charset=ascii \
    --legal-comments=none --log-level=warning \
    --banner:js="$BUNDLE_BANNER" --outfile="$BUNDLE_OUT"
  if [ ! -s "$BUNDLE_OUT" ]; then
    echo "build-typescript.sh: esbuild wrote no $BUNDLE_OUT" >&2
    exit 1
  fi
  # AND THE CONSOLE ITSELF (#446, step 5): `admin-ui/console.js`, the
  # runtime (`web_runtime.ts`, started by `web_console.ts`) with every
  # renderer, the shell and the form table in one file. `console.bundle.js`
  # above stays, the renderers alone under a global, because that is what
  # `tests/console_web_bundle.js` compares this process's pages with.
  #
  # **MINIFIED (rcbj, 2026-10-05)**, because it is the one generated file a
  # browser downloads: whitespace and syntax compacted and local names
  # shortened (`--minify`): 1.89 MB to 1.47 MB (461 KB to 420 KB gzipped)
  # on 2026-10-05 — most of it is the pages' own prose, which minifying
  # cannot shorten. The renderers are string-building functions and nothing
  # reads a function's or a class's name, so shortening them changes nothing
  # a page does. No source map: one would carry the sources' comments, which
  # the shipped image strips (#365).
  # `console.bundle.js` above is NOT minified: no browser loads it, and the
  # tests that do are easier to read a failure out of in its own shape.
  # The stylesheet (`/admin/console.css`) needs no step: `stylesheet()`
  # writes it as one line with no whitespace or comments to remove.
  CONSOLE_ENTRY=admin-ui/web_console.ts
  CONSOLE_OUT=admin-ui/console.js
  "$ESBUILD" "$CONSOLE_ENTRY" --bundle --platform=browser --format=iife \
    --target=es2022 --charset=ascii --legal-comments=none --minify \
    --log-level=warning --banner:js="$BUNDLE_BANNER" --outfile="$CONSOLE_OUT"
  if [ ! -s "$CONSOLE_OUT" ]; then
    echo "build-typescript.sh: esbuild wrote no $CONSOLE_OUT" >&2
    exit 1
  fi
fi

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
