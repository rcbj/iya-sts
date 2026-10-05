#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: tests/tools/convert-console-page.py
#
# ---------------------------------------------------------------------------
# MOVE A CONSOLE PAGE'S RENDERER INTO A `web_` MODULE (#446, 2026-10-05).
#
# The admin console is being converted into a static application whose pages
# are drawn in the browser by the `admin-ui/web_*.ts` modules
# (`admin-ui/CLAUDE.md`, *The static console's renderers*). A page whose
# renderer is already a set of methods taking the view and drawing with the
# console's helpers is converted by MOVING those methods, and this does the
# move so that it is the same move every time:
#
#   * the named methods leave the page's class, with their comments, and
#     become static methods of a new class in a new `web_` file;
#   * the lines only a server has are dropped: the `this.deps` destructuring
#     of `log` and `admin`, and every `log.debug(...)` statement;
#   * `admin.` becomes `kit.` (the kit, imported under a name no longer than
#     `admin`, so no moved line grows past 80 columns); `this` and `self`
#     stay, a static method called on its class having the class for `this`;
#   * the ENTRY method stays on the page's class as a delegate that calls the
#     new module's `render()` with the view passed through JSON.
#
# IT REFUSES RATHER THAN GUESSES: a helper the kit does not have, a call to a
# method that was not named, or anything of `deps` or `log` left behind stops
# it with nothing written. What it cannot see is a module constant or a
# static of the old class the moved code reads (`tsc` reports those, as it
# did for the node health page), and a test that calls a moved method on the
# old instance.
#
# `COPY_CONSTS=PAGE,OTHER` in the environment copies those constants of the
# old file into the new one. A file that says `const esc = admin.esc;` gets
# `const esc = kit.esc;` in the new one. The new file may be beside
# its page's module, in any directory; the kit is imported by its relative
# path.
#
# AFTER IT: a row in `admin-ui/web_pages.ts`, a view in
# `tests/console_web_bundle.js`'s `VIEWS`, and the image build.
#
# A tool for the length of #446, run on a checkout (it writes sources, never
# anything compiled), and deleted with the server-rendered console.
#
#   tests/tools/convert-console-page.py <root> <source.ts> <SourceClass> \
#       <admin-ui/web_x.ts> <PageClass> <entry> <method,method,...> \
#       "<HEADLINE FOR THE NEW FILE>" "<What the page class draws.>"
# ---------------------------------------------------------------------------
import re, sys

if len(sys.argv) != 10:
    sys.stderr.write(__doc__ or 'see the header of this file\n')
    sys.exit(2)
(root, source, src_class, web_file, page_class, entry, names, headline,
 what) = sys.argv[1:10]
names = names.split(',')
path = root + '/' + source
lines = open(path).read().split('\n')
KIT = set(re.findall(r'^  static (?:readonly )?([A-Za-z_]+)', open(root + '/admin-ui/web_kit.ts').read(), re.M))

def span(name):
    hits = [i for i, l in enumerate(lines)
            if re.match(r'^  (?:private |static )?%s\(' % re.escape(name), l)]
    assert len(hits) == 1, (name, hits)
    start = hits[0]
    end = start
    while lines[end] != '  }':
        end += 1
    doc = start
    while doc > 0 and lines[doc - 1].strip() != '':
        doc -= 1
    return doc, start, end

def strip_logs(text):
    out = []
    i = 0
    while True:
        m = re.search(r'(^|\n)([ \t]*)log\.debug\(', text[i:])
        if not m:
            out.append(text[i:])
            break
        s = i + m.start() + len(m.group(1))
        out.append(text[i:s])
        j = i + m.end()
        depth = 1
        quote = None
        while depth:
            c = text[j]
            if quote:
                if c == '\\':
                    j += 1
                elif c == quote:
                    quote = None
            elif c in '"\'`':
                quote = c
            elif c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
            j += 1
        assert text[j] == ';', repr(text[j:j + 20])
        j += 1
        if text[j] == '\n':
            j += 1
        i = j
    return ''.join(out)

import os
BARE_ESC = bool(re.search(r'^const esc = admin\.esc;$', '\n'.join(lines), re.M))
# CONSTANTS THE MOVED CODE READS, named in $COPY_CONSTS (comma-separated):
# each `const NAME = ...;` of the old file is copied into the new one with
# the comment above it, and stays where it was too.
COPY = [c for c in os.environ.get('COPY_CONSTS', '').split(',') if c]
copied = []
# A module that says `const esc = admin.esc;` calls the console's escaping
# by its bare name. The new file says the same of the kit's, so no moved
# line changes.
if BARE_ESC:
    copied.append("// The console's escaping, under the name the moved code "
                  "calls it by.\nconst esc = kit.esc;\n")
for const in COPY:
    m = re.search(r'((?:^(?://|/\*\*| \*)[^\n]*\n)*)^const %s = [^;]*;\n'
                  % re.escape(const), '\n'.join(lines), re.M)
    assert m, ('no such constant', const)
    copied.append(m.group(0))
spans = sorted((span(n) + (n,) for n in names))
blocks = []
for doc, start, end, name in spans:
    block = '\n'.join(lines[doc:end + 1])
    block = re.sub(r'^  (?:private |static )?%s\(' % re.escape(name),
                   '  static %s(' % name, block, flags=re.M)
    block = strip_logs(block)
    kept = []
    for l in block.split('\n'):
        if re.match(r'^\s*const \{ log(?:, admin)? \} = this\.deps;$', l) or \
           re.match(r'^\s*const \{ admin(?:, log)? \} = this\.deps;$', l):
            continue
        kept.append(l)
    block = '\n'.join(kept)
    # `this` and `self` stay: a static method called on its class has the
    # class for `this`. The kit is imported as `kit`, shorter than `admin`,
    # so no line the move touches grows.
    block = re.sub(r'\badmin\.', 'kit.', block)
    blocks.append(block)
body = '\n\n'.join(blocks)
assert '.deps' not in body, [l for l in body.split('\n') if '.deps' in l][:3]
assert not re.search(r'\blog\.', body), [l for l in body.split('\n') if re.search(r'\blog\.', l)][:3]
used = set(re.findall(r'\bkit\.([A-Za-z_]+)', body))
assert used <= KIT, ('helpers not in the kit', sorted(used - KIT))
# What the moved code reads that stays behind: a module-level name of the
# source file, or a static of its class. Reported, not refused, because the
# answer differs each time (copy a constant, move a table, put a fact in the
# view) and `tsc` would only say the same thing after an image build.
top = set(re.findall(r'^(?:const|let|function|class|import) ([A-Za-z_$][\w$]*)',
                     '\n'.join(lines), re.M)) - {'kit', 'WebKit'}
top -= set(COPY)
if BARE_ESC:
    top.discard('esc')
code_only = '\n'.join(l for l in body.split('\n')
                      if not re.match(r'^\s*(//|\*|/\*)', l))
left = sorted(n for n in top
              if re.search(r'(?<![\w$.\'"`-])%s(?![\w$\'"`-])' % re.escape(n),
                           code_only))
if left:
    sys.stderr.write('STAYS BEHIND, and the moved code names it: ' +
                     ', '.join(left) + '\n')
called = set(re.findall(r'\b(?:this|self)\.([A-Za-z_]+)\(', body))
assert called <= set(names), ('calls a method that did not move', sorted(called - set(names)))
import textwrap
def wrap(prefix, text):
    return '\n'.join(prefix + l for l in textwrap.wrap(
        text, 79 - len(prefix), break_on_hyphens=False, break_long_words=False))
leaf = web_file.split('/')[-1]
kit_path = os.path.relpath(root + '/admin-ui/web_kit',
                           os.path.dirname(root + '/' + web_file))
if not kit_path.startswith('.'):
    kit_path = './' + kit_path
web = """// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: %s
//
// ---------------------------------------------------------------------------
%s
//
%s
//
%s
// ---------------------------------------------------------------------------

import kit = require('%s');

type Json = any;
%s
/**
%s
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class %s {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static render(view: Json): string {
    return %s.%s(view);
  }

%s
}

export = %s;
""" % (leaf, wrap('// ', headline), wrap('// ', what),
       wrap('// ', "A `web_` MODULE, on `web_kit.ts`'s terms: it requires other "
            "`web_` modules only, logs nothing, and is bundled for a browser by "
            "`build-typescript.sh`. Its methods were `" + src_class + "`'s in `" +
            source + "`, moved with their comments; that module still draws the "
            "page until the console's cutover, by calling `render()` with its "
            "view passed through JSON."),
       kit_path, ('\n' + '\n'.join(copied)) if copied else '',
       wrap(' * ', what), page_class, page_class, entry, body, page_class)
open(root + '/' + web_file, 'w').write(web)

# the source module: the methods go, the entry stays as the round trip
for doc, start, end, name in sorted(spans, reverse=True):
    if name == entry:
        sig = lines[start]
        lines[doc:end + 1] = wrap('  // ', "DRAWN BY `" + leaf + "` (#446): this "
            "page is converted for the static console, and its renderer is a "
            "module a browser can load. Until the cutover this process still "
            "draws it, handing the renderer the view passed THROUGH JSON, so it "
            "is held to what the API's caller receives.").split('\n') + [
            sig,
            "    const { log } = this.deps;",
            "    log.debug(\"Entering %s.%s().\");" % (src_class, entry),
            "    const drawn = %s.render(JSON.parse(JSON.stringify(json)));" % page_class,
            "    log.debug(\"Leaving %s.%s().\");" % (src_class, entry),
            "    return drawn;",
            "  }"]
        assert re.search(r'\(json(: Json)?\)(: string)? \{$', sig), sig
    else:
        del lines[doc:end + 2]
out = '\n'.join(lines)
web_rel = os.path.relpath(root + '/' + web_file[:-3],
                          os.path.dirname(root + '/' + source))
if not web_rel.startswith('.'):
    web_rel = './' + web_rel
imp = "import %s = require('%s');\n" % (page_class, web_rel)
m = list(re.finditer(r'^import [A-Za-z]+ = require\([^)]*\);\n', out, re.M))
assert m
k = m[-1].end()
out = out[:k] + "// The page's renderer (#446): a `web_` module, loadable in a browser.\n" + imp + out[k:]
open(path, 'w').write(out)
print('moved', names, 'kit helpers used:', sorted(used))
