#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: tests/tools/convert-console-route.py
#
# ---------------------------------------------------------------------------
# MOVE A CONSOLE PAGE DRAWN INSIDE ITS ROUTE INTO A `web_` MODULE (#446).
#
# `convert-console-page.py` moves a page whose renderer is already a set of
# methods. Most of `admin-ui/admin.ts`'s pages are not: the route computes
# the view and then draws the page in the same function body, ending in one
# `self.respond(req, res, <view>, <title>, <active>, <html>[, <up>]);`. This
# does the move for that shape, the same way every time:
#
#   * the statements between the view's own line (`const <view> = ...;`, the
#     first statement that declares the name `respond()` is given) and the
#     `respond()` call become a static method of a new class in a new `web_`
#     file, `static <method>(ctx, <view>)`, returning what was `<html>`;
#   * `self.`/`this.` calls of a kit helper become `kit.`; calls of a helper
#     named on the command line become `<Page>.`, and that helper MOVES with
#     its comments into the new file — leaving behind, on the console's class,
#     a delegate of the same name, because other pages still call it;
#   * `req.query` becomes `ctx.query`, `self.mayWrite(req)` becomes
#     `ctx.write`, and anything else read off the request is refused;
#   * every `log.debug(...)` in the moved code is dropped;
#   * the route keeps its view line and calls the renderer with the view
#     passed through JSON and `self.renderContext(req)`.
#
# IT REFUSES RATHER THAN GUESSES: a route with more than one `respond()`, a
# `self.` call of anything neither the kit nor the command line names, a
# read of the request beyond its query. And it REPORTS (`STAYS BEHIND`)
# every free name the moved code uses that it did not declare and that is
# not a JavaScript global — a module constant to copy, a closure of
# `registerRoutes()` to replace with a member of the view.
#
#   tests/tools/convert-console-route.py <root> <source.ts> <route path> \
#       <web file> <PageClass> <method> [helper,helper,...] \
#       "<HEADLINE FOR THE NEW FILE>" "<What it draws.>"
#
# A new file is created; an existing one gains the method (and helpers) at
# the end of its class. `COPY_CONSTS=A,B` copies module constants as
# `convert-console-page.py` does.
#
# A tool for the length of #446, run on a checkout (it writes sources,
# never anything compiled), and deleted with the server-rendered console.
# ---------------------------------------------------------------------------
import os
import re
import sys
import textwrap

if len(sys.argv) not in (9, 10):
    sys.stderr.write('see the header of this file\n')
    sys.exit(2)
if len(sys.argv) == 9:
    (root, source, route, web_file, page_class, method,
     headline, what) = sys.argv[1:9]
    helpers = []
else:
    (root, source, route, web_file, page_class, method, helper_list,
     headline, what) = sys.argv[1:10]
    helpers = [h for h in helper_list.split(',') if h]

path = os.path.join(root, source)
src = open(path).read()
KIT = set(re.findall(r'^  static (?:readonly )?([A-Za-z_]+)',
                     open(os.path.join(root, 'admin-ui/web_kit.ts')).read(),
                     re.M))


def scan_to_close(text, i, open_ch, close_ch):
    """Index just past the bracket closing the one before `i`."""
    depth = 1
    quote = None
    while depth:
        c = text[i]
        if quote:
            if c == '\\':
                i += 1
            elif c == quote:
                quote = None
        elif c in '\'"`':
            quote = c
        elif c == '/' and text[i + 1] == '/':
            i = text.index('\n', i)
            continue
        elif c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
        i += 1
    return i


def strip_logs(text):
    out = []
    i = 0
    while True:
        m = re.search(r'(^|\n)([ \t]*)(?:helpers\.|this\.deps\.)?log\.debug\(',
                      text[i:])
        if not m:
            out.append(text[i:])
            break
        s0 = i + m.start() + len(m.group(1))
        out.append(text[i:s0])
        j = scan_to_close(text, i + m.end(), '(', ')')
        assert text[j] == ';', repr(text[j:j + 30])
        j += 1
        if text[j] == '\n':
            j += 1
        i = j
    return ''.join(out)


def dedent(text, n):
    return '\n'.join(l[n:] if l.startswith(' ' * n) else l
                     for l in text.split('\n'))


# --- the route --------------------------------------------------------------
# `method:NAME` names a console method `NAME(req)` that builds a page's
# `{ inner, json }` rather than a route: its `const json = ...;` is the view
# line and its last `return {` ends what is drawn, `inner` being the markup.
METHOD = route.startswith('method:')
if METHOD:
    m = re.search(r"^  (?:private )?%s\(req(?:, \w+\??(?:: \w+)?)*\)"
                  r"(?:: [^{]*)? \{\n" %
                  re.escape(route[len('method:'):]), src, re.M)
else:
    m = re.search(r"app\.get\((['\"])%s\1, function \(req, res\) \{\n" %
                  re.escape(route), src)
assert m, ('no such route', route)
body_start = m.end()
body_end = scan_to_close(src, body_start, '{', '}') - 1
body = src[body_start:body_end]
def split_args(args_text):
    """The arguments of a call, split at depth 0."""
    out = []
    depth = 0
    quote = None
    cur = ''
    i = 0
    while i < len(args_text):
        c = args_text[i]
        if quote:
            cur += c
            if c == '\\':
                cur += args_text[i + 1]
                i += 1
            elif c == quote:
                quote = None
        elif c in '\'"`':
            quote = c
            cur += c
        elif c in '([{':
            depth += 1
            cur += c
        elif c in ')]}':
            depth -= 1
            cur += c
        elif c == ',' and depth == 0:
            out.append(cur)
            cur = ''
        else:
            cur += c
        i += 1
    out.append(cur)
    return [x.strip() for x in out]


# THE LAST `respond()` IS THE PAGE'S. An earlier one is an early answer — a
# branch that draws something else and returns — and becomes `return
# <html>;` in the renderer, provided it answers the same view, title and tab.
if METHOD:
    r = body.rindex('    return {')
    r_line = r
    indent = 4
    r_end = None
    args = ['req', 'res', 'json', "''", "''", 'inner']
else:
    assert body.count('self.respond(') >= 1, 'no respond() call'
    r = body.rindex('self.respond(')
    r_line = body.rindex('\n', 0, r) + 1
    indent = r - r_line
    r_end = scan_to_close(body, r + len('self.respond('), '(', ')')
    assert body[r_end] == ';'
    args = split_args(body[r + len('self.respond('):r_end - 1])
assert args[0] == 'req' and args[1] == 'res', args[:2]
view_name = args[2]
assert re.match(r'^[A-Za-z_]\w*$', view_name), view_name
html_expr = args[5]
up = args[6] if len(args) > 6 else None
vm = re.search(r'^([ \t]*)const %s(?:: \w+)? = [^;]*;\n' %
               re.escape(view_name), body, re.M)
assert vm and vm.end() <= r_line, ('no view line', view_name)
code = body[vm.end():r_line]
while 'self.respond(' in code:
    e0 = code.index('self.respond(')
    e_end = scan_to_close(code, e0 + len('self.respond('), '(', ')')
    assert code[e_end] == ';'
    eargs = split_args(code[e0 + len('self.respond('):e_end - 1])
    assert eargs[:5] == args[:5], ('an early respond() answers something '
                                   'else', eargs[:5], args[:5])
    rest = code[e_end + 1:]
    # the `return;` that ends the early branch, after any logging
    mret = re.match(r'(\s*(?:log\.debug\((?:[^;]|\n)*?\);\s*)*)return;', rest)
    assert mret, 'an early respond() not followed by return;'
    code = (code[:e0] + 'return ' + eargs[5] + ';' + rest[mret.end():])
# THE NOTICE BANNER STAYS IN THE ROUTE: `messagesOf(req)` draws what a
# redirect brought back, and in the browser the runtime that sent the act
# draws its answer. Wherever the moved code puts it in its markup (an early
# answer too), it is taken out and put in front of the renderer's call.
messages = False
if re.search(r'(?:self|this)\.messagesOf\(req\)\s*\+\s*', code):
    code = re.sub(r'(?:self|this)\.messagesOf\(req\)\s*\+\s*', '', code)
    messages = True
elif re.match(r'^self\.messagesOf\(req\)\s*\+\s*', html_expr):
    html_expr = re.sub(r'^self\.messagesOf\(req\)\s*\+\s*', '', html_expr)
    messages = True

# --- the helpers ------------------------------------------------------------
lines = src.split('\n')


def span(name):
    hits = [k for k, l in enumerate(lines)
            if re.match(r'^  (?:private |static )?%s\(' % re.escape(name), l)]
    assert len(hits) == 1, (name, hits)
    st = hits[0]
    e = st
    while lines[e] != '  }':
        e += 1
    d = st
    while d > 0 and lines[d - 1].strip() != '':
        d -= 1
    return d, st, e


def convert(text):
    text = strip_logs(text)
    text = re.sub(r'^[ \t]*const \{[^}]*\} = this\.deps;\n', '', text,
                  flags=re.M)
    text = re.sub(r'\b(?:self|this)\.mayWrite\(req\)', 'ctx.write', text)
    # The gate's state read only for its write flag is the context's.
    text = re.sub(r'const state = gateStateFor\(req\);\n(\s*)const mayChange = '
                  r'!!\(state && state\.write\);',
                  r'const mayChange = ctx.write;', text)
    # THE SETTINGS BLOCK, from the view's own `settings` member (which the
    # view must carry: the bundle check draws the page from the operation's
    # answer and fails on a page whose view has none).
    if re.search(r'\b(?:self|this)\.configFormsFor\(', text):
        USES_SETTINGS.append(True)
        text = re.sub(r'\b(?:self|this)\.configFormsFor\(',
                      'SettingsForms.forms(' + view_name + '.settings, ', text)
    # A Source column: the settings block's wording, told the two file
    # names by the view's `context` (`AdminConsole.settingsContext()`).
    if re.search(r'\b(?:self|this)\.sourceNote\(', text):
        USES_SETTINGS.append(True)
        text = re.sub(r'\b(?:self|this)\.sourceNote\(([^()]*)\)',
                      r'SettingsForms.sourceNote(\1, ' + view_name +
                      '.context || {})', text)
    # The kit's constants (the page-size cap, the line and tooltip lengths),
    # which the console reads as module constants of the same names.
    # A kit helper the console reached through its deps by a bare name.
    for kname in sorted(k for k in KIT if not k.isupper()):
        text = re.sub(r'(?<![\w.$])%s\(' % kname, 'kit.%s(' % kname, text)
    # The console's own name for the kit.
    text = re.sub(r'\bWebKit\.', 'kit.', text)
    for const in sorted(c for c in KIT if c.isupper()):
        text = re.sub(r'(?<![\w.$])%s\b' % const, 'kit.' + const, text)
    text = re.sub(r'\breq\.query\b', 'ctx.query', text)
    code_only = re.sub(r'//[^\n]*', '', text)
    assert not re.search(r'\breq\b', code_only), (
        'reads the request', [l.strip() for l in code_only.split('\n')
                              if re.search(r'\breq\b', l)][:3])

    def call(mm):
        name = mm.group(1)
        if name in helpers or name in ALREADY:
            return page_class + '.' + name + '('
        if name in KIT:
            return 'kit.' + name + '('
        UNKNOWN.add(name)
        return 'self.' + name + '('
    text = re.sub(r'\b(?:self|this)\.([A-Za-z_]\w*)\(', call, text)
    # `self.esc` handed on as a function, as `.map(self.esc)` does
    def ref(mm):
        name = mm.group(1)
        if name in KIT:
            return 'kit.' + name
        if name not in helpers and name not in ALREADY:
            UNKNOWN.add(name)
        return page_class + '.' + name
    text = re.sub(r'\b(?:self|this)\.([A-Za-z_]\w*)\b', ref, text)
    # A method handed on with `.bind(self)` is bound to what holds it now.
    text = re.sub(r'\b(kit|%s)\.(\w+)\.bind\((?:self|this)\)' % page_class,
                  r'\1.\2.bind(\1)', text)
    return text


UNKNOWN = set()
USES_SETTINGS = []
# Helpers an earlier conversion already moved into this page class, whose
# console methods are delegates now: called on the class, not moved again.
ALREADY = set(h for h in os.environ.get('ALREADY', '').split(',') if h)
moved_helpers = []
for name in helpers:
    d, st, e = span(name)
    block = '\n'.join(lines[d:e + 1])
    block = re.sub(r'^  (?:private |static )?%s\(' % re.escape(name),
                   '  static %s(' % name, block, flags=re.M)
    block = re.sub(r'^(\s*)const self = this;\n', '', block, flags=re.M)
    moved_helpers.append(convert(block))

render = convert(dedent(code, indent - 4))
render = re.sub(r'^(\s*)const self = this;\n', '', render, flags=re.M)
html_conv = convert(html_expr)
if UNKNOWN:
    raise SystemExit('calls console methods neither the kit nor the command '
                     'line names: ' + ','.join(sorted(UNKNOWN)))
method_text = """  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param %s - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static %s(ctx, %s) {
%s    return %s;
  }
""" % (view_name, method, view_name, render if render.strip() else '',
       html_conv.strip())

# --- what stays behind -------------------------------------------------------
GLOBALS = set('''undefined null true false this new return const let var
function if else for while do switch case break continue typeof instanceof
in of try catch finally throw Object Array String Number Boolean Math Date
JSON RegExp Error Map Set WeakMap Promise encodeURIComponent
decodeURIComponent parseInt parseFloat isNaN isFinite Infinity NaN kit ctx
default void delete Symbol BigInt URL URLSearchParams SettingsForms'''.split())
GLOBALS.add(page_class)
everything = method_text + '\n'.join(moved_helpers)
bare = re.sub(r'//[^\n]*', '', everything)
bare = re.sub(r"'(?:[^'\\\n]|\\.)*'", "''", bare)
bare = re.sub(r'"(?:[^"\\\n]|\\.)*"', '""', bare)
bare = re.sub(r'/\*[\s\S]*?\*/', '', bare)
declared = set(re.findall(r'\b(?:const|let|var|function)\s+([A-Za-z_$][\w$]*)',
                          bare))
for params in re.findall(r'function\s*[\w$]*\s*\(([^)]*)\)', bare):
    declared.update(p.split(':')[0].split('=')[0].strip().lstrip('.')
                    for p in params.split(',') if p.strip())
declared.update(re.findall(r'^\s*static (\w+)\(', bare, re.M))
for sig in re.findall(r'^\s*static \w+\(([^)]*)\)', bare, re.M):
    declared.update(p.split(':')[0].split('?')[0].split('=')[0].strip()
                    for p in sig.split(',') if p.strip())
used = set(re.findall(r'(?<![\w$.])([A-Za-z_$][\w$]*)\b(?!\s*:(?!:))', bare))
free = sorted(u for u in used - declared - GLOBALS
              if not re.match(r'^(?:static|Json|any|string|number|boolean|'
                              r'unknown|void|of)$', u))
if free:
    sys.stderr.write('STAYS BEHIND, and the moved code names it: ' +
                     ', '.join(free) + '\n')

if os.environ.get('DRY_RUN'):
    print('would move', route, 'with', helpers)
    sys.exit(0)

# --- write the web file -----------------------------------------------------
web_path = os.path.join(root, web_file)
kit_rel = os.path.relpath(os.path.join(root, 'admin-ui/web_kit'),
                          os.path.dirname(web_path))
if not kit_rel.startswith('.'):
    kit_rel = './' + kit_rel
COPY = [c for c in os.environ.get('COPY_CONSTS', '').split(',') if c]
copied = []
def statement_end(text, i):
    """Index just past the `;` ending the statement that starts at `i`,
    skipping strings, brackets and comments."""
    depth = 0
    quote = None
    while True:
        c = text[i]
        if quote:
            if c == '\\':
                i += 1
            elif c == quote:
                quote = None
        elif c in '\'"`':
            quote = c
        elif c == '/' and text[i + 1] == '/':
            i = text.index('\n', i)
            continue
        elif c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        elif c == ';' and depth == 0:
            return i + 1
        i += 1


for const in COPY:
    cm = re.search(r'((?:^(?://|/\*\*| \*)[^\n]*\n)*)^const %s(?::[^=\n]*)?'
                   r'\s*=' % re.escape(const), src, re.M)
    assert cm, ('no such constant', const)
    end = statement_end(src, cm.end())
    copied.append(src[cm.start():end] + '\n')


def wrap(prefix, text):
    return '\n'.join(prefix + l for l in textwrap.wrap(
        text, 79 - len(prefix), break_on_hyphens=False,
        break_long_words=False))


settings_import = ''
if USES_SETTINGS:
    rel_s = os.path.relpath(os.path.join(root, 'admin-ui/web_settings'),
                            os.path.dirname(web_path))
    if not rel_s.startswith('.'):
        rel_s = './' + rel_s
    settings_import = "\nimport SettingsForms = require('%s');" % rel_s
addition = method_text + ('\n' + '\n\n'.join(moved_helpers)
                          if moved_helpers else '')
addition = addition.rstrip('\n') + '\n'
if os.path.exists(web_path):
    web = open(web_path).read()
    k = web.rindex('\n}\n\nexport = %s;' % page_class)
    web = web[:k] + '\n\n' + addition.rstrip('\n') + web[k:]
    if settings_import and 'import SettingsForms' not in web:
        k = web.index('\n', web.index("import kit = require("))
        web = web[:k] + settings_import + web[k:]
    if copied:
        k = web.index('\n/**\n', web.index("import kit = require("))
        web = web[:k] + '\n' + '\n'.join(c for c in copied
                                         if c not in web) + web[k:]
else:
    leaf = os.path.basename(web_file)
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

import kit = require('%s');%s

type Json = any;
%s
/**
%s
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class %s {
%s}

export = %s;
""" % (leaf, wrap('// ', headline), wrap('// ', what),
       wrap('// ', "A `web_` MODULE, on `web_kit.ts`'s terms: it requires "
            "other `web_` modules only, logs nothing, and is bundled for a "
            "browser by `build-typescript.sh`. It was drawn inside the "
            "route of `" + route + "` in `" + source + "`, which still draws "
            "the page until the console's cutover by calling this with its "
            "view passed through JSON."),
       kit_rel, settings_import, ('\n' + '\n'.join(copied)) if copied else '',
       wrap(' * ', what), page_class, addition, page_class)
for n, l in enumerate(web.split('\n')):
    if len(l) > 80:
        sys.stderr.write('OVER 80 COLUMNS, %s line %d: reflow it\n'
                         % (os.path.basename(web_file), n + 1))
open(web_path, 'w').write(web)

# --- the source: the route, and a delegate per moved helper -----------------
head = ' ' * indent + 'self.respond(req, res, %s, %s, %s,\n' % (
    view_name, args[3], args[4])
if len(head) > 81:
    head = (' ' * indent + 'self.respond(req, res, %s, %s,\n' %
            (view_name, args[3]) + ' ' * (indent + len('self.respond(')) +
            '%s,\n' % args[4])
call = (head + ' ' * (indent + 2) +
        '// Drawn by `%s` (#446).\n' % os.path.basename(web_file) +
        ' ' * (indent + 2) + ('self.messagesOf(req) +\n' + ' ' * (indent + 2)
                              if messages else '') +
        '%s.%s(self.renderContext(req),\n' %
        (page_class, method) + ' ' * (indent + 4) +
        'JSON.parse(JSON.stringify(%s)))%s);' %
        (view_name, (', ' + up) if up else ''))
if METHOD:
    new_body = (body[:vm.end()] + '    // Drawn by `%s` (#446).\n' %
                os.path.basename(web_file) + '    const inner = ' +
                ('this.messagesOf(req) +\n      ' if messages else '') +
                '%s.%s(this.renderContext(req),\n' % (page_class, method) +
                '        JSON.parse(JSON.stringify(json)));\n' +
                '    log.debug("Leaving AdminConsole.%s().");\n' %
                route[len('method:'):] +
                body[r_line:])
else:
    new_body = body[:vm.end()] + call + body[r_end + 1:]
src = src[:body_start] + new_body + src[body_end:]
lines = src.split('\n')
for name in reversed(helpers):
    d, st, e = span(name)
    k = st
    sig = [lines[k]]
    while not sig[-1].rstrip().endswith('{'):
        k += 1
        sig.append(lines[k])
    joined = ' '.join(x.strip() for x in sig)
    params = joined[joined.index('(') + 1:joined.rindex(')')]
    names = ', '.join(p.split(':')[0].split('?')[0].split('=')[0].strip()
                      for p in params.split(',') if p.strip())
    jsd = [q for q in range(d, st) if lines[q].strip() == '/**']
    keep = lines[jsd[0]:k + 1] if jsd else lines[st:k + 1]
    lines[d:e + 1] = (['  // Drawn by `%s` (#446).' %
                       os.path.basename(web_file)] + keep +
                      ['    const { log } = this.deps;',
                       '    log.debug("Entering AdminConsole.%s().");' % name,
                       '    log.debug("Leaving AdminConsole.%s().");' % name,
                       '    return %s.%s(%s);' % (page_class, name, names),
                       '  }'])
src = '\n'.join(lines)
rel = os.path.relpath(web_path[:-3], os.path.dirname(path))
if not rel.startswith('.'):
    rel = './' + rel
imp = "import %s = require('%s');\n" % (page_class, rel)
if imp not in src:
    last = list(re.finditer(r'^import [A-Za-z]+ = require\([^)]*\);\n', src,
                            re.M))[-1]
    src = src[:last.end()] + imp + src[last.end():]
open(path, 'w').write(src)
print('moved', route, 'to', page_class + '.' + method, 'and', helpers)
