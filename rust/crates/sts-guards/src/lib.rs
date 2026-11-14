// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The architecture guards' reader of the workspace (#444).
//!
//! The root `CLAUDE.md` states rules that hold the service together — every
//! failure has an error code and none is sent, anything periodic is a
//! scheduler job, all cryptography is the crypto module's, the parent
//! project's logging rule, an SPDX header on every file. The Node service
//! holds each with an in-process test that READS ITS SOURCE
//! (`tests/error_codes.js`, `tests/no_periodic_timers.js`,
//! `tests/crypto_centralised.js`, `tests/copyright_notices.js`), and those
//! tests are removed with the modules they test at the cutover
//! (rust/DESIGN.md D12). This crate's integration tests are the same rules
//! held over the Rust workspace, written while the Rust code is small enough
//! that what they find can be fixed rather than listed.
//!
//! This file is what they share: a walk of `rust/` (never `target/`), a
//! source file with its comments, string contents and test code blanked to
//! spaces — so a rule reads CODE, a comment quoting a call is not a call, and
//! the byte offsets still line up with the raw text — its blocks, and its
//! functions; `cargo metadata` for the packages, their targets and their
//! direct dependencies; and the ratchet every allow-list is compared through.
//!
//! **Not service code.** This crate runs only under `cargo test`, so the
//! logging rule (D3) does not bind it and guard 5 does not read it, as the
//! Node guards' own Entering/Leaving lines are the Node tests' business and
//! not the service's.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use regex::Regex;
use serde_json::Value as Json;

/// The workspace: `rust/`, which holds `Cargo.toml`.
pub struct Workspace {
    root: PathBuf,
}

/// One package, as `cargo metadata --no-deps` describes it.
#[derive(Debug, Clone)]
pub struct Package {
    pub name: String,
    /// `crates/sts-core`, `bins/xacml-pep`: relative to the workspace.
    pub dir: String,
    pub manifest: PathBuf,
    pub dependencies: Vec<Dependency>,
    pub targets: Vec<Target>,
}

/// A DIRECT dependency. `kind` is `None` for a normal one, `dev` or `build`.
#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub kind: Option<String>,
}

/// A target: a library, a binary, a build script, an integration test.
#[derive(Debug, Clone)]
pub struct Target {
    pub kinds: Vec<String>,
    /// Relative to the workspace.
    pub src: String,
}

/// A string literal: where its content starts and ends in the raw text,
/// and the content as written (escapes unprocessed).
#[derive(Debug, Clone)]
pub struct Literal {
    pub start: usize,
    pub end: usize,
    pub text: String,
}

/// A named function found in the code.
#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    /// `pub`, `pub(crate)`, … or `None` for a private one.
    pub visibility: Option<String>,
    pub is_const: bool,
    /// Where the keyword `fn` is.
    pub at: usize,
    /// The body's braces, or `None` for a declaration without one.
    pub body: Option<(usize, usize)>,
    /// From the end of the previous item to `fn`: its attributes and doc
    /// comments, blanked (`preamble_code`) and as written (`preamble_raw`).
    pub preamble_code: String,
    pub preamble_raw: String,
}

/// One Rust source file.
pub struct SourceFile {
    /// Relative to the workspace, with `/`.
    pub rel: String,
    pub raw: String,
    /// `raw` with comments, the contents of string and character literals,
    /// and `#[cfg(test)]` / `#[test]` items replaced by spaces, newlines
    /// kept.
    pub code: String,
    /// Every string literal outside test code.
    pub literals: Vec<Literal>,
    /// `{` offset → its `}` offset, over `code`.
    closes: HashMap<usize, usize>,
    /// Every `{` with its `}`, in order of the `{`.
    blocks: Vec<(usize, usize)>,
}

impl Workspace {
    /// The workspace this crate is a member of.
    pub fn here() -> Workspace {
        let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = crate_dir
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .unwrap_or(crate_dir);
        Workspace { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Every file under the workspace, relative and sorted, less cargo's
    /// build output.
    pub fn files(&self) -> io::Result<Vec<String>> {
        let mut out = Vec::new();
        let mut stack = vec![String::new()];
        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(self.root.join(&dir))? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().to_string();
                let rel = if dir.is_empty() {
                    name.clone()
                } else {
                    format!("{}/{}", dir, name)
                };
                let kind = entry.file_type()?;
                if kind.is_dir() {
                    if rel != "target" && name != ".git" {
                        stack.push(rel);
                    }
                } else if kind.is_file() {
                    out.push(rel);
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// Every `.rs` file, read and blanked.
    pub fn sources(&self) -> io::Result<Vec<SourceFile>> {
        let mut out = Vec::new();
        for rel in self.files()? {
            if rel.ends_with(".rs") {
                let raw = fs::read_to_string(self.root.join(&rel))?;
                out.push(SourceFile::new(rel, raw));
            }
        }
        Ok(out)
    }

    /// `cargo metadata --no-deps`: the members, their targets and their
    /// DIRECT dependencies — nothing is resolved, so it needs no network.
    pub fn packages(&self) -> Result<Vec<Package>, String> {
        let cargo =
            std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        let output = Command::new(cargo)
            .args(["metadata", "--format-version", "1", "--no-deps"])
            .arg("--offline")
            .arg("--manifest-path")
            .arg(self.root.join("Cargo.toml"))
            .output()
            .map_err(|e| format!("cargo metadata did not run: {}", e))?;
        if !output.status.success() {
            return Err(format!(
                "cargo metadata failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        let doc: Json = serde_json::from_slice(&output.stdout)
            .map_err(|e| format!("cargo metadata's answer: {}", e))?;
        let mut out = Vec::new();
        for p in doc["packages"].as_array().into_iter().flatten() {
            let manifest =
                PathBuf::from(p["manifest_path"].as_str().unwrap_or(""));
            let dir = manifest
                .parent()
                .map(|d| self.relative(d))
                .unwrap_or_default();
            let dependencies = p["dependencies"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|d| Dependency {
                    name: d["name"].as_str().unwrap_or("").to_string(),
                    kind: d["kind"].as_str().map(str::to_string),
                })
                .collect();
            let targets = p["targets"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|t| Target {
                    kinds: t["kind"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|k| k.as_str().map(str::to_string))
                        .collect(),
                    src: self.relative(Path::new(
                        t["src_path"].as_str().unwrap_or(""),
                    )),
                })
                .collect();
            out.push(Package {
                name: p["name"].as_str().unwrap_or("").to_string(),
                dir,
                manifest,
                dependencies,
                targets,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn relative(&self, path: &Path) -> String {
        path.strip_prefix(&self.root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/")
    }
}

/// The package directory a workspace path is in: `crates/sts-core` for
/// `crates/sts-core/src/lib.rs`.
pub fn crate_dir_of(rel: &str) -> String {
    rel.split('/').take(2).collect::<Vec<_>>().join("/")
}

/// Whether a path is code the SERVICE runs, as the Node guards read only
/// the service's own source: not an integration test, bench or example,
/// not a build script, and not this crate.
pub fn is_service_code(rel: &str) -> bool {
    let inside = rel.splitn(3, '/').nth(2).unwrap_or("");
    !(inside.starts_with("tests/")
        || inside.starts_with("benches/")
        || inside.starts_with("examples/")
        || inside == "build.rs"
        || rel.starts_with("crates/sts-guards/"))
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn utf8_len(b: u8) -> usize {
    match b {
        0xF0..=0xFF => 4,
        0xE0..=0xEF => 3,
        0xC0..=0xDF => 2,
        _ => 1,
    }
}

fn blank(out: &mut [u8], from: usize, to: usize) {
    for b in out.iter_mut().take(to).skip(from) {
        if *b != b'\n' {
            *b = b' ';
        }
    }
}

/// Comments and the contents of string and character literals to spaces.
fn blank_comments_and_strings(raw: &str) -> (Vec<u8>, Vec<Literal>) {
    let b = raw.as_bytes();
    let n = b.len();
    let mut out = b.to_vec();
    let mut literals = Vec::new();
    let mut i = 0;
    while i < n {
        let c = b[i];
        let next = if i + 1 < n { b[i + 1] } else { 0 };
        let prev = if i > 0 { b[i - 1] } else { 0 };
        if c == b'/' && next == b'/' {
            let mut j = i;
            while j < n && b[j] != b'\n' {
                j += 1;
            }
            blank(&mut out, i, j);
            i = j;
        } else if c == b'/' && next == b'*' {
            let mut depth = 1;
            let mut j = i + 2;
            while j < n && depth > 0 {
                if b[j] == b'/' && j + 1 < n && b[j + 1] == b'*' {
                    depth += 1;
                    j += 2;
                } else if b[j] == b'*' && j + 1 < n && b[j + 1] == b'/' {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i, j);
            i = j;
        } else if (c == b'r' || (c == b'b' && next == b'r')) && !is_ident(prev)
        {
            // A raw string, `r"…"`, `r#"…"#`, `br"…"`; or an identifier
            // that starts with r (`return`, `r#type`), which is left alone.
            let mut j = if c == b'b' { i + 2 } else { i + 1 };
            let mut hashes = 0;
            while j < n && b[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < n && b[j] == b'"' {
                let start = j + 1;
                let closes_at = |k: usize| {
                    b[k] == b'"'
                        && k + hashes < n
                        && b[k + 1..=k + hashes].iter().all(|h| *h == b'#')
                };
                let end = (start..n).find(|k| closes_at(*k)).unwrap_or(n);
                literals.push(Literal {
                    start,
                    end,
                    text: raw.get(start..end).unwrap_or("").to_string(),
                });
                blank(&mut out, start, end);
                i = (end + 1 + hashes).min(n);
            } else {
                i += 1;
            }
        } else if c == b'"' {
            let start = i + 1;
            let mut k = start;
            while k < n && b[k] != b'"' {
                if b[k] == b'\\' {
                    k += 1;
                }
                k += 1;
            }
            let end = k.min(n);
            literals.push(Literal {
                start,
                end,
                text: raw.get(start..end).unwrap_or("").to_string(),
            });
            blank(&mut out, start, end);
            i = end + 1;
        } else if c == b'\'' {
            if next == b'\\' {
                // An escaped character: '\n', '\'', '\u{1F600}'.
                let mut k = i + 3;
                while k < n && b[k] != b'\'' {
                    k += 1;
                }
                blank(&mut out, i + 1, k);
                i = k + 1;
            } else if i + 1 < n {
                let len = utf8_len(next);
                if i + 1 + len < n && b[i + 1 + len] == b'\'' {
                    blank(&mut out, i + 1, i + 1 + len);
                    i += len + 2;
                } else {
                    // A lifetime or a loop label.
                    i += 1;
                }
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    (out, literals)
}

fn match_braces(code: &[u8]) -> Vec<(usize, usize)> {
    let mut stack = Vec::new();
    let mut out = Vec::new();
    for (i, c) in code.iter().enumerate() {
        if *c == b'{' {
            stack.push(i);
        } else if *c == b'}' {
            if let Some(open) = stack.pop() {
                out.push((open, i));
            }
        }
    }
    out.sort();
    out
}

/// The end of the item that starts at `from`: its `;`, or its body's `}`.
fn item_end(code: &[u8], closes: &HashMap<usize, usize>, from: usize) -> usize {
    let mut depth = 0i32;
    let mut i = from;
    while i < code.len() {
        match code[i] {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b';' if depth <= 0 => return i + 1,
            b'{' if depth <= 0 => {
                return closes.get(&i).map(|c| c + 1).unwrap_or(code.len())
            }
            _ => {}
        }
        i += 1;
    }
    code.len()
}

impl SourceFile {
    /// The file as the service runs it: test items blanked too.
    pub fn new(rel: String, raw: String) -> SourceFile {
        SourceFile::read(rel, raw, true)
    }

    /// The file with its test items kept, for a rule that binds tests too.
    pub fn with_tests(rel: String, raw: String) -> SourceFile {
        SourceFile::read(rel, raw, false)
    }

    fn read(rel: String, raw: String, blank_tests: bool) -> SourceFile {
        let (mut code, literals) = blank_comments_and_strings(&raw);
        let first = match_braces(&code);
        let closes: HashMap<usize, usize> = first.iter().copied().collect();
        // The test items: what a rule about the service does not read, as
        // the Node guards do not walk `tests/`.
        let text = String::from_utf8_lossy(&code).to_string();
        let mut test_spans = Vec::new();
        let attr = Regex::new(r"#\[(?:cfg\(test\)|test)\]").ok();
        if let Some(attr) = attr.filter(|_| blank_tests) {
            for m in attr.find_iter(&text) {
                let end = item_end(&code, &closes, m.end());
                test_spans.push((m.start(), end));
            }
        }
        for (from, to) in &test_spans {
            blank(&mut code, *from, *to);
        }
        let literals = literals
            .into_iter()
            .filter(|l| {
                !test_spans
                    .iter()
                    .any(|(from, to)| l.start >= *from && l.start < *to)
            })
            .collect();
        let blocks = match_braces(&code);
        let closes = blocks.iter().copied().collect();
        let code = String::from_utf8_lossy(&code).to_string();
        SourceFile {
            rel,
            raw,
            code,
            literals,
            closes,
            blocks,
        }
    }

    /// The 1-based line of an offset.
    pub fn line_of(&self, at: usize) -> usize {
        self.raw
            .as_bytes()
            .iter()
            .take(at)
            .filter(|b| **b == b'\n')
            .count()
            + 1
    }

    /// The package directory the file is in.
    pub fn crate_dir(&self) -> String {
        crate_dir_of(&self.rel)
    }

    /// Where the item that owns the `{` at `open` starts: just after the
    /// previous `;`, `{` or `}`.
    fn boundary_before(&self, at: usize) -> usize {
        self.code.as_bytes()[..at]
            .iter()
            .rposition(|c| matches!(c, b';' | b'{' | b'}'))
            .map(|p| p + 1)
            .unwrap_or(0)
    }

    /// What stands before a `{`: `loop`, `while x`, `pub fn f(&self)`.
    pub fn header(&self, open: usize) -> &str {
        let from = self.boundary_before(open);
        self.code.get(from..open).unwrap_or("").trim()
    }

    /// The blocks that contain an offset, innermost first.
    pub fn enclosing(&self, at: usize) -> Vec<(usize, usize)> {
        let mut out: Vec<(usize, usize)> = self
            .blocks
            .iter()
            .copied()
            .filter(|(open, close)| *open < at && at < *close)
            .collect();
        out.sort_by_key(|b| std::cmp::Reverse(b.0));
        out
    }

    /// The `}` of the `{` at `open`.
    pub fn close_of(&self, open: usize) -> Option<usize> {
        self.closes.get(&open).copied()
    }

    /// Every named function outside test code.
    pub fn functions(&self) -> Vec<Function> {
        let mut out = Vec::new();
        let (Ok(fn_re), Ok(qualifiers)) = (
            Regex::new(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)"),
            Regex::new(
                r#"^\s*(pub(?:\s*\([^)]*\))?)?\s*(?:(?:const|async|unsafe|default)\s+|extern\s*(?:"\s*"\s*)?)*$"#,
            ),
        ) else {
            return out;
        };
        let bytes = self.code.as_bytes();
        for c in fn_re.captures_iter(&self.code) {
            let (Some(whole), Some(name)) = (c.get(0), c.get(1)) else {
                continue;
            };
            let line_start = bytes[..whole.start()]
                .iter()
                .rposition(|b| *b == b'\n')
                .map(|p| p + 1)
                .unwrap_or(0);
            let prefix = &self.code[line_start..whole.start()];
            let (visibility, is_const) = match qualifiers.captures(prefix) {
                Some(q) => (
                    q.get(1).map(|v| v.as_str().replace(' ', "")),
                    prefix.contains("const"),
                ),
                None => (None, false),
            };
            let mut depth = 0i32;
            let mut body = None;
            let mut i = whole.end();
            while i < bytes.len() {
                match bytes[i] {
                    b'(' | b'[' => depth += 1,
                    b')' | b']' => depth -= 1,
                    b';' if depth <= 0 => break,
                    b'{' if depth <= 0 => {
                        body = self.close_of(i).map(|close| (i, close));
                        break;
                    }
                    _ => {}
                }
                i += 1;
            }
            let from = self.boundary_before(line_start);
            out.push(Function {
                name: name.as_str().to_string(),
                visibility,
                is_const,
                at: whole.start(),
                body,
                preamble_code: self.code[from..whole.start()].to_string(),
                preamble_raw: self
                    .raw
                    .get(from..whole.start())
                    .unwrap_or("")
                    .to_string(),
            });
        }
        out
    }

    /// The innermost named function whose body contains an offset.
    pub fn function_at(&self, at: usize) -> Option<Function> {
        self.functions()
            .into_iter()
            .filter(|f| f.body.is_some_and(|(o, c)| o < at && at < c))
            .max_by_key(|f| f.at)
    }

    /// The file's inner doc comment (`//!` lines), as written.
    pub fn module_doc(&self) -> String {
        self.raw
            .lines()
            .filter(|l| l.trim_start().starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// A repeating timer found by [`SourceFile::repeating_timers`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timer {
    /// The named function it is in (empty at the top level).
    pub function: String,
    /// `interval`, `loop` (a sleep in a loop) or `chain` (a sleep in a
    /// function that calls itself).
    pub kind: &'static str,
    pub at: usize,
}

impl SourceFile {
    /// Every REPEATING timer in the code (guard 2): an `interval(` /
    /// `interval_at(`; a `sleep(` / `sleep_until(` inside a `loop`, `while`
    /// or `for` of its own function; a `sleep(` in a function that calls
    /// itself. A one-shot delay is none of these.
    pub fn repeating_timers(&self) -> Vec<Timer> {
        let mut out = Vec::new();
        let (Ok(timer), Ok(repeat)) = (
            Regex::new(
                r"(?:\.|\bfn\s+)?\b(sleep|sleep_until|interval|interval_at)\s*\(",
            ),
            Regex::new(r"^(?:'\w+\s*:\s*)?(?:loop$|while\b|for\b)"),
        ) else {
            return out;
        };
        for c in timer.captures_iter(&self.code) {
            let (Some(whole), Some(name)) = (c.get(0), c.get(1)) else {
                continue;
            };
            // A method of something else (`watcher.interval()`) or the
            // definition of a function of that name is not a timer.
            if whole.as_str().starts_with('.')
                || whole.as_str().starts_with("fn")
            {
                continue;
            }
            let function = self.function_at(whole.start());
            let fn_open = function.as_ref().and_then(|g| g.body).map(|b| b.0);
            let in_loop = self
                .enclosing(whole.start())
                .into_iter()
                .take_while(|(open, _)| Some(*open) != fn_open)
                .any(|(open, _)| repeat.is_match(self.header(open)));
            let calls_itself = function.as_ref().is_some_and(|g| {
                g.body.is_some_and(|(open, close)| {
                    Regex::new(&format!(r"\b{}\s*\(", g.name))
                        .map(|r| r.is_match(&self.code[open..close]))
                        .unwrap_or(false)
                })
            });
            let kind = if name.as_str().starts_with("interval") {
                "interval"
            } else if in_loop {
                "loop"
            } else if calls_itself {
                "chain"
            } else {
                continue;
            };
            out.push(Timer {
                function: function.map(|g| g.name).unwrap_or_default(),
                kind,
                at: whole.start(),
            });
        }
        out
    }
}

/// The comparison every allow-list goes through: what was FOUND against
/// what is ALLOWED, both as multisets of keys. A key found and not allowed
/// is a new violation; a key allowed and no longer found is an entry whose
/// reason has gone, and fails too — THE LIST ONLY EVER SHRINKS, as Node's
/// `ALLOWED` and `PENDING` do.
pub fn ratchet<'a>(
    found: impl IntoIterator<Item = String>,
    allowed: impl IntoIterator<Item = &'a str>,
) -> (Vec<String>, Vec<String>) {
    let mut counts: BTreeMap<String, i64> = BTreeMap::new();
    for key in found {
        *counts.entry(key).or_insert(0) += 1;
    }
    for key in allowed {
        *counts.entry(key.to_string()).or_insert(0) -= 1;
    }
    let mut new = Vec::new();
    let mut stale = Vec::new();
    for (key, n) in counts {
        for _ in 0..n.max(0) {
            new.push(key.clone());
        }
        for _ in 0..(-n).max(0) {
            stale.push(key.clone());
        }
    }
    (new, stale)
}

/// A list for a failure message, one item a line.
pub fn listed(items: &[String]) -> String {
    if items.is_empty() {
        return "none".to_string();
    }
    let mut out = format!("{}:", items.len());
    for item in items.iter().take(80) {
        out.push_str("\n    ");
        out.push_str(item);
    }
    if items.len() > 80 {
        out.push_str(&format!("\n    … and {} more", items.len() - 80));
    }
    out
}

// The reader is what every guard stands on, so it is held to sources whose
// answers are known: a guard that silently read nothing would pass.
#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str) -> SourceFile {
        SourceFile::new("crates/x/src/lib.rs".to_string(), text.to_string())
    }

    #[test]
    fn comments_and_strings_are_blanked_and_literals_kept() {
        let f = read(
            "// \"STS-A-0001\" in a comment\n\
             /* nested /* STS-B-0001 */ still */\n\
             fn a() -> char { let q = '\"'; let s = \"STS-C-0001\"; \
             let r = r#\"a \"STS-D-0001\" b\"#; let l: &'static str = s; \
             q }\n",
        );
        let texts: Vec<&str> =
            f.literals.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(texts, vec!["STS-C-0001", "a \"STS-D-0001\" b"]);
        assert!(!f.code.contains("STS-"));
        assert!(f.code.contains("'static"));
        assert_eq!(f.code.len(), f.raw.len());
    }

    #[test]
    fn test_items_are_blanked() {
        let f = read(
            "pub fn kept() {}\n#[cfg(test)]\nmod tests {\n    \
             fn gone() { let s = \"STS-E-0001\"; }\n}\n#[test]\n\
             fn also_gone() {}\npub fn after() {}\n",
        );
        let names: Vec<String> =
            f.functions().into_iter().map(|g| g.name).collect();
        assert_eq!(names, vec!["kept", "after"]);
        assert!(f.literals.is_empty());
        let t = SourceFile::with_tests(f.rel.clone(), f.raw.clone());
        assert_eq!(t.functions().len(), 4);
    }

    #[test]
    fn functions_carry_visibility_body_and_preamble() {
        let f = read(
            "impl X {\n    /// Hot path: no span.\n    \
             pub(crate) fn a(&self, n: [u8; 4]) -> u8 { n[0] }\n\n    \
             #[tracing::instrument(level = \"debug\", skip_all)]\n    \
             pub async fn b(&self) {}\n    pub const fn c() -> u8 { 1 }\n    \
             fn d(&self);\n}\n",
        );
        let g = f.functions();
        assert_eq!(g.len(), 4);
        assert_eq!(g[0].visibility.as_deref(), Some("pub(crate)"));
        assert!(g[0].body.is_some());
        assert!(g[0].preamble_raw.contains("Hot path"));
        assert!(!g[0].preamble_code.contains("instrument"));
        assert!(g[1].preamble_code.contains("instrument"));
        assert!(!g[1].preamble_raw.contains("Hot path"));
        assert!(g[2].is_const);
        assert!(g[3].visibility.is_none() && g[3].body.is_none());
    }

    #[test]
    fn repeating_timers_are_found_and_one_shots_are_not() {
        let f = read(
            "pub fn heartbeat(&self) {\n    tokio::spawn(async move {\n        \
             loop {\n            tokio::time::sleep(every).await;\n        \
             }\n    });\n}\n\
             fn debounce() {\n    tokio::spawn(async move {\n        \
             tokio::time::sleep(d).await;\n        flush();\n    });\n}\n\
             fn ticker() { let mut i = tokio::time::interval(d); }\n\
             fn again(n: u32) { std::thread::sleep(d); again(n - 1); }\n\
             fn waits() { 'outer: while go() { sleep_until(t).await; } }\n\
             fn method() { loop { watcher.interval(); } }\n",
        );
        let found: Vec<(String, &str)> = f
            .repeating_timers()
            .into_iter()
            .map(|t| (t.function, t.kind))
            .collect();
        assert_eq!(
            found,
            vec![
                ("heartbeat".to_string(), "loop"),
                ("ticker".to_string(), "interval"),
                ("again".to_string(), "chain"),
                ("waits".to_string(), "loop"),
            ]
        );
    }

    #[test]
    fn the_ratchet_reports_new_and_stale_keys_as_multisets() {
        let (new, stale) = ratchet(
            vec!["a".to_string(), "a".to_string(), "b".to_string()],
            ["a", "c"],
        );
        assert_eq!(new, vec!["a", "b"]);
        assert_eq!(stale, vec!["c"]);
    }
}
