// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The operator's appconfig file, the file `CONFIG_FILE` names: a port of
//! `common/config_file.js` (what the variable means) and of the top of
//! `common/config.js` (how the file is loaded, and the fatal refusal when
//! it cannot be).
//!
//! **A 1.x OPERATOR'S FILE IS A JAVASCRIPT MODULE, AND IT IS READ AS ONE.**
//! `docs/configuration.md` says `CONFIG_FILE` "names a JavaScript module",
//! and every file this repository ships is one: `var config = { … };
//! module.exports = config;` with comments, `env/npm-tests.js` with a
//! `require('./local')` and an `Object.assign()`. Under the compatible
//! upgrade (rust/DESIGN.md D11, 2026-11-14) the Rust runtime must start on
//! the file an operator already has, so this EVALUATES it — in QuickJS
//! (`rquickjs`), a complete ES2023 engine, with:
//!
//!   * **no I/O but appconfig files**: no `std` or `os` module, no loader, no
//!     timers, no network. `require()` resolves a RELATIVE or ABSOLUTE path
//!     as node does (`X`, `X.js`, `X.json`, `X/index.js`, `X/index.json`)
//!     and reads only that file; a bare name — `fs`, `path`, a package — is
//!     refused by name, since an appconfig file is data and this runtime has
//!     no node modules to give it;
//!   * **CommonJS as node runs it**: the module wrapper's five arguments
//!     (`exports`, `require`, `module`, `__filename`, `__dirname`), a
//!     module cache so a cycle answers a half-built `exports` exactly as
//!     node's does, `this` the module's exports, a leading `#!` line and a
//!     byte-order mark ignored, a `.json` file `JSON.parse`d;
//!   * **`process.env` as a frozen copy of the environment** this process was
//!     started with (a file may well read one: `process.env.X || 'y'`), and
//!     `process.platform`; `console.*` writes to stderr;
//!   * **bounds**: 64 MiB of heap and ten seconds, after which the file is
//!     refused as one that could not be loaded.
//!
//! **What comes out is DATA**: the exports are copied to JSON by a walk that
//! keeps what `config.js` can read — objects, arrays, strings, finite
//! numbers, booleans, `null` — drops an `undefined` member (which `dig()`
//! cannot tell from an absent one) and refuses, naming its path, a function,
//! a symbol, a `BigInt`, a non-finite number and any object that is not a
//! plain one (a `Date`, a `RegExp`, a `Map`): `config.js` would read each of
//! those through `String()`, which no setting's documentation describes.
//! Key order is the module's own, which is the order `Object.keys()` gives.
//!
//! A `.json` `CONFIG_FILE` is read as node's `require()` reads one, so the
//! `env/*.json` copies the first Rust runtime read keep working.
//!
//! A file that cannot be loaded is FATAL (STS-CORE-0001), in config.js's
//! words — the service would otherwise start configured as nobody asked.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use rquickjs::{Context, Ctx, Exception, Function, Object, Runtime, Value};
use serde_json::Value as Json;

use crate::errors::codes;
use crate::log::tag;

/// The heap an appconfig file may use while it is evaluated.
const MEMORY_LIMIT: usize = 64 * 1024 * 1024;
/// How long it may run.
const TIME_LIMIT: Duration = Duration::from_secs(10);
/// The largest file `require()` reads.
const MAX_FILE: u64 = 16 * 1024 * 1024;

/// The loaded file: what the operator's module exported, as JSON, and the
/// path `CONFIG_FILE` resolved to.
#[derive(Debug, Clone, PartialEq)]
pub struct Appconfig {
    /// `CONFIG_FILE` after `resolve_config_file()`; `None` when unset.
    pub config_file: Option<String>,
    /// What the module exported; `Null` when there is no file.
    pub operator: Json,
}

impl Appconfig {
    /// `appconfig.logLevel`, the bootstrap logger's level before the
    /// table exists: the operator's, else `info` (env/defaults.js's).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn log_level(&self) -> String {
        match self.operator.get("logLevel") {
            Some(Json::String(level)) if !level.is_empty() => level.clone(),
            _ => "info".to_string(),
        }
    }
}

/// `resolveConfigFile()`: `CONFIG_FILE` made absolute. Left alone when it is
/// unset (`None`), already absolute, or does not start with `.` (node would
/// resolve a bare name as a package; see [`load`]). A relative path is
/// tried against the package root and then the working directory, and the
/// first that exists wins; when neither does, the value as given.
#[tracing::instrument(level = "debug", skip_all)]
pub fn resolve_config_file(
    given: Option<&str>,
    root: &Path,
    cwd: &Path,
) -> Option<String> {
    let given = given.filter(|g| !g.is_empty())?;
    if Path::new(given).is_absolute() || !given.starts_with('.') {
        return Some(given.to_string());
    }
    for candidate in [normalize(&root.join(given)), normalize(&cwd.join(given))]
    {
        if candidate.exists() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    Some(given.to_string())
}

/// `path.resolve()`'s lexical half: `.` and `..` folded away.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Reads the appconfig layer: `CONFIG_FILE` from `env`, resolved against
/// `root` and the working directory, evaluated. `Err` carries the whole
/// STS-CORE-0001 sentence config.js writes to stderr before it exits.
#[tracing::instrument(level = "debug", skip_all)]
pub fn load(
    root: &Path,
    env: &HashMap<String, String>,
) -> Result<Appconfig, String> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| root.to_path_buf());
    let resolved = resolve_config_file(
        env.get("CONFIG_FILE").map(String::as_str),
        root,
        &cwd,
    );
    let Some(file) = resolved else {
        return Ok(Appconfig {
            config_file: None,
            operator: Json::Null,
        });
    };
    match evaluate(&file, env) {
        Ok(operator) => Ok(Appconfig {
            config_file: Some(file),
            operator,
        }),
        Err(why) => Err(fatal(&file, &why)),
    }
}

/// config.js's refusal, word for word.
fn fatal(file: &str, why: &str) -> String {
    format!(
        "{}config: FATAL — the appconfig file {} could not be loaded: {}\n\
         CONFIG_FILE names a JavaScript module, resolved against this \
         package root and then against the working directory (see \
         common/config_file.js).\n",
        tag(codes::STS_CORE_0001),
        file,
        why
    )
}

/// node's resolution of a path a module `require()`s: the file, then with
/// `.js` and `.json`, then a directory's `index.js` and `index.json`.
/// `Err` is node's "Cannot find module" sentence, or the refusal of a bare
/// name.
fn resolve_require(dir: &Path, spec: &str) -> Result<PathBuf, String> {
    let relative = spec.starts_with("./")
        || spec.starts_with("../")
        || spec == "."
        || spec == "..";
    if !relative && !Path::new(spec).is_absolute() {
        return Err(format!(
            "require('{}') is not available to an appconfig file: this \
             runtime reads the file as data, and it may require only \
             another appconfig file, by a relative or absolute path",
            spec
        ));
    }
    let base = normalize(&dir.join(spec));
    let mut tries = vec![base.clone()];
    for ext in ["js", "json"] {
        let mut with = base.clone().into_os_string();
        with.push(".");
        with.push(ext);
        tries.push(PathBuf::from(with));
    }
    tries.push(base.join("index.js"));
    tries.push(base.join("index.json"));
    tries
        .into_iter()
        .find(|p| p.is_file())
        .ok_or_else(|| format!("Cannot find module '{}'", spec))
}

/// One file's text, for the loader: at most [`MAX_FILE`], a byte-order mark
/// dropped (node's `stripBOM()`), and a leading `#!` line blanked as node
/// does, so line numbers in an error are the file's.
fn read_module(path: &Path) -> Result<String, String> {
    let size = std::fs::metadata(path)
        .map_err(|e| format!("{}: {}", path.display(), e))?
        .len();
    if size > MAX_FILE {
        return Err(format!(
            "{} is {} bytes, more than an appconfig file may be",
            path.display(),
            size
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("{}: {}", path.display(), e))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    Ok(match text.strip_prefix("#!") {
        Some(rest) => format!("//{}", rest),
        None => text.to_string(),
    })
}

/// The CommonJS loader and the walk that turns the exports into JSON,
/// in the engine. `__sts` is the three natives below.
const LOADER: &str = r#"
(function (sts, env, platform) {
  'use strict';
  const cache = Object.create(null);
  const toText = function (v) { return String(v); };
  globalThis.process = Object.freeze({
    env: Object.freeze(JSON.parse(env)),
    platform: platform
  });
  const write = function () {
    sts.stderr(Array.prototype.map.call(arguments, toText).join(' '));
  };
  globalThis.console = Object.freeze({
    log: write, info: write, warn: write, error: write, debug: write
  });
  function load(file) {
    if (cache[file]) {
      return cache[file].exports;
    }
    const module = { id: file, filename: file, exports: {}, loaded: false,
                     children: [] };
    cache[file] = module;
    const text = sts.read(file);
    if (/\.json$/i.test(file)) {
      try {
        module.exports = JSON.parse(text);
      } catch (e) {
        e.message = file + ': ' + e.message;
        throw e;
      }
      module.loaded = true;
      return module.exports;
    }
    const dir = sts.dirname(file);
    const require = function require(spec) {
      return load(sts.resolve(dir, String(spec)));
    };
    require.cache = cache;
    module.require = require;
    const wrapped = (0, eval)('(function (exports, require, module, ' +
      '__filename, __dirname) {' + text + '\n})');
    wrapped.call(module.exports, module.exports, require, module, file, dir);
    module.loaded = true;
    return module.exports;
  }
  function data(v, where) {
    if (v === null || typeof v === 'string' || typeof v === 'boolean') {
      return v;
    }
    if (typeof v === 'number') {
      if (!isFinite(v)) {
        throw new TypeError(where + ' is ' + String(v) + ', which no ' +
          'setting can hold');
      }
      return v;
    }
    if (v === undefined) {
      return undefined;
    }
    if (Array.isArray(v)) {
      return v.map(function (one, i) {
        const out = data(one, where + '[' + i + ']');
        return out === undefined ? null : out;
      });
    }
    if (typeof v === 'object') {
      const proto = Object.getPrototypeOf(v);
      if (proto !== Object.prototype && proto !== null) {
        throw new TypeError(where + ' is ' +
          Object.prototype.toString.call(v) + ', which is not a plain ' +
          'object; an appconfig file holds objects, arrays, strings, ' +
          'numbers and booleans');
      }
      const out = {};
      Object.keys(v).forEach(function (key) {
        const one = data(v[key], where + '.' + key);
        if (one !== undefined) {
          out[key] = one;
        }
      });
      return out;
    }
    throw new TypeError(where + ' is a ' + typeof v + ', which no ' +
      'setting can hold');
  }
  return function (file) {
    const exported = data(load(file), 'module.exports');
    return JSON.stringify(exported === undefined ? null : exported);
  };
})
"#;

/// Evaluates the module at `file` and answers its exports as JSON. `Err`
/// is the reason, as `err.message` would say it.
#[tracing::instrument(level = "debug", skip_all)]
pub fn evaluate(
    file: &str,
    env: &HashMap<String, String>,
) -> Result<Json, String> {
    let path = PathBuf::from(file);
    if !path.is_absolute() || !path.is_file() {
        // node's first line; its "Require stack" follows, and so does what
        // this runtime cannot do: a relative path that resolved nowhere, or
        // a bare name node would look for as a package, of which there are
        // none here.
        return Err(format!(
            "Cannot find module '{}'\nCONFIG_FILE names no file here{}",
            file,
            if path.is_absolute() || file.starts_with('.') {
                ""
            } else {
                "; a package name is not one this runtime can load"
            }
        ));
    }
    let runtime = Runtime::new().map_err(|e| e.to_string())?;
    runtime.set_memory_limit(MEMORY_LIMIT);
    runtime.set_max_stack_size(1024 * 1024);
    let deadline = Instant::now() + TIME_LIMIT;
    runtime.set_interrupt_handler(Some(Box::new(move || {
        Instant::now() > deadline
    })));
    let context = Context::full(&runtime).map_err(|e| e.to_string())?;
    let env_json = serde_json::to_string(env).map_err(|e| e.to_string())?;
    let text = context.with(|ctx| -> Result<String, String> {
        let answer = run(&ctx, &path, &env_json);
        answer.map_err(|e| match e {
            rquickjs::Error::Exception => describe(&ctx.catch(), deadline),
            other => other.to_string(),
        })
    })?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

fn run(ctx: &Ctx<'_>, path: &Path, env: &str) -> rquickjs::Result<String> {
    let natives = Object::new(ctx.clone())?;
    natives.set(
        "read",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, file: String| -> rquickjs::Result<String> {
                read_module(Path::new(&file))
                    .map_err(|why| Exception::throw_message(&ctx, &why))
            },
        )?,
    )?;
    natives.set(
        "resolve",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>,
             dir: String,
             spec: String|
             -> rquickjs::Result<String> {
                resolve_require(Path::new(&dir), &spec)
                    .map(|p| p.to_string_lossy().into_owned())
                    .map_err(|why| Exception::throw_message(&ctx, &why))
            },
        )?,
    )?;
    natives.set(
        "dirname",
        Function::new(ctx.clone(), |file: String| -> String {
            Path::new(&file)
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default()
        })?,
    )?;
    natives.set(
        "stderr",
        Function::new(ctx.clone(), |line: String| {
            eprintln!("{}", line);
        })?,
    )?;
    let factory: Function = ctx.eval(LOADER)?;
    let reader: Function =
        factory.call((natives, env.to_string(), std::env::consts::OS))?;
    reader.call((path.to_string_lossy().into_owned(),))
}

/// An exception's `message`, as config.js prints `err.message`, or the
/// value itself when what was thrown is not an error.
fn describe(thrown: &Value<'_>, deadline: Instant) -> String {
    if Instant::now() > deadline {
        return format!(
            "it ran for more than {} seconds and was stopped",
            TIME_LIMIT.as_secs()
        );
    }
    // `err.message`, concatenated: a thrown value with no `message` (a
    // string, a number) is "undefined" in config.js's sentence, as it is
    // here.
    if let Some(object) = thrown.as_object() {
        if let Ok(message) = object.get::<_, Value>("message") {
            if let Some(text) = js_text(&message) {
                return text;
            }
        }
    }
    if !thrown.is_undefined() && !thrown.is_null() {
        return "undefined".to_string();
    }
    match thrown.type_of() {
        rquickjs::Type::Uninitialized => {
            "it used more memory than an appconfig file may".to_string()
        }
        other => format!("a {} was thrown", other.as_str()),
    }
}

/// `String(v)` for the values a `message` holds.
fn js_text(value: &Value<'_>) -> Option<String> {
    if value.is_undefined() {
        return Some("undefined".to_string());
    }
    if let Some(text) = value.as_string() {
        return text.to_string().ok();
    }
    let ctx = value.ctx().clone();
    let string: Function = ctx.globals().get("String").ok()?;
    string.call::<_, String>((value.clone(),)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sts-appconfig-{}-{}",
            std::process::id(),
            crate::time::iso_now().replace([':', '.'], "-")
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn eval(dir: &Path, name: &str, text: &str) -> Result<Json, String> {
        let file = dir.join(name);
        std::fs::write(&file, text).unwrap();
        let env: HashMap<String, String> =
            [("PROBE".to_string(), "from-env".to_string())].into();
        evaluate(file.to_str().unwrap(), &env)
    }

    #[test]
    fn reads_the_forms_operators_write() {
        let d = dir();
        std::fs::write(
            d.join("base.js"),
            "// a comment\nvar config = { logLevel: 'info', global: \
             { port: 8081, https: true } };\nmodule.exports = config;\n",
        )
        .unwrap();
        std::fs::write(d.join("extra.json"), "\u{feff}{\"x\": [1, 2]}")
            .unwrap();
        let got = eval(
            &d,
            "top.js",
            "#!/usr/bin/env node\n'use strict';\nconst base = \
             require('./base');\nmodule.exports = Object.assign({}, base, \
             { extra: require('./extra.json'), who: process.env.PROBE, \
             gone: undefined, list: [undefined, 'a'], n: -0 });",
        )
        .unwrap();
        assert_eq!(
            got,
            json!({"logLevel": "info", "global": {"port": 8081,
                   "https": true}, "extra": {"x": [1, 2]},
                   "who": "from-env", "list": [null, "a"], "n": 0})
        );
        let keys: Vec<&String> = got.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["logLevel", "global", "extra", "who", "list", "n"]);
        assert_eq!(
            eval(&d, "e.js", "exports.a = 1; this.b = 2;").unwrap(),
            json!({"a": 1, "b": 2})
        );
    }

    #[test]
    fn refuses_what_is_not_data_or_reaches_outside() {
        let d = dir();
        let fs = eval(&d, "fs.js", "module.exports = require('fs');");
        assert!(fs.unwrap_err().contains("require('fs') is not available"));
        let f =
            eval(&d, "f.js", "module.exports = { a: { b: function(){} } };");
        assert!(f.unwrap_err().contains("module.exports.a.b is a function"));
        let date = eval(&d, "d.js", "module.exports = { when: new Date() };");
        assert!(date.unwrap_err().contains("[object Date]"));
        let nan = eval(&d, "n.js", "module.exports = { n: 0/0 };");
        assert!(nan.unwrap_err().contains("NaN"));
        let syntax = eval(&d, "s.js", "module.exports = {");
        assert!(syntax.is_err());
        let missing = eval(&d, "m.js", "require('./nope');");
        assert_eq!(missing.unwrap_err(), "Cannot find module './nope'");
        let thrown = eval(&d, "t.js", "throw 'plain';");
        assert_eq!(thrown.unwrap_err(), "undefined");
        let coded = eval(&d, "c.js", "throw { message: 42 };");
        assert_eq!(coded.unwrap_err(), "42");
    }

    #[test]
    fn a_runaway_file_is_stopped() {
        let d = dir();
        let big = eval(
            &d,
            "big.js",
            "const a = []; for (;;) { a.push('x'.repeat(1 << 20)); }",
        );
        assert!(big.is_err());
    }

    #[test]
    fn a_cycle_answers_the_half_built_exports() {
        let d = dir();
        std::fs::write(
            d.join("a.js"),
            "exports.early = 1; const b = require('./b'); exports.b = b;",
        )
        .unwrap();
        std::fs::write(
            d.join("b.js"),
            "const a = require('./a'); module.exports = { sawEarly: \
             a.early, sawB: a.b === undefined };",
        )
        .unwrap();
        let got = evaluate(d.join("a.js").to_str().unwrap(), &HashMap::new());
        assert_eq!(
            got.unwrap(),
            json!({"early": 1, "b": {"sawEarly": 1, "sawB": true}})
        );
    }

    #[test]
    fn config_file_resolves_as_config_file_js_does() {
        let d = dir();
        std::fs::create_dir_all(d.join("env")).unwrap();
        std::fs::write(d.join("env/local.js"), "module.exports = {};").unwrap();
        let elsewhere = Path::new("/nonexistent-cwd");
        assert_eq!(
            resolve_config_file(Some("./env/local.js"), &d, elsewhere),
            Some(d.join("env/local.js").to_string_lossy().into_owned())
        );
        assert_eq!(
            resolve_config_file(Some("./env/none.js"), &d, elsewhere),
            Some("./env/none.js".to_string())
        );
        assert_eq!(
            resolve_config_file(Some("some-package"), &d, elsewhere),
            Some("some-package".to_string())
        );
        assert_eq!(resolve_config_file(None, &d, elsewhere), None);
        assert_eq!(resolve_config_file(Some(""), &d, elsewhere), None);
        let env: HashMap<String, String> =
            [("CONFIG_FILE".to_string(), "./env/none.js".to_string())].into();
        let refused = load(&d, &env).unwrap_err();
        assert!(refused.starts_with(&format!(
            "{}config: FATAL — the appconfig file ./env/none.js could not \
             be loaded: ",
            tag(codes::STS_CORE_0001)
        )));
    }
}
