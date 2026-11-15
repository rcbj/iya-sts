// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The replay tests receive Node's error codes as TEXT (a port's answer
//! carries the code Node marked on it), and an `ErrorCode` can be made only
//! by its generated constant. So this writes, for the tests alone, the one
//! table from text to constant, from the same `error_codes.json` sts-core's
//! build reads. The library never includes it.

use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn Error>> {
    let table = "../sts-core/tables/error_codes.json";
    println!("cargo::rerun-if-changed={table}");
    let source = fs::read_to_string(table)?;
    let value: serde_json::Value = serde_json::from_str(&source)?;
    let mut out = String::from(
        "#[allow(deprecated)]\n\
         pub fn code_named(text: &str) -> \
         Option<sts_core::errors::ErrorCode> {\n    \
         use sts_core::errors::codes;\n    match text {\n",
    );
    for row in value
        .get("codes")
        .and_then(|c| c.as_array())
        .ok_or("no codes")?
    {
        let code = row.get("code").and_then(|c| c.as_str()).ok_or("code")?;
        writeln!(
            out,
            "        {:?} => Some(codes::{}),",
            code,
            code.replace('-', "_")
        )?;
    }
    out.push_str("        _ => None,\n    }\n}\n");
    let dir = std::env::var("OUT_DIR")?;
    fs::write(Path::new(&dir).join("code_named.rs"), out)?;
    Ok(())
}
