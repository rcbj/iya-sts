// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE INVENTED PERSON AND THE TYPED-ATTRIBUTE CHECK (#444, phase 5, the
//! `apis5` slice): what `users/create` reads about a person in Node.
//!
//! * [`Persona::for_name`] — `oid4vc/vc_claims.ts`'s `personaFor(name)`,
//!   WHOLE: what `applyVcAttributes()` writes beyond the five facts
//!   `namePlan()` takes, which are `sts_directory::funnel::persona_for()`'s
//!   (the identity funnel's, from the same stream; `tests/people_vectors.rs`
//!   holds the two to each other):
//!   one consistent person drawn from a mulberry32 stream seeded by the
//!   first four bytes (little-endian) of SHA-256 over the username, every
//!   field from the same stream in Node's order, so one name is one person
//!   in both runtimes, across restarts.
//! * [`Persona::generated_for`] — `generatedFor(name)`: the values the
//!   realm's SELECTED catalogue rows take for that person, keyed by the
//!   lower-cased attribute. The selection here is the catalogue's default
//!   (`DEFAULT_SELECTION`): the per-realm selection `/admin/vc` sets
//!   (`vc_claims.state`) is not read in this runtime yet.
//! * [`check_create_values`] — `ldap/person_editor.ts`'s
//!   `checkCreateValues(name, values)`: one value where the schema allows
//!   one, at most `MAX_VALUE_LENGTH` characters, no control character, and
//!   the attribute's format (a country code, a date, a language range, a
//!   URI, an integer, a boolean, an address, a DN).
//! * [`person_attributes_from`] — `ldap_server.js`'s
//!   `personAttributesFrom(given)`: a create's attributes held to the
//!   catalogue (`vcClaims.personField()`) and the editor's rows,
//!   STS-LDAP-0047 for a name neither knows and STS-LDAP-0106 for a value
//!   the editor refuses.
//!
//! The tables are Node's, exported by `tests/tools/export-person-tables.js`
//! into `tables/people.json`; `tests/people_vectors.rs` holds the port to
//! Node's own answers both ways.

use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sts_core::errors::{codes, ErrorCode};

const TEXT: &str = include_str!("../tables/people.json");

/// One place: a locality, its region, its country and the SHAPE of that
/// country's postal codes.
#[derive(Debug, Clone, Deserialize)]
pub struct Place {
    pub locality: String,
    pub region: String,
    pub country: String,
    pub postal: String,
}

/// `PERSONA_TABLES`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Names {
    pub given_names: Vec<String>,
    pub family_names: Vec<String>,
    pub streets: Vec<String>,
    pub places: Vec<Place>,
    pub titles: Vec<String>,
    pub honorifics: Vec<String>,
    pub salutations: Vec<String>,
    pub departments: Vec<String>,
    pub units: Vec<String>,
    pub employee_types: Vec<String>,
    pub employee_statuses: Vec<String>,
    pub locales: Vec<String>,
    pub time_zones: Vec<String>,
    pub gender_codes: Vec<String>,
    pub mail_domains: Vec<String>,
}

/// One catalogue row: the attribute and the persona member that fills it.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogueRow {
    pub ldap: String,
    pub from: String,
    pub by_default: bool,
}

/// One of the editor's rows a create holds a value to.
#[derive(Debug, Clone, Deserialize)]
pub struct EditableRow {
    pub name: String,
    pub multi: bool,
    pub format: String,
    pub choices: Option<Vec<String>>,
}

/// The editor's shapes, as regex sources.
#[derive(Debug, Clone, Deserialize)]
pub struct Shapes {
    pub email: String,
    pub control: String,
    pub language: String,
    pub dn: String,
}

/// The whole export.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tables {
    pub persona: Names,
    pub catalogue: Vec<CatalogueRow>,
    pub default_selection: Vec<String>,
    pub person_fields: Vec<String>,
    pub editable: Vec<EditableRow>,
    pub format_hints: Map<String, Value>,
    pub max_value_length: usize,
    pub shapes: Shapes,
    pub countries: Vec<String>,
}

static TABLES: LazyLock<Option<Tables>> = LazyLock::new(|| {
    serde_json::from_str(TEXT)
        .map_err(|e| tracing::error!("tables/people.json: {}", e))
        .ok()
});

struct Compiled {
    email: Regex,
    control: Regex,
    language: Regex,
    dn: Regex,
}

static SHAPES: LazyLock<Option<Compiled>> = LazyLock::new(|| {
    let t = TABLES.as_ref()?;
    // The sources are JavaScript's; the four use nothing the regex crate
    // spells differently (`\uXXXX` is `\x{XXXX}` there).
    let js = |src: &str| src.replace("\\u", "\\x");
    Some(Compiled {
        email: Regex::new(&js(&t.shapes.email)).ok()?,
        control: Regex::new(
            &js(&t.shapes.control)
                .replace("\\x0000", "\\x{0000}")
                .replace("\\x001f", "\\x{001f}")
                .replace("\\x007f", "\\x{007f}")
                .replace("\\x009f", "\\x{009f}"),
        )
        .ok()?,
        language: Regex::new(&js(&t.shapes.language)).ok()?,
        dn: Regex::new(&js(&t.shapes.dn)).ok()?,
    })
});

/// The tables, or None for a build whose table does not parse.
#[tracing::instrument(level = "debug")]
pub fn tables() -> Option<&'static Tables> {
    TABLES.as_ref()
}

/// mulberry32 over a seed, as `randomFor()` writes it out.
struct Stream {
    state: u32,
}

impl Stream {
    fn seeded(text: &str) -> Stream {
        let hex = sts_crypto::raw_sig::Sha256Digester::new()
            .ok()
            .and_then(|mut d| {
                d.update(text.as_bytes()).ok()?;
                d.hex().ok()
            })
            .unwrap_or_default();
        let byte = |i: usize| {
            u32::from_str_radix(hex.get(i * 2..i * 2 + 2).unwrap_or("0"), 16)
                .unwrap_or(0)
        };
        Stream {
            state: byte(0) | (byte(1) << 8) | (byte(2) << 16) | (byte(3) << 24),
        }
    }

    fn next(&mut self) -> f64 {
        self.state = self.state.wrapping_add(0x6d2b_79f5);
        let mut t = self.state;
        t = (t ^ (t >> 15)).wrapping_mul(t | 1);
        t ^= t.wrapping_add((t ^ (t >> 7)).wrapping_mul(t | 61));
        f64::from(t ^ (t >> 14)) / 4_294_967_296.0
    }

    fn pick<'a, T>(&mut self, list: &'a [T]) -> &'a T {
        let n = list.len();
        let i = ((self.next() * n as f64).floor() as usize) % n.max(1);
        &list[i]
    }

    fn digits(&mut self, count: usize) -> String {
        (0..count)
            .map(|_| ((self.next() * 10.0).floor() as u32).to_string())
            .collect()
    }

    fn postal(&mut self, template: &str) -> String {
        const LETTERS: &[u8] = b"ABCDEFGHJKLMNPRSTUVWXYZ";
        template
            .chars()
            .map(|ch| match ch {
                '#' => ((self.next() * 10.0).floor() as u32).to_string(),
                '@' => {
                    let i =
                        (self.next() * LETTERS.len() as f64).floor() as usize;
                    (LETTERS.get(i).copied().unwrap_or(b'A') as char)
                        .to_string()
                }
                other => other.to_string(),
            })
            .collect()
    }
}

/// The invented people.
pub struct Persona;

impl Persona {
    /// `personaFor(name)`, for a name already normalised the way
    /// `stats.identityKeyOf()` normalises it; `somebody` for the empty one.
    #[tracing::instrument(level = "debug")]
    pub fn for_name(key: &str) -> Value {
        let Some(t) = TABLES.as_ref() else {
            return Value::Null;
        };
        let n = &t.persona;
        let username = if key.is_empty() { "somebody" } else { key };
        let mut r = Stream::seeded(username);
        let given = r.pick(&n.given_names).clone();
        let family = r.pick(&n.family_names).clone();
        let place = r.pick(&n.places).clone();
        let street = format!("{} {}", r.digits(3), r.pick(&n.streets));
        let postal = r.postal(&place.postal);
        let mailbox = format!(
            "{}.{}",
            format!("{given}.{family}").to_lowercase(),
            r.digits(4)
        );
        let email = format!("{mailbox}@{}", r.pick(&n.mail_domains));
        let year = 1955 + (r.next() * 50.0).floor() as i64;
        let month = 1 + (r.next() * 12.0).floor() as i64;
        let day = 1 + (r.next() * 28.0).floor() as i64;
        let phone = format!("+1-555-01{}", r.digits(2));
        let mobile = format!("+1-555-01{}", r.digits(2));
        let title = r.pick(&n.titles).clone();
        let unit = r.pick(&n.units).clone();
        let department = r.pick(&n.departments).clone();
        let employee_number = format!("E{}", r.digits(6));
        let employee_type = r.pick(&n.employee_types).clone();
        let employee_status = r.pick(&n.employee_statuses).clone();
        let locale = r.pick(&n.locales).clone();
        let lower = username.to_lowercase();
        let honorific = r.pick(&n.honorifics).clone();
        let salutation = r.pick(&n.salutations).clone();
        let middle = r.pick(&n.given_names).clone();
        let gender = r.pick(&n.gender_codes).clone();
        let zoneinfo = r.pick(&n.time_zones).clone();
        json!({
            "username": username,
            "given": given,
            "family": family,
            "display": format!("{given} {family}"),
            "email": email,
            "birth": format!("{year}{month:02}{day:02}"),
            "country": place.country,
            "street": street,
            "locality": place.locality,
            "region": place.region,
            "postalCode": postal,
            "formatted": format!("{street}${}${} {postal}${}",
                                 place.locality, place.region, place.country),
            "phone": phone,
            "mobile": mobile,
            "title": title,
            "organization": "Example Corporation",
            "unit": unit,
            "department": department,
            "employeeNumber": employee_number,
            "employeeType": employee_type,
            "employeeStatus": employee_status,
            "locale": locale,
            "website": format!("https://www.example.com/~{lower}"),
            "honorific": honorific,
            "salutation": salutation,
            "middle": middle,
            "gender": gender,
            "zoneinfo": zoneinfo,
            "picture": format!("https://www.example.com/~{lower}/photo.jpg"),
            "profile": format!("https://www.example.com/~{lower}/profile"),
        })
    }

    /// `generatedFor(name)` in a mode that invents claim values: the
    /// selected rows' persona values, keyed by the lower-cased attribute,
    /// in the catalogue's order. A row with no `from`, or whose value is
    /// empty, gives nothing.
    #[tracing::instrument(level = "debug")]
    pub fn generated_for(key: &str) -> Vec<(String, String)> {
        let Some(t) = TABLES.as_ref() else {
            return Vec::new();
        };
        let persona = Persona::for_name(key);
        let selected: Vec<String> = t
            .default_selection
            .iter()
            .map(|s| s.to_lowercase())
            .collect();
        t.catalogue
            .iter()
            .filter(|row| selected.contains(&row.ldap.to_lowercase()))
            .filter(|row| !row.from.is_empty())
            .filter_map(|row| {
                let value = match persona.get(&row.from)? {
                    Value::String(s) => s.clone(),
                    Value::Null => return None,
                    other => other.to_string(),
                };
                (!value.is_empty()).then(|| (row.ldap.to_lowercase(), value))
            })
            .collect()
    }
}

/// `identityKeyOf(name)` for a plain name (no subject to resolve): trimmed,
/// and a Kerberos-style `name@REALM` cut at its LAST `@` unless the value
/// is a DN or a DID.
#[tracing::instrument(level = "debug")]
pub fn plain_identity_key(name: &str) -> String {
    let rest = name.trim();
    let dn = rest.split_once('=').is_some_and(|(a, _)| {
        a.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    });
    let did = rest
        .get(..4)
        .is_some_and(|p| rest.len() > 4 && p.eq_ignore_ascii_case("did:"));
    if dn || did {
        return rest.to_string();
    }
    match rest.rfind('@') {
        Some(at) if at > 0 => rest[..at].to_string(),
        _ => rest.to_string(),
    }
}

/// `personEditor.checkCreateValues(name, values)`: None where the editor
/// does not know the attribute; else `{name, values}` in their normal form
/// or `{error}`.
#[tracing::instrument(level = "debug", skip(values))]
pub fn check_create_values(name: &str, values: &[String]) -> Option<Value> {
    let t = TABLES.as_ref()?;
    let row = t
        .editable
        .iter()
        .find(|r| r.name.to_lowercase() == name.to_lowercase())?;
    if !row.multi && values.len() > 1 {
        return Some(json!({ "error": format!(
            "{} holds one value, and {} were given.", row.name, values.len()) }));
    }
    let mut out: Vec<String> = Vec::new();
    for one in values {
        let value = match normalised(t, row, one) {
            Ok(v) => v,
            Err(e) => {
                return Some(json!({ "error": format!(
                    "The value for {} {}.", row.name, e) }));
            }
        };
        if let Some(choices) = &row.choices {
            // `PolicySelection.referenceProblem()`: not reached in a
            // realm whose policy kinds name no person (the export's).
            if !value.is_empty() && !choices.contains(&value) {
                return Some(json!({ "error": format!(
                    "\"{value}\" is not one of {}.", choices.join(", ")) }));
            }
        }
        if !value.is_empty()
            && !out.iter().any(|h| h.to_lowercase() == value.to_lowercase())
        {
            out.push(value);
        }
    }
    Some(json!({ "name": row.name, "values": out }))
}

// `normalised(row, raw)`: its length counted in UTF-16 code units, as
// `value.length` counts it.
fn normalised(
    t: &Tables,
    row: &EditableRow,
    raw: &str,
) -> Result<String, String> {
    let value = raw.trim();
    let units = value.encode_utf16().count();
    if units > t.max_value_length {
        return Err(format!(
            "is {units} characters long, and a value here may be at most {}",
            t.max_value_length
        ));
    }
    let Some(shapes) = SHAPES.as_ref() else {
        return Ok(value.to_string());
    };
    if shapes.control.is_match(value) {
        return Err("contains a control character (a line break, a tab); \
                    a multi-line postal address separates its lines with $"
            .to_string());
    }
    shaped(t, shapes, &row.format, value)
}

// `shaped(format, value, alpha3)`.
fn shaped(
    t: &Tables,
    shapes: &Compiled,
    format: &str,
    value: &str,
) -> Result<String, String> {
    if format.is_empty() || value.is_empty() {
        return Ok(value.to_string());
    }
    let hint = format!(
        "is not {}",
        t.format_hints
            .get(format)
            .and_then(Value::as_str)
            .unwrap_or("")
    );
    let ok =
        |good: bool, v: String| if good { Ok(v) } else { Err(hint.clone()) };
    match format {
        "country" => {
            let code = value.to_uppercase();
            let known = code.len() == 2
                && code.chars().all(|c| c.is_ascii_uppercase())
                && t.countries.contains(&code);
            ok(known, code)
        }
        "date" => {
            let digits: Vec<&str> = if value.len() == 10
                && value.as_bytes()[4] == b'-'
                && value.as_bytes()[7] == b'-'
            {
                vec![&value[..4], &value[5..7], &value[8..]]
            } else if value.len() == 8 {
                vec![&value[..4], &value[4..6], &value[6..]]
            } else if value.len() == 9
                && (value.as_bytes()[4] == b'-' || value.as_bytes()[6] == b'-')
            {
                // `-?` on each side: one of the two dashes.
                if value.as_bytes()[4] == b'-' {
                    vec![&value[..4], &value[5..7], &value[7..]]
                } else {
                    vec![&value[..4], &value[4..6], &value[7..]]
                }
            } else {
                Vec::new()
            };
            let all_digits = digits.len() == 3
                && digits.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()));
            if !all_digits {
                return Err(hint);
            }
            let (y, m, d): (i32, u32, u32) = (
                digits[0].parse().unwrap_or(0),
                digits[1].parse().unwrap_or(0),
                digits[2].parse().unwrap_or(0),
            );
            // `Date.UTC(y, m - 1, d)` read back: a day past the month's
            // end rolls over and is refused, and a year below 100 is
            // taken as 1900 + y and is refused too.
            let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
            let days = match m {
                1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
                4 | 6 | 9 | 11 => 30,
                2 if leap => 29,
                2 => 28,
                _ => 0,
            };
            let real = y >= 100 && d >= 1 && d <= days;
            ok(real, format!("{}{}{}", digits[0], digits[1], digits[2]))
        }
        "language" => ok(
            value
                .split(',')
                .all(|part| shapes.language.is_match(part.trim())),
            value.to_string(),
        ),
        "uri" => {
            let uri = value.split(char::is_whitespace).next().unwrap_or("");
            let good = url::Url::parse(uri)
                .is_ok_and(|u| u.scheme() == "https" || u.scheme() == "http");
            ok(good, value.to_string())
        }
        "integer" => {
            let body = value.strip_prefix('-').unwrap_or(value);
            let good = body == "0"
                || (!body.is_empty()
                    && body.len() <= 18
                    && body.chars().all(|c| c.is_ascii_digit())
                    && !body.starts_with('0'));
            ok(good, value.to_string())
        }
        "boolean" => {
            let upper = value.to_uppercase();
            let good = upper == "TRUE" || upper == "FALSE";
            ok(good, upper)
        }
        "email" => ok(shapes.email.is_match(value), value.to_string()),
        _ => ok(shapes.dn.is_match(value), value.to_string()),
    }
}

/// `valuesOf(x)`: the store's coercion, each trimmed, the empty dropped.
fn values_of(given: &Value) -> Vec<String> {
    let list: Vec<&Value> = match given {
        Value::Array(l) => l.iter().collect(),
        Value::Null => Vec::new(),
        one => vec![one],
    };
    list.into_iter()
        .filter(|v| !v.is_null())
        .map(|v| match v {
            Value::String(s) => s.trim().to_string(),
            other => other.to_string().trim().to_string(),
        })
        .filter(|s| !s.is_empty())
        .collect()
}

/// What a create's attributes come to: each name with its values, or the
/// refusal and its code.
pub type Supplied = Result<Vec<(String, Vec<String>)>, (ErrorCode, Value)>;

/// `personAttributesFrom(given)`: every attribute a create carries, held
/// to the catalogue and the editor's rows, in the order given; a name
/// neither knows is STS-LDAP-0047 (every such name listed), a value the
/// editor refuses STS-LDAP-0106 (where no name was unknown).
#[tracing::instrument(level = "debug", skip_all)]
pub fn person_attributes_from(given: &Value) -> Supplied {
    let Some(t) = TABLES.as_ref() else {
        return Ok(Vec::new());
    };
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();
    let mut refused: Vec<String> = Vec::new();
    for (name, value) in given.as_object().cloned().unwrap_or_default() {
        let row = t
            .person_fields
            .iter()
            .find(|f| f.to_lowercase() == name.trim().to_lowercase());
        let values = values_of(&value);
        let checked = check_create_values(&name, &values);
        if row.is_none() && checked.is_none() {
            unknown.push(name.chars().take(64).collect());
            continue;
        }
        if let Some(error) = checked.as_ref().and_then(|c| c.get("error")) {
            refused.push(error.as_str().unwrap_or("").to_string());
            continue;
        }
        let (named, kept) = match &checked {
            Some(c) => (
                c["name"].as_str().unwrap_or(&name).to_string(),
                c["values"]
                    .as_array()
                    .map(|l| {
                        l.iter()
                            .map(|v| v.as_str().unwrap_or("").to_string())
                            .collect()
                    })
                    .unwrap_or_default(),
            ),
            None => (row.cloned().unwrap_or_default(), values),
        };
        if kept.is_empty() {
            continue;
        }
        match out.iter_mut().find(|(k, _)| *k == named) {
            Some(slot) => slot.1 = kept,
            None => out.push((named, kept)),
        }
    }
    if !refused.is_empty() && unknown.is_empty() {
        return Err((
            codes::STS_LDAP_0106,
            json!({ "ok": false, "errors": refused }),
        ));
    }
    if !unknown.is_empty() {
        let one = unknown.len() == 1;
        return Err((
            codes::STS_LDAP_0047,
            json!({ "ok": false, "errors": [format!(
                "A person here does not have {} called {}. The attributes a \
                 create may write are the catalogue on /admin/vc, which \
                 /admin/users/new draws as its form and GET \
                 /admin-api/users/new publishes. A PASSWORD IS NOT ONE OF \
                 THEM: it is set through the `credential` option on this \
                 same call, or by POST /admin-api/users/set-password, so \
                 that it is hashed rather than written down.",
                if one { "an attribute" } else { "attributes" },
                unknown.join(", "))],
                "unknown": unknown }),
        ));
    }
    Ok(out)
}
