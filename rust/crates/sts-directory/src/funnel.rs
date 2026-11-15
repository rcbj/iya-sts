// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE IDENTITY FUNNEL'S PURE HALF (#444 phase 5, the `oauth7` slice):
//! what `common/admin_stats.js`'s `recordAuthentication()` and
//! `ldap/ldap_server.js`'s `observeIdentity()` / `autoCreateUser()` decide
//! about an authentication before anything is written —
//!
//! * [`identity_of`]: `identityOf()`, the fold of what was presented into
//!   the key the directory files a person under (the legacy subject
//!   prefix dropped, a `urn:uuid:` resolved, a Kerberos realm split off
//!   at the LAST `@`, a DN and a DID taken whole);
//! * [`persona_for`]: `VcClaims.personaFor()`'s first five facts (the
//!   names and the address), drawn from Node's seeded stream so an entry
//!   either runtime invents for a name is the same person;
//! * [`name_plan`]: `namePlan()`, the entry a name-shaped identity gets
//!   (`uid=<name>,ou=users`, the persona only where
//!   `mode.inventsClaimValues()`);
//! * [`not_a_person`]: the early returns of `autoCreateUser()` that are
//!   about the identity rather than the directory;
//! * [`apply_authentication_factors`]: `applyAuthenticationFactors()`, the
//!   `authnMethod` values and the `mfaAuthenticated` flag an
//!   authentication's RFC 8176 `amr` writes.
//!
//! The writes themselves (the lookup, `putEntry()`, the flush) are the
//! runtime's (`sts-runtime`'s `identity_funnel`), over the live directory.
//!
//! NOT PORTED, and said where it would run: `applyVcAttributes()` (the
//! credential claim set's invented values beyond the persona's five), the
//! certificate, DID and SPIFFE plans (`certificatePlan()`, `didPlan()`,
//! `spiffePlan()` — those doors are not in the runtime yet), and the
//! federated attributes (`applyFederatedAttributes()`; federation is not in
//! the runtime yet).

use crate::entry::{Entry, EntryExt};

/// `LEGACY_SUBJECT_PREFIX` (`common/helpers.js`).
pub const LEGACY_SUBJECT_PREFIX: &str = "urn:sts:user:";

/// `identityOf()`'s answer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identity {
    /// The key a person is filed under.
    pub key: String,
    /// The name (the key, for every shape here).
    pub name: String,
    /// The Kerberos realm or mail domain split off, or "".
    pub realm: String,
    /// What was presented, trimmed.
    pub form: String,
    /// A `urn:uuid:` subject naming nobody.
    pub unresolved: bool,
}

/// `identityOf(value)`: `resolve` is `subjectNameOf()`, the name a
/// `urn:uuid:` subject's person is filed under, or `None`.
#[tracing::instrument(level = "trace", skip(resolve))]
pub fn identity_of(
    presented: &str,
    resolve: &dyn Fn(&str) -> Option<String>,
) -> Identity {
    let text = presented.trim();
    if text.is_empty() {
        return Identity::default();
    }
    let rest = text.strip_prefix(LEGACY_SUBJECT_PREFIX).unwrap_or(text);
    if rest.len() >= 9 && rest[..9].eq_ignore_ascii_case("urn:uuid:") {
        return match resolve(rest).filter(|n| !n.is_empty()) {
            Some(named) => Identity {
                key: named.clone(),
                name: named,
                realm: String::new(),
                form: text.to_string(),
                unresolved: false,
            },
            None => Identity {
                key: rest.to_string(),
                name: rest.to_string(),
                realm: String::new(),
                form: text.to_string(),
                unresolved: true,
            },
        };
    }
    // A DN and a DID are taken whole: the '@' of a DN is inside an
    // attribute value, and a DID carries no realm.
    let whole = crate::uuid::dn_shaped(rest) || crate::uuid::did_shaped(rest);
    let (key, realm) = match rest.rfind('@') {
        Some(at) if at > 0 && !whole => {
            (rest[..at].to_string(), rest[at + 1..].to_string())
        }
        _ => (rest.to_string(), String::new()),
    };
    Identity {
        key: key.clone(),
        name: key,
        realm,
        form: text.to_string(),
        unresolved: false,
    }
}

// The persona's tables (`oid4vc/vc_claims.ts`), in Node's order: the
// stream picks by index, so the order is the parity.
const GIVEN_NAMES: [&str; 16] = [
    "Ada", "Kwame", "Ingrid", "Hiroshi", "Rosa", "Tariq", "Mei", "Olof",
    "Priya", "Diego", "Yusuf", "Freya", "Nadia", "Emeka", "Sofia", "Jonas",
];
const FAMILY_NAMES: [&str; 16] = [
    "Lovelace",
    "Osei",
    "Lindqvist",
    "Tanaka",
    "Marquez",
    "Haddad",
    "Chen",
    "Nilsen",
    "Raman",
    "Duarte",
    "Demir",
    "Halvorsen",
    "Farouk",
    "Okonkwo",
    "Ferrari",
    "Weber",
];
const STREETS: [&str; 8] = [
    "Fictitious Way",
    "Placeholder Street",
    "Example Avenue",
    "Sample Road",
    "Mock Lane",
    "Nowhere Terrace",
    "Specimen Close",
    "Dummy Boulevard",
];
/// `PLACES`' postal-code templates, which is all of a place the five facts
/// need: the draws they consume.
const POSTAL_TEMPLATES: [&str; 8] = [
    "#####", "#####", "#####", "@#@ #@#", "@@# #@@", "####", "####", "#### @@",
];
const MAIL_DOMAINS: [&str; 3] = ["example.com", "example.org", "example.net"];

/// `randomFor(seedText)`: mulberry32 seeded from the first four bytes,
/// little-endian, of the seed's SHA-256.
struct Stream(u32);

impl Stream {
    fn new(seed: &str) -> Stream {
        let digest = sts_crypto::jws_alg::Hash::Sha256.digest(seed.as_bytes());
        let mut first = [0u8; 4];
        first.copy_from_slice(&digest[..4]);
        Stream(u32::from_le_bytes(first))
    }

    fn next(&mut self) -> f64 {
        self.0 = self.0.wrapping_add(0x6d2b_79f5);
        let mut t = self.0;
        t = (t ^ (t >> 15)).wrapping_mul(t | 1);
        t ^= t.wrapping_add((t ^ (t >> 7)).wrapping_mul(t | 61));
        f64::from(t ^ (t >> 14)) / 4_294_967_296.0
    }

    fn index(&mut self, len: usize) -> usize {
        ((self.next() * len as f64).floor() as usize) % len
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
            .map(|c| match c {
                '#' => ((self.next() * 10.0).floor() as u32).to_string(),
                '@' => {
                    let i = (self.next() * LETTERS.len() as f64).floor();
                    char::from(LETTERS[i as usize]).to_string()
                }
                other => other.to_string(),
            })
            .collect()
    }
}

/// The persona's five facts an entry is given (`namePlan()`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Persona {
    pub username: String,
    pub given: String,
    pub family: String,
    pub display: String,
    pub email: String,
}

/// `personaFor(name)` as far as its address: the key normalised as
/// `identityKeyOf()` folds it (`somebody` for none), then the stream's
/// draws in Node's order — a given and a family name, a place, a street
/// number and street, the postal code, the mailbox's discriminator and the
/// mail domain.
#[tracing::instrument(level = "trace", skip(resolve))]
pub fn persona_for(
    name: &str,
    resolve: &dyn Fn(&str) -> Option<String>,
) -> Persona {
    let key = identity_of(name, resolve).key;
    let username = if key.is_empty() {
        "somebody".to_string()
    } else {
        key
    };
    let mut random = Stream::new(&username);
    let given = GIVEN_NAMES[random.index(GIVEN_NAMES.len())].to_string();
    let family = FAMILY_NAMES[random.index(FAMILY_NAMES.len())].to_string();
    let place = random.index(POSTAL_TEMPLATES.len());
    let _street = format!(
        "{} {}",
        random.digits(3),
        STREETS[random.index(STREETS.len())]
    );
    let _postal = random.postal(POSTAL_TEMPLATES[place]);
    let mailbox = format!(
        "{}.{}.{}",
        given.to_lowercase(),
        family.to_lowercase(),
        random.digits(4)
    );
    let email = format!(
        "{}@{}",
        mailbox,
        MAIL_DOMAINS[random.index(MAIL_DOMAINS.len())]
    );
    Persona {
        display: format!("{} {}", given, family),
        username,
        given,
        family,
        email,
    }
}

/// `namePlan()`'s answer: where the entry goes and what it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub dn: String,
    /// Lower-cased attribute names, in Node's order.
    pub attributes: Vec<(String, Vec<String>)>,
    /// What is appended onto an entry the name already has.
    pub merge: Vec<(String, String)>,
}

/// `namePlan(name)`: `already` is `existingUserEntry(name)`, `users_dn`
/// the realm's `ou=users`, and `invents` `mode.inventsClaimValues()`.
#[tracing::instrument(level = "trace", skip(already, resolve))]
pub fn name_plan(
    name: &str,
    already: Option<&Entry>,
    users_dn: &str,
    invents: bool,
    resolve: &dyn Fn(&str) -> Option<String>,
) -> Plan {
    let filed = match already {
        Some(e) => {
            let n = crate::Directory::person_name_of(e);
            if n.is_empty() {
                name.to_string()
            } else {
                n
            }
        }
        None => name.to_string(),
    };
    let mut attributes: Vec<(String, Vec<String>)> = vec![
        (
            "objectclass".into(),
            ["top", "person", "organizationalPerson", "inetOrgPerson"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        ),
        ("uid".into(), vec![filed.clone()]),
    ];
    if invents {
        let persona = persona_for(name, resolve);
        attributes.push(("cn".into(), vec![persona.display.clone()]));
        attributes.push(("sn".into(), vec![persona.family.clone()]));
        attributes.push(("givenname".into(), vec![persona.given.clone()]));
        attributes.push((
            "displayname".into(),
            vec![format!("{} (mock)", persona.display)],
        ));
        attributes.push(("mail".into(), vec![persona.email]));
    }
    Plan {
        dn: match already {
            Some(e) => e.dn.clone(),
            None => format!("uid={},{}", filed, users_dn),
        },
        attributes,
        merge: if already.is_some() {
            vec![("uid".into(), filed)]
        } else {
            Vec::new()
        },
    }
}

/// Why `autoCreateUser()` creates nobody for this identity, before the
/// directory is asked: `None` where it goes on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAPerson {
    /// No identity at all.
    Empty,
    /// An LDAP bind names a DN, not a user.
    Ldap,
    /// A client is not a person.
    Client,
    /// A subject identifier naming nobody here (`STS-LDAP-0091`).
    Subject,
    /// A shape whose plan is not in the runtime yet (a DN, a DID, a
    /// SPIFFE ID).
    UnportedShape,
}

/// The identity half of `autoCreateUser()`'s early returns.
#[tracing::instrument(level = "trace")]
pub fn not_a_person(
    key: &str,
    protocol: &str,
    is_client: bool,
) -> Option<NotAPerson> {
    let name = key.trim();
    if name.is_empty() {
        return Some(NotAPerson::Empty);
    }
    if protocol.eq_ignore_ascii_case("ldap") {
        return Some(NotAPerson::Ldap);
    }
    if is_client {
        return Some(NotAPerson::Client);
    }
    let lower = name.to_lowercase();
    if lower.starts_with("urn:uuid:") || crate::uuid::uuid_shaped(&lower) {
        return Some(NotAPerson::Subject);
    }
    if crate::uuid::dn_shaped(name)
        || crate::uuid::did_shaped(name)
        || lower.starts_with("spiffe://")
    {
        return Some(NotAPerson::UnportedShape);
    }
    None
}

/// `addValues(stored, name, values)`: the values the attribute does not
/// already hold appended, '' never; true where one was.
#[tracing::instrument(level = "trace", skip(entry, values))]
pub fn add_values(entry: &mut Entry, name: &str, values: &[String]) -> bool {
    let key = name.to_lowercase();
    let have = entry.values(&key).to_vec();
    let added: Vec<String> = values
        .iter()
        .filter(|v| !v.is_empty() && !have.contains(v))
        .cloned()
        .collect();
    if added.is_empty() {
        return false;
    }
    let mut all = have;
    all.extend(added);
    entry.attributes.insert(key, all);
    true
}

/// `applyAuthenticationFactors(stored, info)`: RFC 8176's `amr` appended
/// to `authnMethod`, `mfaAuthenticated` TRUE for more than one method or
/// an `acr` of `mfa` (and `mfaLastAuthTime` then), FALSE otherwise;
/// nothing for an authentication that states neither. `now` is the
/// generalized time.
#[tracing::instrument(level = "trace", skip(entry))]
pub fn apply_authentication_factors(
    entry: &mut Entry,
    amr: &[String],
    acr: &str,
    now: &str,
) -> bool {
    let amr: Vec<String> = amr
        .iter()
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty())
        .collect();
    let acr = acr.trim();
    if amr.is_empty() && acr.is_empty() {
        return false;
    }
    let mut changed = add_values(entry, "authnMethod", &amr);
    let multi = amr.len() > 1 || acr.eq_ignore_ascii_case("mfa");
    let flag = if multi { "TRUE" } else { "FALSE" };
    if entry.first("mfaauthenticated") != Some(flag) {
        entry
            .attributes
            .insert("mfaauthenticated".into(), vec![flag.into()]);
        changed = true;
    }
    if multi {
        entry
            .attributes
            .insert("mfalastauthtime".into(), vec![now.to_string()]);
        changed = true;
    }
    if changed {
        entry
            .attributes
            .insert("modifytimestamp".into(), vec![now.to_string()]);
    }
    changed
}

/// The `description` an authentication writes (`autoCreateUser()`'s
/// `note`): an enrolment says so rather than "authenticated".
#[tracing::instrument(level = "trace")]
pub fn note_of(event: &str, protocol: &str) -> String {
    if event == "enrolment" {
        format!(
            "a security key was enrolled for them ({}) — a credential being \
             GIVEN rather than presented, which is a different act from \
             signing in even when the same ceremony does both",
            if protocol.is_empty() {
                "WebAuthn"
            } else {
                protocol
            }
        )
    } else {
        format!(
            "authenticated through {}",
            if protocol.is_empty() {
                "an unstated protocol"
            } else {
                protocol
            }
        )
    }
}
