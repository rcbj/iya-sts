// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The product-mode paths the Node vectors cannot reach without the
//! console roster (another slice's): an administrator's writes, the
//! Security Administrator's rule, a clear password through the password
//! policy, and the attribute policy, which only an administrator's add
//! gets as far as. Each expectation is `ldap_server.js`'s, read from its
//! handler.

#![allow(clippy::unwrap_used, clippy::expect_used)] // a test file

use std::sync::Arc;

use sts_directory::directory::{Change, Operation, Request};
use sts_directory::ports::{
    DefaultPersonRules, DirectoryAuthority, FixedMode, PersonRules,
    PolicyRefusal, PreparedPassword, Roles,
};
use sts_directory::{Attributes, Directory, Entry, EntryExt};

const BASE: &str = "dc=example,dc=com";

struct Roster;
impl DirectoryAuthority for Roster {
    fn roles_of(&self, key: &str, _realm: &str) -> Roles {
        match key {
            "root" => Roles {
                read: true,
                write: true,
                ..Roles::default()
            },
            "sec" => Roles {
                security: true,
                ..Roles::default()
            },
            "open" => Roles {
                write: true,
                open: true,
                ..Roles::default()
            },
            _ => Roles::default(),
        }
    }
    fn policy_containers(&self) -> Vec<String> {
        vec!["ou=passwordpolicies".to_string()]
    }
}

struct Hashing;
impl PersonRules for Hashing {
    fn prepare_password(
        &self,
        _u: &str,
        password: &str,
        _c: &str,
        history: &[String],
    ) -> Result<PreparedPassword, PolicyRefusal> {
        if password.len() < 8 {
            return Err(PolicyRefusal {
                code: None,
                message: "too short".into(),
                names: vec![],
            });
        }
        let mut h = history.to_vec();
        h.push("$scrypt$old".into());
        Ok(PreparedPassword {
            hash: format!("$scrypt${password}"),
            history: h,
        })
    }
    fn population_language(&self, a: &str, d: &str) -> String {
        DefaultPersonRules.population_language(a, d)
    }
    fn service_account_reference_refusal(
        &self,
        a: &Attributes,
    ) -> Option<PolicyRefusal> {
        DefaultPersonRules.service_account_reference_refusal(a)
    }
    fn service_account_requires_owner(&self, r: &str, u: &str) -> bool {
        DefaultPersonRules.service_account_requires_owner(r, u)
    }
    fn attribute_create_refusal(
        &self,
        a: &Attributes,
        e: bool,
    ) -> Option<PolicyRefusal> {
        DefaultPersonRules.attribute_create_refusal(a, e)
    }
    fn attribute_edit_refusal(
        &self,
        b: &Attributes,
        a: &Attributes,
        e: bool,
    ) -> Option<PolicyRefusal> {
        DefaultPersonRules.attribute_edit_refusal(b, a, e)
    }
}

fn entry(dn: &str, pairs: &[(&str, &[&str])]) -> Entry {
    Entry {
        dn: dn.into(),
        attributes: pairs
            .iter()
            .map(|(k, v)| {
                (k.to_string(), v.iter().map(|s| s.to_string()).collect())
            })
            .collect(),
        origin: Some("seed".into()),
        created_at: None,
        modified_at: None,
    }
}

fn directory(product: bool) -> Directory {
    let mut d = Directory::new(BASE)
        .with_mode(Arc::new(FixedMode { product }))
        .with_authority(Arc::new(Roster))
        .with_rules(Arc::new(Hashing));
    d.restore(
        "default",
        vec![
            entry(BASE, &[("objectclass", &["domain"])]),
            entry(&format!("ou=users,{BASE}"), &[("ou", &["users"])]),
            entry(
                &format!("ou=passwordPolicies,{BASE}"),
                &[("ou", &["passwordPolicies"])],
            ),
            entry(
                &format!("uid=root,ou=users,{BASE}"),
                &[("uid", &["root"]), ("cn", &["root"]), ("sn", &["root"])],
            ),
            entry(
                &format!("uid=sec,ou=users,{BASE}"),
                &[("uid", &["sec"]), ("cn", &["sec"]), ("sn", &["sec"])],
            ),
            entry(&format!("uid=open,ou=users,{BASE}"), &[("uid", &["open"])]),
        ],
    );
    d
}

fn add(dn: &str, bound: &str, pairs: &[(&str, &[&str])]) -> Request {
    Request {
        dn: dn.into(),
        bound_dn: bound.into(),
        encrypted: true,
        operation: Operation::Add {
            attributes: pairs
                .iter()
                .map(|(k, v)| {
                    (k.to_string(), v.iter().map(|s| s.to_string()).collect())
                })
                .collect(),
        },
    }
}

#[test]
fn an_administrator_writes_and_the_attribute_policy_holds_them() {
    let mut d = directory(true);
    let root = format!("uid=root,ou=users,{BASE}");
    let short = d.perform(&add(
        &format!("uid=amy,ou=users,{BASE}"),
        &root,
        &[("uid", &["amy"]), ("cn", &["Amy"])],
    ));
    let e = short.error.expect("refused");
    assert_eq!(e.name, "ObjectclassViolationError");
    assert_eq!(e.code.map(|c| c.as_str()), Some("STS-LDAP-0162"));
    assert_eq!(
        e.message,
        "This realm's attribute policy requires every person to hold uid, cn, sn, givenName, mail, and this one \
would have no value of sn, givenName, mail. Directory > Policies > Attribute policy sets the list."
    );
    let whole = d.perform(&add(
        &format!("uid=amy,ou=users,{BASE}"),
        &root,
        &[
            ("uid", &["amy"]),
            ("cn", &["Amy"]),
            ("sn", &["A"]),
            ("givenName", &["Amy"]),
            ("mail", &["amy@x"]),
            ("userPassword", &["longenough"]),
        ],
    ));
    assert!(whole.error.is_none(), "{:?}", whole.error);
    let stored = d.get(0, &format!("uid=amy,ou=users,{BASE}")).unwrap();
    assert_eq!(stored.first("userpassword"), Some("$scrypt$longenough"));
    assert_eq!(stored.values("pwdhistory"), ["$scrypt$old".to_string()]);
    assert!(stored.first("pwdchangedtime").is_some());
}

#[test]
fn a_short_password_is_the_policys_refusal() {
    let mut d = directory(false);
    let out = d.perform(&add(
        &format!("uid=bo,ou=users,{BASE}"),
        "",
        &[("uid", &["bo"]), ("userPassword", &["short"])],
    ));
    let e = out.error.expect("refused");
    assert_eq!(
        (e.name.as_str(), e.message.as_str()),
        ("ConstraintViolationError", "too short")
    );
    assert_eq!(e.code.map(|c| c.as_str()), Some("STS-LDAP-0012"));
}

#[test]
fn a_policy_container_needs_the_security_administrator() {
    let mut d = directory(true);
    let dn = format!("cn=p,ou=passwordPolicies,{BASE}");
    let root = d.perform(&add(
        &dn,
        &format!("uid=root,ou=users,{BASE}"),
        &[("cn", &["p"])],
    ));
    let e = root.error.expect("refused");
    assert_eq!(e.code.map(|c| c.as_str()), Some("STS-LDAP-0203"));
    assert_eq!(
        e.message,
        "only a Security Administrator may make this change: it is under ou=passwordpolicies, a Directory → \
Policies container"
    );
    let sec = d.perform(&add(
        &dn,
        &format!("uid=sec,ou=users,{BASE}"),
        &[("cn", &["p"])],
    ));
    assert!(sec.error.is_none(), "{:?}", sec.error);
}

#[test]
fn a_role_held_only_because_the_roster_is_open_is_not_a_role() {
    let mut d = directory(true);
    let out = d.perform(&Request {
        dn: format!("uid=root,ou=users,{BASE}"),
        bound_dn: format!("uid=open,ou=users,{BASE}"),
        encrypted: true,
        operation: Operation::Modify {
            changes: vec![Change {
                operation: "replace".into(),
                attribute: "title".into(),
                values: vec!["x".into()],
            }],
        },
    });
    assert_eq!(
        out.error.and_then(|e| e.code).map(|c| c.as_str()),
        Some("STS-LDAP-0053")
    );
}

#[test]
fn development_authorizes_nothing() {
    let mut d = directory(false);
    let dn = format!("cn=p,ou=passwordPolicies,{BASE}");
    assert!(d.perform(&add(&dn, "", &[("cn", &["p"])])).error.is_none());
}
