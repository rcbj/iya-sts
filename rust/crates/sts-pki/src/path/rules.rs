// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! RFC 5280 section 6.1, once: the rules every path is held to (`pki.js`'s
//! `pathRuleProblem()`, `constraintProblem()`, `pathPolicyOutcome()` and
//! `pathValidityProblem()`, #201).
//!
//! A path is leaf first and anchor last. What is answered here is every
//! section 6.1 question that is not a signature or a clock — critical
//! extensions, broken hashes, the CA rules, pathLenConstraint counting only
//! non-self-issued certificates, name constraints in the five forms
//! evaluated, and the certificate policy tree whole — and, separately, the
//! clock. The signature and the issuer-to-subject link are the builder's.

use chrono::{TimeZone, Utc};

use super::entry::Entry;
use super::facts::{
    Form, GeneralName, NameValue, Subtree, PATH_EXTENSION_OIDS,
};

pub const ANY_POLICY: &str = "2.5.29.32.0";
/// The most nodes one path's valid_policy_tree may hold (CVE-2023-0464).
const PATH_MAX_POLICY_NODES: usize = 10000;
/// The name-constraint work one path may cost: names times subtrees.
const PATH_MAX_NAME_CHECKS: usize = 1 << 20;
const ML_DSA_OIDS: &[&str] = &[
    "2.16.840.1.101.3.4.3.17",
    "2.16.840.1.101.3.4.3.18",
    "2.16.840.1.101.3.4.3.19",
];
const ML_DSA_USAGES: &[&str] = &[
    "digitalSignature",
    "nonRepudiation",
    "keyCertSign",
    "cRLSign",
];

/// A refusal: `{ check, index, why }`, and for some checks a detail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    pub check: &'static str,
    pub index: usize,
    pub why: String,
}

/// The four inputs of section 6.1 a caller may set.
#[derive(Clone, Debug, Default)]
pub struct PolicyInputs {
    pub initial_policy_set: Vec<String>,
    pub initial_explicit_policy: bool,
    pub initial_inhibit_any_policy: bool,
    pub initial_policy_mapping_inhibit: bool,
}

/// `opts` of the rules.
#[derive(Clone, Debug, Default)]
pub struct RuleOptions {
    /// Critical extensions, by name or OID, the caller evaluates itself.
    pub allow_critical: Vec<String>,
    pub allow_sha1: bool,
    pub policy: PolicyInputs,
}

/// `hostNameValid()`: RFC 1034 as RFC 1123 relaxed it; `wildcard` allows a
/// whole `*` as the first label.
pub fn host_name_valid(name: &str, wildcard: bool) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    let n = labels.len();
    labels.iter().enumerate().all(|(at, label)| {
        if wildcard && at == 0 && *label == "*" && n > 1 {
            return true;
        }
        let b = label.as_bytes();
        !b.is_empty()
            && b.len() <= 63
            && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
            && b[0] != b'-'
            && b[b.len() - 1] != b'-'
    })
}

fn text(v: &NameValue) -> Option<&str> {
    match v {
        NameValue::Text(t) => t.as_deref(),
        _ => None,
    }
}

/// JavaScript's `String(x)` of a name value, for a sentence.
fn shown(v: &NameValue) -> String {
    match v {
        NameValue::Text(Some(t)) => t.clone(),
        NameValue::Text(None) | NameValue::None => "null".to_string(),
        NameValue::Bytes(b) => {
            b.iter().map(u8::to_string).collect::<Vec<_>>().join(",")
        }
        NameValue::Rdns(r) => r.join(","),
    }
}

/// `uriHostOf()`: the host a URI names (WHATWG URL), or empty.
fn uri_host_of(uri: &str) -> String {
    let host = url::Url::parse(uri)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_lowercase()))
        .unwrap_or_default();
    if host_name_valid(&host, false) {
        host
    } else {
        String::new()
    }
}

fn name_within_subtree(name: &GeneralName, subtree: &Subtree) -> bool {
    match (name.form, &name.value, &subtree.value) {
        (Form::Dns, n, c) => {
            let n = shown(n).to_lowercase();
            let n = n.strip_prefix("*.").unwrap_or(&n).to_string();
            let base = shown(c).to_lowercase();
            base.is_empty() || n == base || n.ends_with(&format!(".{}", base))
        }
        (Form::Email, NameValue::Text(Some(n)), NameValue::Text(Some(c))) => {
            let at = n.rfind('@').map_or(0, |a| a);
            let host = n.get(at + 1..).unwrap_or_default().to_lowercase();
            if let Some(cat) = c.rfind('@') {
                n.get(..at) == c.get(..cat)
                    && host == c[cat + 1..].to_lowercase()
            } else if c.starts_with('.') {
                host.ends_with(&c.to_lowercase())
            } else {
                host == c.to_lowercase()
            }
        }
        (Form::Uri, NameValue::Text(Some(n)), c) => {
            let host = uri_host_of(n);
            let base = shown(c).to_lowercase();
            !host.is_empty()
                && if base.starts_with('.') {
                    host.ends_with(&base)
                } else {
                    host == base
                }
        }
        (Form::Ip, NameValue::Bytes(n), NameValue::Bytes(c)) => {
            let half = c.len() / 2;
            n.len() == half
                && (0..half).all(|i| n[i] & c[half + i] == c[i] & c[half + i])
        }
        (Form::Dn, NameValue::Rdns(n), NameValue::Rdns(c)) => {
            c.len() <= n.len()
                && c.iter().enumerate().all(|(at, rdn)| &n[at] == rdn)
        }
        _ => false,
    }
}

fn constrained_name_problem(name: &GeneralName) -> String {
    match name.form {
        Form::Dns => match text(&name.value) {
            Some(v) if host_name_valid(v, true) => String::new(),
            _ => format!(
                "the dNSName \"{}\" is not a host name",
                shown(&name.value)
            ),
        },
        Form::Email => {
            let ok = text(&name.value).is_some_and(|v| match v.rfind('@') {
                Some(at) if at > 0 => {
                    v.find('@') == Some(at)
                        && host_name_valid(&v[at + 1..], false)
                }
                _ => false,
            });
            if ok {
                String::new()
            } else {
                format!(
                    "the rfc822Name \"{}\" is not a mailbox",
                    shown(&name.value)
                )
            }
        }
        Form::Uri => match text(&name.value) {
            Some(v) if !uri_host_of(v).is_empty() => String::new(),
            _ => format!(
                "the URI \"{}\" names no host a constraint can be applied to",
                shown(&name.value)
            ),
        },
        Form::Ip => match &name.value {
            NameValue::Bytes(b) if b.len() == 4 || b.len() == 16 => {
                String::new()
            }
            _ => "an iPAddress is neither four nor sixteen bytes".to_string(),
        },
        _ => String::new(),
    }
}

fn wildcard_reaches(name: &GeneralName, subtree: &Subtree) -> bool {
    let n = text(&name.value).unwrap_or_default().to_lowercase();
    let base = text(&subtree.value).unwrap_or_default().to_lowercase();
    n.starts_with("*.") && base.ends_with(&format!(".{}", &n[2..]))
}

fn describe_path_name(name: &GeneralName) -> String {
    let t = match (&name.form, &name.value) {
        (Form::Ip, NameValue::Bytes(b)) if b.len() == 4 => {
            b.iter().map(u8::to_string).collect::<Vec<_>>().join(".")
        }
        (Form::Ip, NameValue::Bytes(b)) => crate::der::hex(b),
        (Form::Dn, NameValue::Rdns(r)) => r.join(", "),
        (_, v) => shown(v),
    };
    format!("\"{}\"", t)
}

/// `constraintProblem()`: the first name of `below` the constraints of `ca`
/// refuse, as a sentence, or empty.
fn constraint_problem(
    ca: &Entry,
    below: &Entry,
    is_leaf: bool,
    checks: &mut usize,
) -> String {
    let Some(nc) = ca.facts().name_constraints.as_ref() else {
        return String::new();
    };
    let facts = below.facts();
    let mut names = facts.names.clone();
    if is_leaf && !facts.has_san {
        names.extend(
            facts
                .common_names
                .iter()
                .filter(|cn| host_name_valid(cn, true))
                .map(|cn| GeneralName {
                    form: Form::Dns,
                    value: NameValue::Text(Some(cn.clone())),
                }),
        );
    }
    let permitted_all = nc.permitted.as_deref().unwrap_or_default();
    let excluded_all = nc.excluded.as_deref().unwrap_or_default();
    *checks += names.len() * (permitted_all.len() + excluded_all.len());
    if *checks > PATH_MAX_NAME_CHECKS {
        return format!(
            "it and the CAs above it carry more names and name constraints between them than this service will compare ({} comparisons)",
            PATH_MAX_NAME_CHECKS
        );
    }
    for name in &names {
        let permitted: Vec<&Subtree> = permitted_all
            .iter()
            .filter(|s| s.form == name.form)
            .collect();
        let excluded: Vec<&Subtree> = excluded_all
            .iter()
            .filter(|s| s.form == name.form)
            .collect();
        if permitted.is_empty() && excluded.is_empty() {
            continue;
        }
        if permitted
            .iter()
            .chain(excluded.iter())
            .any(|s| s.bounded || !s.form.evaluated())
        {
            return format!(
                "it carries a {} name and a CA above it constrains that form in a way this service does not evaluate (RFC 5280 section 4.2.1.10 then requires the certificate be refused)",
                name.form.word()
            );
        }
        let malformed = constrained_name_problem(name);
        if !malformed.is_empty() {
            return format!(
                "{}, and a CA above it constrains that form",
                malformed
            );
        }
        if !permitted.is_empty()
            && !permitted.iter().any(|s| name_within_subtree(name, s))
        {
            return format!(
                "its {} name {} is outside every permitted subtree of that form",
                name.form.word(),
                describe_path_name(name)
            );
        }
        if excluded.iter().any(|s| {
            name_within_subtree(name, s)
                || (name.form == Form::Dns && wildcard_reaches(name, s))
        }) {
            return format!(
                "its {} name {} is inside an excluded subtree",
                name.form.word(),
                describe_path_name(name)
            );
        }
    }
    String::new()
}

/// The outcome of section 6.1's policy processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyOutcome {
    pub ok: bool,
    pub why: String,
    pub user_constrained_policy_set: Vec<String>,
    pub explicit_policy: bool,
}

/// One node of the valid_policy_tree, in an arena.
struct Node {
    policy: String,
    expected: Vec<String>,
    parent: Option<usize>,
    children: Vec<usize>,
    depth: usize,
    alive: bool,
}

struct Tree {
    nodes: Vec<Node>,
    root: Option<usize>,
}

impl Tree {
    fn add(
        &mut self,
        policy: &str,
        expected: Vec<String>,
        parent: Option<usize>,
    ) -> usize {
        let depth = parent.map_or(0, |p| self.nodes[p].depth + 1);
        let id = self.nodes.len();
        self.nodes.push(Node {
            policy: policy.to_string(),
            expected,
            parent,
            children: Vec::new(),
            depth,
            alive: true,
        });
        if let Some(p) = parent {
            self.nodes[p].children.push(id);
        }
        id
    }

    fn at_depth(&self, depth: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let Some(root) = self.root else {
            return out;
        };
        let mut stack = vec![root];
        // Depth-first, children in order, as the recursive walk visits them.
        let mut order = Vec::new();
        while let Some(n) = stack.pop() {
            order.push(n);
            for &c in self.nodes[n].children.iter().rev() {
                stack.push(c);
            }
        }
        for n in order {
            if self.nodes[n].depth == depth {
                out.push(n);
            }
        }
        out
    }

    fn remove(&mut self, id: usize) {
        self.nodes[id].alive = false;
        match self.nodes[id].parent {
            None => self.root = None,
            Some(p) => self.nodes[p].children.retain(|&c| c != id),
        }
    }

    fn prune(&mut self, depth: usize) {
        for d in (0..depth).rev() {
            if self.root.is_none() {
                break;
            }
            for n in self.at_depth(d) {
                if self.nodes[n].children.is_empty() {
                    self.remove(n);
                }
            }
        }
    }
}

/// `pathPolicyOutcome()`: section 6.1's certificate policy processing over
/// a path (leaf first, the anchor not processed).
pub fn path_policy_outcome(
    path: &[&Entry],
    inputs: &PolicyInputs,
) -> PolicyOutcome {
    let n = path.len() as i64 - 1;
    let initial: Vec<String> = if inputs.initial_policy_set.is_empty() {
        vec![ANY_POLICY.to_string()]
    } else {
        inputs.initial_policy_set.clone()
    };
    if n < 1 {
        return PolicyOutcome {
            ok: true,
            why: String::new(),
            user_constrained_policy_set: initial,
            explicit_policy: false,
        };
    }
    let n = n as usize;
    let refuse = |why: String| PolicyOutcome {
        ok: false,
        why,
        user_constrained_policy_set: Vec::new(),
        explicit_policy: true,
    };
    let mut explicit_policy: i64 = if inputs.initial_explicit_policy {
        0
    } else {
        n as i64 + 1
    };
    let mut inhibit_any: i64 = if inputs.initial_inhibit_any_policy {
        0
    } else {
        n as i64 + 1
    };
    let mut policy_mapping: i64 = if inputs.initial_policy_mapping_inhibit {
        0
    } else {
        n as i64 + 1
    };
    let mut tree = Tree {
        nodes: Vec::new(),
        root: None,
    };
    let root = tree.add(ANY_POLICY, vec![ANY_POLICY.to_string()], None);
    tree.root = Some(root);
    let mut count = 2usize;
    for i in 1..=n {
        let cert = path[n - i];
        let facts = cert.facts();
        match (&facts.policies, tree.root.is_some()) {
            (Some(policies), true) => {
                let parents = tree.at_depth(i - 1);
                for policy in policies {
                    if policy == ANY_POLICY {
                        continue;
                    }
                    let mut matched = false;
                    for &p in &parents {
                        if tree.nodes[p].expected.contains(policy) {
                            tree.add(policy, vec![policy.clone()], Some(p));
                            count += 1;
                            matched = true;
                        }
                    }
                    if !matched {
                        for &p in &parents {
                            if tree.nodes[p].policy == ANY_POLICY {
                                tree.add(policy, vec![policy.clone()], Some(p));
                                count += 1;
                            }
                        }
                    }
                }
                if policies.iter().any(|p| p == ANY_POLICY)
                    && (inhibit_any > 0 || (i < n && facts.self_issued))
                {
                    for &p in &parents {
                        let expected = tree.nodes[p].expected.clone();
                        for policy in expected {
                            let has = tree.nodes[p]
                                .children
                                .iter()
                                .any(|&c| tree.nodes[c].policy == policy);
                            if !has {
                                tree.add(
                                    &policy,
                                    vec![policy.clone()],
                                    Some(p),
                                );
                                count += 1;
                            }
                        }
                    }
                }
                tree.prune(i);
                if count > PATH_MAX_POLICY_NODES {
                    return refuse(format!(
                        "the certificate policies and mappings along the path make more than {} policy tree nodes",
                        PATH_MAX_POLICY_NODES
                    ));
                }
            }
            _ => tree.root = None,
        }
        if explicit_policy <= 0 && tree.root.is_none() {
            return refuse(format!(
                "\"{}\" leaves no acceptable certificate policy and the path requires an explicit one (RFC 5280 section 6.1.3(f))",
                cert.subject_text()
            ));
        }
        if i == n {
            break;
        }
        let mappings = facts.policy_mappings.clone().unwrap_or_default();
        if mappings
            .iter()
            .any(|m| m.issuer == ANY_POLICY || m.subject == ANY_POLICY)
        {
            return refuse(format!(
                "\"{}\" maps anyPolicy, which RFC 5280 section 6.1.4(a) refuses",
                cert.subject_text()
            ));
        }
        if !mappings.is_empty() && tree.root.is_some() {
            let mut issuers: Vec<String> = Vec::new();
            for m in &mappings {
                if !issuers.contains(&m.issuer) {
                    issuers.push(m.issuer.clone());
                }
            }
            for issuer_policy in issuers {
                let mut mapped: Vec<String> = Vec::new();
                for m in mappings.iter().filter(|m| m.issuer == issuer_policy) {
                    if !mapped.contains(&m.subject) {
                        mapped.push(m.subject.clone());
                    }
                }
                let level = tree.at_depth(i);
                let holders: Vec<usize> = level
                    .iter()
                    .copied()
                    .filter(|&x| tree.nodes[x].policy == issuer_policy)
                    .collect();
                if policy_mapping > 0 {
                    if !holders.is_empty() {
                        for h in holders {
                            tree.nodes[h].expected = mapped.clone();
                        }
                    } else if let Some(any) = level
                        .iter()
                        .copied()
                        .find(|&x| tree.nodes[x].policy == ANY_POLICY)
                    {
                        if let Some(parent) = tree.nodes[any].parent {
                            tree.add(
                                &issuer_policy,
                                mapped.clone(),
                                Some(parent),
                            );
                            count += 1;
                        }
                    }
                } else {
                    for h in holders {
                        tree.remove(h);
                    }
                    tree.prune(i);
                }
            }
        }
        if !facts.self_issued {
            explicit_policy = (explicit_policy - 1).max(0);
            policy_mapping = (policy_mapping - 1).max(0);
            inhibit_any = (inhibit_any - 1).max(0);
        }
        if let Some(r) = facts.require_explicit_policy {
            explicit_policy = explicit_policy.min(r);
        }
        if let Some(r) = facts.inhibit_policy_mapping {
            policy_mapping = policy_mapping.min(r);
        }
        if let Some(r) = facts.inhibit_any_policy {
            inhibit_any = inhibit_any.min(r);
        }
    }
    let leaf_facts = path[0].facts();
    if explicit_policy > 0 {
        explicit_policy -= 1;
    }
    if leaf_facts.require_explicit_policy == Some(0) {
        explicit_policy = 0;
    }
    if let (Some(root), false) =
        (tree.root, initial.iter().any(|p| p == ANY_POLICY))
    {
        let mut boundary = Vec::new();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            for &child in &tree.nodes[node].children.clone() {
                if tree.nodes[node].policy == ANY_POLICY {
                    boundary.push(child);
                }
                if tree.nodes[child].policy == ANY_POLICY {
                    stack.push(child);
                }
            }
        }
        for &b in &boundary {
            if tree.nodes[b].policy != ANY_POLICY
                && !initial.contains(&tree.nodes[b].policy)
            {
                tree.remove(b);
            }
        }
        if let Some(leaf_any) = tree
            .at_depth(n)
            .into_iter()
            .find(|&x| tree.nodes[x].policy == ANY_POLICY)
        {
            let present: Vec<String> = boundary
                .iter()
                .map(|&b| tree.nodes[b].policy.clone())
                .collect();
            let parent = tree.nodes[leaf_any].parent;
            for policy in &initial {
                if !present.contains(policy) {
                    tree.add(policy, vec![policy.clone()], parent);
                }
            }
            tree.remove(leaf_any);
        }
        tree.prune(n);
    }
    if explicit_policy <= 0 && tree.root.is_none() {
        return refuse(
            "no certificate policy acceptable to the path and to this service remains, and the path requires an explicit one (RFC 5280 section 6.1.5(g))"
                .to_string(),
        );
    }
    let mut user: Vec<String> = Vec::new();
    fn gather(tree: &Tree, node: usize, n: usize, user: &mut Vec<String>) {
        for &child in &tree.nodes[node].children {
            let c = &tree.nodes[child];
            if tree.nodes[node].policy == ANY_POLICY
                && (c.policy != ANY_POLICY || c.depth == n)
                && !user.contains(&c.policy)
            {
                user.push(c.policy.clone());
            }
            if c.policy == ANY_POLICY {
                gather(tree, child, n, user);
            }
        }
    }
    if let Some(root) = tree.root {
        gather(&tree, root, n, &mut user);
    }
    PolicyOutcome {
        ok: true,
        why: String::new(),
        user_constrained_policy_set: user,
        explicit_policy: explicit_policy <= 0,
    }
}

/// `pathRuleProblem()`: the first certificate from the leaf that breaks a
/// rule, or `None`.
pub fn path_rule_problem(
    path: &[&Entry],
    options: &RuleOptions,
) -> Option<Problem> {
    let allowed: Vec<String> = options
        .allow_critical
        .iter()
        .map(|name| {
            PATH_EXTENSION_OIDS
                .iter()
                .find(|(n, _)| n == name)
                .map_or(name.clone(), |(_, o)| o.to_string())
        })
        .collect();
    let understood: Vec<&str> =
        PATH_EXTENSION_OIDS.iter().map(|(_, o)| *o).collect();
    let refuse = |check: &'static str, index: usize, why: String| {
        Some(Problem {
            check,
            index,
            why: format!("\"{}\" {}", path[index].subject_text(), why),
        })
    };
    for (i, entry) in path.iter().enumerate() {
        let facts = entry.facts();
        if !facts.problem.is_empty() {
            return refuse("unusable", i, facts.problem.clone());
        }
        let unknown: Vec<&String> = facts
            .critical
            .iter()
            .filter(|oid| {
                !understood.contains(&oid.as_str()) && !allowed.contains(oid)
            })
            .collect();
        if !unknown.is_empty() {
            return refuse(
                "critical",
                i,
                format!(
                    "carries a critical extension this service does not implement ({}), which RFC 5280 section 4.2 says must be refused",
                    unknown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                ),
            );
        }
        if i < path.len() - 1
            && !facts.weak_signature.is_empty()
            && (facts.weak_signature == "md" || !options.allow_sha1)
        {
            return refuse(
                "weak-signature",
                i,
                format!(
                    "is signed with {}, a hash whose collisions are practical, so the signature does not bind what it signs",
                    if facts.weak_signature == "md" { "MD2 or MD5" } else { "SHA-1" }
                ),
            );
        }
        if facts.subject_rdns.is_empty()
            && (!facts.has_san || !facts.san_critical)
        {
            return refuse(
                "malformed",
                i,
                "has an empty subject and no critical subjectAltName (RFC 5280 section 4.2.1.6)".to_string(),
            );
        }
        if let (true, Some(ku)) = (
            ML_DSA_OIDS.contains(&facts.spki_oid.as_str()),
            &facts.key_usage,
        ) {
            if ku.iter().any(|u| !ML_DSA_USAGES.contains(u)) {
                return refuse(
                    "malformed",
                    i,
                    format!(
                        "holds an ML-DSA key and a keyUsage naming {} — RFC 9881 section 5 permits only digitalSignature, nonRepudiation, keyCertSign and cRLSign",
                        ku.join(", ")
                    ),
                );
            }
        }
        if i == 0
            && !facts.ca
            && facts
                .key_usage
                .as_ref()
                .is_some_and(|k| k.contains(&"keyCertSign"))
        {
            return refuse("malformed", i, "asserts keyCertSign and is not a CA (RFC 5280 section 4.2.1.9)".to_string());
        }
        if !facts.ca && facts.name_constraints.is_some() {
            return refuse("malformed", i, "carries nameConstraints and is not a CA (RFC 5280 section 4.2.1.10)".to_string());
        }
        if i == 0 {
            continue;
        }
        if !facts.ca {
            return refuse(
                "not-ca",
                i,
                "signs the certificate below it and is not a certificate authority (basicConstraints cA is not set)".to_string(),
            );
        }
        if facts
            .key_usage
            .as_ref()
            .is_some_and(|k| !k.contains(&"keyCertSign"))
        {
            return refuse(
                "key-cert-sign",
                i,
                "carries a keyUsage that does not permit keyCertSign"
                    .to_string(),
            );
        }
        if facts.subject_rdns.is_empty() {
            return refuse(
                "malformed",
                i,
                "is a CA with an empty subject (RFC 5280 section 4.1.2.6)"
                    .to_string(),
            );
        }
        let below =
            (1..i).filter(|&k| !path[k].facts().self_issued).count() as i64;
        if let Some(path_len) = facts.path_len {
            if below > path_len {
                return refuse(
                    "path-len",
                    i,
                    format!(
                        "allows {} CA certificate(s) below it (pathLenConstraint) and the path has {}",
                        path_len, below
                    ),
                );
            }
        }
    }
    let mut checks = 0usize;
    for i in (1..path.len()).rev() {
        if path[i].facts().name_constraints.is_none() {
            continue;
        }
        for j in (0..i).rev() {
            if j > 0 && path[j].facts().self_issued {
                continue;
            }
            // Node's `constraintBaseProblem()` (a malformed constraint base)
            // is defined and never called, so a base is not checked here
            // either; the parity test would show it.
            let problem =
                constraint_problem(path[i], path[j], j == 0, &mut checks);
            if !problem.is_empty() {
                return refuse(
                    "name-constraints",
                    j,
                    format!(
                        "{} (nameConstraints of \"{}\", RFC 5280 section 4.2.1.10)",
                        problem,
                        path[i].subject_text()
                    ),
                );
            }
        }
    }
    let policy = path_policy_outcome(path, &options.policy);
    if !policy.ok {
        return Some(Problem {
            check: "policy",
            index: 0,
            why: policy.why,
        });
    }
    None
}

/// `pathValidityProblem()`: every certificate inside its window at `now`
/// (whole seconds), widened by `skew_ms`.
pub fn path_validity_problem(
    path: &[&Entry],
    now_ms: i64,
    skew_ms: i64,
) -> Option<Problem> {
    let at = now_ms.div_euclid(1000) * 1000;
    for (i, entry) in path.iter().enumerate() {
        let f = entry.facts();
        if !f.problem.is_empty() {
            continue;
        }
        if f.not_before_ms - skew_ms > at || f.not_after_ms + skew_ms < at {
            let iso = |ms: i64| {
                Utc.timestamp_millis_opt(ms)
                    .single()
                    .map(|t| crate::x509::time::iso(&t))
                    .unwrap_or_default()
            };
            return Some(Problem {
                check: "validity",
                index: i,
                why: format!(
                    "\"{}\" is outside its validity window ({} to {})",
                    entry.subject_text(),
                    iso(f.not_before_ms),
                    iso(f.not_after_ms)
                ),
            });
        }
    }
    None
}
