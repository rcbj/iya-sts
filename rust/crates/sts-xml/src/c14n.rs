// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Canonical XML 1.0, inclusive and exclusive, with and without comments —
//! a line-for-line port of the two canonicalizers in
//! `common/vendored/xmldsig.js` (`c14nSerialize()` and `c14nIncl()`), which
//! every signature the Node service makes and checks goes through.
//!
//! **A port and not a fresh implementation, on purpose**: a signature made
//! in one runtime is verified in the other while the two coexist in the
//! suite, so the bytes must be the SAME bytes, including where the Node code
//! departs from the letter of the specification. Each departure is kept and
//! named:
//!
//! * attributes are never filtered by the node-set — an element in it
//!   contributes all of its attributes (`xmldsig.js` says so);
//! * `xml:*` attributes are not inherited by the inclusive form;
//! * the inclusive form emits an element's own `xmlns=""` whenever the
//!   rendered default differs, as `c14nIncl()` does.
//!
//! Options: `comments` (the `#WithComments` twins), `prefixes` (exclusive
//! C14N's InclusiveNamespaces PrefixList, `#default` naming the default
//! namespace) and `include` (node-set membership: a node outside it
//! contributes no tags of its own and its children are still visited).

use std::cmp::Ordering;

use crate::dom::{Attribute, Document, NodeId, NodeKind};

/// What to canonicalize with.
#[derive(Default)]
pub struct Options<'a> {
    pub comments: bool,
    /// The PrefixList, for the exclusive form.
    pub prefixes: Option<Vec<String>>,
    pub include: Option<&'a dyn Fn(NodeId) -> bool>,
}

impl Options<'_> {
    fn included(&self, id: NodeId) -> bool {
        self.include.is_none_or(|include| include(id))
    }
}

/// JavaScript's `<` on strings: UTF-16 code unit order.
fn js_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn text_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\r', "&#xD;")
}

fn attr_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('"', "&quot;")
        .replace('\t', "&#x9;")
        .replace('\n', "&#xA;")
        .replace('\r', "&#xD;")
}

/// A rendered-namespace map: prefix to URI, as the Node code's plain object.
type Rendered = Vec<(String, String)>;

fn get<'a>(map: &'a Rendered, prefix: &str) -> Option<&'a str> {
    map.iter()
        .find(|(k, _)| k == prefix)
        .map(|(_, v)| v.as_str())
}

fn set(map: &mut Rendered, prefix: &str, uri: &str) {
    match map.iter_mut().find(|(k, _)| k == prefix) {
        Some(entry) => entry.1 = uri.to_string(),
        None => map.push((prefix.to_string(), uri.to_string())),
    }
}

/// The non-element children both forms share.
fn leaf(doc: &Document, child: NodeId, o: &Options) -> String {
    if !o.included(child) {
        return String::new();
    }
    match doc.kind(child) {
        NodeKind::Text(t) | NodeKind::CData(t) => text_escape(t),
        NodeKind::Comment(t) if o.comments => format!("<!--{}-->", t),
        NodeKind::Pi { target, data } => {
            if data.is_empty() {
                format!("<?{}?>", target)
            } else {
                format!("<?{} {}?>", target, data)
            }
        }
        _ => String::new(),
    }
}

fn sort_namespaces(ns: &mut [(String, String)]) {
    ns.sort_by(|a, b| {
        if a.0 == b.0 {
            Ordering::Equal
        } else if a.0.is_empty() {
            Ordering::Less
        } else if b.0.is_empty() {
            Ordering::Greater
        } else {
            js_cmp(&a.0, &b.0)
        }
    });
}

fn sort_attributes(attrs: &mut [&Attribute]) {
    attrs.sort_by(|a, b| {
        let (au, bu) =
            (a.ns.as_deref().unwrap_or(""), b.ns.as_deref().unwrap_or(""));
        if au != bu {
            return js_cmp(au, bu);
        }
        js_cmp(&a.local, &b.local)
    });
}

fn render_start(
    name: &str,
    ns_out: &[(String, String)],
    attrs: &[&Attribute],
) -> String {
    let mut out = format!("<{}", name);
    for (prefix, uri) in ns_out {
        if prefix.is_empty() {
            out.push_str(&format!(" xmlns=\"{}\"", attr_escape(uri)));
        } else {
            out.push_str(&format!(
                " xmlns:{}=\"{}\"",
                prefix,
                attr_escape(uri)
            ));
        }
    }
    for a in attrs {
        out.push_str(&format!(" {}=\"{}\"", a.name(), attr_escape(&a.value)));
    }
    out.push('>');
    out
}

/// Exclusive Canonical XML 1.0 of the subtree at `apex`.
pub fn exclusive(doc: &Document, apex: NodeId, o: &Options) -> String {
    exclusive_at(doc, apex, &Vec::new(), o)
}

fn exclusive_at(
    doc: &Document,
    id: NodeId,
    rendered: &Rendered,
    o: &Options,
) -> String {
    let Some(el) = doc.element(id) else {
        return leaf(doc, id, o);
    };
    let included = o.included(id);
    let mut child_rendered = rendered.clone();
    let mut out = String::new();
    if included {
        let in_scope = doc.in_scope(id);
        // The order Object.keys() gives the utilized map: insertion order.
        let mut utilized: Vec<String> =
            vec![el.prefix.clone().unwrap_or_default()];
        let note = |p: &str, list: &mut Vec<String>| {
            if !list.iter().any(|q| q == p) {
                list.push(p.to_string());
            }
        };
        if let Some(prefixes) = &o.prefixes {
            for p in prefixes {
                note(if p == "#default" { "" } else { p }, &mut utilized);
            }
        }
        let mut attrs: Vec<&Attribute> = Vec::new();
        for a in &el.attrs {
            if a.declared_prefix().is_some() {
                continue;
            }
            if let Some(p) = &a.prefix {
                note(p, &mut utilized);
            }
            attrs.push(a);
        }
        let mut ns_out: Vec<(String, String)> = Vec::new();
        for prefix in &utilized {
            let uri = match get(&in_scope, prefix) {
                Some(uri) => uri.to_string(),
                None if prefix.is_empty() => String::new(),
                None => continue,
            };
            if prefix.is_empty()
                && uri.is_empty()
                && get(rendered, "").is_none()
            {
                continue;
            }
            if get(&child_rendered, prefix) != Some(uri.as_str()) {
                ns_out.push((prefix.clone(), uri.clone()));
                set(&mut child_rendered, prefix, &uri);
            }
        }
        sort_namespaces(&mut ns_out);
        sort_attributes(&mut attrs);
        out = render_start(&el.name(), &ns_out, &attrs);
    }
    for &child in doc.children(id) {
        out.push_str(&exclusive_at(doc, child, &child_rendered, o));
    }
    if included {
        out.push_str(&format!("</{}>", el.name()));
    }
    out
}

/// Inclusive Canonical XML 1.0 of the subtree at `apex`.
pub fn inclusive(doc: &Document, apex: NodeId, o: &Options) -> String {
    inclusive_at(doc, apex, &Vec::new(), true, o)
}

fn inclusive_at(
    doc: &Document,
    id: NodeId,
    rendered: &Rendered,
    is_apex: bool,
    o: &Options,
) -> String {
    let Some(el) = doc.element(id) else {
        return leaf(doc, id, o);
    };
    let included = o.included(id);
    let mut child_rendered = rendered.clone();
    let mut out = String::new();
    if included {
        let source: Rendered = if is_apex {
            doc.in_scope(id)
        } else {
            let mut own = Vec::new();
            for a in &el.attrs {
                if let Some(p) = a.declared_prefix() {
                    set(&mut own, p, &a.value);
                }
            }
            own
        };
        let mut ns_out: Vec<(String, String)> = Vec::new();
        for (prefix, uri) in &source {
            if get(&child_rendered, prefix) != Some(uri.as_str()) {
                ns_out.push((prefix.clone(), uri.clone()));
                set(&mut child_rendered, prefix, uri);
            }
        }
        sort_namespaces(&mut ns_out);
        let mut attrs: Vec<&Attribute> = el
            .attrs
            .iter()
            .filter(|a| a.declared_prefix().is_none())
            .collect();
        sort_attributes(&mut attrs);
        out = render_start(&el.name(), &ns_out, &attrs);
    }
    for &child in doc.children(id) {
        out.push_str(&inclusive_at(doc, child, &child_rendered, false, o));
    }
    if included {
        out.push_str(&format!("</{}>", el.name()));
    }
    out
}

/// The canonicalization method URIs.
pub mod method {
    pub const C14N: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    pub const C14N_COMMENTS: &str =
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
    pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
    pub const EXC_C14N_COMMENTS: &str =
        "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
}

/// Canonicalizes by method URI (`canonicalizeBy()`); `None` for a method
/// this service does not implement.
pub fn by_method(
    doc: &Document,
    apex: NodeId,
    uri: &str,
    prefixes: Option<Vec<String>>,
    include: Option<&dyn Fn(NodeId) -> bool>,
) -> Option<String> {
    let (exclusive_form, comments) = match uri {
        method::C14N => (false, false),
        method::C14N_COMMENTS => (false, true),
        method::EXC_C14N => (true, false),
        method::EXC_C14N_COMMENTS => (true, true),
        _ => return None,
    };
    let o = Options {
        comments,
        prefixes: if exclusive_form { prefixes } else { None },
        include,
    };
    Some(if exclusive_form {
        exclusive(doc, apex, &o)
    } else {
        inclusive(doc, apex, &o)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exc(xml: &str) -> String {
        let doc = Document::parse(xml).unwrap();
        exclusive(&doc, doc.document_element().unwrap(), &Options::default())
    }

    #[test]
    fn exclusive_renders_only_what_is_used() {
        assert_eq!(
            exc(
                r#"<a:r xmlns:a="urn:a" xmlns:b="urn:b" z="1" a:y="&lt;2&gt;"><c>x&amp;y</c></a:r>"#
            ),
            r#"<a:r xmlns:a="urn:a" z="1" a:y="&lt;2>"><c>x&amp;y</c></a:r>"#
        );
    }

    #[test]
    fn inclusive_renders_every_declaration_once() {
        let doc = Document::parse(
            r#"<r xmlns="urn:d" xmlns:b="urn:b"><c xmlns:b="urn:b"><!--x--></c></r>"#,
        )
        .unwrap();
        let root = doc.document_element().unwrap();
        assert_eq!(
            inclusive(&doc, root, &Options::default()),
            r#"<r xmlns="urn:d" xmlns:b="urn:b"><c></c></r>"#
        );
        let with = Options {
            comments: true,
            ..Options::default()
        };
        assert_eq!(
            inclusive(&doc, root, &with),
            r#"<r xmlns="urn:d" xmlns:b="urn:b"><c><!--x--></c></r>"#
        );
    }
}
