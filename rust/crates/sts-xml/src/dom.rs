// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A namespace-aware, mutable XML DOM — what `@xmldom/xmldom` is to the Node
//! service (rust/DESIGN.md section 6, XML-DSig row).
//!
//! **Why a DOM of our own rather than a crate's.** Canonical XML has to print
//! each element with the exact prefix it was written with and every
//! namespace declaration where it was made; `roxmltree` resolves names and
//! drops the prefixes, and the mutable trees on crates.io either do the same
//! or bring an XPath engine this service does not use (the service refuses
//! the XPath transforms: `common/vendored/xmldsig.js`). So the parse is
//! `quick-xml`'s, and the tree is this arena: an element keeps its prefix,
//! its local name, its resolved namespace, and its attributes IN DOCUMENT
//! ORDER with the `xmlns` declarations among them, as the xmldom DOM the
//! Node canonicalizer walks does.
//!
//! **The parse is strict, and changes no byte it does not have to.** A
//! document that is not well-formed is refused by name; a DOCTYPE is
//! refused (no entity of any kind is ever defined, so none can be expanded
//! against this process); an undeclared prefix is refused. What XML 1.0
//! itself requires is done: line ends become `\n` (2.11), attribute values
//! are normalized (3.3.3), and the five predefined entities and character
//! references are resolved.

use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;
use quick_xml::XmlVersion;

/// The namespace of the `xml:` prefix.
pub const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
/// The namespace xmldom gives an `xmlns` / `xmlns:p` attribute.
pub const XMLNS_NS: &str = "http://www.w3.org/2000/xmlns/";

/// What went wrong reading a document.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct XmlError(pub String);

fn err(message: impl Into<String>) -> XmlError {
    XmlError(message.into())
}

pub type XmlResult<T> = Result<T, XmlError>;

/// A node's handle in its document's arena.
pub type NodeId = usize;

/// An attribute, namespace declarations included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub prefix: Option<String>,
    pub local: String,
    /// `None` for an unprefixed attribute; [`XMLNS_NS`] for a declaration.
    pub ns: Option<String>,
    pub value: String,
}

impl Attribute {
    /// The name as written: `p:local` or `local`.
    pub fn name(&self) -> String {
        match &self.prefix {
            Some(p) => format!("{}:{}", p, self.local),
            None => self.local.clone(),
        }
    }

    /// The prefix this attribute declares, if it is a declaration: `""` for
    /// `xmlns`, `"p"` for `xmlns:p`.
    pub fn declared_prefix(&self) -> Option<&str> {
        match (&self.prefix, self.local.as_str()) {
            (None, "xmlns") => Some(""),
            (Some(p), local) if p == "xmlns" => Some(local),
            _ => None,
        }
    }
}

/// An element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    pub prefix: Option<String>,
    pub local: String,
    pub ns: Option<String>,
    pub attrs: Vec<Attribute>,
}

impl Element {
    /// The name as written (xmldom's `nodeName`).
    pub fn name(&self) -> String {
        match &self.prefix {
            Some(p) => format!("{}:{}", p, self.local),
            None => self.local.clone(),
        }
    }

    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|a| a.name() == name)
            .map(|a| a.value.as_str())
    }
}

/// What a node is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeKind {
    Document,
    Element(Element),
    Text(String),
    CData(String),
    Comment(String),
    Pi { target: String, data: String },
}

#[derive(Debug, Clone)]
struct NodeData {
    kind: NodeKind,
    parent: Option<NodeId>,
    children: Vec<NodeId>,
}

/// A document: an arena of nodes, the document node first.
#[derive(Debug, Clone)]
pub struct Document {
    nodes: Vec<NodeData>,
}

impl Default for Document {
    fn default() -> Document {
        Document::new()
    }
}

impl Document {
    pub const ROOT: NodeId = 0;

    /// An empty document.
    pub fn new() -> Document {
        Document {
            nodes: vec![NodeData {
                kind: NodeKind::Document,
                parent: None,
                children: Vec::new(),
            }],
        }
    }

    /// Parses a whole document, refusing anything not well-formed.
    pub fn parse(xml: &str) -> XmlResult<Document> {
        let mut doc = Document::new();
        let children = doc.parse_into(xml, &[])?;
        for child in children {
            doc.append(Document::ROOT, child);
        }
        if doc.document_element().is_none() {
            return Err(err("the document has no root element"));
        }
        Ok(doc)
    }

    /// The root element.
    pub fn document_element(&self) -> Option<NodeId> {
        self.children(Document::ROOT)
            .iter()
            .copied()
            .find(|&id| self.element(id).is_some())
    }

    pub fn kind(&self, id: NodeId) -> &NodeKind {
        &self.nodes[id].kind
    }

    pub fn element(&self, id: NodeId) -> Option<&Element> {
        match &self.nodes.get(id)?.kind {
            NodeKind::Element(e) => Some(e),
            _ => None,
        }
    }

    pub fn element_mut(&mut self, id: NodeId) -> Option<&mut Element> {
        match &mut self.nodes.get_mut(id)?.kind {
            NodeKind::Element(e) => Some(e),
            _ => None,
        }
    }

    pub fn parent(&self, id: NodeId) -> Option<NodeId> {
        self.nodes.get(id)?.parent
    }

    pub fn children(&self, id: NodeId) -> &[NodeId] {
        self.nodes
            .get(id)
            .map(|n| n.children.as_slice())
            .unwrap_or(&[])
    }

    /// The element children of a node.
    pub fn child_elements(&self, id: NodeId) -> Vec<NodeId> {
        self.children(id)
            .iter()
            .copied()
            .filter(|&c| self.element(c).is_some())
            .collect()
    }

    /// The first element child with this local name (any namespace).
    pub fn child_by_local(&self, id: NodeId, local: &str) -> Option<NodeId> {
        self.children(id)
            .iter()
            .copied()
            .find(|&c| self.element(c).is_some_and(|e| e.local == local))
    }

    /// Every element of a subtree, in document order, the node first.
    pub fn descendants(&self, id: NodeId) -> Vec<NodeId> {
        let mut out = Vec::new();
        let mut stack = vec![id];
        while let Some(n) = stack.pop() {
            if self.element(n).is_some() {
                out.push(n);
            }
            for &c in self.children(n).iter().rev() {
                stack.push(c);
            }
        }
        out
    }

    /// The concatenated text of a node's subtree.
    pub fn text(&self, id: NodeId) -> String {
        let mut out = String::new();
        self.collect_text(id, &mut out);
        out
    }

    fn collect_text(&self, id: NodeId, out: &mut String) {
        match self.kind(id) {
            NodeKind::Text(t) | NodeKind::CData(t) => out.push_str(t),
            _ => {
                for &c in self.children(id) {
                    self.collect_text(c, out);
                }
            }
        }
    }

    /// Whether `id` is `ancestor` or below it.
    pub fn is_within(&self, id: NodeId, ancestor: NodeId) -> bool {
        let mut n = Some(id);
        while let Some(current) = n {
            if current == ancestor {
                return true;
            }
            n = self.parent(current);
        }
        false
    }

    // --- mutation -------------------------------------------------------

    fn alloc(&mut self, kind: NodeKind) -> NodeId {
        self.nodes.push(NodeData {
            kind,
            parent: None,
            children: Vec::new(),
        });
        self.nodes.len() - 1
    }

    pub fn create_text(&mut self, text: &str) -> NodeId {
        self.alloc(NodeKind::Text(text.to_string()))
    }

    fn detach(&mut self, child: NodeId) {
        if let Some(parent) = self.nodes[child].parent.take() {
            self.nodes[parent].children.retain(|&c| c != child);
        }
    }

    /// Appends `child` (moved from wherever it was) to `parent`.
    pub fn append(&mut self, parent: NodeId, child: NodeId) {
        self.detach(child);
        self.nodes[child].parent = Some(parent);
        self.nodes[parent].children.push(child);
    }

    /// Inserts `child` before `before` (a child of `parent`), or appends it.
    pub fn insert_before(
        &mut self,
        parent: NodeId,
        child: NodeId,
        before: Option<NodeId>,
    ) {
        self.detach(child);
        self.nodes[child].parent = Some(parent);
        let at = before
            .and_then(|b| {
                self.nodes[parent].children.iter().position(|&c| c == b)
            })
            .unwrap_or(self.nodes[parent].children.len());
        self.nodes[parent].children.insert(at, child);
    }

    /// Removes a node from its parent; it stays in the arena, unattached.
    pub fn remove(&mut self, child: NodeId) {
        self.detach(child);
    }

    /// Replaces `old` with `new` in `old`'s parent.
    pub fn replace(&mut self, old: NodeId, new: NodeId) {
        let Some(parent) = self.parent(old) else {
            return;
        };
        let next = self.nodes[parent]
            .children
            .iter()
            .position(|&c| c == old)
            .and_then(|i| self.nodes[parent].children.get(i + 1).copied());
        self.detach(old);
        self.insert_before(parent, new, next);
    }

    /// Sets (or adds) an unprefixed attribute.
    pub fn set_attr(&mut self, id: NodeId, name: &str, value: &str) {
        if let Some(e) = self.element_mut(id) {
            match e
                .attrs
                .iter_mut()
                .find(|a| a.prefix.is_none() && a.local == name)
            {
                Some(a) => a.value = value.to_string(),
                None => e.attrs.push(Attribute {
                    prefix: None,
                    local: name.to_string(),
                    ns: None,
                    value: value.to_string(),
                }),
            }
        }
    }

    /// The namespace bindings in scope at an element, from its `xmlns`
    /// attributes and its ancestors' (xmldom's view: declarations are
    /// attributes).
    pub fn in_scope(&self, id: NodeId) -> Vec<(String, String)> {
        let mut chain = Vec::new();
        let mut n = Some(id);
        while let Some(current) = n {
            if self.element(current).is_some() {
                chain.push(current);
            }
            n = self.parent(current);
        }
        let mut map: Vec<(String, String)> = Vec::new();
        for &e in chain.iter().rev() {
            for a in
                &self.element(e).map(|e| e.attrs.clone()).unwrap_or_default()
            {
                if let Some(p) = a.declared_prefix() {
                    map.retain(|(k, _)| k != p);
                    map.push((p.to_string(), a.value.clone()));
                }
            }
        }
        map
    }

    /// Parses `xml` as a fragment whose prefixes may also resolve through
    /// `context` (the bindings in scope where it will be placed), returning
    /// the top-level nodes, unattached. This is how a built `<ds:Signature>`
    /// is brought into a document (xmldom's `importNode`).
    pub fn parse_fragment(
        &mut self,
        xml: &str,
        context: &[(String, String)],
    ) -> XmlResult<Vec<NodeId>> {
        self.parse_into(xml, context)
    }

    fn parse_into(
        &mut self,
        xml: &str,
        context: &[(String, String)],
    ) -> XmlResult<Vec<NodeId>> {
        let mut reader = Reader::from_str(xml);
        let config = reader.config_mut();
        config.expand_empty_elements = true;
        config.check_end_names = true;
        config.trim_text_start = false;
        config.trim_text_end = false;
        let mut scopes: Vec<Vec<(String, String)>> = vec![context.to_vec()];
        let mut stack: Vec<NodeId> = Vec::new();
        let mut top: Vec<NodeId> = Vec::new();
        let mut pending_text = String::new();
        loop {
            let event = reader.read_event().map_err(|e| {
                err(format!(
                    "not well-formed XML at byte {}: {}",
                    reader.error_position(),
                    e
                ))
            })?;
            if !matches!(event, Event::Text(_) | Event::GeneralRef(_)) {
                self.flush_text(&mut pending_text, &stack, &mut top);
            }
            match event {
                Event::Start(start) => {
                    let id = self.start_element(&start, &mut scopes)?;
                    self.place(id, &stack, &mut top);
                    stack.push(id);
                }
                Event::End(_) => {
                    stack.pop();
                    scopes.pop();
                }
                Event::Empty(_) => {
                    return Err(err("an empty element was not expanded"));
                }
                Event::Text(text) => {
                    pending_text.push_str(&text.xml10_content());
                }
                Event::GeneralRef(reference) => {
                    let resolved =
                        match reference.resolve_char_ref().map_err(|e| {
                            err(format!("a bad character reference: {}", e))
                        })? {
                            Some(c) => c.to_string(),
                            None => match &*reference {
                                "amp" => "&".into(),
                                "lt" => "<".into(),
                                "gt" => ">".into(),
                                "quot" => "\"".into(),
                                "apos" => "'".into(),
                                other => {
                                    return Err(err(format!(
                                    "the entity &{}; is not defined (no DTD is \
                                     accepted, so only the five predefined \
                                     entities exist)",
                                    other
                                )))
                                }
                            },
                        };
                    pending_text.push_str(&resolved);
                }
                Event::CData(data) => {
                    let text = data.xml10_content().into_owned();
                    let id = self.alloc(NodeKind::CData(text));
                    self.place(id, &stack, &mut top);
                }
                Event::Comment(comment) => {
                    let text = comment.xml10_content().into_owned();
                    let id = self.alloc(NodeKind::Comment(text));
                    self.place(id, &stack, &mut top);
                }
                Event::PI(pi) => {
                    let id = self.alloc(NodeKind::Pi {
                        target: pi.target().to_string(),
                        data: pi.content().trim_start().to_string(),
                    });
                    self.place(id, &stack, &mut top);
                }
                Event::DocType(_) => return Err(err(
                    "a DOCTYPE is not accepted: no DTD is processed, so no \
                         entity can be defined or expanded",
                )),
                Event::Decl(decl) => {
                    // Kept, as xmldom keeps it: a processing instruction
                    // whose target is `xml`, written back verbatim.
                    let raw: &str = &decl;
                    let data = raw.strip_prefix("xml").unwrap_or(raw);
                    let id = self.alloc(NodeKind::Pi {
                        target: "xml".to_string(),
                        data: data.trim_start().to_string(),
                    });
                    self.place(id, &stack, &mut top);
                }
                Event::Eof => break,
            }
        }
        if !stack.is_empty() {
            return Err(err("not well-formed XML: an element is not closed"));
        }
        Ok(top)
    }

    fn flush_text(
        &mut self,
        text: &mut String,
        stack: &[NodeId],
        top: &mut Vec<NodeId>,
    ) {
        if text.is_empty() {
            return;
        }
        let content = std::mem::take(text);
        // Text outside the root is whitespace in a well-formed document, and
        // it is kept as the document's own child — xmldom keeps it, and the
        // serialized document is compared with xmldom's byte for byte. No
        // canonical form sees it: C14N here always starts at an element.
        // AFTER the root it is dropped, as xmldom drops it.
        if stack.is_empty() && top.iter().any(|&n| self.element(n).is_some()) {
            return;
        }
        let id = self.alloc(NodeKind::Text(content));
        self.place(id, stack, top);
    }

    fn place(&mut self, id: NodeId, stack: &[NodeId], top: &mut Vec<NodeId>) {
        match stack.last() {
            Some(&parent) => {
                self.nodes[id].parent = Some(parent);
                self.nodes[parent].children.push(id);
            }
            None => top.push(id),
        }
    }

    fn start_element(
        &mut self,
        start: &BytesStart,
        scopes: &mut Vec<Vec<(String, String)>>,
    ) -> XmlResult<NodeId> {
        let qname = start.name().into_inner().to_string();
        let mut raw_attrs = Vec::new();
        for attr in start.attributes() {
            let attr =
                attr.map_err(|e| err(format!("a malformed attribute: {}", e)))?;
            let name = attr.key.into_inner().to_string();
            let value = attr
                .normalized_value(XmlVersion::Explicit1_0)
                .map_err(|e| {
                    err(format!("a malformed attribute value: {}", e))
                })?
                .into_owned();
            if raw_attrs.iter().any(|(n, _): &(String, String)| n == &name) {
                return Err(err(format!("the attribute {} is repeated", name)));
            }
            raw_attrs.push((name, value));
        }
        let mut scope = scopes.last().cloned().unwrap_or_default();
        for (name, value) in &raw_attrs {
            let declared = if name == "xmlns" {
                Some("")
            } else {
                name.strip_prefix("xmlns:")
            };
            if let Some(p) = declared {
                scope.retain(|(k, _)| k != p);
                scope.push((p.to_string(), value.clone()));
            }
        }
        let resolve = |prefix: &str| -> XmlResult<Option<String>> {
            if prefix == "xml" {
                return Ok(Some(XML_NS.to_string()));
            }
            match scope.iter().rev().find(|(k, _)| k == prefix) {
                Some((_, uri)) if uri.is_empty() => Ok(None),
                Some((_, uri)) => Ok(Some(uri.clone())),
                None if prefix.is_empty() => Ok(None),
                None => {
                    Err(err(format!("the prefix {} is not declared", prefix)))
                }
            }
        };
        let (prefix, local) = split(&qname);
        let ns = resolve(prefix.unwrap_or(""))?;
        let mut attrs = Vec::new();
        for (name, value) in raw_attrs {
            let (aprefix, alocal) = split(&name);
            let ans = if name == "xmlns" || aprefix == Some("xmlns") {
                Some(XMLNS_NS.to_string())
            } else {
                match aprefix {
                    Some(p) => resolve(p)?,
                    None => None,
                }
            };
            attrs.push(Attribute {
                prefix: aprefix.map(str::to_string),
                local: alocal.to_string(),
                ns: ans,
                value,
            });
        }
        scopes.push(scope);
        Ok(self.alloc(NodeKind::Element(Element {
            prefix: prefix.map(str::to_string),
            local: local.to_string(),
            ns,
            attrs,
        })))
    }

    // --- serialization -------------------------------------------------

    /// The document as text, as `XMLSerializer` writes it.
    pub fn serialize(&self) -> String {
        self.serialize_node(Document::ROOT)
    }

    pub fn serialize_node(&self, id: NodeId) -> String {
        let mut out = String::new();
        self.write_node(id, &mut out);
        out
    }

    fn write_node(&self, id: NodeId, out: &mut String) {
        match self.kind(id) {
            NodeKind::Document => {
                for &c in self.children(id) {
                    self.write_node(c, out);
                }
            }
            NodeKind::Element(e) => {
                out.push_str(&format!("<{}", e.name()));
                for a in &e.attrs {
                    out.push_str(&format!(
                        " {}=\"{}\"",
                        a.name(),
                        escape_attr(&a.value)
                    ));
                }
                if self.children(id).is_empty() {
                    out.push_str("/>");
                    return;
                }
                out.push('>');
                for &c in self.children(id) {
                    self.write_node(c, out);
                }
                out.push_str(&format!("</{}>", e.name()));
            }
            NodeKind::Text(t) => out.push_str(&escape_text(t)),
            NodeKind::CData(t) => {
                out.push_str(&format!("<![CDATA[{}]]>", t));
            }
            NodeKind::Comment(t) => {
                out.push_str(&format!("<!--{}-->", t));
            }
            NodeKind::Pi { target, data } => {
                if data.is_empty() {
                    out.push_str(&format!("<?{}?>", target));
                } else {
                    out.push_str(&format!("<?{} {}?>", target, data));
                }
            }
        }
    }
}

fn split(qname: &str) -> (Option<&str>, &str) {
    match qname.split_once(':') {
        Some((p, l)) => (Some(p), l),
        None => (None, qname),
    }
}

/// Text as a serializer writes it.
pub fn escape_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// An attribute value as a serializer writes it.
pub fn escape_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\t', "&#x9;")
        .replace('\n', "&#xA;")
        .replace('\r', "&#xD;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_namespaces_and_order_survive() {
        let doc = Document::parse(
            r#"<a:r xmlns:a="urn:a" xmlns="urn:d" z="1" a:y="2"><c/></a:r>"#,
        )
        .unwrap();
        let root = doc.document_element().unwrap();
        let e = doc.element(root).unwrap();
        assert_eq!(e.name(), "a:r");
        assert_eq!(e.ns.as_deref(), Some("urn:a"));
        let names: Vec<String> = e.attrs.iter().map(Attribute::name).collect();
        assert_eq!(names, ["xmlns:a", "xmlns", "z", "a:y"]);
        let c = doc.child_elements(root)[0];
        assert_eq!(doc.element(c).unwrap().ns.as_deref(), Some("urn:d"));
    }

    #[test]
    fn the_refusals() {
        assert!(Document::parse("<a><b></a>").is_err());
        assert!(Document::parse("<!DOCTYPE a [<!ENTITY x 'y'>]><a>&x;</a>")
            .is_err());
        assert!(Document::parse("<p:a/>").is_err());
        assert!(Document::parse("<a>&nope;</a>").is_err());
        assert!(Document::parse("<a x='1' x='2'/>").is_err());
        assert!(Document::parse("").is_err());
    }

    #[test]
    fn line_ends_and_attribute_values_are_normalized() {
        let doc =
            Document::parse("<a b=\"x\ty\r\nz\">1\r\n2\r3&#xD;</a>").unwrap();
        let root = doc.document_element().unwrap();
        assert_eq!(doc.element(root).unwrap().attr("b"), Some("x y z"));
        assert_eq!(doc.text(root), "1\n2\n3\r");
    }
}
