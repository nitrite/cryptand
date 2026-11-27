//! A maintained full-text index — `07-fulltext.md`. Three levelled trees
//! (`term_dict`, `term_index`, `postings`); the byte layer is
//! [`crate::fulltext`], the analyzer [`crate::analyzer`]. Ported from Java's
//! `FullTextIndex`, so the two write the same trees for the same documents.

use std::collections::{BTreeMap, BTreeSet};

use crate::analyzer::Analyzer;
use crate::catalog::TreeDescriptor;
use crate::engine::Engine;
use crate::error::{corrupt, Result};
use crate::fulltext::{phrase_matches, postings_key, require_positions, Posting, PostingsBlock, TermEntry, BLOCK_MAX};
use crate::value::{NumType, Value};
use crate::{cke, cve};

pub struct TextIndex {
    pub name: String,
    pub owner: String,
    fields: Vec<String>,
    analyzer: Analyzer,
    positions: bool,
    term_dict: u32,
    term_index: u32,
    postings: u32,
    next_term_id: u32,
}

fn u32v(x: u32) -> Value {
    Value::int(NumType::U32, x as i128)
}

fn pkey(term: u32, first: i64) -> Value {
    Value::Array(vec![u32v(term), Value::NitriteId(first)])
}

impl TextIndex {
    pub fn open(e: &mut Engine, name: &str, d: &TreeDescriptor) -> Result<TextIndex> {
        let fields: Vec<String> = match d.param("fields") {
            Some(Value::Array(a)) => a.iter().filter_map(|v| if let Value::Str(s) = v { Some(s.clone()) } else { None }).collect(),
            _ => return corrupt(format!("text index '{name}' has no params.fields")),
        };
        let (mut stopwords, mut stemmer) = (Vec::new(), "none".to_string());
        if let Some(ap) = d.param("analyzer_params") {
            if let Some(Value::Array(a)) = ap.field("stopwords") {
                stopwords = a.iter().filter_map(|v| if let Value::Str(s) = v { Some(s.clone()) } else { None }).collect();
            }
            if let Some(Value::Str(s)) = ap.field("stemmer") {
                stemmer = s.clone();
            }
        }
        let Some(an) = d.param_str("analyzer") else { return corrupt(format!("text index '{name}' has no params.analyzer")) };
        let analyzer = Analyzer::new(an, stopwords, &stemmer)?;
        let (Some(term_dict), Some(term_index)) = (d.param_u64("term_dict"), d.param_u64("term_index")) else {
            return corrupt(format!("text index '{name}' does not name its term trees"));
        };
        let mut ix = TextIndex {
            name: name.to_string(),
            owner: d.owner().unwrap_or("").to_string(),
            fields,
            analyzer,
            positions: matches!(d.param("positions"), Some(Value::Bool(true))),
            term_dict: term_dict as u32,
            term_index: term_index as u32,
            postings: d.tree_id(),
            next_term_id: 1,
        };
        for (_, t) in ix.terms(e)? {
            ix.next_term_id = ix.next_term_id.max(t.id + 1);
        }
        Ok(ix)
    }

    pub fn has_positions(&self) -> bool {
        self.positions
    }

    /// Every dictionary entry, in term order.
    pub fn terms(&self, e: &mut Engine) -> Result<Vec<(String, TermEntry)>> {
        let mut out = Vec::new();
        for (k, v) in e.scan_tree(self.term_dict, None, None, None, true)? {
            if let Value::Str(t) = cke::decode_all(&k)? {
                out.push((t, TermEntry::decode(&v)?));
            }
        }
        Ok(out)
    }

    pub fn term(&self, e: &mut Engine, text: &str) -> Result<Option<TermEntry>> {
        e.get(self.term_dict, &Value::Str(text.into()))?.map(|v| TermEntry::decode(&v)).transpose()
    }

    /// `term -> sorted positions`, over every indexed field (§2.2 step 1:
    /// non-string values are skipped).
    fn terms_of(&self, doc: &Value) -> BTreeMap<String, Vec<u32>> {
        let mut by: BTreeMap<String, Vec<u32>> = BTreeMap::new();
        for f in &self.fields {
            let path = crate::index::parse_field_path(f);
            for v in crate::index::resolve(doc, &path).unwrap_or_default() {
                if let Value::Str(s) = v {
                    for t in self.analyzer.analyze(&s) {
                        by.entry(t.text).or_default().push(t.position as u32);
                    }
                }
            }
        }
        for p in by.values_mut() {
            p.sort_unstable();
        }
        by
    }

    /// Indexes `doc`, replacing what `previous` contributed (F-190: only its
    /// own terms are visited).
    pub fn put(&mut self, e: &mut Engine, id: i64, doc: &Value, previous: Option<&Value>) -> Result<()> {
        self.remove(e, id, previous)?;
        for (text, pos) in self.terms_of(doc) {
            let t = self.intern(e, &text)?;
            let freq = pos.len() as u32;
            let positions = if self.positions { pos } else { Vec::new() };
            self.add_posting(e, t.id, Posting { doc: id, freq, positions })?;
            self.adjust(e, &text, TermEntry { id: t.id, df: t.df + 1, ttf: t.ttf + freq as u64 })?;
        }
        Ok(())
    }

    pub fn remove(&mut self, e: &mut Engine, id: i64, previous: Option<&Value>) -> Result<()> {
        let Some(prev) = previous else { return Ok(()) };
        for text in self.terms_of(prev).into_keys() {
            let Some(t) = self.term(e, &text)? else { continue };
            let freq = self.remove_posting(e, t.id, id)?;
            if freq > 0 {
                // §4.4: a term whose blocks are gone keeps its entry at df 0.
                let te = TermEntry { id: t.id, df: t.df.saturating_sub(1), ttf: t.ttf.saturating_sub(freq as u64) };
                self.adjust(e, &text, te)?;
            }
        }
        Ok(())
    }

    fn intern(&mut self, e: &mut Engine, text: &str) -> Result<TermEntry> {
        if let Some(t) = self.term(e, text)? {
            return Ok(t);
        }
        let t = TermEntry { id: self.next_term_id, df: 0, ttf: 0 };
        self.next_term_id += 1;
        e.put(self.term_dict, &Value::Str(text.into()), &t.encode())?;
        e.put(self.term_index, &u32v(t.id), &cve::encode(&Value::Str(text.into())))?;
        Ok(t)
    }

    fn adjust(&self, e: &mut Engine, text: &str, t: TermEntry) -> Result<()> {
        e.put(self.term_dict, &Value::Str(text.into()), &t.encode())?;
        Ok(())
    }

    /// `(first_doc, block)` of every block of `term`, in document order,
    /// with `first_doc < upper` when given.
    fn blocks(&self, e: &mut Engine, term: u32, upper: Option<i64>) -> Result<Vec<(i64, PostingsBlock)>> {
        let lo = postings_key(term, i64::MIN);
        let hi = match upper {
            Some(u) => postings_key(term, u),
            None if term == u32::MAX => return corrupt("term id u32::MAX"),
            None => postings_key(term + 1, i64::MIN),
        };
        let mut out = Vec::new();
        for (k, v) in e.scan_tree(self.postings, Some(&lo), Some(&hi), None, true)? {
            match cke::decode_all(&k)? {
                Value::Array(a) if a.len() == 2 => match (&a[0], &a[1]) {
                    (Value::Int { mag, .. }, Value::NitriteId(first)) if *mag == term as u128 => {
                        out.push((*first, PostingsBlock::decode_value(&v)?))
                    }
                    _ => {}
                },
                _ => return corrupt(format!("text index '{}': a postings key is not [term, first_doc]", self.name)),
            }
        }
        Ok(out)
    }

    pub fn postings(&self, e: &mut Engine, term: u32) -> Result<Vec<Posting>> {
        Ok(self.blocks(e, term, None)?.into_iter().flat_map(|(_, b)| b.postings).collect())
    }

    /// The block that holds or would hold `id`: the last starting at or
    /// before it, else the term's first. ponytail: scans the term's blocks
    /// up to `id` (no reverse cursor in the engine); a seek-last is the
    /// upgrade if high-df terms make writes slow.
    fn block_for(&self, e: &mut Engine, term: u32, id: i64) -> Result<Option<(i64, PostingsBlock)>> {
        let upper = id.checked_add(1);
        if let Some(b) = self.blocks(e, term, upper)?.pop() {
            return Ok(Some(b));
        }
        Ok(self.blocks(e, term, None)?.into_iter().next())
    }

    fn add_posting(&self, e: &mut Engine, term: u32, p: Posting) -> Result<()> {
        let found = self.block_for(e, term, p.doc)?;
        let old = found.as_ref().map(|(f, _)| *f);
        let mut list = found.map(|(_, b)| b.postings).unwrap_or_default();
        list.retain(|x| x.doc != p.doc);
        list.push(p);
        list.sort_by_key(|x| x.doc);
        self.rewrite(e, term, old, list)
    }

    fn remove_posting(&self, e: &mut Engine, term: u32, id: i64) -> Result<u32> {
        let Some((first, b)) = self.block_for(e, term, id)? else { return Ok(0) };
        let Some(freq) = b.postings.iter().find(|x| x.doc == id).map(|x| x.freq) else { return Ok(0) };
        let list = b.postings.into_iter().filter(|x| x.doc != id).collect();
        self.rewrite(e, term, Some(first), list)?;
        Ok(freq)
    }

    /// Replaces one block; past 128 it splits, an empty one is dropped (§4.4).
    fn rewrite(&self, e: &mut Engine, term: u32, old_first: Option<i64>, list: Vec<Posting>) -> Result<()> {
        if let Some(f) = old_first {
            e.remove(self.postings, &pkey(term, f))?;
        }
        for part in list.chunks(BLOCK_MAX) {
            let b = PostingsBlock { postings: part.to_vec(), has_positions: self.positions };
            e.put(self.postings, &pkey(term, part[0].doc), &b.encode_value()?)?;
        }
        Ok(())
    }

    /// Documents holding every term of the analyzed query, ascending.
    pub fn search(&self, e: &mut Engine, query: &str) -> Result<Vec<i64>> {
        let terms: Vec<String> = self.analyzer.analyze(query).into_iter().map(|t| t.text).collect();
        let mut result: Option<BTreeSet<i64>> = None;
        for text in &terms {
            let Some(t) = self.term(e, text)? else { return Ok(Vec::new()) };
            let ids: BTreeSet<i64> = self.postings(e, t.id)?.into_iter().map(|p| p.doc).collect();
            result = Some(match result {
                None => ids,
                Some(r) => r.intersection(&ids).copied().collect(),
            });
        }
        Ok(result.map(|r| r.into_iter().collect()).unwrap_or_default())
    }

    /// Documents holding the query's terms adjacently, in order. §4.3: refused
    /// on an index without positions, never approximated.
    pub fn phrase(&self, e: &mut Engine, query: &str) -> Result<Vec<i64>> {
        require_positions(self.positions)?;
        let terms: Vec<String> = self.analyzer.analyze(query).into_iter().map(|t| t.text).collect();
        let mut per_term: Vec<BTreeMap<i64, Vec<u32>>> = Vec::new();
        for text in &terms {
            let Some(t) = self.term(e, text)? else { return Ok(Vec::new()) };
            per_term.push(self.postings(e, t.id)?.into_iter().map(|p| (p.doc, p.positions)).collect());
        }
        let mut out = Vec::new();
        for id in self.search(e, query)? {
            let lists: Vec<Vec<u32>> = per_term.iter().map(|m| m.get(&id).cloned().unwrap_or_default()).collect();
            if phrase_matches(&lists) {
                out.push(id);
            }
        }
        Ok(out)
    }

    /// §6: rebuild df/ttf from the live documents and compare; the findings,
    /// empty when the index agrees.
    pub fn verify(&self, e: &mut Engine, docs: &[Value]) -> Result<Vec<String>> {
        let mut want: BTreeMap<String, (u32, u64)> = BTreeMap::new();
        for d in docs {
            for (t, pos) in self.terms_of(d) {
                let w = want.entry(t).or_default();
                w.0 += 1;
                w.1 += pos.len() as u64;
            }
        }
        let mut findings = Vec::new();
        let stored: BTreeMap<String, TermEntry> = self.terms(e)?.into_iter().collect();
        for (t, (df, ttf)) in &want {
            match stored.get(t) {
                None => findings.push(format!("term '{t}' is produced by a live document but absent")),
                Some(s) if s.df != *df || s.ttf != *ttf => {
                    findings.push(format!("term '{t}' declares df {} ttf {}, the documents give {df} {ttf}", s.df, s.ttf))
                }
                _ => {}
            }
        }
        for (t, s) in &stored {
            if s.df > 0 && !want.contains_key(t) {
                findings.push(format!("term '{t}' has postings but no live document produces it"));
            }
            for (first, b) in self.blocks(e, s.id, None)? {
                if let Err(x) = crate::fulltext::check_block(&b, first) {
                    findings.push(format!("term '{t}': {x}"));
                }
            }
            let docs: u32 = self.postings(e, s.id)?.len() as u32;
            if docs != s.df {
                findings.push(format!("term '{t}' declares df {}, its blocks hold {docs}", s.df));
            }
        }
        Ok(findings)
    }
}
