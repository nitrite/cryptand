//! `06-indexes.md` — one layout for every index type:
//! `key = CKE(Array[v1..vk, NitriteId])`, value empty.

use crate::cke;
use crate::value::Value;
use crate::{corrupt, Result};

/// §4 — a writer MUST cap the cartesian product rather than write an unbounded
/// number of rows.
pub const CAP_PER_DOCUMENT: usize = 1024;

/// §5 — the only escaping in the format: `\.` is a literal dot, `\\` a literal
/// backslash, and a lone `.` separates components.
pub fn parse_field_path(path: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut chars = path.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(next) => cur.push(next),
                // A trailing backslash is not an escape of anything; keep it.
                None => cur.push('\\'),
            },
            '.' => {
                parts.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    parts.push(cur);
    parts
}

/// Resolves a path, flattening every array it traverses (§5).
/// `None` means the path is unresolvable — §3's "field absent".
pub fn resolve(doc: &Value, path: &[String]) -> Option<Vec<Value>> {
    let Some((head, rest)) = path.split_first() else {
        return Some(vec![doc.clone()]);
    };
    match doc {
        Value::Array(items) => {
            // Traversing an array applies the remainder of the path to every
            // element and flattens the results.
            let mut out = Vec::new();
            let mut any = false;
            for it in items {
                if let Some(vs) = resolve(it, path) {
                    any = true;
                    out.extend(vs);
                }
            }
            if any {
                Some(out)
            } else {
                None
            }
        }
        Value::Doc(fields) => {
            let value = fields.iter().find(|(k, _)| k == head).map(|(_, v)| v)?;
            if rest.is_empty() {
                match value {
                    Value::Array(items) => Some(items.clone()),
                    other => Some(vec![other.clone()]),
                }
            } else {
                resolve(value, rest)
            }
        }
        _ => None,
    }
}

/// Every index entry a document produces (§3–§5), in encoded form.
pub fn index_keys(
    document: &Value,
    fields: &[String],
    sparse: bool,
    id: i64,
) -> Result<Vec<Vec<u8>>> {
    let mut per_field: Vec<Vec<Value>> = Vec::with_capacity(fields.len());
    for f in fields {
        let path = parse_field_path(f);
        match resolve(document, &path) {
            Some(vs) => per_field.push(vs),
            // §3: an absent field is indexed as NULL, unless the index is sparse.
            None if sparse => return Ok(Vec::new()),
            None => per_field.push(vec![Value::Null]),
        }
    }

    let mut combos: Vec<Vec<Value>> = vec![Vec::new()];
    for vs in &per_field {
        let mut next = Vec::new();
        for c in &combos {
            for v in vs {
                let mut row = c.clone();
                row.push(v.clone());
                next.push(row);
            }
        }
        if next.len() > CAP_PER_DOCUMENT {
            return corrupt(format!(
                "index entries for one document exceed the cap of {CAP_PER_DOCUMENT}"
            ));
        }
        combos = next;
    }

    let mut keys: Vec<Vec<u8>> = Vec::new();
    for mut row in combos {
        row.push(Value::NitriteId(id));
        let k = cke::encode(&Value::Array(row))?;
        // §4: duplicate elements produce one entry, not two -- the key is
        // identical, so the second write is a no-op.
        if !keys.contains(&k) {
            keys.push(k);
        }
    }
    Ok(keys)
}

/// §3 — a **unique** index treats every `NULL` as distinct: the uniqueness
/// check is **skipped** whenever any of `v1..vk` is `NULL`. It is not that the
/// check runs and passes.
pub fn uniqueness_applies(values: &[Value]) -> bool {
    !values.iter().any(|v| matches!(v, Value::Null))
}

/// §1 — the indexed values and the document id, decoded back out of a key. A
/// scan therefore never needs a second lookup to learn which document matched.
pub fn entry_values(key: &[u8]) -> Result<(Vec<Value>, i64)> {
    let Value::Array(mut items) = cke::decode_all(key)? else {
        return corrupt("an index key is a CKE ARRAY");
    };
    let Some(Value::NitriteId(id)) = items.pop() else {
        return corrupt("an index key ends with a NITRITE_ID");
    };
    Ok((items, id))
}

pub fn entry_id(key: &[u8]) -> Result<i64> {
    Ok(entry_values(key)?.1)
}

/// §6 — the values that cannot be indexed, named so the error can name them.
pub fn check_indexable(v: &Value) -> Result<()> {
    if !crate::compare::is_ordered(v) || !cke::is_key_encodable(v) {
        return corrupt(format!("{} has no CKE encoding and cannot be indexed", cke::type_label(v)));
    }
    Ok(())
}

/// §7 — the scan bounds. Every indexed predicate MUST be expressed as one of
/// these, built from `03-key-encoding.md` §8's helpers and no others.
#[derive(Clone, Debug)]
pub struct IndexScan {
    pub lower: Vec<u8>,
    /// `None` is §8's `UNBOUNDED_ABOVE`.
    pub upper: Option<Vec<u8>>,
}

impl IndexScan {
    pub fn contains(&self, key: &[u8]) -> bool {
        key >= &self.lower[..] && self.upper.as_ref().map_or(true, |u| key < &u[..])
    }
}

/// Equality on a prefix, with the last element type-exact.
pub fn scan_prefix(prefix: &[Value]) -> Result<IndexScan> {
    let lower = cke::prefix_of_array(prefix)?;
    let upper = cke::successor(&lower);
    Ok(IndexScan { lower, upper })
}

/// Equality on a prefix whose **last element is numeric and type-agnostic** —
/// the helper that makes `eq(5)` match `I32(5)` and `F64(5.0)` alike. Without
/// it, an index on a numeric field answers `eq(5)` only for the exact type
/// that was written, which is the divergence chapter 03 exists to remove.
pub fn scan_prefix_numeric(prefix: &[Value]) -> Result<IndexScan> {
    let lower = cke::array_prefix_numeric(prefix)?;
    let upper = cke::successor(&lower);
    Ok(IndexScan { lower, upper })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmp {
    Gt,
    Ge,
    Lt,
    Le,
}

/// A range on the j-th element after equality on `v1..v(j-1)`.
///
/// **A numeric bound is built from `N(v)`, never from `CKE(v)`** (§8.2): a
/// bound carrying a type code cuts the domain in the middle of a group of
/// numerically equal keys, so `field >= 5` misses an `I8(5)` and `field > 5`
/// returns a `U8(5)`.
pub fn scan_range(head: &[Value], op: Cmp, bound: &Value) -> Result<IndexScan> {
    let mut base = cke::prefix_of_array(head)?;
    base.push(0x01); // ELEM_CONTINUE
    let numeric = crate::compare::is_numeric(bound);
    let b = if numeric { cke::n_of(bound)? } else { cke::encode(bound)? };
    let mut at = base.clone();
    at.extend_from_slice(&b);
    let after = cke::successor(&at);
    let all_below = base.clone();
    let all_above = cke::successor(&base);
    Ok(match op {
        Cmp::Ge => IndexScan { lower: at, upper: all_above },
        Cmp::Gt => IndexScan { lower: after.unwrap_or(all_above.clone().unwrap_or_default()), upper: all_above },
        Cmp::Lt => IndexScan { lower: all_below, upper: Some(at) },
        Cmp::Le => IndexScan { lower: all_below, upper: after },
    })
}

/// `starts_with` on a string in the j-th position (§8.3).
pub fn scan_starts_with(head: &[Value], s: &str) -> Result<IndexScan> {
    let mut lower = cke::prefix_of_array(head)?;
    lower.push(0x01);
    lower.push(cke::STRING);
    lower.extend_from_slice(&cke::esc_open(s.as_bytes()));
    let upper = cke::successor(&lower);
    Ok(IndexScan { lower, upper })
}

/// §8.1's scalar predicates over a bare (non-array) key space.
pub fn scan_scalar(op: Cmp, v: &Value) -> Result<IndexScan> {
    let numeric = crate::compare::is_numeric(v);
    let b = if numeric { cke::n_of(v)? } else { cke::encode(v)? };
    Ok(match op {
        Cmp::Ge => IndexScan { lower: b, upper: None },
        Cmp::Gt => IndexScan { lower: cke::successor(&b).unwrap_or_default(), upper: None },
        Cmp::Lt => IndexScan { lower: Vec::new(), upper: Some(b) },
        Cmp::Le => IndexScan { lower: Vec::new(), upper: cke::successor(&b) },
    })
}

pub fn scan_eq(v: &Value) -> Result<IndexScan> {
    let numeric = crate::compare::is_numeric(v);
    let lower = if numeric { cke::n_of(v)? } else { cke::encode(v)? };
    let upper = cke::successor(&lower);
    Ok(IndexScan { lower, upper })
}
