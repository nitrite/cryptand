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
