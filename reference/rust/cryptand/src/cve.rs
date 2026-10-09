//! CVE — `02-value-encoding.md`. Little-endian throughout (`00-conventions.md` §3).

use crate::cke;
use crate::value::{NumType, Value};
use crate::varint::{get_uvar, put_ivar, put_uvar};
use crate::{corrupt, Result};

pub const DEPTH_LIMIT: usize = 100;

fn tag_of(v: &Value) -> u8 {
    use Value::*;
    match v {
        Null => 0x00,
        Bool(false) => 0x01,
        Bool(true) => 0x02,
        Int { w, .. } => match w {
            NumType::I8 => 0x03,
            NumType::I16 => 0x04,
            NumType::I32 => 0x05,
            NumType::I64 => 0x06,
            NumType::I128 => 0x07,
            NumType::U8 => 0x08,
            NumType::U16 => 0x09,
            NumType::U32 => 0x0A,
            NumType::U64 => 0x0B,
            NumType::U128 => 0x0C,
            _ => 0x0D,
        },
        Float { w: NumType::F32, .. } => 0x0E,
        Float { .. } => 0x0F,
        Dec128(_) => 0x10,
        Char(_) => 0x11,
        Str(_) => 0x12,
        Bytes(_) => 0x13,
        Timestamp(_) => 0x14,
        TimestampNs(..) => 0x15,
        Zoned(..) => 0x16,
        Date(_) => 0x17,
        Time(_) => 0x18,
        Duration(..) => 0x19,
        Uuid(_) => 0x1A,
        NitriteId(_) => 0x1B,
        Regex(..) => 0x1C,
        Array(_) => 0x20,
        Map(_) => 0x21,
        Doc(_) => 0x22,
        VectorF32(_) => 0x23,
        Geometry(_) => 0x24,
        Opaque { .. } => 0x7F,
        Unknown { tag, .. } => *tag,
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_uvar(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

/// Encodes with no name dictionary: every document field name is inline.
/// `02-value-encoding.md` §4's two **writer** rules, checked over a whole value
/// before it is encoded.
///
/// > "A map key MUST be CKE-encodable ... A writer MUST reject one"
/// > "Duplicate keys — two entries whose `CKE(key)` bytes are equal — are
/// > corruption."
///
/// This is a separate function rather than a check inside [`encode`] because
/// `encode` is infallible, and that is not an accident to work around: every
/// call to it inside this crate encodes a value the engine itself built — a
/// catalog document, a name, a byte string — none of which can carry a map at
/// all. The one place a *caller's* value reaches the encoder is
/// [`crate::database::Collection::insert`], and that is where this is called.
///
/// Dart and Java enforce these inside their encoders, which their fallible
/// signatures allow. The behaviour is the same; only the seam differs.
pub fn check_writable(v: &Value) -> Result<()> {
    match v {
        Value::Map(entries) => {
            let mut keys: Vec<Vec<u8>> = Vec::with_capacity(entries.len());
            for (k, val) in entries {
                let Ok(kb) = crate::cke::encode(k) else {
                    return Err(crate::Error::Invalid(format!(
                        "a value with CVE tag {:#04x} has no CKE encoding and cannot be a map key (02-value-encoding.md §4)",
                        tag_of(k)
                    )));
                };
                keys.push(kb);
                check_writable(k)?;
                check_writable(val)?;
            }
            keys.sort();
            if keys.windows(2).any(|w| w[0] == w[1]) {
                return Err(crate::Error::Invalid("duplicate map key".into()));
            }
            Ok(())
        }
        Value::Array(items) => items.iter().try_for_each(check_writable),
        Value::Doc(fields) if fields.len() > crate::limits::MAX_FIELDS => Err(crate::Error::Invalid(format!(
            "document has {} fields, limit is {} (00-conventions.md)",
            fields.len(),
            crate::limits::MAX_FIELDS
        ))),
        Value::Doc(fields) => fields.iter().try_for_each(|(_, x)| check_writable(x)),
        _ => Ok(()),
    }
}

pub fn encode(v: &Value) -> Vec<u8> {
    encode_with_dict(v, &|_| None)
}

/// `02-value-encoding.md` §5.3 — `dict` maps a field name to its `name_id`.
pub fn encode_with_dict(v: &Value, dict: &dyn Fn(&str) -> Option<u32>) -> Vec<u8> {
    let mut out = Vec::new();
    write(&mut out, v, dict);
    out
}

fn write(out: &mut Vec<u8>, v: &Value, dict: &dyn Fn(&str) -> Option<u32>) {
    out.push(tag_of(v));
    match v {
        Value::Null | Value::Bool(_) => {}
        Value::Int { w, neg, mag } => {
            let signed = || -> i128 {
                if *neg {
                    (mag.wrapping_neg()) as i128
                } else {
                    *mag as i128
                }
            };
            match w {
                NumType::I8 => out.push(signed() as i8 as u8),
                NumType::I16 => out.extend_from_slice(&(signed() as i16).to_le_bytes()),
                NumType::I32 => out.extend_from_slice(&(signed() as i32).to_le_bytes()),
                NumType::I64 => out.extend_from_slice(&(signed() as i64).to_le_bytes()),
                NumType::I128 => out.extend_from_slice(&signed().to_le_bytes()),
                NumType::U8 => out.push(*mag as u8),
                NumType::U16 => out.extend_from_slice(&(*mag as u16).to_le_bytes()),
                NumType::U32 => out.extend_from_slice(&(*mag as u32).to_le_bytes()),
                NumType::U64 => out.extend_from_slice(&(*mag as u64).to_le_bytes()),
                NumType::U128 => out.extend_from_slice(&mag.to_le_bytes()),
                _ => put_ivar(out, signed() as i64),
            }
        }
        Value::Float { w, v } => {
            // `00-conventions.md` §3: NaN is canonicalized on encode.
            if *w == NumType::F32 {
                let f = *v as f32;
                let f = if f.is_nan() { f32::from_bits(0x7FC0_0000) } else { f };
                out.extend_from_slice(&f.to_le_bytes());
            } else {
                let f = if v.is_nan() { f64::from_bits(0x7FF8_0000_0000_0000) } else { *v };
                out.extend_from_slice(&f.to_le_bytes());
            }
        }
        Value::Dec128(b) | Value::Uuid(b) => out.extend_from_slice(b),
        Value::Char(c) => out.extend_from_slice(&c.to_le_bytes()),
        Value::Str(s) => put_str(out, s),
        Value::Bytes(b) | Value::Geometry(b) => {
            put_uvar(out, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Timestamp(ms) => out.extend_from_slice(&ms.to_le_bytes()),
        Value::TimestampNs(s, n) => {
            out.extend_from_slice(&s.to_le_bytes());
            out.extend_from_slice(&n.to_le_bytes());
        }
        Value::Zoned(ms, zone) => {
            out.extend_from_slice(&ms.to_le_bytes());
            put_str(out, zone);
        }
        Value::Date(d) => out.extend_from_slice(&d.to_le_bytes()),
        Value::Time(n) => out.extend_from_slice(&n.to_le_bytes()),
        Value::Duration(s, n) => {
            out.extend_from_slice(&s.to_le_bytes());
            out.extend_from_slice(&n.to_le_bytes());
        }
        Value::NitriteId(id) => out.extend_from_slice(&id.to_le_bytes()),
        Value::Regex(p, f) => {
            put_str(out, p);
            put_str(out, f);
        }
        Value::Array(items) => {
            let mut body = Vec::new();
            put_uvar(&mut body, items.len() as u64);
            for it in items {
                write(&mut body, it, dict);
            }
            put_uvar(out, body.len() as u64);
            out.extend_from_slice(&body);
        }
        Value::Map(entries) => {
            // §4: entries MUST be sorted by CKE(key).
            let mut sorted: Vec<&(Value, Value)> = entries.iter().collect();
            sorted.sort_by(|a, b| {
                cke::encode(&a.0).unwrap_or_default().cmp(&cke::encode(&b.0).unwrap_or_default())
            });
            let mut body = Vec::new();
            put_uvar(&mut body, sorted.len() as u64);
            for (k, v) in sorted {
                write(&mut body, k, dict);
                write(&mut body, v, dict);
            }
            put_uvar(out, body.len() as u64);
            out.extend_from_slice(&body);
        }
        Value::Doc(fields) => {
            let mut body = Vec::new();
            write_doc_body(&mut body, fields, dict);
            put_uvar(out, body.len() as u64);
            out.extend_from_slice(&body);
        }
        Value::VectorF32(xs) => {
            out.push(0); // dtype 0 = f32
            put_uvar(out, xs.len() as u64);
            for x in xs {
                out.extend_from_slice(&x.to_le_bytes());
            }
        }
        Value::Opaque { origin, type_name, data } => {
            let mut body = Vec::new();
            put_str(&mut body, origin);
            put_str(&mut body, type_name);
            put_uvar(&mut body, data.len() as u64);
            body.extend_from_slice(data);
            put_uvar(out, body.len() as u64);
            out.extend_from_slice(&body);
        }
        Value::Unknown { payload, .. } => {
            // §1.1: every unassigned tag is length-prefixed.
            put_uvar(out, payload.len() as u64);
            out.extend_from_slice(payload);
        }
    }
}

/// §5: field table sorted by resolved name bytes, then the name area, then the
/// value area. Values are encoded first because a `value_offset` is measured
/// from the start of the value area and so does not depend on the table.
fn write_doc_body(
    out: &mut Vec<u8>,
    fields: &[(String, Value)],
    dict: &dyn Fn(&str) -> Option<u32>,
) {
    let mut sorted: Vec<&(String, Value)> = fields.iter().collect();
    sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

    let mut table = Vec::new();
    let mut names = Vec::new();
    let mut values = Vec::new();
    let mut inline_index = 0u64;
    for (name, value) in &sorted {
        let name_ref = match dict(name) {
            Some(id) => (id as u64) << 1,
            None => {
                let r = (inline_index << 1) | 1;
                inline_index += 1;
                put_str(&mut names, name);
                r
            }
        };
        put_uvar(&mut table, name_ref);
        put_uvar(&mut table, values.len() as u64);
        write(&mut values, value, dict);
    }

    put_uvar(out, sorted.len() as u64);
    out.push(0x01); // flags: SORTED_BY_NAME_ID, which v1 requires to be 1
    out.extend_from_slice(&table);
    out.extend_from_slice(&names);
    out.extend_from_slice(&values);
}

/// Decodes exactly one value and returns it with the byte count consumed.
/// `dict` resolves a `name_id` to a field name.
pub fn decode(b: &[u8], dict: &dyn Fn(u32) -> Option<String>) -> Result<(Value, usize)> {
    read(b, dict, 0)
}

/// Decodes a whole buffer, rejecting trailing bytes.
pub fn decode_all(b: &[u8], dict: &dyn Fn(u32) -> Option<String>) -> Result<Value> {
    let (v, n) = decode(b, dict)?;
    if n != b.len() {
        return corrupt("trailing bytes after a complete value");
    }
    Ok(v)
}

fn need(b: &[u8], at: usize, n: usize) -> Result<()> {
    if at.checked_add(n).is_none_or(|end| b.len() < end) {
        return corrupt("value truncated");
    }
    Ok(())
}

fn fixed<'a>(b: &'a [u8], at: usize, n: usize) -> Result<&'a [u8]> {
    need(b, at, n)?;
    Ok(&b[at..at + n])
}

fn read_str(b: &[u8], at: usize) -> Result<(String, usize)> {
    let (len, n) = get_uvar(&b[at..])?;
    let len = len as usize;
    need(b, at + n, len)?;
    let s = std::str::from_utf8(&b[at + n..at + n + len])
        .map_err(|_| crate::Error::Corrupt("ill-formed UTF-8".into()))?;
    Ok((s.to_string(), n + len))
}

fn read(b: &[u8], dict: &dyn Fn(u32) -> Option<String>, depth: usize) -> Result<(Value, usize)> {
    if depth > DEPTH_LIMIT {
        return corrupt("nesting deeper than 100");
    }
    if b.is_empty() {
        return corrupt("empty value");
    }
    let tag = b[0];
    let p = 1usize;
    let int = |w: NumType, v: i128| Value::Int { w, neg: v < 0, mag: v.unsigned_abs() };
    Ok(match tag {
        0x00 => (Value::Null, 1),
        0x01 => (Value::Bool(false), 1),
        0x02 => (Value::Bool(true), 1),
        0x03 => (int(NumType::I8, fixed(b, p, 1)?[0] as i8 as i128), 2),
        0x04 => (int(NumType::I16, i16::from_le_bytes(fixed(b, p, 2)?.try_into().unwrap()) as i128), 3),
        0x05 => (int(NumType::I32, i32::from_le_bytes(fixed(b, p, 4)?.try_into().unwrap()) as i128), 5),
        0x06 => (int(NumType::I64, i64::from_le_bytes(fixed(b, p, 8)?.try_into().unwrap()) as i128), 9),
        0x07 => (int(NumType::I128, i128::from_le_bytes(fixed(b, p, 16)?.try_into().unwrap())), 17),
        0x08 => (Value::Int { w: NumType::U8, neg: false, mag: fixed(b, p, 1)?[0] as u128 }, 2),
        0x09 => (
            Value::Int {
                w: NumType::U16,
                neg: false,
                mag: u16::from_le_bytes(fixed(b, p, 2)?.try_into().unwrap()) as u128,
            },
            3,
        ),
        0x0A => (
            Value::Int {
                w: NumType::U32,
                neg: false,
                mag: u32::from_le_bytes(fixed(b, p, 4)?.try_into().unwrap()) as u128,
            },
            5,
        ),
        0x0B => (
            Value::Int {
                w: NumType::U64,
                neg: false,
                mag: u64::from_le_bytes(fixed(b, p, 8)?.try_into().unwrap()) as u128,
            },
            9,
        ),
        0x0C => (
            Value::Int {
                w: NumType::U128,
                neg: false,
                mag: u128::from_le_bytes(fixed(b, p, 16)?.try_into().unwrap()),
            },
            17,
        ),
        0x0D => {
            let (v, n) = crate::varint::get_ivar(&b[p..])?;
            (int(NumType::IntVar, v as i128), p + n)
        }
        0x0E => (
            Value::Float {
                w: NumType::F32,
                v: f32::from_le_bytes(fixed(b, p, 4)?.try_into().unwrap()) as f64,
            },
            5,
        ),
        0x0F => (
            Value::Float {
                w: NumType::F64,
                v: f64::from_le_bytes(fixed(b, p, 8)?.try_into().unwrap()),
            },
            9,
        ),
        0x10 => (Value::Dec128(fixed(b, p, 16)?.try_into().unwrap()), 17),
        0x11 => {
            let c = u32::from_le_bytes(fixed(b, p, 4)?.try_into().unwrap());
            if char::from_u32(c).is_none() {
                return corrupt("CHAR is not a Unicode scalar value");
            }
            (Value::Char(c), 5)
        }
        0x12 => {
            let (s, n) = read_str(b, p)?;
            (Value::Str(s), p + n)
        }
        0x13 | 0x24 => {
            let (len, n) = get_uvar(&b[p..])?;
            let len = len as usize;
            need(b, p + n, len)?;
            let raw = b[p + n..p + n + len].to_vec();
            (if tag == 0x13 { Value::Bytes(raw) } else { Value::Geometry(raw) }, p + n + len)
        }
        0x14 => (
            Value::Timestamp(i64::from_le_bytes(fixed(b, p, 8)?.try_into().unwrap())),
            9,
        ),
        0x15 => (
            Value::TimestampNs(
                i64::from_le_bytes(fixed(b, p, 8)?.try_into().unwrap()),
                u32::from_le_bytes(fixed(b, p + 8, 4)?.try_into().unwrap()),
            ),
            13,
        ),
        0x16 => {
            let ms = i64::from_le_bytes(fixed(b, p, 8)?.try_into().unwrap());
            let (zone, n) = read_str(b, p + 8)?;
            (Value::Zoned(ms, zone), p + 8 + n)
        }
        0x17 => (Value::Date(i32::from_le_bytes(fixed(b, p, 4)?.try_into().unwrap())), 5),
        0x18 => (Value::Time(u64::from_le_bytes(fixed(b, p, 8)?.try_into().unwrap())), 9),
        0x19 => (
            Value::Duration(
                i64::from_le_bytes(fixed(b, p, 8)?.try_into().unwrap()),
                u32::from_le_bytes(fixed(b, p + 8, 4)?.try_into().unwrap()),
            ),
            13,
        ),
        0x1A => (Value::Uuid(fixed(b, p, 16)?.try_into().unwrap()), 17),
        0x1B => (
            Value::NitriteId(i64::from_le_bytes(fixed(b, p, 8)?.try_into().unwrap())),
            9,
        ),
        0x1C => {
            let (pat, n1) = read_str(b, p)?;
            let (flags, n2) = read_str(b, p + n1)?;
            (Value::Regex(pat, flags), p + n1 + n2)
        }
        0x20 | 0x21 => {
            let (byte_len, n) = get_uvar(&b[p..])?;
            let start = p + n;
            let byte_len = byte_len as usize;
            need(b, start, byte_len)?;
            let body = &b[start..start + byte_len];
            let (count, cn) = get_uvar(body)?;
            let mut at = cn;
            if tag == 0x20 {
                let mut items = Vec::new();
                for _ in 0..count {
                    let (v, used) = read(&body[at..], dict, depth + 1)?;
                    at += used;
                    items.push(v);
                }
                if at != body.len() {
                    return corrupt("ARRAY count does not span its byte_len");
                }
                (Value::Array(items), start + byte_len)
            } else {
                let mut entries = Vec::new();
                // §4's three reader rules. Dart and Java both enforce all
                // three; this side enforced none, so it accepted MAPs that
                // neither of the others will open — and §4's own justification
                // is that sorting "makes a lookup a binary search", which over
                // unsorted entries silently returns the wrong answer rather
                // than failing.
                let mut prev: Option<Vec<u8>> = None;
                for _ in 0..count {
                    let (k, used) = read(&body[at..], dict, depth + 1)?;
                    at += used;
                    let (v, used) = read(&body[at..], dict, depth + 1)?;
                    at += used;
                    // "A map key MUST be CKE-encodable ... a reader
                    // encountering one MUST report corruption."
                    let Ok(kb) = crate::cke::encode(&k) else {
                        return corrupt("MAP key has no CKE encoding");
                    };
                    if let Some(before) = &prev {
                        match kb.cmp(before) {
                            std::cmp::Ordering::Less => {
                                return corrupt("MAP entries are not sorted by CKE(key)")
                            }
                            std::cmp::Ordering::Equal => return corrupt("duplicate MAP key"),
                            std::cmp::Ordering::Greater => {}
                        }
                    }
                    prev = Some(kb);
                    entries.push((k, v));
                }
                if at != body.len() {
                    return corrupt("MAP count does not span its byte_len");
                }
                (Value::Map(entries), start + byte_len)
            }
        }
        0x22 => {
            let (byte_len, n) = get_uvar(&b[p..])?;
            let start = p + n;
            let byte_len = byte_len as usize;
            need(b, start, byte_len)?;
            let fields = read_doc_body(&b[start..start + byte_len], dict, depth)?;
            (Value::Doc(fields), start + byte_len)
        }
        0x23 => {
            let dtype = *fixed(b, p, 1)?.first().unwrap();
            if dtype != 0 {
                return corrupt("only VECTOR dtype 0 (f32) is implemented here");
            }
            let (dim, n) = get_uvar(&b[p + 1..])?;
            let dim = dim as usize;
            let at = p + 1 + n;
            need(b, at, dim * 4)?;
            let xs = (0..dim)
                .map(|i| f32::from_le_bytes(b[at + i * 4..at + i * 4 + 4].try_into().unwrap()))
                .collect();
            (Value::VectorF32(xs), at + dim * 4)
        }
        0x7F => {
            let (byte_len, n) = get_uvar(&b[p..])?;
            let start = p + n;
            let byte_len = byte_len as usize;
            need(b, start, byte_len)?;
            let body = &b[start..start + byte_len];
            let (origin, n1) = read_str(body, 0)?;
            let (type_name, n2) = read_str(body, n1)?;
            let (dlen, n3) = get_uvar(&body[n1 + n2..])?;
            let dstart = n1 + n2 + n3;
            need(body, dstart, dlen as usize)?;
            (
                Value::Opaque {
                    origin,
                    type_name,
                    data: body[dstart..dstart + dlen as usize].to_vec(),
                },
                start + byte_len,
            )
        }
        _ => {
            // §1.1: reserved and implementation-private tags are length-prefixed,
            // which is the only reason an unknown value can be preserved.
            let (byte_len, n) = get_uvar(&b[p..]).map_err(|_| {
                crate::Error::Corrupt(format!("unassigned tag 0x{tag:02x} with no length prefix"))
            })?;
            let start = p + n;
            let byte_len = byte_len as usize;
            need(b, start, byte_len)?;
            (
                Value::Unknown { tag, payload: b[start..start + byte_len].to_vec() },
                start + byte_len,
            )
        }
    })
}

fn read_doc_body(
    body: &[u8],
    dict: &dyn Fn(u32) -> Option<String>,
    depth: usize,
) -> Result<Vec<(String, Value)>> {
    let (count, mut at) = get_uvar(body)?;
    let count = count as usize;
    need(body, at, 1)?;
    let flags = body[at];
    at += 1;
    if flags & 1 == 0 {
        return corrupt("SORTED_BY_NAME_ID MUST be 1 in v1");
    }
    // Each field-table entry is two uvarints, at least two bytes (14 §9.1:
    // never size an allocation from an untrusted count).
    if count > crate::limits::MAX_FIELDS {
        return corrupt(format!("document declares {count} fields, limit is {}", crate::limits::MAX_FIELDS));
    }
    if count > (body.len() - at) / 2 {
        return corrupt(format!("document declares {count} fields in {} bytes", body.len() - at));
    }
    let mut refs = Vec::with_capacity(count);
    for _ in 0..count {
        let (name_ref, n1) = get_uvar(&body[at..])?;
        at += n1;
        let (offset, n2) = get_uvar(&body[at..])?;
        at += n2;
        refs.push((name_ref, offset as usize));
    }
    // The name area holds one string per inline name, in table order.
    let mut names = Vec::with_capacity(count);
    for (name_ref, _) in &refs {
        if name_ref & 1 == 1 {
            let (s, n) = read_str(body, at)?;
            at += n;
            names.push(Some(s));
        } else {
            names.push(None);
        }
    }
    let value_area = at;
    let mut out = Vec::with_capacity(count);
    for (i, (name_ref, offset)) in refs.iter().enumerate() {
        let name = match &names[i] {
            Some(s) => s.clone(),
            // F-041: checked, not `as u32`, which aliased a hostile id onto a real name.
            None => u32::try_from(name_ref >> 1)
                .ok()
                .and_then(&dict)
                .ok_or_else(|| crate::Error::Corrupt(format!("unknown name_id {}", name_ref >> 1)))?,
        };
        if value_area + offset > body.len() {
            return corrupt("field value_offset past the document");
        }
        let (v, _) = read(&body[value_area + offset..], dict, depth + 1)?;
        out.push((name, v));
    }
    Ok(out)
}
