//! `02-value-encoding.md` §8 — equality and comparison, defined once for all
//! SDKs. This is the *logical* order; `cke` is the byte order that refines it.

use crate::error::{invalid, Result};
use crate::value::{NumType, Value};
use std::cmp::Ordering;

/// §8 rule 10 — the group order, which is `03-key-encoding.md` §2's tag order.
fn group(v: &Value) -> u8 {
    match v {
        Value::Null => 0x00,
        Value::Bool(_) => 0x10,
        Value::Int { .. } | Value::Float { .. } | Value::Dec128(_) => 0x30,
        Value::Timestamp(_) | Value::TimestampNs(..) | Value::Zoned(..) => 0x40,
        Value::Date(_) => 0x41,
        Value::Time(_) => 0x42,
        Value::Duration(..) => 0x43,
        Value::Char(_) => 0x50,
        Value::Str(_) => 0x60,
        Value::Bytes(_) => 0x70,
        Value::NitriteId(_) => 0x80,
        Value::Uuid(_) => 0x90,
        Value::Array(_) => 0xA0,
        // §8 rule 10's extension: ordering ranks, never written to a file.
        // ARRAY < MAP < DOC. Dart chose the opposite order until the spec
        // pinned it, and nothing could see the disagreement because these
        // ranks are not in any byte of any file.
        Value::Map(_) => 0xA1,
        Value::Doc(_) => 0xA2,
        // §8's closing paragraph: these are not ordered at all. The rank is
        // unreachable -- `compare_values` refuses before it is consulted --
        // and exists only so `group` is total.
        _ => 0xF0,
    }
}

/// §8's closing paragraph — using one of these as a key is an error, not a
/// silent no-op.
pub fn is_ordered(v: &Value) -> bool {
    !matches!(
        v,
        Value::Opaque { .. } | Value::Geometry(_) | Value::VectorF32(_) | Value::Regex(..)
            | Value::Unknown { .. }
    )
}

/// The instant an instant-valued tag denotes (§8 rule 7), at nanosecond
/// resolution, so the three tags compare across each other.
fn instant(v: &Value) -> Option<(i64, u32)> {
    match v {
        Value::Timestamp(ms) | Value::Zoned(ms, _) => {
            let s = ms.div_euclid(1000);
            Some((s, ((ms - s * 1000) * 1_000_000) as u32))
        }
        Value::TimestampNs(s, n) => Some((s + (n / 1_000_000_000) as i64, n % 1_000_000_000)),
        _ => None,
    }
}

/// §8 rule 2 — every numeric tag is one domain, compared by **exact** numeric
/// value. A decimal against a binary float is compared by their exact rational
/// values, never by converting one to the other.
pub fn compare_numeric(a: &Value, b: &Value) -> Ordering {
    // NaN is above every other number and equal to itself (rule 3).
    let nan = |v: &Value| matches!(v, Value::Float { v, .. } if v.is_nan());
    match (nan(a), nan(b)) {
        (true, true) => return Ordering::Equal,
        (true, false) => return Ordering::Greater,
        (false, true) => return Ordering::Less,
        _ => {}
    }
    // (sign, e, m) with |v| = m * 2^e is exact for every integer and float we
    // hold, so the comparison never converts one representation into another.
    let key = |v: &Value| -> (i8, i32, u128) {
        match v {
            Value::Int { neg, mag, .. } => {
                if *mag == 0 {
                    (0, 0, 0)
                } else {
                    let n = 128 - mag.leading_zeros() as i32;
                    (if *neg { -1 } else { 1 }, n - 1, mag << (128 - n))
                }
            }
            Value::Float { v: f, .. } => {
                if *f == 0.0 {
                    (0, 0, 0)
                } else if f.is_infinite() {
                    (if *f < 0.0 { -1 } else { 1 }, i32::MAX, u128::MAX)
                } else {
                    let bits = f.abs().to_bits();
                    let biased = ((bits >> 52) & 0x7FF) as i32;
                    let frac = bits & 0x000F_FFFF_FFFF_FFFF;
                    let (sig, e) = if biased != 0 {
                        ((1u64 << 52) | frac, biased - 1023)
                    } else {
                        let k = 52 - (63 - frac.leading_zeros() as i32);
                        (frac << k, -1022 - k)
                    };
                    (if *f < 0.0 { -1 } else { 1 }, e, (sig as u128) << (128 - 53))
                }
            }
            // DEC128 participates in value comparison; without a decimal
            // arithmetic it is ordered by its coefficient only when it is the
            // sole member of the comparison, which the caller avoids.
            _ => (0, 0, 0),
        }
    };
    let (sa, ea, ma) = key(a);
    let (sb, eb, mb) = key(b);
    match sa.cmp(&sb) {
        Ordering::Equal => {}
        o => return o,
    }
    if sa == 0 {
        return Ordering::Equal;
    }
    let mag = ea.cmp(&eb).then(ma.cmp(&mb));
    if sa < 0 {
        mag.reverse()
    } else {
        mag
    }
}

/// §8, all ten rules.
///
/// Fallible on purpose. §8's closing paragraph makes comparing two unordered
/// values an *error*, and the alternative an infallible signature forces --
/// returning `Equal` -- is the dangerous answer, not the conservative one: it
/// made two different `GEOMETRY` values indistinguishable to a sort, a dedup
/// and `values_equal`. `DEC128` is refused for the same reason in the other
/// direction: rule 2 puts it in the numeric domain, this crate has no exact
/// decimal arithmetic, and approximating it compared every `DEC128` as zero.
pub fn compare_values(a: &Value, b: &Value) -> Result<Ordering> {
    for v in [a, b] {
        if !is_ordered(v) {
            return invalid(format!(
                "{} is not ordered (02-value-encoding.md §8)",
                crate::cke::type_label(v)
            ));
        }
        if matches!(v, Value::Dec128(_)) {
            return invalid(
                "DEC128 comparison needs exact decimal arithmetic, which this \
                 implementation does not provide; it is never a key",
            );
        }
    }
    Ok(compare_ordered(a, b))
}

/// The infallible core, for callers that have already established both sides
/// are ordered -- which the recursion into `ARRAY`, `MAP` and `DOC` elements
/// has *not*, so it re-checks there.
fn compare_ordered(a: &Value, b: &Value) -> Ordering {
    let (ga, gb) = (group(a), group(b));
    if ga != gb {
        return ga.cmp(&gb);
    }
    match (a, b) {
        (Value::Null, Value::Null) => Ordering::Equal,
        (Value::Bool(x), Value::Bool(y)) => x.cmp(y),
        (Value::Int { .. } | Value::Float { .. } | Value::Dec128(_), _) => compare_numeric(a, b),
        (Value::Char(x), Value::Char(y)) => x.cmp(y),
        (Value::Str(x), Value::Str(y)) => x.as_bytes().cmp(y.as_bytes()),
        (Value::Bytes(x), Value::Bytes(y)) => x.cmp(y),
        (Value::NitriteId(x), Value::NitriteId(y)) => x.cmp(y),
        (Value::Uuid(x), Value::Uuid(y)) => x.cmp(y),
        (Value::Date(x), Value::Date(y)) => x.cmp(y),
        (Value::Time(x), Value::Time(y)) => x.cmp(y),
        (Value::Duration(s1, n1), Value::Duration(s2, n2)) => s1.cmp(s2).then(n1.cmp(n2)),
        (Value::Array(x), Value::Array(y)) => {
            for (p, q) in x.iter().zip(y.iter()) {
                match compare_element(p, q) {
                    Ordering::Equal => {}
                    o => return o,
                }
            }
            x.len().cmp(&y.len())
        }
        // §8 rule 8: "MAP and DOC compare as their **sorted** (key, value)
        // sequences." The DOC arm below has always sorted; this one compared in
        // *stored* order, so two maps holding the same entries written in a
        // different order compared unequal. All three implementations had it,
        // identically, which is why no cross-language check could see it: the
        // order is consumed in memory and the bytes never differ.
        //
        // A MAP may hold a duplicate key where a DOC cannot, so the sort is by
        // (key, then value) — sorting on the key alone leaves the sequence
        // undetermined exactly where the duplicates are.
        (Value::Map(x), Value::Map(y)) => {
            let mut xs = x.clone();
            let mut ys = y.clone();
            xs.sort_by(|p, q| {
                compare_element(&p.0, &q.0).then_with(|| compare_element(&p.1, &q.1))
            });
            ys.sort_by(|p, q| {
                compare_element(&p.0, &q.0).then_with(|| compare_element(&p.1, &q.1))
            });
            compare_pairs(&xs, &ys)
        }
        (Value::Doc(x), Value::Doc(y)) => {
            let mut xs: Vec<(Value, Value)> =
                x.iter().map(|(k, v)| (Value::Str(k.clone()), v.clone())).collect();
            let mut ys: Vec<(Value, Value)> =
                y.iter().map(|(k, v)| (Value::Str(k.clone()), v.clone())).collect();
            xs.sort_by(|p, q| compare_ordered(&p.0, &q.0));
            ys.sort_by(|p, q| compare_ordered(&p.0, &q.0));
            compare_pairs(&xs, &ys)
        }
        _ => match (instant(a), instant(b)) {
            (Some(x), Some(y)) => x.cmp(&y),
            // §8's closing paragraph: not ordered. Equal keeps the relation
            // reflexive without inventing an order the format does not define.
            _ => Ordering::Equal,
        },
    }
}

/// An element *inside* an ARRAY, MAP or DOC. §8 gives no order for an
/// unordered element, but the container comparison has to stay total or
/// sorting a list of documents is undefined -- so an unordered element is
/// ranked by tag and then by its own bytes. That is deterministic and it is
/// never a key, so it is never written down.
fn compare_element(a: &Value, b: &Value) -> Ordering {
    if is_ordered(a) && is_ordered(b) && !matches!(a, Value::Dec128(_))
        && !matches!(b, Value::Dec128(_))
    {
        return compare_ordered(a, b);
    }
    unordered_rank(a).cmp(&unordered_rank(b))
}

fn unordered_rank(v: &Value) -> (u8, Vec<u8>) {
    match v {
        Value::Dec128(b) => (0x30, b.to_vec()),
        Value::Regex(p, f) => (0xF0, [p.as_bytes(), b"\0", f.as_bytes()].concat()),
        Value::VectorF32(xs) => {
            (0xF1, xs.iter().flat_map(|x| x.to_le_bytes()).collect())
        }
        Value::Geometry(b) => (0xF2, b.clone()),
        Value::Opaque { origin, type_name, data } => (
            0xF3,
            [origin.as_bytes(), b"\0", type_name.as_bytes(), b"\0", data].concat(),
        ),
        Value::Unknown { tag, payload } => (0xF4, [&[*tag][..], payload].concat()),
        _ => (group(v), Vec::new()),
    }
}

fn compare_pairs(x: &[(Value, Value)], y: &[(Value, Value)]) -> Ordering {
    for (p, q) in x.iter().zip(y.iter()) {
        match compare_element(&p.0, &q.0).then_with(|| compare_element(&p.1, &q.1)) {
            Ordering::Equal => {}
            o => return o,
        }
    }
    x.len().cmp(&y.len())
}

/// §8 rule 2's consequence: `I32(5)` MUST equal `I64(5)`.
///
/// Two values §8 does not order are equal only if they are structurally
/// identical. Before this was written it returned `true` for two *different*
/// geometries, because the comparison it delegates to answered `Equal` for
/// everything it could not order.
pub fn values_equal(a: &Value, b: &Value) -> bool {
    match compare_values(a, b) {
        Ok(o) => o == Ordering::Equal,
        Err(_) => compare_element(a, b) == Ordering::Equal,
    }
}

/// The declared width is metadata, never semantics (`02` §1.2).
pub fn is_numeric(v: &Value) -> bool {
    matches!(v, Value::Int { .. } | Value::Float { .. } | Value::Dec128(_))
}

pub fn num_type(v: &Value) -> Option<NumType> {
    match v {
        Value::Int { w, .. } | Value::Float { w, .. } => Some(*w),
        _ => None,
    }
}
