//! CKE — `03-key-encoding.md`. Big-endian throughout: this is the one place in
//! the format where that is true (`00-conventions.md` §3).

use crate::value::{NumType, Value};
use crate::{corrupt, Result};

pub const NULL: u8 = 0x00;
pub const BOOL: u8 = 0x10;
pub const NUMBER: u8 = 0x30;
pub const TEMPORAL: u8 = 0x40;
pub const CHAR: u8 = 0x50;
pub const STRING: u8 = 0x60;
pub const BYTES: u8 = 0x70;
pub const NITRITE_ID: u8 = 0x80;
pub const UUID: u8 = 0x90;
pub const ARRAY: u8 = 0xA0;

const ELEM_CONTINUE: u8 = 0x01;
const ELEM_END: u8 = 0x00;

/// §3.1 — the escaped, self-delimiting byte string.
pub fn esc(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() + 2);
    for &b in s {
        if b == 0x00 {
            out.push(0x00);
            out.push(0x01);
        } else {
            out.push(b);
        }
    }
    out.push(0x00);
    out.push(0x00);
    out
}

/// §8 — `esc(s)` without its terminator: the shared prefix of every string
/// beginning with `s`.
pub fn esc_open(s: &[u8]) -> Vec<u8> {
    let mut v = esc(s);
    v.truncate(v.len() - 2);
    v
}

fn unesc(b: &[u8], complemented: bool) -> Result<(Vec<u8>, usize)> {
    let at = |i: usize| if complemented { !b[i] } else { b[i] };
    let mut out = Vec::new();
    let mut i = 0usize;
    loop {
        if i >= b.len() {
            return corrupt("truncated escaped byte string");
        }
        let c = at(i);
        if c != 0x00 {
            out.push(c);
            i += 1;
            continue;
        }
        if i + 1 >= b.len() {
            return corrupt("truncated escape");
        }
        match at(i + 1) {
            0x00 => return Ok((out, i + 2)),
            0x01 => {
                out.push(0x00);
                i += 2;
            }
            _ => return corrupt("non-canonical escape"),
        }
    }
}

/// §4.1 — the exact `(e, m)` of `|v| = m x 2^e`, `1 <= m < 2`, with `m` held as
/// a 128-bit MSB-aligned fraction. Shifts and a leading-zero count, no bignum.
fn normalize_int(mag: u128) -> (i32, u128) {
    let n = 128 - mag.leading_zeros() as i32; // significant bits, 1..128
    (n - 1, mag << (128 - n))
}

fn normalize_f64(v: f64) -> (i32, u128) {
    let bits = v.to_bits();
    let biased = ((bits >> 52) & 0x7FF) as i32;
    let frac = bits & 0x000F_FFFF_FFFF_FFFF;
    let (sig, e) = if biased != 0 {
        ((1u64 << 52) | frac, biased - 1023)
    } else {
        let k = 52 - (63 - frac.leading_zeros() as i32);
        (frac << k, -1022 - k)
    };
    (e, (sig as u128) << (128 - 53))
}

/// §4.2 — the ordering region of a finite non-zero magnitude.
fn ordering_region(e: i32, m: u128) -> Vec<u8> {
    let all = m.to_be_bytes();
    let end = all.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
    let mut body = Vec::new();
    body.extend_from_slice(&(((e + 16384) as u16).to_be_bytes()));
    body.extend_from_slice(&esc(&all[..end]));
    body
}

fn complement(mut v: Vec<u8>) -> Vec<u8> {
    for b in v.iter_mut() {
        *b = !*b;
    }
    v
}

/// The NUMBER body without its type code — §8's `N(v)` minus the group tag.
fn number_region(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    match v {
        Value::Int { neg, mag, .. } => {
            if *mag == 0 {
                out.push(0x02);
            } else {
                out.push(if *neg { 0x01 } else { 0x03 });
                let (e, m) = normalize_int(*mag);
                let region = ordering_region(e, m);
                out.extend_from_slice(&if *neg { complement(region) } else { region });
            }
        }
        Value::Float { v: f, .. } => {
            if f.is_nan() {
                out.push(0x05);
            } else if f.is_infinite() {
                out.push(if *f < 0.0 { 0x00 } else { 0x04 });
            } else if *f == 0.0 {
                // §7: -0.0 encodes as the zero class, and so decodes as +0.0.
                out.push(0x02);
            } else {
                let neg = *f < 0.0;
                out.push(if neg { 0x01 } else { 0x03 });
                let (e, m) = normalize_f64(f.abs());
                let region = ordering_region(e, m);
                out.extend_from_slice(&if neg { complement(region) } else { region });
            }
        }
        _ => unreachable!("number_region on a non-number"),
    }
    out
}

/// §5 — every instant-valued tag canonicalizes into subclass 0x01.
fn instant_of(millis: i64) -> (i64, u32) {
    let secs = millis.div_euclid(1000);
    let nanos = ((millis - secs * 1000) * 1_000_000) as u32;
    (secs, nanos)
}

fn put_u64_flipped(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(&((v as u64) ^ 0x8000_0000_0000_0000).to_be_bytes());
}

pub fn encode(v: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    match v {
        Value::Null => out.push(NULL),
        Value::Bool(b) => {
            out.push(BOOL);
            out.push(if *b { 1 } else { 0 });
        }
        Value::Int { w, .. } | Value::Float { w, .. } => {
            out.push(NUMBER);
            out.extend_from_slice(&number_region(v));
            out.push(w.type_code());
        }
        Value::Char(c) => {
            out.push(CHAR);
            out.extend_from_slice(&c.to_be_bytes());
        }
        Value::Str(s) => {
            out.push(STRING);
            out.extend_from_slice(&esc(s.as_bytes()));
        }
        Value::Bytes(b) => {
            out.push(BYTES);
            out.extend_from_slice(&esc(b));
        }
        Value::NitriteId(id) => {
            out.push(NITRITE_ID);
            put_u64_flipped(&mut out, *id);
        }
        Value::Uuid(b) => {
            out.push(UUID);
            out.extend_from_slice(b);
        }
        Value::Timestamp(ms) => {
            let (s, n) = instant_of(*ms);
            out.push(TEMPORAL);
            out.push(0x01);
            put_u64_flipped(&mut out, s);
            out.extend_from_slice(&n.to_be_bytes());
        }
        Value::Zoned(ms, _) => return encode(&Value::Timestamp(*ms)),
        Value::TimestampNs(s, n) => {
            // §5: nanos normalized to 0..999_999_999.
            let (s, n) = (s + (*n / 1_000_000_000) as i64, n % 1_000_000_000);
            out.push(TEMPORAL);
            out.push(0x01);
            put_u64_flipped(&mut out, s);
            out.extend_from_slice(&n.to_be_bytes());
        }
        Value::Date(d) => {
            out.push(TEMPORAL);
            out.push(0x03);
            out.extend_from_slice(&((*d as u32) ^ 0x8000_0000).to_be_bytes());
        }
        Value::Time(n) => {
            out.push(TEMPORAL);
            out.push(0x04);
            out.extend_from_slice(&n.to_be_bytes());
        }
        Value::Duration(s, n) => {
            out.push(TEMPORAL);
            out.push(0x05);
            put_u64_flipped(&mut out, *s);
            out.extend_from_slice(&n.to_be_bytes());
        }
        Value::Array(items) => {
            out.push(ARRAY);
            for it in items {
                out.push(ELEM_CONTINUE);
                out.extend_from_slice(&encode(it)?);
            }
            out.push(ELEM_END);
        }
        // §2: these have no key encoding, and the attempt is an error rather
        // than a silent no-op.
        Value::Dec128(_) => return corrupt("DEC128 has no CKE encoding (§4.4)"),
        other => {
            return corrupt(format!("{} has no CKE encoding", type_name(other)));
        }
    }
    Ok(out)
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Doc(_) => "DOC",
        Value::Map(_) => "MAP",
        Value::VectorF32(_) => "VECTOR",
        Value::Geometry(_) => "GEOMETRY",
        Value::Regex(..) => "REGEX",
        Value::Opaque { .. } => "OPAQUE",
        Value::Unknown { .. } => "an unassigned tag",
        _ => "this value",
    }
}

/// Decodes one key, rejecting trailing bytes (§7).
pub fn decode_all(b: &[u8]) -> Result<Value> {
    let (v, n) = decode(b)?;
    if n != b.len() {
        return corrupt("trailing bytes after a complete key");
    }
    Ok(v)
}

pub fn decode(b: &[u8]) -> Result<(Value, usize)> {
    if b.is_empty() {
        return corrupt("empty key");
    }
    let need = |n: usize| -> Result<()> {
        if b.len() < 1 + n {
            corrupt("truncated body")
        } else {
            Ok(())
        }
    };
    match b[0] {
        NULL => Ok((Value::Null, 1)),
        BOOL => {
            need(1)?;
            match b[1] {
                0 => Ok((Value::Bool(false), 2)),
                1 => Ok((Value::Bool(true), 2)),
                _ => corrupt("BOOL body is not 0 or 1"),
            }
        }
        CHAR => {
            need(4)?;
            let c = u32::from_be_bytes(b[1..5].try_into().unwrap());
            if char::from_u32(c).is_none() {
                return corrupt("CHAR is not a Unicode scalar value");
            }
            Ok((Value::Char(c), 5))
        }
        NITRITE_ID => {
            need(8)?;
            let u = u64::from_be_bytes(b[1..9].try_into().unwrap()) ^ 0x8000_0000_0000_0000;
            Ok((Value::NitriteId(u as i64), 9))
        }
        UUID => {
            need(16)?;
            Ok((Value::Uuid(b[1..17].try_into().unwrap()), 17))
        }
        STRING | BYTES => {
            let (raw, n) = unesc(&b[1..], false)?;
            if b[0] == STRING {
                let s = String::from_utf8(raw)
                    .map_err(|_| crate::Error::Corrupt("ill-formed UTF-8 in a STRING key".into()))?;
                Ok((Value::Str(s), 1 + n))
            } else {
                Ok((Value::Bytes(raw), 1 + n))
            }
        }
        TEMPORAL => decode_temporal(b),
        NUMBER => decode_number(b),
        ARRAY => {
            let mut items = Vec::new();
            let mut at = 1usize;
            loop {
                if at >= b.len() {
                    return corrupt("ARRAY key has no ELEM_END");
                }
                match b[at] {
                    ELEM_END => return Ok((Value::Array(items), at + 1)),
                    ELEM_CONTINUE => {
                        let (v, n) = decode(&b[at + 1..])?;
                        items.push(v);
                        at += 1 + n;
                    }
                    _ => return corrupt("ARRAY element marker is neither 0x00 nor 0x01"),
                }
            }
        }
        t => corrupt(format!("unknown group tag 0x{t:02x}")),
    }
}

fn decode_temporal(b: &[u8]) -> Result<(Value, usize)> {
    if b.len() < 2 {
        return corrupt("truncated TEMPORAL");
    }
    let want = |n: usize| -> Result<()> {
        if b.len() < 2 + n {
            corrupt("truncated TEMPORAL body")
        } else {
            Ok(())
        }
    };
    let flipped_i64 = |at: usize| -> i64 {
        (u64::from_be_bytes(b[at..at + 8].try_into().unwrap()) ^ 0x8000_0000_0000_0000) as i64
    };
    match b[1] {
        0x01 => {
            want(12)?;
            let secs = flipped_i64(2);
            let nanos = u32::from_be_bytes(b[10..14].try_into().unwrap());
            Ok((Value::TimestampNs(secs, nanos), 14))
        }
        0x02 => corrupt("temporal subclass 0x02 is reserved and MUST NOT be written"),
        0x03 => {
            want(4)?;
            let d = (u32::from_be_bytes(b[2..6].try_into().unwrap()) ^ 0x8000_0000) as i32;
            Ok((Value::Date(d), 6))
        }
        0x04 => {
            want(8)?;
            Ok((Value::Time(u64::from_be_bytes(b[2..10].try_into().unwrap())), 10))
        }
        0x05 => {
            want(12)?;
            let secs = flipped_i64(2);
            let nanos = u32::from_be_bytes(b[10..14].try_into().unwrap());
            Ok((Value::Duration(secs, nanos), 14))
        }
        s => corrupt(format!("unknown temporal subclass 0x{s:02x}")),
    }
}

fn decode_number(b: &[u8]) -> Result<(Value, usize)> {
    if b.len() < 2 {
        return corrupt("truncated NUMBER");
    }
    let sign_class = b[1];
    let (e, m, used) = match sign_class {
        0x00 | 0x02 | 0x04 | 0x05 => (0i32, 0u128, 2usize),
        0x01 | 0x03 => {
            let neg = sign_class == 0x01;
            if b.len() < 4 {
                return corrupt("truncated NUMBER exponent");
            }
            let raw = [b[2], b[3]];
            let exp = if neg {
                u16::from_be_bytes([!raw[0], !raw[1]])
            } else {
                u16::from_be_bytes(raw)
            };
            let (mbytes, n) = unesc(&b[4..], neg)?;
            if mbytes.is_empty() {
                return corrupt("empty mantissa");
            }
            if mbytes[0] < 0x80 {
                return corrupt("mantissa first byte below 0x80");
            }
            if mbytes.len() > 16 {
                return corrupt("mantissa longer than 16 bytes");
            }
            let mut padded = [0u8; 16];
            padded[..mbytes.len()].copy_from_slice(&mbytes);
            (exp as i32 - 16384, u128::from_be_bytes(padded), 4 + n)
        }
        c => return corrupt(format!("unknown sign class 0x{c:02x}")),
    };
    if b.len() < used + 1 {
        return corrupt("NUMBER has no type code");
    }
    let w = NumType::from_type_code(b[used])
        .ok_or_else(|| crate::Error::Corrupt(format!("type code 0x{:02x} is reserved", b[used])))?;
    let neg = sign_class == 0x01 || sign_class == 0x00;
    let value = if w.is_float() {
        let f = match sign_class {
            0x00 => f64::NEG_INFINITY,
            0x02 => 0.0,
            0x04 => f64::INFINITY,
            0x05 => f64::NAN,
            _ => {
                let mag = float_from(e, m, w)?;
                if neg {
                    -mag
                } else {
                    mag
                }
            }
        };
        Value::Float { w, v: f }
    } else {
        match sign_class {
            0x02 => Value::Int { w, neg: false, mag: 0 },
            0x00 | 0x04 | 0x05 => {
                return corrupt("an integer type code cannot carry an infinity or NaN sign class")
            }
            _ => {
                if !(0..=127).contains(&e) {
                    return corrupt("integer exponent out of range");
                }
                let shift = 127 - e as u32;
                if shift < 128 && shift > 0 && (m & ((1u128 << shift) - 1)) != 0 {
                    return corrupt("integer type code over a non-integral ordering region");
                }
                Value::Int { w, neg, mag: m >> shift }
            }
        }
    };
    Ok((value, used + 1))
}

/// The inverse of §4.1's normalization, for the two float widths.
fn float_from(e: i32, m: u128, w: NumType) -> Result<f64> {
    if w == NumType::F32 {
        let sig = (m >> 104) as u64; // 24 significant bits
        let bits: u32 = if e >= -126 {
            if e > 127 {
                return corrupt("f32 exponent out of range");
            }
            (((e + 127) as u32) << 23) | ((sig as u32) & 0x007F_FFFF)
        } else {
            let shift = (-126 - e) as u32;
            if shift >= 24 {
                0
            } else {
                (sig >> shift) as u32
            }
        };
        Ok(f32::from_bits(bits) as f64)
    } else {
        let sig = (m >> 75) as u64; // 53 significant bits
        let bits: u64 = if e >= -1022 {
            if e > 1023 {
                return corrupt("f64 exponent out of range");
            }
            (((e + 1023) as u64) << 52) | (sig & 0x000F_FFFF_FFFF_FFFF)
        } else {
            let shift = (-1022 - e) as u32;
            if shift >= 53 {
                0
            } else {
                sig >> shift
            }
        };
        Ok(f64::from_bits(bits))
    }
}

// ---------------------------------------------------------------------------
// §8 — the five normative range helpers. A planner uses these and no others.
// ---------------------------------------------------------------------------

/// The least byte string greater than every string having `k` as a prefix.
/// `None` is §8's `UNBOUNDED_ABOVE`, which is why tag 0xFF is reserved.
pub fn successor(k: &[u8]) -> Option<Vec<u8>> {
    let mut b = k.to_vec();
    while b.last() == Some(&0xFF) {
        b.pop();
    }
    if b.is_empty() {
        return None;
    }
    let last = b.len() - 1;
    b[last] += 1;
    Some(b)
}

/// `N(v)` — `CKE(v)` minus its trailing type code: the shared prefix of every
/// numeric type equal to `v`. A numeric bound MUST be built from this (§8.2).
pub fn n_of(v: &Value) -> Result<Vec<u8>> {
    match v {
        Value::Int { .. } | Value::Float { .. } => {
            let mut out = vec![NUMBER];
            out.extend_from_slice(&number_region(v));
            Ok(out)
        }
        _ => corrupt("N(v) is defined for numbers only"),
    }
}

pub fn prefix_of_array(prefix: &[Value]) -> Result<Vec<u8>> {
    let mut out = vec![ARRAY];
    for p in prefix {
        out.push(ELEM_CONTINUE);
        out.extend_from_slice(&encode(p)?);
    }
    Ok(out)
}

/// `prefix_of_array`, with the last element left type-agnostic.
pub fn array_prefix_numeric(prefix: &[Value]) -> Result<Vec<u8>> {
    let (last, head) = prefix.split_last().ok_or_else(|| crate::Error::Corrupt("empty prefix".into()))?;
    let mut out = prefix_of_array(head)?;
    out.push(ELEM_CONTINUE);
    out.extend_from_slice(&n_of(last)?);
    Ok(out)
}

/// §2 — whether a value has a CKE encoding at all. `DEC128` is the one that
/// looks encodable and is not (§4.4).
pub fn is_key_encodable(v: &Value) -> bool {
    matches!(
        v,
        Value::Null
            | Value::Bool(_)
            | Value::Int { .. }
            | Value::Float { .. }
            | Value::Char(_)
            | Value::Str(_)
            | Value::Bytes(_)
            | Value::NitriteId(_)
            | Value::Uuid(_)
            | Value::Timestamp(_)
            | Value::TimestampNs(..)
            | Value::Zoned(..)
            | Value::Date(_)
            | Value::Time(_)
            | Value::Duration(..)
    ) || matches!(v, Value::Array(items) if items.iter().all(is_key_encodable))
}

pub fn type_label(v: &Value) -> &'static str {
    match v {
        Value::Doc(_) => "DOC",
        Value::Map(_) => "MAP",
        Value::VectorF32(_) => "VECTOR",
        Value::Geometry(_) => "GEOMETRY",
        Value::Regex(..) => "REGEX",
        Value::Opaque { .. } => "OPAQUE",
        Value::Dec128(_) => "DEC128",
        Value::Unknown { .. } => "an unassigned tag",
        _ => "this value",
    }
}
