//! Shared helpers for the conformance tests: JSON loading and the one function
//! `11-conformance.md` §7 expects a consuming SDK to write — rebuilding a value
//! from the language-neutral description the vectors carry.

use cryptand::value::{NumType, Value};
use serde_json::Value as J;

pub const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/vectors");

pub fn load(name: &str) -> J {
    let path = format!("{ROOT}/{name}.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{path}: {e} -- run tool/generate_vectors.dart first"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

pub fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex: {s}");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn s(j: &J, k: &str) -> String {
    j[k].as_str().unwrap_or_else(|| panic!("{k} missing or not a string in {j}")).to_string()
}

fn i(j: &J, k: &str) -> i64 {
    j[k].as_i64().unwrap_or_else(|| panic!("{k} missing or not an integer in {j}"))
}

/// Rebuilds a value from the vectors' description. A consuming SDK writes this
/// function and nothing else.
pub fn build(d: &J) -> Value {
    match d["t"].as_str().expect("every described value carries a type") {
        "null" => Value::Null,
        "bool" => Value::Bool(d["v"].as_bool().unwrap()),
        "int" => {
            let w = NumType::from_vector_name(&s(d, "w")).expect("known width");
            let text = s(d, "v");
            let neg = text.starts_with('-');
            let mag: u128 = text.trim_start_matches('-').parse().expect("decimal magnitude");
            Value::Int { w, neg, mag }
        }
        "float" => {
            let bits = unhex(&s(d, "bits"));
            if s(d, "w") == "f64" {
                Value::Float {
                    w: NumType::F64,
                    v: f64::from_bits(u64::from_be_bytes(bits.try_into().unwrap())),
                }
            } else {
                Value::Float {
                    w: NumType::F32,
                    v: f32::from_bits(u32::from_be_bytes(bits.try_into().unwrap())) as f64,
                }
            }
        }
        "str" => Value::Str(String::from_utf8(unhex(&s(d, "utf8"))).expect("well-formed UTF-8")),
        "bytes" => Value::Bytes(unhex(&s(d, "v"))),
        "char" => Value::Char(i(d, "v") as u32),
        "timestamp" => Value::Timestamp(i(d, "millis")),
        "timestamp_ns" => Value::TimestampNs(i(d, "secs"), i(d, "nanos") as u32),
        "zoned" => Value::Zoned(i(d, "millis"), s(d, "zone")),
        "date" => Value::Date(i(d, "days") as i32),
        "time" => Value::Time(i(d, "nanos") as u64),
        "duration" => Value::Duration(i(d, "secs"), i(d, "nanos") as u32),
        "uuid" => Value::Uuid(unhex(&s(d, "v")).try_into().unwrap()),
        "nitrite_id" => Value::NitriteId(s(d, "v").parse().expect("i64 id")),
        "regex" => Value::Regex(s(d, "pattern"), s(d, "flags")),
        "array" => Value::Array(d["items"].as_array().unwrap().iter().map(build).collect()),
        "map" => Value::Map(
            d["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| (build(&e["k"]), build(&e["v"])))
                .collect(),
        ),
        "doc" => Value::Doc(
            d["fields"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), build(v)))
                .collect(),
        ),
        "vector" => Value::VectorF32(
            d["f32"].as_array().unwrap().iter().map(|x| x.as_f64().unwrap() as f32).collect(),
        ),
        "geometry" => Value::Geometry(unhex(&s(d, "wkb"))),
        "opaque" => Value::Opaque {
            origin: s(d, "origin"),
            type_name: s(d, "type_name"),
            data: unhex(&s(d, "data")),
        },
        "dec128" => Value::Dec128(unhex(&s(d, "v")).try_into().unwrap()),
        "unknown" => Value::Unknown { tag: i(d, "tag") as u8, payload: unhex(&s(d, "payload")) },
        other => panic!("the vectors describe a value type this reader does not know: {other}"),
    }
}
