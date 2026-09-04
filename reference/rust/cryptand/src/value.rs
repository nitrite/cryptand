//! The value model of `02-value-encoding.md` §1.
//!
//! Integers are held as `(negative, magnitude: u128)` rather than as an
//! `i128`, because `|i128::MIN|` is 2^127 and the normalization of
//! `03-key-encoding.md` §4.1 is defined over the unsigned magnitude.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NumType {
    I8,
    I16,
    I32,
    I64,
    I128,
    U8,
    U16,
    U32,
    U64,
    U128,
    F32,
    F64,
    IntVar,
}

impl NumType {
    /// `03-key-encoding.md` §4.3.
    pub fn type_code(self) -> u8 {
        use NumType::*;
        match self {
            I8 => 0x00,
            I16 => 0x01,
            I32 => 0x02,
            I64 => 0x03,
            I128 => 0x04,
            U8 => 0x05,
            U16 => 0x06,
            U32 => 0x07,
            U64 => 0x08,
            U128 => 0x09,
            F32 => 0x0A,
            F64 => 0x0B,
            IntVar => 0x0C,
        }
    }

    pub fn from_type_code(c: u8) -> Option<NumType> {
        use NumType::*;
        Some(match c {
            0x00 => I8,
            0x01 => I16,
            0x02 => I32,
            0x03 => I64,
            0x04 => I128,
            0x05 => U8,
            0x06 => U16,
            0x07 => U32,
            0x08 => U64,
            0x09 => U128,
            0x0A => F32,
            0x0B => F64,
            0x0C => IntVar,
            _ => return None,
        })
    }

    pub fn is_float(self) -> bool {
        matches!(self, NumType::F32 | NumType::F64)
    }

    /// The name the conformance vectors use for this width.
    pub fn vector_name(self) -> &'static str {
        use NumType::*;
        match self {
            I8 => "i8",
            I16 => "i16",
            I32 => "i32",
            I64 => "i64",
            I128 => "i128",
            U8 => "u8",
            U16 => "u16",
            U32 => "u32",
            U64 => "u64",
            U128 => "u128",
            F32 => "f32",
            F64 => "f64",
            IntVar => "intVar",
        }
    }

    pub fn from_vector_name(s: &str) -> Option<NumType> {
        [
            NumType::I8,
            NumType::I16,
            NumType::I32,
            NumType::I64,
            NumType::I128,
            NumType::U8,
            NumType::U16,
            NumType::U32,
            NumType::U64,
            NumType::U128,
            NumType::F32,
            NumType::F64,
            NumType::IntVar,
        ]
        .into_iter()
        .find(|t| t.vector_name() == s)
    }
}

#[derive(Clone, Debug)]
pub enum Value {
    Null,
    Bool(bool),
    Int { w: NumType, neg: bool, mag: u128 },
    /// `w` is `F32` or `F64`; the value is exact in either case, because every
    /// f32 is an f64.
    Float { w: NumType, v: f64 },
    Dec128([u8; 16]),
    Char(u32),
    Str(String),
    Bytes(Vec<u8>),
    Timestamp(i64),
    TimestampNs(i64, u32),
    Zoned(i64, String),
    Date(i32),
    Time(u64),
    Duration(i64, u32),
    Uuid([u8; 16]),
    NitriteId(i64),
    Regex(String, String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    /// Field order is not part of the value; `cve::encode` sorts by name bytes
    /// as `02-value-encoding.md` §5.1 requires.
    Doc(Vec<(String, Value)>),
    VectorF32(Vec<f32>),
    Geometry(Vec<u8>),
    Opaque { origin: String, type_name: String, data: Vec<u8> },
    /// A reserved or implementation-private tag, preserved byte for byte
    /// (`02-value-encoding.md` §1.1).
    Unknown { tag: u8, payload: Vec<u8> },
}

impl Value {
    pub fn int(w: NumType, v: i128) -> Value {
        Value::Int { w, neg: v < 0, mag: v.unsigned_abs() }
    }

    pub fn f64(v: f64) -> Value {
        Value::Float { w: NumType::F64, v }
    }

    pub fn doc(fields: Vec<(&str, Value)>) -> Value {
        Value::Doc(fields.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    pub fn as_doc(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Doc(f) => Some(f),
            _ => None,
        }
    }

    pub fn field(&self, name: &str) -> Option<&Value> {
        self.as_doc()?.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }
}

/// Structural equality, used by the tests to check a decode round trip.
/// It is *not* `02-value-encoding.md` §8's logical equality — that one makes
/// `I32(5)` equal `F64(5.0)`, which would make a round-trip test vacuous.
impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        use Value::*;
        match (self, other) {
            (Null, Null) => true,
            (Bool(a), Bool(b)) => a == b,
            (Int { w: w1, neg: n1, mag: m1 }, Int { w: w2, neg: n2, mag: m2 }) => {
                // -0 and +0 are the same integer whatever the sign flag says.
                w1 == w2 && m1 == m2 && (n1 == n2 || *m1 == 0)
            }
            (Float { w: w1, v: v1 }, Float { w: w2, v: v2 }) => {
                w1 == w2 && (v1 == v2 || (v1.is_nan() && v2.is_nan()))
            }
            (Dec128(a), Dec128(b)) => a == b,
            (Char(a), Char(b)) => a == b,
            (Str(a), Str(b)) => a == b,
            (Bytes(a), Bytes(b)) => a == b,
            (Timestamp(a), Timestamp(b)) => a == b,
            (TimestampNs(a, b), TimestampNs(c, d)) => a == c && b == d,
            (Zoned(a, b), Zoned(c, d)) => a == c && b == d,
            (Date(a), Date(b)) => a == b,
            (Time(a), Time(b)) => a == b,
            (Duration(a, b), Duration(c, d)) => a == c && b == d,
            (Uuid(a), Uuid(b)) => a == b,
            (NitriteId(a), NitriteId(b)) => a == b,
            (Regex(a, b), Regex(c, d)) => a == c && b == d,
            (Array(a), Array(b)) => a == b,
            (Map(a), Map(b)) => a == b,
            (Doc(a), Doc(b)) => {
                let mut a = a.clone();
                let mut b = b.clone();
                a.sort_by(|x, y| x.0.as_bytes().cmp(y.0.as_bytes()));
                b.sort_by(|x, y| x.0.as_bytes().cmp(y.0.as_bytes()));
                a.len() == b.len()
                    && a.iter().zip(b.iter()).all(|(x, y)| x.0 == y.0 && x.1 == y.1)
            }
            (VectorF32(a), VectorF32(b)) => a == b,
            (Geometry(a), Geometry(b)) => a == b,
            (
                Opaque { origin: o1, type_name: t1, data: d1 },
                Opaque { origin: o2, type_name: t2, data: d2 },
            ) => o1 == o2 && t1 == t2 && d1 == d2,
            (Unknown { tag: t1, payload: p1 }, Unknown { tag: t2, payload: p2 }) => {
                t1 == t2 && p1 == p2
            }
            _ => false,
        }
    }
}
