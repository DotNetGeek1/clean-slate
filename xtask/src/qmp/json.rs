//! Bounded JSON value, parser and writer for QMP traffic.

pub(crate) const MAX_DEPTH: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum JsonValue {
    Null,
    Bool(bool),
    Number(JsonNumber),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

/// A validated RFC 8259 number lexeme, kept verbatim (no float arithmetic).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct JsonNumber(String);

impl JsonNumber {
    pub(crate) fn lexeme(&self) -> &str {
        &self.0
    }

    pub(crate) fn as_i64(&self) -> Option<i64> {
        let s = &self.0;
        if s.contains('.') || s.contains('e') || s.contains('E') {
            return None;
        }
        parse_i64_lexeme(s)
    }

    pub(crate) fn as_u64(&self) -> Option<u64> {
        let s = &self.0;
        if s.contains('.') || s.contains('e') || s.contains('E') {
            return None;
        }
        if s.starts_with('-') {
            return None;
        }
        parse_u64_lexeme(s)
    }
}

fn parse_i64_lexeme(s: &str) -> Option<i64> {
    if s.is_empty() {
        return None;
    }
    let (sign, digits) = if let Some(rest) = s.strip_prefix('-') {
        (-1i64, rest)
    } else {
        (1, s)
    };
    if digits.is_empty() {
        return None;
    }
    let mut value: u64 = 0;
    for b in digits.bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
    }
    if sign < 0 {
        if value > i64::MAX as u64 + 1 {
            return None;
        }
        if value == i64::MAX as u64 + 1 {
            Some(i64::MIN)
        } else {
            Some(-(value as i64))
        }
    } else {
        (value <= i64::MAX as u64).then_some(value as i64)
    }
}

fn parse_u64_lexeme(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut value: u64 = 0;
    for b in s.bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
    }
    Some(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JsonErrorKind {
    UnexpectedEnd,
    UnexpectedByte(u8),
    InvalidNumber,
    InvalidEscape,
    LoneSurrogate,
    ControlCharacter,
    DuplicateKey,
    DepthExceeded,
    TrailingCharacters,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct JsonError {
    pub(crate) offset: usize,
    pub(crate) kind: JsonErrorKind,
}

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            JsonErrorKind::UnexpectedEnd => write!(f, "unexpected end at byte {}", self.offset),
            JsonErrorKind::UnexpectedByte(b) => {
                write!(f, "unexpected byte 0x{b:02x} at byte {}", self.offset)
            }
            JsonErrorKind::InvalidNumber => write!(f, "invalid number at byte {}", self.offset),
            JsonErrorKind::InvalidEscape => write!(f, "invalid escape at byte {}", self.offset),
            JsonErrorKind::LoneSurrogate => write!(f, "lone surrogate at byte {}", self.offset),
            JsonErrorKind::ControlCharacter => {
                write!(f, "control character at byte {}", self.offset)
            }
            JsonErrorKind::DuplicateKey => write!(f, "duplicate key at byte {}", self.offset),
            JsonErrorKind::DepthExceeded => write!(f, "depth exceeded at byte {}", self.offset),
            JsonErrorKind::TrailingCharacters => {
                write!(f, "trailing characters at byte {}", self.offset)
            }
        }
    }
}

pub(crate) fn parse(text: &str) -> Result<JsonValue, JsonError> {
    let mut p = Parser::new(text);
    let value = p.parse_value()?;
    p.skip_whitespace();
    if p.offset < p.bytes.len() {
        return Err(p.err(JsonErrorKind::TrailingCharacters));
    }
    Ok(value)
}

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    offset: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            bytes: text.as_bytes(),
            offset: 0,
            depth: 0,
        }
    }

    fn err(&self, kind: JsonErrorKind) -> JsonError {
        JsonError {
            offset: self.offset,
            kind,
        }
    }

    fn err_at(&self, offset: usize, kind: JsonErrorKind) -> JsonError {
        JsonError { offset, kind }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.offset += 1;
        Some(b)
    }

    fn skip_whitespace(&mut self) {
        while matches!(
            self.peek(),
            Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r')
        ) {
            self.offset += 1;
        }
    }

    fn parse_value(&mut self) -> Result<JsonValue, JsonError> {
        self.skip_whitespace();
        let Some(b) = self.peek() else {
            return Err(self.err(JsonErrorKind::UnexpectedEnd));
        };
        match b {
            b'n' => self.parse_literal("null", JsonValue::Null),
            b't' => self.parse_literal("true", JsonValue::Bool(true)),
            b'f' => self.parse_literal("false", JsonValue::Bool(false)),
            b'"' => self.parse_string().map(JsonValue::String),
            b'[' => self.parse_array(),
            b'{' => self.parse_object(),
            b'-' | b'0'..=b'9' => self.parse_number().map(JsonValue::Number),
            _ => Err(self.err(JsonErrorKind::UnexpectedByte(b))),
        }
    }

    fn parse_literal(&mut self, word: &str, value: JsonValue) -> Result<JsonValue, JsonError> {
        for expected in word.bytes() {
            match self.bump() {
                Some(b) if b == expected => {}
                Some(b) => {
                    return Err(JsonError {
                        offset: self.offset - 1,
                        kind: JsonErrorKind::UnexpectedByte(b),
                    });
                }
                None => {
                    return Err(JsonError {
                        offset: self.bytes.len(),
                        kind: JsonErrorKind::UnexpectedEnd,
                    });
                }
            }
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<JsonNumber, JsonError> {
        let start = self.offset;
        if self.peek() == Some(b'-') {
            self.bump();
        }
        match self.peek() {
            Some(b'0') => {
                self.bump();
                if self.peek().is_some_and(|b| b.is_ascii_digit()) {
                    return Err(self.err_at(start, JsonErrorKind::InvalidNumber));
                }
            }
            Some(b'1'..=b'9') => {
                self.bump();
                while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                    self.bump();
                }
            }
            Some(_) => {
                return Err(JsonError {
                    offset: self.offset - 1,
                    kind: JsonErrorKind::InvalidNumber,
                });
            }
            None => return Err(self.err_at(start, JsonErrorKind::InvalidNumber)),
        }

        if self.peek() == Some(b'.') {
            self.bump();
            if !self.peek().is_some_and(|b| b.is_ascii_digit()) {
                return Err(self.err_at(start, JsonErrorKind::InvalidNumber));
            }
            while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                self.bump();
            }
        }

        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.bump();
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.bump();
            }
            if !self.peek().is_some_and(|b| b.is_ascii_digit()) {
                return Err(self.err_at(start, JsonErrorKind::InvalidNumber));
            }
            while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                self.bump();
            }
        }

        let lexeme = std::str::from_utf8(&self.bytes[start..self.offset])
            .map_err(|_| self.err_at(start, JsonErrorKind::InvalidNumber))?;
        Ok(JsonNumber(lexeme.to_owned()))
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        let _quote = self.offset;
        if self.bump() != Some(b'"') {
            return Err(self.err(JsonErrorKind::UnexpectedByte(b'"')));
        }
        let mut out = String::new();
        loop {
            let Some(b) = self.bump() else {
                return Err(JsonError {
                    offset: self.bytes.len(),
                    kind: JsonErrorKind::UnexpectedEnd,
                });
            };
            match b {
                b'"' => return Ok(out),
                b'\\' => out.push(self.parse_escape()?),
                0x00..=0x1f => return Err(self.err(JsonErrorKind::ControlCharacter)),
                0x20..=0x7f => out.push(char::from(b)),
                _ => {
                    let start = self.offset - 1;
                    let ch = self
                        .text
                        .get(start..)
                        .and_then(|rest| rest.chars().next())
                        .ok_or(JsonError {
                            offset: start,
                            kind: JsonErrorKind::UnexpectedByte(b),
                        })?;
                    self.offset = start + ch.len_utf8();
                    out.push(ch);
                }
            }
        }
    }

    fn parse_escape(&mut self) -> Result<char, JsonError> {
        let esc = self.offset;
        let Some(b) = self.bump() else {
            return Err(JsonError {
                offset: esc,
                kind: JsonErrorKind::UnexpectedEnd,
            });
        };
        match b {
            b'"' => Ok('"'),
            b'\\' => Ok('\\'),
            b'/' => Ok('/'),
            b'b' => Ok('\u{8}'),
            b'f' => Ok('\u{c}'),
            b'n' => Ok('\n'),
            b'r' => Ok('\r'),
            b't' => Ok('\t'),
            b'u' => self.parse_unicode_escape(),
            _ => Err(JsonError {
                offset: esc,
                kind: JsonErrorKind::InvalidEscape,
            }),
        }
    }

    fn parse_unicode_escape(&mut self) -> Result<char, JsonError> {
        let u_off = self.offset - 1;
        let code = self.parse_hex4()?;
        if (0xD800..=0xDBFF).contains(&code) {
            if self.peek() != Some(b'\\') {
                return Err(JsonError {
                    offset: u_off,
                    kind: JsonErrorKind::LoneSurrogate,
                });
            }
            self.bump();
            if self.bump() != Some(b'u') {
                return Err(JsonError {
                    offset: u_off,
                    kind: JsonErrorKind::LoneSurrogate,
                });
            }
            let low = self.parse_hex4()?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(JsonError {
                    offset: u_off,
                    kind: JsonErrorKind::LoneSurrogate,
                });
            }
            let combined = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
            char::from_u32(combined).ok_or(JsonError {
                offset: u_off,
                kind: JsonErrorKind::LoneSurrogate,
            })
        } else if (0xDC00..=0xDFFF).contains(&code) {
            Err(JsonError {
                offset: u_off,
                kind: JsonErrorKind::LoneSurrogate,
            })
        } else {
            char::from_u32(code).ok_or(JsonError {
                offset: u_off,
                kind: JsonErrorKind::InvalidEscape,
            })
        }
    }

    fn parse_hex4(&mut self) -> Result<u32, JsonError> {
        let start = self.offset;
        let mut value: u32 = 0;
        for _ in 0..4 {
            let Some(b) = self.bump() else {
                return Err(JsonError {
                    offset: start,
                    kind: JsonErrorKind::InvalidEscape,
                });
            };
            let digit = match b {
                b'0'..=b'9' => u32::from(b - b'0'),
                b'a'..=b'f' => u32::from(b - b'a') + 10,
                b'A'..=b'F' => u32::from(b - b'A') + 10,
                _ => {
                    return Err(JsonError {
                        offset: self.offset - 1,
                        kind: JsonErrorKind::InvalidEscape,
                    });
                }
            };
            value = value * 16 + digit;
        }
        Ok(value)
    }

    fn parse_array(&mut self) -> Result<JsonValue, JsonError> {
        if self.depth >= MAX_DEPTH {
            return Err(self.err(JsonErrorKind::DepthExceeded));
        }
        self.depth += 1;
        if self.bump() != Some(b'[') {
            self.depth -= 1;
            return Err(self.err(JsonErrorKind::UnexpectedByte(b'[')));
        }
        self.skip_whitespace();
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.bump();
            self.depth -= 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_whitespace();
            match self.bump() {
                Some(b']') => {
                    self.depth -= 1;
                    return Ok(JsonValue::Array(items));
                }
                Some(b',') => {
                    self.skip_whitespace();
                    if self.peek() == Some(b']') {
                        return Err(self.err(JsonErrorKind::UnexpectedByte(b']')));
                    }
                }
                Some(b) => {
                    self.depth -= 1;
                    return Err(JsonError {
                        offset: self.offset - 1,
                        kind: JsonErrorKind::UnexpectedByte(b),
                    });
                }
                None => {
                    self.depth -= 1;
                    return Err(JsonError {
                        offset: self.bytes.len(),
                        kind: JsonErrorKind::UnexpectedEnd,
                    });
                }
            }
        }
    }

    fn parse_object(&mut self) -> Result<JsonValue, JsonError> {
        if self.depth >= MAX_DEPTH {
            return Err(self.err(JsonErrorKind::DepthExceeded));
        }
        self.depth += 1;
        if self.bump() != Some(b'{') {
            self.depth -= 1;
            return Err(self.err(JsonErrorKind::UnexpectedByte(b'{')));
        }
        self.skip_whitespace();
        let mut entries = Vec::new();
        let mut keys = std::collections::HashSet::new();
        if self.peek() == Some(b'}') {
            self.bump();
            self.depth -= 1;
            return Ok(JsonValue::Object(entries));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                self.depth -= 1;
                let off = self.offset;
                return Err(match self.peek() {
                    Some(b) => JsonError {
                        offset: off,
                        kind: JsonErrorKind::UnexpectedByte(b),
                    },
                    None => JsonError {
                        offset: self.bytes.len(),
                        kind: JsonErrorKind::UnexpectedEnd,
                    },
                });
            }
            let key_start = self.offset;
            let key = self.parse_string()?;
            if !keys.insert(key.clone()) {
                self.depth -= 1;
                return Err(JsonError {
                    offset: key_start + 1,
                    kind: JsonErrorKind::DuplicateKey,
                });
            }
            self.skip_whitespace();
            if self.bump() != Some(b':') {
                self.depth -= 1;
                return Err(match self.peek() {
                    Some(b) => JsonError {
                        offset: self.offset,
                        kind: JsonErrorKind::UnexpectedByte(b),
                    },
                    None => JsonError {
                        offset: self.bytes.len(),
                        kind: JsonErrorKind::UnexpectedEnd,
                    },
                });
            }
            let val = self.parse_value()?;
            entries.push((key, val));
            self.skip_whitespace();
            match self.bump() {
                Some(b'}') => {
                    self.depth -= 1;
                    return Ok(JsonValue::Object(entries));
                }
                Some(b',') => {
                    self.skip_whitespace();
                    if self.peek() == Some(b'}') {
                        return Err(self.err(JsonErrorKind::UnexpectedByte(b'}')));
                    }
                }
                Some(b) => {
                    self.depth -= 1;
                    return Err(JsonError {
                        offset: self.offset - 1,
                        kind: JsonErrorKind::UnexpectedByte(b),
                    });
                }
                None => {
                    self.depth -= 1;
                    return Err(JsonError {
                        offset: self.bytes.len(),
                        kind: JsonErrorKind::UnexpectedEnd,
                    });
                }
            }
        }
    }
}

impl JsonValue {
    pub(crate) fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub(crate) fn as_i64(&self) -> Option<i64> {
        match self {
            JsonValue::Number(n) => n.as_i64(),
            _ => None,
        }
    }

    pub(crate) fn as_u64(&self) -> Option<u64> {
        match self {
            JsonValue::Number(n) => n.as_u64(),
            _ => None,
        }
    }

    pub(crate) fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            JsonValue::Array(a) => Some(a),
            _ => None,
        }
    }

    pub(crate) fn as_object(&self) -> Option<&[(String, JsonValue)]> {
        match self {
            JsonValue::Object(o) => Some(o),
            _ => None,
        }
    }

    pub(crate) fn object<'a>(entries: impl IntoIterator<Item = (&'a str, JsonValue)>) -> JsonValue {
        JsonValue::Object(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v))
                .collect(),
        )
    }

    pub(crate) fn str(value: impl Into<String>) -> JsonValue {
        JsonValue::String(value.into())
    }

    pub(crate) fn int(value: i64) -> JsonValue {
        JsonValue::Number(JsonNumber(value.to_string()))
    }

    pub(crate) fn to_json(&self) -> String {
        let mut out = String::new();
        self.write_json(&mut out);
        out
    }

    fn write_json(&self, out: &mut String) {
        match self {
            JsonValue::Null => out.push_str("null"),
            JsonValue::Bool(true) => out.push_str("true"),
            JsonValue::Bool(false) => out.push_str("false"),
            JsonValue::Number(n) => out.push_str(n.lexeme()),
            JsonValue::String(s) => {
                out.push('"');
                write_string_body(out, s);
                out.push('"');
            }
            JsonValue::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_json(out);
                }
                out.push(']');
            }
            JsonValue::Object(entries) => {
                out.push('{');
                for (i, (k, v)) in entries.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push('"');
                    write_string_body(out, k);
                    out.push('"');
                    out.push(':');
                    v.write_json(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_string_body(out: &mut String, s: &str) {
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u00");
                let hex = format!("{:02x}", c as u32);
                out.push_str(&hex);
            }
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_compact() {
        let v = parse(r#" { "a" : [1, -2, true, false, null, "x"], "b": {} } "#).unwrap();
        assert_eq!(v.to_json(), r#"{"a":[1,-2,true,false,null,"x"],"b":{}}"#);
    }

    #[test]
    fn object_key_order() {
        let v = parse(r#"{"z":1,"a":2}"#).unwrap();
        assert_eq!(v.to_json(), r#"{"z":1,"a":2}"#);
    }

    #[test]
    fn duplicate_key_offset() {
        let err = parse(r#"{"a":1,"a":2}"#).unwrap_err();
        assert_eq!(err.kind, JsonErrorKind::DuplicateKey);
        assert_eq!(err.offset, 8);
    }

    #[test]
    fn depth_32_ok_33_exceeded() {
        let mut s = String::new();
        for _ in 0..32 {
            s.push('[');
        }
        s.push('1');
        for _ in 0..32 {
            s.push(']');
        }
        parse(&s).unwrap();

        let mut deep = String::new();
        for _ in 0..33 {
            deep.push('[');
        }
        deep.push('1');
        for _ in 0..33 {
            deep.push(']');
        }
        assert_eq!(parse(&deep).unwrap_err().kind, JsonErrorKind::DepthExceeded);

        let mut obj = String::new();
        obj.push('{');
        for _ in 0..31 {
            obj.push_str(r#""a":{"#);
        }
        obj.push_str(r#""v":1"#);
        for _ in 0..32 {
            obj.push('}');
        }
        parse(&obj).unwrap();

        let mut obj_deep = String::new();
        obj_deep.push('{');
        for _ in 0..32 {
            obj_deep.push_str(r#""a":{"#);
        }
        obj_deep.push_str(r#""v":1"#);
        for _ in 0..33 {
            obj_deep.push('}');
        }
        assert_eq!(
            parse(&obj_deep).unwrap_err().kind,
            JsonErrorKind::DepthExceeded
        );
    }

    #[test]
    fn string_escapes() {
        assert_eq!(parse(r#""\u00e9""#).unwrap().as_str().unwrap(), "é");
        assert_eq!(parse(r#""\ud83d\ude00""#).unwrap().as_str().unwrap(), "😀");
        assert_eq!(
            parse(r#""\ud83d""#).unwrap_err().kind,
            JsonErrorKind::LoneSurrogate
        );
        assert_eq!(
            parse(r#""\ude00""#).unwrap_err().kind,
            JsonErrorKind::LoneSurrogate
        );
        assert_eq!(
            parse(r#""\x""#).unwrap_err().kind,
            JsonErrorKind::InvalidEscape
        );
        assert_eq!(
            parse(r#""\u12G4""#).unwrap_err().kind,
            JsonErrorKind::InvalidEscape
        );
    }

    #[test]
    fn raw_utf8_and_long_strings_parse_in_one_pass() {
        assert_eq!(
            parse("\"h\u{e9}llo \u{1f600}\"").unwrap().as_str(),
            Some("h\u{e9}llo \u{1f600}")
        );
        let long = format!("\"{}\"", "\u{e9}a".repeat(128 * 1024));
        let parsed = parse(&long).unwrap();
        assert_eq!(parsed.as_str().map(str::len), Some(3 * 128 * 1024));
        let many_keys = format!(
            "{{{}}}",
            (0..20_000)
                .map(|i| format!("\"k{i}\":{i}"))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(
            parse(&many_keys).unwrap().as_object().map(<[_]>::len),
            Some(20_000)
        );
    }

    #[test]
    fn control_character_in_string() {
        assert_eq!(
            parse("\" \u{1f} \"").unwrap_err().kind,
            JsonErrorKind::ControlCharacter
        );
    }

    #[test]
    fn number_validation() {
        for bad in ["01", "1.", ".5", "+1", "-", "1e", "1e+"] {
            let err = parse(bad).unwrap_err();
            assert!(
                matches!(
                    err.kind,
                    JsonErrorKind::InvalidNumber | JsonErrorKind::UnexpectedByte(_)
                ),
                "bad={bad:?} kind={:?}",
                err.kind
            );
        }
        assert_eq!(
            parse("+1").unwrap_err().kind,
            JsonErrorKind::UnexpectedByte(b'+')
        );

        for (lex, _) in [
            ("-0", "-0"),
            ("0", "0"),
            ("1e5", "1e5"),
            ("1.5e-3", "1.5e-3"),
            ("-12.25E+2", "-12.25E+2"),
        ] {
            let v = parse(lex).unwrap();
            assert!(v.as_object().is_none());
            if let JsonValue::Number(n) = v {
                assert_eq!(n.lexeme(), lex);
            } else {
                panic!("expected number");
            }
        }
        let n1 = parse("1e5").unwrap();
        assert_eq!(n1.as_i64(), None);
        let n2 = parse("1.5e-3").unwrap();
        assert_eq!(n2.as_i64(), None);
        assert_eq!(
            parse("-9223372036854775808").unwrap().as_i64(),
            Some(i64::MIN)
        );
        let big = parse("9223372036854775808").unwrap();
        assert_eq!(big.as_i64(), None);
        assert_eq!(big.as_u64(), Some(9223372036854775808));
        assert_eq!(parse("-1").unwrap().as_u64(), None);
        assert_eq!(parse("-0").unwrap().as_i64(), Some(0));
        assert_eq!(parse("-0").unwrap().as_u64(), None);
    }

    #[test]
    fn syntax_errors() {
        let err = parse("{} x").unwrap_err();
        assert_eq!(err.kind, JsonErrorKind::TrailingCharacters);
        assert_eq!(err.offset, 3);
        assert_eq!(
            parse("[1,]").unwrap_err().kind,
            JsonErrorKind::UnexpectedByte(b']')
        );
        assert_eq!(
            parse(r#"{"a":1,}"#).unwrap_err().kind,
            JsonErrorKind::UnexpectedByte(b'}')
        );
        for s in [r#"""#, "[", "{", "tru"] {
            let err = parse(s).unwrap_err();
            assert_eq!(err.kind, JsonErrorKind::UnexpectedEnd);
            assert_eq!(err.offset, s.len());
        }
        assert!(matches!(
            parse(r#"{"a" 1}"#).unwrap_err().kind,
            JsonErrorKind::UnexpectedByte(_) | JsonErrorKind::UnexpectedEnd
        ));
        assert!(matches!(
            parse("{1:2}").unwrap_err().kind,
            JsonErrorKind::UnexpectedByte(_)
        ));
    }

    #[test]
    fn writer_escaping_golden() {
        let mut s = String::new();
        s.push('"');
        s.push('\\');
        s.push('\n');
        s.push('\u{1}');
        s.push('\t');
        s.push_str(r"C:\Users\a b\x.ppm");
        let v = JsonValue::String(s.clone());
        let expected = concat!(
            "\"",
            "\\\"",
            "\\\\",
            "\\n",
            "\\u0001",
            "\\t",
            "C:\\\\Users\\\\a b\\\\x.ppm",
            "\"",
        );
        assert_eq!(v.to_json(), expected);
        assert_eq!(parse(expected).unwrap(), v);
    }

    #[test]
    fn accessors_and_builder() {
        assert_eq!(JsonValue::Null.get("x"), None);
        assert_eq!(JsonValue::str("hi").as_str(), Some("hi"));
        assert_eq!(JsonValue::Bool(true).as_bool(), Some(true));
        assert_eq!(JsonValue::int(3).as_i64(), Some(3));
        assert_eq!(
            JsonValue::object([
                ("execute", JsonValue::str("quit")),
                ("id", JsonValue::str("xtask-1")),
            ])
            .to_json(),
            r#"{"execute":"quit","id":"xtask-1"}"#
        );
    }
}
