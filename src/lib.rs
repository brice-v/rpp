use std::str;

use anyhow::{anyhow, Error};

const DELIMETER: &str = "\r\n";
const PLUS: &str = "+";
const PLUS_BYTE: u8 = b'+';
const MINUS: &str = "-";
const MINUS_BYTE: u8 = b'-';
const DOLLAR: &str = "$";
const DOLLAR_BYTE: u8 = b'$';
const COLON: &str = ":";
const COLON_BYTE: u8 = b':';
const STAR: &str = "*";
const STAR_BYTE: u8 = b'*';

pub fn encode_bulk_string(s: Option<&str>) -> Vec<u8> {
    match s {
        Some(s) => format!("{}{}{}{}{}", DOLLAR, s.len(), DELIMETER, s, DELIMETER)
            .as_bytes()
            .to_vec(),
        None => format!("{}{}1{}", DOLLAR, MINUS, DELIMETER)
            .as_bytes()
            .to_vec(),
    }
}

pub fn encode_simple_string(s: &str) -> Vec<u8> {
    format!("{}{}{}", PLUS, s, DELIMETER).as_bytes().to_vec()
}

pub fn encode_error(s: &str) -> Vec<u8> {
    format!("{}{}{}", MINUS, s, DELIMETER).as_bytes().to_vec()
}

pub fn encode_integer(i: i128) -> Vec<u8> {
    format!("{}{}{}", COLON, i, DELIMETER).as_bytes().to_vec()
}

pub fn encode_array(elems: Vec<Vec<u8>>) -> Vec<u8> {
    let mut s = format!("{}{}{}", STAR, elems.len(), DELIMETER)
        .as_bytes()
        .to_vec();
    for e in elems.iter() {
        for c in e.iter() {
            s.push(*c);
        }
    }
    s
}

#[derive(Debug, PartialEq)]
pub enum RedisValue {
    SimpleString(String),
    BulkString(Option<String>),
    Error(String),
    Integer(i128),
    Array(Vec<RedisValue>),
}

fn check_delimeter(bs: &Vec<u8>) -> Result<bool, Error> {
    let len = bs.len();
    if len < 3 {
        return Err(anyhow!("invalid length {}", len));
    }
    let last_byte = bs[len - 1];
    let second_last_byte = bs[len - 2];
    if last_byte != b'\n' {
        return Err(anyhow!("last byte was not \\n, got {:?}", last_byte));
    }
    if second_last_byte != b'\r' {
        return Err(anyhow!(
            "second to last byte was not \\r, got {:?}",
            second_last_byte
        ));
    }
    return Ok(true);
}

fn get_number_after_first_byte(bs: &Vec<u8>) -> Result<(i128, usize), Error> {
    let len = bs.len();
    let mut ibuf: Vec<u8> = vec![];
    let mut cur: usize = 1;
    for b in &bs[1..len] {
        let c = *b;
        if c == b'\r' {
            // cur += 1;
            break;
        }
        ibuf.push(c);
        cur += 1;
    }
    if cur + 1 > len {
        return Err(anyhow!(
            "get_number_after_first_byte: error trying to get length of bulk string. cur+1 > len ({}) > ({})",
            cur + 1,
            len
        ));
    }
    if bs[cur + 1] != b'\n' {
        return Err(anyhow!(
            "get_number_after_first_byte: byte at cursor was not \\n. got {:?}",
            bs[cur + 1]
        ));
    }
    // for the \r\n
    cur += 2;

    match str::from_utf8(&ibuf) {
        Ok(s) => match s.parse::<i128>() {
            Ok(i) => return Ok((i, cur)),
            Err(e) => {
                return Err(anyhow!(
                    "get_number_after_first_byte: bytes were not i128. error: {}",
                    e
                ));
            }
        },
        Err(e) => {
            return Err(anyhow!(
                "get_number_after_first_byte: bytes were not utf-8. error: {}",
                e
            ));
        }
    }
}

fn decode_simple_string(bs: Vec<u8>) -> Result<RedisValue, Error> {
    // assert last 2 bytes are \r\n
    let ok = check_delimeter(&bs)?;
    if !ok {
        return Err(anyhow!(
            "decode_simple_string: this error should not be reached"
        ));
    }
    let len = bs.len();
    let buf = &bs[1..len - 2];
    match str::from_utf8(buf) {
        Ok(s) => {
            return Ok(RedisValue::SimpleString(s.to_owned()));
        }
        Err(e) => {
            return Err(anyhow!(
                "decode_simple_string: simple string bytes were not utf-8. error: {}",
                e
            ));
        }
    }
}

fn decode_bulk_string(bs: Vec<u8>) -> Result<RedisValue, Error> {
    // assert last 2 bytes are \r\n
    let ok = check_delimeter(&bs)?;
    if !ok {
        return Err(anyhow!(
            "decode_simple_string: this error should not be reached"
        ));
    }
    let (bulk_string_len, index_after_len) = get_number_after_first_byte(&bs)?;

    let is_null_bulk_string = bulk_string_len == -1;
    let bulk_string_len: usize = match bulk_string_len.try_into() {
        Ok(i) => i,
        Err(_) => 0,
    };
    let buf = &bs[index_after_len..index_after_len + bulk_string_len];
    match str::from_utf8(buf) {
        Ok(s) => {
            if s.len() != bulk_string_len {
                return Err(anyhow!(
                    "decode_bulk_string: bulk string len ({}) did not match expected ({}).",
                    s.len(),
                    bulk_string_len
                ));
            }
            if is_null_bulk_string {
                return Ok(RedisValue::BulkString(None));
            }
            return Ok(RedisValue::BulkString(Some(s.to_owned())));
        }
        Err(e) => {
            return Err(anyhow!(
                "decode_bulk_string: bulk string bytes were not utf-8. error: {}",
                e
            ));
        }
    }
}

fn decode_error(bs: Vec<u8>) -> Result<RedisValue, Error> {
    // assert last 2 bytes are \r\n
    let ok = check_delimeter(&bs)?;
    if !ok {
        return Err(anyhow!("decode_error: this error should not be reached"));
    }
    let len = bs.len();
    let buf = &bs[1..len - 2];
    match str::from_utf8(buf) {
        Ok(s) => {
            return Ok(RedisValue::Error(s.to_owned()));
        }
        Err(e) => {
            return Err(anyhow!(
                "decode_error: error string bytes were not utf-8. error: {}",
                e
            ));
        }
    }
}

fn decode_integer(bs: Vec<u8>) -> Result<RedisValue, Error> {
    todo!("implement: decode_integer");
}

fn decode_array(bs: Vec<u8>) -> Result<RedisValue, Error> {
    todo!("implement: decode_array");
}

pub fn decode(bs: Vec<u8>) -> Result<RedisValue, Error> {
    if let Some(b) = bs.get(0) {
        match *b {
            PLUS_BYTE => {
                return decode_simple_string(bs);
            }
            DOLLAR_BYTE => {
                return decode_bulk_string(bs);
            }
            MINUS_BYTE => {
                return decode_error(bs);
            }
            COLON_BYTE => {
                return decode_integer(bs);
            }
            STAR_BYTE => {
                return decode_array(bs);
            }
            _ => {
                return Err(anyhow!("first byte was not +-:$*"));
            }
        }
    }
    todo!("PANIC");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_simple_string_test() {
        let result = encode_simple_string("ok");
        assert_eq!(result, vec![b'+', b'o', b'k', b'\r', b'\n']);
    }

    #[test]
    fn encode_error_test() {
        let result = encode_error("Err: Invalid Thing");
        assert_eq!(
            result,
            vec![
                b'-', b'E', b'r', b'r', b':', b' ', b'I', b'n', b'v', b'a', b'l', b'i', b'd', b' ',
                b'T', b'h', b'i', b'n', b'g', b'\r', b'\n'
            ]
        );
    }

    #[test]
    fn encode_bulk_string_test() {
        let result = encode_bulk_string(Some("Hello\n World!"));
        assert_eq!(
            result,
            vec![
                b'$', b'1', b'3', b'\r', b'\n', b'H', b'e', b'l', b'l', b'o', b'\n', b' ', b'W',
                b'o', b'r', b'l', b'd', b'!', b'\r', b'\n'
            ]
        );
        let result = encode_bulk_string(Some(""));
        assert_eq!(result, vec![b'$', b'0', b'\r', b'\n', b'\r', b'\n']);
        let result = encode_bulk_string(None);
        assert_eq!(result, vec![b'$', b'-', b'1', b'\r', b'\n']);
    }

    #[test]
    fn encode_integer_test() {
        let result = encode_integer(120);
        assert_eq!(result, vec![b':', b'1', b'2', b'0', b'\r', b'\n']);
    }

    #[test]
    fn encode_array_test() {
        let to_encode = vec![encode_simple_string("ok"), encode_integer(120)];
        let result = encode_array(to_encode);
        assert_eq!(
            result,
            vec![
                b'*', b'2', b'\r', b'\n', b'+', b'o', b'k', b'\r', b'\n', b':', b'1', b'2', b'0',
                b'\r', b'\n'
            ]
        );
    }

    #[test]
    fn decode_simple_string_test() {
        let result =
            decode(vec![b'+', b'o', b'k', b'\r', b'\n']).expect("Simple String should decode");
        let expected = RedisValue::SimpleString("ok".into());
        assert_eq!(result, expected);

        let result = decode(encode_simple_string("ok"))
            .expect("Simple String should decode from encoded simple string");
        assert_eq!(result, expected);
    }

    #[test]
    fn decode_error_test() {
        let result =
            decode(vec![b'-', b'e', b'r', b'r', b'\r', b'\n']).expect("Error should decode");
        let expected = RedisValue::Error("err".into());
        assert_eq!(result, expected);

        let result = decode(encode_error("err")).expect("Error should decode from encoded error");
        assert_eq!(result, expected);
    }

    #[test]
    fn decode_bulk_string_test() {
        let result = decode(vec![
            b'$', b'5', b'\r', b'\n', b'h', b'e', b'l', b'l', b'o', b'\r', b'\n',
        ])
        .expect("Bulk String should decode");
        let expected = RedisValue::BulkString(Some("hello".into()));
        assert_eq!(result, expected);

        let result = decode(encode_bulk_string(Some("Hello There!")))
            .expect("Bulk String should be decoded from encoded value");
        let expected = RedisValue::BulkString(Some("Hello There!".into()));
        assert_eq!(result, expected);

        let result = decode(encode_bulk_string(Some("".into())))
            .expect("should be able to decode encoded empty bulk string");
        let expected = RedisValue::BulkString(Some("".into()));
        assert_eq!(result, expected);

        let result = decode(encode_bulk_string(None))
            .expect("should be able to decode encoded null bulk string");
        let expected = RedisValue::BulkString(None);
        assert_eq!(result, expected);
    }
}
