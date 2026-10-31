//! Protobuf's wire format, as far as a splice needs it: the fields of a
//! message as they lie in its bytes, and a field written back.
//!
//! The graph ONNX Runtime is handed is the vendor's bytes with fields taken out
//! and added, and every field it keeps is copied as it was read — tag, length
//! and payload — so whatever the schema in `onnx` does not know survives as it
//! was.

/// One field of a message, as it lies.
pub(crate) struct Field<'a> {
    /// Its number.
    pub number: u32,
    /// The whole field, tag included: what a copy of it writes.
    pub raw: &'a [u8],
    /// The payload of a length-delimited field — a message, a string, a packed
    /// list; `None` for the other wire types.
    pub payload: Option<&'a [u8]>,
}

/// The bytes are not a protobuf message: a field runs past the end, a varint
/// past ten bytes, or a wire type is a group or unknown.
#[derive(Debug)]
pub(crate) struct Malformed;

/// The fields of `message`, in the order they lie.
pub(crate) fn fields(message: &[u8]) -> impl Iterator<Item = Result<Field<'_>, Malformed>> {
    let mut rest = message;
    let mut failed = false;
    std::iter::from_fn(move || {
        if rest.is_empty() || failed {
            return None;
        }
        let field = next(&mut rest);
        failed = field.is_err();
        Some(field)
    })
}

fn next<'a>(rest: &mut &'a [u8]) -> Result<Field<'a>, Malformed> {
    let start = *rest;
    let key = varint(rest)?;
    let number = u32::try_from(key >> 3)
        .ok()
        .filter(|&n| n != 0)
        .ok_or(Malformed)?;
    let payload = match key & 7 {
        0 => varint(rest).map(|_| None)?,
        1 => take(rest, 8).map(|_| None)?,
        2 => {
            let len = usize::try_from(varint(rest)?).map_err(|_| Malformed)?;
            Some(take(rest, len)?)
        }
        5 => take(rest, 4).map(|_| None)?,
        _ => return Err(Malformed),
    };
    let used = start.len() - rest.len();
    Ok(Field {
        number,
        raw: &start[..used],
        payload,
    })
}

fn take<'a>(rest: &mut &'a [u8], len: usize) -> Result<&'a [u8], Malformed> {
    if rest.len() < len {
        return Err(Malformed);
    }
    let (head, tail) = rest.split_at(len);
    *rest = tail;
    Ok(head)
}

fn varint(rest: &mut &[u8]) -> Result<u64, Malformed> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let (&byte, tail) = rest.split_first().ok_or(Malformed)?;
        *rest = tail;
        value |= u64::from(byte & 0x7f).checked_shl(shift).unwrap_or(0);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(Malformed)
}

/// Write a length-delimited field: `number`'s tag, `payload`'s length, then
/// `payload`.
pub(crate) fn put_delimited(out: &mut Vec<u8>, number: u32, payload: &[u8]) {
    put_varint(out, (u64::from(number) << 3) | 2);
    put_varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fields come back as they lie, each with its whole bytes, and a field
    /// written back reads as the same field.
    #[test]
    fn fields_read_as_they_lie_and_write_back() {
        let mut message = Vec::new();
        // field 1, varint 300; field 2, fixed64; field 3, a payload; field 4, fixed32
        message.extend_from_slice(&[0x08, 0xac, 0x02]);
        message.extend_from_slice(&[0x11, 1, 2, 3, 4, 5, 6, 7, 8]);
        put_delimited(&mut message, 3, b"abc");
        message.extend_from_slice(&[0x25, 9, 9, 9, 9]);

        let read: Vec<_> = fields(&message).collect::<Result<_, _>>().unwrap();
        let numbers: Vec<u32> = read.iter().map(|f| f.number).collect();
        assert_eq!(numbers, [1, 2, 3, 4]);
        assert_eq!(read[0].raw, [0x08, 0xac, 0x02]);
        assert_eq!(read[2].payload, Some(&b"abc"[..]));
        assert!(read[0].payload.is_none() && read[3].payload.is_none());
        let copied: Vec<u8> = read.iter().flat_map(|f| f.raw.iter().copied()).collect();
        assert_eq!(copied, message);
    }

    /// What is not a message stops the reading at the first bad field.
    #[test]
    fn what_is_not_a_message_is_malformed() {
        for bad in [
            &[0x1a, 0x05, b'a'][..], // a payload past the end
            &[0x08][..],             // a varint with no bytes
            &[0x0b][..],             // a group
            &[0x00, 0x00][..],       // field 0
            &[
                0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
            ][..], // eleven bytes
        ] {
            assert!(fields(bad).any(|f| f.is_err()), "{bad:x?}");
        }
        assert_eq!(
            fields(&[0x0b, 0x08, 0x01]).count(),
            1,
            "nothing after the first error"
        );
    }
}
