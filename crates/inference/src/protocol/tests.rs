use super::*;

fn tensor(dims: &[u64]) -> Tensor {
    let n = dims.iter().product::<u64>() as usize;
    Tensor {
        dims: dims.to_vec(),
        data: Data::F32((0..n).map(|i| i as f32 * 0.5).collect()),
    }
}

/// A request and both kinds of answer read back as they were written, each
/// tensor in its own element type.
#[test]
fn messages_read_back_as_written() {
    let request = Request {
        model: 7,
        inputs: vec![
            tensor(&[1, 3, 4, 4]),
            tensor(&[]),
            tensor(&[2, 0]),
            Tensor {
                dims: vec![3],
                data: Data::U8(vec![1, 2, 255]),
            },
            Tensor {
                dims: vec![2],
                data: Data::I64(vec![-1, i64::MAX]),
            },
            Tensor {
                dims: vec![1],
                data: Data::F16(vec![0x3c00]),
            },
        ],
    };
    let mut wire = Vec::new();
    write_request(&mut wire, &request).unwrap();
    assert_eq!(read_request(&mut &wire[..]).unwrap(), Some(request));

    for answer in [Ok(vec![tensor(&[1, 3])]), Err(Failure::Inputs)] {
        let mut wire = Vec::new();
        write_answer(&mut wire, &answer).unwrap();
        assert_eq!(read_answer(&mut &wire[..]).unwrap(), answer);
    }
}

/// The other end closing before a request is the end of the conversation,
/// not an error; closing inside one is.
#[test]
fn a_close_between_requests_ends_and_one_inside_fails() {
    assert!(read_request(&mut &[][..]).unwrap().is_none());
    let mut wire = Vec::new();
    write_request(
        &mut wire,
        &Request {
            model: 0,
            inputs: vec![tensor(&[4])],
        },
    )
    .unwrap();
    for cut in [2, 6, 10, wire.len() - 1] {
        assert!(read_request(&mut &wire[..cut]).is_err(), "cut at {cut}");
    }
}

/// A request of one tensor's head: its element type, rank and dimensions.
fn with_tensor(element: i32, rank: u32, dims: &[u64]) -> Vec<u8> {
    let mut wire = 0u32.to_le_bytes().to_vec();
    wire.extend_from_slice(&1u32.to_le_bytes());
    wire.extend_from_slice(&element.to_le_bytes());
    wire.extend_from_slice(&rank.to_le_bytes());
    for d in dims {
        wire.extend_from_slice(&d.to_le_bytes());
    }
    wire
}

/// Counts, ranks and sizes past the bounds are refused before anything is
/// allocated for them — a message claiming a huge tensor is a few bytes.
#[test]
fn bounds_hold_before_anything_is_allocated() {
    let mut too_many = 0u32.to_le_bytes().to_vec();
    too_many.extend_from_slice(&(MAX_TENSORS + 1).to_le_bytes());
    let f32 = Element::F32.code();
    let too_deep = with_tensor(f32, MAX_RANK + 1, &[]);
    let too_large = with_tensor(f32, 2, &[MAX_BYTES / 4, 2]);
    // As many elements as the bound holds bytes, but of eight bytes each.
    let too_wide = with_tensor(Element::I64.code(), 1, &[MAX_BYTES / 4]);
    let overflowing = with_tensor(f32, 3, &[u64::MAX, u64::MAX, 2]);
    for wire in [too_many, too_deep, too_large, too_wide, overflowing] {
        assert!(matches!(
            read_request(&mut &wire[..]),
            Err(ProtocolError::Bounds)
        ));
    }
}

/// An element type no tensor has — a string, a bool, a number nothing is — is
/// refused as such.
#[test]
fn an_element_type_that_is_none_is_refused() {
    for code in [0, 8, 9, 99] {
        assert!(matches!(
            read_request(&mut &with_tensor(code, 1, &[1])[..]),
            Err(ProtocolError::Element(c)) if c == code
        ));
    }
}

/// The bound is on the message, not each tensor: two that fit alone may not
/// fit together.
#[test]
fn the_bytes_bound_is_the_whole_messages() {
    let half = MAX_BYTES / 2 / 4 + 1;
    let mut wire = 0u32.to_le_bytes().to_vec();
    wire.extend_from_slice(&2u32.to_le_bytes());
    for at in 0..2 {
        wire.extend_from_slice(&Element::F32.code().to_le_bytes());
        wire.extend_from_slice(&1u32.to_le_bytes());
        wire.extend_from_slice(&half.to_le_bytes());
        if at == 0 {
            wire.resize(wire.len() + 4 * half as usize, 0);
        }
    }
    assert!(matches!(
        read_request(&mut &wire[..]),
        Err(ProtocolError::Bounds)
    ));
}

/// An answer with a status no failure has is no answer.
#[test]
fn an_unknown_status_is_refused() {
    let wire = 9u32.to_le_bytes();
    assert!(matches!(
        read_answer(&mut &wire[..]),
        Err(ProtocolError::Status(9))
    ));
}

/// A tensor whose elements are not what its dimensions hold is not written.
#[test]
fn a_tensor_unlike_its_dimensions_is_not_written() {
    let request = Request {
        model: 0,
        inputs: vec![Tensor {
            dims: vec![2, 2],
            data: Data::F32(vec![0.0; 3]),
        }],
    };
    let mut wire = Vec::new();
    let err = write_request(&mut wire, &request).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
}
