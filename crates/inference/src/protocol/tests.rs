use std::io::Cursor;

use coprocess_channel::{ChannelError, receive, send};

use super::*;

fn tensor(dims: &[u64]) -> Tensor {
    let n = dims.iter().product::<u64>() as usize;
    Tensor {
        dims: dims.to_vec(),
        data: Data::F32((0..n).map(|i| i as f32 * 0.5).collect()),
    }
}

fn sent(message: &impl Serialize) -> Vec<u8> {
    let mut bytes = Vec::new();
    send(&mut bytes, message).expect("it sends");
    bytes
}

/// A request and both kinds of response read back as they were sent, each
/// tensor in its own element type.
#[test]
fn messages_read_back_as_sent() {
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
            tensor(&[1; MAX_RANK as usize]),
        ],
    };
    let back: Option<Request> =
        receive(&mut Cursor::new(sent(&request)), MAX_MESSAGE_BYTES).unwrap();
    assert_eq!(back, Some(request));

    let responses = [
        Response::Outputs(vec![tensor(&[1, 3])]),
        Response::Failed(Failure::Inputs),
    ];
    for response in responses {
        let back: Option<Response> =
            receive(&mut Cursor::new(sent(&response)), MAX_MESSAGE_BYTES).unwrap();
        assert_eq!(back, Some(response));
    }
}

/// A tensor whose elements are not what its dimensions hold is not sent.
#[test]
fn a_tensor_unlike_its_dimensions_is_not_sent() {
    let request = Request {
        model: 0,
        inputs: vec![Tensor {
            dims: vec![2, 2],
            data: Data::F32(vec![0.0; 3]),
        }],
    };
    assert!(matches!(
        send(&mut Vec::new(), &request),
        Err(ChannelError::Unencodable)
    ));
}

/// A tensor as a peer may write one, whatever it holds.
#[derive(Serialize)]
struct Written {
    element: i32,
    dims: Vec<u64>,
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}

fn request_of(tensor: Written) -> Vec<u8> {
    #[derive(Serialize)]
    struct Request {
        model: u32,
        inputs: Vec<Written>,
    }
    sent(&Request {
        model: 0,
        inputs: vec![tensor],
    })
}

/// A tensor is read only as what a tensor can be: an element type there is,
/// no more dimensions than [`MAX_RANK`], and exactly the bytes its dimensions
/// hold — counted without overflowing.
#[test]
fn a_tensor_that_cannot_be_is_refused() {
    let f32 = Element::F32.code();
    for wrong in [
        // A string, a bool, a number nothing is.
        Written {
            element: 8,
            dims: vec![1],
            bytes: vec![0],
        },
        Written {
            element: 9,
            dims: vec![1],
            bytes: vec![0],
        },
        Written {
            element: 99,
            dims: vec![1],
            bytes: vec![0; 4],
        },
        Written {
            element: f32,
            dims: vec![1; MAX_RANK as usize + 1],
            bytes: vec![0; 4],
        },
        Written {
            element: f32,
            dims: vec![2, 2],
            bytes: vec![0; 12],
        },
        Written {
            element: f32,
            dims: vec![2],
            bytes: vec![0; 12],
        },
        Written {
            element: f32,
            dims: vec![u64::MAX, u64::MAX, 2],
            bytes: Vec::new(),
        },
    ] {
        let wire = request_of(wrong);
        assert!(matches!(
            receive::<Request>(&mut Cursor::new(wire), MAX_MESSAGE_BYTES),
            Err(ChannelError::Malformed)
        ));
    }
}

/// A run's tensors are read up to as many as a run takes or gives, and
/// refused past them, in a request and a response alike.
#[test]
fn more_tensors_than_a_run_takes_are_refused() {
    let full = vec![tensor(&[]); MAX_TENSORS as usize];
    let request = Request {
        model: 0,
        inputs: full.clone(),
    };
    let back: Option<Request> =
        receive(&mut Cursor::new(sent(&request)), MAX_MESSAGE_BYTES).unwrap();
    assert_eq!(back, Some(request));

    let mut long = full;
    long.push(tensor(&[]));
    let request = sent(&Request {
        model: 0,
        inputs: long.clone(),
    });
    assert!(matches!(
        receive::<Request>(&mut Cursor::new(request), MAX_MESSAGE_BYTES),
        Err(ChannelError::Malformed)
    ));
    let response = sent(&Response::Outputs(long));
    assert!(matches!(
        receive::<Response>(&mut Cursor::new(response), MAX_MESSAGE_BYTES),
        Err(ChannelError::Malformed)
    ));
}

/// The bound holds the largest message there is: as many tensors as a run
/// takes, each of every dimension a tensor has, their elements at the bound.
#[test]
fn the_bound_holds_the_largest_message() {
    let each = (MAX_BYTES / u64::from(MAX_TENSORS) / 4) as usize;
    let mut dims = vec![1u64; MAX_RANK as usize];
    *dims.last_mut().unwrap() = each as u64;
    let inputs = (0..MAX_TENSORS)
        .map(|_| Tensor {
            dims: dims.clone(),
            data: Data::F32(vec![0.0; each]),
        })
        .collect();
    let wire = sent(&Request {
        model: u32::MAX,
        inputs,
    });
    assert!(wire.len() - 4 <= MAX_MESSAGE_BYTES);
}
