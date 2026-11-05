use std::io::Cursor;

use super::*;

const REGION_ASKED: Region = Region {
    x: 10,
    y: 20,
    w: 300,
    h: 200,
    out_w: 4,
    out_h: 2,
    mode: ResizeMode::Average,
};

const LANDSCAPE: Size = Size {
    width: 1280,
    height: 720,
};

/// `message` as the channel carries it.
fn sent(message: &impl Serialize) -> Vec<u8> {
    let mut bytes = Vec::new();
    coprocess_channel::send(&mut bytes, message).expect("it sends");
    bytes
}

/// A request sent from bytes the round holds reads back as the coprocess's
/// own, and a response as it was sent.
#[test]
fn messages_read_back_as_sent() {
    let jpeg = b"\xff\xd8jpeg".to_vec();
    let open = Request::Open {
        kind: Kind::Photo,
        bytes: Bytes::new(&jpeg),
    };
    let back: Request =
        coprocess_channel::receive(&mut Cursor::new(sent(&open)), MAX_REQUEST_BYTES)
            .unwrap()
            .unwrap();
    assert_eq!(
        back,
        Request::Open {
            kind: Kind::Photo,
            bytes: ByteBuf::from(jpeg)
        }
    );

    for response in [
        Response::Opened(Opened::Video {
            size: LANDSCAPE,
            frames: vec![FrameInfo {
                timestamp_ms: 67,
                keyframe: false,
            }],
        }),
        Response::Pixels(vec![9u8; REGION_ASKED.rgb_len().unwrap()]),
        Response::Failed(Failure::Corrupt),
    ] {
        let back: Response =
            coprocess_channel::receive(&mut Cursor::new(sent(&response)), MAX_RESPONSE_BYTES)
                .unwrap()
                .unwrap();
        assert_eq!(back, response);
    }
}

/// The bounds hold the largest messages there are: an open at its bound, a
/// region at its bound, a video's frames as many as a decode reads.
#[test]
fn the_bounds_hold_the_largest_messages() {
    let capture = vec![0u8; MAX_OPEN_BYTES];
    let open: Request<&Bytes> = Request::Open {
        kind: Kind::Video,
        bytes: Bytes::new(&capture),
    };
    assert!(sent(&open).len() - 4 <= MAX_REQUEST_BYTES);

    let frame = Region {
        out_w: MAX_PICTURE_LONG_SIDE,
        out_h: MAX_PICTURE_SHORT_SIDE,
        ..REGION_ASKED
    };
    let pixels = Response::Pixels(vec![0u8; frame.rgb_len().unwrap()]);
    assert!(sent(&pixels).len() - 4 <= MAX_RESPONSE_BYTES);

    let frames = Response::Opened(Opened::Video {
        size: LANDSCAPE,
        frames: vec![
            FrameInfo {
                timestamp_ms: u32::MAX,
                keyframe: true,
            };
            MAX_VIDEO_FRAMES as usize
        ],
    });
    assert!(sent(&frames).len() - 4 <= MAX_RESPONSE_BYTES);
}

/// A picture is held to its bounds whichever way it is turned: a frame of a
/// video held upright fits as one held across does.
#[test]
fn a_picture_is_bounded_in_either_orientation() {
    let upright = Size {
        width: MAX_PICTURE_SHORT_SIDE,
        height: MAX_PICTURE_LONG_SIDE,
    };
    let across = Size {
        width: MAX_PICTURE_LONG_SIDE,
        height: MAX_PICTURE_SHORT_SIDE,
    };
    assert!(upright.within_bounds() && across.within_bounds());
    for past in [
        Size {
            width: MAX_PICTURE_LONG_SIDE + 1,
            height: 10,
        },
        Size {
            width: MAX_PICTURE_SHORT_SIDE + 1,
            height: MAX_PICTURE_SHORT_SIDE + 1,
        },
        Size {
            width: 0,
            height: 10,
        },
    ] {
        assert!(!past.within_bounds(), "{past:?}");
    }
}

/// An open's response fits only what a decode can tell: the kind opened, a size
/// within the bounds, no more frames than a decode reads.
#[test]
fn an_open_answers_only_what_a_decode_can_tell() {
    let photo = Opened::Photo(LANDSCAPE);
    assert!(photo.fits(Kind::Photo));
    assert!(!photo.fits(Kind::Video));

    let wide = Opened::Photo(Size {
        width: MAX_PICTURE_LONG_SIDE + 1,
        height: 10,
    });
    assert!(!wide.fits(Kind::Photo));

    let frame = FrameInfo {
        timestamp_ms: 0,
        keyframe: true,
    };
    let full = Opened::Video {
        size: LANDSCAPE,
        frames: vec![frame; MAX_VIDEO_FRAMES as usize],
    };
    assert!(full.fits(Kind::Video));
    let long = Opened::Video {
        size: LANDSCAPE,
        frames: vec![frame; MAX_VIDEO_FRAMES as usize + 1],
    };
    assert!(!long.fits(Kind::Video));
}

/// A region past its bound gives no length: the round refuses it before it
/// asks.
#[test]
fn a_region_past_its_bound_has_no_length() {
    let huge = Region {
        out_w: MAX_PICTURE_LONG_SIDE + 1,
        out_h: MAX_PICTURE_SHORT_SIDE,
        ..REGION_ASKED
    };
    assert_eq!(huge.rgb_len(), None);
    assert_eq!(REGION_ASKED.rgb_len(), Some(4 * 2 * 3));
}
