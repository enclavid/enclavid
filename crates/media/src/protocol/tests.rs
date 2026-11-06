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

const BOUNDS: PictureBounds = PictureBounds::DEFAULT;

const SMALLER: PictureBounds = PictureBounds {
    long: 640,
    short: 480,
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
        bounds: BOUNDS,
    };
    let back: Request =
        coprocess_channel::receive(&mut Cursor::new(sent(&open)), MAX_REQUEST_BYTES)
            .unwrap()
            .unwrap();
    assert_eq!(
        back,
        Request::Open {
            kind: Kind::Photo,
            bytes: ByteBuf::from(jpeg),
            bounds: BOUNDS,
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
        Response::Pixels(vec![9u8; REGION_ASKED.rgb_len(BOUNDS).unwrap()]),
        Response::Failed(Failure::Corrupt),
    ] {
        let back: Response = coprocess_channel::receive(
            &mut Cursor::new(sent(&response)),
            max_response_bytes(BOUNDS),
        )
        .unwrap()
        .unwrap();
        assert_eq!(back, response);
    }
}

/// The bounds hold the largest messages there are: an open at its bound, a
/// region at the pictures' bounds, a video's frames as many as a decode
/// reads — those whatever the bounds, the smallest too.
#[test]
fn the_bounds_hold_the_largest_messages() {
    let capture = vec![0u8; MAX_OPEN_BYTES];
    let open: Request<&Bytes> = Request::Open {
        kind: Kind::Video,
        bytes: Bytes::new(&capture),
        bounds: BOUNDS,
    };
    assert!(sent(&open).len() - 4 <= MAX_REQUEST_BYTES);

    let frame = Region {
        out_w: BOUNDS.long,
        out_h: BOUNDS.short,
        ..REGION_ASKED
    };
    let pixels = Response::Pixels(vec![0u8; frame.rgb_len(BOUNDS).unwrap()]);
    assert!(sent(&pixels).len() - 4 <= max_response_bytes(BOUNDS));

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
    let smallest = PictureBounds { long: 1, short: 1 };
    assert!(sent(&frames).len() - 4 <= max_response_bytes(smallest));
}

/// A picture is held to its bounds whichever way it is turned: a frame of a
/// video held upright fits as one held across does.
#[test]
fn a_picture_is_bounded_in_either_orientation() {
    for bounds in [BOUNDS, SMALLER] {
        let upright = Size {
            width: bounds.short,
            height: bounds.long,
        };
        let across = Size {
            width: bounds.long,
            height: bounds.short,
        };
        assert!(upright.within(bounds), "{bounds:?}");
        assert!(across.within(bounds), "{bounds:?}");
        for past in [
            Size {
                width: bounds.long + 1,
                height: 10,
            },
            Size {
                width: bounds.short + 1,
                height: bounds.short + 1,
            },
            Size {
                width: 0,
                height: 10,
            },
        ] {
            assert!(!past.within(bounds), "{past:?} in {bounds:?}");
        }
    }
}

/// An open's response fits only what a decode can tell: the kind opened, a size
/// within the bounds, no more frames than a decode reads.
#[test]
fn an_open_answers_only_what_a_decode_can_tell() {
    let photo = Opened::Photo(LANDSCAPE);
    assert!(photo.fits(Kind::Photo, BOUNDS));
    assert!(!photo.fits(Kind::Video, BOUNDS));
    assert!(!photo.fits(Kind::Photo, SMALLER));

    let wide = Opened::Photo(Size {
        width: BOUNDS.long + 1,
        height: 10,
    });
    assert!(!wide.fits(Kind::Photo, BOUNDS));

    let frame = FrameInfo {
        timestamp_ms: 0,
        keyframe: true,
    };
    let full = Opened::Video {
        size: LANDSCAPE,
        frames: vec![frame; MAX_VIDEO_FRAMES as usize],
    };
    assert!(full.fits(Kind::Video, BOUNDS));
    let long = Opened::Video {
        size: LANDSCAPE,
        frames: vec![frame; MAX_VIDEO_FRAMES as usize + 1],
    };
    assert!(!long.fits(Kind::Video, BOUNDS));
}

/// A region past the bounds gives no length, whichever side is past them —
/// a column as tall as the bounds' pixels together too: the round refuses it
/// before it asks.
#[test]
fn a_region_past_the_bounds_has_no_length() {
    let wide = Region {
        out_w: BOUNDS.long + 1,
        out_h: BOUNDS.short,
        ..REGION_ASKED
    };
    let column = Region {
        out_w: 1,
        out_h: u32::try_from(BOUNDS.pixels()).unwrap(),
        ..REGION_ASKED
    };
    assert_eq!(wide.rgb_len(BOUNDS), None);
    assert_eq!(column.rgb_len(BOUNDS), None);
    assert_eq!(REGION_ASKED.rgb_len(BOUNDS), Some(4 * 2 * 3));
}

/// Bounds as large as the host can write overflow nothing: a region's length
/// that no memory could hold is none, and a response's bound is the most
/// there is.
#[test]
fn the_largest_bounds_overflow_nothing() {
    let largest = PictureBounds {
        long: u32::MAX,
        short: u32::MAX,
    };
    let everything = Region {
        out_w: u32::MAX,
        out_h: u32::MAX,
        ..REGION_ASKED
    };
    assert_eq!(everything.rgb_len(largest), None);
    assert_eq!(max_response_bytes(largest), usize::MAX);
}
