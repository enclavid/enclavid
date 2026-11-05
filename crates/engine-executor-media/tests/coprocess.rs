//! The coprocess as a round meets it: started on a socket, sent a capture,
//! asked for regions of its pictures, let go of.
//!
//! The video is `fixtures/square.webm`: 12 frames of 160×120 at 15 a second, a
//! keyframe every 5, a dark luma gradient with a bright 16×16 square that moves
//! 8 px right each frame, made by vpxenc from a synthetic picture. The photos
//! are made here.

use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use coprocess_channel::{receive, send};
use enclavid_media::protocol::{
    Bytes, Failure, Kind, MAX_RESPONSE_BYTES, Opened, Region, Request, ResizeMode, Response, Size,
};

const VIDEO: &[u8] = include_bytes!("fixtures/square.webm");

/// The whole frame, at a quarter its size each way.
const QUARTER: Region = Region {
    x: 0,
    y: 0,
    w: 160,
    h: 120,
    out_w: 40,
    out_h: 30,
    mode: ResizeMode::Nearest,
};

/// The coprocess on a socket, and the round's end of it, whose reads wait no
/// more than 10 s for a response.
fn started() -> (Child, UnixStream) {
    let (ours, theirs) = UnixStream::pair().expect("a socket pair");
    ours.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("a read timeout");
    let child = Command::new(env!("CARGO_BIN_EXE_engine-executor-media"))
        .stdin(Stdio::from(OwnedFd::from(theirs)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the coprocess starts");
    (child, ours)
}

/// The coprocess, sent `bytes` as a capture of `kind`, and what it said of
/// them.
fn open(kind: Kind, bytes: &[u8]) -> (Child, UnixStream, Result<Opened, Failure>) {
    let (child, mut socket) = started();
    let bytes = Bytes::new(bytes);
    send(&mut socket, &Request::Open { kind, bytes }).unwrap();
    let said = opened(&mut socket);
    (child, socket, said)
}

/// What the coprocess responded to an open.
fn opened(socket: &mut UnixStream) -> Result<Opened, Failure> {
    match response(socket) {
        Response::Opened(opened) => Ok(opened),
        Response::Failed(failure) => Err(failure),
        Response::Pixels(_) => panic!("pixels in response to an open"),
    }
}

/// The region `region` of picture `frame`, as the coprocess responds with it.
fn region(socket: &mut UnixStream, frame: u32, region: Region) -> Result<Vec<u8>, Failure> {
    let request: Request = Request::Region { frame, region };
    send(socket, &request).unwrap();
    match response(socket) {
        Response::Pixels(rgb) => Ok(rgb),
        Response::Failed(failure) => Err(failure),
        Response::Opened(_) => panic!("an open's response to a region"),
    }
}

/// The coprocess's next response.
fn response(socket: &mut UnixStream) -> Response {
    receive(socket, MAX_RESPONSE_BYTES)
        .unwrap()
        .expect("a response")
}

/// Let go of the socket, and see the coprocess end as it should.
fn let_go(mut child: Child, socket: UnixStream) {
    drop(socket);
    assert!(child.wait().unwrap().success());
}

/// Where across a quarter-size frame (`width` pixels a row) the square is: the
/// mean column of the pixels brighter than the background can be, in the rows
/// it crosses — 52 to 68 of the frame, 13 to 17 at a quarter.
fn square_column(rgb: &[u8], width: usize) -> f64 {
    let (mut weight, mut moment) = (0.0, 0.0);
    for (i, pixel) in rgb.as_chunks::<3>().0.iter().enumerate() {
        if (13..17).contains(&(i / width)) && pixel[0] > 160 {
            weight += 1.0;
            moment += (i % width) as f64;
        }
    }
    moment / weight
}

/// A JPEG of `width` × `height`, each pixel's red its column's share of 255
/// and its green its row's.
fn jpeg(width: u16, height: u16) -> Vec<u8> {
    use jpeg_encoder::{ColorType, Encoder};

    let rgb: Vec<u8> = (0..height)
        .flat_map(|row| {
            (0..width).flat_map(move |col| {
                let red = (u32::from(col) * 255 / u32::from(width.max(2) - 1)) as u8;
                let green = (u32::from(row) * 255 / u32::from(height.max(2) - 1)) as u8;
                [red, green, 128]
            })
        })
        .collect();
    let mut out = Vec::new();
    Encoder::new(&mut out, 95)
        .encode(&rgb, width, height, ColorType::Rgb)
        .expect("a JPEG");
    out
}

/// A video lists its frames as its container says — in order, at their
/// times, its keyframes marked — and each frame asked in order is that frame:
/// the square is seen moving right.
#[test]
fn a_video_lists_its_frames_and_each_decodes_as_itself() {
    let (child, mut socket, opened) = open(Kind::Video, VIDEO);
    let Ok(Opened::Video { size, frames }) = opened else {
        panic!("the video opens: {opened:?}");
    };
    assert_eq!(
        size,
        Size {
            width: 160,
            height: 120
        }
    );
    assert_eq!(frames.len(), 12);
    for (i, frame) in frames.iter().enumerate() {
        // 15 a second: a frame each 66.7 ms, as the WebM's millisecond ticks
        // round it.
        assert!(
            frame.timestamp_ms.abs_diff(i as u32 * 1000 / 15) <= 1,
            "{frame:?}"
        );
        assert_eq!(frame.keyframe, i % 5 == 0, "{frame:?}");
    }
    for k in 0..12u32 {
        let rgb = region(&mut socket, k, QUARTER).unwrap();
        // The square's middle at 18 + 8k px is at (18 + 8k) / 4 in the
        // quarter-size region, give or take a column for the codec and the
        // sampling.
        let column = square_column(&rgb, 40);
        let expected = (18 + 8 * k) as f64 / 4.0;
        assert!(
            (column - expected).abs() <= 1.0,
            "frame {k}: column {column}"
        );
    }
    let_go(child, socket);
}

/// A frame asked for out of order — behind the frame decoded last, or ahead
/// past a keyframe — is the same picture as when it was asked in order.
#[test]
fn a_frame_asked_out_of_order_is_the_same_frame() {
    let (child, mut socket, opened) = open(Kind::Video, VIDEO);
    assert!(opened.is_ok());
    let in_order: Vec<Vec<u8>> = (0..12)
        .map(|k| region(&mut socket, k, QUARTER).unwrap())
        .collect();
    for k in [7, 2, 11, 0, 6, 6] {
        assert_eq!(
            region(&mut socket, k, QUARTER).unwrap(),
            in_order[k as usize],
            "frame {k}"
        );
    }
    let_go(child, socket);
}

/// A photo says its size when it opens and decodes when a region asks: the
/// region is the photo's, crop and all.
#[test]
fn a_photo_decodes_when_a_region_asks() {
    let (child, mut socket, opened) = open(Kind::Photo, &jpeg(64, 48));
    assert_eq!(
        opened,
        Ok(Opened::Photo(Size {
            width: 64,
            height: 48
        }))
    );
    // Its right half, one pixel a row, two rows: each the pixel at the middle
    // of what it covers — three quarters across, a quarter and three quarters
    // down — give or take the JPEG.
    let right = Region {
        x: 32,
        y: 0,
        w: 32,
        h: 48,
        out_w: 1,
        out_h: 2,
        mode: ResizeMode::Nearest,
    };
    let rgb = region(&mut socket, 0, right).unwrap();
    let near = |got: u8, want: u8| got.abs_diff(want) <= 16;
    // Column 48 of 63, rows 12 and 36 of 47.
    assert!(near(rgb[0], 194) && near(rgb[1], 65), "{rgb:?}");
    assert!(near(rgb[3], 194) && near(rgb[4], 195), "{rgb:?}");
    let_go(child, socket);
}

/// A photo past the bounds decodes at half its size where half fits, and is
/// refused where it does not.
#[test]
fn a_photo_past_the_bounds_decodes_at_half() {
    let (child, mut socket, opened) = open(Kind::Photo, &jpeg(1922, 10));
    assert_eq!(
        opened,
        Ok(Opened::Photo(Size {
            width: 961,
            height: 5
        }))
    );
    let whole = Region {
        x: 0,
        y: 0,
        w: 961,
        h: 5,
        out_w: 961,
        out_h: 5,
        mode: ResizeMode::Average,
    };
    assert_eq!(region(&mut socket, 0, whole).unwrap().len(), 961 * 5 * 3);
    let_go(child, socket);

    let (child, socket, opened) = open(Kind::Photo, &jpeg(3842, 10));
    assert_eq!(opened, Err(Failure::PastBounds));
    let_go(child, socket);
}

/// Bytes that are not of the kind they are sent as are not opened, and the
/// coprocess ends.
#[test]
fn what_is_not_its_kind_is_refused() {
    for kind in [Kind::Photo, Kind::Video] {
        let (child, socket, opened) = open(kind, b"not media");
        assert_eq!(opened, Err(Failure::NotMedia), "{kind:?}");
        let_go(child, socket);
    }
    let (child, socket, opened) = open(Kind::Photo, VIDEO);
    assert_eq!(opened, Err(Failure::NotMedia));
    let_go(child, socket);
}

/// The video with frame `k`'s bytes as `change` leaves them.
fn with_frame(k: usize, change: impl FnOnce(&mut [u8])) -> Vec<u8> {
    use webm_iterable::WebmIterator;
    use webm_iterable::matroska_spec::{MatroskaSpec, SimpleBlock};

    let frame = WebmIterator::new(std::io::Cursor::new(VIDEO), &[])
        .filter_map(|tag| match tag.expect("a tag") {
            tag @ MatroskaSpec::SimpleBlock(_) => Some(
                SimpleBlock::try_from(&tag)
                    .expect("a block")
                    .raw_frame_data()
                    .to_vec(),
            ),
            _ => None,
        })
        .nth(k)
        .expect("the video has the frame");
    let at = VIDEO
        .windows(frame.len())
        .position(|bytes| bytes == frame.as_slice())
        .expect("the frame's bytes are in the file");
    let mut video = VIDEO.to_vec();
    change(&mut video[at..at + frame.len()]);
    video
}

/// The video with frame `k`'s first partition said to run far past the
/// frame's end, which libvpx refuses to decode.
fn with_frame_broken(k: usize) -> Vec<u8> {
    with_frame(k, |frame| frame[1..3].copy_from_slice(&[0xff, 0xff]))
}

/// The video with keyframe `k` saying its picture is 16383 × 16383, the most
/// a keyframe can say: frames of that size need more memory than a round has.
fn with_keyframe_oversized(k: usize) -> Vec<u8> {
    with_frame(k, |frame| {
        assert_eq!(frame[3..6], [0x9d, 0x01, 0x2a], "frame {k} is a keyframe");
        frame[6..10].copy_from_slice(&[0xff, 0x3f, 0xff, 0x3f]);
    })
}

/// A keyframe that says its picture is of another size than the video's ends
/// the list of frames there, before the decoder allocates for it: the frames
/// before it decode as ever, and a video whose first keyframe says so has
/// none.
#[test]
fn a_keyframe_of_another_size_ends_the_frames() {
    let (child, mut socket, _) = open(Kind::Video, VIDEO);
    let clean: Vec<Vec<u8>> = (0..5)
        .map(|k| region(&mut socket, k, QUARTER).unwrap())
        .collect();
    let_go(child, socket);

    let (child, mut socket, opened) = open(Kind::Video, &with_keyframe_oversized(5));
    let Ok(Opened::Video { frames, .. }) = opened else {
        panic!("the video opens: {opened:?}");
    };
    assert_eq!(frames.len(), 5);
    for k in 0..5 {
        assert_eq!(
            region(&mut socket, k, QUARTER).unwrap(),
            clean[k as usize],
            "frame {k}"
        );
    }
    let_go(child, socket);

    let (child, socket, opened) = open(Kind::Video, &with_keyframe_oversized(0));
    let Ok(Opened::Video { frames, .. }) = opened else {
        panic!("the video opens: {opened:?}");
    };
    assert!(frames.is_empty(), "{frames:?}");
    let_go(child, socket);
}

/// A frame that does not decode is answered so, and so is every frame that
/// needs it, up to the next keyframe; from there the video decodes again, and
/// the frames before it decode as ever. The coprocess goes on answering.
#[test]
fn a_frame_that_does_not_decode_is_answered_so() {
    let (child, mut socket, _) = open(Kind::Video, VIDEO);
    let clean: Vec<Vec<u8>> = (0..12)
        .map(|k| region(&mut socket, k, QUARTER).unwrap())
        .collect();
    let_go(child, socket);

    let (child, mut socket, opened) = open(Kind::Video, &with_frame_broken(3));
    assert!(opened.is_ok(), "the container is whole: {opened:?}");
    for k in [3, 4, 3] {
        assert_eq!(
            region(&mut socket, k, QUARTER),
            Err(Failure::Corrupt),
            "frame {k}"
        );
    }
    for k in [5, 6, 2, 9] {
        assert_eq!(
            region(&mut socket, k, QUARTER).unwrap(),
            clean[k as usize],
            "frame {k}"
        );
    }
    let_go(child, socket);
}

/// A region before the open, or of a frame the video has not, is out of turn
/// — and the coprocess answers nothing after: it ends.
#[test]
fn a_request_out_of_turn_ends_it() {
    let (child, mut socket) = started();
    let first: Request = Request::Region {
        frame: 0,
        region: QUARTER,
    };
    send(&mut socket, &first).unwrap();
    assert_eq!(opened(&mut socket), Err(Failure::OutOfTurn));
    let_go(child, socket);

    let (mut child, mut socket, opened) = open(Kind::Video, VIDEO);
    assert!(opened.is_ok());
    assert_eq!(region(&mut socket, 12, QUARTER), Err(Failure::OutOfTurn));
    // Its end of the socket closes with it, the round's still open.
    assert_eq!(socket.read(&mut [0u8; 1]).unwrap(), 0);
    assert!(child.wait().unwrap().success());
}
