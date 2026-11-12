//! A decoded picture's region as RGB8. A frame's I420 is converted whole by
//! `yuv`, by BT.601's limited range, which VP8 is coded in; a region of it,
//! or of a photo's RGB8 as the JPEG decoder gave it, is cropped inside the
//! picture and brought to the size asked by `fast_image_resize` — each output
//! pixel the source pixel nearest its place, or a box filter's mean of the
//! source pixels it covers.

use enclavid_media::protocol::{Region, ResizeMode};
use fast_image_resize::images::{Image, ImageRef};
use fast_image_resize::{FilterType, PixelType, ResizeAlg, ResizeOptions, Resizer};
#[cfg(feature = "video")]
use yuv::{YuvPlanarImage, YuvRange, YuvStandardMatrix, yuv420_to_rgb};

/// A picture decoded as RGB8, row by row: a photo, as the JPEG decoder gives
/// it, or a frame, converted.
pub struct Rgb<'a> {
    /// The picture's width in pixels.
    pub width: u32,
    /// The picture's height in pixels.
    pub height: u32,
    /// Its pixels, three bytes each.
    pub pixels: &'a [u8],
}

/// A decoded picture as the decoder holds it: I420, its two chroma planes at
/// half the size each way, rounded up.
#[cfg(feature = "video")]
pub struct Planes<'a> {
    /// The picture's width in pixels.
    pub width: u32,
    /// The picture's height in pixels.
    pub height: u32,
    /// Luma, `y_stride` bytes a row.
    pub y: &'a [u8],
    /// The bytes from one luma row to the next.
    pub y_stride: usize,
    /// Blue-difference chroma, `uv_stride` bytes a row.
    pub u: &'a [u8],
    /// Red-difference chroma, `uv_stride` bytes a row.
    pub v: &'a [u8],
    /// The bytes from one chroma row to the next.
    pub uv_stride: usize,
}

/// The picture `planes` hold as RGB8, row by row; `None` for planes that do
/// not hold what their size and strides say.
#[cfg(feature = "video")]
pub fn rgb_of(planes: &Planes) -> Option<Vec<u8>> {
    let (width, height) = (planes.width, planes.height);
    let row = width.checked_mul(3)?;
    let mut rgb = vec![0u8; usize::try_from(u64::from(row) * u64::from(height)).ok()?];
    let image = YuvPlanarImage {
        y_plane: planes.y,
        y_stride: u32::try_from(planes.y_stride).ok()?,
        u_plane: planes.u,
        u_stride: u32::try_from(planes.uv_stride).ok()?,
        v_plane: planes.v,
        v_stride: u32::try_from(planes.uv_stride).ok()?,
        width,
        height,
    };
    yuv420_to_rgb(
        &image,
        &mut rgb,
        row,
        YuvRange::Limited,
        YuvStandardMatrix::Bt601,
    )
    .ok()?;
    Some(rgb)
}

/// `region` of `picture` as RGB8, row by row: its crop held inside the
/// picture, brought to its output size, a pixel at least each way. `None` for
/// pixels fewer than the picture's size says. What output a caller may ask
/// for, the caller holds to the bounds before.
pub fn rgb_region(picture: &Rgb, region: &Region) -> Option<Vec<u8>> {
    let pixels = u64::from(region.out_w.max(1)) * u64::from(region.out_h.max(1));
    let length = usize::try_from(pixels).ok()?.checked_mul(3)?;
    let source = ImageRef::new(
        picture.width,
        picture.height,
        picture.pixels,
        PixelType::U8x3,
    )
    .ok()?;
    let held = region.held(picture.width, picture.height);
    let mut out = Image::new(held.out_w.max(1), held.out_h.max(1), PixelType::U8x3);
    let algorithm = match held.mode {
        ResizeMode::Nearest => ResizeAlg::Nearest,
        ResizeMode::Average => ResizeAlg::Convolution(FilterType::Box),
        // A kernel of the source's own pixel, not widened as it shrinks.
        ResizeMode::Bilinear => ResizeAlg::Interpolation(FilterType::Bilinear),
    };
    let options = ResizeOptions::new().resize_alg(algorithm).crop(
        f64::from(held.x),
        f64::from(held.y),
        f64::from(held.w),
        f64::from(held.h),
    );
    Resizer::new().resize(&source, &mut out, &options).ok()?;
    let rgb = out.into_vec();
    (rgb.len() == length).then_some(rgb)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `w` × `h` picture whose luma is `luma(x, y)` and whose chroma is
    /// grey, on strides wider than its rows.
    #[cfg(feature = "video")]
    fn picture(w: u32, h: u32, luma: impl Fn(u32, u32) -> u8) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let (y_stride, uv_stride) = (w as usize + 3, (w as usize).div_ceil(2) + 1);
        let mut y = vec![0u8; y_stride * h as usize];
        for row in 0..h {
            for col in 0..w {
                y[row as usize * y_stride + col as usize] = luma(col, row);
            }
        }
        let chroma = vec![128u8; uv_stride * (h as usize).div_ceil(2)];
        (y, chroma.clone(), chroma)
    }

    #[cfg(feature = "video")]
    fn planes<'a>(w: u32, h: u32, y: &'a [u8], u: &'a [u8], v: &'a [u8]) -> Planes<'a> {
        Planes {
            width: w,
            height: h,
            y,
            y_stride: w as usize + 3,
            u,
            v,
            uv_stride: (w as usize).div_ceil(2) + 1,
        }
    }

    /// The whole of a `w` × `h` picture, brought to `out_w` × `out_h` by
    /// `mode`.
    fn whole(w: u32, h: u32, out_w: u32, out_h: u32, mode: ResizeMode) -> Region {
        Region {
            x: 0,
            y: 0,
            w,
            h,
            out_w,
            out_h,
            mode,
        }
    }

    /// 4 × 2, each pixel [10 × column, 100 × row, 7].
    fn gradient() -> Vec<u8> {
        (0..2u8)
            .flat_map(|row| (0..4u8).flat_map(move |col| [10 * col, 100 * row, 7]))
            .collect()
    }

    /// Video black and white come out as RGB black and white, and a red in
    /// BT.601 as red, give or take the conversion's rounding.
    #[cfg(feature = "video")]
    #[test]
    fn limited_range_converts_to_full_range() {
        for (luma, u, v, want) in [
            (16, 128, 128, [0, 0, 0]),
            (235, 128, 128, [255, 255, 255]),
            (81, 90, 240, [255, 0, 0]),
        ] {
            let y = vec![luma; 4];
            let p = Planes {
                width: 2,
                height: 2,
                y: &y,
                y_stride: 2,
                u: &[u],
                v: &[v],
                uv_stride: 1,
            };
            let rgb = rgb_of(&p).unwrap();
            for (got, want) in rgb[..3].iter().zip(want) {
                assert!(got.abs_diff(want) <= 2, "{rgb:?} for {want:?}");
            }
        }
    }

    /// Planes shorter than their size and strides say give nothing, rather
    /// than a read past their end.
    #[cfg(feature = "video")]
    #[test]
    fn short_planes_give_nothing() {
        let (y, u, v) = picture(4, 4, |_, _| 16);
        // A byte short of the last row's last pixel: three strides and a row.
        let needed = (4 + 3) * 3 + 4;
        assert!(rgb_of(&planes(4, 4, &y, &u, &v)).is_some());
        assert_eq!(rgb_of(&planes(4, 4, &y[..needed - 1], &u, &v)), None);
    }

    /// The crop is taken where the region says, and each output pixel from
    /// the source pixel nearest its place.
    #[test]
    fn a_region_is_cropped_and_resampled() {
        let pixels = gradient();
        let photo = Rgb {
            width: 4,
            height: 2,
            pixels: &pixels,
        };
        let right_half = Region {
            x: 2,
            y: 0,
            w: 2,
            h: 2,
            out_w: 2,
            out_h: 2,
            mode: ResizeMode::Nearest,
        };
        let rgb = rgb_region(&photo, &right_half).unwrap();
        assert_eq!(rgb, [20, 0, 7, 30, 0, 7, 20, 100, 7, 30, 100, 7]);
    }

    /// Averaged, each output pixel is the mean of the source pixels it covers:
    /// shrunk by two, of each two-by-two block; to a single pixel, of all.
    #[test]
    fn an_average_is_the_mean_of_the_pixels_covered() {
        let pixels = gradient();
        let photo = Rgb {
            width: 4,
            height: 2,
            pixels: &pixels,
        };
        let halved = rgb_region(&photo, &whole(4, 2, 2, 1, ResizeMode::Average)).unwrap();
        assert_eq!(halved, [5, 50, 7, 25, 50, 7]);
        let one = rgb_region(&photo, &whole(4, 2, 1, 1, ResizeMode::Average)).unwrap();
        assert_eq!(one, [15, 50, 7]);
    }

    /// Bilinear, each output pixel is OpenCV's `INTER_LINEAR`, to within its
    /// rounding: the values below are `cv2.resize`'s of the same picture.
    #[test]
    fn a_bilinear_resize_is_opencvs() {
        // 8 × 6, each pixel [(31 col + 7 row) % 256, (41 row + 3 col) % 256,
        // (col² + 5 row²) % 256].
        let pixels: Vec<u8> = (0..6u32)
            .flat_map(|row| {
                (0..8u32).flat_map(move |col| {
                    [
                        (31 * col + 7 * row) % 256,
                        (41 * row + 3 * col) % 256,
                        (col * col + 5 * row * row) % 256,
                    ]
                    .map(|v| v as u8)
                })
            })
            .collect();
        let photo = Rgb {
            width: 8,
            height: 6,
            pixels: &pixels,
        };
        let shrunk: [((u32, u32), &[u8]); 2] = [
            (
                (3, 2),
                &[
                    33, 44, 6, 116, 52, 18, 198, 59, 43, 54, 167, 81, 137, 175, 93, 219, 182, 118,
                ],
            ),
            (
                (5, 4),
                &[
                    11, 11, 1, 60, 16, 5, 110, 21, 14, 160, 25, 27, 209, 30, 46, 21, 72, 16, 71,
                    77, 20, 121, 82, 29, 170, 87, 42, 220, 92, 61, 32, 134, 54, 81, 139, 57, 131,
                    144, 66, 181, 148, 80, 230, 153, 99, 42, 195, 114, 92, 200, 117, 142, 205, 126,
                    191, 210, 140, 241, 215, 159,
                ],
            ),
        ];
        for ((out_w, out_h), opencv) in shrunk {
            let rgb = rgb_region(&photo, &whole(8, 6, out_w, out_h, ResizeMode::Bilinear)).unwrap();
            assert_eq!(rgb.len(), opencv.len());
            for (i, (&ours, &theirs)) in rgb.iter().zip(opencv).enumerate() {
                assert!(
                    ours.abs_diff(theirs) <= 1,
                    "{out_w}x{out_h} at {i}: {ours}, OpenCV's {theirs}"
                );
            }
        }
    }

    /// At its own size, by any mode, a crop's pixels are its own.
    #[test]
    fn a_region_at_its_own_size_is_its_pixels() {
        let pixels = gradient();
        let photo = Rgb {
            width: 4,
            height: 2,
            pixels: &pixels,
        };
        for mode in [
            ResizeMode::Nearest,
            ResizeMode::Average,
            ResizeMode::Bilinear,
        ] {
            let rgb = rgb_region(&photo, &whole(4, 2, 4, 2, mode)).unwrap();
            assert_eq!(rgb, pixels, "{mode:?}");
        }
    }

    /// A crop past the picture's edge is held inside it, and an output of no
    /// pixels gives one; pixels fewer than the picture's size give nothing.
    #[test]
    fn a_region_past_the_edge_is_held_inside() {
        let pixels = gradient();
        let photo = Rgb {
            width: 4,
            height: 2,
            pixels: &pixels,
        };
        for mode in [
            ResizeMode::Nearest,
            ResizeMode::Average,
            ResizeMode::Bilinear,
        ] {
            let past_the_edge = Region {
                x: 9,
                y: 9,
                w: 9,
                h: 9,
                out_w: 0,
                out_h: 0,
                mode,
            };
            let rgb = rgb_region(&photo, &past_the_edge).unwrap();
            assert_eq!(rgb, [30, 100, 7], "{mode:?}");
        }
        let short = Rgb {
            pixels: &pixels[..pixels.len() - 1],
            ..photo
        };
        assert_eq!(
            rgb_region(&short, &whole(4, 2, 1, 1, ResizeMode::Nearest)),
            None
        );
    }
}
