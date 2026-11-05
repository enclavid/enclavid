// A narrow C face over libvpx's VP8 decoder, so the Rust side needs none of
// its struct layouts: read the size a keyframe says, start, decode one
// compressed frame, read the picture it gave, end. One decoder a process.
#include <stdint.h>

#include "vpx/vp8dx.h"
#include "vpx/vpx_decoder.h"

static vpx_codec_ctx_t ctx;
static vpx_image_t *picture;

// The size a keyframe says its picture is, read as the decoder reads it
// before it allocates for one; no decoder need be started. Returns 1 for a
// keyframe, its size written; 0 for a frame the decoder does not read as one;
// -1 for a keyframe whose header it refuses.
int enclavid_vpx_keyframe_size(const uint8_t *data, uint32_t size,
                               uint32_t *width, uint32_t *height) {
  vpx_codec_stream_info_t info = {sizeof(info), 0, 0, 0};
  vpx_codec_err_t read =
      vpx_codec_peek_stream_info(vpx_codec_vp8_dx(), data, size, &info);
  // Every frame but a keyframe is answered with an error, which the decoder
  // itself takes as no keyframe.
  if (!info.is_kf) return 0;
  if (read != VPX_CODEC_OK) return -1;
  *width = info.w;
  *height = info.h;
  return 1;
}

// Starts the decoder. Returns 0, or -1 when it does not start.
int enclavid_vpx_start(void) {
  return vpx_codec_dec_init(&ctx, vpx_codec_vp8_dx(), NULL, 0) == VPX_CODEC_OK
             ? 0
             : -1;
}

// Decodes one compressed frame. Returns 1 when a picture came out, 0 when none
// did, -1 when the frame does not decode or its picture is not I420. The
// picture stays readable until the next call.
int enclavid_vpx_decode(const uint8_t *data, uint32_t size) {
  picture = NULL;
  if (vpx_codec_decode(&ctx, data, size, NULL, 0) != VPX_CODEC_OK) return -1;
  vpx_codec_iter_t it = NULL;
  picture = vpx_codec_get_frame(&ctx, &it);
  if (!picture) return 0;
  if (picture->fmt != VPX_IMG_FMT_I420) {
    picture = NULL;
    return -1;
  }
  return 1;
}

// The picture the last decode gave: its size, each plane's start, and the
// bytes from one row of each plane to the next. Returns 0, or -1 when there is
// no picture to read.
int enclavid_vpx_picture(uint32_t *width, uint32_t *height, const uint8_t **y,
                         const uint8_t **u, const uint8_t **v,
                         int32_t *y_stride, int32_t *u_stride,
                         int32_t *v_stride) {
  if (!picture) return -1;
  *width = picture->d_w;
  *height = picture->d_h;
  *y = picture->planes[VPX_PLANE_Y];
  *u = picture->planes[VPX_PLANE_U];
  *v = picture->planes[VPX_PLANE_V];
  *y_stride = picture->stride[VPX_PLANE_Y];
  *u_stride = picture->stride[VPX_PLANE_U];
  *v_stride = picture->stride[VPX_PLANE_V];
  return 0;
}

// Ends the decoder, and with it the picture it gave.
void enclavid_vpx_end(void) {
  picture = NULL;
  vpx_codec_destroy(&ctx);
}
