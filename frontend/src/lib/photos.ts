// Fitting a capture under the upload limit the server states.
//
// A body over the limit is refused with 413, and on that device it would be
// refused on every retry — the applicant has nothing they could change. So
// the photos are brought under a budget here, before anything is sent: a
// capture that already fits goes as it is; one that does not is re-encoded,
// lower JPEG quality first and a smaller picture only if that is not enough,
// so the detail a check needs is the last thing given up.

/// The share of the server's limit the photos may take together. The rest is
/// the multipart framing around them, with a wide margin — an upload that
/// lands just over the line is the one outcome worth any amount of headroom.
const BUDGET_SHARE = 2 / 3;

const QUALITIES = [0.75, 0.6, 0.45];
const SCALES = [1, 0.75, 0.5];

/// Photos that fit the capture budget for `maxUploadBytes`. Throws when even
/// the smallest re-encoding does not.
export async function fitPhotos(
  photos: Blob[],
  maxUploadBytes: number,
): Promise<Blob[]> {
  const budget = Math.floor(maxUploadBytes * BUDGET_SHARE);
  if (totalSize(photos) <= budget) return photos;

  const bitmaps = await Promise.all(photos.map((f) => createImageBitmap(f)));
  try {
    for (const scale of SCALES) {
      for (const quality of QUALITIES) {
        const out = await Promise.all(
          bitmaps.map((b) => encode(b, scale, quality)),
        );
        if (totalSize(out) <= budget) return out;
      }
    }
  } finally {
    bitmaps.forEach((b) => b.close());
  }
  throw new Error("the capture does not fit the upload limit");
}

function totalSize(photos: Blob[]): number {
  return photos.reduce((n, f) => n + f.size, 0);
}

async function encode(
  bitmap: ImageBitmap,
  scale: number,
  quality: number,
): Promise<Blob> {
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.round(bitmap.width * scale));
  canvas.height = Math.max(1, Math.round(bitmap.height * scale));
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("no 2d context");
  ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  const blob = await new Promise<Blob | null>((resolve) =>
    canvas.toBlob(resolve, "image/jpeg", quality),
  );
  if (!blob) throw new Error("toBlob returned null");
  return blob;
}
