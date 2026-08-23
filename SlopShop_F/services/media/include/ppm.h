/*
 * Binary PPM (Netpbm P6) decoding and encoding.
 *
 * The decoder operates on a caller-owned byte buffer of known length. Images
 * larger than PPM_MAX_DIMENSION on either edge are refused, as is a header
 * whose declared payload is not present in full.
 */
#ifndef SLOPSHOP_PPM_H
#define SLOPSHOP_PPM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Largest edge accepted, in pixels. Chosen so that one decoded image fits in
 * the working set the media nodes reserve for a single render.
 */
#define PPM_MAX_DIMENSION 8192u

/* Largest encoded file the decoder will consider. */
#define PPM_MAX_ENCODED_BYTES 268435456u /* 256 MiB */

/* Only 8-bit channels are supported. */
#define PPM_MAX_CHANNEL_VALUE 255u

#define PPM_CHANNELS 3u

typedef enum {
    PPM_OK = 0,
    PPM_ERR_NULL_ARGUMENT,
    PPM_ERR_TRUNCATED,
    PPM_ERR_BAD_MAGIC,
    PPM_ERR_BAD_HEADER,
    PPM_ERR_DIMENSION_TOO_LARGE,
    PPM_ERR_UNSUPPORTED_DEPTH,
    PPM_ERR_OUT_OF_MEMORY
} ppm_status_t;

/*
 * A decoded image. `pixels` holds width * height * PPM_CHANNELS bytes and is
 * owned by the struct; release it with ppm_image_release.
 */
typedef struct {
    uint32_t width;
    uint32_t height;
    size_t   pixel_bytes;
    uint8_t *pixels;
} ppm_image_t;

/* Returns a human-readable description of a status code. */
const char *ppm_status_message(ppm_status_t status);

/*
 * Computes width * height * PPM_CHANNELS.
 *
 * Returns PPM_OK and writes the result to *out when both dimensions are in
 * 1..PPM_MAX_DIMENSION, and PPM_ERR_DIMENSION_TOO_LARGE otherwise.
 */
ppm_status_t ppm_buffer_size(uint32_t width, uint32_t height, size_t *out);

/*
 * Allocates a zeroed image of the given dimensions.
 */
ppm_status_t ppm_image_init(ppm_image_t *image, uint32_t width, uint32_t height);

/* Frees the pixel buffer and clears the struct. Safe on a zeroed struct. */
void ppm_image_release(ppm_image_t *image);

/*
 * Decodes `length` bytes of P6 data into `out`.
 *
 * On success `out` owns a freshly allocated pixel buffer. On any failure `out`
 * is left zeroed and nothing is allocated.
 */
ppm_status_t ppm_decode(const uint8_t *data, size_t length, ppm_image_t *out);

/*
 * Encodes `image` into `buffer`.
 *
 * `capacity` is the number of bytes writable at `buffer`. The number of bytes
 * produced is written to *written. Returns PPM_ERR_TRUNCATED, and writes
 * nothing, when the encoded form would not fit.
 */
ppm_status_t ppm_encode(const ppm_image_t *image, uint8_t *buffer, size_t capacity,
                        size_t *written);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SLOPSHOP_PPM_H */
