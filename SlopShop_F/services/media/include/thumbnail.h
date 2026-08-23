/*
 * Thumbnail generation for rendered artifacts.
 *
 * Downscaling is a box filter over integer-sized blocks, which keeps the whole
 * pipeline in integer arithmetic.
 */
#ifndef SLOPSHOP_THUMBNAIL_H
#define SLOPSHOP_THUMBNAIL_H

#include "ppm.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Smallest and largest thumbnail edge the service will produce. */
#define THUMBNAIL_MIN_EDGE 16u
#define THUMBNAIL_MAX_EDGE 2048u

/* The edge used when a caller does not ask for a specific size. */
#define THUMBNAIL_DEFAULT_EDGE 256u

/*
 * Writes a downscaled copy of `source` into `destination`, sized so that
 * neither edge exceeds `max_edge`. Aspect ratio is preserved to within one
 * pixel of rounding.
 *
 * `max_edge` must lie in THUMBNAIL_MIN_EDGE..THUMBNAIL_MAX_EDGE. A source that
 * already fits is copied unchanged rather than upscaled.
 *
 * `destination` is zeroed on entry and left zeroed on failure; on success it
 * owns a buffer the caller releases with ppm_image_release.
 */
ppm_status_t thumbnail_generate(const ppm_image_t *source, uint32_t max_edge,
                                ppm_image_t *destination);

/*
 * Computes the destination dimensions thumbnail_generate would choose, without
 * allocating. Useful for capacity planning before decoding.
 */
ppm_status_t thumbnail_target_size(uint32_t source_width, uint32_t source_height,
                                   uint32_t max_edge, uint32_t *out_width,
                                   uint32_t *out_height);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SLOPSHOP_THUMBNAIL_H */
