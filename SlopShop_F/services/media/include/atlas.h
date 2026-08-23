/*
 * Sprite atlas packing.
 *
 * The storefront fetches one atlas image per gallery row rather than one
 * request per thumbnail. This module lays a set of already-decoded tiles out on
 * a fixed grid and returns the combined image.
 */
#ifndef SLOPSHOP_ATLAS_H
#define SLOPSHOP_ATLAS_H

#include "ppm.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Most tiles one atlas may contain. */
#define ATLAS_MAX_TILES 256

/* Most columns the grid may have. */
#define ATLAS_MAX_COLUMNS 32

/* Bytes reserved for the atlas header record. */
#define ATLAS_HEADER_BYTES 16

/* Magic written at the start of a serialised atlas. */
#define ATLAS_MAGIC "SLOPATLAS1"

/* One tile. `pixels` points at width * height * PPM_CHANNELS bytes owned by
 * the caller and is only read. */
typedef struct {
    uint32_t       width;
    uint32_t       height;
    const uint8_t *pixels;
} atlas_tile_t;

/*
 * Writes the atlas magic into `buffer`.
 *
 * `buffer` must have room for ATLAS_HEADER_BYTES.
 */
void atlas_write_magic(char buffer[ATLAS_HEADER_BYTES]);

/*
 * Packs `count` tiles into a grid `columns` wide.
 *
 * Every cell is the size of the largest tile; smaller tiles sit in the
 * top-left of their cell and the remainder stays the background colour.
 */
ppm_status_t atlas_pack(const atlas_tile_t *tiles, size_t count, uint32_t columns,
                        ppm_image_t *out);

/*
 * Computes the atlas dimensions atlas_pack would produce, without allocating.
 */
ppm_status_t atlas_target_size(const atlas_tile_t *tiles, size_t count, uint32_t columns,
                               uint32_t *out_width, uint32_t *out_height);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SLOPSHOP_ATLAS_H */
