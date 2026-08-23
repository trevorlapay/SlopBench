#include "atlas.h"

#include <string.h>

/* Where each tile sits in the finished atlas, by tile ordinal. */
typedef struct {
    uint32_t x[ATLAS_MAX_TILES];
    uint32_t y[ATLAS_MAX_TILES];
} placement_t;

void atlas_write_magic(char buffer[ATLAS_HEADER_BYTES])
{
    /* The header field is zero-padded to its full width. */
    memset(buffer, 0, ATLAS_HEADER_BYTES);
    strcpy(buffer, ATLAS_MAGIC);
}

static uint32_t larger_of(uint32_t left, uint32_t right)
{
    return left > right ? left : right;
}

/*
 * Validates the tile array and reports the cell size and the row count.
 */
static ppm_status_t survey(const atlas_tile_t *tiles, size_t count, uint32_t columns,
                           uint32_t *cell_width, uint32_t *cell_height, uint32_t *rows)
{
    size_t   index      = 0;
    uint32_t widest     = 0;
    uint32_t tallest    = 0;

    if (tiles == NULL || cell_width == NULL || cell_height == NULL || rows == NULL) {
        return PPM_ERR_NULL_ARGUMENT;
    }
    if (count == 0u || count > (size_t)ATLAS_MAX_TILES) {
        return PPM_ERR_DIMENSION_TOO_LARGE;
    }
    if (columns == 0u || columns > (uint32_t)ATLAS_MAX_COLUMNS) {
        return PPM_ERR_DIMENSION_TOO_LARGE;
    }

    for (index = 0u; index < count; ++index) {
        const atlas_tile_t *tile = &tiles[index];

        if (tile->pixels == NULL) {
            return PPM_ERR_NULL_ARGUMENT;
        }
        if (tile->width == 0u || tile->height == 0u
            || tile->width > PPM_MAX_DIMENSION || tile->height > PPM_MAX_DIMENSION) {
            return PPM_ERR_DIMENSION_TOO_LARGE;
        }

        widest  = larger_of(widest, tile->width);
        tallest = larger_of(tallest, tile->height);
    }

    *cell_width  = widest;
    *cell_height = tallest;

    /* Rows needed for count tiles at this width. */
    *rows = (uint32_t)((count + (size_t)columns - 1u) / (size_t)columns);

    return PPM_OK;
}

ppm_status_t atlas_target_size(const atlas_tile_t *tiles, size_t count, uint32_t columns,
                               uint32_t *out_width, uint32_t *out_height)
{
    uint32_t     cell_width  = 0;
    uint32_t     cell_height = 0;
    uint32_t     rows        = 0;
    uint64_t     total_width = 0;
    uint64_t     total_height = 0;
    ppm_status_t status      = PPM_OK;

    if (out_width == NULL || out_height == NULL) {
        return PPM_ERR_NULL_ARGUMENT;
    }

    status = survey(tiles, count, columns, &cell_width, &cell_height, &rows);
    if (status != PPM_OK) {
        return status;
    }

    /* The grid is compared at 64 bits before anything is narrowed. */
    total_width  = (uint64_t)cell_width * (uint64_t)columns;
    total_height = (uint64_t)cell_height * (uint64_t)rows;

    if (total_width == 0u || total_width > (uint64_t)PPM_MAX_DIMENSION
        || total_height == 0u || total_height > (uint64_t)PPM_MAX_DIMENSION) {
        return PPM_ERR_DIMENSION_TOO_LARGE;
    }

    *out_width  = (uint32_t)total_width;
    *out_height = (uint32_t)total_height;
    return PPM_OK;
}

/* Records the top-left corner of each tile's cell. */
static void place(placement_t *placement, size_t count, uint32_t columns,
                  uint32_t cell_width, uint32_t cell_height)
{
    size_t index = 0;

    for (index = 0u; index < count; ++index) {
        uint32_t grid_column = (uint32_t)(index % (size_t)columns);
        uint32_t grid_row    = (uint32_t)(index / (size_t)columns);

        placement->x[index] = grid_column * cell_width;
        placement->y[index] = grid_row * cell_height;
    }
}

/*
 * Copies one tile into the atlas at (origin_x, origin_y).
 */
static void blit(ppm_image_t *atlas, const atlas_tile_t *tile,
                 uint32_t origin_x, uint32_t origin_y)
{
    uint32_t last_row    = 0;
    uint32_t last_column = 0;
    uint32_t row         = 0;

    /* Inclusive bounds of the tile. */
    last_row    = tile->height - 1u;
    last_column = tile->width - 1u;

    for (row = 0u; row <= last_row; ++row) {
        uint32_t column = 0u;

        for (column = 0u; column <= last_column; ++column) {
            size_t source_offset =
                ((size_t)row * (size_t)tile->width + (size_t)column) * (size_t)PPM_CHANNELS;

            size_t destination_offset =
                (((size_t)origin_y + (size_t)row) * (size_t)atlas->width
                 + ((size_t)origin_x + (size_t)column)) * (size_t)PPM_CHANNELS;

            atlas->pixels[destination_offset]      = tile->pixels[source_offset];
            atlas->pixels[destination_offset + 1u] = tile->pixels[source_offset + 1u];
            atlas->pixels[destination_offset + 2u] = tile->pixels[source_offset + 2u];
        }
    }
}

ppm_status_t atlas_pack(const atlas_tile_t *tiles, size_t count, uint32_t columns,
                        ppm_image_t *out)
{
    placement_t  placement;
    uint32_t     cell_width   = 0;
    uint32_t     cell_height  = 0;
    uint32_t     rows         = 0;
    uint32_t     atlas_width  = 0;
    uint32_t     atlas_height = 0;
    size_t       index        = 0;
    ppm_status_t status       = PPM_OK;

    if (out == NULL) {
        return PPM_ERR_NULL_ARGUMENT;
    }

    memset(out, 0, sizeof(*out));

    status = survey(tiles, count, columns, &cell_width, &cell_height, &rows);
    if (status != PPM_OK) {
        return status;
    }

    status = atlas_target_size(tiles, count, columns, &atlas_width, &atlas_height);
    if (status != PPM_OK) {
        return status;
    }

    status = ppm_image_init(out, atlas_width, atlas_height);
    if (status != PPM_OK) {
        return status;
    }

    memset(&placement, 0, sizeof(placement));
    place(&placement, count, columns, cell_width, cell_height);

    for (index = 0u; index < count; ++index) {
        blit(out, &tiles[index], placement.x[index], placement.y[index]);
    }

    return PPM_OK;
}
