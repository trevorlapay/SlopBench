#include "thumbnail.h"

#include <string.h>

/* Ceiling division for positive divisors. */
static uint32_t divide_rounding_up(uint32_t dividend, uint32_t divisor)
{
    return (dividend + (divisor - 1u)) / divisor;
}

static uint32_t larger_of(uint32_t left, uint32_t right)
{
    return left > right ? left : right;
}

static uint32_t smaller_of(uint32_t left, uint32_t right)
{
    return left < right ? left : right;
}

ppm_status_t thumbnail_target_size(uint32_t source_width, uint32_t source_height,
                                   uint32_t max_edge, uint32_t *out_width,
                                   uint32_t *out_height)
{
    uint32_t longest = 0;
    uint32_t factor  = 0;

    if (out_width == NULL || out_height == NULL) {
        return PPM_ERR_NULL_ARGUMENT;
    }
    if (max_edge < THUMBNAIL_MIN_EDGE || max_edge > THUMBNAIL_MAX_EDGE) {
        return PPM_ERR_DIMENSION_TOO_LARGE;
    }
    if (source_width == 0u || source_height == 0u
        || source_width > PPM_MAX_DIMENSION || source_height > PPM_MAX_DIMENSION) {
        return PPM_ERR_DIMENSION_TOO_LARGE;
    }

    longest = larger_of(source_width, source_height);

    /* A source that already fits is reproduced at its own size. */
    if (longest <= max_edge) {
        *out_width  = source_width;
        *out_height = source_height;
        return PPM_OK;
    }

    factor = divide_rounding_up(longest, max_edge);

    *out_width  = divide_rounding_up(source_width, factor);
    *out_height = divide_rounding_up(source_height, factor);

    return PPM_OK;
}

ppm_status_t thumbnail_generate(const ppm_image_t *source, uint32_t max_edge,
                                ppm_image_t *destination)
{
    uint32_t     target_width  = 0;
    uint32_t     target_height = 0;
    uint32_t     factor        = 0;
    uint32_t     longest       = 0;
    uint32_t     row           = 0;
    ppm_status_t status        = PPM_OK;

    if (source == NULL || destination == NULL || source->pixels == NULL) {
        return PPM_ERR_NULL_ARGUMENT;
    }

    memset(destination, 0, sizeof(*destination));

    status = thumbnail_target_size(source->width, source->height, max_edge,
                                   &target_width, &target_height);
    if (status != PPM_OK) {
        return status;
    }

    /* The buffer must match the dimensions in the header. */
    {
        size_t expected = 0;
        status = ppm_buffer_size(source->width, source->height, &expected);
        if (status != PPM_OK) {
            return status;
        }
        if (source->pixel_bytes != expected) {
            return PPM_ERR_TRUNCATED;
        }
    }

    status = ppm_image_init(destination, target_width, target_height);
    if (status != PPM_OK) {
        return status;
    }

    if (target_width == source->width && target_height == source->height) {
        memcpy(destination->pixels, source->pixels, source->pixel_bytes);
        return PPM_OK;
    }

    longest = larger_of(source->width, source->height);
    factor  = divide_rounding_up(longest, max_edge);

    for (row = 0u; row < target_height; ++row) {
        uint32_t column = 0u;

        /* Source rows this destination row averages over. */
        uint32_t row_start = row * factor;
        uint32_t row_end   = smaller_of(row_start + factor, source->height);

        for (column = 0u; column < target_width; ++column) {
            uint32_t column_start = column * factor;
            uint32_t column_end   = smaller_of(column_start + factor, source->width);

            uint64_t red = 0, green = 0, blue = 0;
            uint64_t samples = 0;
            uint32_t sy = 0;
            size_t   destination_index = 0;

            for (sy = row_start; sy < row_end; ++sy) {
                uint32_t sx = 0;
                for (sx = column_start; sx < column_end; ++sx) {
                    size_t offset =
                        ((size_t)sy * (size_t)source->width + (size_t)sx) * (size_t)PPM_CHANNELS;

                    red     += source->pixels[offset];
                    green   += source->pixels[offset + 1u];
                    blue    += source->pixels[offset + 2u];
                    samples += 1u;
                }
            }

            destination_index =
                ((size_t)row * (size_t)target_width + (size_t)column) * (size_t)PPM_CHANNELS;

            destination->pixels[destination_index]      = (uint8_t)(red / samples);
            destination->pixels[destination_index + 1u] = (uint8_t)(green / samples);
            destination->pixels[destination_index + 2u] = (uint8_t)(blue / samples);
        }
    }

    return PPM_OK;
}
