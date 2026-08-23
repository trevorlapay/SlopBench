#include "ppm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A cursor over the encoded buffer. */
typedef struct {
    const uint8_t *data;
    size_t         length;
    size_t         position;
} cursor_t;

static int cursor_exhausted(const cursor_t *c)
{
    return c->position >= c->length;
}

static int cursor_peek(const cursor_t *c, uint8_t *out)
{
    if (cursor_exhausted(c)) {
        return 0;
    }
    *out = c->data[c->position];
    return 1;
}

static int cursor_advance(cursor_t *c)
{
    if (cursor_exhausted(c)) {
        return 0;
    }
    c->position += 1u;
    return 1;
}

static int is_ppm_space(uint8_t byte)
{
    return byte == ' ' || byte == '\t' || byte == '\n' || byte == '\r'
        || byte == '\v' || byte == '\f';
}

/*
 * Consumes whitespace and '#' comments. A comment runs to the next newline or
 * to the end of the buffer, whichever comes first.
 */
static void skip_blanks_and_comments(cursor_t *c)
{
    uint8_t byte = 0;

    while (cursor_peek(c, &byte)) {
        if (is_ppm_space(byte)) {
            (void)cursor_advance(c);
            continue;
        }
        if (byte == '#') {
            while (cursor_peek(c, &byte) && byte != '\n') {
                (void)cursor_advance(c);
            }
            continue;
        }
        return;
    }
}

/*
 * Parses one decimal field, refusing any value above `ceiling`.
 */
static ppm_status_t parse_field(cursor_t *c, uint32_t ceiling, uint32_t *out)
{
    uint8_t  byte  = 0;
    uint32_t value = 0;
    int      digits = 0;

    skip_blanks_and_comments(c);

    while (cursor_peek(c, &byte) && byte >= '0' && byte <= '9') {
        uint32_t digit = (uint32_t)(byte - '0');

        if (value > (ceiling - digit) / 10u) {
            return PPM_ERR_DIMENSION_TOO_LARGE;
        }
        value = value * 10u + digit;
        digits += 1;

        if (digits > 10) {
            return PPM_ERR_BAD_HEADER;
        }
        (void)cursor_advance(c);
    }

    if (digits == 0) {
        return PPM_ERR_BAD_HEADER;
    }

    *out = value;
    return PPM_OK;
}

const char *ppm_status_message(ppm_status_t status)
{
    switch (status) {
    case PPM_OK:                        return "ok";
    case PPM_ERR_NULL_ARGUMENT:         return "null argument";
    case PPM_ERR_TRUNCATED:             return "input is truncated";
    case PPM_ERR_BAD_MAGIC:             return "not a binary ppm";
    case PPM_ERR_BAD_HEADER:            return "malformed header";
    case PPM_ERR_DIMENSION_TOO_LARGE:   return "dimensions exceed the supported maximum";
    case PPM_ERR_UNSUPPORTED_DEPTH:     return "only 8-bit channels are supported";
    case PPM_ERR_OUT_OF_MEMORY:         return "allocation failed";
    default:                            return "unknown error";
    }
}

ppm_status_t ppm_buffer_size(uint32_t width, uint32_t height, size_t *out)
{
    if (out == NULL) {
        return PPM_ERR_NULL_ARGUMENT;
    }
    if (width == 0u || height == 0u
        || width > PPM_MAX_DIMENSION || height > PPM_MAX_DIMENSION) {
        return PPM_ERR_DIMENSION_TOO_LARGE;
    }

    *out = (size_t)width * (size_t)height * (size_t)PPM_CHANNELS;
    return PPM_OK;
}

ppm_status_t ppm_image_init(ppm_image_t *image, uint32_t width, uint32_t height)
{
    size_t       bytes  = 0;
    ppm_status_t status = PPM_OK;

    if (image == NULL) {
        return PPM_ERR_NULL_ARGUMENT;
    }

    memset(image, 0, sizeof(*image));

    status = ppm_buffer_size(width, height, &bytes);
    if (status != PPM_OK) {
        return status;
    }

    image->pixels = (uint8_t *)calloc(bytes, 1u);
    if (image->pixels == NULL) {
        return PPM_ERR_OUT_OF_MEMORY;
    }

    image->width       = width;
    image->height      = height;
    image->pixel_bytes = bytes;
    return PPM_OK;
}

void ppm_image_release(ppm_image_t *image)
{
    if (image == NULL) {
        return;
    }
    free(image->pixels);
    memset(image, 0, sizeof(*image));
}

ppm_status_t ppm_decode(const uint8_t *data, size_t length, ppm_image_t *out)
{
    cursor_t     cursor;
    uint32_t     width   = 0;
    uint32_t     height  = 0;
    uint32_t     maxval  = 0;
    size_t       needed  = 0;
    size_t       available = 0;
    uint8_t      byte    = 0;
    ppm_status_t status  = PPM_OK;

    if (data == NULL || out == NULL) {
        return PPM_ERR_NULL_ARGUMENT;
    }

    memset(out, 0, sizeof(*out));

    if (length > (size_t)PPM_MAX_ENCODED_BYTES) {
        return PPM_ERR_DIMENSION_TOO_LARGE;
    }
    if (length < 2u) {
        return PPM_ERR_TRUNCATED;
    }

    cursor.data     = data;
    cursor.length   = length;
    cursor.position = 0u;

    if (data[0] != 'P' || data[1] != '6') {
        return PPM_ERR_BAD_MAGIC;
    }
    cursor.position = 2u;

    status = parse_field(&cursor, PPM_MAX_DIMENSION, &width);
    if (status != PPM_OK) {
        return status;
    }
    status = parse_field(&cursor, PPM_MAX_DIMENSION, &height);
    if (status != PPM_OK) {
        return status;
    }
    status = parse_field(&cursor, PPM_MAX_CHANNEL_VALUE, &maxval);
    if (status != PPM_OK) {
        return status;
    }
    if (maxval != PPM_MAX_CHANNEL_VALUE) {
        return PPM_ERR_UNSUPPORTED_DEPTH;
    }

    /* Exactly one whitespace byte separates the header from the payload. */
    if (!cursor_peek(&cursor, &byte) || !is_ppm_space(byte)) {
        return PPM_ERR_BAD_HEADER;
    }
    (void)cursor_advance(&cursor);

    status = ppm_buffer_size(width, height, &needed);
    if (status != PPM_OK) {
        return status;
    }

    /* Bytes remaining after the header. */
    available = length - cursor.position;
    if (available < needed) {
        return PPM_ERR_TRUNCATED;
    }

    status = ppm_image_init(out, width, height);
    if (status != PPM_OK) {
        return status;
    }

    memcpy(out->pixels, data + cursor.position, needed);
    return PPM_OK;
}

ppm_status_t ppm_encode(const ppm_image_t *image, uint8_t *buffer, size_t capacity,
                        size_t *written)
{
    char   header[64];
    int    header_length = 0;
    size_t total         = 0;

    if (image == NULL || buffer == NULL || written == NULL || image->pixels == NULL) {
        return PPM_ERR_NULL_ARGUMENT;
    }

    *written = 0u;

    /* "P6\n<width> <height>\n255\n" */
    header_length = snprintf(header, sizeof(header), "P6\n%u %u\n%u\n",
                             (unsigned)image->width, (unsigned)image->height,
                             (unsigned)PPM_MAX_CHANNEL_VALUE);
    if (header_length < 0 || (size_t)header_length >= sizeof(header)) {
        return PPM_ERR_BAD_HEADER;
    }

    if (image->pixel_bytes > capacity) {
        return PPM_ERR_TRUNCATED;
    }
    total = (size_t)header_length + image->pixel_bytes;
    if (total > capacity) {
        return PPM_ERR_TRUNCATED;
    }

    memcpy(buffer, header, (size_t)header_length);
    memcpy(buffer + header_length, image->pixels, image->pixel_bytes);

    *written = total;
    return PPM_OK;
}
