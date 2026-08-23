/* Bounds-checked image geometry helpers. */
#include <stddef.h>
#include <string.h>

typedef struct {
    int width;
    int height;
} Size;

int clampi(int v, int lo, int hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

/* Returns 1 and writes the pixel index if (x, y) is inside the image, else 0. */
int pixel_index(const Size *img, int x, int y, size_t *out_index) {
    if (x < 0 || y < 0 || x >= img->width || y >= img->height) {
        return 0;
    }
    *out_index = (size_t)y * (size_t)img->width + (size_t)x;
    return 1;
}

/* Safe copy: never writes more than dst_cap bytes and always NUL-terminates. */
size_t copy_label(char *dst, size_t dst_cap, const char *src) {
    if (dst_cap == 0) {
        return 0;
    }
    size_t i = 0;
    while (i + 1 < dst_cap && src[i] != '\0') {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    return i;
}

/* Overflow-checked allocation size; returns 0 on overflow. */
size_t buffer_bytes(size_t count, size_t elem_size) {
    if (elem_size != 0 && count > (size_t)-1 / elem_size) {
        return 0;
    }
    return count * elem_size;
}

int histogram_add(unsigned int *bins, size_t bin_count, unsigned char value) {
    size_t idx = (size_t)value * bin_count / 256;
    if (idx >= bin_count) {
        return 0;
    }
    bins[idx]++;
    return 1;
}
/* Rectangle intersection; returns 0 when the rectangles do not overlap. */
int intersect(const Size *a, const Size *b, Size *out) {
    int w = a->width < b->width ? a->width : b->width;
    int h = a->height < b->height ? a->height : b->height;
    if (w <= 0 || h <= 0) {
        return 0;
    }
    out->width = w;
    out->height = h;
    return 1;
}

/* Total pixel count, or 0 when the dimensions would overflow the product. */
size_t pixel_count(const Size *img) {
    if (img->width <= 0 || img->height <= 0) {
        return 0;
    }
    return buffer_bytes((size_t)img->width, (size_t)img->height);
}

/* Scale a dimension to fit inside a box while preserving the aspect ratio. */
void fit_within(const Size *src, const Size *box, Size *out) {
    if (src->width <= 0 || src->height <= 0) {
        out->width = 0;
        out->height = 0;
        return;
    }
    int by_width = box->width * src->height / src->width;
    if (by_width <= box->height) {
        out->width = box->width;
        out->height = by_width;
    } else {
        out->width = box->height * src->width / src->height;
        out->height = box->height;
    }
}

/* Clamp a rectangle so it lies entirely inside the image bounds. */
void clamp_rect(const Size *img, int *x, int *y, int *w, int *h) {
    *x = clampi(*x, 0, img->width);
    *y = clampi(*y, 0, img->height);
    *w = clampi(*w, 0, img->width - *x);
    *h = clampi(*h, 0, img->height - *y);
}

/* Reset every bin to zero before a histogram pass. */
void histogram_reset(unsigned int *bins, size_t bin_count) {
    memset(bins, 0, bin_count * sizeof(unsigned int));
}

/* Index of the fullest bin, or bin_count when the histogram is empty. */
size_t histogram_peak(const unsigned int *bins, size_t bin_count) {
    size_t best = bin_count;
    unsigned int best_value = 0;
    for (size_t i = 0; i < bin_count; i++) {
        if (bins[i] > best_value) {
            best_value = bins[i];
            best = i;
        }
    }
    return best;
}
