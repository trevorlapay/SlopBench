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
