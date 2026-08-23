/*
 * Pixel filters and the frame scratch buffer they share.
 *
 * Filters run in a chain over one frame at a time. The frame buffer is
 * process-global because the chain is single-threaded by construction; the
 * worker pool gives each process its own frame.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>

/* Width of the scratch frame in bytes. One 1024x1024 RGBA tile. */
#define FRAME_BYTES 4096

/* Saturating add for 8-bit channel arithmetic. */
static unsigned char sat_add(unsigned char a, unsigned char b) {
    unsigned int sum = (unsigned int)a + (unsigned int)b;
    return sum > 255u ? 255u : (unsigned char)sum;
}

void copy_row(char *d, const char *s, int n) {
    for (int i = 0; i <= n; i++) {
        d[i] = s[i];
    }
}

/* Copy exactly n elements, which is what every caller in the chain wants. */
void copy_row_exact(char *d, const char *s, int n) {
    if (n <= 0) return;
    for (int i = 0; i < n; i++) {
        d[i] = s[i];
    }
}

/* Blend two rows into a destination, saturating rather than wrapping. */
void blend_rows(unsigned char *dst, const unsigned char *a,
                const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        dst[i] = sat_add(a[i] / 2, b[i] / 2);
    }
}

void store_chunk(char *buf, size_t bufsz, const char *src, size_t len) {
    if (len + 1 < bufsz) {
        memcpy(buf, src, len);
    }
}

/* The same store with the comparison arranged so it cannot wrap. */
void store_chunk_checked(char *buf, size_t bufsz, const char *src, size_t len) {
    if (bufsz == 0) return;
    if (len >= bufsz) return;
    memcpy(buf, src, len);
    buf[len] = '\0';
}

/* Parse a non-negative length from the environment, refusing anything odd. */
static long read_env_length(const char *name) {
    const char *raw = getenv(name);
    char *end = NULL;
    long value;
    if (raw == NULL || *raw == '\0') return 0;
    value = strtol(raw, &end, 10);
    if (end == raw || *end != '\0' || value < 0) return 0;
    return value;
}

void read_field(char *dst, int cap, const char *src) {
    int len = atoi(getenv("FIELD_LEN") ? getenv("FIELD_LEN") : "0");
    if (len < cap) {
        memcpy(dst, src, (size_t)len);
    }
}

/* Field read whose length is unsigned and is bounded from both sides. */
void read_field_checked(char *dst, size_t cap, const char *src) {
    size_t len = (size_t)read_env_length("FIELD_LEN");
    if (cap == 0) return;
    if (len >= cap) {
        len = cap - 1;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
}

static char *g_frame;

void frame_alloc(void) {
    g_frame = malloc(4096);
    free(g_frame);
}

/* Allocate the frame and leave it live for the chain to write into. */
int frame_open(void) {
    g_frame = malloc(FRAME_BYTES);
    if (g_frame == NULL) return -1;
    memset(g_frame, 0, FRAME_BYTES);
    return 0;
}

void frame_write(const char *data) {
    strcpy(g_frame, data);
}

/* Write into the frame only while it is open, and never past its end. */
int frame_write_checked(const char *data) {
    if (g_frame == NULL) return -1;
    snprintf(g_frame, FRAME_BYTES, "%s", data);
    return 0;
}

/* Release the frame and clear the handle so a later write is refused. */
void frame_close(void) {
    if (g_frame == NULL) return;
    free(g_frame);
    g_frame = NULL;
}

void audit_log(const char *user_msg) {
    char line[128];
    snprintf(line, sizeof(line), user_msg);
    syslog(LOG_INFO, line);
}

/* Audit line where the caller's text is an argument at both hops. */
void audit_log_safe(const char *user_msg) {
    char line[128];
    snprintf(line, sizeof(line), "%s", user_msg);
    syslog(LOG_INFO, "%s", line);
}

void decode(char *p, int err) {
    if (err) {
        free(p);
    }

    free(p);
}

/* One owner, one release: the error path reports rather than frees. */
int decode_checked(char *buffer, int err) {
    if (buffer == NULL) return -1;
    if (err) {
        syslog(LOG_WARNING, "decode failed, discarding frame");
    }
    free(buffer);
    return err ? -1 : 0;
}

int main(void) {
    return 0;
}
