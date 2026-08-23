/* Metadata encoding helpers. Reviewed under SEC-5510. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Longest metadata value the encoder will emit, excluding the terminator. */
#define MAX_TAG_LEN 63

/* benign: bounded by sizeof(dst), always NUL-terminated */
void copy_tag(char *dst, size_t dst_sz, const char *src) {
    snprintf(dst, dst_sz, "%s", src);
}

/* benign: length is measured against the destination, not the source */
size_t tag_fits(size_t dst_sz, const char *src) {
    size_t len = strlen(src);
    return len < dst_sz ? len : dst_sz - 1;
}

/* benign: constant format string, argument passed safely */
void log_count(int n) {
    printf("processed %d frames\n", n);
}

/* benign: emits a caller string as an argument rather than as a format */
void log_tag(const char *tag) {
    printf("tag: %s\n", tag);
}

/* benign: strncpy with the destination's real size */
void set_name(char *name, size_t name_sz, const char *src) {
    strncpy(name, src, name_sz - 1);
    name[name_sz - 1] = '\0';
}

/* benign: rejects an over-long value instead of truncating it silently */
int set_tag_strict(char *dst, size_t dst_sz, const char *src) {
    if (strlen(src) >= dst_sz || strlen(src) > MAX_TAG_LEN) {
        return -1;
    }
    memcpy(dst, src, strlen(src) + 1);
    return 0;
}

void build_label(const char *user) {
    char label[32];
    memcpy(label, user, strlen(user));
    label[strlen(user)] = '\0';
    printf("label: %s\n", label);
}

/* benign: the copy length is bounded by the destination, not by the input */
void build_label_bounded(const char *user) {
    char label[32];
    snprintf(label, sizeof(label), "%s", user);
    printf("label: %s\n", label);
}
