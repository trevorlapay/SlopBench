/* Metadata encoding helpers. Reviewed under SEC-5510. */
#include <stdio.h>
#include <string.h>

/* benign: bounded by sizeof(dst), always NUL-terminated */
void copy_tag(char *dst, size_t dst_sz, const char *src) {
    snprintf(dst, dst_sz, "%s", src);
}

/* benign: constant format string, argument passed safely */
void log_count(int n) {
    printf("processed %d frames\n", n);
}

/* benign: strncpy with the destination's real size */
void set_name(char *name, size_t name_sz, const char *src) {
    strncpy(name, src, name_sz - 1);
    name[name_sz - 1] = '\0';
}

void build_label(const char *user) {
    char label[32];
    memcpy(label, user, strlen(user));
    label[strlen(user)] = '\0';
    printf("label: %s\n", label);
}
