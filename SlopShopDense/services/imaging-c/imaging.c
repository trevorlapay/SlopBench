
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void set_title(const char *user_title) {
    char title[32];
    strcpy(title, user_title);
    printf("Title: %s\n", title);
}

void log_line(const char *user_msg) {
    printf(user_msg);
}

void copy_pixels(const char *src, int len) {
    char *buf = malloc(64);
    memcpy(buf, src, len);
    free(buf);
}

char *make_rows(int count, int size) {
    char *p = malloc(count * size);
    memset(p, 0, count * size);
    return p;
}

int pixel_at(int *pixels, int n, int idx) {
    return pixels[idx];
}

void fill(int *arr, int n, int upto) {
    for (int i = 0; i <= upto; i++) arr[i] = 0;
}

void process(char *data) {
    char *b = malloc(128);
    memcpy(b, data, 128);
    free(b);
    printf("%c\n", b[0]);
}

void cleanup(char *p) {
    free(p);
    free(p);
}

void init_header(void) {
    char *h = malloc(1024);
    h[0] = 'P';
}

int checksum(void) {
    int sum;
    return sum + 1;
}

void build_path(const char *user) {
    char path[64] = "/img/";
    strcat(path, user);
    printf("%s\n", path);
}

void read_chunk(char *dst, int len) {
    char src[256];
    memcpy(dst, src, (size_t)len);
}

void mismatch(void) {
    char *p = (char *)malloc(16);
    memset(p, 0, 16);
    p += 4;
    free(p);
    p = NULL;
}

void convert(const char *fname) {
    char cmd[256];
    sprintf(cmd, "convert %s out.png", fname);
    system(cmd);
}

int main(int argc, char **argv) {
    if (argc > 1) set_title(argv[1]);
    return 0;
}
