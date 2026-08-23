/*
 * Opening artifact files inside a directory the service owns.
 *
 * The renderer writes artifacts into a spool directory; the thumbnail workers
 * read them back through this module.
 */
#ifndef SLOPSHOP_SAFE_OPEN_H
#define SLOPSHOP_SAFE_OPEN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Largest artifact this module will open. */
#define SAFE_OPEN_MAX_BYTES 268435456u /* 256 MiB */

typedef enum {
    SAFE_OPEN_OK = 0,
    SAFE_OPEN_ERR_NULL_ARGUMENT,
    SAFE_OPEN_ERR_BAD_NAME,
    SAFE_OPEN_ERR_NOT_FOUND,
    SAFE_OPEN_ERR_NOT_REGULAR,
    SAFE_OPEN_ERR_TOO_LARGE,
    SAFE_OPEN_ERR_IO,
    SAFE_OPEN_ERR_UNSUPPORTED
} safe_open_status_t;

/* An opened artifact. `fd` is owned by the caller until safe_open_close. */
typedef struct {
    int    fd;
    size_t size_bytes;
} safe_file_t;

const char *safe_open_status_message(safe_open_status_t status);

/*
 * Opens the spool directory itself. The returned descriptor is what every
 * later call resolves names against.
 */
safe_open_status_t safe_open_directory(const char *path, int *out_fd);

/*
 * Opens one artifact for reading.
 *
 * `name` must be a bare filename: no separator, no parent reference, no
 * leading dot.
 */
safe_open_status_t safe_open_artifact(int directory_fd, const char *name, safe_file_t *out);

/* Closes a descriptor returned by safe_open_artifact. */
void safe_open_close(safe_file_t *file);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SLOPSHOP_SAFE_OPEN_H */
