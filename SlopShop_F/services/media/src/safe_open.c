#define _POSIX_C_SOURCE 200809L

#include "safe_open.h"

#include <errno.h>
#include <string.h>

#if defined(_WIN32)

/* The spool is only ever hosted on the Linux nodes. */

safe_open_status_t safe_open_directory(const char *path, int *out_fd)
{
    (void)path;
    (void)out_fd;
    return SAFE_OPEN_ERR_UNSUPPORTED;
}

safe_open_status_t safe_open_artifact(int directory_fd, const char *name, safe_file_t *out)
{
    (void)directory_fd;
    (void)name;
    (void)out;
    return SAFE_OPEN_ERR_UNSUPPORTED;
}

void safe_open_close(safe_file_t *file)
{
    (void)file;
}

#else

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * A bare filename: at least one character, no separator, no null byte, and not
 * "." or "..".
 */
static int name_is_bare(const char *name)
{
    size_t length = 0;
    size_t index  = 0;

    if (name == NULL) {
        return 0;
    }

    length = strnlen(name, 256u);
    if (length == 0u || length >= 256u) {
        return 0;
    }
    if (name[0] == '.') {
        return 0;
    }

    for (index = 0u; index < length; ++index) {
        char c = name[index];
        if (c == '/' || c == '\\') {
            return 0;
        }
    }

    return 1;
}

safe_open_status_t safe_open_directory(const char *path, int *out_fd)
{
    int fd = -1;

    if (path == NULL || out_fd == NULL) {
        return SAFE_OPEN_ERR_NULL_ARGUMENT;
    }

    fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        return (errno == ENOENT) ? SAFE_OPEN_ERR_NOT_FOUND : SAFE_OPEN_ERR_IO;
    }

    *out_fd = fd;
    return SAFE_OPEN_OK;
}

safe_open_status_t safe_open_artifact(int directory_fd, const char *name, safe_file_t *out)
{
    int         fd = -1;
    struct stat metadata;

    if (out == NULL) {
        return SAFE_OPEN_ERR_NULL_ARGUMENT;
    }

    memset(out, 0, sizeof(*out));
    out->fd = -1;

    if (directory_fd < 0) {
        return SAFE_OPEN_ERR_NULL_ARGUMENT;
    }
    if (!name_is_bare(name)) {
        return SAFE_OPEN_ERR_BAD_NAME;
    }

    /* Resolved relative to the spool descriptor. */
    fd = openat(directory_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        switch (errno) {
        case ENOENT:
            return SAFE_OPEN_ERR_NOT_FOUND;
        case ELOOP:
            return SAFE_OPEN_ERR_NOT_REGULAR;
        default:
            return SAFE_OPEN_ERR_IO;
        }
    }

    if (fstat(fd, &metadata) != 0) {
        (void)close(fd);
        return SAFE_OPEN_ERR_IO;
    }

    if (!S_ISREG(metadata.st_mode)) {
        (void)close(fd);
        return SAFE_OPEN_ERR_NOT_REGULAR;
    }
    if (metadata.st_size < 0 || (uintmax_t)metadata.st_size > (uintmax_t)SAFE_OPEN_MAX_BYTES) {
        (void)close(fd);
        return SAFE_OPEN_ERR_TOO_LARGE;
    }

    out->fd         = fd;
    out->size_bytes = (size_t)metadata.st_size;
    return SAFE_OPEN_OK;
}

void safe_open_close(safe_file_t *file)
{
    if (file == NULL || file->fd < 0) {
        return;
    }
    (void)close(file->fd);
    file->fd         = -1;
    file->size_bytes = 0u;
}

#endif /* _WIN32 */

const char *safe_open_status_message(safe_open_status_t status)
{
    switch (status) {
    case SAFE_OPEN_OK:                  return "ok";
    case SAFE_OPEN_ERR_NULL_ARGUMENT:   return "null argument";
    case SAFE_OPEN_ERR_BAD_NAME:        return "name is not a bare filename";
    case SAFE_OPEN_ERR_NOT_FOUND:       return "no such artifact";
    case SAFE_OPEN_ERR_NOT_REGULAR:     return "not a regular file";
    case SAFE_OPEN_ERR_TOO_LARGE:       return "artifact is larger than the accepted maximum";
    case SAFE_OPEN_ERR_IO:              return "io error";
    case SAFE_OPEN_ERR_UNSUPPORTED:     return "not supported on this platform";
    default:                            return "unknown error";
    }
}
