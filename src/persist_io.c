/**
 * @file persist_io.c
 * @brief POSIX and Windows implementation of the private file layer.
 *
 * Every file opened through this module is verified to be a regular, privately
 * owned, singly linked file. Durability primitives (fsync, F_FULLFSYNC,
 * FlushFileBuffers, write-through renames) are centralised here so the rest of
 * the code base never needs platform conditionals for storage.
 */

#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <fcntl.h>
#include <io.h>
#include <windows.h>

/* SDDL declarations depend on the Windows types and calling conventions. */
#include <sddl.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "persist_io.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/** @brief Accept only non-empty paths shorter than #CV_PERSIST_PATH_LIMIT. */
static bool valid_path(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return false;
    }

    for (size_t i = 0; i < CV_PERSIST_PATH_LIMIT; ++i) {
        if (path[i] == '\0') {
            return true;
        }
    }

    return false;
}

char *cv_io_path(const char *directory, const char *name) {
    if (!valid_path(directory) || name == NULL || (name[0] != '\0' && !valid_path(name))) {
        return NULL;
    }

    size_t directory_length = strlen(directory), name_length = strlen(name);

    if (directory_length + name_length + 2 > CV_PERSIST_PATH_LIMIT) {
        return NULL;
    }

    char *path = malloc(directory_length + name_length + 2);

    if (path != NULL) {
        memcpy(path, directory, directory_length);
        path[directory_length] = '/';
        memcpy(path + directory_length + 1, name, name_length + 1);
    }

    return path;
}

#ifdef _WIN32
/** @brief Convert a UTF-8 path to a newly allocated wide string (NULL on error). */
static wchar_t *wide_path(const char *path) {
    if (!valid_path(path)) {
        return NULL;
    }

    int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);

    if (length <= 0) {
        return NULL;
    }

    wchar_t *wide = malloc((size_t)length * sizeof(*wide));

    if (wide != NULL &&
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, length) == 0) {
        free(wide);

        return NULL;
    }

    return wide;
}

/**
 * @brief Build a protected DACL for new files and directories.
 *
 * Only the owning identity and SYSTEM may access the object. OWNER RIGHTS
 * follows the file owner, and inherited broad permissions are removed. The
 * caller releases `lpSecurityDescriptor` with LocalFree().
 */
static bool private_security(SECURITY_ATTRIBUTES *attributes) {
    PSECURITY_DESCRIPTOR descriptor = NULL;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)", SDDL_REVISION_1, &descriptor, NULL)) {
        return false;
    }

    *attributes = (SECURITY_ATTRIBUTES){sizeof(*attributes), descriptor, FALSE};

    return true;
}

/** @brief Check that a handle is a plain file with exactly one hard link. */
static bool regular_handle(HANDLE handle) {
    BY_HANDLE_FILE_INFORMATION info;

    return GetFileInformationByHandle(handle, &info) != 0 &&
           (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ==
               0 &&
           info.nNumberOfLinks == 1;
}
#endif

cv_status cv_io_sync_directory(const char *path) {
#ifdef _WIN32
    (void)path;

    /* Windows publication uses file flush + same-directory write-through rename. */
    return CV_OK;
#else
    int descriptor = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);

    if (descriptor < 0) {
        return CV_ERR_IO;
    }

    int result;

    do {
        result = fsync(descriptor);
    } while (result < 0 && errno == EINTR);

    (void)close(descriptor);

    return result == 0 ? CV_OK : CV_ERR_IO;
#endif
}

cv_status cv_io_sync_parent(const char *path) {
    char *parent = malloc(strlen(path) + 1);

    if (parent == NULL) {
        return CV_ERR_NO_MEMORY;
    }

    memcpy(parent, path, strlen(path) + 1);

    /* Drop trailing slashes, then cut at the last separator. */
    size_t length = strlen(parent);

    while (length > 1 && parent[length - 1] == '/') {
        parent[--length] = '\0';
    }

    char *separator = strrchr(parent, '/');

    if (separator == parent) {
        separator[1] = '\0';
    } else if (separator != NULL) {
        *separator = '\0';
    } else {
        /* A bare file name lives in the current directory. */
        parent[0] = '.';
        parent[1] = '\0';
    }

    cv_status status = cv_io_sync_directory(parent);

    free(parent);

    return status;
}

cv_status cv_io_directory(const char *path) {
    if (!valid_path(path)) {
        return CV_ERR_INVALID_ARGUMENT;
    }

#ifdef _WIN32
    wchar_t *wide = wide_path(path);

    if (wide == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    SECURITY_ATTRIBUTES attributes;

    if (!private_security(&attributes)) {
        free(wide);

        return CV_ERR_IO;
    }

    BOOL created = CreateDirectoryW(wide, &attributes);
    DWORD error = GetLastError();

    LocalFree(attributes.lpSecurityDescriptor);

    DWORD flags = GetFileAttributesW(wide);

    free(wide);

    if ((!created && error != ERROR_ALREADY_EXISTS) || flags == INVALID_FILE_ATTRIBUTES ||
        !(flags & FILE_ATTRIBUTE_DIRECTORY) || (flags & FILE_ATTRIBUTE_REPARSE_POINT)) {
        return CV_ERR_IO;
    }

    return CV_OK;
#else
    bool created = mkdir(path, 0700) == 0;

    if (!created && errno != EEXIST) {
        return CV_ERR_IO;
    }

    char *normalized = malloc(strlen(path) + 1);

    if (normalized == NULL) {
        return CV_ERR_NO_MEMORY;
    }

    memcpy(normalized, path, strlen(path) + 1);

    size_t length = strlen(normalized);

    while (length > 1 && normalized[length - 1] == '/') {
        normalized[--length] = '\0';
    }

    /* lstat() so that a symlink in the leaf position is rejected, not followed. */
    struct stat info;
    bool safe = lstat(normalized, &info) == 0 && S_ISDIR(info.st_mode) &&
                info.st_uid == geteuid() && (info.st_mode & 0022) == 0;

    free(normalized);

    if (!safe) {
        return CV_ERR_IO;
    }

    return created ? cv_io_sync_parent(path) : CV_OK;
#endif
}

cv_status cv_io_open(const char *path, bool create, bool exclusive, bool writable, FILE **out) {
    if (out == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    *out = NULL;

    if (!valid_path(path)) {
        return CV_ERR_INVALID_ARGUMENT;
    }

#ifdef _WIN32
    wchar_t *wide = wide_path(path);
    SECURITY_ATTRIBUTES attributes;

    if (wide == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    if (!private_security(&attributes)) {
        free(wide);

        return CV_ERR_IO;
    }

    DWORD disposition = exclusive ? CREATE_NEW : (create ? OPEN_ALWAYS : OPEN_EXISTING);
    HANDLE handle = CreateFileW(wide,
                                GENERIC_READ | (writable ? GENERIC_WRITE : 0),
                                FILE_SHARE_READ,
                                &attributes,
                                disposition,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                                NULL);
    DWORD error = GetLastError();

    LocalFree(attributes.lpSecurityDescriptor);
    free(wide);

    if (handle == INVALID_HANDLE_VALUE) {
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            return CV_ERR_NOT_FOUND;
        }

        return error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS ? CV_ERR_BUSY
                                                                           : CV_ERR_IO;
    }

    if (!regular_handle(handle)) {
        CloseHandle(handle);

        return CV_ERR_IO;
    }

    int descriptor =
        _open_osfhandle((intptr_t)handle, _O_BINARY | (writable ? _O_RDWR : _O_RDONLY));

    if (descriptor < 0) {
        CloseHandle(handle);

        return CV_ERR_IO;
    }

    *out = _fdopen(descriptor, writable ? "r+b" : "rb");

    if (*out == NULL) {
        _close(descriptor);

        return CV_ERR_IO;
    }
#else
    /* O_NOFOLLOW rejects a symlink in the leaf position; fstat() below rejects
     * anything that is not a private, singly linked regular file we own. */
    int flags = writable ? O_RDWR : O_RDONLY;

    flags |= O_CLOEXEC | O_NOFOLLOW;

    if (create) {
        flags |= O_CREAT;
    }

    if (exclusive) {
        flags |= O_EXCL;
    }

    int descriptor = open(path, flags, 0600);

    if (descriptor < 0) {
        return errno == ENOENT ? CV_ERR_NOT_FOUND : (errno == EEXIST ? CV_ERR_BUSY : CV_ERR_IO);
    }

    struct stat info;

    if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != geteuid() ||
        info.st_nlink != 1 || (info.st_mode & 0077) != 0) {
        (void)close(descriptor);

        return CV_ERR_IO;
    }

    *out = fdopen(descriptor, writable ? "r+b" : "rb");

    if (*out == NULL) {
        (void)close(descriptor);

        return CV_ERR_IO;
    }
#endif

    return CV_OK;
}

cv_status cv_io_lock(const char *path, cv_file_lock *lock) {
    lock->native = -1;

#ifdef _WIN32
    wchar_t *wide = wide_path(path);
    SECURITY_ATTRIBUTES attributes;

    if (wide == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    if (!private_security(&attributes)) {
        free(wide);

        return CV_ERR_IO;
    }

    /* Share mode 0 makes a second opener fail with a sharing violation. */
    HANDLE handle = CreateFileW(wide,
                                GENERIC_READ | GENERIC_WRITE,
                                0,
                                &attributes,
                                OPEN_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                                NULL);
    DWORD error = GetLastError();

    LocalFree(attributes.lpSecurityDescriptor);
    free(wide);

    if (handle == INVALID_HANDLE_VALUE) {
        return error == ERROR_SHARING_VIOLATION ? CV_ERR_BUSY : CV_ERR_IO;
    }

    if (!regular_handle(handle)) {
        CloseHandle(handle);

        return CV_ERR_IO;
    }

    lock->native = (intptr_t)handle;
#else
    int descriptor = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);

    if (descriptor < 0) {
        return CV_ERR_IO;
    }

    struct stat info;

    if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != geteuid() ||
        info.st_nlink != 1 || (info.st_mode & 0077) != 0) {
        (void)close(descriptor);

        return CV_ERR_IO;
    }

    if (flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
        cv_status status = errno == EWOULDBLOCK ? CV_ERR_BUSY : CV_ERR_IO;

        (void)close(descriptor);

        return status;
    }

    lock->native = descriptor;
#endif

    return CV_OK;
}

void cv_io_unlock(cv_file_lock *lock) {
    if (lock->native == -1) {
        return;
    }

#ifdef _WIN32
    CloseHandle((HANDLE)lock->native);
#else
    (void)flock((int)lock->native, LOCK_UN);
    (void)close((int)lock->native);
#endif

    lock->native = -1;
}

cv_status cv_io_write(FILE *file, const void *bytes, size_t length) {
    return fwrite(bytes, 1, length, file) == length ? CV_OK : CV_ERR_IO;
}

cv_status cv_io_sync(FILE *file) {
    if (fflush(file) != 0) {
        return CV_ERR_IO;
    }

#ifdef _WIN32
    return FlushFileBuffers((HANDLE)_get_osfhandle(_fileno(file))) ? CV_OK : CV_ERR_IO;
#else
    int result;

    do {
        result = fsync(fileno(file));
    } while (result < 0 && errno == EINTR);

#ifdef __APPLE__
    /* Apple fsync alone does not request flushing the drive's write cache. */
    if (result == 0) {
        do {
            result = fcntl(fileno(file), F_FULLFSYNC);
        } while (result < 0 && errno == EINTR);
    }
#endif

    return result == 0 ? CV_OK : CV_ERR_IO;
#endif
}

cv_status cv_io_seek(FILE *file, uint64_t offset) {
    if (offset > INT64_MAX) {
        return CV_ERR_LIMIT;
    }

#ifdef _WIN32
    return _fseeki64(file, (__int64)offset, SEEK_SET) == 0 ? CV_OK : CV_ERR_IO;
#else
    return fseeko(file, (off_t)offset, SEEK_SET) == 0 ? CV_OK : CV_ERR_IO;
#endif
}

cv_status cv_io_tell(FILE *file, uint64_t *offset) {
#ifdef _WIN32
    __int64 position = _ftelli64(file);
#else
    off_t position = ftello(file);
#endif

    if (position < 0) {
        return CV_ERR_IO;
    }

    *offset = (uint64_t)position;

    return CV_OK;
}

cv_status cv_io_truncate(FILE *file, uint64_t offset) {
    if (offset > INT64_MAX) {
        return CV_ERR_LIMIT;
    }

#ifdef _WIN32
    if (_chsize_s(_fileno(file), offset) != 0) {
        return CV_ERR_IO;
    }
#else
    if (ftruncate(fileno(file), (off_t)offset) != 0) {
        return CV_ERR_IO;
    }
#endif

    return cv_io_seek(file, offset) == CV_OK ? cv_io_sync(file) : CV_ERR_IO;
}

cv_status cv_io_publish(const char *temporary, const char *destination, const char *directory) {
#ifdef _WIN32
    wchar_t *source = wide_path(temporary), *target = wide_path(destination);

    if (source == NULL || target == NULL) {
        free(source);
        free(target);

        return CV_ERR_NO_MEMORY;
    }

    BOOL success = MoveFileExW(source, target, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);

    free(source);
    free(target);

    if (!success) {
        return CV_ERR_IO;
    }
#else
    if (rename(temporary, destination) != 0) {
        return CV_ERR_IO;
    }
#endif

    return cv_io_sync_directory(directory);
}

void cv_io_remove(const char *path) {
#ifdef _WIN32
    wchar_t *wide = wide_path(path);

    if (wide != NULL) {
        (void)DeleteFileW(wide);
        free(wide);
    }
#else
    (void)unlink(path);
#endif
}
