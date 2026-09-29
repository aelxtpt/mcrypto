#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#ifndef __APPLE__
#include <sys/random.h>
#endif
#include <sys/syscall.h>
#include <unistd.h>

#ifdef __APPLE__
extern int getentropy(void *, size_t);
#endif

static unsigned long getrandom_calls;

static int fault_is(const char *name) {
    const char *fault = getenv("MCRYPTO_FAULT");
    return fault != NULL && strcmp(fault, name) == 0;
}

static void log_event(const char *event, size_t length, int zero) {
    const char *path = getenv("MCRYPTO_FAULT_LOG");
    if (path == NULL) return;
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) return;
    char line[160];
    int count = snprintf(
        line, sizeof(line), "%s length=%zu zero=%d call=%lu\n",
        event, length, zero, getrandom_calls
    );
    if (count > 0) (void) write(fd, line, (size_t) count);
    (void) close(fd);
}

#ifndef __APPLE__
ssize_t getrandom(void *buffer, size_t length, unsigned int flags) {
    ++getrandom_calls;
    if (fault_is("getrandom-control")) {
        memset(buffer, 0xA5, length);
        log_event("getrandom-control", length, 0);
        return (ssize_t) length;
    }
    if (fault_is("getrandom-error")) {
        log_event("getrandom-error", length, 0);
        errno = EIO;
        return -1;
    }
    if (fault_is("getrandom-eintr") && getrandom_calls == 1) {
        log_event("getrandom-eintr", length, 0);
        errno = EINTR;
        return -1;
    }
    size_t requested = length;
    if (fault_is("getrandom-partial") && requested > 7) requested = 7;
    ssize_t result = syscall(SYS_getrandom, buffer, requested, flags);
    log_event(
        fault_is("getrandom-partial") ? "getrandom-partial" : "getrandom",
        result > 0 ? (size_t) result : 0,
        0
    );
    return result;
}
#else
static int fallback_entropy(void *buffer, size_t length) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t filled = 0;
    while (filled < length) {
        ssize_t received = read(fd, (unsigned char *)buffer + filled, length - filled);
        if (received <= 0) {
            (void) close(fd);
            return -1;
        }
        filled += (size_t) received;
    }
    return close(fd);
}

int mcrypto_getentropy(void *buffer, size_t length) {
    static int (*real_getentropy)(void *, size_t);
    static int resolving;
    static int error_delivered;
    if (real_getentropy == NULL) {
        if (resolving) return fallback_entropy(buffer, length);
        resolving = 1;
        real_getentropy = dlsym(RTLD_NEXT, "getentropy");
        resolving = 0;
    }
    if (real_getentropy == NULL) {
        errno = ENOSYS;
        return -1;
    }
    ++getrandom_calls;
    if (fault_is("getentropy-control") && getrandom_calls > 1) {
        memset(buffer, 0xA5, length);
        log_event("getentropy-control", length, 0);
        return 0;
    }
    if (
        fault_is("getentropy-error")
        && getrandom_calls > 1
        && !error_delivered
    ) {
        error_delivered = 1;
        log_event("getentropy-error", length, 0);
        errno = EIO;
        return -1;
    }
    int result = (int) syscall(SYS_getentropy, buffer, length);
    log_event("getentropy", length, 0);
    return result;
}
#endif

#ifdef __APPLE__
int mcrypto_mlock(const void *address, size_t length) {
#else
int mlock(const void *address, size_t length) {
#endif
    if (fault_is("mlock-error")) {
        log_event("mlock-error", length, 0);
        errno = EPERM;
        return -1;
    }
    static int (*real_mlock)(const void *, size_t);
    if (real_mlock == NULL) real_mlock = dlsym(RTLD_NEXT, "mlock");
    if (real_mlock == NULL) {
        errno = ENOSYS;
        return -1;
    }
#ifdef __APPLE__
    int result = (int) syscall(SYS_mlock, address, length);
#else
    int result = real_mlock(address, length);
#endif
    log_event("mlock", length, 0);
    return result;
}

#ifdef __APPLE__
int mcrypto_munlock(const void *address, size_t length) {
#else
int munlock(const void *address, size_t length) {
#endif
    const unsigned char *bytes = address;
    const char *secret_length_text = getenv("MCRYPTO_SECRET_LENGTH");
    size_t checked_length = length;
    if (secret_length_text != NULL) {
        char *end = NULL;
        unsigned long parsed = strtoul(secret_length_text, &end, 10);
        if (end != secret_length_text && *end == '\0' && parsed <= length) {
            checked_length = (size_t) parsed;
            bytes += length - checked_length;
        }
    }
    int zero = 1;
    for (size_t index = 0; index < checked_length; ++index) {
        if (bytes[index] != 0) {
            zero = 0;
            break;
        }
    }
    log_event(
        fault_is("munlock-error") ? "munlock-error" : "munlock",
        length,
        zero
    );
    if (fault_is("munlock-error")) {
        errno = EPERM;
        return -1;
    }
    static int (*real_munlock)(const void *, size_t);
    if (real_munlock == NULL) real_munlock = dlsym(RTLD_NEXT, "munlock");
    if (real_munlock == NULL) {
        errno = ENOSYS;
        return -1;
    }
#ifdef __APPLE__
    return (int) syscall(SYS_munlock, address, length);
#else
    return real_munlock(address, length);
#endif
}

#ifdef __APPLE__
#define DYLD_INTERPOSE(replacement, replacee)                              \
    __attribute__((used)) static struct {                                  \
        const void *replacement;                                           \
        const void *replacee;                                              \
    } _interpose_##replacee __attribute__((section("__DATA,__interpose"))) \
        = {(const void *)(uintptr_t)&replacement,                           \
           (const void *)(uintptr_t)&replacee};

DYLD_INTERPOSE(mcrypto_getentropy, getentropy)
DYLD_INTERPOSE(mcrypto_mlock, mlock)
DYLD_INTERPOSE(mcrypto_munlock, munlock)
#endif
