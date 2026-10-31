/*
 * Small finit_module helper used after the CVE-2026-98260 temporary-root
 * stage. It intentionally does not parse ELF files: HOneClick patches the
 * module's undefined symbols and vermagic before staging it.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/module.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int module_is_loaded(void)
{
    FILE *fp = fopen("/proc/modules", "re");
    char line[512];
    int found = 0;

    if (!fp)
        return 0;
    while (fgets(line, sizeof(line), fp)) {
        if (!strncmp(line, "kernelsu ", 9)) {
            found = 1;
            break;
        }
    }
    fclose(fp);
    return found;
}

int main(int argc, char **argv)
{
    const char *path;
    const char *params = "allow_shell=1";
    static const unsigned int flags[] = {
        0,
        MODULE_INIT_IGNORE_MODVERSIONS,
        MODULE_INIT_IGNORE_MODVERSIONS | MODULE_INIT_IGNORE_VERMAGIC,
    };
    int fd;
    long rc;
    int saved_errno;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <module.ko> [parameters]\n", argv[0]);
        return 2;
    }
    if (argc == 3)
        params = argv[2];

    if (module_is_loaded()) {
        puts("MODULE_ALREADY_LOADED");
        return 0;
    }

    path = argv[1];
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        return 3;
    }

    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        if (i) {
            close(fd);
            fd = open(path, O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                fprintf(stderr, "open %s: %s\n", path, strerror(errno));
                return 3;
            }
        }
        errno = 0;
        rc = syscall(SYS_finit_module, fd, params, flags[i]);
        saved_errno = errno;
        if (rc == 0 || module_is_loaded()) {
            close(fd);
            fprintf(stderr, "MODULE_LOADED flags=%#x\n", flags[i]);
            return 0;
        }
        fprintf(stderr,
                "finit_module: flags=%#x rc=%ld errno=%d (%s)\n",
                flags[i], rc, saved_errno, strerror(saved_errno));
    }
    close(fd);
    return 4;
}
