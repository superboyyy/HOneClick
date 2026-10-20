/*
 * Minimal KernelSU root-fd bootstrap for HOneClick.
 *
 * The loaded KernelSU driver exposes a controlled root fd through its
 * reboot hook. The fd is granted root with KSU_IOCTL_GRANT_ROOT, then kept
 * open across exec so the userspace initializer runs in the ksu SELinux
 * domain.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <unistd.h>

#define KSU_MAGIC_1 0xdeadbeefU
#define KSU_MAGIC_2 0xcafebabeU
#define KSU_IOCTL_GRANT_ROOT 0x4b01UL

extern char **environ;

int main(void) {
    int fd = -1;
    errno = 0;
    long reboot_rc = syscall(SYS_reboot, KSU_MAGIC_1, KSU_MAGIC_2, 0, &fd);
    int reboot_errno = errno;

    printf("reboot_rc=%ld errno=%d(%s) fd=%d\n",
           reboot_rc, reboot_errno, strerror(reboot_errno), fd);

    if (fd < 0) {
        printf("NO_KSU_FD\n");
        return 2;
    }

    errno = 0;
    long grant_rc = ioctl(fd, KSU_IOCTL_GRANT_ROOT, 0);
    int grant_errno = errno;
    printf("grant_root_rc=%ld errno=%d(%s)\n",
           grant_rc, grant_errno, strerror(grant_errno));
    printf("uid=%d euid=%d\n", getuid(), geteuid());
    fflush(stdout);

    if (grant_rc != 0 || geteuid() != 0) {
        close(fd);
        return 3;
    }

    char *const argv[] = {
        (char *)"/data/local/tmp/root_stage.sh",
        NULL
    };
    execve("/data/local/tmp/root_stage.sh", argv, environ);

    int exec_errno = errno;
    printf("EXEC_FAIL errno=%d(%s)\n", exec_errno, strerror(exec_errno));
    close(fd);
    return 4;
}
