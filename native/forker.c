/* forker.c —— 制造可识别的 task_struct / cred 分配
 *
 * 目的：配合 perfetto 采集静态 tracepoint `kmem/kmem_cache_alloc`，
 *       从 `name=task_struct` 的 ptr 字段直接拿到 task_struct 的堆地址。
 *
 * 为了让事件容易辨认，我们让每个子进程都执行 prctl(PR_SET_NAME, "fkb<pid>")，
 * 这样：
 *   - sched/sched_process_fork 给出 child_pid + child_comm
 *   - kmem/kmem_cache_alloc 给出 name=task_struct + ptr
 * 两边按时间顺序就能对上。
 *
 * 用法: forker <nchild> <hold_ms>
 *   nchild   fork 出的子进程数
 *   hold_ms  子进程存活时长（毫秒）；期间主进程等它们
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>

int main(int argc, char **argv)
{
    int nchild = argc > 1 ? atoi(argv[1]) : 4;
    int hold_ms = argc > 2 ? atoi(argv[2]) : 800;
    pid_t *pids = calloc((size_t)nchild, sizeof(pid_t));

    if (!pids) return 1;

    for (int i = 0; i < nchild; i++) {
        pid_t p = fork();
        if (p < 0) { perror("fork"); break; }
        if (p == 0) {
            char comm[16];
            snprintf(comm, sizeof comm, "fkb%05d", (int)getpid());
            prctl(PR_SET_NAME, comm, 0, 0, 0);   /* 触发 __set_task_comm */
            usleep((useconds_t)hold_ms * 1000);
            _exit(0);
        }
        pids[i] = p;
        printf("forked %d\n", (int)p);
    }
    fflush(stdout);

    for (int i = 0; i < nchild; i++)
        if (pids[i] > 0) waitpid(pids[i], NULL, 0);

    printf("done\n");
    return 0;
}
