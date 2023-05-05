#include <linux/types.h>
#include <bpf_helpers.h>

struct checker_ctx {
    union {
        struct {
            long long offset;
            unsigned int size;
        };
        struct {
            __u64 flags;
            __u64 mode;
        };
    };
};


SEC("checker/decide")
int check(void *a)
{
    return 3;
}

SEC("checker/calculate")
int bpf_prog1(struct checker_ctx *ctx)
{
    char buf[3];
    int res = 0;

    bpf_copy_to_buffer(ctx, 0, buf, 3);
    for (int i = 0; i < 3; i++) {
        res += buf[i];
    }

    return res;
}

char _license[] SEC("license") = "GPL";
