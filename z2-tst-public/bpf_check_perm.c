#include "vmlinux.h"
#include <bpf_helpers.h>

#define S_IROTH 00004

SEC("checker/decide")
int check(struct checker_ctx *ctx)
{
    u64 uidgid = bpf_get_current_uid_gid();
    if ((uidgid & ((1L<<32) - 1)) != ctx->uid.val)
        return 1;

    if (((uidgid >> 32) & ((1L<<32) - 1)) != ctx->gid.val)
        return 1;

    if (ctx->mode & S_IROTH)
        return 1;
    return 0;
}

SEC("checker/calculate")
int bpf_prog1(struct checker_ctx *ctx)
{
    return 0;
}

char _license[] SEC("license") = "GPL";
