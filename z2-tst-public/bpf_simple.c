#include <linux/types.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>
#include <linux/bpf.h>

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


// int my_pid = 0;

// SEC("tp/syscalls/sys_enter_write")
// int handle_tp(void *ctx)
// {
// 	int pid = bpf_get_current_pid_tgid() >> 32;

// 	if (pid != my_pid)
// 		return 0;

// 	bpf_printk("BPF triggered from PID %d.\n", pid);

// 	return 0;
// }

// Skąd program libbpf wie, jakie będzie prog_attach_fn?
SEC("checker/decide")
int check(void *a)
{
    // char fmt[] = "[MATI] bpf_simple.c: checker/decide called!";
    // bpf_trace_printk(fmt, sizeof(fmt));
    return 3;
}

// TEST COMMENT
SEC("checker/calculate")
int bpf_prog1(struct checker_ctx *ctx)
{
    __u64 gid = bpf_get_current_uid_gid();
    if (gid < 0) {
        return -4;    
    }
    // char fmt[] = "[MATI] bpf_simple.c: checker/calculate called!";
    // bpf_trace_printk(fmt, sizeof(fmt));
    return 4;
}

char _license[] SEC("license") = "GPL";
