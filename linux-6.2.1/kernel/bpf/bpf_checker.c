#include <linux/bpf.h>
#include "bpf_checker.h"
#include <linux/syscalls.h>


// [MATI] TODO co z lockami, czy moge ich używać
// static void free_checksum_list(struct file *f) {
// 	struct checksums_l_t *curr;
// 	struct checksums_l_t *next;
	
// 	checksum_list_write_lock(f);
// 	list_for_each_entry_safe(curr, next, &f->checksums_list_head, checksums) {
// 		list_del(&curr->checksums);
// 		kfree(curr);
// 	}
// 	checksum_list_write_unlock(f);
// }

SYSCALL_DEFINE4(last_checksum, int, fd, int *, checksum, size_t *, size, off_t *, offset)
{
	printk(KERN_INFO "[MATI] last_checksum: hello world!\n");
	return 0;
}

SYSCALL_DEFINE4(get_checksum, int, fd, size_t, size, off_t, offset, int *, checksum)
{
	printk(KERN_INFO "[MATI] get_checksum: hello world!\n");
	return 0;
}

SYSCALL_DEFINE1(count_checksums, int, fd)
{
	printk(KERN_INFO "[MATI] count_checksums: hello world!\n");
	return 0;
}

SYSCALL_DEFINE1(reset_checksums, int, fd)
{
	printk(KERN_INFO "[MATI] reset_checksum: hello world!\n");
	return 0;
}


int bpf_checker_decide(struct checker_ctx *ctx)
{
	// printk(KERN_INFO "[MATI] bpf_checker_decide code is running!\n");
	return 0;
}
int bpf_checker_calculate(struct checker_ctx *ctx)
{
	printk(KERN_INFO "[MATI] bpf_checker_calculate code is running!\n");
	return 1;
}

// influenced by
// bpf_lsm_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
// in bpf_lsm.c
// static const struct bpf_func_proto *bpf_checker_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog) {
// 	return tracing_prog_func_proto(func_id, prog);
// }


const struct bpf_prog_ops checker_prog_ops = {};

const struct bpf_verifier_ops checker_verifier_ops = {
	// .get_func_proto = bpf_checker_func_proto,
};
