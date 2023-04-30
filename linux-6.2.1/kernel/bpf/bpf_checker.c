#include <linux/bpf.h>
#include "bpf_checker.h"

int bpf_checker_decide(struct checker_ctx *ctx) {
	// printk(KERN_INFO "[MATI] bpf_checker_decide code is running!\n");
	return 0;
}
int bpf_checker_calculate(struct checker_ctx *ctx) {
	printk(KERN_INFO "[MATI] bpf_checker_calculate code is running!\n");
	return 1;
}

// influenced by 
// bpf_lsm_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
// in bpf_lsm.c
	// static const struct bpf_func_proto *bpf_checker_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog) {
	// 	return tracing_prog_func_proto(func_id, prog);
	// }

const struct bpf_prog_ops checker_prog_ops = {
};

const struct bpf_verifier_ops checker_verifier_ops = {
	// .get_func_proto = bpf_checker_func_proto,
};
