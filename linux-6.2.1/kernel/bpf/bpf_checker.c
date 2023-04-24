#include <linux/bpf.h>
#include "bpf_checker.h"

int bpf_checker_decide(struct checker_ctx *ctx) {
	return 1;
}
int bpf_checker_calculate(struct checker_ctx *ctx) {
	return 1;
}

const struct bpf_prog_ops checker_prog_ops = {
};

const struct bpf_verifier_ops checker_verifier_ops = {
	
};
