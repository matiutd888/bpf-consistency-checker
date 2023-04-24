
#ifndef _LINUX_BPF_CHECKER_H
#define _LINUX_BPF_CHECKER_H

#include <linux/bpf.h>

int bpf_checker_decide(struct checker_ctx *ctx);
int bpf_checker_calculate(struct checker_ctx *ctx);

#endif