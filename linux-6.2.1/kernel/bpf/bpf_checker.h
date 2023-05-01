
#ifndef _LINUX_BPF_CHECKER_H
#define _LINUX_BPF_CHECKER_H

#include <linux/bpf.h>

int bpf_checker_decide(struct checker_ctx *ctx);
int bpf_checker_calculate(struct checker_ctx *ctx);

asmlinkage int sys_last_checksum(int fd, int * checksum, size_t * size, off_t * offset);
asmlinkage int sys_get_checksum(int fd, size_t size, off_t offset, int * checksum);
asmlinkage int sys_count_checksums(int fd);
asmlinkage int sys_reset_checksums(int fd);


#endif