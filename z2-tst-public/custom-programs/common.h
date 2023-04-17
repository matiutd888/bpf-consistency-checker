#ifndef COMMON_H
#define COMMON_H

#include <bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <libbpf.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>   
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>


struct bpf_test {
	struct bpf_program *prog;
	struct bpf_object *obj;
	int j;
	struct bpf_link *links[2];
};

static inline void syserr(const char *c) {
	perror(c);
	exit(-1);
}

static inline void perr(const char *c) {
	fprintf(stderr, "%s\n", c);
	exit(-1);
}


void do_write(int fd, char *buf, int size, int pos);
int bpf_test_load(char *bpf, struct bpf_test *test);
void bpf_test_cleanup(struct bpf_test *test);
#endif
