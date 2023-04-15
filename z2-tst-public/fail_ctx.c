#include "common.h"

void fatal(char *m) {
	perror(m);
	exit(-1);
}

int main(int argc, char **argv)
{
	struct bpf_program *prog;
	struct bpf_object *obj;
	int fd, j = 0;
	int res = 0;
	struct bpf_link *links[2];


	obj = bpf_object__open("bpf_check_ctx.o");
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 1;
	}
	
	if (bpf_object__load(obj)) {
        printf("OK\n");
	} else {
        printf("FAIL\n");
        res = -1;
    }


	bpf_object__close(obj);
	return res;
}

