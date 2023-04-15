#include "common.h"


const char msg[] = "xyzzy xyzzy xyzzy\n";
int main(int argc, char **argv)
{
	int fd, j = 0;
	int res = 0;
	struct bpf_test test;

    if (argc != 2)
        perr("Missing file name");

    if (bpf_test_load("bpf_check_perm.o", &test) != 0)
        return -1;

    if ((fd = open(argv[1], O_RDWR)) < 0) {
        fprintf(stderr, "Unable to open\n");
        res = -1;
        goto cleanup;
    }

    if (write(fd, msg, sizeof(msg) - 1) != sizeof(msg) - 1) {
        res = -1;
        perror("write");
    }

	close(fd);

cleanup:
    bpf_test_cleanup(&test);
    return res;
}
