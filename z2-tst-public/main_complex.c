#include "common.h"
#include <assert.h>

char msg[10] = "0123456789";

int main(int argc, char **argv)
{
	int fd;
	int res = 0;
	struct bpf_test test;
    if (bpf_test_load("bpf_complex.o", &test) != 0)
        return -1;

	if ((fd = open("tst", O_RDWR | O_CREAT, 0644)) < 0) {
        fprintf(stderr, "Unable to open\n");
        res = -1;
        goto cleanup;
    }

	int checksum;
	size_t size;
	off_t offset;
	assert(syscall(453, fd) == 0);
	do_write(fd, msg, strlen(msg), 0);
	syscall(451, fd, &checksum, &size, &offset);
	assert(checksum == 156 && size == 7 && offset == 3);
	close(fd);


cleanup:
    bpf_test_cleanup(&test);
	return res;
}
