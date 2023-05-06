#include "common.h"
#include <assert.h>

char msg[] = "xyzzy xyzzy xyzzy\n";
int main(int argc, char **argv)
{
	int fd;
	int res = 0;
	struct bpf_test test;
    if (bpf_test_load("bpf_simple.o", &test) != 0)
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
	write(fd, msg, strlen(msg));
	assert(syscall(451, fd, &checksum, &size, &offset) == 0);
	assert(checksum == 4 && size == strlen(msg) && offset == 0);
	syscall(454, fd);
	assert(syscall(453, fd) == 0);
    write(fd, msg, strlen(msg));
	assert(syscall(451, fd, &checksum, &size, &offset) == 0);
	assert(checksum == 4 && size == strlen(msg) && offset == strlen(msg));
	
    close(fd);


cleanup:
    bpf_test_cleanup(&test);
	return res;
}
