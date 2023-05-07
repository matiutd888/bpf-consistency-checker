#include "common.h"
#include <assert.h>

void test_ret(int res) {
    printf("res: %d\n", res);
    assert(res != 0);
}

int main() {
    int fd;
	int res = 0;
	struct bpf_test test;
    
    test_ret(syscall(453, -1));
    test_ret(syscall(454, -1));
    test_ret(syscall(452, -1, 2, NULL));
    test_ret(syscall(451, NULL, NULL, NULL));
	test_ret(syscall(453, 45));
    int checksum;
	size_t size;
	off_t offset;
    
    if ((fd = open("tst", O_RDWR | O_CREAT, 0644)) < 0) {
        fprintf(stderr, "Unable to open\n");
        res = -1;
        goto cleanup;
    }
    test_ret(syscall(451, fd, &checksum, &size, &offset));


    if (bpf_test_load("bpf_simple.o", &test) != 0)
        return -1;


    write(fd, "dupa", 4);
    test_ret(syscall(451, fd, NULL, &size, &offset));
    close(fd);
cleanup:
    bpf_test_cleanup(&test);
    return 0;
}