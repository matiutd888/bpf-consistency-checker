#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include "common.h"
#include <assert.h>

char parent[] = "6789";
char child[] = "012345";
int main() {
    FILE *fp;
    pid_t pid;

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
    printf("Loaded correctly!\n");
    pid = fork();

    if (pid == -1) {
        perror("Error forking process");
        exit(1);
    }

    int checksum;
	size_t size;
	off_t offset;
	

    if (pid == 0) {
        assert(syscall(453, fd) == 0);
        write(fd, child, sizeof(child));
        assert(syscall(453, fd) == 1);
        printf("child executed\n");
        close(fd);
        // bpf_test_cleanup(&test);
        exit(0);
    } else {
        sleep(2);
        assert(syscall(453, fd) == 1);
	    assert(syscall(451, fd, &checksum, &size, &offset) == 0);
        assert(checksum == (0 + 1 + 2 + 3 * (int)'0') && size == sizeof(child) && offset == 0);
        write(fd, parent, sizeof(parent));
        
        assert(syscall(453, fd) == 2);
        assert(syscall(451, fd, &checksum, &size, &offset) == 0);
        assert(checksum == (6 + 7 + 8 + 3 * (int)'0') && size == sizeof(parent) && offset == sizeof(child));
        write(fd, parent, sizeof(parent));        
        assert(syscall(453, fd) == 3);
        assert(syscall(451, fd, &checksum, &size, &offset) == 0);
        assert(checksum == (6 + 7 + 8 + 3 * (int)'0') && size == sizeof(parent) && offset == sizeof(child) + sizeof(parent));
        syscall(452, sizeof(parent), sizeof(child), &checksum);
        assert(checksum == (6 + 7 + 8 + 3 * (int)'0'));
        // fprintf(fp, "parent\n");  
        close(fd);
        wait(NULL);
        printf("parent executed\n");
    }


cleanup:
    bpf_test_cleanup(&test);
	return res;
}
