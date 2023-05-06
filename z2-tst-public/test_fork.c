#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include "common.h"

int main() {
    FILE *fp;
    pid_t pid;

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
    pid = fork();

    if (pid == -1) {
        perror("Error forking process");
        exit(1);
    }

    if (pid == 0) {
        fprintf(fp, "child\n");
        exit(0);
    } else {
        sleep(5);
        // fprintf(fp, "parent\n");
        wait(NULL);
        fclose(fp);
    }


cleanup:
    bpf_test_cleanup(&test);
	return res;
}
