#include "common.h"


void do_write(int fd, char *buf, int size, int pos) {
	if (lseek(fd, pos, SEEK_SET) != pos)
		syserr("lseek");
    const int split = size / 3;

	if (write(fd, buf, split) != split)
		syserr("Write error");

	if (write(fd, buf + split, size - split) != size - split)
		syserr("Write error");

}

