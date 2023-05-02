#include <linux/bpf.h>
#include "bpf_checker.h"
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/file.h>

extern void free_checksum_list(struct file *f);
// struct checksums_l_t;
// struct file;
// struct checksum_t;



SYSCALL_DEFINE4(last_checksum, int, fd, int *, checksum, size_t *, size,
		off_t *, offset)
{
	struct file *f;
	struct list_head *l;
	struct checksums_l_t *last_entry_checksum;

	int cs;
	size_t ss;
	off_t os;

	f = fget(fd);
	if (!f) {
		return -EINVAL;
	}
	printk(KERN_INFO "[MATI] last_checksum: hello!\n");
	checksum_list_read_lock(f);
	printk(KERN_INFO "[MATI] last_checksum: locked!\n");
	l = &f->checksums_list_head;	
	if (list_empty(l)) {

		checksum_list_read_unlock(f);
		return -EINVAL;
	}
	printk(KERN_INFO "[MATI] last_checksum: list not empty!\n");
	last_entry_checksum = list_first_entry(l, struct checksums_l_t, checksums);
	if (!last_entry_checksum) {
		printk(KERN_INFO "[MATI] last_checksum: unexpected NULL when getting list_last_entry!\n");
	}
	printk(KERN_INFO "[MATI] last_checksum: found! %d, %zu, %lld\n", last_entry_checksum->c.value, last_entry_checksum->c.size, last_entry_checksum->c.offset);
	cs = last_entry_checksum->c.value;
	ss = last_entry_checksum->c.size;;
	os = last_entry_checksum->c.offset;
	checksum_list_read_unlock(f);
	printk(KERN_INFO "[MATI] last_checksum: unlocked success!\n");
	
	if (put_user(cs, checksum)) {
		return -EFAULT;
	}
	printk(KERN_INFO "[MATI] last_checksum: assignment correct! 1\n");
	if (put_user(ss, size)) {
		return -EFAULT;	
	}
	printk(KERN_INFO "[MATI] last_checksum: assignment correct! 2\n");
	if (put_user(os, offset)) {
		return -EFAULT;		
	}
	return 0;
}

SYSCALL_DEFINE4(get_checksum, int, fd, size_t, size, off_t, offset, int *,
		checksum)
{
	struct file *f;
	struct checksums_l_t *entry_it;
	int ret;
	
	ret = -1;
	f = fget(fd);
	if (!f) {
		return -EINVAL;
	}
	checksum_list_read_lock(f);
	// printk(KERN_INFO "[MATI] get_checksum: searching for size=%zu, offset=%ld\n", size, offset);
	list_for_each_entry(entry_it, &f->checksums_list_head, checksums) {
		// printk(KERN_INFO "[MATI] get_checksum: iterating, size=%zu, offset=%lld\n", entry_it->c.size, entry_it->c.offset);
		if (entry_it->c.size == size && entry_it->c.offset == offset) {
			printk(KERN_INFO "[MATI] found!\n");
			ret = entry_it->c.value;
			break;
		}
	}
	checksum_list_read_unlock(f);
	if (put_user(ret, checksum)) {
		return -EFAULT;
	}
	return 0;
}

SYSCALL_DEFINE1(count_checksums, int, fd)
{
	struct file *f;
	struct list_head *	pos;
	size_t s;
	printk(KERN_INFO "[MATI] count_checksums: hello world!\n");
	f = fget(fd);
	if (!f) {
		return -EINVAL;
	}
	s = 0;
	checksum_list_read_lock(f);
	list_for_each(pos, &f->checksums_list_head) {
		s++;
	}
	checksum_list_read_unlock(f);
	return s;
}

SYSCALL_DEFINE1(reset_checksums, int, fd)
{
	struct file *f;
	if (fd < 0) {
		return -EINVAL;
	}
	f = fget(fd);
	if (!f) {
		return -EINVAL;
	}
	free_checksum_list(f);
	return 0;
}

int bpf_checker_decide(struct checker_ctx *ctx)
{
	// printk(KERN_INFO "[MATI] bpf_checker_decide code is running!\n");
	return 0;
}
int bpf_checker_calculate(struct checker_ctx *ctx)
{
	printk(KERN_INFO "[MATI] bpf_checker_calculate code is running!\n");
	return 1;
}

// influenced by
// bpf_lsm_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
// in bpf_lsm.c
// static const struct bpf_func_proto *bpf_checker_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog) {
// 	return tracing_prog_func_proto(func_id, prog);
// }

const struct bpf_prog_ops checker_prog_ops = {};

const struct bpf_verifier_ops checker_verifier_ops = {
	// .get_func_proto = bpf_checker_func_proto,
};
