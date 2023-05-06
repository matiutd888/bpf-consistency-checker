#include <linux/bpf.h>
#include "bpf_checker.h"
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/file.h>
#include <linux/filter.h>

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
	last_entry_checksum =
		list_first_entry(l, struct checksums_l_t, checksums);
	if (!last_entry_checksum) {
		printk(KERN_INFO
		       "[MATI] last_checksum: unexpected NULL when getting list_last_entry!\n");
	}
	printk(KERN_INFO "[MATI] last_checksum: found! %d, %zu, %lld\n",
	       last_entry_checksum->c.value, last_entry_checksum->c.size,
	       last_entry_checksum->c.offset);
	cs = last_entry_checksum->c.value;
	ss = last_entry_checksum->c.size;
	;
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
	printk(KERN_INFO
	       "[MATI] get_checksum: searching for size=%zu, offset=%ld\n",
	       size, offset);
	list_for_each_entry(entry_it, &f->checksums_list_head, checksums) {
		printk(KERN_INFO
		       "[MATI] get_checksum: iterating, size=%zu, offset=%lld\n",
		       entry_it->c.size, entry_it->c.offset);
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
	struct list_head *pos;
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
	checksum_list_write_lock(f);
	free_checksum_list(f);
	checksum_list_write_unlock(f);
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
};


BPF_CALL_4(bpf_copy_to_buffer, void *, ctx, unsigned long, offset, void *, ptr,
	   unsigned long, size)
{
	ssize_t ret;
	loff_t s_offset;
	struct bpf_checker_ctx_with_file *ctx_with_file =
		container_of(ctx, struct bpf_checker_ctx_with_file, c);
	printk(KERN_INFO "[MATI] bpf_copy_to_buffer: Successfully retrieved file with fd: %p\n",
	       ctx_with_file->f);
	

	s_offset = ctx_with_file->o + offset;
	ctx_with_file->f->checker_log_flag = true;
	ret = kernel_read(ctx_with_file->f, ptr, size, &s_offset);
	ctx_with_file->f->checker_log_flag = false;
	if (ret < 0) {
		printk(KERN_INFO "[MATI] bpf_copy_to_buffer: Error during vfs_read!\n");
	}
	return ret;
}

const struct bpf_func_proto bpf_copy_to_buffer_proto = {
	.func = bpf_copy_to_buffer,
	.gpl_only = true,
	.ret_type = RET_INTEGER,
	.arg1_type = ARG_PTR_TO_CTX,
	.arg2_type = ARG_ANYTHING,
	.arg3_type = ARG_PTR_TO_UNINIT_MEM,
	.arg4_type = ARG_CONST_SIZE_OR_ZERO,
};

static bool bpf_checker_prog_is_valid_access(int off, int size,
					     enum bpf_access_type type,
					     const struct bpf_prog *prog,
					     struct bpf_insn_access_aux *info)
{
	printk("[MATI] bpf_checker_prog_is_valid_access:  off: %d, size: %d sizeof(checker_ctx): %zu\n",
	       off, size, sizeof(struct checker_ctx));
	if (off < 0 || off >= sizeof(struct checker_ctx))
		return false;
	if (type != BPF_READ)
		return false;
	if (off % size != 0)
		return false;

	// from kprobe_prog_is_valid_access
	// if (off + size > sizeof(struct checker_ctx))
	// 	return false;

	return true;
}

// influenced by
// bpf_lsm_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
// in bpf_lsm.c
static const struct bpf_func_proto *
bpf_checker_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_get_current_uid_gid:
		printk(KERN_INFO
		       "[MATI] bpf_checker_func_proto: BPF_FUNC_get_current_uid_gid\n");
		return &bpf_get_current_uid_gid_proto;
	case BPF_FUNC_get_current_pid_tgid:
		printk(KERN_INFO
		       "[MATI] bpf_checker_func_proto: BPF_FUNC_get_current_pid_tgid\n");
		return &bpf_get_current_pid_tgid_proto;
	case BPF_FUNC_copy_to_buffer:
		return &bpf_copy_to_buffer_proto;
	default:
		return bpf_base_func_proto(func_id);
	}
}

const struct bpf_prog_ops checker_prog_ops = {};

const struct bpf_verifier_ops checker_verifier_ops = {
	.get_func_proto = bpf_checker_func_proto,
	.is_valid_access = bpf_checker_prog_is_valid_access,
};
