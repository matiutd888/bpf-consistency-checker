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
	checksum_list_read_lock(f);
	l = &f->checksums_list_head;
	if (list_empty(l)) {
		checksum_list_read_unlock(f);
		return -EINVAL;
	}
	last_entry_checksum =
		list_first_entry(l, struct checksums_l_t, checksums);
	if (!last_entry_checksum) {
		printk(KERN_INFO
		       "[MATI] last_checksum: unexpected NULL when getting list_last_entry!\n");
	}
	cs = last_entry_checksum->c.value;
	ss = last_entry_checksum->c.size;
	os = last_entry_checksum->c.offset;
	checksum_list_read_unlock(f);
	if (put_user(cs, checksum)) {
		return -EFAULT;
	}
	if (put_user(ss, size)) {
		return -EFAULT;
	}
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
	list_for_each_entry(entry_it, &f->checksums_list_head, checksums) {
		if (entry_it->c.size == size && entry_it->c.offset == offset) {
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
	return 0;
}
int bpf_checker_calculate(struct checker_ctx *ctx)
{
	struct bpf_checker_ctx_with_file *ctx_with_file;	
	ctx_with_file = container_of(ctx, struct bpf_checker_ctx_with_file, c);	
	ctx_with_file->was_calculated_by_default_function = true;
	return 0;
};


BPF_CALL_4(bpf_copy_to_buffer, void *, ctx, unsigned long, offset, void *, ptr,
	   unsigned long, size)
{
	ssize_t ret;
	loff_t s_offset;
	struct bpf_checker_ctx_with_file *ctx_with_file =
		container_of(ctx, struct bpf_checker_ctx_with_file, c);
	
	s_offset = ctx_with_file->o + offset;
	ctx_with_file->f->checker_log_flag = true;
	ret = kernel_read(ctx_with_file->f, ptr, size, &s_offset);
	ctx_with_file->f->checker_log_flag = false;
	if (ret < 0) {
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
		return &bpf_get_current_uid_gid_proto;
	case BPF_FUNC_get_current_pid_tgid:
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
