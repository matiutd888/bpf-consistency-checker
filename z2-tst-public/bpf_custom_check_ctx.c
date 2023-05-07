#include <linux/types.h>
#include <bpf_helpers.h>

struct checker_ctx {
  union {
     /* write */
     struct {
         long long offset;
         size_t size;
     };
     /* open */
     struct {
         __u64 flags; /* open flags */
         __u64 mode; /* inode mode */
         __u32 uid; /* owner */
         __u32 gid; /* group */
     };
  };
};

SEC("checker/decide")
int check(void *ctx)
{


	struct checker_ctx *x = (struct checker_ctx *)ctx;
	
	__u64 flag = x->flags;
	__u64 mode = x->mode;
	long uid = x->uid;
	long gid = x->gid;
	x->gid = 2137;
	
	// __u64 *gid2 = &x->gid + 2;
	// __u64 siema = *gid2;
	
	bpf_printk("Hello, world, from BPF! %lu %lu\n", uid, gid);
	

	// x->flags = 10;
	// char *test = (char*) &ctxChar[1000];
	/* access should be blocked */
	// if (*test == 1)
	// return 0;
	// return 42;
	return 10;
}

char _license[] SEC("license") = "GPL";
