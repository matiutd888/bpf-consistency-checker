#include <linux/types.h>
#include <bpf_helpers.h>

struct checker_ctx
{
	union
	{
		struct
		{
			long long offset;
			unsigned int size;
		};
		struct
		{
			__u64 flags;
			__u64 mode;
		};
	};
};

SEC("checker/decide")
int check(void *ctx)
{
	struct checker_ctx *x = (struct checker_ctx *)ctx;
	x->flags = 10;
	// char *test = (char*) &ctxChar[1000];
	/* access should be blocked */
	// if (*test == 1)
	// return 0;
	// return 42;
	return 0;
}

char _license[] SEC("license") = "GPL";
