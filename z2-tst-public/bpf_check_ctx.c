#include <linux/types.h>
#include <bpf_helpers.h>


SEC("checker/decide")
int check(void *ctx)
{
	char *ctxChar = (char *) ctx; 
	char *test = (char*) &ctxChar[1000];
	/* access should be blocked */
	if (*test == 1)
		return 0;
	return 42;
}


char _license[] SEC("license") = "GPL";
