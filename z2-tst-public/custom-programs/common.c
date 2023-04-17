#include "common.h"


int bpf_test_load(char *bpf, struct bpf_test *test)
{
	test->obj = bpf_object__open(bpf);
	if (libbpf_get_error(test->obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 1;
	}
	
	if (bpf_object__load(test->obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

    test->j = 0;
    bpf_object__for_each_program(test->prog, test->obj) {
		printf("Program %s %s %d\n", test->prog->name, test->prog->sec_name, test->prog->sec_def->handler_id);
		test->links[test->j] = bpf_program__attach(test->prog);

		if (libbpf_get_error(test->links[test->j])) {
			fprintf(stderr, "ERROR: bpf_program__attach failed\n");
			test->links[test->j] = NULL;
			goto cleanup;
		}
		test->j++;
    }

    return 0;

cleanup:
        return -1;
}

void bpf_test_cleanup(struct bpf_test *test)
{
	for (test->j--; test->j >= 0; test->j--)
		bpf_link__destroy(test->links[test->j]);

	bpf_object__close(test->obj);

}
