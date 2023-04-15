TESTS=write
MISC=fail_ctx check_perm
HOST=$(addprefix simple_,$(TESTS)) \
     $(addprefix complex_,$(TESTS)) \
	 $(MISC)

BPF=bpf_simple.o bpf_complex.o bpf_check_ctx.o bpf_check_perm.o
TARGETS=$(HOST) $(BPF)

LIBBPF=libbpf/src/libbpf.a

# Override local libbpf
CFLAGS=-I libbpf/src -I libbpf/include -I libbpf/include/uapi -O2
LDFLAGS=-lelf -lz

all: $(TARGETS)


simple_%: do_%.c main_simple.c common.c $(LIBBPF)
	$(CC) -o $@ $< main_simple.c common.c $(LIBBPF) $(LDFLAGS) $(CFLAGS)

complex_%: do_%.c main_complex.c common.c $(LIBBPF)
	$(CC) -o $@ $< main_complex.c common.c $(LIBBPF) $(LDFLAGS) $(CFLAGS)


$(MISC): %: %.c common.c $(LIBBPF)
	cc -o $@ $< common.c $(LIBBPF) $(LDFLAGS) $(CFLAGS)

$(BPF): %.o: %.c
	clang-11 -target bpf -D__KERNEL__ -D__BPF_TRACING__ $(CFLAGS) $< -c

$(LIBBPF):
	$(MAKE) -C libbpf/src

.PHONY: clean $(LIBBPF) $(LIBBPF32)
clean:
	$(MAKE) -C libbpf/src clean
	rm -f $(TARGETS)