TESTS=shed
HOST=$(TESTS)
BPF=bpf_shed.o
TARGETS=$(HOST) $(BPF)

LIBBPF=../libbpf/src/libbpf.a

# Override local libbpf
CFLAGS=-I libbpf/src -I libbpf/include -I libbpf/include/uapi -O2
LDFLAGS=-lelf -lz

all: $(TARGETS)

simple_%: do_%.c main_simple.c common.c $(LIBBPF)
	$(CC) -o $@ $< main_simple.c common.c $(LIBBPF) $(LDFLAGS) $(CFLAGS)

$(BPF): %.o: %.c
	clang-11 -target bpf -D__KERNEL__ -D__BPF_TRACING__ $(CFLAGS) $< -c

$(LIBBPF):
	$(MAKE) -C ../libbpf/src

.PHONY: clean $(LIBBPF) $(LIBBPF32)
clean:
	$(MAKE) -C ../libbpf/src clean
	rm -f $(TARGETS)
