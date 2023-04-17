TESTS=shed
HOST=$(addprefix custom_,$(TESTS))
BPF=bpf_shed.o
TARGETS=$(HOST) $(BPF)

LIBBPF=../libbpf/src/libbpf.a

# Override local libbpf
CFLAGS=-I ../libbpf/src -I ../libbpf/include -I ../libbpf/include/uapi -O2
LDFLAGS=-lelf -lz

all: $(TARGETS)

custom_%: do_%.c main_custom.c ../common.c common.c $(LIBBPF)
	cp ../common.c common.c
	cp ../common.h common.h
	$(CC) -o $@ $< main_custom.c common.c $(LIBBPF) $(LDFLAGS) $(CFLAGS)

$(BPF): %.o: %.c
	clang-11 -target bpf -D__KERNEL__ -D__BPF_TRACING__ $(CFLAGS) $< -c

$(LIBBPF):
	$(MAKE) -C ../libbpf/src

.PHONY: clean $(LIBBPF) $(LIBBPF32)
clean:
	$(MAKE) -C ../libbpf/src clean
	rm -f $(TARGETS)
