CLANG = clang
CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86

BPF_OBJ = bpf/xdp_collector.o
GO_BIN = bin/collector

.PHONY: all bpf build clean

all: bpf build

bpf: $(BPF_OBJ)

$(BPF_OBJ): bpf/xdp_collector.c bpf/xdp_collector.h
	$(CLANG) $(CFLAGS) -c $< -o $@

build:
	go generate ./...
	go build -o $(GO_BIN) ./cmd/collector

clean:
	rm -f $(BPF_OBJ)
	rm -f $(GO_BIN)
	rm -f internal/ebpf/bpf_*.go internal/ebpf/*.o