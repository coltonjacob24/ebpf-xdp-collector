CLANG = clang
CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86

HOST_CFLAGS := -std=gnu11 -O2 -Wall -Wextra -Werror

BPF_OBJ = bpf/xdp_collector.o
GO_BIN = bin/collector
C_TEST_BIN = bin/packet_parser_test

.PHONY: all bpf build clean test-c

all: bpf build

bpf: $(BPF_OBJ)

$(BPF_OBJ): bpf/xdp_collector.c bpf/xdp_collector.h bpf/packet_parser.h
	$(CLANG) $(CFLAGS) -c $< -o $@

build:
	go generate ./...
	mkdir -p bin
	go build -o $(GO_BIN) ./cmd/collector

test-c: $(C_TEST_BIN)
	./$(C_TEST_BIN)

$(C_TEST_BIN): bpf/tests/packet_parser_test.c bpf/packet_parser.h bpf/xdp_collector.h
	mkdir -p bin
	$(CLANG) $(HOST_CFLAGS) -Ibpf $< -o $@

clean:
	rm -f $(BPF_OBJ)
	rm -f $(GO_BIN)
	rm -f $(C_TEST_BIN)
	rm -f internal/ebpf/bpf_*.go internal/ebpf/*.o
