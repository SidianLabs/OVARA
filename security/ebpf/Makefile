# Makefile for Ovara eBPF interceptor
#
# Prerequisites:
#   clang/llvm (with BPF target)
#   bpftool (from linux-tools or libbpf)
#
# Usage:
#   make          — build .o and generate skeleton .skel.h
#   make clean    — remove build artifacts

CLANG    ?= clang
LLVM-strip ?= llvm-strip
BPFTOOL  ?= bpftool

BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf
BPF_CFLAGS += -D__TARGET_ARCH_x86

SRCS := ovara_interceptor.c
OBJS := $(SRCS:.c=.o)
SKEL := $(SRCS:.c=.skel.h)

.PHONY: all bpf clean

all: bpf $(SKEL)

bpf: $(OBJS)

%.o: %.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM-strip) -g $@

%.skel.h: %.o
	$(BPFTOOL) gen skeleton $< > $@

clean:
	rm -f $(OBJS) $(SKEL)
