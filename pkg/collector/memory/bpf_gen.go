//go:build linux
// +build linux

package memory

//go:generate bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86" memory_bpf ../../../bpf/memory_faults.c
