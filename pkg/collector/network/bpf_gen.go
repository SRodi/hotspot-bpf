//go:build linux
// +build linux

package network

//go:generate bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86" network_bpf ../../../bpf/network_bandwidth.c
