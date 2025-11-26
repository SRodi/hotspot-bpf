//go:build linux
// +build linux

package cpu

//go:generate bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86" hotspot_bpf ../../../bpf/cpu_hotspot.c
