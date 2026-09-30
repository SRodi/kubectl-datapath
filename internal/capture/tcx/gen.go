package tcx

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip -cc clang -type event bpf ../../../bpf/datapath.c -- -O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu
