#!/bin/sh
set -eu

clang_version=$(clang --version | sed -n '1p')
if [ "$clang_version" != "clang version 19.1.7" ]; then
	echo "expected clang version 19.1.7, got: $clang_version" >&2
	exit 1
fi

mkdir -p /usr/include
if [ ! -e /usr/include/x86_64-linux-gnu ]; then
	ln -s /usr/x86_64-linux-gnu/include /usr/include/x86_64-linux-gnu
fi

rm -rf /tmp/gen
mkdir /tmp/gen
cd /tmp/gen
go mod init bpfgen >/dev/null
GOTOOLCHAIN=local GOPACKAGE=tcx go run github.com/cilium/ebpf/cmd/bpf2go@v0.22.0 \
	-no-strip -cc clang -type event bpf /src/bpf/datapath.c -- \
	-O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu

cp bpf_bpfeb.go bpf_bpfeb.o bpf_bpfel.go bpf_bpfel.o /src/internal/capture/tcx/
chown "$HOST_UID:$HOST_GID" /src/internal/capture/tcx/bpf_bpf*.go /src/internal/capture/tcx/bpf_bpf*.o
