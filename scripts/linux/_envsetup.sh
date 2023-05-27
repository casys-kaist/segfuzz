#!/bin/sh -e

export ARCH="x86_64"

export LLVM=1
export MEMCOV_PASS_SO="$TOOLS_DIR/MemcovPass/build/pass/libMemcovPass.so"
export CFLAGS_KSSB="-Xclang -load -Xclang $MEMCOV_PASS_SO"
