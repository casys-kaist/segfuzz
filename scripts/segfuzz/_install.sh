#!/bin/sh -e

[ -n "$__RAZZERV2_READY" ] || exit 1

_download() {
	:
}

_build() {
	(cd $SYZKALLER_PATH; make)
	MEMCOV_BUILD_DIR="$TOOLS_DIR/MemcovPass/build"
	mkdir -p "$MEMCOV_BUILD_DIR"
	(cd $MEMCOV_BUILD_DIR; cmake ../; ninja)
}

_install() {
	:
}

_target="segfuzz"
