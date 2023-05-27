#!/bin/sh -e

[ -n "$__RAZZERV2_READY" ] || exit 1

. $SCRIPTS_DIR/linux/_envsetup.sh

_download() {
	LINUX="$KERNELS_DIR/linux"
	if [ -f "$LINUX/.git" ]; then
		return 0
	fi
	git submodule update --init "$LINUX"
}

_build() {
	# Don't want to build a kernel at this time
	:
}

_install() {
	# Don't want to install a kernel at this time
	:
}

_target="linux-submodule"
