#!/bin/sh -e

[ -n "$__RAZZERV2_READY" ] || exit 1

. $SCRIPTS_DIR/linux/_envsetup.sh

_build_image() {
	IMAGE_DIR="$KERNELS_DIR/guest/images/x86_64"
	SCRIPT="create-image-x86_64.sh"
	(cd $IMAGE_DIR; sh $SCRIPT)
}

_build_linux() {
	_CONFIG="$KERNELS_DIR/guest/configs/config.x86_64"
	_SCRIPT="$SCRIPTS_DIR/linux/build.sh"
	CONFIG="$_CONFIG" sh "$_SCRIPT"
}

_download() {
	:
}

_build() {
	_build_image
	_build_linux
}

_install() {
	# Don't want to install a kernel at this time
	:
}

_target="exp-binaries"
