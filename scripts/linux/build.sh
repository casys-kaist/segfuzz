#!/bin/sh -e

if [ -z "$ARCH" ]; then
	echo "\$ARCH is empty"
	exit 1
fi

_GUEST=1
if [ -n "$HOST" ]; then
	_GUEST=
fi

if [ -n "$_GUEST" ]; then
	SCRIPTS_LINUX_DIR="$SCRIPTS_DIR/linux/"
	$SCRIPTS_LINUX_DIR/__create_symlinks.sh "all"
	$SCRIPTS_LINUX_DIR/__check_suffix.sh "all"
	OUTDIR="$PROJECT_HOME/kernels/guest/builds/$ARCH"
	echo "Building a guest kernel"
else
	# No need to make symlinks
	OUTDIR="$PROJECT_HOME/kernels/host/builds/$ARCH"
	echo "Building a host kernel"
fi

LINUXDIR="$PROJECT_HOME/kernels/linux"

mkdir -p "$OUTDIR"
if [ -n "$CONFIG" ]; then
	_CONFIG="$CONFIG"
	COPY_CONFIG=1
else
	_CONFIG="$KERNELS_DIR/guest/configs/config.$ARCH"
fi

if [ -n "$COPY_CONFIG" -o ! -f "$OUTDIR/.config" ]; then
	echo "copy $_CONFIG to $OUTDIR/.config"
	cp "$_CONFIG" "$OUTDIR/.config"
fi

if [ -z "$NPROC" ]; then
	NPROC=$(expr `nproc` / 2)
fi

(cd $LINUXDIR; make O=$OUTDIR oldconfig; make O=$OUTDIR -j"$NPROC" "$@")
