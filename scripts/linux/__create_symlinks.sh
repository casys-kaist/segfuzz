#!/bin/sh -e

if [ -z $SUFFIX ]; then
	_SUFFIX=$(git rev-parse --abbrev-ref HEAD)
else
	_SUFFIX=$SUFFIX
fi

__exit() {
	echo "[-]" $1
	if [ -z "$IGNORE" ]; then
		exit 1
	fi
}

__append_suffix() {
	echo "$1-$_SUFFIX"
}

__create_symlink() {
	SRC="$1"
	DST="$2"
	if [ ! -e "$SRC" ]; then
		__exit "$SRC doest not exist"
	fi
	if [ -e "$DST" -a ! -h "$DST" ]; then
		__exit "cannot create symbolic link $DST"
	fi
	ln -sf -T "$SRC" "$DST"
}

create_builddir_symlink() {
	SRC="$(__append_suffix $KERNEL_X86_64)"

	mkdir -p "$SRC"

	__create_symlink "$SRC" "$KERNEL_X86_64"
}

create_builddir_symlink

