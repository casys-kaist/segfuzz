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

__check_symlink() {
	if [ -z "$1" -o -z "$2" ]; then
		__exit "empty \"$1\" or \"$2\"?"
	fi
	if [ ! -f "$1" -a ! -d "$1" ]; then
		__exit "$1 does not exist"
	fi
	if [ ! -h "$2" -o $(readlink -e "$1")'-' != $(readlink -f "$2")'-' ]; then
		__exit "symbolic link $2 is broken"
	fi
}

check_builddir() {
	ORIG="$KERNEL_X86_64""-$_SUFFIX"
	LINK="$KERNEL_X86_64"
	__check_symlink $ORIG $LINK
}

check_builddir
