#!/bin/sh -e

__export_envvar "QEMU" "$TOOLS_DIR/qemu"
__append_path "$QEMU_INSTALL/bin"
export QEMU_VERSION="v6.0.0"
export QEMU_X86="$QEMU_INSTALL/bin/qemu-system-x86_64"
export QEMU_ARM="$QEMU_INSTALL/bin/qemu-system-aarch64"
export QEMU_RISCV="$QEMU_INSTALL/bin/qemu-system-riscv64"
