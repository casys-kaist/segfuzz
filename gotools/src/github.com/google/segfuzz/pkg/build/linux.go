// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:generate ./linux_gen.sh

package build

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

type linux struct{}

func (linux linux) build(params Params) (ImageDetails, error) {
	if err := linux.buildKernel(params); err != nil {
		return ImageDetails{}, err
	}
	compilerID, err := queryLinuxCompiler(params.KernelDir)
	if err != nil {
		return ImageDetails{}, err
	}

	kernelPath := filepath.Join(params.KernelDir, filepath.FromSlash(kernelBin(params.TargetArch)))
	if fileInfo, err := os.Stat(params.UserspaceDir); err == nil && fileInfo.IsDir() {
		// The old way of assembling the image from userspace dir.
		// It should be removed once all syzbot instances are switched.
		if err := linux.createImage(params, kernelPath); err != nil {
			return ImageDetails{}, err
		}
	} else if params.VMType == "qemu" {
		// If UserspaceDir is a file (image) and we use qemu, we just copy image and kernel to the output dir
		// assuming that qemu will use injected kernel boot. In this mode we also assume password/key-less ssh.
		if err := osutil.CopyFile(kernelPath, filepath.Join(params.OutputDir, "kernel")); err != nil {
			return ImageDetails{}, err
		}
		if err := osutil.CopyFile(params.UserspaceDir, filepath.Join(params.OutputDir, "image")); err != nil {
			return ImageDetails{}, err
		}
	} else if err := embedLinuxKernel(params, kernelPath); err != nil {
		return ImageDetails{}, err
	}
	signature, err := elfBinarySignature(filepath.Join(params.OutputDir, "obj", "vmlinux"))
	if err != nil {
		return ImageDetails{}, err
	}
	return ImageDetails{
		Signature:  signature,
		CompilerID: compilerID,
	}, nil
}

func (linux linux) buildKernel(params Params) error {
	configFile := filepath.Join(params.KernelDir, ".config")
	if err := linux.writeFile(configFile, params.Config); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}
	// One would expect olddefconfig here, but olddefconfig is not present in v3.6 and below.
	// oldconfig is the same as olddefconfig if stdin is not set.
	if err := runMake(params, "oldconfig"); err != nil {
		return err
	}
	// Write updated kernel config early, so that it's captured on build failures.
	outputConfig := filepath.Join(params.OutputDir, "kernel.config")
	if err := osutil.CopyFile(configFile, outputConfig); err != nil {
		return err
	}
	// Ensure CONFIG_GCC_PLUGIN_RANDSTRUCT doesn't prevent ccache usage.
	// See /Documentation/kbuild/reproducible-builds.rst.
	const seed = `const char *randstruct_seed = "e9db0ca5181da2eedb76eba144df7aba4b7f9359040ee58409765f2bdc4cb3b8";`
	gccPluginsDir := filepath.Join(params.KernelDir, "scripts", "gcc-plugins")
	if osutil.IsExist(gccPluginsDir) {
		if err := linux.writeFile(filepath.Join(gccPluginsDir, "randomize_layout_seed.h"), []byte(seed)); err != nil {
			return err
		}
	}

	// Different key is generated for each build if key is not provided.
	// see Documentation/reproducible-builds.rst. This is causing problems to our signature calculation.
	certsDir := filepath.Join(params.KernelDir, "certs")
	if osutil.IsExist(certsDir) {
		if err := linux.writeFile(filepath.Join(certsDir, "signing_key.pem"), []byte(moduleSigningKey)); err != nil {
			return err
		}
	}
	target := path.Base(kernelBin(params.TargetArch))
	if err := runMake(params, target); err != nil {
		return err
	}
	vmlinux := filepath.Join(params.KernelDir, "vmlinux")
	outputVmlinux := filepath.Join(params.OutputDir, "obj", "vmlinux")
	if err := osutil.Rename(vmlinux, outputVmlinux); err != nil {
		return fmt.Errorf("failed to rename vmlinux: %v", err)
	}
	return nil
}

func (linux) createImage(params Params, kernelPath string) error {
	tempDir, err := ioutil.TempDir("", "syz-build")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	scriptFile := filepath.Join(tempDir, "create.sh")
	if err := osutil.WriteExecFile(scriptFile, []byte(createImageScript)); err != nil {
		return fmt.Errorf("failed to write script file: %v", err)
	}
	cmd := osutil.Command(scriptFile, params.UserspaceDir, kernelPath, params.TargetArch)
	cmd.Dir = tempDir
	cmd.Env = append([]string{}, os.Environ()...)
	cmd.Env = append(cmd.Env,
		"SYZ_VM_TYPE="+params.VMType,
		"SYZ_CMDLINE_FILE="+osutil.Abs(params.CmdlineFile),
		"SYZ_SYSCTL_FILE="+osutil.Abs(params.SysctlFile),
	)
	if _, err = osutil.Run(time.Hour, cmd); err != nil {
		return fmt.Errorf("image build failed: %v", err)
	}
	// Note: we use CopyFile instead of Rename because src and dst can be on different filesystems.
	imageFile := filepath.Join(params.OutputDir, "image")
	if err := osutil.CopyFile(filepath.Join(tempDir, "disk.raw"), imageFile); err != nil {
		return err
	}
	return nil
}

func (linux) clean(kernelDir, targetArch string) error {
	return runMakeImpl(targetArch, "", "", kernelDir, "distclean")
}

func (linux) writeFile(file string, data []byte) error {
	if err := osutil.WriteFile(file, data); err != nil {
		return err
	}
	return osutil.SandboxChown(file)
}

func runMakeImpl(arch, compiler, ccache, kernelDir string, addArgs ...string) error {
	target := targets.Get(targets.Linux, arch)
	args := LinuxMakeArgs(target, compiler, ccache, "")
	args = append(args, addArgs...)
	cmd := osutil.Command("make", args...)
	if err := osutil.Sandbox(cmd, true, true); err != nil {
		return err
	}
	cmd.Dir = kernelDir
	cmd.Env = append([]string{}, os.Environ()...)
	// This makes the build [more] deterministic:
	// 2 builds from the same sources should result in the same vmlinux binary.
	// Build on a release commit and on the previous one should result in the same vmlinux too.
	// We use it for detecting no-op changes during bisection.
	cmd.Env = append(cmd.Env,
		"KBUILD_BUILD_VERSION=0",
		"KBUILD_BUILD_TIMESTAMP=now",
		"KBUILD_BUILD_USER=syzkaller",
		"KBUILD_BUILD_HOST=syzkaller",
		"KERNELVERSION=syzkaller",
		"LOCALVERSION=-syzkaller",
	)
	_, err := osutil.Run(time.Hour, cmd)
	return err
}

func runMake(params Params, addArgs ...string) error {
	return runMakeImpl(params.TargetArch, params.Compiler, params.Ccache, params.KernelDir, addArgs...)
}

func LinuxMakeArgs(target *targets.Target, compiler, ccache, buildDir string) []string {
	args := []string{
		"-j", fmt.Sprint(runtime.NumCPU()),
		"ARCH=" + target.KernelArch,
	}
	if target.Triple != "" {
		args = append(args, "CROSS_COMPILE="+target.Triple+"-")
	}
	if compiler == "" {
		compiler = target.KernelCompiler
		if target.KernelLinker != "" {
			args = append(args, "LD="+target.KernelLinker)
		}
	}
	if compiler != "" {
		if ccache != "" {
			compiler = ccache + " " + compiler
		}
		args = append(args, "CC="+compiler)
	}
	if buildDir != "" {
		args = append(args, "O="+buildDir)
	}
	return args
}

func kernelBin(arch string) string {
	// We build only zImage/bzImage as we currently don't use modules.
	switch arch {
	case targets.AMD64:
		return "arch/x86/boot/bzImage"
	case targets.I386:
		return "arch/x86/boot/bzImage"
	case targets.S390x:
		return "arch/s390/boot/bzImage"
	case targets.PPC64LE:
		return "arch/powerpc/boot/zImage.pseries"
	case targets.ARM:
		return "arch/arm/boot/zImage"
	case targets.ARM64:
		return "arch/arm64/boot/Image"
	case targets.RiscV64:
		return "arch/riscv/boot/Image"
	case targets.MIPS64LE:
		return "vmlinux"
	default:
		panic(fmt.Sprintf("pkg/build: unsupported arch %v", arch))
	}
}

var linuxCompilerRegexp = regexp.MustCompile(`#define\s+LINUX_COMPILER\s+"(.*)"`)

func queryLinuxCompiler(kernelDir string) (string, error) {
	bytes, err := ioutil.ReadFile(filepath.Join(kernelDir, "include", "generated", "compile.h"))
	if err != nil {
		return "", err
	}
	result := linuxCompilerRegexp.FindSubmatch(bytes)
	if result == nil {
		return "", fmt.Errorf("include/generated/compile.h does not contain build information")
	}
	return string(result[1]), nil
}

// elfBinarySignature calculates signature of an elf binary aiming at runtime behavior
// (text/data, debug info is ignored).
func elfBinarySignature(bin string) (string, error) {
	f, err := os.Open(bin)
	if err != nil {
		return "", fmt.Errorf("failed to open binary for signature: %v", err)
	}
	ef, err := elf.NewFile(f)
	if err != nil {
		return "", fmt.Errorf("failed to open elf binary: %v", err)
	}
	hasher := sha256.New()
	for _, sec := range ef.Sections {
		// Hash allocated sections (e.g. no debug info as it's not allocated)
		// with file data (e.g. no bss). We also ignore .notes section as it
		// contains some small changing binary blob that seems irrelevant.
		// It's unclear if it's better to check NOTE type,
		// or ".notes" name or !PROGBITS type.
		if sec.Flags&elf.SHF_ALLOC == 0 || sec.Type == elf.SHT_NOBITS || sec.Type == elf.SHT_NOTE {
			continue
		}
		io.Copy(hasher, sec.Open())
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// moduleSigningKey is a constant module signing key for reproducible builds.
const moduleSigningKey = `-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAxu5GRXw7d13xTLlZ
GT1y63U4Firk3WjXapTgf9radlfzpqheFr5HWO8f11U/euZQWXDzi+Bsq+6s/2lJ
AU9XWQIDAQABAkB24ZxTGBv9iMGURUvOvp83wRRkgvvEqUva4N+M6MAXagav3GRi
K/gl3htzQVe+PLGDfbIkstPJUvI2izL8ZWmBAiEA/P72IitEYE4NQj4dPcYglEYT
Hbh2ydGYFbYxvG19DTECIQDJSvg7NdAaZNd9faE5UIAcLF35k988m9hSqBjtz0tC
qQIgGOJC901mJkrHBxLw8ViBb9QMoUm5dVRGLyyCa9QhDqECIQCQGLX4lP5DVrsY
X43BnMoI4Q3o8x1Uou/JxAIMg1+J+QIgamNCPBLeP8Ce38HtPcm8BXmhPKkpCXdn
uUf4bYtfSSw=
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIBvzCCAWmgAwIBAgIUKoM7Idv4nw571nWDgYFpw6I29u0wDQYJKoZIhvcNAQEF
BQAwLjEsMCoGA1UEAwwjQnVpbGQgdGltZSBhdXRvZ2VuZXJhdGVkIGtlcm5lbCBr
ZXkwIBcNMjAxMDA4MTAzMzIwWhgPMjEyMDA5MTQxMDMzMjBaMC4xLDAqBgNVBAMM
I0J1aWxkIHRpbWUgYXV0b2dlbmVyYXRlZCBrZXJuZWwga2V5MFwwDQYJKoZIhvcN
AQEBBQADSwAwSAJBAMbuRkV8O3dd8Uy5WRk9cut1OBYq5N1o12qU4H/a2nZX86ao
Xha+R1jvH9dVP3rmUFlw84vgbKvurP9pSQFPV1kCAwEAAaNdMFswDAYDVR0TAQH/
BAIwADALBgNVHQ8EBAMCB4AwHQYDVR0OBBYEFPhQx4etmYw5auCJwIO5QP8Kmrt3
MB8GA1UdIwQYMBaAFPhQx4etmYw5auCJwIO5QP8Kmrt3MA0GCSqGSIb3DQEBBQUA
A0EAK5moCH39eLLn98pBzSm3MXrHpLtOWuu2p696fg/ZjiUmRSdHK3yoRONxMHLJ
1nL9cAjWPantqCm5eoyhj7V7gg==
-----END CERTIFICATE-----`