//go:build linux

package gpwntools

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const (
	ptraceHelperEnv = "GPWNTOOLS_PTRACE_HELPER"
	ptraceHelperArg = "--gpwntools-ptrace-helper"
	prSetPtracer    = 0x59616d61
)

func init() {
	if os.Getenv(ptraceHelperEnv) != "1" {
		return
	}
	if len(os.Args) < 3 || os.Args[1] != ptraceHelperArg {
		fmt.Fprintln(os.Stderr, "gpwntools ptrace helper: invalid arguments")
		os.Exit(127)
	}

	targetArgv := os.Args[2:]
	targetPath := targetArgv[0]
	if !strings.Contains(targetPath, "/") {
		if resolved, err := exec.LookPath(targetPath); err == nil {
			targetPath = resolved
			targetArgv[0] = resolved
		}
	}

	_ = allowAnyPtracer()
	if err := syscall.Exec(targetPath, targetArgv, filteredHelperEnv(os.Environ())); err != nil {
		fmt.Fprintf(os.Stderr, "gpwntools ptrace helper: exec %s failed: %v\n", targetPath, err)
		os.Exit(127)
	}
}

func processCommand(argv []string, opts ProcessOptions) (*exec.Cmd, error) {
	helper, err := os.Executable()
	if err != nil {
		return nil, err
	}

	targetArgv := append([]string{}, argv...)
	if !strings.Contains(targetArgv[0], "/") {
		if resolved, err := exec.LookPath(targetArgv[0]); err == nil {
			targetArgv[0] = resolved
		}
	}

	args := append([]string{ptraceHelperArg}, targetArgv...)
	cmd := exec.Command(helper, args...)
	cmd.Dir = opts.Cwd
	cmd.Env = append(filteredHelperEnv(processTargetEnv(opts)), ptraceHelperEnv+"=1")
	return cmd, nil
}

// Let gdb.attach-style sibling debuggers attach when Linux Yama ptrace_scope=1.
func allowAnyPtracer() error {
	_, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, uintptr(prSetPtracer), ^uintptr(0), 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func filteredHelperEnv(env []string) []string {
	out := env[:0]
	prefix := ptraceHelperEnv + "="
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			continue
		}
		out = append(out, item)
	}
	return out
}
