package gpwntools

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultGDBPath = "gdb"

// GDBOptions configures how gdb is started.
type GDBOptions struct {
	// Path is the gdb executable path. It defaults to "gdb".
	Path string
	// Binary is an optional local executable path used for symbols.
	Binary string
	// Script is an inline gdb script, such as "break main\ncontinue".
	Script string
	// Args are extra raw arguments passed to gdb after "-q".
	Args []string
	// Terminal starts gdb in another terminal. The shell-escaped gdb command is
	// appended as the final argument, for example []string{"tmux", "split-window", "-h"}.
	Terminal []string
	// Env appends environment variables for the gdb process.
	Env []string
	// Dir sets the working directory for the gdb process.
	Dir string
}

// GDBSession is a running gdb process.
type GDBSession struct {
	Cmd        *exec.Cmd
	ScriptPath string
	WatchPath  string
	PidPath    string

	done       chan struct{}
	onExit     func() error
	finishOnce sync.Once

	cleanupOnce sync.Once
	cleanupErr  error
	waitErr     error
}

// GDBAttach starts gdb and attaches it to a process id or process-like target.
//
// Supported target types are int, *ProcessTube, *os.Process, *exec.Cmd, and any
// value implementing PID() int.
func GDBAttach(target any, script string) (*GDBSession, error) {
	terminal, err := contextGDBTerminal()
	if err != nil {
		return nil, err
	}
	return GDBAttachWithOptions(target, GDBOptions{
		Script:   script,
		Terminal: terminal,
	})
}

// GDBAttachHere starts gdb in the current terminal and attaches to the target.
func GDBAttachHere(target any, script string) (*GDBSession, error) {
	return GDBAttachWithOptions(target, GDBOptions{Script: script})
}

// GDBAttachProcess starts gdb and attaches it to a ProcessTube.
func GDBAttachProcess(p *ProcessTube, script string) (*GDBSession, error) {
	return GDBAttach(p, script)
}

// GDBAttachWithOptions starts gdb and attaches it using explicit options.
func GDBAttachWithOptions(target any, opts GDBOptions) (*GDBSession, error) {
	pid, err := gdbTargetPID(target)
	if err != nil {
		return nil, err
	}
	scriptPath, err := writeGDBScript(opts.Script)
	if err != nil {
		return nil, err
	}
	args := buildGDBAttachArgs(pid, opts, scriptPath)
	return startGDB(args, opts, scriptPath, gdbTargetCloser(target))
}

// GDBDebug starts gdb for a new local process, equivalent to "gdb --args ...".
func GDBDebug(argv []string, script string) (*GDBSession, error) {
	terminal, err := contextGDBTerminal()
	if err != nil {
		return nil, err
	}
	return GDBDebugWithOptions(argv, GDBOptions{
		Script:   script,
		Terminal: terminal,
	})
}

// GDBDebugHere starts gdb for a new local process in the current terminal.
func GDBDebugHere(argv []string, script string) (*GDBSession, error) {
	return GDBDebugWithOptions(argv, GDBOptions{Script: script})
}

// GDBDebugWithOptions starts gdb for a new local process with explicit options.
func GDBDebugWithOptions(argv []string, opts GDBOptions) (*GDBSession, error) {
	if len(argv) == 0 {
		return nil, errors.New("gdb debug requires at least one argument")
	}
	scriptPath, err := writeGDBScript(opts.Script)
	if err != nil {
		return nil, err
	}
	args := buildGDBDebugArgs(argv, opts, scriptPath)
	return startGDB(args, opts, scriptPath, nil)
}

// GDBRemote starts gdb and connects to a gdbserver at host:port.
func GDBRemote(host string, port int, binary string, script string) (*GDBSession, error) {
	return GDBRemoteAddress(netJoinHostPort(host, port), binary, script)
}

// GDBRemoteAddress starts gdb and connects to a gdbserver address.
func GDBRemoteAddress(address string, binary string, script string) (*GDBSession, error) {
	terminal, err := contextGDBTerminal()
	if err != nil {
		return nil, err
	}
	return GDBRemoteAddressWithOptions(address, GDBOptions{
		Binary:   binary,
		Script:   script,
		Terminal: terminal,
	})
}

// GDBRemoteAddressHere starts gdb in the current terminal and connects to a gdbserver address.
func GDBRemoteAddressHere(address string, binary string, script string) (*GDBSession, error) {
	return GDBRemoteAddressWithOptions(address, GDBOptions{
		Binary: binary,
		Script: script,
	})
}

// GDBRemoteAddressWithOptions starts gdb and connects to a gdbserver address.
func GDBRemoteAddressWithOptions(address string, opts GDBOptions) (*GDBSession, error) {
	if strings.TrimSpace(address) == "" {
		return nil, errors.New("gdb remote requires an address")
	}
	opts.Script = joinGDBScript("target remote "+address, opts.Script)
	scriptPath, err := writeGDBScript(opts.Script)
	if err != nil {
		return nil, err
	}
	args := buildGDBRemoteArgs(opts, scriptPath)
	return startGDB(args, opts, scriptPath, nil)
}

// Wait waits for gdb to exit and removes any temporary script file.
func (s *GDBSession) Wait() error {
	if s == nil {
		return nil
	}
	<-s.done
	return s.waitErr
}

// Close kills gdb if it is still running and removes any temporary script file.
func (s *GDBSession) Close() error {
	if s == nil {
		return nil
	}

	err := s.kill()
	waitErr := s.Wait()
	if err == nil {
		err = normalizeGDBWaitError(waitErr)
	}
	return err
}

func (s *GDBSession) cleanup() error {
	s.cleanupOnce.Do(func() {
		for _, path := range []string{s.ScriptPath, s.WatchPath, s.PidPath} {
			if err := removeIfExists(path); s.cleanupErr == nil && err != nil {
				s.cleanupErr = err
			}
		}
	})
	return s.cleanupErr
}

func startGDB(args []string, opts GDBOptions, scriptPath string, onExit func() error) (*GDBSession, error) {
	if len(opts.Terminal) > 0 {
		return startGDBInTerminal(args, opts, scriptPath, onExit)
	}

	cmd := exec.Command(gdbPath(opts), args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), opts.Env...)
	cmd.Dir = opts.Dir

	session := &GDBSession{
		Cmd:        cmd,
		ScriptPath: scriptPath,
		done:       make(chan struct{}),
		onExit:     onExit,
	}

	if err := cmd.Start(); err != nil {
		_ = session.cleanup()
		return nil, err
	}
	go session.waitForCommand()
	return session, nil
}

func startGDBInTerminal(args []string, opts GDBOptions, scriptPath string, onExit func() error) (*GDBSession, error) {
	if opts.Terminal[0] == "" {
		return nil, errors.New("gdb terminal executable must not be empty")
	}

	watchPath, err := tempMarker("gpwntools-gdb-watch-*")
	if err != nil {
		return nil, err
	}
	pidPath, err := tempFilePath("gpwntools-gdb-pid-*")
	if err != nil {
		_ = removeIfExists(watchPath)
		return nil, err
	}

	command := buildTerminalGDBCommand(gdbPath(opts), args, watchPath, pidPath, scriptPath)

	terminalArgs := append([]string{}, opts.Terminal[1:]...)
	terminalArgs = append(terminalArgs, command)
	cmd := exec.Command(opts.Terminal[0], terminalArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), opts.Env...)
	cmd.Dir = opts.Dir

	session := &GDBSession{
		Cmd:        cmd,
		ScriptPath: scriptPath,
		WatchPath:  watchPath,
		PidPath:    pidPath,
		done:       make(chan struct{}),
		onExit:     onExit,
	}

	if err := cmd.Start(); err != nil {
		_ = session.cleanup()
		return nil, err
	}
	go session.reapLauncher()
	go session.waitForWatchPath()
	return session, nil
}

func writeGDBScript(script string) (string, error) {
	if strings.TrimSpace(script) == "" {
		return "", nil
	}

	f, err := os.CreateTemp("", "gpwntools-*.gdb")
	if err != nil {
		return "", err
	}
	path := f.Name()
	if _, err := f.WriteString(script); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", err
	}
	if !strings.HasSuffix(script, "\n") {
		if _, err := f.WriteString("\n"); err != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return "", err
		}
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func buildGDBAttachArgs(pid int, opts GDBOptions, scriptPath string) []string {
	args := buildGDBBaseArgs(opts)
	if opts.Binary != "" {
		args = append(args, opts.Binary)
	}
	args = append(args, "-p", strconv.Itoa(pid))
	if scriptPath != "" {
		args = append(args, "-x", scriptPath)
	}
	return args
}

func buildGDBDebugArgs(argv []string, opts GDBOptions, scriptPath string) []string {
	args := buildGDBBaseArgs(opts)
	if scriptPath != "" {
		args = append(args, "-x", scriptPath)
	}
	args = append(args, "--args")
	args = append(args, argv...)
	return args
}

func buildGDBRemoteArgs(opts GDBOptions, scriptPath string) []string {
	args := buildGDBBaseArgs(opts)
	if opts.Binary != "" {
		args = append(args, opts.Binary)
	}
	if scriptPath != "" {
		args = append(args, "-x", scriptPath)
	}
	return args
}

func buildGDBBaseArgs(opts GDBOptions) []string {
	args := []string{"-q"}
	return append(args, opts.Args...)
}

func gdbPath(opts GDBOptions) string {
	if opts.Path == "" {
		return defaultGDBPath
	}
	return opts.Path
}

func contextGDBTerminal() ([]string, error) {
	terminal := contextTerminal()
	if len(terminal) == 0 {
		return nil, errors.New("no gdb terminal found; set gpwntools.Context.Terminal or install tmux/gnome-terminal/konsole/kitty/alacritty/xterm")
	}
	return terminal, nil
}

// GDBTerminalDefault chooses a usable terminal launcher for GDB.
func GDBTerminalDefault() []string {
	if os.Getenv("TMUX") != "" && commandExists("tmux") {
		return GDBTerminalTmuxSplit()
	}
	if commandExists("gnome-terminal") {
		return GDBTerminalGnome()
	}
	if commandExists("konsole") {
		return GDBTerminalKonsole()
	}
	if commandExists("kitty") {
		return GDBTerminalKitty()
	}
	if commandExists("alacritty") {
		return GDBTerminalAlacritty()
	}
	if commandExists("xterm") {
		return GDBTerminalXTerm()
	}
	return nil
}

// GDBTerminalTmuxSplit returns a tmux split-window launcher for GDB.
func GDBTerminalTmuxSplit() []string {
	return []string{"tmux", "split-window", "-h"}
}

// GDBTerminalGnome returns a GNOME Terminal launcher for GDB.
func GDBTerminalGnome() []string {
	return []string{"gnome-terminal", "--", "sh", "-lc"}
}

// GDBTerminalKonsole returns a Konsole launcher for GDB.
func GDBTerminalKonsole() []string {
	return []string{"konsole", "-e", "sh", "-lc"}
}

// GDBTerminalKitty returns a kitty launcher for GDB.
func GDBTerminalKitty() []string {
	return []string{"kitty", "sh", "-lc"}
}

// GDBTerminalAlacritty returns an Alacritty launcher for GDB.
func GDBTerminalAlacritty() []string {
	return []string{"alacritty", "-e", "sh", "-lc"}
}

// GDBTerminalXTerm returns an xterm launcher for GDB.
func GDBTerminalXTerm() []string {
	return []string{"xterm", "-e", "sh", "-lc"}
}

func gdbTargetPID(target any) (int, error) {
	switch t := target.(type) {
	case int:
		return validatePID(t)
	case *ProcessTube:
		if t == nil {
			return 0, errors.New("gdb attach target is nil")
		}
		return validatePID(t.PID())
	case *os.Process:
		if t == nil {
			return 0, errors.New("gdb attach target is nil")
		}
		return validatePID(t.Pid)
	case *exec.Cmd:
		if t == nil || t.Process == nil {
			return 0, errors.New("gdb attach target process has not started")
		}
		return validatePID(t.Process.Pid)
	case interface{ PID() int }:
		return validatePID(t.PID())
	default:
		return 0, fmt.Errorf("unsupported gdb attach target %T", target)
	}
}

func validatePID(pid int) (int, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("invalid process id %d", pid)
	}
	return pid, nil
}

func joinGDBScript(first string, rest string) string {
	var b strings.Builder
	b.WriteString(first)
	if !strings.HasSuffix(first, "\n") {
		b.WriteByte('\n')
	}
	if rest != "" {
		b.WriteString(rest)
		if !strings.HasSuffix(rest, "\n") {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func normalizeGDBWaitError(err error) error {
	if err == nil {
		return nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return nil
	}
	return err
}

func netJoinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func (s *GDBSession) waitForCommand() {
	var err error
	if s.Cmd != nil {
		err = s.Cmd.Wait()
	}
	s.finish(err)
}

func (s *GDBSession) reapLauncher() {
	if s.Cmd != nil {
		if err := s.Cmd.Wait(); err != nil {
			s.finish(err)
		}
	}
}

func (s *GDBSession) waitForWatchPath() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		if _, err := os.Stat(s.WatchPath); errors.Is(err, os.ErrNotExist) {
			s.finish(nil)
			return
		}
		<-ticker.C
	}
}

func (s *GDBSession) finish(err error) {
	s.finishOnce.Do(func() {
		err = normalizeGDBWaitError(err)
		if cleanupErr := s.cleanup(); err == nil {
			err = cleanupErr
		}
		if s.onExit != nil {
			if closeErr := normalizeInteractiveError(s.onExit()); err == nil {
				err = closeErr
			}
		}
		s.waitErr = err
		close(s.done)
	})
}

func (s *GDBSession) kill() error {
	if s == nil {
		return nil
	}
	if pid, err := readPIDFile(s.PidPath); err == nil && pid > 0 {
		if err := killPID(pid); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		return nil
	}
	if s.Cmd != nil && s.Cmd.Process != nil {
		err := s.Cmd.Process.Kill()
		if errors.Is(err, os.ErrProcessDone) {
			return nil
		}
		return err
	}
	return nil
}

func gdbTargetCloser(target any) func() error {
	if closer, ok := target.(interface{ Close() error }); ok {
		return closer.Close
	}
	return nil
}

func buildTerminalGDBCommand(gdb string, args []string, watchPath string, pidPath string, scriptPath string) string {
	cleanup := []string{watchPath, pidPath}
	if scriptPath != "" {
		cleanup = append(cleanup, scriptPath)
	}

	var b strings.Builder
	b.WriteString(shellCommand(gdb, args))
	b.WriteString(" & child=$!; ")
	b.WriteString("echo \"$child\" > ")
	b.WriteString(shellQuote(pidPath))
	b.WriteString("; ")
	b.WriteString("wait \"$child\"; status=$?; ")
	b.WriteString("rm -f")
	for _, path := range cleanup {
		b.WriteByte(' ')
		b.WriteString(shellQuote(path))
	}
	b.WriteString("; exit \"$status\"")
	return b.String()
}

func tempMarker(pattern string) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	path := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func tempFilePath(pattern string) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	path := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	if err := os.Remove(path); err != nil {
		return "", err
	}
	return path, nil
}

func readPIDFile(path string) (int, error) {
	if path == "" {
		return 0, os.ErrNotExist
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, err
	}
	return pid, nil
}

func killPID(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Kill()
}

func removeIfExists(path string) error {
	if path == "" {
		return nil
	}
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func shellCommand(name string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, shellQuote(name))
	for _, arg := range args {
		parts = append(parts, shellQuote(arg))
	}
	return strings.Join(parts, " ")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool {
		return !(r == '/' || r == '.' || r == '_' || r == '-' || r == ':' || r == '=' ||
			r == '+' || r == ',' || r == '@' ||
			(r >= '0' && r <= '9') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= 'a' && r <= 'z'))
	}) == -1 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
