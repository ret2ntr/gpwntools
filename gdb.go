package gpwntools

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultGDBPath       = "gdb"
	defaultGDBServerPath = "gdbserver"
)

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

// GDBDebugOptions configures GDBDebugWithOptions.
type GDBDebugOptions struct {
	// Process configures the target process whose IO is returned as a tube.
	Process ProcessOptions
	// GDB configures the debugger session.
	GDB GDBOptions
	// GDBServerPath is the gdbserver executable path. It defaults to "gdbserver".
	GDBServerPath string
	// GDBServerArgs are extra arguments passed to gdbserver before the listen address.
	GDBServerArgs []string
}

// GDBSession is a running gdb process.
type GDBSession struct {
	Cmd        *exec.Cmd
	ScriptPath string
	WatchPath  string
	PidPath    string
	ReadyPath  string

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

// GDBDebugSession starts gdb for a new local process, equivalent to "gdb --args ...".
func GDBDebugSession(argv []string, script string) (*GDBSession, error) {
	terminal, err := contextGDBTerminal()
	if err != nil {
		return nil, err
	}
	return GDBDebugSessionWithOptions(argv, GDBOptions{
		Script:   script,
		Terminal: terminal,
	})
}

// GDBDebugSessionWithOptions starts gdb for a new local process with explicit options.
func GDBDebugSessionWithOptions(argv []string, opts GDBOptions) (*GDBSession, error) {
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

// GDBDebug starts a local process under gdbserver, connects gdb in another
// terminal, and returns both the process tube and gdb session.
func GDBDebug(argv []string, script string) (*ProcessTube, *GDBSession, error) {
	terminal, err := contextGDBTerminal()
	if err != nil {
		return nil, nil, err
	}
	return GDBDebugWithOptions(argv, GDBDebugOptions{
		GDB: GDBOptions{
			Script:   script,
			Terminal: terminal,
		},
	})
}

// GDBDebugWithOptions starts a local process under gdbserver with retained tube
// IO and connects gdb using explicit process and debugger options.
func GDBDebugWithOptions(argv []string, opts GDBDebugOptions) (*ProcessTube, *GDBSession, error) {
	if len(argv) == 0 {
		return nil, nil, errors.New("gdb debug process requires at least one argument")
	}

	p, address, err := startGDBServer(argv, opts)
	if err != nil {
		return nil, nil, err
	}

	gdbOpts := opts.GDB
	if gdbOpts.Binary == "" {
		gdbOpts.Binary = gdbDebugProcessBinary(argv[0])
	}
	if gdbOpts.Dir == "" {
		gdbOpts.Dir = opts.Process.Cwd
	}
	gdbOpts.Script = joinGDBScript("set breakpoint pending on", gdbOpts.Script)

	g, err := startGDBRemote(address, gdbOpts, p.Close)
	if err != nil {
		_ = p.Close()
		return nil, nil, err
	}
	return p, g, nil
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

// GDBRemoteAddressWithOptions starts gdb and connects to a gdbserver address.
func GDBRemoteAddressWithOptions(address string, opts GDBOptions) (*GDBSession, error) {
	return startGDBRemote(address, opts, nil)
}

func startGDBRemote(address string, opts GDBOptions, onExit func() error) (*GDBSession, error) {
	if strings.TrimSpace(address) == "" {
		return nil, errors.New("gdb remote requires an address")
	}
	opts.Script = joinGDBScript("target remote "+address, opts.Script)
	scriptPath, err := writeGDBScript(opts.Script)
	if err != nil {
		return nil, err
	}
	args := buildGDBRemoteArgs(opts, scriptPath)
	return startGDB(args, opts, scriptPath, onExit)
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
		for _, path := range []string{s.ScriptPath, s.WatchPath, s.PidPath, s.ReadyPath} {
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
	readyPath := ""
	if scriptPath != "" {
		readyPath, err = tempFilePath("gpwntools-gdb-ready-*")
		if err != nil {
			_ = removeIfExists(watchPath)
			_ = removeIfExists(pidPath)
			return nil, err
		}
		if err := prepareTerminalGDBScript(scriptPath, readyPath); err != nil {
			_ = removeIfExists(watchPath)
			_ = removeIfExists(pidPath)
			_ = removeIfExists(readyPath)
			return nil, err
		}
	}

	command := buildTerminalGDBCommand(gdbPath(opts), args, watchPath, pidPath, readyPath, scriptPath)

	terminalArgs := append([]string{}, opts.Terminal[1:]...)
	terminalArgs = append(terminalArgs, command)
	cmd := exec.Command(opts.Terminal[0], terminalArgs...)
	launcherOutput := &terminalOutputBuffer{limit: 8192}
	cmd.Stdout = launcherOutput
	cmd.Stderr = launcherOutput
	cmd.Env = append(os.Environ(), opts.Env...)
	cmd.Dir = opts.Dir

	session := &GDBSession{
		Cmd:        cmd,
		ScriptPath: scriptPath,
		WatchPath:  watchPath,
		PidPath:    pidPath,
		ReadyPath:  readyPath,
		done:       make(chan struct{}),
		onExit:     onExit,
	}

	if err := cmd.Start(); err != nil {
		_ = session.cleanup()
		return nil, err
	}

	launcherDone := make(chan error, 1)
	go func() {
		launcherDone <- cmd.Wait()
	}()

	startupTimeout := 500 * time.Millisecond
	if readyPath != "" {
		startupTimeout = 5 * time.Second
	}
	if err := session.waitForTerminalStartup(launcherDone, startupTimeout); err != nil {
		_ = session.cleanup()
		if output := launcherOutput.String(); output != "" {
			err = fmt.Errorf("%w\nterminal output:\n%s", err, output)
		}
		return nil, err
	}

	go session.reapLauncher(launcherDone)
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

func startGDBServer(argv []string, opts GDBDebugOptions) (*ProcessTube, string, error) {
	gdbserverPath := opts.GDBServerPath
	if gdbserverPath == "" {
		gdbserverPath = defaultGDBServerPath
	}

	args := []string{"--once", "--no-startup-with-shell"}
	args = append(args, opts.GDBServerArgs...)
	args = append(args, "127.0.0.1:0")
	args = append(args, argv...)

	cmd := exec.Command(gdbserverPath, args...)
	cmd.Dir = opts.Process.Cwd
	if opts.Process.ClearEnv || len(opts.Process.Env) > 0 {
		cmd.Env = processTargetEnv(opts.Process)
	}

	p, err := startProcessCommand(cmd, opts.Process)
	if err != nil {
		return nil, "", err
	}

	address, err := waitForGDBServerAddress(p, 5*time.Second)
	if err != nil {
		_ = p.Close()
		return nil, "", err
	}
	p.filterOutput(newGDBServerOutputFilter(p.bufferedReader()))
	return p, address, nil
}

func waitForGDBServerAddress(p *ProcessTube, timeout time.Duration) (string, error) {
	const marker = "Listening on port "

	received, err := p.RecvUntilTimeout([]byte(marker), timeout)
	if err != nil {
		return "", fmt.Errorf("gdbserver did not report a listening port after %q: %w", string(received), err)
	}
	line, err := p.RecvLineTimeout(timeout)
	if err != nil {
		return "", fmt.Errorf("gdbserver did not finish listening port line after %q: %w", string(received), err)
	}
	port := strings.TrimSpace(string(line))
	if _, err := strconv.Atoi(port); err != nil {
		return "", fmt.Errorf("gdbserver reported invalid listening port %q", port)
	}
	return net.JoinHostPort("127.0.0.1", port), nil
}

type gdbServerOutputFilter struct {
	r         *bufio.Reader
	lineStart bool
	pending   []byte
}

func newGDBServerOutputFilter(r *bufio.Reader) io.Reader {
	return &gdbServerOutputFilter{
		r:         r,
		lineStart: true,
	}
}

func (f *gdbServerOutputFilter) Read(p []byte) (int, error) {
	for len(f.pending) == 0 {
		if err := f.readNext(); err != nil {
			return 0, err
		}
	}
	n := copy(p, f.pending)
	f.pending = f.pending[n:]
	return n, nil
}

func (f *gdbServerOutputFilter) readNext() error {
	b, err := f.r.ReadByte()
	if err != nil {
		return err
	}

	if f.lineStart {
		f.lineStart = false
		if b == 'R' {
			_ = f.discardKnownLine([]byte{b}, "Remote debugging from host ")
			return nil
		}
	}

	if b == '\n' {
		f.lineStart = true
	}
	f.pending = append(f.pending, b)
	return nil
}

func (f *gdbServerOutputFilter) discardKnownLine(prefix []byte, statusPrefix string) bool {
	for len(prefix) < len(statusPrefix) {
		b, err := f.r.ReadByte()
		if err != nil {
			f.pending = append(f.pending, prefix...)
			return false
		}
		prefix = append(prefix, b)
		if b != statusPrefix[len(prefix)-1] {
			f.pending = append(f.pending, prefix...)
			if b == '\n' {
				f.lineStart = true
			}
			return false
		}
	}

	for {
		b, err := f.r.ReadByte()
		if err != nil {
			f.lineStart = true
			return true
		}
		if b == '\n' {
			f.lineStart = true
			return true
		}
	}
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

func gdbDebugProcessBinary(argv0 string) string {
	if strings.Contains(argv0, "/") {
		return argv0
	}
	if resolved, err := exec.LookPath(argv0); err == nil {
		return resolved
	}
	return argv0
}

func contextGDBTerminal() ([]string, error) {
	terminal := contextTerminal()
	if len(terminal) == 0 {
		return nil, errors.New("no gdb terminal found; set gpwntools.Context.Terminal or install pwntools-terminal/tmux/zellij/screen/ptyxis/kgx/gnome-terminal/konsole/wezterm/kitty/terminator/alacritty/tilix/x-terminal-emulator/xterm")
	}
	return terminal, nil
}

// GDBTerminalDefault chooses a usable terminal launcher for GDB.
func GDBTerminalDefault() []string {
	if commandExists("pwntools-terminal") {
		return GDBTerminalPwntools()
	}
	if os.Getenv("TMUX") != "" && commandExists("tmux") {
		return GDBTerminalTmuxSplit()
	}
	if os.Getenv("ZELLIJ") != "" && commandExists("zellij") {
		return GDBTerminalZellij()
	}
	if os.Getenv("STY") != "" && commandExists("screen") {
		return GDBTerminalScreen()
	}
	if terminal := gdbTerminalFromTermProgram(); len(terminal) > 0 {
		return terminal
	}
	if commandExists("ptyxis") {
		return GDBTerminalPtyxis()
	}
	if commandExists("kgx") {
		return GDBTerminalKGX()
	}
	if commandExists("gnome-terminal") {
		return GDBTerminalGnome()
	}
	if commandExists("konsole") {
		return GDBTerminalKonsole()
	}
	if commandExists("kconsole") {
		return GDBTerminalKConsole()
	}
	if commandExists("wezterm") {
		return GDBTerminalWezTerm()
	}
	if commandExists("kitty") {
		return GDBTerminalKitty()
	}
	if commandExists("terminator") {
		return GDBTerminalTerminator()
	}
	if commandExists("ghostty") {
		return GDBTerminalGhostty()
	}
	if commandExists("alacritty") {
		return GDBTerminalAlacritty()
	}
	if commandExists("tilix") {
		return GDBTerminalTilix()
	}
	if os.Getenv("DISPLAY") != "" && commandExists("x-terminal-emulator") {
		return GDBTerminalXTerminalEmulator()
	}
	if commandExists("xterm") {
		return GDBTerminalXTerm()
	}
	return nil
}

// GDBTerminalByName returns a built-in terminal launcher by name.
func GDBTerminalByName(name string) ([]string, error) {
	switch normalizeTerminalName(name) {
	case "pwntools", "pwntools-terminal":
		return GDBTerminalPwntools(), nil
	case "tmux", "tmux-split", "tmux-split-window":
		return GDBTerminalTmuxSplit(), nil
	case "zellij":
		return GDBTerminalZellij(), nil
	case "screen", "gnu-screen":
		return GDBTerminalScreen(), nil
	case "ptyxis":
		return GDBTerminalPtyxis(), nil
	case "kgx", "gnome-console", "console":
		return GDBTerminalKGX(), nil
	case "gnome", "gnome-terminal":
		return GDBTerminalGnome(), nil
	case "konsole":
		return GDBTerminalKonsole(), nil
	case "kconsole":
		return GDBTerminalKConsole(), nil
	case "wezterm":
		return GDBTerminalWezTerm(), nil
	case "kitty":
		return GDBTerminalKitty(), nil
	case "terminator":
		return GDBTerminalTerminator(), nil
	case "ghostty":
		return GDBTerminalGhostty(), nil
	case "alacritty":
		return GDBTerminalAlacritty(), nil
	case "tilix":
		return GDBTerminalTilix(), nil
	case "x-terminal-emulator", "xterminalemulator":
		return GDBTerminalXTerminalEmulator(), nil
	case "xterm":
		return GDBTerminalXTerm(), nil
	default:
		return nil, unsupportedGDBTerminalError(name)
	}
}

// GDBTerminalCustom returns a copy of a custom terminal command prefix.
func GDBTerminalCustom(command ...string) []string {
	return append([]string{}, command...)
}

// GDBTerminalPwntools returns a pwntools-terminal launcher for GDB.
func GDBTerminalPwntools() []string {
	return []string{"pwntools-terminal"}
}

// GDBTerminalTmuxSplit returns a tmux split-window launcher for GDB.
func GDBTerminalTmuxSplit() []string {
	return []string{"tmux", "split-window", "-h"}
}

// GDBTerminalZellij returns a zellij pane launcher for GDB.
func GDBTerminalZellij() []string {
	return []string{"zellij", "action", "new-pane", "--"}
}

// GDBTerminalScreen returns a GNU screen launcher for GDB.
func GDBTerminalScreen() []string {
	return []string{"screen", "-t", "gpwntools-gdb", "bash", "-c"}
}

// GDBTerminalPtyxis returns a Ptyxis launcher for GDB.
func GDBTerminalPtyxis() []string {
	return []string{"ptyxis", "--", "sh", "-lc"}
}

// GDBTerminalKGX returns a GNOME Console launcher for GDB.
func GDBTerminalKGX() []string {
	return []string{"kgx", "--", "sh", "-lc"}
}

// GDBTerminalGnome returns a GNOME Terminal launcher for GDB.
func GDBTerminalGnome() []string {
	return []string{"gnome-terminal", "--", "sh", "-lc"}
}

// GDBTerminalKonsole returns a Konsole launcher for GDB.
func GDBTerminalKonsole() []string {
	return []string{"konsole", "-e", "sh", "-lc"}
}

// GDBTerminalKConsole returns a kconsole launcher for GDB.
func GDBTerminalKConsole() []string {
	return []string{"kconsole", "-e", "sh", "-lc"}
}

// GDBTerminalWezTerm returns a WezTerm launcher for GDB.
func GDBTerminalWezTerm() []string {
	return []string{"wezterm", "start", "--", "sh", "-lc"}
}

// GDBTerminalKitty returns a kitty launcher for GDB.
func GDBTerminalKitty() []string {
	return []string{"kitty", "sh", "-lc"}
}

// GDBTerminalTerminator returns a Terminator launcher for GDB.
func GDBTerminalTerminator() []string {
	return []string{"terminator", "-e"}
}

// GDBTerminalGhostty returns a Ghostty launcher for GDB.
func GDBTerminalGhostty() []string {
	return []string{"ghostty", "-e", "sh", "-lc"}
}

// GDBTerminalAlacritty returns an Alacritty launcher for GDB.
func GDBTerminalAlacritty() []string {
	return []string{"alacritty", "-e", "sh", "-lc"}
}

// GDBTerminalTilix returns a Tilix launcher for GDB.
func GDBTerminalTilix() []string {
	return []string{"tilix", "-a", "session-add-right", "-e"}
}

// GDBTerminalXTerminalEmulator returns a Debian x-terminal-emulator launcher for GDB.
func GDBTerminalXTerminalEmulator() []string {
	return []string{"x-terminal-emulator", "-e"}
}

// GDBTerminalXTerm returns an xterm launcher for GDB.
func GDBTerminalXTerm() []string {
	return []string{"xterm", "-e", "sh", "-lc"}
}

func gdbTerminalFromTermProgram() []string {
	termProgram := strings.TrimSpace(os.Getenv("TERM_PROGRAM"))
	if termProgram == "" || termProgram == "iTerm.app" {
		return nil
	}
	if commandExists(termProgram) {
		return []string{termProgram}
	}
	return nil
}

func normalizeTerminalName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, " ", "-")
	return name
}

func unsupportedGDBTerminalError(name string) error {
	normalized := normalizeTerminalName(name)
	if strings.HasPrefix(normalized, "tmux-") {
		return fmt.Errorf("unsupported gdb terminal %q; SetTerminalByName only accepts built-in terminal names such as %q; for tmux arguments use gpwntools.Context.SetTerminal(%q, %q, %q)", name, "tmux", "tmux", "split-window", "-h")
	}
	return fmt.Errorf("unsupported gdb terminal %q; use gpwntools.Context.SetTerminal(...) for custom launchers, for example gpwntools.Context.SetTerminal(%q, %q, %q, %q, %q)", name, "wezterm", "start", "--", "sh", "-lc")
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

type terminalOutputBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *terminalOutputBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.limit <= 0 {
		return len(p), nil
	}
	if remaining := b.limit - b.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			_, _ = b.buf.Write(p[:remaining])
			b.truncated = true
		} else {
			_, _ = b.buf.Write(p)
		}
	} else {
		b.truncated = true
	}
	return len(p), nil
}

func (b *terminalOutputBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	output := strings.TrimSpace(b.buf.String())
	if output == "" {
		return ""
	}
	if b.truncated {
		output += "\n[truncated]"
	}
	return output
}

func prepareTerminalGDBScript(scriptPath string, readyPath string) error {
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		return err
	}
	return os.WriteFile(scriptPath, []byte(wrapTerminalGDBScriptForReady(string(data), readyPath)), 0600)
}

func wrapTerminalGDBScriptForReady(script string, readyPath string) string {
	readyCommand := "shell printf ready > " + shellQuote(readyPath)
	var b strings.Builder

	for _, command := range []string{"continue", "run", "start"} {
		b.WriteString("define hook-")
		b.WriteString(command)
		b.WriteByte('\n')
		b.WriteString(readyCommand)
		b.WriteString("\nend\n")
	}

	b.WriteByte('\n')
	b.WriteString(script)
	if !strings.HasSuffix(script, "\n") {
		b.WriteByte('\n')
	}
	b.WriteString(readyCommand)
	b.WriteByte('\n')
	return b.String()
}

func (s *GDBSession) reapLauncher(launcherDone <-chan error) {
	if err := <-launcherDone; err != nil {
		s.finish(err)
	}
}

func (s *GDBSession) waitForTerminalStartup(launcherDone chan error, timeout time.Duration) error {
	return waitForTerminalStartup(s.Cmd.Path, s.WatchPath, s.PidPath, s.ReadyPath, launcherDone, timeout)
}

func waitForTerminalStartup(cmdPath string, watchPath string, pidPath string, readyPath string, launcherDone chan error, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()

	launcherExited := false
	for {
		if terminalGDBStarted(watchPath, pidPath, readyPath) {
			return nil
		}

		select {
		case err := <-launcherDone:
			launcherExited = true
			if terminalGDBStarted(watchPath, pidPath, readyPath) {
				launcherDone <- err
				return nil
			}
			if err == nil {
				// tmux split-window and similar launchers exit successfully after
				// handing the command to the new pane/window. Keep waiting for
				// the wrapper to write its pid/ready marker.
				launcherDone <- nil
				launcherDone = nil
				continue
			}
			return fmt.Errorf("gdb terminal %s exited before gdb started: %w", cmdPath, err)
		case <-ticker.C:
		case <-deadline.C:
			if launcherExited && !terminalGDBStarted(watchPath, pidPath, readyPath) {
				return fmt.Errorf("gdb terminal %s exited before gdb started", cmdPath)
			}
			return nil
		}
	}
}

func terminalGDBStarted(watchPath string, pidPath string, readyPath string) bool {
	if readyPath != "" {
		if _, err := os.Stat(readyPath); err == nil {
			return true
		}
		if _, err := os.Stat(watchPath); errors.Is(err, os.ErrNotExist) {
			return true
		}
		return false
	}
	if _, err := os.Stat(pidPath); err == nil {
		return true
	}
	if _, err := os.Stat(watchPath); errors.Is(err, os.ErrNotExist) {
		return true
	}
	return false
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

func buildTerminalGDBCommand(gdb string, args []string, watchPath string, pidPath string, readyPath string, scriptPath string) string {
	cleanup := []string{watchPath, pidPath}
	if readyPath != "" {
		cleanup = append(cleanup, readyPath)
	}
	if scriptPath != "" {
		cleanup = append(cleanup, scriptPath)
	}

	var b strings.Builder
	b.WriteString("set -m; ")
	b.WriteString(shellCommand(gdb, args))
	b.WriteString(" & child=$!; ")
	b.WriteString("echo \"$child\" > ")
	b.WriteString(shellQuote(pidPath))
	b.WriteString("; ")
	b.WriteString("fg %1; status=$?; ")
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
