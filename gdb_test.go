package gpwntools

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestGDBSessionOnExitCurrentTerminal(t *testing.T) {
	called := make(chan struct{}, 1)

	session, err := startGDB([]string{"-c", "exit 0"}, GDBOptions{Path: "sh"}, "", func() error {
		select {
		case called <- struct{}{}:
		default:
		}
		return nil
	})
	if err != nil {
		t.Fatalf("startGDB failed: %v", err)
	}

	if err := session.Wait(); err != nil {
		t.Fatalf("Wait failed: %v", err)
	}

	select {
	case <-called:
	default:
		t.Fatal("onExit callback was not called")
	}
}

func TestGDBSessionOnExitTerminalWrapper(t *testing.T) {
	called := make(chan struct{}, 1)

	session, err := startGDB([]string{"-c", "exit 0"}, GDBOptions{
		Path:     "sh",
		Terminal: []string{"sh", "-lc"},
	}, "", func() error {
		select {
		case called <- struct{}{}:
		default:
		}
		return nil
	})
	if err != nil {
		t.Fatalf("startGDB failed: %v", err)
	}

	if err := session.Wait(); err != nil {
		t.Fatalf("Wait failed: %v", err)
	}

	select {
	case <-called:
	default:
		t.Fatal("onExit callback was not called")
	}
}

func TestGDBTerminalLauncherOutputSuppressed(t *testing.T) {
	restoreOutput := captureStdoutStderr(t)
	defer restoreOutput()

	session, err := startGDB([]string{"-c", "exit 0"}, GDBOptions{
		Path: "sh",
		Terminal: []string{
			"sh",
			"-lc",
			"printf 'launcher stdout\\n'; printf 'launcher stderr\\n' >&2; eval \"$0\"",
		},
	}, "", nil)
	if err != nil {
		t.Fatalf("startGDB failed: %v", err)
	}

	if err := session.Wait(); err != nil {
		t.Fatalf("Wait failed: %v", err)
	}

	stdout, stderr := restoreOutput()
	if stdout != "" || stderr != "" {
		t.Fatalf("launcher output leaked: stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestGDBTerminalWaitsForScriptReady(t *testing.T) {
	fakeGDB := writeReadyFakeGDB(t, 150*time.Millisecond)
	scriptPath, err := writeGDBScript("break main")
	if err != nil {
		t.Fatalf("writeGDBScript failed: %v", err)
	}

	start := time.Now()
	session, err := startGDB([]string{"-x", scriptPath}, GDBOptions{
		Path:     fakeGDB,
		Terminal: []string{"sh", "-lc"},
	}, scriptPath, nil)
	if err != nil {
		t.Fatalf("startGDB failed: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Fatalf("startGDB returned before script readiness: elapsed=%s", elapsed)
	}

	if err := session.Wait(); err != nil {
		t.Fatalf("Wait failed: %v", err)
	}
}

func TestGDBTerminalAllowsSuccessfulDetachedLauncher(t *testing.T) {
	watchPath, err := tempMarker("gpwntools-test-watch-*")
	if err != nil {
		t.Fatalf("tempMarker failed: %v", err)
	}
	t.Cleanup(func() { _ = removeIfExists(watchPath) })

	start := time.Now()
	launcherDone := make(chan error, 1)
	launcherDone <- nil
	err = waitForTerminalStartup("tmux", watchPath, "", "", launcherDone, 100*time.Millisecond)
	if err == nil {
		t.Fatal("waitForTerminalStartup succeeded without marker after detached launcher exit")
	}
	if elapsed := time.Since(start); elapsed < 80*time.Millisecond {
		t.Fatalf("waitForTerminalStartup returned before timeout: %s", elapsed)
	}
	if !strings.Contains(err.Error(), "exited before gdb started") {
		t.Fatalf("waitForTerminalStartup error = %q, want detached launcher startup error", err.Error())
	}

	watchPath2, err := tempMarker("gpwntools-test-watch-*")
	if err != nil {
		t.Fatalf("tempMarker failed: %v", err)
	}
	pidPath := t.TempDir() + "/pid"
	launcherDone = make(chan error, 1)
	launcherDone <- nil
	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = os.WriteFile(pidPath, []byte("1234\n"), 0600)
	}()
	if err := waitForTerminalStartup("tmux", watchPath2, pidPath, "", launcherDone, time.Second); err != nil {
		t.Fatalf("waitForTerminalStartup failed after detached launcher marker: %v", err)
	}
}

func TestGDBDebugSessionWithOptionsTerminalWaitsForScriptReady(t *testing.T) {
	scriptCopy := t.TempDir() + "/debug-script.gdb"
	fakeGDB := writeReadyFakeGDB(t, 0)

	session, err := GDBDebugSessionWithOptions([]string{"/bin/true", "arg"}, GDBOptions{
		Path:     fakeGDB,
		Script:   "break main\nrun",
		Terminal: []string{"sh", "-lc"},
		Env:      []string{"GPWNTOOLS_FAKE_GDB_SCRIPT_COPY=" + scriptCopy},
	})
	if err != nil {
		t.Fatalf("GDBDebugSessionWithOptions failed: %v", err)
	}
	if err := session.Wait(); err != nil {
		t.Fatalf("Wait failed: %v", err)
	}

	copied := readFile(t, scriptCopy)
	if !strings.Contains(copied, "define hook-run\n") {
		t.Fatalf("debug script missing run ready hook:\n%s", copied)
	}
	if !strings.Contains(copied, "\nbreak main\nrun\n") {
		t.Fatalf("debug script missing original commands:\n%s", copied)
	}
}

func TestGDBDebugWithOptionsReturnsTubeAndSession(t *testing.T) {
	scriptCopy := t.TempDir() + "/debug-process-script.gdb"
	fakeGDB := writeReadyFakeGDB(t, 0)
	fakeGDBServer := writeFakeGDBServer(t, "31337")

	p, g, err := GDBDebugWithOptions([]string{"sh", "-c", "sleep 1"}, GDBDebugOptions{
		Process: ProcessOptions{
			DisablePTY: true,
		},
		GDB: GDBOptions{
			Path:     fakeGDB,
			Script:   "break main\ncontinue",
			Terminal: []string{"sh", "-lc"},
			Env:      []string{"GPWNTOOLS_FAKE_GDB_SCRIPT_COPY=" + scriptCopy},
		},
		GDBServerPath: fakeGDBServer,
	})
	if err != nil {
		t.Fatalf("GDBDebugWithOptions failed: %v", err)
	}
	if p == nil {
		t.Fatal("process tube is nil")
	}
	if g == nil {
		t.Fatal("gdb session is nil")
	}
	t.Cleanup(func() {
		_ = g.Close()
		_ = p.Close()
	})

	copied := readFile(t, scriptCopy)
	if !strings.Contains(copied, "\ntarget remote 127.0.0.1:31337\nset breakpoint pending on\nbreak main\ncontinue\n") {
		t.Fatalf("debug process script missing target remote or original commands:\n%s", copied)
	}
}

func TestGDBServerOutputFilterSuppressesStatusLine(t *testing.T) {
	input := "" +
		"target output\n" +
		"Remote debugging from host 127.0.0.1, port 57174\n" +
		"Remote debug text from target\n" +
		"done\n"

	got, err := io.ReadAll(newGDBServerOutputFilter(bufio.NewReader(strings.NewReader(input))))
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	want := "" +
		"target output\n" +
		"Remote debug text from target\n" +
		"done\n"
	if string(got) != want {
		t.Fatalf("filtered output = %q, want %q", got, want)
	}
}

func TestGDBRemoteWithOptionsTerminalWaitsForScriptReady(t *testing.T) {
	scriptCopy := t.TempDir() + "/remote-script.gdb"
	fakeGDB := writeReadyFakeGDB(t, 0)

	session, err := GDBRemoteAddressWithOptions("127.0.0.1:31337", GDBOptions{
		Path:     fakeGDB,
		Binary:   "/bin/true",
		Script:   "break *main\ncontinue",
		Terminal: []string{"sh", "-lc"},
		Env:      []string{"GPWNTOOLS_FAKE_GDB_SCRIPT_COPY=" + scriptCopy},
	})
	if err != nil {
		t.Fatalf("GDBRemoteAddressWithOptions failed: %v", err)
	}
	if err := session.Wait(); err != nil {
		t.Fatalf("Wait failed: %v", err)
	}

	copied := readFile(t, scriptCopy)
	if !strings.Contains(copied, "define hook-continue\n") {
		t.Fatalf("remote script missing continue ready hook:\n%s", copied)
	}
	if !strings.Contains(copied, "\ntarget remote 127.0.0.1:31337\nbreak *main\ncontinue\n") {
		t.Fatalf("remote script missing target remote or original commands:\n%s", copied)
	}
}

func TestWrapTerminalGDBScriptForReady(t *testing.T) {
	got := wrapTerminalGDBScriptForReady("b *0x401184\nc\n", "/tmp/gdb ready")
	readyCommand := "shell printf ready > '/tmp/gdb ready'"

	for _, command := range []string{"continue", "run", "start"} {
		want := "define hook-" + command + "\n" + readyCommand + "\nend\n"
		if !strings.Contains(got, want) {
			t.Fatalf("wrapped script missing %s hook:\n%s", command, got)
		}
	}
	if !strings.Contains(got, "\nb *0x401184\nc\n"+readyCommand+"\n") {
		t.Fatalf("wrapped script missing original script or final ready command:\n%s", got)
	}
}

func TestGDBTerminalStartFailureReturned(t *testing.T) {
	called := make(chan struct{}, 1)

	session, err := startGDB([]string{"-c", "exit 0"}, GDBOptions{
		Path:     "sh",
		Terminal: []string{"sh", "-lc", "printf 'launcher failed\\n' >&2; exit 7"},
	}, "", func() error {
		select {
		case called <- struct{}{}:
		default:
		}
		return nil
	})
	if err == nil {
		if session != nil {
			_ = session.Close()
		}
		t.Fatal("startGDB succeeded, want terminal startup error")
	}
	if !strings.Contains(err.Error(), "launcher failed") {
		t.Fatalf("startGDB error = %q, want launcher output", err.Error())
	}

	select {
	case <-called:
		t.Fatal("onExit callback should not be called when terminal never starts gdb")
	default:
	}
}

func TestGDBTerminalByName(t *testing.T) {
	cases := map[string][]string{
		"pwntools-terminal":   {"pwntools-terminal"},
		"tmux_split":          {"tmux", "split-window", "-h"},
		"zellij":              {"zellij", "action", "new-pane", "--"},
		"screen":              {"screen", "-t", "gpwntools-gdb", "bash", "-c"},
		"ptyxis":              {"ptyxis", "--", "sh", "-lc"},
		"kgx":                 {"kgx", "--", "sh", "-lc"},
		"gnome-console":       {"kgx", "--", "sh", "-lc"},
		"wezterm":             {"wezterm", "start", "--", "sh", "-lc"},
		"terminator":          {"terminator", "-e"},
		"ghostty":             {"ghostty", "-e", "sh", "-lc"},
		"konsole":             {"konsole", "-e", "sh", "-lc"},
		"kconsole":            {"kconsole", "-e", "sh", "-lc"},
		"tilix":               {"tilix", "-a", "session-add-right", "-e"},
		"x-terminal-emulator": {"x-terminal-emulator", "-e"},
	}

	for name, want := range cases {
		got, err := GDBTerminalByName(name)
		if err != nil {
			t.Fatalf("GDBTerminalByName(%q) failed: %v", name, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("GDBTerminalByName(%q) = %#v, want %#v", name, got, want)
		}
	}

	if _, err := GDBTerminalByName("missing-terminal"); err == nil {
		t.Fatal("GDBTerminalByName accepted unsupported terminal")
	} else if !strings.Contains(err.Error(), "Context.SetTerminal") {
		t.Fatalf("unsupported terminal error = %q, want custom terminal hint", err.Error())
	}

	if _, err := GDBTerminalByName("tmux split-window -h"); err == nil {
		t.Fatal("GDBTerminalByName accepted tmux command string")
	} else if !strings.Contains(err.Error(), `Context.SetTerminal("tmux", "split-window", "-h")`) {
		t.Fatalf("tmux terminal error = %q, want tmux SetTerminal hint", err.Error())
	}
}

func TestGDBTerminalFromTermProgramUsesBuiltInProfile(t *testing.T) {
	t.Setenv("TERM_PROGRAM", "ghostty")

	got := gdbTerminalFromTermProgram()
	want := []string{"ghostty", "-e", "sh", "-lc"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("gdbTerminalFromTermProgram = %#v, want %#v", got, want)
	}
}

func writeFakeGDB(t *testing.T, content string) string {
	t.Helper()

	path := t.TempDir() + "/fake-gdb"
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatalf("write fake gdb: %v", err)
	}
	return path
}

func writeReadyFakeGDB(t *testing.T, delay time.Duration) string {
	t.Helper()

	delaySeconds := float64(delay) / float64(time.Second)
	return writeFakeGDB(t, `#!/bin/sh
script=
while [ "$#" -gt 0 ]; do
	case "$1" in
		-x)
			script=$2
			shift 2
			;;
		*)
			shift
			;;
	esac
done
if [ `+shellQuote(fmt.Sprintf("%.3f", delaySeconds))+` != 0.000 ]; then
	sleep `+shellQuote(fmt.Sprintf("%.3f", delaySeconds))+`
fi
if [ -n "$script" ]; then
	if [ -n "$GPWNTOOLS_FAKE_GDB_SCRIPT_COPY" ]; then
		cp "$script" "$GPWNTOOLS_FAKE_GDB_SCRIPT_COPY"
	fi
	while IFS= read -r line; do
		case "$line" in
			shell\ *) sh -c "${line#shell }" ;;
		esac
	done < "$script"
fi
`)
}

func writeFakeGDBServer(t *testing.T, port string) string {
	t.Helper()

	return writeFakeGDB(t, `#!/bin/sh
printf 'Process created; pid = 1234\n' >&2
printf 'Listening on port `+port+`\n' >&2
sleep 60
`)
}

func readFile(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func captureStdoutStderr(t *testing.T) func() (string, string) {
	t.Helper()

	oldStdout := os.Stdout
	oldStderr := os.Stderr
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		t.Fatalf("create stderr pipe: %v", err)
	}

	os.Stdout = stdoutW
	os.Stderr = stderrW
	restored := false

	return func() (string, string) {
		if restored {
			return "", ""
		}
		restored = true

		_ = stdoutW.Close()
		_ = stderrW.Close()
		os.Stdout = oldStdout
		os.Stderr = oldStderr

		stdout, _ := io.ReadAll(stdoutR)
		stderr, _ := io.ReadAll(stderrR)
		_ = stdoutR.Close()
		_ = stderrR.Close()
		return string(stdout), string(stderr)
	}
}
