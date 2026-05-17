package gpwntools

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestContextLogLevelDebugLogsTubePackets(t *testing.T) {
	saved := Context.Clone()
	t.Cleanup(func() { Context.Apply(saved) })

	var logs bytes.Buffer
	SetLogOutput(&logs)
	t.Cleanup(func() { SetLogOutput(os.Stderr) })

	Context.SetLogLevel("debug")

	var sent bytes.Buffer
	if err := SendLine(&sent, []byte("AAAA")); err != nil {
		t.Fatalf("SendLine failed: %v", err)
	}
	if !bytes.Equal(sent.Bytes(), []byte("AAAA\n")) {
		t.Fatalf("sent bytes = %q, want %q", sent.Bytes(), "AAAA\n")
	}

	got, err := Recv(bytes.NewBufferString("hi!"), 3)
	if err != nil {
		t.Fatalf("Recv failed: %v", err)
	}
	if string(got) != "hi!" {
		t.Fatalf("Recv = %q, want %q", got, "hi!")
	}

	text := logs.String()
	for _, want := range []string{
		"[DEBUG] Sent 0x5 bytes:",
		"41 41 41 41 0a",
		"[DEBUG] Received 0x3 bytes:",
		"68 69 21",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("debug log missing %q:\n%s", want, text)
		}
	}
}

func TestRecvUntilDropLogsWireBytes(t *testing.T) {
	saved := Context.Clone()
	t.Cleanup(func() { Context.Apply(saved) })

	var logs bytes.Buffer
	SetLogOutput(&logs)
	t.Cleanup(func() { SetLogOutput(os.Stderr) })

	Context.LogLevel = "debug"

	got, err := RecvUntil(bytes.NewBufferString("abc:"), []byte(":"), true)
	if err != nil {
		t.Fatalf("RecvUntil failed: %v", err)
	}
	if string(got) != "abc" {
		t.Fatalf("RecvUntil drop = %q, want %q", got, "abc")
	}

	text := logs.String()
	if !strings.Contains(text, "[DEBUG] Received 0x4 bytes:") ||
		!strings.Contains(text, "61 62 63 3a") {
		t.Fatalf("RecvUntil debug log did not include delimiter wire bytes:\n%s", text)
	}
}
