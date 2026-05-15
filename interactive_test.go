package gpwntools

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestInteractiveInputNormalizerConvertsWindowsNewlines(t *testing.T) {
	got, err := io.ReadAll(newInteractiveInputNormalizer(strings.NewReader("ls\r\nid\r\npwd\n")))
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if string(got) != "ls\nid\npwd\n" {
		t.Fatalf("normalized input = %q, want %q", got, "ls\nid\npwd\n")
	}
}

func TestInteractiveInputNormalizerConvertsBareCarriageReturn(t *testing.T) {
	got, err := io.ReadAll(newInteractiveInputNormalizer(strings.NewReader("ls\rid")))
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if string(got) != "ls\nid" {
		t.Fatalf("normalized input = %q, want %q", got, "ls\nid")
	}
}

func TestInteractiveLineInputEchoesInput(t *testing.T) {
	var echo bytes.Buffer
	got, err := io.ReadAll(newInteractiveLineInput(strings.NewReader("ls\rid\n"), &echo))
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if string(got) != "ls\nid\n" {
		t.Fatalf("normalized input = %q, want %q", got, "ls\nid\n")
	}
	if echo.String() != "ls\r\nid\r\n" {
		t.Fatalf("echo = %q, want %q", echo.String(), "ls\r\nid\r\n")
	}
}
