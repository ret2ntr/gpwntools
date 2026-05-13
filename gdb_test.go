package gpwntools

import "testing"

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
