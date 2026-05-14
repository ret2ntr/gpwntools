package gpwntools

import "testing"

func TestLjust(t *testing.T) {
	got := Ljust([]byte("abc"), 5, 'X')
	if string(got) != "abcXX" {
		t.Fatalf("Ljust = %q, want %q", got, "abcXX")
	}
}

func TestRjust(t *testing.T) {
	got := Rjust([]byte("abc"), 5, 'X')
	if string(got) != "XXabc" {
		t.Fatalf("Rjust = %q, want %q", got, "XXabc")
	}
}

func TestJustDefaultFiller(t *testing.T) {
	got := Ljust([]byte("abc"), 5)
	want := []byte{'a', 'b', 'c', 0, 0}
	if string(got) != string(want) {
		t.Fatalf("Ljust default filler = %#v, want %#v", got, want)
	}
}

func TestJustDoesNotTruncate(t *testing.T) {
	got := Rjust([]byte("abcdef"), 3, 'X')
	if string(got) != "abcdef" {
		t.Fatalf("Rjust truncated data: got %q", got)
	}
}
