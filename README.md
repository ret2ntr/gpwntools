# gpwntools

`gpwntools` is a small Go package inspired by Python pwntools.

## Use as a Package

```go
import "github.com/ret2ntr/gpwntools"

payload := gpwntools.Gp64(0xdeadbeef)
_ = payload
```

Context defaults:

```go
gpwntools.Context.SetArch("amd64")
gpwntools.Context.SetTerminal("tmux", "split-window", "-h")
gpwntools.Context.Timeout = 2 * time.Second
gpwntools.Context.Endian = "little"
gpwntools.Context.PTY = true // Linux default: local Process stdout/stderr use PTY
```

Packing helpers:

- `Gp64/Gp32/Gp16/Gp8`: little-endian
- `GP64/GP32/GP16/GP8`: big-endian
- `Gu64/Gu32/Gu16/Gu8`: little-endian unpack
- `GU64/GU32/GU16/GU8`: big-endian unpack

```go
leak, err := gpwntools.Gu64(data)
if err != nil {
	panic(err)
}
_ = leak
```

Assembler helper:

```go
code, err := gpwntools.Asm("xor rax, rax\nret")
if err != nil {
	panic(err)
}
fmt.Printf("% x\n", code) // 48 31 c0 c3
```

```go
code, err := gpwntools.AsmArch("xor eax, eax\nret", "i386")
```

ELF helpers:

```go
e, err := gpwntools.ELF("./chall")
if err != nil {
	panic(err)
}
defer e.Close()

e.SetBase(0x7ffff7dc0000)
system, ok := e.Resolve("system")
_ = ok

win := e.Symbols["win"]
putsGOT := e.GOT["puts"]
putsPLT := e.PLT["puts"]
text := e.Sections[".text"]
binsh, err := e.Search([]byte("/bin/sh\x00"))

_, _, _, _, _, _ = system, win, putsGOT, putsPLT, text, binsh
```

Checksec:

```go
sec, err := gpwntools.Checksec("./chall")
if err != nil {
	panic(err)
}
fmt.Printf("PIE=%v NX=%v Canary=%v RELRO=%s\n", sec.PIE, sec.NX, sec.Canary, sec.RELRO)
```

Payload helpers:

```go
payload := gpwntools.MustFlat(
	bytes.Repeat([]byte("A"), 0x28),
	uint64(ret),
	uint64(win),
)

payload = gpwntools.MustFit(map[int]any{
	0x00: []byte("AAAA"),
	0x28: uint64(win),
}, 'A')

pattern := gpwntools.Cyclic(200)
offset := gpwntools.CyclicFind(pattern[40:44])

fmt.Print(gpwntools.Hexdump(payload))

_, _, _ = payload, offset, pattern
```

Logging:

```go
gpwntools.Info("puts leak: %#x", leak)
gpwntools.Success("libc base: %#x", base)
gpwntools.Warn("retrying")
gpwntools.Error("failed: %v", err)

gpwntools.SetLogLevel(gpwntools.LogLevelDebug)
gpwntools.Debug("payload size: %d", len(payload))
```

Tubes:

```go
r, err := gpwntools.Remote("127.0.0.1", 31337)
if err != nil {
	panic(err)
}
defer r.Close()
_ = r.Interactive()
```

```go
p, err := gpwntools.Process("./chall")
if err != nil {
	panic(err)
}
defer p.Close()

banner, err := p.RecvUntil([]byte("> "))
if err != nil {
	panic(err)
}
_ = banner

if err := p.Send([]byte("AAAA\n")); err != nil {
	panic(err)
}

if err := p.SendLine([]byte("BBBB")); err != nil {
	panic(err)
}

if _, err := p.SendLineAfter([]byte("> "), []byte("CCCC")); err != nil {
	panic(err)
}

line, err := p.RecvLine()
if err != nil {
	panic(err)
}
_ = line

data, err := p.Recv(64)
if err != nil {
	panic(err)
}
_ = data

p.SetTimeout(2 * time.Second)
line, err = p.RecvLine()
if err != nil {
	panic(err)
}

data, err = p.RecvUntilTimeout([]byte("done"), 500*time.Millisecond)
if err != nil {
	panic(err)
}

_ = p.Interactive()
```

`Interactive()` keeps terminal input in line mode, so single keystrokes such as
`c` or `ni` are not forwarded before Enter while debugging in a separate GDB
terminal. Use raw mode when you want each keystroke forwarded immediately:

```go
_ = p.InteractiveRaw()
```

```go
p, err := gpwntools.ProcessWithOptions([]string{"./chall"}, gpwntools.ProcessOptions{
	Cwd: "./target",
	Env: []string{"LD_PRELOAD=./libc.so.6"},
})
if err != nil {
	panic(err)
}
defer p.Close()
```

On Linux, `Process` uses a PTY for stdout/stderr by default, like pwntools, so
common C targets flush line-buffered prompts immediately. To force plain pipes:

```go
p, err := gpwntools.ProcessWithOptions([]string{"./chall"}, gpwntools.ProcessOptions{
	DisablePTY: true,
})
```

GDB helpers:

```go
gpwntools.Context.SetTerminal("tmux", "split-window", "-h")

p, err := gpwntools.Process("./chall")
if err != nil {
	panic(err)
}
defer p.Close()

g, err := p.GDB("break main\ncontinue")
if err != nil {
	panic(err)
}
defer g.Close()

_ = p.Interactive()
```

When the GDB session exits, `gpwntools` now closes the attached local process as
well, so a blocked `Interactive()` call can unwind cleanly. Pressing `Ctrl+C`
inside `Interactive()` also closes the tube and restores the terminal state.

To run GDB in the current terminal instead:

```go
g, err := p.GDBHere("break main\ncontinue")
if err != nil {
	panic(err)
}
defer g.Close()
```

```go
g, err := gpwntools.GDBDebugHere([]string{"./chall", "AAAA"}, "break main\nrun")
if err != nil {
	panic(err)
}
defer g.Close()
_ = g.Wait()
```

```go
g, err := gpwntools.GDBRemoteAddress("127.0.0.1:1234", "./chall", "continue")
if err != nil {
	panic(err)
}
defer g.Close()
```

## Demo Program

```bash
go run ./cmd/demo
```
