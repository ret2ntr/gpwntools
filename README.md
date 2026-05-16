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
gpwntools.Context.SetOS("linux")
gpwntools.Context.SetKernel("amd64") // useful for i386 SROP on a 64-bit kernel
gpwntools.Context.SetTerminal("tmux", "split-window", "-h")
// or use a built-in profile:
_ = gpwntools.Context.SetTerminalByName("wezterm")
gpwntools.Context.Timeout = 2 * time.Second
gpwntools.Context.KillOnTimeout = false
gpwntools.Context.Endian = "little"
gpwntools.Context.PTY = true // Linux default: local Process stdout/stderr use PTY
gpwntools.Context.InteractiveSystemEcho = true
gpwntools.Context.InteractiveLineEcho = false
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

ASCII hex helpers:

```go
value, err := gpwntools.ParseHexUint64([]byte("0x7fffdeadbeef"))
if err != nil {
	panic(err)
}
_ = value
```

```go
addr, raw, err := gpwntools.RecvHexUint64(p, []byte("\n"))
if err != nil {
	panic(err)
}
_, _ = addr, raw
```

Assembler helper:

```go
code, err := gpwntools.Asm("xor rax, rax\nret")
if err != nil {
	panic(err)
}
fmt.Printf("% x\n", code) // 48 31 c0 c3
```

`Asm` defaults to `gpwntools.Context.Arch`, `Context.OS`, and `Context.Syntax`.
`ELF(path)` updates `Context.Arch` and `Context.OS` from the target ELF, so
assembling small gadgets after loading the binary uses the target defaults:

```go
e, err := gpwntools.ELF("./chall")
if err != nil {
	panic(err)
}
defer e.Close()

ret := gpwntools.MustAsm("ret")
_ = ret
```

Simple x86 snippets such as `ret`, `pop rdi; ret`, `syscall`, and
`mov eax, SYS_select` are encoded by gpwntools directly, so they also work
when a Windows build is running under Wine without Linux `as`/`clang` in that
runtime. Longer or unsupported assembly still needs an assembler available to
the process.

Override only the fields you need:

```go
code, err := gpwntools.AsmWithOptions("mov eax, SYS_select\nret", gpwntools.AsmOptions{
	Arch: "i386",
	OS:   "freebsd",
})
```

Shellcraft helpers:

```go
code := gpwntools.Shellcraft.Sh()
payload, err := gpwntools.Shellcraft.Asm(code)
if err != nil {
	panic(err)
}
_ = payload
```

`Shellcraft` returns assembly strings, like pwntools' `shellcraft`. It uses
`Context.Arch` and `Context.OS` by default, and currently supports Linux
`amd64`, `i386`, `arm`, `aarch64`, `mips`, `mipsel`, `mips64`, and `mips64el`
for common pwn snippets:

`gpwntools.MustAsm(code)` assembles with the global `Context`. `Shellcraft.Asm`
and `Shellcraft.MustAsm` assemble with that shellcraft builder's own `Arch/OS`,
which is useful after `WithArch` or `WithOS`:

```go
orw := gpwntools.Shellcraft.ORW("/flag", 0x100)
payload = gpwntools.Shellcraft.MustAsm(orw)

sc32 := gpwntools.Shellcraft.WithArch("i386").WithOS("linux")
payload = sc32.MustAsm(sc32.Sh())

// This would use gpwntools.Context instead of sc32's i386/linux defaults.
payload = gpwntools.MustAsm(sc32.Sh())

openReadWrite := "" +
	gpwntools.Shellcraft.PushString("/flag") +
	gpwntools.Shellcraft.Open("rsp") +
	gpwntools.Shellcraft.Read("rax", "rsp", 0x80) +
	gpwntools.Shellcraft.Write(1, "rsp", "rax")

_, _, _ = payload, sc32, openReadWrite
```

Available helpers include `PushString`, `Syscall`, `Sh`, `Execve`, `Open`,
`OpenAt`, `Read`, `Write`, `Sendfile`, `Close`, `Dup2`, `Mmap`, `Mprotect`,
`Munmap`, `IoUringSetup`, `IoUringEnter`, `IoUringRegister`, `IoUringORW`,
`Exit`, `ORW`, and `Cat`.

Architecture-specific syscall ABIs are handled for you. For example, `Open`
uses `openat(AT_FDCWD, ...)` on `aarch64`, since Linux aarch64 does not expose
the old `open` syscall.

`Syscall` can use any Linux syscall name present in pwntools' constants for the
supported architecture:

```go
code = gpwntools.Shellcraft.Syscall("mmap", 0, 0x1000, 7, 0x22, -1, 0)
code = gpwntools.Shellcraft.Syscall("bpf", 0, 0, 0)
code = gpwntools.Shellcraft.Sendfile(1, 3, 0, 0x100)
code = gpwntools.Shellcraft.IoUringSetup(8, "rsp")
code = gpwntools.Shellcraft.IoUringEnter("rax", 1, 1, gpwntools.IORING_ENTER_GETEVENTS, 0, 8)
code = gpwntools.Shellcraft.IoUringORW("/flag", 0x100) // returns after write; it does not call exit
code = gpwntools.Shellcraft.WithArch("mipsel").IoUringORW("/flag", 0x100)

// Mmap picks mmap2 for 32-bit Linux ABIs where that is the shellcode-friendly
// syscall, and mmap for 64-bit ABIs.
code = gpwntools.Shellcraft.Mmap(0, 0x1000, 7, 0x22, -1, 0)
_ = code
```

`IoUringORW` currently supports Linux `amd64`, `i386`, `arm`, `aarch64`,
`mips`, `mipsel`, `mips64`, and `mips64el`.

`io_uring` helpers include Linux UAPI constants and struct packers for payloads:

```go
params := gpwntools.IoUringParams{
	Flags: gpwntools.IORING_SETUP_CQSIZE,
}

sqe := gpwntools.IoUringSQE{
	Opcode:   gpwntools.IORING_OP_WRITE,
	FD:       1,
	Addr:     0xdead0000,
	Len:      0x40,
	UserData: 0x1337,
}

payload := gpwntools.MustFlat(params, sqe)
_ = payload
```

`IoUringSQE.Bytes()` is 64 bytes, `IoUringParams.Bytes()` is 120 bytes, and
`IoUringCQE.Bytes()` is 16 bytes. The `IOUring*` type and method names are
also available as aliases if you prefer the all-caps acronym spelling.

Alphanumeric shellcode:

```go
sc := gpwntools.Shellcraft.MustAsm(gpwntools.Shellcraft.Sh())
encoded, err := gpwntools.Alphanumeric.Encode(sc)
if err != nil {
	panic(err)
}
if !gpwntools.IsAlphanumeric(encoded) {
	panic("encoder returned non-alphanumeric bytes")
}

// Equivalent to ae64's encode(shellcode, "r13", 0x30, "fast").
encoded, err = gpwntools.Alphanumeric.Encode(
	sc,
	gpwntools.WithAlphanumericRegister("r13"),
	gpwntools.WithAlphanumericOffset(0x30),
)
_, _ = encoded, err
```

The alphanumeric encoder currently targets amd64 and implements ae64's `fast`
strategy without requiring keystone or z3. The decoded shellcode is written back
in place, so the target page must be writable.

SROP helpers:

```go
frame, err := gpwntools.SigreturnFrame(
	gpwntools.WithSigreturnFrameArch("amd64"),
)
if err != nil {
	panic(err)
}
syscallRet := uint64(0x401000)
sigreturnGadget := uint64(0x401010)

if err := frame.SetSyscallName("mprotect"); err != nil {
	panic(err)
}
_ = frame.SetArguments(0x601000, 0x1000, 7)
_ = frame.SetSP(0x602000)
_ = frame.SetPC(syscallRet)

payload := gpwntools.MustFlat(
	bytes.Repeat([]byte("A"), 0x28),
	sigreturnGadget,
	frame,
)

_, _ = payload, frame.Bytes()
```

`SigreturnFrame` uses `Context.Arch` and `Context.Endian` by default. Its
Linux layouts match pwntools for `amd64`, `i386`, `arm`, `aarch64`, `mips`,
and `mipsel`. For i386 frames, `Kernel` controls the default segment selectors:
empty/`i386` uses `cs=0x73, ss=0x7b`, while `amd64` uses `cs=0x23, ss=0x2b`.

```go
frame32, err := gpwntools.SigreturnFrameWithOptions(gpwntools.SigreturnFrameOptions{
	Arch:   "i386",
	Kernel: "amd64",
})
if err != nil {
	panic(err)
}
_ = frame32.Set("eax", 125)
_ = frame32.Set("ebx", 0x601000)
_ = frame32.Set("ecx", 0x1000)
_ = frame32.Set("edx", 7)

mipsel, err := gpwntools.SigreturnFrameWithOptions(gpwntools.SigreturnFrameOptions{
	Arch: "mipsel",
})
if err != nil {
	panic(err)
}
_ = mipsel.Set("$v0", 4004)
_ = mipsel.SetArguments(1, 0xdead0000, 0x40)

_, _ = frame32, mipsel
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
ret, err := e.SearchExecutableOne(gpwntools.MustAsm("ret"))
textRets, err := e.SearchSection(".text", gpwntools.MustAsm("ret"))

_, _, _, _, _, _, _, _ = system, win, putsGOT, putsPLT, text, binsh, ret, textRets
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

payload = gpwntools.Ljust(payload, 0x40, 'A')
payload = append(payload, gpwntools.Gp64(win)...)

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

Pass `drop=true` to omit the matched delimiter from `RecvUntil` results:

```go
field, err := p.RecvUntil([]byte(":"), true)
if err != nil {
	panic(err)
}
_ = field
```

`Interactive()` keeps terminal input in line mode, so single keystrokes such as
`c` or `ni` are not forwarded before Enter while debugging in a separate GDB
terminal. It also normalizes Windows/Wine `\r\n` input to `\n`, which keeps
Unix shells from receiving commands such as `ls\r`.

By default `Interactive()` uses the terminal driver's system echo. To let
gpwntools draw typed line input instead:

```go
gpwntools.Context.InteractiveSystemEcho = false
gpwntools.Context.InteractiveLineEcho = true
```

Use raw mode when you want each keystroke forwarded immediately:

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

`Process` timeout is a per-call recv timeout. It does not kill the child by
default. If you want timeout to terminate the process as well, enable:

```go
gpwntools.Context.Timeout = 2 * time.Second
gpwntools.Context.KillOnTimeout = true
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

Terminal selection:

If `Context.Terminal` is empty, GDB helpers auto-detect a terminal. To switch
to a built-in terminal profile:

```go
if err := gpwntools.Context.SetTerminalByName("wezterm"); err != nil {
	panic(err)
}

if err := gpwntools.Context.SetTerminalByName("ptyxis"); err != nil {
	panic(err)
}
```

Built-in terminal names include `pwntools-terminal`, `tmux`, `zellij`,
`screen`, `ptyxis`, `kgx`, `gnome-terminal`, `konsole`, `kconsole`, `wezterm`,
`kitty`, `terminator`, `ghostty`, `alacritty`, `tilix`,
`x-terminal-emulator`, and `xterm`.

For custom launchers, use `SetTerminal`. Like pwntools, this is a command
prefix; gpwntools appends the shell-escaped GDB command as the final argument:

```go
gpwntools.Context.SetTerminal("tmux", "split-window", "-h")
gpwntools.Context.SetTerminal("wezterm", "start", "--", "sh", "-lc")
gpwntools.Context.SetTerminal("my-terminal", "--exec", "sh", "-lc")
```

To start a new process under gdbserver while keeping target IO as a tube,
similar to pwntools `gdb.debug(...).interactive()`:

```go
p, g, err := gpwntools.GDBDebug([]string{"./chall"}, "break main\ncontinue")
if err != nil {
	panic(err)
}
defer g.Close()
defer p.Close()

_ = p.Interactive()
```

`GDBDebug` returns both the target tube and the GDB session. Target output stays
in the tube; GDB status lines such as `Remote debugging from host ...` are
filtered out. On Linux, the target PTY is kept in pwntools-style raw mode, so
prompts stay as `\n` instead of `\r\n`.

When the GDB session exits, `gpwntools` now closes the attached local process as
well, so a blocked `Interactive()` call can unwind cleanly. Pressing `Ctrl+C`
inside `Interactive()` also closes the tube and restores the terminal state.

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
