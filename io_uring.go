package gpwntools

import (
	"encoding/binary"
)

const (
	IoUringSQESize    = 64
	IoUringCQESize    = 16
	IoUringParamsSize = 120

	// Matching Linux's mmap offsets for io_uring rings.
	IORING_OFF_SQ_RING   uint64 = 0
	IORING_OFF_CQ_RING   uint64 = 0x8000000
	IORING_OFF_SQES      uint64 = 0x10000000
	IORING_OFF_PBUF_RING uint64 = 0x80000000
)

const (
	IOSQE_FIXED_FILE        = 1 << 0
	IOSQE_IO_DRAIN          = 1 << 1
	IOSQE_IO_LINK           = 1 << 2
	IOSQE_IO_HARDLINK       = 1 << 3
	IOSQE_ASYNC             = 1 << 4
	IOSQE_BUFFER_SELECT     = 1 << 5
	IOSQE_CQE_SKIP_SUCCESS  = 1 << 6
	IORING_FILE_INDEX_ALLOC = ^uint32(0)
)

const (
	IORING_SETUP_IOPOLL             = 1 << 0
	IORING_SETUP_SQPOLL             = 1 << 1
	IORING_SETUP_SQ_AFF             = 1 << 2
	IORING_SETUP_CQSIZE             = 1 << 3
	IORING_SETUP_CLAMP              = 1 << 4
	IORING_SETUP_ATTACH_WQ          = 1 << 5
	IORING_SETUP_R_DISABLED         = 1 << 6
	IORING_SETUP_SUBMIT_ALL         = 1 << 7
	IORING_SETUP_COOP_TASKRUN       = 1 << 8
	IORING_SETUP_TASKRUN_FLAG       = 1 << 9
	IORING_SETUP_SQE128             = 1 << 10
	IORING_SETUP_CQE32              = 1 << 11
	IORING_SETUP_SINGLE_ISSUER      = 1 << 12
	IORING_SETUP_DEFER_TASKRUN      = 1 << 13
	IORING_SETUP_NO_MMAP            = 1 << 14
	IORING_SETUP_REGISTERED_FD_ONLY = 1 << 15
	IORING_SETUP_NO_SQARRAY         = 1 << 16
	IORING_SETUP_HYBRID_IOPOLL      = 1 << 17
	IORING_SETUP_CQE_MIXED          = 1 << 18
	IORING_SETUP_SQE_MIXED          = 1 << 19
)

const (
	IORING_OP_NOP = iota
	IORING_OP_READV
	IORING_OP_WRITEV
	IORING_OP_FSYNC
	IORING_OP_READ_FIXED
	IORING_OP_WRITE_FIXED
	IORING_OP_POLL_ADD
	IORING_OP_POLL_REMOVE
	IORING_OP_SYNC_FILE_RANGE
	IORING_OP_SENDMSG
	IORING_OP_RECVMSG
	IORING_OP_TIMEOUT
	IORING_OP_TIMEOUT_REMOVE
	IORING_OP_ACCEPT
	IORING_OP_ASYNC_CANCEL
	IORING_OP_LINK_TIMEOUT
	IORING_OP_CONNECT
	IORING_OP_FALLOCATE
	IORING_OP_OPENAT
	IORING_OP_CLOSE
	IORING_OP_FILES_UPDATE
	IORING_OP_STATX
	IORING_OP_READ
	IORING_OP_WRITE
	IORING_OP_FADVISE
	IORING_OP_MADVISE
	IORING_OP_SEND
	IORING_OP_RECV
	IORING_OP_OPENAT2
	IORING_OP_EPOLL_CTL
	IORING_OP_SPLICE
	IORING_OP_PROVIDE_BUFFERS
	IORING_OP_REMOVE_BUFFERS
	IORING_OP_TEE
	IORING_OP_SHUTDOWN
	IORING_OP_RENAMEAT
	IORING_OP_UNLINKAT
	IORING_OP_MKDIRAT
	IORING_OP_SYMLINKAT
	IORING_OP_LINKAT
	IORING_OP_MSG_RING
	IORING_OP_FSETXATTR
	IORING_OP_SETXATTR
	IORING_OP_FGETXATTR
	IORING_OP_GETXATTR
	IORING_OP_SOCKET
	IORING_OP_URING_CMD
	IORING_OP_SEND_ZC
	IORING_OP_SENDMSG_ZC
	IORING_OP_READ_MULTISHOT
	IORING_OP_WAITID
	IORING_OP_FUTEX_WAIT
	IORING_OP_FUTEX_WAKE
	IORING_OP_FUTEX_WAITV
	IORING_OP_FIXED_FD_INSTALL
	IORING_OP_FTRUNCATE
	IORING_OP_BIND
	IORING_OP_LISTEN
	IORING_OP_RECV_ZC
	IORING_OP_EPOLL_WAIT
	IORING_OP_READV_FIXED
	IORING_OP_WRITEV_FIXED
	IORING_OP_PIPE
	IORING_OP_NOP128
	IORING_OP_URING_CMD128
	IORING_OP_LAST
)

const (
	IORING_ENTER_GETEVENTS       = 1 << 0
	IORING_ENTER_SQ_WAKEUP       = 1 << 1
	IORING_ENTER_SQ_WAIT         = 1 << 2
	IORING_ENTER_EXT_ARG         = 1 << 3
	IORING_ENTER_REGISTERED_RING = 1 << 4
	IORING_ENTER_ABS_TIMER       = 1 << 5
	IORING_ENTER_EXT_ARG_REG     = 1 << 6
	IORING_ENTER_NO_IOWAIT       = 1 << 7
)

const (
	IORING_REGISTER_BUFFERS = iota
	IORING_UNREGISTER_BUFFERS
	IORING_REGISTER_FILES
	IORING_UNREGISTER_FILES
	IORING_REGISTER_EVENTFD
	IORING_UNREGISTER_EVENTFD
	IORING_REGISTER_FILES_UPDATE
	IORING_REGISTER_EVENTFD_ASYNC
	IORING_REGISTER_PROBE
	IORING_REGISTER_PERSONALITY
	IORING_UNREGISTER_PERSONALITY
	IORING_REGISTER_RESTRICTIONS
	IORING_REGISTER_ENABLE_RINGS
	IORING_REGISTER_FILES2
	IORING_REGISTER_FILES_UPDATE2
	IORING_REGISTER_BUFFERS2
	IORING_REGISTER_BUFFERS_UPDATE
	IORING_REGISTER_IOWQ_AFF
	IORING_UNREGISTER_IOWQ_AFF
	IORING_REGISTER_IOWQ_MAX_WORKERS
	IORING_REGISTER_RING_FDS
	IORING_UNREGISTER_RING_FDS
	IORING_REGISTER_PBUF_RING
	IORING_UNREGISTER_PBUF_RING
	IORING_REGISTER_SYNC_CANCEL
	IORING_REGISTER_FILE_ALLOC_RANGE
	IORING_REGISTER_PBUF_STATUS
	IORING_REGISTER_NAPI
	IORING_UNREGISTER_NAPI
	IORING_REGISTER_CLOCK
	IORING_REGISTER_CLONE_BUFFERS
	IORING_REGISTER_SEND_MSG_RING
	IORING_REGISTER_ZCRX_IFQ
	IORING_REGISTER_RESIZE_RINGS
	IORING_REGISTER_MEM_REGION
	IORING_REGISTER_QUERY
	IORING_REGISTER_ZCRX_CTRL
	IORING_REGISTER_LAST
)

const IORING_REGISTER_USE_REGISTERED_RING = 1 << 31

const (
	IORING_CQE_F_BUFFER        = 1 << 0
	IORING_CQE_F_MORE          = 1 << 1
	IORING_CQE_F_SOCK_NONEMPTY = 1 << 2
	IORING_CQE_F_NOTIF         = 1 << 3
	IORING_CQE_F_BUF_MORE      = 1 << 4
	IORING_CQE_F_SKIP          = 1 << 5
	IORING_CQE_F_32            = 1 << 15
)

const (
	IORING_FEAT_SINGLE_MMAP      = 1 << 0
	IORING_FEAT_NODROP           = 1 << 1
	IORING_FEAT_SUBMIT_STABLE    = 1 << 2
	IORING_FEAT_RW_CUR_POS       = 1 << 3
	IORING_FEAT_CUR_PERSONALITY  = 1 << 4
	IORING_FEAT_FAST_POLL        = 1 << 5
	IORING_FEAT_POLL_32BITS      = 1 << 6
	IORING_FEAT_SQPOLL_NONFIXED  = 1 << 7
	IORING_FEAT_EXT_ARG          = 1 << 8
	IORING_FEAT_NATIVE_WORKERS   = 1 << 9
	IORING_FEAT_RSRC_TAGS        = 1 << 10
	IORING_FEAT_CQE_SKIP         = 1 << 11
	IORING_FEAT_LINKED_FILE      = 1 << 12
	IORING_FEAT_REG_REG_RING     = 1 << 13
	IORING_FEAT_RECVSEND_BUNDLE  = 1 << 14
	IORING_FEAT_MIN_TIMEOUT      = 1 << 15
	IORING_FEAT_RW_ATTR          = 1 << 16
	IORING_FEAT_NO_IOWAIT        = 1 << 17
	IORING_CQE_BUFFER_SHIFT      = 16
	IORING_SQ_NEED_WAKEUP        = 1 << 0
	IORING_SQ_CQ_OVERFLOW        = 1 << 1
	IORING_SQ_TASKRUN            = 1 << 2
	IORING_CQ_EVENTFD_DISABLED   = 1 << 0
	IORING_FIXED_FD_NO_CLOEXEC   = 1 << 0
	IORING_URING_CMD_FIXED       = 1 << 0
	IORING_URING_CMD_MULTISHOT   = 1 << 1
	IORING_URING_CMD_MASK        = IORING_URING_CMD_FIXED | IORING_URING_CMD_MULTISHOT
	IORING_FSYNC_DATASYNC        = 1 << 0
	IORING_TIMEOUT_ABS           = 1 << 0
	IORING_TIMEOUT_UPDATE        = 1 << 1
	IORING_TIMEOUT_BOOTTIME      = 1 << 2
	IORING_TIMEOUT_REALTIME      = 1 << 3
	IORING_LINK_TIMEOUT_UPDATE   = 1 << 4
	IORING_TIMEOUT_ETIME_SUCCESS = 1 << 5
	IORING_TIMEOUT_MULTISHOT     = 1 << 6
	IORING_POLL_ADD_MULTI        = 1 << 0
	IORING_POLL_UPDATE_EVENTS    = 1 << 1
	IORING_POLL_UPDATE_USER_DATA = 1 << 2
	IORING_POLL_ADD_LEVEL        = 1 << 3
	IORING_ASYNC_CANCEL_ALL      = 1 << 0
	IORING_ASYNC_CANCEL_FD       = 1 << 1
	IORING_ASYNC_CANCEL_ANY      = 1 << 2
	IORING_ASYNC_CANCEL_FD_FIXED = 1 << 3
	IORING_ASYNC_CANCEL_USERDATA = 1 << 4
	IORING_ASYNC_CANCEL_OP       = 1 << 5
	IORING_RECVSEND_POLL_FIRST   = 1 << 0
	IORING_RECV_MULTISHOT        = 1 << 1
	IORING_RECVSEND_FIXED_BUF    = 1 << 2
	IORING_SEND_ZC_REPORT_USAGE  = 1 << 3
	IORING_RECVSEND_BUNDLE       = 1 << 4
	IORING_SEND_VECTORIZED       = 1 << 5
	IORING_ACCEPT_MULTISHOT      = 1 << 0
	IORING_ACCEPT_DONTWAIT       = 1 << 1
	IORING_ACCEPT_POLL_FIRST     = 1 << 2
	IORING_MSG_DATA              = 0
	IORING_MSG_SEND_FD           = 1
	IORING_MSG_RING_CQE_SKIP     = 1 << 0
	IORING_MSG_RING_FLAGS_PASS   = 1 << 1
)

// IoUringSQE mirrors Linux struct io_uring_sqe. Bytes serializes to 64 bytes.
type IoUringSQE struct {
	Opcode      uint8
	Flags       uint8
	Ioprio      uint16
	FD          int32
	Off         uint64
	Addr        uint64
	Len         uint32
	OpFlags     uint32
	UserData    uint64
	BufIndex    uint16
	Personality uint16
	FileIndex   uint32
	Addr3       uint64
	Pad2        uint64
}

// IOUringSQE is an alias for IoUringSQE.
type IOUringSQE = IoUringSQE

// Bytes serializes the SQE using Context.Endian.
func (s IoUringSQE) Bytes() []byte {
	return s.BytesEndian(contextEndian())
}

// BytesEndian serializes the SQE using little or big endian.
func (s IoUringSQE) BytesEndian(endian string) []byte {
	out := make([]byte, IoUringSQESize)
	out[0] = s.Opcode
	out[1] = s.Flags
	ioUringPutU16(out[2:4], s.Ioprio, endian)
	ioUringPutU32(out[4:8], uint32(s.FD), endian)
	ioUringPutU64(out[8:16], s.Off, endian)
	ioUringPutU64(out[16:24], s.Addr, endian)
	ioUringPutU32(out[24:28], s.Len, endian)
	ioUringPutU32(out[28:32], s.OpFlags, endian)
	ioUringPutU64(out[32:40], s.UserData, endian)
	ioUringPutU16(out[40:42], s.BufIndex, endian)
	ioUringPutU16(out[42:44], s.Personality, endian)
	ioUringPutU32(out[44:48], s.FileIndex, endian)
	ioUringPutU64(out[48:56], s.Addr3, endian)
	ioUringPutU64(out[56:64], s.Pad2, endian)
	return out
}

// IoUringSQOffsets mirrors Linux struct io_sqring_offsets.
type IoUringSQOffsets struct {
	Head        uint32
	Tail        uint32
	RingMask    uint32
	RingEntries uint32
	Flags       uint32
	Dropped     uint32
	Array       uint32
	Resv1       uint32
	UserAddr    uint64
}

// IOUringSQOffsets is an alias for IoUringSQOffsets.
type IOUringSQOffsets = IoUringSQOffsets

// IoUringCQOffsets mirrors Linux struct io_cqring_offsets.
type IoUringCQOffsets struct {
	Head        uint32
	Tail        uint32
	RingMask    uint32
	RingEntries uint32
	Overflow    uint32
	CQEs        uint32
	Flags       uint32
	Resv1       uint32
	UserAddr    uint64
}

// IOUringCQOffsets is an alias for IoUringCQOffsets.
type IOUringCQOffsets = IoUringCQOffsets

// IoUringParams mirrors Linux struct io_uring_params. Bytes serializes to 120 bytes.
type IoUringParams struct {
	SQEntries    uint32
	CQEntries    uint32
	Flags        uint32
	SQThreadCPU  uint32
	SQThreadIdle uint32
	Features     uint32
	WqFD         uint32
	Resv         [3]uint32
	SQOff        IoUringSQOffsets
	CQOff        IoUringCQOffsets
}

// IOUringParams is an alias for IoUringParams.
type IOUringParams = IoUringParams

// Bytes serializes the params using Context.Endian.
func (p IoUringParams) Bytes() []byte {
	return p.BytesEndian(contextEndian())
}

// BytesEndian serializes the params using little or big endian.
func (p IoUringParams) BytesEndian(endian string) []byte {
	out := make([]byte, IoUringParamsSize)
	ioUringPutU32(out[0:4], p.SQEntries, endian)
	ioUringPutU32(out[4:8], p.CQEntries, endian)
	ioUringPutU32(out[8:12], p.Flags, endian)
	ioUringPutU32(out[12:16], p.SQThreadCPU, endian)
	ioUringPutU32(out[16:20], p.SQThreadIdle, endian)
	ioUringPutU32(out[20:24], p.Features, endian)
	ioUringPutU32(out[24:28], p.WqFD, endian)
	ioUringPutU32(out[28:32], p.Resv[0], endian)
	ioUringPutU32(out[32:36], p.Resv[1], endian)
	ioUringPutU32(out[36:40], p.Resv[2], endian)
	p.SQOff.put(out[40:80], endian)
	p.CQOff.put(out[80:120], endian)
	return out
}

func (o IoUringSQOffsets) put(out []byte, endian string) {
	ioUringPutU32(out[0:4], o.Head, endian)
	ioUringPutU32(out[4:8], o.Tail, endian)
	ioUringPutU32(out[8:12], o.RingMask, endian)
	ioUringPutU32(out[12:16], o.RingEntries, endian)
	ioUringPutU32(out[16:20], o.Flags, endian)
	ioUringPutU32(out[20:24], o.Dropped, endian)
	ioUringPutU32(out[24:28], o.Array, endian)
	ioUringPutU32(out[28:32], o.Resv1, endian)
	ioUringPutU64(out[32:40], o.UserAddr, endian)
}

func (o IoUringCQOffsets) put(out []byte, endian string) {
	ioUringPutU32(out[0:4], o.Head, endian)
	ioUringPutU32(out[4:8], o.Tail, endian)
	ioUringPutU32(out[8:12], o.RingMask, endian)
	ioUringPutU32(out[12:16], o.RingEntries, endian)
	ioUringPutU32(out[16:20], o.Overflow, endian)
	ioUringPutU32(out[20:24], o.CQEs, endian)
	ioUringPutU32(out[24:28], o.Flags, endian)
	ioUringPutU32(out[28:32], o.Resv1, endian)
	ioUringPutU64(out[32:40], o.UserAddr, endian)
}

// IoUringCQE mirrors Linux struct io_uring_cqe. Bytes serializes to 16 bytes.
type IoUringCQE struct {
	UserData uint64
	Res      int32
	Flags    uint32
}

// IOUringCQE is an alias for IoUringCQE.
type IOUringCQE = IoUringCQE

// Bytes serializes the CQE using Context.Endian.
func (c IoUringCQE) Bytes() []byte {
	return c.BytesEndian(contextEndian())
}

// BytesEndian serializes the CQE using little or big endian.
func (c IoUringCQE) BytesEndian(endian string) []byte {
	out := make([]byte, IoUringCQESize)
	ioUringPutU64(out[0:8], c.UserData, endian)
	ioUringPutU32(out[8:12], uint32(c.Res), endian)
	ioUringPutU32(out[12:16], c.Flags, endian)
	return out
}

func ioUringPutU16(out []byte, value uint16, endian string) {
	if normalizeEndian(endian) == "big" {
		binary.BigEndian.PutUint16(out, value)
		return
	}
	binary.LittleEndian.PutUint16(out, value)
}

func ioUringPutU32(out []byte, value uint32, endian string) {
	if normalizeEndian(endian) == "big" {
		binary.BigEndian.PutUint32(out, value)
		return
	}
	binary.LittleEndian.PutUint32(out, value)
}

func ioUringPutU64(out []byte, value uint64, endian string) {
	if normalizeEndian(endian) == "big" {
		binary.BigEndian.PutUint64(out, value)
		return
	}
	binary.LittleEndian.PutUint64(out, value)
}
