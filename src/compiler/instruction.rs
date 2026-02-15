//! eBPF instruction encoding
//!
//! eBPF instructions are 64-bit fixed-length, encoded as:
//! ```text
//! opcode:8 src_reg:4 dst_reg:4 offset:16 imm:32
//! ```
//!
//! Some instructions (like 64-bit immediate loads) use two 64-bit slots.

/// eBPF register identifiers (r0-r10)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EbpfReg {
    /// Return value from functions, exit value for eBPF program
    R0 = 0,
    /// First argument to BPF helpers, also context pointer
    R1 = 1,
    /// Second argument to BPF helpers
    R2 = 2,
    /// Third argument to BPF helpers
    R3 = 3,
    /// Fourth argument to BPF helpers
    R4 = 4,
    /// Fifth argument to BPF helpers
    R5 = 5,
    /// Callee-saved register
    R6 = 6,
    /// Callee-saved register
    R7 = 7,
    /// Callee-saved register
    R8 = 8,
    /// Callee-saved register
    R9 = 9,
    /// Frame pointer (read-only)
    R10 = 10,
}

impl EbpfReg {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// BPF helper function numbers
///
/// These are the kernel helper functions that eBPF programs can call.
/// See: https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum BpfHelper {
    /// void *bpf_map_lookup_elem(map, key)
    MapLookupElem = 1,
    /// int bpf_map_update_elem(map, key, value, flags)
    MapUpdateElem = 2,
    /// int bpf_map_delete_elem(map, key)
    MapDeleteElem = 3,
    /// int bpf_probe_read(dst, size, src)
    ProbeRead = 4,
    /// long bpf_probe_read_user(dst, size, unsafe_ptr)
    ProbeReadUser = 112,
    /// long bpf_probe_read_kernel(dst, size, unsafe_ptr)
    ProbeReadKernel = 113,
    /// u64 bpf_ktime_get_ns(void)
    KtimeGetNs = 5,
    /// int bpf_trace_printk(fmt, fmt_size, ...)
    TracePrintk = 6,
    /// u32 bpf_get_smp_processor_id(void)
    GetSmpProcessorId = 8,
    /// long bpf_tail_call(ctx, prog_array_map, index)
    TailCall = 12,
    /// u64 bpf_get_current_pid_tgid(void)
    GetCurrentPidTgid = 14,
    /// u64 bpf_get_current_uid_gid(void)
    GetCurrentUidGid = 15,
    /// int bpf_get_current_comm(buf, size)
    GetCurrentComm = 16,
    /// int bpf_perf_event_output(ctx, map, flags, data, size)
    PerfEventOutput = 25,
    /// long bpf_get_stackid(ctx, map, flags)
    GetStackId = 27,
    /// struct bpf_sock *bpf_sk_lookup_tcp(ctx, tuple, tuple_size, netns, flags)
    SkLookupTcp = 84,
    /// struct bpf_sock *bpf_sk_lookup_udp(ctx, tuple, tuple_size, netns, flags)
    SkLookupUdp = 85,
    /// void bpf_sk_release(sock)
    SkRelease = 86,
    /// long bpf_map_push_elem(map, value, flags)
    MapPushElem = 87,
    /// long bpf_map_pop_elem(map, value)
    MapPopElem = 88,
    /// long bpf_map_peek_elem(map, value)
    MapPeekElem = 89,
    /// struct bpf_sock *bpf_sk_fullsock(sk)
    SkFullsock = 95,
    /// struct bpf_tcp_sock *bpf_tcp_sock(sk)
    TcpSock = 96,
    /// struct bpf_sock *bpf_get_listener_sock(sk)
    GetListenerSock = 98,
    /// struct bpf_sock *bpf_skc_lookup_tcp(ctx, tuple, tuple_size, netns, flags)
    SkcLookupTcp = 99,
    /// long bpf_tcp_check_syncookie(sk, iph, iph_len, th, th_len)
    TcpCheckSyncookie = 100,
    /// void *bpf_sk_storage_get(map, sk, value, flags)
    SkStorageGet = 107,
    /// long bpf_sk_storage_delete(map, sk)
    SkStorageDelete = 108,
    /// s64 bpf_tcp_gen_syncookie(sk, iph, iph_len, th, th_len)
    TcpGenSyncookie = 110,
    /// long bpf_sk_assign(ctx, sk, flags)
    SkAssign = 124,
    /// void *bpf_task_storage_get(map, task, value, flags)
    TaskStorageGet = 156,
    /// long bpf_task_storage_delete(map, task)
    TaskStorageDelete = 157,
    /// struct tcp6_sock *bpf_skc_to_tcp6_sock(sk)
    SkcToTcp6Sock = 136,
    /// struct tcp_sock *bpf_skc_to_tcp_sock(sk)
    SkcToTcpSock = 137,
    /// struct tcp_timewait_sock *bpf_skc_to_tcp_timewait_sock(sk)
    SkcToTcpTimewaitSock = 138,
    /// struct tcp_request_sock *bpf_skc_to_tcp_request_sock(sk)
    SkcToTcpRequestSock = 139,
    /// struct udp6_sock *bpf_skc_to_udp6_sock(sk)
    SkcToUdp6Sock = 140,
    /// struct unix_sock *bpf_skc_to_unix_sock(sk)
    SkcToUnixSock = 178,
    /// void *bpf_inode_storage_get(map, inode, value, flags)
    InodeStorageGet = 145,
    /// long bpf_inode_storage_delete(map, inode)
    InodeStorageDelete = 146,
    /// struct socket *bpf_sock_from_file(file)
    SockFromFile = 162,
    /// struct pt_regs *bpf_task_pt_regs(task)
    TaskPtRegs = 175,
    /// long bpf_ringbuf_output(map, data, size, flags)
    RingbufOutput = 130,
    /// void *bpf_ringbuf_reserve(map, size, flags)
    RingbufReserve = 131,
    /// void bpf_ringbuf_submit(data, flags)
    RingbufSubmit = 132,
    /// void bpf_ringbuf_discard(data, flags)
    RingbufDiscard = 133,
    /// u64 bpf_ringbuf_query(map, flags)
    RingbufQuery = 134,
    /// void *bpf_kptr_xchg(dst, ptr)
    KptrXchg = 194,
    /// long bpf_probe_read_user_str(dst, size, unsafe_ptr)
    ProbeReadUserStr = 114,
    /// long bpf_probe_read_kernel_str(dst, size, unsafe_ptr)
    ProbeReadKernelStr = 115,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperArgKind {
    Scalar,
    Pointer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperRetKind {
    Scalar,
    PointerMaybeNull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfuncArgKind {
    Scalar,
    Pointer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfuncRetKind {
    Scalar,
    PointerMaybeNull,
    Void,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfuncRefKind {
    Task,
    Cgroup,
    Inode,
    Cpumask,
    CryptoCtx,
    Object,
    File,
    Socket,
}

impl KfuncRefKind {
    pub const fn label(self) -> &'static str {
        match self {
            KfuncRefKind::Task => "task",
            KfuncRefKind::Cgroup => "cgroup",
            KfuncRefKind::Inode => "inode",
            KfuncRefKind::Cpumask => "cpumask",
            KfuncRefKind::CryptoCtx => "crypto_ctx",
            KfuncRefKind::Object => "object",
            KfuncRefKind::File => "file",
            KfuncRefKind::Socket => "socket",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperAllowedPtrSpaces {
    pub allow_stack: bool,
    pub allow_map: bool,
    pub allow_kernel: bool,
    pub allow_user: bool,
}

impl HelperAllowedPtrSpaces {
    pub const fn new(
        allow_stack: bool,
        allow_map: bool,
        allow_kernel: bool,
        allow_user: bool,
    ) -> Self {
        Self {
            allow_stack,
            allow_map,
            allow_kernel,
            allow_user,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperPtrArgRule {
    pub arg_idx: usize,
    pub op: &'static str,
    pub allowed: HelperAllowedPtrSpaces,
    pub fixed_size: Option<usize>,
    pub size_from_arg: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
pub struct HelperSemantics {
    pub ptr_arg_rules: &'static [HelperPtrArgRule],
    pub positive_size_args: &'static [usize],
    pub ringbuf_record_arg0: bool,
}

impl HelperSemantics {
    pub const EMPTY: Self = Self {
        ptr_arg_rules: &[],
        positive_size_args: &[],
        ringbuf_record_arg0: false,
    };
}

#[derive(Debug, Clone, Copy)]
pub struct HelperSignature {
    pub min_args: usize,
    pub max_args: usize,
    pub arg_kinds: [HelperArgKind; 5],
    pub ret_kind: HelperRetKind,
}

impl HelperSignature {
    pub const fn for_id(helper_id: u32) -> Option<Self> {
        match BpfHelper::from_u32(helper_id) {
            Some(helper) => Some(helper.signature()),
            None => None,
        }
    }

    pub const fn arg_kind(&self, idx: usize) -> HelperArgKind {
        self.arg_kinds[idx]
    }
}

#[derive(Debug, Clone, Copy)]
pub struct KfuncSignature {
    pub min_args: usize,
    pub max_args: usize,
    pub arg_kinds: [KfuncArgKind; 5],
    pub ret_kind: KfuncRetKind,
}

#[path = "instruction/kfunc_signature.rs"]
mod kfunc_signature;

#[path = "instruction/ref_kinds.rs"]
mod ref_kinds;

pub use kfunc_signature::unknown_kfunc_signature_message;
pub use ref_kinds::{
    KfuncAllowedPtrSpaces, KfuncPtrArgRule, KfuncSemantics, helper_acquire_ref_kind,
    helper_pointer_arg_ref_kind, helper_release_ref_kind, kfunc_acquire_ref_kind,
    kfunc_pointer_arg_allows_const_zero, kfunc_pointer_arg_ref_kind,
    kfunc_pointer_arg_requires_kernel, kfunc_pointer_arg_requires_stack,
    kfunc_pointer_arg_requires_stack_slot_base, kfunc_release_ref_arg_index,
    kfunc_release_ref_kind, kfunc_scalar_arg_requires_known_const, kfunc_semantics,
};

#[path = "instruction/helper_metadata.rs"]
mod helper_metadata;

#[path = "instruction/encoding.rs"]
mod encoding;

/// eBPF instruction opcodes
pub mod opcode {
    // Instruction classes (3 bits)
    pub const BPF_LD: u8 = 0x00;
    pub const BPF_LDX: u8 = 0x01;
    pub const BPF_ST: u8 = 0x02;
    pub const BPF_STX: u8 = 0x03;
    pub const BPF_ALU: u8 = 0x04;
    pub const BPF_JMP: u8 = 0x05;
    pub const BPF_JMP32: u8 = 0x06;
    pub const BPF_ALU64: u8 = 0x07;

    // Size modifiers (2 bits)
    pub const BPF_W: u8 = 0x00; // 32-bit
    pub const BPF_H: u8 = 0x08; // 16-bit
    pub const BPF_B: u8 = 0x10; // 8-bit
    pub const BPF_DW: u8 = 0x18; // 64-bit

    // Source modifiers
    pub const BPF_K: u8 = 0x00; // Immediate
    pub const BPF_X: u8 = 0x08; // Register

    // ALU operations (4 bits, shifted left by 4)
    pub const BPF_ADD: u8 = 0x00;
    pub const BPF_SUB: u8 = 0x10;
    pub const BPF_MUL: u8 = 0x20;
    pub const BPF_DIV: u8 = 0x30;
    pub const BPF_OR: u8 = 0x40;
    pub const BPF_AND: u8 = 0x50;
    pub const BPF_LSH: u8 = 0x60;
    pub const BPF_RSH: u8 = 0x70;
    pub const BPF_NEG: u8 = 0x80;
    pub const BPF_MOD: u8 = 0x90;
    pub const BPF_XOR: u8 = 0xa0;
    pub const BPF_MOV: u8 = 0xb0;
    pub const BPF_ARSH: u8 = 0xc0; // Arithmetic right shift

    // Jump operations
    pub const BPF_JA: u8 = 0x00; // Jump always
    pub const BPF_JEQ: u8 = 0x10; // Jump if equal
    pub const BPF_JGT: u8 = 0x20; // Jump if greater than
    pub const BPF_JGE: u8 = 0x30; // Jump if greater or equal
    pub const BPF_JSET: u8 = 0x40; // Jump if set (bitwise AND)
    pub const BPF_JNE: u8 = 0x50; // Jump if not equal
    pub const BPF_JSGT: u8 = 0x60; // Jump if signed greater than
    pub const BPF_JSGE: u8 = 0x70; // Jump if signed greater or equal
    pub const BPF_CALL: u8 = 0x80; // Function call
    pub const BPF_EXIT: u8 = 0x90; // Exit program
    pub const BPF_JLT: u8 = 0xa0; // Jump if less than
    pub const BPF_JLE: u8 = 0xb0; // Jump if less or equal
    pub const BPF_JSLT: u8 = 0xc0; // Jump if signed less than
    pub const BPF_JSLE: u8 = 0xd0; // Jump if signed less or equal

    // Memory modes
    pub const BPF_IMM: u8 = 0x00;
    pub const BPF_ABS: u8 = 0x20;
    pub const BPF_IND: u8 = 0x40;
    pub const BPF_MEM: u8 = 0x60;

    // Composite opcodes for common operations
    pub const MOV64_IMM: u8 = BPF_ALU64 | BPF_MOV | BPF_K; // 0xb7
    pub const MOV64_REG: u8 = BPF_ALU64 | BPF_MOV | BPF_X; // 0xbf
    pub const ADD64_IMM: u8 = BPF_ALU64 | BPF_ADD | BPF_K; // 0x07
    pub const ADD64_REG: u8 = BPF_ALU64 | BPF_ADD | BPF_X; // 0x0f
    pub const SUB64_IMM: u8 = BPF_ALU64 | BPF_SUB | BPF_K; // 0x17
    pub const SUB64_REG: u8 = BPF_ALU64 | BPF_SUB | BPF_X; // 0x1f
    pub const MUL64_IMM: u8 = BPF_ALU64 | BPF_MUL | BPF_K; // 0x27
    pub const MUL64_REG: u8 = BPF_ALU64 | BPF_MUL | BPF_X; // 0x2f
    pub const DIV64_IMM: u8 = BPF_ALU64 | BPF_DIV | BPF_K; // 0x37
    pub const DIV64_REG: u8 = BPF_ALU64 | BPF_DIV | BPF_X; // 0x3f
    pub const MOD64_IMM: u8 = BPF_ALU64 | BPF_MOD | BPF_K; // 0x97
    pub const MOD64_REG: u8 = BPF_ALU64 | BPF_MOD | BPF_X; // 0x9f
    pub const OR64_IMM: u8 = BPF_ALU64 | BPF_OR | BPF_K; // 0x47
    pub const OR64_REG: u8 = BPF_ALU64 | BPF_OR | BPF_X; // 0x4f
    pub const AND64_IMM: u8 = BPF_ALU64 | BPF_AND | BPF_K; // 0x57
    pub const AND64_REG: u8 = BPF_ALU64 | BPF_AND | BPF_X; // 0x5f
    pub const XOR64_IMM: u8 = BPF_ALU64 | BPF_XOR | BPF_K; // 0xa7
    pub const XOR64_REG: u8 = BPF_ALU64 | BPF_XOR | BPF_X; // 0xaf
    pub const LSH64_IMM: u8 = BPF_ALU64 | BPF_LSH | BPF_K; // 0x67
    pub const LSH64_REG: u8 = BPF_ALU64 | BPF_LSH | BPF_X; // 0x6f
    pub const RSH64_IMM: u8 = BPF_ALU64 | BPF_RSH | BPF_K; // 0x77
    pub const RSH64_REG: u8 = BPF_ALU64 | BPF_RSH | BPF_X; // 0x7f
    pub const CALL: u8 = BPF_JMP | BPF_CALL; // 0x85
    pub const EXIT: u8 = BPF_JMP | BPF_EXIT; // 0x95
    pub const LD_DW_IMM: u8 = BPF_LD | BPF_DW | BPF_IMM; // 0x18 (64-bit immediate load)
}

/// A single eBPF instruction (64-bit)
#[derive(Debug, Clone, Copy)]
pub struct EbpfInsn {
    /// Operation code
    pub opcode: u8,
    /// Destination register (4 bits, lower nibble)
    pub dst_reg: u8,
    /// Source register (4 bits, upper nibble)
    pub src_reg: u8,
    /// Signed offset for memory/branch operations
    pub offset: i16,
    /// Signed immediate value
    pub imm: i32,
}

/// Builder for constructing eBPF programs
#[derive(Debug, Default)]
pub struct EbpfBuilder {
    instructions: Vec<EbpfInsn>,
}

#[cfg(test)]
mod tests;
