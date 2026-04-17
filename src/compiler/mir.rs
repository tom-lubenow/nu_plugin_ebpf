//! Mid-Level Intermediate Representation (MIR) for eBPF compilation
//!
//! MIR sits between Nushell IR and eBPF bytecode, providing:
//! - Virtual registers (unlimited, unlike eBPF's 10)
//! - Explicit basic blocks with terminators
//! - Type information for verification
//! - A target for optimization passes

use std::collections::HashMap;
use std::fmt;

mod function_impl;
mod inst_impl;

/// Virtual register ID - unlimited, will be allocated to physical registers later
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VReg(pub u32);

impl fmt::Display for VReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// Basic block identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockId(pub u32);

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bb{}", self.0)
    }
}

/// Stack slot identifier for explicit stack allocation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StackSlotId(pub u32);

/// Subfunction identifier for BPF-to-BPF calls
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubfunctionId(pub u32);

impl fmt::Display for SubfunctionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "subfn{}", self.0)
    }
}

/// Map reference for BPF map operations
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MapRef {
    pub name: String,
    pub kind: MapKind,
}

/// Types of BPF maps
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MapKind {
    Hash,
    Array,
    LpmTrie,
    LruHash,
    PerCpuHash,
    PerCpuArray,
    LruPerCpuHash,
    PerfEventArray,
    Queue,
    Stack,
    RingBuf,
    StackTrace,
    DevMap,
    DevMapHash,
    CpuMap,
    XskMap,
    SockMap,
    SockHash,
    ProgArray,
}

pub const RINGBUF_MAP_NAME: &str = "events";
pub const COUNTER_MAP_NAME: &str = "counters";
pub const STRING_COUNTER_MAP_NAME: &str = "str_counters";
pub const BYTES_COUNTER_MAP_NAME: &str = "bytes_counters";
pub const HISTOGRAM_MAP_NAME: &str = "histogram";
pub const TIMESTAMP_MAP_NAME: &str = "timestamps";
pub const KSTACK_MAP_NAME: &str = "kstacks";
pub const USTACK_MAP_NAME: &str = "ustacks";

/// Bitfield extraction metadata for a logical struct field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BitfieldInfo {
    pub bit_offset: u32,
    pub bit_size: u32,
}

/// Type of value being appended in StringAppend
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringAppendType {
    /// Append a literal string (bytes embedded in MIR)
    Literal { bytes: Vec<u8> },
    /// Append from a string slot on the stack
    StringSlot { slot: StackSlotId, max_len: usize },
    /// Append an integer converted to decimal
    Integer,
}

/// MIR type system - internal, inferred from context
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MirType {
    // Primitives
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    Bool,

    // Pointers with address space (for verifier)
    Ptr {
        pointee: Box<MirType>,
        address_space: AddressSpace,
    },

    // Fixed-size array
    Array {
        elem: Box<MirType>,
        len: usize,
    },

    // Struct with named fields
    Struct {
        name: Option<String>,
        kernel_btf_type_id: Option<u32>,
        fields: Vec<StructField>,
    },

    // BPF-specific
    MapRef {
        key_ty: Box<MirType>,
        val_ty: Box<MirType>,
    },

    // Unknown type (before inference)
    Unknown,
}

impl MirType {
    /// Size in bytes
    pub fn size(&self) -> usize {
        match self {
            MirType::I8 | MirType::U8 | MirType::Bool => 1,
            MirType::I16 | MirType::U16 => 2,
            MirType::I32 | MirType::U32 => 4,
            MirType::I64 | MirType::U64 => 8,
            MirType::Ptr { .. } => 8,
            MirType::Array { elem, len } => elem.size() * len,
            MirType::Struct { fields, .. } => fields
                .iter()
                .filter_map(|field| field.offset.checked_add(field.ty.size()))
                .max()
                .unwrap_or(0),
            MirType::MapRef { .. } => 8, // Map FD
            MirType::Unknown => 8,       // Default to 64-bit
        }
    }

    /// Length for a fixed-size byte array (`[i8; N]` or `[u8; N]`).
    pub fn byte_array_len(&self) -> Option<usize> {
        match self {
            MirType::Array { elem, len } if matches!(elem.as_ref(), MirType::I8 | MirType::U8) => {
                Some(*len)
            }
            _ => None,
        }
    }

    pub fn is_raw_kernel_u8_ptr(&self) -> bool {
        matches!(
            self,
            MirType::Ptr {
                address_space: AddressSpace::Kernel,
                pointee,
            } if matches!(pointee.as_ref(), MirType::U8)
        )
    }

    pub fn opaque_named_struct(name: &str) -> Self {
        MirType::Struct {
            name: Some(name.to_string()),
            kernel_btf_type_id: None,
            fields: vec![StructField {
                name: "__opaque".to_string(),
                ty: MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: 1,
                },
                offset: 0,
                synthetic: false,
                bitfield: None,
            }],
        }
    }

    pub fn named_kernel_struct_ptr(name: &str) -> Self {
        MirType::Ptr {
            pointee: Box::new(Self::opaque_named_struct(name)),
            address_space: AddressSpace::Kernel,
        }
    }

    pub fn is_task_struct_ptr(&self) -> bool {
        self.is_named_kernel_struct_ptr(&["task_struct"])
    }

    pub fn is_file_ptr(&self) -> bool {
        self.is_named_kernel_struct_ptr(&["file"])
    }

    pub fn is_inode_ptr(&self) -> bool {
        self.is_named_kernel_struct_ptr(&["inode"])
    }

    pub fn is_socket_ptr(&self) -> bool {
        matches!(
            self,
            MirType::Ptr {
                address_space: AddressSpace::Kernel,
                pointee,
            } if pointee.is_socket_cookie_socket_pointee()
        )
    }

    pub fn is_socket_cookie_socket_ptr(&self) -> bool {
        self.is_socket_ptr()
    }

    fn is_named_kernel_struct_ptr(&self, candidates: &[&str]) -> bool {
        let MirType::Ptr {
            address_space: AddressSpace::Kernel,
            pointee,
        } = self
        else {
            return false;
        };
        pointee.has_struct_name(candidates)
    }

    fn has_struct_name(&self, candidates: &[&str]) -> bool {
        let MirType::Struct {
            name: Some(name), ..
        } = self
        else {
            return false;
        };
        let lower = name.to_ascii_lowercase();
        candidates
            .iter()
            .any(|candidate| lower == candidate.to_ascii_lowercase())
    }

    fn is_socket_cookie_socket_pointee(&self) -> bool {
        let MirType::Struct {
            name: Some(name), ..
        } = self
        else {
            return false;
        };
        let lower = name.to_ascii_lowercase();
        lower == "sock"
            || lower == "sock_common"
            || lower == "bpf_sock"
            || lower.starts_with("sock_")
            || lower.ends_with("_sock")
            || lower.contains("_sock_")
    }

    /// Inclusive scalar value bounds when they fit in the analysis range model.
    pub fn scalar_value_range(&self) -> Option<(i64, i64)> {
        match self {
            MirType::Bool => Some((0, 1)),
            MirType::I8 => Some((i8::MIN as i64, i8::MAX as i64)),
            MirType::I16 => Some((i16::MIN as i64, i16::MAX as i64)),
            MirType::I32 => Some((i32::MIN as i64, i32::MAX as i64)),
            MirType::I64 => Some((i64::MIN, i64::MAX)),
            MirType::U8 => Some((0, u8::MAX as i64)),
            MirType::U16 => Some((0, u16::MAX as i64)),
            MirType::U32 => Some((0, u32::MAX as i64)),
            MirType::U64 => None,
            _ => None,
        }
    }

    /// Return the backing kernel BTF type id for struct layouts when known.
    pub fn kernel_btf_type_id(&self) -> Option<u32> {
        match self {
            MirType::Struct {
                kernel_btf_type_id, ..
            } => *kernel_btf_type_id,
            _ => None,
        }
    }

    /// Alignment in bytes
    pub fn align(&self) -> usize {
        match self {
            MirType::I8 | MirType::U8 | MirType::Bool => 1,
            MirType::I16 | MirType::U16 => 2,
            MirType::I32 | MirType::U32 => 4,
            MirType::I64 | MirType::U64 | MirType::Ptr { .. } => 8,
            MirType::Array { elem, .. } => elem.align(),
            MirType::Struct { fields, .. } => {
                fields.iter().map(|f| f.ty.align()).max().unwrap_or(1)
            }
            MirType::MapRef { .. } => 8,
            MirType::Unknown => 8,
        }
    }
}

/// Address space for pointer provenance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressSpace {
    /// Stack-relative (R10 + offset), always valid
    Stack,
    /// Kernel memory, requires bpf_probe_read_kernel
    Kernel,
    /// User memory, requires bpf_probe_read_user
    User,
    /// XDP packet data pointer, direct-accessible after a data_end bounds check
    Packet,
    /// Map value pointer (trusted after null check)
    Map,
}

/// Field in a struct type
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StructField {
    pub name: String,
    pub ty: MirType,
    pub offset: usize,
    pub synthetic: bool,
    pub bitfield: Option<BitfieldInfo>,
}

/// A field in a record being emitted
#[derive(Debug, Clone)]
pub struct RecordFieldDef {
    /// Field name
    pub name: String,
    /// Virtual register holding the value
    pub value: VReg,
    /// Type of the field
    pub ty: MirType,
}

/// Stack slot for explicit stack allocation
#[derive(Debug, Clone)]
pub struct StackSlot {
    pub id: StackSlotId,
    pub size: usize,
    pub align: usize,
    pub kind: StackSlotKind,
    /// Assigned offset from R10 (negative), filled in during layout
    pub offset: Option<i16>,
}

/// Purpose of a stack slot
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackSlotKind {
    /// Register spill
    Spill,
    /// Local variable
    Local,
    /// Outgoing call argument
    Argument,
    /// Event buffer for ring buffer output
    EventBuffer,
    /// String comparison buffer
    StringBuffer,
    /// Record field storage
    RecordField,
    /// List buffer storage (length + elements)
    ListBuffer,
}

/// Value that can be used as an operand
#[derive(Debug, Clone, PartialEq)]
pub enum MirValue {
    /// Virtual register
    VReg(VReg),
    /// Compile-time constant
    Const(i64),
    /// Stack slot reference
    StackSlot(StackSlotId),
}

impl fmt::Display for MirValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MirValue::VReg(v) => write!(f, "{}", v),
            MirValue::Const(c) => write!(f, "{}", c),
            MirValue::StackSlot(s) => write!(f, "slot{}", s.0),
        }
    }
}

impl MirValue {
    /// Visit virtual registers referenced by this value.
    pub fn visit_vregs_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut VReg),
    {
        if let MirValue::VReg(vreg) = self {
            f(vreg);
        }
    }

    /// Return a copy of this value with all referenced virtual registers rewritten.
    pub fn map_vregs<F>(&self, mut map: F) -> MirValue
    where
        F: FnMut(VReg) -> VReg,
    {
        let mut cloned = self.clone();
        cloned.visit_vregs_mut(|vreg| *vreg = map(*vreg));
        cloned
    }
}

/// Binary operation kinds
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOpKind {
    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Mod,

    // Bitwise
    And,
    Or,
    Xor,
    Shl,
    Shr,

    // Comparison (result is 0 or 1)
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl fmt::Display for BinOpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            BinOpKind::Add => "+",
            BinOpKind::Sub => "-",
            BinOpKind::Mul => "*",
            BinOpKind::Div => "/",
            BinOpKind::Mod => "%",
            BinOpKind::And => "&",
            BinOpKind::Or => "|",
            BinOpKind::Xor => "^",
            BinOpKind::Shl => "<<",
            BinOpKind::Shr => ">>",
            BinOpKind::Eq => "==",
            BinOpKind::Ne => "!=",
            BinOpKind::Lt => "<",
            BinOpKind::Le => "<=",
            BinOpKind::Gt => ">",
            BinOpKind::Ge => ">=",
        };
        write!(f, "{}", s)
    }
}

/// Unary operation kinds
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOpKind {
    /// Logical not (0 -> 1, non-zero -> 0)
    Not,
    /// Bitwise negation
    BitNot,
    /// Arithmetic negation
    Neg,
}

/// Context field access
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CtxField {
    /// Raw program context pointer
    Context,
    /// Process ID
    Pid,
    /// Thread ID
    Tid,
    /// User ID
    Uid,
    /// Group ID
    Gid,
    /// Process name (comm)
    Comm,
    /// CPU ID
    Cpu,
    /// Timestamp (nanoseconds)
    Timestamp,
    /// Current task cgroup ID
    CgroupId,
    /// perf_event sample period (`bpf_perf_event_data::sample_period`)
    PerfSamplePeriod,
    /// perf_event sampled address (`bpf_perf_event_data::addr`)
    PerfAddr,
    /// XDP packet length (`data_end - data`)
    PacketLen,
    /// skb packet type (`__sk_buff.pkt_type`)
    PktType,
    /// skb queue mapping (`__sk_buff.queue_mapping`)
    QueueMapping,
    /// skb protocol / ethertype (normalized to host byte order)
    EthProtocol,
    /// skb VLAN presence flag (`__sk_buff.vlan_present`)
    VlanPresent,
    /// skb VLAN TCI (`__sk_buff.vlan_tci`)
    VlanTci,
    /// skb VLAN protocol / ethertype (normalized to host byte order)
    VlanProto,
    /// skb cb[5]
    SkbCb,
    /// skb tc_classid (`__sk_buff.tc_classid`)
    TcClassid,
    /// skb napi_id (`__sk_buff.napi_id`)
    NapiId,
    /// skb wire_len (`__sk_buff.wire_len`)
    WireLen,
    /// skb gso_segs (`__sk_buff.gso_segs`)
    GsoSegs,
    /// skb gso_size (`__sk_buff.gso_size`)
    GsoSize,
    /// skb timestamp (`__sk_buff.tstamp`)
    Tstamp,
    /// skb timestamp type (`__sk_buff.tstamp_type`)
    TstampType,
    /// skb hwtstamp (`__sk_buff.hwtstamp`)
    Hwtstamp,
    /// XDP packet data pointer
    Data,
    /// XDP packet metadata pointer
    DataMeta,
    /// XDP packet data_end pointer
    DataEnd,
    /// XDP ingress interface index
    IngressIfindex,
    /// skb ifindex (`__sk_buff.ifindex`)
    Ifindex,
    /// XDP receive queue index
    RxQueueIndex,
    /// XDP egress interface index
    EgressIfindex,
    /// skb tc_index (`__sk_buff.tc_index`)
    TcIndex,
    /// skb hash (`__sk_buff.hash`)
    SkbHash,
    /// bpf_sock_addr::user_family
    UserFamily,
    /// bpf_sock_addr::user_ip4 (normalized to host byte order)
    UserIp4,
    /// bpf_sock_addr::user_ip6[4] (normalized to host-byte-order u32 words)
    UserIp6,
    /// bpf_sock_addr::user_port (normalized to host byte order)
    UserPort,
    /// bpf_sock_addr::family
    Family,
    /// bpf_sock_addr::type
    SockType,
    /// bpf_sock_addr::protocol
    Protocol,
    /// current bpf_sock pointer on sk_lookup/sk_msg
    Socket,
    /// bpf_sock::bound_dev_if
    BoundDevIf,
    /// bpf_sock::mark
    SockMark,
    /// bpf_sock::priority
    SockPriority,
    /// bpf_sock_addr::msg_src_ip4 (normalized to host byte order)
    MsgSrcIp4,
    /// bpf_sock_addr::msg_src_ip6[4] (normalized to host-byte-order u32 words)
    MsgSrcIp6,
    /// bpf_sk_lookup::remote_ip4 (normalized to host byte order)
    RemoteIp4,
    /// bpf_sk_lookup::remote_ip6[4] (normalized to host-byte-order u32 words)
    RemoteIp6,
    /// bpf_sk_lookup::remote_port (normalized to host byte order)
    RemotePort,
    /// bpf_sk_lookup::local_ip4 (normalized to host byte order)
    LocalIp4,
    /// bpf_sk_lookup::local_ip6[4] (normalized to host-byte-order u32 words)
    LocalIp6,
    /// bpf_sk_lookup::local_port (host byte order)
    LocalPort,
    /// bpf_sk_lookup::cookie
    LookupCookie,
    /// lirc mode2 raw sample word
    LircSample,
    /// lirc mode2 low 24-bit payload value
    LircValue,
    /// lirc mode2 high-byte event kind mask
    LircMode,
    /// Stable kernel socket cookie for supported socket-backed contexts
    SocketCookie,
    /// Owner UID of the socket associated with the current skb
    SocketUid,
    /// Stable kernel network-namespace cookie for supported socket-backed contexts
    NetnsCookie,
    /// bpf_cgroup_dev_ctx::access_type
    DeviceAccessType,
    /// bpf_cgroup_dev_ctx::major
    DeviceMajor,
    /// bpf_cgroup_dev_ctx::minor
    DeviceMinor,
    /// bpf_sock_ops::op
    SockOp,
    /// bpf_sock_ops::args[4]
    SockOpsArgs,
    /// bpf_sock_ops::is_fullsock
    IsFullsock,
    /// bpf_sock_ops::snd_cwnd
    SockOpsSndCwnd,
    /// bpf_sock_ops::srtt_us
    SockOpsSrttUs,
    /// bpf_sock_ops::bpf_sock_ops_cb_flags
    SockOpsCbFlags,
    /// bpf_sock_ops::state
    SockState,
    /// bpf_sock_ops::rtt_min
    SockOpsRttMin,
    /// bpf_sock_ops::snd_ssthresh
    SockOpsSndSsthresh,
    /// bpf_sock_ops::rcv_nxt
    SockOpsRcvNxt,
    /// bpf_sock_ops::snd_nxt
    SockOpsSndNxt,
    /// bpf_sock_ops::snd_una
    SockOpsSndUna,
    /// bpf_sock_ops::mss_cache
    SockOpsMssCache,
    /// bpf_sock_ops::ecn_flags
    SockOpsEcnFlags,
    /// bpf_sock_ops::rate_delivered
    SockOpsRateDelivered,
    /// bpf_sock_ops::rate_interval_us
    SockOpsRateIntervalUs,
    /// bpf_sock_ops::packets_out
    SockOpsPacketsOut,
    /// bpf_sock_ops::retrans_out
    SockOpsRetransOut,
    /// bpf_sock_ops::total_retrans
    SockOpsTotalRetrans,
    /// bpf_sock_ops::segs_in
    SockOpsSegsIn,
    /// bpf_sock_ops::data_segs_in
    SockOpsDataSegsIn,
    /// bpf_sock_ops::segs_out
    SockOpsSegsOut,
    /// bpf_sock_ops::data_segs_out
    SockOpsDataSegsOut,
    /// bpf_sock_ops::lost_out
    SockOpsLostOut,
    /// bpf_sock_ops::sacked_out
    SockOpsSackedOut,
    /// bpf_sock_ops::sk_txhash
    SockOpsSkTxhash,
    /// bpf_sock_ops::bytes_received
    SockOpsBytesReceived,
    /// bpf_sock_ops::bytes_acked
    SockOpsBytesAcked,
    /// bpf_sock_ops::skb_len
    SockOpsSkbLen,
    /// bpf_sock_ops::skb_tcp_flags
    SockOpsSkbTcpFlags,
    /// bpf_sock_ops::skb_hwtstamp
    SockOpsSkbHwtstamp,
    /// bpf_sysctl::write
    SysctlWrite,
    /// bpf_sysctl::file_pos
    SysctlFilePos,
    /// bpf_sockopt::level
    SockoptLevel,
    /// bpf_sockopt::optname
    SockoptOptname,
    /// bpf_sockopt::optlen
    SockoptOptlen,
    /// bpf_sockopt::optval kernel pointer
    SockoptOptval,
    /// bpf_sockopt::optval_end kernel pointer
    SockoptOptvalEnd,
    /// bpf_sockopt::retval
    SockoptRetval,
    /// Program argument (pt_regs-backed probes, raw tracepoints, and BTF-backed trampolines)
    Arg(u8),
    /// Return value (kretprobe/uretprobe)
    RetVal,
    /// Kernel stack ID
    KStack,
    /// User stack ID
    UStack,
    /// Tracepoint field by name
    TracepointField(String),
}

impl CtxField {
    pub fn display_name(&self) -> String {
        match self {
            CtxField::Context => "ctx".to_string(),
            CtxField::Pid => "pid".to_string(),
            CtxField::Tid => "tid".to_string(),
            CtxField::Uid => "uid".to_string(),
            CtxField::Gid => "gid".to_string(),
            CtxField::Comm => "comm".to_string(),
            CtxField::Cpu => "cpu".to_string(),
            CtxField::Timestamp => "timestamp".to_string(),
            CtxField::CgroupId => "cgroup_id".to_string(),
            CtxField::PerfSamplePeriod => "sample_period".to_string(),
            CtxField::PerfAddr => "addr".to_string(),
            CtxField::PacketLen => "packet_len".to_string(),
            CtxField::PktType => "pkt_type".to_string(),
            CtxField::QueueMapping => "queue_mapping".to_string(),
            CtxField::EthProtocol => "eth_protocol".to_string(),
            CtxField::VlanPresent => "vlan_present".to_string(),
            CtxField::VlanTci => "vlan_tci".to_string(),
            CtxField::VlanProto => "vlan_proto".to_string(),
            CtxField::SkbCb => "cb".to_string(),
            CtxField::TcClassid => "tc_classid".to_string(),
            CtxField::NapiId => "napi_id".to_string(),
            CtxField::WireLen => "wire_len".to_string(),
            CtxField::GsoSegs => "gso_segs".to_string(),
            CtxField::GsoSize => "gso_size".to_string(),
            CtxField::Tstamp => "tstamp".to_string(),
            CtxField::TstampType => "tstamp_type".to_string(),
            CtxField::Hwtstamp => "hwtstamp".to_string(),
            CtxField::Data => "data".to_string(),
            CtxField::DataMeta => "data_meta".to_string(),
            CtxField::DataEnd => "data_end".to_string(),
            CtxField::IngressIfindex => "ingress_ifindex".to_string(),
            CtxField::Ifindex => "ifindex".to_string(),
            CtxField::RxQueueIndex => "rx_queue_index".to_string(),
            CtxField::EgressIfindex => "egress_ifindex".to_string(),
            CtxField::TcIndex => "tc_index".to_string(),
            CtxField::SkbHash => "hash".to_string(),
            CtxField::UserFamily => "user_family".to_string(),
            CtxField::UserIp4 => "user_ip4".to_string(),
            CtxField::UserIp6 => "user_ip6".to_string(),
            CtxField::UserPort => "user_port".to_string(),
            CtxField::Family => "family".to_string(),
            CtxField::SockType => "sock_type".to_string(),
            CtxField::Protocol => "protocol".to_string(),
            CtxField::Socket => "sk".to_string(),
            CtxField::BoundDevIf => "bound_dev_if".to_string(),
            CtxField::SockMark => "mark".to_string(),
            CtxField::SockPriority => "priority".to_string(),
            CtxField::MsgSrcIp4 => "msg_src_ip4".to_string(),
            CtxField::MsgSrcIp6 => "msg_src_ip6".to_string(),
            CtxField::RemoteIp4 => "remote_ip4".to_string(),
            CtxField::RemoteIp6 => "remote_ip6".to_string(),
            CtxField::RemotePort => "remote_port".to_string(),
            CtxField::LocalIp4 => "local_ip4".to_string(),
            CtxField::LocalIp6 => "local_ip6".to_string(),
            CtxField::LocalPort => "local_port".to_string(),
            CtxField::LookupCookie => "cookie".to_string(),
            CtxField::LircSample => "sample".to_string(),
            CtxField::LircValue => "value".to_string(),
            CtxField::LircMode => "mode".to_string(),
            CtxField::SocketCookie => "socket_cookie".to_string(),
            CtxField::SocketUid => "socket_uid".to_string(),
            CtxField::NetnsCookie => "netns_cookie".to_string(),
            CtxField::DeviceAccessType => "access_type".to_string(),
            CtxField::DeviceMajor => "major".to_string(),
            CtxField::DeviceMinor => "minor".to_string(),
            CtxField::SockOp => "op".to_string(),
            CtxField::SockOpsArgs => "args".to_string(),
            CtxField::IsFullsock => "is_fullsock".to_string(),
            CtxField::SockOpsSndCwnd => "snd_cwnd".to_string(),
            CtxField::SockOpsSrttUs => "srtt_us".to_string(),
            CtxField::SockOpsCbFlags => "cb_flags".to_string(),
            CtxField::SockState => "state".to_string(),
            CtxField::SockOpsRttMin => "rtt_min".to_string(),
            CtxField::SockOpsSndSsthresh => "snd_ssthresh".to_string(),
            CtxField::SockOpsRcvNxt => "rcv_nxt".to_string(),
            CtxField::SockOpsSndNxt => "snd_nxt".to_string(),
            CtxField::SockOpsSndUna => "snd_una".to_string(),
            CtxField::SockOpsMssCache => "mss_cache".to_string(),
            CtxField::SockOpsEcnFlags => "ecn_flags".to_string(),
            CtxField::SockOpsRateDelivered => "rate_delivered".to_string(),
            CtxField::SockOpsRateIntervalUs => "rate_interval_us".to_string(),
            CtxField::SockOpsPacketsOut => "packets_out".to_string(),
            CtxField::SockOpsRetransOut => "retrans_out".to_string(),
            CtxField::SockOpsTotalRetrans => "total_retrans".to_string(),
            CtxField::SockOpsSegsIn => "segs_in".to_string(),
            CtxField::SockOpsDataSegsIn => "data_segs_in".to_string(),
            CtxField::SockOpsSegsOut => "segs_out".to_string(),
            CtxField::SockOpsDataSegsOut => "data_segs_out".to_string(),
            CtxField::SockOpsLostOut => "lost_out".to_string(),
            CtxField::SockOpsSackedOut => "sacked_out".to_string(),
            CtxField::SockOpsSkTxhash => "sk_txhash".to_string(),
            CtxField::SockOpsBytesReceived => "bytes_received".to_string(),
            CtxField::SockOpsBytesAcked => "bytes_acked".to_string(),
            CtxField::SockOpsSkbLen => "skb_len".to_string(),
            CtxField::SockOpsSkbTcpFlags => "skb_tcp_flags".to_string(),
            CtxField::SockOpsSkbHwtstamp => "skb_hwtstamp".to_string(),
            CtxField::SysctlWrite => "write".to_string(),
            CtxField::SysctlFilePos => "file_pos".to_string(),
            CtxField::SockoptLevel => "level".to_string(),
            CtxField::SockoptOptname => "optname".to_string(),
            CtxField::SockoptOptlen => "optlen".to_string(),
            CtxField::SockoptOptval => "optval".to_string(),
            CtxField::SockoptOptvalEnd => "optval_end".to_string(),
            CtxField::SockoptRetval => "sockopt_retval".to_string(),
            CtxField::Arg(idx) => format!("arg{}", idx),
            CtxField::RetVal => "retval".to_string(),
            CtxField::KStack => "kstack".to_string(),
            CtxField::UStack => "ustack".to_string(),
            CtxField::TracepointField(name) => name.clone(),
        }
    }

    pub fn bounded_end_field(&self) -> Option<CtxField> {
        match self {
            CtxField::DataMeta => Some(CtxField::Data),
            CtxField::SockoptOptval => Some(CtxField::SockoptOptvalEnd),
            _ => None,
        }
    }
}

/// Writable context-field targets.
///
/// This is intentionally narrower than `CtxField`: some context values are
/// readable but not writable, and some writable semantics do not map cleanly
/// to the read-side surface.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CtxStoreTarget {
    /// `bpf_sock_ops.reply`
    SockOpsReply,
    /// `bpf_sock_ops.replylong[idx]`
    SockOpsReplyLong(u8),
    /// `bpf_sock_ops.sk_txhash`
    SockOpsSkTxhash,
    /// `bpf_sock.bound_dev_if`
    CgroupSockBoundDevIf,
    /// `bpf_sock.mark`
    CgroupSockMark,
    /// `bpf_sock.priority`
    CgroupSockPriority,
    /// `__sk_buff.mark`
    SkbMark,
    /// `__sk_buff.priority`
    SkbPriority,
    /// `__sk_buff.tc_index`
    SkbTcIndex,
    /// `__sk_buff.cb[idx]`
    SkbCbWord(u8),
    /// `__sk_buff.tc_classid`
    SkbTcClassid,
    /// `__sk_buff.tstamp`
    SkbTstamp,
    /// `bpf_sysctl.file_pos`
    SysctlFilePos,
    /// `bpf_sockopt.level`
    SockoptLevel,
    /// `bpf_sockopt.optname`
    SockoptOptname,
    /// `bpf_sockopt.optlen`
    SockoptOptlen,
    /// `bpf_sockopt.retval`
    SockoptRetval,
    /// `bpf_sock_addr.user_ip4` (stored in network byte order)
    CgroupSockAddrUserIp4,
    /// `bpf_sock_addr.user_ip6[idx]` (stored in network byte order)
    CgroupSockAddrUserIp6Word(u8),
    /// `bpf_sock_addr.user_port` (stored in network byte order)
    CgroupSockAddrUserPort,
    /// `bpf_sock_addr.msg_src_ip4` (stored in network byte order)
    CgroupSockAddrMsgSrcIp4,
    /// `bpf_sock_addr.msg_src_ip6[idx]` (stored in network byte order)
    CgroupSockAddrMsgSrcIp6Word(u8),
}

impl CtxStoreTarget {
    pub fn value_type(&self) -> MirType {
        match self {
            CtxStoreTarget::SockOpsReply
            | CtxStoreTarget::SockOpsReplyLong(_)
            | CtxStoreTarget::SockOpsSkTxhash
            | CtxStoreTarget::CgroupSockBoundDevIf
            | CtxStoreTarget::CgroupSockMark
            | CtxStoreTarget::CgroupSockPriority
            | CtxStoreTarget::SkbMark
            | CtxStoreTarget::SkbPriority
            | CtxStoreTarget::SkbTcIndex
            | CtxStoreTarget::SkbCbWord(_)
            | CtxStoreTarget::SkbTcClassid
            | CtxStoreTarget::SysctlFilePos => MirType::U32,
            CtxStoreTarget::SkbTstamp => MirType::U64,
            CtxStoreTarget::SockoptLevel
            | CtxStoreTarget::SockoptOptname
            | CtxStoreTarget::SockoptOptlen
            | CtxStoreTarget::SockoptRetval => MirType::I32,
            CtxStoreTarget::CgroupSockAddrUserIp4
            | CtxStoreTarget::CgroupSockAddrUserIp6Word(_)
            | CtxStoreTarget::CgroupSockAddrUserPort
            | CtxStoreTarget::CgroupSockAddrMsgSrcIp4
            | CtxStoreTarget::CgroupSockAddrMsgSrcIp6Word(_) => MirType::U32,
        }
    }

    pub fn type_error_message(&self, actual: &MirType) -> String {
        match self {
            CtxStoreTarget::SockOpsReply | CtxStoreTarget::SockOpsReplyLong(_) => {
                format!(
                    "writable sock_ops reply fields require a u32 store, got {:?}",
                    actual
                )
            }
            CtxStoreTarget::SockOpsSkTxhash => {
                format!(
                    "writable sock_ops sk_txhash requires a u32 store, got {:?}",
                    actual
                )
            }
            CtxStoreTarget::CgroupSockBoundDevIf
            | CtxStoreTarget::CgroupSockMark
            | CtxStoreTarget::CgroupSockPriority => {
                format!(
                    "writable cgroup_sock scalar fields require a u32 store, got {:?}",
                    actual
                )
            }
            CtxStoreTarget::SkbMark
            | CtxStoreTarget::SkbPriority
            | CtxStoreTarget::SkbTcIndex
            | CtxStoreTarget::SkbCbWord(_)
            | CtxStoreTarget::SkbTcClassid => {
                format!(
                    "writable skb metadata fields require a u32 store, got {:?}",
                    actual
                )
            }
            CtxStoreTarget::SkbTstamp => {
                format!("writable skb tstamp requires a u64 store, got {:?}", actual)
            }
            CtxStoreTarget::SysctlFilePos => {
                format!(
                    "writable cgroup_sysctl file_pos requires a u32 store, got {:?}",
                    actual
                )
            }
            CtxStoreTarget::SockoptLevel
            | CtxStoreTarget::SockoptOptname
            | CtxStoreTarget::SockoptOptlen
            | CtxStoreTarget::SockoptRetval => format!(
                "writable cgroup_sockopt scalar fields require an i32 store, got {:?}",
                actual
            ),
            CtxStoreTarget::CgroupSockAddrUserIp4
            | CtxStoreTarget::CgroupSockAddrUserIp6Word(_)
            | CtxStoreTarget::CgroupSockAddrUserPort
            | CtxStoreTarget::CgroupSockAddrMsgSrcIp4
            | CtxStoreTarget::CgroupSockAddrMsgSrcIp6Word(_) => {
                format!(
                    "writable cgroup_sock_addr rewrite fields require a u32 store, got {:?}",
                    actual
                )
            }
        }
    }

    pub fn missing_context_error(&self) -> &'static str {
        match self {
            CtxStoreTarget::SockOpsReply | CtxStoreTarget::SockOpsReplyLong(_) => {
                "writable sock_ops reply fields are only supported on sock_ops programs"
            }
            CtxStoreTarget::SockOpsSkTxhash => {
                "writable sock_ops sk_txhash is only supported on sock_ops programs"
            }
            CtxStoreTarget::CgroupSockBoundDevIf => {
                "writable cgroup_sock bound_dev_if is only supported on cgroup_sock programs"
            }
            CtxStoreTarget::CgroupSockMark => {
                "writable cgroup_sock mark is only supported on cgroup_sock programs"
            }
            CtxStoreTarget::CgroupSockPriority => {
                "writable cgroup_sock priority is only supported on cgroup_sock programs"
            }
            CtxStoreTarget::SkbMark => "ctx.mark is only writable on tc and cgroup_skb programs",
            CtxStoreTarget::SkbPriority => {
                "ctx.priority is only writable on tc, cgroup_skb, sk_skb, and sk_skb_parser programs"
            }
            CtxStoreTarget::SkbTcIndex => {
                "ctx.tc_index is only writable on tc, sk_skb, and sk_skb_parser programs"
            }
            CtxStoreTarget::SkbCbWord(_) => {
                "ctx.cb is only writable on socket_filter, tc, and cgroup_skb programs"
            }
            CtxStoreTarget::SkbTcClassid => "ctx.tc_classid is only writable on tc programs",
            CtxStoreTarget::SkbTstamp => {
                "ctx.tstamp is only writable on tc and cgroup_skb:egress programs"
            }
            CtxStoreTarget::SysctlFilePos => {
                "writable cgroup_sysctl file_pos is only supported on cgroup_sysctl programs"
            }
            CtxStoreTarget::SockoptLevel
            | CtxStoreTarget::SockoptOptname
            | CtxStoreTarget::SockoptOptlen
            | CtxStoreTarget::SockoptRetval => {
                "writable cgroup_sockopt scalar fields require cgroup_sockopt context"
            }
            CtxStoreTarget::CgroupSockAddrUserIp4
            | CtxStoreTarget::CgroupSockAddrUserIp6Word(_)
            | CtxStoreTarget::CgroupSockAddrUserPort
            | CtxStoreTarget::CgroupSockAddrMsgSrcIp4
            | CtxStoreTarget::CgroupSockAddrMsgSrcIp6Word(_) => {
                "writable cgroup_sock_addr rewrite fields require cgroup_sock_addr context"
            }
        }
    }
}

/// MIR instruction
#[derive(Debug, Clone)]
pub enum MirInst {
    // Data movement
    /// Copy value to virtual register
    Copy { dst: VReg, src: MirValue },

    /// Load from memory (stack or via pointer)
    Load {
        dst: VReg,
        ptr: VReg,
        offset: i32,
        ty: MirType,
    },

    /// Store to memory
    Store {
        ptr: VReg,
        offset: i32,
        val: MirValue,
        ty: MirType,
    },

    /// Load from stack slot
    LoadSlot {
        dst: VReg,
        slot: StackSlotId,
        offset: i32,
        ty: MirType,
    },

    /// Store to stack slot
    StoreSlot {
        slot: StackSlotId,
        offset: i32,
        val: MirValue,
        ty: MirType,
    },

    // Arithmetic
    /// Binary operation
    BinOp {
        dst: VReg,
        op: BinOpKind,
        lhs: MirValue,
        rhs: MirValue,
    },

    /// Unary operation
    UnaryOp {
        dst: VReg,
        op: UnaryOpKind,
        src: MirValue,
    },

    // BPF helpers
    /// Call BPF helper function
    CallHelper {
        dst: VReg,
        helper: u32, // BPF helper ID
        args: Vec<MirValue>,
    },

    /// Call BPF kfunc (BTF-described kernel function)
    CallKfunc {
        dst: VReg,
        kfunc: String,
        /// Optional explicit BTF ID. If absent, backend resolves from `kfunc`.
        btf_id: Option<u32>,
        args: Vec<VReg>,
    },

    /// Materialize a map reference for helper-call lowering.
    LoadMapFd { dst: VReg, map: MapRef },

    /// Map lookup
    MapLookup { dst: VReg, map: MapRef, key: VReg },

    /// Load a compiler-generated global symbol from `.rodata`, `.data`, or `.bss`
    LoadGlobal {
        dst: VReg,
        symbol: String,
        ty: MirType,
    },

    /// Map update
    MapUpdate {
        map: MapRef,
        key: VReg,
        val: VReg,
        flags: u64,
    },

    /// Map delete
    MapDelete { map: MapRef, key: VReg },

    /// Queue/stack push
    MapPush { map: MapRef, val: VReg, flags: u64 },

    /// Histogram aggregation - computes log2 bucket and increments counter
    Histogram {
        /// Value to compute histogram bucket for
        value: VReg,
    },

    /// Start timer - stores current ktime keyed by TID
    StartTimer,

    /// Stop timer - looks up start time, computes delta, deletes entry
    /// Result is stored in dst (0 if no matching start)
    StopTimer { dst: VReg },

    /// Emit event to ring buffer
    EmitEvent { data: VReg, size: usize },

    /// Emit structured record to ring buffer
    EmitRecord {
        /// Fields to emit, in order
        fields: Vec<RecordFieldDef>,
    },

    // Context access
    /// Load context field
    LoadCtxField {
        dst: VReg,
        field: CtxField,
        /// Optional stack slot backing the field (for stack-based ctx data like comm)
        slot: Option<StackSlotId>,
    },

    /// Store a writable context field
    StoreCtxField {
        target: CtxStoreTarget,
        val: MirValue,
        ty: MirType,
    },

    // String operations
    /// Read string from user/kernel memory
    ReadStr {
        dst: StackSlotId,
        ptr: VReg,
        user_space: bool,
        max_len: usize,
    },

    /// Compare two strings on stack
    StrCmp {
        dst: VReg,
        lhs: StackSlotId,
        rhs: StackSlotId,
        len: usize,
    },

    /// Append a value to a string buffer
    /// dst_buffer is the destination string buffer on stack
    /// dst_len is a vreg holding the current string length
    /// val is the value to append (string slot or int)
    StringAppend {
        dst_buffer: StackSlotId,
        dst_len: VReg,
        val: MirValue,
        val_type: StringAppendType,
    },

    /// Format an integer as decimal string into a buffer
    /// Used for string interpolation with integers
    IntToString {
        dst_buffer: StackSlotId,
        dst_len: VReg,
        val: VReg,
    },

    // Record building
    /// Store field to record buffer
    RecordStore {
        buffer: StackSlotId,
        field_offset: usize,
        val: MirValue,
        ty: MirType,
    },

    // List operations
    /// Initialize an empty list on the stack
    /// Layout: [length: u64, elem0: u64, elem1: u64, ...]
    /// max_len determines the allocated buffer size
    ListNew {
        dst: VReg,
        buffer: StackSlotId,
        max_len: usize,
    },

    /// Push an element onto the end of a list
    /// Stores at offset (length * 8) + 8, then increments length
    ListPush { list: VReg, item: VReg },

    /// Get the current length of a list
    ListLen { dst: VReg, list: VReg },

    /// Get an element from a list by index
    /// Returns 0 if index out of bounds
    ListGet {
        dst: VReg,
        list: VReg,
        idx: MirValue,
    },

    // SSA phi function
    /// Phi node for SSA form - selects value based on incoming edge
    /// Must appear at the start of a block, before any non-phi instructions
    Phi {
        dst: VReg,
        /// (predecessor block, value from that predecessor)
        args: Vec<(BlockId, VReg)>,
    },

    // Control flow (terminators - must be last in block)
    /// Unconditional jump
    Jump { target: BlockId },

    /// Conditional branch
    Branch {
        cond: VReg,
        if_true: BlockId,
        if_false: BlockId,
    },

    /// Return from program
    Return { val: Option<MirValue> },

    /// Tail call to another program
    TailCall { prog_map: MapRef, index: MirValue },

    /// Call a BPF subfunction (BPF-to-BPF call)
    /// Arguments are passed in R1-R5, return value in R0
    CallSubfn {
        dst: VReg,
        subfn: SubfunctionId,
        args: Vec<VReg>,
    },

    // Pseudo-instructions (expanded during lowering)
    /// Bounded loop header (eBPF verifier requirement)
    LoopHeader {
        counter: VReg,
        start: i64,
        limit: i64,
        body: BlockId,
        exit: BlockId,
    },

    /// Loop increment and back-edge
    LoopBack {
        counter: VReg,
        step: i64,
        header: BlockId,
    },

    /// Placeholder terminator (not a real terminator, must be replaced)
    Placeholder,
}

/// A basic block with instructions and a terminator
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: BlockId,
    /// Non-terminator instructions
    pub instructions: Vec<MirInst>,
    /// Block terminator (must be Jump, Branch, Return, or TailCall)
    pub terminator: MirInst,
}

/// A complete MIR function
#[derive(Debug, Clone)]
pub struct MirFunction {
    /// Function name (for debugging and ELF section naming)
    pub name: Option<String>,
    /// Basic blocks (entry block is first)
    pub blocks: Vec<BasicBlock>,
    /// Entry block ID
    pub entry: BlockId,
    /// Number of virtual registers used
    pub vreg_count: u32,
    /// Stack slots
    pub stack_slots: Vec<StackSlot>,
    /// Maps used by this function
    pub maps_used: Vec<MapRef>,
    /// Parameter count (for BPF subfunction calling convention)
    pub param_count: usize,
    /// Mutable-global symbols that semantically alias incoming parameters.
    ///
    /// This is used to recover "returns arg N" summaries for subfunctions that
    /// read aliased parameters back through `LoadGlobal` to preserve non-null
    /// global semantics.
    pub global_param_aliases: HashMap<String, usize>,
}

/// A complete MIR program (may have subfunctions for BPF-to-BPF calls)
#[derive(Debug, Clone)]
pub struct MirProgram {
    /// Main function
    pub main: MirFunction,
    /// Subfunctions (for BPF-to-BPF calls)
    pub subfunctions: Vec<MirFunction>,
}

/// Optional type hints for MIR registers, usually derived from HIR inference.
#[derive(Debug, Clone, Default)]
pub struct MirTypeHints {
    pub main: HashMap<VReg, MirType>,
    pub subfunctions: Vec<HashMap<VReg, MirType>>,
    pub main_stack_slots: HashMap<StackSlotId, MirType>,
    pub subfunction_stack_slots: Vec<HashMap<StackSlotId, MirType>>,
    pub generic_map_value_types: HashMap<MapRef, MirType>,
    pub generic_map_value_semantics:
        HashMap<MapRef, crate::compiler::ir_to_mir::AnnotatedValueSemantics>,
}

#[cfg(test)]
mod tests;
