use crate::compiler::{
    EbpfProgramType,
    instruction::BpfHelper,
    mir::{AddressSpace, CtxField, MirType, StructField},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextFieldTypeSpec {
    pub semantic_ty: MirType,
    pub runtime_ty: MirType,
    pub kernel_btf_runtime_type_name: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextFieldLoadGuard {
    SockOpsCallback(SockOpsCallbackGuard),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockOpsCallbackGuard {
    PacketData,
    PacketMetadata,
    TcpFlags,
    Hwtstamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextFieldProjectionSpec {
    pub runtime_ty: MirType,
    pub stack_slot_ty: Option<MirType>,
    pub normalize_u32_words_host_order: bool,
    pub validate_socket_projection: bool,
}

impl ContextFieldTypeSpec {
    fn value(ty: MirType) -> Self {
        Self {
            semantic_ty: ty.clone(),
            runtime_ty: ty,
            kernel_btf_runtime_type_name: None,
        }
    }

    fn stack_backed(semantic_ty: MirType) -> Self {
        Self {
            runtime_ty: MirType::Ptr {
                pointee: Box::new(semantic_ty.clone()),
                address_space: AddressSpace::Stack,
            },
            semantic_ty,
            kernel_btf_runtime_type_name: None,
        }
    }

    fn with_kernel_btf_runtime_type(mut self, type_name: &'static str) -> Self {
        self.kernel_btf_runtime_type_name = Some(type_name);
        self
    }
}

impl ContextFieldProjectionSpec {
    fn direct(runtime_ty: MirType) -> Self {
        Self {
            runtime_ty,
            stack_slot_ty: None,
            normalize_u32_words_host_order: false,
            validate_socket_projection: false,
        }
    }

    fn stack_backed(semantic_ty: MirType, normalize_u32_words_host_order: bool) -> Self {
        Self {
            runtime_ty: MirType::Ptr {
                pointee: Box::new(semantic_ty.clone()),
                address_space: AddressSpace::Stack,
            },
            stack_slot_ty: Some(semantic_ty),
            normalize_u32_words_host_order,
            validate_socket_projection: false,
        }
    }
}

const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: i64 = 4;
const BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: i64 = 5;
const BPF_SOCK_OPS_PARSE_HDR_OPT_CB: i64 = 13;
const BPF_SOCK_OPS_HDR_OPT_LEN_CB: i64 = 14;
const BPF_SOCK_OPS_WRITE_HDR_OPT_CB: i64 = 15;
const BPF_SOCK_OPS_TSTAMP_SCHED_CB: i64 = 16;
const BPF_SOCK_OPS_TSTAMP_SND_SW_CB: i64 = 17;
const BPF_SOCK_OPS_TSTAMP_SND_HW_CB: i64 = 18;
const BPF_SOCK_OPS_TSTAMP_ACK_CB: i64 = 19;
const BPF_SOCK_OPS_TSTAMP_SENDMSG_CB: i64 = 20;
pub(crate) const SYSCTL_STRING_FIELD_LEN: usize = 256;

impl ContextFieldLoadGuard {
    pub(crate) fn witness_field(self) -> CtxField {
        match self {
            Self::SockOpsCallback(_) => CtxField::SockOp,
        }
    }

    pub(crate) fn allows_value(self, value: i64) -> bool {
        match self {
            Self::SockOpsCallback(guard) => guard.allows_callback_op(value),
        }
    }

    pub(crate) fn error(self, field: &CtxField) -> String {
        match self {
            Self::SockOpsCallback(_) => format!(
                "ctx.{} on sock_ops requires proving a packet-aware ctx.op callback before use",
                field.display_name()
            ),
        }
    }
}

impl SockOpsCallbackGuard {
    fn allows_callback_op(self, op: i64) -> bool {
        match self {
            Self::PacketData => Self::callback_has_packet_data(op),
            Self::PacketMetadata => Self::callback_has_packet_metadata(op),
            Self::TcpFlags => Self::callback_has_tcp_flags(op),
            Self::Hwtstamp => Self::callback_has_hwtstamp(op),
        }
    }

    fn callback_has_packet_data(op: i64) -> bool {
        matches!(
            op,
            BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB
                | BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB
                | BPF_SOCK_OPS_PARSE_HDR_OPT_CB
                | BPF_SOCK_OPS_WRITE_HDR_OPT_CB
        )
    }

    fn callback_has_packet_metadata(op: i64) -> bool {
        Self::callback_has_packet_data(op) || Self::callback_has_hwtstamp(op)
    }

    fn callback_has_tcp_flags(op: i64) -> bool {
        Self::callback_has_packet_data(op) || op == BPF_SOCK_OPS_HDR_OPT_LEN_CB
    }

    fn callback_has_hwtstamp(op: i64) -> bool {
        matches!(
            op,
            BPF_SOCK_OPS_TSTAMP_SCHED_CB
                | BPF_SOCK_OPS_TSTAMP_SND_SW_CB
                | BPF_SOCK_OPS_TSTAMP_SND_HW_CB
                | BPF_SOCK_OPS_TSTAMP_ACK_CB
                | BPF_SOCK_OPS_TSTAMP_SENDMSG_CB
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaseContextFieldProjectionKind {
    None,
    Direct,
    SocketValidated,
    StackBacked {
        normalize_u32_words_host_order: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BaseContextFieldSchemaSpec {
    type_spec: ContextFieldTypeSpec,
    projection_kind: BaseContextFieldProjectionKind,
    pointer_non_null: bool,
    trusted_btf_pointer: bool,
    sock_ops_load_guard: Option<SockOpsCallbackGuard>,
}

impl BaseContextFieldSchemaSpec {
    fn value(type_spec: ContextFieldTypeSpec) -> Self {
        Self {
            type_spec,
            projection_kind: BaseContextFieldProjectionKind::None,
            pointer_non_null: false,
            trusted_btf_pointer: false,
            sock_ops_load_guard: None,
        }
    }

    fn direct(type_spec: ContextFieldTypeSpec) -> Self {
        Self {
            type_spec,
            projection_kind: BaseContextFieldProjectionKind::Direct,
            pointer_non_null: false,
            trusted_btf_pointer: false,
            sock_ops_load_guard: None,
        }
    }

    fn socket_validated(type_spec: ContextFieldTypeSpec) -> Self {
        Self {
            type_spec,
            projection_kind: BaseContextFieldProjectionKind::SocketValidated,
            pointer_non_null: false,
            trusted_btf_pointer: false,
            sock_ops_load_guard: None,
        }
    }

    fn stack_backed(type_spec: ContextFieldTypeSpec, normalize_u32_words_host_order: bool) -> Self {
        Self {
            type_spec,
            projection_kind: BaseContextFieldProjectionKind::StackBacked {
                normalize_u32_words_host_order,
            },
            pointer_non_null: false,
            trusted_btf_pointer: false,
            sock_ops_load_guard: None,
        }
    }

    fn non_null_pointer(mut self) -> Self {
        self.pointer_non_null = true;
        self
    }

    fn trusted_btf_pointer(mut self) -> Self {
        self.trusted_btf_pointer = true;
        self
    }

    fn with_sock_ops_load_guard(mut self, guard: SockOpsCallbackGuard) -> Self {
        self.sock_ops_load_guard = Some(guard);
        self
    }

    fn projection_spec(&self) -> Option<ContextFieldProjectionSpec> {
        match self.projection_kind {
            BaseContextFieldProjectionKind::None => None,
            BaseContextFieldProjectionKind::Direct => Some(ContextFieldProjectionSpec::direct(
                self.type_spec.runtime_ty.clone(),
            )),
            BaseContextFieldProjectionKind::SocketValidated => Some(ContextFieldProjectionSpec {
                runtime_ty: self.type_spec.runtime_ty.clone(),
                stack_slot_ty: None,
                normalize_u32_words_host_order: false,
                validate_socket_projection: true,
            }),
            BaseContextFieldProjectionKind::StackBacked {
                normalize_u32_words_host_order,
            } => Some(ContextFieldProjectionSpec::stack_backed(
                self.type_spec.semantic_ty.clone(),
                normalize_u32_words_host_order,
            )),
        }
    }

    fn sock_ops_load_guard(&self) -> Option<SockOpsCallbackGuard> {
        self.sock_ops_load_guard
    }

    fn pointer_is_non_null(&self) -> bool {
        self.pointer_non_null
    }

    fn is_trusted_btf_kernel_pointer(&self) -> bool {
        self.trusted_btf_pointer
    }
}

pub(crate) fn ctx_field_for_bpf_sock_projection_member(member: &str) -> Option<CtxField> {
    Some(match member {
        "bound_dev_if" => CtxField::BoundDevIf,
        "family" => CtxField::Family,
        "type" | "sock_type" => CtxField::SockType,
        "protocol" | "ip_protocol" => CtxField::Protocol,
        "mark" => CtxField::SockMark,
        "priority" => CtxField::SockPriority,
        "src_ip4" => CtxField::LocalIp4,
        "src_ip6" => CtxField::LocalIp6,
        "src_port" => CtxField::LocalPort,
        "dst_port" => CtxField::RemotePort,
        "dst_ip4" => CtxField::RemoteIp4,
        "dst_ip6" => CtxField::RemoteIp6,
        "state" => CtxField::SockState,
        "rx_queue_mapping" => CtxField::SockRxQueueMapping,
        _ => return None,
    })
}

pub(crate) fn synthetic_bpf_sock_type() -> MirType {
    MirType::Struct {
        name: Some("bpf_sock".to_string()),
        kernel_btf_type_id: None,
        fields: vec![
            StructField {
                name: "bound_dev_if".to_string(),
                ty: MirType::U32,
                offset: 0,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "family".to_string(),
                ty: MirType::U32,
                offset: 4,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "type".to_string(),
                ty: MirType::U32,
                offset: 8,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "protocol".to_string(),
                ty: MirType::U32,
                offset: 12,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "mark".to_string(),
                ty: MirType::U32,
                offset: 16,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "priority".to_string(),
                ty: MirType::U32,
                offset: 20,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "src_ip4".to_string(),
                ty: MirType::U32,
                offset: 24,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "src_ip6".to_string(),
                ty: MirType::Array {
                    elem: Box::new(MirType::U32),
                    len: 4,
                },
                offset: 28,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "src_port".to_string(),
                ty: MirType::U32,
                offset: 44,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "dst_port".to_string(),
                ty: MirType::U16,
                offset: 48,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "dst_ip4".to_string(),
                ty: MirType::U32,
                offset: 52,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "dst_ip6".to_string(),
                ty: MirType::Array {
                    elem: Box::new(MirType::U32),
                    len: 4,
                },
                offset: 56,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "state".to_string(),
                ty: MirType::U32,
                offset: 72,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "rx_queue_mapping".to_string(),
                ty: MirType::I32,
                offset: 76,
                synthetic: false,
                bitfield: None,
            },
        ],
    }
}

pub(crate) fn synthetic_bpf_tcp_sock_type() -> MirType {
    let field = |name: &str, ty: MirType, offset| StructField {
        name: name.to_string(),
        ty,
        offset,
        synthetic: false,
        bitfield: None,
    };

    MirType::Struct {
        name: Some("bpf_tcp_sock".to_string()),
        kernel_btf_type_id: None,
        fields: vec![
            field("snd_cwnd", MirType::U32, 0),
            field("srtt_us", MirType::U32, 4),
            field("rtt_min", MirType::U32, 8),
            field("snd_ssthresh", MirType::U32, 12),
            field("rcv_nxt", MirType::U32, 16),
            field("snd_nxt", MirType::U32, 20),
            field("snd_una", MirType::U32, 24),
            field("mss_cache", MirType::U32, 28),
            field("ecn_flags", MirType::U32, 32),
            field("rate_delivered", MirType::U32, 36),
            field("rate_interval_us", MirType::U32, 40),
            field("packets_out", MirType::U32, 44),
            field("retrans_out", MirType::U32, 48),
            field("total_retrans", MirType::U32, 52),
            field("segs_in", MirType::U32, 56),
            field("data_segs_in", MirType::U32, 60),
            field("segs_out", MirType::U32, 64),
            field("data_segs_out", MirType::U32, 68),
            field("lost_out", MirType::U32, 72),
            field("sacked_out", MirType::U32, 76),
            field("bytes_received", MirType::U64, 80),
            field("bytes_acked", MirType::U64, 88),
            field("dsack_dups", MirType::U32, 96),
            field("delivered", MirType::U32, 100),
            field("delivered_ce", MirType::U32, 104),
            field("icsk_retransmits", MirType::U32, 108),
        ],
    }
}

pub(crate) fn synthetic_bpf_flow_keys_type() -> MirType {
    let field = |name: &str, ty: MirType, offset| StructField {
        name: name.to_string(),
        ty,
        offset,
        synthetic: false,
        bitfield: None,
    };

    MirType::Struct {
        name: Some("bpf_flow_keys".to_string()),
        kernel_btf_type_id: None,
        fields: vec![
            field("nhoff", MirType::U16, 0),
            field("thoff", MirType::U16, 2),
            field("addr_proto", MirType::U16, 4),
            field("is_frag", MirType::U8, 6),
            field("is_first_frag", MirType::U8, 7),
            field("is_encap", MirType::U8, 8),
            field("ip_proto", MirType::U8, 9),
            field("n_proto", MirType::U16, 10),
            field("sport", MirType::U16, 12),
            field("dport", MirType::U16, 14),
            field("ipv4_src", MirType::U32, 16),
            field("ipv4_dst", MirType::U32, 20),
            field(
                "ipv6_src",
                MirType::Array {
                    elem: Box::new(MirType::U32),
                    len: 4,
                },
                16,
            ),
            field(
                "ipv6_dst",
                MirType::Array {
                    elem: Box::new(MirType::U32),
                    len: 4,
                },
                32,
            ),
            field("flags", MirType::U32, 48),
            field("flow_label", MirType::U32, 52),
        ],
    }
}

fn base_ctx_field_schema_spec(field: &CtxField) -> Option<BaseContextFieldSchemaSpec> {
    Some(match field {
        CtxField::Pid
        | CtxField::Tgid
        | CtxField::Uid
        | CtxField::Gid
        | CtxField::PktType
        | CtxField::QueueMapping
        | CtxField::EthProtocol
        | CtxField::VlanPresent
        | CtxField::VlanTci
        | CtxField::VlanProto
        | CtxField::TcClassid
        | CtxField::CgroupClassid
        | CtxField::RouteRealm
        | CtxField::NapiId
        | CtxField::WireLen
        | CtxField::GsoSegs
        | CtxField::GsoSize
        | CtxField::IngressIfindex
        | CtxField::Ifindex
        | CtxField::RxQueueIndex
        | CtxField::EgressIfindex
        | CtxField::TcIndex
        | CtxField::SkbHash
        | CtxField::HashRecalc
        | CtxField::UserFamily
        | CtxField::UserIp4
        | CtxField::UserPort
        | CtxField::Family
        | CtxField::SockType
        | CtxField::Protocol
        | CtxField::BindInany
        | CtxField::BoundDevIf
        | CtxField::SockMark
        | CtxField::SockPriority
        | CtxField::MsgSrcIp4
        | CtxField::RemoteIp4
        | CtxField::RemotePort
        | CtxField::LocalIp4
        | CtxField::LocalPort
        | CtxField::LircSample
        | CtxField::LircValue
        | CtxField::LircMode
        | CtxField::DeviceAccessType
        | CtxField::DeviceAccess
        | CtxField::DeviceType
        | CtxField::DeviceMajor
        | CtxField::DeviceMinor
        | CtxField::SockOp
        | CtxField::IsFullsock
        | CtxField::SockOpsSndCwnd
        | CtxField::SockOpsSrttUs
        | CtxField::SockOpsCbFlags
        | CtxField::SockState
        | CtxField::SockOpsRttMin
        | CtxField::SockOpsSndSsthresh
        | CtxField::SockOpsRcvNxt
        | CtxField::SockOpsSndNxt
        | CtxField::SockOpsSndUna
        | CtxField::SockOpsMssCache
        | CtxField::SockOpsEcnFlags
        | CtxField::SockOpsRateDelivered
        | CtxField::SockOpsRateIntervalUs
        | CtxField::SockOpsPacketsOut
        | CtxField::SockOpsRetransOut
        | CtxField::SockOpsTotalRetrans
        | CtxField::SockOpsSegsIn
        | CtxField::SockOpsDataSegsIn
        | CtxField::SockOpsSegsOut
        | CtxField::SockOpsDataSegsOut
        | CtxField::SockOpsLostOut
        | CtxField::SockOpsSackedOut
        | CtxField::SockOpsSkTxhash
        | CtxField::SysctlWrite
        | CtxField::SysctlFilePos
        | CtxField::Random
        | CtxField::SocketUid => {
            BaseContextFieldSchemaSpec::value(ContextFieldTypeSpec::value(MirType::U32))
        }
        CtxField::PacketLen => {
            BaseContextFieldSchemaSpec::value(ContextFieldTypeSpec::value(MirType::U32))
                .with_sock_ops_load_guard(SockOpsCallbackGuard::PacketMetadata)
        }
        CtxField::SockOpsSkbLen => {
            BaseContextFieldSchemaSpec::value(ContextFieldTypeSpec::value(MirType::U32))
                .with_sock_ops_load_guard(SockOpsCallbackGuard::PacketMetadata)
        }
        CtxField::SockOpsSkbTcpFlags => {
            BaseContextFieldSchemaSpec::value(ContextFieldTypeSpec::value(MirType::U32))
                .with_sock_ops_load_guard(SockOpsCallbackGuard::TcpFlags)
        }
        CtxField::TstampType => {
            BaseContextFieldSchemaSpec::value(ContextFieldTypeSpec::value(MirType::U8))
        }
        CtxField::NumaNode => {
            BaseContextFieldSchemaSpec::value(ContextFieldTypeSpec::value(MirType::I64))
        }
        CtxField::Cpu => {
            BaseContextFieldSchemaSpec::value(ContextFieldTypeSpec::value(MirType::U32))
        }
        CtxField::Timestamp
        | CtxField::BootTimestamp
        | CtxField::CoarseTimestamp
        | CtxField::TaiTimestamp
        | CtxField::Jiffies
        | CtxField::PidTgid
        | CtxField::UidGid
        | CtxField::FuncIp
        | CtxField::AttachCookie
        | CtxField::ArgCount
        | CtxField::CgroupId
        | CtxField::PerfSamplePeriod
        | CtxField::PerfAddr
        | CtxField::PerfCounter
        | CtxField::PerfEnabled
        | CtxField::PerfRunning
        | CtxField::XdpBuffLen
        | CtxField::SkbCgroupId
        | CtxField::LookupCookie
        | CtxField::SocketCookie
        | CtxField::NetnsCookie
        | CtxField::Tstamp
        | CtxField::Hwtstamp
        | CtxField::SockOpsBytesReceived
        | CtxField::SockOpsBytesAcked => {
            BaseContextFieldSchemaSpec::value(ContextFieldTypeSpec::value(MirType::U64))
        }
        CtxField::SockOpsSkbHwtstamp => {
            BaseContextFieldSchemaSpec::value(ContextFieldTypeSpec::value(MirType::U64))
                .with_sock_ops_load_guard(SockOpsCallbackGuard::Hwtstamp)
        }
        CtxField::CsumLevel => {
            BaseContextFieldSchemaSpec::value(ContextFieldTypeSpec::value(MirType::I64))
        }
        CtxField::SockRxQueueMapping => {
            BaseContextFieldSchemaSpec::value(ContextFieldTypeSpec::value(MirType::I32))
        }
        CtxField::SockoptLevel
        | CtxField::SockoptOptname
        | CtxField::SockoptOptlen
        | CtxField::SockoptRetval => {
            BaseContextFieldSchemaSpec::value(ContextFieldTypeSpec::value(MirType::I32))
        }
        CtxField::Task => BaseContextFieldSchemaSpec::value(
            ContextFieldTypeSpec::value(MirType::named_kernel_struct_ptr("task_struct"))
                .with_kernel_btf_runtime_type("task_struct"),
        )
        .non_null_pointer()
        .trusted_btf_pointer(),
        CtxField::IterTask => BaseContextFieldSchemaSpec::value(
            ContextFieldTypeSpec::value(MirType::named_kernel_struct_ptr("task_struct"))
                .with_kernel_btf_runtime_type("task_struct"),
        ),
        CtxField::IterMeta => BaseContextFieldSchemaSpec::value(
            ContextFieldTypeSpec::value(MirType::named_kernel_struct_ptr("bpf_iter_meta"))
                .with_kernel_btf_runtime_type("bpf_iter_meta"),
        )
        .non_null_pointer()
        .trusted_btf_pointer(),
        CtxField::IterFd => {
            BaseContextFieldSchemaSpec::value(ContextFieldTypeSpec::value(MirType::U32))
        }
        CtxField::IterFile => BaseContextFieldSchemaSpec::value(
            ContextFieldTypeSpec::value(MirType::named_kernel_struct_ptr("file"))
                .with_kernel_btf_runtime_type("file"),
        ),
        CtxField::IterVma => BaseContextFieldSchemaSpec::value(
            ContextFieldTypeSpec::value(MirType::named_kernel_struct_ptr("vm_area_struct"))
                .with_kernel_btf_runtime_type("vm_area_struct"),
        ),
        CtxField::IterCgroup => BaseContextFieldSchemaSpec::value(
            ContextFieldTypeSpec::value(MirType::named_kernel_struct_ptr("cgroup"))
                .with_kernel_btf_runtime_type("cgroup"),
        ),
        CtxField::IterMap => BaseContextFieldSchemaSpec::value(
            ContextFieldTypeSpec::value(MirType::named_kernel_struct_ptr("bpf_map"))
                .with_kernel_btf_runtime_type("bpf_map"),
        ),
        CtxField::IterMapKey | CtxField::IterMapValue => {
            BaseContextFieldSchemaSpec::value(ContextFieldTypeSpec::value(MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            }))
        }
        CtxField::IterProg => BaseContextFieldSchemaSpec::value(
            ContextFieldTypeSpec::value(MirType::named_kernel_struct_ptr("bpf_prog"))
                .with_kernel_btf_runtime_type("bpf_prog"),
        ),
        CtxField::IterLink => BaseContextFieldSchemaSpec::value(
            ContextFieldTypeSpec::value(MirType::named_kernel_struct_ptr("bpf_link"))
                .with_kernel_btf_runtime_type("bpf_link"),
        ),
        CtxField::IterSkCommon => BaseContextFieldSchemaSpec::value(
            ContextFieldTypeSpec::value(MirType::named_kernel_struct_ptr("sock_common"))
                .with_kernel_btf_runtime_type("sock_common"),
        ),
        CtxField::IterUdpSk => BaseContextFieldSchemaSpec::value(
            ContextFieldTypeSpec::value(MirType::named_kernel_struct_ptr("udp_sock"))
                .with_kernel_btf_runtime_type("udp_sock"),
        ),
        CtxField::IterUnixSk => BaseContextFieldSchemaSpec::value(
            ContextFieldTypeSpec::value(MirType::named_kernel_struct_ptr("unix_sock"))
                .with_kernel_btf_runtime_type("unix_sock"),
        ),
        CtxField::IterUid | CtxField::IterBucket => {
            BaseContextFieldSchemaSpec::value(ContextFieldTypeSpec::value(MirType::U32))
        }
        CtxField::IterDmabuf => BaseContextFieldSchemaSpec::value(
            ContextFieldTypeSpec::value(MirType::named_kernel_struct_ptr("dma_buf"))
                .with_kernel_btf_runtime_type("dma_buf"),
        ),
        CtxField::IterIpv6Route => BaseContextFieldSchemaSpec::value(
            ContextFieldTypeSpec::value(MirType::named_kernel_struct_ptr("fib6_info"))
                .with_kernel_btf_runtime_type("fib6_info"),
        ),
        CtxField::IterKmemCache => BaseContextFieldSchemaSpec::value(
            ContextFieldTypeSpec::value(MirType::named_kernel_struct_ptr("kmem_cache"))
                .with_kernel_btf_runtime_type("kmem_cache"),
        ),
        CtxField::IterKsym => BaseContextFieldSchemaSpec::value(
            ContextFieldTypeSpec::value(MirType::named_kernel_struct_ptr("kallsym_iter"))
                .with_kernel_btf_runtime_type("kallsym_iter"),
        ),
        CtxField::IterNetlinkSk => BaseContextFieldSchemaSpec::value(
            ContextFieldTypeSpec::value(MirType::named_kernel_struct_ptr("netlink_sock"))
                .with_kernel_btf_runtime_type("netlink_sock"),
        ),
        CtxField::IterSock => BaseContextFieldSchemaSpec::value(
            ContextFieldTypeSpec::value(MirType::named_kernel_struct_ptr("sock"))
                .with_kernel_btf_runtime_type("sock"),
        ),
        CtxField::Cgroup => BaseContextFieldSchemaSpec::value(
            ContextFieldTypeSpec::value(MirType::named_kernel_struct_ptr("cgroup"))
                .with_kernel_btf_runtime_type("cgroup"),
        )
        .trusted_btf_pointer(),
        CtxField::Context => {
            BaseContextFieldSchemaSpec::value(ContextFieldTypeSpec::value(MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            }))
        }
        CtxField::Socket | CtxField::MigratingSocket => {
            BaseContextFieldSchemaSpec::socket_validated(ContextFieldTypeSpec::value(
                MirType::Ptr {
                    pointee: Box::new(synthetic_bpf_sock_type()),
                    address_space: AddressSpace::Kernel,
                },
            ))
        }
        CtxField::FlowKeys => {
            // The verifier treats __sk_buff::flow_keys as a trusted direct-access
            // pointer for flow_dissector; use Context space so projections emit
            // direct loads without treating it as a writable map-value buffer.
            BaseContextFieldSchemaSpec::direct(ContextFieldTypeSpec::value(MirType::Ptr {
                pointee: Box::new(synthetic_bpf_flow_keys_type()),
                address_space: AddressSpace::Context,
            }))
            .non_null_pointer()
        }
        CtxField::NetfilterState => BaseContextFieldSchemaSpec::value(
            ContextFieldTypeSpec::value(MirType::named_kernel_struct_ptr("nf_hook_state"))
                .with_kernel_btf_runtime_type("nf_hook_state"),
        )
        .non_null_pointer()
        .trusted_btf_pointer(),
        CtxField::NetfilterSkb => BaseContextFieldSchemaSpec::value(
            ContextFieldTypeSpec::value(MirType::named_kernel_struct_ptr("sk_buff"))
                .with_kernel_btf_runtime_type("sk_buff"),
        )
        .non_null_pointer()
        .trusted_btf_pointer(),
        CtxField::NetfilterHook | CtxField::NetfilterProtocolFamily => {
            BaseContextFieldSchemaSpec::value(ContextFieldTypeSpec::value(MirType::U8))
        }
        CtxField::SockoptOptval | CtxField::SockoptOptvalEnd => {
            BaseContextFieldSchemaSpec::direct(ContextFieldTypeSpec::value(MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            }))
        }
        CtxField::UserIp6 | CtxField::MsgSrcIp6 => BaseContextFieldSchemaSpec::stack_backed(
            ContextFieldTypeSpec::stack_backed(MirType::Array {
                elem: Box::new(MirType::U32),
                len: 4,
            }),
            true,
        ),
        CtxField::RemoteIp6 | CtxField::LocalIp6 | CtxField::SockOpsArgs => {
            BaseContextFieldSchemaSpec::stack_backed(
                ContextFieldTypeSpec::stack_backed(MirType::Array {
                    elem: Box::new(MirType::U32),
                    len: 4,
                }),
                false,
            )
        }
        CtxField::SkbCb => BaseContextFieldSchemaSpec::stack_backed(
            ContextFieldTypeSpec::stack_backed(MirType::Array {
                elem: Box::new(MirType::U32),
                len: 5,
            }),
            false,
        ),
        CtxField::Data => {
            BaseContextFieldSchemaSpec::direct(ContextFieldTypeSpec::value(MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Packet,
            }))
            .non_null_pointer()
            .with_sock_ops_load_guard(SockOpsCallbackGuard::PacketData)
        }
        CtxField::DataMeta => {
            BaseContextFieldSchemaSpec::direct(ContextFieldTypeSpec::value(MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Packet,
            }))
            .non_null_pointer()
        }
        CtxField::DataEnd => {
            BaseContextFieldSchemaSpec::direct(ContextFieldTypeSpec::value(MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Packet,
            }))
            .non_null_pointer()
            .with_sock_ops_load_guard(SockOpsCallbackGuard::PacketData)
        }
        CtxField::Comm => BaseContextFieldSchemaSpec::stack_backed(
            ContextFieldTypeSpec::stack_backed(MirType::Array {
                elem: Box::new(MirType::U8),
                len: 16,
            }),
            false,
        ),
        CtxField::SysctlName
        | CtxField::SysctlBaseName
        | CtxField::SysctlCurrentValue
        | CtxField::SysctlNewValue => BaseContextFieldSchemaSpec::stack_backed(
            ContextFieldTypeSpec::stack_backed(MirType::Array {
                elem: Box::new(MirType::U8),
                len: SYSCTL_STRING_FIELD_LEN,
            }),
            false,
        ),
        CtxField::Arg(_) | CtxField::RetVal | CtxField::KStack | CtxField::UStack => {
            return None;
        }
        CtxField::TracepointField(_) => return None,
    })
}

fn raw_ctx_field_type_spec(field: &CtxField) -> Option<ContextFieldTypeSpec> {
    base_ctx_field_schema_spec(field).map(|spec| spec.type_spec)
}

fn raw_ctx_field_pointer_is_non_null(field: &CtxField) -> bool {
    base_ctx_field_schema_spec(field).is_some_and(|spec| spec.pointer_is_non_null())
}

fn raw_ctx_field_is_trusted_btf_kernel_pointer(field: &CtxField) -> bool {
    base_ctx_field_schema_spec(field).is_some_and(|spec| spec.is_trusted_btf_kernel_pointer())
}

pub(crate) fn static_ctx_field_type_spec(field: &CtxField) -> Option<ContextFieldTypeSpec> {
    raw_ctx_field_type_spec(field)
}

pub(crate) fn program_type_ctx_field_type_spec(
    program_type: EbpfProgramType,
    field: &CtxField,
) -> Option<ContextFieldTypeSpec> {
    program_type
        .base_ctx_field_access_error(field)
        .is_none()
        .then(|| raw_ctx_field_type_spec(field))
        .flatten()
}

pub(crate) fn static_ctx_field_pointer_is_non_null(field: &CtxField) -> bool {
    raw_ctx_field_pointer_is_non_null(field)
}

pub(crate) fn program_type_ctx_field_pointer_is_non_null(
    program_type: EbpfProgramType,
    field: &CtxField,
) -> bool {
    program_type.base_ctx_field_access_error(field).is_none()
        && raw_ctx_field_pointer_is_non_null(field)
}

pub(crate) fn program_type_ctx_field_is_trusted_btf_kernel_pointer(
    program_type: EbpfProgramType,
    field: &CtxField,
) -> bool {
    program_type.base_ctx_field_access_error(field).is_none()
        && raw_ctx_field_is_trusted_btf_kernel_pointer(field)
}

pub(crate) fn ctx_field_sock_ops_load_guard(field: &CtxField) -> Option<SockOpsCallbackGuard> {
    base_ctx_field_schema_spec(field).and_then(|spec| spec.sock_ops_load_guard())
}

pub(crate) fn ctx_field_backing_helper(field: &CtxField) -> Option<BpfHelper> {
    Some(match field {
        CtxField::Pid | CtxField::Tgid | CtxField::PidTgid => BpfHelper::GetCurrentPidTgid,
        CtxField::Uid | CtxField::Gid | CtxField::UidGid => BpfHelper::GetCurrentUidGid,
        CtxField::Task | CtxField::Cgroup => BpfHelper::GetCurrentTaskBtf,
        CtxField::Timestamp => BpfHelper::KtimeGetNs,
        CtxField::BootTimestamp => BpfHelper::KtimeGetBootNs,
        CtxField::CoarseTimestamp => BpfHelper::KtimeGetCoarseNs,
        CtxField::TaiTimestamp => BpfHelper::KtimeGetTaiNs,
        CtxField::Jiffies => BpfHelper::Jiffies64,
        CtxField::FuncIp => BpfHelper::GetFuncIp,
        CtxField::AttachCookie => BpfHelper::GetAttachCookie,
        CtxField::Cpu => BpfHelper::GetSmpProcessorId,
        CtxField::NumaNode => BpfHelper::GetNumaNodeId,
        CtxField::Random => BpfHelper::GetPrandomU32,
        CtxField::CgroupId => BpfHelper::GetCurrentCgroupId,
        CtxField::PerfCounter | CtxField::PerfEnabled | CtxField::PerfRunning => {
            BpfHelper::PerfProgReadValue
        }
        CtxField::SocketCookie => BpfHelper::GetSocketCookie,
        CtxField::SocketUid => BpfHelper::GetSocketUid,
        CtxField::NetnsCookie => BpfHelper::GetNetnsCookie,
        CtxField::CgroupClassid => BpfHelper::GetCgroupClassid,
        CtxField::RouteRealm => BpfHelper::GetRouteRealm,
        CtxField::CsumLevel => BpfHelper::CsumLevel,
        CtxField::HashRecalc => BpfHelper::GetHashRecalc,
        CtxField::SkbCgroupId => BpfHelper::SkbCgroupId,
        CtxField::XdpBuffLen => BpfHelper::XdpGetBuffLen,
        CtxField::SysctlName | CtxField::SysctlBaseName => BpfHelper::SysctlGetName,
        CtxField::SysctlCurrentValue => BpfHelper::SysctlGetCurrentValue,
        CtxField::SysctlNewValue => BpfHelper::SysctlGetNewValue,
        CtxField::Comm => BpfHelper::GetCurrentComm,
        CtxField::ArgCount => BpfHelper::GetFuncArgCnt,
        CtxField::KStack | CtxField::UStack => BpfHelper::GetStackId,
        _ => return None,
    })
}

fn raw_ctx_field_projection_spec(field: &CtxField) -> Option<ContextFieldProjectionSpec> {
    base_ctx_field_schema_spec(field).and_then(|spec| spec.projection_spec())
}

pub(crate) fn static_ctx_field_projection_spec(
    field: &CtxField,
) -> Option<ContextFieldProjectionSpec> {
    raw_ctx_field_projection_spec(field)
}

pub(crate) fn program_type_ctx_field_projection_spec(
    program_type: EbpfProgramType,
    field: &CtxField,
) -> Option<ContextFieldProjectionSpec> {
    program_type
        .base_ctx_field_access_error(field)
        .is_none()
        .then(|| raw_ctx_field_projection_spec(field))
        .flatten()
}
