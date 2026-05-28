use super::{
    ContextFieldArrayLoad, ContextFieldDirectLoad, CtxField, EbpfProgramType,
    IngressIfindexContextLayout, PacketContextKind, SocketContextLayout,
};
use crate::compiler::ctx_field_schema::{
    ContextFieldLoadGuard, ContextFieldProjectionSpec, ContextFieldTypeSpec,
    ctx_field_sock_ops_load_guard, program_type_ctx_field_is_trusted_btf_kernel_pointer,
    program_type_ctx_field_pointer_is_non_null, program_type_ctx_field_projection_spec,
    program_type_ctx_field_type_spec,
};
use crate::program_spec::ProgramSpec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProgramContextLayoutSpec {
    program_type: EbpfProgramType,
    packet_context: Option<PacketContextKind>,
    data_meta: Option<PacketContextKind>,
    socket_family: Option<SocketContextLayout>,
    sock_type: Option<SocketContextLayout>,
    protocol: Option<SocketContextLayout>,
    socket_ref: Option<SocketContextLayout>,
    ingress_ifindex: Option<IngressIfindexContextLayout>,
    sock_mark_priority: Option<SocketContextLayout>,
    sock_state: Option<SocketContextLayout>,
    socket_cookie: bool,
    socket_uid: bool,
    netns_cookie: bool,
    lookup_cookie: bool,
    raw_socket_context_pointer: bool,
    direct_packet_writes: bool,
    non_null_ctx_fields: &'static [CtxField],
    sock_ops_load_guards: bool,
}

impl ProgramContextLayoutSpec {
    const fn skb_backed(
        program_type: EbpfProgramType,
        data_meta: Option<PacketContextKind>,
        socket_family: Option<SocketContextLayout>,
        netns_cookie: bool,
    ) -> Self {
        Self {
            program_type,
            packet_context: Some(PacketContextKind::SkBuff),
            data_meta,
            socket_family,
            sock_type: None,
            protocol: Some(SocketContextLayout::SkBuff),
            socket_ref: Some(SocketContextLayout::SkBuff),
            ingress_ifindex: Some(IngressIfindexContextLayout::SkBuff),
            sock_mark_priority: Some(SocketContextLayout::SkBuff),
            sock_state: None,
            socket_cookie: true,
            socket_uid: true,
            netns_cookie,
            lookup_cookie: false,
            raw_socket_context_pointer: false,
            direct_packet_writes: false,
            non_null_ctx_fields: &[],
            sock_ops_load_guards: false,
        }
    }

    const fn skb_packet_only(program_type: EbpfProgramType) -> Self {
        Self {
            program_type,
            packet_context: Some(PacketContextKind::SkBuff),
            data_meta: None,
            socket_family: None,
            sock_type: None,
            protocol: Some(SocketContextLayout::SkBuff),
            socket_ref: None,
            ingress_ifindex: Some(IngressIfindexContextLayout::SkBuff),
            sock_mark_priority: Some(SocketContextLayout::SkBuff),
            sock_state: None,
            socket_cookie: false,
            socket_uid: false,
            netns_cookie: false,
            lookup_cookie: false,
            raw_socket_context_pointer: false,
            direct_packet_writes: false,
            non_null_ctx_fields: &[],
            sock_ops_load_guards: false,
        }
    }

    const fn with_direct_packet_writes(mut self) -> Self {
        self.direct_packet_writes = true;
        self
    }

    fn ctx_field_pointer_is_non_null(&self, field: &CtxField) -> bool {
        self.non_null_ctx_fields.contains(field)
    }
}

const PROGRAM_CONTEXT_LAYOUT_SPECS: &[ProgramContextLayoutSpec] = &[
    ProgramContextLayoutSpec {
        program_type: EbpfProgramType::Xdp,
        packet_context: Some(PacketContextKind::XdpMd),
        data_meta: Some(PacketContextKind::XdpMd),
        socket_family: None,
        sock_type: None,
        protocol: None,
        socket_ref: None,
        ingress_ifindex: Some(IngressIfindexContextLayout::XdpMd),
        sock_mark_priority: None,
        sock_state: None,
        socket_cookie: false,
        socket_uid: false,
        netns_cookie: false,
        lookup_cookie: false,
        raw_socket_context_pointer: false,
        direct_packet_writes: true,
        non_null_ctx_fields: &[],
        sock_ops_load_guards: false,
    },
    ProgramContextLayoutSpec::skb_backed(EbpfProgramType::SocketFilter, None, None, true),
    ProgramContextLayoutSpec::skb_backed(
        EbpfProgramType::Tc,
        Some(PacketContextKind::SkBuff),
        None,
        true,
    )
    .with_direct_packet_writes(),
    ProgramContextLayoutSpec::skb_backed(
        EbpfProgramType::Tcx,
        Some(PacketContextKind::SkBuff),
        None,
        true,
    )
    .with_direct_packet_writes(),
    ProgramContextLayoutSpec::skb_backed(
        EbpfProgramType::Netkit,
        Some(PacketContextKind::SkBuff),
        None,
        true,
    )
    .with_direct_packet_writes(),
    ProgramContextLayoutSpec::skb_backed(
        EbpfProgramType::TcAction,
        Some(PacketContextKind::SkBuff),
        None,
        true,
    )
    .with_direct_packet_writes(),
    ProgramContextLayoutSpec::skb_backed(
        EbpfProgramType::CgroupSkb,
        None,
        Some(SocketContextLayout::SkBuff),
        true,
    ),
    ProgramContextLayoutSpec::skb_backed(
        EbpfProgramType::SkSkb,
        None,
        Some(SocketContextLayout::SkBuff),
        false,
    )
    .with_direct_packet_writes(),
    ProgramContextLayoutSpec::skb_backed(
        EbpfProgramType::SkSkbParser,
        None,
        Some(SocketContextLayout::SkBuff),
        false,
    )
    .with_direct_packet_writes(),
    ProgramContextLayoutSpec::skb_packet_only(EbpfProgramType::LwtIn),
    ProgramContextLayoutSpec::skb_packet_only(EbpfProgramType::LwtOut),
    ProgramContextLayoutSpec::skb_packet_only(EbpfProgramType::LwtXmit).with_direct_packet_writes(),
    ProgramContextLayoutSpec::skb_packet_only(EbpfProgramType::LwtSeg6Local),
    ProgramContextLayoutSpec {
        program_type: EbpfProgramType::CgroupSock,
        packet_context: None,
        data_meta: None,
        socket_family: Some(SocketContextLayout::CgroupSock),
        sock_type: Some(SocketContextLayout::CgroupSock),
        protocol: Some(SocketContextLayout::CgroupSock),
        socket_ref: Some(SocketContextLayout::CgroupSock),
        ingress_ifindex: None,
        sock_mark_priority: Some(SocketContextLayout::CgroupSock),
        sock_state: Some(SocketContextLayout::CgroupSock),
        socket_cookie: true,
        socket_uid: false,
        netns_cookie: true,
        lookup_cookie: false,
        raw_socket_context_pointer: true,
        direct_packet_writes: false,
        non_null_ctx_fields: &[],
        sock_ops_load_guards: false,
    },
    ProgramContextLayoutSpec {
        program_type: EbpfProgramType::CgroupSockAddr,
        packet_context: None,
        data_meta: None,
        socket_family: Some(SocketContextLayout::SockAddr),
        sock_type: Some(SocketContextLayout::SockAddr),
        protocol: Some(SocketContextLayout::SockAddr),
        socket_ref: Some(SocketContextLayout::SockAddr),
        ingress_ifindex: None,
        sock_mark_priority: None,
        sock_state: None,
        socket_cookie: true,
        socket_uid: false,
        netns_cookie: true,
        lookup_cookie: false,
        raw_socket_context_pointer: false,
        direct_packet_writes: false,
        non_null_ctx_fields: &[],
        sock_ops_load_guards: false,
    },
    ProgramContextLayoutSpec {
        program_type: EbpfProgramType::CgroupSockopt,
        packet_context: None,
        data_meta: None,
        socket_family: None,
        sock_type: None,
        protocol: None,
        socket_ref: Some(SocketContextLayout::CgroupSockopt),
        ingress_ifindex: None,
        sock_mark_priority: None,
        sock_state: None,
        socket_cookie: false,
        socket_uid: false,
        netns_cookie: true,
        lookup_cookie: false,
        raw_socket_context_pointer: false,
        direct_packet_writes: false,
        non_null_ctx_fields: &[],
        sock_ops_load_guards: false,
    },
    ProgramContextLayoutSpec {
        program_type: EbpfProgramType::SkLookup,
        packet_context: None,
        data_meta: None,
        socket_family: Some(SocketContextLayout::SkLookup),
        sock_type: None,
        protocol: Some(SocketContextLayout::SkLookup),
        socket_ref: Some(SocketContextLayout::SkLookup),
        ingress_ifindex: Some(IngressIfindexContextLayout::SkLookup),
        sock_mark_priority: None,
        sock_state: None,
        socket_cookie: false,
        socket_uid: false,
        netns_cookie: false,
        lookup_cookie: true,
        raw_socket_context_pointer: false,
        direct_packet_writes: false,
        non_null_ctx_fields: &[],
        sock_ops_load_guards: false,
    },
    ProgramContextLayoutSpec {
        program_type: EbpfProgramType::FlowDissector,
        packet_context: Some(PacketContextKind::SkBuff),
        data_meta: None,
        socket_family: None,
        sock_type: None,
        protocol: None,
        socket_ref: None,
        ingress_ifindex: None,
        sock_mark_priority: None,
        sock_state: None,
        socket_cookie: false,
        socket_uid: false,
        netns_cookie: false,
        lookup_cookie: false,
        raw_socket_context_pointer: false,
        direct_packet_writes: false,
        non_null_ctx_fields: &[],
        sock_ops_load_guards: false,
    },
    ProgramContextLayoutSpec {
        program_type: EbpfProgramType::SkReuseport,
        packet_context: Some(PacketContextKind::SkReuseport),
        data_meta: None,
        socket_family: None,
        sock_type: None,
        protocol: Some(SocketContextLayout::SkReuseport),
        socket_ref: Some(SocketContextLayout::SkReuseport),
        ingress_ifindex: None,
        sock_mark_priority: None,
        sock_state: None,
        socket_cookie: true,
        socket_uid: false,
        netns_cookie: false,
        lookup_cookie: false,
        raw_socket_context_pointer: false,
        direct_packet_writes: false,
        non_null_ctx_fields: &[CtxField::Socket],
        sock_ops_load_guards: false,
    },
    ProgramContextLayoutSpec {
        program_type: EbpfProgramType::SkMsg,
        packet_context: Some(PacketContextKind::SkMsg),
        data_meta: None,
        socket_family: Some(SocketContextLayout::SkMsg),
        sock_type: None,
        protocol: None,
        socket_ref: Some(SocketContextLayout::SkMsg),
        ingress_ifindex: None,
        sock_mark_priority: None,
        sock_state: None,
        socket_cookie: false,
        socket_uid: false,
        netns_cookie: true,
        lookup_cookie: false,
        raw_socket_context_pointer: false,
        direct_packet_writes: true,
        non_null_ctx_fields: &[],
        sock_ops_load_guards: false,
    },
    ProgramContextLayoutSpec {
        program_type: EbpfProgramType::SockOps,
        packet_context: Some(PacketContextKind::SockOps),
        data_meta: None,
        socket_family: Some(SocketContextLayout::SockOps),
        sock_type: None,
        protocol: None,
        socket_ref: Some(SocketContextLayout::SockOps),
        ingress_ifindex: None,
        sock_mark_priority: None,
        sock_state: Some(SocketContextLayout::SockOps),
        socket_cookie: true,
        socket_uid: false,
        netns_cookie: true,
        lookup_cookie: false,
        raw_socket_context_pointer: false,
        direct_packet_writes: false,
        non_null_ctx_fields: &[],
        sock_ops_load_guards: true,
    },
];

fn program_context_layout_spec(
    program_type: EbpfProgramType,
) -> Option<&'static ProgramContextLayoutSpec> {
    PROGRAM_CONTEXT_LAYOUT_SPECS
        .iter()
        .find(|spec| spec.program_type == program_type)
}

impl PacketContextKind {
    pub(crate) fn ctx_field_direct_load(self, field: &CtxField) -> Option<ContextFieldDirectLoad> {
        match (self, field) {
            (Self::XdpMd, CtxField::Data) => Some(ContextFieldDirectLoad::u32(0)),
            (Self::XdpMd, CtxField::DataEnd) => Some(ContextFieldDirectLoad::u32(4)),
            (Self::XdpMd, CtxField::DataMeta) => Some(ContextFieldDirectLoad::u32(8)),
            (Self::XdpMd, CtxField::IngressIfindex) => Some(ContextFieldDirectLoad::u32(12)),
            (Self::XdpMd, CtxField::RxQueueIndex) => Some(ContextFieldDirectLoad::u32(16)),
            (Self::XdpMd, CtxField::EgressIfindex) => Some(ContextFieldDirectLoad::u32(20)),
            (Self::SkBuff, CtxField::PacketLen) => Some(ContextFieldDirectLoad::u32(0)),
            (Self::SkBuff, CtxField::PktType) => Some(ContextFieldDirectLoad::u32(4)),
            (Self::SkBuff, CtxField::QueueMapping) => Some(ContextFieldDirectLoad::u32(12)),
            (Self::SkBuff, CtxField::EthProtocol) => Some(ContextFieldDirectLoad::u16(16)),
            (Self::SkBuff, CtxField::VlanPresent) => Some(ContextFieldDirectLoad::u32(20)),
            (Self::SkBuff, CtxField::VlanTci) => Some(ContextFieldDirectLoad::u32(24)),
            (Self::SkBuff, CtxField::VlanProto) => Some(ContextFieldDirectLoad::u16(28)),
            (Self::SkBuff, CtxField::IngressIfindex) => Some(ContextFieldDirectLoad::u32(36)),
            (Self::SkBuff, CtxField::Ifindex) => Some(ContextFieldDirectLoad::u32(40)),
            (Self::SkBuff, CtxField::TcIndex) => Some(ContextFieldDirectLoad::u32(44)),
            (Self::SkBuff, CtxField::SkbHash) => Some(ContextFieldDirectLoad::u32(68)),
            (Self::SkBuff, CtxField::TcClassid) => Some(ContextFieldDirectLoad::u32(72)),
            (Self::SkBuff, CtxField::Data) => Some(ContextFieldDirectLoad::u32(76)),
            (Self::SkBuff, CtxField::DataEnd) => Some(ContextFieldDirectLoad::u32(80)),
            (Self::SkBuff, CtxField::NapiId) => Some(ContextFieldDirectLoad::u32(84)),
            (Self::SkBuff, CtxField::DataMeta) => Some(ContextFieldDirectLoad::u32(140)),
            (Self::SkBuff, CtxField::Tstamp) => Some(ContextFieldDirectLoad::u64(152)),
            (Self::SkBuff, CtxField::WireLen) => Some(ContextFieldDirectLoad::u32(160)),
            (Self::SkBuff, CtxField::GsoSegs) => Some(ContextFieldDirectLoad::u32(164)),
            (Self::SkBuff, CtxField::GsoSize) => Some(ContextFieldDirectLoad::u32(176)),
            (Self::SkBuff, CtxField::TstampType) => Some(ContextFieldDirectLoad::u8(180)),
            (Self::SkBuff, CtxField::Hwtstamp) => Some(ContextFieldDirectLoad::u64(184)),
            (Self::SkMsg, CtxField::Data) => Some(ContextFieldDirectLoad::u64(0)),
            (Self::SkMsg, CtxField::DataEnd) => Some(ContextFieldDirectLoad::u64(8)),
            (Self::SkMsg, CtxField::PacketLen) => Some(ContextFieldDirectLoad::u32(68)),
            (Self::SockOps, CtxField::Data) => Some(ContextFieldDirectLoad::u64(192)),
            (Self::SockOps, CtxField::DataEnd) => Some(ContextFieldDirectLoad::u64(200)),
            (Self::SockOps, CtxField::PacketLen) => Some(ContextFieldDirectLoad::u32(208)),
            (Self::SkReuseport, CtxField::Data) => Some(ContextFieldDirectLoad::u64(0)),
            (Self::SkReuseport, CtxField::DataEnd) => Some(ContextFieldDirectLoad::u64(8)),
            (Self::SkReuseport, CtxField::PacketLen) => Some(ContextFieldDirectLoad::u32(16)),
            (Self::SkReuseport, CtxField::EthProtocol) => Some(ContextFieldDirectLoad::u16(20)),
            (Self::SkReuseport, CtxField::SkbHash) => Some(ContextFieldDirectLoad::u32(32)),
            _ => None,
        }
    }

    pub(crate) fn ctx_field_array_load(self, field: &CtxField) -> Option<ContextFieldArrayLoad> {
        match (self, field) {
            (Self::SkBuff, CtxField::SkbCb) => Some(ContextFieldArrayLoad::u32_words(48, 5, false)),
            _ => None,
        }
    }
}

impl SocketContextLayout {
    pub(crate) fn ctx_field_direct_load(self, field: &CtxField) -> Option<ContextFieldDirectLoad> {
        match (self, field) {
            (Self::CgroupSock, CtxField::BoundDevIf) => Some(ContextFieldDirectLoad::u32(0)),
            (Self::CgroupSock, CtxField::Family) => Some(ContextFieldDirectLoad::u32(4)),
            (Self::CgroupSock, CtxField::SockType) => Some(ContextFieldDirectLoad::u32(8)),
            (Self::CgroupSock, CtxField::Protocol) => Some(ContextFieldDirectLoad::u32(12)),
            (Self::CgroupSock, CtxField::SockMark) => Some(ContextFieldDirectLoad::u32(16)),
            (Self::CgroupSock, CtxField::SockPriority) => Some(ContextFieldDirectLoad::u32(20)),
            (Self::CgroupSock, CtxField::LocalIp4) => Some(ContextFieldDirectLoad::u32(24)),
            (Self::CgroupSock, CtxField::LocalPort) => Some(ContextFieldDirectLoad::u32(44)),
            (Self::CgroupSock, CtxField::RemotePort) => Some(ContextFieldDirectLoad::u16(48)),
            (Self::CgroupSock, CtxField::RemoteIp4) => Some(ContextFieldDirectLoad::u32(52)),
            (Self::CgroupSock, CtxField::SockState) => Some(ContextFieldDirectLoad::u32(72)),
            (Self::CgroupSock, CtxField::SockRxQueueMapping) => {
                Some(ContextFieldDirectLoad::u32(76))
            }
            (Self::SockAddr, CtxField::UserFamily) => Some(ContextFieldDirectLoad::u32(0)),
            (Self::SockAddr, CtxField::UserIp4) => Some(ContextFieldDirectLoad::u32(4)),
            (Self::SockAddr, CtxField::UserPort) => Some(ContextFieldDirectLoad::u32(24)),
            (Self::SockAddr, CtxField::Family) => Some(ContextFieldDirectLoad::u32(28)),
            (Self::SockAddr, CtxField::SockType) => Some(ContextFieldDirectLoad::u32(32)),
            (Self::SockAddr, CtxField::Protocol) => Some(ContextFieldDirectLoad::u32(36)),
            (Self::SockAddr, CtxField::MsgSrcIp4) => Some(ContextFieldDirectLoad::u32(40)),
            (Self::SockAddr, CtxField::Socket) => Some(ContextFieldDirectLoad::u64(64)),
            (Self::CgroupSockopt, CtxField::Socket) => Some(ContextFieldDirectLoad::u64(0)),
            (Self::SkLookup, CtxField::Socket | CtxField::LookupCookie) => {
                Some(ContextFieldDirectLoad::u64(0))
            }
            (Self::SkLookup, CtxField::Family) => Some(ContextFieldDirectLoad::u32(8)),
            (Self::SkLookup, CtxField::Protocol) => Some(ContextFieldDirectLoad::u32(12)),
            (Self::SkLookup, CtxField::RemoteIp4) => Some(ContextFieldDirectLoad::u32(16)),
            (Self::SkLookup, CtxField::RemotePort) => Some(ContextFieldDirectLoad::u16(36)),
            (Self::SkLookup, CtxField::LocalIp4) => Some(ContextFieldDirectLoad::u32(40)),
            (Self::SkLookup, CtxField::LocalPort) => Some(ContextFieldDirectLoad::u32(60)),
            (Self::SkMsg, CtxField::Family) => Some(ContextFieldDirectLoad::u32(16)),
            (Self::SkMsg, CtxField::RemoteIp4) => Some(ContextFieldDirectLoad::u32(20)),
            (Self::SkMsg, CtxField::LocalIp4) => Some(ContextFieldDirectLoad::u32(24)),
            (Self::SkMsg, CtxField::RemotePort) => Some(ContextFieldDirectLoad::u32(60)),
            (Self::SkMsg, CtxField::LocalPort) => Some(ContextFieldDirectLoad::u32(64)),
            (Self::SkMsg, CtxField::Socket) => Some(ContextFieldDirectLoad::u64(72)),
            (Self::SkBuff, CtxField::Family) => Some(ContextFieldDirectLoad::u32(88)),
            (Self::SkBuff, CtxField::RemoteIp4) => Some(ContextFieldDirectLoad::u32(92)),
            (Self::SkBuff, CtxField::LocalIp4) => Some(ContextFieldDirectLoad::u32(96)),
            (Self::SkBuff, CtxField::RemotePort) => Some(ContextFieldDirectLoad::u32(132)),
            (Self::SkBuff, CtxField::LocalPort) => Some(ContextFieldDirectLoad::u32(136)),
            (Self::SkBuff, CtxField::Protocol) => Some(ContextFieldDirectLoad::u16(16)),
            (Self::SkBuff, CtxField::Socket) => Some(ContextFieldDirectLoad::u64(168)),
            (Self::SkBuff, CtxField::SockMark) => Some(ContextFieldDirectLoad::u32(8)),
            (Self::SkBuff, CtxField::SockPriority) => Some(ContextFieldDirectLoad::u32(32)),
            (Self::SockOps, CtxField::Family) => Some(ContextFieldDirectLoad::u32(20)),
            (Self::SockOps, CtxField::RemoteIp4) => Some(ContextFieldDirectLoad::u32(24)),
            (Self::SockOps, CtxField::LocalIp4) => Some(ContextFieldDirectLoad::u32(28)),
            (Self::SockOps, CtxField::RemotePort) => Some(ContextFieldDirectLoad::u16(64)),
            (Self::SockOps, CtxField::LocalPort) => Some(ContextFieldDirectLoad::u32(68)),
            (Self::SockOps, CtxField::Socket) => Some(ContextFieldDirectLoad::u64(184)),
            (Self::SockOps, CtxField::SockState) => Some(ContextFieldDirectLoad::u32(88)),
            (Self::SkReuseport, CtxField::Protocol) => Some(ContextFieldDirectLoad::u32(24)),
            (Self::SkReuseport, CtxField::Socket) => Some(ContextFieldDirectLoad::u64(40)),
            _ => None,
        }
    }

    pub(crate) fn ctx_field_array_load(self, field: &CtxField) -> Option<ContextFieldArrayLoad> {
        match (self, field) {
            (Self::SockAddr, CtxField::UserIp6) => {
                Some(ContextFieldArrayLoad::u32_words(8, 4, false))
            }
            (Self::SockAddr, CtxField::MsgSrcIp6) => {
                Some(ContextFieldArrayLoad::u32_words(44, 4, false))
            }
            (Self::CgroupSock, CtxField::LocalIp6) => {
                Some(ContextFieldArrayLoad::u32_words(28, 4, true))
            }
            (Self::CgroupSock, CtxField::RemoteIp6) => {
                Some(ContextFieldArrayLoad::u32_words(56, 4, true))
            }
            (Self::SkLookup, CtxField::RemoteIp6) => {
                Some(ContextFieldArrayLoad::u32_words(20, 4, true))
            }
            (Self::SkLookup, CtxField::LocalIp6) => {
                Some(ContextFieldArrayLoad::u32_words(44, 4, true))
            }
            (Self::SkMsg, CtxField::RemoteIp6) => {
                Some(ContextFieldArrayLoad::u32_words(28, 4, true))
            }
            (Self::SkMsg, CtxField::LocalIp6) => {
                Some(ContextFieldArrayLoad::u32_words(44, 4, true))
            }
            (Self::SkBuff, CtxField::RemoteIp6) => {
                Some(ContextFieldArrayLoad::u32_words(100, 4, true))
            }
            (Self::SkBuff, CtxField::LocalIp6) => {
                Some(ContextFieldArrayLoad::u32_words(116, 4, true))
            }
            (Self::SockOps, CtxField::RemoteIp6) => {
                Some(ContextFieldArrayLoad::u32_words(32, 4, true))
            }
            (Self::SockOps, CtxField::LocalIp6) => {
                Some(ContextFieldArrayLoad::u32_words(48, 4, true))
            }
            _ => None,
        }
    }
}

impl EbpfProgramType {
    pub fn packet_context_kind(&self) -> Option<PacketContextKind> {
        program_context_layout_spec(*self).and_then(|spec| spec.packet_context)
    }

    pub(crate) fn data_meta_context_kind(&self) -> Option<PacketContextKind> {
        program_context_layout_spec(*self).and_then(|spec| spec.data_meta)
    }

    pub fn supports_data_meta_ctx_field(&self) -> bool {
        self.data_meta_context_kind().is_some()
    }

    pub fn supports_direct_packet_writes(&self) -> bool {
        program_context_layout_spec(*self).is_some_and(|spec| spec.direct_packet_writes)
    }

    pub(crate) fn socket_family_context_layout(&self) -> Option<SocketContextLayout> {
        program_context_layout_spec(*self).and_then(|spec| spec.socket_family)
    }

    pub(crate) fn socket_tuple_context_layout(&self) -> Option<SocketContextLayout> {
        self.socket_family_context_layout()
    }

    pub(crate) fn sock_type_context_layout(&self) -> Option<SocketContextLayout> {
        program_context_layout_spec(*self).and_then(|spec| spec.sock_type)
    }

    pub(crate) fn protocol_context_layout(&self) -> Option<SocketContextLayout> {
        program_context_layout_spec(*self).and_then(|spec| spec.protocol)
    }

    pub(crate) fn socket_ref_context_layout(&self) -> Option<SocketContextLayout> {
        program_context_layout_spec(*self).and_then(|spec| spec.socket_ref)
    }

    pub(crate) fn ingress_ifindex_context_layout(&self) -> Option<IngressIfindexContextLayout> {
        program_context_layout_spec(*self).and_then(|spec| spec.ingress_ifindex)
    }

    pub(crate) fn sock_mark_priority_context_layout(&self) -> Option<SocketContextLayout> {
        program_context_layout_spec(*self).and_then(|spec| spec.sock_mark_priority)
    }

    pub(crate) fn sock_state_context_layout(&self) -> Option<SocketContextLayout> {
        program_context_layout_spec(*self).and_then(|spec| spec.sock_state)
    }

    pub fn supports_socket_ref_ctx_field(&self) -> bool {
        self.socket_ref_context_layout().is_some()
    }

    pub fn supports_socket_common_ctx_fields(&self) -> bool {
        self.socket_family_context_layout().is_some()
    }

    pub fn supports_socket_tuple_ctx_fields(&self) -> bool {
        self.socket_tuple_context_layout().is_some()
    }

    pub fn supports_sock_type_ctx_field(&self) -> bool {
        self.sock_type_context_layout().is_some()
    }

    pub fn supports_protocol_ctx_field(&self) -> bool {
        self.protocol_context_layout().is_some()
    }

    pub fn supports_sock_mark_priority_ctx_fields(&self) -> bool {
        self.sock_mark_priority_context_layout().is_some()
    }

    pub fn supports_sock_state_ctx_field(&self) -> bool {
        self.sock_state_context_layout().is_some()
    }

    pub fn uses_perf_event_context(&self) -> bool {
        self.context_family().is_perf_event()
    }

    pub fn supports_perf_event_ctx_fields(&self) -> bool {
        self.uses_perf_event_context() && cfg!(target_arch = "x86_64")
    }

    pub fn supports_socket_cookie_ctx_field(&self) -> bool {
        program_context_layout_spec(*self).is_some_and(|spec| spec.socket_cookie)
    }

    pub fn supports_socket_uid_ctx_field(&self) -> bool {
        program_context_layout_spec(*self).is_some_and(|spec| spec.socket_uid)
    }

    pub fn supports_netns_cookie_ctx_field(&self) -> bool {
        program_context_layout_spec(*self).is_some_and(|spec| spec.netns_cookie)
    }

    pub fn supports_lookup_cookie_ctx_field(&self) -> bool {
        program_context_layout_spec(*self).is_some_and(|spec| spec.lookup_cookie)
    }

    pub(crate) fn ctx_field_is_raw_context_pointer(&self, field: &CtxField) -> bool {
        matches!(field, CtxField::Context)
            || (matches!(field, CtxField::Socket)
                && program_context_layout_spec(*self)
                    .is_some_and(|spec| spec.raw_socket_context_pointer))
    }

    pub(crate) fn ctx_field_pointer_is_non_null(&self, field: &CtxField) -> bool {
        self.base_ctx_field_access_error(field).is_none()
            && (self.ctx_field_is_raw_context_pointer(field)
                || program_context_layout_spec(*self)
                    .is_some_and(|spec| spec.ctx_field_pointer_is_non_null(field))
                || program_type_ctx_field_pointer_is_non_null(*self, field))
    }

    pub(crate) fn ctx_field_is_trusted_btf_kernel_pointer(&self, field: &CtxField) -> bool {
        program_type_ctx_field_is_trusted_btf_kernel_pointer(*self, field)
    }

    pub(crate) fn ctx_field_load_guard(&self, field: &CtxField) -> Option<ContextFieldLoadGuard> {
        program_context_layout_spec(*self)
            .filter(|spec| spec.sock_ops_load_guards)
            .and_then(|_| ctx_field_sock_ops_load_guard(field))
            .map(ContextFieldLoadGuard::SockOpsCallback)
    }

    pub(crate) fn socket_ctx_field_direct_load(
        &self,
        field: &CtxField,
    ) -> Option<ContextFieldDirectLoad> {
        let layout = match field {
            CtxField::Family => self.socket_family_context_layout(),
            CtxField::SockType => self.sock_type_context_layout(),
            CtxField::Protocol => self.protocol_context_layout(),
            CtxField::Socket => self.socket_ref_context_layout(),
            CtxField::UserFamily | CtxField::UserIp4 | CtxField::UserPort | CtxField::MsgSrcIp4 => {
                self.socket_family_context_layout()
            }
            CtxField::RemoteIp4
            | CtxField::RemotePort
            | CtxField::LocalIp4
            | CtxField::LocalPort => self.socket_tuple_context_layout(),
            CtxField::SockMark | CtxField::SockPriority => self.sock_mark_priority_context_layout(),
            CtxField::SockState => self.sock_state_context_layout(),
            CtxField::BoundDevIf | CtxField::SockRxQueueMapping => {
                self.socket_family_context_layout()
            }
            CtxField::LookupCookie => self
                .supports_lookup_cookie_ctx_field()
                .then_some(SocketContextLayout::SkLookup),
            _ => None,
        }?;

        layout.ctx_field_direct_load(field)
    }

    pub(crate) fn socket_ctx_field_array_load(
        &self,
        field: &CtxField,
    ) -> Option<ContextFieldArrayLoad> {
        let layout = match field {
            CtxField::UserIp6 | CtxField::MsgSrcIp6 => self.socket_family_context_layout(),
            CtxField::RemoteIp6 | CtxField::LocalIp6 => self.socket_tuple_context_layout(),
            _ => None,
        }?;

        layout.ctx_field_array_load(field)
    }

    pub(crate) fn ctx_field_direct_load(&self, field: &CtxField) -> Option<ContextFieldDirectLoad> {
        if let Some(load) = self.socket_ctx_field_direct_load(field) {
            return Some(load);
        }
        if let Some(load) = self.packet_ctx_field_direct_load(field) {
            return Some(load);
        }

        match (self, field) {
            (Self::FlowDissector, CtxField::FlowKeys) => Some(ContextFieldDirectLoad::u64(144)),
            (Self::Netfilter, CtxField::NetfilterState) => Some(ContextFieldDirectLoad::u64(0)),
            (Self::Netfilter, CtxField::NetfilterSkb) => Some(ContextFieldDirectLoad::u64(8)),
            (Self::SkReuseport, CtxField::BindInany) => Some(ContextFieldDirectLoad::u32(28)),
            (Self::SkReuseport, CtxField::MigratingSocket) => Some(ContextFieldDirectLoad::u64(48)),
            (Self::LircMode2, CtxField::LircSample | CtxField::LircValue | CtxField::LircMode) => {
                Some(ContextFieldDirectLoad::u32(0))
            }
            (
                Self::CgroupDevice,
                CtxField::DeviceAccessType | CtxField::DeviceAccess | CtxField::DeviceType,
            ) => Some(ContextFieldDirectLoad::u32(0)),
            (Self::CgroupDevice, CtxField::DeviceMajor) => Some(ContextFieldDirectLoad::u32(4)),
            (Self::CgroupDevice, CtxField::DeviceMinor) => Some(ContextFieldDirectLoad::u32(8)),
            (Self::SockOps, CtxField::SockOp) => Some(ContextFieldDirectLoad::u32(0)),
            (Self::SockOps, CtxField::SockOpsReply) => Some(ContextFieldDirectLoad::u32(4)),
            (Self::SockOps, CtxField::IsFullsock) => Some(ContextFieldDirectLoad::u32(72)),
            (Self::SockOps, CtxField::SockOpsSndCwnd) => Some(ContextFieldDirectLoad::u32(76)),
            (Self::SockOps, CtxField::SockOpsSrttUs) => Some(ContextFieldDirectLoad::u32(80)),
            (Self::SockOps, CtxField::SockOpsCbFlags) => Some(ContextFieldDirectLoad::u32(84)),
            (Self::SockOps, CtxField::SockOpsRttMin) => Some(ContextFieldDirectLoad::u32(92)),
            (Self::SockOps, CtxField::SockOpsSndSsthresh) => Some(ContextFieldDirectLoad::u32(96)),
            (Self::SockOps, CtxField::SockOpsRcvNxt) => Some(ContextFieldDirectLoad::u32(100)),
            (Self::SockOps, CtxField::SockOpsSndNxt) => Some(ContextFieldDirectLoad::u32(104)),
            (Self::SockOps, CtxField::SockOpsSndUna) => Some(ContextFieldDirectLoad::u32(108)),
            (Self::SockOps, CtxField::SockOpsMssCache) => Some(ContextFieldDirectLoad::u32(112)),
            (Self::SockOps, CtxField::SockOpsEcnFlags) => Some(ContextFieldDirectLoad::u32(116)),
            (Self::SockOps, CtxField::SockOpsRateDelivered) => {
                Some(ContextFieldDirectLoad::u32(120))
            }
            (Self::SockOps, CtxField::SockOpsRateIntervalUs) => {
                Some(ContextFieldDirectLoad::u32(124))
            }
            (Self::SockOps, CtxField::SockOpsPacketsOut) => Some(ContextFieldDirectLoad::u32(128)),
            (Self::SockOps, CtxField::SockOpsRetransOut) => Some(ContextFieldDirectLoad::u32(132)),
            (Self::SockOps, CtxField::SockOpsTotalRetrans) => {
                Some(ContextFieldDirectLoad::u32(136))
            }
            (Self::SockOps, CtxField::SockOpsSegsIn) => Some(ContextFieldDirectLoad::u32(140)),
            (Self::SockOps, CtxField::SockOpsDataSegsIn) => Some(ContextFieldDirectLoad::u32(144)),
            (Self::SockOps, CtxField::SockOpsSegsOut) => Some(ContextFieldDirectLoad::u32(148)),
            (Self::SockOps, CtxField::SockOpsDataSegsOut) => Some(ContextFieldDirectLoad::u32(152)),
            (Self::SockOps, CtxField::SockOpsLostOut) => Some(ContextFieldDirectLoad::u32(156)),
            (Self::SockOps, CtxField::SockOpsSackedOut) => Some(ContextFieldDirectLoad::u32(160)),
            (Self::SockOps, CtxField::SockOpsSkTxhash) => Some(ContextFieldDirectLoad::u32(164)),
            (Self::SockOps, CtxField::SockOpsBytesReceived) => {
                Some(ContextFieldDirectLoad::u64(168))
            }
            (Self::SockOps, CtxField::SockOpsBytesAcked) => Some(ContextFieldDirectLoad::u64(176)),
            (Self::SockOps, CtxField::SockOpsSkbLen) => Some(ContextFieldDirectLoad::u32(208)),
            (Self::SockOps, CtxField::SockOpsSkbTcpFlags) => Some(ContextFieldDirectLoad::u32(212)),
            (Self::SockOps, CtxField::SockOpsSkbHwtstamp) => Some(ContextFieldDirectLoad::u64(216)),
            (Self::CgroupSysctl, CtxField::SysctlWrite) => Some(ContextFieldDirectLoad::u32(0)),
            (Self::CgroupSysctl, CtxField::SysctlFilePos) => Some(ContextFieldDirectLoad::u32(4)),
            (Self::CgroupSockopt, CtxField::SockoptLevel) => Some(ContextFieldDirectLoad::u32(24)),
            (Self::CgroupSockopt, CtxField::SockoptOptname) => {
                Some(ContextFieldDirectLoad::u32(28))
            }
            (Self::CgroupSockopt, CtxField::SockoptOptlen) => Some(ContextFieldDirectLoad::u32(32)),
            (Self::CgroupSockopt, CtxField::SockoptOptval) => Some(ContextFieldDirectLoad::u64(8)),
            (Self::CgroupSockopt, CtxField::SockoptOptvalEnd) => {
                Some(ContextFieldDirectLoad::u64(16))
            }
            (Self::CgroupSockopt, CtxField::SockoptRetval) => Some(ContextFieldDirectLoad::u32(36)),
            _ => None,
        }
    }

    pub(crate) fn ctx_field_array_load(&self, field: &CtxField) -> Option<ContextFieldArrayLoad> {
        if let Some(load) = self.socket_ctx_field_array_load(field) {
            return Some(load);
        }
        if let Some(load) = self.packet_ctx_field_array_load(field) {
            return Some(load);
        }

        match (self, field) {
            (Self::SockOps, CtxField::SockOpsArgs | CtxField::SockOpsReplyLong) => {
                Some(ContextFieldArrayLoad::u32_words(4, 4, false))
            }
            _ => None,
        }
    }

    fn packet_ctx_field_direct_load(&self, field: &CtxField) -> Option<ContextFieldDirectLoad> {
        match field {
            CtxField::DataMeta => self.data_meta_context_kind()?.ctx_field_direct_load(field),
            CtxField::IngressIfindex => match self.ingress_ifindex_context_layout()? {
                IngressIfindexContextLayout::XdpMd => Some(ContextFieldDirectLoad::u32(12)),
                IngressIfindexContextLayout::SkBuff => Some(ContextFieldDirectLoad::u32(36)),
                IngressIfindexContextLayout::SkLookup => Some(ContextFieldDirectLoad::u32(64)),
            },
            _ => self.packet_context_kind()?.ctx_field_direct_load(field),
        }
    }

    fn packet_ctx_field_array_load(&self, field: &CtxField) -> Option<ContextFieldArrayLoad> {
        self.packet_context_kind()?.ctx_field_array_load(field)
    }
}

impl ProgramSpec {
    pub(crate) fn ctx_field_is_raw_context_pointer(&self, field: &CtxField) -> bool {
        self.program_type().ctx_field_is_raw_context_pointer(field)
    }

    pub(crate) fn ctx_field_pointer_is_non_null(&self, field: &CtxField) -> bool {
        self.ctx_field_access_error(field).is_none()
            && self.program_type().ctx_field_pointer_is_non_null(field)
    }

    pub(crate) fn ctx_field_is_trusted_btf_kernel_pointer(&self, field: &CtxField) -> bool {
        self.ctx_field_access_error(field).is_none()
            && self
                .program_type()
                .ctx_field_is_trusted_btf_kernel_pointer(field)
    }

    pub(crate) fn packet_context_kind(&self) -> Option<PacketContextKind> {
        self.program_type().packet_context_kind()
    }

    pub(crate) fn data_meta_context_kind(&self) -> Option<PacketContextKind> {
        self.program_type().data_meta_context_kind()
    }

    pub(crate) fn supports_direct_packet_writes(&self) -> bool {
        self.program_type().supports_direct_packet_writes()
    }

    pub(crate) fn socket_tuple_context_layout(&self) -> Option<SocketContextLayout> {
        self.program_type().socket_tuple_context_layout()
    }

    pub(crate) fn protocol_context_layout(&self) -> Option<SocketContextLayout> {
        self.program_type().protocol_context_layout()
    }

    pub(crate) fn socket_ref_context_layout(&self) -> Option<SocketContextLayout> {
        self.program_type().socket_ref_context_layout()
    }

    pub(crate) fn ctx_field_type_spec(&self, field: &CtxField) -> Option<ContextFieldTypeSpec> {
        self.ctx_field_access_error(field)
            .is_none()
            .then(|| program_type_ctx_field_type_spec(self.program_type(), field))
            .flatten()
    }

    pub(crate) fn ctx_field_projection_spec(
        &self,
        field: &CtxField,
    ) -> Option<ContextFieldProjectionSpec> {
        self.ctx_field_access_error(field)
            .is_none()
            .then(|| program_type_ctx_field_projection_spec(self.program_type(), field))
            .flatten()
    }

    pub(crate) fn ctx_field_load_guard(&self, field: &CtxField) -> Option<ContextFieldLoadGuard> {
        self.ctx_field_access_error(field)
            .is_none()
            .then(|| self.program_type().ctx_field_load_guard(field))
            .flatten()
    }

    pub(crate) fn ctx_field_direct_load(&self, field: &CtxField) -> Option<ContextFieldDirectLoad> {
        if self.ctx_field_access_error(field).is_some() {
            return None;
        }

        self.iter_ctx_field_direct_load(field)
            .or_else(|| self.program_type().ctx_field_direct_load(field))
    }

    pub(crate) fn ctx_field_array_load(&self, field: &CtxField) -> Option<ContextFieldArrayLoad> {
        if self.ctx_field_access_error(field).is_some() {
            return None;
        }

        self.program_type().ctx_field_array_load(field)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_program_context_layout_specs_are_unique_and_consistent() {
        let mut program_types = HashSet::new();

        for spec in PROGRAM_CONTEXT_LAYOUT_SPECS {
            assert!(
                program_types.insert(spec.program_type),
                "duplicate context layout spec for {:?}",
                spec.program_type
            );

            if spec.data_meta.is_some() {
                assert!(
                    spec.packet_context.is_some(),
                    "data_meta layout for {:?} requires a packet context",
                    spec.program_type
                );
            }

            if spec.raw_socket_context_pointer {
                assert!(
                    spec.socket_ref.is_some(),
                    "raw socket context pointer for {:?} requires a socket reference layout",
                    spec.program_type
                );
            }

            if spec.socket_cookie || spec.socket_uid || spec.netns_cookie {
                assert!(
                    spec.socket_ref.is_some(),
                    "socket identity helper fields for {:?} require a socket reference layout",
                    spec.program_type
                );
            }

            if spec.lookup_cookie {
                assert_eq!(
                    spec.program_type,
                    EbpfProgramType::SkLookup,
                    "lookup_cookie should stay tied to sk_lookup layout metadata"
                );
            }

            if spec.sock_ops_load_guards {
                assert_eq!(
                    spec.program_type,
                    EbpfProgramType::SockOps,
                    "sock_ops load guards should stay tied to sock_ops layout metadata"
                );
            }

            let mut non_null_fields = HashSet::new();
            for field in spec.non_null_ctx_fields {
                assert!(
                    non_null_fields.insert(field),
                    "duplicate non-null context field {field:?} for {:?}",
                    spec.program_type
                );
                assert!(
                    spec.program_type
                        .base_ctx_field_access_error(field)
                        .is_none(),
                    "non-null context field {field:?} for {:?} must also be legal",
                    spec.program_type
                );
            }
        }
    }

    #[test]
    fn test_direct_packet_write_programs_are_unique_and_packet_backed() {
        let expected_program_types = HashSet::from([
            EbpfProgramType::Xdp,
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
            EbpfProgramType::LwtXmit,
            EbpfProgramType::SkMsg,
            EbpfProgramType::SkSkb,
            EbpfProgramType::SkSkbParser,
        ]);
        let actual_program_types = PROGRAM_CONTEXT_LAYOUT_SPECS
            .iter()
            .filter(|spec| spec.direct_packet_writes)
            .map(|spec| spec.program_type)
            .collect::<HashSet<_>>();

        assert_eq!(actual_program_types, expected_program_types);

        for program_type in actual_program_types {
            assert!(
                program_type.packet_context_kind().is_some(),
                "direct packet write program {program_type:?} must have a packet context"
            );
            assert!(
                program_type
                    .base_ctx_field_access_error(&CtxField::Data)
                    .is_none(),
                "direct packet write program {program_type:?} must expose ctx.data"
            );
            assert!(
                program_type
                    .base_ctx_field_access_error(&CtxField::DataEnd)
                    .is_none(),
                "direct packet write program {program_type:?} must expose ctx.data_end"
            );
        }
    }

    fn assert_layout_support_matches_field_access(
        program_type: EbpfProgramType,
        supports: bool,
        fields: &[CtxField],
        label: &str,
    ) {
        for field in fields {
            assert_eq!(
                program_type.base_ctx_field_access_error(field).is_none(),
                supports,
                "{program_type:?} {label} layout support should match ctx.{} access",
                field.display_name()
            );
        }
    }

    #[test]
    fn test_program_context_layout_support_matches_base_access_policy() {
        for program_type in EbpfProgramType::supported_program_types() {
            assert_layout_support_matches_field_access(
                *program_type,
                program_type.supports_data_meta_ctx_field(),
                &[CtxField::DataMeta],
                "data_meta",
            );
            assert_layout_support_matches_field_access(
                *program_type,
                program_type.supports_socket_common_ctx_fields(),
                &[CtxField::Family],
                "socket common",
            );
            assert_layout_support_matches_field_access(
                *program_type,
                program_type.supports_socket_tuple_ctx_fields(),
                &[
                    CtxField::RemoteIp4,
                    CtxField::RemoteIp6,
                    CtxField::RemotePort,
                    CtxField::LocalIp4,
                    CtxField::LocalIp6,
                    CtxField::LocalPort,
                ],
                "socket tuple",
            );
            assert_layout_support_matches_field_access(
                *program_type,
                program_type.supports_sock_type_ctx_field(),
                &[CtxField::SockType],
                "sock_type",
            );
            assert_layout_support_matches_field_access(
                *program_type,
                program_type.supports_protocol_ctx_field(),
                &[CtxField::Protocol],
                "protocol",
            );
            assert_layout_support_matches_field_access(
                *program_type,
                program_type.supports_socket_ref_ctx_field(),
                &[CtxField::Socket],
                "socket reference",
            );
            assert_layout_support_matches_field_access(
                *program_type,
                program_type.supports_sock_mark_priority_ctx_fields(),
                &[CtxField::SockMark, CtxField::SockPriority],
                "socket mark/priority",
            );
            assert_layout_support_matches_field_access(
                *program_type,
                program_type.supports_sock_state_ctx_field(),
                &[CtxField::SockState],
                "socket state",
            );
            assert_layout_support_matches_field_access(
                *program_type,
                program_type.supports_socket_cookie_ctx_field(),
                &[CtxField::SocketCookie],
                "socket cookie",
            );
            assert_layout_support_matches_field_access(
                *program_type,
                program_type.supports_socket_uid_ctx_field(),
                &[CtxField::SocketUid],
                "socket uid",
            );
            assert_layout_support_matches_field_access(
                *program_type,
                program_type.supports_netns_cookie_ctx_field(),
                &[CtxField::NetnsCookie],
                "netns cookie",
            );
            assert_layout_support_matches_field_access(
                *program_type,
                program_type.supports_lookup_cookie_ctx_field(),
                &[CtxField::LookupCookie],
                "lookup cookie",
            );
        }
    }

    #[test]
    fn test_socket_context_direct_load_metadata_tracks_layouts() {
        for (spec, field, expected) in [
            (
                "cgroup_sock:/sys/fs/cgroup:sock_create",
                CtxField::BoundDevIf,
                Some(ContextFieldDirectLoad::u32(0)),
            ),
            (
                "cgroup_sock:/sys/fs/cgroup:sock_create",
                CtxField::Family,
                Some(ContextFieldDirectLoad::u32(4)),
            ),
            (
                "cgroup_sock:/sys/fs/cgroup:sock_create",
                CtxField::Protocol,
                Some(ContextFieldDirectLoad::u32(12)),
            ),
            (
                "cgroup_sock:/sys/fs/cgroup:post_bind4",
                CtxField::LocalIp4,
                Some(ContextFieldDirectLoad::u32(24)),
            ),
            (
                "cgroup_sock:/sys/fs/cgroup:post_bind4",
                CtxField::LocalPort,
                Some(ContextFieldDirectLoad::u32(44)),
            ),
            (
                "cgroup_sock:/sys/fs/cgroup:sock_create",
                CtxField::RemotePort,
                Some(ContextFieldDirectLoad::u16(48)),
            ),
            (
                "cgroup_sock:/sys/fs/cgroup:sock_create",
                CtxField::RemoteIp4,
                Some(ContextFieldDirectLoad::u32(52)),
            ),
            (
                "cgroup_sock:/sys/fs/cgroup:sock_create",
                CtxField::Socket,
                None,
            ),
            (
                "cgroup_sock:/sys/fs/cgroup:sock_create",
                CtxField::SockState,
                Some(ContextFieldDirectLoad::u32(72)),
            ),
            (
                "cgroup_sock:/sys/fs/cgroup:sock_create",
                CtxField::SockRxQueueMapping,
                Some(ContextFieldDirectLoad::u32(76)),
            ),
            (
                "cgroup_sock_addr:/sys/fs/cgroup:connect4",
                CtxField::UserFamily,
                Some(ContextFieldDirectLoad::u32(0)),
            ),
            (
                "cgroup_sock_addr:/sys/fs/cgroup:connect4",
                CtxField::UserIp4,
                Some(ContextFieldDirectLoad::u32(4)),
            ),
            (
                "cgroup_sock_addr:/sys/fs/cgroup:connect4",
                CtxField::UserPort,
                Some(ContextFieldDirectLoad::u32(24)),
            ),
            (
                "cgroup_sock_addr:/sys/fs/cgroup:connect4",
                CtxField::SockType,
                Some(ContextFieldDirectLoad::u32(32)),
            ),
            (
                "cgroup_sock_addr:/sys/fs/cgroup:sendmsg4",
                CtxField::MsgSrcIp4,
                Some(ContextFieldDirectLoad::u32(40)),
            ),
            (
                "cgroup_sock_addr:/sys/fs/cgroup:connect4",
                CtxField::Socket,
                Some(ContextFieldDirectLoad::u64(64)),
            ),
            (
                "cgroup_sockopt:/sys/fs/cgroup:get",
                CtxField::Socket,
                Some(ContextFieldDirectLoad::u64(0)),
            ),
            (
                "sk_lookup:/proc/self/ns/net",
                CtxField::LookupCookie,
                Some(ContextFieldDirectLoad::u64(0)),
            ),
            (
                "sk_lookup:/proc/self/ns/net",
                CtxField::RemoteIp4,
                Some(ContextFieldDirectLoad::u32(16)),
            ),
            (
                "sk_lookup:/proc/self/ns/net",
                CtxField::RemotePort,
                Some(ContextFieldDirectLoad::u16(36)),
            ),
            (
                "sk_lookup:/proc/self/ns/net",
                CtxField::LocalIp4,
                Some(ContextFieldDirectLoad::u32(40)),
            ),
            (
                "sk_lookup:/proc/self/ns/net",
                CtxField::LocalPort,
                Some(ContextFieldDirectLoad::u32(60)),
            ),
            (
                "sk_msg:/sys/fs/bpf/demo",
                CtxField::Family,
                Some(ContextFieldDirectLoad::u32(16)),
            ),
            (
                "sk_msg:/sys/fs/bpf/demo",
                CtxField::RemotePort,
                Some(ContextFieldDirectLoad::u32(60)),
            ),
            (
                "sk_msg:/sys/fs/bpf/demo",
                CtxField::LocalPort,
                Some(ContextFieldDirectLoad::u32(64)),
            ),
            (
                "sk_msg:/sys/fs/bpf/demo",
                CtxField::Socket,
                Some(ContextFieldDirectLoad::u64(72)),
            ),
            ("sk_msg:/sys/fs/bpf/demo", CtxField::SockPriority, None),
            (
                "sock_ops:/sys/fs/cgroup",
                CtxField::Family,
                Some(ContextFieldDirectLoad::u32(20)),
            ),
            (
                "sock_ops:/sys/fs/cgroup",
                CtxField::RemotePort,
                Some(ContextFieldDirectLoad::u16(64)),
            ),
            (
                "sock_ops:/sys/fs/cgroup",
                CtxField::LocalPort,
                Some(ContextFieldDirectLoad::u32(68)),
            ),
            (
                "sock_ops:/sys/fs/cgroup",
                CtxField::SockState,
                Some(ContextFieldDirectLoad::u32(88)),
            ),
            (
                "socket_filter:tcp4:127.0.0.1:80",
                CtxField::Socket,
                Some(ContextFieldDirectLoad::u64(168)),
            ),
            (
                "socket_filter:tcp4:127.0.0.1:80",
                CtxField::Protocol,
                Some(ContextFieldDirectLoad::u16(16)),
            ),
            (
                "cgroup_skb:/sys/fs/cgroup:egress",
                CtxField::RemotePort,
                Some(ContextFieldDirectLoad::u32(132)),
            ),
            (
                "cgroup_skb:/sys/fs/cgroup:egress",
                CtxField::LocalPort,
                Some(ContextFieldDirectLoad::u32(136)),
            ),
            (
                "cgroup_skb:/sys/fs/cgroup:ingress",
                CtxField::SockMark,
                Some(ContextFieldDirectLoad::u32(8)),
            ),
            (
                "sk_reuseport:select",
                CtxField::Socket,
                Some(ContextFieldDirectLoad::u64(40)),
            ),
            (
                "sk_reuseport:select",
                CtxField::Protocol,
                Some(ContextFieldDirectLoad::u32(24)),
            ),
        ] {
            let spec = ProgramSpec::parse(spec).expect("program spec should parse");
            assert_eq!(spec.ctx_field_direct_load(&field), expected);
        }
    }

    #[test]
    fn test_simple_context_direct_load_metadata_tracks_program_layouts() {
        for (spec, field, expected) in [
            (
                "flow_dissector:/proc/self/ns/net",
                CtxField::FlowKeys,
                Some(ContextFieldDirectLoad::u64(144)),
            ),
            (
                "netfilter:ipv4:pre_routing:priority=-100:defrag",
                CtxField::NetfilterState,
                Some(ContextFieldDirectLoad::u64(0)),
            ),
            (
                "netfilter:ipv4:pre_routing:priority=-100:defrag",
                CtxField::NetfilterSkb,
                Some(ContextFieldDirectLoad::u64(8)),
            ),
            (
                "sk_reuseport:select",
                CtxField::BindInany,
                Some(ContextFieldDirectLoad::u32(28)),
            ),
            (
                "sk_reuseport:migrate",
                CtxField::MigratingSocket,
                Some(ContextFieldDirectLoad::u64(48)),
            ),
            (
                "lirc_mode2:/dev/lirc0",
                CtxField::LircValue,
                Some(ContextFieldDirectLoad::u32(0)),
            ),
            (
                "cgroup_device:/sys/fs/cgroup",
                CtxField::DeviceAccess,
                Some(ContextFieldDirectLoad::u32(0)),
            ),
            (
                "cgroup_device:/sys/fs/cgroup",
                CtxField::DeviceMajor,
                Some(ContextFieldDirectLoad::u32(4)),
            ),
            (
                "cgroup_device:/sys/fs/cgroup",
                CtxField::DeviceMinor,
                Some(ContextFieldDirectLoad::u32(8)),
            ),
            (
                "sock_ops:/sys/fs/cgroup",
                CtxField::SockOp,
                Some(ContextFieldDirectLoad::u32(0)),
            ),
            (
                "sock_ops:/sys/fs/cgroup",
                CtxField::SockOpsSndCwnd,
                Some(ContextFieldDirectLoad::u32(76)),
            ),
            (
                "sock_ops:/sys/fs/cgroup",
                CtxField::SockOpsBytesReceived,
                Some(ContextFieldDirectLoad::u64(168)),
            ),
            (
                "sock_ops:/sys/fs/cgroup",
                CtxField::SockOpsSkbHwtstamp,
                Some(ContextFieldDirectLoad::u64(216)),
            ),
            (
                "cgroup_sysctl:/sys/fs/cgroup",
                CtxField::SysctlWrite,
                Some(ContextFieldDirectLoad::u32(0)),
            ),
            (
                "cgroup_sysctl:/sys/fs/cgroup",
                CtxField::SysctlFilePos,
                Some(ContextFieldDirectLoad::u32(4)),
            ),
            (
                "cgroup_sockopt:/sys/fs/cgroup:get",
                CtxField::SockoptLevel,
                Some(ContextFieldDirectLoad::u32(24)),
            ),
            (
                "cgroup_sockopt:/sys/fs/cgroup:get",
                CtxField::SockoptOptval,
                Some(ContextFieldDirectLoad::u64(8)),
            ),
            (
                "cgroup_sockopt:/sys/fs/cgroup:get",
                CtxField::SockoptRetval,
                Some(ContextFieldDirectLoad::u32(36)),
            ),
            (
                "cgroup_sockopt:/sys/fs/cgroup:set",
                CtxField::SockoptRetval,
                None,
            ),
        ] {
            let spec = ProgramSpec::parse(spec).expect("program spec should parse");
            assert_eq!(spec.ctx_field_direct_load(&field), expected);
        }
    }

    #[test]
    fn test_packet_context_direct_load_metadata_tracks_layouts() {
        for (spec, field, expected) in [
            ("xdp:lo", CtxField::PacketLen, None),
            (
                "xdp:lo",
                CtxField::Data,
                Some(ContextFieldDirectLoad::u32(0)),
            ),
            (
                "xdp:lo",
                CtxField::DataMeta,
                Some(ContextFieldDirectLoad::u32(8)),
            ),
            (
                "xdp:lo",
                CtxField::IngressIfindex,
                Some(ContextFieldDirectLoad::u32(12)),
            ),
            (
                "xdp:lo",
                CtxField::RxQueueIndex,
                Some(ContextFieldDirectLoad::u32(16)),
            ),
            (
                "tc:lo:ingress",
                CtxField::PacketLen,
                Some(ContextFieldDirectLoad::u32(0)),
            ),
            (
                "tc:lo:ingress",
                CtxField::Data,
                Some(ContextFieldDirectLoad::u32(76)),
            ),
            (
                "tc:lo:ingress",
                CtxField::EthProtocol,
                Some(ContextFieldDirectLoad::u16(16)),
            ),
            (
                "tc:lo:ingress",
                CtxField::DataMeta,
                Some(ContextFieldDirectLoad::u32(140)),
            ),
            (
                "tc:lo:ingress",
                CtxField::VlanProto,
                Some(ContextFieldDirectLoad::u16(28)),
            ),
            (
                "tc:lo:ingress",
                CtxField::TstampType,
                Some(ContextFieldDirectLoad::u8(180)),
            ),
            (
                "tc:lo:ingress",
                CtxField::Hwtstamp,
                Some(ContextFieldDirectLoad::u64(184)),
            ),
            (
                "cgroup_skb:/sys/fs/cgroup:ingress",
                CtxField::DataMeta,
                None,
            ),
            (
                "sk_lookup:/proc/self/ns/net",
                CtxField::IngressIfindex,
                Some(ContextFieldDirectLoad::u32(64)),
            ),
            (
                "sk_msg:/sys/fs/bpf/demo",
                CtxField::Data,
                Some(ContextFieldDirectLoad::u64(0)),
            ),
            (
                "sk_msg:/sys/fs/bpf/demo",
                CtxField::PacketLen,
                Some(ContextFieldDirectLoad::u32(68)),
            ),
            (
                "sock_ops:/sys/fs/cgroup",
                CtxField::Data,
                Some(ContextFieldDirectLoad::u64(192)),
            ),
            (
                "sock_ops:/sys/fs/cgroup",
                CtxField::PacketLen,
                Some(ContextFieldDirectLoad::u32(208)),
            ),
            (
                "sk_reuseport:select",
                CtxField::DataEnd,
                Some(ContextFieldDirectLoad::u64(8)),
            ),
            (
                "sk_reuseport:select",
                CtxField::EthProtocol,
                Some(ContextFieldDirectLoad::u16(20)),
            ),
            (
                "sk_reuseport:select",
                CtxField::PacketLen,
                Some(ContextFieldDirectLoad::u32(16)),
            ),
            (
                "sk_reuseport:select",
                CtxField::SkbHash,
                Some(ContextFieldDirectLoad::u32(32)),
            ),
        ] {
            let spec = ProgramSpec::parse(spec).expect("program spec should parse");
            assert_eq!(spec.ctx_field_direct_load(&field), expected);
        }
    }

    #[test]
    fn test_context_array_load_metadata_tracks_layouts() {
        for (spec, field, expected) in [
            (
                "tc:lo:ingress",
                CtxField::SkbCb,
                Some(ContextFieldArrayLoad::u32_words(48, 5, false)),
            ),
            ("xdp:lo", CtxField::SkbCb, None),
            (
                "cgroup_sock_addr:/sys/fs/cgroup:connect6",
                CtxField::UserIp6,
                Some(ContextFieldArrayLoad::u32_words(8, 4, false)),
            ),
            (
                "cgroup_sock_addr:/sys/fs/cgroup:sendmsg6",
                CtxField::MsgSrcIp6,
                Some(ContextFieldArrayLoad::u32_words(44, 4, false)),
            ),
            (
                "cgroup_sock_addr:/sys/fs/cgroup:connect4",
                CtxField::UserIp6,
                None,
            ),
            (
                "cgroup_sock:/sys/fs/cgroup:post_bind6",
                CtxField::LocalIp6,
                Some(ContextFieldArrayLoad::u32_words(28, 4, true)),
            ),
            (
                "cgroup_sock:/sys/fs/cgroup:sock_create",
                CtxField::RemoteIp6,
                Some(ContextFieldArrayLoad::u32_words(56, 4, true)),
            ),
            (
                "sk_lookup:/proc/self/ns/net",
                CtxField::RemoteIp6,
                Some(ContextFieldArrayLoad::u32_words(20, 4, true)),
            ),
            (
                "sk_lookup:/proc/self/ns/net",
                CtxField::LocalIp6,
                Some(ContextFieldArrayLoad::u32_words(44, 4, true)),
            ),
            (
                "sk_msg:/sys/fs/bpf/demo",
                CtxField::RemoteIp6,
                Some(ContextFieldArrayLoad::u32_words(28, 4, true)),
            ),
            (
                "sk_msg:/sys/fs/bpf/demo",
                CtxField::LocalIp6,
                Some(ContextFieldArrayLoad::u32_words(44, 4, true)),
            ),
            (
                "cgroup_skb:/sys/fs/cgroup:egress",
                CtxField::RemoteIp6,
                Some(ContextFieldArrayLoad::u32_words(100, 4, true)),
            ),
            (
                "cgroup_skb:/sys/fs/cgroup:egress",
                CtxField::LocalIp6,
                Some(ContextFieldArrayLoad::u32_words(116, 4, true)),
            ),
            (
                "sock_ops:/sys/fs/cgroup",
                CtxField::SockOpsArgs,
                Some(ContextFieldArrayLoad::u32_words(4, 4, false)),
            ),
            (
                "sock_ops:/sys/fs/cgroup",
                CtxField::SockOpsReplyLong,
                Some(ContextFieldArrayLoad::u32_words(4, 4, false)),
            ),
            (
                "sock_ops:/sys/fs/cgroup",
                CtxField::RemoteIp6,
                Some(ContextFieldArrayLoad::u32_words(32, 4, true)),
            ),
            (
                "sock_ops:/sys/fs/cgroup",
                CtxField::LocalIp6,
                Some(ContextFieldArrayLoad::u32_words(48, 4, true)),
            ),
            ("sk_reuseport:select", CtxField::RemoteIp6, None),
        ] {
            let spec = ProgramSpec::parse(spec).expect("program spec should parse");
            assert_eq!(spec.ctx_field_array_load(&field), expected);
        }
    }
}
