use super::{
    CtxField, EbpfProgramType, IngressIfindexContextLayout, PacketContextKind,
    ProgramContextFamily, SocketContextLayout,
};
use crate::compiler::ctx_field_schema::{
    ContextFieldLoadGuard, ContextFieldProjectionSpec, ContextFieldTypeSpec,
    ctx_field_sock_ops_load_guard, program_type_ctx_field_pointer_is_non_null,
    program_type_ctx_field_projection_spec, program_type_ctx_field_type_spec,
};
use crate::program_spec::ProgramSpec;

fn context_family_ctx_field_load_guard(
    context_family: ProgramContextFamily,
    field: &CtxField,
) -> Option<ContextFieldLoadGuard> {
    match context_family {
        ProgramContextFamily::SockOps => {
            ctx_field_sock_ops_load_guard(field).map(ContextFieldLoadGuard::SockOpsCallback)
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProgramContextLayoutSpec {
    program_type: EbpfProgramType,
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
        }
    }
}

const PROGRAM_CONTEXT_LAYOUT_SPECS: &[ProgramContextLayoutSpec] = &[
    ProgramContextLayoutSpec {
        program_type: EbpfProgramType::Xdp,
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
    },
    ProgramContextLayoutSpec::skb_backed(EbpfProgramType::SocketFilter, None, None, true),
    ProgramContextLayoutSpec::skb_backed(
        EbpfProgramType::Tc,
        Some(PacketContextKind::SkBuff),
        None,
        true,
    ),
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
    ),
    ProgramContextLayoutSpec::skb_backed(
        EbpfProgramType::SkSkbParser,
        None,
        Some(SocketContextLayout::SkBuff),
        false,
    ),
    ProgramContextLayoutSpec {
        program_type: EbpfProgramType::CgroupSock,
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
    },
    ProgramContextLayoutSpec {
        program_type: EbpfProgramType::CgroupSockAddr,
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
    },
    ProgramContextLayoutSpec {
        program_type: EbpfProgramType::CgroupSockopt,
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
    },
    ProgramContextLayoutSpec {
        program_type: EbpfProgramType::SkLookup,
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
    },
    ProgramContextLayoutSpec {
        program_type: EbpfProgramType::SkMsg,
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
    },
    ProgramContextLayoutSpec {
        program_type: EbpfProgramType::SockOps,
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
    },
];

fn program_context_layout_spec(
    program_type: EbpfProgramType,
) -> Option<&'static ProgramContextLayoutSpec> {
    PROGRAM_CONTEXT_LAYOUT_SPECS
        .iter()
        .find(|spec| spec.program_type == program_type)
}

impl EbpfProgramType {
    pub fn supports_tracepoint_fields(&self) -> bool {
        self.info().supports_tracepoint_fields
    }

    pub fn supports_task_ctx_fields(&self) -> bool {
        self.info().supports_task_ctx_fields
    }

    pub fn supports_cpu_ctx_field(&self) -> bool {
        self.info().supports_cpu_ctx_field
    }

    pub fn supports_timestamp_ctx_field(&self) -> bool {
        self.info().supports_timestamp_ctx_field
    }

    pub fn supports_stack_ctx_fields(&self) -> bool {
        self.info().supports_stack_ctx_fields
    }

    pub fn supports_xdp_md_ctx_fields(&self) -> bool {
        self.info().supports_xdp_md_ctx_fields
    }

    pub fn packet_context_kind(&self) -> Option<PacketContextKind> {
        self.info().packet_context_kind
    }

    pub(crate) fn data_meta_context_kind(&self) -> Option<PacketContextKind> {
        program_context_layout_spec(*self).and_then(|spec| spec.data_meta)
    }

    pub fn supports_packet_len_ctx_field(&self) -> bool {
        self.info().supports_packet_len_ctx_field
    }

    pub fn supports_packet_data_ctx_fields(&self) -> bool {
        self.info().supports_packet_data_ctx_fields
    }

    pub fn supports_data_meta_ctx_field(&self) -> bool {
        self.data_meta_context_kind().is_some()
    }

    pub fn supports_direct_packet_writes(&self) -> bool {
        self.info().supports_direct_packet_writes
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

    pub fn supports_ingress_ifindex_ctx_field(&self) -> bool {
        self.info().supports_ingress_ifindex_ctx_field
    }

    pub fn supports_rx_queue_index_ctx_field(&self) -> bool {
        self.info().supports_rx_queue_index_ctx_field
    }

    pub fn supports_egress_ifindex_ctx_field(&self) -> bool {
        self.info().supports_egress_ifindex_ctx_field
    }

    pub fn supports_skb_ctx_fields(&self) -> bool {
        matches!(self.context_family(), ProgramContextFamily::SkBuffPacket)
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
        matches!(self.context_family(), ProgramContextFamily::PerfEvent)
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

    pub fn supports_cgroup_sock_ctx_fields(&self) -> bool {
        matches!(self.context_family(), ProgramContextFamily::CgroupSock)
    }

    pub fn supports_cgroup_sock_addr_ctx_fields(&self) -> bool {
        matches!(self.context_family(), ProgramContextFamily::CgroupSockAddr)
    }

    pub fn supports_cgroup_sockopt_ctx_fields(&self) -> bool {
        matches!(self.context_family(), ProgramContextFamily::CgroupSockopt)
    }

    pub fn supports_cgroup_sysctl_ctx_fields(&self) -> bool {
        matches!(self.context_family(), ProgramContextFamily::CgroupSysctl)
    }

    pub fn supports_device_ctx_fields(&self) -> bool {
        matches!(self.context_family(), ProgramContextFamily::CgroupDevice)
    }

    pub fn supports_sock_ops_ctx_fields(&self) -> bool {
        matches!(self.context_family(), ProgramContextFamily::SockOps)
    }

    pub fn supports_lirc_ctx_fields(&self) -> bool {
        matches!(self.context_family(), ProgramContextFamily::LircMode2)
    }

    pub(crate) fn ctx_field_is_raw_context_pointer(&self, field: &CtxField) -> bool {
        matches!(field, CtxField::Context)
            || (matches!(field, CtxField::Socket)
                && program_context_layout_spec(*self)
                    .is_some_and(|spec| spec.raw_socket_context_pointer))
    }

    #[cfg(test)]
    pub(crate) fn ctx_field_pointer_is_non_null(&self, field: &CtxField) -> bool {
        self.ctx_field_is_raw_context_pointer(field)
            || program_type_ctx_field_pointer_is_non_null(*self, field)
    }

    pub(crate) fn ctx_field_load_guard(&self, field: &CtxField) -> Option<ContextFieldLoadGuard> {
        context_family_ctx_field_load_guard(self.context_family(), field)
    }
}

impl ProgramSpec {
    pub(crate) fn ctx_field_is_raw_context_pointer(&self, field: &CtxField) -> bool {
        self.program_type().ctx_field_is_raw_context_pointer(field)
    }

    pub(crate) fn ctx_field_pointer_is_non_null(&self, field: &CtxField) -> bool {
        self.ctx_field_access_error(field).is_none()
            && (self.ctx_field_is_raw_context_pointer(field)
                || program_type_ctx_field_pointer_is_non_null(self.program_type(), field))
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

    pub(crate) fn socket_family_context_layout(&self) -> Option<SocketContextLayout> {
        self.program_type().socket_family_context_layout()
    }

    pub(crate) fn socket_tuple_context_layout(&self) -> Option<SocketContextLayout> {
        self.program_type().socket_tuple_context_layout()
    }

    pub(crate) fn sock_type_context_layout(&self) -> Option<SocketContextLayout> {
        self.program_type().sock_type_context_layout()
    }

    pub(crate) fn protocol_context_layout(&self) -> Option<SocketContextLayout> {
        self.program_type().protocol_context_layout()
    }

    pub(crate) fn socket_ref_context_layout(&self) -> Option<SocketContextLayout> {
        self.program_type().socket_ref_context_layout()
    }

    pub(crate) fn ingress_ifindex_context_layout(&self) -> Option<IngressIfindexContextLayout> {
        self.program_type().ingress_ifindex_context_layout()
    }

    pub(crate) fn sock_mark_priority_context_layout(&self) -> Option<SocketContextLayout> {
        self.program_type().sock_mark_priority_context_layout()
    }

    pub(crate) fn sock_state_context_layout(&self) -> Option<SocketContextLayout> {
        self.program_type().sock_state_context_layout()
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
}
