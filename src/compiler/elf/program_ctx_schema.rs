use super::{
    CtxField, EbpfProgramType, IngressIfindexContextLayout, PacketContextKind,
    ProgramContextFamily, SocketContextLayout,
};
use crate::compiler::ctx_field_schema::{
    ContextFieldLoadGuard, ContextFieldProjectionSpec, ContextFieldTypeSpec,
    program_type_ctx_field_load_guard, program_type_ctx_field_projection_spec,
    program_type_ctx_field_type_spec,
};
use crate::program_spec::ProgramSpec;

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
        match self {
            EbpfProgramType::Xdp => Some(PacketContextKind::XdpMd),
            EbpfProgramType::Tc => Some(PacketContextKind::SkBuff),
            _ => None,
        }
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
        match self {
            EbpfProgramType::CgroupSock => Some(SocketContextLayout::CgroupSock),
            EbpfProgramType::CgroupSockAddr => Some(SocketContextLayout::SockAddr),
            EbpfProgramType::SkLookup => Some(SocketContextLayout::SkLookup),
            EbpfProgramType::SkMsg => Some(SocketContextLayout::SkMsg),
            EbpfProgramType::SkSkb | EbpfProgramType::SkSkbParser => {
                Some(SocketContextLayout::SkBuff)
            }
            EbpfProgramType::SockOps => Some(SocketContextLayout::SockOps),
            _ => None,
        }
    }

    pub(crate) fn socket_tuple_context_layout(&self) -> Option<SocketContextLayout> {
        match self {
            EbpfProgramType::SkLookup => Some(SocketContextLayout::SkLookup),
            EbpfProgramType::SkMsg => Some(SocketContextLayout::SkMsg),
            EbpfProgramType::SkSkb | EbpfProgramType::SkSkbParser => {
                Some(SocketContextLayout::SkBuff)
            }
            EbpfProgramType::SockOps => Some(SocketContextLayout::SockOps),
            _ => None,
        }
    }

    pub(crate) fn sock_type_context_layout(&self) -> Option<SocketContextLayout> {
        match self {
            EbpfProgramType::CgroupSock => Some(SocketContextLayout::CgroupSock),
            EbpfProgramType::CgroupSockAddr => Some(SocketContextLayout::SockAddr),
            _ => None,
        }
    }

    pub(crate) fn protocol_context_layout(&self) -> Option<SocketContextLayout> {
        match self {
            EbpfProgramType::CgroupSock => Some(SocketContextLayout::CgroupSock),
            EbpfProgramType::CgroupSockAddr => Some(SocketContextLayout::SockAddr),
            EbpfProgramType::SkLookup => Some(SocketContextLayout::SkLookup),
            _ => None,
        }
    }

    pub(crate) fn socket_ref_context_layout(&self) -> Option<SocketContextLayout> {
        match self {
            EbpfProgramType::SocketFilter
            | EbpfProgramType::Tc
            | EbpfProgramType::CgroupSkb
            | EbpfProgramType::SkSkb
            | EbpfProgramType::SkSkbParser => Some(SocketContextLayout::SkBuff),
            EbpfProgramType::CgroupSock => Some(SocketContextLayout::CgroupSock),
            EbpfProgramType::CgroupSockAddr => Some(SocketContextLayout::SockAddr),
            EbpfProgramType::CgroupSockopt => Some(SocketContextLayout::CgroupSockopt),
            EbpfProgramType::SkLookup => Some(SocketContextLayout::SkLookup),
            EbpfProgramType::SkMsg => Some(SocketContextLayout::SkMsg),
            EbpfProgramType::SockOps => Some(SocketContextLayout::SockOps),
            _ => None,
        }
    }

    pub(crate) fn ingress_ifindex_context_layout(&self) -> Option<IngressIfindexContextLayout> {
        match self {
            EbpfProgramType::Xdp => Some(IngressIfindexContextLayout::XdpMd),
            EbpfProgramType::SocketFilter
            | EbpfProgramType::Tc
            | EbpfProgramType::CgroupSkb
            | EbpfProgramType::SkSkb
            | EbpfProgramType::SkSkbParser => Some(IngressIfindexContextLayout::SkBuff),
            EbpfProgramType::SkLookup => Some(IngressIfindexContextLayout::SkLookup),
            _ => None,
        }
    }

    pub(crate) fn sock_mark_priority_context_layout(&self) -> Option<SocketContextLayout> {
        match self {
            EbpfProgramType::CgroupSock => Some(SocketContextLayout::CgroupSock),
            EbpfProgramType::SocketFilter
            | EbpfProgramType::Tc
            | EbpfProgramType::CgroupSkb
            | EbpfProgramType::SkSkb
            | EbpfProgramType::SkSkbParser => Some(SocketContextLayout::SkBuff),
            _ => None,
        }
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

    pub fn supports_socket_cookie_ctx_field(&self) -> bool {
        matches!(
            self,
            EbpfProgramType::SocketFilter
                | EbpfProgramType::Tc
                | EbpfProgramType::CgroupSkb
                | EbpfProgramType::CgroupSock
                | EbpfProgramType::CgroupSockAddr
                | EbpfProgramType::SkSkb
                | EbpfProgramType::SkSkbParser
                | EbpfProgramType::SockOps
        )
    }

    pub fn supports_socket_uid_ctx_field(&self) -> bool {
        matches!(
            self,
            EbpfProgramType::SocketFilter
                | EbpfProgramType::Tc
                | EbpfProgramType::CgroupSkb
                | EbpfProgramType::SkSkb
                | EbpfProgramType::SkSkbParser
        )
    }

    pub fn supports_netns_cookie_ctx_field(&self) -> bool {
        matches!(
            self,
            EbpfProgramType::SocketFilter
                | EbpfProgramType::Tc
                | EbpfProgramType::CgroupSkb
                | EbpfProgramType::CgroupSock
                | EbpfProgramType::CgroupSockopt
                | EbpfProgramType::CgroupSockAddr
                | EbpfProgramType::SkMsg
                | EbpfProgramType::SockOps
        )
    }

    pub fn supports_lookup_cookie_ctx_field(&self) -> bool {
        matches!(self, EbpfProgramType::SkLookup)
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
            || matches!(
                (self, field),
                (EbpfProgramType::CgroupSock, CtxField::Socket)
            )
    }

    pub(crate) fn ctx_field_load_guard(&self, field: &CtxField) -> Option<ContextFieldLoadGuard> {
        program_type_ctx_field_load_guard(*self, field)
    }
}

impl ProgramSpec {
    pub(crate) fn ctx_field_is_raw_context_pointer(&self, field: &CtxField) -> bool {
        self.program_type().ctx_field_is_raw_context_pointer(field)
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

    pub(crate) fn ctx_field_type_spec(&self, field: &CtxField) -> Option<ContextFieldTypeSpec> {
        program_type_ctx_field_type_spec(self.program_type(), field)
    }

    pub(crate) fn ctx_field_projection_spec(
        &self,
        field: &CtxField,
    ) -> Option<ContextFieldProjectionSpec> {
        program_type_ctx_field_projection_spec(self.program_type(), field)
    }

    pub(crate) fn ctx_field_load_guard(&self, field: &CtxField) -> Option<ContextFieldLoadGuard> {
        self.program_type().ctx_field_load_guard(field)
    }
}
