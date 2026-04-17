use super::{
    CtxField, EbpfProgramType, IngressIfindexContextLayout, PacketContextKind,
    ProgramContextFamily, SocketContextLayout,
};
use crate::compiler::ctx_field_schema::{
    ContextFieldLoadGuard, ContextFieldProjectionSpec, ContextFieldTypeSpec,
    ctx_field_sock_ops_load_guard, program_type_ctx_field_projection_spec,
    program_type_ctx_field_type_spec,
};
use crate::program_spec::ProgramSpec;

type ProgramTypeLayoutSurfaceSpec<T> = (&'static [EbpfProgramType], T);

const XDP_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::Xdp];
const TC_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::Tc];
const SK_BUFF_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::SocketFilter,
    EbpfProgramType::Tc,
    EbpfProgramType::CgroupSkb,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkSkbParser,
];
const SK_SKB_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::SkSkb, EbpfProgramType::SkSkbParser];
const CGROUP_SOCK_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::CgroupSock];
const CGROUP_SOCK_ADDR_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::CgroupSockAddr];
const CGROUP_SOCKOPT_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::CgroupSockopt];
const SK_LOOKUP_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::SkLookup];
const SK_MSG_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::SkMsg];
const SOCK_OPS_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::SockOps];
const SOCKET_COOKIE_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::SocketFilter,
    EbpfProgramType::Tc,
    EbpfProgramType::CgroupSkb,
    EbpfProgramType::CgroupSock,
    EbpfProgramType::CgroupSockAddr,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkSkbParser,
    EbpfProgramType::SockOps,
];
const SOCKET_UID_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::SocketFilter,
    EbpfProgramType::Tc,
    EbpfProgramType::CgroupSkb,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkSkbParser,
];
const NETNS_COOKIE_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::SocketFilter,
    EbpfProgramType::Tc,
    EbpfProgramType::CgroupSkb,
    EbpfProgramType::CgroupSock,
    EbpfProgramType::CgroupSockopt,
    EbpfProgramType::CgroupSockAddr,
    EbpfProgramType::SkMsg,
    EbpfProgramType::SockOps,
];
const LOOKUP_COOKIE_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::SkLookup];

const DATA_META_CONTEXT_KIND_SURFACES: &[ProgramTypeLayoutSurfaceSpec<PacketContextKind>] = &[
    (XDP_PROGRAMS, PacketContextKind::XdpMd),
    (TC_PROGRAMS, PacketContextKind::SkBuff),
];
const SOCKET_FAMILY_CONTEXT_LAYOUT_SURFACES: &[ProgramTypeLayoutSurfaceSpec<
    SocketContextLayout,
>] = &[
    (CGROUP_SOCK_PROGRAMS, SocketContextLayout::CgroupSock),
    (CGROUP_SOCK_ADDR_PROGRAMS, SocketContextLayout::SockAddr),
    (SK_LOOKUP_PROGRAMS, SocketContextLayout::SkLookup),
    (SK_MSG_PROGRAMS, SocketContextLayout::SkMsg),
    (SK_SKB_PROGRAMS, SocketContextLayout::SkBuff),
    (SOCK_OPS_PROGRAMS, SocketContextLayout::SockOps),
];
const SOCKET_TUPLE_CONTEXT_LAYOUT_SURFACES: &[ProgramTypeLayoutSurfaceSpec<SocketContextLayout>] =
    &[
        (SK_LOOKUP_PROGRAMS, SocketContextLayout::SkLookup),
        (SK_MSG_PROGRAMS, SocketContextLayout::SkMsg),
        (SK_SKB_PROGRAMS, SocketContextLayout::SkBuff),
        (SOCK_OPS_PROGRAMS, SocketContextLayout::SockOps),
    ];
const SOCK_TYPE_CONTEXT_LAYOUT_SURFACES: &[ProgramTypeLayoutSurfaceSpec<SocketContextLayout>] = &[
    (CGROUP_SOCK_PROGRAMS, SocketContextLayout::CgroupSock),
    (CGROUP_SOCK_ADDR_PROGRAMS, SocketContextLayout::SockAddr),
];
const PROTOCOL_CONTEXT_LAYOUT_SURFACES: &[ProgramTypeLayoutSurfaceSpec<SocketContextLayout>] = &[
    (CGROUP_SOCK_PROGRAMS, SocketContextLayout::CgroupSock),
    (CGROUP_SOCK_ADDR_PROGRAMS, SocketContextLayout::SockAddr),
    (SK_LOOKUP_PROGRAMS, SocketContextLayout::SkLookup),
];
const SOCKET_REF_CONTEXT_LAYOUT_SURFACES: &[ProgramTypeLayoutSurfaceSpec<SocketContextLayout>] = &[
    (SK_BUFF_PROGRAMS, SocketContextLayout::SkBuff),
    (CGROUP_SOCK_PROGRAMS, SocketContextLayout::CgroupSock),
    (CGROUP_SOCK_ADDR_PROGRAMS, SocketContextLayout::SockAddr),
    (CGROUP_SOCKOPT_PROGRAMS, SocketContextLayout::CgroupSockopt),
    (SK_LOOKUP_PROGRAMS, SocketContextLayout::SkLookup),
    (SK_MSG_PROGRAMS, SocketContextLayout::SkMsg),
    (SOCK_OPS_PROGRAMS, SocketContextLayout::SockOps),
];
const INGRESS_IFINDEX_CONTEXT_LAYOUT_SURFACES: &[ProgramTypeLayoutSurfaceSpec<
    IngressIfindexContextLayout,
>] = &[
    (XDP_PROGRAMS, IngressIfindexContextLayout::XdpMd),
    (SK_BUFF_PROGRAMS, IngressIfindexContextLayout::SkBuff),
    (SK_LOOKUP_PROGRAMS, IngressIfindexContextLayout::SkLookup),
];
const SOCK_MARK_PRIORITY_CONTEXT_LAYOUT_SURFACES: &[ProgramTypeLayoutSurfaceSpec<
    SocketContextLayout,
>] = &[
    (CGROUP_SOCK_PROGRAMS, SocketContextLayout::CgroupSock),
    (SK_BUFF_PROGRAMS, SocketContextLayout::SkBuff),
];

fn find_program_type_layout_surface<T: Clone>(
    program_type: EbpfProgramType,
    surfaces: &[ProgramTypeLayoutSurfaceSpec<T>],
) -> Option<T> {
    surfaces
        .iter()
        .find(|(allowed_programs, _)| allowed_programs.contains(&program_type))
        .map(|(_, layout)| layout.clone())
}

fn supports_program_type_surface(
    program_type: EbpfProgramType,
    allowed_programs: &[EbpfProgramType],
) -> bool {
    allowed_programs.contains(&program_type)
}

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
        find_program_type_layout_surface(*self, DATA_META_CONTEXT_KIND_SURFACES)
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
        find_program_type_layout_surface(*self, SOCKET_FAMILY_CONTEXT_LAYOUT_SURFACES)
    }

    pub(crate) fn socket_tuple_context_layout(&self) -> Option<SocketContextLayout> {
        find_program_type_layout_surface(*self, SOCKET_TUPLE_CONTEXT_LAYOUT_SURFACES)
    }

    pub(crate) fn sock_type_context_layout(&self) -> Option<SocketContextLayout> {
        find_program_type_layout_surface(*self, SOCK_TYPE_CONTEXT_LAYOUT_SURFACES)
    }

    pub(crate) fn protocol_context_layout(&self) -> Option<SocketContextLayout> {
        find_program_type_layout_surface(*self, PROTOCOL_CONTEXT_LAYOUT_SURFACES)
    }

    pub(crate) fn socket_ref_context_layout(&self) -> Option<SocketContextLayout> {
        find_program_type_layout_surface(*self, SOCKET_REF_CONTEXT_LAYOUT_SURFACES)
    }

    pub(crate) fn ingress_ifindex_context_layout(&self) -> Option<IngressIfindexContextLayout> {
        find_program_type_layout_surface(*self, INGRESS_IFINDEX_CONTEXT_LAYOUT_SURFACES)
    }

    pub(crate) fn sock_mark_priority_context_layout(&self) -> Option<SocketContextLayout> {
        find_program_type_layout_surface(*self, SOCK_MARK_PRIORITY_CONTEXT_LAYOUT_SURFACES)
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
        supports_program_type_surface(*self, SOCKET_COOKIE_PROGRAMS)
    }

    pub fn supports_socket_uid_ctx_field(&self) -> bool {
        supports_program_type_surface(*self, SOCKET_UID_PROGRAMS)
    }

    pub fn supports_netns_cookie_ctx_field(&self) -> bool {
        supports_program_type_surface(*self, NETNS_COOKIE_PROGRAMS)
    }

    pub fn supports_lookup_cookie_ctx_field(&self) -> bool {
        supports_program_type_surface(*self, LOOKUP_COOKIE_PROGRAMS)
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
        context_family_ctx_field_load_guard(self.context_family(), field)
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
