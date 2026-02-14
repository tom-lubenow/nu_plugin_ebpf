use super::*;

impl BpfHelper {
    pub const fn from_u32(helper_id: u32) -> Option<Self> {
        match helper_id {
            1 => Some(Self::MapLookupElem),
            2 => Some(Self::MapUpdateElem),
            3 => Some(Self::MapDeleteElem),
            4 => Some(Self::ProbeRead),
            5 => Some(Self::KtimeGetNs),
            6 => Some(Self::TracePrintk),
            8 => Some(Self::GetSmpProcessorId),
            12 => Some(Self::TailCall),
            14 => Some(Self::GetCurrentPidTgid),
            15 => Some(Self::GetCurrentUidGid),
            16 => Some(Self::GetCurrentComm),
            25 => Some(Self::PerfEventOutput),
            27 => Some(Self::GetStackId),
            84 => Some(Self::SkLookupTcp),
            85 => Some(Self::SkLookupUdp),
            86 => Some(Self::SkRelease),
            87 => Some(Self::MapPushElem),
            88 => Some(Self::MapPopElem),
            89 => Some(Self::MapPeekElem),
            95 => Some(Self::SkFullsock),
            96 => Some(Self::TcpSock),
            98 => Some(Self::GetListenerSock),
            99 => Some(Self::SkcLookupTcp),
            136 => Some(Self::SkcToTcp6Sock),
            137 => Some(Self::SkcToTcpSock),
            138 => Some(Self::SkcToTcpTimewaitSock),
            139 => Some(Self::SkcToTcpRequestSock),
            140 => Some(Self::SkcToUdp6Sock),
            114 => Some(Self::ProbeReadUserStr),
            115 => Some(Self::ProbeReadKernelStr),
            130 => Some(Self::RingbufOutput),
            131 => Some(Self::RingbufReserve),
            132 => Some(Self::RingbufSubmit),
            133 => Some(Self::RingbufDiscard),
            134 => Some(Self::RingbufQuery),
            194 => Some(Self::KptrXchg),
            _ => None,
        }
    }

    pub const fn signature(self) -> HelperSignature {
        const S: HelperArgKind = HelperArgKind::Scalar;
        const P: HelperArgKind = HelperArgKind::Pointer;
        match self {
            BpfHelper::MapLookupElem => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::PointerMaybeNull,
            },
            BpfHelper::MapUpdateElem => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, P, P, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::MapDeleteElem => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::MapPushElem => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::MapPopElem | BpfHelper::MapPeekElem => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::ProbeRead => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, S, P, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::KtimeGetNs
            | BpfHelper::GetSmpProcessorId
            | BpfHelper::GetCurrentPidTgid
            | BpfHelper::GetCurrentUidGid => HelperSignature {
                min_args: 0,
                max_args: 0,
                arg_kinds: [S, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::TracePrintk => HelperSignature {
                min_args: 2,
                max_args: 5,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::TailCall => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::GetCurrentComm => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::PerfEventOutput => HelperSignature {
                min_args: 5,
                max_args: 5,
                arg_kinds: [P, P, S, P, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::GetStackId => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SkLookupTcp | BpfHelper::SkLookupUdp | BpfHelper::SkcLookupTcp => {
                HelperSignature {
                    min_args: 5,
                    max_args: 5,
                    arg_kinds: [P, P, S, S, S],
                    ret_kind: HelperRetKind::PointerMaybeNull,
                }
            }
            BpfHelper::SkRelease => HelperSignature {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::SkFullsock
            | BpfHelper::TcpSock
            | BpfHelper::SkcToTcp6Sock
            | BpfHelper::SkcToTcpSock
            | BpfHelper::SkcToTcpTimewaitSock
            | BpfHelper::SkcToTcpRequestSock
            | BpfHelper::SkcToUdp6Sock => HelperSignature {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::PointerMaybeNull,
            },
            BpfHelper::GetListenerSock => HelperSignature {
                min_args: 1,
                max_args: 1,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::PointerMaybeNull,
            },
            BpfHelper::RingbufOutput => HelperSignature {
                min_args: 4,
                max_args: 4,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::RingbufReserve => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::PointerMaybeNull,
            },
            BpfHelper::RingbufQuery => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::RingbufSubmit | BpfHelper::RingbufDiscard => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, S, S, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
            BpfHelper::KptrXchg => HelperSignature {
                min_args: 2,
                max_args: 2,
                arg_kinds: [P, P, S, S, S],
                ret_kind: HelperRetKind::PointerMaybeNull,
            },
            BpfHelper::ProbeReadUserStr | BpfHelper::ProbeReadKernelStr => HelperSignature {
                min_args: 3,
                max_args: 3,
                arg_kinds: [P, S, P, S, S],
                ret_kind: HelperRetKind::Scalar,
            },
        }
    }

    pub const fn semantics(self) -> HelperSemantics {
        const STACK_MAP: HelperAllowedPtrSpaces =
            HelperAllowedPtrSpaces::new(true, true, false, false);
        const MAP_ONLY: HelperAllowedPtrSpaces =
            HelperAllowedPtrSpaces::new(false, true, false, false);
        const STACK_ONLY: HelperAllowedPtrSpaces =
            HelperAllowedPtrSpaces::new(true, false, false, false);
        const STACK_MAP_KERNEL: HelperAllowedPtrSpaces =
            HelperAllowedPtrSpaces::new(true, true, true, false);
        const KERNEL: HelperAllowedPtrSpaces =
            HelperAllowedPtrSpaces::new(false, false, true, false);
        const USER: HelperAllowedPtrSpaces = HelperAllowedPtrSpaces::new(false, false, false, true);

        const MAP_LOOKUP_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper map_lookup map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper map_lookup key",
                allowed: STACK_MAP,
                fixed_size: Some(1),
                size_from_arg: None,
            },
        ];

        const MAP_UPDATE_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper map_update map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper map_update key",
                allowed: STACK_MAP,
                fixed_size: Some(1),
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 2,
                op: "helper map_update value",
                allowed: STACK_MAP,
                fixed_size: Some(1),
                size_from_arg: None,
            },
        ];

        const MAP_DELETE_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper map_delete map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper map_delete key",
                allowed: STACK_MAP,
                fixed_size: Some(1),
                size_from_arg: None,
            },
        ];

        const MAP_PUSH_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper map_push map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper map_push value",
                allowed: STACK_MAP,
                fixed_size: Some(1),
                size_from_arg: None,
            },
        ];

        const MAP_POP_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper map_pop map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper map_pop value",
                allowed: STACK_MAP,
                fixed_size: Some(1),
                size_from_arg: None,
            },
        ];

        const MAP_PEEK_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper map_peek map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper map_peek value",
                allowed: STACK_MAP,
                fixed_size: Some(1),
                size_from_arg: None,
            },
        ];

        const GET_CURRENT_COMM_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper get_current_comm dst",
            allowed: STACK_MAP,
            fixed_size: None,
            size_from_arg: Some(1),
        }];

        const TRACE_PRINTK_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper trace_printk fmt",
            allowed: STACK_MAP,
            fixed_size: None,
            size_from_arg: Some(1),
        }];

        const PROBE_READ_KERNEL_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper probe_read dst",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: Some(1),
            },
            HelperPtrArgRule {
                arg_idx: 2,
                op: "helper probe_read src",
                allowed: STACK_MAP_KERNEL,
                fixed_size: None,
                size_from_arg: Some(1),
            },
        ];

        const PROBE_READ_USER_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper probe_read dst",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: Some(1),
            },
            HelperPtrArgRule {
                arg_idx: 2,
                op: "helper probe_read src",
                allowed: USER,
                fixed_size: None,
                size_from_arg: Some(1),
            },
        ];

        const RINGBUF_RESERVE_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper ringbuf_reserve map",
            allowed: STACK_ONLY,
            fixed_size: None,
            size_from_arg: None,
        }];

        const RINGBUF_OUTPUT_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper ringbuf_output map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper ringbuf_output data",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: Some(2),
            },
        ];

        const RINGBUF_QUERY_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper ringbuf_query map",
            allowed: STACK_ONLY,
            fixed_size: None,
            size_from_arg: None,
        }];

        const TAIL_CALL_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper tail_call ctx",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper tail_call map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
        ];

        const PERF_EVENT_OUTPUT_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper perf_event_output ctx",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper perf_event_output map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 3,
                op: "helper perf_event_output data",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: Some(4),
            },
        ];

        const GET_STACKID_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper get_stackid ctx",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper get_stackid map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
        ];

        const SK_LOOKUP_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper sk_lookup ctx",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper sk_lookup tuple",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: Some(2),
            },
        ];

        const SK_RELEASE_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper sk_release sock",
            allowed: KERNEL,
            fixed_size: None,
            size_from_arg: None,
        }];

        const GET_LISTENER_SOCK_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper get_listener_sock sk",
            allowed: KERNEL,
            fixed_size: None,
            size_from_arg: None,
        }];

        const SK_FULLSOCK_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper sk_fullsock sk",
            allowed: KERNEL,
            fixed_size: None,
            size_from_arg: None,
        }];

        const TCP_SOCK_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper tcp_sock sk",
            allowed: KERNEL,
            fixed_size: None,
            size_from_arg: None,
        }];

        const SKC_TO_TCP6_SOCK_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper skc_to_tcp6_sock sk",
            allowed: KERNEL,
            fixed_size: None,
            size_from_arg: None,
        }];

        const SKC_TO_TCP_SOCK_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper skc_to_tcp_sock sk",
            allowed: KERNEL,
            fixed_size: None,
            size_from_arg: None,
        }];

        const SKC_TO_TCP_TIMEWAIT_SOCK_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper skc_to_tcp_timewait_sock sk",
            allowed: KERNEL,
            fixed_size: None,
            size_from_arg: None,
        }];

        const SKC_TO_TCP_REQUEST_SOCK_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper skc_to_tcp_request_sock sk",
            allowed: KERNEL,
            fixed_size: None,
            size_from_arg: None,
        }];

        const SKC_TO_UDP6_SOCK_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper skc_to_udp6_sock sk",
            allowed: KERNEL,
            fixed_size: None,
            size_from_arg: None,
        }];

        const KPTR_XCHG_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper kptr_xchg dst",
                allowed: MAP_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper kptr_xchg ptr",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
        ];

        match self {
            BpfHelper::MapLookupElem => HelperSemantics {
                ptr_arg_rules: MAP_LOOKUP_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::MapUpdateElem => HelperSemantics {
                ptr_arg_rules: MAP_UPDATE_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::MapDeleteElem => HelperSemantics {
                ptr_arg_rules: MAP_DELETE_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::MapPushElem => HelperSemantics {
                ptr_arg_rules: MAP_PUSH_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::MapPopElem => HelperSemantics {
                ptr_arg_rules: MAP_POP_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::MapPeekElem => HelperSemantics {
                ptr_arg_rules: MAP_PEEK_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::GetCurrentComm => HelperSemantics {
                ptr_arg_rules: GET_CURRENT_COMM_RULES,
                positive_size_args: &[1],
                ringbuf_record_arg0: false,
            },
            BpfHelper::TracePrintk => HelperSemantics {
                ptr_arg_rules: TRACE_PRINTK_RULES,
                positive_size_args: &[1],
                ringbuf_record_arg0: false,
            },
            BpfHelper::ProbeRead | BpfHelper::ProbeReadKernelStr => HelperSemantics {
                ptr_arg_rules: PROBE_READ_KERNEL_RULES,
                positive_size_args: &[1],
                ringbuf_record_arg0: false,
            },
            BpfHelper::ProbeReadUserStr => HelperSemantics {
                ptr_arg_rules: PROBE_READ_USER_RULES,
                positive_size_args: &[1],
                ringbuf_record_arg0: false,
            },
            BpfHelper::RingbufReserve => HelperSemantics {
                ptr_arg_rules: RINGBUF_RESERVE_RULES,
                positive_size_args: &[1],
                ringbuf_record_arg0: false,
            },
            BpfHelper::RingbufOutput => HelperSemantics {
                ptr_arg_rules: RINGBUF_OUTPUT_RULES,
                positive_size_args: &[2],
                ringbuf_record_arg0: false,
            },
            BpfHelper::RingbufQuery => HelperSemantics {
                ptr_arg_rules: RINGBUF_QUERY_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::TailCall => HelperSemantics {
                ptr_arg_rules: TAIL_CALL_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::RingbufSubmit | BpfHelper::RingbufDiscard => HelperSemantics {
                ptr_arg_rules: &[],
                positive_size_args: &[],
                ringbuf_record_arg0: true,
            },
            BpfHelper::PerfEventOutput => HelperSemantics {
                ptr_arg_rules: PERF_EVENT_OUTPUT_RULES,
                positive_size_args: &[4],
                ringbuf_record_arg0: false,
            },
            BpfHelper::GetStackId => HelperSemantics {
                ptr_arg_rules: GET_STACKID_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SkLookupTcp | BpfHelper::SkLookupUdp | BpfHelper::SkcLookupTcp => {
                HelperSemantics {
                    ptr_arg_rules: SK_LOOKUP_RULES,
                    positive_size_args: &[2],
                    ringbuf_record_arg0: false,
                }
            }
            BpfHelper::SkRelease => HelperSemantics {
                ptr_arg_rules: SK_RELEASE_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SkFullsock => HelperSemantics {
                ptr_arg_rules: SK_FULLSOCK_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::TcpSock => HelperSemantics {
                ptr_arg_rules: TCP_SOCK_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SkcToTcp6Sock => HelperSemantics {
                ptr_arg_rules: SKC_TO_TCP6_SOCK_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SkcToTcpSock => HelperSemantics {
                ptr_arg_rules: SKC_TO_TCP_SOCK_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SkcToTcpTimewaitSock => HelperSemantics {
                ptr_arg_rules: SKC_TO_TCP_TIMEWAIT_SOCK_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SkcToTcpRequestSock => HelperSemantics {
                ptr_arg_rules: SKC_TO_TCP_REQUEST_SOCK_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SkcToUdp6Sock => HelperSemantics {
                ptr_arg_rules: SKC_TO_UDP6_SOCK_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::GetListenerSock => HelperSemantics {
                ptr_arg_rules: GET_LISTENER_SOCK_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::KptrXchg => HelperSemantics {
                ptr_arg_rules: KPTR_XCHG_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            _ => HelperSemantics::EMPTY,
        }
    }
}
