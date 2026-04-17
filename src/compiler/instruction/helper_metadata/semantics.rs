use super::*;

impl BpfHelper {
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
        const XDP_ADJUST_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper xdp_adjust ctx",
            allowed: KERNEL,
            fixed_size: None,
            size_from_arg: None,
        }];
        const SKB_MUTATE_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper skb_mutate skb",
            allowed: KERNEL,
            fixed_size: None,
            size_from_arg: None,
        }];
        const SKB_STORE_BYTES_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper skb_store_bytes skb",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 2,
                op: "helper skb_store_bytes from",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: Some(3),
            },
        ];

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

        const SYSCTL_GET_NAME_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper sysctl_get_name ctx",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper sysctl_get_name buf",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: Some(2),
            },
        ];

        const SYSCTL_GET_CURRENT_VALUE_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper sysctl_get_current_value ctx",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper sysctl_get_current_value buf",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: Some(2),
            },
        ];

        const SYSCTL_GET_NEW_VALUE_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper sysctl_get_new_value ctx",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper sysctl_get_new_value buf",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: Some(2),
            },
        ];

        const SYSCTL_SET_VALUE_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper sysctl_set_value ctx",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper sysctl_set_value buf",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: Some(2),
            },
        ];

        const SET_SOCKOPT_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper setsockopt ctx",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 3,
                op: "helper setsockopt optval",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: Some(4),
            },
        ];

        const GET_SOCKOPT_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper getsockopt ctx",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 3,
                op: "helper getsockopt optval",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: Some(4),
            },
        ];

        const SK_REDIRECT_MAP_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper sk_redirect_map skb",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper sk_redirect_map map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
        ];

        const REDIRECT_MAP_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper redirect_map map",
            allowed: STACK_ONLY,
            fixed_size: None,
            size_from_arg: None,
        }];

        const SOCK_MAP_UPDATE_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper sock_map_update ctx",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper sock_map_update map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 2,
                op: "helper sock_map_update key",
                allowed: STACK_MAP,
                fixed_size: Some(4),
                size_from_arg: None,
            },
        ];

        const MSG_REDIRECT_MAP_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper msg_redirect_map msg",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper msg_redirect_map map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
        ];

        const SOCK_HASH_UPDATE_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper sock_hash_update ctx",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper sock_hash_update map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 2,
                op: "helper sock_hash_update key",
                allowed: STACK_MAP,
                fixed_size: Some(1),
                size_from_arg: None,
            },
        ];

        const MSG_REDIRECT_HASH_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper msg_redirect_hash msg",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper msg_redirect_hash map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 2,
                op: "helper msg_redirect_hash key",
                allowed: STACK_MAP,
                fixed_size: Some(1),
                size_from_arg: None,
            },
        ];

        const SK_REDIRECT_HASH_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper sk_redirect_hash skb",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper sk_redirect_hash map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 2,
                op: "helper sk_redirect_hash key",
                allowed: STACK_MAP,
                fixed_size: Some(1),
                size_from_arg: None,
            },
        ];

        const BIND_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper bind ctx",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper bind addr",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: Some(2),
            },
        ];

        const LOAD_HDR_OPT_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper load_hdr_opt ctx",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper load_hdr_opt searchby_res",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: Some(2),
            },
        ];

        const STORE_HDR_OPT_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper store_hdr_opt ctx",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper store_hdr_opt from",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: Some(2),
            },
        ];

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

        const REDIRECT_NEIGH_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 1,
            op: "helper redirect_neigh params",
            allowed: STACK_ONLY,
            fixed_size: None,
            size_from_arg: None,
        }];

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

        const TCP_CHECK_SYNCOOKIE_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper tcp_check_syncookie sk",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper tcp_check_syncookie iph",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: Some(2),
            },
            HelperPtrArgRule {
                arg_idx: 3,
                op: "helper tcp_check_syncookie th",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: Some(4),
            },
        ];

        const TCP_GEN_SYNCOOKIE_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper tcp_gen_syncookie sk",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper tcp_gen_syncookie iph",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: Some(2),
            },
            HelperPtrArgRule {
                arg_idx: 3,
                op: "helper tcp_gen_syncookie th",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: Some(4),
            },
        ];

        const SK_ASSIGN_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper sk_assign ctx",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper sk_assign sk",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
        ];

        const SK_STORAGE_GET_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper sk_storage_get map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper sk_storage_get sk",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 2,
                op: "helper sk_storage_get value",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: None,
            },
        ];

        const SK_STORAGE_DELETE_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper sk_storage_delete map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper sk_storage_delete sk",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
        ];

        const TASK_STORAGE_GET_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper task_storage_get map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper task_storage_get task",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 2,
                op: "helper task_storage_get value",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: None,
            },
        ];

        const TASK_STORAGE_DELETE_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper task_storage_delete map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper task_storage_delete task",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
        ];

        const INODE_STORAGE_GET_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper inode_storage_get map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper inode_storage_get inode",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 2,
                op: "helper inode_storage_get value",
                allowed: STACK_MAP,
                fixed_size: None,
                size_from_arg: None,
            },
        ];

        const INODE_STORAGE_DELETE_RULES: &[HelperPtrArgRule] = &[
            HelperPtrArgRule {
                arg_idx: 0,
                op: "helper inode_storage_delete map",
                allowed: STACK_ONLY,
                fixed_size: None,
                size_from_arg: None,
            },
            HelperPtrArgRule {
                arg_idx: 1,
                op: "helper inode_storage_delete inode",
                allowed: KERNEL,
                fixed_size: None,
                size_from_arg: None,
            },
        ];

        const SOCK_FROM_FILE_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper sock_from_file file",
            allowed: KERNEL,
            fixed_size: None,
            size_from_arg: None,
        }];

        const TASK_PT_REGS_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper task_pt_regs task",
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

        const SKC_TO_UNIX_SOCK_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper skc_to_unix_sock sk",
            allowed: KERNEL,
            fixed_size: None,
            size_from_arg: None,
        }];

        const LIRC_CTX_RULES: &[HelperPtrArgRule] = &[HelperPtrArgRule {
            arg_idx: 0,
            op: "helper lirc ctx",
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
            BpfHelper::SysctlGetName => HelperSemantics {
                ptr_arg_rules: SYSCTL_GET_NAME_RULES,
                positive_size_args: &[2],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SysctlGetCurrentValue => HelperSemantics {
                ptr_arg_rules: SYSCTL_GET_CURRENT_VALUE_RULES,
                positive_size_args: &[2],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SysctlGetNewValue => HelperSemantics {
                ptr_arg_rules: SYSCTL_GET_NEW_VALUE_RULES,
                positive_size_args: &[2],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SysctlSetNewValue => HelperSemantics {
                ptr_arg_rules: SYSCTL_SET_VALUE_RULES,
                positive_size_args: &[2],
                ringbuf_record_arg0: false,
            },
            BpfHelper::MsgApplyBytes => HelperSemantics {
                ptr_arg_rules: &[HelperPtrArgRule {
                    arg_idx: 0,
                    op: "helper msg_apply_bytes ctx",
                    allowed: KERNEL,
                    fixed_size: None,
                    size_from_arg: None,
                }],
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::MsgCorkBytes => HelperSemantics {
                ptr_arg_rules: &[HelperPtrArgRule {
                    arg_idx: 0,
                    op: "helper msg_cork_bytes ctx",
                    allowed: KERNEL,
                    fixed_size: None,
                    size_from_arg: None,
                }],
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::MsgPullData => HelperSemantics {
                ptr_arg_rules: &[HelperPtrArgRule {
                    arg_idx: 0,
                    op: "helper msg_pull_data ctx",
                    allowed: KERNEL,
                    fixed_size: None,
                    size_from_arg: None,
                }],
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::MsgPushData => HelperSemantics {
                ptr_arg_rules: &[HelperPtrArgRule {
                    arg_idx: 0,
                    op: "helper msg_push_data ctx",
                    allowed: KERNEL,
                    fixed_size: None,
                    size_from_arg: None,
                }],
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::MsgPopData => HelperSemantics {
                ptr_arg_rules: &[HelperPtrArgRule {
                    arg_idx: 0,
                    op: "helper msg_pop_data ctx",
                    allowed: KERNEL,
                    fixed_size: None,
                    size_from_arg: None,
                }],
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SkbStoreBytes => HelperSemantics {
                ptr_arg_rules: SKB_STORE_BYTES_RULES,
                positive_size_args: &[3],
                ringbuf_record_arg0: false,
            },
            BpfHelper::L3CsumReplace
            | BpfHelper::L4CsumReplace
            | BpfHelper::GetHashRecalc
            | BpfHelper::CsumUpdate
            | BpfHelper::SetHashInvalid => HelperSemantics {
                ptr_arg_rules: SKB_MUTATE_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SkbChangeTail
            | BpfHelper::SkbPullData
            | BpfHelper::SkbChangeHead
            | BpfHelper::SkbAdjustRoom
            | BpfHelper::SkbSetTstamp => HelperSemantics {
                ptr_arg_rules: SKB_MUTATE_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SkRedirectMap => HelperSemantics {
                ptr_arg_rules: SK_REDIRECT_MAP_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::RedirectMap => HelperSemantics {
                ptr_arg_rules: REDIRECT_MAP_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SockMapUpdate => HelperSemantics {
                ptr_arg_rules: SOCK_MAP_UPDATE_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::MsgRedirectMap => HelperSemantics {
                ptr_arg_rules: MSG_REDIRECT_MAP_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SockHashUpdate => HelperSemantics {
                ptr_arg_rules: SOCK_HASH_UPDATE_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::MsgRedirectHash => HelperSemantics {
                ptr_arg_rules: MSG_REDIRECT_HASH_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SkRedirectHash => HelperSemantics {
                ptr_arg_rules: SK_REDIRECT_HASH_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::Redirect => HelperSemantics {
                ptr_arg_rules: &[],
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::XdpAdjustHead | BpfHelper::XdpAdjustMeta | BpfHelper::XdpAdjustTail => {
                HelperSemantics {
                    ptr_arg_rules: XDP_ADJUST_RULES,
                    positive_size_args: &[],
                    ringbuf_record_arg0: false,
                }
            }
            BpfHelper::RedirectNeigh => HelperSemantics {
                ptr_arg_rules: REDIRECT_NEIGH_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::RedirectPeer => HelperSemantics {
                ptr_arg_rules: &[],
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::GetSocketCookie => HelperSemantics {
                ptr_arg_rules: &[HelperPtrArgRule {
                    arg_idx: 0,
                    op: "helper get_socket_cookie ctx",
                    allowed: KERNEL,
                    fixed_size: None,
                    size_from_arg: None,
                }],
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::GetSocketUid => HelperSemantics {
                ptr_arg_rules: &[HelperPtrArgRule {
                    arg_idx: 0,
                    op: "helper get_socket_uid ctx",
                    allowed: KERNEL,
                    fixed_size: None,
                    size_from_arg: None,
                }],
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SetSockOpt => HelperSemantics {
                ptr_arg_rules: SET_SOCKOPT_RULES,
                positive_size_args: &[4],
                ringbuf_record_arg0: false,
            },
            BpfHelper::GetSockOpt => HelperSemantics {
                ptr_arg_rules: GET_SOCKOPT_RULES,
                positive_size_args: &[4],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SockOpsCbFlagsSet => HelperSemantics {
                ptr_arg_rules: &[HelperPtrArgRule {
                    arg_idx: 0,
                    op: "helper sock_ops_cb_flags_set ctx",
                    allowed: KERNEL,
                    fixed_size: None,
                    size_from_arg: None,
                }],
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::LoadHdrOpt => HelperSemantics {
                ptr_arg_rules: LOAD_HDR_OPT_RULES,
                positive_size_args: &[2],
                ringbuf_record_arg0: false,
            },
            BpfHelper::StoreHdrOpt => HelperSemantics {
                ptr_arg_rules: STORE_HDR_OPT_RULES,
                positive_size_args: &[2],
                ringbuf_record_arg0: false,
            },
            BpfHelper::ReserveHdrOpt => HelperSemantics {
                ptr_arg_rules: &[HelperPtrArgRule {
                    arg_idx: 0,
                    op: "helper reserve_hdr_opt ctx",
                    allowed: KERNEL,
                    fixed_size: None,
                    size_from_arg: None,
                }],
                positive_size_args: &[1],
                ringbuf_record_arg0: false,
            },
            BpfHelper::Bind => HelperSemantics {
                ptr_arg_rules: BIND_RULES,
                positive_size_args: &[2],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SkCgroupId => HelperSemantics {
                ptr_arg_rules: &[HelperPtrArgRule {
                    arg_idx: 0,
                    op: "helper sk_cgroup_id sk",
                    allowed: KERNEL,
                    fixed_size: None,
                    size_from_arg: None,
                }],
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SkAncestorCgroupId => HelperSemantics {
                ptr_arg_rules: &[HelperPtrArgRule {
                    arg_idx: 0,
                    op: "helper sk_ancestor_cgroup_id sk",
                    allowed: KERNEL,
                    fixed_size: None,
                    size_from_arg: None,
                }],
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::GetNetnsCookie => HelperSemantics {
                ptr_arg_rules: &[HelperPtrArgRule {
                    arg_idx: 0,
                    op: "helper get_netns_cookie ctx",
                    allowed: KERNEL,
                    fixed_size: None,
                    size_from_arg: None,
                }],
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::RcRepeat | BpfHelper::RcKeydown | BpfHelper::RcPointerRel => {
                HelperSemantics {
                    ptr_arg_rules: LIRC_CTX_RULES,
                    positive_size_args: &[],
                    ringbuf_record_arg0: false,
                }
            }
            BpfHelper::TracePrintk => HelperSemantics {
                ptr_arg_rules: TRACE_PRINTK_RULES,
                positive_size_args: &[1],
                ringbuf_record_arg0: false,
            },
            BpfHelper::ProbeRead | BpfHelper::ProbeReadKernel | BpfHelper::ProbeReadKernelStr => {
                HelperSemantics {
                    ptr_arg_rules: PROBE_READ_KERNEL_RULES,
                    positive_size_args: &[1],
                    ringbuf_record_arg0: false,
                }
            }
            BpfHelper::ProbeReadUser | BpfHelper::ProbeReadUserStr => HelperSemantics {
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
            BpfHelper::TcpCheckSyncookie => HelperSemantics {
                ptr_arg_rules: TCP_CHECK_SYNCOOKIE_RULES,
                positive_size_args: &[2, 4],
                ringbuf_record_arg0: false,
            },
            BpfHelper::TcpGenSyncookie => HelperSemantics {
                ptr_arg_rules: TCP_GEN_SYNCOOKIE_RULES,
                positive_size_args: &[2, 4],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SkAssign => HelperSemantics {
                ptr_arg_rules: SK_ASSIGN_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SkStorageGet => HelperSemantics {
                ptr_arg_rules: SK_STORAGE_GET_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SkStorageDelete => HelperSemantics {
                ptr_arg_rules: SK_STORAGE_DELETE_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::TaskStorageGet => HelperSemantics {
                ptr_arg_rules: TASK_STORAGE_GET_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::TaskStorageDelete => HelperSemantics {
                ptr_arg_rules: TASK_STORAGE_DELETE_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::InodeStorageGet => HelperSemantics {
                ptr_arg_rules: INODE_STORAGE_GET_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::InodeStorageDelete => HelperSemantics {
                ptr_arg_rules: INODE_STORAGE_DELETE_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::SockFromFile => HelperSemantics {
                ptr_arg_rules: SOCK_FROM_FILE_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
            BpfHelper::TaskPtRegs => HelperSemantics {
                ptr_arg_rules: TASK_PT_REGS_RULES,
                positive_size_args: &[],
                ringbuf_record_arg0: false,
            },
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
            BpfHelper::SkcToUnixSock => HelperSemantics {
                ptr_arg_rules: SKC_TO_UNIX_SOCK_RULES,
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
