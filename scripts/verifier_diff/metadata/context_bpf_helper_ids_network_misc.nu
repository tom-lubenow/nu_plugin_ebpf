const BPF_HELPER_IDS_NETWORK_MISC_BASE = [
    { name: "bpf_msg_apply_bytes", id: 61 }
    { name: "bpf_msg_cork_bytes", id: 62 }
    { name: "bpf_msg_pop_data", id: 91 }
    { name: "bpf_msg_pull_data", id: 63 }
    { name: "bpf_msg_push_data", id: 90 }
    { name: "bpf_msg_redirect_hash", id: 71 }
    { name: "bpf_msg_redirect_map", id: 60 }
    { name: "bpf_override_return", id: 58 }
    { name: "bpf_per_cpu_ptr", id: 153 }
    { name: "bpf_probe_read", id: 4 }
    { name: "bpf_probe_read_kernel", id: 113 }
    { name: "bpf_probe_read_kernel_str", id: 115 }
    { name: "bpf_probe_read_str", id: 45 }
    { name: "bpf_probe_read_user", id: 112 }
    { name: "bpf_probe_read_user_str", id: 114 }
    { name: "bpf_probe_write_user", id: 36 }
    { name: "bpf_rc_keydown", id: 78 }
    { name: "bpf_rc_pointer_rel", id: 92 }
    { name: "bpf_rc_repeat", id: 77 }
    { name: "bpf_redirect", id: 23 }
    { name: "bpf_redirect_map", id: 51 }
    { name: "bpf_redirect_neigh", id: 152 }
    { name: "bpf_redirect_peer", id: 155 }
    { name: "bpf_reserve_hdr_opt", id: 144 }
    { name: "bpf_send_signal", id: 109 }
    { name: "bpf_send_signal_thread", id: 117 }
    { name: "bpf_set_hash", id: 48 }
    { name: "bpf_set_hash_invalid", id: 41 }
    { name: "bpf_set_retval", id: 187 }
    { name: "bpf_setsockopt", id: 49 }
    { name: "bpf_snprintf", id: 165 }
    { name: "bpf_snprintf_btf", id: 149 }
    { name: "bpf_sock_from_file", id: 162 }
    { name: "bpf_sock_hash_update", id: 70 }
    { name: "bpf_sock_map_update", id: 53 }
    { name: "bpf_sock_ops_cb_flags_set", id: 59 }
    { name: "bpf_spin_lock", id: 93 }
    { name: "bpf_spin_unlock", id: 94 }
    { name: "bpf_store_hdr_opt", id: 143 }
    { name: "bpf_strncmp", id: 182 }
    { name: "bpf_strtol", id: 105 }
    { name: "bpf_strtoul", id: 106 }
    { name: "bpf_sys_bpf", id: 166 }
    { name: "bpf_sys_close", id: 168 }
    { name: "bpf_sysctl_get_current_value", id: 102 }
    { name: "bpf_sysctl_get_name", id: 101 }
    { name: "bpf_sysctl_get_new_value", id: 103 }
    { name: "bpf_sysctl_set_new_value", id: 104 }
    { name: "bpf_tail_call", id: 12 }
    { name: "bpf_task_pt_regs", id: 175 }
    { name: "bpf_task_storage_delete", id: 157 }
    { name: "bpf_task_storage_get", id: 156 }
    { name: "bpf_tcp_check_syncookie", id: 100 }
    { name: "bpf_tcp_gen_syncookie", id: 110 }
    { name: "bpf_tcp_raw_check_syncookie_ipv4", id: 206 }
    { name: "bpf_tcp_raw_check_syncookie_ipv6", id: 207 }
    { name: "bpf_tcp_raw_gen_syncookie_ipv4", id: 204 }
    { name: "bpf_tcp_raw_gen_syncookie_ipv6", id: 205 }
    { name: "bpf_tcp_send_ack", id: 116 }
    { name: "bpf_tcp_sock", id: 96 }
    { name: "bpf_this_cpu_ptr", id: 154 }
    { name: "bpf_xdp_adjust_head", id: 44 }
    { name: "bpf_xdp_adjust_meta", id: 54 }
    { name: "bpf_xdp_adjust_tail", id: 65 }
    { name: "bpf_xdp_get_buff_len", id: 188 }
    { name: "bpf_xdp_load_bytes", id: 189 }
    { name: "bpf_xdp_output", id: 121 }
    { name: "bpf_xdp_store_bytes", id: 190 }
]

let BPF_HELPER_IDS_NETWORK_MISC = (
    $BPF_HELPER_IDS_NETWORK_MISC_BASE
    | append $BPF_HELPER_IDS_SOCKET_PACKET
    | append $BPF_HELPER_IDS_EVENT_TIMER
)
