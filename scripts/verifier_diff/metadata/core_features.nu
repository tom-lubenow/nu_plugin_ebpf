const VERIFIER_DIFF_METADATA_DIR = (path self | path dirname)

source ($VERIFIER_DIFF_METADATA_DIR | path join core_runtime_config.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_program_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_program_xdp_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_program_network_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_program_struct_ops_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_program_cgroup_struct_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_iter_network_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_iter_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_program_target_expectations.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_program_language_expectations.nu)

source ($VERIFIER_DIFF_METADATA_DIR | path join core_program_map_redirect_expectations.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_program_map_storage_expectations.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_program_map_helper_storage_expectations.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_program_map_expectations.nu)

const PROGRAM_RESERVED_MAP_KERNEL_FEATURE_EXPECTATIONS = [
    {
        program: [
            '{|ctx|'
            '  let docs = "emit events user_events perf_events kstacks ustacks .kstack .ustack"'
            '  # emit events user_events perf_events kstacks ustacks .kstack .ustack'
            '  let ignored = 0 # | emit | count | histogram | start-timer | stop-timer'
            '  let more_ignored = 0 # events user_events perf_events kstacks ustacks .kstack .ustack'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  1 | emit'
            '  2 | count'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb| 0 } "ctx" 0'
            '  helper-call "bpf_perf_event_read" perf_events 0'
            '  helper-call "bpf_get_stackid" $ctx kstacks 0'
            '  0'
            '}'
        ]
        feature_keys: [
            "map:BPF_MAP_TYPE_RINGBUF"
            "map:BPF_MAP_TYPE_HASH"
            "map:BPF_MAP_TYPE_USER_RINGBUF"
            "map:BPF_MAP_TYPE_PERF_EVENT_ARRAY"
            "map:BPF_MAP_TYPE_STACK_TRACE"
        ]
    }
]

source ($VERIFIER_DIFF_METADATA_DIR | path join core_program_map_value_expectations.nu)

source ($VERIFIER_DIFF_METADATA_DIR | path join core_program_global_context_expectations.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_program_global_literal_data_expectations.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_program_global_mutable_data_expectations.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_program_global_data_expectations.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_program_global_expectations.nu)

source ($VERIFIER_DIFF_METADATA_DIR | path join core_basic_map_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_map_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_network_map_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_special_map_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_map_helper_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_context_helper_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_cgroup_socket_helper_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_ringbuf_helper_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_probe_perf_helper_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_helper_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_socket_sysctl_helper_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_xdp_packet_helper_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_packet_helper_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_stream_msg_helper_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_skb_socket_redirect_helper_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_stream_timer_dynptr_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_dynptr_helper_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_map_value_kfunc_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_task_cgroup_kfunc_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_cpumask_kfunc_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_object_kfunc_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_sched_ext_kfunc_features.nu)
