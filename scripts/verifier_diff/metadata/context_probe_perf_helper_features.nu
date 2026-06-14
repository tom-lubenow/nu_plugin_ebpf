const HELPER_PROBE_PERF_KERNEL_FEATURES = [
    { name: "bpf_probe_read", feature: $KERNEL_FEATURE_BPF_PROBE_READ }
    { name: "bpf_probe_read_str", feature: $KERNEL_FEATURE_BPF_PROBE_READ_STR }
    { name: "bpf_probe_read_user", feature: $KERNEL_FEATURE_BPF_PROBE_READ_USER }
    { name: "bpf_probe_read_kernel", feature: $KERNEL_FEATURE_BPF_PROBE_READ_KERNEL }
    { name: "bpf_probe_read_user_str", feature: $KERNEL_FEATURE_BPF_PROBE_READ_USER_STR }
    { name: "bpf_probe_read_kernel_str", feature: $KERNEL_FEATURE_BPF_PROBE_READ_KERNEL_STR }
    { name: "bpf_get_prandom_u32", feature: $KERNEL_FEATURE_BPF_GET_PRANDOM_U32 }
    { name: "bpf_tail_call", feature: $KERNEL_FEATURE_BPF_TAIL_CALL }
    { name: "bpf_perf_event_read", feature: $KERNEL_FEATURE_BPF_PERF_EVENT_READ }
    { name: "bpf_perf_event_read_value", feature: $KERNEL_FEATURE_BPF_PERF_EVENT_READ_VALUE }
    { name: "bpf_perf_prog_read_value", feature: $KERNEL_FEATURE_BPF_PERF_PROG_READ_VALUE }
    { name: "bpf_override_return", feature: $KERNEL_FEATURE_BPF_OVERRIDE_RETURN }
    { name: "bpf_get_stackid", feature: $KERNEL_FEATURE_BPF_GET_STACKID }
    { name: "bpf_get_stack", feature: $KERNEL_FEATURE_BPF_GET_STACK }
]
