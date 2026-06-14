const HELPER_CALL_EXPLICIT_MAP_KIND_FEATURES = [
    { helper: "bpf_map_push_elem", map_arg: 0, kinds: ["queue" "stack" "bloom-filter"] }
    { helper: "bpf_map_peek_elem", map_arg: 0, kinds: ["queue" "stack" "bloom-filter"] }
    { helper: "bpf_map_pop_elem", map_arg: 0, kinds: ["queue" "stack"] }
    { helper: "bpf_redirect_map", map_arg: 0, kinds: ["devmap" "devmap-hash" "cpumap" "xskmap"] }
    { helper: "bpf_map_lookup_percpu_elem", map_arg: 0, kinds: ["per-cpu-hash" "per-cpu-array" "lru-per-cpu-hash"] }
    { helper: "bpf_for_each_map_elem", map_arg: 0, kinds: ["hash" "array" "lru-hash" "per-cpu-hash" "per-cpu-array" "lru-per-cpu-hash"] }
    { helper: "bpf_timer_init", map_arg: 1, kinds: ["hash" "array" "lru-hash"] }
]

const HELPER_CALL_FIXED_MAP_KIND_FEATURES = [
    { helper: "bpf_tail_call", map_arg: 1, kind: "prog-array" }
    { helper: "bpf_perf_event_output", map_arg: 1, kind: "perf-event-array" }
    { helper: "bpf_skb_output", map_arg: 1, kind: "perf-event-array" }
    { helper: "bpf_xdp_output", map_arg: 1, kind: "perf-event-array" }
    { helper: "bpf_perf_event_read", map_arg: 0, kind: "perf-event-array" }
    { helper: "bpf_perf_event_read_value", map_arg: 0, kind: "perf-event-array" }
    { helper: "bpf_get_stackid", map_arg: 1, kind: "stack-trace" }
    { helper: "bpf_skb_under_cgroup", map_arg: 1, kind: "cgroup-array" }
    { helper: "bpf_current_task_under_cgroup", map_arg: 0, kind: "cgroup-array" }
    { helper: "bpf_ringbuf_output", map_arg: 0, kind: "ringbuf" }
    { helper: "bpf_ringbuf_reserve", map_arg: 0, kind: "ringbuf" }
    { helper: "bpf_ringbuf_reserve_dynptr", map_arg: 0, kind: "ringbuf" }
    { helper: "bpf_ringbuf_query", map_arg: 0, kind: "ringbuf" }
    { helper: "bpf_user_ringbuf_drain", map_arg: 0, kind: "user-ringbuf" }
    { helper: "bpf_sk_redirect_map", map_arg: 1, kind: "sockmap" }
    { helper: "bpf_sock_map_update", map_arg: 1, kind: "sockmap" }
    { helper: "bpf_msg_redirect_map", map_arg: 1, kind: "sockmap" }
    { helper: "bpf_sock_hash_update", map_arg: 1, kind: "sockhash" }
    { helper: "bpf_msg_redirect_hash", map_arg: 1, kind: "sockhash" }
    { helper: "bpf_sk_redirect_hash", map_arg: 1, kind: "sockhash" }
    { helper: "bpf_sk_select_reuseport", map_arg: 1, kind: "reuseport-sockarray" }
    { helper: "bpf_sk_storage_get", map_arg: 0, kind: "sk-storage" }
    { helper: "bpf_sk_storage_delete", map_arg: 0, kind: "sk-storage" }
    { helper: "bpf_task_storage_get", map_arg: 0, kind: "task-storage" }
    { helper: "bpf_task_storage_delete", map_arg: 0, kind: "task-storage" }
    { helper: "bpf_inode_storage_get", map_arg: 0, kind: "inode-storage" }
    { helper: "bpf_inode_storage_delete", map_arg: 0, kind: "inode-storage" }
    { helper: "bpf_cgrp_storage_get", map_arg: 0, kind: "cgrp-storage" }
    { helper: "bpf_cgrp_storage_delete", map_arg: 0, kind: "cgrp-storage" }
    { helper: "bpf_get_local_storage", map_arg: 0, kind: "deprecated-cgroup-storage" }
]
