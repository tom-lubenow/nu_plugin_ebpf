let EXPLICIT_HELPER_MAP_KIND_KERNEL_FEATURE_EXPECTATIONS = (
    [
    {
        call: 'helper-call "bpf_map_push_elem" raw_queue value 0 --kind queue'
        feature: "map:BPF_MAP_TYPE_QUEUE"
    }
    {
        call: 'helper-call "bpf_map_push_elem" raw_stack value 0 --kind stack'
        feature: "map:BPF_MAP_TYPE_STACK"
    }
    {
        call: 'helper-call "bpf_map_push_elem" raw_bloom value 0 --kind bloom-filter'
        feature: "map:BPF_MAP_TYPE_BLOOM_FILTER"
    }
    {
        call: 'helper-call "bpf_map_peek_elem" raw_queue value --kind queue'
        feature: "map:BPF_MAP_TYPE_QUEUE"
    }
    {
        call: 'helper-call "bpf_map_peek_elem" raw_stack value --kind stack'
        feature: "map:BPF_MAP_TYPE_STACK"
    }
    {
        call: 'helper-call "bpf_map_peek_elem" raw_bloom value --kind bloom-filter'
        feature: "map:BPF_MAP_TYPE_BLOOM_FILTER"
    }
    {
        call: 'helper-call "bpf_map_pop_elem" raw_queue value --kind queue'
        feature: "map:BPF_MAP_TYPE_QUEUE"
    }
    {
        call: 'helper-call "bpf_map_pop_elem" raw_stack value --kind stack'
        feature: "map:BPF_MAP_TYPE_STACK"
    }
    {
        call: 'helper-call "bpf_redirect_map" redirects 0 0 --kind devmap'
        feature: "map:BPF_MAP_TYPE_DEVMAP"
    }
    {
        call: 'helper-call "bpf_redirect_map" redirects 0 0 --kind devmap-hash'
        feature: "map:BPF_MAP_TYPE_DEVMAP_HASH"
    }
    {
        call: 'helper-call "bpf_redirect_map" redirects 0 0 --kind cpumap'
        feature: "map:BPF_MAP_TYPE_CPUMAP"
    }
    {
        call: 'helper-call "bpf_redirect_map" redirects 0 0 --kind xskmap'
        feature: "map:BPF_MAP_TYPE_XSKMAP"
    }
    {
        call: 'helper-call "bpf_map_lookup_percpu_elem" per_cpu_values key0 0 --kind per-cpu-hash'
        feature: "map:BPF_MAP_TYPE_PERCPU_HASH"
    }
    {
        call: 'helper-call "bpf_map_lookup_percpu_elem" per_cpu_values key0 0 --kind per-cpu-array'
        feature: "map:BPF_MAP_TYPE_PERCPU_ARRAY"
    }
    {
        call: 'helper-call "bpf_map_lookup_percpu_elem" per_cpu_values key0 0 --kind lru-per-cpu-hash'
        feature: "map:BPF_MAP_TYPE_LRU_PERCPU_HASH"
    }
    {
        call: 'helper-call "bpf_for_each_map_elem" elems {|m k v cb| 0 } "ctx" 0 --kind hash'
        feature: "map:BPF_MAP_TYPE_HASH"
    }
    {
        call: 'helper-call "bpf_for_each_map_elem" elems {|m k v cb| 0 } "ctx" 0 --kind array'
        feature: "map:BPF_MAP_TYPE_ARRAY"
    }
    {
        call: 'helper-call "bpf_for_each_map_elem" elems {|m k v cb| 0 } "ctx" 0 --kind lru-hash'
        feature: "map:BPF_MAP_TYPE_LRU_HASH"
    }
    {
        call: 'helper-call "bpf_for_each_map_elem" elems {|m k v cb| 0 } "ctx" 0 --kind per-cpu-hash'
        feature: "map:BPF_MAP_TYPE_PERCPU_HASH"
    }
    {
        call: 'helper-call "bpf_for_each_map_elem" elems {|m k v cb| 0 } "ctx" 0 --kind per-cpu-array'
        feature: "map:BPF_MAP_TYPE_PERCPU_ARRAY"
    }
    {
        call: 'helper-call "bpf_for_each_map_elem" elems {|m k v cb| 0 } "ctx" 0 --kind lru-per-cpu-hash'
        feature: "map:BPF_MAP_TYPE_LRU_PERCPU_HASH"
    }
    {
        call: 'helper-call "bpf_timer_init" timer timers 0 --kind hash'
        feature: "map:BPF_MAP_TYPE_HASH"
    }
    {
        call: 'helper-call "bpf_timer_init" timer timers 0 --kind array'
        feature: "map:BPF_MAP_TYPE_ARRAY"
    }
    {
        call: 'helper-call "bpf_timer_init" timer timers 0 --kind lru-hash'
        feature: "map:BPF_MAP_TYPE_LRU_HASH"
    }
    ]
    | each {|entry|
        {
            program: [
                '{|ctx|'
                $"  ($entry.call)"
                '  0'
                '}'
            ]
            feature_keys: [$entry.feature]
        }
    }
)

let FIXED_HELPER_MAP_KERNEL_FEATURE_EXPECTATIONS = (
    [
    {
        call: 'helper-call "bpf_tail_call" $ctx jumps 0'
        feature: "map:BPF_MAP_TYPE_PROG_ARRAY"
    }
    {
        call: 'helper-call "bpf_perf_event_output" $ctx custom_perf_out 0 "abcd" 4'
        feature: "map:BPF_MAP_TYPE_PERF_EVENT_ARRAY"
    }
    {
        call: 'helper-call "bpf_skb_output" $ctx packet_events 0 data 4'
        feature: "map:BPF_MAP_TYPE_PERF_EVENT_ARRAY"
    }
    {
        call: 'helper-call "bpf_xdp_output" $ctx packet_events 0 data 4'
        feature: "map:BPF_MAP_TYPE_PERF_EVENT_ARRAY"
    }
    {
        call: 'helper-call "bpf_perf_event_read" perf_events 0'
        feature: "map:BPF_MAP_TYPE_PERF_EVENT_ARRAY"
    }
    {
        call: 'helper-call "bpf_perf_event_read_value" perf_events 0 value 24'
        feature: "map:BPF_MAP_TYPE_PERF_EVENT_ARRAY"
    }
    {
        call: 'helper-call "bpf_get_stackid" $ctx custom_stacks 0'
        feature: "map:BPF_MAP_TYPE_STACK_TRACE"
    }
    {
        call: 'helper-call "bpf_skb_under_cgroup" $ctx cgroups 0'
        feature: "map:BPF_MAP_TYPE_CGROUP_ARRAY"
    }
    {
        call: 'helper-call "bpf_current_task_under_cgroup" cgroups 0'
        feature: "map:BPF_MAP_TYPE_CGROUP_ARRAY"
    }
    {
        call: 'helper-call "bpf_ringbuf_output" events data 4 0'
        feature: "map:BPF_MAP_TYPE_RINGBUF"
    }
    {
        call: 'helper-call "bpf_ringbuf_reserve" events 8 0'
        feature: "map:BPF_MAP_TYPE_RINGBUF"
    }
    {
        call: 'helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 dynptr'
        feature: "map:BPF_MAP_TYPE_RINGBUF"
    }
    {
        call: 'helper-call "bpf_ringbuf_query" custom_ringbuf 0'
        feature: "map:BPF_MAP_TYPE_RINGBUF"
    }
    {
        call: 'helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb| 0 } "ctx" 0'
        feature: "map:BPF_MAP_TYPE_USER_RINGBUF"
    }
    {
        call: 'helper-call "bpf_sk_redirect_map" $ctx socket_peers 0 0'
        feature: "map:BPF_MAP_TYPE_SOCKMAP"
    }
    {
        call: 'helper-call "bpf_sock_map_update" $ctx socket_peers key0 0'
        feature: "map:BPF_MAP_TYPE_SOCKMAP"
    }
    {
        call: 'helper-call "bpf_msg_redirect_map" $ctx socket_peers 0 0'
        feature: "map:BPF_MAP_TYPE_SOCKMAP"
    }
    {
        call: 'helper-call "bpf_sock_hash_update" $ctx socket_hash key0 0'
        feature: "map:BPF_MAP_TYPE_SOCKHASH"
    }
    {
        call: 'helper-call "bpf_msg_redirect_hash" $ctx socket_hash "peer-a" 0'
        feature: "map:BPF_MAP_TYPE_SOCKHASH"
    }
    {
        call: 'helper-call "bpf_sk_redirect_hash" $ctx socket_hash 0 0'
        feature: "map:BPF_MAP_TYPE_SOCKHASH"
    }
    {
        call: 'helper-call "bpf_sk_select_reuseport" $ctx reuseport_sockets key0 0'
        feature: "map:BPF_MAP_TYPE_REUSEPORT_SOCKARRAY"
    }
    {
        call: 'helper-call "bpf_sk_storage_get" socket_storage $ctx.sk 0 0'
        feature: "map:BPF_MAP_TYPE_SK_STORAGE"
    }
    {
        call: 'helper-call "bpf_sk_storage_delete" socket_storage $ctx.sk'
        feature: "map:BPF_MAP_TYPE_SK_STORAGE"
    }
    {
        call: 'helper-call "bpf_task_storage_get" task_state $ctx.task 0 0'
        feature: "map:BPF_MAP_TYPE_TASK_STORAGE"
    }
    {
        call: 'helper-call "bpf_task_storage_delete" task_state $ctx.task'
        feature: "map:BPF_MAP_TYPE_TASK_STORAGE"
    }
    {
        call: 'helper-call "bpf_inode_storage_get" inode_state $ctx.arg.file.f_inode 0 0'
        feature: "map:BPF_MAP_TYPE_INODE_STORAGE"
    }
    {
        call: 'helper-call "bpf_inode_storage_delete" inode_state $ctx.arg.file.f_inode'
        feature: "map:BPF_MAP_TYPE_INODE_STORAGE"
    }
    {
        call: 'helper-call "bpf_cgrp_storage_get" cgrp_state $ctx.current_cgroup 0 0'
        feature: "map:BPF_MAP_TYPE_CGRP_STORAGE"
    }
    {
        call: 'helper-call "bpf_cgrp_storage_delete" cgrp_state $ctx.current_cgroup'
        feature: "map:BPF_MAP_TYPE_CGRP_STORAGE"
    }
    {
        call: 'helper-call "bpf_get_local_storage" legacy_storage 0'
        feature: "map:BPF_MAP_TYPE_CGROUP_STORAGE"
    }
    ]
    | each {|entry|
        {
            program: [
                '{|ctx|'
                $"  ($entry.call)"
                '  0'
                '}'
            ]
            feature_keys: [$entry.feature]
        }
    }
)

let PROGRAM_MAP_HELPER_STORAGE_KERNEL_FEATURE_EXPECTATIONS = (
    [
    ]
    | append $EXPLICIT_HELPER_MAP_KIND_KERNEL_FEATURE_EXPECTATIONS
    | append $FIXED_HELPER_MAP_KERNEL_FEATURE_EXPECTATIONS
    | append $PROGRAM_MAP_STORAGE_KERNEL_FEATURE_EXPECTATIONS
)
