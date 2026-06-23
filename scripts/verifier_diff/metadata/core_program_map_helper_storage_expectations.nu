let PROGRAM_MAP_HELPER_STORAGE_KERNEL_FEATURE_EXPECTATIONS = (
    [
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_map_lookup_percpu_elem" per_cpu_values key0 0 --kind lru-per-cpu-hash'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_LRU_PERCPU_HASH"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb| 0 } "ctx" 0 --kind per-cpu-array'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_PERCPU_ARRAY"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_timer_init" timer timers 0 --kind array'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_ARRAY"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_map_push_elem" queue_or_bloom 1 0 --kind bloom-filter'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_BLOOM_FILTER"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_map_push_elem" raw_queue value 0 --kind queue'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_QUEUE"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_map_push_elem" raw_stack value 0 --kind stack'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_STACK"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_map_peek_elem" raw_queue value --kind queue'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_QUEUE"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_map_peek_elem" raw_stack value --kind stack'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_STACK"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_map_pop_elem" raw_queue value --kind queue'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_QUEUE"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_map_pop_elem" raw_stack value --kind stack'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_STACK"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_ringbuf_query" custom_ringbuf 0'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_RINGBUF"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_stackid" $ctx custom_stacks 0'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_STACK_TRACE"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_sk_redirect_hash" $ctx socket_hash 0 0'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_SOCKHASH"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_sk_storage_get" socket_storage $ctx.sk 0 0'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_SK_STORAGE"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_perf_event_output" $ctx custom_perf_out 0 "abcd" 4'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_PERF_EVENT_ARRAY"]
    }
    ]
    | append $PROGRAM_MAP_STORAGE_KERNEL_FEATURE_EXPECTATIONS
)
