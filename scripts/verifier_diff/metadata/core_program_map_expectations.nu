const PROGRAM_MAP_KERNEL_FEATURE_EXPECTATIONS = [
    {
        program: [
            '{|ctx|'
            '  let text = "helper-call \"bpf_ringbuf_query\" custom_ringbuf 0"'
            '  # helper-call "bpf_redirect_map" redirects 0 0 --kind devmap-hash'
            '  let docs = "redirect-map tx_ports 0 --kind devmap"'
            '  let more_docs = "map-define xsks --kind xskmap"'
            '  let ignored = 0 # | helper-call "bpf_map_lookup_percpu_elem" values key 0 --kind lru-per-cpu-hash'
            '  let more_ignored = 0 # | map-get values --kind queue'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  let entry = ($ctx.pid | map-get default_counts)'
            '  if $entry { $entry | count }'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_HASH"]
    }
    {
        program: [
            '{|ctx|'
            '  map-define array_counts --kind array --key-type u32 --value-type u64'
            '  let entry = ($ctx.pid | map-get array_counts)'
            '  1 | map-put array_counts $ctx.pid'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_ARRAY"]
    }
    {
        program: [
            '{|ctx|'
            '  let entry = ($ctx.pid | map-get lru_counts --kind lru-hash)'
            '  if $entry { 1 | map-put lru_counts $ctx.pid }'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_LRU_HASH"]
    }
    {
        program: [
            '{|ctx|'
            '  let inner = ($ctx.pid | map-get outer_maps --kind array-of-maps)'
            '  if $inner { $ctx.pid | map-get $inner }'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_ARRAY_OF_MAPS"]
    }
    {
        program: [
            '{|ctx|'
            '  redirect-map tx_ports 0 --kind devmap'
            '  redirect-map tx_hash 0 --kind devmap-hash'
            '  redirect-map cpu_targets 0 --kind cpumap'
            '  redirect-map xsks 0 --kind xskmap'
            '  0'
            '}'
        ]
        feature_keys: [
            "map:BPF_MAP_TYPE_DEVMAP"
            "map:BPF_MAP_TYPE_DEVMAP_HASH"
            "map:BPF_MAP_TYPE_CPUMAP"
            "map:BPF_MAP_TYPE_XSKMAP"
        ]
    }
    {
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockmap'
            '  redirect-socket hash_peers 0 --kind sockhash'
            '  redirect-socket sockets 0 --kind reuseport-sockarray'
            '  0'
            '}'
        ]
        feature_keys: [
            "map:BPF_MAP_TYPE_SOCKMAP"
            "map:BPF_MAP_TYPE_SOCKHASH"
            "map:BPF_MAP_TYPE_REUSEPORT_SOCKARRAY"
        ]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_map" redirects 0 0 --kind devmap-hash'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_DEVMAP_HASH"]
    }
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
    {
        program: [
            '{|ctx|'
            '  $ctx.task | map-get task_state --kind task-storage --init { hits: 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_TASK_STORAGE"]
    }
    {
        program: [
            '{|ctx|'
            '  $ctx.arg.file.f_inode | map-delete inode_state --kind inode-storage'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_INODE_STORAGE"]
    }
    {
        program: [
            '{|ctx|'
            '  $ctx.current_cgroup | map-contains cgrp_state --kind cgrp-storage'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_CGRP_STORAGE"]
    }
    {
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  map-define outer_hash --kind hash-of-maps --key-type u32 --inner-map inner_seen --max-entries 4'
            '  0'
            '}'
        ]
        feature_keys: [
            "map:BPF_MAP_TYPE_HASH"
            "map:BPF_MAP_TYPE_ARRAY_OF_MAPS"
            "map:BPF_MAP_TYPE_HASH_OF_MAPS"
        ]
    }
]
