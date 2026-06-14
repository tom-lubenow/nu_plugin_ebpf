let PROGRAM_MAP_KERNEL_FEATURE_EXPECTATIONS = (
    [
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
    ]
    | append $PROGRAM_MAP_REDIRECT_KERNEL_FEATURE_EXPECTATIONS
    | append $PROGRAM_MAP_HELPER_STORAGE_KERNEL_FEATURE_EXPECTATIONS
)
