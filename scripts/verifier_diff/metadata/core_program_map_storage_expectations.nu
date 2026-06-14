const PROGRAM_MAP_STORAGE_KERNEL_FEATURE_EXPECTATIONS = [
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
