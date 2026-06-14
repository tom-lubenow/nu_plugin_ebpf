const PROGRAM_MAP_VALUE_KERNEL_FEATURE_EXPECTATIONS = [
    {
        program: [
            '{|ctx|'
            '  let text = "map-define resources --kind hash --value-type record{lock:bpf_spin_lock}"'
            '  # map-define resources --kind hash --value-type "record{timer:bpf_timer}"'
            '  map-define docs --kind hash # --value-type "record{lock:bpf_spin_lock}"'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  map-define resources --kind hash --value-type "record{lock:bpf_spin_lock,timer:bpf_timer,task:kptr:task_struct,work:bpf_wq,refs:bpf_refcount}"'
            '  0'
            '}'
        ]
        feature_keys: [
            "map-value:bpf_spin_lock"
            "map-value:bpf_timer"
            "map-value:kptr"
            "map-value:bpf_wq"
            "map-value:bpf_refcount"
        ]
    }
    {
        program: [
            '{|ctx|'
            '  map-define list_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node}"'
            '  0'
            '}'
        ]
        feature_keys: [
            "map-value:bpf_spin_lock"
            "map-value:bpf_list_head"
            "map-value:bpf_list_node"
        ]
    }
    {
        program: [
            '{|ctx|'
            '  map-define list_items --kind hash --value-type "record{root:bpf_list_head:node_data:node:record{refs:bpf_refcount,cookie:u64}}"'
            '  0'
            '}'
        ]
        feature_keys: [
            "map-value:bpf_list_head"
            "map-value:bpf_list_node"
            "map-value:bpf_refcount"
        ]
    }
    {
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:node_data:node}"'
            '  0'
            '}'
        ]
        feature_keys: [
            "map-value:bpf_spin_lock"
            "map-value:bpf_rb_root"
            "map-value:bpf_rb_node"
        ]
    }
    {
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{root:bpf_rb_root:rb_item:rb:record{refs:bpf_refcount,cookie:u64}}"'
            '  0'
            '}'
        ]
        feature_keys: [
            "map-value:bpf_rb_root"
            "map-value:bpf_rb_node"
            "map-value:bpf_refcount"
        ]
    }
]
