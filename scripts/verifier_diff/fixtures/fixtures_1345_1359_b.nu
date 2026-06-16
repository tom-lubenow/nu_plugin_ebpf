const VERIFIER_DIFF_FIXTURES_1345_1359_B = [
    {
        name: "source-kfunc-rbtree-right-refcount-acquire-rejects-object-without-refcount"
        category: "helper-state"
        tags: [kfunc object graph bpf_refcount source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb:record{cookie:u64}}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $node {'
            '      let right = (kfunc-call "bpf_rbtree_right" $node)'
            '      if $right {'
            '        let clone = (kfunc-call "bpf_refcount_acquire_impl" $right 0)'
            '        if $clone {'
            '          kfunc-call "bpf_obj_drop_impl" $clone 0'
            '        }'
            '      }'
            '    } else {'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 expects object pointer containing bpf_refcount"
    }
    {
        name: "source-kfunc-rbtree-root-rejects-map-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let root = (kfunc-call "bpf_rbtree_root" $entry.root)'
            '    if $root {'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects kernel pointer, got Map"
    }
    {
        name: "source-kfunc-rbtree-left-rejects-list-node"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_list_front" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $node {'
            '      let left = (kfunc-call "bpf_rbtree_left" $node)'
            '      if $left {'
            '        0'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_rb_node pointer"
    }
    {
        name: "source-kfunc-rbtree-right-rejects-list-node"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_list_front" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $node {'
            '      let right = (kfunc-call "bpf_rbtree_right" $node)'
            '      if $right {'
            '        0'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_rb_node pointer"
    }
    {
        name: "source-kfunc-rbtree-root-rejects-list-node"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_list_front" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $node {'
            '      let root = (kfunc-call "bpf_rbtree_root" $node)'
            '      if $root {'
            '        0'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_rb_node pointer"
    }
]
