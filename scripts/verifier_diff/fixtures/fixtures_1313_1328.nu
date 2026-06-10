const VERIFIER_DIFF_FIXTURES_1313_1328 = [
    {
        name: "source-kfunc-list-front-equivalent-expr-dynamic-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --key-type u64 --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let key = $ctx.packet_len'
            '  let lock_key = ($key + 1)'
            '  let root_key = ($key + 1)'
            '  let lock_entry = ($lock_key | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($root_key | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_front" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-front-rejects-offset-dynamic-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --key-type u64 --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let key = $ctx.packet_len'
            '  let root_key = ($key + 1)'
            '  let lock_entry = ($key | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($root_key | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_front" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-front-rejects-different-expr-dynamic-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --key-type u64 --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let key = $ctx.packet_len'
            '  let lock_key = ($key + 1)'
            '  let root_key = ($key + 2)'
            '  let lock_entry = ($lock_key | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($root_key | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_front" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-front-phi-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source phi accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let base_key = $ctx.packet_len'
            '  let left_key = $base_key'
            '  let right_key = $base_key'
            '  let key = (if $selector == 0 { $left_key } else { $right_key })'
            '  let lock_entry = ($key | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($key | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_front" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-front-rejects-different-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let lock_entry = (0 | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = (1 | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_front" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-front-rejects-different-dynamic-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let lock_key = $ctx.packet_len'
            '  let root_key = $ctx.ifindex'
            '  let lock_entry = ($lock_key | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($root_key | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_front" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-back-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let obj = (kfunc-call "bpf_list_back" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj {'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-back-rejects-missing-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_list_back" $entry.root)'
            '    if $obj {'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-back-rejects-different-map-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let lock_entry = (0 | map-get locks --kind hash)'
            '    if $lock_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_back" $entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-back-rejects-rbtree-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let obj = (kfunc-call "bpf_list_back" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj { 0 }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_list_head pointer"
    }
    {
        name: "source-kfunc-list-back-projects-object-payload"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node:record{refs:bpf_refcount,cookie:u64}}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_list_back" $entry.root)'
            '    if $node {'
            '      let cookie = $node.cookie'
            '      let clone = (kfunc-call "bpf_refcount_acquire_impl" $node 0)'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      if $clone {'
            '        kfunc-call "bpf_obj_drop_impl" $clone 0'
            '      }'
            '      $cookie'
            '    } else {'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-back-refcount-acquire-rejects-object-without-refcount"
        category: "helper-state"
        tags: [kfunc object graph bpf_refcount source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node:record{cookie:u64}}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_list_back" $entry.root)'
            '    if $node {'
            '      let clone = (kfunc-call "bpf_refcount_acquire_impl" $node 0)'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      if $clone {'
            '        kfunc-call "bpf_obj_drop_impl" $clone 0'
            '      }'
            '    } else {'
            '      helper-call "bpf_spin_unlock" $entry.lock'
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
        name: "source-kfunc-list-back-same-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let key = 0'
            '  let lock_entry = ($key | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($key | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_back" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-back-rejects-different-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let lock_entry = (0 | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = (1 | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_back" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-rbtree-first-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let obj = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj {'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rbtree-first-rejects-missing-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    if $obj {'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
]
