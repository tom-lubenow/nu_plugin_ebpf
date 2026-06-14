const VERIFIER_DIFF_FIXTURES_1313_1328_A = [
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
            '  let lock_key = ($key + 2)'
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
]
