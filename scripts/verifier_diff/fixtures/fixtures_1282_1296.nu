const VERIFIER_DIFF_FIXTURES_1282_1296 = [
    {
        name: "source-kfunc-list-front-rejects-rbtree-root"
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
            '    let obj = (kfunc-call "bpf_list_front" $entry.root)'
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
        name: "source-kfunc-list-push-front-rejects-dynamic-meta"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      let meta = ($ctx.packet_len + 1)'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '      kfunc-call "bpf_list_push_front_impl" $entry.root $obj $meta 0'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_list_push_front_impl' arg2 must be known zero"
    }
    {
        name: "source-kfunc-list-push-back-rejects-dynamic-meta"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      let meta = ($ctx.packet_len + 1)'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '      kfunc-call "bpf_list_push_back_impl" $entry.root $obj $meta 0'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_list_push_back_impl' arg2 must be known zero"
    }
    {
        name: "source-kfunc-list-push-back-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '      kfunc-call "bpf_list_push_back_impl" $entry.root $obj 0 0'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-push-back-rejects-missing-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      kfunc-call "bpf_list_push_back_impl" $entry.root $obj 0 0'
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
        name: "source-kfunc-list-push-back-rejects-different-map-spin-lock"
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
            '      let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '      if $obj {'
            '        helper-call "bpf_spin_lock" $lock_entry.lock'
            '        kfunc-call "bpf_list_push_back_impl" $entry.root $obj 0 0'
            '        helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      }'
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
        name: "source-kfunc-list-push-back-rejects-rbtree-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '      kfunc-call "bpf_list_push_back_impl" $entry.root $obj 0 0'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_list_head pointer"
    }
    {
        name: "source-kfunc-list-push-back-same-key-repeated-map-root"
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
            '      let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '      if $obj {'
            '        helper-call "bpf_spin_lock" $lock_entry.lock'
            '        kfunc-call "bpf_list_push_back_impl" $root_entry.root $obj 0 0'
            '        helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-push-back-rejects-different-key-repeated-map-root"
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
            '      let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '      if $obj {'
            '        helper-call "bpf_spin_lock" $lock_entry.lock'
            '        kfunc-call "bpf_list_push_back_impl" $root_entry.root $obj 0 0'
            '        helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      }'
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
        name: "source-kfunc-list-pop-front-map-root"
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
            '    let obj = (kfunc-call "bpf_list_pop_front" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-pop-front-rejects-missing-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_list_pop_front" $entry.root)'
            '    if $obj {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
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
        name: "source-kfunc-list-pop-front-rejects-different-map-spin-lock"
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
            '      let obj = (kfunc-call "bpf_list_pop_front" $entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj {'
            '        kfunc-call "bpf_obj_drop_impl" $obj 0'
            '      }'
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
        name: "source-kfunc-list-pop-front-rejects-rbtree-root"
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
            '    let obj = (kfunc-call "bpf_list_pop_front" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_list_head pointer"
    }
    {
        name: "source-kfunc-list-pop-front-same-key-repeated-map-root"
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
            '      let obj = (kfunc-call "bpf_list_pop_front" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj {'
            '        kfunc-call "bpf_obj_drop_impl" $obj 0'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-pop-front-rejects-different-key-repeated-map-root"
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
            '      let obj = (kfunc-call "bpf_list_pop_front" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj {'
            '        kfunc-call "bpf_obj_drop_impl" $obj 0'
            '      }'
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
