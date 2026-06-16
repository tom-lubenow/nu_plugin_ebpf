const VERIFIER_DIFF_FIXTURES_1297_1312_A = [
    {
        name: "source-kfunc-list-pop-front-projects-object-payload"
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
            '    let obj = (kfunc-call "bpf_list_pop_front" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj {'
            '      let cookie = $obj.cookie'
            '      let clone = (kfunc-call "bpf_refcount_acquire_impl" $obj 0)'
            '      if $clone {'
            '        kfunc-call "bpf_obj_drop_impl" $clone 0'
            '      }'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '      $cookie'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-pop-front-refcount-acquire-accepts-nested-refcount-payload"
        category: "helper-state"
        tags: [kfunc object graph bpf_refcount source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node:record{meta:record{refs:bpf_refcount},cookie:u64}}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let obj = (kfunc-call "bpf_list_pop_front" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj {'
            '      let clone = (kfunc-call "bpf_refcount_acquire_impl" $obj 0)'
            '      if $clone {'
            '        kfunc-call "bpf_obj_drop_impl" $clone 0'
            '      }'
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
        name: "source-kfunc-refcount-acquire-rejects-graph-object-without-refcount"
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
            '    let obj = (kfunc-call "bpf_list_pop_front" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj {'
            '      let clone = (kfunc-call "bpf_refcount_acquire_impl" $obj 0)'
            '      if $clone {'
            '        kfunc-call "bpf_obj_drop_impl" $clone 0'
            '      }'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 expects object pointer containing bpf_refcount"
    }
]
