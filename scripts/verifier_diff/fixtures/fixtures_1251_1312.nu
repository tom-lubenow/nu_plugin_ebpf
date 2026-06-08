const VERIFIER_DIFF_FIXTURES_1251_1312 = [
    {
        name: "source-kfunc-obj-new-rejects-dynamic-type-id"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let type_id = ($ctx.pid + 1)'
            '  let obj = (kfunc-call "bpf_obj_new_impl" $type_id 0)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 must be known constant"
    }
    {
        name: "source-kfunc-obj-new-rejects-zero-type-id"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 0 0)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 must be > 0"
    }
    {
        name: "source-kfunc-obj-new-rejects-dynamic-meta"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let meta = ($ctx.pid + 1)'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 $meta)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_obj_new_impl' arg1 must be known zero"
    }
    {
        name: "source-kfunc-obj-drop-rejects-nonzero-meta"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 1'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_obj_drop_impl' arg1 must be known zero"
    }
    {
        name: "source-kfunc-obj-drop-rejects-double-drop"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_obj_drop_impl' arg0 reference already released"
    }
    {
        name: "source-kfunc-obj-drop-accepts-both-branch-release"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source phi accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  if $obj {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    if $selector == 0 {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    } else {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-obj-drop-rejects-one-branch-release-leak"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source phi reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  if $obj {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    if $selector == 0 {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-obj-drop-rejects-release-after-conditional-release"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source phi reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  if $obj {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    if $selector == 0 {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_obj_drop_impl' arg0 reference already released"
    }
    {
        name: "source-kfunc-refcount-acquire-rejects-map-field"
        category: "helper-state"
        tags: [kfunc object bpf_refcount ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ref_items --kind hash --value-type "record{refs:bpf_refcount,cookie:u64}"'
            '  let entry = (0 | map-get ref_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_refcount_acquire_impl" $entry.refs 0)'
            '    if $obj {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects kernel pointer, got Map"
    }
    {
        name: "source-kfunc-refcount-acquire-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc object bpf_refcount ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    let obj = (kfunc-call "bpf_refcount_acquire_impl" $task 0)'
            '    if $obj {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '    kfunc-call "bpf_task_release" $task'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects object reference"
    }
    {
        name: "source-kfunc-percpu-obj-new-drop"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  if $obj {'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-percpu-obj-drop-accepts-new-or-null-release"
        category: "helper-state"
        tags: [kfunc object ref-lifetime phi source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let obj = (if $selector == 0 { kfunc-call "bpf_percpu_obj_new_impl" 1 0 } else { 0 })'
            '  if $obj {'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-percpu-obj-new-rejects-leak"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-percpu-obj-new-rejects-dynamic-type-id"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let type_id = ($ctx.pid + 1)'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" $type_id 0)'
            '  if $obj {'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 must be known constant"
    }
    {
        name: "source-kfunc-percpu-obj-new-rejects-zero-type-id"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 0 0)'
            '  if $obj {'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 must be > 0"
    }
    {
        name: "source-kfunc-percpu-obj-new-rejects-dynamic-meta"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let meta = ($ctx.pid + 1)'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 $meta)'
            '  if $obj {'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_percpu_obj_new_impl' arg1 must be known zero"
    }
    {
        name: "source-kfunc-percpu-obj-drop-rejects-dynamic-meta"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  if $obj {'
            '    let meta = ($ctx.pid + 1)'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj $meta'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_percpu_obj_drop_impl' arg1 must be known zero"
    }
    {
        name: "source-kfunc-percpu-obj-drop-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $task 0'
            '    kfunc-call "bpf_task_release" $task'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects object reference"
    }
    {
        name: "source-kfunc-obj-drop-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    kfunc-call "bpf_obj_drop_impl" $task 0'
            '    kfunc-call "bpf_task_release" $task'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects object reference"
    }
    {
        name: "source-kfunc-percpu-obj-drop-rejects-double-drop"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  if $obj {'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_percpu_obj_drop_impl' arg0 reference already released"
    }
    {
        name: "source-kfunc-percpu-obj-drop-accepts-both-branch-release"
        category: "helper-state"
        tags: [kfunc object ref-lifetime branch source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  if $obj {'
            '    if $ctx.pid {'
            '      kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '    } else {'
            '      kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-percpu-obj-drop-rejects-one-branch-release-leak"
        category: "helper-state"
        tags: [kfunc object ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  if $obj {'
            '    if $ctx.pid {'
            '      kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-percpu-obj-drop-rejects-release-after-conditional-release"
        category: "helper-state"
        tags: [kfunc object ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  if $obj {'
            '    if $ctx.pid {'
            '      kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '    }'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_percpu_obj_drop_impl' arg0 reference already released"
    }
    {
        name: "source-kfunc-list-push-front-map-root"
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
            '      kfunc-call "bpf_list_push_front_impl" $entry.root $obj 0 0'
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
        name: "source-kfunc-list-push-front-rejects-missing-spin-lock"
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
            '      kfunc-call "bpf_list_push_front_impl" $entry.root $obj 0 0'
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
        name: "source-kfunc-list-push-front-rejects-different-map-spin-lock"
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
            '        kfunc-call "bpf_list_push_front_impl" $entry.root $obj 0 0'
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
        name: "source-kfunc-list-push-front-rejects-rbtree-root"
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
            '      kfunc-call "bpf_list_push_front_impl" $entry.root $obj 0 0'
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
        name: "source-kfunc-list-push-front-same-key-repeated-map-root"
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
            '        kfunc-call "bpf_list_push_front_impl" $root_entry.root $obj 0 0'
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
        name: "source-kfunc-list-push-front-rejects-different-key-repeated-map-root"
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
            '        kfunc-call "bpf_list_push_front_impl" $root_entry.root $obj 0 0'
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
        name: "source-kfunc-list-front-rejects-missing-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_list_front" $entry.root)'
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
        name: "source-kfunc-list-front-rejects-different-map-spin-lock"
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
            '      let obj = (kfunc-call "bpf_list_front" $entry.root)'
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
    {
        name: "source-kfunc-list-pop-back-map-root"
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
            '    let obj = (kfunc-call "bpf_list_pop_back" $entry.root)'
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
        name: "source-kfunc-list-pop-back-rejects-missing-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_list_pop_back" $entry.root)'
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
        name: "source-kfunc-list-pop-back-rejects-different-map-spin-lock"
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
            '      let obj = (kfunc-call "bpf_list_pop_back" $entry.root)'
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
        name: "source-kfunc-list-pop-back-rejects-rbtree-root"
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
            '    let obj = (kfunc-call "bpf_list_pop_back" $entry.root)'
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
        name: "source-kfunc-list-pop-back-same-key-repeated-map-root"
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
            '      let obj = (kfunc-call "bpf_list_pop_back" $root_entry.root)'
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
        name: "source-kfunc-list-pop-back-rejects-different-key-repeated-map-root"
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
            '      let obj = (kfunc-call "bpf_list_pop_back" $root_entry.root)'
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
        name: "source-kfunc-list-front-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,lock:bpf_spin_lock,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let obj = (kfunc-call "bpf_list_front" $entry.root)'
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
        name: "source-kfunc-list-front-projects-object-payload"
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
            '    let node = (kfunc-call "bpf_list_front" $entry.root)'
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
        name: "source-kfunc-list-front-refcount-acquire-rejects-object-without-refcount"
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
            '    let node = (kfunc-call "bpf_list_front" $entry.root)'
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
        name: "source-kfunc-list-front-same-key-repeated-map-root"
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
        name: "source-kfunc-list-front-dynamic-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let key = $ctx.packet_len'
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
        name: "source-kfunc-list-front-copied-dynamic-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let key = $ctx.packet_len'
            '  let lock_key = $key'
            '  let root_key = $key'
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
        name: "source-kfunc-list-front-noop-dynamic-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let key = $ctx.packet_len'
            '  let root_key = ($key + 0)'
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
        local: "accept"
        kernel: "accept"
    }
]
