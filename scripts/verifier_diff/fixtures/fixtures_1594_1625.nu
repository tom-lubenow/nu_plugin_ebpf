const VERIFIER_DIFF_FIXTURES_1594_1625 = [
    {
        name: "callback-bpf-loop-rejects-out-of-range-return"
        category: "callbacks"
        tags: [helper-call callback bpf-loop return reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_loop" 4 {|i cb| 2 } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "callback return"
    }
    {
        name: "callback-bpf-loop-allows-prefix-params"
        category: "callbacks"
        tags: [helper-call callback bpf-loop prefix-arity accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_loop" 4 {|i|'
            '    $i | count'
            '    0'
            '  } "ctx" 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-bpf-loop-rejects-extra-declared-param"
        category: "callbacks"
        tags: [helper-call callback bpf-loop reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_loop" 4 {|i cb extra| $i } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "declares 3 parameters, but the callback ABI supplies 2"
    }
    {
        name: "callback-for-each-map-elem"
        category: "callbacks"
        tags: [helper-call callback map array]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define elems --kind array --value-type "record{seen:u64}"'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb|'
            '    $v.seen | count'
            '    0'
            '  } "ctx" 0 --kind array'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-for-each-map-elem-rejects-extra-declared-param"
        category: "callbacks"
        tags: [helper-call callback map array reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define elems --kind array --value-type "record{seen:u64}"'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb extra|'
            '    0'
            '  } "ctx" 0 --kind array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "declares 5 parameters, but the callback ABI supplies 4"
    }
    {
        name: "callback-for-each-map-elem-rejects-out-of-range-return"
        category: "callbacks"
        tags: [helper-call callback map array return reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define elems --kind array --value-type "record{seen:u64}"'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb| 2 } "ctx" 0 --kind array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "callback return"
    }
    {
        name: "callback-for-each-map-elem-record-context"
        category: "callbacks"
        tags: [helper-call callback map array record]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define elems --kind array --value-type "record{seen:u64}"'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb|'
            '    $cb.threshold | count'
            '    0'
            '  } { threshold: 7 } 0 --kind array'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-for-each-map-elem-allows-prefix-params"
        category: "callbacks"
        tags: [helper-call callback map array prefix-arity accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define elems --kind array --value-type "record{seen:u64}"'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v|'
            '    $v.seen | count'
            '    0'
            '  } "ctx" 0 --kind array'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-for-each-map-elem-map-btf-field"
        category: "callbacks"
        tags: [helper-call callback map btf kernel-btf]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define elems --kind array --value-type "record{seen:u64}"'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb|'
            '    $m.id | count'
            '    0'
            '  } "ctx" 0 --kind array'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-map-sum-elem-count-for-each-map-callback"
        category: "callbacks"
        tags: [kfunc helper-call callback map btf kernel-btf accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define elems --kind array --value-type "record{seen:u64}"'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb|'
            '    let total = (kfunc-call "bpf_map_sum_elem_count" $m)'
            '    $total | count'
            '    0'
            '  } "ctx" 0 --kind array'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-map-sum-elem-count-rejects-stack-pointer"
        category: "callbacks"
        tags: [kfunc callback map pointer reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let stack_map = "abcdefgh"'
            '  kfunc-call "bpf_map_sum_elem_count" $stack_map'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_map_sum_elem_count' arg0 expects kernel pointer, got Stack"
    }
    {
        name: "callback-for-each-map-elem-rejects-nonzero-flags"
        category: "callbacks"
        tags: [helper-call callback map array flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define elems --kind array --value-type "record{seen:u64}"'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb|'
            '    0'
            '  } "ctx" 1 --kind array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_for_each_map_elem' requires arg3 flags to be 0"
    }
    {
        name: "callback-for-each-map-elem-rejects-dynamic-flags"
        category: "callbacks"
        tags: [helper-call callback map array flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define elems --kind array --value-type "record{seen:u64}"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb|'
            '    0'
            '  } "ctx" $flags --kind array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_for_each_map_elem' requires arg3 flags to be 0"
    }
    {
        name: "callback-find-vma-btf-field"
        category: "callbacks"
        tags: [helper-call callback btf kernel-btf]
        requires: [kernel-btf]
        target: "kprobe:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_find_vma" $ctx.current_task 0 {|task vma cb|'
            '    $vma.vm_start | count'
            '    0'
            '  } "ctx" 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-find-vma-rejects-nonzero-flags"
        category: "callbacks"
        tags: [helper-call callback btf kernel-btf flags reject]
        requires: [kernel-btf]
        target: "kprobe:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_find_vma" $ctx.current_task 0 {|task vma cb|'
            '    0'
            '  } "ctx" 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_find_vma' requires arg4 flags to be 0"
    }
    {
        name: "callback-find-vma-rejects-dynamic-flags"
        category: "callbacks"
        tags: [helper-call callback btf kernel-btf flags reject]
        requires: [kernel-btf]
        target: "kprobe:tcp_connect"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_find_vma" $ctx.current_task 0 {|task vma cb|'
            '    0'
            '  } "ctx" $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_find_vma' requires arg4 flags to be 0"
    }
    {
        name: "callback-find-vma-rejects-extra-declared-param"
        category: "callbacks"
        tags: [helper-call callback btf kernel-btf reject]
        requires: [kernel-btf]
        target: "kprobe:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_find_vma" $ctx.current_task 0 {|task vma cb extra|'
            '    0'
            '  } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "declares 4 parameters, but the callback ABI supplies 3"
    }
    {
        name: "callback-find-vma-rejects-out-of-range-return"
        category: "callbacks"
        tags: [helper-call callback btf kernel-btf return reject]
        requires: [kernel-btf]
        target: "kprobe:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_find_vma" $ctx.current_task 0 {|task vma cb| 2 } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "callback return"
    }
    {
        name: "callback-find-vma-rejects-non-task-pointer"
        category: "callbacks"
        tags: [helper-call callback btf reject]
        target: "kprobe:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_find_vma" $ctx 0 {|task vma cb|'
            '    0'
            '  } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_find_vma' arg0 expects task pointer"
    }
    {
        name: "callback-find-vma-record-context"
        category: "callbacks"
        tags: [helper-call callback btf kernel-btf record]
        requires: [kernel-btf]
        target: "kprobe:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_find_vma" $ctx.current_task 0 {|task vma cb|'
            '    $cb.cookie | count'
            '    0'
            '  } { cookie: 11 } 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-find-vma-allows-prefix-params"
        category: "callbacks"
        tags: [helper-call callback btf kernel-btf prefix-arity accept]
        requires: [kernel-btf]
        target: "kprobe:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_find_vma" $ctx.current_task 0 {|task vma|'
            '    $task.pid | count'
            '    0'
            '  } "ctx" 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-user-ringbuf-drain"
        category: "callbacks"
        tags: [helper-call callback dynptr user-ringbuf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb| 0 } "ctx" 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-user-ringbuf-drain-dynptr-data-guarded"
        category: "callbacks"
        tags: [helper-call callback dynptr user-ringbuf null-check accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb|'
            '    let data = (helper-call "bpf_dynptr_data" $dyn 0 4)'
            '    if $data {'
            '      $data | count'
            '    }'
            '    0'
            '  } "ctx" 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-user-ringbuf-drain-dynptr-data-requires-null-check"
        category: "callbacks"
        tags: [helper-call callback dynptr user-ringbuf null-check reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb|'
            '    helper-call "bpf_dynptr_data" $dyn 0 4 | count'
            '    0'
            '  } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "may dereference null pointer"
    }
    {
        name: "callback-user-ringbuf-drain-allows-prefix-params"
        category: "callbacks"
        tags: [helper-call callback dynptr user-ringbuf prefix-arity accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn| 0 } "ctx" 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-user-ringbuf-drain-rejects-extra-declared-param"
        category: "callbacks"
        tags: [helper-call callback dynptr user-ringbuf reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb extra| 0 } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "declares 3 parameters, but the callback ABI supplies 2"
    }
    {
        name: "callback-user-ringbuf-drain-rejects-out-of-range-return"
        category: "callbacks"
        tags: [helper-call callback dynptr user-ringbuf return reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb| 2 } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "callback return"
    }
    {
        name: "callback-user-ringbuf-drain-record-context"
        category: "callbacks"
        tags: [helper-call callback dynptr user-ringbuf record]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb| $cb.limit } { limit: 1 } 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "reserved-events-rejects-user-ringbuf"
        category: "maps"
        tags: [helper-call callback user-ringbuf reject reserved-name]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_user_ringbuf_drain" events {|dyn cb| 0 } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map name 'events' is reserved"
    }
    {
        name: "helper-call-kind-rejects-implied-map-kind"
        category: "maps"
        tags: [helper-call map-kind reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_ringbuf_query" demo_ringbuf 0 --kind ringbuf'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper-call --kind is only supported for helpers whose map family is ambiguous"
    }
    {
        name: "csum-diff-allows-null-zero-side"
        category: "helper-state"
        tags: [csum null-pointer tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  helper-call "bpf_csum_diff" 0 0 0 0 0 | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "csum-diff-rejects-null-nonzero-side"
        category: "helper-state"
        tags: [csum null-pointer reject tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  helper-call "bpf_csum_diff" 0 4 0 0 0'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 28 arg0 requires arg1 = 0 when arg0 is null"
    }
]
