const VERIFIER_DIFF_FIXTURES_1594_1625_A = [
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
]
