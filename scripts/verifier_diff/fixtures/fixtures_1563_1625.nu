const VERIFIER_DIFF_FIXTURES_1563_1625 = [
    {
        name: "snprintf-accepts-map-format-and-stack-data"
        category: "helper-state"
        tags: [helper-call snprintf accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let out = "00000000000000000000000000000000"'
            '  map-define snprintf_fmt --kind array --value-type bytes:9 --max-entries 1'
            '  let fmt = (0 | map-get snprintf_fmt)'
            '  let data = "0123456789abcdef"'
            '  if $fmt { helper-call "bpf_snprintf" $out 32 $fmt $data 16 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "snprintf-rejects-extra-format-size-arg"
        category: "helper-state"
        tags: [helper-call snprintf reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let out = "00000000000000000000000000000000"'
            '  let fmt = "value %d\u{0}"'
            '  let data = "0123456789abcdef"'
            '  helper-call "bpf_snprintf" $out 32 $fmt 9 $data 16'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "BPF helper calls support at most 5 arguments"
    }
    {
        name: "snprintf-btf-rejects-negative-output-size"
        category: "helper-state"
        tags: [helper-call snprintf-btf scalar-policy reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let out = "00000000000000000000000000000000"'
            '  let btf_ptr = "0123456789abcdef"'
            '  let size = (0 - 1)'
            '  helper-call "bpf_snprintf_btf" $out $size $btf_ptr 16 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 149 arg1 must be > 0"
    }
    {
        name: "snprintf-btf-rejects-dynamic-negative-output-size"
        category: "helper-state"
        tags: [helper-call snprintf-btf scalar-policy dynamic reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let out = "00000000000000000000000000000000"'
            '  let btf_ptr = "0123456789abcdef"'
            '  let size = (0 - (helper-call "bpf_get_prandom_u32"))'
            '  helper-call "bpf_snprintf_btf" $out $size $btf_ptr 16 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 149 arg1 must be > 0"
    }
    {
        name: "snprintf-btf-rejects-bad-btf-ptr-size"
        category: "helper-state"
        tags: [helper-call snprintf-btf scalar-policy reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let out = "00000000000000000000000000000000"'
            '  let btf_ptr = "0123456789abcdef"'
            '  helper-call "bpf_snprintf_btf" $out 32 $btf_ptr 8 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_snprintf_btf' requires arg3 = 16"
    }
    {
        name: "snprintf-btf-rejects-dynamic-btf-ptr-size"
        category: "helper-state"
        tags: [helper-call snprintf-btf scalar-policy dynamic reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let out = "00000000000000000000000000000000"'
            '  let btf_ptr = "0123456789abcdef"'
            '  let btf_size = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_snprintf_btf" $out 32 $btf_ptr $btf_size 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_snprintf_btf' requires arg3 = 16"
    }
    {
        name: "snprintf-btf-rejects-invalid-flags"
        category: "helper-state"
        tags: [helper-call snprintf-btf flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let out = "00000000000000000000000000000000"'
            '  let btf_ptr = "0123456789abcdef"'
            '  helper-call "bpf_snprintf_btf" $out 32 $btf_ptr 16 16'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_snprintf_btf' requires arg4 to contain only BTF_F_* bits"
    }
    {
        name: "snprintf-btf-rejects-dynamic-flags"
        category: "helper-state"
        tags: [helper-call snprintf-btf flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let out = "00000000000000000000000000000000"'
            '  let btf_ptr = "0123456789abcdef"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_snprintf_btf" $out 32 $btf_ptr 16 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_snprintf_btf' requires arg4 to contain only BTF_F_* bits"
    }
    {
        name: "snprintf-btf-rejects-small-btf-ptr-buffer"
        category: "helper-state"
        tags: [helper-call snprintf-btf bounds reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let out = "00000000000000000000000000000000"'
            '  map-define snprintf_btf_ptr --kind array --value-type bytes:8 --max-entries 1'
            '  let btf_ptr = (0 | map-get snprintf_btf_ptr)'
            '  if $btf_ptr { helper-call "bpf_snprintf_btf" $out 32 $btf_ptr 16 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper snprintf_btf ptr"
    }
    {
        name: "perf-event-read-helpers"
        category: "helper-state"
        tags: [perf-event helper-call]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  let value = "012345678901234567890123"'
            '  helper-call "bpf_perf_event_read" perf_events 0'
            '  helper-call "bpf_perf_event_read_value" perf_events 0 $value 24'
            '  helper-call "bpf_perf_prog_read_value" $ctx $value 24'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "perf-event-read-rejects-invalid-flags"
        category: "helper-state"
        tags: [perf-event flags reject]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  helper-call "bpf_perf_event_read" perf_events 4294967296'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "perf event read helpers require arg1 flags to fit BPF_F_INDEX_MASK/BPF_F_CURRENT_CPU"
    }
    {
        name: "perf-event-read-rejects-dynamic-out-of-range-flags"
        category: "helper-state"
        tags: [perf-event flags dynamic reject]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  let flags = ((helper-call "bpf_get_prandom_u32") + 4294967296)'
            '  helper-call "bpf_perf_event_read" perf_events $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "perf event read helpers require arg1 flags to fit BPF_F_INDEX_MASK/BPF_F_CURRENT_CPU"
    }
    {
        name: "perf-event-read-value-rejects-size"
        category: "helper-state"
        tags: [perf-event scalar-policy reject]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  let value = "01234567"'
            '  helper-call "bpf_perf_event_read_value" perf_events 0 $value 8'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_perf_event_read_value' requires arg3 = 24"
    }
    {
        name: "perf-event-read-value-rejects-dynamic-size"
        category: "helper-state"
        tags: [perf-event scalar-policy dynamic reject]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  let value = "012345678901234567890123"'
            '  let size = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_perf_event_read_value" perf_events 0 $value $size'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_perf_event_read_value' requires arg3 = 24"
    }
    {
        name: "syscall-helpers"
        category: "helper-state"
        tags: [syscall helper-call]
        target: "syscall:demo"
        program: [
            '{||'
            '  let attr = "01234567"'
            '  let name = "init_task\u{0}"'
            '  let btf_name = "task_struct"'
            '  let out = "00000000"'
            '  helper-call "bpf_sys_bpf" 0 $attr 8'
            '  helper-call "bpf_kallsyms_lookup_name" $name 10 0 $out'
            '  helper-call "bpf_btf_find_by_name_kind" $btf_name 11 4 0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "syscall-helper-rejects-zero-attr-size"
        category: "helper-state"
        tags: [syscall scalar-policy reject]
        target: "syscall:demo"
        program: [
            '{||'
            '  let attr = "01234567"'
            '  helper-call "bpf_sys_bpf" 0 $attr 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 166 arg2 must be > 0"
    }
    {
        name: "syscall-helper-rejects-dynamic-zero-attr-size"
        category: "helper-state"
        tags: [syscall scalar-policy dynamic branch reject]
        target: "syscall:demo"
        program: [
            '{||'
            '  let attr = "01234567"'
            '  let selector = (helper-call "bpf_sys_bpf" 0 $attr 8)'
            '  let size = (if $selector == 0 { 0 } else { 8 })'
            '  helper-call "bpf_sys_bpf" 0 $attr $size'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 166 arg2 must be > 0"
    }
    {
        name: "syscall-helper-rejects-kallsyms-flags"
        category: "helper-state"
        tags: [syscall flags reject]
        target: "syscall:demo"
        program: [
            '{||'
            '  let name = "init_task\u{0}"'
            '  let out = "00000000"'
            '  helper-call "bpf_kallsyms_lookup_name" $name 10 1 $out'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_kallsyms_lookup_name' requires arg2 = 0"
    }
    {
        name: "syscall-helper-rejects-dynamic-kallsyms-flags"
        category: "helper-state"
        tags: [syscall flags dynamic reject]
        target: "syscall:demo"
        program: [
            '{||'
            '  let attr = "01234567"'
            '  let name = "init_task\u{0}"'
            '  let out = "00000000"'
            '  let flags = (helper-call "bpf_sys_bpf" 0 $attr 8)'
            '  helper-call "bpf_kallsyms_lookup_name" $name 10 $flags $out'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_kallsyms_lookup_name' requires arg2 = 0"
    }
    {
        name: "lsm-bprm-opts-set"
        category: "helper-state"
        tags: [lsm helper-call]
        requires: [kernel-btf]
        target: "lsm:bprm_check_security"
        program: [
            '{|ctx|'
            '  helper-call "bpf_bprm_opts_set" $ctx.arg.bprm 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lsm-bprm-opts-set-rejects-flags"
        category: "helper-state"
        tags: [lsm flags reject]
        requires: [kernel-btf]
        target: "lsm:bprm_check_security"
        program: [
            '{|ctx|'
            '  helper-call "bpf_bprm_opts_set" $ctx.arg.bprm 2'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_bprm_opts_set' requires arg1 flags to contain only BPF_F_BPRM_* bits"
    }
    {
        name: "lsm-bprm-opts-set-rejects-dynamic-flags"
        category: "helper-state"
        tags: [lsm flags dynamic reject]
        requires: [kernel-btf]
        target: "lsm:bprm_check_security"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_bprm_opts_set" $ctx.arg.bprm $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_bprm_opts_set' requires arg1 flags to contain only BPF_F_BPRM_* bits"
    }
    {
        name: "kprobe-override-return"
        category: "helper-state"
        tags: [kprobe helper-call]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  helper-call "bpf_override_return" $ctx 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "kretprobe-rejects-override-return"
        category: "helper-state"
        tags: [kretprobe helper-call reject]
        target: "kretprobe:ksys_read"
        program: [
            '{|ctx|'
            '  helper-call "bpf_override_return" $ctx 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_override_return' is only valid in kprobe, kprobe.multi, and ksyscall programs"
    }
    {
        name: "seq-write-iter-meta"
        category: "helper-state"
        tags: [iter helper-call seq]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let data = "abcd"'
            '  helper-call "bpf_seq_write" $ctx.meta.seq $data 4'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "seq-write-rejects-non-iter"
        category: "helper-state"
        tags: [raw-tracepoint helper-call seq reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let data = "abcd"'
            '  helper-call "bpf_seq_write" 0 $data 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_seq_write' is only valid in iter programs"
    }
    {
        name: "seq-printf-allows-null-zero-data"
        category: "helper-state"
        tags: [iter helper-call seq]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let fmt = "value\u{0}"'
            '  let btf_ptr = "0123456789abcdef"'
            '  helper-call "bpf_seq_printf" $ctx.meta.seq $fmt 6 0 0'
            '  helper-call "bpf_seq_printf_btf" $ctx.meta.seq $btf_ptr 16 15'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "seq-printf-rejects-unaligned-data-len"
        category: "helper-state"
        tags: [iter helper-call seq reject]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let fmt = "value\u{0}"'
            '  let data = "01234567"'
            '  helper-call "bpf_seq_printf" $ctx.meta.seq $fmt 6 $data 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_seq_printf' requires arg4 to be a multiple of 8"
    }
    {
        name: "seq-printf-rejects-dynamic-unaligned-data-len"
        category: "helper-state"
        tags: [iter helper-call seq dynamic branch reject]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let fmt = "value\u{0}"'
            '  let data = "01234567"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let data_len = (if $selector == 0 { 8 } else { 4 })'
            '  helper-call "bpf_seq_printf" $ctx.meta.seq $fmt 6 $data $data_len'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_seq_printf' requires arg4 to be a multiple of 8"
    }
    {
        name: "callback-bpf-loop"
        category: "callbacks"
        tags: [helper-call callback bpf-loop]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_loop" 4 {|i cb|'
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
        name: "callback-bpf-loop-record-context"
        category: "callbacks"
        tags: [helper-call callback bpf-loop record]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_loop" 4 {|i cb|'
            '    $cb.count | count'
            '    0'
            '  } { count: 9 } 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
