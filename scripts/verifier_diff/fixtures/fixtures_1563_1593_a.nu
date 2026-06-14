const VERIFIER_DIFF_FIXTURES_1563_1593_A = [
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
        default_test_lane: "dry-run"
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
]
