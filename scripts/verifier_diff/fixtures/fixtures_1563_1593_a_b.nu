const VERIFIER_DIFF_FIXTURES_1563_1593_A_B = [
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
