const VERIFIER_DIFF_FIXTURES_0157_0187_B = [
    {
        name: "tracepoint-rt-sigreturn-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_rt_sigreturn]
        target: "tracepoint:syscalls/sys_enter_rt_sigreturn"
        program: [
            '{|ctx|'
            '  $ctx.id | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-map-shadow-stack-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_map_shadow_stack]
        target: "tracepoint:syscalls/sys_enter_map_shadow_stack"
        program: [
            '{|ctx|'
            '  ($ctx.addr + $ctx.size + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-kcmp-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_kcmp]
        target: "tracepoint:syscalls/sys_enter_kcmp"
        program: [
            '{|ctx|'
            '  ($ctx.pid1 + $ctx.pid2 + $ctx.type + $ctx.idx1 + $ctx.idx2) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-cachestat-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_cachestat]
        target: "tracepoint:syscalls/sys_enter_cachestat"
        program: [
            '{|ctx|'
            '  let cstat_range = $ctx.cstat_range'
            '  let cstat = $ctx.cstat'
            '  if $cstat_range { 1 | count }'
            '  if $cstat { 1 | count }'
            '  ($ctx.fd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-mseal-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_mseal]
        target: "tracepoint:syscalls/sys_enter_mseal"
        program: [
            '{|ctx|'
            '  ($ctx.start + $ctx.len + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-file-getattr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_file_getattr]
        target: "tracepoint:syscalls/sys_enter_file_getattr"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  let ufattr = $ctx.ufattr'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  if $ufattr { 1 | count }'
            '  ($ctx.dfd + $ctx.usize + $ctx.at_flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-file-setattr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_file_setattr]
        target: "tracepoint:syscalls/sys_enter_file_setattr"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  let ufattr = $ctx.ufattr'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  if $ufattr { 1 | count }'
            '  ($ctx.dfd + $ctx.usize + $ctx.at_flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-uretprobe-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_uretprobe]
        target: "tracepoint:syscalls/sys_enter_uretprobe"
        program: [
            '{|ctx|'
            '  $ctx.id | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "perf-event-context"
        category: "tracing"
        tags: [perf-event context]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  ($ctx.cpu + $ctx.sample_period + $ctx.addr + $ctx.perf_counter) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "perf-event-pt-regs-arg-context"
        category: "context-surface"
        tags: [perf-event context pt-regs]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  ($ctx.arg0 + $ctx.arg1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "perf-event-hardware-frequency-context"
        category: "context-surface"
        tags: [perf-event context hardware freq]
        target: "perf_event:hardware:instructions:freq=99"
        program: [
            '{|ctx|'
            '  ($ctx.perf_counter + $ctx.perf_enabled + $ctx.perf_running + $ctx.cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tp-btf-context"
        category: "tracing"
        tags: [tp-btf context]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.arg0.orig_ax + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tp-btf-bound-arg-context"
        category: "tracing"
        tags: [tp-btf context alias]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let regs = $ctx.arg0'
            '  ($regs.orig_ax + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tp-btf-missing-target-help-reject"
        category: "tracing"
        tags: [tp-btf context diagnostic reject]
        requires: [kernel-btf]
        target: "tp_btf:nu_plugin_ebpf_missing_tracepoint_for_help"
        program: [
            '{|ctx|'
            '  ($ctx.arg0.orig_ax + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "tracepoint name"
    }
    {
        name: "fentry-context"
        category: "tracing"
        tags: [fentry context]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fentry-bound-arg-context"
        category: "tracing"
        tags: [fentry context alias]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let file = $ctx.arg.file'
            '  ($file.f_flags + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
