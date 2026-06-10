const VERIFIER_DIFF_FIXTURES_0157_0187 = [
    {
        name: "tracepoint-msgctl-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_msgctl]
        target: "tracepoint:syscalls/sys_enter_msgctl"
        program: [
            '{|ctx|'
            '  $ctx.cmd | count'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-msgrcv-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_msgrcv]
        target: "tracepoint:syscalls/sys_enter_msgrcv"
        program: [
            '{|ctx|'
            '  ($ctx.msgsz + $ctx.msgtyp + $ctx.msgflg) | count'
            '  let msgp = $ctx.msgp'
            '  if $msgp { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-semctl-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_semctl]
        target: "tracepoint:syscalls/sys_enter_semctl"
        program: [
            '{|ctx|'
            '  ($ctx.semid + $ctx.semnum + $ctx.cmd) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-semtimedop-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_semtimedop]
        target: "tracepoint:syscalls/sys_enter_semtimedop"
        program: [
            '{|ctx|'
            '  $ctx.nsops | count'
            '  let tsops = $ctx.tsops'
            '  let timeout = $ctx.timeout'
            '  if $tsops { 1 | count }'
            '  if $timeout { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-shmctl-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_shmctl]
        target: "tracepoint:syscalls/sys_enter_shmctl"
        program: [
            '{|ctx|'
            '  $ctx.cmd | count'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-shmat-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_shmat]
        target: "tracepoint:syscalls/sys_enter_shmat"
        program: [
            '{|ctx|'
            '  $ctx.shmflg | count'
            '  let shmaddr = $ctx.shmaddr'
            '  if $shmaddr { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-futex-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_futex]
        target: "tracepoint:syscalls/sys_enter_futex"
        program: [
            '{|ctx|'
            '  let uaddr = $ctx.uaddr'
            '  let utime = $ctx.utime'
            '  let uaddr2 = $ctx.uaddr2'
            '  if $uaddr { 1 | count }'
            '  if $utime { 1 | count }'
            '  if $uaddr2 { 1 | count }'
            '  ($ctx.op + $ctx.val + $ctx.val3) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-futex-waitv-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_futex_waitv]
        target: "tracepoint:syscalls/sys_enter_futex_waitv"
        program: [
            '{|ctx|'
            '  let waiters = $ctx.waiters'
            '  let timeout = $ctx.timeout'
            '  if $waiters { 1 | count }'
            '  if $timeout { 1 | count }'
            '  ($ctx.nr_futexes + $ctx.flags + $ctx.clockid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-futex-wake-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_futex_wake]
        target: "tracepoint:syscalls/sys_enter_futex_wake"
        program: [
            '{|ctx|'
            '  let uaddr = $ctx.uaddr'
            '  if $uaddr { 1 | count }'
            '  ($ctx.mask + $ctx.nr + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-futex-wait-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_futex_wait]
        target: "tracepoint:syscalls/sys_enter_futex_wait"
        program: [
            '{|ctx|'
            '  let uaddr = $ctx.uaddr'
            '  let timeout = $ctx.timeout'
            '  if $uaddr { 1 | count }'
            '  if $timeout { 1 | count }'
            '  ($ctx.val + $ctx.mask + $ctx.flags + $ctx.clockid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-futex-requeue-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_futex_requeue]
        target: "tracepoint:syscalls/sys_enter_futex_requeue"
        program: [
            '{|ctx|'
            '  let waiters = $ctx.waiters'
            '  if $waiters { 1 | count }'
            '  ($ctx.flags + $ctx.nr_wake + $ctx.nr_requeue) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-arch-prctl-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_arch_prctl]
        target: "tracepoint:syscalls/sys_enter_arch_prctl"
        program: [
            '{|ctx|'
            '  $ctx.option | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-ioperm-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_ioperm]
        target: "tracepoint:syscalls/sys_enter_ioperm"
        program: [
            '{|ctx|'
            '  ($ctx.from + $ctx.num + $ctx.turn_on) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-iopl-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_iopl]
        target: "tracepoint:syscalls/sys_enter_iopl"
        program: [
            '{|ctx|'
            '  $ctx.level | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-modify-ldt-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_modify_ldt]
        target: "tracepoint:syscalls/sys_enter_modify_ldt"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.ptr'
            '  if $ptr { 1 | count }'
            '  ($ctx.func + $ctx.bytecount) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
