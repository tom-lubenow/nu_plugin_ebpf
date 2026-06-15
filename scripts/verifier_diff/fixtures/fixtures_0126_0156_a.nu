const VERIFIER_DIFF_FIXTURES_0126_0156_A = [
    {
        name: "tracepoint-memfd-secret-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_memfd_secret]
        target: "tracepoint:syscalls/sys_enter_memfd_secret"
        program: [
            '{|ctx|'
            '  $ctx.flags | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-gettimeofday-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_gettimeofday"
        program: [
            '{|ctx|'
            '  let tv = $ctx.tv'
            '  let tz = $ctx.tz'
            '  if $tv { 1 | count }'
            '  if $tz { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-utimensat-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_utimensat]
        target: "tracepoint:syscalls/sys_enter_utimensat"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  let utimes = $ctx.utimes'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  if $utimes { 1 | count }'
            '  ($ctx.dfd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-clock-gettime-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_clock_gettime"
        program: [
            '{|ctx|'
            '  $ctx.which_clock | count'
            '  let tp = $ctx.tp'
            '  if $tp { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-timer-create-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_timer_create"
        program: [
            '{|ctx|'
            '  $ctx.which_clock | count'
            '  let event = $ctx.timer_event_spec'
            '  let created = $ctx.created_timer_id'
            '  if $event { 1 | count }'
            '  if $created { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-timerfd-settime-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_timerfd_settime"
        program: [
            '{|ctx|'
            '  ($ctx.ufd + $ctx.flags) | count'
            '  let utmr = $ctx.utmr'
            '  let otmr = $ctx.otmr'
            '  if $utmr { 1 | count }'
            '  if $otmr { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-io-uring-setup-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_io_uring_setup]
        target: "tracepoint:syscalls/sys_enter_io_uring_setup"
        program: [
            '{|ctx|'
            '  $ctx.entries | count'
            '  let params = $ctx.params'
            '  if $params { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-io-uring-enter-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_io_uring_enter]
        target: "tracepoint:syscalls/sys_enter_io_uring_enter"
        program: [
            '{|ctx|'
            '  ($ctx.fd + $ctx.to_submit + $ctx.min_complete + $ctx.flags + $ctx.sigsz) | count'
            '  let sig = $ctx.sig'
            '  if $sig { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-io-uring-register-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_io_uring_register]
        target: "tracepoint:syscalls/sys_enter_io_uring_register"
        program: [
            '{|ctx|'
            '  ($ctx.fd + $ctx.opcode + $ctx.nr_args) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
