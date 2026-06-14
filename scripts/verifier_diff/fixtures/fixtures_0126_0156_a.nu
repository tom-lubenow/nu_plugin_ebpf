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
    {
        name: "tracepoint-kill-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_kill"
        program: [
            '{|ctx|'
            '  $ctx.sig | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-rt-sigaction-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_rt_sigaction"
        program: [
            '{|ctx|'
            '  ($ctx.sig + $ctx.sigsetsize) | count'
            '  let act = $ctx.act'
            '  let oact = $ctx.oact'
            '  if $act { 1 | count }'
            '  if $oact { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-rt-sigtimedwait-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_rt_sigtimedwait"
        program: [
            '{|ctx|'
            '  $ctx.sigsetsize | count'
            '  let uthese = $ctx.uthese'
            '  let uinfo = $ctx.uinfo'
            '  let uts = $ctx.uts'
            '  if $uthese { 1 | count }'
            '  if $uinfo { 1 | count }'
            '  if $uts { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-pidfd-send-signal-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_pidfd_send_signal"
        program: [
            '{|ctx|'
            '  ($ctx.pidfd + $ctx.sig + $ctx.flags) | count'
            '  let info = $ctx.info'
            '  if $info { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-pidfd-open-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_pidfd_open]
        target: "tracepoint:syscalls/sys_enter_pidfd_open"
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
        name: "tracepoint-pidfd-getfd-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_pidfd_getfd]
        target: "tracepoint:syscalls/sys_enter_pidfd_getfd"
        program: [
            '{|ctx|'
            '  ($ctx.pidfd + $ctx.fd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
