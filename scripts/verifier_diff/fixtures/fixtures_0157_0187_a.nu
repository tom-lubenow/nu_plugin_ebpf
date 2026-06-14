const VERIFIER_DIFF_FIXTURES_0157_0187_A = [
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
]
