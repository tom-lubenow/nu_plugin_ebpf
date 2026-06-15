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
]
