const VERIFIER_DIFF_FIXTURES_0094_0125_B = [
    {
        name: "tracepoint-ioctl-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_ioctl]
        target: "tracepoint:syscalls/sys_enter_ioctl"
        program: [
            '{|ctx|'
            '  ($ctx.fd + $ctx.cmd) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-pipe2-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_pipe2"
        program: [
            '{|ctx|'
            '  let fildes = $ctx.fildes'
            '  if $fildes { 1 | count }'
            '  $ctx.flags | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-epoll-ctl-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_epoll_ctl"
        program: [
            '{|ctx|'
            '  let event = $ctx.event'
            '  if $event { 1 | count }'
            '  ($ctx.epfd + $ctx.op + $ctx.fd) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-epoll-pwait-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_epoll_pwait"
        program: [
            '{|ctx|'
            '  let events = $ctx.events'
            '  if $events { 1 | count }'
            '  let sigmask = $ctx.sigmask'
            '  if $sigmask { 1 | count }'
            '  ($ctx.epfd + $ctx.maxevents + $ctx.timeout + $ctx.sigsetsize) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-epoll-pwait2-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_epoll_pwait2]
        target: "tracepoint:syscalls/sys_enter_epoll_pwait2"
        program: [
            '{|ctx|'
            '  let events = $ctx.events'
            '  let timeout = $ctx.timeout'
            '  let sigmask = $ctx.sigmask'
            '  if $events { 1 | count }'
            '  if $timeout { 1 | count }'
            '  if $sigmask { 1 | count }'
            '  ($ctx.epfd + $ctx.maxevents + $ctx.sigsetsize) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-inotify-add-watch-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_inotify_add_watch]
        target: "tracepoint:syscalls/sys_enter_inotify_add_watch"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  if $pathname { $pathname | read-str --max-len 64 | count }'
            '  ($ctx.fd + $ctx.mask) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-fanotify-mark-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_fanotify_mark]
        target: "tracepoint:syscalls/sys_enter_fanotify_mark"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  if $pathname { $pathname | read-str --max-len 64 | count }'
            '  ($ctx.fanotify_fd + $ctx.flags + $ctx.mask + $ctx.dfd) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-ppoll-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_ppoll]
        target: "tracepoint:syscalls/sys_enter_ppoll"
        program: [
            '{|ctx|'
            '  let ufds = $ctx.ufds'
            '  let tsp = $ctx.tsp'
            '  let sigmask = $ctx.sigmask'
            '  if $ufds { 1 | count }'
            '  if $tsp { 1 | count }'
            '  if $sigmask { 1 | count }'
            '  ($ctx.nfds + $ctx.sigsetsize) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-pselect6-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_pselect6]
        target: "tracepoint:syscalls/sys_enter_pselect6"
        program: [
            '{|ctx|'
            '  let inp = $ctx.inp'
            '  let outp = $ctx.outp'
            '  let exp = $ctx.exp'
            '  let tsp = $ctx.tsp'
            '  let sig = $ctx.sig'
            '  if $inp { 1 | count }'
            '  if $outp { 1 | count }'
            '  if $exp { 1 | count }'
            '  if $tsp { 1 | count }'
            '  if $sig { 1 | count }'
            '  $ctx.n | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-mmap-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_mmap"
        program: [
            '{|ctx|'
            '  ($ctx.addr + $ctx.len + $ctx.prot + $ctx.flags + $ctx.fd + $ctx.off) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-mprotect-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_mprotect"
        program: [
            '{|ctx|'
            '  ($ctx.start + $ctx.len + $ctx.prot) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-mremap-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_mremap"
        program: [
            '{|ctx|'
            '  ($ctx.addr + $ctx.old_len + $ctx.new_len + $ctx.flags + $ctx.new_addr) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-mincore-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_mincore"
        program: [
            '{|ctx|'
            '  let vec = $ctx.vec'
            '  if $vec { 1 | count }'
            '  ($ctx.start + $ctx.len) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-process-madvise-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_process_madvise]
        target: "tracepoint:syscalls/sys_enter_process_madvise"
        program: [
            '{|ctx|'
            '  let vec = $ctx.vec'
            '  if $vec { 1 | count }'
            '  ($ctx.pidfd + $ctx.vlen + $ctx.behavior + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-process-mrelease-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_process_mrelease]
        target: "tracepoint:syscalls/sys_enter_process_mrelease"
        program: [
            '{|ctx|'
            '  ($ctx.pidfd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-memfd-create-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_memfd_create]
        target: "tracepoint:syscalls/sys_enter_memfd_create"
        program: [
            '{|ctx|'
            '  let uname = $ctx.uname'
            '  if $uname { $uname | read-str --max-len 64 | count }'
            '  $ctx.flags | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
