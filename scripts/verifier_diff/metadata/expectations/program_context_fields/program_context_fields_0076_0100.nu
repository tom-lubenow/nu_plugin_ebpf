[
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let base = { optval: $ctx.optval }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut rec = { optval: ($ctx | get optval) }'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert optval ($ctx | get optval))'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def wrap [optval] { { optval: $optval } }'
            '  let optval = $ctx.optval'
            '  mut rec = (wrap $optval)'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def wrap [optval] {'
            '    let base = { optval: $optval }'
            '    { ok: true, ...$base }'
            '  }'
            '  let optval = $ctx.optval'
            '  mut rec = (wrap $optval)'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def wrap [optval] { { optval: $optval } }'
            '  def outer [event] {'
            '    let optval = $event.optval'
            '    let base = (wrap $optval)'
            '    { ok: true, ...$base }'
            '  }'
            '  mut rec = (outer $ctx)'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.level = 1'
            '  $ctx.optname = 2'
            '  $ctx.optlen = 4'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:level" "ctx:optname" "ctx:optlen"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:getpeername4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.remote_ip4 = 2130706433'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:remote_ip4"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:getsockname6"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.local_ip6.1 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:local_ip6"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:sendmsg6"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.msg_src_ip6.3 = 42'
            '  $ctx.local_ip6.2 = 24'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:msg_src_ip6" "ctx:local_ip6"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let full = $ctx.sk.full'
            '  if $full { $full.family | count }'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_sk_fullsock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  let listener = $ctx.sk.listener'
            '  if $listener { $listener.family | count }'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_get_listener_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let task = $ctx.task'
            '  $task.pt_regs.arg0 | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:task" "helper:bpf_get_current_task_btf" "helper:bpf_task_pt_regs"]
    }
    {
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let cg = $ctx.current_cgroup'
            '  $cg.kn.id | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:cgroup" "helper:bpf_get_current_task_btf"]
    }
    {
        target: "tracepoint:syscalls/sys_enter_openat"
        program: [
            '{|ctx|'
            '  $ctx.current_task.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:task" "helper:bpf_get_current_task_btf"]
    }
    {
        target: "tracepoint:syscalls/sys_enter_openat"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { 1 | count }'
            '  ($ctx.dfd + $ctx.flags + $ctx.mode) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_openat:field:filename"
            "tracepoint:syscalls/sys_enter_openat:field:dfd"
            "tracepoint:syscalls/sys_enter_openat:field:flags"
            "tracepoint:syscalls/sys_enter_openat:field:mode"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_openat2"
        program: [
            '{|ctx|'
            '  let how = $ctx.how'
            '  if $how { 1 | count }'
            '  ($ctx.dfd + $ctx.usize) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_openat2:field:how"
            "tracepoint:syscalls/sys_enter_openat2:field:dfd"
            "tracepoint:syscalls/sys_enter_openat2:field:usize"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_open"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { 1 | count }'
            '  ($ctx.flags + $ctx.mode) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_open:field:filename"
            "tracepoint:syscalls/sys_enter_open:field:flags"
            "tracepoint:syscalls/sys_enter_open:field:mode"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_fchmodat2"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { 1 | count }'
            '  ($ctx.dfd + $ctx.mode + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_fchmodat2:field:filename"
            "tracepoint:syscalls/sys_enter_fchmodat2:field:dfd"
            "tracepoint:syscalls/sys_enter_fchmodat2:field:mode"
            "tracepoint:syscalls/sys_enter_fchmodat2:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_utimensat"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  let utimes = $ctx.utimes'
            '  if $filename { 1 | count }'
            '  if $utimes { 1 | count }'
            '  ($ctx.dfd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_utimensat:field:filename"
            "tracepoint:syscalls/sys_enter_utimensat:field:utimes"
            "tracepoint:syscalls/sys_enter_utimensat:field:dfd"
            "tracepoint:syscalls/sys_enter_utimensat:field:flags"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_ppoll:field:ufds"
            "tracepoint:syscalls/sys_enter_ppoll:field:tsp"
            "tracepoint:syscalls/sys_enter_ppoll:field:sigmask"
            "tracepoint:syscalls/sys_enter_ppoll:field:nfds"
            "tracepoint:syscalls/sys_enter_ppoll:field:sigsetsize"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_epoll_pwait2:field:events"
            "tracepoint:syscalls/sys_enter_epoll_pwait2:field:timeout"
            "tracepoint:syscalls/sys_enter_epoll_pwait2:field:sigmask"
            "tracepoint:syscalls/sys_enter_epoll_pwait2:field:epfd"
            "tracepoint:syscalls/sys_enter_epoll_pwait2:field:maxevents"
            "tracepoint:syscalls/sys_enter_epoll_pwait2:field:sigsetsize"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_fanotify_mark"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  if $pathname { 1 | count }'
            '  ($ctx.fanotify_fd + $ctx.flags + $ctx.mask + $ctx.dfd) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_fanotify_mark:field:pathname"
            "tracepoint:syscalls/sys_enter_fanotify_mark:field:fanotify_fd"
            "tracepoint:syscalls/sys_enter_fanotify_mark:field:flags"
            "tracepoint:syscalls/sys_enter_fanotify_mark:field:mask"
            "tracepoint:syscalls/sys_enter_fanotify_mark:field:dfd"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_sync_file_range"
        program: [
            '{|ctx|'
            '  ($ctx.fd + $ctx.offset + $ctx.nbytes + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_sync_file_range:field:fd"
            "tracepoint:syscalls/sys_enter_sync_file_range:field:offset"
            "tracepoint:syscalls/sys_enter_sync_file_range:field:nbytes"
            "tracepoint:syscalls/sys_enter_sync_file_range:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_ioctl"
        program: [
            '{|ctx|'
            '  ($ctx.fd + $ctx.cmd) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_ioctl:field:fd"
            "tracepoint:syscalls/sys_enter_ioctl:field:cmd"
        ]
    }
]
