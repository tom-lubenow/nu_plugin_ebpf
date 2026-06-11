const PROGRAM_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS_2 = [
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  $sk.tcp.snd_cwnd | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_tcp_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let tcp = $ctx.socket.tcp'
            '  if $tcp { $tcp.snd_cwnd | count }'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_tcp_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let tcp = $ctx.sk.tcp'
            '  if $tcp { $tcp.snd_cwnd | count }'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_tcp_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let tcp = $ctx.sk.tcp'
            '  let rec = { tcp: $tcp }'
            '  if $rec.tcp { $rec.tcp.snd_cwnd | count }'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_tcp_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.retval = 0'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sockopt_retval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut optval = $ctx.optval'
            '  $optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut optval = ($ctx | get optval)'
            '  $optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def get_optval [event] { $event | get optval }'
            '  mut optval = (get_optval $ctx)'
            '  $optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
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
    {
        target: "tracepoint:syscalls/sys_enter_readlinkat"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  let buf = $ctx.buf'
            '  if $pathname { 1 | count }'
            '  if $buf { 1 | count }'
            '  ($ctx.dfd + $ctx.bufsiz) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_readlinkat:field:pathname"
            "tracepoint:syscalls/sys_enter_readlinkat:field:buf"
            "tracepoint:syscalls/sys_enter_readlinkat:field:dfd"
            "tracepoint:syscalls/sys_enter_readlinkat:field:bufsiz"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_name_to_handle_at"
        program: [
            '{|ctx|'
            '  let name = $ctx.name'
            '  let handle = $ctx.handle'
            '  let mnt_id = $ctx.mnt_id'
            '  if $name { 1 | count }'
            '  if $handle { 1 | count }'
            '  if $mnt_id { 1 | count }'
            '  ($ctx.dfd + $ctx.flag) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_name_to_handle_at:field:name"
            "tracepoint:syscalls/sys_enter_name_to_handle_at:field:handle"
            "tracepoint:syscalls/sys_enter_name_to_handle_at:field:mnt_id"
            "tracepoint:syscalls/sys_enter_name_to_handle_at:field:dfd"
            "tracepoint:syscalls/sys_enter_name_to_handle_at:field:flag"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_fchownat"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { 1 | count }'
            '  ($ctx.dfd + $ctx.user + $ctx.group + $ctx.flag) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_fchownat:field:filename"
            "tracepoint:syscalls/sys_enter_fchownat:field:dfd"
            "tracepoint:syscalls/sys_enter_fchownat:field:user"
            "tracepoint:syscalls/sys_enter_fchownat:field:group"
            "tracepoint:syscalls/sys_enter_fchownat:field:flag"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_mknod"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { 1 | count }'
            '  ($ctx.mode + $ctx.dev) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_mknod:field:filename"
            "tracepoint:syscalls/sys_enter_mknod:field:mode"
            "tracepoint:syscalls/sys_enter_mknod:field:dev"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_read"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.fd + $ctx.count) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_read:field:buf"
            "tracepoint:syscalls/sys_enter_read:field:fd"
            "tracepoint:syscalls/sys_enter_read:field:count"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_write"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.fd + $ctx.count) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_write:field:buf"
            "tracepoint:syscalls/sys_enter_write:field:fd"
            "tracepoint:syscalls/sys_enter_write:field:count"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_pread64"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.fd + $ctx.count + $ctx.pos) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_pread64:field:buf"
            "tracepoint:syscalls/sys_enter_pread64:field:fd"
            "tracepoint:syscalls/sys_enter_pread64:field:count"
            "tracepoint:syscalls/sys_enter_pread64:field:pos"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_readv"
        program: [
            '{|ctx|'
            '  let vec = $ctx.vec'
            '  if $vec { 1 | count }'
            '  ($ctx.fd + $ctx.vlen) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_readv:field:vec"
            "tracepoint:syscalls/sys_enter_readv:field:fd"
            "tracepoint:syscalls/sys_enter_readv:field:vlen"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_preadv2"
        program: [
            '{|ctx|'
            '  let vec = $ctx.vec'
            '  if $vec { 1 | count }'
            '  ($ctx.fd + $ctx.vlen + $ctx.pos_l + $ctx.pos_h + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_preadv2:field:vec"
            "tracepoint:syscalls/sys_enter_preadv2:field:fd"
            "tracepoint:syscalls/sys_enter_preadv2:field:vlen"
            "tracepoint:syscalls/sys_enter_preadv2:field:pos_l"
            "tracepoint:syscalls/sys_enter_preadv2:field:pos_h"
            "tracepoint:syscalls/sys_enter_preadv2:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_copy_file_range"
        program: [
            '{|ctx|'
            '  let off_in = $ctx.off_in'
            '  if $off_in { 1 | count }'
            '  let off_out = $ctx.off_out'
            '  if $off_out { 1 | count }'
            '  ($ctx.fd_in + $ctx.fd_out + $ctx.len + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_copy_file_range:field:off_in"
            "tracepoint:syscalls/sys_enter_copy_file_range:field:off_out"
            "tracepoint:syscalls/sys_enter_copy_file_range:field:fd_in"
            "tracepoint:syscalls/sys_enter_copy_file_range:field:fd_out"
            "tracepoint:syscalls/sys_enter_copy_file_range:field:len"
            "tracepoint:syscalls/sys_enter_copy_file_range:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_splice"
        program: [
            '{|ctx|'
            '  let off_in = $ctx.off_in'
            '  if $off_in { 1 | count }'
            '  let off_out = $ctx.off_out'
            '  if $off_out { 1 | count }'
            '  ($ctx.fd_in + $ctx.fd_out + $ctx.len + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_splice:field:off_in"
            "tracepoint:syscalls/sys_enter_splice:field:off_out"
            "tracepoint:syscalls/sys_enter_splice:field:fd_in"
            "tracepoint:syscalls/sys_enter_splice:field:fd_out"
            "tracepoint:syscalls/sys_enter_splice:field:len"
            "tracepoint:syscalls/sys_enter_splice:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_setxattr"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  if $pathname { 1 | count }'
            '  let name = $ctx.name'
            '  if $name { 1 | count }'
            '  let value = $ctx.value'
            '  if $value { 1 | count }'
            '  ($ctx.size + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_setxattr:field:pathname"
            "tracepoint:syscalls/sys_enter_setxattr:field:name"
            "tracepoint:syscalls/sys_enter_setxattr:field:value"
            "tracepoint:syscalls/sys_enter_setxattr:field:size"
            "tracepoint:syscalls/sys_enter_setxattr:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_fgetxattr"
        program: [
            '{|ctx|'
            '  let name = $ctx.name'
            '  if $name { 1 | count }'
            '  let value = $ctx.value'
            '  if $value { 1 | count }'
            '  ($ctx.fd + $ctx.size) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_fgetxattr:field:name"
            "tracepoint:syscalls/sys_enter_fgetxattr:field:value"
            "tracepoint:syscalls/sys_enter_fgetxattr:field:fd"
            "tracepoint:syscalls/sys_enter_fgetxattr:field:size"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_listxattr"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  if $pathname { 1 | count }'
            '  let list = $ctx.list'
            '  if $list { 1 | count }'
            '  $ctx.size | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_listxattr:field:pathname"
            "tracepoint:syscalls/sys_enter_listxattr:field:list"
            "tracepoint:syscalls/sys_enter_listxattr:field:size"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_setxattrat"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  if $pathname { 1 | count }'
            '  let name = $ctx.name'
            '  if $name { 1 | count }'
            '  let uargs = $ctx.uargs'
            '  if $uargs { 1 | count }'
            '  ($ctx.dfd + $ctx.at_flags + $ctx.usize) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_setxattrat:field:pathname"
            "tracepoint:syscalls/sys_enter_setxattrat:field:name"
            "tracepoint:syscalls/sys_enter_setxattrat:field:uargs"
            "tracepoint:syscalls/sys_enter_setxattrat:field:dfd"
            "tracepoint:syscalls/sys_enter_setxattrat:field:at_flags"
            "tracepoint:syscalls/sys_enter_setxattrat:field:usize"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_listxattrat"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  if $pathname { 1 | count }'
            '  let list = $ctx.list'
            '  if $list { 1 | count }'
            '  ($ctx.dfd + $ctx.at_flags + $ctx.size) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_listxattrat:field:pathname"
            "tracepoint:syscalls/sys_enter_listxattrat:field:list"
            "tracepoint:syscalls/sys_enter_listxattrat:field:dfd"
            "tracepoint:syscalls/sys_enter_listxattrat:field:at_flags"
            "tracepoint:syscalls/sys_enter_listxattrat:field:size"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_close"
        program: [
            '{|ctx|'
            '  $ctx.fd | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_close:field:fd"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_execve"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { 1 | count }'
            '  let argv = $ctx.argv'
            '  if $argv { 1 | count }'
            '  let envp = $ctx.envp'
            '  if $envp { 1 | count }'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_execve:field:filename"
            "tracepoint:syscalls/sys_enter_execve:field:argv"
            "tracepoint:syscalls/sys_enter_execve:field:envp"
        ]
    }
]
