const VERIFIER_DIFF_FIXTURES_0001_0250 = [
    {
        name: "raw-tracepoint-count"
        category: "tracing"
        tags: [raw-tracepoint counter]
        target: "raw_tracepoint:sys_enter"
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
        name: "raw-tracepoint-context-param-alias"
        category: "context-surface"
        tags: [raw-tracepoint context source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|event|'
            '  $event.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-tracepoint-random-context"
        category: "context-surface"
        tags: [raw-tracepoint context random]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.random + $ctx.prandom_u32) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-tracepoint-time-context"
        category: "context-surface"
        tags: [raw-tracepoint context time]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.ktime + $ctx.ktime_boot + $ctx.ktime_tai + $ctx.jiffies) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-tracepoint-coarse-time-reject"
        category: "context-surface"
        tags: [raw-tracepoint context time reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.ktime_coarse | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.ktime_coarse is not available on raw_tracepoint programs"
    }
    {
        name: "kprobe-multi-context"
        category: "tracing"
        tags: [kprobe-multi context]
        target: "kprobe.multi:vfs_*"
        program: [
            '{|ctx|'
            '  ($ctx.arg0 + $ctx.func_ip + $ctx.attach_cookie) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "kprobe-multi-task-pt-regs-context"
        category: "context-surface"
        tags: [kprobe-multi context task pt-regs helper-backed source metadata]
        requires: [kernel-btf]
        target: "kprobe.multi:vfs_*"
        program: [
            '{|ctx|'
            '  let task = $ctx.task'
            '  ($task.pt_regs.arg0 + $ctx.func_ip) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "kretprobe-multi-context"
        category: "tracing"
        tags: [kretprobe-multi context]
        target: "kretprobe.multi:vfs_*"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.func_ip + $ctx.attach_cookie) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "kretprobe-multi-task-pt-regs-context"
        category: "context-surface"
        tags: [kretprobe-multi context task pt-regs helper-backed source metadata]
        requires: [kernel-btf]
        target: "kretprobe.multi:vfs_*"
        program: [
            '{|ctx|'
            '  let task = $ctx.task'
            '  ($task.pt_regs.retval + $ctx.retval + $ctx.func_ip) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "uprobe-multi-context"
        category: "tracing"
        tags: [uprobe-multi context]
        target: "uprobe.multi:/bin/true:*"
        program: [
            '{|ctx|'
            '  ($ctx.pid + $ctx.func_ip + $ctx.attach_cookie) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "uprobe-sleepable-context"
        category: "tracing"
        tags: [uprobe sleepable context]
        target: "uprobe.s:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    ($ctx.pid + $ctx.func_ip + $ctx.attach_cookie) | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "uretprobe-sleepable-context"
        category: "tracing"
        tags: [uretprobe sleepable context]
        target: "uretprobe.s:/bin/true:main"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.pid + $ctx.func_ip + $ctx.attach_cookie) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "uprobe-multi-sleepable-context"
        category: "tracing"
        tags: [uprobe-multi sleepable context]
        target: "uprobe.multi.s:/bin/true:*"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    ($ctx.pid + $ctx.func_ip + $ctx.attach_cookie) | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "uretprobe-multi-context"
        category: "tracing"
        tags: [uretprobe-multi context]
        target: "uretprobe.multi:/bin/true:*"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.pid + $ctx.func_ip) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "uretprobe-multi-sleepable-context"
        category: "tracing"
        tags: [uretprobe-multi sleepable context]
        target: "uretprobe.multi.s:/bin/true:*"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.pid + $ctx.func_ip + $ctx.attach_cookie) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "kretprobe-context"
        category: "tracing"
        tags: [kretprobe context]
        target: "kretprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ksyscall-context"
        category: "tracing"
        tags: [ksyscall context]
        target: "ksyscall:nanosleep"
        program: [
            '{|ctx|'
            '  ($ctx.arg0 + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ksyscall-task-pt-regs-context"
        category: "context-surface"
        tags: [ksyscall context task pt-regs helper-backed source metadata]
        requires: [kernel-btf]
        target: "ksyscall:nanosleep"
        program: [
            '{|ctx|'
            '  let task = $ctx.task'
            '  ($task.pt_regs.arg0 + $ctx.func_ip) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "kretsyscall-context"
        category: "tracing"
        tags: [kretsyscall context]
        target: "kretsyscall:nanosleep"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "kretsyscall-task-pt-regs-context"
        category: "context-surface"
        tags: [kretsyscall context task pt-regs helper-backed source metadata]
        requires: [kernel-btf]
        target: "kretsyscall:nanosleep"
        program: [
            '{|ctx|'
            '  let task = $ctx.task'
            '  ($task.pt_regs.retval + $ctx.retval + $ctx.func_ip) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-openat-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_openat"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  ($ctx.dfd + $ctx.flags + $ctx.mode + $ctx.current_task.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-openat-common-context"
        category: "tracing"
        tags: [tracepoint context compatibility]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_openat"
        program: [
            '{|ctx|'
            '  ($ctx.id + ($ctx.args | get 0)) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-read-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_read"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { $buf | read-str --max-len 16 | count }'
            '  ($ctx.fd + $ctx.count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-write-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_write"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { $buf | read-str --max-len 16 | count }'
            '  ($ctx.fd + $ctx.count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-pread64-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_pread64]
        target: "tracepoint:syscalls/sys_enter_pread64"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.fd + $ctx.count + $ctx.pos) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-readv-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_readv]
        target: "tracepoint:syscalls/sys_enter_readv"
        program: [
            '{|ctx|'
            '  let vec = $ctx.vec'
            '  if $vec { 1 | count }'
            '  ($ctx.fd + $ctx.vlen) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-preadv2-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_preadv2]
        target: "tracepoint:syscalls/sys_enter_preadv2"
        program: [
            '{|ctx|'
            '  let vec = $ctx.vec'
            '  if $vec { 1 | count }'
            '  ($ctx.fd + $ctx.vlen + $ctx.pos_l + $ctx.pos_h + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-sendfile64-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_sendfile64]
        target: "tracepoint:syscalls/sys_enter_sendfile64"
        program: [
            '{|ctx|'
            '  let offset = $ctx.offset'
            '  if $offset { 1 | count }'
            '  ($ctx.out_fd + $ctx.in_fd + $ctx.count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-copy-file-range-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_copy_file_range]
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
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-splice-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_splice]
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
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-setxattr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_setxattr]
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
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-fgetxattr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_fgetxattr]
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
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-listxattr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_listxattr]
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
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-setxattrat-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_setxattrat]
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
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-listxattrat-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_listxattrat]
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
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-close-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_close"
        program: [
            '{|ctx|'
            '  $ctx.fd | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-close-range-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_close_range]
        target: "tracepoint:syscalls/sys_enter_close_range"
        program: [
            '{|ctx|'
            '  ($ctx.fd + $ctx.max_fd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-openat2-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_openat2"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  let how = $ctx.how'
            '  if $how { 1 | count }'
            '  ($ctx.dfd + $ctx.usize) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-faccessat2-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_faccessat2]
        target: "tracepoint:syscalls/sys_enter_faccessat2"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  ($ctx.dfd + $ctx.mode + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-fchmodat2-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_fchmodat2]
        target: "tracepoint:syscalls/sys_enter_fchmodat2"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  ($ctx.dfd + $ctx.mode + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-readlinkat-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_readlinkat]
        target: "tracepoint:syscalls/sys_enter_readlinkat"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  let buf = $ctx.buf'
            '  if $pathname { $pathname | read-str --max-len 64 | count }'
            '  if $buf { 1 | count }'
            '  ($ctx.dfd + $ctx.bufsiz) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-getdents64-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_getdents64]
        target: "tracepoint:syscalls/sys_enter_getdents64"
        program: [
            '{|ctx|'
            '  let dirent = $ctx.dirent'
            '  if $dirent { 1 | count }'
            '  ($ctx.fd + $ctx.count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-name-to-handle-at-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_name_to_handle_at]
        target: "tracepoint:syscalls/sys_enter_name_to_handle_at"
        program: [
            '{|ctx|'
            '  let name = $ctx.name'
            '  let handle = $ctx.handle'
            '  let mnt_id = $ctx.mnt_id'
            '  if $name { $name | read-str --max-len 64 | count }'
            '  if $handle { 1 | count }'
            '  if $mnt_id { 1 | count }'
            '  ($ctx.dfd + $ctx.flag) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-legacy-open-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_open]
        target: "tracepoint:syscalls/sys_enter_open"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  ($ctx.flags + $ctx.mode) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-exit-openat2-context"
        category: "tracing"
        tags: [tracepoint context compatibility]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_exit_openat2"
        program: [
            '{|ctx|'
            '  ($ctx.id + $ctx.ret) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-execve-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_execve"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  let argv = $ctx.argv'
            '  if $argv { 1 | count }'
            '  let envp = $ctx.envp'
            '  if $envp { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-connect-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_connect"
        program: [
            '{|ctx|'
            '  let addr = $ctx.uservaddr'
            '  if $addr { 1 | count }'
            '  ($ctx.fd + $ctx.addrlen) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-sendto-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_sendto"
        program: [
            '{|ctx|'
            '  let buff = $ctx.buff'
            '  if $buff { 1 | count }'
            '  let addr = $ctx.addr'
            '  if $addr { 1 | count }'
            '  ($ctx.fd + $ctx.len + $ctx.flags + $ctx.addr_len) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-recvfrom-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_recvfrom"
        program: [
            '{|ctx|'
            '  let ubuf = $ctx.ubuf'
            '  if $ubuf { 1 | count }'
            '  let addr = $ctx.addr'
            '  if $addr { 1 | count }'
            '  let addr_len = $ctx.addr_len'
            '  if $addr_len { 1 | count }'
            '  ($ctx.fd + $ctx.size + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-accept4-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_accept4"
        program: [
            '{|ctx|'
            '  let sockaddr = $ctx.upeer_sockaddr'
            '  if $sockaddr { 1 | count }'
            '  let addrlen = $ctx.upeer_addrlen'
            '  if $addrlen { 1 | count }'
            '  ($ctx.fd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-socket-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_socket"
        program: [
            '{|ctx|'
            '  ($ctx.family + $ctx.type + $ctx.protocol) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-bind-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_bind"
        program: [
            '{|ctx|'
            '  let addr = $ctx.umyaddr'
            '  if $addr { 1 | count }'
            '  ($ctx.fd + $ctx.addrlen) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-setsockopt-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_setsockopt"
        program: [
            '{|ctx|'
            '  let optval = $ctx.optval'
            '  if $optval { 1 | count }'
            '  ($ctx.fd + $ctx.level + $ctx.optname + $ctx.optlen) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-recvmmsg-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_recvmmsg"
        program: [
            '{|ctx|'
            '  let mmsg = $ctx.mmsg'
            '  if $mmsg { 1 | count }'
            '  let timeout = $ctx.timeout'
            '  if $timeout { 1 | count }'
            '  ($ctx.fd + $ctx.vlen + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-getpeername-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_getpeername]
        target: "tracepoint:syscalls/sys_enter_getpeername"
        program: [
            '{|ctx|'
            '  let usockaddr = $ctx.usockaddr'
            '  let usockaddr_len = $ctx.usockaddr_len'
            '  if $usockaddr { 1 | count }'
            '  if $usockaddr_len { 1 | count }'
            '  $ctx.fd | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-getrandom-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_getrandom]
        target: "tracepoint:syscalls/sys_enter_getrandom"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.count + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-signalfd4-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_signalfd4]
        target: "tracepoint:syscalls/sys_enter_signalfd4"
        program: [
            '{|ctx|'
            '  let user_mask = $ctx.user_mask'
            '  if $user_mask { 1 | count }'
            '  ($ctx.ufd + $ctx.sizemask + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-io-pgetevents-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_io_pgetevents]
        target: "tracepoint:syscalls/sys_enter_io_pgetevents"
        program: [
            '{|ctx|'
            '  let events = $ctx.events'
            '  let timeout = $ctx.timeout'
            '  let usig = $ctx.usig'
            '  if $events { 1 | count }'
            '  if $timeout { 1 | count }'
            '  if $usig { 1 | count }'
            '  ($ctx.ctx_id + $ctx.min_nr + $ctx.nr) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-ioprio-set-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_ioprio_set]
        target: "tracepoint:syscalls/sys_enter_ioprio_set"
        program: [
            '{|ctx|'
            '  ($ctx.which + $ctx.who + $ctx.ioprio) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-add-key-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_add_key]
        target: "tracepoint:syscalls/sys_enter_add_key"
        program: [
            '{|ctx|'
            '  let key_type = $ctx._type'
            '  let description = $ctx._description'
            '  let payload = $ctx._payload'
            '  if $key_type { 1 | count }'
            '  if $description { 1 | count }'
            '  if $payload { 1 | count }'
            '  ($ctx.plen + $ctx.ringid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-mbind-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_mbind]
        target: "tracepoint:syscalls/sys_enter_mbind"
        program: [
            '{|ctx|'
            '  let nmask = $ctx.nmask'
            '  if $nmask { 1 | count }'
            '  ($ctx.start + $ctx.len + $ctx.mode + $ctx.maxnode + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-move-pages-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_move_pages]
        target: "tracepoint:syscalls/sys_enter_move_pages"
        program: [
            '{|ctx|'
            '  let pages = $ctx.pages'
            '  let nodes = $ctx.nodes'
            '  let status = $ctx.status'
            '  if $pages { 1 | count }'
            '  if $nodes { 1 | count }'
            '  if $status { 1 | count }'
            '  ($ctx.nr_pages + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-set-mempolicy-home-node-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_set_mempolicy_home_node]
        target: "tracepoint:syscalls/sys_enter_set_mempolicy_home_node"
        program: [
            '{|ctx|'
            '  ($ctx.start + $ctx.len + $ctx.home_node + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-mq-open-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_mq_open]
        target: "tracepoint:syscalls/sys_enter_mq_open"
        program: [
            '{|ctx|'
            '  let name = $ctx.u_name'
            '  let attr = $ctx.u_attr'
            '  if $name { 1 | count }'
            '  if $attr { 1 | count }'
            '  ($ctx.oflag + $ctx.mode) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-mq-timedreceive-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_mq_timedreceive]
        target: "tracepoint:syscalls/sys_enter_mq_timedreceive"
        program: [
            '{|ctx|'
            '  let msg = $ctx.u_msg_ptr'
            '  let prio = $ctx.u_msg_prio'
            '  let timeout = $ctx.u_abs_timeout'
            '  if $msg { 1 | count }'
            '  if $prio { 1 | count }'
            '  if $timeout { 1 | count }'
            '  ($ctx.mqdes + $ctx.msg_len) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-mq-getsetattr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_mq_getsetattr]
        target: "tracepoint:syscalls/sys_enter_mq_getsetattr"
        program: [
            '{|ctx|'
            '  let mqstat = $ctx.u_mqstat'
            '  let omqstat = $ctx.u_omqstat'
            '  if $mqstat { 1 | count }'
            '  if $omqstat { 1 | count }'
            '  $ctx.mqdes | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-process-vm-readv-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_process_vm_readv]
        target: "tracepoint:syscalls/sys_enter_process_vm_readv"
        program: [
            '{|ctx|'
            '  let lvec = $ctx.lvec'
            '  let rvec = $ctx.rvec'
            '  if $lvec { 1 | count }'
            '  if $rvec { 1 | count }'
            '  ($ctx.liovcnt + $ctx.riovcnt + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-pkey-mprotect-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_pkey_mprotect]
        target: "tracepoint:syscalls/sys_enter_pkey_mprotect"
        program: [
            '{|ctx|'
            '  ($ctx.start + $ctx.len + $ctx.prot + $ctx.pkey) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-prlimit64-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_prlimit64]
        target: "tracepoint:syscalls/sys_enter_prlimit64"
        program: [
            '{|ctx|'
            '  let new_rlim = $ctx.new_rlim'
            '  let old_rlim = $ctx.old_rlim'
            '  if $new_rlim { 1 | count }'
            '  if $old_rlim { 1 | count }'
            '  $ctx.resource | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-get-robust-list-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_get_robust_list]
        target: "tracepoint:syscalls/sys_enter_get_robust_list"
        program: [
            '{|ctx|'
            '  let head_ptr = $ctx.head_ptr'
            '  let len_ptr = $ctx.len_ptr'
            '  if $head_ptr { 1 | count }'
            '  if $len_ptr { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-rseq-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_rseq]
        target: "tracepoint:syscalls/sys_enter_rseq"
        program: [
            '{|ctx|'
            '  let user_rseq = $ctx.rseq'
            '  if $user_rseq { 1 | count }'
            '  ($ctx.rseq_len + $ctx.flags + $ctx.sig) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-init-module-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_init_module]
        target: "tracepoint:syscalls/sys_enter_init_module"
        program: [
            '{|ctx|'
            '  let umod = $ctx.umod'
            '  let uargs = $ctx.uargs'
            '  if $umod { 1 | count }'
            '  if $uargs { 1 | count }'
            '  $ctx.len | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-kexec-file-load-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_kexec_file_load]
        target: "tracepoint:syscalls/sys_enter_kexec_file_load"
        program: [
            '{|ctx|'
            '  let cmdline = $ctx.cmdline_ptr'
            '  if $cmdline { 1 | count }'
            '  ($ctx.kernel_fd + $ctx.initrd_fd + $ctx.cmdline_len + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-swapon-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_swapon]
        target: "tracepoint:syscalls/sys_enter_swapon"
        program: [
            '{|ctx|'
            '  let specialfile = $ctx.specialfile'
            '  if $specialfile { 1 | count }'
            '  $ctx.swap_flags | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-bpf-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_bpf]
        target: "tracepoint:syscalls/sys_enter_bpf"
        program: [
            '{|ctx|'
            '  let uattr = $ctx.uattr'
            '  if $uattr { 1 | count }'
            '  ($ctx.cmd + $ctx.size) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-perf-event-open-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_perf_event_open]
        target: "tracepoint:syscalls/sys_enter_perf_event_open"
        program: [
            '{|ctx|'
            '  let attr = $ctx.attr_uptr'
            '  if $attr { 1 | count }'
            '  ($ctx.group_fd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-seccomp-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_seccomp]
        target: "tracepoint:syscalls/sys_enter_seccomp"
        program: [
            '{|ctx|'
            '  let uargs = $ctx.uargs'
            '  if $uargs { 1 | count }'
            '  ($ctx.op + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-clone-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_clone]
        target: "tracepoint:syscalls/sys_enter_clone"
        program: [
            '{|ctx|'
            '  let parent_tidptr = $ctx.parent_tidptr'
            '  let child_tidptr = $ctx.child_tidptr'
            '  if $parent_tidptr { 1 | count }'
            '  if $child_tidptr { 1 | count }'
            '  ($ctx.clone_flags + $ctx.newsp + $ctx.tls) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-syslog-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_syslog]
        target: "tracepoint:syscalls/sys_enter_syslog"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.type + $ctx.len) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-personality-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_personality]
        target: "tracepoint:syscalls/sys_enter_personality"
        program: [
            '{|ctx|'
            '  $ctx.personality | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-newfstatat-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_newfstatat"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  let statbuf = $ctx.statbuf'
            '  if $statbuf { 1 | count }'
            '  ($ctx.dfd + $ctx.flag) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-statx-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_statx"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  let buffer = $ctx.buffer'
            '  if $buffer { 1 | count }'
            '  ($ctx.dfd + $ctx.flags + $ctx.mask) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-mknod-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_mknod]
        target: "tracepoint:syscalls/sys_enter_mknod"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  ($ctx.mode + $ctx.dev) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-renameat2-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_renameat2"
        program: [
            '{|ctx|'
            '  let oldname = $ctx.oldname'
            '  if $oldname { $oldname | read-str --max-len 64 | count }'
            '  let newname = $ctx.newname'
            '  if $newname { $newname | read-str --max-len 64 | count }'
            '  ($ctx.olddfd + $ctx.newdfd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-linkat-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_linkat"
        program: [
            '{|ctx|'
            '  let oldname = $ctx.oldname'
            '  if $oldname { $oldname | read-str --max-len 64 | count }'
            '  let newname = $ctx.newname'
            '  if $newname { $newname | read-str --max-len 64 | count }'
            '  ($ctx.olddfd + $ctx.newdfd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-open-tree-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_open_tree]
        target: "tracepoint:syscalls/sys_enter_open_tree"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  ($ctx.dfd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-move-mount-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_move_mount]
        target: "tracepoint:syscalls/sys_enter_move_mount"
        program: [
            '{|ctx|'
            '  let from_pathname = $ctx.from_pathname'
            '  let to_pathname = $ctx.to_pathname'
            '  if $from_pathname { $from_pathname | read-str --max-len 64 | count }'
            '  if $to_pathname { $to_pathname | read-str --max-len 64 | count }'
            '  ($ctx.from_dfd + $ctx.to_dfd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-fsopen-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_fsopen]
        target: "tracepoint:syscalls/sys_enter_fsopen"
        program: [
            '{|ctx|'
            '  let fs_name = $ctx._fs_name'
            '  if $fs_name { $fs_name | read-str --max-len 64 | count }'
            '  $ctx.flags | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-fsconfig-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_fsconfig]
        target: "tracepoint:syscalls/sys_enter_fsconfig"
        program: [
            '{|ctx|'
            '  let key = $ctx._key'
            '  let value = $ctx._value'
            '  if $key { $key | read-str --max-len 64 | count }'
            '  if $value { 1 | count }'
            '  ($ctx.fd + $ctx.cmd + $ctx.aux) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-fsmount-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_fsmount]
        target: "tracepoint:syscalls/sys_enter_fsmount"
        program: [
            '{|ctx|'
            '  ($ctx.fs_fd + $ctx.flags + $ctx.attr_flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-fspick-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_fspick]
        target: "tracepoint:syscalls/sys_enter_fspick"
        program: [
            '{|ctx|'
            '  let path = $ctx.path'
            '  if $path { $path | read-str --max-len 64 | count }'
            '  ($ctx.dfd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-mount-setattr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_mount_setattr]
        target: "tracepoint:syscalls/sys_enter_mount_setattr"
        program: [
            '{|ctx|'
            '  let path = $ctx.path'
            '  let uattr = $ctx.uattr'
            '  if $path { $path | read-str --max-len 64 | count }'
            '  if $uattr { 1 | count }'
            '  ($ctx.dfd + $ctx.flags + $ctx.usize) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-statmount-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_statmount]
        target: "tracepoint:syscalls/sys_enter_statmount"
        program: [
            '{|ctx|'
            '  let req = $ctx.req'
            '  let buf = $ctx.buf'
            '  if $req { 1 | count }'
            '  if $buf { 1 | count }'
            '  ($ctx.bufsize + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-listmount-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_listmount]
        target: "tracepoint:syscalls/sys_enter_listmount"
        program: [
            '{|ctx|'
            '  let req = $ctx.req'
            '  let mnt_ids = $ctx.mnt_ids'
            '  if $req { 1 | count }'
            '  if $mnt_ids { 1 | count }'
            '  ($ctx.nr_mnt_ids + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-open-tree-attr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_open_tree_attr]
        target: "tracepoint:syscalls/sys_enter_open_tree_attr"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  let uattr = $ctx.uattr'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  if $uattr { 1 | count }'
            '  ($ctx.dfd + $ctx.flags + $ctx.usize) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-mount-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_mount]
        target: "tracepoint:syscalls/sys_enter_mount"
        program: [
            '{|ctx|'
            '  let dev_name = $ctx.dev_name'
            '  let dir_name = $ctx.dir_name'
            '  let fstype = $ctx.type'
            '  let data = $ctx.data'
            '  if $dev_name { $dev_name | read-str --max-len 64 | count }'
            '  if $dir_name { $dir_name | read-str --max-len 64 | count }'
            '  if $fstype { $fstype | read-str --max-len 64 | count }'
            '  if $data { 1 | count }'
            '  $ctx.flags | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-umount-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_umount]
        target: "tracepoint:syscalls/sys_enter_umount"
        program: [
            '{|ctx|'
            '  let name = $ctx.name'
            '  if $name { $name | read-str --max-len 64 | count }'
            '  $ctx.flags | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-pivot-root-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_pivot_root]
        target: "tracepoint:syscalls/sys_enter_pivot_root"
        program: [
            '{|ctx|'
            '  let new_root = $ctx.new_root'
            '  let put_old = $ctx.put_old'
            '  if $new_root { $new_root | read-str --max-len 64 | count }'
            '  if $put_old { $put_old | read-str --max-len 64 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-quotactl-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_quotactl]
        target: "tracepoint:syscalls/sys_enter_quotactl"
        program: [
            '{|ctx|'
            '  let special = $ctx.special'
            '  let addr = $ctx.addr'
            '  if $special { $special | read-str --max-len 64 | count }'
            '  if $addr { 1 | count }'
            '  ($ctx.cmd + $ctx.id) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-quotactl-fd-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_quotactl_fd]
        target: "tracepoint:syscalls/sys_enter_quotactl_fd"
        program: [
            '{|ctx|'
            '  let addr = $ctx.addr'
            '  if $addr { 1 | count }'
            '  ($ctx.fd + $ctx.cmd + $ctx.id) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-ustat-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_ustat]
        target: "tracepoint:syscalls/sys_enter_ustat"
        program: [
            '{|ctx|'
            '  let ubuf = $ctx.ubuf'
            '  if $ubuf { 1 | count }'
            '  $ctx.dev | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-execveat-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_execveat"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  let argv = $ctx.argv'
            '  if $argv { 1 | count }'
            '  let envp = $ctx.envp'
            '  if $envp { 1 | count }'
            '  ($ctx.fd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-wait4-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_wait4"
        program: [
            '{|ctx|'
            '  let stat_addr = $ctx.stat_addr'
            '  if $stat_addr { 1 | count }'
            '  let ru = $ctx.ru'
            '  if $ru { 1 | count }'
            '  ($ctx.upid + $ctx.options) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-setns-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_setns"
        program: [
            '{|ctx|'
            '  ($ctx.fd + $ctx.nstype) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-clone3-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_clone3]
        target: "tracepoint:syscalls/sys_enter_clone3"
        program: [
            '{|ctx|'
            '  let uargs = $ctx.uargs'
            '  if $uargs { 1 | count }'
            '  $ctx.size | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-dup3-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_dup3"
        program: [
            '{|ctx|'
            '  ($ctx.oldfd + $ctx.newfd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-lseek-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_lseek]
        target: "tracepoint:syscalls/sys_enter_lseek"
        program: [
            '{|ctx|'
            '  ($ctx.fd + $ctx.offset + $ctx.whence) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-fallocate-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_fallocate]
        target: "tracepoint:syscalls/sys_enter_fallocate"
        program: [
            '{|ctx|'
            '  ($ctx.fd + $ctx.mode + $ctx.offset + $ctx.len) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-sync-file-range-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_sync_file_range]
        target: "tracepoint:syscalls/sys_enter_sync_file_range"
        program: [
            '{|ctx|'
            '  ($ctx.fd + $ctx.offset + $ctx.nbytes + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
    {
        name: "tracepoint-landlock-create-ruleset-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_landlock_create_ruleset]
        target: "tracepoint:syscalls/sys_enter_landlock_create_ruleset"
        program: [
            '{|ctx|'
            '  let attr = $ctx.attr'
            '  if $attr { 1 | count }'
            '  ($ctx.size + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-landlock-add-rule-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_landlock_add_rule]
        target: "tracepoint:syscalls/sys_enter_landlock_add_rule"
        program: [
            '{|ctx|'
            '  let rule_attr = $ctx.rule_attr'
            '  if $rule_attr { 1 | count }'
            '  ($ctx.ruleset_fd + $ctx.rule_type + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-landlock-restrict-self-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_landlock_restrict_self]
        target: "tracepoint:syscalls/sys_enter_landlock_restrict_self"
        program: [
            '{|ctx|'
            '  ($ctx.ruleset_fd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-lsm-get-self-attr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_lsm_get_self_attr]
        target: "tracepoint:syscalls/sys_enter_lsm_get_self_attr"
        program: [
            '{|ctx|'
            '  let lsm_ctx = $ctx.ctx'
            '  let size = $ctx.size'
            '  if $lsm_ctx { 1 | count }'
            '  if $size { 1 | count }'
            '  ($ctx.attr + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-lsm-set-self-attr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_lsm_set_self_attr]
        target: "tracepoint:syscalls/sys_enter_lsm_set_self_attr"
        program: [
            '{|ctx|'
            '  let lsm_ctx = $ctx.ctx'
            '  if $lsm_ctx { 1 | count }'
            '  ($ctx.attr + $ctx.size + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-lsm-list-modules-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_lsm_list_modules]
        target: "tracepoint:syscalls/sys_enter_lsm_list_modules"
        program: [
            '{|ctx|'
            '  let ids = $ctx.ids'
            '  let size = $ctx.size'
            '  if $ids { 1 | count }'
            '  if $size { 1 | count }'
            '  $ctx.flags | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-setresuid-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_setresuid"
        program: [
            '{|ctx|'
            '  ($ctx.ruid + $ctx.euid + $ctx.suid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-getresgid-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_getresgid"
        program: [
            '{|ctx|'
            '  let rgidp = $ctx.rgidp'
            '  let egidp = $ctx.egidp'
            '  let sgidp = $ctx.sgidp'
            '  if $rgidp { 1 | count }'
            '  if $egidp { 1 | count }'
            '  if $sgidp { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-setgroups-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_setgroups"
        program: [
            '{|ctx|'
            '  $ctx.gidsetsize | count'
            '  let grouplist = $ctx.grouplist'
            '  if $grouplist { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-capset-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_capset"
        program: [
            '{|ctx|'
            '  let header = $ctx.header'
            '  let data = $ctx.data'
            '  if $header { 1 | count }'
            '  if $data { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-prctl-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_prctl"
        program: [
            '{|ctx|'
            '  ($ctx.option + ($ctx.args | get 1)) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-sched-setscheduler-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_sched_setscheduler]
        target: "tracepoint:syscalls/sys_enter_sched_setscheduler"
        program: [
            '{|ctx|'
            '  $ctx.policy | count'
            '  let param = $ctx.param'
            '  if $param { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-sched-setaffinity-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_sched_setaffinity]
        target: "tracepoint:syscalls/sys_enter_sched_setaffinity"
        program: [
            '{|ctx|'
            '  $ctx.len | count'
            '  let mask = $ctx.user_mask_ptr'
            '  if $mask { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-sched-getattr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_sched_getattr]
        target: "tracepoint:syscalls/sys_enter_sched_getattr"
        program: [
            '{|ctx|'
            '  ($ctx.size + $ctx.flags) | count'
            '  let uattr = $ctx.uattr'
            '  if $uattr { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-sched-rr-get-interval-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_sched_rr_get_interval]
        target: "tracepoint:syscalls/sys_enter_sched_rr_get_interval"
        program: [
            '{|ctx|'
            '  let interval = $ctx.interval'
            '  if $interval { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-nice-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_nice]
        target: "tracepoint:syscalls/sys_enter_nice"
        program: [
            '{|ctx|'
            '  $ctx.increment | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
    {
        name: "fentry-array-element-context"
        category: "tracing"
        tags: [fentry context array]
        requires: [kernel-btf]
        target: "fentry:wake_up_new_task"
        program: [
            '{|ctx|'
            '  ($ctx.arg0.comm.0 + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fentry-sleepable-context"
        category: "tracing"
        tags: [fentry sleepable context]
        requires: [kernel-btf]
        target: "fentry.s:security_file_open"
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
        name: "fexit-context"
        category: "tracing"
        tags: [fexit context]
        requires: [kernel-btf]
        target: "fexit:ksys_read"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.arg0 + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fexit-func-arg-ret-helper-calls"
        category: "tracing"
        tags: [fexit helper-call context source metadata]
        requires: [kernel-btf]
        target: "fexit:ksys_read"
        program: [
            '{|ctx|'
            '  let arg0 = "01234567"'
            '  let retval = "01234567"'
            '  (helper-call "bpf_get_func_arg" $ctx 0 $arg0) | count'
            '  (helper-call "bpf_get_func_ret" $ctx $retval) | count'
            '  (helper-call "bpf_get_func_arg_cnt" $ctx) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fentry-func-ret-helper-reject"
        category: "tracing"
        tags: [fentry helper-call context reject]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let retval = "01234567"'
            '  helper-call "bpf_get_func_ret" $ctx $retval'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_func_ret' is only valid in fexit and fmod_ret programs"
    }
    {
        name: "fentry-missing-target-help-reject"
        category: "tracing"
        tags: [fentry context diagnostic reject]
        requires: [kernel-btf]
        target: "fentry:nu_plugin_ebpf_missing_function_for_help"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "target signature"
    }
    {
        name: "fexit-sleepable-context"
        category: "tracing"
        tags: [fexit sleepable context]
        requires: [kernel-btf]
        target: "fexit.s:ksys_read"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.arg0 + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fmod-ret-context"
        category: "tracing"
        tags: [fmod-ret context]
        requires: [kernel-btf]
        target: "fmod_ret:security_file_open"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.arg.file.f_flags + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fmod-ret-sleepable-context"
        category: "tracing"
        tags: [fmod-ret sleepable context]
        requires: [kernel-btf]
        target: "fmod_ret.s:security_file_open"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.arg.file.f_flags + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lsm-context"
        category: "tracing"
        tags: [lsm context]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lsm-sleepable-context"
        category: "tracing"
        tags: [lsm sleepable context]
        requires: [kernel-btf]
        target: "lsm.s:file_open"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lsm-bound-arg-context"
        category: "tracing"
        tags: [lsm context alias]
        requires: [kernel-btf]
        target: "lsm:file_open"
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
    {
        name: "lsm-missing-target-help-reject"
        category: "tracing"
        tags: [lsm context diagnostic reject]
        requires: [kernel-btf]
        target: "lsm:nu_plugin_ebpf_missing_hook_for_help"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "LSM hook name"
    }
    {
        name: "lsm-cgroup-context"
        category: "tracing"
        tags: [lsm-cgroup context]
        requires: [kernel-btf]
        target: "lsm_cgroup:socket_bind"
        program: [
            '{|ctx|'
            '  ($ctx.arg2 + $ctx.arg_count + $ctx.pid) | count'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.arg_count is only available on BTF-backed tracing contexts with bpf_get_func_arg_cnt support"
    }
    {
        name: "lsm-cgroup-named-arg-context"
        category: "tracing"
        tags: [lsm-cgroup context named-arg source metadata]
        requires: [kernel-btf]
        target: "lsm_cgroup:socket_bind"
        program: [
            '{|ctx|'
            '  ($ctx.arg.address.sa_family + $ctx.arg.addrlen) | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "syscall-helper-context"
        category: "tracing"
        tags: [syscall helper-call]
        target: "syscall:demo"
        program: [
            '{||'
            '  helper-call "bpf_sys_close" 0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "freplace-context"
        category: "tracing"
        tags: [freplace context]
        target: "freplace:replace_me"
        program: [
            '{|ctx|'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "syscall-rejects-context-field"
        category: "context-policy"
        tags: [syscall context reject]
        target: "syscall:demo"
        program: [
            '{|ctx|'
            '  $ctx.pid | count'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.pid is not available on syscall programs"
    }
    {
        name: "freplace-rejects-arg-context"
        category: "context-policy"
        tags: [freplace context reject]
        target: "freplace:replace_me"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | count'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.arg0 is only available on contexts with argument access"
    }
    {
        name: "xdp-packet-count"
        category: "packet"
        tags: [xdp counter]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.packet_len | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-derived-header-fields"
        category: "packet"
        tags: [xdp packet header bitfield source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let ip4 = ($ctx.data.eth.ipv4.version + $ctx.data.eth.ipv4.ihl + $ctx.data.eth.ipv4.dscp + $ctx.data.eth.ipv4.ecn + $ctx.data.eth.ipv4.flags + $ctx.data.eth.ipv4.dont_fragment + $ctx.data.eth.ipv4.more_fragments + $ctx.data.eth.ipv4.fragment_offset)'
            '  let ip6 = ($ctx.data.eth.ipv6.version + $ctx.data.eth.ipv6.traffic_class + $ctx.data.eth.ipv6.flow_label)'
            '  let tcp = ($ctx.data.eth.ipv4.tcp.data_offset + $ctx.data.eth.ipv4.tcp.flags + $ctx.data.eth.ipv4.tcp.syn)'
            '  ($ip4 + $ip6 + $tcp) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-bitfield-writes"
        category: "packet"
        tags: [xdp packet header bitfield write source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.data.eth.ipv4.version = 4'
            '  $ctx.data.eth.ipv4.flags = 2'
            '  $ctx.data.eth.ipv4.tcp.syn = 1'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-arp-header-fields"
        category: "packet"
        tags: [xdp packet header arp source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let arp = ($ctx.data.eth.arp.hardware_type + $ctx.data.eth.arp.protocol_type + $ctx.data.eth.arp.hardware_len + $ctx.data.eth.arp.protocol_len + $ctx.data.eth.arp.opcode)'
            '  $arp | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-header-field-aliases"
        category: "packet"
        tags: [xdp packet header alias source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let eth = $ctx.data.eth.h_proto'
            '  let ip4 = ($ctx.data.eth.ipv4.tot_len + $ctx.data.eth.ipv4.saddr.0 + $ctx.data.eth.ipv4.daddr.0)'
            '  let udp = ($ctx.data.eth.ipv4.udp.source + $ctx.data.eth.ipv4.udp.dest)'
            '  ($eth + $ip4 + $udp) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-icmp-echo-fields"
        category: "packet"
        tags: [xdp packet header icmp source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let icmp4 = ($ctx.data.eth.ipv4.icmp.rest_of_header + $ctx.data.eth.ipv4.icmp.echo_id + $ctx.data.eth.ipv4.icmp.echo_sequence)'
            '  let icmp6 = ($ctx.data.eth.ipv6.icmpv6.rest + $ctx.data.eth.ipv6.icmpv6.identifier + $ctx.data.eth.ipv6.icmpv6.sequence)'
            '  ($icmp4 + $icmp6) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-frags-driver-context"
        category: "context-surface"
        tags: [xdp context frags]
        requires: [loopback-interface]
        target: "xdp:lo:drv:frags"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.rx_queue_index + $ctx.xdp_buff_len + $ctx.ancestor_cgroup_id.0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-devmap-secondary-context"
        category: "program-model"
        tags: [xdp devmap context]
        target: "xdp:devmap"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.egress_ifindex) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-cpumap-secondary-context"
        category: "program-model"
        tags: [xdp cpumap context]
        target: "xdp:cpumap"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.rx_queue_index) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tcx-egress-target-metadata"
        category: "program-model"
        tags: [tcx metadata]
        requires: [loopback-interface]
        target: "tcx:lo:egress"
        program: [
            '{|ctx|'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "netkit-peer-target-metadata"
        category: "program-model"
        tags: [netkit metadata]
        requires: [loopback-interface]
        target: "netkit:lo:peer"
        program: [
            '{|ctx|'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-target-metadata"
        category: "program-model"
        tags: [flow-dissector metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  "fallback"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "netfilter-defrag-target-metadata"
        category: "program-model"
        tags: [netfilter metadata]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  "accept"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-target-metadata"
        category: "program-model"
        tags: [lwt metadata seg6local]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sk-reuseport-migrate-target-metadata"
        category: "program-model"
        tags: [sk-reuseport metadata migrate]
        target: "sk_reuseport:migrate"
        program: [
            '{|ctx|'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-unix-target-metadata"
        category: "program-model"
        tags: [cgroup-sock-addr metadata unix]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "syscall-target-metadata"
        category: "program-model"
        tags: [syscall metadata]
        target: "syscall:demo"
        program: [
            '{||'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "freplace-target-metadata"
        category: "program-model"
        tags: [freplace metadata]
        target: "freplace:replace_me"
        program: [
            '{|ctx|'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-task-vma-target-metadata"
        category: "program-model"
        tags: [iter metadata task-vma]
        target: "iter:task_vma"
        program: [
            '{|ctx|'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-put-get-null-checked"
        category: "maps"
        tags: [hash-map null-check]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put seen_args 0 --kind hash'
            '  let entry = (0 | map-get seen_args --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-direct-pointer-branch"
        category: "maps"
        tags: [hash-map null-check branch]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put direct_seen_args 0 --kind hash'
            '  let entry = (0 | map-get direct_seen_args --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-record-key-put-get"
        category: "maps"
        tags: [maps map-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed --kind hash --key-type "record{pid:int,cookie:int}" --value-type int'
            '  let key = { pid: 1, cookie: 7 }'
            '  42 | map-put keyed $key --kind hash'
            '  let entry = ($key | map-get keyed --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-aligned-record-key-put-get"
        category: "maps"
        tags: [maps map-define records alignment accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_aligned --kind hash --key-type "record{tag:int,flag:bool}" --value-type int'
            '  let key = { tag: 7, flag: true }'
            '  42 | map-put keyed_aligned $key --kind hash'
            '  let entry = ($key | map-get keyed_aligned --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-array-record-key-put-get"
        category: "maps"
        tags: [maps map-define records arrays map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_batches --kind hash --key-type "array{record{pid:int,cpu:int}:2}" --value-type int'
            '  let put_key = [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }]'
            '  42 | map-put keyed_batches $put_key --kind hash'
            '  let get_key = [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }]'
            '  let entry = ($get_key | map-get keyed_batches --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-array-record-key-contains-delete"
        category: "maps"
        tags: [maps map-define records arrays map-contains map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_batches_ops --kind hash --key-type "array{record{pid:int,cpu:int}:2}" --value-type int'
            '  let put_key = [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }]'
            '  42 | map-put keyed_batches_ops $put_key --kind hash'
            '  let contains_key = [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }]'
            '  if (map-contains keyed_batches_ops $contains_key --kind hash) {'
            '    let delete_key = [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }]'
            '    map-delete keyed_batches_ops $delete_key --kind hash'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-value-type-invalid-array-length-rejects-context"
        category: "maps"
        tags: [maps map-define arrays diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define bad_values --kind hash --value-type "array{u32:x}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map value type spec 'array{u32:x}' has an invalid array length"
    }
    {
        name: "map-define-graph-root-payload-unmatched-braces-rejects-context"
        category: "maps"
        tags: [maps map-define graph diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "bpf_list_head:node_data:node:record{refs:bpf_refcount"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map value type spec 'bpf_list_head:node_data:node:record{refs:bpf_refcount' has unmatched '{' braces"
    }
    {
        name: "map-define-value-type-invalid-graph-root-field-rejects-path"
        category: "maps"
        tags: [maps map-define graph records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node-field,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'root' type spec 'bpf_list_head:node_data:node-field' requires a valid node field name"
    }
    {
        name: "map-define-value-type-graph-root-payload-non-record-rejects-path"
        category: "maps"
        tags: [maps map-define graph records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node:u64,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'root' type spec 'bpf_list_head:node_data:node:u64' requires the object payload schema to be record{...}"
    }
    {
        name: "map-define-value-type-graph-root-payload-refcount-array-rejects-path"
        category: "maps"
        tags: [maps map-define graph records bpf_refcount diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node:record{refs:array{bpf_refcount:2},cookie:u64},count:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'root.refs' type spec 'array{bpf_refcount:2}' has bpf_refcount, but arrays of verifier-managed bpf_refcount fields are not supported"
    }
    {
        name: "map-define-value-type-top-level-graph-root-payload-refcount-array-rejects-path"
        category: "maps"
        tags: [maps map-define graph bpf_refcount diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "bpf_list_head:node_data:node:record{refs:array{bpf_refcount:2},cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'refs' type spec 'array{bpf_refcount:2}' has bpf_refcount, but arrays of verifier-managed bpf_refcount fields are not supported"
    }
    {
        name: "map-define-key-type-duplicate-record-field-rejects-path"
        category: "maps"
        tags: [maps map-define records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define dup_keys --kind hash --key-type "record{pid:u32,pid:u64}" --value-type int'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'pid' is duplicated in type spec 'record{pid:u32,pid:u64}'"
    }
    {
        name: "map-define-value-type-invalid-kptr-field-rejects-path"
        category: "maps"
        tags: [maps map-define records kptr diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define state --kind hash --value-type "record{task:kptr:task-struct}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'task' type spec 'kptr:task-struct' requires a kernel struct type name"
    }
    {
        name: "annotated-mut-record-alignment"
        category: "globals"
        tags: [globals records alignment accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<tag: bool count: int> = { tag: true, count: 7 }'
            '  $state.count | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-record-empty-zero-init"
        category: "globals"
        tags: [globals records zero-init accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<pid: int stats: record<hits: int ok: bool>> = {}'
            '  ($state.pid + $state.stats.hits) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-scalar-null-rejected-by-nushell-parser"
        category: "globals"
        tags: [globals scalar "null" parser reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut hits: int = null'
            '  $hits | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expected int, found nothing"
    }
    {
        name: "annotated-mut-record-null-rejected-by-nushell-parser"
        category: "globals"
        tags: [globals records "null" parser reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<pid: int stats: record<hits: int ok: bool>> = null'
            '  ($state.pid + $state.stats.hits) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expected record<pid: int, stats: record<hits: int, ok: bool>>, found nothing"
    }
    {
        name: "annotated-mut-record-nested-empty-zero-fill"
        category: "globals"
        tags: [globals records zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<pid: int stats: record<hits: int ok: bool>> = { pid: 7 stats: {} }'
            '  ($state.pid + $state.stats.hits) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-record-nested-extra-field-rejects-path"
        category: "globals"
        tags: [globals records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<stats: record<hits: int>> = { stats: { hits: 7 extra: true } }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unexpected record field 'stats.extra'"
    }
    {
        name: "annotated-mut-list-spread-initializer"
        category: "globals"
        tags: [globals list list-spread accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut vals: list<int> = [1, ...[2, 3]]'
            '  ($vals | get 2) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-record-string-field-count"
        category: "globals"
        tags: [globals records string accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<comm: string pid: int> = { comm: "hi" pid: 7 }'
            '  $state.comm | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-record-array-inline-spread-initializer"
        category: "globals"
        tags: [globals records arrays list-spread accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut entries: list<record<pid: int cpu: int>> = [{ pid: 7 cpu: 2 }, ...[{ pid: 9 cpu: 3 }]]'
            '  $entries.1.cpu | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-record-array-bound-spread-initializer"
        category: "globals"
        tags: [globals records arrays list-spread accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let tail = [{ pid: 9 cpu: 3 }]'
            '  mut entries: list<record<pid: int cpu: int>> = [{ pid: 7 cpu: 2 }, ...$tail]'
            '  $entries.1.cpu | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-top-level-record-omission-rejected-by-nushell-parser"
        category: "globals"
        tags: [globals records parser reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<pid: int stats: record<hits: int ok: bool>> = { pid: 7 }'
            '  ($state.pid + $state.stats.hits) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expected record<pid: int, stats: record<hits: int, ok: bool>>, found record<pid: int>"
    }
]
