const VERIFIER_DIFF_FIXTURES_0094_0125 = [
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
]
