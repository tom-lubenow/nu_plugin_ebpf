const VERIFIER_DIFF_FIXTURES_0094_0125_A = [
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
]
