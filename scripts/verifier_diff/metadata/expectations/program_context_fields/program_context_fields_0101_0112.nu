[
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
]
