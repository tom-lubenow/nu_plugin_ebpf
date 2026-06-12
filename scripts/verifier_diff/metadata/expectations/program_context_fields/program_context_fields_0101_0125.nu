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
    {
        target: "tracepoint:syscalls/sys_enter_execve"
        program: [
            '{|ctx|'
            '  let event = $ctx'
            '  let rec = { root: $ctx }'
            '  $event.filename | count'
            '  $rec.root.argv | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_execve:field:filename"
            "tracepoint:syscalls/sys_enter_execve:field:argv"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_execve"
        program: [
            '{|ctx|'
            '  def read_env [event] {'
            '    $event.envp | count'
            '    0'
            '  }'
            '  read_env $ctx'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_execve:field:envp"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_connect"
        program: [
            '{|ctx|'
            '  let addr = $ctx.uservaddr'
            '  if $addr { 1 | count }'
            '  ($ctx.fd + $ctx.addrlen) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_connect:field:uservaddr"
            "tracepoint:syscalls/sys_enter_connect:field:fd"
            "tracepoint:syscalls/sys_enter_connect:field:addrlen"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_sendto:field:buff"
            "tracepoint:syscalls/sys_enter_sendto:field:addr"
            "tracepoint:syscalls/sys_enter_sendto:field:fd"
            "tracepoint:syscalls/sys_enter_sendto:field:len"
            "tracepoint:syscalls/sys_enter_sendto:field:flags"
            "tracepoint:syscalls/sys_enter_sendto:field:addr_len"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_recvfrom:field:ubuf"
            "tracepoint:syscalls/sys_enter_recvfrom:field:addr"
            "tracepoint:syscalls/sys_enter_recvfrom:field:addr_len"
            "tracepoint:syscalls/sys_enter_recvfrom:field:fd"
            "tracepoint:syscalls/sys_enter_recvfrom:field:size"
            "tracepoint:syscalls/sys_enter_recvfrom:field:flags"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_accept4:field:upeer_sockaddr"
            "tracepoint:syscalls/sys_enter_accept4:field:upeer_addrlen"
            "tracepoint:syscalls/sys_enter_accept4:field:fd"
            "tracepoint:syscalls/sys_enter_accept4:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_socket"
        program: [
            '{|ctx|'
            '  ($ctx.family + $ctx.type + $ctx.protocol) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_socket:field:family"
            "tracepoint:syscalls/sys_enter_socket:field:type"
            "tracepoint:syscalls/sys_enter_socket:field:protocol"
        ]
    }
]
