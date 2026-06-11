const PROGRAM_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS_3 = [
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
    {
        target: "tracepoint:syscalls/sys_enter_bind"
        program: [
            '{|ctx|'
            '  let addr = $ctx.umyaddr'
            '  if $addr { 1 | count }'
            '  ($ctx.fd + $ctx.addrlen) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_bind:field:umyaddr"
            "tracepoint:syscalls/sys_enter_bind:field:fd"
            "tracepoint:syscalls/sys_enter_bind:field:addrlen"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_setsockopt"
        program: [
            '{|ctx|'
            '  let optval = $ctx.optval'
            '  if $optval { 1 | count }'
            '  ($ctx.fd + $ctx.level + $ctx.optname + $ctx.optlen) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_setsockopt:field:optval"
            "tracepoint:syscalls/sys_enter_setsockopt:field:fd"
            "tracepoint:syscalls/sys_enter_setsockopt:field:level"
            "tracepoint:syscalls/sys_enter_setsockopt:field:optname"
            "tracepoint:syscalls/sys_enter_setsockopt:field:optlen"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_recvmmsg:field:mmsg"
            "tracepoint:syscalls/sys_enter_recvmmsg:field:timeout"
            "tracepoint:syscalls/sys_enter_recvmmsg:field:fd"
            "tracepoint:syscalls/sys_enter_recvmmsg:field:vlen"
            "tracepoint:syscalls/sys_enter_recvmmsg:field:flags"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_getpeername:field:usockaddr"
            "tracepoint:syscalls/sys_enter_getpeername:field:usockaddr_len"
            "tracepoint:syscalls/sys_enter_getpeername:field:fd"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_getrandom"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.count + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_getrandom:field:buf"
            "tracepoint:syscalls/sys_enter_getrandom:field:count"
            "tracepoint:syscalls/sys_enter_getrandom:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_signalfd4"
        program: [
            '{|ctx|'
            '  let user_mask = $ctx.user_mask'
            '  if $user_mask { 1 | count }'
            '  ($ctx.ufd + $ctx.sizemask + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_signalfd4:field:user_mask"
            "tracepoint:syscalls/sys_enter_signalfd4:field:ufd"
            "tracepoint:syscalls/sys_enter_signalfd4:field:sizemask"
            "tracepoint:syscalls/sys_enter_signalfd4:field:flags"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:events"
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:timeout"
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:usig"
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:ctx_id"
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:min_nr"
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:nr"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_ioprio_set"
        program: [
            '{|ctx|'
            '  ($ctx.which + $ctx.who + $ctx.ioprio) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_ioprio_set:field:which"
            "tracepoint:syscalls/sys_enter_ioprio_set:field:who"
            "tracepoint:syscalls/sys_enter_ioprio_set:field:ioprio"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_add_key:field:_type"
            "tracepoint:syscalls/sys_enter_add_key:field:_description"
            "tracepoint:syscalls/sys_enter_add_key:field:_payload"
            "tracepoint:syscalls/sys_enter_add_key:field:plen"
            "tracepoint:syscalls/sys_enter_add_key:field:ringid"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_mbind"
        program: [
            '{|ctx|'
            '  let nmask = $ctx.nmask'
            '  if $nmask { 1 | count }'
            '  ($ctx.start + $ctx.len + $ctx.mode + $ctx.maxnode + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_mbind:field:nmask"
            "tracepoint:syscalls/sys_enter_mbind:field:start"
            "tracepoint:syscalls/sys_enter_mbind:field:len"
            "tracepoint:syscalls/sys_enter_mbind:field:mode"
            "tracepoint:syscalls/sys_enter_mbind:field:maxnode"
            "tracepoint:syscalls/sys_enter_mbind:field:flags"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_move_pages:field:pages"
            "tracepoint:syscalls/sys_enter_move_pages:field:nodes"
            "tracepoint:syscalls/sys_enter_move_pages:field:status"
            "tracepoint:syscalls/sys_enter_move_pages:field:nr_pages"
            "tracepoint:syscalls/sys_enter_move_pages:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_set_mempolicy_home_node"
        program: [
            '{|ctx|'
            '  ($ctx.start + $ctx.len + $ctx.home_node + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_set_mempolicy_home_node:field:start"
            "tracepoint:syscalls/sys_enter_set_mempolicy_home_node:field:len"
            "tracepoint:syscalls/sys_enter_set_mempolicy_home_node:field:home_node"
            "tracepoint:syscalls/sys_enter_set_mempolicy_home_node:field:flags"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_mq_open:field:u_name"
            "tracepoint:syscalls/sys_enter_mq_open:field:u_attr"
            "tracepoint:syscalls/sys_enter_mq_open:field:oflag"
            "tracepoint:syscalls/sys_enter_mq_open:field:mode"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_mq_timedreceive:field:u_msg_ptr"
            "tracepoint:syscalls/sys_enter_mq_timedreceive:field:u_msg_prio"
            "tracepoint:syscalls/sys_enter_mq_timedreceive:field:u_abs_timeout"
            "tracepoint:syscalls/sys_enter_mq_timedreceive:field:mqdes"
            "tracepoint:syscalls/sys_enter_mq_timedreceive:field:msg_len"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_mq_getsetattr:field:u_mqstat"
            "tracepoint:syscalls/sys_enter_mq_getsetattr:field:u_omqstat"
            "tracepoint:syscalls/sys_enter_mq_getsetattr:field:mqdes"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_process_vm_readv:field:lvec"
            "tracepoint:syscalls/sys_enter_process_vm_readv:field:rvec"
            "tracepoint:syscalls/sys_enter_process_vm_readv:field:liovcnt"
            "tracepoint:syscalls/sys_enter_process_vm_readv:field:riovcnt"
            "tracepoint:syscalls/sys_enter_process_vm_readv:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_pkey_mprotect"
        program: [
            '{|ctx|'
            '  ($ctx.start + $ctx.len + $ctx.prot + $ctx.pkey) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_pkey_mprotect:field:start"
            "tracepoint:syscalls/sys_enter_pkey_mprotect:field:len"
            "tracepoint:syscalls/sys_enter_pkey_mprotect:field:prot"
            "tracepoint:syscalls/sys_enter_pkey_mprotect:field:pkey"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_prlimit64:field:new_rlim"
            "tracepoint:syscalls/sys_enter_prlimit64:field:old_rlim"
            "tracepoint:syscalls/sys_enter_prlimit64:field:resource"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_get_robust_list:field:head_ptr"
            "tracepoint:syscalls/sys_enter_get_robust_list:field:len_ptr"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_rseq"
        program: [
            '{|ctx|'
            '  let user_rseq = $ctx.rseq'
            '  if $user_rseq { 1 | count }'
            '  ($ctx.rseq_len + $ctx.flags + $ctx.sig) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_rseq:field:rseq"
            "tracepoint:syscalls/sys_enter_rseq:field:rseq_len"
            "tracepoint:syscalls/sys_enter_rseq:field:flags"
            "tracepoint:syscalls/sys_enter_rseq:field:sig"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_init_module:field:umod"
            "tracepoint:syscalls/sys_enter_init_module:field:uargs"
            "tracepoint:syscalls/sys_enter_init_module:field:len"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_kexec_file_load"
        program: [
            '{|ctx|'
            '  let cmdline = $ctx.cmdline_ptr'
            '  if $cmdline { 1 | count }'
            '  ($ctx.kernel_fd + $ctx.initrd_fd + $ctx.cmdline_len + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_kexec_file_load:field:cmdline_ptr"
            "tracepoint:syscalls/sys_enter_kexec_file_load:field:kernel_fd"
            "tracepoint:syscalls/sys_enter_kexec_file_load:field:initrd_fd"
            "tracepoint:syscalls/sys_enter_kexec_file_load:field:cmdline_len"
            "tracepoint:syscalls/sys_enter_kexec_file_load:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_swapon"
        program: [
            '{|ctx|'
            '  let specialfile = $ctx.specialfile'
            '  if $specialfile { 1 | count }'
            '  $ctx.swap_flags | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_swapon:field:specialfile"
            "tracepoint:syscalls/sys_enter_swapon:field:swap_flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_bpf"
        program: [
            '{|ctx|'
            '  let uattr = $ctx.uattr'
            '  if $uattr { 1 | count }'
            '  ($ctx.cmd + $ctx.size) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_bpf:field:uattr"
            "tracepoint:syscalls/sys_enter_bpf:field:cmd"
            "tracepoint:syscalls/sys_enter_bpf:field:size"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_perf_event_open"
        program: [
            '{|ctx|'
            '  let attr = $ctx.attr_uptr'
            '  if $attr { 1 | count }'
            '  ($ctx.group_fd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_perf_event_open:field:attr_uptr"
            "tracepoint:syscalls/sys_enter_perf_event_open:field:group_fd"
            "tracepoint:syscalls/sys_enter_perf_event_open:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_seccomp"
        program: [
            '{|ctx|'
            '  let uargs = $ctx.uargs'
            '  if $uargs { 1 | count }'
            '  ($ctx.op + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_seccomp:field:uargs"
            "tracepoint:syscalls/sys_enter_seccomp:field:op"
            "tracepoint:syscalls/sys_enter_seccomp:field:flags"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_clone:field:parent_tidptr"
            "tracepoint:syscalls/sys_enter_clone:field:child_tidptr"
            "tracepoint:syscalls/sys_enter_clone:field:clone_flags"
            "tracepoint:syscalls/sys_enter_clone:field:newsp"
            "tracepoint:syscalls/sys_enter_clone:field:tls"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_syslog"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.type + $ctx.len) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_syslog:field:buf"
            "tracepoint:syscalls/sys_enter_syslog:field:type"
            "tracepoint:syscalls/sys_enter_syslog:field:len"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_personality"
        program: [
            '{|ctx|'
            '  $ctx.personality | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_personality:field:personality"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_openat"
        program: [
            '{|ctx|'
            '  ($ctx.id + ($ctx.args | get 0)) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_openat:field:id"
            "tracepoint:syscalls/sys_enter_openat:field:args"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_exit_openat2"
        program: [
            '{|ctx|'
            '  ($ctx.id + $ctx.ret) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_exit_openat2:field:id"
            "tracepoint:syscalls/sys_exit_openat2:field:ret"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_openat"
        program: [
            '{|ctx|'
            '  $ctx.ifindex | count'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx.flow_keys.ip_proto | count'
            '  "fallback"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.flow_keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut keys = $ctx.flow_keys'
            '  $keys.ip_proto = 17'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut keys = ($ctx | get flow_keys)'
            '  $keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  def get_keys [event] { $event | get flow_keys }'
            '  mut keys = (get_keys $ctx)'
            '  $keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = { keys: $ctx.flow_keys }'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = { keys: ($ctx | get flow_keys) }'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert keys ($ctx | get flow_keys))'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | insert keys ($ctx | get flow_keys))'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | merge { keys: ($ctx | get flow_keys) })'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | default ($ctx | get flow_keys) keys)'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
]
