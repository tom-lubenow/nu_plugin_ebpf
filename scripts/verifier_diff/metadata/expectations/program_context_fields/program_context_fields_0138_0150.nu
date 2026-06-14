[
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
]
