const VERIFIER_DIFF_FIXTURES_0063_0093_A = [
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
]
