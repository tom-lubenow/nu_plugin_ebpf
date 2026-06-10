const VERIFIER_DIFF_FIXTURES_0563_0593 = [
    {
        name: "dynptr-kfunc-from-xdp-rejects-non-xdp-program"
        category: "helper-state"
        tags: [kfunc dynptr xdp program-policy reject]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_xdp" $ctx 0 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_xdp' is only valid in xdp programs"
    }
    {
        name: "dynptr-kfunc-from-skb-initializes-dynptr"
        category: "helper-state"
        tags: [kfunc dynptr skb tc accept]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-skb-copied-raw-context"
        category: "helper-state"
        tags: [kfunc dynptr skb tc accept context-alias]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let raw_ctx = $ctx'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $raw_ctx 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-skb-user-function-raw-context"
        category: "helper-state"
        tags: [kfunc dynptr skb tc accept user-function]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def init [raw_ctx] {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_dynptr_from_skb" $raw_ctx 0 $d'
            '    let size = (kfunc-call "bpf_dynptr_size" $d)'
            '    $size | count'
            '    0'
            '  }'
            '  init $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-skb-returned-raw-context"
        category: "helper-state"
        tags: [kfunc dynptr skb tc accept user-function source metadata]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def get_ctx [event] { $event }'
            '  let raw_ctx = (get_ctx $ctx)'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $raw_ctx 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-skb-user-function-out-param"
        category: "helper-state"
        tags: [kfunc dynptr skb tc accept user-function]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def init [raw_ctx d] {'
            '    kfunc-call "bpf_dynptr_from_skb" $raw_ctx 0 $d'
            '    0'
            '  }'
            '  def size [d] {'
            '    let size = (kfunc-call "bpf_dynptr_size" $d)'
            '    $size | count'
            '    0'
            '  }'
            '  let d = "0123456789abcdef"'
            '  init $ctx $d'
            '  size $d'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-skb-rejects-reinit-after-conditional-user-function-init"
        category: "helper-state"
        tags: [kfunc dynptr skb tc reject user-function branch]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def maybe-init [raw_ctx d selector] {'
            '    if $selector == 0 {'
            '      kfunc-call "bpf_dynptr_from_skb" $raw_ctx 0 $d'
            '    }'
            '    0'
            '  }'
            '  let d = "0123456789abcdef"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  maybe-init $ctx $d $selector'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx 0 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires uninitialized dynptr stack object slot"
    }
    {
        name: "dynptr-kfunc-from-skb-accepts-netfilter-skb-pointer"
        category: "helper-state"
        tags: [kfunc dynptr skb netfilter accept]
        requires: [kernel-btf]
        target: "netfilter:ipv4:pre_routing"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx.skb 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "dynptr-kfunc-from-skb-accepts-netfilter-copied-skb-pointer"
        category: "helper-state"
        tags: [kfunc dynptr skb netfilter accept context-alias]
        requires: [kernel-btf]
        target: "netfilter:ipv4:pre_routing"
        program: [
            '{|ctx|'
            '  let skb = $ctx.skb'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $skb 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "dynptr-kfunc-from-skb-accepts-netfilter-user-function-skb-pointer"
        category: "helper-state"
        tags: [kfunc dynptr skb netfilter accept user-function]
        requires: [kernel-btf]
        target: "netfilter:ipv4:pre_routing"
        program: [
            '{|ctx|'
            '  def init [skb] {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_dynptr_from_skb" $skb 0 $d'
            '    let size = (kfunc-call "bpf_dynptr_size" $d)'
            '    $size | count'
            '    0'
            '  }'
            '  init $ctx.skb'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "dynptr-kfunc-from-skb-accepts-tracing-skb-argument"
        category: "helper-state"
        tags: [kfunc dynptr skb tracing accept]
        requires: [kernel-btf]
        target: "fentry:tcp_v4_rcv"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx.arg0 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-skb-accepts-tracing-copied-skb-argument"
        category: "helper-state"
        tags: [kfunc dynptr skb tracing accept context-alias]
        requires: [kernel-btf]
        target: "fentry:tcp_v4_rcv"
        program: [
            '{|ctx|'
            '  let skb = $ctx.arg0'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $skb 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-skb-accepts-tracing-user-function-skb-argument"
        category: "helper-state"
        tags: [kfunc dynptr skb tracing accept user-function]
        requires: [kernel-btf]
        target: "fentry:tcp_v4_rcv"
        program: [
            '{|ctx|'
            '  def init [skb] {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_dynptr_from_skb" $skb 0 $d'
            '    let size = (kfunc-call "bpf_dynptr_size" $d)'
            '    $size | count'
            '    0'
            '  }'
            '  init $ctx.arg0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-skb-rejects-packet-arg"
        category: "helper-state"
        tags: [kfunc dynptr skb tc source reject]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx.data 0 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_skb' arg0 expects __sk_buff context or sk_buff pointer"
    }
    {
        name: "dynptr-kfunc-from-skb-rejects-netfilter-raw-context"
        category: "helper-state"
        tags: [kfunc dynptr skb netfilter source reject]
        requires: [kernel-btf]
        target: "netfilter:ipv4:pre_routing"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx 0 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_skb' arg0 expects __sk_buff context or sk_buff pointer"
    }
    {
        name: "dynptr-kfunc-from-skb-rejects-tracing-raw-context"
        category: "helper-state"
        tags: [kfunc dynptr skb tracing source reject]
        requires: [kernel-btf]
        target: "fentry:tcp_v4_rcv"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx 0 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_skb' arg0 expects __sk_buff context or sk_buff pointer"
    }
    {
        name: "dynptr-kfunc-from-skb-rejects-reinitialize"
        category: "helper-state"
        tags: [kfunc dynptr skb tc reject]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx 0 $d'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx 0 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_skb' arg2 requires uninitialized dynptr stack object slot"
    }
    {
        name: "dynptr-kfunc-from-skb-rejects-nonzero-flags"
        category: "helper-state"
        tags: [kfunc dynptr skb tc flags reject]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx 1 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_skb' arg1 must be known zero"
    }
    {
        name: "dynptr-kfunc-from-skb-rejects-dynamic-flags"
        category: "helper-state"
        tags: [kfunc dynptr skb tc flags reject]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx $flags $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_skb' arg1 must be known zero"
    }
    {
        name: "dynptr-kfunc-from-skb-rejects-non-skb-program"
        category: "helper-state"
        tags: [kfunc dynptr skb program-policy reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx 0 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_skb' is only valid in socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, sk_skb_parser, netfilter, fentry, fexit, fmod_ret, and tp_btf programs"
    }
    {
        name: "dynptr-kfunc-size-initialized-ringbuf"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-size-rejects-uninitialized"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_size" $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_size' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-slice-initialized-ringbuf"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let ptr = (kfunc-call "bpf_dynptr_slice" $d 0 0 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-record-field-local-tracks-lifecycle"
        category: "helper-state"
        tags: [kfunc dynptr record source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let rec = { d: "0123456789abcdef" }'
            '  let d = $rec.d'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let ptr = (kfunc-call "bpf_dynptr_slice" $d 0 0 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-record-field-direct-tracks-lifecycle"
        category: "helper-state"
        tags: [kfunc dynptr record source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let rec = { d: "0123456789abcdef" }'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $rec.d'
            '  let ptr = (kfunc-call "bpf_dynptr_slice" $rec.d 0 0 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $rec.d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-slice-rejects-nonzero-buffer"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let ptr = (kfunc-call "bpf_dynptr_slice" $d 0 1 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_slice' arg2 expects null (0) or pointer"
    }
    {
        name: "dynptr-kfunc-slice-allows-zero-vreg-buffer"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let buf = 0'
            '  let ptr = (kfunc-call "bpf_dynptr_slice" $d 0 $buf 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-slice-rejects-nonzero-vreg-buffer"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let buf = 1'
            '  let ptr = (kfunc-call "bpf_dynptr_slice" $d 0 $buf 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_slice' arg2 expects null (0) or pointer"
    }
    {
        name: "dynptr-kfunc-slice-rejects-dynamic-size"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let size = (helper-call "bpf_get_prandom_u32")'
            '  let ptr = (kfunc-call "bpf_dynptr_slice" $d 0 0 $size)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_slice' arg3 must be known constant"
    }
    {
        name: "dynptr-kfunc-slice-rejects-uninitialized"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let ptr = (kfunc-call "bpf_dynptr_slice" $d 0 0 4)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_slice' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-slice-rdwr-initialized-ringbuf"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let ptr = (kfunc-call "bpf_dynptr_slice_rdwr" $d 0 0 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
