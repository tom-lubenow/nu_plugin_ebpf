const VERIFIER_DIFF_FIXTURES_0563_0625 = [
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
    {
        name: "dynptr-kfunc-slice-rdwr-rejects-uninitialized"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let ptr = (kfunc-call "bpf_dynptr_slice_rdwr" $d 0 0 4)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_slice_rdwr' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-slice-rdwr-rejects-nonzero-buffer"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let ptr = (kfunc-call "bpf_dynptr_slice_rdwr" $d 0 1 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_slice_rdwr' arg2 expects null (0) or pointer"
    }
    {
        name: "dynptr-kfunc-slice-rdwr-allows-zero-vreg-buffer"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let buf = 0'
            '  let ptr = (kfunc-call "bpf_dynptr_slice_rdwr" $d 0 $buf 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-slice-rdwr-rejects-nonzero-vreg-buffer"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let buf = 1'
            '  let ptr = (kfunc-call "bpf_dynptr_slice_rdwr" $d 0 $buf 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_slice_rdwr' arg2 expects null (0) or pointer"
    }
    {
        name: "dynptr-kfunc-slice-rdwr-rejects-dynamic-size"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let size = (helper-call "bpf_get_prandom_u32")'
            '  let ptr = (kfunc-call "bpf_dynptr_slice_rdwr" $d 0 0 $size)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_slice_rdwr' arg3 must be known constant"
    }
    {
        name: "dynptr-kfunc-adjust-initialized-ringbuf"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_adjust" $d 0 4'
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
        name: "dynptr-kfunc-adjust-rejects-uninitialized"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_adjust" $d 0 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_adjust' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-memset-initialized-ringbuf"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_memset" $d 0 0 4'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-memset-rejects-uninitialized"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_memset" $d 0 0 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_memset' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-null-rdonly-queries-initialized-ringbuf"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let is_null = (kfunc-call "bpf_dynptr_is_null" $d)'
            '  let is_rdonly = (kfunc-call "bpf_dynptr_is_rdonly" $d)'
            '  $is_null | count'
            '  $is_rdonly | count'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-copy-initialized-ringbuf"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = "0123456789abcdef"'
            '  let src = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $dst'
            '  kfunc-call "bpf_dynptr_clone" $dst $src'
            '  kfunc-call "bpf_dynptr_copy" $dst 0 $src 0 4'
            '  helper-call "bpf_ringbuf_submit_dynptr" $dst 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-copy-rejects-uninitialized-destination"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = "0123456789abcdef"'
            '  let src = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $src'
            '  kfunc-call "bpf_dynptr_copy" $dst 0 $src 0 4'
            '  helper-call "bpf_ringbuf_discard_dynptr" $src 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_copy' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-copy-rejects-uninitialized-source"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = "0123456789abcdef"'
            '  let src = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $dst'
            '  kfunc-call "bpf_dynptr_copy" $dst 0 $src 0 4'
            '  helper-call "bpf_ringbuf_discard_dynptr" $dst 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_copy' arg2 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-clone-initializes-destination"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let clone = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_clone" $d $clone'
            '  let size = (kfunc-call "bpf_dynptr_size" $clone)'
            '  $size | count'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-clone-rejects-same-stack-slot"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_clone" $d $d'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_clone' arg1 must reference distinct stack slot from arg0"
    }
    {
        name: "dynptr-kfunc-clone-rejects-initialized-destination"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let src = "0123456789abcdef"'
            '  let dst = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $src'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $dst'
            '  kfunc-call "bpf_dynptr_clone" $src $dst'
            '  helper-call "bpf_ringbuf_discard_dynptr" $src 0'
            '  helper-call "bpf_ringbuf_discard_dynptr" $dst 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_clone' arg1 requires uninitialized dynptr stack object slot"
    }
    {
        name: "dynptr-kfunc-clone-rejects-destination-initialized-on-one-path"
        category: "helper-state"
        tags: [kfunc dynptr branch reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let src = "0123456789abcdef"'
            '  let dst = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $src'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $dst'
            '  }'
            '  kfunc-call "bpf_dynptr_clone" $src $dst'
            '  helper-call "bpf_ringbuf_discard_dynptr" $src 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_clone' arg1 requires uninitialized dynptr stack object slot"
    }
    {
        name: "dynptr-kfunc-clone-submit-through-clone-balanced"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let clone = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_clone" $d $clone'
            '  helper-call "bpf_ringbuf_submit_dynptr" $clone 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-clone-submit-through-clone-invalidates-source"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let clone = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_clone" $d $clone'
            '  helper-call "bpf_ringbuf_submit_dynptr" $clone 0'
            '  kfunc-call "bpf_dynptr_size" $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_size' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-clone-discard-invalidates-clone"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let clone = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_clone" $d $clone'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  kfunc-call "bpf_dynptr_size" $clone'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_size' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-clone-rejects-uninitialized-source"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let clone = "fedcba9876543210"'
            '  kfunc-call "bpf_dynptr_clone" $d $clone'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_clone' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-clone-rejects-use-after-ringbuf-submit"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let clone = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_clone" $d $clone'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  kfunc-call "bpf_dynptr_size" $clone'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_size' arg0 requires initialized dynptr stack object"
    }
    {
        name: "stackid-built-in-kstacks"
        category: "maps"
        tags: [helper-call stack-trace reserved-name]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_stackid" $ctx kstacks 0 | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "stackid-built-in-kstacks-rejects-dynamic-flags"
        category: "maps"
        tags: [helper-call stack-trace reserved-name flags reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_get_stackid" $ctx kstacks $flags | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_stackid' requires arg2 flags"
    }
    {
        name: "stackid-context-fields"
        category: "context-surface"
        tags: [context stack-trace kstack ustack accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ($ctx.kstack + $ctx.ustack) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "task-pt-regs-context"
        category: "context-surface"
        tags: [context task pt-regs helper-backed accept]
        requires: [kernel-btf]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.task.pt_regs.arg0 | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "task-pt-regs-bound-context"
        category: "context-surface"
        tags: [context task pt-regs helper-backed source metadata accept]
        requires: [kernel-btf]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let task = $ctx.task'
            '  $task.pt_regs.arg0 | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "helper-current-task-bound-projection"
        category: "context-surface"
        tags: [context task helper-call source metadata accept]
        requires: [kernel-btf]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let task = (helper-call "bpf_get_current_task_btf")'
            '  $task.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "current-cgroup-bound-context"
        category: "context-surface"
        tags: [context cgroup btf source metadata accept]
        requires: [kernel-btf]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let cg = $ctx.current_cgroup'
            '  $cg.kn.id | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-scalar-mut"
        category: "globals"
        tags: [data-global scalar]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut hits: int = 0'
            '  $hits = ($hits + 1)'
            '  $hits | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-cgroup-array-contains"
        category: "packet"
        tags: [tc-action cgroup-array helper-policy]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  map-contains tracked_cgroups 0 --kind cgroup-array'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-coarse-time-context"
        category: "context-surface"
        tags: [tc context time source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx.ktime_coarse | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
