const VERIFIER_DIFF_FIXTURES_0751_0781_B = [
    {
        name: "source-helper-get-stack-rejects-dynamic-negative-size"
        category: "helper-state"
        tags: [helper stack-copy size dynamic reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define get_stack_dynamic_negative_buf --kind array --value-type bytes:24 --max-entries 1'
            '  let buf = (0 | map-get get_stack_dynamic_negative_buf)'
            '  let size = (0 - (helper-call "bpf_get_prandom_u32"))'
            '  if $buf { helper-call "bpf_get_stack" $ctx $buf $size 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stack-copy helpers require arg2 size to be between 0 and u32::MAX"
    }
    {
        name: "source-helper-get-stack-rejects-invalid-flags"
        category: "helper-state"
        tags: [helper stack-copy flags reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define get_stack_flag_buf --kind array --value-type bytes:24 --max-entries 1'
            '  let buf = (0 | map-get get_stack_flag_buf)'
            '  if $buf { helper-call "bpf_get_stack" $ctx $buf 24 512 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stack-copy helpers require flags"
    }
    {
        name: "source-helper-get-stack-rejects-dynamic-flags"
        category: "helper-state"
        tags: [helper stack-copy flags reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define get_stack_dynamic_flag_buf --kind array --value-type bytes:24 --max-entries 1'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let buf = (0 | map-get get_stack_dynamic_flag_buf)'
            '  if $buf { helper-call "bpf_get_stack" $ctx $buf 24 $flags }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stack-copy helpers require flags"
    }
    {
        name: "source-helper-get-stack-rejects-xdp"
        category: "helper-state"
        tags: [helper stack-copy program-policy reject source metadata]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define get_stack_xdp_buf --kind array --value-type bytes:24 --max-entries 1'
            '  let buf = (0 | map-get get_stack_xdp_buf)'
            '  if $buf { helper-call "bpf_get_stack" $ctx $buf 24 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_stack' is only valid"
    }
    {
        name: "helper-packet-output-accepts-skb-argument"
        category: "helper-state"
        tags: [helper packet-output skb tracing accept source metadata]
        requires: [kernel-btf]
        target: "fentry:netif_receive_skb"
        program: [
            '{|ctx|'
            '  let data = "abcd"'
            '  helper-call "bpf_skb_output" $ctx.arg0 packet_events 0 $data 4'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "helper-packet-output-rejects-raw-tracing-context"
        category: "helper-state"
        tags: [helper packet-output skb tracing raw-context reject source metadata]
        requires: [kernel-btf]
        target: "fentry:netif_receive_skb"
        program: [
            '{|ctx|'
            '  let data = "abcd"'
            '  helper-call "bpf_skb_output" $ctx packet_events 0 $data 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_output' arg0 expects sk_buff pointer"
    }
    {
        name: "helper-xdp-output-rejects-raw-tracing-context"
        category: "helper-state"
        tags: [helper packet-output xdp tracing raw-context reject source metadata]
        requires: [kernel-btf]
        target: "fentry:xdp_do_redirect"
        program: [
            '{|ctx|'
            '  let data = "abcd"'
            '  helper-call "bpf_xdp_output" $ctx packet_events 0 $data 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_xdp_output' arg0 expects xdp_buff pointer"
    }
]
