const VERIFIER_DIFF_FIXTURES_1001_1031_A_C = [
    {
        name: "sk-msg-basic-context"
        category: "context-surface"
        tags: [sk-msg context]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.size + $ctx.family + $ctx.local_port + $ctx.remote_port + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-msg-rich-context"
        category: "context-surface"
        tags: [sk-msg context packet socket source metadata]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.len + $ctx.size + $ctx.remote_ip4 + $ctx.local_ip4 + ($ctx.remote_ip6 | get 0) + ($ctx.local_ip6 | get 1)) | count'
            '  if $ctx.data_end { 1 | count }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
