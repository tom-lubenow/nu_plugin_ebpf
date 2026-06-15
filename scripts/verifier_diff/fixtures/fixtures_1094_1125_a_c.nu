const VERIFIER_DIFF_FIXTURES_1094_1125_A_C = [
    {
        name: "iter-tcp-context"
        category: "context-surface"
        tags: [iter context socket]
        target: "iter:tcp"
        program: [
            '{|ctx|'
            '  $ctx.uid | count'
            '  if $ctx.sk_common { 1 | count }'
            '  if $ctx.sock_common { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-tcp-btf-field"
        category: "context-surface"
        tags: [iter context socket btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:tcp"
        program: [
            '{|ctx|'
            '  if $ctx.sk_common { $ctx.sk_common.skc_family | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-udp-context"
        category: "context-surface"
        tags: [iter context socket]
        target: "iter:udp"
        program: [
            '{|ctx|'
            '  ($ctx.uid + $ctx.bucket) | count'
            '  if $ctx.udp_sk { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
