const VERIFIER_DIFF_FIXTURES_0688_0718_B_B = [
    {
        name: "tc-skb-store-bytes-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper packet-bounds reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  let bytes = "x"'
            '  helper-call "bpf_skb_store_bytes" $ctx 0 $bytes 1 0'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-skb-store-bytes-allows-reloaded-data"
        category: "helper-state"
        tags: [tc helper packet-bounds accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let bytes = "x"'
            '  helper-call "bpf_skb_store_bytes" $ctx 0 $bytes 1 0'
            '  ($ctx.data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-store-bytes-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper packet-bounds flags reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let bytes = "x"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_store_bytes" $ctx 0 $bytes 1 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_store_bytes' requires arg4 flags"
    }
    {
        name: "tc-subfn-skb-store-bytes-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper user-function packet-bounds reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def mutate [skb bytes] {'
            '    helper-call "bpf_skb_store_bytes" $skb 0 $bytes 1 0'
            '    0'
            '  }'
            '  let data = $ctx.data'
            '  let bytes = "x"'
            '  mutate $ctx $bytes'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-subfn-skb-store-bytes-allows-reloaded-data"
        category: "helper-state"
        tags: [tc helper user-function packet-bounds accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def mutate [skb bytes] {'
            '    helper-call "bpf_skb_store_bytes" $skb 0 $bytes 1 0'
            '    0'
            '  }'
            '  let bytes = "x"'
            '  mutate $ctx $bytes'
            '  ($ctx.data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-subfn-skb-pull-data-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper user-function packet-bounds reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def pull [skb] {'
            '    helper-call "bpf_skb_pull_data" $skb 0'
            '    0'
            '  }'
            '  let data = $ctx.data'
            '  pull $ctx'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-subfn-skb-pull-data-allows-reloaded-data"
        category: "helper-state"
        tags: [tc helper user-function packet-bounds accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def pull [skb] {'
            '    helper-call "bpf_skb_pull_data" $skb 0'
            '    0'
            '  }'
            '  pull $ctx'
            '  ($ctx.data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-nested-subfn-skb-pull-data-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper user-function nested packet-bounds reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  def mutate [skb] {'
            '    let actual = (id $skb)'
            '    helper-call "bpf_skb_pull_data" $actual 0'
            '    0'
            '  }'
            '  let data = $ctx.data'
            '  mutate $ctx'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
]
