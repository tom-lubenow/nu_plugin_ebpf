const VERIFIER_DIFF_FIXTURES_0719_0750_A = [
    {
        name: "tc-record-context-helper-arg"
        category: "helper-state"
        tags: [tc helper record context accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { skb: $ctx }'
            '  helper-call "bpf_skb_pull_data" $rec.skb 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-record-context-helper-arg"
        category: "helper-state"
        tags: [tc helper user-function record context accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [x] { { skb: $x } }'
            '  let rec = (wrap $ctx)'
            '  helper-call "bpf_skb_pull_data" $rec.skb 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-raw-context-helper-arg"
        category: "helper-state"
        tags: [tc helper user-function context accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def pull [skb] {'
            '    helper-call "bpf_skb_pull_data" $skb 0'
            '    0'
            '  }'
            '  pull $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-l3-csum-replace-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper checksum packet-bounds reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  helper-call "bpf_l3_csum_replace" $ctx 0 0 0 0'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-l3-csum-replace-allows-reloaded-data"
        category: "helper-state"
        tags: [tc helper checksum packet-bounds accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_l3_csum_replace" $ctx 0 0 0 0'
            '  ($ctx.data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-l3-csum-replace-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper checksum flags reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_l3_csum_replace" $ctx 0 0 0 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_l3_csum_replace' requires arg4 flags"
    }
    {
        name: "tc-l4-csum-replace-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper checksum packet-bounds reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  helper-call "bpf_l4_csum_replace" $ctx 0 0 0 0'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-l4-csum-replace-allows-reloaded-data"
        category: "helper-state"
        tags: [tc helper checksum packet-bounds accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_l4_csum_replace" $ctx 0 0 0 0'
            '  ($ctx.data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-l4-csum-replace-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper checksum flags reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_l4_csum_replace" $ctx 0 0 0 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_l4_csum_replace' requires arg4 flags"
    }
    {
        name: "tc-csum-update-preserves-packet-data"
        category: "helper-state"
        tags: [tc helper checksum packet-bounds accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  helper-call "bpf_csum_update" $ctx 0'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-set-hash-invalid-preserves-packet-data"
        category: "helper-state"
        tags: [tc helper hash packet-bounds accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  helper-call "bpf_set_hash_invalid" $ctx'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-set-hash-invalid-rejects-return-use"
        category: "helper-state"
        tags: [tc helper hash void-return reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_set_hash_invalid" $ctx | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "void helper 'bpf_set_hash_invalid' return value cannot be used"
    }
    {
        name: "tc-skb-pull-data-rejects-socket-ctx-arg"
        category: "helper-state"
        tags: [tc helper raw-context reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  if $sk { helper-call "bpf_skb_pull_data" $sk 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_pull_data' arg0 expects raw context pointer"
    }
    {
        name: "tc-fib-lookup-rejects-socket-ctx-arg"
        category: "helper-state"
        tags: [tc helper fib raw-context reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define scratch --kind array --value-type bytes:64 --max-entries 1'
            '  let params = (0 | map-get scratch --kind array)'
            '  let sk = $ctx.sk'
            '  if $sk { if $params { helper-call "bpf_fib_lookup" $sk $params 64 0 } }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_fib_lookup' arg0 expects raw context pointer"
    }
    {
        name: "tc-fib-lookup-helper"
        category: "helper-state"
        tags: [tc helper fib accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:64 --max-entries 1'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 0 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-fib-lookup-rejects-small-params-buffer"
        category: "helper-state"
        tags: [tc helper fib bounds reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:8 --max-entries 1'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper fib_lookup params requires 64 bytes"
    }
]
