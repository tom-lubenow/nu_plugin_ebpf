const VERIFIER_DIFF_FIXTURES_0719_0750_A_B = [
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
