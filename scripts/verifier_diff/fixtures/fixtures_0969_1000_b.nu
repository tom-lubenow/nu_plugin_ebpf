const VERIFIER_DIFF_FIXTURES_0969_1000_B = [
    {
        name: "sock-ops-store-hdr-opt-allows-reloaded-data"
        category: "helper-state"
        tags: [sock-ops helper-call hdr-opt packet-bounds accept]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  if ($ctx.op == 15) {'
            '    let opt = "0123456789abcdef"'
            '    helper-call "bpf_store_hdr_opt" $ctx $opt 16 0'
            '    ($ctx.data | get 0) | count'
            '  }'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-packet-metadata-requires-op-guard"
        category: "context-policy"
        tags: [sock-ops context packet reject]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.skb_len + $ctx.skb_tcp_flags) | count'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.packet_len on sock_ops requires proving a packet-aware ctx.op callback before use"
    }
    {
        name: "sock-ops-packet-metadata-op-guard"
        category: "context-surface"
        tags: [sock-ops context packet accept]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  if ($ctx.op == 13) {'
            '    ($ctx.packet_len + $ctx.skb_len + $ctx.skb_tcp_flags) | count'
            '  }'
            '  if ($ctx.op == 16) {'
            '    ($ctx.packet_len + $ctx.skb_len + ($ctx.skb_hwtstamp mod 1024)) | count'
            '  }'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-packet-data-requires-op-guard"
        category: "context-policy"
        tags: [sock-ops context packet reject]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.data | get 0) | count'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.data on sock_ops requires proving a packet-aware ctx.op callback before use"
    }
    {
        name: "sock-ops-packet-data-op-guard"
        category: "context-surface"
        tags: [sock-ops context packet accept]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  if ($ctx.op == 13) {'
            '    if ($ctx.data_end != 0) {'
            '      ($ctx.data | get 0) | count'
            '    }'
            '  }'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
