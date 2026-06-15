const VERIFIER_DIFF_FIXTURES_0969_1000_A = [
    {
        name: "sock-ops-enable-tx-tstamp-copied-raw-context"
        category: "kfunc"
        tags: [sock-ops kfunc timestamp source metadata context-alias]
        requires: [cgroup-v2 kernel-btf]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let raw_ctx = $ctx'
            '  kfunc-call "bpf_sock_ops_enable_tx_tstamp" $raw_ctx 0'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sock-ops-enable-tx-tstamp-user-function-raw-context"
        category: "kfunc"
        tags: [sock-ops kfunc timestamp source metadata user-function]
        requires: [cgroup-v2 kernel-btf]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  def enable [raw_ctx] {'
            '    kfunc-call "bpf_sock_ops_enable_tx_tstamp" $raw_ctx 0'
            '    0'
            '  }'
            '  enable $ctx'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sock-ops-enable-tx-tstamp-returned-raw-context"
        category: "kfunc"
        tags: [sock-ops kfunc timestamp source metadata user-function]
        requires: [cgroup-v2 kernel-btf]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  def get_ctx [event] { $event }'
            '  let raw_ctx = (get_ctx $ctx)'
            '  kfunc-call "bpf_sock_ops_enable_tx_tstamp" $raw_ctx 0'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sock-ops-enable-tx-tstamp-rejects-socket-arg"
        category: "kfunc"
        tags: [sock-ops kfunc timestamp source reject]
        requires: [cgroup-v2 kernel-btf]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_sock_ops_enable_tx_tstamp" $ctx.sk 0'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_sock_ops_enable_tx_tstamp' arg0 expects bpf_sock_ops pointer"
    }
    {
        name: "sock-ops-enable-tx-tstamp-rejects-non-sock-ops"
        category: "kfunc"
        tags: [sock-ops kfunc timestamp source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_sock_ops_enable_tx_tstamp" $ctx 0'
            '  2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_sock_ops_enable_tx_tstamp' is only valid in sock_ops programs"
    }
]
