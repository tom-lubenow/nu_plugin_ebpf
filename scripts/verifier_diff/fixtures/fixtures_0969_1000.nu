const VERIFIER_DIFF_FIXTURES_0969_1000 = [
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
    {
        name: "sock-ops-hdr-opt-helpers"
        category: "helper-state"
        tags: [sock-ops helper-call hdr-opt source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let opt = "0123456789abcdef"'
            '  if ($ctx.op == 4) {'
            '    helper-call "bpf_load_hdr_opt" $ctx $opt 16 0'
            '  }'
            '  if ($ctx.op == 15) {'
            '    helper-call "bpf_store_hdr_opt" $ctx $opt 16 0'
            '  }'
            '  if ($ctx.op == 14) {'
            '    helper-call "bpf_reserve_hdr_opt" $ctx 16 0'
            '  }'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-load-hdr-opt-rejects-dynamic-flags"
        category: "helper-state"
        tags: [sock-ops helper-call hdr-opt flags reject source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let opt = "0123456789abcdef"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_load_hdr_opt" $ctx $opt 16 $flags'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_load_hdr_opt' requires arg3 flags"
    }
    {
        name: "sock-ops-store-hdr-opt-rejects-dynamic-flags"
        category: "helper-state"
        tags: [sock-ops helper-call hdr-opt flags reject source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  if ($ctx.op == 15) {'
            '    let opt = "0123456789abcdef"'
            '    let flags = (helper-call "bpf_get_prandom_u32")'
            '    helper-call "bpf_store_hdr_opt" $ctx $opt 16 $flags'
            '  }'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_store_hdr_opt' requires arg3 = 0"
    }
    {
        name: "sock-ops-reserve-hdr-opt-rejects-dynamic-flags"
        category: "helper-state"
        tags: [sock-ops helper-call hdr-opt flags reject source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_reserve_hdr_opt" $ctx 16 $flags'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_reserve_hdr_opt' requires arg2 = 0"
    }
    {
        name: "sock-ops-sock-map-update-helper"
        category: "helper-state"
        tags: [sock-ops helper-call sockmap accept source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  helper-call "bpf_sock_map_update" $ctx peers $key 0'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-sock-hash-update-helper"
        category: "helper-state"
        tags: [sock-ops helper-call sockhash accept source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  helper-call "bpf_sock_hash_update" $ctx hash_peers $key 0'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-sock-map-update-rejects-invalid-flags"
        category: "helper-state"
        tags: [sock-ops helper-call sockmap flags reject source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  helper-call "bpf_sock_map_update" $ctx peers $key 4'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "socket map update helpers require arg3 flags"
    }
    {
        name: "sock-ops-sock-map-update-rejects-dynamic-flags"
        category: "helper-state"
        tags: [sock-ops helper-call sockmap flags reject source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_sock_map_update" $ctx peers $key $flags'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "socket map update helpers require arg3 flags"
    }
    {
        name: "sock-ops-sock-hash-update-rejects-dynamic-flags"
        category: "helper-state"
        tags: [sock-ops helper-call sockhash flags reject source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_sock_hash_update" $ctx hash_peers $key $flags'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "socket map update helpers require arg3 flags"
    }
    {
        name: "sock-ops-sock-map-update-rejects-non-sock-ops"
        category: "helper-state"
        tags: [sock-ops helper-call sockmap program-policy reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  helper-call "bpf_sock_map_update" $ctx peers $key 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sock_map_update' is only valid in sock_ops programs"
    }
    {
        name: "sock-ops-store-hdr-opt-rejects-stale-data"
        category: "helper-state"
        tags: [sock-ops helper-call hdr-opt packet-bounds reject]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  if ($ctx.op == 15) {'
            '    let data = $ctx.data'
            '    let opt = "0123456789abcdef"'
            '    helper-call "bpf_store_hdr_opt" $ctx $opt 16 0'
            '    ($data | get 0) | count'
            '  }'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
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
    {
        name: "sk-reuseport-select-context"
        category: "context-surface"
        tags: [sk-reuseport context]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  ($ctx.hash + $ctx.socket_cookie + $ctx.sk.family) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-select-packet-context"
        category: "context-surface"
        tags: [sk-reuseport context packet]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  (($ctx.data | get 0) + $ctx.packet_len + $ctx.sk.bound_dev_if) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-select-rich-context"
        category: "context-surface"
        tags: [sk-reuseport context packet socket source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  (($ctx.data | get 0) + $ctx.packet_len + $ctx.eth_protocol + $ctx.protocol + $ctx.hash + $ctx.bind_inany + $ctx.socket_cookie) | count'
            '  ($ctx.sk.family + $ctx.sk.type + $ctx.sk.protocol + $ctx.sk.mark + $ctx.sk.priority + $ctx.sk.rx_queue_mapping) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-socket-root-alias-context"
        category: "context-surface"
        tags: [sk-reuseport context socket alias source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  ($ctx.sock.family + $ctx.socket.priority) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-record-socket-context"
        category: "context-surface"
        tags: [sk-reuseport context socket record source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  let rec = { sock: $ctx.sk }'
            '  ($rec.sock.family + $ctx.hash) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-record-spread-socket-context"
        category: "context-surface"
        tags: [sk-reuseport context socket record spread source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  let base = { sock: $ctx.sock }'
            '  let rec = { ok: true, ...$base }'
            '  ($rec.sock.priority + $ctx.protocol) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-user-function-record-socket-context"
        category: "context-surface"
        tags: [sk-reuseport context socket user-function record source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  def wrap [sock] { { sock: $sock } }'
            '  let rec = (wrap $ctx.sk)'
            '  ($rec.sock.rx_queue_mapping + $ctx.bind_inany) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-migrate-context"
        category: "context-surface"
        tags: [sk-reuseport context]
        target: "sk_reuseport:migrate"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.protocol + $ctx.hash + $ctx.bind_inany + $ctx.socket_cookie + $ctx.sk.bound_dev_if + $ctx.migrating_sk.bound_dev_if) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-migrating-socket-alias-context"
        category: "context-surface"
        tags: [sk-reuseport context socket alias source metadata]
        target: "sk_reuseport:migrate"
        program: [
            '{|ctx|'
            '  let migrating = $ctx.migrating_socket'
            '  if $migrating {'
            '    $migrating.remote_port | count'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-record-migrating-socket-context"
        category: "context-surface"
        tags: [sk-reuseport context socket record source metadata]
        target: "sk_reuseport:migrate"
        program: [
            '{|ctx|'
            '  let rec = { migrating: $ctx.migrating_socket }'
            '  if $rec.migrating {'
            '    $rec.migrating.remote_port | count'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-select-migrating-sk-nullable-context"
        category: "context-surface"
        tags: [sk-reuseport context socket source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  if $ctx.migrating_sk {'
            '    $ctx.migrating_sk.family | count'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
