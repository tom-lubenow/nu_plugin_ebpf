const VERIFIER_DIFF_FIXTURES_0938_0968_B = [
    {
        name: "cgroup-sysctl-rejects-write-field-write"
        category: "context-policy"
        tags: [cgroup-sysctl reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.write = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.write is read-only"
    }
    {
        name: "cgroup-sysctl-rejects-new-value-index-write"
        category: "context-policy"
        tags: [cgroup-sysctl reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.new_value.0 = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.new_value does not support indexed assignment"
    }
    {
        name: "cgroup-sysctl-rejects-file-pos-on-packet-context"
        category: "context-policy"
        tags: [cgroup-sysctl reject context]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.file_pos | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.file_pos is only available on cgroup_sysctl programs"
    }
    {
        name: "sock-ops-basic-context-write"
        category: "context-surface"
        tags: [sock-ops context writable]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.op + ($ctx.args | get 0) + $ctx.reply + ($ctx.replylong | get 0) + $ctx.family + $ctx.remote_port + $ctx.socket_cookie + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.reply = 1'
            '  $ctx.replylong.0 = 7'
            '  $ctx.cb_flags = 1'
            '  $ctx.sk_txhash = 7'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-cb-flags-helper-backed-write"
        category: "context-surface"
        tags: [sock-ops context writable source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.cb_flags = 1'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-cb-flags-record-helper-backed-write"
        category: "context-surface"
        tags: [sock-ops context writable record source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.cb_flags = 1'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-cb-flags-user-function-returned-context-write"
        category: "context-surface"
        tags: [sock-ops context writable user-function alias source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  def get_event [event] { $event }'
            '  mut writable = (get_event $ctx)'
            '  $writable.cb_flags = 1'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-metrics-context"
        category: "context-surface"
        tags: [sock-ops context source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.is_fullsock + $ctx.snd_cwnd + $ctx.srtt_us + $ctx.state + $ctx.rtt_min + $ctx.snd_ssthresh + $ctx.rcv_nxt + $ctx.snd_nxt) | count'
            '  ($ctx.snd_una + $ctx.mss_cache + $ctx.ecn_flags + $ctx.rate_delivered + $ctx.rate_interval_us + $ctx.packets_out + $ctx.retrans_out + $ctx.total_retrans) | count'
            '  ($ctx.segs_in + $ctx.data_segs_in + $ctx.segs_out + $ctx.data_segs_out + $ctx.lost_out + $ctx.sacked_out + ($ctx.bytes_received mod 1024) + ($ctx.bytes_acked mod 1024)) | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-rejects-replylong-write-without-index"
        category: "context-policy"
        tags: [sock-ops reject context writable]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.replylong = 7'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a fixed index"
    }
    {
        name: "sock-ops-rejects-reply-write-on-packet-context"
        category: "context-policy"
        tags: [sock-ops reject context writable]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.reply = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "sock_ops programs"
    }
    {
        name: "sock-ops-rejects-cb-flags-write-on-packet-context"
        category: "context-policy"
        tags: [sock-ops reject context writable]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.cb_flags = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "sock_ops programs"
    }
    {
        name: "sock-ops-rejects-sk-txhash-write-on-packet-context"
        category: "context-policy"
        tags: [sock-ops reject context writable]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk_txhash = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "sock_ops programs"
    }
    {
        name: "sock-ops-bound-socket-projection-context"
        category: "context-surface"
        tags: [sock-ops context source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  $sk.rx_queue_mapping | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-bound-socket-parenthesized-projection-context"
        category: "context-surface"
        tags: [sock-ops context alias parenthesized source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let sk = ($ctx.sk)'
            '  $sk.rx_queue_mapping | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-socket-root-alias-context"
        category: "context-surface"
        tags: [sock-ops context socket alias source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let sock = $ctx.sock'
            '  ($sock.rx_queue_mapping + $ctx.socket.state) | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-enable-tx-tstamp-kfunc"
        category: "kfunc"
        tags: [sock-ops kfunc timestamp source metadata]
        requires: [cgroup-v2 kernel-btf]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_sock_ops_enable_tx_tstamp" $ctx 0'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
]
