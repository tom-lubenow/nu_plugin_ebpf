const VERIFIER_DIFF_FIXTURES_2251_2284 = [
    {
        name: "assign-socket-tc-action-rejects-flags"
        category: "language-surface"
        tags: [assign-socket tc-action reject flags]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  assign-socket 0 --replace'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_assign' requires arg2 = 0 in tc_action programs"
    }
    {
        name: "sk-assign-tc-action-rejects-dynamic-flags"
        category: "helper-state"
        tags: [sk-assign tc-action reject flags dynamic]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_sk_assign" $ctx 0 $flags'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_assign' requires arg2 = 0 in tc_action programs"
    }
    {
        name: "adjust-message-sk-msg-apply"
        category: "language-surface"
        tags: [adjust-message sk-msg]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --apply 8'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-message-rejects-non-sk-msg"
        category: "language-surface"
        tags: [adjust-message reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  adjust-message --apply 8'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-message is not supported on raw_tracepoint programs"
    }
    {
        name: "adjust-message-sk-msg-cork"
        category: "language-surface"
        tags: [adjust-message sk-msg]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --cork 8'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-message-sk-msg-pull"
        category: "language-surface"
        tags: [adjust-message sk-msg]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --pull 0 1'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "msg-pull-data-rejects-dynamic-flags"
        category: "helper-state"
        tags: [adjust-message sk-msg flags reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_msg_pull_data" $ctx 0 1 $flags'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "message data reshaping helpers require arg3 flags to be 0"
    }
    {
        name: "adjust-message-sk-msg-pull-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-message sk-msg packet-bounds reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-message --pull 0 1'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-message-sk-msg-pull-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-message sk-msg packet-bounds accept]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --pull 0 1'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-message-sk-msg-push"
        category: "language-surface"
        tags: [adjust-message sk-msg]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --push 0 1'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "msg-push-data-rejects-dynamic-flags"
        category: "helper-state"
        tags: [adjust-message sk-msg flags reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_msg_push_data" $ctx 0 1 $flags'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "message data reshaping helpers require arg3 flags to be 0"
    }
    {
        name: "adjust-message-sk-msg-push-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-message sk-msg packet-bounds reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-message --push 0 1'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-message-sk-msg-push-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-message sk-msg packet-bounds accept]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --push 0 1'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-message-sk-msg-pop"
        category: "language-surface"
        tags: [adjust-message sk-msg]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --pop 0 1'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "msg-pop-data-rejects-dynamic-flags"
        category: "helper-state"
        tags: [adjust-message sk-msg flags reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_msg_pop_data" $ctx 0 1 $flags'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "message data reshaping helpers require arg3 flags to be 0"
    }
    {
        name: "adjust-message-sk-msg-pop-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-message sk-msg packet-bounds reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-message --pop 0 1'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-message-sk-msg-pop-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-message sk-msg packet-bounds accept]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --pop 0 1'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-msg-sockmap"
        category: "language-surface"
        tags: [redirect-socket sk-msg sockmap]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockmap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-msg-sockhash"
        category: "language-surface"
        tags: [redirect-socket sk-msg sockhash]
        target: "sk_msg:/sys/fs/bpf/demo_sockhash"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockhash'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "msg-redirect-map-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect-socket sk-msg sockmap flags reject source metadata]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_msg_redirect_map" $ctx peers 0 $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skb/message redirect helpers require flags to contain only BPF_F_INGRESS"
    }
    {
        name: "msg-redirect-hash-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect-socket sk-msg sockhash flags reject source metadata]
        target: "sk_msg:/sys/fs/bpf/demo_sockhash"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_msg_redirect_hash" $ctx hash_peers "peer-a" $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skb/message redirect helpers require flags to contain only BPF_F_INGRESS"
    }
    {
        name: "map-put-sock-ops-sockmap"
        category: "language-surface"
        tags: [maps map-put sock-ops sockmap]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx | map-put active_sockmap $ctx.remote_port --kind sockmap --flags 2'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-put-sock-ops-sockhash"
        category: "language-surface"
        tags: [maps map-put sock-ops sockhash]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx | map-put active_sockhash $ctx.remote_port --kind sockhash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-sk-skb-pull"
        category: "language-surface"
        tags: [adjust-packet sk-skb]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-packet --pull 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-sk-skb-pull-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-packet sk-skb packet-bounds reject]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-packet --pull 0'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-packet-sk-skb-pull-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-packet sk-skb packet-bounds accept]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-packet --pull 0'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-skb-sockmap"
        category: "language-surface"
        tags: [redirect-socket sk-skb sockmap]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockmap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-skb-sockhash"
        category: "language-surface"
        tags: [redirect-socket sk-skb sockhash]
        target: "sk_skb:/sys/fs/bpf/demo_sockhash"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockhash'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-redirect-map-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect-socket sk-skb sockmap flags reject source metadata]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_sk_redirect_map" $ctx peers 0 $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skb/message redirect helpers require flags to contain only BPF_F_INGRESS"
    }
    {
        name: "sk-redirect-hash-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect-socket sk-skb sockhash flags reject source metadata]
        target: "sk_skb:/sys/fs/bpf/demo_sockhash"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_sk_redirect_hash" $ctx hash_peers "peer-a" $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skb/message redirect helpers require flags to contain only BPF_F_INGRESS"
    }
    {
        name: "redirect-socket-sk-reuseport-sockarray"
        category: "language-surface"
        tags: [redirect-socket sk-reuseport reuseport-sockarray]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  redirect-socket sockets 0 --kind reuseport-sockarray'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-sk-select-reuseport-helper"
        category: "helper-state"
        tags: [helper-call sk-reuseport reuseport-sockarray accept source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  let key = "0000"'
            '  helper-call "bpf_sk_select_reuseport" $ctx sockets $key 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "adjust-packet-sk-skb-parser-pull"
        category: "language-surface"
        tags: [adjust-packet sk-skb-parser]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-packet --pull 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-skb-parser-sockhash"
        category: "language-surface"
        tags: [redirect-socket sk-skb-parser sockhash]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockhash"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockhash'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
