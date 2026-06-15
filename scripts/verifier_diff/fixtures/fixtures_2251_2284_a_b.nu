const VERIFIER_DIFF_FIXTURES_2251_2284_A_B = [
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
]
