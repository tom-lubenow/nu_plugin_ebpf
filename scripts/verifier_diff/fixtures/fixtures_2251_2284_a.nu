const VERIFIER_DIFF_FIXTURES_2251_2284_A = [
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
]
