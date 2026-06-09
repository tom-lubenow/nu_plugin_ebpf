const VERIFIER_DIFF_FIXTURES_3039_3045 = [
    {
        name: "adjust-message-apply-rejects-missing-bytes"
        category: "language-surface"
        tags: [adjust-message sk-msg diagnostics reject arguments]
        requires: [cgroup-v2]
        target: "sk_msg:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  adjust-message --apply'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-message --apply requires bytes from pipeline input or a first positional argument"
    }
    {
        name: "adjust-message-cork-rejects-flags"
        category: "language-surface"
        tags: [adjust-message sk-msg diagnostics reject flags]
        requires: [cgroup-v2]
        target: "sk_msg:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  adjust-message --cork --flags 1 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-message --cork does not accept --flags"
    }
    {
        name: "adjust-message-cork-rejects-missing-bytes"
        category: "language-surface"
        tags: [adjust-message sk-msg diagnostics reject arguments]
        requires: [cgroup-v2]
        target: "sk_msg:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  adjust-message --cork'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-message --cork requires bytes from pipeline input or a first positional argument"
    }
    {
        name: "adjust-message-push-rejects-missing-start"
        category: "language-surface"
        tags: [adjust-message sk-msg diagnostics reject arguments]
        requires: [cgroup-v2]
        target: "sk_msg:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  adjust-message --push'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-message --push requires start from pipeline input or a first positional argument"
    }
    {
        name: "adjust-message-push-rejects-missing-len"
        category: "language-surface"
        tags: [adjust-message sk-msg diagnostics reject arguments]
        requires: [cgroup-v2]
        target: "sk_msg:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  adjust-message --push 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-message --push requires a len as the second positional argument"
    }
    {
        name: "adjust-message-pop-rejects-missing-start"
        category: "language-surface"
        tags: [adjust-message sk-msg diagnostics reject arguments]
        requires: [cgroup-v2]
        target: "sk_msg:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  adjust-message --pop'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-message --pop requires start from pipeline input or a first positional argument"
    }
    {
        name: "adjust-message-pop-rejects-missing-len"
        category: "language-surface"
        tags: [adjust-message sk-msg diagnostics reject arguments]
        requires: [cgroup-v2]
        target: "sk_msg:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  adjust-message --pop 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-message --pop requires a len as the second positional argument"
    }
]
