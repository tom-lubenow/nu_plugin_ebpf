export const VERIFIER_DIFF_FIXTURES_3377_3377 = [
    {
        name: "adjust-message-sk-msg-reshape-flags-zero"
        category: "language-surface"
        tags: [adjust-message sk-msg flags accept]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --pull 0 1 --flags 0'
            '  adjust-message --push 0 1 --flags 0'
            '  adjust-message --pop 0 1 --flags 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
