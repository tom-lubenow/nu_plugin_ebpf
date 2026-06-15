const VERIFIER_DIFF_FIXTURES_2251_2284_B_C = [
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
]
