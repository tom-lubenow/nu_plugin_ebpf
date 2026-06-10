export const VERIFIER_DIFF_FIXTURES_3186_3186 = [
    {
        name: "global-define-type-bytes-is-not-empty"
        category: "globals"
        tags: [globals binary is-not-empty global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[] | global-define --type bytes:8 scratch'
            '  let b = (global-get scratch)'
            '  $b | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
