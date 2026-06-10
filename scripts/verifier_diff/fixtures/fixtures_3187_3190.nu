export const VERIFIER_DIFF_FIXTURES_3187_3190 = [
    {
        name: "global-define-type-bytes-no-init-bytes-length"
        category: "globals"
        tags: [globals binary bytes length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type bytes:8 scratch'
            '  let b = (global-get scratch)'
            '  ($b | bytes length) == 8'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-bytes-no-init-length"
        category: "globals"
        tags: [globals binary length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type bytes:8 scratch'
            '  let b = (global-get scratch)'
            '  ($b | length) == 8'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-bytes-no-init-is-empty"
        category: "globals"
        tags: [globals binary is-empty global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type bytes:8 scratch'
            '  let b = (global-get scratch)'
            '  ($b | is-empty) == false'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-bytes-no-init-is-not-empty"
        category: "globals"
        tags: [globals binary is-not-empty global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type bytes:8 scratch'
            '  let b = (global-get scratch)'
            '  $b | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
