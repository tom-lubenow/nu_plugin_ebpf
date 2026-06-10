export const VERIFIER_DIFF_FIXTURES_3197_3199 = [
    {
        name: "global-define-type-array-bytes-length"
        category: "globals"
        tags: [globals arrays binary length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  ((global-get buffers) | length) == 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-is-empty"
        category: "globals"
        tags: [globals arrays binary is-empty global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  ((global-get buffers) | is-empty) == false'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-is-not-empty"
        category: "globals"
        tags: [globals arrays binary is-not-empty global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  (global-get buffers) | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
