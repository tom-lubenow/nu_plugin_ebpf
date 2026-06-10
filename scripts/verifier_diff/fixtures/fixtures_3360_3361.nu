export const VERIFIER_DIFF_FIXTURES_3360_3361 = [
    {
        name: "global-define-type-array-bytes-starts-with-bool-list"
        category: "globals"
        tags: [globals arrays binary bytes starts-with bool-list get global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | bytes starts-with 0x[00] | get 1) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-ends-with-bool-list"
        category: "globals"
        tags: [globals arrays binary bytes ends-with bool-list get global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | bytes ends-with 0x[00] | get 0) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
