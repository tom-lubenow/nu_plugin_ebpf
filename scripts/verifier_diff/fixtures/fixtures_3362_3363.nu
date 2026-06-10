export const VERIFIER_DIFF_FIXTURES_3362_3363 = [
    {
        name: "global-define-type-array-bytes-index-of-list"
        category: "globals"
        tags: [globals arrays binary bytes index-of list get global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | bytes index-of 0x[00] | get 1) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-index-of-end-list"
        category: "globals"
        tags: [globals arrays binary bytes index-of end list get global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | bytes index-of --end 0x[00] | get 0) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
