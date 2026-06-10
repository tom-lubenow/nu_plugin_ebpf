export const VERIFIER_DIFF_FIXTURES_3366_3367 = [
    {
        name: "global-define-type-array-bytes-at-collect"
        category: "globals"
        tags: [globals arrays binary bytes at collect global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  ((global-get buffers) | bytes at 1..2 | bytes collect | bytes starts-with 0x[00 00])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-at-get"
        category: "globals"
        tags: [globals arrays binary bytes at get global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  ((global-get buffers) | bytes at 1..2 | get 1 | bytes starts-with 0x[00 00])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
