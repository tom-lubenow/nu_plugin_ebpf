export const VERIFIER_DIFF_FIXTURES_3368_3369 = [
    {
        name: "global-define-type-array-bytes-add-collect"
        category: "globals"
        tags: [globals arrays binary bytes add collect global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  ((global-get buffers) | bytes add 0x[ff] --index 2 | bytes collect | bytes starts-with 0x[00 00 ff 00 00 00 00 ff])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-add-get"
        category: "globals"
        tags: [globals arrays binary bytes add get global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  ((global-get buffers) | bytes add 0x[ff] --index 2 | get 1 | bytes starts-with 0x[00 00 ff])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
