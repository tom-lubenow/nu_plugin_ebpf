export const VERIFIER_DIFF_FIXTURES_3372_3373 = [
    {
        name: "global-define-type-array-bytes-remove-collect"
        category: "globals"
        tags: [globals arrays binary bytes remove collect global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  ((global-get buffers) | bytes remove --all --end 0x[00 00 00 00 00] | bytes collect | bytes starts-with 0x[00 00 00 00 00])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-remove-get"
        category: "globals"
        tags: [globals arrays binary bytes remove get global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  ((global-get buffers) | bytes remove --all --end 0x[00 00 00 00 00] | get 1 | bytes starts-with 0x[00 00 00 00])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
