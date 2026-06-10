export const VERIFIER_DIFF_FIXTURES_3364_3365 = [
    {
        name: "global-define-type-array-bytes-bytes-reverse-collect"
        category: "globals"
        tags: [globals arrays binary bytes reverse collect global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  ((global-get buffers) | bytes reverse | bytes collect | bytes starts-with 0x[00 00])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-bytes-reverse-get"
        category: "globals"
        tags: [globals arrays binary bytes reverse get global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  ((global-get buffers) | bytes reverse | get 1 | bytes starts-with 0x[00])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
