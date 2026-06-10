export const VERIFIER_DIFF_FIXTURES_3370_3371 = [
    {
        name: "global-define-type-array-bytes-replace-collect"
        category: "globals"
        tags: [globals arrays binary bytes replace collect global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  ((global-get buffers) | bytes replace --all 0x[00] 0x[ff] | bytes collect | bytes starts-with 0x[ff ff ff ff ff])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-replace-get"
        category: "globals"
        tags: [globals arrays binary bytes replace get global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  ((global-get buffers) | bytes replace --all 0x[00] 0x[ff] | get 1 | bytes starts-with 0x[ff ff])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
