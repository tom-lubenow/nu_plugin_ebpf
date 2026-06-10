export const VERIFIER_DIFF_FIXTURES_3321_3323 = [
    {
        name: "global-define-type-bytes-reverse"
        category: "globals"
        tags: [globals binary bytes reverse global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[01 02 03 04] | global-define --type bytes:4 scratch'
            '  ((global-get scratch) | bytes reverse | bytes starts-with 0x[04 03])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-bytes-field-reverse"
        category: "globals"
        tags: [globals records binary bytes reverse global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: 7 comm: 0x[6e 75 2d 65] } | global-define --type "record{pid:int,comm:bytes:4}" seen_state'
            '  let state = (global-get seen_state)'
            '  $state.comm | bytes reverse | bytes starts-with 0x[65 2d]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-get-reverse"
        category: "globals"
        tags: [globals arrays binary get bytes reverse global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  ((global-get buffers) | get 1 | bytes reverse | bytes starts-with 0x[04 03])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
