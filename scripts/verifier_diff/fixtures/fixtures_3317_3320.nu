export const VERIFIER_DIFF_FIXTURES_3317_3320 = [
    {
        name: "global-define-type-bytes-at"
        category: "globals"
        tags: [globals binary bytes at global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type bytes:4 scratch'
            '  ((global-get scratch) | bytes at 1..2 | bytes starts-with 0x[00 00])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-bytes-field-at"
        category: "globals"
        tags: [globals records binary bytes at global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: 7 comm: 0x[6e 75 2d 65] } | global-define --type "record{pid:int,comm:bytes:4}" seen_state'
            '  let state = (global-get seen_state)'
            '  $state.comm | bytes at 1..2 | bytes starts-with 0x[75 2d]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-get-at"
        category: "globals"
        tags: [globals arrays binary get bytes at global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  ((global-get buffers) | get 1 | bytes at 0..1 | bytes starts-with 0x[03 04])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-bytes-at-empty-length"
        category: "globals"
        tags: [globals binary bytes at length empty global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type bytes:4 scratch'
            '  (((global-get scratch) | bytes at 2..1 | bytes length) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
