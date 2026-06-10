export const VERIFIER_DIFF_FIXTURES_3324_3326 = [
    {
        name: "global-define-type-bytes-add"
        category: "globals"
        tags: [globals binary bytes add global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[01 04] | global-define --type bytes:2 scratch'
            '  ((global-get scratch) | bytes add 0x[02 03] --index 1 | bytes starts-with 0x[01 02 03])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-bytes-field-add"
        category: "globals"
        tags: [globals records binary bytes add global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: 7 comm: 0x[6e 75 65] } | global-define --type "record{pid:int,comm:bytes:3}" seen_state'
            '  let state = (global-get seen_state)'
            '  $state.comm | bytes add 0x[2d] --index 1 --end | bytes starts-with 0x[6e 75 2d]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-get-add"
        category: "globals"
        tags: [globals arrays binary get bytes add global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:2:2}" buffers'
            '  ((global-get buffers) | get 1 | bytes add 0x[05] | bytes starts-with 0x[05 03])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
