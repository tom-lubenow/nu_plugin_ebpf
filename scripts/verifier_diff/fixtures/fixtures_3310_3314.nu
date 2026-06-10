export const VERIFIER_DIFF_FIXTURES_3310_3314 = [
    {
        name: "global-define-type-bytes-index-of"
        category: "globals"
        tags: [globals binary bytes index-of global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[01 02 03 02] | global-define --type bytes:4 scratch'
            '  (((global-get scratch) | bytes index-of 0x[02]) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-bytes-index-of-end"
        category: "globals"
        tags: [globals binary bytes index-of end global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[01 02 03 02] | global-define --type bytes:4 scratch'
            '  (((global-get scratch) | bytes index-of --end 0x[02]) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-bytes-field-index-of"
        category: "globals"
        tags: [globals records binary bytes index-of global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: 7 comm: 0x[6e 75 2d 65] } | global-define --type "record{pid:int,comm:bytes:4}" seen_state'
            '  let state = (global-get seen_state)'
            '  ($state.comm | bytes index-of 0x[2d]) == 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-get-index-of"
        category: "globals"
        tags: [globals arrays binary get bytes index-of global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | get 1 | bytes index-of 0x[04]) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-last-index-of-end"
        category: "globals"
        tags: [globals arrays binary last bytes index-of end global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | last | bytes index-of --end 0x[04]) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
