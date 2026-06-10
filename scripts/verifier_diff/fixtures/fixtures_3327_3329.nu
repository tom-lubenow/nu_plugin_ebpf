export const VERIFIER_DIFF_FIXTURES_3327_3329 = [
    {
        name: "global-define-type-bytes-replace"
        category: "globals"
        tags: [globals binary bytes replace global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[01 aa 01 bb] | global-define --type bytes:4 scratch'
            '  ((global-get scratch) | bytes replace --all 0x[01] 0x[ff] | bytes starts-with 0x[ff aa ff])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-bytes-field-replace"
        category: "globals"
        tags: [globals records binary bytes replace global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: 7 comm: 0x[6e 75 2d 65] } | global-define --type "record{pid:int,comm:bytes:4}" seen_state'
            '  let state = (global-get seen_state)'
            '  $state.comm | bytes replace 0x[2d] 0x[5f] | bytes starts-with 0x[6e 75 5f]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-get-replace"
        category: "globals"
        tags: [globals arrays binary get bytes replace global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:2:2}" buffers'
            '  ((global-get buffers) | get 1 | bytes replace 0x[04] 0x[05] | bytes starts-with 0x[03 05])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
