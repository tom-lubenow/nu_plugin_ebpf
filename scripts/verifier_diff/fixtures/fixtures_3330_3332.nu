export const VERIFIER_DIFF_FIXTURES_3330_3332 = [
    {
        name: "global-define-type-array-bytes-collect"
        category: "globals"
        tags: [globals arrays binary bytes collect global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:2:2}" buffers'
            '  ((global-get buffers) | bytes collect 0x[ff] | bytes starts-with 0x[01 02 ff 03])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-array-bytes-field-collect"
        category: "globals"
        tags: [globals records arrays binary bytes collect global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: 7 buffers: [0x[6e 75] 0x[2d 65]] } | global-define --type "record{pid:int,buffers:array{bytes:2:2}}" seen_state'
            '  let state = (global-get seen_state)'
            '  $state.buffers | bytes collect | bytes starts-with 0x[6e 75 2d]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-reverse-collect"
        category: "globals"
        tags: [globals arrays binary reverse bytes collect global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:2:2}" buffers'
            '  ((global-get buffers) | reverse | bytes collect | bytes starts-with 0x[03 04 01])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
