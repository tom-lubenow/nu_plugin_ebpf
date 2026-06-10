export const VERIFIER_DIFF_FIXTURES_3333_3335 = [
    {
        name: "global-define-type-bytes-remove-impossible-match"
        category: "globals"
        tags: [globals binary bytes remove global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[01 02] | global-define --type bytes:2 scratch'
            '  ((global-get scratch) | bytes remove --all --end 0x[01 02 03] | bytes starts-with 0x[01 02])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-bytes-field-remove-impossible-match"
        category: "globals"
        tags: [globals records binary bytes remove global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: 7 comm: 0x[6e 75] } | global-define --type "record{pid:int,comm:bytes:2}" seen_state'
            '  let state = (global-get seen_state)'
            '  $state.comm | bytes remove 0x[6e 75 21] | bytes starts-with 0x[6e 75]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-bytes-remove-rejects-matchable-pattern"
        category: "globals"
        tags: [globals binary bytes remove global-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[01 02] | global-define --type bytes:2 scratch'
            '  (global-get scratch) | bytes remove 0x[01]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes remove on typed fixed-size binary input requires a pattern longer than the input length"
    }
]
