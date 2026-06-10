export const VERIFIER_DIFF_FIXTURES_3336_3338 = [
    {
        name: "global-define-type-bytes-split-impossible-separator"
        category: "globals"
        tags: [globals binary bytes split collect global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[01 02] | global-define --type bytes:2 scratch'
            '  ((global-get scratch) | bytes split 0x[01 02 03] | bytes collect | bytes starts-with 0x[01 02])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-bytes-field-split-first"
        category: "globals"
        tags: [globals records binary bytes split first global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: 7 comm: 0x[6e 75] } | global-define --type "record{pid:int,comm:bytes:2}" seen_state'
            '  let state = (global-get seen_state)'
            '  $state.comm | bytes split "---" | first | bytes starts-with 0x[6e 75]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-bytes-split-rejects-matchable-separator"
        category: "globals"
        tags: [globals binary bytes split global-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[01 02] | global-define --type bytes:2 scratch'
            '  (global-get scratch) | bytes split 0x[01]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bytes split on typed fixed-size binary input requires a separator longer than the input length"
    }
]
