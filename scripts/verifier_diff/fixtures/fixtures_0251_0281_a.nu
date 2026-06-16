const VERIFIER_DIFF_FIXTURES_0251_0281_A = [
    {
        name: "constant-record-nested-list"
        category: "globals"
        tags: [globals records list accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let config = { pid: 7 samples: [11 22] }'
            '  (($config.samples | get 1) + $config.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-bytes-empty-binary-zero-fills"
        category: "globals"
        tags: [globals binary bytes global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[] | global-define --type bytes:8 scratch'
            '  let b = (global-get scratch)'
            '  ($b | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-empty-binary-field-zero-fills"
        category: "globals"
        tags: [globals records binary bytes global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: 7 comm: 0x[] } | global-define --type "record{pid:int,comm:bytes:4}" seen_state'
            '  let state = (global-get seen_state)'
            '  ($state.comm | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-bytes-length"
        category: "globals"
        tags: [globals binary bytes length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[] | global-define --type bytes:8 scratch'
            '  let b = (global-get scratch)'
            '  ($b | bytes length) == 8'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-bytes-length-command"
        category: "globals"
        tags: [globals binary length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[] | global-define --type bytes:8 scratch'
            '  let b = (global-get scratch)'
            '  ($b | length) == 8'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-bytes-is-empty"
        category: "globals"
        tags: [globals binary is-empty global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[] | global-define --type bytes:8 scratch'
            '  let b = (global-get scratch)'
            '  ($b | is-empty) == false'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-bytes-describe"
        category: "globals"
        tags: [globals binary describe global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type bytes:8 scratch'
            '  (global-get scratch) | describe | str starts-with "binary"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-bytes-field-length"
        category: "globals"
        tags: [globals records binary bytes length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: 7 comm: 0x[] } | global-define --type "record{pid:int,comm:bytes:4}" seen_state'
            '  let state = (global-get seen_state)'
            '  ($state.comm | bytes length) == 4'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
