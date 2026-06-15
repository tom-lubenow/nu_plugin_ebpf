const VERIFIER_DIFF_FIXTURES_0251_0281_B_B = [
    {
        name: "global-define-type-bound-record-empty-binary-field-zero-fills"
        category: "globals"
        tags: [globals records binary bytes global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let state = { pid: 7 comm: 0x[] }'
            '  $state | global-define --type "record{pid:int,comm:bytes:4}" seen_state'
            '  let state = (global-get seen_state)'
            '  ($state.comm | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-string-concat-initializer"
        category: "globals"
        tags: [globals string global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let greeting = ("hel" + "lo")'
            '  $greeting | global-define --type string:8 greeting'
            '  let stored = (global-get greeting)'
            '  ($stored | str length) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-runtime-string-concat"
        category: "globals"
        tags: [globals string global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  let greeting = ($left + "lo")'
            '  $greeting | str length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-runtime-string-equality"
        category: "globals"
        tags: [globals string global-define equality accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "lo" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left == "lo"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-builder-initializer"
        category: "globals"
        tags: [globals records global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let state = ({} | insert pid 7)'
            '  $state | global-define --type "record{pid:int}" state'
            '  let stored = (global-get state)'
            '  $stored.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
