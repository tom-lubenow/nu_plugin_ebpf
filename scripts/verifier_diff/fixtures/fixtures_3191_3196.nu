export const VERIFIER_DIFF_FIXTURES_3191_3196 = [
    {
        name: "global-define-type-record-no-init-bytes-field-bytes-length"
        category: "globals"
        tags: [globals records binary bytes length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,comm:bytes:4,label:string:8}" seen_state'
            '  let state = (global-get seen_state)'
            '  ($state.comm | bytes length) == 4'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-no-init-bytes-field-length"
        category: "globals"
        tags: [globals records binary length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,comm:bytes:4,label:string:8}" seen_state'
            '  let state = (global-get seen_state)'
            '  ($state.comm | length) == 4'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-no-init-bytes-field-is-not-empty"
        category: "globals"
        tags: [globals records binary is-not-empty global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,comm:bytes:4,label:string:8}" seen_state'
            '  let state = (global-get seen_state)'
            '  $state.comm | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-no-init-string-field-str-length"
        category: "globals"
        tags: [globals records string str length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,comm:bytes:4,label:string:8}" seen_state'
            '  let state = (global-get seen_state)'
            '  ($state.label | str length) == 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-no-init-string-field-is-empty"
        category: "globals"
        tags: [globals records string is-empty global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,comm:bytes:4,label:string:8}" seen_state'
            '  let state = (global-get seen_state)'
            '  $state.label | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-no-init-string-field-length"
        category: "globals"
        tags: [globals records string length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,comm:bytes:4,label:string:8}" seen_state'
            '  let state = (global-get seen_state)'
            '  ($state.label | length) == 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
