const VERIFIER_DIFF_FIXTURES_0251_0281_B = [
    {
        name: "global-define-type-array-u32-first-count-length"
        category: "globals"
        tags: [globals arrays first length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  ((global-get ports) | first 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-is-empty"
        category: "globals"
        tags: [globals arrays is-empty global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  ((global-get ports) | is-empty) == false'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-is-not-empty"
        category: "globals"
        tags: [globals arrays is-not-empty global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (global-get ports) | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-last-count-get"
        category: "globals"
        tags: [globals arrays get first last global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | last 1) | get 0) == 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
    {
        name: "global-define-type-bool-not-initializer"
        category: "globals"
        tags: [globals scalar bool global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let enabled = (not false)'
            '  $enabled | global-define --type bool enabled'
            '  let stored = (global-get enabled)'
            '  if $stored { 1 } else { 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-int-add-initializer"
        category: "globals"
        tags: [globals scalar global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let sum = (3 + 4)'
            '  $sum | global-define --type int sum'
            '  let stored = (global-get sum)'
            '  $stored | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-int-record-field-initializer"
        category: "globals"
        tags: [globals records scalar global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let state = { pid: 7 }'
            '  $state.pid | global-define --type int seen_pid'
            '  let stored = (global-get seen_pid)'
            '  $stored | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-int-bool-initializer-rejects"
        category: "globals"
        tags: [globals scalar bool global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  true | global-define --type int state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'int' initializer requires a i64-compatible constant"
    }
    {
        name: "global-define-type-list-int-initializer"
        category: "globals"
        tags: [globals list global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [11 22] | global-define --type "list:int:4" samples'
            '  let samples = (global-get samples)'
            '  ($samples | get 1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-list-int-bool-item-rejects"
        category: "globals"
        tags: [globals list bool global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [true] | global-define --type "list:int:4" samples'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'list:int:4' initializer[0] requires a numeric constant item, found bool"
    }
    {
        name: "global-define-type-bound-list-int-initializer"
        category: "globals"
        tags: [globals list global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let initial = [11 22]'
            '  $initial | global-define --type "list:int:4" samples'
            '  let samples = (global-get samples)'
            '  ($samples | get 1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
