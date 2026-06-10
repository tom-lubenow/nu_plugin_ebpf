export const VERIFIER_DIFF_FIXTURES_3298_3309 = [
    {
        name: "global-define-type-bytes-starts-with"
        category: "globals"
        tags: [globals binary bytes starts-with global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[01 02 03 04] | global-define --type bytes:4 scratch'
            '  (global-get scratch) | bytes starts-with 0x[01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-bytes-ends-with"
        category: "globals"
        tags: [globals binary bytes ends-with global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0x[01 02 03 04] | global-define --type bytes:4 scratch'
            '  (global-get scratch) | bytes ends-with 0x[03 04]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-bytes-field-starts-with"
        category: "globals"
        tags: [globals records binary bytes starts-with global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: 7 comm: 0x[6e 75 2d 65] } | global-define --type "record{pid:int,comm:bytes:4}" seen_state'
            '  let state = (global-get seen_state)'
            '  $state.comm | bytes starts-with 0x[6e 75]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-record-bytes-field-ends-with"
        category: "globals"
        tags: [globals records binary bytes ends-with global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: 7 comm: 0x[6e 75 2d 65] } | global-define --type "record{pid:int,comm:bytes:4}" seen_state'
            '  let state = (global-get seen_state)'
            '  $state.comm | bytes ends-with 0x[2d 65]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-last-starts-with"
        category: "globals"
        tags: [globals arrays binary last bytes starts-with global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | last | bytes starts-with 0x[03]) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-take-last-starts-with"
        category: "globals"
        tags: [globals arrays binary take last bytes starts-with global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | take 1 | last | bytes starts-with 0x[01]) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-skip-first-starts-with"
        category: "globals"
        tags: [globals arrays binary skip first bytes starts-with global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | skip 1 | first | bytes starts-with 0x[03]) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-drop-last-starts-with"
        category: "globals"
        tags: [globals arrays binary drop last bytes starts-with global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | drop 1 | last | bytes starts-with 0x[01]) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-reverse-first-starts-with"
        category: "globals"
        tags: [globals arrays binary reverse first bytes starts-with global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | reverse | first | bytes starts-with 0x[03]) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-append-last-starts-with"
        category: "globals"
        tags: [globals arrays binary append last bytes starts-with global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | append 0x[09] | last | bytes starts-with 0x[09]) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-prepend-first-starts-with"
        category: "globals"
        tags: [globals arrays binary prepend first bytes starts-with global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | prepend 0x[09] | first | bytes starts-with 0x[09]) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-get-starts-with"
        category: "globals"
        tags: [globals arrays binary get bytes starts-with global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | get 1 | bytes starts-with 0x[03]) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
