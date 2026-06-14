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
    {
        name: "global-define-type-array-bytes-describe"
        category: "globals"
        tags: [globals arrays binary describe global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  (global-get buffers) | describe | str starts-with "list<binary>"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-bytes-length"
        category: "globals"
        tags: [globals arrays binary bytes length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  let lens = ((global-get buffers) | bytes length)'
            '  ($lens | get 1) == 4'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-first-length"
        category: "globals"
        tags: [globals arrays binary bytes first length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  ((global-get buffers) | first | bytes length) == 4'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-last"
        category: "globals"
        tags: [globals arrays first last global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  ((global-get ports) | last) == 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-take-length"
        category: "globals"
        tags: [globals arrays binary bytes take length get global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | take 1 | bytes length) | get 0) == 4'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-skip-length"
        category: "globals"
        tags: [globals arrays skip length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  ((global-get ports) | skip 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-drop-length"
        category: "globals"
        tags: [globals arrays drop length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  ((global-get ports) | drop 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
