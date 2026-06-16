const VERIFIER_DIFF_FIXTURES_0251_0281_A_C = [
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
