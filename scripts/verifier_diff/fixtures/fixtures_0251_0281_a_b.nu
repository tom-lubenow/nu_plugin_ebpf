const VERIFIER_DIFF_FIXTURES_0251_0281_A_B = [
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
]
