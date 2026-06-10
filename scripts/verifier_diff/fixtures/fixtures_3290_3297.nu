export const VERIFIER_DIFF_FIXTURES_3290_3297 = [
    {
        name: "global-define-type-array-bytes-last-length"
        category: "globals"
        tags: [globals arrays binary last bytes length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | last | bytes length) == 4)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-take-last-length"
        category: "globals"
        tags: [globals arrays binary take last bytes length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | take 1 | last | bytes length) == 4)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-skip-first-length"
        category: "globals"
        tags: [globals arrays binary skip first bytes length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | skip 1 | first | bytes length) == 4)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-drop-last-length"
        category: "globals"
        tags: [globals arrays binary drop last bytes length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | drop 1 | last | bytes length) == 4)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-reverse-first-length"
        category: "globals"
        tags: [globals arrays binary reverse first bytes length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | reverse | first | bytes length) == 4)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-append-last-length"
        category: "globals"
        tags: [globals arrays binary append last bytes length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | append 0x[09] | last | bytes length) == 4)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-prepend-first-length"
        category: "globals"
        tags: [globals arrays binary prepend first bytes length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | prepend 0x[09] | first | bytes length) == 4)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-get-length"
        category: "globals"
        tags: [globals arrays binary get bytes length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | get 1 | bytes length) == 4)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
