export const VERIFIER_DIFF_FIXTURES_3273_3281 = [
    {
        name: "global-define-type-array-u64-length"
        category: "globals"
        tags: [globals arrays u64 length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u64:2}" ports'
            '  (((global-get ports) | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u64-first"
        category: "globals"
        tags: [globals arrays u64 first global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [11 22] | global-define --type "array{u64:2}" ports'
            '  ((global-get ports) | first) == 11'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u64-last"
        category: "globals"
        tags: [globals arrays u64 last global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [11 22] | global-define --type "array{u64:2}" ports'
            '  ((global-get ports) | last) == 22'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u64-append-last"
        category: "globals"
        tags: [globals arrays u64 append last global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u64:2}" ports'
            '  (((global-get ports) | append 7 | last) == 7)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u64-prepend-first"
        category: "globals"
        tags: [globals arrays u64 prepend first global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u64:2}" ports'
            '  (((global-get ports) | prepend 7 | first) == 7)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u64-reverse-first"
        category: "globals"
        tags: [globals arrays u64 reverse first global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [11 22] | global-define --type "array{u64:2}" ports'
            '  (((global-get ports) | reverse | first) == 22)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u64-take-last"
        category: "globals"
        tags: [globals arrays u64 take last global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [11 22] | global-define --type "array{u64:2}" ports'
            '  (((global-get ports) | take 1 | last) == 11)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u64-skip-first"
        category: "globals"
        tags: [globals arrays u64 skip first global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [11 22] | global-define --type "array{u64:2}" ports'
            '  (((global-get ports) | skip 1 | first) == 22)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u64-sort-first"
        category: "globals"
        tags: [globals arrays u64 sort first global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [22 11] | global-define --type "array{u64:2}" ports'
            '  (((global-get ports) | sort | first) == 11)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
