export const VERIFIER_DIFF_FIXTURES_3216_3219 = [
    {
        name: "global-define-type-array-string-append-length"
        category: "globals"
        tags: [globals arrays string append length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (((global-get names) | append "x" | length) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-append-last-str-length"
        category: "globals"
        tags: [globals arrays string append last str length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (((global-get names) | append "x" | last | str length) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-prepend-length"
        category: "globals"
        tags: [globals arrays string prepend length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (((global-get names) | prepend "x" | length) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-prepend-first-str-length"
        category: "globals"
        tags: [globals arrays string prepend first str length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (((global-get names) | prepend "x" | first | str length) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
