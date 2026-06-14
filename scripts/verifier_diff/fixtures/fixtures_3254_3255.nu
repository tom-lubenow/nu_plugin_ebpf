export const VERIFIER_DIFF_FIXTURES_3254_3255 = [
    {
        name: "global-define-type-array-string-compact-length"
        category: "globals"
        tags: [globals arrays string compact length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (((global-get names) | compact | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-compact-empty-length"
        category: "globals"
        tags: [globals arrays string compact empty length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (global-get names) | compact --empty | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-compact-empty-get-rejects"
        category: "globals"
        tags: [globals arrays string compact empty diagnostics reject global-define]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (global-get names) | compact --empty | get 0 | str length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "variable-length filtering for fixed-array elements is supported only for metadata-only shape consumers"
    }
]
