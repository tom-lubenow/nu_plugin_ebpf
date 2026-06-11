export const VERIFIER_DIFF_FIXTURES_3427_3427 = [
    {
        name: "global-define-type-array-string-str-length-over-capacity-rejects"
        category: "globals"
        tags: [globals arrays string str length capacity diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:61}" names'
            '  (global-get names) | str length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stack-backed numeric list capacity 60"
    }
]
