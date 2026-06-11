export const VERIFIER_DIFF_FIXTURES_3428_3428 = [
    {
        name: "global-define-type-array-string-str-starts-with-over-capacity-rejects"
        category: "globals"
        tags: [globals arrays string str starts-with capacity diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:61}" names'
            '  (global-get names) | str starts-with "a"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stack-backed numeric list capacity 60"
    }
]
