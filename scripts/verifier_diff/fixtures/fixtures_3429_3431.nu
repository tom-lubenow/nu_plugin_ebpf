export const VERIFIER_DIFF_FIXTURES_3429_3431 = [
    {
        name: "global-define-type-array-string-str-ends-with-over-capacity-rejects"
        category: "globals"
        tags: [globals arrays string str ends-with capacity diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:61}" names'
            '  (global-get names) | str ends-with "a"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stack-backed numeric list capacity 60"
    }
    {
        name: "global-define-type-array-string-str-contains-over-capacity-rejects"
        category: "globals"
        tags: [globals arrays string str contains capacity diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:61}" names'
            '  (global-get names) | str contains "a"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stack-backed numeric list capacity 60"
    }
    {
        name: "global-define-type-array-string-str-index-of-over-capacity-rejects"
        category: "globals"
        tags: [globals arrays string str index-of capacity diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:61}" names'
            '  (global-get names) | str index-of "a"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stack-backed numeric list capacity 60"
    }
]
