const VERIFIER_DIFF_FIXTURES_2335_2335 = [
    {
        name: "map-define-value-type-fixed-array-kptr-rejects-context"
        category: "maps"
        tags: [maps map-define arrays kptr diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define bad_values --kind hash --value-type "array{kptr:task_struct:2}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map value type spec 'array{kptr:task_struct:2}' requires elements that can be embedded in fixed arrays, got 'kptr:task_struct'"
    }
]
