const VERIFIER_DIFF_FIXTURES_2432_2432 = [
    {
        name: "map-put-rejects-declared-value-semantics-conflict"
        category: "maps"
        tags: [maps map-define map-put schema semantics diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  ["aa" "bb"] | map-put names 0 --kind array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-put value semantics for 'names' conflicts with declared map schema"
    }
]
