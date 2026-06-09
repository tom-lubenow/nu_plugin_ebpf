const VERIFIER_DIFF_FIXTURES_2418_2418 = [
    {
        name: "task-storage-map-define-rejects-max-entries"
        category: "maps"
        tags: [maps local-storage task-storage map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_values --kind task-storage --value-type u64 --max-entries 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --max-entries is not supported for object-local storage map kind task-storage"
    }
]
