const VERIFIER_DIFF_FIXTURES_2345_2345 = [
    {
        name: "map-define-kptr-nested-record-rejects-top-level"
        category: "maps"
        tags: [maps map-define kptr records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --value-type "record{nested:record{task:kptr:task_struct},cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kptr slots must be top-level map-value record fields"
    }
]
