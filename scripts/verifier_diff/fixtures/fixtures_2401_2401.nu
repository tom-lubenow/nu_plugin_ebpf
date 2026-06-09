const VERIFIER_DIFF_FIXTURES_2401_2401 = [
    {
        name: "cgroup-array-map-define-rejects-membership-map-kind"
        category: "maps"
        tags: [maps cgroup-array map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define tracked_cgroups --kind cgroup-array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --kind cgroup-array is reserved for cgroup membership helper-calls"
    }
]
