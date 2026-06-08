const VERIFIER_DIFF_FIXTURES_2373_2373 = [
    {
        name: "cgroup-array-map-delete-rejects-membership-map-kind"
        category: "maps"
        tags: [maps cgroup-array map-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete tracked_cgroups --kind cgroup-array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete --kind cgroup-array is reserved for cgroup membership helper-calls"
    }
]
