const VERIFIER_DIFF_FIXTURES_2396_2396 = [
    {
        name: "cgroup-array-map-put-rejects-membership-map-kind"
        category: "maps"
        tags: [maps cgroup-array map-put diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put tracked_cgroups $ctx.pid --kind cgroup-array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-put --kind cgroup-array is reserved for cgroup membership helper-calls"
    }
]
