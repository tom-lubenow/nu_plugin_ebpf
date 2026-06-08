const VERIFIER_DIFF_FIXTURES_2372_2372 = [
    {
        name: "cgroup-array-map-get-rejects-membership-map-kind"
        category: "maps"
        tags: [maps cgroup-array map-get diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entry = ($ctx.pid | map-get tracked_cgroups --kind cgroup-array)'
            '  if $entry { 1 } else { 0 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-get --kind cgroup-array is reserved for cgroup membership helper-calls"
    }
]
