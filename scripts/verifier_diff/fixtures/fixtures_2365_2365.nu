const VERIFIER_DIFF_FIXTURES_2365_2365 = [
    {
        name: "deprecated-cgroup-storage-map-put-rejects-kind"
        category: "maps"
        tags: [maps deprecated-cgroup-storage map-put diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put legacy_storage $ctx.pid --kind deprecated-cgroup-storage'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "deprecated cgroup-storage map"
    }
]
