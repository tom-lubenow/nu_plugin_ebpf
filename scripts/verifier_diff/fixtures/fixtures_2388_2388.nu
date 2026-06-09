const VERIFIER_DIFF_FIXTURES_2388_2388 = [
    {
        name: "deprecated-cgroup-storage-map-delete-rejects-legacy-kind"
        category: "maps"
        tags: [maps deprecated-cgroup-storage map-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete legacy_storage --kind deprecated-cgroup-storage'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete --kind deprecated-cgroup-storage names a deprecated cgroup-storage map"
    }
]
