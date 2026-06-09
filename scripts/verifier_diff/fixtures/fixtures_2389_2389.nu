const VERIFIER_DIFF_FIXTURES_2389_2389 = [
    {
        name: "per-cpu-cgroup-storage-map-delete-rejects-legacy-kind"
        category: "maps"
        tags: [maps per-cpu-cgroup-storage map-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete legacy_per_cpu_storage --kind per-cpu-cgroup-storage'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete --kind per-cpu-cgroup-storage names a deprecated cgroup-storage map"
    }
]
