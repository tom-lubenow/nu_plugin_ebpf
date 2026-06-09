const VERIFIER_DIFF_FIXTURES_2413_2413 = [
    {
        name: "per-cpu-cgroup-storage-map-define-rejects-legacy-kind"
        category: "maps"
        tags: [maps cgroup-storage per-cpu deprecated map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define legacy_per_cpu_storage --kind per-cpu-cgroup-storage'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --kind per-cpu-cgroup-storage names a deprecated cgroup-storage map"
    }
]
