const VERIFIER_DIFF_FIXTURES_2412_2412 = [
    {
        name: "deprecated-cgroup-storage-map-define-rejects-legacy-kind"
        category: "maps"
        tags: [maps cgroup-storage deprecated map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define legacy_storage --kind deprecated-cgroup-storage'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --kind deprecated-cgroup-storage names a deprecated cgroup-storage map"
    }
]
