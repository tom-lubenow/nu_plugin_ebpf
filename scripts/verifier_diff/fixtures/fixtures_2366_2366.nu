const VERIFIER_DIFF_FIXTURES_2366_2366 = [
    {
        name: "per-cpu-cgroup-storage-map-put-rejects-kind"
        category: "maps"
        tags: [maps per-cpu-cgroup-storage map-put diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put legacy_per_cpu_storage $ctx.pid --kind per-cpu-cgroup-storage'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "deprecated cgroup-storage map"
    }
]
