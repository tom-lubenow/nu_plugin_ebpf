const VERIFIER_DIFF_FIXTURES_2369_2369 = [
    {
        name: "cpumap-map-get-rejects-redirect-map-kind"
        category: "maps"
        tags: [maps cpumap map-get diagnostics reject redirect-map]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entry = ($ctx.pid | map-get cpu_targets --kind cpumap)'
            '  if $entry { 1 } else { 0 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-get --kind cpumap is reserved for bpf_redirect_map"
    }
]
