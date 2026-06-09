const VERIFIER_DIFF_FIXTURES_3013_3018 = [
    {
        name: "map-get-rejects-init-for-generic-map"
        category: "maps"
        tags: [maps map-get diagnostics reject init]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  map-get seen --kind hash --init 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-get --init is only supported for local-storage map kinds"
    }
    {
        name: "map-get-rejects-flags-for-generic-map"
        category: "maps"
        tags: [maps map-get diagnostics reject flags]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  map-get seen --kind hash --flags 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-get --flags is only supported for local-storage map kinds"
    }
    {
        name: "map-get-rejects-missing-key"
        category: "maps"
        tags: [maps map-get diagnostics reject key]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  map-get seen --kind hash'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-get requires a key from pipeline input or a second positional argument"
    }
    {
        name: "map-push-rejects-runtime-flags"
        category: "maps"
        tags: [maps map-push diagnostics reject flags runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | map-push q --kind queue --flags $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-push --flags must be a compile-time integer literal"
    }
    {
        name: "map-push-rejects-negative-flags"
        category: "maps"
        tags: [maps map-push diagnostics reject flags]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | map-push q --kind queue --flags (-1)'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-push --flags must be >= 0"
    }
    {
        name: "map-delete-rejects-missing-key"
        category: "maps"
        tags: [maps map-delete diagnostics reject key]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  map-delete seen --kind hash'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete requires a key from pipeline input or a second positional argument"
    }
]
