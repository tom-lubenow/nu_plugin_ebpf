const VERIFIER_DIFF_FIXTURES_3056_3059 = [
    {
        name: "map-define-rejects-pipeline-input"
        category: "maps"
        tags: [maps map-define diagnostics reject pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | map-define seen --kind hash --key-type u32 --value-type u64'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define does not accept pipeline input"
    }
    {
        name: "map-in-map-map-define-rejects-value-type"
        category: "maps"
        tags: [maps map-in-map array-of-maps map-define diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  map-define outer --kind array-of-maps --value-type u64 --inner-map inner --max-entries 4'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --value-type is not supported for map-in-map outer map 'outer'"
    }
    {
        name: "hash-of-maps-map-define-rejects-missing-key-type"
        category: "maps"
        tags: [maps map-in-map hash-of-maps map-define diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  map-define outer --kind hash-of-maps --inner-map inner --max-entries 4'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --kind hash-of-maps requires --key-type for the outer map"
    }
    {
        name: "array-of-maps-map-define-rejects-missing-inner-map"
        category: "maps"
        tags: [maps map-in-map array-of-maps map-define diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  map-define outer --kind array-of-maps --max-entries 4'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --kind array-of-maps requires --inner-map naming a previously declared inner map template"
    }
]
