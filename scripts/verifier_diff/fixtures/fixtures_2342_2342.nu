const VERIFIER_DIFF_FIXTURES_2342_2342 = [
    {
        name: "map-define-key-type-rejects-keyless-queue"
        category: "maps"
        tags: [maps map-define keyless diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define queued --kind queue --key-type u32 --value-type u64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "--key-type is not supported for keyless"
    }
]
