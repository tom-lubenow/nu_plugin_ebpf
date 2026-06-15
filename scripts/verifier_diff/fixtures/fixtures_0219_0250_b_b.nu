const VERIFIER_DIFF_FIXTURES_0219_0250_B_B = [
    {
        name: "annotated-mut-record-alignment"
        category: "globals"
        tags: [globals records alignment accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<tag: bool count: int> = { tag: true, count: 7 }'
            '  $state.count | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-record-empty-zero-init"
        category: "globals"
        tags: [globals records zero-init accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<pid: int stats: record<hits: int ok: bool>> = {}'
            '  ($state.pid + $state.stats.hits) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-scalar-null-rejected-by-nushell-parser"
        category: "globals"
        tags: [globals scalar "null" parser reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut hits: int = null'
            '  $hits | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expected int, found nothing"
    }
    {
        name: "annotated-mut-record-null-rejected-by-nushell-parser"
        category: "globals"
        tags: [globals records "null" parser reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<pid: int stats: record<hits: int ok: bool>> = null'
            '  ($state.pid + $state.stats.hits) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expected record<pid: int, stats: record<hits: int, ok: bool>>, found nothing"
    }
    {
        name: "annotated-mut-record-nested-empty-zero-fill"
        category: "globals"
        tags: [globals records zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<pid: int stats: record<hits: int ok: bool>> = { pid: 7 stats: {} }'
            '  ($state.pid + $state.stats.hits) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-record-nested-extra-field-rejects-path"
        category: "globals"
        tags: [globals records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<stats: record<hits: int>> = { stats: { hits: 7 extra: true } }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unexpected record field 'stats.extra'"
    }
]
