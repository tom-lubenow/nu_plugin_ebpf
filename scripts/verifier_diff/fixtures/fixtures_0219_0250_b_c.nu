const VERIFIER_DIFF_FIXTURES_0219_0250_B_C = [
    {
        name: "annotated-mut-list-spread-initializer"
        category: "globals"
        tags: [globals list list-spread accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut vals: list<int> = [1, ...[2, 3]]'
            '  ($vals | get 2) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-record-string-field-count"
        category: "globals"
        tags: [globals records string accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<comm: string pid: int> = { comm: "hi" pid: 7 }'
            '  $state.comm | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-record-array-inline-spread-initializer"
        category: "globals"
        tags: [globals records arrays list-spread accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut entries: list<record<pid: int cpu: int>> = [{ pid: 7 cpu: 2 }, ...[{ pid: 9 cpu: 3 }]]'
            '  $entries.1.cpu | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-record-array-bound-spread-initializer"
        category: "globals"
        tags: [globals records arrays list-spread accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let tail = [{ pid: 9 cpu: 3 }]'
            '  mut entries: list<record<pid: int cpu: int>> = [{ pid: 7 cpu: 2 }, ...$tail]'
            '  $entries.1.cpu | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-top-level-record-omission-rejected-by-nushell-parser"
        category: "globals"
        tags: [globals records parser reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<pid: int stats: record<hits: int ok: bool>> = { pid: 7 }'
            '  ($state.pid + $state.stats.hits) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expected record<pid: int, stats: record<hits: int, ok: bool>>, found record<pid: int>"
    }
]
