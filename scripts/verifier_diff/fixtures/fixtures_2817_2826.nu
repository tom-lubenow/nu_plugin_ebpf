const VERIFIER_DIFF_FIXTURES_2817_2826 = [
    {
        name: "core-match-or-rejects-list-alternative"
        category: "language-core"
        tags: [match diagnostics reject or-pattern list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  match $ctx.pid { [a b] | 1 => 10, _ => 20 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Match or-pattern alternative List"
    }
    {
        name: "core-match-or-rejects-record-alternative"
        category: "language-core"
        tags: [match diagnostics reject or-pattern record]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  match $ctx.pid { {pid: x} | 1 => 10, _ => 20 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Match or-pattern alternative Record"
    }
    {
        name: "core-match-range-rejects-too-large-step"
        category: "language-core"
        tags: [match range diagnostics reject step]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  match $ctx.pid { 0..-9223372036854775808..1 => 1, _ => 0 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Match range pattern step is too large for eBPF"
    }
    {
        name: "core-match-rejects-datetime-pattern"
        category: "language-core"
        tags: [match diagnostics reject datetime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  match $ctx.pid { 2024-01-01 => 1, _ => 0 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Match against expression pattern DateTime"
    }
    {
        name: "xdp-packet-scalar-view-rejects-field-member"
        category: "packet"
        tags: [xdp packet diagnostics reject scalar-view]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.data.u16be.foo | count'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "typed field path 'data.u16be.foo' expects a numeric index after packet scalar view"
    }
    {
        name: "xdp-packet-scalar-view-rejects-nested-index"
        category: "packet"
        tags: [xdp packet diagnostics reject scalar-view]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.data.u16be.0.foo | count'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "typed field path 'data.u16be.0.foo' does not support nested projection after a packet scalar index"
    }
    {
        name: "xdp-packet-scalar-view-rejects-index-overflow"
        category: "packet"
        tags: [xdp packet diagnostics reject scalar-view overflow]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.data.u16be.-1 | count'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "typed field path 'data.u16be.18446744073709551615' packet scalar index overflowed"
    }
    {
        name: "xdp-packet-header-rejects-struct-index"
        category: "packet"
        tags: [xdp packet diagnostics reject header struct]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.data.eth.0 | count'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "typed field path 'data.eth.0' cannot index 0 on a struct"
    }
    {
        name: "xdp-packet-header-rejects-array-field"
        category: "packet"
        tags: [xdp packet diagnostics reject header array]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.data.eth.dst.foo | count'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "typed field path 'data.eth.dst.foo' cannot access field 'foo' on an array; use a numeric index"
    }
    {
        name: "xdp-packet-header-rejects-array-index-out-of-bounds"
        category: "packet"
        tags: [xdp packet diagnostics reject header array bounds]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.data.eth.dst.6 | count'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "typed field path 'data.eth.dst.6' index 6 is out of bounds (len 6)"
    }
]
