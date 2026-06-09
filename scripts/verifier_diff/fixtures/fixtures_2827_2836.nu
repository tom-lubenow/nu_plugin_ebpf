const VERIFIER_DIFF_FIXTURES_2827_2836 = [
    {
        name: "xdp-packet-update-rejects-header-view-target"
        category: "packet"
        tags: [xdp packet diagnostics reject update header]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.data.eth = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "context cell path update '.data.eth = ...' requires a scalar packet field, not a header view"
    }
    {
        name: "xdp-packet-update-rejects-payload-pointer-target"
        category: "packet"
        tags: [xdp packet diagnostics reject update payload]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.data.eth.payload = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "context cell path update '.data.eth.payload = ...' requires a scalar packet field, not a payload pointer"
    }
    {
        name: "xdp-packet-update-rejects-scalar-view-field-member"
        category: "packet"
        tags: [xdp packet diagnostics reject update scalar-view]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.data.u16be.foo = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "context cell path update '.data.u16be.foo = ...' expects a numeric index after a packet scalar view"
    }
    {
        name: "xdp-packet-update-rejects-scalar-view-nested-index"
        category: "packet"
        tags: [xdp packet diagnostics reject update scalar-view]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.data.u16be.0.foo = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "context cell path update '.data.u16be.0.foo = ...' does not support nested projection after a packet scalar index"
    }
    {
        name: "xdp-packet-update-rejects-scalar-view-index-overflow"
        category: "packet"
        tags: [xdp packet diagnostics reject update scalar-view overflow]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.data.u16be.-1 = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "context cell path update '.data.u16be.18446744073709551615 = ...' packet scalar index overflowed"
    }
    {
        name: "xdp-packet-update-rejects-array-target"
        category: "packet"
        tags: [xdp packet diagnostics reject update array]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.data.eth.dst = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "context cell path update '.data.eth.dst = ...' requires a scalar packet field, not Array"
    }
    {
        name: "xdp-packet-update-rejects-non-integer-value"
        category: "packet"
        tags: [xdp packet diagnostics reject update value]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.data.0 = "x"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "context cell path update '.data.0 = ...' requires an integer-compatible scalar value"
    }
    {
        name: "xdp-packet-update-rejects-bitfield-traversal"
        category: "packet"
        tags: [xdp packet diagnostics reject update bitfield]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.data.eth.ipv4.version.foo = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "context cell path update '.data.eth.ipv4.version.foo = ...' cannot traverse through a packet bitfield"
    }
    {
        name: "xdp-packet-update-rejects-unknown-header-field"
        category: "packet"
        tags: [xdp packet diagnostics reject update header field]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.data.eth.nope = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "typed field path 'data.eth.nope' has no field 'nope'"
    }
    {
        name: "xdp-packet-update-rejects-array-index-out-of-bounds"
        category: "packet"
        tags: [xdp packet diagnostics reject update array bounds]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.data.eth.dst.6 = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "typed field path 'data.eth.dst.6' index 6 is out of bounds (len 6)"
    }
]
