const VERIFIER_DIFF_FIXTURES_1907_1937_A = [
    {
        name: "core-binary-bytes-replace-starts-with"
        category: "language-core"
        tags: [binary bytes replace starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[10 aa 10 bb 10] | bytes replace --all 0x[10] 0x[a0] | bytes starts-with 0x[a0 aa a0]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-replace-empty-length"
        category: "language-core"
        tags: [binary bytes replace empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[10] | bytes replace 0x[10] 0x[] | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-collect-starts-with"
        category: "language-core"
        tags: [binary bytes collect starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[11] 0x[33] 0x[44]] | bytes collect 0x[01] | bytes starts-with 0x[11 01 33]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-collect-empty-length"
        category: "language-core"
        tags: [binary bytes collect empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[]] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-sort-collect"
        category: "language-core"
        tags: [binary list sort bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[03] 0x[01] 0x[02]] | sort | bytes collect | bytes starts-with 0x[01 02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-length"
        category: "language-core"
        tags: [binary list length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-is-empty"
        category: "language-core"
        tags: [binary list is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01]] | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-is-not-empty"
        category: "language-core"
        tags: [binary list is-not-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01]] | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-is-empty"
        category: "language-core"
        tags: [binary is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[] | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-is-not-empty"
        category: "language-core"
        tags: [binary is-not-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-is-empty"
        category: "language-core"
        tags: [scalar int is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0 | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-is-not-empty"
        category: "language-core"
        tags: [scalar bool duration is-not-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (false | is-not-empty) and (0sec | is-not-empty)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-append-collect"
        category: "language-core"
        tags: [binary list append bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02]] | append 0x[03] | bytes collect | bytes starts-with 0x[01 02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-prepend-collect"
        category: "language-core"
        tags: [binary list prepend bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02]] | prepend 0x[00] | bytes collect | bytes starts-with 0x[00 01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-reverse-collect"
        category: "language-core"
        tags: [binary list reverse bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | reverse | bytes collect | bytes starts-with 0x[03 02 01]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
