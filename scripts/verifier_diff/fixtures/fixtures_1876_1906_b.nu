const VERIFIER_DIFF_FIXTURES_1876_1906_B = [
    {
        name: "core-binary-list-bytes-remove-collect"
        category: "language-core"
        tags: [binary list bytes remove collect starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10 aa] 0x[10 bb]] | bytes remove 0x[10] | bytes collect | bytes starts-with 0x[aa bb]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-remove-empty-collect-length"
        category: "language-core"
        tags: [binary list bytes remove empty collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10]] | bytes remove 0x[10] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-remove-unequal-collect-length"
        category: "language-core"
        tags: [binary list bytes remove unequal collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10 20]] | bytes remove 0x[10] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-remove-unequal-get"
        category: "language-core"
        tags: [binary list bytes remove unequal get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes remove 0x[ff] | get 1 | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-remove-empty-get-length"
        category: "language-core"
        tags: [binary list bytes remove empty get length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10]] | bytes remove 0x[10] | get 0 | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-remove-unequal-last"
        category: "language-core"
        tags: [binary list bytes remove unequal last starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes remove 0x[ff] | last | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-remove-empty-first-length"
        category: "language-core"
        tags: [binary list bytes remove empty first length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10]] | bytes remove 0x[10] | first | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-remove-unequal-describe"
        category: "language-core"
        tags: [binary list bytes remove unequal describe]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes remove 0x[ff] | describe | str starts-with "list<binary>"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-collect"
        category: "language-core"
        tags: [binary list bytes replace collect starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10 aa] 0x[10 bb]] | bytes replace 0x[10] 0x[a0] | bytes collect | bytes starts-with 0x[a0 aa a0 bb]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-empty-collect-length"
        category: "language-core"
        tags: [binary list bytes replace empty collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10]] | bytes replace 0x[10] 0x[] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-unequal-collect-length"
        category: "language-core"
        tags: [binary list bytes replace unequal collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10 aa] 0x[10 bb cc]] | bytes replace 0x[10] 0x[] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-unequal-get"
        category: "language-core"
        tags: [binary list bytes replace unequal get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10 aa] 0x[10 bb cc]] | bytes replace 0x[10] 0x[] | get 1 | bytes starts-with 0x[bb cc]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-empty-get-length"
        category: "language-core"
        tags: [binary list bytes replace empty get length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10]] | bytes replace 0x[10] 0x[] | get 0 | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-unequal-last"
        category: "language-core"
        tags: [binary list bytes replace unequal last starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10 aa] 0x[10 bb cc]] | bytes replace 0x[10] 0x[] | last | bytes starts-with 0x[bb cc]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-empty-first-length"
        category: "language-core"
        tags: [binary list bytes replace empty first length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10]] | bytes replace 0x[10] 0x[] | first | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-unequal-describe"
        category: "language-core"
        tags: [binary list bytes replace unequal describe]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10 aa] 0x[10 bb cc]] | bytes replace 0x[10] 0x[] | describe | str starts-with "list<binary>"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-remove-starts-with"
        category: "language-core"
        tags: [binary bytes remove starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[10 aa 10 bb 10] | bytes remove --all 0x[10] | bytes starts-with 0x[aa bb]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-remove-empty-length"
        category: "language-core"
        tags: [binary bytes remove empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[10] | bytes remove 0x[10] | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
