const VERIFIER_DIFF_FIXTURES_1907_1937_B = [
    {
        name: "core-binary-list-uniq-collect"
        category: "language-core"
        tags: [binary list uniq bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[01]] | uniq | bytes collect | bytes starts-with 0x[01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-find-collect"
        category: "language-core"
        tags: [binary list find bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03] 0x[02]] | find 0x[02] | bytes collect | bytes starts-with 0x[02 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-take-collect"
        category: "language-core"
        tags: [binary list take bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | take 2 | bytes collect | bytes starts-with 0x[01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-skip-collect"
        category: "language-core"
        tags: [binary list skip bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | skip 1 | bytes collect | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-drop-collect"
        category: "language-core"
        tags: [binary list drop bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | drop 1 | bytes collect | bytes starts-with 0x[01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-first-collect"
        category: "language-core"
        tags: [binary list first bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | first 2 | bytes collect | bytes starts-with 0x[01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-last-collect"
        category: "language-core"
        tags: [binary list last bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | last 2 | bytes collect | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-get-starts-with"
        category: "language-core"
        tags: [binary list get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | get 1 | bytes starts-with 0x[02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-compact-collect"
        category: "language-core"
        tags: [binary list compact bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[] 0x[02]] | compact --empty | bytes collect | bytes starts-with 0x[01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
