const VERIFIER_DIFF_FIXTURES_1907_1937_A_C = [
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
