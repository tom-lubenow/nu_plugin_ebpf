const VERIFIER_DIFF_FIXTURES_1969_2000_B_B = [
    {
        name: "core-string-stats-get-field"
        category: "language-core"
        tags: [string str stats record get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "Amélie Amelie" | str stats | get bytes'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-stats-unicode-width-get-field"
        category: "language-core"
        tags: [string str stats record get unicode-width]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "字\r\n字" | str stats | get unicode-width'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
