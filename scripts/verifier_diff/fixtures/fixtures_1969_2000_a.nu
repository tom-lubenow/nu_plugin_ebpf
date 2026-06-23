const VERIFIER_DIFF_FIXTURES_1969_2000_A = [
    {
        name: "core-int-fill-right"
        category: "language-core"
        tags: [int fill right]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  42 | fill --alignment right --character "0" --width 5 | str starts-with "00042"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-unsigned-int-fill"
        category: "language-core"
        tags: [int runtime fill context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | fill | str starts-with "0"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-tracked-string-fill"
        category: "language-core"
        tags: [string runtime fill tracked]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  random int 0..9 | fill | fill --alignment right --character "0" --width 2 | str starts-with "0"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-float-fill-right"
        category: "language-core"
        tags: [float fill right]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1.25 | fill --alignment right --character "0" --width 6 | str starts-with "001.25"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-filesize-fill-right"
        category: "language-core"
        tags: [filesize fill right]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1kb | fill --alignment right --character "_" --width 8 | str starts-with "____1000"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
