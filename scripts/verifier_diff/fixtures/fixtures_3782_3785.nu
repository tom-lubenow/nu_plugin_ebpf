export const VERIFIER_DIFF_FIXTURES_3782_3785 = [
    {
        name: "core-string-starts-with-accepts-context-comm-input"
        category: "language-core"
        tags: [string str starts-with accept runtime context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | str starts-with "n"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-ends-with-accepts-context-comm-input"
        category: "language-core"
        tags: [string str ends-with accept runtime context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | str ends-with "d"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-contains-accepts-context-comm-input"
        category: "language-core"
        tags: [string str contains accept runtime context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | str contains "u"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-str-trim-char-accepts-context-comm-input"
        category: "language-core"
        tags: [string str trim char length accept runtime context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (($ctx.comm | str trim --char "x" | str length) >= 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
