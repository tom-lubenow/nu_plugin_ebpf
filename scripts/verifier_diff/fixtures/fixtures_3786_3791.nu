export const VERIFIER_DIFF_FIXTURES_3786_3791 = [
    {
        name: "core-operator-string-equality-accepts-context-comm-literal"
        category: "language-core"
        tags: [operators string-equality accept runtime context literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm == "nu"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-operator-string-inequality-accepts-context-comm-literal"
        category: "language-core"
        tags: [operators string-equality not-equal accept runtime context literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm != "nu"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-operator-starts-with-accepts-context-comm-literal"
        category: "language-core"
        tags: [operators starts-with accept runtime context literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm starts-with "n"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-operator-ends-with-accepts-context-comm-literal"
        category: "language-core"
        tags: [operators ends-with accept runtime context literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm ends-with "d"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-operator-in-accepts-literal-context-comm"
        category: "language-core"
        tags: [operators in accept runtime context literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "u" in $ctx.comm'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-operator-has-accepts-context-comm-literal"
        category: "language-core"
        tags: [operators has accept runtime context literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm has "u"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
