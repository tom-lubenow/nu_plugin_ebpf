export const VERIFIER_DIFF_FIXTURES_3792_3795 = [
    {
        name: "core-is-empty-accepts-context-comm-input"
        category: "language-core"
        tags: [aggregate string is-empty input runtime context accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-is-not-empty-accepts-context-comm-input"
        category: "language-core"
        tags: [aggregate string is-not-empty input runtime context accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-str-index-of-end-accepts-context-comm-input"
        category: "language-core"
        tags: [string str index-of end accept runtime context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (($ctx.comm | str index-of --end "a") >= -1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-str-replace-all-accepts-context-comm-input"
        category: "language-core"
        tags: [string str replace all length accept runtime context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (($ctx.comm | str replace --all "a" "b" | str length) >= 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
