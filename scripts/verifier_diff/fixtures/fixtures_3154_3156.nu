const VERIFIER_DIFF_FIXTURES_3154_3156 = [
    {
        name: "core-string-starts-with-accepts-runtime-input-literal-prefix"
        category: "language-core"
        tags: [string str starts-with accept runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str starts-with "a"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-ends-with-accepts-runtime-input-literal-suffix"
        category: "language-core"
        tags: [string str ends-with accept runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str ends-with "a"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-contains-accepts-runtime-input-literal-substring"
        category: "language-core"
        tags: [string str contains accept runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str contains "a"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
