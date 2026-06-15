const VERIFIER_DIFF_FIXTURES_3157_3178_B = [
    {
        name: "core-operator-in-accepts-overlong-needle-runtime-right"
        category: "language-core"
        tags: [operators in accept runtime literal capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  "abcdefghijklmnop" in $left'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-operator-has-accepts-runtime-left-empty-needle"
        category: "language-core"
        tags: [operators has accept runtime literal empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left has ""'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-operator-has-accepts-runtime-left-overlong-needle"
        category: "language-core"
        tags: [operators has accept runtime literal capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left has "abcdefghijklmnop"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-operator-not-starts-with-accepts-runtime-left-empty-prefix"
        category: "language-core"
        tags: [operators not-starts-with accept runtime literal empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left not-starts-with ""'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-operator-not-starts-with-accepts-runtime-left-overlong-prefix"
        category: "language-core"
        tags: [operators not-starts-with accept runtime literal capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left not-starts-with "abcdefghijklmnop"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-operator-not-ends-with-accepts-runtime-left-empty-suffix"
        category: "language-core"
        tags: [operators not-ends-with accept runtime literal empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left not-ends-with ""'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-operator-not-ends-with-accepts-runtime-left-overlong-suffix"
        category: "language-core"
        tags: [operators not-ends-with accept runtime literal capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left not-ends-with "abcdefghijklmnop"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-operator-not-in-accepts-empty-needle-runtime-right"
        category: "language-core"
        tags: [operators not-in accept runtime literal empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  "" not-in $left'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-operator-not-in-accepts-overlong-needle-runtime-right"
        category: "language-core"
        tags: [operators not-in accept runtime literal capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  "abcdefghijklmnop" not-in $left'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-operator-not-has-accepts-runtime-left-empty-needle"
        category: "language-core"
        tags: [operators not-has accept runtime literal empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left not-has ""'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-operator-not-has-accepts-runtime-left-overlong-needle"
        category: "language-core"
        tags: [operators not-has accept runtime literal capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left not-has "abcdefghijklmnop"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
