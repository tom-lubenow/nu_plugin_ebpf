const VERIFIER_DIFF_FIXTURES_3157_3178 = [
    {
        name: "core-string-starts-with-accepts-runtime-input-empty-prefix"
        category: "language-core"
        tags: [string str starts-with accept runtime literal empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str starts-with ""'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-starts-with-accepts-runtime-input-overlong-prefix"
        category: "language-core"
        tags: [string str starts-with accept runtime literal capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str starts-with "abcdefghijklmnop"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-ends-with-accepts-runtime-input-empty-suffix"
        category: "language-core"
        tags: [string str ends-with accept runtime literal empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str ends-with ""'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-ends-with-accepts-runtime-input-overlong-suffix"
        category: "language-core"
        tags: [string str ends-with accept runtime literal capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str ends-with "abcdefghijklmnop"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-contains-accepts-runtime-input-empty-substring"
        category: "language-core"
        tags: [string str contains accept runtime literal empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str contains ""'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-contains-accepts-runtime-input-overlong-substring"
        category: "language-core"
        tags: [string str contains accept runtime literal capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str contains "abcdefghijklmnop"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-operator-starts-with-accepts-runtime-left-empty-prefix"
        category: "language-core"
        tags: [operators starts-with accept runtime literal empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left starts-with ""'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-operator-starts-with-accepts-runtime-left-overlong-prefix"
        category: "language-core"
        tags: [operators starts-with accept runtime literal capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left starts-with "abcdefghijklmnop"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-operator-ends-with-accepts-runtime-left-empty-suffix"
        category: "language-core"
        tags: [operators ends-with accept runtime literal empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left ends-with ""'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-operator-ends-with-accepts-runtime-left-overlong-suffix"
        category: "language-core"
        tags: [operators ends-with accept runtime literal capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left ends-with "abcdefghijklmnop"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-operator-in-accepts-empty-needle-runtime-right"
        category: "language-core"
        tags: [operators in accept runtime literal empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let left = (global-get left)'
            '  "" in $left'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
