const VERIFIER_DIFF_FIXTURES_2032_2062_A = [
    {
        name: "core-string-replace-missing"
        category: "language-core"
        tags: [string str replace]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str replace "zz" "XY" | str starts-with "abc"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-replace-all"
        category: "language-core"
        tags: [string str replace all]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcabc" | str replace --all "ab" "XY" | str starts-with "XYcXYc"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-replace-regex"
        category: "language-core"
        tags: [string str replace regex]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc123" | str replace --regex "([a-z]+)([0-9]+)" "${2}-${1}" | str starts-with "123-abc"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-replace-regex-no-expand"
        category: "language-core"
        tags: [string str replace regex no-expand]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc123" | str replace --regex --no-expand "([a-z]+)([0-9]+)" "${2}-${1}" | str starts-with "${2}-${1}"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-trim"
        category: "language-core"
        tags: [string str trim]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "  abc  " | str trim | str starts-with "abc"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-trim-join"
        category: "language-core"
        tags: [string list str trim join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [" ab " " cd "] | str trim | str join "-" | str starts-with "ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-trim-left"
        category: "language-core"
        tags: [string str trim]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "  abc  " | str trim --left | str starts-with "abc  "'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-trim-right-char"
        category: "language-core"
        tags: [string str trim char]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "xxabcxx" | str trim --right --char "x" | str starts-with "xxabc"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-downcase"
        category: "language-core"
        tags: [string str downcase]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "AbC" | str downcase | str starts-with "abc"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-downcase-join"
        category: "language-core"
        tags: [string list str downcase join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["Ab" "Cd"] | str downcase | str join "-" | str starts-with "ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-upcase"
        category: "language-core"
        tags: [string str upcase]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "AbC" | str upcase | str starts-with "ABC"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-reverse"
        category: "language-core"
        tags: [string str reverse]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str reverse | str starts-with "cba"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-capitalize"
        category: "language-core"
        tags: [string str capitalize]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str capitalize | str starts-with "Abc"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-camel-case"
        category: "language-core"
        tags: [string str camel-case]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "this-is-the-first-case" | str camel-case | str starts-with "thisIsTheFirstCase"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-kebab-case"
        category: "language-core"
        tags: [string str kebab-case]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "THIS_IS_THE_SECOND_CASE" | str kebab-case | str starts-with "this-is-the-second-case"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
