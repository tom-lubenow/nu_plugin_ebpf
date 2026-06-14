const VERIFIER_DIFF_FIXTURES_1938_1968_B = [
    {
        name: "core-string-ends-with-too-long"
        category: "language-core"
        tags: [string str ends-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a" | str ends-with "abcdef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-ends-with-tracked-length"
        category: "language-core"
        tags: [string str ends-with runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str ends-with "lo"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-ends-with-ignore-case"
        category: "language-core"
        tags: [string str ends-with ignore-case]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "AbCd" | str ends-with --ignore-case "CD"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-ends-with-join"
        category: "language-core"
        tags: [string list str ends-with join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc" "abx"] | str ends-with "c" | str join "-" | str starts-with "true-false"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-contains"
        category: "language-core"
        tags: [string str contains]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str contains "cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-contains-tracked-length"
        category: "language-core"
        tags: [string str contains runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str contains "ll"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-contains-join"
        category: "language-core"
        tags: [string list str contains join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc" "def"] | str contains "a" | str join "-" | str starts-with "true-false"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-contains-ignore-case-join"
        category: "language-core"
        tags: [string list str contains ignore-case join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["Abc" "def"] | str contains --ignore-case "a" | str join "-" | str starts-with "true-false"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-contains-missing"
        category: "language-core"
        tags: [string str contains]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str contains "zz"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-contains-ignore-case"
        category: "language-core"
        tags: [string str contains ignore-case]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "AbCd" | str contains --ignore-case "bc"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-distance"
        category: "language-core"
        tags: [string str distance]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "nushell" | str distance "nutshell"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-join-scalar"
        category: "language-core"
        tags: [string str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str join "-" | str starts-with "abc"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-join"
        category: "language-core"
        tags: [string list str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | str join "-" | str starts-with "ab-cd-ef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-scalar-list-join"
        category: "language-core"
        tags: [string list scalar str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 1.5 1kb 1sec 0x[01 02] true null] | str join ":" | str starts-with "1:1.5:1.0 kB:1sec:[1, 2]:true:"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-aggregate-list-join"
        category: "language-core"
        tags: [string list aggregate record str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let records = ([{a: 1 b: 2} {c: 3}] | str join ":")'
            '  let lists = ([[1 2] [3]] | str join ":")'
            '  (($records | str starts-with "{a: 1") and ($records | str contains "b: 2}:{c: 3}")) and (($lists | str starts-with "[1") and ($lists | str contains "2]:[3]"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-fill-right"
        category: "language-core"
        tags: [string fill right]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "ab" | fill --alignment right --character "0" --width 5 | str starts-with "000ab"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
