const VERIFIER_DIFF_FIXTURES_1938_1968 = [
    {
        name: "core-binary-bytes-split-string-separator-unequal-last"
        category: "language-core"
        tags: [binary bytes split string separator unequal last starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[61 2d 2d 62 62] | bytes split "--" | last | bytes starts-with 0x[62 62]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-empty-input-length"
        category: "language-core"
        tags: [binary bytes split empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[] | bytes split 0x[20] | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-is-empty"
        category: "language-core"
        tags: [string is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "" | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-str-length"
        category: "language-core"
        tags: [string str length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-str-length-grapheme-clusters"
        category: "language-core"
        tags: [string str length grapheme-clusters]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "🇯🇵ほげ" | str length --grapheme-clusters'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-str-length-chars"
        category: "language-core"
        tags: [string str length chars]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ("Amélie" | str length --chars) == 7'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-str-length-sum"
        category: "language-core"
        tags: [string list str length sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "bb"] | str length | math sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-str-length-grapheme-clusters-sum"
        category: "language-core"
        tags: [string list str length grapheme-clusters sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["🇯🇵" "ほげ"] | str length --grapheme-clusters | math sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-str-length-chars-sum"
        category: "language-core"
        tags: [string list str length chars sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (["Amélie" "字"] | str length --chars | math sum) == 8'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-starts-with"
        category: "language-core"
        tags: [string str starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str starts-with "abc"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-starts-with-too-long"
        category: "language-core"
        tags: [string str starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a" | str starts-with "abcdefghijklmnopqrstu"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-starts-with-tracked-length"
        category: "language-core"
        tags: [string str starts-with runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str starts-with "hello"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-starts-with-ignore-case"
        category: "language-core"
        tags: [string str starts-with ignore-case]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "AbCd" | str starts-with --ignore-case "ab"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-starts-with-join"
        category: "language-core"
        tags: [string list str starts-with join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc" "xbc"] | str starts-with "a" | str join "-" | str starts-with "true-false"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-ends-with"
        category: "language-core"
        tags: [string str ends-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str ends-with "def"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
