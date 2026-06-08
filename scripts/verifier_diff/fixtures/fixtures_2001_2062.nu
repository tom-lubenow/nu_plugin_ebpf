const VERIFIER_DIFF_FIXTURES_2001_2062 = [
    {
        name: "core-string-index-of"
        category: "language-core"
        tags: [string str index-of]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "ababa" | str index-of "ba"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-index-of-missing"
        category: "language-core"
        tags: [string str index-of]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str index-of "zz"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-index-of-from-end"
        category: "language-core"
        tags: [string str index-of end]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "ababa" | str index-of --end "ba"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-index-of-tracked-length"
        category: "language-core"
        tags: [string str index-of runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str index-of "ll"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-index-of-end-tracked-length"
        category: "language-core"
        tags: [string str index-of end runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str index-of --end "l"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-index-of-range-tracked-length"
        category: "language-core"
        tags: [string str index-of range runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str index-of "l" --range 2..5'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-index-of-negative-range-tracked-length"
        category: "language-core"
        tags: [string str index-of range runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str index-of "l" --range 1..-2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-index-of-negative-start-range-tracked-length"
        category: "language-core"
        tags: [string str index-of range runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str index-of "l" --range -3..'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-index-of-empty-negative-range-tracked-length"
        category: "language-core"
        tags: [string str index-of range empty runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str index-of "" --range 1..-2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-index-of-empty-negative-start-range-tracked-length"
        category: "language-core"
        tags: [string str index-of range empty runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str index-of "" --range -3..'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-index-of-empty-end-negative-range-tracked-length"
        category: "language-core"
        tags: [string str index-of end range empty runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str index-of --end "" --range 1..-2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-index-of-empty-range-tracked-length"
        category: "language-core"
        tags: [string str index-of range empty runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str index-of "" --range 2..5'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-index-of-empty-end-range-tracked-length"
        category: "language-core"
        tags: [string str index-of end range empty runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str index-of --end "" --range 2..5'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-index-of-range"
        category: "language-core"
        tags: [string str index-of range]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcabc" | str index-of "bc" --range 2..5'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-index-of-range-explicit-step"
        category: "language-core"
        tags: [string str index-of range step]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcabc" | str index-of "bc" --range 2..4..5'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-index-of-open-end-range"
        category: "language-core"
        tags: [string str index-of range]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcabc" | str index-of "bc" --range 2..'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-index-of-grapheme-clusters"
        category: "language-core"
        tags: [string str index-of grapheme-clusters]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "🇯🇵ほげ ふが ぴよ" | str index-of --grapheme-clusters "ふが"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-index-of-grapheme-clusters-from-end"
        category: "language-core"
        tags: [string str index-of end grapheme-clusters]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a🇯🇵b🇯🇵c" | str index-of --grapheme-clusters --end "🇯🇵"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-index-of-grapheme-clusters-range"
        category: "language-core"
        tags: [string str index-of range grapheme-clusters]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "ほげ ふが" | str index-of --grapheme-clusters "ふ" --range 6..9'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-index-of-join"
        category: "language-core"
        tags: [string list str index-of join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ababa" "xaba"] | str index-of "ba" | str join "-" | str starts-with "1-2"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-index-of-from-end-join"
        category: "language-core"
        tags: [string list str index-of end join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ababa" "baba"] | str index-of --end "ba" | str join "-" | str starts-with "3-2"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-index-of-range-join"
        category: "language-core"
        tags: [string list str index-of range join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abcabc" "zzbc"] | str index-of "bc" --range 2..5 | str join "-" | str starts-with "4-2"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-index-of-grapheme-clusters-join"
        category: "language-core"
        tags: [string list str index-of grapheme-clusters join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["🇯🇵ほげ ふが" "a🇯🇵b"] | str index-of --grapheme-clusters "🇯🇵" | str join "-" | str starts-with "0-1"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-substring"
        category: "language-core"
        tags: [string str substring]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str substring 1..3 | str starts-with "bcd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-substring-explicit-step"
        category: "language-core"
        tags: [string str substring range step]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str substring 1..3..4 | str starts-with "bcde"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-substring-join"
        category: "language-core"
        tags: [string list str substring join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abcd" "wxyz"] | str substring 1..2 | str join "-" | str starts-with "bc-xy"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-substring-negative-end"
        category: "language-core"
        tags: [string str substring]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str substring 1..-2 | str starts-with "bcde"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-substring-grapheme-clusters"
        category: "language-core"
        tags: [string str substring grapheme-clusters]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "🇯🇵ほげ ふが ぴよ" | str substring --grapheme-clusters 4..5 | str starts-with "ふが"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-replace"
        category: "language-core"
        tags: [string str replace]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcabc" | str replace "ab" "XY" | str starts-with "XYc"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-replace-join"
        category: "language-core"
        tags: [string list str replace join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc" "aba"] | str replace "a" "z" | str join "-" | str starts-with "zbc-zba"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-replace-regex-join"
        category: "language-core"
        tags: [string list str replace regex join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc123" "x9"] | str replace --regex "([a-z]+)([0-9]+)" "${2}" | str join "-" | str starts-with "123-9"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
    {
        name: "core-string-pascal-case"
        category: "language-core"
        tags: [string str pascal-case]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "this_is_the_second_case" | str pascal-case | str starts-with "ThisIsTheSecondCase"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-screaming-snake-case"
        category: "language-core"
        tags: [string str screaming-snake-case]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "NuShell" | str screaming-snake-case | str starts-with "NU_SHELL"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-snake-case"
        category: "language-core"
        tags: [string str snake-case]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "NuShell" | str snake-case | str starts-with "nu_shell"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-title-case"
        category: "language-core"
        tags: [string str title-case]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "nu-shell" | str title-case | str starts-with "Nu Shell"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-null-is-empty"
        category: "language-core"
        tags: ["null" is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  null | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-is-not-empty"
        category: "language-core"
        tags: [aggregate list is-not-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10] | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-is-empty"
        category: "language-core"
        tags: [aggregate record is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {} | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-is-empty"
        category: "language-core"
        tags: [string list is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab"] | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-is-not-empty"
        category: "language-core"
        tags: [string list is-not-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-is-not-empty"
        category: "language-core"
        tags: [aggregate record is-not-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 } | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-get-field"
        category: "language-core"
        tags: [aggregate record get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 cpu: 2 } | get cpu'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-get-list-field"
        category: "language-core"
        tags: [aggregate record get list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { samples: [11 22] } | get samples | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-get-missing-field-reject"
        category: "language-core"
        tags: [aggregate record get reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 cpu: 2 } | get missing'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "get field 'missing' was not found"
    }
    {
        name: "core-record-select"
        category: "language-core"
        tags: [aggregate record select]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 ok: true } | select cpu pid)'
            '  $rec.cpu'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-reject"
        category: "language-core"
        tags: [aggregate record reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 ok: true } | reject pid)'
            '  $rec.cpu'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-select-missing-reject"
        category: "language-core"
        tags: [aggregate record select reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 } | select cpu'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot find record field 'cpu'"
    }
]
