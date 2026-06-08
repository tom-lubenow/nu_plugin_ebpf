const VERIFIER_DIFF_FIXTURES_2001_2282 = [
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
    {
        name: "core-record-rename-fields"
        category: "language-core"
        tags: [aggregate record rename]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 ok: true } | rename tid core)'
            '  $rec.tid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-rename-trailing-fields"
        category: "language-core"
        tags: [aggregate record rename]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 ok: true } | rename tid)'
            '  $rec.cpu'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-rename-column-fields"
        category: "language-core"
        tags: [aggregate record rename column]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 ok: true } | rename --column { pid: tid ok: status })'
            '  $rec.tid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-rename-column-trailing-fields"
        category: "language-core"
        tags: [aggregate record rename column]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 ok: true } | rename --column { pid: tid })'
            '  $rec.cpu'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-rename-column-missing-reject"
        category: "language-core"
        tags: [aggregate record rename column]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 } | rename --column { cpu: core }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "rename --column cannot find record field 'cpu'"
    }
    {
        name: "core-record-rename-block-fields"
        category: "language-core"
        tags: [aggregate record rename block]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 } | rename --block { str upcase })'
            '  $rec.PID'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-merge-add-field"
        category: "language-core"
        tags: [aggregate record merge]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 } | merge { mem: 9 })'
            '  $rec.mem'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-merge-overwrite-field"
        category: "language-core"
        tags: [aggregate record merge]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 } | merge { pid: 9 mem: 4 })'
            '  $rec.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-merge-non-record-reject"
        category: "language-core"
        tags: [aggregate record merge reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 cpu: 2 } | merge $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "merge requires a record argument with compiler-known fields"
    }
    {
        name: "core-record-values-get"
        category: "language-core"
        tags: [aggregate record values list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 cpu: 2 } | values | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-bool-get"
        category: "language-core"
        tags: [aggregate record values list bool]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 ok: true } | values | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-null-get"
        category: "language-core"
        tags: [aggregate record values list "null"]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ({ pid: 7 none: null } | values | get 1) == 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-runtime-bool-get"
        category: "language-core"
        tags: [aggregate record values list bool runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { ok: ($ctx.pid > 0) pid: $ctx.pid } | values | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-after-merge"
        category: "language-core"
        tags: [aggregate record values merge list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 cpu: 2 } | merge { mem: 9 } | values | get 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-string-get"
        category: "language-core"
        tags: [aggregate record values list string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { comm: "nu" exe: "bash" } | values | get 1 | str starts-with "bash"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-float-metadata-consumers"
        category: "language-core"
        tags: [aggregate record values list float length get sort describe str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let count_ok = (({ a: 2.5 b: 1.5 } | values | length) == 2)'
            '  let get_ok = ({ a: 2.5 b: 1.5 } | values | get 0 | describe | str starts-with "float")'
            '  $count_ok and ($get_ok and ({ a: 2.5 b: 1.5 } | values | sort | str join "-" | str starts-with "1.5-2.5"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-mixed-metadata-consumers"
        category: "language-core"
        tags: [aggregate record values list mixed length get string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let length_ok = (({ pid: 7 comm: "nu" } | values | length) == 2)'
            '  $length_ok and ({ pid: 7 comm: "nu" } | values | get 1 | str starts-with "nu")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-mixed-first-last"
        category: "language-core"
        tags: [aggregate record values list mixed first last reverse string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let first_ok = (({ pid: 7 comm: "nu" } | values | first) == 7)'
            '  let last_ok = ({ pid: 7 comm: "nu" } | values | last | str starts-with "nu")'
            '  $first_ok and ($last_ok and ({ pid: 7 comm: "nu" } | values | reverse | first | str starts-with "nu"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-mixed-split-list"
        category: "language-core"
        tags: [aggregate record values list mixed split-list length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 comm: "nu" } | values | split list "nu" | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-columns-get"
        category: "language-core"
        tags: [aggregate record columns list string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 cpu: 2 ok: true } | columns | get 1 | str starts-with "cpu"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-columns-metadata-transforms"
        category: "language-core"
        tags: [aggregate record columns list string sort reverse find split-list str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let sort_ok = ({ b: 2 a: 1 } | columns | sort | str join "-" | str starts-with "a-b")'
            '  let reverse_ok = ({ pid: 7 cpu: 2 ok: true } | columns | reverse | str join "," | str starts-with "ok,cpu,pid")'
            '  $sort_ok and ($reverse_ok and ((({ pid: 7 cpu: 2 ok: true } | columns | find cpu | length) == 1) and (({ pid: 7 cpu: 2 ok: true } | columns | split list cpu | length) == 2)))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-columns-empty-length"
        category: "language-core"
        tags: [aggregate record columns list empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {} | columns | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-empty-length"
        category: "language-core"
        tags: [aggregate record values list empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {} | values | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-transpose-get"
        category: "language-core"
        tags: [aggregate record transpose list get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ({ pid: 7 cpu: 2 } | transpose key value | get 1 | get value) == 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-transpose-mixed-get"
        category: "language-core"
        tags: [aggregate record transpose list get string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 comm: "nu" } | transpose key value | get 1 | get value | str starts-with "nu"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-transpose-ignore-titles-get"
        category: "language-core"
        tags: [aggregate record transpose list get ignore-titles]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ({ pid: 7 cpu: 2 } | transpose --ignore-titles val | get 1 | get val) == 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-transpose-ignore-titles-mixed-get"
        category: "language-core"
        tags: [aggregate record transpose list get string ignore-titles]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 comm: "nu" } | transpose --ignore-titles val | get 1 | get val | str starts-with "nu"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-transpose-length"
        category: "language-core"
        tags: [aggregate record transpose list length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 comm: "nu" } | transpose key value | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-describe-known-record"
        category: "language-core"
        tags: [describe aggregate record string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 cpu: 2 } | describe | str starts-with "record<pid: int, cpu: int>"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-describe-metadata-float"
        category: "language-core"
        tags: [describe scalar aggregate list math sqrt float]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((2.5 | describe | str starts-with "float") and ([2.5 1.5] | describe | str starts-with "list<float>")) and ((4 | math sqrt | describe | str starts-with "float") and ([4 9] | math sqrt | describe | str starts-with "list<float>"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-describe-float-list-builder"
        category: "language-core"
        tags: [describe aggregate list append float]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [2.5] | append 1.5 | describe | str starts-with "list<float>"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-float-list-builder-length-empty"
        category: "language-core"
        tags: [aggregate list append float length is-empty is-not-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([2.5] | append 1.5 | length) == 2) and ((([2.5] | append 1.5 | is-empty) == false) and ([2.5] | append 1.5 | is-not-empty))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-float-list-builder-transform-metadata-consumers"
        category: "language-core"
        tags: [aggregate list append float take skip drop reverse first last get find compact length describe str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let slices = ((([2.5] | append 1.5 | take 1 | length) == 1) and (([2.5] | append 1.5 | skip 1 | str join "," | str starts-with "1.5") and (([2.5] | append 1.5 | drop 1 | length) == 1)))'
            '  let ordering = ([2.5] | append 1.5 | reverse | str join "," | str starts-with "1.5,2.5")'
            '  let scalars = (([2.5] | append 1.5 | first | describe | str starts-with "float") and ([2.5] | append 1.5 | last | describe | str starts-with "float"))'
            '  let projections = (([2.5] | append 1.5 | get 0 | describe | str starts-with "float") and ((([2.5] | append 1.5 | find 1.5 | length) == 1) and ([2.5] | append 1.5 | compact --empty | str join "," | str starts-with "2.5,1.5")))'
            '  $slices and ($ordering and ($scalars and ($projections and ([2.5] | append 1.5 | last 1 | describe | str starts-with "list<float>"))))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-float-list-builder-set-metadata-consumers"
        category: "language-core"
        tags: [aggregate list float uniq sort length str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let uniq_ok = (([2.5 1.5 2.5] | uniq | length) == 2)'
            '  let sort_ok = ([2.5 1.5 2.0] | sort | str join "-" | str starts-with "1.5-2.0-2.5")'
            '  $uniq_ok and ($sort_ok and ([2.5 1.5 2.0] | sort --reverse | str join "-" | str starts-with "2.5-2.0-1.5"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-float-list-builder-chained-append-prepend"
        category: "language-core"
        tags: [aggregate list append prepend float str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let append_ok = ([2.5] | append 1.5 | append 2.0 | str join "-" | str starts-with "2.5-1.5-2.0")'
            '  $append_ok and ([2.5] | prepend 1.5 | prepend 0.5 | str join "-" | str starts-with "0.5-1.5-2.5")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-float-list-builder-split-list"
        category: "language-core"
        tags: [aggregate list float split-list length get str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let count_ok = (([2.5 1.5 3.5 1.5 4.5] | split list 1.5 | length) == 3)'
            '  $count_ok and ([2.5 1.5 3.5 4.5 1.5 5.5] | split list 1.5 | get 1 | str join "-" | str starts-with "3.5-4.5")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-list-describe"
        category: "language-core"
        tags: [describe aggregate list runtime string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = random int'
            '  seq 10 10 20 | append $n | describe | str starts-with "list<int>"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-heterogeneous-reject"
        category: "language-core"
        tags: [aggregate record values reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 comm: "nu" } | values'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "values supports only numeric scalar record fields"
    }
    {
        name: "core-record-transpose-runtime-reject"
        category: "language-core"
        tags: [aggregate record transpose reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: $ctx.pid } | transpose key value'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "transpose requires compile-time known record values"
    }
    {
        name: "core-record-insert-field"
        category: "language-core"
        tags: [aggregate record insert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 } | insert mem 9)'
            '  $rec.mem'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-update-field"
        category: "language-core"
        tags: [aggregate record update]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 } | update pid 9)'
            '  $rec.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-missing-field"
        category: "language-core"
        tags: [aggregate record upsert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 } | upsert mem 9)'
            '  $rec.mem'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-existing-field"
        category: "language-core"
        tags: [aggregate record upsert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 } | upsert pid 9)'
            '  $rec.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-insert-existing-reject"
        category: "language-core"
        tags: [aggregate record insert reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 cpu: 2 } | insert pid 9'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "insert cannot replace existing record field 'pid'"
    }
    {
        name: "core-record-update-missing-reject"
        category: "language-core"
        tags: [aggregate record update reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 cpu: 2 } | update mem 9'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "update cannot find record field 'mem'"
    }
    {
        name: "core-null-default"
        category: "language-core"
        tags: ["null" default]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  null | default 9'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-default-missing-field"
        category: "language-core"
        tags: [aggregate record default]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 } | default 2 cpu)'
            '  $rec.cpu'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-default-null-field"
        category: "language-core"
        tags: [aggregate record default "null"]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: null cpu: 2 } | default 7 pid)'
            '  $rec.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-default-empty"
        category: "language-core"
        tags: [string default empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "" | default --empty "x" | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-upsert-local"
        category: "language-core"
        tags: [aggregate list upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut xs = [1 2 3]'
            '  $xs.1 = 7'
            '  $xs.1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-new-list-field-local"
        category: "language-core"
        tags: [aggregate record list upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0 = 7'
            '  $rec.a.0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-numeric-list-existing-index-local"
        category: "language-core"
        tags: [aggregate record list upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0 = 3'
            '  $rec.a.0 = 7'
            '  $rec.a.0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-numeric-list-append-local"
        category: "language-core"
        tags: [aggregate record list upsert append local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0 = 3'
            '  $rec.a.1 = 7'
            '  $rec.a.0 + $rec.a.1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-numeric-list-sparse-append-reject"
        category: "language-core"
        tags: [aggregate record list upsert append reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0 = 3'
            '  $rec.a.2 = 7'
            '  $rec.a.0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "can only update an existing numeric list item or append at the next index"
    }
    {
        name: "core-record-upsert-new-record-list-field-local"
        category: "language-core"
        tags: [aggregate record list upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0.b = 7'
            '  $rec.a.0.b'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-new-record-list-element-local"
        category: "language-core"
        tags: [aggregate record list upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0 = { b: 3, c: 4 }'
            '  $rec.a.0.b + $rec.a.0.c'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-record-list-new-element-field-local"
        category: "language-core"
        tags: [aggregate record list upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0.b = 3'
            '  $rec.a.0.c = 7'
            '  $rec.a.0.b + $rec.a.0.c'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-record-list-append-local"
        category: "language-core"
        tags: [aggregate record list upsert append local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0.b = 3'
            '  $rec.a.1.b = 7'
            '  $rec.a.0.b + $rec.a.1.b'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-record-list-element-append-local"
        category: "language-core"
        tags: [aggregate record list upsert append local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0 = { b: 3, c: 4 }'
            '  $rec.a.1 = { b: 7, c: 8 }'
            '  $rec.a.0.b + $rec.a.1.c'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-record-list-heterogeneous-append-reject"
        category: "language-core"
        tags: [aggregate record list upsert append reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0.b = 3'
            '  $rec.a.1.c = 7'
            '  $rec.a.1.c'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "can only append homogeneous fixed record array elements"
    }
    {
        name: "core-record-upsert-record-list-element-append-mismatch-reject"
        category: "language-core"
        tags: [aggregate record list upsert append reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0 = { b: 3 }'
            '  $rec.a.1 = { b: 7, c: 8 }'
            '  $rec.a.1.b'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "can only append homogeneous fixed record array elements"
    }
    {
        name: "core-record-spread-local"
        category: "language-core"
        tags: [aggregate record spread local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = { pid: 7 }'
            '  let out = { ok: true, ...$rec }'
            '  $out.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-nested-field-local"
        category: "language-core"
        tags: [aggregate record nested local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = { stats: { pid: 7 } }'
            '  $rec.stats.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-local"
        category: "language-core"
        tags: [aggregate record upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = { pid: 7, msg: "hi" }'
            '  $rec.msg = "ok"'
            '  $rec.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-existing-nested-field-local"
        category: "language-core"
        tags: [aggregate record upsert nested local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = { stats: { pid: 0 } }'
            '  $rec.stats.pid = 7'
            '  $rec.stats.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-new-nested-field-local"
        category: "language-core"
        tags: [aggregate record upsert nested local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.stats.pid = 7'
            '  $rec.stats.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-new-deep-nested-field-local"
        category: "language-core"
        tags: [aggregate record upsert nested local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.b.c = 7'
            '  $rec.a.b.c'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-new-nested-list-field-local"
        category: "language-core"
        tags: [aggregate record list upsert nested local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.stats.values.0 = 7'
            '  $rec.stats.values.0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-nested-numeric-list-existing-index-local"
        category: "language-core"
        tags: [aggregate record list upsert nested local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.stats.values.0 = 3'
            '  $rec.stats.values.0 = 7'
            '  $rec.stats.values.0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-nested-numeric-list-append-local"
        category: "language-core"
        tags: [aggregate record list upsert append nested local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.stats.values.0 = 3'
            '  $rec.stats.values.1 = 7'
            '  $rec.stats.values.0 + $rec.stats.values.1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-annotated-record-array-nested-numeric-list-upsert-local"
        category: "language-core"
        tags: [aggregate record list upsert nested annotated local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rows: list<record<samples: list<int>>> = [{samples: [1 2]} {samples: [3 4]}]'
            '  $rows.1.samples.1 = 9'
            '  $rows.1.samples.1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-annotated-record-array-nested-string-field-local"
        category: "language-core"
        tags: [aggregate record string nested annotated local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rows: list<record<name: string>> = [{name: "aa"} {name: "bb"}]'
            '  $rows.1.name | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-annotated-record-array-nested-string-upsert-local"
        category: "language-core"
        tags: [aggregate record string upsert nested annotated local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rows: list<record<name: string>> = [{name: "aa"} {name: "bb"}]'
            '  $rows.1.name = "cc"'
            '  $rows.1.name | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-annotated-bool-fixed-array-upsert-local"
        category: "language-core"
        tags: [aggregate fixed-array bool upsert annotated local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut flags: list<bool> = [true false]'
            '  $flags.1 = true'
            '  if $flags.1 { 1 } else { 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-nested-numeric-list-sparse-append-reject"
        category: "language-core"
        tags: [aggregate record list upsert append nested reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.stats.values.0 = 3'
            '  $rec.stats.values.2 = 7'
            '  $rec.stats.values.0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "can only update an existing numeric list item or append at the next index"
    }
    {
        name: "core-record-upsert-new-nested-record-list-field-local"
        category: "language-core"
        tags: [aggregate record list upsert nested local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.stats.rows.0.pid = 7'
            '  $rec.stats.rows.0.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-new-nested-string-field-local"
        category: "language-core"
        tags: [aggregate record upsert nested local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.stats.msg = "hi"'
            '  $rec.stats.msg | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-empty-record-nested-field-local"
        category: "language-core"
        tags: [aggregate record upsert nested local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = { stats: {} }'
            '  $rec.stats.pid = 7'
            '  $rec.stats.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-new-field-local"
        category: "language-core"
        tags: [aggregate record upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.pid = 7'
            '  $rec.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-new-string-field-local"
        category: "language-core"
        tags: [aggregate record upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.msg = "hi"'
            '  $rec.msg | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-new-record-field-local"
        category: "language-core"
        tags: [aggregate record upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.stats = { pid: 7 }'
            '  $rec.stats.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-return"
        category: "language-core"
        tags: [user-function aggregate record]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] { { pid: 7, msg: "hi" } }'
            '  let out = (make)'
            '  $out.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-return"
        category: "language-core"
        tags: [user-function aggregate record upsert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = { msg: "hi" }'
            '    $rec.msg = "ok"'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.msg | count'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-new-field-return"
        category: "language-core"
        tags: [user-function aggregate record upsert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = {}'
            '    $rec.pid = 7'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-new-string-field-return"
        category: "language-core"
        tags: [user-function aggregate record upsert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = {}'
            '    $rec.msg = "hi"'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.msg | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-new-nested-field-return"
        category: "language-core"
        tags: [user-function aggregate record upsert nested]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = {}'
            '    $rec.stats.pid = 7'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.stats.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-new-list-field-return"
        category: "language-core"
        tags: [user-function aggregate record list upsert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = {}'
            '    $rec.a.0 = 7'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.a.0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-numeric-list-append-return"
        category: "language-core"
        tags: [user-function aggregate record list upsert append]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = {}'
            '    $rec.a.0 = 3'
            '    $rec.a.1 = 7'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.a.0 + $out.a.1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-new-record-list-field-return"
        category: "language-core"
        tags: [user-function aggregate record list upsert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = {}'
            '    $rec.a.0.b = 7'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.a.0.b'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-new-record-list-element-return"
        category: "language-core"
        tags: [user-function aggregate record list upsert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = {}'
            '    $rec.a.0 = { b: 3, c: 4 }'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.a.0.b + $out.a.0.c'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-record-list-new-element-field-return"
        category: "language-core"
        tags: [user-function aggregate record list upsert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = {}'
            '    $rec.a.0.b = 3'
            '    $rec.a.0.c = 7'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.a.0.b + $out.a.0.c'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-record-list-element-append-return"
        category: "language-core"
        tags: [user-function aggregate record list upsert append]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = {}'
            '    $rec.a.0 = { b: 3, c: 4 }'
            '    $rec.a.1 = { b: 7, c: 8 }'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.a.0.c + $out.a.1.b'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-record-list-append-return"
        category: "language-core"
        tags: [user-function aggregate record list upsert append]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = {}'
            '    $rec.a.0.b = 3'
            '    $rec.a.1.b = 7'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.a.0.b + $out.a.1.b'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-upsert-empty-record-nested-field-return"
        category: "language-core"
        tags: [user-function aggregate record upsert nested]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def make [] {'
            '    mut rec = { stats: {} }'
            '    $rec.stats.pid = 7'
            '    $rec'
            '  }'
            '  let out = (make)'
            '  $out.stats.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-context-arg"
        category: "language-core"
        tags: [user-function context accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def read_pid [c] {'
            '    $c.pid | count'
            '    0'
            '  }'
            '  read_pid $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-parenthesized-context-arg"
        category: "language-core"
        tags: [user-function context accept source metadata]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def read_pid [c] {'
            '    $c.pid | count'
            '    0'
            '  }'
            '  let seen = (read_pid $ctx)'
            '  $seen | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-nested-context-arg"
        category: "language-core"
        tags: [user-function nested context accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  def read_pid [c] {'
            '    let actual = (id $c)'
            '    $actual.pid | count'
            '    0'
            '  }'
            '  read_pid $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-deep-nested-context-arg"
        category: "language-core"
        tags: [user-function nested context accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  def id2 [x] { id $x }'
            '  def read_pid [c] {'
            '    let actual = (id2 $c)'
            '    $actual.pid | count'
            '    0'
            '  }'
            '  read_pid $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-returned-context-alias"
        category: "language-core"
        tags: [user-function context source metadata accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  let actual = (id $ctx)'
            '  $actual.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-returned-parenthesized-context-alias"
        category: "language-core"
        tags: [user-function context source metadata accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def id [x] { ($x) }'
            '  let actual = (id ($ctx))'
            '  $actual.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-context-field-access"
        category: "language-core"
        tags: [record context accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = { k: $ctx }'
            '  $rec.k.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-identity-wrapped-context-field-access"
        category: "language-core"
        tags: [record user-function context source metadata accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  let rec = { event: (id $ctx) }'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-context-upsert-field-access"
        category: "language-core"
        tags: [record context upsert accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = { k: null }'
            '  $rec.k = $ctx'
            '  $rec.k.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-context-upsert-new-field-access"
        category: "language-core"
        tags: [record context upsert accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.k = $ctx'
            '  $rec.k.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-context-spread-field-access"
        category: "language-core"
        tags: [record context spread accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let base = { k: $ctx }'
            '  let rec = { ok: true, ...$base }'
            '  $rec.k.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-context-field-access"
        category: "language-core"
        tags: [user-function record context accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def wrap [x] { { k: $x } }'
            '  let rec = (wrap $ctx)'
            '  $rec.k.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-context-upsert-field-access"
        category: "language-core"
        tags: [user-function record context upsert accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def wrap [x] {'
            '    mut rec = { k: null }'
            '    $rec.k = $x'
            '    $rec'
            '  }'
            '  let rec = (wrap $ctx)'
            '  $rec.k.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-context-upsert-new-field-access"
        category: "language-core"
        tags: [user-function record context upsert accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def wrap [x] {'
            '    mut rec = {}'
            '    $rec.k = $x'
            '    $rec'
            '  }'
            '  let rec = (wrap $ctx)'
            '  $rec.k.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-context-spread-field-access"
        category: "language-core"
        tags: [user-function record context spread accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def wrap [x] {'
            '    let base = { k: $x }'
            '    let rec = { ok: true, ...$base }'
            '    $rec'
            '  }'
            '  let rec = (wrap $ctx)'
            '  $rec.k.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-record-context-direct-spread-return"
        category: "language-core"
        tags: [user-function record context spread accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def wrap [x] {'
            '    let base = { k: $x }'
            '    { ok: true, ...$base }'
            '  }'
            '  let rec = (wrap $ctx)'
            '  $rec.k.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-nested-record-context-spread"
        category: "language-core"
        tags: [user-function record context spread nested source metadata accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def wrap [x] { { k: $x } }'
            '  def outer [x] {'
            '    let base = (wrap $x)'
            '    { ok: true, ...$base }'
            '  }'
            '  let rec = (outer $ctx)'
            '  $rec.k.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-context-emit-rejects-pointer-escape"
        category: "language-core"
        tags: [context emit reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | emit'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-packet-pointer-emit-rejects-pointer-escape"
        category: "language-core"
        tags: [context emit packet reject]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx.data | emit'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-optval-pointer-emit-rejects-pointer-escape"
        category: "language-core"
        tags: [context emit cgroup-sockopt reject]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  $ctx.optval | emit'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-flow-keys-pointer-emit-rejects-pointer-escape"
        category: "language-core"
        tags: [context emit flow-dissector reject]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx.flow_keys | emit'
            '  "fallback"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-histogram-rejects-pointer-escape"
        category: "language-core"
        tags: [context histogram reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | histogram'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-redirect-map-rejects-pointer-escape"
        category: "language-core"
        tags: [context redirect-map reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx | redirect-map tx_ports --kind devmap'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-tail-call-rejects-pointer-escape"
        category: "language-core"
        tags: [context tail-call reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx | tail-call jumps'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-read-str-rejects-pointer-source"
        category: "language-core"
        tags: [context read-str reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | read-str'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-read-kernel-str-rejects-pointer-source"
        category: "language-core"
        tags: [context read-kernel-str reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | read-kernel-str'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-adjust-packet-rejects-pointer-delta"
        category: "language-core"
        tags: [context adjust-packet reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx | adjust-packet --head'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-adjust-message-rejects-pointer-bytes"
        category: "language-core"
        tags: [context adjust-message reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  $ctx | adjust-message --apply'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-adjust-message-rejects-pointer-end"
        category: "language-core"
        tags: [context adjust-message reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --pull 0 $ctx'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-redirect-rejects-pointer-ifindex"
        category: "language-core"
        tags: [context redirect reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx | redirect'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-redirect-socket-rejects-pointer-key"
        category: "language-core"
        tags: [context redirect-socket reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  $ctx | redirect-socket peers --kind sockmap'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-assign-socket-rejects-pointer-socket"
        category: "language-core"
        tags: [context assign-socket reject]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx | assign-socket --replace'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-random-int-rejects-pipeline-input"
        category: "language-core"
        tags: [random reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | random int'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-map-define-rejects-pipeline-input"
        category: "language-core"
        tags: [maps map-define reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | map-define seen --kind hash --key-type u64 --value-type u64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-start-timer-rejects-pipeline-input"
        category: "language-core"
        tags: [timer reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | start-timer'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-stop-timer-rejects-pipeline-input"
        category: "language-core"
        tags: [timer reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | stop-timer'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-timer-allows-after-prior-statement"
        category: "language-core"
        tags: [timer accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | count'
            '  start-timer'
            '  stop-timer'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-map-put-rejects-prior-statement-as-value"
        category: "language-core"
        tags: [maps map-put reject pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  99'
            '  map-put seen 0 --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-put requires a value from pipeline input"
    }
    {
        name: "core-map-push-rejects-prior-statement-as-value"
        category: "language-core"
        tags: [maps map-push reject pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  99'
            '  map-push recent --kind queue'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-push requires a value from pipeline input"
    }
    {
        name: "core-global-set-rejects-prior-statement-as-value"
        category: "language-core"
        tags: [global reject pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  99'
            '  global-set state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global-set requires a value from pipeline input"
    }
    {
        name: "core-global-define-rejects-prior-statement-as-value"
        category: "language-core"
        tags: [global reject pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  99'
            '  global-define state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global-define requires a compile-time constant value from pipeline input"
    }
    {
        name: "core-map-peek-rejects-pipeline-input"
        category: "language-core"
        tags: [maps queue map-peek reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: $ctx.arg0, cookie: 7 } | map-push recent_args --kind queue'
            '  let entry = ($ctx | map-peek recent_args --kind queue)'
            '  if $entry {'
            '    $entry.pid | count'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-map-pop-rejects-pipeline-input"
        category: "language-core"
        tags: [maps stack map-pop reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: $ctx.arg0, cookie: 7 } | map-push recent_args --kind stack'
            '  let entry = ($ctx | map-pop recent_args --kind stack)'
            '  if $entry {'
            '    $entry.cookie | count'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-context-map-get-rejects-pointer-key"
        category: "language-core"
        tags: [context map reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | map-get seen --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-map-delete-rejects-pointer-key"
        category: "language-core"
        tags: [context map reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | map-delete seen --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-map-contains-rejects-pointer-key"
        category: "language-core"
        tags: [context map reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | map-contains seen --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-map-get-rejects-pointer-key"
        category: "language-core"
        tags: [record context map reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { k: $ctx } | map-get seen --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-cgroup-array-contains-rejects-pointer-index"
        category: "language-core"
        tags: [record context map cgroup-array reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { k: $ctx } | map-contains cgroups --kind cgroup-array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-map-put-rejects-pointer-escape"
        category: "language-core"
        tags: [record context map reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { k: $ctx } | map-put seen 0 --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-count-rejects-pointer-escape"
        category: "language-core"
        tags: [record context count reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { k: $ctx } | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-emit-rejects-pointer-escape"
        category: "language-core"
        tags: [record context emit reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { k: $ctx } | emit'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-packet-pointer-emit-rejects-pointer-escape"
        category: "language-core"
        tags: [record context packet emit reject]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  { data: $ctx.data } | emit'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-global-set-rejects-pointer-escape"
        category: "language-core"
        tags: [record context global reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { k: $ctx } | global-set state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-global-define-zero-rejects-pointer-escape"
        category: "language-core"
        tags: [record context global reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { k: $ctx } | global-define state --zero'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "adjust-packet-xdp-head"
        category: "language-surface"
        tags: [adjust-packet xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --head 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-head-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-packet --head 0'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-packet-xdp-head-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --head 0'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-meta"
        category: "language-surface"
        tags: [adjust-packet xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --meta 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-meta-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-packet --meta 0'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-packet-xdp-meta-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --meta 0'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-meta-subfn-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-packet xdp user-function packet-bounds reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def shift [] {'
            '    adjust-packet --meta 0'
            '    0'
            '  }'
            '  let data = $ctx.data'
            '  shift'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-packet-xdp-meta-subfn-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-packet xdp user-function packet-bounds accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def shift [] {'
            '    adjust-packet --meta 0'
            '    0'
            '  }'
            '  shift'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-tail"
        category: "language-surface"
        tags: [adjust-packet xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --tail 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-tail-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-packet --tail 0'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-packet-xdp-tail-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --tail 0'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-tc-action-room"
        category: "language-surface"
        tags: [adjust-packet tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  adjust-packet --room 0 --mode 0'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-tc-action-room-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-packet tc-action packet-bounds reject]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-packet --room 0 --mode 0'
            '  ($data | get 0) | count'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-packet-tc-action-room-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-packet tc-action packet-bounds accept]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  adjust-packet --room 0 --mode 0'
            '  ($ctx.data | get 0) | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-lwt-in-pull"
        category: "language-surface"
        tags: [adjust-packet lwt]
        target: "lwt_in:demo-route"
        program: [
            '{|ctx|'
            '  adjust-packet --pull 0'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "adjust-packet-lwt-xmit-head"
        category: "language-surface"
        tags: [adjust-packet lwt]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  adjust-packet --head 0'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "redirect-xdp-ifindex"
        category: "language-surface"
        tags: [redirect xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-tc-action-ifindex"
        category: "language-surface"
        tags: [redirect tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  redirect 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-tc-action-peer"
        category: "language-surface"
        tags: [redirect peer tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  redirect --peer 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-tc-action-neigh"
        category: "language-surface"
        tags: [redirect neigh tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  redirect --neigh 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-tc-egress-rejects-peer"
        category: "language-surface"
        tags: [redirect peer reject tc]
        target: "tc:lo:egress"
        program: [
            '{|ctx|'
            '  redirect --peer 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_peer' is only valid in tc/tcx ingress programs"
    }
    {
        name: "redirect-tcx-egress-rejects-peer"
        category: "language-surface"
        tags: [redirect peer reject tcx]
        target: "tcx:lo:egress"
        program: [
            '{|ctx|'
            '  redirect --peer 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_peer' is only valid in tc/tcx ingress programs"
    }
    {
        name: "redirect-lwt-xmit-ifindex"
        category: "language-surface"
        tags: [redirect lwt]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  redirect 1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "redirect-map-xdp-devmap"
        category: "language-surface"
        tags: [redirect-map xdp map]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map tx_ports 0 --kind devmap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-map-xdp-devmap-hash"
        category: "language-surface"
        tags: [redirect-map xdp map devmap-hash]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map tx_ports 0 --kind devmap-hash'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-map-xdp-cpumap"
        category: "language-surface"
        tags: [redirect-map xdp map cpumap]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map cpu_targets 0 --kind cpumap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-map-xdp-xskmap"
        category: "language-surface"
        tags: [redirect-map xdp map xskmap]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map xsks 0 --kind xskmap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tail-call-prog-array"
        category: "language-surface"
        tags: [tail-call prog-array]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | tail-call jumps'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tail-call-helper-xdp-rejects-stale-data"
        category: "language-surface"
        tags: [tail-call xdp packet-bounds reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  helper-call "bpf_tail_call" $ctx jumps 0'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "emit-ringbuf-output-surface"
        category: "language-surface"
        tags: [emit ringbuf helper metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | emit'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "histogram-helper-surface"
        category: "language-surface"
        tags: [histogram map helper metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  42 | histogram'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "start-timer-helper-surface"
        category: "language-surface"
        tags: [start-timer map helper metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  start-timer'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "stop-timer-helper-surface"
        category: "language-surface"
        tags: [stop-timer map helper metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let delta = (stop-timer)'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "random-int-helper-surface"
        category: "language-surface"
        tags: [random helper metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let value = (random int)'
            '  $value | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "read-str-user-pointer"
        category: "language-surface"
        tags: [read-str helper metadata]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    $ptr | read-str --max-len 64 | emit'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "read-kernel-str-kernel-pointer"
        category: "language-surface"
        tags: [read-kernel-str helper metadata]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let task = (helper-call "bpf_get_current_task_btf")'
            '  $task.comm | read-kernel-str --max-len 16 | emit'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "assign-socket-sk-lookup-clear"
        category: "language-surface"
        tags: [assign-socket sk-lookup]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  assign-socket 0 --replace'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "assign-socket-tc-ingress-clear"
        category: "language-surface"
        tags: [assign-socket tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  assign-socket 0'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "assign-socket-tc-action-rejects-flags"
        category: "language-surface"
        tags: [assign-socket tc-action reject flags]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  assign-socket 0 --replace'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_assign' requires arg2 = 0 in tc_action programs"
    }
    {
        name: "sk-assign-tc-action-rejects-dynamic-flags"
        category: "helper-state"
        tags: [sk-assign tc-action reject flags dynamic]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_sk_assign" $ctx 0 $flags'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_assign' requires arg2 = 0 in tc_action programs"
    }
    {
        name: "adjust-message-sk-msg-apply"
        category: "language-surface"
        tags: [adjust-message sk-msg]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --apply 8'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-message-rejects-non-sk-msg"
        category: "language-surface"
        tags: [adjust-message reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  adjust-message --apply 8'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-message is not supported on raw_tracepoint programs"
    }
    {
        name: "adjust-message-sk-msg-cork"
        category: "language-surface"
        tags: [adjust-message sk-msg]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --cork 8'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-message-sk-msg-pull"
        category: "language-surface"
        tags: [adjust-message sk-msg]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --pull 0 1'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "msg-pull-data-rejects-dynamic-flags"
        category: "helper-state"
        tags: [adjust-message sk-msg flags reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_msg_pull_data" $ctx 0 1 $flags'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "message data reshaping helpers require arg3 flags to be 0"
    }
    {
        name: "adjust-message-sk-msg-pull-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-message sk-msg packet-bounds reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-message --pull 0 1'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-message-sk-msg-pull-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-message sk-msg packet-bounds accept]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --pull 0 1'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-message-sk-msg-push"
        category: "language-surface"
        tags: [adjust-message sk-msg]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --push 0 1'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "msg-push-data-rejects-dynamic-flags"
        category: "helper-state"
        tags: [adjust-message sk-msg flags reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_msg_push_data" $ctx 0 1 $flags'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "message data reshaping helpers require arg3 flags to be 0"
    }
    {
        name: "adjust-message-sk-msg-push-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-message sk-msg packet-bounds reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-message --push 0 1'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-message-sk-msg-push-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-message sk-msg packet-bounds accept]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --push 0 1'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-message-sk-msg-pop"
        category: "language-surface"
        tags: [adjust-message sk-msg]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --pop 0 1'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "msg-pop-data-rejects-dynamic-flags"
        category: "helper-state"
        tags: [adjust-message sk-msg flags reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_msg_pop_data" $ctx 0 1 $flags'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "message data reshaping helpers require arg3 flags to be 0"
    }
    {
        name: "adjust-message-sk-msg-pop-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-message sk-msg packet-bounds reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-message --pop 0 1'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-message-sk-msg-pop-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-message sk-msg packet-bounds accept]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --pop 0 1'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-msg-sockmap"
        category: "language-surface"
        tags: [redirect-socket sk-msg sockmap]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockmap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-msg-sockhash"
        category: "language-surface"
        tags: [redirect-socket sk-msg sockhash]
        target: "sk_msg:/sys/fs/bpf/demo_sockhash"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockhash'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "msg-redirect-map-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect-socket sk-msg sockmap flags reject source metadata]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_msg_redirect_map" $ctx peers 0 $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skb/message redirect helpers require flags to contain only BPF_F_INGRESS"
    }
    {
        name: "msg-redirect-hash-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect-socket sk-msg sockhash flags reject source metadata]
        target: "sk_msg:/sys/fs/bpf/demo_sockhash"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_msg_redirect_hash" $ctx hash_peers "peer-a" $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skb/message redirect helpers require flags to contain only BPF_F_INGRESS"
    }
    {
        name: "map-put-sock-ops-sockmap"
        category: "language-surface"
        tags: [maps map-put sock-ops sockmap]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx | map-put active_sockmap $ctx.remote_port --kind sockmap --flags 2'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-put-sock-ops-sockhash"
        category: "language-surface"
        tags: [maps map-put sock-ops sockhash]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx | map-put active_sockhash $ctx.remote_port --kind sockhash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-sk-skb-pull"
        category: "language-surface"
        tags: [adjust-packet sk-skb]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-packet --pull 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-sk-skb-pull-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-packet sk-skb packet-bounds reject]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-packet --pull 0'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-packet-sk-skb-pull-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-packet sk-skb packet-bounds accept]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-packet --pull 0'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-skb-sockmap"
        category: "language-surface"
        tags: [redirect-socket sk-skb sockmap]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockmap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-skb-sockhash"
        category: "language-surface"
        tags: [redirect-socket sk-skb sockhash]
        target: "sk_skb:/sys/fs/bpf/demo_sockhash"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockhash'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-redirect-map-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect-socket sk-skb sockmap flags reject source metadata]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_sk_redirect_map" $ctx peers 0 $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skb/message redirect helpers require flags to contain only BPF_F_INGRESS"
    }
    {
        name: "sk-redirect-hash-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect-socket sk-skb sockhash flags reject source metadata]
        target: "sk_skb:/sys/fs/bpf/demo_sockhash"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_sk_redirect_hash" $ctx hash_peers "peer-a" $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skb/message redirect helpers require flags to contain only BPF_F_INGRESS"
    }
    {
        name: "redirect-socket-sk-reuseport-sockarray"
        category: "language-surface"
        tags: [redirect-socket sk-reuseport reuseport-sockarray]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  redirect-socket sockets 0 --kind reuseport-sockarray'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-sk-select-reuseport-helper"
        category: "helper-state"
        tags: [helper-call sk-reuseport reuseport-sockarray accept source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  let key = "0000"'
            '  helper-call "bpf_sk_select_reuseport" $ctx sockets $key 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "adjust-packet-sk-skb-parser-pull"
        category: "language-surface"
        tags: [adjust-packet sk-skb-parser]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-packet --pull 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-skb-parser-sockhash"
        category: "language-surface"
        tags: [redirect-socket sk-skb-parser sockhash]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockhash"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockhash'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
