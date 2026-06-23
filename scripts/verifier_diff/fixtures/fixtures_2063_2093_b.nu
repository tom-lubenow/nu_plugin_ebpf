const VERIFIER_DIFF_FIXTURES_2063_2093_B = [
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
        name: "core-record-values-float-math-mode"
        category: "language-core"
        tags: [aggregate record values list float math mode str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { left: 2.5 right: 1.5 } | values | math mode | str join "-" | str starts-with "1.5-2.5"'
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
        name: "core-record-values-runtime-string-direct-get"
        category: "language-core"
        tags: [aggregate record values get string accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { comm: $ctx.comm pid: $ctx.pid } | values | get 0 | str starts-with "n"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-runtime-string-direct-first"
        category: "language-core"
        tags: [aggregate record values first string accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { comm: $ctx.comm pid: $ctx.pid } | values | first | str starts-with "n"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-runtime-string-direct-last"
        category: "language-core"
        tags: [aggregate record values last string accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: $ctx.pid comm: $ctx.comm } | values | last | str starts-with "n"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-runtime-string-reverse-first"
        category: "language-core"
        tags: [aggregate record values reverse first string accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: $ctx.pid comm: $ctx.comm } | values | reverse | first | str starts-with "n"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-runtime-string-reverse-last"
        category: "language-core"
        tags: [aggregate record values reverse last string accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { comm: $ctx.comm pid: $ctx.pid } | values | reverse | last | str starts-with "n"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-runtime-string-counted-first-last"
        category: "language-core"
        tags: [aggregate record values first last string accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: $ctx.pid comm: $ctx.comm } | values | first 2 | last | str starts-with "n"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-runtime-string-counted-first-get"
        category: "language-core"
        tags: [aggregate record values first get string accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: $ctx.pid comm: $ctx.comm } | values | first 2 | get 1 | str starts-with "n"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-runtime-string-counted-last-first"
        category: "language-core"
        tags: [aggregate record values last first string accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: $ctx.pid comm: $ctx.comm } | values | last 1 | first | str starts-with "n"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-runtime-string-counted-last-get"
        category: "language-core"
        tags: [aggregate record values last get string accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: $ctx.pid comm: $ctx.comm } | values | last 1 | get 0 | str starts-with "n"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-runtime-string-drop-first"
        category: "language-core"
        tags: [aggregate record values drop first string accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: $ctx.pid comm: $ctx.comm } | values | drop 1 | first | str starts-with "n"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-runtime-string-drop-get"
        category: "language-core"
        tags: [aggregate record values drop get string accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: $ctx.pid comm: $ctx.comm } | values | drop 1 | get 0 | str starts-with "n"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-runtime-string-drop-last"
        category: "language-core"
        tags: [aggregate record values drop last string accept runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: $ctx.pid comm: $ctx.comm } | values | drop 1 | last | str starts-with "n"'
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
        name: "core-record-values-mixed-transform-metadata"
        category: "language-core"
        tags: [aggregate record values list mixed reverse compact uniq find describe length metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let reverse_desc_ok = ({ pid: 7 comm: "nu" } | values | reverse | describe | str starts-with "list<oneof<string, int>>")'
            '  let compact_len_ok = (({ pid: 7 comm: "nu" } | values | compact | length) == 2)'
            '  let uniq_len_ok = (({ pid: 7 comm: "nu" } | values | uniq | length) == 2)'
            '  let find_desc_ok = ({ pid: 7 comm: "nu" } | values | find nu | describe | str starts-with "list<string>")'
            '  $reverse_desc_ok and ($compact_len_ok and ($uniq_len_ok and $find_desc_ok))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-mixed-count-transform-metadata"
        category: "language-core"
        tags: [aggregate record values list mixed take first skip drop last describe length metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = { pid: 7 comm: "nu" ok: true }'
            '  let take_desc_ok = ($rec | values | take 2 | describe | str starts-with "list<oneof<int, string>>")'
            '  let first_len_ok = (($rec | values | first 2 | length) == 2)'
            '  let skip_desc_ok = ($rec | values | skip 2 | describe | str starts-with "list<bool>")'
            '  let drop_desc_ok = ($rec | values | drop 2 | describe | str starts-with "list<int>")'
            '  let last_desc_ok = ($rec | values | last 2 | describe | str starts-with "list<oneof<string, bool>>")'
            '  $take_desc_ok and ($first_len_ok and ($skip_desc_ok and ($drop_desc_ok and $last_desc_ok)))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
