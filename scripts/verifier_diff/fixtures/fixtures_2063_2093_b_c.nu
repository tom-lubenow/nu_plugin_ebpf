const VERIFIER_DIFF_FIXTURES_2063_2093_B_C = [
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
        name: "core-record-columns-scalar-first-last"
        category: "language-core"
        tags: [aggregate record columns list string first last metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let first_ok = ({ pid: 7 cpu: 2 ok: true } | columns | first | str starts-with "pid")'
            '  let last_ok = ({ pid: 7 cpu: 2 ok: true } | columns | last | str starts-with "ok")'
            '  $first_ok and $last_ok'
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
        name: "core-record-columns-transform-describe-metadata"
        category: "language-core"
        tags: [aggregate record columns list string skip drop take last append prepend describe str join metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = { pid: 7 cpu: 2 ok: true }'
            '  let skip_join_ok = ($rec | columns | skip | str join "," | str starts-with "cpu,ok")'
            '  let drop_join_ok = ($rec | columns | drop | str join "," | str starts-with "pid,cpu")'
            '  let take_desc_ok = ($rec | columns | take 2 | describe | str starts-with "list<string>")'
            '  let last_desc_ok = ($rec | columns | last 2 | describe | str starts-with "list<string>")'
            '  let append_join_ok = ($rec | columns | append "irq" | str join "," | str starts-with "pid,cpu,ok,irq")'
            '  let prepend_join_ok = ($rec | columns | prepend "irq" | str join "," | str starts-with "irq,pid,cpu,ok")'
            '  $skip_join_ok and ($drop_join_ok and ($take_desc_ok and ($last_desc_ok and ($append_join_ok and $prepend_join_ok))))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-columns-sort-find-describe-metadata"
        category: "language-core"
        tags: [aggregate record columns list string sort reverse find first describe metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = { pid: 7 cpu: 2 ok: true }'
            '  let sort_desc_ok = ($rec | columns | sort | describe | str starts-with "list<string>")'
            '  let reverse_desc_ok = ($rec | columns | reverse | describe | str starts-with "list<string>")'
            '  let find_desc_ok = ($rec | columns | find cpu | describe | str starts-with "list<string>")'
            '  let first_desc_ok = ($rec | columns | first 2 | describe | str starts-with "list<string>")'
            '  $sort_desc_ok and ($reverse_desc_ok and ($find_desc_ok and $first_desc_ok))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
