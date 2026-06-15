const VERIFIER_DIFF_FIXTURES_2063_2093_B_B = [
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
        name: "core-record-values-split-list-metadata-consumers"
        category: "language-core"
        tags: [aggregate record values list mixed split-list describe get first last is-empty metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let desc_ok = ({ pid: 7 comm: "nu" } | values | split list "nu" | describe | str starts-with "list<list<any>>")'
            '  let group0_ok = ({ pid: 7 comm: "nu" } | values | split list "nu" | get 0 | describe | str starts-with "list<int>")'
            '  let group1_ok = ({ pid: 7 comm: "nu" } | values | split list "nu" | get 1 | is-empty)'
            '  let last_desc_ok = ({ pid: 7 comm: "nu" } | values | split list "nu" | last | describe | str starts-with "list<any>")'
            '  $desc_ok and ($group0_ok and ($group1_ok and $last_desc_ok))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-split-list-scalar-consumers"
        category: "language-core"
        tags: [aggregate record values list mixed split-list get first length is-empty is-not-empty describe metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let first_desc_ok = ({ pid: 7 comm: "nu" } | values | split list "nu" | first | describe | str starts-with "list<int>")'
            '  let group0_length_ok = (({ pid: 7 comm: "nu" } | values | split list "nu" | get 0 | length) == 1)'
            '  let group1_empty_ok = ({ pid: 7 comm: "nu" } | values | split list "nu" | get 1 | is-empty)'
            '  let group0_not_empty_ok = ({ pid: 7 comm: "nu" } | values | split list "nu" | get 0 | is-not-empty)'
            '  $first_desc_ok and ($group0_length_ok and ($group1_empty_ok and $group0_not_empty_ok))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
