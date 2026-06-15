const VERIFIER_DIFF_FIXTURES_1719_1750_A = [
    {
        name: "core-seq-float-join"
        category: "language-core"
        tags: [aggregate list seq float str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 1.0 0.5 2.0 | str join "," | str starts-with "1.0,1.5,2.0"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-float-metadata-transforms"
        category: "language-core"
        tags: [aggregate list seq float sort reverse find split-list str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let sort_ok = (seq 2.0 -0.5 1.0 | sort | str join "," | str starts-with "1.0,1.5,2.0")'
            '  let reverse_ok = (seq 1.0 0.5 2.0 | reverse | str join "," | str starts-with "2.0,1.5,1.0")'
            '  $sort_ok and ($reverse_ok and (((seq 1.0 0.5 2.0 | find 1.5 | length) == 1) and ((seq 1.0 0.5 2.0 | split list 1.5 | length) == 2)))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-float-split-list-metadata-consumers"
        category: "language-core"
        tags: [aggregate list seq float split-list describe get first last is-empty is-not-empty str join metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let desc_ok = (seq 1.0 0.5 3.0 | split list 2.0 | describe | str starts-with "list<list<float>>")'
            '  let not_empty_ok = (seq 1.0 0.5 3.0 | split list 2.0 | is-not-empty)'
            '  let empty_check_ok = not (seq 1.0 0.5 3.0 | split list 2.0 | is-empty)'
            '  let group_join_ok = (seq 1.0 0.5 3.0 | split list 2.0 | get 1 | str join "-" | str starts-with "2.5-3.0")'
            '  let group_desc_ok = (seq 1.0 0.5 3.0 | split list 2.0 | get 1 | describe | str starts-with "list<float>")'
            '  let first_desc_ok = (seq 1.0 0.5 3.0 | split list 2.0 | first | describe | str starts-with "list<float>")'
            '  let last_desc_ok = (seq 1.0 0.5 3.0 | split list 2.0 | last | describe | str starts-with "list<float>")'
            '  $desc_ok and ($not_empty_ok and ($empty_check_ok and ($group_join_ok and ($group_desc_ok and ($first_desc_ok and $last_desc_ok)))))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-char-join"
        category: "language-core"
        tags: [aggregate list seq char str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq char e a | str join "-" | str starts-with "e-d-c-b-a"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-char-over-capacity-reject"
        category: "language-core"
        tags: [aggregate list seq char reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq char A ~ | str join ""'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq char output exceeds fixed string-list capacity 60"
    }
]
