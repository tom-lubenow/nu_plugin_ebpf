const VERIFIER_DIFF_FIXTURES_2094_2125_A = [
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
]
