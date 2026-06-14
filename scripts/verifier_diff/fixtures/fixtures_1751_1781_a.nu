const VERIFIER_DIFF_FIXTURES_1751_1781_A = [
    {
        name: "core-list-math-median-mixed-numeric"
        category: "language-core"
        tags: [aggregate list math median float constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([1.5 3 10.5] | math median) == 3'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-math-median"
        category: "language-core"
        tags: [aggregate list seq math median]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 1 5 | math median'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-list-math-median"
        category: "language-core"
        tags: [aggregate list math median runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = random int'
            '  let m = (seq 10 10 20 | append $n | math median)'
            '  ($m >= 10) and ($m <= 20)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-mode"
        category: "language-core"
        tags: [aggregate list math mode]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [5 1 5 2 1] | math mode | str join "-" | str starts-with "1-5"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-list-math-mode"
        category: "language-core"
        tags: [aggregate list math mode runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = random int'
            '  (seq 1 1 3 | append $n | math mode | length) >= 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-mode-empty"
        category: "language-core"
        tags: [aggregate list math mode empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([] | math mode | length) == 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-min-single"
        category: "language-core"
        tags: [aggregate list math min]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [20] | math min'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-sum-empty-reject"
        category: "language-core"
        tags: [aggregate list math sum reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | math sum'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math sum requires a stack-backed numeric list with proven non-empty length"
    }
    {
        name: "core-scalar-math-abs"
        category: "language-core"
        tags: [scalar math abs]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  -42 | math abs'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-math-abs-runtime"
        category: "language-core"
        tags: [scalar math abs runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | math abs) >= 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-abs-float-folded"
        category: "language-core"
        tags: [scalar aggregate list math abs float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (-2.5 | math abs | fill --alignment right --character "0" --width 1 | str starts-with "2.5") and ([-2 -1.5] | math abs | str join "," | str starts-with "2,1.5")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-abs-float-describe"
        category: "language-core"
        tags: [scalar aggregate list math abs float describe metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let scalar_desc_ok = (-2.5 | math abs | describe | str starts-with "float")'
            '  let list_desc_ok = ([-2 -1.5] | math abs | describe | str starts-with "list<any>")'
            '  $scalar_desc_ok and $list_desc_ok'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-math-div-mod-runtime"
        category: "language-core"
        tags: [scalar math divide modulo runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = ((random int | bits and 255) + 1)'
            '  (($n / 3) >= 0) and (($n mod 3) >= 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-math-arithmetic-runtime"
        category: "language-core"
        tags: [scalar math add subtract multiply runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 255)'
            '  ((($n + 7) - 3) * 2) >= 8'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-comparison-boolean-runtime"
        category: "language-core"
        tags: [scalar comparison boolean runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let a = (random int | bits and 255)'
            '  let b = (random int | bits and 255)'
            '  ($a == $b) or ($a != $b)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-comparison-ordering-runtime"
        category: "language-core"
        tags: [scalar comparison ordering runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let a = (random int | bits and 255)'
            '  let b = (random int | bits and 255)'
            '  ($a <= $b) or ($a > $b)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
