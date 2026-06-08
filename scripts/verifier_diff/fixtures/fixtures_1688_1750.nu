const VERIFIER_DIFF_FIXTURES_1688_1750 = [
    {
        name: "core-list-append"
        category: "language-core"
        tags: [aggregate list append]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | append 40 | get 3'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-prepend"
        category: "language-core"
        tags: [aggregate list prepend]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | prepend 5 | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-each"
        category: "language-core"
        tags: [aggregate list each closure]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | each {|x| $x + 1 } | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-where"
        category: "language-core"
        tags: [aggregate list where closure]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | where {|x| $x > 15 } | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-any"
        category: "language-core"
        tags: [aggregate list any closure]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | any {|x| $x > 15 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-all"
        category: "language-core"
        tags: [aggregate list all closure]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | all {|x| $x > 5 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-any-empty"
        category: "language-core"
        tags: [aggregate list any closure empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | any {|x| $x > 15 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-all-empty"
        category: "language-core"
        tags: [aggregate list all closure empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | all {|x| $x > 15 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-append-capacity-reject"
        category: "language-core"
        tags: [aggregate list append reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 0 59 | append 60 | get 60'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "append would exceed stack-backed numeric list capacity 60"
    }
    {
        name: "core-list-is-empty"
        category: "language-core"
        tags: [aggregate list is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-length"
        category: "language-core"
        tags: [aggregate list length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-length"
        category: "language-core"
        tags: [string list length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-get"
        category: "language-core"
        tags: [string list get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | get 1 | str starts-with "cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-first"
        category: "language-core"
        tags: [string list first]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | first | str starts-with "ab"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-last"
        category: "language-core"
        tags: [string list last]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | last | str starts-with "cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-take"
        category: "language-core"
        tags: [string list take]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | take 2 | str join "-" | str starts-with "ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-skip"
        category: "language-core"
        tags: [string list skip]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | skip 1 | str join "-" | str starts-with "cd-ef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-drop"
        category: "language-core"
        tags: [string list drop]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | drop 1 | str join "-" | str starts-with "ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-first-count"
        category: "language-core"
        tags: [string list first]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | first 2 | str join "-" | str starts-with "ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-last-count"
        category: "language-core"
        tags: [string list last]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | last 2 | str join "-" | str starts-with "cd-ef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-reverse"
        category: "language-core"
        tags: [string list reverse]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | reverse | str join "-" | str starts-with "ef-cd-ab"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-append"
        category: "language-core"
        tags: [string list append]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | append "ef" | str join "-" | str starts-with "ab-cd-ef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-prepend"
        category: "language-core"
        tags: [string list prepend]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | prepend "zz" | str join "-" | str starts-with "zz-ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-uniq"
        category: "language-core"
        tags: [string list uniq]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ab" "ef" "cd"] | uniq | str join "-" | str starts-with "ab-cd-ef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-sort"
        category: "language-core"
        tags: [string list sort]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["cd" "aa" "ab"] | sort | str join "-" | str starts-with "aa-ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-sort-reverse"
        category: "language-core"
        tags: [string list sort reverse]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["cd" "aa" "ab"] | sort --reverse | str join "-" | str starts-with "cd-ab-aa"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-find"
        category: "language-core"
        tags: [string list find]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef" "cd"] | find "cd" | str join "-" | str starts-with "cd-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-compact-empty"
        category: "language-core"
        tags: [string list compact empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "" "cd"] | compact --empty | str join "-" | str starts-with "ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-sum"
        category: "language-core"
        tags: [aggregate list math sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | math sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-integer-sum"
        category: "language-core"
        tags: [aggregate list seq math sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (seq 1 5 | math sum) == 15'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-negative-step-join"
        category: "language-core"
        tags: [aggregate list seq str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 5 -2 1 | str join "-" | str starts-with "5-3-1"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
    {
        name: "core-seq-date-join"
        category: "language-core"
        tags: [aggregate list seq date str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --end-date "2020-01-05" --increment 2 | str join "," | str starts-with "2020-01-01,2020-01-03,2020-01-05"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-date-length"
        category: "language-core"
        tags: [aggregate list seq date length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (seq date --begin-date "2020-01-05" --end-date "2020-01-01" | length) == 5'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-date-days-join"
        category: "language-core"
        tags: [aggregate list seq date days str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --days 5 --increment 2 | str join "," | str starts-with "2020-01-01,2020-01-03,2020-01-05"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-date-periods-join"
        category: "language-core"
        tags: [aggregate list seq date periods str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --periods 4 --increment 3 | str join "," | str starts-with "2020-01-01,2020-01-04,2020-01-07,2020-01-10"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-date-format-join"
        category: "language-core"
        tags: [aggregate list seq date format str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --input-format "%m/%d/%Y" --output-format "%Y/%m/%d" --begin-date "01/01/2020" --end-date "01/03/2020" | str join "," | str starts-with "2020/01/01,2020/01/02,2020/01/03"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-date-duration-increment-join"
        category: "language-core"
        tags: [aggregate list seq date duration increment str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --end-date "2020-01-02" --increment 6hr --output-format "%Y-%m-%d %H:%M:%S" | str join "," | str starts-with "2020-01-01 00:00:00,2020-01-01 06:00:00,2020-01-01 12:00:00,2020-01-01 18:00:00,2020-01-02 00:00:00"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-date-reverse-periods-join"
        category: "language-core"
        tags: [aggregate list seq date reverse periods str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --periods 3 --increment 2 --reverse | str join "," | str starts-with "2020-01-01,2019-12-30,2019-12-28,2019-12-26,2019-12-24"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-date-over-capacity-reject"
        category: "language-core"
        tags: [aggregate list seq date reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --end-date "2020-03-15" | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq date output exceeds fixed string-list capacity 60"
    }
    {
        name: "core-seq-date-periods-over-capacity-reject"
        category: "language-core"
        tags: [aggregate list seq date periods reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --periods 61 | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq date output exceeds fixed string-list capacity 60"
    }
    {
        name: "core-list-math-product"
        category: "language-core"
        tags: [aggregate list math product]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [2 3 4] | math product'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-min"
        category: "language-core"
        tags: [aggregate list math min]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [20 10 30] | math min'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-max"
        category: "language-core"
        tags: [aggregate list math max]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [20 10 30] | math max'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-min-max-mixed-numeric"
        category: "language-core"
        tags: [aggregate list math min max float constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([1 2.5 3.5] | math min) == 1) and (([1.5 2.5 3] | math max) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-float-results-fill"
        category: "language-core"
        tags: [aggregate list math min max median float fill]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([1.5 2 3] | math min | fill --alignment right --character "0" --width 4 | str starts-with "01.5") and ([1 2.0 2] | math max | fill --alignment right --character "0" --width 4 | str starts-with "0002")) and (([1 3] | math median | fill --alignment right --character "0" --width 4 | str starts-with "0002") and ([1.5 3.5 10] | math median | fill --alignment right --character "0" --width 4 | str starts-with "03.5"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-float-sum-product-fill"
        category: "language-core"
        tags: [aggregate list math sum product float fill]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([1.5 2] | math sum | fill --alignment right --character "0" --width 4 | str starts-with "03.5") and ([1.5 2] | math product | fill --alignment right --character "0" --width 4 | str starts-with "0003")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-avg-fill"
        category: "language-core"
        tags: [aggregate list math avg float fill]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([1 2 3] | math avg | fill --alignment right --character "0" --width 4 | str starts-with "0002") and ([1.0 2] | math avg | fill --alignment right --character "0" --width 4 | str starts-with "01.5")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-avg-filesize-duration"
        category: "language-core"
        tags: [aggregate list math avg filesize duration constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([1kb 2kb 2kb] | math avg | describe | str starts-with "filesize") and ([1sec 2sec 2sec] | math avg | describe | str starts-with "duration")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-sqrt-folded"
        category: "language-core"
        tags: [scalar aggregate list math sqrt float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (9 | math sqrt | fill --alignment right --character "0" --width 4 | str starts-with "0003") and ([4 2.25 9] | math sqrt | str join "," | str starts-with "2.0,1.5,3.0")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-exp-folded"
        category: "language-core"
        tags: [scalar aggregate list math exp float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (0 | math exp | fill --alignment right --character "0" --width 4 | str starts-with "0001") and ([0 1] | math exp | str join "," | str starts-with "1.0,2.718281828459045")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-ln-folded"
        category: "language-core"
        tags: [scalar aggregate list math ln float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (1 | math ln | fill --alignment right --character "0" --width 4 | str starts-with "0000") and ([1 2] | math ln | str join "," | str starts-with "0.0,0.6931471805599453")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-log-folded"
        category: "language-core"
        tags: [scalar aggregate list math log float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (100 | math log 10 | fill --alignment right --character "0" --width 4 | str starts-with "0002") and ([16 8 4] | math log 2 | str join "," | str starts-with "4.0,3.0,2.0")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-trig-folded"
        category: "language-core"
        tags: [scalar aggregate list math sin cos tan float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((0 | math sin | fill --alignment right --character "0" --width 4 | str starts-with "0000") and (0 | math cos | fill --alignment right --character "0" --width 4 | str starts-with "0001")) and ((0 | math tan | fill --alignment right --character "0" --width 4 | str starts-with "0000") and ([0 0] | math cos | str join "," | str starts-with "1.0,1.0"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-hyperbolic-folded"
        category: "language-core"
        tags: [scalar aggregate list math sinh cosh tanh float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((0 | math sinh | fill --alignment right --character "0" --width 4 | str starts-with "0000") and (0 | math cosh | fill --alignment right --character "0" --width 4 | str starts-with "0001")) and ((0 | math tanh | fill --alignment right --character "0" --width 4 | str starts-with "0000") and ([0 0] | math cosh | str join "," | str starts-with "1.0,1.0"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-inverse-folded"
        category: "language-core"
        tags: [scalar aggregate list math inverse float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (((0 | math arcsin | fill --alignment right --character "0" --width 4 | str starts-with "0000") and (1 | math arccos | fill --alignment right --character "0" --width 4 | str starts-with "0000")) and ((0 | math arctan | fill --alignment right --character "0" --width 4 | str starts-with "0000") and (0 | math arcsinh | fill --alignment right --character "0" --width 4 | str starts-with "0000"))) and (((1 | math arccosh | fill --alignment right --character "0" --width 4 | str starts-with "0000") and (0 | math arctanh | fill --alignment right --character "0" --width 4 | str starts-with "0000")) and ([0 1] | math arcsin | str join "," | str starts-with "0.0,1.5707963267948966"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-degrees-folded"
        category: "language-core"
        tags: [scalar aggregate list math degrees inverse sin cos tan float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (((90 | math sin --degrees | fill --alignment right --character "0" --width 4 | str starts-with "0001") and (180 | math cos --degrees | fill --alignment right --character "0" --width 1 | str starts-with "-1")) and (45 | math tan --degrees | fill --alignment right --character "0" --width 1 | str starts-with "0.999")) and (((1 | math arcsin --degrees | fill --alignment right --character "0" --width 1 | str starts-with "90") and (-1 | math arccos --degrees | fill --alignment right --character "0" --width 1 | str starts-with "180")) and ((1 | math arctan -d | fill --alignment right --character "0" --width 1 | str starts-with "45") and ([0 1] | math arcsin -d | str join "," | str starts-with "0.0,90.0")))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-stats-folded"
        category: "language-core"
        tags: [aggregate list math variance stddev sample float fill]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([1 2 3 4 5] | math variance | fill --alignment right --character "0" --width 4 | str starts-with "0002") and ([1 2 3 4 5] | math stddev --sample | fill --alignment right --character "0" --width 4 | str starts-with "1.581")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-filesize-duration"
        category: "language-core"
        tags: [aggregate list math filesize duration constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([1kb 2kb] | math sum | describe | str starts-with "filesize") and (([1sec 2sec] | math sum | describe | str starts-with "duration"))) and ((([1kb 2] | math max | describe | str starts-with "filesize") and ([1sec 2] | math min) == 2) and (([1kb 2kb] | math median | describe | str starts-with "filesize") and ([1sec 2sec] | math median | describe | str starts-with "duration")))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-median"
        category: "language-core"
        tags: [aggregate list math median]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [20 10 30] | math median'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
