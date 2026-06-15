const VERIFIER_DIFF_FIXTURES_1719_1750_A_B = [
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
]
