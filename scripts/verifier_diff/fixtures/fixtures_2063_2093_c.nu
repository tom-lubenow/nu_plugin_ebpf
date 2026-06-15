const VERIFIER_DIFF_FIXTURES_2063_2093_C = [
    {
        name: "core-record-columns-split-list-metadata-consumers"
        category: "language-core"
        tags: [aggregate record columns list split-list describe get first is-not-empty metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let split = ({ pid: 7 cpu: 2 ok: true } | columns | split list cpu)'
            '  let desc_ok = ($split | describe | str starts-with "list<list<string>>")'
            '  let group_desc_ok = ($split | get 1 | describe | str starts-with "list<string>")'
            '  let first_desc_ok = ($split | first | describe | str starts-with "list<string>")'
            '  $desc_ok and ($group_desc_ok and ($first_desc_ok and ($split | is-not-empty)))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-columns-split-list-scalar-consumers"
        category: "language-core"
        tags: [aggregate record columns list split-list get first last length is-empty is-not-empty describe metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let direct_length_ok = (({ pid: 7 cpu: 2 ok: true } | columns | split list cpu | length) == 2)'
            '  let direct_last_desc_ok = ({ pid: 7 cpu: 2 ok: true } | columns | split list cpu | last | describe | str starts-with "list<string>")'
            '  let group0_length_ok = (({ pid: 7 cpu: 2 ok: true } | columns | split list cpu | get 0 | length) == 1)'
            '  let group1_not_empty_ok = ({ pid: 7 cpu: 2 ok: true } | columns | split list cpu | get 1 | is-not-empty)'
            '  let group0_empty_ok = not ({ pid: 7 cpu: 2 ok: true } | columns | split list cpu | get 0 | is-empty)'
            '  $direct_length_ok and ($direct_last_desc_ok and ($group0_length_ok and ($group1_not_empty_ok and $group0_empty_ok)))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-columns-split-list-predicates"
        category: "language-core"
        tags: [aggregate record columns list split-list get length is-empty is-not-empty metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let split = ({ pid: 7 cpu: 2 ok: true } | columns | split list cpu)'
            '  let direct_not_empty_ok = not ($split | is-empty)'
            '  let group1_length_ok = (($split | get 1 | length) == 1)'
            '  let group1_not_empty_ok = not ($split | get 1 | is-empty)'
            '  let group0_not_empty_ok = ($split | get 0 | is-not-empty)'
            '  $direct_not_empty_ok and ($group1_length_ok and ($group1_not_empty_ok and $group0_not_empty_ok))'
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
        name: "core-record-empty-metadata-list-first-last"
        category: "language-core"
        tags: [aggregate record columns values list empty first last is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let columns_first = ({} | columns | first | is-empty)'
            '  let columns_last = ({} | columns | last | is-empty)'
            '  let values_first = ({} | values | first | is-empty)'
            '  let values_last = ({} | values | last | is-empty)'
            '  $columns_first and ($columns_last and ($values_first and $values_last))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-empty-metadata-list-counted-first-last"
        category: "language-core"
        tags: [aggregate record columns values list empty first last count is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let columns_first = ({} | columns | first 1 | is-empty)'
            '  let columns_last = ({} | columns | last 1 | is-empty)'
            '  let values_first = ({} | values | first 1 | is-empty)'
            '  let values_last = ({} | values | last 1 | is-empty)'
            '  $columns_first and ($columns_last and ($values_first and $values_last))'
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
        name: "core-record-transpose-describe-metadata"
        category: "language-core"
        tags: [aggregate record transpose describe metadata-only as-record ignore-titles]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let table_desc = ({ pid: 7 cpu: 2 } | transpose key value | describe)'
            '  let record_desc = ({ pid: 7 cpu: 2 } | transpose --as-record key value | describe)'
            '  let ignored_desc = ({ pid: 7 cpu: 2 } | transpose --ignore-titles val | describe)'
            '  let ignored_record_desc = ({ pid: 7 cpu: 2 } | transpose --as-record --ignore-titles val | describe)'
            '  ($table_desc | str starts-with "table<key: string, value: int>") and (($record_desc | str starts-with "record<key: list<string>, value: list<int>>") and (($ignored_desc | str starts-with "table<val: int>") and ($ignored_record_desc | str starts-with "record<val: list<int>>")))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-transpose-default-describe-metadata"
        category: "language-core"
        tags: [aggregate record transpose describe metadata-only as-record ignore-titles defaults]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let record_desc = ({ pid: 7 cpu: 2 } | transpose --as-record | describe)'
            '  let ignored_record_desc = ({ pid: 7 cpu: 2 } | transpose --as-record --ignore-titles | describe)'
            '  ($record_desc | str starts-with "record<column0: list<string>, column1: list<int>>") and ($ignored_record_desc | str starts-with "record<column0: list<int>>")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
