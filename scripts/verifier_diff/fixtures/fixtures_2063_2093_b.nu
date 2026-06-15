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
