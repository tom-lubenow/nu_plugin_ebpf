const VERIFIER_DIFF_FIXTURES_2063_2093 = [
    {
        name: "core-record-rename-fields"
        category: "language-core"
        tags: [aggregate record rename]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 ok: true } | rename tid core)'
            '  $rec.tid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-rename-trailing-fields"
        category: "language-core"
        tags: [aggregate record rename]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 ok: true } | rename tid)'
            '  $rec.cpu'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-rename-column-fields"
        category: "language-core"
        tags: [aggregate record rename column]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 ok: true } | rename --column { pid: tid ok: status })'
            '  $rec.tid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-rename-column-trailing-fields"
        category: "language-core"
        tags: [aggregate record rename column]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 ok: true } | rename --column { pid: tid })'
            '  $rec.cpu'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-rename-column-missing-reject"
        category: "language-core"
        tags: [aggregate record rename column]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 } | rename --column { cpu: core }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "rename --column cannot find record field 'cpu'"
    }
    {
        name: "core-record-rename-block-fields"
        category: "language-core"
        tags: [aggregate record rename block]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 } | rename --block { str upcase })'
            '  $rec.PID'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-merge-add-field"
        category: "language-core"
        tags: [aggregate record merge]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 } | merge { mem: 9 })'
            '  $rec.mem'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-merge-overwrite-field"
        category: "language-core"
        tags: [aggregate record merge]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 } | merge { pid: 9 mem: 4 })'
            '  $rec.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-merge-non-record-reject"
        category: "language-core"
        tags: [aggregate record merge reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 cpu: 2 } | merge $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "merge requires a record argument with compiler-known fields"
    }
    {
        name: "core-record-values-get"
        category: "language-core"
        tags: [aggregate record values list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 cpu: 2 } | values | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-bool-get"
        category: "language-core"
        tags: [aggregate record values list bool]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 ok: true } | values | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-null-get"
        category: "language-core"
        tags: [aggregate record values list "null"]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ({ pid: 7 none: null } | values | get 1) == 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-runtime-bool-get"
        category: "language-core"
        tags: [aggregate record values list bool runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { ok: ($ctx.pid > 0) pid: $ctx.pid } | values | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-after-merge"
        category: "language-core"
        tags: [aggregate record values merge list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 cpu: 2 } | merge { mem: 9 } | values | get 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-string-get"
        category: "language-core"
        tags: [aggregate record values list string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { comm: "nu" exe: "bash" } | values | get 1 | str starts-with "bash"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
        name: "core-describe-known-record"
        category: "language-core"
        tags: [describe aggregate record string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 cpu: 2 } | describe | str starts-with "record<pid: int, cpu: int>"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
