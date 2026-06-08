const VERIFIER_DIFF_FIXTURES_2063_2125 = [
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
    {
        name: "core-runtime-list-describe"
        category: "language-core"
        tags: [describe aggregate list runtime string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = random int'
            '  seq 10 10 20 | append $n | describe | str starts-with "list<int>"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-values-heterogeneous-reject"
        category: "language-core"
        tags: [aggregate record values reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 comm: "nu" } | values'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "values supports only numeric scalar record fields"
    }
    {
        name: "core-record-transpose-runtime-reject"
        category: "language-core"
        tags: [aggregate record transpose reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: $ctx.pid } | transpose key value'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "transpose requires compile-time known record values"
    }
    {
        name: "core-record-insert-field"
        category: "language-core"
        tags: [aggregate record insert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 } | insert mem 9)'
            '  $rec.mem'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-update-field"
        category: "language-core"
        tags: [aggregate record update]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 } | update pid 9)'
            '  $rec.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-missing-field"
        category: "language-core"
        tags: [aggregate record upsert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 } | upsert mem 9)'
            '  $rec.mem'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-existing-field"
        category: "language-core"
        tags: [aggregate record upsert]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 cpu: 2 } | upsert pid 9)'
            '  $rec.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-insert-existing-reject"
        category: "language-core"
        tags: [aggregate record insert reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 cpu: 2 } | insert pid 9'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "insert cannot replace existing record field 'pid'"
    }
    {
        name: "core-record-update-missing-reject"
        category: "language-core"
        tags: [aggregate record update reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { pid: 7 cpu: 2 } | update mem 9'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "update cannot find record field 'mem'"
    }
    {
        name: "core-null-default"
        category: "language-core"
        tags: ["null" default]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  null | default 9'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-default-missing-field"
        category: "language-core"
        tags: [aggregate record default]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: 7 } | default 2 cpu)'
            '  $rec.cpu'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-default-null-field"
        category: "language-core"
        tags: [aggregate record default "null"]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let rec = ({ pid: null cpu: 2 } | default 7 pid)'
            '  $rec.pid'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-default-empty"
        category: "language-core"
        tags: [string default empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "" | default --empty "x" | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-upsert-local"
        category: "language-core"
        tags: [aggregate list upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut xs = [1 2 3]'
            '  $xs.1 = 7'
            '  $xs.1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-new-list-field-local"
        category: "language-core"
        tags: [aggregate record list upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0 = 7'
            '  $rec.a.0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-numeric-list-existing-index-local"
        category: "language-core"
        tags: [aggregate record list upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0 = 3'
            '  $rec.a.0 = 7'
            '  $rec.a.0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-numeric-list-append-local"
        category: "language-core"
        tags: [aggregate record list upsert append local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0 = 3'
            '  $rec.a.1 = 7'
            '  $rec.a.0 + $rec.a.1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-numeric-list-sparse-append-reject"
        category: "language-core"
        tags: [aggregate record list upsert append reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0 = 3'
            '  $rec.a.2 = 7'
            '  $rec.a.0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "can only update an existing numeric list item or append at the next index"
    }
    {
        name: "core-record-upsert-new-record-list-field-local"
        category: "language-core"
        tags: [aggregate record list upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0.b = 7'
            '  $rec.a.0.b'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-new-record-list-element-local"
        category: "language-core"
        tags: [aggregate record list upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0 = { b: 3, c: 4 }'
            '  $rec.a.0.b + $rec.a.0.c'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-record-list-new-element-field-local"
        category: "language-core"
        tags: [aggregate record list upsert local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0.b = 3'
            '  $rec.a.0.c = 7'
            '  $rec.a.0.b + $rec.a.0.c'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-record-list-append-local"
        category: "language-core"
        tags: [aggregate record list upsert append local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0.b = 3'
            '  $rec.a.1.b = 7'
            '  $rec.a.0.b + $rec.a.1.b'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-record-list-element-append-local"
        category: "language-core"
        tags: [aggregate record list upsert append local]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0 = { b: 3, c: 4 }'
            '  $rec.a.1 = { b: 7, c: 8 }'
            '  $rec.a.0.b + $rec.a.1.c'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-upsert-record-list-heterogeneous-append-reject"
        category: "language-core"
        tags: [aggregate record list upsert append reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0.b = 3'
            '  $rec.a.1.c = 7'
            '  $rec.a.1.c'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "can only append homogeneous fixed record array elements"
    }
    {
        name: "core-record-upsert-record-list-element-append-mismatch-reject"
        category: "language-core"
        tags: [aggregate record list upsert append reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.a.0 = { b: 3 }'
            '  $rec.a.1 = { b: 7, c: 8 }'
            '  $rec.a.1.b'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "can only append homogeneous fixed record array elements"
    }
]
