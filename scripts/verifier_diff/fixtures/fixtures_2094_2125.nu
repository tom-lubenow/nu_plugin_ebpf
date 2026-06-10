const VERIFIER_DIFF_FIXTURES_2094_2125 = [
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
