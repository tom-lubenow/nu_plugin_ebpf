const VERIFIER_DIFF_FIXTURES_2063_2093_A = [
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
]
