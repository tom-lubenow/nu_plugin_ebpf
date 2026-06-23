const VERIFIER_DIFF_FIXTURES_2063_2093_D = [
    {
        name: "core-record-list-nested-list-field-get"
        category: "language-core"
        tags: [aggregate record list nested get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([{ samples: [1 2] } { samples: [3 4] }] | get 1 | get samples | get 0) == 3'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-list-field-get"
        category: "language-core"
        tags: [aggregate record list get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] | get 1 | get cpu) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-list-each-field-get"
        category: "language-core"
        tags: [aggregate record list each get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] | each {|row| $row.pid } | get 1) == 9)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-list-each-nested-list-field-get"
        category: "language-core"
        tags: [aggregate record list nested each get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([{ samples: [1 2] } { samples: [3 4] }] | each {|row| $row.samples.1 } | get 1) == 4)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-list-string-field-get"
        category: "language-core"
        tags: [aggregate record list string get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([{ name: "aa" } { name: "bbb" }] | get 1 | get name | str length) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-list-each-string-field-length"
        category: "language-core"
        tags: [aggregate record list string each get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([{ name: "aa" } { name: "bbb" }] | each {|row| $row.name | str length } | get 1) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-list-each-binary-field-length"
        category: "language-core"
        tags: [aggregate record list binary bytes each get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([{ payload: 0x[01 02] } { payload: 0x[03 04] }] | each {|row| $row.payload | bytes length } | get 1) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-list-binary-field-bytes-length-cell-path"
        category: "language-core"
        tags: [aggregate record list binary bytes length cell-path get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([{ payload: 0x[01 02] } { payload: 0x[03 04 05] }] | bytes length payload | get 1 | get payload) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-list-each-nested-record-field-get"
        category: "language-core"
        tags: [aggregate record list nested each get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([{ path: { mnt: 1 dentry: 2 } } { path: { mnt: 3 dentry: 4 } }] | each {|row| $row.path.mnt } | get 1) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-binary-field-length"
        category: "language-core"
        tags: [aggregate record binary get bytes length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (({ payload: 0x[01 02] pid: 7 } | get payload | bytes length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-nested-list-field-get"
        category: "language-core"
        tags: [aggregate record list get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (({ numbers: [1 2] } | get numbers | get 1) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-nested-record-list-field-get"
        category: "language-core"
        tags: [aggregate record list nested get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (({ entries: [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] } | get entries | get 1 | get cpu) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-nested-record-list-each-field-get"
        category: "language-core"
        tags: [aggregate record list nested each get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (({ entries: [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] } | get entries | each {|row| $row.cpu } | get 1) == 3)'
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
