const VERIFIER_DIFF_FIXTURES_0938_0968_A_B = [
    {
        name: "cgroup-sysctl-new-value-write"
        category: "context-surface"
        tags: [cgroup-sysctl context writable]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.file_pos = 0'
            '  $ctx.new_value = "1"'
            '  $ctx.name | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-new-value-alias-write"
        category: "context-surface"
        tags: [cgroup-sysctl context writable alias]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut writable = $ctx'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-new-value-record-write"
        category: "context-surface"
        tags: [cgroup-sysctl context writable record source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.new_value = "1"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-base-name-context"
        category: "context-surface"
        tags: [cgroup-sysctl context helper-backed alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.write + $ctx.file_pos) | count'
            '  $ctx.base_name | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-new-value-parenthesized-alias-write"
        category: "context-surface"
        tags: [cgroup-sysctl context writable alias parenthesized source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut writable = ($ctx)'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-user-function-returned-context-new-value-write"
        category: "context-surface"
        tags: [cgroup-sysctl context writable user-function alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  def get_event [event] { $event }'
            '  mut writable = (get_event $ctx)'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
