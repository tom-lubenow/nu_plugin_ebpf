const VERIFIER_DIFF_FIXTURES_0938_0968_A = [
    {
        name: "cgroup-skb-bound-listener-helper-pointer"
        category: "context-surface"
        tags: [cgroup-skb context alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  let listener = $ctx.sk.listener'
            '  if $listener {'
            '    $listener.family | count'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-skb-socket-helper-root-alias-context"
        category: "context-surface"
        tags: [cgroup-skb context socket alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  let listener = $ctx.sock.listener'
            '  let full = $ctx.socket.full'
            '  if $listener {'
            '    $listener.family | count'
            '  }'
            '  if $full {'
            '    $full.family | count'
            '  }'
            '  ($ctx.sock.cgroup_id + $ctx.socket.ancestor_cgroup_id.0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-device-context"
        category: "context-surface"
        tags: [cgroup-device context]
        requires: [cgroup-v2]
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.access_type + $ctx.device_access + $ctx.device_type + $ctx.major + $ctx.minor) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-device-current-context"
        category: "context-surface"
        tags: [cgroup-device context current]
        requires: [cgroup-v2]
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.cpu + $ctx.ktime + $ctx.cgroup_id) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-device-rejects-packet-context"
        category: "context-policy"
        tags: [cgroup-device reject context]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.access_type | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.access_type is only available on cgroup_device programs"
    }
    {
        name: "cgroup-device-rejects-major-write"
        category: "context-policy"
        tags: [cgroup-device reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.major = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.major is read-only"
    }
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
    {
        name: "cgroup-sysctl-current-value-context"
        category: "context-surface"
        tags: [cgroup-sysctl context helper-backed]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx.current_value | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-new-value-context"
        category: "context-surface"
        tags: [cgroup-sysctl context helper-backed]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx.new_value | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-new-value-parenthesized-alias-read"
        category: "context-surface"
        tags: [cgroup-sysctl context helper-backed alias parenthesized source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let readable = ($ctx)'
            '  $readable.new_value | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
