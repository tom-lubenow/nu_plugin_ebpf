const VERIFIER_DIFF_FIXTURES_0844_0875_A = [
    {
        name: "cgroup-sock-addr-unix-sun-path-write"
        category: "context-surface"
        tags: [cgroup-sock-addr context unix writable kfunc source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-unix-sun-path-alias-write"
        category: "context-surface"
        tags: [cgroup-sock-addr context unix writable kfunc alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut event = $ctx'
            '  $event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-unix-sun-path-user-function-returned-context-write"
        category: "context-surface"
        tags: [cgroup-sock-addr context unix writable kfunc user-function alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  def get_event [event] { $event }'
            '  mut event = (get_event $ctx)'
            '  $event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-unix-sun-path-record-write"
        category: "context-surface"
        tags: [cgroup-sock-addr context unix writable kfunc record source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-unix-sun-path-record-upsert-write"
        category: "context-surface"
        tags: [cgroup-sock-addr context unix writable kfunc record upsert source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.event = $ctx'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-unix-sun-path-record-spread-write"
        category: "context-surface"
        tags: [cgroup-sock-addr context unix writable kfunc record spread source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  let base = { event: $ctx }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-unix-sun-path-user-function-record-write"
        category: "context-surface"
        tags: [cgroup-sock-addr context unix writable kfunc record user-function source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  def wrap [event] { { event: $event } }'
            '  mut rec = (wrap $ctx)'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
