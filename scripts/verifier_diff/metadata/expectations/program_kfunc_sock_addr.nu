const PROGRAM_KFUNC_SOCK_ADDR_KERNEL_FEATURE_EXPECTATIONS = [
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup_unix:connect4"
        program: [
            '{|event|'
            '  $event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|event|'
            '  $event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["kfunc:bpf_sock_addr_set_sun_path"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["kfunc:bpf_sock_addr_set_sun_path"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.event = $ctx'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["kfunc:bpf_sock_addr_set_sun_path"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  let base = { event: $ctx }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["kfunc:bpf_sock_addr_set_sun_path"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  def wrap [event] { { event: $event } }'
            '  mut rec = (wrap $ctx)'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["kfunc:bpf_sock_addr_set_sun_path"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|event|'
            '  let text = "$event.sun_path = /tmp/nu-ebpf.sock"'
            '  # $event.sun_path = /tmp/nu-ebpf.sock'
            '  if $event.sun_path == "/tmp/nu-ebpf.sock" { 0 }'
            '  "allow"'
            '}'
        ]
        feature_keys: []
    }
]
