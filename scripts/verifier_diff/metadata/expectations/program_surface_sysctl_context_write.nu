let PROGRAM_SURFACE_SYSCTL_CONTEXT_WRITE_KERNEL_FEATURE_EXPECTATIONS = [
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|event|'
            '  $event.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sysctl_set_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut writable = $ctx'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sysctl_set_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut writable = ($ctx)'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sysctl_set_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  def passthrough [event] {'
            '    let actual = $event'
            '    $actual'
            '  }'
            '  mut writable = (passthrough $ctx)'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sysctl_set_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sysctl_set_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let text = "$ctx.new_value = 1"'
            '  # $ctx.new_value = 1'
            '  if $ctx.new_value == 1 { 0 }'
            '  "allow"'
            '}'
        ]
        feature_keys: []
    }
]
