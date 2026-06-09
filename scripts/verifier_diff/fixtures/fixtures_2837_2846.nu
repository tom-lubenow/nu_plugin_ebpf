const VERIFIER_DIFF_FIXTURES_2837_2846 = [
    {
        name: "cgroup-sysctl-new-value-rejects-integer"
        category: "context-policy"
        tags: [cgroup-sysctl context diagnostics reject update value]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut event = $ctx'
            '  $event.new_value = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "context cell path update '.new_value = ...' requires a string or binary byte-buffer value, got I64"
    }
    {
        name: "cgroup-sysctl-file-pos-rejects-string"
        category: "context-policy"
        tags: [cgroup-sysctl context diagnostics reject update value]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.file_pos = "x"'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "context cell path update '.file_pos = ...' requires an integer-compatible scalar value"
    }
    {
        name: "cgroup-sysctl-file-pos-rejects-nested-write"
        category: "context-policy"
        tags: [cgroup-sysctl context diagnostics reject update path]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.file_pos.foo = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "context cell path update '.file_pos.foo = ...' only supports a direct writable field or a fixed integer index"
    }
    {
        name: "cgroup-sysctl-file-pos-rejects-index-write"
        category: "context-policy"
        tags: [cgroup-sysctl context diagnostics reject update index]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.file_pos.0 = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.file_pos does not support indexed assignment"
    }
    {
        name: "cgroup-sock-addr-sun-path-rejects-empty-string"
        category: "context-policy"
        tags: [cgroup-sock-addr context unix diagnostics reject update path]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sun_path = ""'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "context cell path update '.sun_path = ...' requires a non-empty UNIX socket path"
    }
    {
        name: "cgroup-sock-addr-sun-path-rejects-integer"
        category: "context-policy"
        tags: [cgroup-sock-addr context unix diagnostics reject update value]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sun_path = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "context cell path update '.sun_path = ...' requires a string or binary byte-buffer value, got I64"
    }
    {
        name: "cgroup-sock-addr-sun-path-rejects-too-long"
        category: "context-policy"
        tags: [cgroup-sock-addr context unix diagnostics reject update bounds]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sun_path = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "context cell path update '.sun_path = ...' UNIX socket path is too long (max 108 bytes)"
    }
    {
        name: "cgroup-sockopt-optval-byte-rejects-string"
        category: "context-policy"
        tags: [cgroup-sockopt context diagnostics reject update value]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optval.0 = "x"'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "context cell path update '.optval.0 = ...' requires an integer-compatible scalar value"
    }
    {
        name: "cgroup-sockopt-optval-rejects-huge-index"
        category: "context-policy"
        tags: [cgroup-sockopt context diagnostics reject update index]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optval.-1 = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "context cell path update '.optval.18446744073709551615 = ...' index is too large"
    }
    {
        name: "cgroup-sockopt-optval-alias-rejects-named-index"
        category: "context-policy"
        tags: [cgroup-sockopt context diagnostics reject update alias index]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  mut optval = $ctx.optval'
            '  $optval.foo = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cell path update '.foo = ...' for a ctx.optval alias requires a fixed integer byte index"
    }
]
