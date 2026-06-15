const VERIFIER_DIFF_FIXTURES_0844_0875_A_B = [
    {
        name: "source-kfunc-sock-addr-set-sun-path-accepts-raw-context"
        category: "kfunc"
        tags: [cgroup-sock-addr kfunc unix source accept]
        requires: [cgroup-v2 kernel-btf]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  let path = "/tmp/nu-ebpf.sock"'
            '  kfunc-call "bpf_sock_addr_set_sun_path" $ctx $path 17'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-sock-addr-set-sun-path-accepts-copied-raw-context"
        category: "kfunc"
        tags: [cgroup-sock-addr kfunc unix source accept context-alias]
        requires: [cgroup-v2 kernel-btf]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  let raw_ctx = $ctx'
            '  let path = "/tmp/nu-ebpf.sock"'
            '  kfunc-call "bpf_sock_addr_set_sun_path" $raw_ctx $path 17'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-sock-addr-set-sun-path-user-function-raw-context"
        category: "kfunc"
        tags: [cgroup-sock-addr kfunc unix source accept user-function]
        requires: [cgroup-v2 kernel-btf]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  def set_path [raw_ctx] {'
            '    let path = "/tmp/nu-ebpf.sock"'
            '    kfunc-call "bpf_sock_addr_set_sun_path" $raw_ctx $path 17'
            '    0'
            '  }'
            '  set_path $ctx'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-sock-addr-set-sun-path-returned-raw-context"
        category: "kfunc"
        tags: [cgroup-sock-addr kfunc unix source accept user-function metadata]
        requires: [cgroup-v2 kernel-btf]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  def get_ctx [event] { $event }'
            '  let raw_ctx = (get_ctx $ctx)'
            '  let path = "/tmp/nu-ebpf.sock"'
            '  kfunc-call "bpf_sock_addr_set_sun_path" $raw_ctx $path 17'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-sock-addr-set-sun-path-rejects-socket-arg"
        category: "kfunc"
        tags: [cgroup-sock-addr kfunc unix source reject]
        requires: [cgroup-v2 kernel-btf]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  let path = "/tmp/nu-ebpf.sock"'
            '  kfunc-call "bpf_sock_addr_set_sun_path" $ctx.sk $path 17'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_sock_addr_set_sun_path' arg0 expects bpf_sock_addr pointer"
    }
    {
        name: "source-helper-bind-cgroup-sock-addr-connect4"
        category: "helper-state"
        tags: [helper-call cgroup-sock-addr socket-option source accept]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  let addr = "0123456789abcdef"'
            '  helper-call "bpf_bind" $ctx $addr 16'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-bind-rejects-non-connect-hook"
        category: "helper-state"
        tags: [helper-call cgroup-sock-addr socket-option source reject]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:getpeername4"
        program: [
            '{|ctx|'
            '  let addr = "0123456789abcdef"'
            '  helper-call "bpf_bind" $ctx $addr 16'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_bind' is only valid on cgroup_sock_addr connect4/connect6 hooks"
    }
    {
        name: "flow-dissector-flow-key-context"
        category: "context-surface"
        tags: [flow-dissector context]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  ($ctx.flow_keys.ip_proto + $ctx.flow_keys.nhoff + $ctx.flow_keys.thoff + ($ctx.flow_keys.ipv6_dst | get 3)) | count'
            '  "fallback"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-bound-flow-key-context"
        category: "context-surface"
        tags: [flow-dissector context alias source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  let keys = $ctx.flow_keys'
            '  ($keys.addr_proto + $keys.is_frag + $keys.is_first_frag + $keys.is_encap + $keys.n_proto + $keys.sport + $keys.dport + $keys.ipv4_src + $keys.ipv4_dst + $keys.flags + $keys.flow_label) | count'
            '  (($keys.ipv6_src | get 0) + ($keys.ipv6_dst | get 3)) | count'
            '  "fallback"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
