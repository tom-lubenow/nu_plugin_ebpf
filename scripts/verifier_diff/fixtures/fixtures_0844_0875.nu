const VERIFIER_DIFF_FIXTURES_0844_0875 = [
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
    {
        name: "flow-dissector-flow-key-alias-context"
        category: "context-surface"
        tags: [flow-dissector context alias source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  let keys = $ctx.flow_keys'
            '  ($keys.protocol + $keys.transport_header_offset + $keys.src_port + $keys.destination_ip4 + ($keys.dst_ip6 | get 3)) | count'
            '  "fallback"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.flow_keys.ip_proto = 6'
            '  $ctx.flow_keys.nhoff = 14'
            '  $ctx.flow_keys.ipv6_dst.3 = 1'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-flow-key-alias-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable alias source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut keys = $ctx.flow_keys'
            '  $keys.protocol = 6'
            '  $keys.network_header_offset = 14'
            '  $keys.dst_ip6.3 = 1'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-bound-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable alias source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut keys = $ctx.flow_keys'
            '  $keys.ip_proto = 17'
            '  $keys.ipv6_src.0 = 1'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-bound-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable alias get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut keys = ($ctx | get flow_keys)'
            '  $keys.ip_proto = 17'
            '  $keys.ipv6_src.0 = 1'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-user-function-returned-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable user-function alias source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  def get_keys [event] { $event.flow_keys }'
            '  mut keys = (get_keys $ctx)'
            '  $keys.ip_proto = 17'
            '  $keys.ipv6_src.0 = 1'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-user-function-returned-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable user-function alias get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  def get_keys [event] { $event | get flow_keys }'
            '  mut keys = (get_keys $ctx)'
            '  $keys.ip_proto = 17'
            '  $keys.ipv6_src.0 = 1'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = { keys: $ctx.flow_keys }'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = { keys: ($ctx | get flow_keys) }'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-pipeline-upsert-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record pipeline upsert get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert keys ($ctx | get flow_keys))'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-pipeline-insert-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record pipeline insert get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | insert keys ($ctx | get flow_keys))'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-pipeline-merge-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record pipeline merge get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | merge { keys: ($ctx | get flow_keys) })'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-pipeline-default-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record pipeline default get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | default ($ctx | get flow_keys) keys)'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-pipeline-update-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record pipeline update get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ keys: null } | update keys ($ctx | get flow_keys))'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-pipeline-select-reject-rename-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record pipeline select reject rename get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ keys: ($ctx | get flow_keys), keep: 1 } | select keys keep | reject keep | rename parsed)'
            '  $rec.parsed.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-spread-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record spread source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  let base = { keys: $ctx.flow_keys }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
