const VERIFIER_DIFF_FIXTURES_0813_0875 = [
    {
        name: "socket-filter-cb-context-write"
        category: "context-surface"
        tags: [socket-filter context writable]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.cb.1 = 7'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "socket-filter-rejects-mark-context-write"
        category: "context-policy"
        tags: [socket-filter context writable reject]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.mark is read-only"
    }
    {
        name: "cgroup-skb-egress-context"
        category: "context-surface"
        tags: [cgroup-skb context]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.protocol + $ctx.mark + $ctx.priority + $ctx.remote_ip4 + $ctx.local_port + $ctx.sk.cgroup_id + $ctx.sk.ancestor_cgroup_id.0) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-skb-rich-egress-context"
        category: "context-surface"
        tags: [cgroup-skb context egress source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.ingress_ifindex + $ctx.ifindex + $ctx.tc_index + $ctx.hash + $ctx.tstamp + $ctx.hwtstamp) | count'
            '  (($ctx.remote_ip6 | get 0) + ($ctx.local_ip6 | get 1) + $ctx.family + $ctx.socket_cookie + $ctx.socket_uid + $ctx.netns_cookie) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-skb-egress-timestamp-context-write"
        category: "context-surface"
        tags: [cgroup-skb context writable timestamp egress]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.tstamp + $ctx.hwtstamp + $ctx.priority) | count'
            '  $ctx.tstamp = 123'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-skb-ingress-rejects-tstamp-write"
        category: "context-policy"
        tags: [cgroup-skb context reject writable ingress]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:ingress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.tstamp = 123'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.tstamp is only writable on tc_action, tc, tcx, netkit, and cgroup_skb:egress programs"
    }
    {
        name: "cgroup-skb-ingress-writable-context"
        category: "context-surface"
        tags: [cgroup-skb context writable]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:ingress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 7'
            '  $ctx.priority = 3'
            '  $ctx.cb.0 = 1'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-create-context-write"
        category: "context-surface"
        tags: [cgroup-sock context writable]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:sock_create"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.family + $ctx.sock_type + $ctx.protocol + $ctx.state + $ctx.rx_queue_mapping + $ctx.socket_cookie + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.bound_dev_if = 1'
            '  $ctx.mark = 7'
            '  $ctx.priority = 3'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-release-context-write"
        category: "context-surface"
        tags: [cgroup-sock context writable]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:sock_release"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.bound_dev_if = 1'
            '  $ctx.mark = 7'
            '  $ctx.priority = 3'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-post-bind6-context"
        category: "context-surface"
        tags: [cgroup-sock context ipv6]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind6"
        program: [
            '{|ctx|'
            '  (($ctx.local_ip6 | get 1) + ($ctx.sk.local_ip6 | get 1) + $ctx.local_port + $ctx.sk.remote_port) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-socket-root-alias-context"
        category: "context-surface"
        tags: [cgroup-sock context socket alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  ($ctx.sock.local_port + $ctx.socket.remote_port) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-rejects-post-bind-mark-write"
        category: "context-policy"
        tags: [cgroup-sock reject writable]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 7'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.mark is only writable on cgroup_sock sock_create/sock_release hooks"
    }
    {
        name: "cgroup-sock-rejects-post-bind-bound-dev-if-write"
        category: "context-policy"
        tags: [cgroup-sock reject writable]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.bound_dev_if = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.bound_dev_if is only writable on cgroup_sock sock_create/sock_release hooks"
    }
    {
        name: "cgroup-sock-rejects-post-bind-priority-write"
        category: "context-policy"
        tags: [cgroup-sock reject writable]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.priority = 3'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.priority is only writable on cgroup_sock sock_create/sock_release hooks"
    }
    {
        name: "cgroup-sock-rejects-create-local-ip4"
        category: "context-policy"
        tags: [cgroup-sock reject]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:sock_create"
        program: [
            '{|ctx|'
            '  $ctx.local_ip4 | count'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.local_ip4 is only available on cgroup_sock post_bind4"
    }
    {
        name: "cgroup-sock-rejects-post-bind4-src-ip6"
        category: "context-policy"
        tags: [cgroup-sock reject ipv6]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  ($ctx.sk.src_ip6 | get 0) | count'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk.src_ip6 is only available on cgroup_sock post_bind6 hooks"
    }
    {
        name: "cgroup-sock-addr-rejects-connect4-local-port"
        category: "context-policy"
        tags: [cgroup-sock-addr reject]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  $ctx.local_port | count'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.local_port is only available on cgroup_sock_addr bind4/bind6 and getsockname4/getsockname6 hooks"
    }
    {
        name: "cgroup-sock-addr-rejects-connect4-local-ip4-write"
        category: "context-policy"
        tags: [cgroup-sock-addr reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.local_ip4 = 2130706433'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bind4/bind6, getsockname4/getsockname6, and sendmsg4/sendmsg6"
    }
    {
        name: "cgroup-sock-addr-rejects-connect6-user-ip4-write"
        category: "context-policy"
        tags: [cgroup-sock-addr reject context writable ipv4]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect6"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.user_ip4 = 2130706433'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.user_ip4 is only available on IPv4 cgroup_sock_addr hooks"
    }
    {
        name: "cgroup-sock-addr-rejects-connect4-user-ip6-write"
        category: "context-policy"
        tags: [cgroup-sock-addr reject context writable ipv6]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.user_ip6.0 = 42'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.user_ip6 is only available on IPv6 cgroup_sock_addr hooks"
    }
    {
        name: "cgroup-sock-addr-rejects-unix-remote-port-write"
        category: "context-policy"
        tags: [cgroup-sock-addr reject context writable unix]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.remote_port = 8080'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.remote_port is only available on IPv4/IPv6 cgroup_sock_addr hooks"
    }
    {
        name: "cgroup-sock-addr-rejects-user-family-write"
        category: "context-policy"
        tags: [cgroup-sock-addr reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.user_family = 2'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.user_family is read-only"
    }
    {
        name: "cgroup-sock-addr-connect4-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  ($ctx.user_ip4 + $ctx.user_port + $ctx.remote_ip4 + $ctx.remote_port + $ctx.sk.family) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-socket-root-alias-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context socket alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  ($ctx.sock.family + $ctx.socket.remote_port) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-connect4-writable-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context writable]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.remote_ip4 = 2130706433'
            '  $ctx.remote_port = 8080'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-connect4-alias-writable-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context writable alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  mut event = $ctx'
            '  $event.remote_ip4 = 2130706433'
            '  $event.remote_port = 8080'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-connect6-indexed-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context ipv6]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect6"
        program: [
            '{|ctx|'
            '  (($ctx.user_ip6 | get 3) + ($ctx.remote_ip6 | get 3) + $ctx.user_port + $ctx.remote_port) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-getpeername4-writable-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context writable source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:getpeername4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.remote_ip4 = 2130706433'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-getsockname6-writable-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context writable ipv6 source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:getsockname6"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.local_ip6.1 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-getsockname6-alias-writable-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context writable ipv6 alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:getsockname6"
        program: [
            '{|ctx|'
            '  mut event = $ctx'
            '  $event.local_ip6.1 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-sendmsg6-writable-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context writable ipv6 source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:sendmsg6"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.msg_src_ip6.3 = 42'
            '  $ctx.local_ip6.2 = 24'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
