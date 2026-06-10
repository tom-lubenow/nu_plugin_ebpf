const VERIFIER_DIFF_FIXTURES_1001_1031 = [
    {
        name: "sk-reuseport-rejects-migrating-sk-on-packet-context"
        category: "context-policy"
        tags: [sk-reuseport reject context]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.migrating_sk | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.migrating_sk is only available on sk_reuseport programs"
    }
    {
        name: "sk-reuseport-rejects-sk-assignment"
        category: "context-policy"
        tags: [sk-reuseport reject context writable]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk is read-only"
    }
    {
        name: "sk-reuseport-rejects-skb-pkt-type-context"
        category: "context-policy"
        tags: [sk-reuseport reject context packet]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  $ctx.pkt_type | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.pkt_type is only available on socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, and sk_skb_parser programs"
    }
    {
        name: "sk-reuseport-rejects-skb-vlan-context"
        category: "context-policy"
        tags: [sk-reuseport reject context packet]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  $ctx.vlan_tci | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.vlan_tci is only available on socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, and sk_skb_parser programs"
    }
    {
        name: "sk-lookup-context-clear-socket"
        category: "context-surface"
        tags: [sk-lookup context writable]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.family + $ctx.ip_protocol + $ctx.local_port + $ctx.remote_port + $ctx.cookie + $ctx.ingress_ifindex + $ctx.sk.family) | count'
            '  $ctx.sk = 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-lookup-context-clear-socket-aliases"
        category: "context-surface"
        tags: [sk-lookup context writable socket alias]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sock = 0'
            '  $ctx.socket = 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-lookup-tuple-cookie-context"
        category: "context-surface"
        tags: [sk-lookup context source metadata]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  ($ctx.family + $ctx.protocol + $ctx.ip_protocol + $ctx.remote_ip4 + $ctx.local_ip4 + $ctx.remote_port + $ctx.local_port + $ctx.cookie + $ctx.ingress_ifindex) | count'
            '  (($ctx.remote_ip6 | get 0) + ($ctx.local_ip6 | get 3)) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-lookup-bound-socket-projection-context"
        category: "context-surface"
        tags: [sk-lookup context socket source metadata]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  ($sk.family + $sk.local_port + $sk.remote_port + $sk.priority) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-lookup-socket-root-alias-context"
        category: "context-surface"
        tags: [sk-lookup context socket alias source metadata]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  let sock = $ctx.sock'
            '  ($sock.family + $ctx.socket.dst_port + $sock.priority) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-lookup-rejects-socket-cookie-context"
        category: "context-policy"
        tags: [sk-lookup reject context socket]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx.socket_cookie | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.socket_cookie is only available"
    }
    {
        name: "sk-lookup-rejects-socket-uid-context"
        category: "context-policy"
        tags: [sk-lookup reject context socket]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx.socket_uid | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.socket_uid is only available"
    }
    {
        name: "sk-lookup-rejects-packet-data-context"
        category: "context-policy"
        tags: [sk-lookup reject context packet]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx.data | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.data"
    }
    {
        name: "sk-lookup-rejects-sk-indexed-assignment"
        category: "context-policy"
        tags: [sk-lookup reject context writable]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk.0 = 0'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk does not support indexed assignment"
    }
    {
        name: "sk-msg-basic-context"
        category: "context-surface"
        tags: [sk-msg context]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.size + $ctx.family + $ctx.local_port + $ctx.remote_port + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-msg-rich-context"
        category: "context-surface"
        tags: [sk-msg context packet socket source metadata]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.len + $ctx.size + $ctx.remote_ip4 + $ctx.local_ip4 + ($ctx.remote_ip6 | get 0) + ($ctx.local_ip6 | get 1)) | count'
            '  if $ctx.data_end { 1 | count }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-msg-bound-socket-projection-context"
        category: "context-surface"
        tags: [sk-msg context socket source metadata]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  ($sk.src_port + $sk.dst_port + $sk.priority) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-msg-socket-root-alias-context"
        category: "context-surface"
        tags: [sk-msg context socket alias source metadata]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.sock.src_port + $ctx.socket.dst_port + $ctx.socket.priority) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-msg-data-context-write"
        category: "context-surface"
        tags: [sk-msg context packet writable]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.data | get 0) | count'
            '  $ctx.data.0 = 42'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-msg-rejects-fullsock-projection"
        category: "context-policy"
        tags: [sk-msg reject socket helper-backed]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  $ctx.sk.full.family | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_fullsock' is only valid"
    }
    {
        name: "sk-msg-rejects-socket-uid-context"
        category: "context-policy"
        tags: [sk-msg reject context socket]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  $ctx.socket_uid | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.socket_uid is only available on socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, and sk_skb_parser programs"
    }
    {
        name: "sk-msg-rejects-sk-assignment"
        category: "context-policy"
        tags: [sk-msg reject context writable]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk is read-only"
    }
    {
        name: "sk-msg-rejects-reuseport-redirect"
        category: "language-surface"
        tags: [redirect-socket sk-msg reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket sockets 0 --kind reuseport-sockarray'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "redirect-socket --kind reuseport-sockarray is only valid in sk_reuseport programs"
    }
    {
        name: "sk-skb-basic-context"
        category: "context-surface"
        tags: [sk-skb context]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.eth_protocol + $ctx.local_port + $ctx.socket_uid + $ctx.sk.family) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-rich-context"
        category: "context-surface"
        tags: [sk-skb context packet helper-backed source metadata]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.ingress_ifindex + $ctx.ifindex + $ctx.tc_index + $ctx.hash + $ctx.hash_recalc + $ctx.csum_level) | count'
            '  ($ctx.family + $ctx.remote_ip4 + $ctx.local_ip4 + $ctx.remote_port + $ctx.local_port + $ctx.socket_cookie + $ctx.socket_uid + $ctx.sk.family + $ctx.cb.1) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-bound-socket-projection-context"
        category: "context-surface"
        tags: [sk-skb context socket source metadata]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  ($sk.local_port + $sk.remote_port + $sk.priority) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-socket-root-alias-context"
        category: "context-surface"
        tags: [sk-skb context socket alias source metadata]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.sock.local_port + $ctx.socket.remote_port + $ctx.socket.priority) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-data-context-write"
        category: "context-surface"
        tags: [sk-skb context packet writable]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  (($ctx.data | get 0) + $ctx.protocol + $ctx.priority) | count'
            '  $ctx.data.0 = 42'
            '  $ctx.priority = 3'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-metadata-context-write"
        category: "context-surface"
        tags: [sk-skb context writable]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.priority = 3'
            '  $ctx.tc_index = 5'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-rejects-mark-context"
        category: "context-policy"
        tags: [sk-skb reject context]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  $ctx.mark | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.mark is only available on cgroup_sock, socket_filter, lwt_*, tc_action, tc, tcx, netkit, and cgroup_skb programs"
    }
    {
        name: "sk-skb-rejects-tstamp-context"
        category: "context-policy"
        tags: [sk-skb reject context]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  $ctx.tstamp | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.tstamp is only available on tc_action, tc, tcx, netkit, and cgroup_skb programs"
    }
    {
        name: "sk-skb-rejects-sk-assignment"
        category: "context-policy"
        tags: [sk-skb reject context writable]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk is read-only"
    }
]
