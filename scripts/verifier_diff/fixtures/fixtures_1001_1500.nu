const VERIFIER_DIFF_FIXTURES_1001_1500 = [
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
    {
        name: "sk-skb-rejects-reuseport-redirect"
        category: "language-surface"
        tags: [redirect-socket sk-skb reject]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
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
        name: "sk-skb-parser-basic-context"
        category: "context-surface"
        tags: [sk-skb-parser context]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.eth_protocol + $ctx.local_port + $ctx.sk.family) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-parser-rich-context"
        category: "context-surface"
        tags: [sk-skb-parser context packet helper-backed source metadata]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.ingress_ifindex + $ctx.ifindex + $ctx.tc_index + $ctx.hash + $ctx.hash_recalc + $ctx.csum_level) | count'
            '  ($ctx.family + $ctx.remote_ip4 + $ctx.local_ip4 + $ctx.remote_port + $ctx.local_port + $ctx.socket_cookie + $ctx.socket_uid + $ctx.sk.family + $ctx.cb.2) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-parser-data-context-write"
        category: "context-surface"
        tags: [sk-skb-parser context packet writable]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  (($ctx.data | get 0) + $ctx.protocol + $ctx.priority) | count'
            '  $ctx.data.0 = 42'
            '  $ctx.priority = 3'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-parser-bound-socket-projection-context"
        category: "context-surface"
        tags: [sk-skb-parser context socket source metadata]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  ($sk.local_port + $sk.remote_port + $sk.priority) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-parser-socket-root-alias-context"
        category: "context-surface"
        tags: [sk-skb-parser context socket alias source metadata]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.sock.local_port + $ctx.socket.remote_port + $ctx.socket.priority) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-parser-metadata-context-write"
        category: "context-surface"
        tags: [sk-skb-parser context writable]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.priority = 3'
            '  $ctx.tc_index = 5'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-parser-rejects-mark-context"
        category: "context-policy"
        tags: [sk-skb-parser reject context]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  $ctx.mark | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.mark is only available on cgroup_sock, socket_filter, lwt_*, tc_action, tc, tcx, netkit, and cgroup_skb programs"
    }
    {
        name: "sk-skb-parser-rejects-tstamp-context"
        category: "context-policy"
        tags: [sk-skb-parser reject context]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  $ctx.tstamp | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.tstamp is only available on tc_action, tc, tcx, netkit, and cgroup_skb programs"
    }
    {
        name: "sk-skb-parser-rejects-sk-assignment"
        category: "context-policy"
        tags: [sk-skb-parser reject context writable]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk is read-only"
    }
    {
        name: "sk-skb-parser-rejects-reuseport-redirect"
        category: "language-surface"
        tags: [redirect-socket sk-skb-parser reject]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
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
        name: "lwt-xmit-helper-context"
        category: "context-surface"
        tags: [lwt context helper-backed]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.hash + $ctx.hash_recalc + $ctx.csum_level + $ctx.cgroup_classid + $ctx.route_realm) | count'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-rich-skb-context"
        category: "context-surface"
        tags: [lwt context packet helper-backed source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.ingress_ifindex + $ctx.ifindex + $ctx.priority + $ctx.cb.3) | count'
            '  ($ctx.hash + $ctx.hash_recalc + $ctx.csum_level + $ctx.cgroup_classid + $ctx.route_realm + $ctx.protocol) | count'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-packet-context-write"
        category: "context-surface"
        tags: [lwt context packet writable]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  (($ctx.data | get 0) + $ctx.mark) | count'
            '  $ctx.data.0 = 42'
            '  $ctx.cb.1 = 7'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-record-packet-context-write"
        category: "context-surface"
        tags: [lwt context packet writable record source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  mut rec = { data: $ctx.data }'
            '  $rec.data.0 = 42'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-record-spread-packet-context-write"
        category: "context-surface"
        tags: [lwt context packet writable record spread source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  let base = { data: $ctx.data }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.data.0 = 42'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-user-function-record-packet-context-write"
        category: "context-surface"
        tags: [lwt context packet writable user-function record source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  def wrap [data] { { data: $data } }'
            '  mut rec = (wrap $ctx.data)'
            '  $rec.data.0 = 42'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-metadata-context-write"
        category: "context-surface"
        tags: [lwt context writable source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 7'
            '  $ctx.priority = 3'
            '  $ctx.cb.2 = 9'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-in-rejects-packet-data-write"
        category: "context-policy"
        tags: [lwt reject context packet writable]
        target: "lwt_in:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.data.0 = 42'
            '  "reroute"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "direct packet writes are not supported on lwt_in programs"
    }
    {
        name: "lwt-in-helper-context"
        category: "context-surface"
        tags: [lwt context helper-backed]
        target: "lwt_in:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.ingress_ifindex + $ctx.mark) | count'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-in-rich-skb-context"
        category: "context-surface"
        tags: [lwt context packet helper-backed source metadata]
        target: "lwt_in:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.ingress_ifindex + $ctx.ifindex + $ctx.mark + $ctx.priority + $ctx.cb.0) | count'
            '  ($ctx.hash + $ctx.hash_recalc + $ctx.cgroup_classid + $ctx.route_realm + $ctx.protocol) | count'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-in-context-write"
        category: "context-surface"
        tags: [lwt context writable]
        target: "lwt_in:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 7'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-out-helper-context"
        category: "context-surface"
        tags: [lwt context helper-backed]
        target: "lwt_out:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.queue_mapping + $ctx.protocol + $ctx.priority) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-out-rich-skb-context"
        category: "context-surface"
        tags: [lwt context packet helper-backed source metadata]
        target: "lwt_out:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.ingress_ifindex + $ctx.ifindex + $ctx.mark + $ctx.priority + $ctx.cb.2) | count'
            '  ($ctx.hash + $ctx.hash_recalc + $ctx.cgroup_classid + $ctx.route_realm + $ctx.protocol) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-out-context-write"
        category: "context-surface"
        tags: [lwt context writable]
        target: "lwt_out:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.priority = 3'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-out-rejects-csum-level-context"
        category: "context-policy"
        tags: [lwt reject context helper-backed]
        target: "lwt_out:demo-route"
        program: [
            '{|ctx|'
            '  $ctx.csum_level | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.csum_level is only available on lwt_xmit, tc_action, tc, tcx, netkit, sk_skb, and sk_skb_parser programs"
    }
    {
        name: "lwt-seg6local-helper-context"
        category: "context-surface"
        tags: [lwt context helper-backed seg6local]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.hash + $ctx.route_realm + $ctx.gso_size) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-rich-skb-context"
        category: "context-surface"
        tags: [lwt context packet helper-backed source metadata seg6local]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.ingress_ifindex + $ctx.ifindex + $ctx.mark + $ctx.priority + $ctx.cb.4) | count'
            '  ($ctx.hash + $ctx.hash_recalc + $ctx.cgroup_classid + $ctx.route_realm + $ctx.protocol) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-context-write"
        category: "context-surface"
        tags: [lwt context writable seg6local]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.cb.4 = 7'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-rejects-tstamp-context"
        category: "context-policy"
        tags: [lwt reject context timestamp]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  $ctx.tstamp | count'
            '  "reroute"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.tstamp is only available on tc_action, tc, tcx, netkit, and cgroup_skb programs"
    }
    {
        name: "lwt-xmit-rejects-sk-assignment"
        category: "context-policy"
        tags: [lwt reject context writable socket]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "reroute"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk is only available"
    }
    {
        name: "lwt-xmit-rejects-tc-classid-context"
        category: "context-policy"
        tags: [lwt reject context]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  $ctx.tc_classid | count'
            '  "reroute"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.tc_classid is only available on tc_action, tc, tcx, and netkit programs"
    }
    {
        name: "lwt-xmit-rejects-socket-context"
        category: "context-policy"
        tags: [lwt reject context socket]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  $ctx.sk.family | count'
            '  "reroute"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk is only available on socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sk_lookup, sk_reuseport, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs"
    }
    {
        name: "lwt-push-encap-rejects-non-lwt-program"
        category: "helper-policy"
        tags: [lwt helper-call reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_lwt_push_encap" $ctx 0 0 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_lwt_push_encap' is only valid in lwt_in and lwt_xmit programs"
    }
    {
        name: "lwt-xmit-push-encap-helper"
        category: "helper-state"
        tags: [lwt helper-call accept source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  map-define encap_hdr --kind array --value-type bytes:16 --max-entries 1'
            '  let hdr = (0 | map-get encap_hdr --kind array)'
            '  if $hdr { helper-call "bpf_lwt_push_encap" $ctx 0 $hdr 16 }'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-push-encap-rejects-stale-data"
        category: "helper-state"
        tags: [lwt helper-call packet-bounds reject source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  let hdr = "0123456789abcdef"'
            '  helper-call "bpf_lwt_push_encap" $ctx 0 $hdr 16'
            '  ($data | get 0) | count'
            '  "reroute"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "lwt-xmit-push-encap-allows-reloaded-data"
        category: "helper-state"
        tags: [lwt helper-call packet-bounds accept source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  let hdr = "0123456789abcdef"'
            '  helper-call "bpf_lwt_push_encap" $ctx 0 $hdr 16'
            '  ($ctx.data | get 0) | count'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-store-bytes-helper"
        category: "helper-state"
        tags: [lwt helper-call seg6local accept source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  map-define seg6_bytes --kind array --value-type bytes:16 --max-entries 1'
            '  let bytes = (0 | map-get seg6_bytes --kind array)'
            '  if $bytes { helper-call "bpf_lwt_seg6_store_bytes" $ctx 0 $bytes 16 }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-store-bytes-rejects-stale-data"
        category: "helper-state"
        tags: [lwt helper-call seg6local packet-bounds reject source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  let bytes = "0123456789abcdef"'
            '  helper-call "bpf_lwt_seg6_store_bytes" $ctx 0 $bytes 16'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "lwt-seg6local-store-bytes-allows-reloaded-data"
        category: "helper-state"
        tags: [lwt helper-call seg6local packet-bounds accept source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  let bytes = "0123456789abcdef"'
            '  helper-call "bpf_lwt_seg6_store_bytes" $ctx 0 $bytes 16'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-adjust-srh-helper"
        category: "helper-state"
        tags: [lwt helper-call seg6local accept source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  helper-call "bpf_lwt_seg6_adjust_srh" $ctx 0 4'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-action-helper"
        category: "helper-state"
        tags: [lwt helper-call seg6local accept source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  map-define seg6_action --kind array --value-type bytes:16 --max-entries 1'
            '  let param = (0 | map-get seg6_action --kind array)'
            '  if $param { helper-call "bpf_lwt_seg6_action" $ctx 0 $param 16 }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-store-bytes-rejects-small-buffer"
        category: "helper-state"
        tags: [lwt helper-call seg6local bounds reject source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  map-define seg6_bytes --kind array --value-type bytes:8 --max-entries 1'
            '  let bytes = (0 | map-get seg6_bytes --kind array)'
            '  if $bytes { helper-call "bpf_lwt_seg6_store_bytes" $ctx 0 $bytes 16 }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper lwt buffer requires 16 bytes"
    }
    {
        name: "lwt-seg6local-store-bytes-rejects-dynamic-small-buffer"
        category: "helper-state"
        tags: [lwt helper-call seg6local bounds dynamic reject source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  map-define seg6_bytes_dyn_short --kind array --value-type bytes:8 --max-entries 1'
            '  let bytes = (0 | map-get seg6_bytes_dyn_short --kind array)'
            '  if $bytes {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 8 } else { 16 })'
            '    helper-call "bpf_lwt_seg6_store_bytes" $ctx 0 $bytes $size'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper lwt buffer requires 16 bytes"
    }
    {
        name: "lirc-mode2-context"
        category: "context-surface"
        tags: [lirc context]
        requires: [lirc-device]
        target: "lirc_mode2:/dev/lirc0"
        program: [
            '{|ctx|'
            '  ($ctx.sample + $ctx.value + $ctx.mode) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lirc-mode2-current-context"
        category: "context-surface"
        tags: [lirc context current]
        requires: [lirc-device]
        target: "lirc_mode2:/dev/lirc0"
        program: [
            '{|ctx|'
            '  ($ctx.cpu + $ctx.ktime + $ctx.cgroup_id) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lirc-mode2-rc-helpers"
        category: "helper-state"
        tags: [lirc helper-call accept source metadata]
        target: "lirc_mode2:/dev/null"
        program: [
            '{|ctx|'
            '  helper-call "bpf_rc_repeat" $ctx'
            '  helper-call "bpf_rc_keydown" $ctx 0 0 0'
            '  helper-call "bpf_rc_pointer_rel" $ctx 0 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "raw-tracepoint-writable-args"
        category: "context-surface"
        tags: [raw-tracepoint-w context]
        target: "raw_tracepoint.w:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.arg0 + $ctx.arg1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-tracepoint-writable-current-context"
        category: "context-surface"
        tags: [raw-tracepoint-w context current]
        target: "raw_tracepoint.w:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.pid + $ctx.ktime + $ctx.cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  if $ctx.meta { 1 | count }'
            '  if $ctx.task { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  if $ctx.task { $ctx.task.pid | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-meta-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  $ctx.meta.seq_num | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-alias-btf-fields"
        category: "context-surface"
        tags: [iter context alias btf kernel-btf source metadata]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let meta = $ctx.iter_meta'
            '  $meta.seq_num | count'
            '  if $ctx.iter_task { $ctx.iter_task.pid | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-record-btf-fields"
        category: "context-surface"
        tags: [iter context record btf kernel-btf source metadata]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let rec = { meta: $ctx.iter_meta task: $ctx.iter_task }'
            '  $rec.meta.seq_num | count'
            '  if $rec.task { $rec.task.pid | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-record-spread-btf-fields"
        category: "context-surface"
        tags: [iter context record spread btf kernel-btf source metadata]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let base = { task: $ctx.iter_task }'
            '  let rec = { meta: $ctx.iter_meta, ...$base }'
            '  $rec.meta.seq_num | count'
            '  if $rec.task { $rec.task.pid | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-user-function-record-btf-fields"
        category: "context-surface"
        tags: [iter context user-function record btf kernel-btf source metadata]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  def wrap [task] { { task: $task } }'
            '  let rec = (wrap $ctx.iter_task)'
            '  if $rec.task { $rec.task.pid | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-user-function-returned-btf-root-fields"
        category: "context-surface"
        tags: [iter context user-function alias btf kernel-btf source metadata]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  def get_meta [event] { $event.iter_meta }'
            '  def get_task [event] { $event.iter_task }'
            '  let meta = (get_meta $ctx)'
            '  let task = (get_task $ctx)'
            '  $meta.seq_num | count'
            '  if $task { $task.pid | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-file-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:task_file"
        program: [
            '{|ctx|'
            '  $ctx.fd | count'
            '  if $ctx.task { 1 | count }'
            '  if $ctx.file { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-file-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:task_file"
        program: [
            '{|ctx|'
            '  if $ctx.file { $ctx.file.f_mode | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-vma-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:task_vma"
        program: [
            '{|ctx|'
            '  if $ctx.task { 1 | count }'
            '  if $ctx.vma { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-vma-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:task_vma"
        program: [
            '{|ctx|'
            '  if $ctx.vma { $ctx.vma.vm_start | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-cgroup-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:cgroup"
        program: [
            '{|ctx|'
            '  if $ctx.cgroup { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-cgroup-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:cgroup"
        program: [
            '{|ctx|'
            '  if $ctx.cgroup { $ctx.cgroup.level | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-map-context"
        category: "context-surface"
        tags: [iter context map]
        target: "iter:bpf_map"
        program: [
            '{|ctx|'
            '  if $ctx.map { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-map-btf-field"
        category: "context-surface"
        tags: [iter context map btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:bpf_map"
        program: [
            '{|ctx|'
            '  if $ctx.map { $ctx.map.id | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-map-elem-context"
        category: "context-surface"
        tags: [iter context map]
        target: "iter:bpf_map_elem"
        program: [
            '{|ctx|'
            '  if $ctx.map { 1 | count }'
            '  if $ctx.key { 1 | count }'
            '  if $ctx.value { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-map-elem-map-btf-field"
        category: "context-surface"
        tags: [iter context map btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:bpf_map_elem"
        program: [
            '{|ctx|'
            '  if $ctx.map { $ctx.map.id | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-sk-storage-map-context"
        category: "context-surface"
        tags: [iter context map socket]
        target: "iter:bpf_sk_storage_map"
        program: [
            '{|ctx|'
            '  if $ctx.map { 1 | count }'
            '  if $ctx.value { 1 | count }'
            '  if $ctx.sk { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-sk-storage-map-btf-fields"
        category: "context-surface"
        tags: [iter context map socket btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:bpf_sk_storage_map"
        program: [
            '{|ctx|'
            '  if $ctx.map { $ctx.map.id | count }'
            '  if $ctx.sk { $ctx.sk.__sk_common.skc_family | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-sockmap-context"
        category: "context-surface"
        tags: [iter context map socket]
        target: "iter:sockmap"
        program: [
            '{|ctx|'
            '  if $ctx.map { 1 | count }'
            '  if $ctx.key { 1 | count }'
            '  if $ctx.sk { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-sockmap-btf-fields"
        category: "context-surface"
        tags: [iter context map socket btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:sockmap"
        program: [
            '{|ctx|'
            '  if $ctx.map { $ctx.map.id | count }'
            '  if $ctx.sk { $ctx.sk.__sk_common.skc_family | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-prog-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:bpf_prog"
        program: [
            '{|ctx|'
            '  if $ctx.prog { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-prog-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:bpf_prog"
        program: [
            '{|ctx|'
            '  if $ctx.prog { $ctx.prog.len | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-link-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:bpf_link"
        program: [
            '{|ctx|'
            '  if $ctx.link { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-link-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:bpf_link"
        program: [
            '{|ctx|'
            '  if $ctx.link { $ctx.link.id | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-tcp-context"
        category: "context-surface"
        tags: [iter context socket]
        target: "iter:tcp"
        program: [
            '{|ctx|'
            '  $ctx.uid | count'
            '  if $ctx.sk_common { 1 | count }'
            '  if $ctx.sock_common { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-tcp-btf-field"
        category: "context-surface"
        tags: [iter context socket btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:tcp"
        program: [
            '{|ctx|'
            '  if $ctx.sk_common { $ctx.sk_common.skc_family | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-udp-context"
        category: "context-surface"
        tags: [iter context socket]
        target: "iter:udp"
        program: [
            '{|ctx|'
            '  ($ctx.uid + $ctx.bucket) | count'
            '  if $ctx.udp_sk { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-udp-btf-field"
        category: "context-surface"
        tags: [iter context socket btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:udp"
        program: [
            '{|ctx|'
            '  if $ctx.udp_sk { $ctx.udp_sk.inet.sk.__sk_common.skc_family | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-unix-context"
        category: "context-surface"
        tags: [iter context socket]
        target: "iter:unix"
        program: [
            '{|ctx|'
            '  $ctx.uid | count'
            '  if $ctx.unix_sk { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-unix-btf-field"
        category: "context-surface"
        tags: [iter context socket btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:unix"
        program: [
            '{|ctx|'
            '  if $ctx.unix_sk { $ctx.unix_sk.sk.__sk_common.skc_family | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-dmabuf-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:dmabuf"
        program: [
            '{|ctx|'
            '  if $ctx.dmabuf { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-dmabuf-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:dmabuf"
        program: [
            '{|ctx|'
            '  if $ctx.dmabuf { $ctx.dmabuf.size | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-ipv6-route-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:ipv6_route"
        program: [
            '{|ctx|'
            '  if $ctx.rt { 1 | count }'
            '  if $ctx.ipv6_route { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-ipv6-route-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:ipv6_route"
        program: [
            '{|ctx|'
            '  if $ctx.rt { $ctx.rt.fib6_metric | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-kmem-cache-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:kmem_cache"
        program: [
            '{|ctx|'
            '  if $ctx.kmem_cache { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-kmem-cache-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:kmem_cache"
        program: [
            '{|ctx|'
            '  if $ctx.kmem_cache { $ctx.kmem_cache.size | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-ksym-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:ksym"
        program: [
            '{|ctx|'
            '  if $ctx.ksym { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-ksym-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:ksym"
        program: [
            '{|ctx|'
            '  if $ctx.ksym { $ctx.ksym.value | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-netlink-context"
        category: "context-surface"
        tags: [iter context socket]
        target: "iter:netlink"
        program: [
            '{|ctx|'
            '  if $ctx.netlink_sk { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-netlink-btf-field"
        category: "context-surface"
        tags: [iter context socket btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:netlink"
        program: [
            '{|ctx|'
            '  if $ctx.netlink_sk { $ctx.netlink_sk.sk.__sk_common.skc_family | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-rejects-queue"
        category: "maps"
        tags: [queue reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-get q --kind queue'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-get is not supported for map kind queue"
    }
    {
        name: "map-define-kptr-slot"
        category: "maps"
        tags: [maps map-define kptr accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --value-type "record{task:kptr:task_struct,cookie:u64}" --max-entries 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-kptr-slot-rejects-queue"
        category: "maps"
        tags: [maps map-define kptr reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind queue --value-type "record{task:kptr:task_struct,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kptr fields, which are currently supported for hash, array, and lru-hash maps"
    }
    {
        name: "map-define-kptr-rejects-array-field"
        category: "maps"
        tags: [maps map-define kptr reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --value-type "record{tasks:array{record{task:kptr:task_struct}:2},cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arrays of verifier-managed kptr"
    }
    {
        name: "map-define-bpf-wq-slot"
        category: "maps"
        tags: [maps map-define bpf_wq accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-bpf-wq-slot-rejects-queue"
        category: "maps"
        tags: [maps map-define bpf_wq reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind queue --value-type "record{work:bpf_wq,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "contains bpf_wq, which is only supported for hash, array, and lru-hash maps"
    }
    {
        name: "map-define-bpf-wq-rejects-array-field"
        category: "maps"
        tags: [maps map-define bpf_wq reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work_items:array{bpf_wq:2},cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arrays of verifier-managed bpf_wq"
    }
    {
        name: "bpf-wq-kfunc-init-start"
        category: "helper-state"
        tags: [bpf_wq kfunc-call accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_init" $entry.work work_items 0'
            '    kfunc-call "bpf_wq_start" $entry.work 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "bpf-wq-init-requires-null-checked-map-lookup"
        category: "helper-state"
        tags: [bpf_wq kfunc-call nullability reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  kfunc-call "bpf_wq_init" $entry.work work_items 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "may dereference null pointer"
    }
    {
        name: "bpf-wq-init-rejects-non-wq-map-field"
        category: "helper-state"
        tags: [bpf_wq kfunc-call reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{lock:bpf_spin_lock,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_init" $entry.lock work_items 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_wq field projected from a concrete map value"
    }
    {
        name: "bpf-wq-init-rejects-dynamic-non-map-field"
        category: "helper-state"
        tags: [bpf_wq kfunc-call dynamic branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items_dyn --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items_dyn --kind array)'
            '  if $entry {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let work = (if $selector == 0 { $entry.work } else { 0 })'
            '    kfunc-call "bpf_wq_init" $work work_items_dyn 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_wq field projected from a concrete map value"
    }
    {
        name: "bpf-wq-start-requires-null-checked-map-lookup"
        category: "helper-state"
        tags: [bpf_wq kfunc-call nullability reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  kfunc-call "bpf_wq_start" $entry 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "may dereference null pointer"
    }
    {
        name: "bpf-wq-start-rejects-non-wq-map-field"
        category: "helper-state"
        tags: [bpf_wq kfunc-call reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{lock:bpf_spin_lock,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_start" $entry.lock 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_wq_start' arg0 expects bpf_wq pointer"
    }
    {
        name: "bpf-wq-start-rejects-stack-value"
        category: "helper-state"
        tags: [bpf_wq kfunc-call stack reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let work = "0123456789abcdef"'
            '  kfunc-call "bpf_wq_start" $work 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_wq_start' arg0 expects bpf_wq pointer"
    }
    {
        name: "bpf-wq-set-callback-requires-null-checked-map-lookup"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback nullability reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  kfunc-call "bpf_wq_set_callback_impl" $entry {|map key work| 0} 0 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "may dereference null pointer"
    }
    {
        name: "bpf-wq-set-callback-rejects-non-wq-map-field"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{lock:bpf_spin_lock,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_set_callback_impl" $entry.lock {|map key work| 0} 0 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_wq field projected from a concrete map value"
    }
    {
        name: "bpf-wq-set-callback-rejects-stack-value"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback stack reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let work = "0123456789abcdef"'
            '  kfunc-call "bpf_wq_set_callback_impl" $work {|map key work| 0} 0 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_wq field projected from a concrete map value"
    }
    {
        name: "bpf-wq-set-callback-rejects-dynamic-non-map-field"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback dynamic branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items_dyn_cb --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items_dyn_cb --kind array)'
            '  if $entry {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let work = (if $selector == 0 { $entry.work } else { 0 })'
            '    kfunc-call "bpf_wq_set_callback_impl" $work {|map key work| 0} 0 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_wq field projected from a concrete map value"
    }
    {
        name: "bpf-wq-kfunc-set-callback"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_init" $entry.work work_items 0'
            '    kfunc-call "bpf_wq_set_callback_impl" $entry.work {|map key work| 0} 0 0'
            '    kfunc-call "bpf_wq_start" $entry.work 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "bpf-wq-kfunc-set-callback-allows-prefix-params"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback prefix-arity accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_init" $entry.work work_items 0'
            '    kfunc-call "bpf_wq_set_callback_impl" $entry.work {|map key| 0} 0 0'
            '    kfunc-call "bpf_wq_start" $entry.work 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "bpf-wq-set-callback-rejects-out-of-i32-return"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback return reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_init" $entry.work work_items 0'
            '    kfunc-call "bpf_wq_set_callback_impl" $entry.work {|map key work| 2147483648} 0 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "callback return"
    }
    {
        name: "bpf-wq-kfunc-set-callback-rejects-extra-declared-param"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_set_callback_impl" $entry.work {|map key work extra| 0} 0 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "declares 4 parameters, but the callback ABI supplies 3"
    }
    {
        name: "bpf-wq-init-rejects-mismatched-map"
        category: "helper-state"
        tags: [bpf_wq kfunc-call reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_init" $entry.work other_items 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc-call 'bpf_wq_init' requires arg1 map 'other_items'"
    }
    {
        name: "bpf-wq-init-accepts-phi-joined-same-map-value-source"
        category: "helper-state"
        tags: [bpf_wq kfunc-call phi dynamic branch accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind hash --key-type u32 --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let base_key = $ctx.pid'
            '  let left_key = $base_key'
            '  let right_key = $base_key'
            '  let first = ($left_key | map-get work_items --kind hash)'
            '  let second = ($right_key | map-get work_items --kind hash)'
            '  let entry = (if $selector == 0 { $first } else { $second })'
            '  if $entry {'
            '    kfunc-call "bpf_wq_init" $entry.work work_items 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "bpf-wq-init-rejects-phi-joined-mismatched-map-value-source"
        category: "helper-state"
        tags: [bpf_wq kfunc-call phi dynamic branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind hash --key-type u32 --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  map-define other_work_items --kind hash --key-type u32 --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let base_key = $ctx.pid'
            '  let first = ($base_key | map-get work_items --kind hash)'
            '  let second = ($base_key | map-get other_work_items --kind hash)'
            '  let entry = (if $selector == 0 { $first } else { $second })'
            '  if $entry {'
            '    kfunc-call "bpf_wq_init" $entry.work work_items 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc-call 'bpf_wq_init' requires arg0 to be a bpf_wq field projected from a concrete map value"
    }
    {
        name: "bpf-wq-init-rejects-nonzero-flags"
        category: "helper-state"
        tags: [bpf_wq kfunc-call flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_init" $entry.work work_items 1'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_wq_init' arg2 must be known zero"
    }
    {
        name: "bpf-wq-init-rejects-dynamic-flags"
        category: "helper-state"
        tags: [bpf_wq kfunc-call flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_init" $entry.work work_items $flags'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_wq_init' arg2 must be known zero"
    }
    {
        name: "bpf-wq-start-rejects-nonzero-flags"
        category: "helper-state"
        tags: [bpf_wq kfunc-call flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_start" $entry.work 1'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_wq_start' arg1 must be known zero"
    }
    {
        name: "bpf-wq-start-rejects-dynamic-flags"
        category: "helper-state"
        tags: [bpf_wq kfunc-call flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_start" $entry.work $flags'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_wq_start' arg1 must be known zero"
    }
    {
        name: "bpf-wq-set-callback-rejects-nonzero-flags"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_set_callback_impl" $entry.work {|map key work| 0} 1 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_wq_set_callback_impl' arg2 must be known zero"
    }
    {
        name: "bpf-wq-set-callback-rejects-dynamic-flags"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_set_callback_impl" $entry.work {|map key work| 0} $flags 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_wq_set_callback_impl' arg2 must be known zero"
    }
    {
        name: "bpf-wq-set-callback-rejects-nonzero-aux"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_set_callback_impl" $entry.work {|map key work| 0} 0 1'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_wq_set_callback_impl' arg3 must be known zero"
    }
    {
        name: "bpf-wq-set-callback-rejects-dynamic-aux"
        category: "helper-state"
        tags: [bpf_wq kfunc-call callback reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  let aux = (helper-call "bpf_get_prandom_u32")'
            '  let entry = (0 | map-get work_items --kind array)'
            '  if $entry {'
            '    kfunc-call "bpf_wq_set_callback_impl" $entry.work {|map key work| 0} 0 $aux'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_wq_set_callback_impl' arg3 must be known zero"
    }
    {
        name: "map-define-bpf-refcount-slot"
        category: "maps"
        tags: [maps map-define bpf_refcount accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define refcounted_items --kind array --value-type "record{refs:bpf_refcount,cookie:u64}" --max-entries 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-bpf-refcount-rejects-queue"
        category: "maps"
        tags: [maps map-define bpf_refcount reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define refcounted_items --kind queue --value-type "record{refs:bpf_refcount,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "contains bpf_refcount, which is currently supported for hash, array, and lru-hash maps"
    }
    {
        name: "map-define-bpf-refcount-rejects-array-field"
        category: "maps"
        tags: [maps map-define bpf_refcount reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define refcounted_items --kind array --value-type "record{refs:array{bpf_refcount:2},cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arrays of verifier-managed bpf_refcount"
    }
    {
        name: "map-define-graph-root-schema"
        category: "maps"
        tags: [maps map-define graph accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-rejects-top-level-graph-root-schema"
        category: "maps"
        tags: [maps map-define graph reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "bpf_list_head:node_data:node:record{refs:bpf_refcount,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "must wrap bpf_list_head in a map-value record field"
    }
    {
        name: "map-define-rejects-bare-graph-root"
        category: "maps"
        tags: [maps map-define graph reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'root' type spec 'bpf_list_head'"
    }
    {
        name: "map-define-rejects-bare-rbtree-node"
        category: "maps"
        tags: [maps map-define graph reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{node:bpf_rb_node,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'node' type spec 'bpf_rb_node'"
    }
    {
        name: "map-define-bpf-timer-rejects-array-field"
        category: "maps"
        tags: [maps map-define timer reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timers:array{bpf_timer:2},cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arrays of verifier-managed bpf_timer"
    }
    {
        name: "timer-map-define-lowers-init-start-cancel"
        category: "helper-state"
        tags: [timer map-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_init" $entry.timer timers 0 --kind array'
            '    helper-call "bpf_timer_set_callback" $entry.timer {|timer key val| 0}'
            '    helper-call "bpf_timer_start" $entry.timer 1000 0'
            '    helper-call "bpf_timer_cancel" $entry.timer'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "timer-start-requires-null-checked-map-lookup"
        category: "helper-state"
        tags: [timer map-define nullability reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  helper-call "bpf_timer_start" $entry 1000 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "may dereference null pointer"
    }
    {
        name: "timer-init-requires-null-checked-map-lookup"
        category: "helper-state"
        tags: [timer map-define nullability reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  helper-call "bpf_timer_init" $entry timers 0 --kind array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "may dereference null pointer"
    }
    {
        name: "timer-set-callback-requires-null-checked-map-lookup"
        category: "helper-state"
        tags: [timer callback map-define nullability reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  helper-call "bpf_timer_set_callback" $entry {|timer key val| 0}'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "may dereference null pointer"
    }
    {
        name: "timer-cancel-requires-null-checked-map-lookup"
        category: "helper-state"
        tags: [timer map-define nullability reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  helper-call "bpf_timer_cancel" $entry'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "may dereference null pointer"
    }
    {
        name: "timer-init-rejects-mismatched-owner-map"
        category: "helper-state"
        tags: [timer map-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  map-define other_timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_init" $entry.timer other_timers 0 --kind array'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg1 map 'other_timers'"
    }
    {
        name: "timer-init-accepts-phi-joined-same-map-value-source"
        category: "helper-state"
        tags: [timer map-define phi dynamic branch accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind hash --key-type u32 --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let base_key = $ctx.pid'
            '  let left_key = $base_key'
            '  let right_key = $base_key'
            '  let first = ($left_key | map-get timers --kind hash)'
            '  let second = ($right_key | map-get timers --kind hash)'
            '  let entry = (if $selector == 0 { $first } else { $second })'
            '  if $entry {'
            '    helper-call "bpf_timer_init" $entry.timer timers 0 --kind hash'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "timer-init-rejects-phi-joined-mismatched-map-value-source"
        category: "helper-state"
        tags: [timer map-define phi dynamic branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind hash --key-type u32 --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  map-define other_timers --kind hash --key-type u32 --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let base_key = $ctx.pid'
            '  let first = ($base_key | map-get timers --kind hash)'
            '  let second = ($base_key | map-get other_timers --kind hash)'
            '  let entry = (if $selector == 0 { $first } else { $second })'
            '  if $entry {'
            '    helper-call "bpf_timer_init" $entry.timer timers 0 --kind hash'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
    }
    {
        name: "timer-callback-uses-trailing-value-param"
        category: "helper-state"
        tags: [timer callback accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_set_callback" $entry.timer {|timer key val|'
            '      $val.cookie | count'
            '      0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "timer-callback-allows-prefix-params"
        category: "helper-state"
        tags: [timer callback prefix-arity accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_set_callback" $entry.timer {|timer key|'
            '      $key | count'
            '      0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "timer-callback-map-btf-field"
        category: "helper-state"
        tags: [timer callback btf kernel-btf]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_set_callback" $entry.timer {|timer key val|'
            '      $timer.id | count'
            '      0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "timer-callback-rejects-extra-declared-param"
        category: "helper-state"
        tags: [timer callback reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_set_callback" $entry.timer {|timer key val extra| 0}'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "declares 4 parameters, but the callback ABI supplies 3"
    }
    {
        name: "timer-callback-rejects-nonzero-return"
        category: "helper-state"
        tags: [timer callback return reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_set_callback" $entry.timer {|timer key val| 1}'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "callback return"
    }
    {
        name: "timer-init-rejects-invalid-clock-flags"
        category: "helper-state"
        tags: [timer helper-call flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_init" $entry.timer timers 99 --kind array'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_timer_init' requires arg2 flags to be CLOCK_REALTIME, CLOCK_MONOTONIC, or CLOCK_BOOTTIME"
    }
    {
        name: "timer-start-rejects-invalid-flags"
        category: "helper-state"
        tags: [timer helper-call flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_start" $entry.timer 1000 4'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_timer_start' requires arg2 flags to contain only BPF_F_TIMER_* bits"
    }
    {
        name: "timer-init-rejects-dynamic-clock-flags"
        category: "helper-state"
        tags: [timer helper-call flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_init" $entry.timer timers $flags --kind array'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_timer_init' requires arg2 flags to be CLOCK_REALTIME, CLOCK_MONOTONIC, or CLOCK_BOOTTIME"
    }
    {
        name: "timer-start-rejects-dynamic-flags"
        category: "helper-state"
        tags: [timer helper-call flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_start" $entry.timer 1000 $flags'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_timer_start' requires arg2 flags to contain only BPF_F_TIMER_* bits"
    }
    {
        name: "source-kfunc-iter-num-lifecycle-balanced"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_num_new" $iter 0 4'
            '  let item = (kfunc-call "bpf_iter_num_next" $iter)'
            '  if $item { 0 }'
            '  kfunc-call "bpf_iter_num_destroy" $iter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-iter-num-user-function-new-destroy"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source accept user-function]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def iter-new [iter start end] {'
            '    kfunc-call "bpf_iter_num_new" $iter $start $end'
            '    0'
            '  }'
            '  def iter-destroy [iter] {'
            '    kfunc-call "bpf_iter_num_destroy" $iter'
            '    0'
            '  }'
            '  let iter = "0123456789abcdef"'
            '  iter-new $iter 0 4'
            '  let item = (kfunc-call "bpf_iter_num_next" $iter)'
            '  if $item { 0 }'
            '  iter-destroy $iter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-iter-num-rejects-next-without-new"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_num_next" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_num_next' requires a matching bpf_iter_num_new"
    }
    {
        name: "source-kfunc-iter-num-rejects-leak"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_num_new" $iter 0 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased iter_num iterator"
    }
    {
        name: "source-kfunc-iter-num-rejects-double-destroy"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_num_new" $iter 0 4'
            '  kfunc-call "bpf_iter_num_destroy" $iter'
            '  kfunc-call "bpf_iter_num_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_num_destroy' requires a matching bpf_iter_num_new"
    }
    {
        name: "source-kfunc-iter-num-rejects-reinit-live-slot"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_num_new" $iter 0 4'
            '  kfunc-call "bpf_iter_num_new" $iter 4 8'
            '  kfunc-call "bpf_iter_num_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires uninitialized bpf_iter_num stack object slot"
    }
    {
        name: "source-kfunc-iter-num-rejects-reinit-after-conditional-new"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_iter_num_new" $iter 0 4'
            '  }'
            '  kfunc-call "bpf_iter_num_new" $iter 4 8'
            '  kfunc-call "bpf_iter_num_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires uninitialized bpf_iter_num stack object slot"
    }
    {
        name: "source-kfunc-iter-num-accepts-reinit-after-conditional-balanced-lifecycle"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime branch source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_iter_num_new" $iter 0 4'
            '    kfunc-call "bpf_iter_num_destroy" $iter'
            '  }'
            '  kfunc-call "bpf_iter_num_new" $iter 4 8'
            '  kfunc-call "bpf_iter_num_destroy" $iter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-iter-num-rejects-wrong-family-destroy"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_num_new" $iter 0 4'
            '  kfunc-call "bpf_iter_bits_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_bits_destroy' requires a matching bpf_iter_bits_new"
    }
    {
        name: "source-kfunc-iter-num-rejects-conditional-destroy-leak"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_num_new" $iter 0 4'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_iter_num_destroy" $iter'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased iter_num iterator"
    }
    {
        name: "source-kfunc-iter-num-rejects-destroy-after-conditional-destroy"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_num_new" $iter 0 4'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_iter_num_destroy" $iter'
            '  }'
            '  kfunc-call "bpf_iter_num_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_num_destroy' requires a matching bpf_iter_num_new"
    }
    {
        name: "source-kfunc-iter-bits-lifecycle-balanced"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let bits = "abcdefgh"'
            '  kfunc-call "bpf_iter_bits_new" $iter $bits 1'
            '  let item = (kfunc-call "bpf_iter_bits_next" $iter)'
            '  if $item { 0 }'
            '  kfunc-call "bpf_iter_bits_destroy" $iter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-iter-bits-rejects-next-without-new"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_bits_next" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_bits_next' requires a matching bpf_iter_bits_new"
    }
    {
        name: "source-kfunc-iter-bits-rejects-leak"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let bits = "abcdefgh"'
            '  kfunc-call "bpf_iter_bits_new" $iter $bits 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased iter_bits iterator"
    }
    {
        name: "source-kfunc-iter-bits-rejects-double-destroy"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let bits = "abcdefgh"'
            '  kfunc-call "bpf_iter_bits_new" $iter $bits 1'
            '  kfunc-call "bpf_iter_bits_destroy" $iter'
            '  kfunc-call "bpf_iter_bits_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_bits_destroy' requires a matching bpf_iter_bits_new"
    }
    {
        name: "source-kfunc-iter-bits-rejects-reinit-after-conditional-new"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let bits = "abcdefgh"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_iter_bits_new" $iter $bits 1'
            '  }'
            '  kfunc-call "bpf_iter_bits_new" $iter $bits 1'
            '  kfunc-call "bpf_iter_bits_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires uninitialized bpf_iter_bits stack object slot"
    }
    {
        name: "source-kfunc-iter-bits-accepts-reinit-after-conditional-balanced-lifecycle"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime branch source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let bits = "abcdefgh"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_iter_bits_new" $iter $bits 1'
            '    kfunc-call "bpf_iter_bits_destroy" $iter'
            '  }'
            '  kfunc-call "bpf_iter_bits_new" $iter $bits 1'
            '  kfunc-call "bpf_iter_bits_destroy" $iter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-iter-task-null-task-lifecycle-balanced"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_task_new" $iter 0 0'
            '  let task = (kfunc-call "bpf_iter_task_next" $iter)'
            '  if $task { 0 }'
            '  kfunc-call "bpf_iter_task_destroy" $iter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-iter-task-rejects-nonzero-task-scalar"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_task_new" $iter 1 0'
            '  kfunc-call "bpf_iter_task_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_task_new' arg1 expects null (0) or pointer"
    }
    {
        name: "source-kfunc-iter-task-vma-lifecycle-balanced"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_task_vma_new" $iter $ctx.current_task 0'
            '  let vma = (kfunc-call "bpf_iter_task_vma_next" $iter)'
            '  if $vma { 0 }'
            '  kfunc-call "bpf_iter_task_vma_destroy" $iter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-iter-task-vma-rejects-next-without-new"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_task_vma_next" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_task_vma_next' requires a matching bpf_iter_task_vma_new"
    }
    {
        name: "source-kfunc-iter-task-vma-rejects-leak"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_task_vma_new" $iter $ctx.current_task 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased iter_task_vma iterator"
    }
    {
        name: "source-kfunc-iter-task-vma-rejects-double-destroy"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_task_vma_new" $iter $ctx.current_task 0'
            '  kfunc-call "bpf_iter_task_vma_destroy" $iter'
            '  kfunc-call "bpf_iter_task_vma_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_task_vma_destroy' requires a matching bpf_iter_task_vma_new"
    }
    {
        name: "source-kfunc-iter-css-lifecycle-balanced"
        category: "helper-state"
        tags: [kfunc iter cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    kfunc-call "bpf_iter_css_new" $iter $cgrp 0'
            '    let css = (kfunc-call "bpf_iter_css_next" $iter)'
            '    if $css { 0 }'
            '    kfunc-call "bpf_iter_css_destroy" $iter'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-iter-css-rejects-next-without-new"
        category: "helper-state"
        tags: [kfunc iter cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_css_next" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_css_next' requires a matching bpf_iter_css_new"
    }
    {
        name: "source-kfunc-iter-css-rejects-leak"
        category: "helper-state"
        tags: [kfunc iter cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    kfunc-call "bpf_iter_css_new" $iter $cgrp 0'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased iter_css iterator"
    }
    {
        name: "source-kfunc-iter-css-rejects-double-destroy"
        category: "helper-state"
        tags: [kfunc iter cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    kfunc-call "bpf_iter_css_new" $iter $cgrp 0'
            '    kfunc-call "bpf_iter_css_destroy" $iter'
            '    kfunc-call "bpf_iter_css_destroy" $iter'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_css_destroy' requires a matching bpf_iter_css_new"
    }
    {
        name: "source-kfunc-iter-css-task-lifecycle-balanced"
        category: "helper-state"
        tags: [kfunc iter cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    kfunc-call "bpf_iter_css_task_new" $iter $cgrp 0'
            '    let task = (kfunc-call "bpf_iter_css_task_next" $iter)'
            '    if $task { 0 }'
            '    kfunc-call "bpf_iter_css_task_destroy" $iter'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-iter-css-task-rejects-next-without-new"
        category: "helper-state"
        tags: [kfunc iter cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_css_task_next" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_css_task_next' requires a matching bpf_iter_css_task_new"
    }
    {
        name: "source-kfunc-iter-css-task-rejects-leak"
        category: "helper-state"
        tags: [kfunc iter cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    kfunc-call "bpf_iter_css_task_new" $iter $cgrp 0'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased iter_css_task iterator"
    }
    {
        name: "source-kfunc-iter-css-task-rejects-double-destroy"
        category: "helper-state"
        tags: [kfunc iter cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    kfunc-call "bpf_iter_css_task_new" $iter $cgrp 0'
            '    kfunc-call "bpf_iter_css_task_destroy" $iter'
            '    kfunc-call "bpf_iter_css_task_destroy" $iter'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_css_task_destroy' requires a matching bpf_iter_css_task_new"
    }
    {
        name: "source-kfunc-iter-dmabuf-lifecycle-balanced"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_dmabuf_new" $iter'
            '  let buf = (kfunc-call "bpf_iter_dmabuf_next" $iter)'
            '  if $buf { 0 }'
            '  kfunc-call "bpf_iter_dmabuf_destroy" $iter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-iter-dmabuf-rejects-next-without-new"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_dmabuf_next" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_dmabuf_next' requires a matching bpf_iter_dmabuf_new"
    }
    {
        name: "source-kfunc-iter-dmabuf-rejects-leak"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_dmabuf_new" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased iter_dmabuf iterator"
    }
    {
        name: "source-kfunc-iter-dmabuf-rejects-double-destroy"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_dmabuf_new" $iter'
            '  kfunc-call "bpf_iter_dmabuf_destroy" $iter'
            '  kfunc-call "bpf_iter_dmabuf_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_dmabuf_destroy' requires a matching bpf_iter_dmabuf_new"
    }
    {
        name: "source-kfunc-iter-dmabuf-rejects-reinit-after-conditional-new"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_iter_dmabuf_new" $iter'
            '  }'
            '  kfunc-call "bpf_iter_dmabuf_new" $iter'
            '  kfunc-call "bpf_iter_dmabuf_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires uninitialized bpf_iter_dmabuf stack object slot"
    }
    {
        name: "source-kfunc-iter-dmabuf-accepts-reinit-after-conditional-balanced-lifecycle"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime branch source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_iter_dmabuf_new" $iter'
            '    kfunc-call "bpf_iter_dmabuf_destroy" $iter'
            '  }'
            '  kfunc-call "bpf_iter_dmabuf_new" $iter'
            '  kfunc-call "bpf_iter_dmabuf_destroy" $iter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-iter-kmem-cache-lifecycle-balanced"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_kmem_cache_new" $iter'
            '  let cache = (kfunc-call "bpf_iter_kmem_cache_next" $iter)'
            '  if $cache { 0 }'
            '  kfunc-call "bpf_iter_kmem_cache_destroy" $iter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-iter-kmem-cache-rejects-next-without-new"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_kmem_cache_next" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_kmem_cache_next' requires a matching bpf_iter_kmem_cache_new"
    }
    {
        name: "source-kfunc-iter-kmem-cache-rejects-leak"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_kmem_cache_new" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased iter_kmem_cache iterator"
    }
    {
        name: "source-kfunc-iter-kmem-cache-rejects-double-destroy"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_kmem_cache_new" $iter'
            '  kfunc-call "bpf_iter_kmem_cache_destroy" $iter'
            '  kfunc-call "bpf_iter_kmem_cache_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_kmem_cache_destroy' requires a matching bpf_iter_kmem_cache_new"
    }
    {
        name: "source-kfunc-iter-kmem-cache-rejects-reinit-after-conditional-new"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_iter_kmem_cache_new" $iter'
            '  }'
            '  kfunc-call "bpf_iter_kmem_cache_new" $iter'
            '  kfunc-call "bpf_iter_kmem_cache_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires uninitialized bpf_iter_kmem_cache stack object slot"
    }
    {
        name: "source-kfunc-iter-kmem-cache-accepts-reinit-after-conditional-balanced-lifecycle"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime branch source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_iter_kmem_cache_new" $iter'
            '    kfunc-call "bpf_iter_kmem_cache_destroy" $iter'
            '  }'
            '  kfunc-call "bpf_iter_kmem_cache_new" $iter'
            '  kfunc-call "bpf_iter_kmem_cache_destroy" $iter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-task-ref-release"
        category: "helper-state"
        tags: [kfunc ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    kfunc-call "bpf_task_release" $task'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-task-from-vpid-ref-release"
        category: "helper-state"
        tags: [kfunc ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_vpid" 1)'
            '  if $task {'
            '    kfunc-call "bpf_task_release" $task'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-task-from-vpid-rejects-leak"
        category: "helper-state"
        tags: [kfunc ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_vpid" 1)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-task-ref-rejects-leak"
        category: "helper-state"
        tags: [kfunc ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-task-release-accepts-acquire-or-null-release"
        category: "helper-state"
        tags: [kfunc ref-lifetime phi source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let task = (if $selector == 0 { kfunc-call "bpf_task_from_pid" 1 } else { 0 })'
            '  if $task {'
            '    kfunc-call "bpf_task_release" $task'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-xfrm-state-rejects-wrong-pointer-pointee"
        category: "helper-state"
        tags: [kfunc btf source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define opts --kind array --value-type bytes:32 --max-entries 1'
            '  let opts = (0 | map-get opts --kind array)'
            '  let data = $ctx.data'
            '  if $opts {'
            '    kfunc-call "bpf_xdp_get_xfrm_state" $data $opts 32'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_xdp_get_xfrm_state' arg0 expects xdp_md pointer"
    }
    {
        name: "source-kfunc-xdp-metadata-rx-timestamp"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let timestamp = "01234567"'
            '  let rc = (kfunc-call "bpf_xdp_metadata_rx_timestamp" $ctx $timestamp)'
            '  $rc | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-metadata-rx-timestamp-copied-raw-context"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source accept context-alias]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let raw_ctx = $ctx'
            '  let timestamp = "01234567"'
            '  let rc = (kfunc-call "bpf_xdp_metadata_rx_timestamp" $raw_ctx $timestamp)'
            '  $rc | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-metadata-rx-timestamp-user-function-raw-context"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source accept user-function]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def read_timestamp [raw_ctx] {'
            '    let timestamp = "01234567"'
            '    let rc = (kfunc-call "bpf_xdp_metadata_rx_timestamp" $raw_ctx $timestamp)'
            '    $rc | count'
            '    0'
            '  }'
            '  read_timestamp $ctx'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-metadata-rx-hash"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let hash = "0123"'
            '  let rss_type = "4567"'
            '  let rc = (kfunc-call "bpf_xdp_metadata_rx_hash" $ctx $hash $rss_type)'
            '  $rc | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-metadata-rx-hash-copied-raw-context"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source accept context-alias]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let raw_ctx = $ctx'
            '  let hash = "0123"'
            '  let rss_type = "4567"'
            '  let rc = (kfunc-call "bpf_xdp_metadata_rx_hash" $raw_ctx $hash $rss_type)'
            '  $rc | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-metadata-rx-vlan-tag"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let vlan_proto = "01"'
            '  let vlan_tci = "23"'
            '  let rc = (kfunc-call "bpf_xdp_metadata_rx_vlan_tag" $ctx $vlan_proto $vlan_tci)'
            '  $rc | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-metadata-rx-vlan-tag-copied-raw-context"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source accept context-alias]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let raw_ctx = $ctx'
            '  let vlan_proto = "01"'
            '  let vlan_tci = "23"'
            '  let rc = (kfunc-call "bpf_xdp_metadata_rx_vlan_tag" $raw_ctx $vlan_proto $vlan_tci)'
            '  $rc | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-metadata-rejects-non-xdp"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source reject]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let timestamp = "01234567"'
            '  kfunc-call "bpf_xdp_metadata_rx_timestamp" $ctx $timestamp'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_xdp_metadata_rx_timestamp' is only valid in xdp programs"
    }
    {
        name: "source-kfunc-xdp-metadata-rejects-packet-output-buffer"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: '{|ctx| kfunc-call "bpf_xdp_metadata_rx_timestamp" $ctx $ctx.data; "pass" }'
        local: "reject"
        kernel: "skip"
        error_contains: "got Packet"
    }
    {
        name: "source-kfunc-xdp-metadata-rx-hash-rejects-packet-rss-type-buffer"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let hash = "0123"'
            '  kfunc-call "bpf_xdp_metadata_rx_hash" $ctx $hash $ctx.data'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "got Packet"
    }
    {
        name: "source-kfunc-xdp-metadata-rx-vlan-tag-rejects-packet-tci-buffer"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let vlan_proto = "01"'
            '  kfunc-call "bpf_xdp_metadata_rx_vlan_tag" $ctx $vlan_proto $ctx.data'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "got Packet"
    }
    {
        name: "source-kfunc-xdp-xfrm-state-release"
        category: "helper-state"
        tags: [kfunc btf xdp ref-lifetime source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let opts = { error: 0, netns_id: -1, mark: 0, daddr: [0 0 0 0], spi: 0, proto: 50, family: 2 }'
            '  let state = (kfunc-call "bpf_xdp_get_xfrm_state" $ctx $opts 32)'
            '  if $state {'
            '    kfunc-call "bpf_xdp_xfrm_state_release" $state'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-xfrm-state-release-accepts-acquire-or-null-release"
        category: "helper-state"
        tags: [kfunc btf xdp ref-lifetime phi source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let opts = { error: 0, netns_id: -1, mark: 0, daddr: [0 0 0 0], spi: 0, proto: 50, family: 2 }'
            '  let state = (if $selector == 0 { kfunc-call "bpf_xdp_get_xfrm_state" $ctx $opts 32 } else { 0 })'
            '  if $state {'
            '    kfunc-call "bpf_xdp_xfrm_state_release" $state'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-xfrm-state-copied-raw-context-release"
        category: "helper-state"
        tags: [kfunc btf xdp ref-lifetime source accept context-alias]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let raw_ctx = $ctx'
            '  let opts = { error: 0, netns_id: -1, mark: 0, daddr: [0 0 0 0], spi: 0, proto: 50, family: 2 }'
            '  let state = (kfunc-call "bpf_xdp_get_xfrm_state" $raw_ctx $opts 32)'
            '  if $state {'
            '    kfunc-call "bpf_xdp_xfrm_state_release" $state'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-xfrm-state-user-function-raw-context-release"
        category: "helper-state"
        tags: [kfunc btf xdp ref-lifetime source accept user-function]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def get_state [raw_ctx] {'
            '    let opts = { error: 0, netns_id: -1, mark: 0, daddr: [0 0 0 0], spi: 0, proto: 50, family: 2 }'
            '    let state = (kfunc-call "bpf_xdp_get_xfrm_state" $raw_ctx $opts 32)'
            '    if $state {'
            '      kfunc-call "bpf_xdp_xfrm_state_release" $state'
            '    }'
            '    0'
            '  }'
            '  get_state $ctx'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-xfrm-state-rejects-small-opts-buffer"
        category: "helper-state"
        tags: [kfunc btf xdp bounds source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define opts --kind array --value-type bytes:16 --max-entries 1'
            '  let opts = (0 | map-get opts --kind array)'
            '  if $opts {'
            '    let state = (kfunc-call "bpf_xdp_get_xfrm_state" $ctx $opts 32)'
            '    if $state { kfunc-call "bpf_xdp_xfrm_state_release" $state }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc bpf_xdp_get_xfrm_state opts requires 32 bytes"
    }
    {
        name: "source-kfunc-xdp-xfrm-state-rejects-non-xdp-program"
        category: "helper-state"
        tags: [kfunc btf xdp program-policy source reject]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define opts --kind array --value-type bytes:32 --max-entries 1'
            '  let opts = (0 | map-get opts --kind array)'
            '  if $opts {'
            '    let state = (kfunc-call "bpf_xdp_get_xfrm_state" $ctx $opts 32)'
            '    if $state { kfunc-call "bpf_xdp_xfrm_state_release" $state }'
            '  }'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_xdp_get_xfrm_state' is only valid in xdp programs"
    }
    {
        name: "source-kfunc-xdp-xfrm-state-rejects-leak"
        category: "helper-state"
        tags: [kfunc btf xdp ref-lifetime source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let opts = { error: 0, netns_id: -1, mark: 0, daddr: [0 0 0 0], spi: 0, proto: 50, family: 2 }'
            '  let state = (kfunc-call "bpf_xdp_get_xfrm_state" $ctx $opts 32)'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-obj-new-drop"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-obj-drop-accepts-new-or-null-release"
        category: "helper-state"
        tags: [kfunc object ref-lifetime phi source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let obj = (if $selector == 0 { kfunc-call "bpf_obj_new_impl" 1 0 } else { 0 })'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-obj-new-rejects-leak"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-obj-new-rejects-dynamic-type-id"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let type_id = ($ctx.pid + 1)'
            '  let obj = (kfunc-call "bpf_obj_new_impl" $type_id 0)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 must be known constant"
    }
    {
        name: "source-kfunc-obj-new-rejects-zero-type-id"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 0 0)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 must be > 0"
    }
    {
        name: "source-kfunc-obj-new-rejects-dynamic-meta"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let meta = ($ctx.pid + 1)'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 $meta)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_obj_new_impl' arg1 must be known zero"
    }
    {
        name: "source-kfunc-obj-drop-rejects-nonzero-meta"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 1'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_obj_drop_impl' arg1 must be known zero"
    }
    {
        name: "source-kfunc-obj-drop-rejects-double-drop"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_obj_drop_impl' arg0 reference already released"
    }
    {
        name: "source-kfunc-obj-drop-accepts-both-branch-release"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source phi accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  if $obj {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    if $selector == 0 {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    } else {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-obj-drop-rejects-one-branch-release-leak"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source phi reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  if $obj {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    if $selector == 0 {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-obj-drop-rejects-release-after-conditional-release"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source phi reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  if $obj {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    if $selector == 0 {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_obj_drop_impl' arg0 reference already released"
    }
    {
        name: "source-kfunc-refcount-acquire-rejects-map-field"
        category: "helper-state"
        tags: [kfunc object bpf_refcount ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ref_items --kind hash --value-type "record{refs:bpf_refcount,cookie:u64}"'
            '  let entry = (0 | map-get ref_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_refcount_acquire_impl" $entry.refs 0)'
            '    if $obj {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects kernel pointer, got Map"
    }
    {
        name: "source-kfunc-refcount-acquire-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc object bpf_refcount ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    let obj = (kfunc-call "bpf_refcount_acquire_impl" $task 0)'
            '    if $obj {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '    kfunc-call "bpf_task_release" $task'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects object reference"
    }
    {
        name: "source-kfunc-percpu-obj-new-drop"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  if $obj {'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-percpu-obj-drop-accepts-new-or-null-release"
        category: "helper-state"
        tags: [kfunc object ref-lifetime phi source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let obj = (if $selector == 0 { kfunc-call "bpf_percpu_obj_new_impl" 1 0 } else { 0 })'
            '  if $obj {'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-percpu-obj-new-rejects-leak"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-percpu-obj-new-rejects-dynamic-type-id"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let type_id = ($ctx.pid + 1)'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" $type_id 0)'
            '  if $obj {'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 must be known constant"
    }
    {
        name: "source-kfunc-percpu-obj-new-rejects-zero-type-id"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 0 0)'
            '  if $obj {'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 must be > 0"
    }
    {
        name: "source-kfunc-percpu-obj-new-rejects-dynamic-meta"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let meta = ($ctx.pid + 1)'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 $meta)'
            '  if $obj {'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_percpu_obj_new_impl' arg1 must be known zero"
    }
    {
        name: "source-kfunc-percpu-obj-drop-rejects-dynamic-meta"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  if $obj {'
            '    let meta = ($ctx.pid + 1)'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj $meta'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_percpu_obj_drop_impl' arg1 must be known zero"
    }
    {
        name: "source-kfunc-percpu-obj-drop-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $task 0'
            '    kfunc-call "bpf_task_release" $task'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects object reference"
    }
    {
        name: "source-kfunc-obj-drop-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    kfunc-call "bpf_obj_drop_impl" $task 0'
            '    kfunc-call "bpf_task_release" $task'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects object reference"
    }
    {
        name: "source-kfunc-percpu-obj-drop-rejects-double-drop"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  if $obj {'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_percpu_obj_drop_impl' arg0 reference already released"
    }
    {
        name: "source-kfunc-percpu-obj-drop-accepts-both-branch-release"
        category: "helper-state"
        tags: [kfunc object ref-lifetime branch source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  if $obj {'
            '    if $ctx.pid {'
            '      kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '    } else {'
            '      kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-percpu-obj-drop-rejects-one-branch-release-leak"
        category: "helper-state"
        tags: [kfunc object ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  if $obj {'
            '    if $ctx.pid {'
            '      kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-percpu-obj-drop-rejects-release-after-conditional-release"
        category: "helper-state"
        tags: [kfunc object ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  if $obj {'
            '    if $ctx.pid {'
            '      kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '    }'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_percpu_obj_drop_impl' arg0 reference already released"
    }
    {
        name: "source-kfunc-list-push-front-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '      kfunc-call "bpf_list_push_front_impl" $entry.root $obj 0 0'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-push-front-rejects-missing-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      kfunc-call "bpf_list_push_front_impl" $entry.root $obj 0 0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-push-front-rejects-different-map-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let lock_entry = (0 | map-get locks --kind hash)'
            '    if $lock_entry {'
            '      let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '      if $obj {'
            '        helper-call "bpf_spin_lock" $lock_entry.lock'
            '        kfunc-call "bpf_list_push_front_impl" $entry.root $obj 0 0'
            '        helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-push-front-rejects-rbtree-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '      kfunc-call "bpf_list_push_front_impl" $entry.root $obj 0 0'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_list_head pointer"
    }
    {
        name: "source-kfunc-list-push-front-same-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let key = 0'
            '  let lock_entry = ($key | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($key | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '      if $obj {'
            '        helper-call "bpf_spin_lock" $lock_entry.lock'
            '        kfunc-call "bpf_list_push_front_impl" $root_entry.root $obj 0 0'
            '        helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-push-front-rejects-different-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let lock_entry = (0 | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = (1 | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '      if $obj {'
            '        helper-call "bpf_spin_lock" $lock_entry.lock'
            '        kfunc-call "bpf_list_push_front_impl" $root_entry.root $obj 0 0'
            '        helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-front-rejects-missing-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_list_front" $entry.root)'
            '    if $obj {'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-front-rejects-different-map-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let lock_entry = (0 | map-get locks --kind hash)'
            '    if $lock_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_front" $entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-front-rejects-rbtree-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let obj = (kfunc-call "bpf_list_front" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj { 0 }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_list_head pointer"
    }
    {
        name: "source-kfunc-list-push-front-rejects-dynamic-meta"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      let meta = ($ctx.packet_len + 1)'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '      kfunc-call "bpf_list_push_front_impl" $entry.root $obj $meta 0'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_list_push_front_impl' arg2 must be known zero"
    }
    {
        name: "source-kfunc-list-push-back-rejects-dynamic-meta"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      let meta = ($ctx.packet_len + 1)'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '      kfunc-call "bpf_list_push_back_impl" $entry.root $obj $meta 0'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_list_push_back_impl' arg2 must be known zero"
    }
    {
        name: "source-kfunc-list-push-back-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '      kfunc-call "bpf_list_push_back_impl" $entry.root $obj 0 0'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-push-back-rejects-missing-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      kfunc-call "bpf_list_push_back_impl" $entry.root $obj 0 0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-push-back-rejects-different-map-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let lock_entry = (0 | map-get locks --kind hash)'
            '    if $lock_entry {'
            '      let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '      if $obj {'
            '        helper-call "bpf_spin_lock" $lock_entry.lock'
            '        kfunc-call "bpf_list_push_back_impl" $entry.root $obj 0 0'
            '        helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-push-back-rejects-rbtree-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '      kfunc-call "bpf_list_push_back_impl" $entry.root $obj 0 0'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_list_head pointer"
    }
    {
        name: "source-kfunc-list-push-back-same-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let key = 0'
            '  let lock_entry = ($key | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($key | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '      if $obj {'
            '        helper-call "bpf_spin_lock" $lock_entry.lock'
            '        kfunc-call "bpf_list_push_back_impl" $root_entry.root $obj 0 0'
            '        helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-push-back-rejects-different-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let lock_entry = (0 | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = (1 | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '      if $obj {'
            '        helper-call "bpf_spin_lock" $lock_entry.lock'
            '        kfunc-call "bpf_list_push_back_impl" $root_entry.root $obj 0 0'
            '        helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-pop-front-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let obj = (kfunc-call "bpf_list_pop_front" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-pop-front-rejects-missing-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_list_pop_front" $entry.root)'
            '    if $obj {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-pop-front-rejects-different-map-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let lock_entry = (0 | map-get locks --kind hash)'
            '    if $lock_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_pop_front" $entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj {'
            '        kfunc-call "bpf_obj_drop_impl" $obj 0'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-pop-front-rejects-rbtree-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let obj = (kfunc-call "bpf_list_pop_front" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_list_head pointer"
    }
    {
        name: "source-kfunc-list-pop-front-same-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let key = 0'
            '  let lock_entry = ($key | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($key | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_pop_front" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj {'
            '        kfunc-call "bpf_obj_drop_impl" $obj 0'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-pop-front-rejects-different-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let lock_entry = (0 | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = (1 | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_pop_front" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj {'
            '        kfunc-call "bpf_obj_drop_impl" $obj 0'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-pop-front-projects-object-payload"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node:record{refs:bpf_refcount,cookie:u64}}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let obj = (kfunc-call "bpf_list_pop_front" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj {'
            '      let cookie = $obj.cookie'
            '      let clone = (kfunc-call "bpf_refcount_acquire_impl" $obj 0)'
            '      if $clone {'
            '        kfunc-call "bpf_obj_drop_impl" $clone 0'
            '      }'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '      $cookie'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-pop-front-refcount-acquire-accepts-nested-refcount-payload"
        category: "helper-state"
        tags: [kfunc object graph bpf_refcount source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node:record{meta:record{refs:bpf_refcount},cookie:u64}}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let obj = (kfunc-call "bpf_list_pop_front" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj {'
            '      let clone = (kfunc-call "bpf_refcount_acquire_impl" $obj 0)'
            '      if $clone {'
            '        kfunc-call "bpf_obj_drop_impl" $clone 0'
            '      }'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-refcount-acquire-rejects-graph-object-without-refcount"
        category: "helper-state"
        tags: [kfunc object graph bpf_refcount source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node:record{cookie:u64}}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let obj = (kfunc-call "bpf_list_pop_front" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj {'
            '      let clone = (kfunc-call "bpf_refcount_acquire_impl" $obj 0)'
            '      if $clone {'
            '        kfunc-call "bpf_obj_drop_impl" $clone 0'
            '      }'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 expects object pointer containing bpf_refcount"
    }
    {
        name: "source-kfunc-list-pop-back-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let obj = (kfunc-call "bpf_list_pop_back" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-pop-back-rejects-missing-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_list_pop_back" $entry.root)'
            '    if $obj {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-pop-back-rejects-different-map-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let lock_entry = (0 | map-get locks --kind hash)'
            '    if $lock_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_pop_back" $entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj {'
            '        kfunc-call "bpf_obj_drop_impl" $obj 0'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-pop-back-rejects-rbtree-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let obj = (kfunc-call "bpf_list_pop_back" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_list_head pointer"
    }
    {
        name: "source-kfunc-list-pop-back-same-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let key = 0'
            '  let lock_entry = ($key | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($key | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_pop_back" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj {'
            '        kfunc-call "bpf_obj_drop_impl" $obj 0'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-pop-back-rejects-different-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let lock_entry = (0 | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = (1 | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_pop_back" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj {'
            '        kfunc-call "bpf_obj_drop_impl" $obj 0'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-front-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,lock:bpf_spin_lock,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let obj = (kfunc-call "bpf_list_front" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj {'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-front-projects-object-payload"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node:record{refs:bpf_refcount,cookie:u64}}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_list_front" $entry.root)'
            '    if $node {'
            '      let cookie = $node.cookie'
            '      let clone = (kfunc-call "bpf_refcount_acquire_impl" $node 0)'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      if $clone {'
            '        kfunc-call "bpf_obj_drop_impl" $clone 0'
            '      }'
            '      $cookie'
            '    } else {'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-front-refcount-acquire-rejects-object-without-refcount"
        category: "helper-state"
        tags: [kfunc object graph bpf_refcount source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node:record{cookie:u64}}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_list_front" $entry.root)'
            '    if $node {'
            '      let clone = (kfunc-call "bpf_refcount_acquire_impl" $node 0)'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      if $clone {'
            '        kfunc-call "bpf_obj_drop_impl" $clone 0'
            '      }'
            '    } else {'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 expects object pointer containing bpf_refcount"
    }
    {
        name: "source-kfunc-list-front-same-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let key = 0'
            '  let lock_entry = ($key | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($key | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_front" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-front-dynamic-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let key = $ctx.packet_len'
            '  let lock_entry = ($key | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($key | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_front" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-front-copied-dynamic-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let key = $ctx.packet_len'
            '  let lock_key = $key'
            '  let root_key = $key'
            '  let lock_entry = ($lock_key | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($root_key | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_front" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-front-noop-dynamic-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let key = $ctx.packet_len'
            '  let root_key = ($key + 0)'
            '  let lock_entry = ($key | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($root_key | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_front" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-front-equivalent-expr-dynamic-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --key-type u64 --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let key = $ctx.packet_len'
            '  let lock_key = ($key + 1)'
            '  let root_key = ($key + 1)'
            '  let lock_entry = ($lock_key | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($root_key | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_front" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-front-rejects-offset-dynamic-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --key-type u64 --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let key = $ctx.packet_len'
            '  let root_key = ($key + 1)'
            '  let lock_entry = ($key | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($root_key | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_front" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-front-rejects-different-expr-dynamic-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --key-type u64 --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let key = $ctx.packet_len'
            '  let lock_key = ($key + 1)'
            '  let root_key = ($key + 2)'
            '  let lock_entry = ($lock_key | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($root_key | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_front" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-front-phi-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source phi accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let base_key = $ctx.packet_len'
            '  let left_key = $base_key'
            '  let right_key = $base_key'
            '  let key = (if $selector == 0 { $left_key } else { $right_key })'
            '  let lock_entry = ($key | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($key | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_front" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-front-rejects-different-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let lock_entry = (0 | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = (1 | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_front" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-front-rejects-different-dynamic-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let lock_key = $ctx.packet_len'
            '  let root_key = $ctx.ifindex'
            '  let lock_entry = ($lock_key | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($root_key | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_front" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-back-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let obj = (kfunc-call "bpf_list_back" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj {'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-back-rejects-missing-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_list_back" $entry.root)'
            '    if $obj {'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-back-rejects-different-map-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let lock_entry = (0 | map-get locks --kind hash)'
            '    if $lock_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_back" $entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-list-back-rejects-rbtree-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let obj = (kfunc-call "bpf_list_back" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj { 0 }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_list_head pointer"
    }
    {
        name: "source-kfunc-list-back-projects-object-payload"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node:record{refs:bpf_refcount,cookie:u64}}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_list_back" $entry.root)'
            '    if $node {'
            '      let cookie = $node.cookie'
            '      let clone = (kfunc-call "bpf_refcount_acquire_impl" $node 0)'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      if $clone {'
            '        kfunc-call "bpf_obj_drop_impl" $clone 0'
            '      }'
            '      $cookie'
            '    } else {'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-back-refcount-acquire-rejects-object-without-refcount"
        category: "helper-state"
        tags: [kfunc object graph bpf_refcount source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node:record{cookie:u64}}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_list_back" $entry.root)'
            '    if $node {'
            '      let clone = (kfunc-call "bpf_refcount_acquire_impl" $node 0)'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      if $clone {'
            '        kfunc-call "bpf_obj_drop_impl" $clone 0'
            '      }'
            '    } else {'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 expects object pointer containing bpf_refcount"
    }
    {
        name: "source-kfunc-list-back-same-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let key = 0'
            '  let lock_entry = ($key | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($key | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_back" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-list-back-rejects-different-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let lock_entry = (0 | map-get graph_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = (1 | map-get graph_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_list_back" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-rbtree-first-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let obj = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj {'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rbtree-first-rejects-missing-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    if $obj {'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-rbtree-first-rejects-different-map-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let lock_entry = (0 | map-get locks --kind hash)'
            '    if $lock_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj {'
            '        0'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-rbtree-first-rejects-list-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let obj = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $obj {'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_rb_root pointer"
    }
    {
        name: "source-kfunc-rbtree-first-projects-object-payload"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb:record{refs:bpf_refcount,cookie:u64}}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    if $node {'
            '      let cookie = $node.cookie'
            '      let clone = (kfunc-call "bpf_refcount_acquire_impl" $node 0)'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      if $clone {'
            '        kfunc-call "bpf_obj_drop_impl" $clone 0'
            '      }'
            '      $cookie'
            '    } else {'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rbtree-first-refcount-acquire-rejects-object-without-refcount"
        category: "helper-state"
        tags: [kfunc object graph bpf_refcount source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb:record{cookie:u64}}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    if $node {'
            '      let clone = (kfunc-call "bpf_refcount_acquire_impl" $node 0)'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      if $clone {'
            '        kfunc-call "bpf_obj_drop_impl" $clone 0'
            '      }'
            '    } else {'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 expects object pointer containing bpf_refcount"
    }
    {
        name: "source-kfunc-rbtree-first-same-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let key = 0'
            '  let lock_entry = ($key | map-get rb_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($key | map-get rb_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_rbtree_first" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rbtree-first-dynamic-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let key = $ctx.packet_len'
            '  let lock_entry = ($key | map-get rb_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($key | map-get rb_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_rbtree_first" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rbtree-first-copied-dynamic-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let key = $ctx.packet_len'
            '  let lock_key = $key'
            '  let root_key = $key'
            '  let lock_entry = ($lock_key | map-get rb_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($root_key | map-get rb_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_rbtree_first" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rbtree-first-rejects-different-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let lock_entry = (0 | map-get rb_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = (1 | map-get rb_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let obj = (kfunc-call "bpf_rbtree_first" $root_entry.root)'
            '      helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      if $obj { 0 }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-rbtree-remove-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    if $node {'
            '      let obj = (kfunc-call "bpf_rbtree_remove" $entry.root $node)'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      if $obj {'
            '        kfunc-call "bpf_obj_drop_impl" $obj 0'
            '      }'
            '    } else {'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rbtree-remove-rejects-missing-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $node {'
            '      let obj = (kfunc-call "bpf_rbtree_remove" $entry.root $node)'
            '      if $obj {'
            '        kfunc-call "bpf_obj_drop_impl" $obj 0'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-rbtree-remove-rejects-different-map-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $node {'
            '      let lock_entry = (0 | map-get locks --kind hash)'
            '      if $lock_entry {'
            '        helper-call "bpf_spin_lock" $lock_entry.lock'
            '        let obj = (kfunc-call "bpf_rbtree_remove" $entry.root $node)'
            '        helper-call "bpf_spin_unlock" $lock_entry.lock'
            '        if $obj {'
            '          kfunc-call "bpf_obj_drop_impl" $obj 0'
            '        }'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-rbtree-remove-rejects-list-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let rb_entry = (0 | map-get rb_items --kind hash)'
            '  if $rb_entry {'
            '    let graph_entry = (0 | map-get graph_items --kind hash)'
            '    if $graph_entry {'
            '      helper-call "bpf_spin_lock" $rb_entry.lock'
            '      let node = (kfunc-call "bpf_rbtree_first" $rb_entry.root)'
            '      helper-call "bpf_spin_unlock" $rb_entry.lock'
            '      if $node {'
            '        helper-call "bpf_spin_lock" $graph_entry.lock'
            '        let obj = (kfunc-call "bpf_rbtree_remove" $graph_entry.root $node)'
            '        helper-call "bpf_spin_unlock" $graph_entry.lock'
            '        if $obj {'
            '          kfunc-call "bpf_obj_drop_impl" $obj 0'
            '        }'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_rb_root pointer"
    }
    {
        name: "source-kfunc-rbtree-remove-rejects-list-node"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let rb_entry = (0 | map-get rb_items --kind hash)'
            '  if $rb_entry {'
            '    let graph_entry = (0 | map-get graph_items --kind hash)'
            '    if $graph_entry {'
            '      helper-call "bpf_spin_lock" $graph_entry.lock'
            '      let node = (kfunc-call "bpf_list_front" $graph_entry.root)'
            '      helper-call "bpf_spin_unlock" $graph_entry.lock'
            '      if $node {'
            '        helper-call "bpf_spin_lock" $rb_entry.lock'
            '        let obj = (kfunc-call "bpf_rbtree_remove" $rb_entry.root $node)'
            '        helper-call "bpf_spin_unlock" $rb_entry.lock'
            '        if $obj {'
            '          kfunc-call "bpf_obj_drop_impl" $obj 0'
            '        }'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_rb_node pointer"
    }
    {
        name: "source-kfunc-rbtree-remove-projects-object-payload"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb:record{refs:bpf_refcount,cookie:u64}}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    if $node {'
            '      let obj = (kfunc-call "bpf_rbtree_remove" $entry.root $node)'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      if $obj {'
            '        let cookie = $obj.cookie'
            '        let clone = (kfunc-call "bpf_refcount_acquire_impl" $obj 0)'
            '        if $clone {'
            '          kfunc-call "bpf_obj_drop_impl" $clone 0'
            '        }'
            '        kfunc-call "bpf_obj_drop_impl" $obj 0'
            '        $cookie'
            '      }'
            '    } else {'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rbtree-remove-refcount-acquire-rejects-object-without-refcount"
        category: "helper-state"
        tags: [kfunc object graph bpf_refcount source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb:record{cookie:u64}}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    if $node {'
            '      let obj = (kfunc-call "bpf_rbtree_remove" $entry.root $node)'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      if $obj {'
            '        let clone = (kfunc-call "bpf_refcount_acquire_impl" $obj 0)'
            '        if $clone {'
            '          kfunc-call "bpf_obj_drop_impl" $clone 0'
            '        }'
            '        kfunc-call "bpf_obj_drop_impl" $obj 0'
            '      }'
            '    } else {'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 expects object pointer containing bpf_refcount"
    }
    {
        name: "source-kfunc-rbtree-remove-same-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let key = 0'
            '  let lock_entry = ($key | map-get rb_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($key | map-get rb_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let node = (kfunc-call "bpf_rbtree_first" $root_entry.root)'
            '      if $node {'
            '        let obj = (kfunc-call "bpf_rbtree_remove" $root_entry.root $node)'
            '        helper-call "bpf_spin_unlock" $lock_entry.lock'
            '        if $obj {'
            '          kfunc-call "bpf_obj_drop_impl" $obj 0'
            '        }'
            '      } else {'
            '        helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rbtree-remove-rejects-different-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let lock_entry = (0 | map-get rb_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = (1 | map-get rb_items --kind hash)'
            '    if $root_entry {'
            '      helper-call "bpf_spin_lock" $lock_entry.lock'
            '      let node = (kfunc-call "bpf_rbtree_first" $lock_entry.root)'
            '      if $node {'
            '        let obj = (kfunc-call "bpf_rbtree_remove" $root_entry.root $node)'
            '        helper-call "bpf_spin_unlock" $lock_entry.lock'
            '        if $obj {'
            '          kfunc-call "bpf_obj_drop_impl" $obj 0'
            '        }'
            '      } else {'
            '        helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-rbtree-root-from-node"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $node {'
            '      let root = (kfunc-call "bpf_rbtree_root" $node)'
            '      if $root {'
            '        0'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rbtree-left-from-node"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $node {'
            '      let left = (kfunc-call "bpf_rbtree_left" $node)'
            '      if $left {'
            '        0'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rbtree-left-projects-object-payload"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb:record{refs:bpf_refcount,cookie:u64}}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $node {'
            '      let left = (kfunc-call "bpf_rbtree_left" $node)'
            '      if $left {'
            '        let cookie = $left.cookie'
            '        let clone = (kfunc-call "bpf_refcount_acquire_impl" $left 0)'
            '        if $clone {'
            '          kfunc-call "bpf_obj_drop_impl" $clone 0'
            '        }'
            '        $cookie'
            '      }'
            '    } else {'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rbtree-left-refcount-acquire-rejects-object-without-refcount"
        category: "helper-state"
        tags: [kfunc object graph bpf_refcount source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb:record{cookie:u64}}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $node {'
            '      let left = (kfunc-call "bpf_rbtree_left" $node)'
            '      if $left {'
            '        let clone = (kfunc-call "bpf_refcount_acquire_impl" $left 0)'
            '        if $clone {'
            '          kfunc-call "bpf_obj_drop_impl" $clone 0'
            '        }'
            '      }'
            '    } else {'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 expects object pointer containing bpf_refcount"
    }
    {
        name: "source-kfunc-rbtree-right-from-node"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $node {'
            '      let right = (kfunc-call "bpf_rbtree_right" $node)'
            '      if $right {'
            '        0'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rbtree-right-projects-object-payload"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb:record{refs:bpf_refcount,cookie:u64}}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $node {'
            '      let right = (kfunc-call "bpf_rbtree_right" $node)'
            '      if $right {'
            '        let cookie = $right.cookie'
            '        let clone = (kfunc-call "bpf_refcount_acquire_impl" $right 0)'
            '        if $clone {'
            '          kfunc-call "bpf_obj_drop_impl" $clone 0'
            '        }'
            '        $cookie'
            '      }'
            '    } else {'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rbtree-right-refcount-acquire-rejects-object-without-refcount"
        category: "helper-state"
        tags: [kfunc object graph bpf_refcount source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb:record{cookie:u64}}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $node {'
            '      let right = (kfunc-call "bpf_rbtree_right" $node)'
            '      if $right {'
            '        let clone = (kfunc-call "bpf_refcount_acquire_impl" $right 0)'
            '        if $clone {'
            '          kfunc-call "bpf_obj_drop_impl" $clone 0'
            '        }'
            '      }'
            '    } else {'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 expects object pointer containing bpf_refcount"
    }
    {
        name: "source-kfunc-rbtree-root-rejects-map-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let root = (kfunc-call "bpf_rbtree_root" $entry.root)'
            '    if $root {'
            '      0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects kernel pointer, got Map"
    }
    {
        name: "source-kfunc-rbtree-left-rejects-list-node"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_list_front" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $node {'
            '      let left = (kfunc-call "bpf_rbtree_left" $node)'
            '      if $left {'
            '        0'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_rb_node pointer"
    }
    {
        name: "source-kfunc-rbtree-right-rejects-list-node"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_list_front" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $node {'
            '      let right = (kfunc-call "bpf_rbtree_right" $node)'
            '      if $right {'
            '        0'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_rb_node pointer"
    }
    {
        name: "source-kfunc-rbtree-root-rejects-list-node"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    let node = (kfunc-call "bpf_list_front" $entry.root)'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '    if $node {'
            '      let root = (kfunc-call "bpf_rbtree_root" $node)'
            '      if $root {'
            '        0'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_rb_node pointer"
    }
    {
        name: "source-kfunc-rbtree-add-map-root"
        category: "helper-state"
        tags: [kfunc object graph callback source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '      kfunc-call "bpf_rbtree_add_impl" $entry.root $obj {|a b| 0} 0 0'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rbtree-add-rejects-missing-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph callback source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      kfunc-call "bpf_rbtree_add_impl" $entry.root $obj {|a b| 0} 0 0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-rbtree-add-rejects-different-map-spin-lock"
        category: "helper-state"
        tags: [kfunc object graph callback source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let lock_entry = (0 | map-get locks --kind hash)'
            '    if $lock_entry {'
            '      let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '      if $obj {'
            '        helper-call "bpf_spin_lock" $lock_entry.lock'
            '        kfunc-call "bpf_rbtree_add_impl" $entry.root $obj {|a b| 0} 0 0'
            '        helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-rbtree-add-rejects-list-root"
        category: "helper-state"
        tags: [kfunc object graph callback source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '      kfunc-call "bpf_rbtree_add_impl" $entry.root $obj {|a b| 0} 0 0'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_rb_root pointer"
    }
    {
        name: "source-kfunc-rbtree-add-same-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph callback source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let key = 0'
            '  let lock_entry = ($key | map-get rb_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = ($key | map-get rb_items --kind hash)'
            '    if $root_entry {'
            '      let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '      if $obj {'
            '        helper-call "bpf_spin_lock" $lock_entry.lock'
            '        kfunc-call "bpf_rbtree_add_impl" $root_entry.root $obj {|a b| 0} 0 0'
            '        helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rbtree-add-rejects-different-key-repeated-map-root"
        category: "helper-state"
        tags: [kfunc object graph callback source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let lock_entry = (0 | map-get rb_items --kind hash)'
            '  if $lock_entry {'
            '    let root_entry = (1 | map-get rb_items --kind hash)'
            '    if $root_entry {'
            '      let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '      if $obj {'
            '        helper-call "bpf_spin_lock" $lock_entry.lock'
            '        kfunc-call "bpf_rbtree_add_impl" $root_entry.root $obj {|a b| 0} 0 0'
            '        helper-call "bpf_spin_unlock" $lock_entry.lock'
            '      }'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires bpf_spin_lock from the same map value"
    }
    {
        name: "source-kfunc-rbtree-add-rejects-dynamic-meta"
        category: "helper-state"
        tags: [kfunc object graph callback source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      let meta = ($ctx.packet_len + 1)'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '      kfunc-call "bpf_rbtree_add_impl" $entry.root $obj {|a b| 0} $meta 0'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_rbtree_add_impl' arg3 must be known zero"
    }
    {
        name: "source-kfunc-rbtree-add-callback-uses-node-args"
        category: "helper-state"
        tags: [kfunc object graph callback source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '      kfunc-call "bpf_rbtree_add_impl" $entry.root $obj {|a b| if $a { if $b { 1 } else { 0 } } else { 0 }} 0 0'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rbtree-add-callback-rejects-out-of-range-return"
        category: "helper-state"
        tags: [kfunc object graph callback return source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '      kfunc-call "bpf_rbtree_add_impl" $entry.root $obj {|a b| 2} 0 0'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "callback return"
    }
    {
        name: "source-kfunc-rbtree-add-callback-allows-prefix-params"
        category: "helper-state"
        tags: [kfunc object graph callback prefix-arity source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '      kfunc-call "bpf_rbtree_add_impl" $entry.root $obj {|a| if $a { 1 } else { 0 }} 0 0'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rbtree-add-callback-rejects-extra-declared-param"
        category: "helper-state"
        tags: [kfunc object graph callback source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '      kfunc-call "bpf_rbtree_add_impl" $entry.root $obj {|a b extra| 0} 0 0'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "declares 3 parameters, but the callback ABI supplies 2"
    }
    {
        name: "source-kfunc-rbtree-add-callback-node-kfunc"
        category: "helper-state"
        tags: [kfunc object graph callback source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '      kfunc-call "bpf_rbtree_add_impl" $entry.root $obj {|a b|'
            '        let left = (kfunc-call "bpf_rbtree_left" $a)'
            '        if $left { 1 } else { 0 }'
            '      } 0 0'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rbtree-add-rejects-non-callback"
        category: "helper-state"
        tags: [kfunc object graph callback source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '      kfunc-call "bpf_rbtree_add_impl" $entry.root $obj 0 0 0'
            '      helper-call "bpf_spin_unlock" $entry.lock'
            '    }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a closure or block literal callback"
    }
    {
        name: "source-kfunc-task-acquire-release"
        category: "helper-state"
        tags: [kfunc ref-lifetime source accept]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  if $task {'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-task-acquire-user-function-release"
        category: "helper-state"
        tags: [kfunc ref-lifetime source accept user-function]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  def release_task [task] {'
            '    $task | kfunc-call "bpf_task_release"'
            '    0'
            '  }'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  if $task {'
            '    release_task $task'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-task-user-function-acquire-release"
        category: "helper-state"
        tags: [kfunc ref-lifetime source accept user-function]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  def acquire_task [task] {'
            '    kfunc-call "bpf_task_acquire" $task'
            '  }'
            '  let task = (acquire_task $ctx.task)'
            '  if $task {'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-task-acquire-project-release"
        category: "helper-state"
        tags: [kfunc ref-lifetime source metadata accept]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  if $task {'
            '    $task.pid | count'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-task-acquire-rejects-leak"
        category: "helper-state"
        tags: [kfunc ref-lifetime source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-task-release-rejects-use-after-release"
        category: "helper-state"
        tags: [kfunc ref-lifetime source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  if $task {'
            '    kfunc-call "bpf_task_release" $task'
            '    $task.pid | count'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "uses released reference"
    }
    {
        name: "source-kfunc-task-release-rejects-double-release"
        category: "helper-state"
        tags: [kfunc ref-lifetime source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  if $task {'
            '    kfunc-call "bpf_task_release" $task'
            '    kfunc-call "bpf_task_release" $task'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "reference already released"
    }
    {
        name: "source-kfunc-task-release-rejects-cgroup-ref"
        category: "helper-state"
        tags: [kfunc ref-lifetime source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    kfunc-call "bpf_task_release" $cgrp'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects task reference, got cgroup reference"
    }
    {
        name: "source-helper-sk-lookup-release"
        category: "helper-state"
        tags: [helper-call socket ref-lifetime source accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let tuple = "0123456789ab"'
            '  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 12 0 0)'
            '  let skc = (helper-call "bpf_skc_lookup_tcp" $ctx $tuple 12 0 0)'
            '  if $sk {'
            '    helper-call "bpf_sk_release" $sk'
            '  }'
            '  if $skc {'
            '    helper-call "bpf_sk_release" $skc'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-sk-lookup-udp-release"
        category: "helper-state"
        tags: [helper-call socket ref-lifetime source accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let tuple = "0123456789abcdef"'
            '  let sk = (helper-call "bpf_sk_lookup_udp" $ctx $tuple 16 0 0)'
            '  if $sk {'
            '    helper-call "bpf_sk_release" $sk'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-tcp-raw-syncookie"
        category: "helper-state"
        tags: [helper-call tcp syncookie source accept]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let ip4 = "01234567890123456789"'
            '  let ip6 = "0123456789012345678901234567890123456789"'
            '  let th = "01234567890123456789"'
            '  helper-call "bpf_tcp_raw_gen_syncookie_ipv4" $ip4 $th 20'
            '  helper-call "bpf_tcp_raw_gen_syncookie_ipv6" $ip6 $th 20'
            '  helper-call "bpf_tcp_raw_check_syncookie_ipv4" $ip4 $th'
            '  helper-call "bpf_tcp_raw_check_syncookie_ipv6" $ip6 $th'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-tcp-syncookie"
        category: "helper-state"
        tags: [helper-call tcp syncookie socket ref-lifetime source accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let tuple = "0123456789ab"'
            '  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 12 0 0)'
            '  if $sk {'
            '    helper-call "bpf_tcp_check_syncookie" $sk $sk 20 $sk 20'
            '    helper-call "bpf_tcp_gen_syncookie" $sk $sk 20 $sk 20'
            '    helper-call "bpf_sk_release" $sk'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-sk-lookup-rejects-leak"
        category: "helper-state"
        tags: [helper-call socket ref-lifetime source reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let tuple = "0123456789abcdef"'
            '  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 16 0 0)'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-helper-sk-release-accepts-lookup-or-null-release"
        category: "helper-state"
        tags: [helper-call socket ref-lifetime phi source accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let tuple = "0123456789abcdef"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let sk = (if $selector == 0 { helper-call "bpf_sk_lookup_tcp" $ctx $tuple 16 0 0 } else { 0 })'
            '  if $sk {'
            '    helper-call "bpf_sk_release" $sk'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-sk-release-rejects-unchecked-null"
        category: "helper-state"
        tags: [helper-call socket ref-lifetime source reject nullability]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let tuple = "0123456789abcdef"'
            '  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 16 0 0)'
            '  helper-call "bpf_sk_release" $sk'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper sk_release sock may dereference null pointer"
    }
    {
        name: "source-helper-sk-release-rejects-double-release"
        category: "helper-state"
        tags: [helper-call socket ref-lifetime source reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let tuple = "0123456789abcdef"'
            '  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 16 0 0)'
            '  if $sk {'
            '    helper-call "bpf_sk_release" $sk'
            '    helper-call "bpf_sk_release" $sk'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "reference already released"
    }
    {
        name: "source-helper-sk-release-rejects-use-after-release"
        category: "helper-state"
        tags: [helper-call socket ref-lifetime source reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let tuple = "0123456789abcdef"'
            '  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 16 0 0)'
            '  if $sk {'
            '    helper-call "bpf_sk_release" $sk'
            '    $sk.family | count'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "reference already released"
    }
    {
        name: "source-helper-sk-release-rejects-task-ref"
        category: "helper-state"
        tags: [helper-call socket ref-lifetime source reject]
        requires: [loopback-interface kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    helper-call "bpf_sk_release" $task'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_release' arg0 expects socket pointer"
    }
    {
        name: "source-kfunc-file-ref-release"
        category: "helper-state"
        tags: [kfunc file ref-lifetime source accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let file = (kfunc-call "bpf_get_task_exe_file" $ctx.current_task)'
            '  if $file {'
            '    $file | kfunc-call "bpf_put_file"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-file-ref-project-release"
        category: "helper-state"
        tags: [kfunc file ref-lifetime source metadata accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let file = (kfunc-call "bpf_get_task_exe_file" $ctx.current_task)'
            '  if $file {'
            '    $file.f_mode | count'
            '    $file | kfunc-call "bpf_put_file"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-file-release-accepts-acquire-or-null-release"
        category: "helper-state"
        tags: [kfunc file ref-lifetime phi source accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let file = (if $selector == 0 { kfunc-call "bpf_get_task_exe_file" $ctx.current_task } else { 0 })'
            '  if $file {'
            '    $file | kfunc-call "bpf_put_file"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-file-ref-rejects-leak"
        category: "helper-state"
        tags: [kfunc file ref-lifetime source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let file = (kfunc-call "bpf_get_task_exe_file" $ctx.current_task)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-file-release-accepts-both-branch-release"
        category: "helper-state"
        tags: [kfunc file ref-lifetime branch source accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let file = (kfunc-call "bpf_get_task_exe_file" $ctx.current_task)'
            '  if $file {'
            '    if $ctx.pid {'
            '      $file | kfunc-call "bpf_put_file"'
            '    } else {'
            '      $file | kfunc-call "bpf_put_file"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-file-release-rejects-one-branch-release-leak"
        category: "helper-state"
        tags: [kfunc file ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let file = (kfunc-call "bpf_get_task_exe_file" $ctx.current_task)'
            '  if $file {'
            '    if $ctx.pid {'
            '      $file | kfunc-call "bpf_put_file"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-file-release-rejects-release-after-conditional-release"
        category: "helper-state"
        tags: [kfunc file ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let file = (kfunc-call "bpf_get_task_exe_file" $ctx.current_task)'
            '  if $file {'
            '    if $ctx.pid {'
            '      $file | kfunc-call "bpf_put_file"'
            '    }'
            '    $file | kfunc-call "bpf_put_file"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_put_file' arg0 reference already released"
    }
    {
        name: "source-kfunc-file-release-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc file ref-lifetime source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  if $task {'
            '    kfunc-call "bpf_put_file" $task'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects file reference, got task reference"
    }
    {
        name: "source-helper-d-path-accepts-file-path"
        category: "helper-state"
        tags: [helper-call file path source accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
            '  helper-call "bpf_d_path" $ctx.arg0.f_path $buf 64'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-d-path-rejects-stack-path"
        category: "helper-state"
        tags: [helper-call file path source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
            '  helper-call "bpf_d_path" $buf $buf 64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper d_path path expects pointer in [Kernel]"
    }
    {
        name: "source-helper-d-path-accepts-zero-size-null-buffer"
        category: "helper-state"
        tags: [helper-call file path source zero-size accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_d_path" $ctx.arg0.f_path 0 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-d-path-rejects-small-buffer"
        category: "helper-state"
        tags: [helper-call file path source bounds reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "01234567"'
            '  helper-call "bpf_d_path" $ctx.arg0.f_path $buf 64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper d_path buf"
    }
    {
        name: "source-helper-d-path-rejects-negative-size"
        category: "helper-state"
        tags: [helper-call file path source size reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef"'
            '  let size = (0 - 1)'
            '  helper-call "bpf_d_path" $ctx.arg0.f_path $buf $size'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_d_path' requires arg2 size to be between 0 and u32::MAX"
    }
    {
        name: "source-helper-d-path-rejects-dynamic-negative-size"
        category: "helper-state"
        tags: [helper-call file path source size dynamic reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef"'
            '  let size = (0 - (helper-call "bpf_get_prandom_u32"))'
            '  helper-call "bpf_d_path" $ctx.arg0.f_path $buf $size'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_d_path' requires arg2 size to be between 0 and u32::MAX"
    }
    {
        name: "source-helper-d-path-pipeline-requires-explicit-path"
        category: "helper-state"
        tags: [helper-call file path source reject pipeline diagnostic]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
            '  $ctx.arg0.f_path | helper-call "bpf_d_path" $buf 64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "pass that value explicitly as the first helper argument"
    }
    {
        name: "source-helper-call-prior-statement-does-not-inject"
        category: "helper-state"
        tags: [helper-call source reject pipeline diagnostic]
        target: "kprobe:sys_read"
        program: [
            '{|ctx|'
            '  99'
            '  helper-call "bpf_get_socket_cookie"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects 1..=1 helper arguments after the helper name, got 0"
    }
    {
        name: "source-kfunc-call-prior-statement-does-not-inject"
        category: "helper-state"
        tags: [kfunc source reject pipeline diagnostic]
        target: "kprobe:sys_read"
        program: [
            '{|ctx|'
            '  99'
            '  kfunc-call "bpf_cgroup_ancestor" 7 --btf-id 4242'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects 2..=2 arguments, got 1"
    }
    {
        name: "source-kfunc-path-d-path-accepts-file-path"
        category: "helper-state"
        tags: [kfunc file path source accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
            '  kfunc-call "bpf_path_d_path" $ctx.arg0.f_path $buf 64'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-path-d-path-pipeline-file-path"
        category: "helper-state"
        tags: [kfunc file path source accept pipeline]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
            '  $ctx.arg0.f_path | kfunc-call "bpf_path_d_path" $buf 64'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-path-d-path-rejects-stack-path"
        category: "helper-state"
        tags: [kfunc file path source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
            '  kfunc-call "bpf_path_d_path" $buf $buf 64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_path_d_path' arg0 expects kernel pointer"
    }
    {
        name: "source-kfunc-path-d-path-rejects-kernel-buffer"
        category: "helper-state"
        tags: [kfunc file path source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_path_d_path" $ctx.arg0.f_path $ctx.arg0 64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc path_d_path buffer expects pointer in [Stack, Map], got Kernel"
    }
    {
        name: "source-kfunc-path-d-path-rejects-small-buffer"
        category: "helper-state"
        tags: [kfunc file path source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef"'
            '  kfunc-call "bpf_path_d_path" $ctx.arg0.f_path $buf 64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc path_d_path buffer requires 64 bytes"
    }
    {
        name: "source-kfunc-path-d-path-rejects-zero-size"
        category: "helper-state"
        tags: [kfunc file path source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
            '  kfunc-call "bpf_path_d_path" $ctx.arg0.f_path $buf 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_path_d_path' arg2 must be > 0"
    }
    {
        name: "source-kfunc-path-d-path-rejects-dynamic-zero-size"
        category: "helper-state"
        tags: [kfunc file path source dynamic branch reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let size = (if $selector == 0 { 0 } else { 64 })'
            '  kfunc-call "bpf_path_d_path" $ctx.arg0.f_path $buf $size'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_path_d_path' arg2 must be > 0"
    }
    {
        name: "source-kfunc-crypto-ctx-release-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  if $task {'
            '    kfunc-call "bpf_crypto_ctx_release" $task'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects crypto_ctx reference, got task reference"
    }
    {
        name: "source-kfunc-crypto-encrypt-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  let siv = "0000000000000000"'
            '  if $task {'
            '    kfunc-call "bpf_crypto_encrypt" $task $src $dst $siv'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 expects crypto_ctx reference, got task reference"
    }
    {
        name: "source-kfunc-crypto-ctx-create-rejects-kernel-params"
        category: "helper-state"
        tags: [kfunc crypto source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  let err = "00000000"'
            '  if $task {'
            '    kfunc-call "bpf_crypto_ctx_create" $task 408 $err'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc bpf_crypto_ctx_create params expects pointer in [Stack, Map], got Kernel"
    }
    {
        name: "source-kfunc-crypto-ctx-create-release"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-ctx-acquire-release"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      let owned = (kfunc-call "bpf_crypto_ctx_acquire" $crypto)'
            '      if $owned {'
            '        $owned | kfunc-call "bpf_crypto_ctx_release"'
            '      }'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-ctx-acquire-rejects-owned-leak"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      let owned = (kfunc-call "bpf_crypto_ctx_acquire" $crypto)'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-crypto-ctx-release-accepts-create-or-null-release"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime phi source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  if $params {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let crypto = (if $selector == 0 { kfunc-call "bpf_crypto_ctx_create" $params 408 $err } else { 0 })'
            '    if $crypto {'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-ctx-create-record-field-err"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime record source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let rec = { err: "00000000" }'
            '  let err = $rec.err'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-ctx-create-rejects-leak"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      1 | count'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-crypto-encrypt-accepts-tracked-ctx"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  let siv = "0000000000000000"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      kfunc-call "bpf_crypto_encrypt" $crypto $src $dst $siv'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-decrypt-accepts-tracked-ctx"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  let siv = "0000000000000000"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      kfunc-call "bpf_crypto_decrypt" $crypto $src $dst $siv'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-encrypt-allows-null-siv"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      kfunc-call "bpf_crypto_encrypt" $crypto $src $dst 0'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-encrypt-allows-zero-vreg-siv"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  let siv = 0'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      kfunc-call "bpf_crypto_encrypt" $crypto $src $dst $siv'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-encrypt-rejects-nonzero-siv"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      kfunc-call "bpf_crypto_encrypt" $crypto $src $dst 7'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_crypto_encrypt' arg3 expects null (0) or pointer"
    }
    {
        name: "source-kfunc-crypto-encrypt-rejects-nonzero-vreg-siv"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  let siv = 7'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      kfunc-call "bpf_crypto_encrypt" $crypto $src $dst $siv'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_crypto_encrypt' arg3 expects null (0) or pointer"
    }
    {
        name: "source-kfunc-crypto-decrypt-allows-null-siv"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      kfunc-call "bpf_crypto_decrypt" $crypto $src $dst 0'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-decrypt-rejects-nonzero-siv"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      kfunc-call "bpf_crypto_decrypt" $crypto $src $dst 9'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_crypto_decrypt' arg3 expects null (0) or pointer"
    }
    {
        name: "source-kfunc-crypto-encrypt-rejects-kernel-src"
        category: "helper-state"
        tags: [kfunc crypto source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  let siv = "0000000000000000"'
            '  if $params {'
            '    if $task {'
            '      let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '      if $crypto {'
            '        kfunc-call "bpf_crypto_encrypt" $crypto $task $dst $siv'
            '        $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '      }'
            '      $task | kfunc-call "bpf_task_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc bpf_crypto_encrypt src expects pointer in [Stack, Map], got Kernel"
    }
    {
        name: "source-kfunc-crypto-decrypt-rejects-kernel-src"
        category: "helper-state"
        tags: [kfunc crypto source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  let siv = "0000000000000000"'
            '  if $params {'
            '    if $task {'
            '      let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '      if $crypto {'
            '        kfunc-call "bpf_crypto_decrypt" $crypto $task $dst $siv'
            '        $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '      }'
            '      $task | kfunc-call "bpf_task_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc bpf_crypto_decrypt src expects pointer in [Stack, Map], got Kernel"
    }
    {
        name: "source-kfunc-cgroup-acquire-release"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_acquire" $ctx.cgroup)'
            '  if $cgrp {'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cgroup-acquire-rejects-leak"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_acquire" $ctx.cgroup)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-cgroup-release-accepts-both-branch-release"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime branch source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_acquire" $ctx.cgroup)'
            '  if $cgrp {'
            '    if $ctx.pid {'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
            '    } else {'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cgroup-release-rejects-one-branch-release-leak"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_acquire" $ctx.cgroup)'
            '  if $cgrp {'
            '    if $ctx.pid {'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-cgroup-release-rejects-release-after-conditional-release"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_acquire" $ctx.cgroup)'
            '  if $cgrp {'
            '    if $ctx.pid {'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
            '    }'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_cgroup_release' arg0 reference already released"
    }
    {
        name: "source-kfunc-cgroup-release-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  if $task {'
            '    kfunc-call "bpf_cgroup_release" $task'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects cgroup reference, got task reference"
    }
    {
        name: "source-kfunc-cgroup-from-id-release"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-task-get-cgroup1-release"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    let cgrp = (kfunc-call "bpf_task_get_cgroup1" $task 0)'
            '    if $cgrp {'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
            '    }'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-task-get-cgroup1-rejects-cgroup-leak"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    let cgrp = (kfunc-call "bpf_task_get_cgroup1" $task 0)'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-task-under-cgroup-accepts-task-and-cgroup"
        category: "helper-state"
        tags: [kfunc task cgroup source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    let cgrp = (kfunc-call "bpf_task_get_cgroup1" $task 0)'
            '    if $cgrp {'
            '      let under = (kfunc-call "bpf_task_under_cgroup" $task $cgrp)'
            '      $under | count'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
            '    }'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-task-under-cgroup-rejects-task-ref-cgroup-arg"
        category: "helper-state"
        tags: [kfunc task cgroup source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    kfunc-call "bpf_task_under_cgroup" $task $task'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg1 expects cgroup reference, got task reference"
    }
    {
        name: "source-kfunc-cgroup-release-accepts-acquire-or-null-release"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime phi source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let cgrp = (if $selector == 0 { kfunc-call "bpf_cgroup_from_id" 1 } else { 0 })'
            '  if $cgrp {'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cgroup-ancestor-release"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    let parent = (kfunc-call "bpf_cgroup_ancestor" $cgrp 0)'
            '    if $parent {'
            '      $parent | kfunc-call "bpf_cgroup_release"'
            '    }'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cpumask-ref-release"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cpumask-ref-release-dtor"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    $mask | kfunc-call "bpf_cpumask_release_dtor"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cpumask-release-accepts-acquire-or-null-release"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime phi source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let mask = (if $selector == 0 { kfunc-call "bpf_cpumask_create" } else { 0 })'
            '  if $mask {'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cpumask-ref-rejects-leak"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-cpumask-release-accepts-both-branch-release"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime branch source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    if $ctx.pid {'
            '      $mask | kfunc-call "bpf_cpumask_release"'
            '    } else {'
            '      $mask | kfunc-call "bpf_cpumask_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cpumask-release-rejects-one-branch-release-leak"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    if $ctx.pid {'
            '      $mask | kfunc-call "bpf_cpumask_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-cpumask-release-rejects-release-after-conditional-release"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    if $ctx.pid {'
            '      $mask | kfunc-call "bpf_cpumask_release"'
            '    }'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_cpumask_release' arg0 reference already released"
    }
    {
        name: "source-kfunc-cpumask-release-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  if $task {'
            '    kfunc-call "bpf_cpumask_release" $task'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects cpumask reference, got task reference"
    }
    {
        name: "source-kfunc-cpumask-release-dtor-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  if $task {'
            '    kfunc-call "bpf_cpumask_release_dtor" $task'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects cpumask reference, got task reference"
    }
    {
        name: "source-kfunc-cpumask-acquire-release"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    let owned = (kfunc-call "bpf_cpumask_acquire" $mask)'
            '    if $owned {'
            '      $owned | kfunc-call "bpf_cpumask_release"'
            '    }'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cpumask-acquire-rejects-owned-leak"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    let owned = (kfunc-call "bpf_cpumask_acquire" $mask)'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-cpumask-populate-release"
        category: "helper-state"
        tags: [kfunc cpumask source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    let bits = "0100000000000000"'
            '    let populated = (kfunc-call "bpf_cpumask_populate" $mask $bits 8)'
            '    $populated | count'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-cpumask-populate-rejects-scalar-mask"
        category: "helper-state"
        tags: [kfunc cpumask source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let bits = "0100000000000000"'
            '  kfunc-call "bpf_cpumask_populate" 7 $bits 8'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 expects pointer"
    }
    {
        name: "source-kfunc-cpumask-set-first-release"
        category: "helper-state"
        tags: [kfunc cpumask source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    kfunc-call "bpf_cpumask_set_cpu" 0 $mask'
            '    let first = (kfunc-call "bpf_cpumask_first" $mask)'
            '    $first | count'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cpumask-and-release"
        category: "helper-state"
        tags: [kfunc cpumask source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = (kfunc-call "bpf_cpumask_create")'
            '  if $dst {'
            '    let src = (kfunc-call "bpf_cpumask_create")'
            '    if $src {'
            '      kfunc-call "bpf_cpumask_set_cpu" 0 $src'
            '      let matched = (kfunc-call "bpf_cpumask_and" $dst $src $src)'
            '      $matched | count'
            '      $src | kfunc-call "bpf_cpumask_release"'
            '    }'
            '    $dst | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cpumask-and-rejects-scalar-arg"
        category: "helper-state"
        tags: [kfunc cpumask source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    kfunc-call "bpf_cpumask_and" $mask 7 $mask'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg1 expects pointer"
    }
    {
        name: "source-kfunc-cpumask-copy-query-release"
        category: "helper-state"
        tags: [kfunc cpumask source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = (kfunc-call "bpf_cpumask_create")'
            '  if $dst {'
            '    let src = (kfunc-call "bpf_cpumask_create")'
            '    if $src {'
            '      kfunc-call "bpf_cpumask_setall" $src'
            '      kfunc-call "bpf_cpumask_copy" $dst $src'
            '      let equal = (kfunc-call "bpf_cpumask_equal" $dst $src)'
            '      let intersects = (kfunc-call "bpf_cpumask_intersects" $dst $src)'
            '      let test = (kfunc-call "bpf_cpumask_test_cpu" 0 $dst)'
            '      ($equal + $intersects + $test) | count'
            '      $src | kfunc-call "bpf_cpumask_release"'
            '    }'
            '    $dst | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-cpumask-test-cpu-rejects-scalar-mask"
        category: "helper-state"
        tags: [kfunc cpumask source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_cpumask_test_cpu" 0 7'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg1 expects pointer"
    }
    {
        name: "source-kfunc-cpumask-single-mask-query-release"
        category: "helper-state"
        tags: [kfunc cpumask source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    kfunc-call "bpf_cpumask_clear" $mask'
            '    let empty = (kfunc-call "bpf_cpumask_empty" $mask)'
            '    kfunc-call "bpf_cpumask_setall" $mask'
            '    let full = (kfunc-call "bpf_cpumask_full" $mask)'
            '    kfunc-call "bpf_cpumask_clear_cpu" 0 $mask'
            '    let was_set = (kfunc-call "bpf_cpumask_test_and_set_cpu" 0 $mask)'
            '    let cleared = (kfunc-call "bpf_cpumask_test_and_clear_cpu" 0 $mask)'
            '    let first_zero = (kfunc-call "bpf_cpumask_first_zero" $mask)'
            '    let weight = (kfunc-call "bpf_cpumask_weight" $mask)'
            '    ($empty + $full + $was_set + $cleared + $first_zero + $weight) | count'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-cpumask-setops-release"
        category: "helper-state"
        tags: [kfunc cpumask source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = (kfunc-call "bpf_cpumask_create")'
            '  if $dst {'
            '    let src = (kfunc-call "bpf_cpumask_create")'
            '    if $src {'
            '      kfunc-call "bpf_cpumask_set_cpu" 0 $dst'
            '      kfunc-call "bpf_cpumask_setall" $src'
            '      let first_and = (kfunc-call "bpf_cpumask_first_and" $dst $src)'
            '      let subset = (kfunc-call "bpf_cpumask_subset" $dst $src)'
            '      let any = (kfunc-call "bpf_cpumask_any_distribute" $src)'
            '      let any_and = (kfunc-call "bpf_cpumask_any_and_distribute" $dst $src)'
            '      kfunc-call "bpf_cpumask_or" $dst $dst $src'
            '      kfunc-call "bpf_cpumask_xor" $dst $dst $src'
            '      ($first_and + $subset + $any + $any_and) | count'
            '      $src | kfunc-call "bpf_cpumask_release"'
            '    }'
            '    $dst | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kptr-xchg-task-ref-transfer"
        category: "helper-state"
        tags: [kfunc helper-call kptr ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --key-type u32 --value-type "record{task:kptr:task_struct,cookie:u64}" --max-entries 1'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    let entry = (0 | map-get task_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.task $task)'
            '      if $old {'
            '        $old | kfunc-call "bpf_task_release"'
            '      }'
            '    } else {'
            '      $task | kfunc-call "bpf_task_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kptr-xchg-cgroup-clear-requires-null-checked-dst"
        category: "helper-state"
        tags: [helper-call kptr cgroup source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define cgroup_slots --kind array --key-type u32 --value-type "record{cgrp:kptr:cgroup,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get cgroup_slots --kind array)'
            '  helper-call "bpf_kptr_xchg" $entry.cgrp 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper kptr_xchg dst may dereference null pointer"
    }
    {
        name: "source-kptr-xchg-rejects-old-ref-leak"
        category: "helper-state"
        tags: [kfunc helper-call kptr ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --key-type u32 --value-type "record{task:kptr:task_struct,cookie:u64}" --max-entries 1'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    let entry = (0 | map-get task_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.task $task)'
            '      0'
            '    } else {'
            '      $task | kfunc-call "bpf_task_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kptr-xchg-old-ref-accepts-both-branch-release"
        category: "helper-state"
        tags: [kfunc helper-call kptr ref-lifetime branch source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --key-type u32 --value-type "record{task:kptr:task_struct,cookie:u64}" --max-entries 1'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    let entry = (0 | map-get task_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.task $task)'
            '      if $old {'
            '        if $ctx.pid {'
            '          $old | kfunc-call "bpf_task_release"'
            '        } else {'
            '          $old | kfunc-call "bpf_task_release"'
            '        }'
            '      }'
            '    } else {'
            '      $task | kfunc-call "bpf_task_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kptr-xchg-old-ref-rejects-one-branch-release-leak"
        category: "helper-state"
        tags: [kfunc helper-call kptr ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --key-type u32 --value-type "record{task:kptr:task_struct,cookie:u64}" --max-entries 1'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    let entry = (0 | map-get task_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.task $task)'
            '      if $old {'
            '        if $ctx.pid {'
            '          $old | kfunc-call "bpf_task_release"'
            '        }'
            '      }'
            '    } else {'
            '      $task | kfunc-call "bpf_task_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kptr-xchg-old-ref-rejects-release-after-conditional-release"
        category: "helper-state"
        tags: [kfunc helper-call kptr ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --key-type u32 --value-type "record{task:kptr:task_struct,cookie:u64}" --max-entries 1'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    let entry = (0 | map-get task_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.task $task)'
            '      if $old {'
            '        if $ctx.pid {'
            '          $old | kfunc-call "bpf_task_release"'
            '        }'
            '        $old | kfunc-call "bpf_task_release"'
            '      }'
            '    } else {'
            '      $task | kfunc-call "bpf_task_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_task_release' arg0 reference already released"
    }
    {
        name: "source-kptr-xchg-cpumask-ref-transfer"
        category: "helper-state"
        tags: [kfunc helper-call kptr cpumask ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define mask_slots --kind array --key-type u32 --value-type "record{mask:kptr:bpf_cpumask,cookie:u64}" --max-entries 1'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    let entry = (0 | map-get mask_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.mask $mask)'
            '      if $old {'
            '        $old | kfunc-call "bpf_cpumask_release"'
            '      }'
            '    } else {'
            '      $mask | kfunc-call "bpf_cpumask_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kptr-xchg-cpumask-rejects-old-ref-leak"
        category: "helper-state"
        tags: [kfunc helper-call kptr cpumask ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define mask_slots --kind array --key-type u32 --value-type "record{mask:kptr:bpf_cpumask,cookie:u64}" --max-entries 1'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    let entry = (0 | map-get mask_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.mask $mask)'
            '      0'
            '    } else {'
            '      $mask | kfunc-call "bpf_cpumask_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kptr-xchg-file-ref-transfer"
        category: "helper-state"
        tags: [kfunc helper-call kptr file ref-lifetime source accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  map-define file_slots --kind array --key-type u32 --value-type "record{file:kptr:file,cookie:u64}" --max-entries 1'
            '  let file = (kfunc-call "bpf_get_task_exe_file" $ctx.current_task)'
            '  if $file {'
            '    let entry = (0 | map-get file_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.file $file)'
            '      if $old {'
            '        $old | kfunc-call "bpf_put_file"'
            '      }'
            '    } else {'
            '      $file | kfunc-call "bpf_put_file"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kptr-xchg-file-rejects-old-ref-leak"
        category: "helper-state"
        tags: [kfunc helper-call kptr file ref-lifetime source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  map-define file_slots --kind array --key-type u32 --value-type "record{file:kptr:file,cookie:u64}" --max-entries 1'
            '  let file = (kfunc-call "bpf_get_task_exe_file" $ctx.current_task)'
            '  if $file {'
            '    let entry = (0 | map-get file_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.file $file)'
            '      0'
            '    } else {'
            '      $file | kfunc-call "bpf_put_file"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kptr-xchg-cgroup-ref-transfer"
        category: "helper-state"
        tags: [kfunc helper-call kptr cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define cgroup_slots --kind array --key-type u32 --value-type "record{cgrp:kptr:cgroup,cookie:u64}" --max-entries 1'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    let entry = (0 | map-get cgroup_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.cgrp $cgrp)'
            '      if $old {'
            '        $old | kfunc-call "bpf_cgroup_release"'
            '      }'
            '    } else {'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kptr-xchg-cgroup-clear-release"
        category: "helper-state"
        tags: [kfunc helper-call kptr cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define cgroup_slots --kind array --key-type u32 --value-type "record{cgrp:kptr:cgroup,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get cgroup_slots --kind array)'
            '  if $entry {'
            '    let old = (helper-call "bpf_kptr_xchg" $entry.cgrp 0)'
            '    if $old {'
            '      $old | kfunc-call "bpf_cgroup_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kptr-xchg-cgroup-clear-zero-vreg-release"
        category: "helper-state"
        tags: [kfunc helper-call kptr cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define cgroup_slots --kind array --key-type u32 --value-type "record{cgrp:kptr:cgroup,cookie:u64}" --max-entries 1'
            '  let zero = 0'
            '  let entry = (0 | map-get cgroup_slots --kind array)'
            '  if $entry {'
            '    let old = (helper-call "bpf_kptr_xchg" $entry.cgrp $zero)'
            '    if $old {'
            '      $old | kfunc-call "bpf_cgroup_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kptr-xchg-cgroup-clear-conditional-null-old-release"
        category: "helper-state"
        tags: [kfunc helper-call kptr cgroup ref-lifetime phi source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define cgroup_slots --kind array --key-type u32 --value-type "record{cgrp:kptr:cgroup,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get cgroup_slots --kind array)'
            '  if $entry {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let old = (if $selector == 0 { helper-call "bpf_kptr_xchg" $entry.cgrp 0 } else { 0 })'
            '    if $old {'
            '      $old | kfunc-call "bpf_cgroup_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kptr-xchg-cgroup-clear-rejects-conditional-old-release"
        category: "helper-state"
        tags: [kfunc helper-call kptr cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define cgroup_slots --kind array --key-type u32 --value-type "record{cgrp:kptr:cgroup,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get cgroup_slots --kind array)'
            '  if $entry {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let old = (helper-call "bpf_kptr_xchg" $entry.cgrp 0)'
            '    if $selector == 0 {'
            '      if $old {'
            '        $old | kfunc-call "bpf_cgroup_release"'
            '      }'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kptr-xchg-rejects-nonzero-scalar-src"
        category: "helper-state"
        tags: [helper-call kptr cgroup source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define cgroup_slots --kind array --key-type u32 --value-type "record{cgrp:kptr:cgroup,cookie:u64}" --max-entries 1'
            '  let one = 1'
            '  let entry = (0 | map-get cgroup_slots --kind array)'
            '  if $entry {'
            '    helper-call "bpf_kptr_xchg" $entry.cgrp $one'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 194 arg1 expects pointer, got I64"
    }
    {
        name: "source-kptr-xchg-cgroup-clear-rejects-old-ref-leak"
        category: "helper-state"
        tags: [kfunc helper-call kptr cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define cgroup_slots --kind array --key-type u32 --value-type "record{cgrp:kptr:cgroup,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get cgroup_slots --kind array)'
            '  if $entry {'
            '    let old = (helper-call "bpf_kptr_xchg" $entry.cgrp 0)'
            '    0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kptr-xchg-rejects-pointee-mismatch"
        category: "helper-state"
        tags: [kfunc helper-call kptr cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --key-type u32 --value-type "record{task:kptr:task_struct,cookie:u64}" --max-entries 1'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    let entry = (0 | map-get task_slots --kind array)'
            '    if $entry {'
            '      helper-call "bpf_kptr_xchg" $entry.task $cgrp'
            '    } else {'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot store cgroup pointer in kptr:task_struct slot"
    }
    {
        name: "source-kfunc-res-spin-rejects-non-kernel-pointer"
        category: "helper-state"
        tags: [kfunc res-spin-lock source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_res_spin_lock" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_res_spin_lock' arg0 expects pointer"
    }
    {
        name: "source-kfunc-throw"
        category: "helper-state"
        tags: [kfunc throw source accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_throw" 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-throw-rejects-return-use"
        category: "helper-state"
        tags: [kfunc throw source void-return reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_throw" 1 | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "void kfunc 'bpf_throw' return value cannot be used"
    }
    {
        name: "source-kfunc-rcu-read-lock-unlock"
        category: "helper-state"
        tags: [kfunc rcu source accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_rcu_read_lock"'
            '  kfunc-call "bpf_rcu_read_unlock"'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rcu-read-lock-user-function-unlock"
        category: "helper-state"
        tags: [kfunc rcu source accept user-function]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def lock [] {'
            '    kfunc-call "bpf_rcu_read_lock"'
            '    0'
            '  }'
            '  def unlock [] {'
            '    kfunc-call "bpf_rcu_read_unlock"'
            '    0'
            '  }'
            '  lock'
            '  unlock'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-rcu-read-lock-rejects-return-use"
        category: "helper-state"
        tags: [kfunc rcu source void-return reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_rcu_read_lock" | count'
            '  kfunc-call "bpf_rcu_read_unlock"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "void kfunc 'bpf_rcu_read_lock' return value cannot be used"
    }
    {
        name: "source-kfunc-rcu-read-unlock-rejects-unmatched"
        category: "helper-state"
        tags: [kfunc rcu source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_rcu_read_unlock"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_rcu_read_lock"
    }
    {
        name: "source-kfunc-rcu-read-lock-rejects-leak"
        category: "helper-state"
        tags: [kfunc rcu source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_rcu_read_lock"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased RCU read lock"
    }
    {
        name: "source-kfunc-rcu-read-unlock-rejects-mixed-join"
        category: "helper-state"
        tags: [kfunc rcu source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_rcu_read_lock"'
            '  }'
            '  kfunc-call "bpf_rcu_read_unlock"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_rcu_read_lock"
    }
    {
        name: "source-kfunc-rcu-read-lock-rejects-branch-leak"
        category: "helper-state"
        tags: [kfunc rcu source branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_rcu_read_lock"'
            '  } else {'
            '    kfunc-call "bpf_rcu_read_lock"'
            '    kfunc-call "bpf_rcu_read_unlock"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased RCU read lock"
    }
    {
        name: "source-kfunc-preempt-disable-enable"
        category: "helper-state"
        tags: [kfunc preempt source accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_preempt_disable"'
            '  kfunc-call "bpf_preempt_enable"'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-preempt-disable-user-function-enable"
        category: "helper-state"
        tags: [kfunc preempt source accept user-function]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def disable [] {'
            '    kfunc-call "bpf_preempt_disable"'
            '    0'
            '  }'
            '  def enable [] {'
            '    kfunc-call "bpf_preempt_enable"'
            '    0'
            '  }'
            '  disable'
            '  enable'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-preempt-enable-rejects-unmatched"
        category: "helper-state"
        tags: [kfunc preempt source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_preempt_enable"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_preempt_disable"
    }
    {
        name: "source-kfunc-preempt-disable-rejects-leak"
        category: "helper-state"
        tags: [kfunc preempt source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_preempt_disable"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased preempt disable"
    }
    {
        name: "source-kfunc-preempt-enable-rejects-mixed-join"
        category: "helper-state"
        tags: [kfunc preempt source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_preempt_disable"'
            '  }'
            '  kfunc-call "bpf_preempt_enable"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_preempt_disable"
    }
    {
        name: "source-kfunc-preempt-disable-rejects-branch-leak"
        category: "helper-state"
        tags: [kfunc preempt source branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_preempt_disable"'
            '  } else {'
            '    kfunc-call "bpf_preempt_disable"'
            '    kfunc-call "bpf_preempt_enable"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased preempt disable"
    }
    {
        name: "source-kfunc-local-irq-save-restore"
        category: "helper-state"
        tags: [kfunc irq source accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_local_irq_save" $flags'
            '  kfunc-call "bpf_local_irq_restore" $flags'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-local-irq-user-function-save-restore"
        category: "helper-state"
        tags: [kfunc irq source accept user-function]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def save [flags] {'
            '    kfunc-call "bpf_local_irq_save" $flags'
            '    0'
            '  }'
            '  def restore [flags] {'
            '    kfunc-call "bpf_local_irq_restore" $flags'
            '    0'
            '  }'
            '  let flags = "00000000"'
            '  save $flags'
            '  restore $flags'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-local-irq-restore-rejects-unmatched"
        category: "helper-state"
        tags: [kfunc irq source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_local_irq_restore" $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_local_irq_save"
    }
]
