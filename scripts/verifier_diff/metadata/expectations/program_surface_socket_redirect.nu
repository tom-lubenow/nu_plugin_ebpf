const PROGRAM_SURFACE_SOCKET_REDIRECT_KERNEL_FEATURE_EXPECTATIONS = [
    {
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --apply 8'
            '  adjust-message --cork 8'
            '  adjust-message --pull 0 1'
            '  adjust-message --push 0 1'
            '  adjust-message --pop 0 1'
            '  redirect-socket peers 0 --kind sockmap'
            '  redirect-socket hash_peers 0 --kind sockhash'
            '  "pass"'
            '}'
        ]
        feature_keys: [
            "helper:bpf_msg_apply_bytes"
            "helper:bpf_msg_cork_bytes"
            "helper:bpf_msg_pull_data"
            "helper:bpf_msg_push_data"
            "helper:bpf_msg_pop_data"
            "helper:bpf_msg_redirect_map"
            "helper:bpf_msg_redirect_hash"
        ]
    }
    {
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket hash_peers 0 --kind sockhash'
            '  redirect-socket hash_peers 1'
            '  "pass"'
            '}'
        ]
        feature_keys: ["helper:bpf_msg_redirect_hash"]
    }
    {
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  helper-call "bpf_msg_redirect_hash" $ctx hash_peers "peer-a" 0'
            '  redirect-socket hash_peers "peer-b"'
            '  "pass"'
            '}'
        ]
        feature_keys: ["helper:bpf_msg_redirect_hash"]
    }
    {
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockmap'
            '  redirect-socket hash_peers 0 --kind sockhash'
            '  "pass"'
            '}'
        ]
        feature_keys: [
            "helper:bpf_sk_redirect_map"
            "helper:bpf_sk_redirect_hash"
        ]
    }
    {
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  redirect-socket sockets 0 --kind reuseport-sockarray'
            '  "select"'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_select_reuseport"]
    }
    {
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|event|'
            '  assign-socket 0 --replace'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_sk_assign"]
    }
]
