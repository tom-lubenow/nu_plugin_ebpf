const VERIFIER_DIFF_FIXTURES_0469_0500_B_B = [
    {
        name: "source-helper-socket-cookie-accepts-socket-filter-context"
        category: "helper-state"
        tags: [helper socket cookie accept source metadata]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_cookie" $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-socket-cookie-accepts-returned-socket-filter-context"
        category: "helper-state"
        tags: [helper socket cookie accept user-function source metadata]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  def get_ctx [event] { $event }'
            '  let raw_ctx = (get_ctx $ctx)'
            '  helper-call "bpf_get_socket_cookie" $raw_ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-socket-cookie-accepts-fentry-socket-arg"
        category: "helper-state"
        tags: [helper socket cookie tracing accept source metadata]
        requires: [kernel-btf]
        target: "fentry:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_cookie" $ctx.arg0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-socket-cookie-accepts-fentry-null"
        category: "helper-state"
        tags: [helper socket cookie tracing "null" accept source metadata]
        requires: [kernel-btf]
        target: "fentry:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_cookie" 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-socket-cookie-rejects-fentry-raw-context"
        category: "helper-state"
        tags: [helper socket cookie tracing raw-context reject source metadata]
        requires: [kernel-btf]
        target: "fentry:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_cookie" $ctx'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_socket_cookie' arg0 expects socket pointer in fentry programs"
    }
    {
        name: "source-helper-socket-cookie-rejects-socket-filter-null"
        category: "helper-state"
        tags: [helper socket cookie "null" reject source metadata]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_cookie" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 46 arg0 expects pointer"
    }
    {
        name: "source-helper-socket-cookie-rejects-sk-lookup"
        category: "helper-state"
        tags: [helper socket cookie program-policy reject source metadata]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_cookie" $ctx'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_socket_cookie' is only valid"
    }
]
