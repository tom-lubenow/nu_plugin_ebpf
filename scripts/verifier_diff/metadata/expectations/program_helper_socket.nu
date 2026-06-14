const PROGRAM_SOCKET_HELPER_KERNEL_FEATURE_EXPECTATIONS = [
    {
        program: [
            '{|ctx|'
            '  let tuple = "0123456789abcdef"'
            '  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 16 0 0)'
            '  if $sk {'
            '    helper-call "bpf_sk_release" $sk'
            '  }'
            '  "pass"'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_lookup_tcp" "helper:bpf_sk_release"]
    }
]
