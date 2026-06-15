const VERIFIER_DIFF_FIXTURES_0219_0250_A = [
    {
        name: "netfilter-defrag-target-metadata"
        category: "program-model"
        tags: [netfilter metadata]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  "accept"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-target-metadata"
        category: "program-model"
        tags: [lwt metadata seg6local]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sk-reuseport-migrate-target-metadata"
        category: "program-model"
        tags: [sk-reuseport metadata migrate]
        target: "sk_reuseport:migrate"
        program: [
            '{|ctx|'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-unix-target-metadata"
        category: "program-model"
        tags: [cgroup-sock-addr metadata unix]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "syscall-target-metadata"
        category: "program-model"
        tags: [syscall metadata]
        target: "syscall:demo"
        program: [
            '{||'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "freplace-target-metadata"
        category: "program-model"
        tags: [freplace metadata]
        target: "freplace:replace_me"
        program: [
            '{|ctx|'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-task-vma-target-metadata"
        category: "program-model"
        tags: [iter metadata task-vma]
        target: "iter:task_vma"
        program: [
            '{|ctx|'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
