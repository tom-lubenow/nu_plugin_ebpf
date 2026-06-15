const VERIFIER_DIFF_FIXTURES_0376_0406_A_C = [
    {
        name: "raw-get-local-storage-rejects-deprecated-map"
        category: "maps"
        tags: [maps local-storage deprecated helper-call reject source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_local_storage" legacy_storage 0'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "deprecated-cgroup-storage; use cgrp-storage local-storage maps instead"
    }
    {
        name: "raw-get-local-storage-rejects-nonzero-flags"
        category: "maps"
        tags: [maps local-storage deprecated helper-call flags reject source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_local_storage" legacy_storage 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_local_storage' requires arg1 flags to be 0"
    }
    {
        name: "raw-get-local-storage-rejects-dynamic-flags"
        category: "maps"
        tags: [maps local-storage deprecated helper-call flags reject source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_get_local_storage" legacy_storage $flags'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_local_storage' requires arg1 flags to be 0"
    }
]
