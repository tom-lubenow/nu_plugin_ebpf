export const VERIFIER_DIFF_FIXTURES_3416_3417 = [
    {
        name: "cgroup-array-map-contains-rejects-too-large-index"
        category: "language-surface"
        tags: [maps cgroup-array map-contains index reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-contains tracked_cgroups 4294967296 --kind cgroup-array'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cgroup membership helpers require idx to be between 0 and u32::MAX"
    }
    {
        name: "lwt-xmit-cgroup-array-contains"
        category: "packet"
        tags: [lwt cgroup-array helper-policy]
        default_test_lane: "dry-run"
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  map-contains tracked_cgroups 0 --kind cgroup-array'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
]
