const VERIFIER_DIFF_FIXTURES_1219_1250_B = [
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
]
