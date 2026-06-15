const VERIFIER_DIFF_FIXTURES_1219_1250_A_B = [
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
]
