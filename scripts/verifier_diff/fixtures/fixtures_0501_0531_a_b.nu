const VERIFIER_DIFF_FIXTURES_0501_0531_A_B = [
    {
        name: "source-helper-strtox-accepts-stack-buffers"
        category: "helper-state"
        tags: [helper string parse accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let input = "12345678"'
            '  let out = "00000000"'
            '  helper-call "bpf_strtol" $input 8 10 $out'
            '  helper-call "bpf_strtoul" $input 8 16 $out'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-strtox-rejects-invalid-base-flags"
        category: "helper-state"
        tags: [helper string parse flags reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let input = "12345678"'
            '  let out = "00000000"'
            '  helper-call "bpf_strtol" $input 8 2 $out'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_strtol' requires arg2 flags to be one of 0, 8, 10, or 16"
    }
    {
        name: "source-helper-strtol-rejects-dynamic-base-flags"
        category: "helper-state"
        tags: [helper string parse flags reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let input = "12345678"'
            '  let out = "00000000"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_strtol" $input 8 $flags $out'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_strtol' requires arg2 flags to be one of 0, 8, 10, or 16"
    }
    {
        name: "source-helper-strtoul-rejects-dynamic-base-flags"
        category: "helper-state"
        tags: [helper string parse flags reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let input = "12345678"'
            '  let out = "00000000"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_strtoul" $input 8 $flags $out'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_strtoul' requires arg2 flags to be one of 0, 8, 10, or 16"
    }
    {
        name: "source-helper-strtox-rejects-short-map-result"
        category: "helper-state"
        tags: [helper string parse map-bounds reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define strtox_out_short --kind array --value-type bytes:4 --max-entries 1'
            '  let input = "12345678"'
            '  let out = (0 | map-get strtox_out_short)'
            '  if $out {'
            '    helper-call "bpf_strtol" $input 8 10 $out'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper strtox res requires 8 bytes"
    }
    {
        name: "source-helper-strtox-rejects-dynamic-short-map-result"
        category: "helper-state"
        tags: [helper string parse map-bounds dynamic reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define strtox_out_dyn_short --kind array --value-type bytes:4 --max-entries 1'
            '  let input = "12345678"'
            '  let out = (0 | map-get strtox_out_dyn_short)'
            '  if $out {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 4 } else { 8 })'
            '    helper-call "bpf_strtol" $input $size 10 $out'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper strtox res requires 8 bytes"
    }
    {
        name: "source-helper-strncmp-accepts-rodata-binary-needle"
        category: "helper-state"
        tags: [helper string compare rodata accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let input = "abcdefgh"'
            '  helper-call "bpf_strncmp" $input 8 0x[61 62 63 64 65 66 67 68 00]'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-strncmp-accepts-captured-binary-needle"
        category: "helper-state"
        tags: [helper string compare rodata capture accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '(do {'
            '  let needle = 0x[61 62 63 64 65 66 67 68 00]'
            '  {|ctx|'
            '    let input = "abcdefgh"'
            '    helper-call "bpf_strncmp" $input 8 $needle'
            '    "pass"'
            '  }'
            '})'
        ]
        local: "accept"
        kernel: "accept"
    }
]
