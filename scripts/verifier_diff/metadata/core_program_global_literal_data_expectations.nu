let PROGRAM_GLOBAL_LITERAL_DATA_KERNEL_FEATURE_EXPECTATIONS = [
    {
        program: [
            '{|ctx|'
            '  let config = { pid: 7 samples: [11 22] }'
            '  (($config.samples | get 1) + $config.pid) | count'
            '  0'
            '}'
        ]
        feature_keys: ["global:bpf-data-sections"]
    }
    {
        program: [
            '{|ctx|'
            '  let payload = 0x[01 02]'
            '  ($payload | get 0) | count'
            '  0'
            '}'
        ]
        feature_keys: ["global:bpf-data-sections"]
    }
    {
        program: [
            '{|ctx|'
            '  let config = ({ pid: 7 samples: [11 22] })'
            '  (($config.samples | get 1) + $config.pid) | count'
            '  0'
            '}'
        ]
        feature_keys: ["global:bpf-data-sections"]
    }
    {
        program: [
            '{|ctx|'
            '  let samples = []'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  let payload = 0x[]'
            '  0'
            '}'
        ]
        feature_keys: []
    }
]
