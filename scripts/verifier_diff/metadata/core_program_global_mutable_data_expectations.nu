let PROGRAM_GLOBAL_MUTABLE_DATA_KERNEL_FEATURE_EXPECTATIONS = [
    {
        program: [
            '{|ctx|'
            '  7 | global-define --type i64 seen'
            '  global-get seen'
            '}'
        ]
        feature_keys: ["global:bpf-data-sections"]
    }
    {
        program: [
            '{|ctx|'
            '  mut state: record<pid: int stats: record<hits: int ok: bool>> = {}'
            '  ($state.pid + $state.stats.hits) | count'
            '  0'
            '}'
        ]
        feature_keys: ["global:bpf-data-sections"]
    }
    {
        program: [
            '{|ctx| mut state: int = 0; $state | count }'
        ]
        feature_keys: ["global:bpf-data-sections"]
    }
    {
        program: [
            '{|ctx| let config = { pid: 7 samples: [11 22] }; (($config.samples | get 1) + $config.pid) | count }'
        ]
        feature_keys: ["global:bpf-data-sections"]
    }
    {
        program: [
            '{|ctx| let seed = 7; let config = { pid: $seed samples: [11 22] }; (($config.samples | get 1) + $config.pid) | count }'
        ]
        feature_keys: ["global:bpf-data-sections"]
    }
    {
        program: [
            '{|ctx|'
            '  let text = "global-get seen"'
            '  0'
            '}'
        ]
        feature_keys: []
    }
]
