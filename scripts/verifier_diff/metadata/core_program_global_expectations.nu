const PROGRAM_GLOBAL_KERNEL_FEATURE_EXPECTATIONS = [
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
    {
        program: [
            '{|ctx|'
            '  let rec = { root: $ctx nf: $ctx.nf_state }'
            '  $rec.nf.hook | count'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  let state = $ctx.nf_state'
            '  let rec = { state: $state }'
            '  $rec.state.hook | count'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  let base = { state: $ctx.nf_state }'
            '  let rec = { ok: true, ...$base }'
            '  $rec.state.hook | count'
            '  0'
            '}'
        ]
        feature_keys: []
    }
]
