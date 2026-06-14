const PROGRAM_GLOBAL_CONTEXT_KERNEL_FEATURE_EXPECTATIONS = [
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
