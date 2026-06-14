export const VERIFIER_DIFF_FIXTURES_3759_3761 = [
    {
        name: "map-get-array-u64-compact-length"
        category: "maps"
        tags: [maps map-define map-get arrays u64 compact length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define wide_ports --kind array --value-type "array{u64:2}" --max-entries 1'
            '  let entry = (0 | map-get wide_ports --kind array)'
            '  if $entry {'
            '    ((($entry | compact | length) == 2))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u64-reverse-first"
        category: "maps"
        tags: [maps map-define map-get arrays u64 reverse first accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define wide_ports --kind array --value-type "array{u64:2}" --max-entries 1'
            '  let entry = (0 | map-get wide_ports --kind array)'
            '  if $entry {'
            '    ((($entry | reverse | first) == 0))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u64-take-last"
        category: "maps"
        tags: [maps map-define map-get arrays u64 take last accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define wide_ports --kind array --value-type "array{u64:2}" --max-entries 1'
            '  let entry = (0 | map-get wide_ports --kind array)'
            '  if $entry {'
            '    ((($entry | take 1 | last) == 0))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
