export const VERIFIER_DIFF_FIXTURES_3765_3767 = [
    {
        name: "map-get-array-u64-last"
        category: "maps"
        tags: [maps map-define map-get arrays u64 last accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define wide_ports --kind array --value-type "array{u64:2}" --max-entries 1'
            '  let entry = (0 | map-get wide_ports --kind array)'
            '  if $entry {'
            '    ((($entry | last) == 0))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u64-skip-first"
        category: "maps"
        tags: [maps map-define map-get arrays u64 skip first accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define wide_ports --kind array --value-type "array{u64:2}" --max-entries 1'
            '  let entry = (0 | map-get wide_ports --kind array)'
            '  if $entry {'
            '    ((($entry | skip 1 | first) == 0))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u64-drop-last"
        category: "maps"
        tags: [maps map-define map-get arrays u64 drop last accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define wide_ports --kind array --value-type "array{u64:2}" --max-entries 1'
            '  let entry = (0 | map-get wide_ports --kind array)'
            '  if $entry {'
            '    ((($entry | drop 1 | last) == 0))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
