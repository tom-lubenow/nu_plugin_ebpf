export const VERIFIER_DIFF_FIXTURES_3456_3460 = [
    {
        name: "map-get-array-u32-length"
        category: "maps"
        tags: [maps map-define map-get arrays u32 length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{u32:3}" --max-entries 1'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    (($entry | length) == 3)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u32-math-sum"
        category: "maps"
        tags: [maps map-define map-get arrays u32 math sum accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{u32:3}" --max-entries 1'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    (($entry | math sum) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u32-reverse-first"
        category: "maps"
        tags: [maps map-define map-get arrays u32 reverse first accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{u32:3}" --max-entries 1'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    (($entry | reverse | first) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u64-first"
        category: "maps"
        tags: [maps map-define map-get arrays u64 first accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define wide_ports --kind array --value-type "array{u64:2}" --max-entries 1'
            '  let entry = (0 | map-get wide_ports --kind array)'
            '  if $entry {'
            '    (($entry | first) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-bool-first-false"
        category: "maps"
        tags: [maps map-define map-get arrays bool first accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define flags --kind array --value-type "array{bool:2}" --max-entries 1'
            '  let entry = (0 | map-get flags --kind array)'
            '  if $entry {'
            '    (($entry | first) == false)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
