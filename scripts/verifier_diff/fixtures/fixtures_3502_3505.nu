export const VERIFIER_DIFF_FIXTURES_3502_3505 = [
    {
        name: "map-get-array-u32-bits-and-length"
        category: "maps"
        tags: [maps map-define map-get arrays u32 bits and length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{u32:2}" --max-entries 1'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    (($entry | bits and 1 | length) == 2)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u32-bits-not-length"
        category: "maps"
        tags: [maps map-define map-get arrays u32 bits not length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{u32:2}" --max-entries 1'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    (($entry | bits not --number-bytes 4 | length) == 2)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u32-bits-shift-length"
        category: "maps"
        tags: [maps map-define map-get arrays u32 bits shift length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{u32:2}" --max-entries 1'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    ((($entry | bits shl 1 --number-bytes 4 | length) == 2) and (($entry | bits shr 1 --number-bytes 4 | length) == 2))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u32-bits-rotate-length"
        category: "maps"
        tags: [maps map-define map-get arrays u32 bits rotate length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{u32:2}" --max-entries 1'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    ((($entry | bits rol 1 --number-bytes 4 | length) == 2) and (($entry | bits ror 1 --number-bytes 4 | length) == 2))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
