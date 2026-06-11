export const VERIFIER_DIFF_FIXTURES_3461_3463 = [
    {
        name: "map-get-array-record-length"
        category: "maps"
        tags: [maps map-define map-get arrays records length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "array{record{pid:int,cpu:int}:2}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (($entry | length) == 2)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-record-first-field"
        category: "maps"
        tags: [maps map-define map-get arrays records first get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "array{record{pid:int,cpu:int}:2}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    ((($entry | first) | get pid) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-record-reverse-first-field"
        category: "maps"
        tags: [maps map-define map-get arrays records reverse first get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "array{record{pid:int,cpu:int}:2}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    ((($entry | reverse | first) | get cpu) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
