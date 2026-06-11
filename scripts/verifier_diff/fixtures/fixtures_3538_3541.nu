export const VERIFIER_DIFF_FIXTURES_3538_3541 = [
    {
        name: "map-get-array-record-take-last-field"
        category: "maps"
        tags: [maps map-define map-get arrays records take last get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "array{record{pid:int,cpu:int}:2}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    ((($entry | take 1 | last) | get cpu) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-record-skip-first-field"
        category: "maps"
        tags: [maps map-define map-get arrays records skip first get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "array{record{pid:int,cpu:int}:2}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    ((($entry | skip 1 | first) | get cpu) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-record-append-last-field"
        category: "maps"
        tags: [maps map-define map-get arrays records append last get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "array{record{pid:int,cpu:int}:2}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    ((($entry | append { pid: 11 cpu: 4 } | last) | get cpu) == 4)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-record-prepend-first-field"
        category: "maps"
        tags: [maps map-define map-get arrays records prepend first get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "array{record{pid:int,cpu:int}:2}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    ((($entry | prepend { pid: 11 cpu: 4 } | first) | get cpu) == 4)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
