export const VERIFIER_DIFF_FIXTURES_3473_3474 = [
    {
        name: "map-get-record-array-record-field-first"
        category: "maps"
        tags: [maps map-define map-get records arrays first get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{entries:array{record{pid:int,cpu:int}:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get entries) | first) | get pid) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-list-field-first-length"
        category: "maps"
        tags: [maps map-define map-get records arrays list first length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{sets:array{list:int:2:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get sets) | first) | length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
