export const VERIFIER_DIFF_FIXTURES_3464_3466 = [
    {
        name: "map-get-array-list-int-first-length"
        category: "maps"
        tags: [maps map-define map-get arrays list first length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define sample_sets --kind array --value-type "array{list:int:4:2}" --max-entries 1'
            '  let entry = (0 | map-get sample_sets --kind array)'
            '  if $entry {'
            '    (($entry | first | length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-record-list-field-length"
        category: "maps"
        tags: [maps map-define map-get arrays records list first get length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define sample_states --kind array --value-type "array{record{samples:list:int:2}:2}" --max-entries 1'
            '  let entry = (0 | map-get sample_states --kind array)'
            '  if $entry {'
            '    (((($entry | first) | get samples) | length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-record-string-field-length"
        category: "maps"
        tags: [maps map-define map-get arrays records string first get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define name_states --kind array --value-type "array{record{name:string:15}:2}" --max-entries 1'
            '  let entry = (0 | map-get name_states --kind array)'
            '  if $entry {'
            '    (((($entry | first) | get name) | str length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
