export const VERIFIER_DIFF_FIXTURES_3730_3732 = [
    {
        name: "map-get-array-record-list-field-where-length"
        category: "maps"
        tags: [maps map-define map-get arrays records list where closure length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define sample_states --kind array --value-type "array{record{samples:list:int:2}:2}" --max-entries 1'
            '  let entry = (0 | map-get sample_states --kind array)'
            '  if $entry {'
            '    ((($entry | where {|row| (($row.samples | length) == 0) } | length) == 2))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-record-string-field-all-length"
        category: "maps"
        tags: [maps map-define map-get arrays records string all closure str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define name_states --kind array --value-type "array{record{name:string:15}:2}" --max-entries 1'
            '  let entry = (0 | map-get name_states --kind array)'
            '  if $entry {'
            '    (($entry | all {|row| (($row.name | str length) == 0) }))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-list-any-length"
        category: "maps"
        tags: [maps map-define map-get arrays list any closure length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define sample_sets --kind array --value-type "array{list:int:4:2}" --max-entries 1'
            '  let entry = (0 | map-get sample_sets --kind array)'
            '  if $entry {'
            '    (($entry | any {|x| (($x | length) == 0) }))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
