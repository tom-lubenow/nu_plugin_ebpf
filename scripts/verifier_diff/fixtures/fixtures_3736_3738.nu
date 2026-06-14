export const VERIFIER_DIFF_FIXTURES_3736_3738 = [
    {
        name: "map-get-array-record-list-field-each-length"
        category: "maps"
        tags: [maps map-define map-get arrays records list each closure get length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define sample_states --kind array --value-type "array{record{samples:list:int:2}:2}" --max-entries 1'
            '  let entry = (0 | map-get sample_states --kind array)'
            '  if $entry {'
            '    ((($entry | each {|row| ($row.samples | length) } | get 1) == 0))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-record-string-field-each-length"
        category: "maps"
        tags: [maps map-define map-get arrays records string each closure str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define name_states --kind array --value-type "array{record{name:string:15}:2}" --max-entries 1'
            '  let entry = (0 | map-get name_states --kind array)'
            '  if $entry {'
            '    ((($entry | each {|row| ($row.name | str length) } | get 1) == 0))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-list-each-length"
        category: "maps"
        tags: [maps map-define map-get arrays list each closure length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define sample_sets --kind array --value-type "array{list:int:4:2}" --max-entries 1'
            '  let entry = (0 | map-get sample_sets --kind array)'
            '  if $entry {'
            '    ((($entry | each {|x| ($x | length) } | get 1) == 0))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
