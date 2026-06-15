export const VERIFIER_DIFF_FIXTURES_3778_3779 = [
    {
        name: "map-get-array-record-string-field-each-str-length-chars-sum"
        category: "maps"
        tags: [maps map-define map-get arrays records string each closure str length chars math sum accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define name_states --kind array --value-type "array{record{name:string:15}:2}" --max-entries 1'
            '  let entry = (0 | map-get name_states --kind array)'
            '  if $entry {'
            '    (($entry | each {|row| ($row.name | str length --chars) } | math sum) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-record-string-field-where-str-length-chars"
        category: "maps"
        tags: [maps map-define map-get arrays records string where closure str length chars accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define name_states --kind array --value-type "array{record{name:string:15}:2}" --max-entries 1'
            '  let entry = (0 | map-get name_states --kind array)'
            '  if $entry {'
            '    ((($entry | where {|row| ($row.name | str length --chars) == 0 } | length) == 2))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
