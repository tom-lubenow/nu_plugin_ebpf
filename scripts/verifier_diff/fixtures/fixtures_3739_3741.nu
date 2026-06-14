export const VERIFIER_DIFF_FIXTURES_3739_3741 = [
    {
        name: "map-get-array-string-each-length"
        category: "maps"
        tags: [maps map-define map-get arrays string each closure str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    ((($entry | each {|x| ($x | str length) } | get 1) == 0))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-bytes-where-length"
        category: "maps"
        tags: [maps map-define map-get arrays binary bytes where closure length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define buffers --kind array --value-type "array{bytes:4:2}" --max-entries 1'
            '  let entry = (0 | map-get buffers --kind array)'
            '  if $entry {'
            '    ((($entry | where {|x| ($x | bytes length) == 4 } | length) == 2))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-string-all-length"
        category: "maps"
        tags: [maps map-define map-get arrays string all closure str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    (($entry | all {|x| ($x | str length) == 0 }))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
