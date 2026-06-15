export const VERIFIER_DIFF_FIXTURES_3771_3774 = [
    {
        name: "map-get-array-string-first-str-starts-with"
        category: "maps"
        tags: [maps map-define map-get arrays string first str starts-with accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    (($entry | first | str starts-with "a") == false)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-string-each-str-contains-sum"
        category: "maps"
        tags: [maps map-define map-get arrays string each closure str contains math sum accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    (($entry | each {|x| ($x | str contains "a") } | math sum) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-string-each-str-ends-with-sum"
        category: "maps"
        tags: [maps map-define map-get arrays string each closure str ends-with math sum accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    (($entry | each {|x| ($x | str ends-with "a") } | math sum) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-string-each-str-index-of-sum"
        category: "maps"
        tags: [maps map-define map-get arrays string each closure str index-of math sum accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    (($entry | each {|x| ($x | str index-of "a") } | math sum) == -2)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
