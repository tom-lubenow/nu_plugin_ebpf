export const VERIFIER_DIFF_FIXTURES_3440_3444 = [
    {
        name: "map-get-array-string-str-join-zeroed"
        category: "maps"
        tags: [maps map-define map-get arrays string str join length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    (($entry | str join "-" | str length) == 1)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-string-str-starts-with-sum"
        category: "maps"
        tags: [maps map-define map-get arrays string str starts-with math sum accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    (($entry | str starts-with "a" | math sum) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-string-str-ends-with-sum"
        category: "maps"
        tags: [maps map-define map-get arrays string str ends-with math sum accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    (($entry | str ends-with "a" | math sum) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-string-str-contains-sum"
        category: "maps"
        tags: [maps map-define map-get arrays string str contains math sum accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    (($entry | str contains "a" | math sum) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-string-str-index-of-sum"
        category: "maps"
        tags: [maps map-define map-get arrays string str index-of math sum accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    (($entry | str index-of "a" | math sum) == -2)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
