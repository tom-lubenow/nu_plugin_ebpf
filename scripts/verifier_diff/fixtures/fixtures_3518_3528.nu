export const VERIFIER_DIFF_FIXTURES_3518_3528 = [
    {
        name: "map-get-array-string-length"
        category: "maps"
        tags: [maps map-define map-get arrays strings length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
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
        name: "map-get-array-string-is-empty"
        category: "maps"
        tags: [maps map-define map-get arrays strings is-empty accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    (($entry | is-empty) == false)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-string-is-not-empty"
        category: "maps"
        tags: [maps map-define map-get arrays strings is-not-empty accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    $entry | is-not-empty'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-string-get-core-length"
        category: "maps"
        tags: [maps map-define map-get arrays strings get length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    (($entry | get 0 | length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-string-get-is-empty"
        category: "maps"
        tags: [maps map-define map-get arrays strings get is-empty accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    $entry | get 1 | is-empty'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-string-first-str-length"
        category: "maps"
        tags: [maps map-define map-get arrays strings first str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    (($entry | first | str length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-string-last-is-empty"
        category: "maps"
        tags: [maps map-define map-get arrays strings last is-empty accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    $entry | last | is-empty'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-string-take-first-str-length"
        category: "maps"
        tags: [maps map-define map-get arrays strings take first str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    (($entry | take 1 | first | str length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-string-skip-first-is-empty"
        category: "maps"
        tags: [maps map-define map-get arrays strings skip first is-empty accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    $entry | skip 1 | first | is-empty'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-string-drop-last-length"
        category: "maps"
        tags: [maps map-define map-get arrays strings drop last length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    (($entry | drop 1 | last | length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-string-reverse-first-is-empty"
        category: "maps"
        tags: [maps map-define map-get arrays strings reverse first is-empty accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    $entry | reverse | first | is-empty'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
