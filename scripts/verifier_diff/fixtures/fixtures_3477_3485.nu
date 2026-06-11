export const VERIFIER_DIFF_FIXTURES_3477_3485 = [
    {
        name: "map-get-array-bytes-first-length"
        category: "maps"
        tags: [maps map-define map-get arrays binary bytes first length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define buffers --kind array --value-type "array{bytes:4:2}" --max-entries 1'
            '  let entry = (0 | map-get buffers --kind array)'
            '  if $entry {'
            '    (($entry | first | bytes length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-bytes-take-collect-length"
        category: "maps"
        tags: [maps map-define map-get arrays binary bytes take collect length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define buffers --kind array --value-type "array{bytes:4:2}" --max-entries 1'
            '  let entry = (0 | map-get buffers --kind array)'
            '  if $entry {'
            '    (($entry | take 1 | bytes collect | bytes length) == 4)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u32-last"
        category: "maps"
        tags: [maps map-define map-get arrays u32 last accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{u32:3}" --max-entries 1'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    (($entry | last) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u32-last-count-get"
        category: "maps"
        tags: [maps map-define map-get arrays u32 last get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{u32:3}" --max-entries 1'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    (($entry | last 1 | get 0) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u32-skip-length"
        category: "maps"
        tags: [maps map-define map-get arrays u32 skip length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{u32:3}" --max-entries 1'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    (($entry | skip 1 | length) == 2)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u32-drop-length"
        category: "maps"
        tags: [maps map-define map-get arrays u32 drop length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{u32:3}" --max-entries 1'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    (($entry | drop 1 | length) == 2)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-string-get-length"
        category: "maps"
        tags: [maps map-define map-get arrays strings get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    (($entry | get 0 | str length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-string-take-join-length"
        category: "maps"
        tags: [maps map-define map-get arrays strings take str join length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    (($entry | take 1 | str join "-" | str length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-record-last-field"
        category: "maps"
        tags: [maps map-define map-get arrays records last get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "array{record{pid:int,cpu:int}:2}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    ((($entry | last) | get cpu) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
