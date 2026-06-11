export const VERIFIER_DIFF_FIXTURES_3553_3559 = [
    {
        name: "map-get-record-array-u32-field-first"
        category: "maps"
        tags: [maps map-define map-get records arrays u32 first accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{ports:array{u32:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    ((($entry | get ports) | first) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-u32-field-reverse-first"
        category: "maps"
        tags: [maps map-define map-get records arrays u32 reverse first accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{ports:array{u32:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    ((($entry | get ports) | reverse | first) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-string-field-first-length"
        category: "maps"
        tags: [maps map-define map-get records arrays string first str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{names:array{string:8:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get names) | first) | str length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-string-field-reverse-first-length"
        category: "maps"
        tags: [maps map-define map-get records arrays string reverse first str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{names:array{string:8:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get names) | reverse | first) | str length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-bytes-field-first-length"
        category: "maps"
        tags: [maps map-define map-get records arrays binary first bytes length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{buffers:array{bytes:4:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get buffers) | first) | bytes length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-record-field-last"
        category: "maps"
        tags: [maps map-define map-get records arrays last get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{entries:array{record{pid:int,cpu:int}:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get entries) | last) | get cpu) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-list-field-reverse-first-length"
        category: "maps"
        tags: [maps map-define map-get records arrays list reverse first length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{sets:array{list:int:2:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get sets) | reverse | first) | length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
