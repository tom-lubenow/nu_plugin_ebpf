export const VERIFIER_DIFF_FIXTURES_3560_3567 = [
    {
        name: "map-get-record-array-u32-field-take-last"
        category: "maps"
        tags: [maps map-define map-get records arrays u32 take last accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{ports:array{u32:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    ((($entry | get ports) | take 1 | last) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-u32-field-skip-first"
        category: "maps"
        tags: [maps map-define map-get records arrays u32 skip first accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{ports:array{u32:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    ((($entry | get ports) | skip 1 | first) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-u32-field-append-last"
        category: "maps"
        tags: [maps map-define map-get records arrays u32 append last accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{ports:array{u32:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    ((($entry | get ports) | append 7 | last) == 7)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-u32-field-prepend-first"
        category: "maps"
        tags: [maps map-define map-get records arrays u32 prepend first accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{ports:array{u32:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    ((($entry | get ports) | prepend 7 | first) == 7)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-string-field-append-last-length"
        category: "maps"
        tags: [maps map-define map-get records arrays string append last str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{names:array{string:8:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get names) | append "x" | last) | str length) == 1)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-string-field-prepend-first-length"
        category: "maps"
        tags: [maps map-define map-get records arrays string prepend first str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{names:array{string:8:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get names) | prepend "x" | first) | str length) == 1)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-bytes-field-append-last-length"
        category: "maps"
        tags: [maps map-define map-get records arrays binary append last bytes length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{buffers:array{bytes:4:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get buffers) | append 0x[09] | last) | bytes length) == 4)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-bytes-field-prepend-first-length"
        category: "maps"
        tags: [maps map-define map-get records arrays binary prepend first bytes length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{buffers:array{bytes:4:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get buffers) | prepend 0x[09] | first) | bytes length) == 4)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
