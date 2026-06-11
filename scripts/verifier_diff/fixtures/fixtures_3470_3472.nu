export const VERIFIER_DIFF_FIXTURES_3470_3472 = [
    {
        name: "map-get-record-array-u32-field-length"
        category: "maps"
        tags: [maps map-define map-get records arrays u32 length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{ports:array{u32:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    ((($entry | get ports) | length) == 2)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-string-field-length-sum"
        category: "maps"
        tags: [maps map-define map-get records arrays string str length math sum accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{names:array{string:8:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get names) | str length) | math sum) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-bytes-field-length-sum"
        category: "maps"
        tags: [maps map-define map-get records arrays binary bytes length math sum accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{buffers:array{bytes:4:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get buffers) | bytes length) | math sum) == 8)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
