export const VERIFIER_DIFF_FIXTURES_3568_3575 = [
    {
        name: "map-get-record-array-record-field-take-last"
        category: "maps"
        tags: [maps map-define map-get records arrays take last get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{entries:array{record{pid:int,cpu:int}:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get entries) | take 1 | last) | get cpu) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-record-field-skip-first"
        category: "maps"
        tags: [maps map-define map-get records arrays skip first get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{entries:array{record{pid:int,cpu:int}:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get entries) | skip 1 | first) | get cpu) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-record-field-append-last"
        category: "maps"
        tags: [maps map-define map-get records arrays append last get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{entries:array{record{pid:int,cpu:int}:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get entries) | append { pid: 11 cpu: 4 } | last) | get cpu) == 4)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-record-field-prepend-first"
        category: "maps"
        tags: [maps map-define map-get records arrays prepend first get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{entries:array{record{pid:int,cpu:int}:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get entries) | prepend { pid: 11 cpu: 4 } | first) | get cpu) == 4)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-list-field-take-last-length"
        category: "maps"
        tags: [maps map-define map-get records arrays list take last length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{sets:array{list:int:2:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get sets) | take 1 | last) | length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-list-field-skip-first-length"
        category: "maps"
        tags: [maps map-define map-get records arrays list skip first length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{sets:array{list:int:2:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get sets) | skip 1 | first) | length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-list-field-append-last-length"
        category: "maps"
        tags: [maps map-define map-get records arrays list append last length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{sets:array{list:int:2:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get sets) | append [1 2] | last) | length) == 2)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-record-array-list-field-prepend-first-length"
        category: "maps"
        tags: [maps map-define map-get records arrays list prepend first length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define states --kind array --value-type "record{sets:array{list:int:2:2},pid:int}" --max-entries 1'
            '  let entry = (0 | map-get states --kind array)'
            '  if $entry {'
            '    (((($entry | get sets) | prepend [1 2] | first) | length) == 2)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
