export const VERIFIER_DIFF_FIXTURES_3547_3552 = [
    {
        name: "map-get-array-record-list-field-last-length"
        category: "maps"
        tags: [maps map-define map-get arrays records list last get length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define sample_states --kind array --value-type "array{record{samples:list:int:2}:2}" --max-entries 1'
            '  let entry = (0 | map-get sample_states --kind array)'
            '  if $entry {'
            '    (((($entry | last) | get samples) | length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-record-list-field-take-last-length"
        category: "maps"
        tags: [maps map-define map-get arrays records list take last get length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define sample_states --kind array --value-type "array{record{samples:list:int:2}:2}" --max-entries 1'
            '  let entry = (0 | map-get sample_states --kind array)'
            '  if $entry {'
            '    (((($entry | take 1 | last) | get samples) | length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-record-list-field-reverse-first-length"
        category: "maps"
        tags: [maps map-define map-get arrays records list reverse first get length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define sample_states --kind array --value-type "array{record{samples:list:int:2}:2}" --max-entries 1'
            '  let entry = (0 | map-get sample_states --kind array)'
            '  if $entry {'
            '    (((($entry | reverse | first) | get samples) | length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-record-string-field-last-length"
        category: "maps"
        tags: [maps map-define map-get arrays records string last get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define name_states --kind array --value-type "array{record{name:string:15}:2}" --max-entries 1'
            '  let entry = (0 | map-get name_states --kind array)'
            '  if $entry {'
            '    (((($entry | last) | get name) | str length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-record-string-field-take-last-length"
        category: "maps"
        tags: [maps map-define map-get arrays records string take last get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define name_states --kind array --value-type "array{record{name:string:15}:2}" --max-entries 1'
            '  let entry = (0 | map-get name_states --kind array)'
            '  if $entry {'
            '    (((($entry | take 1 | last) | get name) | str length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-record-string-field-reverse-first-length"
        category: "maps"
        tags: [maps map-define map-get arrays records string reverse first get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define name_states --kind array --value-type "array{record{name:string:15}:2}" --max-entries 1'
            '  let entry = (0 | map-get name_states --kind array)'
            '  if $entry {'
            '    (((($entry | reverse | first) | get name) | str length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
