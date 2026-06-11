export const VERIFIER_DIFF_FIXTURES_3542_3546 = [
    {
        name: "map-get-array-list-int-length"
        category: "maps"
        tags: [maps map-define map-get arrays list length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define sample_sets --kind array --value-type "array{list:int:4:2}" --max-entries 1'
            '  let entry = (0 | map-get sample_sets --kind array)'
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
        name: "map-get-array-list-int-last-length"
        category: "maps"
        tags: [maps map-define map-get arrays list last length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define sample_sets --kind array --value-type "array{list:int:4:2}" --max-entries 1'
            '  let entry = (0 | map-get sample_sets --kind array)'
            '  if $entry {'
            '    (($entry | last | length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-list-int-take-first-length"
        category: "maps"
        tags: [maps map-define map-get arrays list take first length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define sample_sets --kind array --value-type "array{list:int:4:2}" --max-entries 1'
            '  let entry = (0 | map-get sample_sets --kind array)'
            '  if $entry {'
            '    (($entry | take 1 | first | length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-list-int-skip-first-length"
        category: "maps"
        tags: [maps map-define map-get arrays list skip first length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define sample_sets --kind array --value-type "array{list:int:4:2}" --max-entries 1'
            '  let entry = (0 | map-get sample_sets --kind array)'
            '  if $entry {'
            '    (($entry | skip 1 | first | length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-list-int-reverse-first-length"
        category: "maps"
        tags: [maps map-define map-get arrays list reverse first length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define sample_sets --kind array --value-type "array{list:int:4:2}" --max-entries 1'
            '  let entry = (0 | map-get sample_sets --kind array)'
            '  if $entry {'
            '    (($entry | reverse | first | length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
