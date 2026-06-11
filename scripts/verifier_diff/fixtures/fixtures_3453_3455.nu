export const VERIFIER_DIFF_FIXTURES_3453_3455 = [
    {
        name: "map-get-array-string-str-substring-join-length"
        category: "maps"
        tags: [maps map-define map-get arrays string str substring range join length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    ((($entry | str substring 0..0 | str join ",") | str length) == 1)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-string-str-replace-all-join-length"
        category: "maps"
        tags: [maps map-define map-get arrays string str replace all join length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    ((($entry | str replace --all "a" "z" | str join ",") | str length) == 1)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-string-str-trim-char-join-length"
        category: "maps"
        tags: [maps map-define map-get arrays string str trim char join length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define names --kind array --value-type "array{string:8:2}" --max-entries 1'
            '  let entry = (0 | map-get names --kind array)'
            '  if $entry {'
            '    ((($entry | str trim --char "x" | str join "-") | str length) == 1)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
