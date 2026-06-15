export const VERIFIER_DIFF_FIXTURES_3854_3854 = [
    {
        name: "map-push-queue-array-bool-direct-first"
        category: "maps"
        tags: [maps queue map-define map-push map-pop arrays bool first accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define flag_queue --kind queue --value-type "array{bool:2}" --max-entries 1'
            '  [true false] | map-push flag_queue --kind queue'
            '  let entry = (map-pop flag_queue --kind queue)'
            '  if $entry {'
            '    (($entry | first) == true)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
