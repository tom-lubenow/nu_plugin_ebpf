export const VERIFIER_DIFF_FIXTURES_3652_3655 = [
    {
        name: "task-storage-map-get-init-array-record-list-builder-tail-element"
        category: "maps"
        tags: [maps local-storage task-storage records arrays list append map-get init get accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let init = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  let state = ($ctx.task | map-get task_batches --kind task-storage --init $init)'
            '  if $state {'
            '    let row = ($state | get 1)'
            '    (($row.id == 2) and (($row.samples | get 0) == 3))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgrp-storage-map-get-init-array-record-string-builder-tail-length"
        category: "maps"
        tags: [maps local-storage cgrp-storage records arrays string append map-get init get str length accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let init = ([] | append { id: 1 name: "aa" } | append { id: 2 name: "bbb" })'
            '  let state = ($ctx.current_cgroup | map-get cgrp_batches --kind cgrp-storage --init $init)'
            '  if $state {'
            '    let row = ($state | get 1)'
            '    (($row.id == 2) and (($row.name | str length) == 3))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "inode-storage-map-get-init-array-record-list-builder-tail-element"
        category: "maps"
        tags: [maps local-storage inode-storage records arrays list append map-get init get accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let init = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  let state = ($ctx.arg.file.f_inode | map-get inode_batches --kind inode-storage --init $init)'
            '  if $state {'
            '    let row = ($state | get 1)'
            '    (($row.id == 2) and (($row.samples | get 1) == 4))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-storage-map-get-init-array-record-string-builder-tail-length"
        category: "maps"
        tags: [maps local-storage sk-storage records arrays string append map-get init get str length accept]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  let init = ([] | append { id: 1 name: "aa" } | append { id: 2 name: "bbb" })'
            '  let state = ($ctx.sk | map-get sock_batches --kind sk-storage --init $init)'
            '  if $state {'
            '    let row = ($state | get 1)'
            '    (($row.id == 2) and (($row.name | str length) == 3))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
