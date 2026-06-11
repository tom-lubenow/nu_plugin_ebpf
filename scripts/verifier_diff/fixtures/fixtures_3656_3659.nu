export const VERIFIER_DIFF_FIXTURES_3656_3659 = [
    {
        name: "task-storage-map-define-array-record-list-init-tail-element"
        category: "maps"
        tags: [maps local-storage task-storage map-define records arrays list append value-type map-get init get accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  map-define typed_task_batches --kind task-storage --value-type "array{record{id:int,samples:list:int:2}:2}"'
            '  let init = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  let state = ($ctx.task | map-get typed_task_batches --kind task-storage --init $init)'
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
        name: "cgrp-storage-map-define-array-record-string-init-tail-length"
        category: "maps"
        tags: [maps local-storage cgrp-storage map-define records arrays string append value-type map-get init get str length accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  map-define typed_cgrp_batches --kind cgrp-storage --value-type "array{record{id:int,name:string:15}:2}"'
            '  let init = ([] | append { id: 1 name: "aa" } | append { id: 2 name: "bbb" })'
            '  let state = ($ctx.current_cgroup | map-get typed_cgrp_batches --kind cgrp-storage --init $init)'
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
        name: "inode-storage-map-define-array-record-list-init-tail-element"
        category: "maps"
        tags: [maps local-storage inode-storage map-define records arrays list append value-type map-get init get accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  map-define typed_inode_batches --kind inode-storage --value-type "array{record{id:int,samples:list:int:2}:2}"'
            '  let init = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  let state = ($ctx.arg.file.f_inode | map-get typed_inode_batches --kind inode-storage --init $init)'
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
        name: "sk-storage-map-define-array-record-string-init-tail-length"
        category: "maps"
        tags: [maps local-storage sk-storage map-define records arrays string append value-type map-get init get str length accept]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  map-define typed_sock_batches --kind sk-storage --value-type "array{record{id:int,name:string:15}:2}"'
            '  let init = ([] | append { id: 1 name: "aa" } | append { id: 2 name: "bbb" })'
            '  let state = ($ctx.sk | map-get typed_sock_batches --kind sk-storage --init $init)'
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
