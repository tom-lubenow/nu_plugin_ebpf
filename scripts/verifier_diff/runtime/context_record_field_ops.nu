def remove-record-context-field [fields field_name: string] {
    $fields | where {|field| $field.field != $field_name }
}

def remove-field-name [fields field_name: string] {
    $fields | where {|field| $field != $field_name }
}

def append-field-name [fields field_name: string] {
    if $field_name in $fields {
        return $fields
    }

    $fields | append $field_name
}

def value-token-null? [raw: string] {
    (normalize-context-path-token (trim-simple-parentheses ($raw | str trim))) == "null"
}

def append-record-context-field [fields field_name: string root: string] {
    unique-record-context-fields (
        $fields
        | append {
            field: $field_name
            root: $root
        }
    )
}

def replace-record-context-field [fields field_name: string root] {
    mut next = (remove-record-context-field $fields $field_name)
    if $root != null {
        $next = (append-record-context-field $next $field_name $root)
    }

    $next
}

def has-record-context-field? [fields field_name: string] {
    $fields | any {|field| $field.field == $field_name }
}

def record-field-index [order field_name: string] {
    if $order == null {
        return null
    }

    for entry in ($order | enumerate) {
        if $entry.item == $field_name {
            return $entry.index
        }
    }

    null
}

def record-field-name-at-index [names index: int fallback: string] {
    if $index < ($names | length) {
        return ($names | get $index)
    }

    $fallback
}

def rename-record-context-fields [fields order rename_names] {
    if $order == null {
        return $fields
    }

    mut renamed = []
    for field in $fields {
        let index = (record-field-index $order $field.field)
        let next_name = if $index == null {
            $field.field
        } else {
            record-field-name-at-index $rename_names $index $field.field
        }
        $renamed = ($renamed | append {
            field: $next_name
            root: ($field | get -o root | default "")
        })
    }

    unique-record-context-fields $renamed
}

def rename-record-field-order [order rename_names] {
    if $order == null {
        return null
    }

    mut renamed = []
    for field in ($order | enumerate) {
        let next_name = (record-field-name-at-index $rename_names $field.index $field.item)
        $renamed = ($renamed | append $next_name)
    }

    $renamed
}

def merge-record-field-order [order merge_fields] {
    if $order == null {
        return null
    }

    mut next = $order
    for field in $merge_fields {
        if $field not-in $next {
            $next = ($next | append $field)
        }
    }

    $next
}

def upsert-record-field-order [order field_name: string] {
    if $order == null {
        return null
    }
    if $field_name in $order {
        return $order
    }

    $order | append $field_name
}
