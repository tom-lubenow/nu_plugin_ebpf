def normalize-map-kind-token [token: string] {
    $token
    | str trim
    | str replace --all ")" ""
    | str replace --all "," ""
    | str replace --all "\"" ""
    | str replace --all "'" ""
    | str replace --all ";" ""
}

def normalize-map-name-token [token: string] {
    $token
    | str trim
    | str replace --all ")" ""
    | str replace --all "(" ""
    | str replace --all "," ""
    | str replace --all "\"" ""
    | str replace --all "'" ""
    | str replace --all "}" ""
    | str replace --all "]" ""
    | str replace --all ";" ""
}

def normalize-helper-name-token [token: string] {
    $token
    | str trim
    | str replace --all ")" ""
    | str replace --all "," ""
    | str replace --all "\"" ""
    | str replace --all "'" ""
}

def normalize-kfunc-name-token [token: string] {
    normalize-helper-name-token $token
}

def normalize-context-field-token [token: string] {
    $token
    | str trim
    | split row " "
    | first
    | split row "."
    | first
    | str replace --all ")" ""
    | str replace --all "(" ""
    | str replace --all "," ""
    | str replace --all "\"" ""
    | str replace --all "'" ""
    | str replace --all "}" ""
    | str replace --all "]" ""
    | str replace --all ";" ""
}

def normalize-context-path-token [token: string] {
    $token
    | str trim
    | split row " "
    | first
    | str replace --all ")" ""
    | str replace --all "(" ""
    | str replace --all "," ""
    | str replace --all "\"" ""
    | str replace --all "'" ""
    | str replace --all "}" ""
    | str replace --all "]" ""
    | str replace --all ";" ""
}
