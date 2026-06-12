def outside-simple-string? [text: string] {
    let double_parts = ($text | split row "\"")
    let single_parts = ($text | split row "'")
    (($double_parts | length) mod 2) == 1 and (($single_parts | length) mod 2) == 1
}

def line-contains-outside-simple-string? [line: string marker: string] {
    let parts = ($line | split row $marker)
    if ($parts | length) <= 1 {
        return false
    }

    for part in ($parts | enumerate) {
        if $part.index == 0 {
            continue
        }

        let before = ($parts | first $part.index | str join $marker)
        if (outside-simple-string? $before) {
            return true
        }
    }

    false
}

def marker-tails-outside-simple-string [line: string marker: string] {
    let trimmed = ($line | str trim)
    if $trimmed == "" or ($trimmed | str starts-with "#") {
        return []
    }
    if not ($trimmed | str contains $marker) {
        return []
    }

    let parts = ($trimmed | split row $marker)
    if ($parts | length) <= 1 {
        return []
    }

    mut tails = []
    for part in ($parts | enumerate) {
        if $part.index == 0 {
            continue
        }

        let before = ($parts | first $part.index | str join $marker)
        if (outside-simple-string? $before) and not (line-contains-outside-simple-string? $before "#") {
            $tails = ($tails | append $part.item)
        }
    }

    $tails
}

def line-contains-code-marker? [line: string marker: string] {
    not ((marker-tails-outside-simple-string $line $marker) | is-empty)
}

def command-tail-after-token [raw_after: string] {
    if $raw_after == "" {
        return ""
    }
    if ($raw_after | str starts-with " ") {
        return ($raw_after | str substring 1..)
    }
    for delimiter in [")" "}" "]" ";"] {
        if ($raw_after | str starts-with $delimiter) {
            return ""
        }
    }

    null
}

def command-invocation-tails [line: string command: string] {
    let trimmed = ($line | str trim)
    if $trimmed == "" or ($trimmed | str starts-with "#") {
        return []
    }
    if not ($trimmed | str contains $command) {
        return []
    }

    mut tails = []
    let command_len = ($command | str length)
    if ($trimmed | str starts-with $command) {
        let tail = (command-tail-after-token ($trimmed | str substring $command_len..))
        if $tail != null {
            $tails = ($tails | append $tail)
        }
    }

    for prefix in ["| " "; " "{ " "( " "("] {
        let marker = $"($prefix)($command)"
        let parts = ($trimmed | split row $marker)
        if ($parts | length) <= 1 {
            continue
        }

        for part in ($parts | enumerate) {
            if $part.index == 0 {
                continue
            }

            let before = ($parts | first $part.index | str join $marker)
            if not (outside-simple-string? $before) {
                continue
            }
            if (line-contains-outside-simple-string? $before "#") {
                continue
            }

            let tail = (command-tail-after-token $part.item)
            if $tail != null {
                $tails = ($tails | append $tail)
            }
        }
    }

    $tails
}

def line-invokes-command? [line: string command: string] {
    not ((command-invocation-tails $line $command) | is-empty)
}

def line-invokes-command-with-tail-prefix? [line: string command: string tail_prefix: string] {
    for tail in (command-invocation-tails $line $command) {
        if ($tail | str trim | str starts-with $tail_prefix) {
            return true
        }
    }

    false
}

def source-invokes-command? [source: string command: string] {
    if not ($source | str contains $command) {
        return false
    }

    for line in ($source | lines) {
        if (line-invokes-command? $line $command) {
            return true
        }
    }

    false
}

def source-invokes-command-with-tail-prefix? [source: string command: string tail_prefix: string] {
    if not ($source | str contains $command) {
        return false
    }

    for line in ($source | lines) {
        if (line-invokes-command-with-tail-prefix? $line $command $tail_prefix) {
            return true
        }
    }

    false
}
