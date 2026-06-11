const VERIFIER_DIFF_FIXTURE_CHUNKS_DIR = (path self | path dirname | path join fixtures)

def parse-verifier-diff-fixture-chunk [path: path] {
    open --raw $path
    | str replace -r "^(export )?const [A-Z0-9_]+ = " ""
    | from nuon
}

let FIXTURES = (
    glob ($VERIFIER_DIFF_FIXTURE_CHUNKS_DIR | path join "fixtures_*.nu")
    | sort
    | each {|path| parse-verifier-diff-fixture-chunk $path }
    | reduce --fold [] {|chunk, acc| $acc | append $chunk }
)
