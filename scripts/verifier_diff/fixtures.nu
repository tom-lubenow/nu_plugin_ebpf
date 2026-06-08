const VERIFIER_DIFF_FIXTURE_CHUNKS_DIR = (path self | path dirname | path join fixtures)
source ($VERIFIER_DIFF_FIXTURE_CHUNKS_DIR | path join fixtures_0001_0500.nu)
source ($VERIFIER_DIFF_FIXTURE_CHUNKS_DIR | path join fixtures_0501_1000.nu)
source ($VERIFIER_DIFF_FIXTURE_CHUNKS_DIR | path join fixtures_1001_1500.nu)
source ($VERIFIER_DIFF_FIXTURE_CHUNKS_DIR | path join fixtures_1501_2000.nu)
source ($VERIFIER_DIFF_FIXTURE_CHUNKS_DIR | path join fixtures_2001_2282.nu)

let FIXTURES = (
    $VERIFIER_DIFF_FIXTURES_0001_0500
    | append $VERIFIER_DIFF_FIXTURES_0501_1000
    | append $VERIFIER_DIFF_FIXTURES_1001_1500
    | append $VERIFIER_DIFF_FIXTURES_1501_2000
    | append $VERIFIER_DIFF_FIXTURES_2001_2282
)
