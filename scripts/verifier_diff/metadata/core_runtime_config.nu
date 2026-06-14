const BPFFS = "/sys/fs/bpf"
const VALID_TIERS = ["fast" "btf" "kernel" "vm-only"]
const VALID_TEST_LANES = ["host-safe" "host-gated" "dry-run" "vm-only"]
const VALID_HOST_FEATURES = [
    "cgroup-v2"
    "kernel-btf"
    "lirc-device"
    "loopback-interface"
    "netns-self"
    "tracefs"
]
const HOST_FEATURE_PREFIX_KERNEL_BTF_KFUNC = "kernel-btf-kfunc:"

def test-lane-description [lane: string] {
    if $lane == "host-safe" {
        "safe for default host integration-test lanes"
    } else if $lane == "host-gated" {
        "requires explicit host resources, elevated privileges, or host-specific setup"
    } else if $lane == "dry-run" {
        "compile/dry-run coverage only; live attach is not modeled as safe"
    } else if $lane == "vm-only" {
        "behavior-changing or high-risk coverage should run in an isolated VM"
    } else {
        ""
    }
}
