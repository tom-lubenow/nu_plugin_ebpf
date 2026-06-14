def helper-kernel-feature [name: string] {
    let matches = ($HELPER_KERNEL_FEATURES | where {|entry| $entry.name == $name })
    if not ($matches | is-empty) {
        return ($matches | first | get feature)
    }

    let helper_ids = ($BPF_HELPER_IDS | where {|entry| $entry.name == $name })
    if ($helper_ids | is-empty) {
        return null
    }

    let helper_id = ($helper_ids | first | get id)
    let floors = ($BPF_HELPER_KERNEL_FLOORS_BY_MAX_ID | where {|floor| $helper_id <= $floor.max_id })
    if ($floors | is-empty) {
        return null
    }

    let floor = ($floors | first)
    let min_kernel = ($floor | get min_kernel)
    {
        key: $"helper:($name)"
        min_kernel: $min_kernel
        source: $"https://github.com/torvalds/linux/blob/v($min_kernel)/include/uapi/linux/bpf.h"
    }
}

def kfunc-kernel-feature [name: string] {
    let matches = ($KFUNC_KERNEL_FEATURES | where {|entry| $entry.name == $name })
    if not ($matches | is-empty) {
        return ($matches | first | get feature)
    }

    let fallback = ($KFUNC_KERNEL_FEATURE_FALLBACKS | where {|entry| $entry.name == $name })
    if ($fallback | is-empty) {
        return null
    }

    let entry = ($fallback | first)
    mut feature = {
        key: $"kfunc:($name)"
        min_kernel: ($entry | get min_kernel)
        source: ($entry | get source)
    }

    let max_kernel = ($entry | get -o max_kernel_exclusive)
    if $max_kernel != null and $max_kernel != "" {
        $feature = ($feature | insert max_kernel_exclusive $max_kernel)
        let max_kernel_source = ($entry | get -o max_kernel_exclusive_source)
        if $max_kernel_source != null and $max_kernel_source != "" {
            $feature = ($feature | insert max_kernel_exclusive_source $max_kernel_source)
        }
    }

    $feature
}
