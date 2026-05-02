use super::*;
use std::cmp::Ordering;
use std::fmt;

const LINUX_HELPERS_C_V6_2_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c";
const LINUX_CPUMASK_C_V6_3_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c";
const LINUX_HELPERS_C_V6_4_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c";
const LINUX_HELPERS_C_V6_5_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.5/kernel/bpf/helpers.c";
const LINUX_CPUMASK_C_V6_5_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.5/kernel/bpf/cpumask.c";
const LINUX_MAP_ITER_C_V6_6_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.6/kernel/bpf/map_iter.c";
const LINUX_NET_CORE_FILTER_C_V6_7_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.7/net/core/filter.c";
const LINUX_HELPERS_C_V6_8_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.8/kernel/bpf/helpers.c";
const LINUX_CPUMASK_C_V6_8_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.8/kernel/bpf/cpumask.c";
const LINUX_BPF_FS_KFUNCS_C_V6_12_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.12/fs/bpf_fs_kfuncs.c";

/// Source-backed kernel compatibility metadata for a named BPF kfunc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KfuncCompatibilityRequirement {
    name: &'static str,
}

impl KfuncCompatibilityRequirement {
    pub fn for_name(name: &str) -> Option<Self> {
        let name = known_kfunc_name(name)?;
        Some(Self { name })
    }

    pub fn name(self) -> &'static str {
        self.name
    }

    pub fn key(self) -> String {
        format!("kfunc:{}", self.name)
    }

    pub fn category(self) -> &'static str {
        "kfunc"
    }

    pub fn minimum_kernel(self) -> &'static str {
        kfunc_minimum_kernel(self.name)
            .expect("kfunc requirement is constructed only for versioned kfuncs")
    }

    pub fn minimum_kernel_source(self) -> &'static str {
        kfunc_minimum_kernel_source(self.name)
            .expect("kfunc requirement is constructed only for versioned kfuncs")
    }

    pub fn effective_minimum_kernel(requirements: &[Self]) -> Option<&'static str> {
        let mut minimum = None;
        for requirement in requirements {
            let candidate = requirement.minimum_kernel();
            let should_replace = match minimum {
                Some(current) => Self::kernel_version_cmp(candidate, current).is_gt(),
                None => true,
            };
            if should_replace {
                minimum = Some(candidate);
            }
        }
        minimum
    }

    pub fn kernel_version_at_least(current: &str, minimum: &str) -> bool {
        !Self::kernel_version_cmp(current, minimum).is_lt()
    }

    fn kernel_version_cmp(left: &str, right: &str) -> Ordering {
        let mut left_parts = left.split(['.', '-']);
        let mut right_parts = right.split(['.', '-']);
        let left_version = [
            Self::kernel_version_part(left_parts.next()),
            Self::kernel_version_part(left_parts.next()),
            Self::kernel_version_part(left_parts.next()),
        ];
        let right_version = [
            Self::kernel_version_part(right_parts.next()),
            Self::kernel_version_part(right_parts.next()),
            Self::kernel_version_part(right_parts.next()),
        ];

        left_version.cmp(&right_version)
    }

    fn kernel_version_part(part: Option<&str>) -> u32 {
        part.unwrap_or("0").parse().unwrap_or(0)
    }
}

impl fmt::Display for KfuncCompatibilityRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.key())
    }
}

impl KfuncSignature {
    pub fn compatibility_requirement_for_name(name: &str) -> Option<KfuncCompatibilityRequirement> {
        KfuncCompatibilityRequirement::for_name(name)
    }
}

fn known_kfunc_name(name: &str) -> Option<&'static str> {
    Some(match name {
        "bpf_dynptr_size" => "bpf_dynptr_size",
        "bpf_dynptr_slice" => "bpf_dynptr_slice",
        "bpf_dynptr_slice_rdwr" => "bpf_dynptr_slice_rdwr",
        "bpf_dynptr_clone" => "bpf_dynptr_clone",
        "bpf_dynptr_adjust" => "bpf_dynptr_adjust",
        "bpf_dynptr_is_null" => "bpf_dynptr_is_null",
        "bpf_dynptr_is_rdonly" => "bpf_dynptr_is_rdonly",
        "bpf_task_acquire" => "bpf_task_acquire",
        "bpf_task_from_pid" => "bpf_task_from_pid",
        "bpf_task_get_cgroup1" => "bpf_task_get_cgroup1",
        "bpf_task_release" => "bpf_task_release",
        "bpf_task_under_cgroup" => "bpf_task_under_cgroup",
        "bpf_cgroup_acquire" => "bpf_cgroup_acquire",
        "bpf_cgroup_ancestor" => "bpf_cgroup_ancestor",
        "bpf_cgroup_from_id" => "bpf_cgroup_from_id",
        "bpf_cgroup_release" => "bpf_cgroup_release",
        "bpf_get_task_exe_file" => "bpf_get_task_exe_file",
        "bpf_put_file" => "bpf_put_file",
        "bpf_cpumask_create" => "bpf_cpumask_create",
        "bpf_cpumask_acquire" => "bpf_cpumask_acquire",
        "bpf_cpumask_release" => "bpf_cpumask_release",
        "bpf_cpumask_first" => "bpf_cpumask_first",
        "bpf_cpumask_set_cpu" => "bpf_cpumask_set_cpu",
        "bpf_cpumask_and" => "bpf_cpumask_and",
        "bpf_cpumask_any_and_distribute" => "bpf_cpumask_any_and_distribute",
        "bpf_cpumask_any_distribute" => "bpf_cpumask_any_distribute",
        "bpf_cpumask_clear" => "bpf_cpumask_clear",
        "bpf_cpumask_clear_cpu" => "bpf_cpumask_clear_cpu",
        "bpf_cpumask_copy" => "bpf_cpumask_copy",
        "bpf_cpumask_empty" => "bpf_cpumask_empty",
        "bpf_cpumask_equal" => "bpf_cpumask_equal",
        "bpf_cpumask_first_and" => "bpf_cpumask_first_and",
        "bpf_cpumask_first_zero" => "bpf_cpumask_first_zero",
        "bpf_cpumask_full" => "bpf_cpumask_full",
        "bpf_cpumask_intersects" => "bpf_cpumask_intersects",
        "bpf_cpumask_or" => "bpf_cpumask_or",
        "bpf_cpumask_release_dtor" => "bpf_cpumask_release_dtor",
        "bpf_cpumask_setall" => "bpf_cpumask_setall",
        "bpf_cpumask_subset" => "bpf_cpumask_subset",
        "bpf_cpumask_test_and_clear_cpu" => "bpf_cpumask_test_and_clear_cpu",
        "bpf_cpumask_test_and_set_cpu" => "bpf_cpumask_test_and_set_cpu",
        "bpf_cpumask_test_cpu" => "bpf_cpumask_test_cpu",
        "bpf_cpumask_weight" => "bpf_cpumask_weight",
        "bpf_cpumask_xor" => "bpf_cpumask_xor",
        "bpf_map_sum_elem_count" => "bpf_map_sum_elem_count",
        "bpf_sock_addr_set_sun_path" => "bpf_sock_addr_set_sun_path",
        _ => return None,
    })
}

fn kfunc_minimum_kernel(name: &str) -> Option<&'static str> {
    Some(match name {
        "bpf_task_acquire"
        | "bpf_task_from_pid"
        | "bpf_task_release"
        | "bpf_cgroup_acquire"
        | "bpf_cgroup_ancestor"
        | "bpf_cgroup_release" => "6.2",
        "bpf_cpumask_create"
        | "bpf_cpumask_acquire"
        | "bpf_cpumask_release"
        | "bpf_cpumask_first"
        | "bpf_cpumask_set_cpu"
        | "bpf_cpumask_and"
        | "bpf_cpumask_clear"
        | "bpf_cpumask_clear_cpu"
        | "bpf_cpumask_copy"
        | "bpf_cpumask_empty"
        | "bpf_cpumask_equal"
        | "bpf_cpumask_first_zero"
        | "bpf_cpumask_full"
        | "bpf_cpumask_intersects"
        | "bpf_cpumask_or"
        | "bpf_cpumask_setall"
        | "bpf_cpumask_subset"
        | "bpf_cpumask_test_and_clear_cpu"
        | "bpf_cpumask_test_and_set_cpu"
        | "bpf_cpumask_test_cpu"
        | "bpf_cpumask_xor" => "6.3",
        "bpf_dynptr_slice" | "bpf_dynptr_slice_rdwr" | "bpf_cgroup_from_id" => "6.4",
        "bpf_cpumask_any_and_distribute"
        | "bpf_cpumask_any_distribute"
        | "bpf_cpumask_first_and" => "6.5",
        "bpf_dynptr_size"
        | "bpf_dynptr_clone"
        | "bpf_dynptr_adjust"
        | "bpf_dynptr_is_null"
        | "bpf_dynptr_is_rdonly"
        | "bpf_task_under_cgroup" => "6.5",
        "bpf_map_sum_elem_count" => "6.6",
        "bpf_sock_addr_set_sun_path" => "6.7",
        "bpf_task_get_cgroup1" => "6.8",
        "bpf_cpumask_release_dtor" | "bpf_cpumask_weight" => "6.8",
        "bpf_get_task_exe_file" | "bpf_put_file" => "6.12",
        _ => return None,
    })
}

fn kfunc_minimum_kernel_source(name: &str) -> Option<&'static str> {
    kfunc_minimum_kernel(name)?;
    Some(match name {
        "bpf_task_acquire"
        | "bpf_task_from_pid"
        | "bpf_task_release"
        | "bpf_cgroup_acquire"
        | "bpf_cgroup_ancestor"
        | "bpf_cgroup_release" => LINUX_HELPERS_C_V6_2_SOURCE,
        "bpf_cpumask_create"
        | "bpf_cpumask_acquire"
        | "bpf_cpumask_release"
        | "bpf_cpumask_first"
        | "bpf_cpumask_set_cpu"
        | "bpf_cpumask_and"
        | "bpf_cpumask_clear"
        | "bpf_cpumask_clear_cpu"
        | "bpf_cpumask_copy"
        | "bpf_cpumask_empty"
        | "bpf_cpumask_equal"
        | "bpf_cpumask_first_zero"
        | "bpf_cpumask_full"
        | "bpf_cpumask_intersects"
        | "bpf_cpumask_or"
        | "bpf_cpumask_setall"
        | "bpf_cpumask_subset"
        | "bpf_cpumask_test_and_clear_cpu"
        | "bpf_cpumask_test_and_set_cpu"
        | "bpf_cpumask_test_cpu"
        | "bpf_cpumask_xor" => LINUX_CPUMASK_C_V6_3_SOURCE,
        "bpf_dynptr_slice" | "bpf_dynptr_slice_rdwr" | "bpf_cgroup_from_id" => {
            LINUX_HELPERS_C_V6_4_SOURCE
        }
        "bpf_cpumask_any_and_distribute"
        | "bpf_cpumask_any_distribute"
        | "bpf_cpumask_first_and" => LINUX_CPUMASK_C_V6_5_SOURCE,
        "bpf_dynptr_size"
        | "bpf_dynptr_clone"
        | "bpf_dynptr_adjust"
        | "bpf_dynptr_is_null"
        | "bpf_dynptr_is_rdonly"
        | "bpf_task_under_cgroup" => LINUX_HELPERS_C_V6_5_SOURCE,
        "bpf_map_sum_elem_count" => LINUX_MAP_ITER_C_V6_6_SOURCE,
        "bpf_sock_addr_set_sun_path" => LINUX_NET_CORE_FILTER_C_V6_7_SOURCE,
        "bpf_task_get_cgroup1" => LINUX_HELPERS_C_V6_8_SOURCE,
        "bpf_cpumask_release_dtor" | "bpf_cpumask_weight" => LINUX_CPUMASK_C_V6_8_SOURCE,
        "bpf_get_task_exe_file" | "bpf_put_file" => LINUX_BPF_FS_KFUNCS_C_V6_12_SOURCE,
        _ => return None,
    })
}
